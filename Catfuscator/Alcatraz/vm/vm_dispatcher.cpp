#include "vm_dispatcher.h"
#include <cstring>

using namespace asmjit;
using namespace asmjit::x86;

// VM dispatcher register convention:
//   RSI = bytecode instruction pointer (VM IP)
//   RBX = base pointer to VM register file on stack
//   Native stack is used for PUSH/POP operations
//   All other native registers are scratch within handlers

// VM register file layout:
//   [0..136)   = GP regs (17 x 8 bytes): VRAX..VRFLAGS
//   [136..392) = XMM regs (16 x 16 bytes): VXMM0..VXMM15

static constexpr int VRFLAGS_OFF = vm_gp_offset(static_cast<int>(vm_reg::VRFLAGS));
static constexpr int VM_REG_FILE_ALLOC = (VM_REG_FILE_TOTAL + 15) & ~15; // 400 -> 400 (already aligned)

vm_dispatcher::vm_dispatcher(const vm_opcode_table& table) : table(table), dispatcher_size(0), mba(opaque_rng), nested_mode(false), inner_dispatcher_rva(0) {}

uint32_t vm_dispatcher::get_dispatcher_size() const {
	return dispatcher_size;
}

bool vm_dispatcher::generate(std::vector<uint8_t>& dispatcher_code,
	const uint8_t* key, int key_size, uint32_t bytecode_size, uint64_t imm_xor_key,
	const vm_settings* settings, uint32_t context_seed, uint64_t image_base,
	bool nested_mode) {
	this->settings = settings;
	this->context_seed = context_seed;
	this->compile_image_base = image_base;
	this->nested_mode = nested_mode;

	// Seed opaque predicate RNG from opcode table + per-region key
	uint32_t op_seed = table.mapping[0] ^ (table.mapping[1] << 16) ^ static_cast<uint32_t>(imm_xor_key);
	opaque_rng.seed(op_seed ^ 0xCAFEBABE);

	JitRuntime rt;
	CodeHolder code;
	code.init(rt.environment());

	x86::Assembler a(&code);
	handler_labels labels;

	labels.entry = a.newLabel();
	labels.dispatch_loop = a.newLabel();
	labels.dispatch_continue = a.newLabel();
	labels.exit_label = a.newLabel();
	for (int i = 0; i < static_cast<int>(vm_op::VM_COUNT); i++)
		labels.handlers[i] = a.newLabel();
	for (int d = 0; d < vm_opcode_table::TOTAL_DUPS; d++)
		labels.dup_handlers[d] = a.newLabel();

	// Entry: RSI already points to bytecode (set by caller)
	a.bind(labels.entry);

	// --- VM_ENTER handler (inline at entry, includes bytecode decrypt) ---
	emit_enter_handler(a, labels, key, key_size, bytecode_size, imm_xor_key);

	// --- Dispatch loop ---
	emit_dispatch_loop(a, labels);

	// --- All opcode handlers: shuffled order with opaque predicates ---
	{
		std::vector<std::function<void()>> handler_list;
		build_handler_list(a, labels, handler_list);
		std::shuffle(handler_list.begin(), handler_list.end(), opaque_rng);
		for (auto& h : handler_list) {
			maybe_emit_opaque(a, labels);
			h();
		}
	}

	// --- VM_EXIT handler ---
	emit_exit_handler(a, labels);

	CodeBuffer& buf = code.sectionById(0)->buffer();
	dispatcher_code.assign(buf.data(), buf.data() + buf.size());
	dispatcher_size = static_cast<uint32_t>(buf.size());

	return true;
}

void vm_dispatcher::emit_enter_handler(x86::Assembler& a, handler_labels& labels,
	const uint8_t* key, int key_size, uint32_t bytecode_size, uint64_t imm_xor_key) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_ENTER)]);

	if (nested_mode) {
		// Inner VM entry: RSI=inner bytecode ptr, RBX=reg file, R14=image base (all set by caller)
		// Just set inner-specific R12/R13, decrypt, and start dispatching

		// --- Decrypt inner bytecode in-place ---
		if (key && key_size > 0 && bytecode_size > 0) {
			Label key_label = a.newLabel();
			Label skip_key = a.newLabel();
			Label decrypt_loop = a.newLabel();
			Label decrypt_done = a.newLabel();
			Label no_wrap = a.newLabel();

			a.push(rsi); // save bytecode start for R13
			a.jmp(skip_key);
			a.bind(key_label);
			for (int i = 0; i < key_size; i++)
				a.db(key[i]);
			a.bind(skip_key);

			a.mov(rdi, rsi);
			a.mov(ecx, bytecode_size);
			a.lea(rdx, qword_ptr(key_label));
			a.xor_(r8d, r8d);

			a.bind(decrypt_loop);
			a.test(ecx, ecx);
			a.jz(decrypt_done);
			a.movzx(eax, byte_ptr(rdx, r8));
			a.xor_(byte_ptr(rdi), al);
			a.inc(rdi);
			a.dec(ecx);
			a.inc(r8d);
			a.cmp(r8d, key_size);
			a.jb(no_wrap);
			a.xor_(r8d, r8d);
			a.bind(no_wrap);
			a.jmp(decrypt_loop);
			a.bind(decrypt_done);
			a.pop(rsi); // restore bytecode start
		}

		// R12 = inner XOR key
		a.mov(r12, Imm(static_cast<int64_t>(imm_xor_key)));

		// R13 = inner bytecode base
		a.mov(r13, rsi);

		// Skip VM_ENTER opcode (2 bytes)
		a.add(rsi, 2);

		// Fall through to inner dispatch loop
		return;
	}

	// --- Outer VM entry (original) ---

	// Save callee-saved registers we'll clobber
	a.push(rbx);
	a.push(rbp);
	a.push(r12);
	a.push(r13);
	a.push(r14);
	a.push(r15);
	a.pushfq();

	// RSI = bytecode pointer, already set by caller before jumping here
	// But we need to save RSI too since we use it as VM IP
	a.push(rsi);
	a.push(rdi);

	// Allocate VM register file on stack: GP (17*8=136) + XMM (16*16=256) = 392 -> 400 aligned
	a.sub(rsp, VM_REG_FILE_ALLOC);
	a.mov(rbx, rsp); // RBX = base of VM register file

	constexpr int S = VM_REG_FILE_ALLOC;

	// Initialize GP registers from native registers
	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VRAX)), rax);
	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VRCX)), rcx);
	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VRDX)), rdx);

	a.mov(rax, qword_ptr(rsp, S + 64));
	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VRBX)), rax);

	// RSP: original RSP before CALL = rsp + alloc + 9 pushes (72) + return addr (8)
	a.lea(rax, qword_ptr(rsp, S + 72 + 8));
	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VRSP)), rax);

	a.mov(rax, qword_ptr(rsp, S + 56));
	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VRBP)), rax);

	a.mov(rax, qword_ptr(rsp, S + 8));
	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VRSI)), rax);
	a.mov(rax, qword_ptr(rsp, S + 0));
	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VRDI)), rax);

	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VR8)), r8);
	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VR9)), r9);
	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VR10)), r10);
	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VR11)), r11);

	a.mov(rax, qword_ptr(rsp, S + 48));
	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VR12)), rax);
	a.mov(rax, qword_ptr(rsp, S + 40));
	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VR13)), rax);
	a.mov(rax, qword_ptr(rsp, S + 32));
	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VR14)), rax);
	a.mov(rax, qword_ptr(rsp, S + 24));
	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VR15)), rax);

	// RFLAGS
	a.mov(rax, qword_ptr(rsp, S + 16));
	a.mov(qword_ptr(rbx, VRFLAGS_OFF), rax);

	// Save XMM registers to VM context
	for (int i = 0; i < 16; i++) {
		int off = vm_xmm_offset(static_cast<int>(vm_reg::VXMM0) + i);
		a.movups(xmmword_ptr(rbx, off), x86::Xmm(i));
	}

	// RSI = bytecode pointer (passed in RCX on Windows x64 ABI)
	a.mov(rsi, qword_ptr(rbx, table.perm_gp_off(vm_reg::VRCX)));

	// --- Decrypt bytecode in-place ---
	if (key && key_size > 0 && bytecode_size > 0) {
		Label key_label = a.newLabel();
		Label skip_key = a.newLabel();
		Label decrypt_loop = a.newLabel();
		Label decrypt_done = a.newLabel();
		Label no_wrap = a.newLabel();

		// Jump over embedded key data
		a.jmp(skip_key);
		a.bind(key_label);
		for (int i = 0; i < key_size; i++)
			a.db(key[i]);
		a.bind(skip_key);

		// rdi = decrypt cursor, ecx = remaining bytes
		a.mov(rdi, rsi);
		a.mov(ecx, bytecode_size);
		a.lea(rdx, qword_ptr(key_label));
		a.xor_(r8d, r8d);

		a.bind(decrypt_loop);
		a.test(ecx, ecx);
		a.jz(decrypt_done);
		a.movzx(eax, byte_ptr(rdx, r8));
		a.xor_(byte_ptr(rdi), al);
		a.inc(rdi);
		a.dec(ecx);
		a.inc(r8d);
		a.cmp(r8d, key_size);
		a.jb(no_wrap);
		a.xor_(r8d, r8d);
		a.bind(no_wrap);
		a.jmp(decrypt_loop);
		a.bind(decrypt_done);
	}

	// R12 = XOR key for encrypted immediates
	a.mov(r12, Imm(static_cast<int64_t>(imm_xor_key)));

	// R13 = bytecode base (for context-dependent decoding)
	a.mov(r13, rsi);

	// R14 = runtime image base (for ASLR relocation)
	// Read from PEB: gs:[0x60] -> PEB, PEB+0x10 -> ImageBaseAddress
	{
		x86::Mem peb_ptr = x86::ptr(0x60);
		peb_ptr.setSegment(x86::SReg::kIdGs);
		a.mov(rax, peb_ptr);
		a.mov(r14, qword_ptr(rax, 0x10));
	}

	// Skip the VM_ENTER opcode (2 bytes)
	a.add(rsi, 2);

	// Fall through to dispatch loop
}

void vm_dispatcher::emit_dispatch_loop(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.dispatch_loop);

	// Context-dependent decoding: XOR opcode with position-based multi-round hash
	if (settings && settings->context_dependent_decoding) {
		// pos = rsi - r13 (bytecode offset before read)
		a.mov(edx, esi);
		a.sub(edx, r13d);
		// h = pos * 0x45D9F3B + context_seed
		a.imul(edx, edx, 0x45D9F3B);
		a.add(edx, Imm(static_cast<int32_t>(context_seed)));
		// h ^= h >> 16
		a.mov(r10d, edx);
		a.shr(r10d, 16);
		a.xor_(edx, r10d);
		// h *= 0x85EBCA6B
		a.imul(edx, edx, Imm(static_cast<int32_t>(0x85EBCA6Bu)));
		// h ^= h >> 13
		a.mov(r10d, edx);
		a.shr(r10d, 13);
		a.xor_(edx, r10d);
		// key16 = h >> 16
		a.shr(edx, 16);

		a.movzx(eax, word_ptr(rsi));
		a.xor_(eax, edx);
		a.and_(eax, 0xFFFF);
		a.add(rsi, 2);
	} else {
		a.movzx(eax, word_ptr(rsi));
		a.add(rsi, 2);
	}

	// Skip variable-length prefix bytes
	a.cmp(eax, Imm(vm_opcode_table::TOTAL_ENCODED));
	a.jae(labels.dispatch_loop);

	a.bind(labels.dispatch_continue);

	// Build dispatch entries: original + dup handlers
	struct dispatch_entry { uint16_t encoded; Label* target; };
	std::vector<dispatch_entry> entries;
	entries.reserve(vm_opcode_table::TOTAL_ENCODED);

	for (int i = 0; i < static_cast<int>(vm_op::VM_COUNT); i++)
		entries.push_back({ table.encode(static_cast<vm_op>(i)), &labels.handlers[i] });
	for (int d = 0; d < vm_opcode_table::TOTAL_DUPS; d++)
		entries.push_back({ table.dup_encoded[d], &labels.dup_handlers[d] });

	int method = (opaque_rng() % 2 == 0) ? 0 : 2; // skip jump table (case 1) — embedLabelDelta not resolved in raw buffer
	switch (method) {
	case 0: {
		// Linear scan (shuffled)
		std::shuffle(entries.begin(), entries.end(), opaque_rng);
		for (auto& e : entries) {
			a.cmp(ax, Imm(e.encoded));
			a.je(*e.target);
		}
		a.jmp(labels.exit_label);
		break;
	}
	case 1: {
		// Jump table: O(1) dispatch via indexed table of relative offsets
		Label table_label = a.newLabel();
		a.lea(rdx, x86::qword_ptr(table_label));
		a.movsxd(rcx, x86::dword_ptr(rdx, rax, 2));
		a.add(rcx, rdx);
		a.jmp(rcx);

		a.bind(table_label);
		std::vector<Label*> jump_targets(vm_opcode_table::TOTAL_ENCODED, &labels.exit_label);
		for (auto& e : entries)
			jump_targets[e.encoded] = e.target;
		for (int i = 0; i < vm_opcode_table::TOTAL_ENCODED; i++)
			a.embedLabelDelta(*jump_targets[i], table_label, 4);
		break;
	}
	case 2: {
		// Binary search tree: O(log n) dispatch
		std::sort(entries.begin(), entries.end(),
			[](const dispatch_entry& a, const dispatch_entry& b) { return a.encoded < b.encoded; });

		std::function<void(int, int)> emit_bst;
		emit_bst = [&](int lo, int hi) {
			if (lo > hi) {
				a.jmp(labels.exit_label);
				return;
			}
			if (lo == hi) {
				a.jmp(*entries[lo].target);
				return;
			}
			int mid = (lo + hi) / 2;
			a.cmp(ax, Imm(entries[mid].encoded));
			a.je(*entries[mid].target);
			Label right_branch = a.newLabel();
			a.ja(right_branch);
			emit_bst(lo, mid - 1);
			a.bind(right_branch);
			emit_bst(mid + 1, hi);
		};
		emit_bst(0, static_cast<int>(entries.size()) - 1);
		break;
	}
	}
}

void vm_dispatcher::emit_nop_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_NOP)]);
	emit_chain_dispatch(a, labels);
}

void vm_dispatcher::emit_mov_reg_imm64_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_MOV_REG_IMM64)]);
	emit_handler_entry_junk(a);
	// Format: [opcode] [vreg:1] [imm64:8]
	a.movzx(ecx, byte_ptr(rsi));       // vreg index
	emit_poly_advance_ip(a, 1);
	a.mov(rax, qword_ptr(rsi));        // imm64 (encrypted)
	a.xor_(rax, r12);                  // decrypt
	emit_poly_advance_ip(a, 8);
	// vm_regs[vreg] = imm64
	emit_poly_index_to_offset(a, rcx);
	a.mov(qword_ptr(rbx, rcx), rax);
	emit_chain_dispatch(a, labels);
}

void vm_dispatcher::emit_mov_reg_reg_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_MOV_REG_REG)]);
	emit_handler_entry_junk(a);
	// Format: [opcode] [dst:1] [src:1]
	a.movzx(ecx, byte_ptr(rsi));       // dst vreg
	a.movzx(edx, byte_ptr(rsi, 1));    // src vreg
	emit_poly_advance_ip(a, 2);
	emit_poly_index_to_offset(a, rcx);
	emit_poly_index_to_offset(a, rdx);
	a.mov(rax, qword_ptr(rbx, rdx));
	a.mov(qword_ptr(rbx, rcx), rax);
	emit_chain_dispatch(a, labels);
}

void vm_dispatcher::emit_mov_reg_mem_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_MOV_REG_MEM)]);
	emit_handler_entry_junk(a);
	// Format: [opcode] [dst:1] [base:1] [disp:4] [size:1]
	a.movzx(ecx, byte_ptr(rsi));       // dst vreg
	a.movzx(edx, byte_ptr(rsi, 1));    // base vreg (0xFF = no base)
	a.movsxd(r8, dword_ptr(rsi, 2));   // displacement
	a.movzx(r9d, byte_ptr(rsi, 6));    // access size
	emit_poly_advance_ip(a, 7);

	// Compute address: base_val + disp
	a.cmp(dl, 0xFF);
	Label has_base = a.newLabel();
	Label addr_ready = a.newLabel();
	a.jne(has_base);
	a.mov(rax, r8);                    // no base, addr = disp only
	a.jmp(addr_ready);
	a.bind(has_base);
	a.shl(rdx, 3);
	a.mov(rax, qword_ptr(rbx, rdx));  // base value
	a.add(rax, r8);                    // + disp
	a.bind(addr_ready);

	// Load from [rax] with appropriate size
	Label sz8 = a.newLabel(), sz4 = a.newLabel(), sz2 = a.newLabel(), sz1 = a.newLabel(), done = a.newLabel();
	a.cmp(r9b, 8);
	a.je(sz8);
	a.cmp(r9b, 4);
	a.je(sz4);
	a.cmp(r9b, 2);
	a.je(sz2);
	a.bind(sz1);
	a.movzx(eax, byte_ptr(rax));
	a.jmp(done);
	a.bind(sz2);
	a.movzx(eax, word_ptr(rax));
	a.jmp(done);
	a.bind(sz4);
	a.mov(eax, dword_ptr(rax));
	a.jmp(done);
	a.bind(sz8);
	a.mov(rax, qword_ptr(rax));
	a.bind(done);

	a.shl(rcx, 3);
	a.mov(qword_ptr(rbx, rcx), rax);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_mov_mem_reg_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_MOV_MEM_REG)]);
	emit_handler_entry_junk(a);
	// Format: [opcode] [base:1] [disp:4] [src:1] [size:1]
	a.movzx(ecx, byte_ptr(rsi));       // base vreg
	a.movsxd(rdx, dword_ptr(rsi, 1));  // displacement
	a.movzx(r8d, byte_ptr(rsi, 5));    // src vreg
	a.movzx(r9d, byte_ptr(rsi, 6));    // size
	emit_poly_advance_ip(a, 7);

	// Compute dest address
	Label has_base = a.newLabel(), addr_ready = a.newLabel();
	a.cmp(cl, 0xFF);
	a.jne(has_base);
	a.mov(rdi, rdx);
	a.jmp(addr_ready);
	a.bind(has_base);
	a.shl(rcx, 3);
	a.mov(rdi, qword_ptr(rbx, rcx));
	a.add(rdi, rdx);
	a.bind(addr_ready);

	// Get source value
	a.shl(r8, 3);
	a.mov(rax, qword_ptr(rbx, r8));

	// Store with appropriate size
	Label sz8 = a.newLabel(), sz4 = a.newLabel(), sz2 = a.newLabel(), sz1 = a.newLabel(), done = a.newLabel();
	a.cmp(r9b, 8);
	a.je(sz8);
	a.cmp(r9b, 4);
	a.je(sz4);
	a.cmp(r9b, 2);
	a.je(sz2);
	a.bind(sz1);
	a.mov(byte_ptr(rdi), al);
	a.jmp(done);
	a.bind(sz2);
	a.mov(word_ptr(rdi), ax);
	a.jmp(done);
	a.bind(sz4);
	a.mov(dword_ptr(rdi), eax);
	a.jmp(done);
	a.bind(sz8);
	a.mov(qword_ptr(rdi), rax);
	a.bind(done);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_alu_reg_reg_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);
	emit_handler_entry_junk(a);
	// Format: [opcode] [dst:1] [src:1] [size:1]
	a.movzx(ecx, byte_ptr(rsi));
	a.movzx(edx, byte_ptr(rsi, 1));
	a.movzx(r9d, byte_ptr(rsi, 2));
	emit_poly_advance_ip(a, 3);

	emit_poly_index_to_offset(a, rcx);
	emit_poly_index_to_offset(a, rdx);
	a.mov(rax, qword_ptr(rbx, rcx));  // dst value
	a.mov(r8, qword_ptr(rbx, rdx));   // src value

	// Check if MBA substitution should be used
	bool use_mba = settings && settings->mba_pct > 0 && ((opaque_rng() % 100) < settings->mba_pct);

	Label do32 = a.newLabel(), do_op = a.newLabel();
	a.cmp(r9b, 4);
	a.je(do32);

	if (use_mba) {
		// 64-bit MBA path: compute result via MBA, then compute flags via real op
		a.push(rax);    // save original x
		a.push(r8);     // save original y
		// MBA computes result in rax from (rax, r8)
		switch (op) {
		case vm_op::VM_ADD_REG_REG: mba.emit_mba_add_64(a); break;
		case vm_op::VM_SUB_REG_REG: mba.emit_mba_sub_64(a); break;
		case vm_op::VM_XOR_REG_REG: mba.emit_mba_xor_64(a); break;
		case vm_op::VM_AND_REG_REG: mba.emit_mba_and_64(a); break;
		case vm_op::VM_OR_REG_REG:  mba.emit_mba_or_64(a); break;
		default: break;
		}
		a.mov(rdx, rax);  // save MBA result
		a.pop(r8);        // restore y
		a.pop(rax);       // restore x
		// Real op just for flags
		switch (op) {
		case vm_op::VM_ADD_REG_REG: a.add(rax, r8); break;
		case vm_op::VM_SUB_REG_REG: a.sub(rax, r8); break;
		case vm_op::VM_XOR_REG_REG: a.xor_(rax, r8); break;
		case vm_op::VM_AND_REG_REG: a.and_(rax, r8); break;
		case vm_op::VM_OR_REG_REG:  a.or_(rax, r8); break;
		default: break;
		}
		a.pushfq();       // capture real flags
		a.mov(rax, rdx);  // use MBA result as actual value
	} else {
		// Plain 64-bit path
		switch (op) {
		case vm_op::VM_ADD_REG_REG: a.add(rax, r8); break;
		case vm_op::VM_SUB_REG_REG: a.sub(rax, r8); break;
		case vm_op::VM_XOR_REG_REG: a.xor_(rax, r8); break;
		case vm_op::VM_AND_REG_REG: a.and_(rax, r8); break;
		case vm_op::VM_OR_REG_REG:  a.or_(rax, r8); break;
		default: break;
		}
		a.pushfq();
	}
	a.jmp(do_op);

	a.bind(do32);
	if (use_mba) {
		// 32-bit MBA path
		a.push(rax);
		a.push(r8);
		switch (op) {
		case vm_op::VM_ADD_REG_REG: mba.emit_mba_add_32(a); break;
		case vm_op::VM_SUB_REG_REG: mba.emit_mba_sub_32(a); break;
		case vm_op::VM_XOR_REG_REG: mba.emit_mba_xor_32(a); break;
		case vm_op::VM_AND_REG_REG: mba.emit_mba_and_32(a); break;
		case vm_op::VM_OR_REG_REG:  mba.emit_mba_or_32(a); break;
		default: break;
		}
		a.mov(edx, eax);
		a.pop(r8);
		a.pop(rax);
		switch (op) {
		case vm_op::VM_ADD_REG_REG: a.add(eax, r8d); break;
		case vm_op::VM_SUB_REG_REG: a.sub(eax, r8d); break;
		case vm_op::VM_XOR_REG_REG: a.xor_(eax, r8d); break;
		case vm_op::VM_AND_REG_REG: a.and_(eax, r8d); break;
		case vm_op::VM_OR_REG_REG:  a.or_(eax, r8d); break;
		default: break;
		}
		a.pushfq();
		a.mov(eax, edx);
	} else {
		switch (op) {
		case vm_op::VM_ADD_REG_REG: a.add(eax, r8d); break;
		case vm_op::VM_SUB_REG_REG: a.sub(eax, r8d); break;
		case vm_op::VM_XOR_REG_REG: a.xor_(eax, r8d); break;
		case vm_op::VM_AND_REG_REG: a.and_(eax, r8d); break;
		case vm_op::VM_OR_REG_REG:  a.or_(eax, r8d); break;
		default: break;
		}
		a.pushfq();
	}
	a.bind(do_op);

	// Save flags (already pushed by pushfq above)
	a.pop(r9);
	a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);

	a.mov(qword_ptr(rbx, rcx), rax);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_alu_reg_imm_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);
	emit_handler_entry_junk(a);
	// Format: [opcode] [dst:1] [imm32:4] [size:1]
	a.movzx(ecx, byte_ptr(rsi));
	a.movsxd(rdx, dword_ptr(rsi, 1));
	a.movzx(r9d, byte_ptr(rsi, 5));
	emit_poly_advance_ip(a, 6);

	emit_poly_index_to_offset(a, rcx);
	a.mov(rax, qword_ptr(rbx, rcx));

	bool use_mba_imm = settings && settings->mba_pct > 0 && ((opaque_rng() % 100) < settings->mba_pct);

	// Move immediate to r8 for MBA compatibility
	a.mov(r8, rdx);

	Label do32 = a.newLabel(), do_op = a.newLabel();
	a.cmp(r9b, 4);
	a.je(do32);

	if (use_mba_imm) {
		a.push(rax);
		a.push(r8);
		switch (op) {
		case vm_op::VM_ADD_REG_IMM: mba.emit_mba_add_64(a); break;
		case vm_op::VM_SUB_REG_IMM: mba.emit_mba_sub_64(a); break;
		case vm_op::VM_XOR_REG_IMM: mba.emit_mba_xor_64(a); break;
		case vm_op::VM_AND_REG_IMM: mba.emit_mba_and_64(a); break;
		case vm_op::VM_OR_REG_IMM:  mba.emit_mba_or_64(a); break;
		default: break;
		}
		a.mov(rdx, rax);
		a.pop(r8);
		a.pop(rax);
		switch (op) {
		case vm_op::VM_ADD_REG_IMM: a.add(rax, r8); break;
		case vm_op::VM_SUB_REG_IMM: a.sub(rax, r8); break;
		case vm_op::VM_XOR_REG_IMM: a.xor_(rax, r8); break;
		case vm_op::VM_AND_REG_IMM: a.and_(rax, r8); break;
		case vm_op::VM_OR_REG_IMM:  a.or_(rax, r8); break;
		default: break;
		}
		a.pushfq();
		a.mov(rax, rdx);
	} else {
		switch (op) {
		case vm_op::VM_ADD_REG_IMM: a.add(rax, r8); break;
		case vm_op::VM_SUB_REG_IMM: a.sub(rax, r8); break;
		case vm_op::VM_XOR_REG_IMM: a.xor_(rax, r8); break;
		case vm_op::VM_AND_REG_IMM: a.and_(rax, r8); break;
		case vm_op::VM_OR_REG_IMM:  a.or_(rax, r8); break;
		default: break;
		}
		a.pushfq();
	}
	a.jmp(do_op);

	a.bind(do32);
	if (use_mba_imm) {
		a.push(rax);
		a.push(r8);
		switch (op) {
		case vm_op::VM_ADD_REG_IMM: mba.emit_mba_add_32(a); break;
		case vm_op::VM_SUB_REG_IMM: mba.emit_mba_sub_32(a); break;
		case vm_op::VM_XOR_REG_IMM: mba.emit_mba_xor_32(a); break;
		case vm_op::VM_AND_REG_IMM: mba.emit_mba_and_32(a); break;
		case vm_op::VM_OR_REG_IMM:  mba.emit_mba_or_32(a); break;
		default: break;
		}
		a.mov(edx, eax);
		a.pop(r8);
		a.pop(rax);
		switch (op) {
		case vm_op::VM_ADD_REG_IMM: a.add(eax, r8d); break;
		case vm_op::VM_SUB_REG_IMM: a.sub(eax, r8d); break;
		case vm_op::VM_XOR_REG_IMM: a.xor_(eax, r8d); break;
		case vm_op::VM_AND_REG_IMM: a.and_(eax, r8d); break;
		case vm_op::VM_OR_REG_IMM:  a.or_(eax, r8d); break;
		default: break;
		}
		a.pushfq();
		a.mov(eax, edx);
	} else {
		switch (op) {
		case vm_op::VM_ADD_REG_IMM: a.add(eax, r8d); break;
		case vm_op::VM_SUB_REG_IMM: a.sub(eax, r8d); break;
		case vm_op::VM_XOR_REG_IMM: a.xor_(eax, r8d); break;
		case vm_op::VM_AND_REG_IMM: a.and_(eax, r8d); break;
		case vm_op::VM_OR_REG_IMM:  a.or_(eax, r8d); break;
		default: break;
		}
		a.pushfq();
	}
	a.bind(do_op);

	a.pop(r9);
	a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);

	a.mov(qword_ptr(rbx, rcx), rax);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_not_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_NOT_REG)]);
	emit_handler_entry_junk(a);
	a.movzx(ecx, byte_ptr(rsi));
	emit_poly_advance_ip(a, 1);
	emit_poly_index_to_offset(a, rcx);
	a.mov(rax, qword_ptr(rbx, rcx));
	a.not_(rax);
	a.mov(qword_ptr(rbx, rcx), rax);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_neg_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_NEG_REG)]);
	emit_handler_entry_junk(a);
	a.movzx(ecx, byte_ptr(rsi));
	emit_poly_advance_ip(a, 1);
	emit_poly_index_to_offset(a, rcx);
	a.mov(rax, qword_ptr(rbx, rcx));
	a.neg(rax);
	a.pushfq();
	a.pop(r9);
	a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
	a.mov(qword_ptr(rbx, rcx), rax);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_shl_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_SHL_REG_IMM)]);
	emit_handler_entry_junk(a);
	// Format: [opcode] [vreg:1] [imm8:1]
	a.movzx(ecx, byte_ptr(rsi));
	a.movzx(edx, byte_ptr(rsi, 1));
	emit_poly_advance_ip(a, 2);
	emit_poly_index_to_offset(a, rcx);
	a.mov(rax, qword_ptr(rbx, rcx));
	// SHL needs count in CL, but we're using RCX for offset
	a.push(rcx);
	a.mov(ecx, edx);
	a.shl(rax, cl);
	a.pop(rcx);
	a.pushfq();
	a.pop(r9);
	a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
	a.mov(qword_ptr(rbx, rcx), rax);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_shr_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_SHR_REG_IMM)]);
	emit_handler_entry_junk(a);
	a.movzx(ecx, byte_ptr(rsi));
	a.movzx(edx, byte_ptr(rsi, 1));
	emit_poly_advance_ip(a, 2);
	emit_poly_index_to_offset(a, rcx);
	a.mov(rax, qword_ptr(rbx, rcx));
	a.push(rcx);
	a.mov(ecx, edx);
	a.shr(rax, cl);
	a.pop(rcx);
	a.pushfq();
	a.pop(r9);
	a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
	a.mov(qword_ptr(rbx, rcx), rax);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_cmp_reg_reg_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_CMP_REG_REG)]);
	emit_handler_entry_junk(a);
	// Format: [opcode] [reg1:1] [reg2:1] [size:1]
	a.movzx(ecx, byte_ptr(rsi));
	a.movzx(edx, byte_ptr(rsi, 1));
	a.movzx(r9d, byte_ptr(rsi, 2));
	emit_poly_advance_ip(a, 3);
	emit_poly_index_to_offset(a, rcx);
	emit_poly_index_to_offset(a, rdx);
	a.mov(rax, qword_ptr(rbx, rcx));
	a.mov(r8, qword_ptr(rbx, rdx));
	Label cmp32 = a.newLabel(), done = a.newLabel();
	a.cmp(r9b, 4);
	a.je(cmp32);
	a.cmp(rax, r8);
	a.jmp(done);
	a.bind(cmp32);
	a.cmp(eax, r8d);
	a.bind(done);
	a.pushfq();
	a.pop(r9);
	a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_cmp_reg_imm_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_CMP_REG_IMM)]);
	emit_handler_entry_junk(a);
	// Format: [opcode] [reg:1] [imm32:4] [size:1]
	a.movzx(ecx, byte_ptr(rsi));
	a.movsxd(rdx, dword_ptr(rsi, 1));
	a.movzx(r9d, byte_ptr(rsi, 5));
	emit_poly_advance_ip(a, 6);
	emit_poly_index_to_offset(a, rcx);
	a.mov(rax, qword_ptr(rbx, rcx));
	Label cmp32 = a.newLabel(), done = a.newLabel();
	a.cmp(r9b, 4);
	a.je(cmp32);
	a.cmp(rax, rdx);
	a.jmp(done);
	a.bind(cmp32);
	a.cmp(eax, edx);
	a.bind(done);
	a.pushfq();
	a.pop(r9);
	a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_test_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_TEST_REG_REG)]);
	emit_handler_entry_junk(a);
	a.movzx(ecx, byte_ptr(rsi));
	a.movzx(edx, byte_ptr(rsi, 1));
	emit_poly_advance_ip(a, 2);
	emit_poly_index_to_offset(a, rcx);
	emit_poly_index_to_offset(a, rdx);
	a.mov(rax, qword_ptr(rbx, rcx));
	a.mov(r8, qword_ptr(rbx, rdx));
	a.test(rax, r8);
	a.pushfq();
	a.pop(r9);
	a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_jmp_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_JMP)]);
	emit_handler_entry_junk(a);
	// Format: [opcode] [offset:4] — signed offset relative to current IP
	a.movsxd(rax, dword_ptr(rsi));
	emit_poly_advance_ip(a, 4);
	a.add(rsi, rax);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_jcc_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);
	emit_handler_entry_junk(a);
	// Format: [opcode] [offset:4]
	a.movsxd(rax, dword_ptr(rsi));
	emit_poly_advance_ip(a, 4);

	// Restore RFLAGS from VM context to check condition
	a.push(qword_ptr(rbx, VRFLAGS_OFF));
	a.popfq();

	Label taken = a.newLabel();
	Label not_taken = a.newLabel();

	switch (op) {
	case vm_op::VM_JZ:  a.jz(taken); break;
	case vm_op::VM_JNZ: a.jnz(taken); break;
	case vm_op::VM_JL:  a.jl(taken); break;
	case vm_op::VM_JLE: a.jle(taken); break;
	case vm_op::VM_JG:  a.jg(taken); break;
	case vm_op::VM_JGE: a.jge(taken); break;
	case vm_op::VM_JB:  a.jb(taken); break;
	case vm_op::VM_JBE: a.jbe(taken); break;
	case vm_op::VM_JA:  a.ja(taken); break;
	case vm_op::VM_JAE: a.jae(taken); break;
	case vm_op::VM_JS:  a.js(taken); break;
	case vm_op::VM_JNS: a.jns(taken); break;
	case vm_op::VM_JP:  a.jp(taken); break;
	case vm_op::VM_JNP: a.jnp(taken); break;
	default: break;
	}

	a.jmp(labels.dispatch_loop); // not taken

	a.bind(taken);
	a.add(rsi, rax);  // apply offset
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_push_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_PUSH_REG)]);
	emit_handler_entry_junk(a);
	a.movzx(ecx, byte_ptr(rsi));
	emit_poly_advance_ip(a, 1);
	emit_poly_index_to_offset(a, rcx);
	a.mov(rax, qword_ptr(rbx, rcx));
	a.push(rax);
	emit_chain_dispatch(a, labels);
}

void vm_dispatcher::emit_pop_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_POP_REG)]);
	emit_handler_entry_junk(a);
	a.movzx(ecx, byte_ptr(rsi));
	emit_poly_advance_ip(a, 1);
	emit_poly_index_to_offset(a, rcx);
	a.pop(rax);
	a.mov(qword_ptr(rbx, rcx), rax);
	emit_chain_dispatch(a, labels);
}

void vm_dispatcher::emit_call_native_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_CALL_NATIVE)]);
	emit_handler_entry_junk(a);
	// Format: [opcode] [addr:8]
	a.mov(rax, qword_ptr(rsi));
	a.xor_(rax, r12);
	emit_poly_advance_ip(a, 8);

	// Save VM state (RSI, RBX are callee-saved or we save them)
	a.push(rsi);
	a.push(rbx);

	// Set up native registers from VM context for the call (Windows x64 ABI)
	a.mov(rcx, qword_ptr(rbx, table.perm_gp_off(vm_reg::VRCX)));
	a.mov(rdx, qword_ptr(rbx, table.perm_gp_off(vm_reg::VRDX)));
	a.mov(r8, qword_ptr(rbx, table.perm_gp_off(vm_reg::VR8)));
	a.mov(r9, qword_ptr(rbx, table.perm_gp_off(vm_reg::VR9)));

	// Shadow space (32 bytes)
	a.sub(rsp, 32);
	a.call(rax);
	a.add(rsp, 32);

	// Restore VM state
	a.pop(rbx);
	a.pop(rsi);

	// Save return value
	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VRAX)), rax);

	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_relocate_reg_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_RELOCATE_REG)]);
	emit_handler_entry_junk(a);
	// Format: [opcode] [reg:1]
	// reg[operand] += R14 (runtime image base)
	a.movzx(ecx, byte_ptr(rsi));
	emit_poly_advance_ip(a, 1);
	emit_poly_index_to_offset(a, rcx);
	a.add(qword_ptr(rbx, rcx), r14);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_call_native_reloc_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_CALL_NATIVE_RELOC)]);
	emit_handler_entry_junk(a);
	// Format: [opcode] [rva:8] (encrypted)
	// target = (rva ^ R12) + R14
	a.mov(rax, qword_ptr(rsi));
	a.xor_(rax, r12);
	a.add(rax, r14);
	emit_poly_advance_ip(a, 8);

	a.push(rsi);
	a.push(rbx);

	a.mov(rcx, qword_ptr(rbx, table.perm_gp_off(vm_reg::VRCX)));
	a.mov(rdx, qword_ptr(rbx, table.perm_gp_off(vm_reg::VRDX)));
	a.mov(r8, qword_ptr(rbx, table.perm_gp_off(vm_reg::VR8)));
	a.mov(r9, qword_ptr(rbx, table.perm_gp_off(vm_reg::VR9)));

	a.sub(rsp, 32);
	a.call(rax);
	a.add(rsp, 32);

	a.pop(rbx);
	a.pop(rsi);

	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VRAX)), rax);

	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_call_import_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_CALL_IMPORT)]);
	// Format: [opcode] [dll_hash:4] [func_hash:4]
	// PEB-walk to resolve import by hash, then call

	a.mov(ecx, dword_ptr(rsi));       // ECX = dll_hash
	a.mov(edx, dword_ptr(rsi, 4));    // EDX = func_hash
	a.add(rsi, 8);

	a.push(rsi);   // save VM IP
	a.push(rbx);   // save VM reg file base
	a.push(rcx);   // dll_hash
	a.push(rdx);   // func_hash
	// Stack: [func_hash] [dll_hash] [rbx] [rsi]

	// --- PEB walk: find module by dll_hash ---
	{
		x86::Mem peb_ptr = x86::ptr(0x60);
		peb_ptr.setSegment(x86::SReg::kIdGs);
		a.mov(rax, peb_ptr);
	}
	a.mov(rax, qword_ptr(rax, 0x18));   // PEB_LDR_DATA
	a.mov(r8, qword_ptr(rax, 0x10));    // InLoadOrderModuleList.Flink
	a.mov(r9, r8);                       // list head sentinel

	Label module_loop = a.newLabel();
	Label module_next = a.newLabel();
	Label module_found = a.newLabel();
	Label not_found = a.newLabel();
	Label do_call = a.newLabel();

	a.bind(module_loop);
	a.movzx(eax, word_ptr(r8, 0x58));   // BaseDllName.Length (bytes)
	a.test(eax, eax);
	a.jz(module_next);

	a.mov(rdi, qword_ptr(r8, 0x60));    // BaseDllName.Buffer (PWSTR)

	// Hash DLL name: FNV-1a, wide chars, case-insensitive
	a.mov(r10d, 0x811C9DC5);
	a.shr(eax, 1);                       // char count
	a.mov(r11d, eax);

	Label hash_dll_loop = a.newLabel();
	Label hash_dll_done = a.newLabel();
	a.bind(hash_dll_loop);
	a.test(r11d, r11d);
	a.jz(hash_dll_done);
	a.movzx(eax, word_ptr(rdi));
	a.add(rdi, 2);
	Label dll_not_upper = a.newLabel();
	a.cmp(al, 0x41);
	a.jb(dll_not_upper);
	a.cmp(al, 0x5A);
	a.ja(dll_not_upper);
	a.add(al, 0x20);
	a.bind(dll_not_upper);
	a.xor_(r10d, eax);
	a.imul(r10d, r10d, 0x01000193);
	a.dec(r11d);
	a.jmp(hash_dll_loop);

	a.bind(hash_dll_done);
	a.cmp(r10d, dword_ptr(rsp, 8));      // compare with dll_hash
	a.je(module_found);

	a.bind(module_next);
	a.mov(r8, qword_ptr(r8));            // Flink
	a.cmp(r8, r9);
	a.jne(module_loop);

	a.bind(not_found);
	a.xor_(eax, eax);
	a.jmp(do_call);

	// --- Module found: walk export table for func_hash ---
	a.bind(module_found);
	a.mov(rdi, qword_ptr(r8, 0x30));     // DllBase

	a.mov(eax, dword_ptr(rdi, 0x3C));    // e_lfanew
	a.add(rax, rdi);
	a.mov(eax, dword_ptr(rax, 0x88));    // ExportDir VirtualAddress
	a.test(eax, eax);
	a.jz(not_found);
	a.lea(r15, qword_ptr(rdi, rax));      // R15 = export directory

	a.mov(r10d, dword_ptr(r15, 0x18));   // NumberOfNames
	a.mov(r11d, dword_ptr(r15, 0x20));   // AddressOfNames RVA
	a.add(r11, rdi);

	Label export_loop = a.newLabel();
	Label export_found = a.newLabel();

	a.xor_(ecx, ecx);                    // ECX = name index

	a.bind(export_loop);
	a.cmp(ecx, r10d);
	a.jge(not_found);

	a.mov(eax, dword_ptr(r11, rcx, 2)); // name RVA (shift=2 → scale=4)
	a.add(rax, rdi);                      // RAX = name string ptr

	// Hash function name: FNV-1a, ASCII, case-insensitive
	a.push(rcx);                          // save index
	// Stack: [idx] [func_hash] [dll_hash] [rbx] [rsi]
	a.mov(r8d, 0x811C9DC5);              // R8D = hash (R8/R9 free now, module loop done)

	Label hash_fn_loop = a.newLabel();
	Label hash_fn_done = a.newLabel();
	a.bind(hash_fn_loop);
	a.movzx(ecx, byte_ptr(rax));
	a.test(cl, cl);
	a.jz(hash_fn_done);
	Label fn_not_upper = a.newLabel();
	a.cmp(cl, 0x41);
	a.jb(fn_not_upper);
	a.cmp(cl, 0x5A);
	a.ja(fn_not_upper);
	a.add(cl, 0x20);
	a.bind(fn_not_upper);
	a.xor_(r8d, ecx);
	a.imul(r8d, r8d, 0x01000193);
	a.inc(rax);
	a.jmp(hash_fn_loop);

	a.bind(hash_fn_done);
	a.pop(rcx);                           // restore index
	// Stack: [func_hash] [dll_hash] [rbx] [rsi]

	a.cmp(r8d, dword_ptr(rsp));           // compare with func_hash
	a.je(export_found);

	a.inc(ecx);
	a.jmp(export_loop);

	// --- Resolve function address ---
	a.bind(export_found);
	a.mov(r10d, dword_ptr(r15, 0x24));   // AddressOfNameOrdinals RVA
	a.add(r10, rdi);
	a.movzx(ecx, word_ptr(r10, rcx, 1)); // ordinal (shift=1 → scale=2)
	a.mov(r10d, dword_ptr(r15, 0x1C));   // AddressOfFunctions RVA
	a.add(r10, rdi);
	a.mov(eax, dword_ptr(r10, rcx, 2));  // function RVA (shift=2 → scale=4)
	a.add(rax, rdi);                      // RAX = resolved address

	// --- Call resolved function ---
	a.bind(do_call);
	// Stack: [func_hash] [dll_hash] [rbx] [rsi]
	a.add(rsp, 16);                       // discard hashes
	// Stack: [rbx] [rsi]

	a.push(rax);                          // save target
	// Stack: [target] [rbx] [rsi]
	a.mov(r10, qword_ptr(rsp, 8));       // R10 = RBX (VM reg file)
	a.mov(rcx, qword_ptr(r10, table.perm_gp_off(vm_reg::VRCX)));
	a.mov(rdx, qword_ptr(r10, table.perm_gp_off(vm_reg::VRDX)));
	a.mov(r8, qword_ptr(r10, table.perm_gp_off(vm_reg::VR8)));
	a.mov(r9, qword_ptr(r10, table.perm_gp_off(vm_reg::VR9)));
	a.pop(rax);                           // restore target
	// Stack: [rbx] [rsi]

	a.sub(rsp, 32);
	a.call(rax);
	a.add(rsp, 32);

	a.pop(rbx);
	a.pop(rsi);

	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VRAX)), rax);

	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_nest_enter_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_NEST_ENTER)]);
	emit_handler_entry_junk(a);
	// Format: [opcode:2] [inner_blob_offset:4]
	// inner_blob_offset is relative to R13 (outer bytecode base)
	// Inner blob layout: [inner_disp_size:4] [inner_disp_code] [inner_bytecode]
	a.movsxd(rax, dword_ptr(rsi));
	emit_poly_advance_ip(a, 4);

	// Save outer VM state
	a.push(rsi);   // outer VM IP (resume point)
	a.push(r12);   // outer XOR key
	a.push(r13);   // outer bytecode base

	// RDI = inner blob start
	a.lea(rdi, qword_ptr(r13, rax));

	// Read inner dispatcher size from blob header
	a.mov(ecx, dword_ptr(rdi));  // inner_disp_size

	// RSI = inner bytecode = blob + 4 + inner_disp_size
	a.lea(rsi, qword_ptr(rdi, 4));
	a.add(rsi, rcx);

	// Inner dispatcher entry = blob + 4
	a.lea(rax, qword_ptr(rdi, 4));

	// Call inner dispatcher (it sets up its own R12/R13, dispatches, then ret's)
	a.call(rax);

	// Restore outer VM state
	a.pop(r13);
	a.pop(r12);
	a.pop(rsi);

	emit_chain_dispatch(a, labels);
}

void vm_dispatcher::emit_lea_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_LEA_REG)]);
	emit_handler_entry_junk(a);
	// Format: [opcode] [dst:1] [base:1] [disp:4]
	a.movzx(ecx, byte_ptr(rsi));
	a.movzx(edx, byte_ptr(rsi, 1));
	a.movsxd(r8, dword_ptr(rsi, 2));
	emit_poly_advance_ip(a, 6);

	Label has_base = a.newLabel(), done = a.newLabel();
	a.cmp(dl, 0xFF);
	a.jne(has_base);
	a.mov(rax, r8);
	a.jmp(done);
	a.bind(has_base);
	emit_poly_index_to_offset(a, rdx);
	a.mov(rax, qword_ptr(rbx, rdx));
	a.add(rax, r8);
	a.bind(done);

	emit_poly_index_to_offset(a, rcx);
	a.mov(qword_ptr(rbx, rcx), rax);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_imul_reg_reg_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_IMUL_REG_REG)]);
	emit_handler_entry_junk(a);
	a.movzx(ecx, byte_ptr(rsi));
	a.movzx(edx, byte_ptr(rsi, 1));
	// skip size byte at rsi+2
	emit_poly_advance_ip(a, 3);
	emit_poly_index_to_offset(a, rcx);
	emit_poly_index_to_offset(a, rdx);
	a.mov(rax, qword_ptr(rbx, rcx));
	a.mov(r8, qword_ptr(rbx, rdx));
	a.imul(rax, r8);
	a.pushfq();
	a.pop(r9);
	a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
	a.mov(qword_ptr(rbx, rcx), rax);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_mul_reg_imm_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_MUL_REG_IMM)]);
	emit_handler_entry_junk(a);
	// Format: [opcode] [vreg:1] [imm32:4]
	a.movzx(ecx, byte_ptr(rsi));
	a.movsxd(rdx, dword_ptr(rsi, 1));
	emit_poly_advance_ip(a, 5);
	emit_poly_index_to_offset(a, rcx);
	a.mov(rax, qword_ptr(rbx, rcx));
	a.imul(rax, rdx);
	a.pushfq();
	a.pop(r9);
	a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
	a.mov(qword_ptr(rbx, rcx), rax);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_cdq_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_CDQ)]);
	emit_handler_entry_junk(a);
	// CDQ: sign-extend EAX into EDX:EAX
	a.mov(eax, dword_ptr(rbx, table.perm_gp_off(vm_reg::VRAX)));
	a.cdq();
	a.mov(dword_ptr(rbx, table.perm_gp_off(vm_reg::VRAX)), eax);
	a.mov(dword_ptr(rbx, table.perm_gp_off(vm_reg::VRDX)), edx);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_cqo_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_CQO)]);
	emit_handler_entry_junk(a);
	// CQO: sign-extend RAX into RDX:RAX
	a.mov(rax, qword_ptr(rbx, table.perm_gp_off(vm_reg::VRAX)));
	a.cqo();
	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VRAX)), rax);
	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VRDX)), rdx);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_div_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);
	emit_handler_entry_junk(a);
	// Format: [opcode] [vreg:1]
	a.movzx(ecx, byte_ptr(rsi));
	emit_poly_advance_ip(a, 1);

	// Load RDX:RAX from VM context
	a.mov(rax, qword_ptr(rbx, table.perm_gp_off(vm_reg::VRAX)));
	a.mov(rdx, qword_ptr(rbx, table.perm_gp_off(vm_reg::VRDX)));

	// Load divisor
	emit_poly_index_to_offset(a, rcx);
	a.mov(r8, qword_ptr(rbx, rcx));

	// Perform division
	if (op == vm_op::VM_IDIV_REG)
		a.idiv(r8);
	else
		a.div(r8);

	// Store results: RAX=quotient, RDX=remainder
	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VRAX)), rax);
	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VRDX)), rdx);
	a.pushfq();
	a.pop(r9);
	a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_cmov_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);
	emit_handler_entry_junk(a);
	// Format: [opcode] [dst:1] [src:1]
	a.movzx(ecx, byte_ptr(rsi));
	a.movzx(edx, byte_ptr(rsi, 1));
	emit_poly_advance_ip(a, 2);

	emit_poly_index_to_offset(a, rcx);
	emit_poly_index_to_offset(a, rdx);
	a.mov(rax, qword_ptr(rbx, rcx));  // dst value
	a.mov(r8, qword_ptr(rbx, rdx));   // src value

	// Restore flags
	a.push(qword_ptr(rbx, VRFLAGS_OFF));
	a.popfq();

	Label skip = a.newLabel();
	switch (op) {
	case vm_op::VM_CMOVZ_REG_REG:  a.jnz(skip); break;
	case vm_op::VM_CMOVNZ_REG_REG: a.jz(skip); break;
	case vm_op::VM_CMOVL_REG_REG:  a.jnl(skip); break;
	case vm_op::VM_CMOVLE_REG_REG: a.jnle(skip); break;
	case vm_op::VM_CMOVG_REG_REG:  a.jle(skip); break;
	case vm_op::VM_CMOVGE_REG_REG: a.jl(skip); break;
	case vm_op::VM_CMOVB_REG_REG:  a.jnb(skip); break;
	case vm_op::VM_CMOVBE_REG_REG: a.jnbe(skip); break;
	case vm_op::VM_CMOVA_REG_REG:  a.jbe(skip); break;
	case vm_op::VM_CMOVAE_REG_REG: a.jb(skip); break;
	case vm_op::VM_CMOVS_REG_REG:  a.jns(skip); break;
	case vm_op::VM_CMOVNS_REG_REG: a.js(skip); break;
	case vm_op::VM_CMOVP_REG_REG:  a.jnp(skip); break;
	case vm_op::VM_CMOVNP_REG_REG: a.jp(skip); break;
	default: break;
	}
	a.mov(rax, r8); // condition met: dst = src
	a.bind(skip);
	a.mov(qword_ptr(rbx, rcx), rax);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_setcc_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);
	emit_handler_entry_junk(a);
	// Format: [opcode] [vreg:1]
	a.movzx(ecx, byte_ptr(rsi));
	emit_poly_advance_ip(a, 1);

	// Restore flags
	a.push(qword_ptr(rbx, VRFLAGS_OFF));
	a.popfq();

	a.xor_(eax, eax); // default 0
	Label skip = a.newLabel();
	switch (op) {
	case vm_op::VM_SETZ_REG:  a.jnz(skip); break;
	case vm_op::VM_SETNZ_REG: a.jz(skip); break;
	case vm_op::VM_SETL_REG:  a.jnl(skip); break;
	case vm_op::VM_SETLE_REG: a.jnle(skip); break;
	case vm_op::VM_SETG_REG:  a.jle(skip); break;
	case vm_op::VM_SETGE_REG: a.jl(skip); break;
	case vm_op::VM_SETB_REG:  a.jnb(skip); break;
	case vm_op::VM_SETBE_REG: a.jnbe(skip); break;
	case vm_op::VM_SETA_REG:  a.jbe(skip); break;
	case vm_op::VM_SETAE_REG: a.jb(skip); break;
	case vm_op::VM_SETS_REG:  a.jns(skip); break;
	case vm_op::VM_SETNS_REG: a.js(skip); break;
	case vm_op::VM_SETP_REG:  a.jnp(skip); break;
	case vm_op::VM_SETNP_REG: a.jp(skip); break;
	default: break;
	}
	a.mov(eax, 1); // condition met
	a.bind(skip);
	a.shl(rcx, 3);
	a.mov(qword_ptr(rbx, rcx), rax);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_movzx_mem_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);
	// Format: [opcode] [dst:1] [base:1] [disp:4]
	a.movzx(ecx, byte_ptr(rsi));       // dst vreg
	a.movzx(edx, byte_ptr(rsi, 1));    // base vreg
	a.movsxd(r8, dword_ptr(rsi, 2));   // disp
	a.add(rsi, 6);

	// Compute address
	Label has_base = a.newLabel(), addr_ready = a.newLabel();
	a.cmp(dl, 0xFF);
	a.jne(has_base);
	a.mov(rax, r8);
	a.jmp(addr_ready);
	a.bind(has_base);
	a.shl(rdx, 3);
	a.mov(rax, qword_ptr(rbx, rdx));
	a.add(rax, r8);
	a.bind(addr_ready);

	// Zero-extend load
	if (op == vm_op::VM_MOVZX_REG_MEM8)
		a.movzx(eax, byte_ptr(rax));
	else
		a.movzx(eax, word_ptr(rax));

	a.shl(rcx, 3);
	a.mov(qword_ptr(rbx, rcx), rax);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_movsx_mem_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);
	// Format: [opcode] [dst:1] [base:1] [disp:4]
	a.movzx(ecx, byte_ptr(rsi));
	a.movzx(edx, byte_ptr(rsi, 1));
	a.movsxd(r8, dword_ptr(rsi, 2));
	a.add(rsi, 6);

	Label has_base = a.newLabel(), addr_ready = a.newLabel();
	a.cmp(dl, 0xFF);
	a.jne(has_base);
	a.mov(rax, r8);
	a.jmp(addr_ready);
	a.bind(has_base);
	a.shl(rdx, 3);
	a.mov(rax, qword_ptr(rbx, rdx));
	a.add(rax, r8);
	a.bind(addr_ready);

	// Sign-extend load
	if (op == vm_op::VM_MOVSX_REG_MEM8)
		a.movsx(rax, byte_ptr(rax));
	else if (op == vm_op::VM_MOVSX_REG_MEM16)
		a.movsx(rax, word_ptr(rax));
	else // MOVSXD — 32-bit to 64-bit
		a.movsxd(rax, dword_ptr(rax));

	a.shl(rcx, 3);
	a.mov(qword_ptr(rbx, rcx), rax);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_test_reg_imm_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_TEST_REG_IMM)]);
	emit_handler_entry_junk(a);
	// Format: [opcode] [vreg:1] [imm32:4]
	a.movzx(ecx, byte_ptr(rsi));
	a.movsxd(rdx, dword_ptr(rsi, 1));
	emit_poly_advance_ip(a, 5);
	emit_poly_index_to_offset(a, rcx);
	a.mov(rax, qword_ptr(rbx, rcx));
	a.test(rax, rdx);
	a.pushfq();
	a.pop(r9);
	a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_sar_imm_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_SAR_REG_IMM)]);
	emit_handler_entry_junk(a);
	a.movzx(ecx, byte_ptr(rsi));
	a.movzx(edx, byte_ptr(rsi, 1));
	emit_poly_advance_ip(a, 2);
	a.shl(rcx, 3);
	a.mov(rax, qword_ptr(rbx, rcx));
	a.push(rcx);
	a.mov(ecx, edx);
	a.sar(rax, cl);
	a.pop(rcx);
	a.pushfq();
	a.pop(r9);
	a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
	a.mov(qword_ptr(rbx, rcx), rax);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_shift_cl_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);
	// Format: [opcode] [vreg:1]
	a.movzx(ecx, byte_ptr(rsi));
	a.inc(rsi);
	a.shl(rcx, 3);
	a.mov(rax, qword_ptr(rbx, rcx));
	// Load CL from VRCX
	a.push(rcx);
	a.mov(ecx, dword_ptr(rbx, table.perm_gp_off(vm_reg::VRCX)));
	switch (op) {
	case vm_op::VM_SHL_REG_CL: a.shl(rax, cl); break;
	case vm_op::VM_SHR_REG_CL: a.shr(rax, cl); break;
	case vm_op::VM_SAR_REG_CL: a.sar(rax, cl); break;
	default: break;
	}
	a.pop(rcx);
	a.pushfq();
	a.pop(r9);
	a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
	a.mov(qword_ptr(rbx, rcx), rax);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_mov_reg_sib_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_MOV_REG_SIB)]);
	// Format: [opcode] [dst:1] [base:1] [index:1] [scale:1] [disp:4] [size:1]
	a.movzx(ecx, byte_ptr(rsi));       // dst
	a.movzx(edx, byte_ptr(rsi, 1));    // base
	a.movzx(r8d, byte_ptr(rsi, 2));    // index
	a.movzx(r9d, byte_ptr(rsi, 3));    // scale
	a.movsxd(r10, dword_ptr(rsi, 4));  // disp
	a.movzx(r11d, byte_ptr(rsi, 8));   // size
	a.add(rsi, 9);

	// Compute address: base_val + index_val * scale + disp
	a.xor_(rax, rax);
	Label has_base = a.newLabel(), base_done = a.newLabel();
	a.cmp(dl, 0xFF);
	a.jne(has_base);
	a.jmp(base_done);
	a.bind(has_base);
	a.push(rdx);
	a.shl(rdx, 3);
	a.mov(rax, qword_ptr(rbx, rdx));
	a.pop(rdx);
	a.bind(base_done);

	// index * scale
	a.push(rcx);
	a.shl(r8, 3);
	a.mov(rcx, qword_ptr(rbx, r8));
	a.imul(rcx, r9);  // index_val * scale
	a.add(rax, rcx);
	a.pop(rcx);
	a.add(rax, r10);  // + disp

	// Load from [rax] with size
	Label sz8 = a.newLabel(), sz4 = a.newLabel(), sz2 = a.newLabel(), sz1 = a.newLabel(), done = a.newLabel();
	a.cmp(r11b, 8); a.je(sz8);
	a.cmp(r11b, 4); a.je(sz4);
	a.cmp(r11b, 2); a.je(sz2);
	a.bind(sz1); a.movzx(eax, byte_ptr(rax)); a.jmp(done);
	a.bind(sz2); a.movzx(eax, word_ptr(rax)); a.jmp(done);
	a.bind(sz4); a.mov(eax, dword_ptr(rax)); a.jmp(done);
	a.bind(sz8); a.mov(rax, qword_ptr(rax));
	a.bind(done);

	a.shl(rcx, 3);
	a.mov(qword_ptr(rbx, rcx), rax);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_mov_sib_reg_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_MOV_SIB_REG)]);
	// Format: [opcode] [base:1] [index:1] [scale:1] [disp:4] [src:1] [size:1]
	a.movzx(ecx, byte_ptr(rsi));       // base
	a.movzx(edx, byte_ptr(rsi, 1));    // index
	a.movzx(r8d, byte_ptr(rsi, 2));    // scale
	a.movsxd(r9, dword_ptr(rsi, 3));   // disp
	a.movzx(r10d, byte_ptr(rsi, 7));   // src
	a.movzx(r11d, byte_ptr(rsi, 8));   // size
	a.add(rsi, 9);

	// Compute dest address
	a.xor_(rdi, rdi);
	Label has_base = a.newLabel(), base_done = a.newLabel();
	a.cmp(cl, 0xFF);
	a.jne(has_base);
	a.jmp(base_done);
	a.bind(has_base);
	a.push(rcx);
	a.shl(rcx, 3);
	a.mov(rdi, qword_ptr(rbx, rcx));
	a.pop(rcx);
	a.bind(base_done);

	// index * scale
	a.push(rcx);
	a.shl(rdx, 3);
	a.mov(rcx, qword_ptr(rbx, rdx));
	a.imul(rcx, r8);
	a.add(rdi, rcx);
	a.pop(rcx);
	a.add(rdi, r9); // + disp

	// Get source value
	a.shl(r10, 3);
	a.mov(rax, qword_ptr(rbx, r10));

	// Store with size
	Label sz8 = a.newLabel(), sz4 = a.newLabel(), sz2 = a.newLabel(), sz1 = a.newLabel(), done = a.newLabel();
	a.cmp(r11b, 8); a.je(sz8);
	a.cmp(r11b, 4); a.je(sz4);
	a.cmp(r11b, 2); a.je(sz2);
	a.bind(sz1); a.mov(byte_ptr(rdi), al); a.jmp(done);
	a.bind(sz2); a.mov(word_ptr(rdi), ax); a.jmp(done);
	a.bind(sz4); a.mov(dword_ptr(rdi), eax); a.jmp(done);
	a.bind(sz8); a.mov(qword_ptr(rdi), rax);
	a.bind(done);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_lea_sib_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_LEA_SIB)]);
	// Format: [opcode] [dst:1] [base:1] [index:1] [scale:1] [disp:4]
	a.movzx(ecx, byte_ptr(rsi));       // dst
	a.movzx(edx, byte_ptr(rsi, 1));    // base
	a.movzx(r8d, byte_ptr(rsi, 2));    // index
	a.movzx(r9d, byte_ptr(rsi, 3));    // scale
	a.movsxd(r10, dword_ptr(rsi, 4));  // disp
	a.add(rsi, 8);

	// Compute: base_val + index_val * scale + disp
	a.xor_(rax, rax);
	Label has_base = a.newLabel(), base_done = a.newLabel();
	a.cmp(dl, 0xFF);
	a.jne(has_base);
	a.jmp(base_done);
	a.bind(has_base);
	a.shl(rdx, 3);
	a.mov(rax, qword_ptr(rbx, rdx));
	a.bind(base_done);

	a.shl(r8, 3);
	a.mov(r11, qword_ptr(rbx, r8));
	a.imul(r11, r9);
	a.add(rax, r11);
	a.add(rax, r10);

	a.shl(rcx, 3);
	a.mov(qword_ptr(rbx, rcx), rax);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_adc_reg_reg_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_ADC_REG_REG)]);
	a.movzx(ecx, byte_ptr(rsi));
	a.movzx(edx, byte_ptr(rsi, 1));
	// skip size byte at rsi+2
	a.add(rsi, 3);
	a.shl(rcx, 3);
	a.shl(rdx, 3);
	a.mov(rax, qword_ptr(rbx, rcx));
	a.mov(r8, qword_ptr(rbx, rdx));
	a.push(qword_ptr(rbx, VRFLAGS_OFF));
	a.popfq();
	a.adc(rax, r8);
	a.pushfq();
	a.pop(r9);
	a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
	a.mov(qword_ptr(rbx, rcx), rax);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_adc_reg_imm_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_ADC_REG_IMM)]);
	a.movzx(ecx, byte_ptr(rsi));
	a.movsxd(rdx, dword_ptr(rsi, 1));
	// skip size byte at rsi+5
	a.add(rsi, 6);
	a.shl(rcx, 3);
	a.mov(rax, qword_ptr(rbx, rcx));
	a.push(qword_ptr(rbx, VRFLAGS_OFF));
	a.popfq();
	a.adc(rax, rdx);
	a.pushfq();
	a.pop(r9);
	a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
	a.mov(qword_ptr(rbx, rcx), rax);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_sbb_reg_reg_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_SBB_REG_REG)]);
	a.movzx(ecx, byte_ptr(rsi));
	a.movzx(edx, byte_ptr(rsi, 1));
	// skip size byte at rsi+2
	a.add(rsi, 3);
	a.shl(rcx, 3);
	a.shl(rdx, 3);
	a.mov(rax, qword_ptr(rbx, rcx));
	a.mov(r8, qword_ptr(rbx, rdx));
	a.push(qword_ptr(rbx, VRFLAGS_OFF));
	a.popfq();
	a.sbb(rax, r8);
	a.pushfq();
	a.pop(r9);
	a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
	a.mov(qword_ptr(rbx, rcx), rax);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_sbb_reg_imm_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_SBB_REG_IMM)]);
	a.movzx(ecx, byte_ptr(rsi));
	a.movsxd(rdx, dword_ptr(rsi, 1));
	// skip size byte at rsi+5
	a.add(rsi, 6);
	a.shl(rcx, 3);
	a.mov(rax, qword_ptr(rbx, rcx));
	a.push(qword_ptr(rbx, VRFLAGS_OFF));
	a.popfq();
	a.sbb(rax, rdx);
	a.pushfq();
	a.pop(r9);
	a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
	a.mov(qword_ptr(rbx, rcx), rax);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_xchg_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_XCHG_REG_REG)]);
	a.movzx(ecx, byte_ptr(rsi));
	a.movzx(edx, byte_ptr(rsi, 1));
	a.add(rsi, 2);
	a.shl(rcx, 3);
	a.shl(rdx, 3);
	a.mov(rax, qword_ptr(rbx, rcx));
	a.mov(r8, qword_ptr(rbx, rdx));
	a.mov(qword_ptr(rbx, rcx), r8);
	a.mov(qword_ptr(rbx, rdx), rax);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_leave_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_LEAVE)]);
	// LEAVE = mov rsp, rbp; pop rbp
	a.mov(rax, qword_ptr(rbx, table.perm_gp_off(vm_reg::VRBP)));
	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VRSP)), rax);
	// Pop from [VRSP] into VRBP, increment VRSP
	a.mov(rdi, rax); // rdi = old RSP = RBP value
	a.mov(rax, qword_ptr(rdi));
	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VRBP)), rax);
	a.add(rdi, 8);
	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VRSP)), rdi);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_call_indirect_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_CALL_REG_INDIRECT)]);
	// Format: [opcode] [base:1] [disp:4]
	a.movzx(ecx, byte_ptr(rsi));
	a.movsxd(rdx, dword_ptr(rsi, 1));
	a.add(rsi, 5);

	// Compute address and load target
	Label has_base = a.newLabel(), addr_ready = a.newLabel();
	a.cmp(cl, 0xFF);
	a.jne(has_base);
	a.mov(rax, rdx);
	a.jmp(addr_ready);
	a.bind(has_base);
	a.shl(rcx, 3);
	a.mov(rax, qword_ptr(rbx, rcx));
	a.add(rax, rdx);
	a.bind(addr_ready);
	a.mov(rax, qword_ptr(rax)); // load function pointer from memory

	// Same call sequence as CALL_NATIVE
	a.push(rsi);
	a.push(rbx);
	a.mov(rcx, qword_ptr(rbx, table.perm_gp_off(vm_reg::VRCX)));
	a.mov(rdx, qword_ptr(rbx, table.perm_gp_off(vm_reg::VRDX)));
	a.mov(r8, qword_ptr(rbx, table.perm_gp_off(vm_reg::VR8)));
	a.mov(r9, qword_ptr(rbx, table.perm_gp_off(vm_reg::VR9)));
	a.sub(rsp, 32);
	a.call(rax);
	a.add(rsp, 32);
	a.pop(rbx);
	a.pop(rsi);
	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VRAX)), rax);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_btc_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);

	if (op == vm_op::VM_BTC_REG_IMM) {
		a.movzx(ecx, byte_ptr(rsi));
		a.movzx(edx, byte_ptr(rsi, 1));
		a.add(rsi, 2);
		a.shl(rcx, 3);
		a.mov(rax, qword_ptr(rbx, rcx));
		a.btc(rax, rdx);
	} else {
		a.movzx(ecx, byte_ptr(rsi));
		a.movzx(edx, byte_ptr(rsi, 1));
		a.add(rsi, 2);
		a.shl(rcx, 3);
		a.shl(rdx, 3);
		a.mov(rax, qword_ptr(rbx, rcx));
		a.mov(r8, qword_ptr(rbx, rdx));
		a.btc(rax, r8);
	}

	a.pushfq();
	a.pop(r9);
	a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
	a.mov(qword_ptr(rbx, rcx), rax);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_bswap_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_BSWAP_REG)]);
	a.movzx(ecx, byte_ptr(rsi));
	a.inc(rsi);
	a.shl(rcx, 3);
	a.mov(rax, qword_ptr(rbx, rcx));
	a.bswap(rax);
	a.mov(qword_ptr(rbx, rcx), rax);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_rot_cl_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);
	// Format: [opcode] [vreg:1]
	a.movzx(ecx, byte_ptr(rsi));
	a.inc(rsi);
	a.shl(rcx, 3);
	a.mov(rax, qword_ptr(rbx, rcx));
	a.push(rcx);
	a.mov(ecx, dword_ptr(rbx, table.perm_gp_off(vm_reg::VRCX)));
	if (op == vm_op::VM_ROL_REG_CL)
		a.rol(rax, cl);
	else
		a.ror(rax, cl);
	a.pop(rcx);
	a.pushfq();
	a.pop(r9);
	a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
	a.mov(qword_ptr(rbx, rcx), rax);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_cbw_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_CBW)]);
	// CBW: sign-extend AL → AX
	a.mov(al, byte_ptr(rbx, table.perm_gp_off(vm_reg::VRAX)));
	a.cbw();
	a.mov(word_ptr(rbx, table.perm_gp_off(vm_reg::VRAX)), ax);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_cwde_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_CWDE)]);
	// CWDE: sign-extend AX → EAX
	a.mov(ax, word_ptr(rbx, table.perm_gp_off(vm_reg::VRAX)));
	a.cwde();
	a.mov(dword_ptr(rbx, table.perm_gp_off(vm_reg::VRAX)), eax);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_cdqe_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_CDQE)]);
	// CDQE: sign-extend EAX → RAX
	a.mov(eax, dword_ptr(rbx, table.perm_gp_off(vm_reg::VRAX)));
	a.cdqe();
	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VRAX)), rax);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_mul_reg_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_MUL_REG)]);
	// Format: [opcode] [vreg:1]
	// MUL vreg: RDX:RAX = RAX * vreg (unsigned)
	a.movzx(ecx, byte_ptr(rsi));
	a.inc(rsi);
	a.mov(rax, qword_ptr(rbx, table.perm_gp_off(vm_reg::VRAX)));
	a.shl(rcx, 3);
	a.mov(r8, qword_ptr(rbx, rcx));
	a.mul(r8);
	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VRAX)), rax);
	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VRDX)), rdx);
	a.pushfq();
	a.pop(r9);
	a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_rot_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);
	// Format: [opcode] [vreg:1] [imm8:1]
	a.movzx(ecx, byte_ptr(rsi));
	a.movzx(edx, byte_ptr(rsi, 1));
	a.add(rsi, 2);
	a.shl(rcx, 3);
	a.mov(rax, qword_ptr(rbx, rcx));

	// For RCL/RCR we need to restore CF from flags first
	if (op == vm_op::VM_RCL_REG_IMM || op == vm_op::VM_RCR_REG_IMM) {
		a.push(qword_ptr(rbx, VRFLAGS_OFF));
		a.popfq();
	}

	a.push(rcx);
	a.mov(ecx, edx);
	switch (op) {
	case vm_op::VM_ROL_REG_IMM: a.rol(rax, cl); break;
	case vm_op::VM_ROR_REG_IMM: a.ror(rax, cl); break;
	case vm_op::VM_RCL_REG_IMM: a.rcl(rax, cl); break;
	case vm_op::VM_RCR_REG_IMM: a.rcr(rax, cl); break;
	default: break;
	}
	a.pop(rcx);

	a.pushfq();
	a.pop(r9);
	a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
	a.mov(qword_ptr(rbx, rcx), rax);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_bt_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);

	bool is_imm = (op == vm_op::VM_BT_REG_IMM || op == vm_op::VM_BTS_REG_IMM || op == vm_op::VM_BTR_REG_IMM);

	if (is_imm) {
		// Format: [opcode] [vreg:1] [imm8:1]
		a.movzx(ecx, byte_ptr(rsi));
		a.movzx(edx, byte_ptr(rsi, 1));
		a.add(rsi, 2);
		a.shl(rcx, 3);
		a.mov(rax, qword_ptr(rbx, rcx));

		// BT/BTS/BTR rax, edx — but x86 bt only takes reg,reg or reg,imm8
		// We use the reg form with edx
		switch (op) {
		case vm_op::VM_BT_REG_IMM:  a.bt(rax, rdx); break;
		case vm_op::VM_BTS_REG_IMM: a.bts(rax, rdx); break;
		case vm_op::VM_BTR_REG_IMM: a.btr(rax, rdx); break;
		default: break;
		}
	} else {
		// Format: [opcode] [vreg1:1] [vreg2:1]
		a.movzx(ecx, byte_ptr(rsi));
		a.movzx(edx, byte_ptr(rsi, 1));
		a.add(rsi, 2);
		a.shl(rcx, 3);
		a.shl(rdx, 3);
		a.mov(rax, qword_ptr(rbx, rcx));
		a.mov(r8, qword_ptr(rbx, rdx));

		switch (op) {
		case vm_op::VM_BT_REG_REG:  a.bt(rax, r8); break;
		case vm_op::VM_BTS_REG_REG: a.bts(rax, r8); break;
		case vm_op::VM_BTR_REG_REG: a.btr(rax, r8); break;
		default: break;
		}
	}

	a.pushfq();
	a.pop(r9);
	a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
	// BTS/BTR modify the operand
	if (op == vm_op::VM_BTS_REG_REG || op == vm_op::VM_BTS_REG_IMM ||
		op == vm_op::VM_BTR_REG_REG || op == vm_op::VM_BTR_REG_IMM) {
		a.mov(qword_ptr(rbx, rcx), rax);
	}
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_bsf_bsr_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);
	// Format: [opcode] [dst:1] [src:1]
	a.movzx(ecx, byte_ptr(rsi));
	a.movzx(edx, byte_ptr(rsi, 1));
	a.add(rsi, 2);
	a.shl(rcx, 3);
	a.shl(rdx, 3);
	a.mov(r8, qword_ptr(rbx, rdx));

	if (op == vm_op::VM_BSF_REG_REG)
		a.bsf(rax, r8);
	else
		a.bsr(rax, r8);

	a.pushfq();
	a.pop(r9);
	a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
	a.mov(qword_ptr(rbx, rcx), rax);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_popcnt_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);
	// Format: [opcode] [dst:1] [src:1]
	a.movzx(ecx, byte_ptr(rsi));
	a.movzx(edx, byte_ptr(rsi, 1));
	a.add(rsi, 2);
	a.shl(rcx, 3);
	a.shl(rdx, 3);
	a.mov(r8, qword_ptr(rbx, rdx));

	if (op == vm_op::VM_POPCNT_REG_REG)
		a.popcnt(rax, r8);
	else if (op == vm_op::VM_LZCNT_REG_REG)
		a.lzcnt(rax, r8);
	else
		a.tzcnt(rax, r8);

	a.pushfq();
	a.pop(r9);
	a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
	a.mov(qword_ptr(rbx, rcx), rax);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_string_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);
	// No operands in bytecode — string ops use implicit RSI, RDI, RCX from VM context

	// Load RSI, RDI from VM context (and RCX for rep, RAX for stos/scas)
	a.push(rsi); // save VM IP
	a.mov(rdi, qword_ptr(rbx, table.perm_gp_off(vm_reg::VRDI)));
	a.mov(rcx, qword_ptr(rbx, table.perm_gp_off(vm_reg::VRCX)));
	a.mov(rax, qword_ptr(rbx, table.perm_gp_off(vm_reg::VRAX)));
	a.mov(rsi, qword_ptr(rbx, table.perm_gp_off(vm_reg::VRSI)));

	// Restore flags for repe/repne
	a.push(qword_ptr(rbx, VRFLAGS_OFF));
	a.popfq();

	switch (op) {
	case vm_op::VM_REP_MOVSB: a.rep().movsb(); break;
	case vm_op::VM_REP_MOVSW: a.rep().movsw(); break;
	case vm_op::VM_REP_MOVSD: a.rep().movsd(); break;
	case vm_op::VM_REP_MOVSQ: a.rep().movsq(); break;
	case vm_op::VM_REP_STOSB: a.rep().stosb(); break;
	case vm_op::VM_REP_STOSW: a.rep().stosw(); break;
	case vm_op::VM_REP_STOSD: a.rep().stosd(); break;
	case vm_op::VM_REP_STOSQ: a.rep().stosq(); break;
	case vm_op::VM_MOVSB:     a.movsb(); break;
	case vm_op::VM_MOVSQ:     a.movsq(); break;
	case vm_op::VM_STOSB:     a.stosb(); break;
	case vm_op::VM_STOSQ:     a.stosq(); break;
	case vm_op::VM_REP_SCASB: a.repne().scasb(); break;
	case vm_op::VM_REPE_CMPSB: a.repe().cmpsb(); break;
	default: break;
	}

	// Save updated RSI, RDI, RCX, RAX back to VM context
	a.pushfq();
	a.pop(r9);
	a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VRDI)), rdi);
	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VRCX)), rcx);
	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VRAX)), rax);
	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VRSI)), rsi);

	// Restore VM IP
	a.pop(rsi);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_cwd_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_CWD)]);
	// CWD: sign-extend AX → DX:AX (16-bit)
	a.mov(ax, word_ptr(rbx, table.perm_gp_off(vm_reg::VRAX)));
	a.cwd();
	a.mov(word_ptr(rbx, table.perm_gp_off(vm_reg::VRAX)), ax);
	a.mov(word_ptr(rbx, table.perm_gp_off(vm_reg::VRDX)), dx);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_jmp_reg_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_JMP_REG)]);
	a.movzx(ecx, byte_ptr(rsi));
	a.inc(rsi);
	a.shl(rcx, 3);
	a.mov(rax, qword_ptr(rbx, rcx));
	for (int i = 0; i < 16; i++)
		a.movups(x86::Xmm(i), xmmword_ptr(rbx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0) + i)));
	a.mov(rcx, qword_ptr(rbx, table.perm_gp_off(vm_reg::VRCX)));
	a.mov(rdx, qword_ptr(rbx, table.perm_gp_off(vm_reg::VRDX)));
	a.mov(r8, qword_ptr(rbx, table.perm_gp_off(vm_reg::VR8)));
	a.mov(r9, qword_ptr(rbx, table.perm_gp_off(vm_reg::VR9)));
	a.mov(r10, qword_ptr(rbx, table.perm_gp_off(vm_reg::VR10)));
	a.mov(r11, qword_ptr(rbx, table.perm_gp_off(vm_reg::VR11)));
	a.push(qword_ptr(rbx, VRFLAGS_OFF));
	a.popfq();
	a.add(rsp, VM_REG_FILE_ALLOC);
	a.pop(rdi);
	a.pop(rsi);
	a.add(rsp, 8);
	a.pop(r15);
	a.pop(r14);
	a.pop(r13);
	a.pop(r12);
	a.pop(rbp);
	a.pop(rbx);
	a.jmp(rax);
}

void vm_dispatcher::emit_jmp_mem_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_JMP_MEM)]);
	a.movzx(ecx, byte_ptr(rsi));
	a.movsxd(rdx, dword_ptr(rsi, 1));
	a.add(rsi, 5);
	a.shl(rcx, 3);
	a.mov(rax, qword_ptr(rbx, rcx));
	a.add(rax, rdx);
	a.mov(rax, qword_ptr(rax));
	for (int i = 0; i < 16; i++)
		a.movups(x86::Xmm(i), xmmword_ptr(rbx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0) + i)));
	a.mov(rcx, qword_ptr(rbx, table.perm_gp_off(vm_reg::VRCX)));
	a.mov(rdx, qword_ptr(rbx, table.perm_gp_off(vm_reg::VRDX)));
	a.mov(r8, qword_ptr(rbx, table.perm_gp_off(vm_reg::VR8)));
	a.mov(r9, qword_ptr(rbx, table.perm_gp_off(vm_reg::VR9)));
	a.mov(r10, qword_ptr(rbx, table.perm_gp_off(vm_reg::VR10)));
	a.mov(r11, qword_ptr(rbx, table.perm_gp_off(vm_reg::VR11)));
	a.push(qword_ptr(rbx, VRFLAGS_OFF));
	a.popfq();
	a.add(rsp, VM_REG_FILE_ALLOC);
	a.pop(rdi);
	a.pop(rsi);
	a.add(rsp, 8);
	a.pop(r15);
	a.pop(r14);
	a.pop(r13);
	a.pop(r12);
	a.pop(rbp);
	a.pop(rbx);
	a.jmp(rax);
}

void vm_dispatcher::emit_imul_single_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_IMUL_REG)]);
	// Format: [opcode] [vreg:1]
	// IMUL vreg: RDX:RAX = RAX * vreg (signed)
	a.movzx(ecx, byte_ptr(rsi));
	a.inc(rsi);
	a.mov(rax, qword_ptr(rbx, table.perm_gp_off(vm_reg::VRAX)));
	a.shl(rcx, 3);
	a.mov(r8, qword_ptr(rbx, rcx));
	a.imul(r8);
	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VRAX)), rax);
	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VRDX)), rdx);
	a.pushfq();
	a.pop(r9);
	a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_shld_shrd_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);

	bool by_cl = (op == vm_op::VM_SHLD_REG_REG_CL || op == vm_op::VM_SHRD_REG_REG_CL);

	if (by_cl) {
		// Format: [opcode] [dst:1] [src:1]
		a.movzx(ecx, byte_ptr(rsi));
		a.movzx(edx, byte_ptr(rsi, 1));
		a.add(rsi, 2);
	} else {
		// Format: [opcode] [dst:1] [src:1] [imm8:1]
		a.movzx(ecx, byte_ptr(rsi));
		a.movzx(edx, byte_ptr(rsi, 1));
		a.movzx(r9d, byte_ptr(rsi, 2));
		a.add(rsi, 3);
	}

	a.shl(rcx, 3);
	a.shl(rdx, 3);
	a.mov(rax, qword_ptr(rbx, rcx)); // dst
	a.mov(r8, qword_ptr(rbx, rdx));  // src

	a.push(rcx); // save dst offset
	if (by_cl) {
		a.mov(ecx, dword_ptr(rbx, table.perm_gp_off(vm_reg::VRCX)));
		if (op == vm_op::VM_SHLD_REG_REG_CL)
			a.shld(rax, r8, cl);
		else
			a.shrd(rax, r8, cl);
	} else {
		a.mov(ecx, r9d);
		if (op == vm_op::VM_SHLD_REG_REG_IMM)
			a.shld(rax, r8, cl);
		else
			a.shrd(rax, r8, cl);
	}
	a.pop(rcx);

	a.pushfq();
	a.pop(r9);
	a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
	a.mov(qword_ptr(rbx, rcx), rax);
	a.jmp(labels.dispatch_loop);
}

// === SSE HANDLERS ===
// Helper: compute XMM offset for a bytecode xmm index (0..15)
// xmm_vreg_index in bytecode = 0..15, maps to VXMM0..VXMM15
static int xmm_file_offset(int xmm_idx) {
	return vm_xmm_offset(static_cast<int>(vm_reg::VXMM0) + xmm_idx);
}

void vm_dispatcher::emit_sse_mov_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);

	bool is_reg_reg = (op == vm_op::VM_MOVSS_REG_REG || op == vm_op::VM_MOVSD_REG_REG ||
		op == vm_op::VM_MOVAPS_REG_REG || op == vm_op::VM_MOVDQA_REG_REG);
	bool is_mem_store = (op == vm_op::VM_MOVSS_MEM_REG || op == vm_op::VM_MOVSD_MEM_REG ||
		op == vm_op::VM_MOVAPS_MEM_REG || op == vm_op::VM_MOVUPS_MEM_REG ||
		op == vm_op::VM_MOVDQA_MEM_REG || op == vm_op::VM_MOVDQU_MEM_REG);

	if (is_reg_reg) {
		// Format: [opcode] [dst_xmm:1] [src_xmm:1]
		a.movzx(ecx, byte_ptr(rsi));
		a.movzx(edx, byte_ptr(rsi, 1));
		a.add(rsi, 2);
		// Load src into xmm0, store to dst
		a.lea(rax, qword_ptr(rbx, 0));
		a.movzx(r8d, dl);
		a.shl(r8, 4);
		a.add(r8, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
		a.movups(xmm0, xmmword_ptr(rbx, r8));
		a.movzx(r8d, cl);
		a.shl(r8, 4);
		a.add(r8, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
		a.movups(xmmword_ptr(rbx, r8), xmm0);
	} else if (is_mem_store) {
		// Format: [opcode] [base_gp:1] [disp:4] [src_xmm:1]
		a.movzx(ecx, byte_ptr(rsi));       // base GP reg
		a.movsxd(rdx, dword_ptr(rsi, 1));  // disp32
		a.movzx(r8d, byte_ptr(rsi, 5));    // src xmm
		a.add(rsi, 6);
		a.shl(rcx, 3);
		a.mov(rax, qword_ptr(rbx, rcx));
		a.add(rax, rdx);
		a.shl(r8, 4);
		a.add(r8, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
		a.movups(xmm0, xmmword_ptr(rbx, r8));
		if (op == vm_op::VM_MOVSS_MEM_REG)
			a.movss(dword_ptr(rax), xmm0);
		else if (op == vm_op::VM_MOVSD_MEM_REG)
			a.movsd(qword_ptr(rax), xmm0);
		else
			a.movups(xmmword_ptr(rax), xmm0);
	} else {
		// Format: [opcode] [dst_xmm:1] [base_gp:1] [disp:4]
		a.movzx(ecx, byte_ptr(rsi));       // dst xmm
		a.movzx(edx, byte_ptr(rsi, 1));    // base GP reg
		a.movsxd(r8, dword_ptr(rsi, 2));   // disp32
		a.add(rsi, 6);
		a.shl(rdx, 3);
		a.mov(rax, qword_ptr(rbx, rdx));
		a.add(rax, r8);
		if (op == vm_op::VM_MOVSS_REG_MEM)
			a.movss(xmm0, dword_ptr(rax));
		else if (op == vm_op::VM_MOVSD_REG_MEM)
			a.movsd(xmm0, qword_ptr(rax));
		else
			a.movups(xmm0, xmmword_ptr(rax));
		a.shl(rcx, 4);
		a.add(rcx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
		a.movups(xmmword_ptr(rbx, rcx), xmm0);
	}
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_sse_arith_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);

	bool is_mem = (op == vm_op::VM_ADDSS_REG_MEM || op == vm_op::VM_ADDSD_REG_MEM ||
		op == vm_op::VM_SUBSS_REG_MEM || op == vm_op::VM_SUBSD_REG_MEM ||
		op == vm_op::VM_MULSS_REG_MEM || op == vm_op::VM_MULSD_REG_MEM ||
		op == vm_op::VM_DIVSS_REG_MEM || op == vm_op::VM_DIVSD_REG_MEM);

	if (is_mem) {
		// Format: [opcode] [dst_xmm:1] [base_gp:1] [disp:4]
		a.movzx(ecx, byte_ptr(rsi));
		a.movzx(edx, byte_ptr(rsi, 1));
		a.movsxd(r8, dword_ptr(rsi, 2));
		a.add(rsi, 6);
		a.shl(rcx, 4);
		a.add(rcx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
		a.movups(xmm0, xmmword_ptr(rbx, rcx));
		a.shl(rdx, 3);
		a.mov(rax, qword_ptr(rbx, rdx));
		a.add(rax, r8);
		bool is_ss = (op == vm_op::VM_ADDSS_REG_MEM || op == vm_op::VM_SUBSS_REG_MEM ||
			op == vm_op::VM_MULSS_REG_MEM || op == vm_op::VM_DIVSS_REG_MEM);
		if (is_ss) {
			a.movss(xmm1, dword_ptr(rax));
		} else {
			a.movsd(xmm1, qword_ptr(rax));
		}
	} else {
		// Format: [opcode] [dst_xmm:1] [src_xmm:1]
		a.movzx(ecx, byte_ptr(rsi));
		a.movzx(edx, byte_ptr(rsi, 1));
		a.add(rsi, 2);
		a.shl(rcx, 4);
		a.add(rcx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
		a.shl(rdx, 4);
		a.add(rdx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
		a.movups(xmm0, xmmword_ptr(rbx, rcx));
		a.movups(xmm1, xmmword_ptr(rbx, rdx));
	}

	switch (op) {
	case vm_op::VM_ADDSS_REG_REG: case vm_op::VM_ADDSS_REG_MEM: a.addss(xmm0, xmm1); break;
	case vm_op::VM_ADDSD_REG_REG: case vm_op::VM_ADDSD_REG_MEM: a.addsd(xmm0, xmm1); break;
	case vm_op::VM_SUBSS_REG_REG: case vm_op::VM_SUBSS_REG_MEM: a.subss(xmm0, xmm1); break;
	case vm_op::VM_SUBSD_REG_REG: case vm_op::VM_SUBSD_REG_MEM: a.subsd(xmm0, xmm1); break;
	case vm_op::VM_MULSS_REG_REG: case vm_op::VM_MULSS_REG_MEM: a.mulss(xmm0, xmm1); break;
	case vm_op::VM_MULSD_REG_REG: case vm_op::VM_MULSD_REG_MEM: a.mulsd(xmm0, xmm1); break;
	case vm_op::VM_DIVSS_REG_REG: case vm_op::VM_DIVSS_REG_MEM: a.divss(xmm0, xmm1); break;
	case vm_op::VM_DIVSD_REG_REG: case vm_op::VM_DIVSD_REG_MEM: a.divsd(xmm0, xmm1); break;
	default: break;
	}

	a.movups(xmmword_ptr(rbx, rcx), xmm0);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_sse_cmp_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);

	bool is_mem = (op == vm_op::VM_COMISS_REG_MEM || op == vm_op::VM_COMISD_REG_MEM ||
		op == vm_op::VM_UCOMISS_REG_MEM || op == vm_op::VM_UCOMISD_REG_MEM);

	if (is_mem) {
		a.movzx(ecx, byte_ptr(rsi));
		a.movzx(edx, byte_ptr(rsi, 1));
		a.movsxd(r8, dword_ptr(rsi, 2));
		a.add(rsi, 6);
		a.shl(rcx, 4);
		a.add(rcx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
		a.movups(xmm0, xmmword_ptr(rbx, rcx));
		a.shl(rdx, 3);
		a.mov(rax, qword_ptr(rbx, rdx));
		a.add(rax, r8);
		bool is_ss = (op == vm_op::VM_COMISS_REG_MEM || op == vm_op::VM_UCOMISS_REG_MEM);
		if (is_ss) a.movss(xmm1, dword_ptr(rax));
		else a.movsd(xmm1, qword_ptr(rax));
	} else {
		a.movzx(ecx, byte_ptr(rsi));
		a.movzx(edx, byte_ptr(rsi, 1));
		a.add(rsi, 2);
		a.shl(rcx, 4);
		a.add(rcx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
		a.shl(rdx, 4);
		a.add(rdx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
		a.movups(xmm0, xmmword_ptr(rbx, rcx));
		a.movups(xmm1, xmmword_ptr(rbx, rdx));
	}

	switch (op) {
	case vm_op::VM_COMISS_REG_REG:  case vm_op::VM_COMISS_REG_MEM:  a.comiss(xmm0, xmm1); break;
	case vm_op::VM_COMISD_REG_REG:  case vm_op::VM_COMISD_REG_MEM:  a.comisd(xmm0, xmm1); break;
	case vm_op::VM_UCOMISS_REG_REG: case vm_op::VM_UCOMISS_REG_MEM: a.ucomiss(xmm0, xmm1); break;
	case vm_op::VM_UCOMISD_REG_REG: case vm_op::VM_UCOMISD_REG_MEM: a.ucomisd(xmm0, xmm1); break;
	default: break;
	}

	a.pushfq();
	a.pop(r9);
	a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_sse_cvt_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);

	bool is_mem = (op == vm_op::VM_CVTSI2SS_REG_MEM || op == vm_op::VM_CVTSI2SD_REG_MEM ||
		op == vm_op::VM_CVTSS2SD_REG_MEM || op == vm_op::VM_CVTSD2SS_REG_MEM);
	bool to_gp = (op == vm_op::VM_CVTSS2SI_REG_REG || op == vm_op::VM_CVTSD2SI_REG_REG ||
		op == vm_op::VM_CVTTSS2SI_REG_REG || op == vm_op::VM_CVTTSD2SI_REG_REG);
	bool from_gp = (op == vm_op::VM_CVTSI2SS_REG_REG || op == vm_op::VM_CVTSI2SD_REG_REG);

	if (is_mem) {
		// Format: [opcode] [dst_xmm:1] [base_gp:1] [disp:4]
		a.movzx(ecx, byte_ptr(rsi));
		a.movzx(edx, byte_ptr(rsi, 1));
		a.movsxd(r8, dword_ptr(rsi, 2));
		a.add(rsi, 6);
		a.shl(rcx, 4);
		a.add(rcx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
		a.movups(xmm0, xmmword_ptr(rbx, rcx));
		a.shl(rdx, 3);
		a.mov(rax, qword_ptr(rbx, rdx));
		a.add(rax, r8);
		switch (op) {
		case vm_op::VM_CVTSI2SS_REG_MEM: a.cvtsi2ss(xmm0, qword_ptr(rax)); break;
		case vm_op::VM_CVTSI2SD_REG_MEM: a.cvtsi2sd(xmm0, qword_ptr(rax)); break;
		case vm_op::VM_CVTSS2SD_REG_MEM: a.movss(xmm1, dword_ptr(rax)); a.cvtss2sd(xmm0, xmm1); break;
		case vm_op::VM_CVTSD2SS_REG_MEM: a.movsd(xmm1, qword_ptr(rax)); a.cvtsd2ss(xmm0, xmm1); break;
		default: break;
		}
		a.movups(xmmword_ptr(rbx, rcx), xmm0);
	} else if (to_gp) {
		// Format: [opcode] [dst_gp:1] [src_xmm:1]
		a.movzx(ecx, byte_ptr(rsi));
		a.movzx(edx, byte_ptr(rsi, 1));
		a.add(rsi, 2);
		a.shl(edx, 4);
		a.add(rdx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
		a.movups(xmm0, xmmword_ptr(rbx, rdx));
		switch (op) {
		case vm_op::VM_CVTSS2SI_REG_REG:  a.cvtss2si(rax, xmm0); break;
		case vm_op::VM_CVTSD2SI_REG_REG:  a.cvtsd2si(rax, xmm0); break;
		case vm_op::VM_CVTTSS2SI_REG_REG: a.cvttss2si(rax, xmm0); break;
		case vm_op::VM_CVTTSD2SI_REG_REG: a.cvttsd2si(rax, xmm0); break;
		default: break;
		}
		a.shl(rcx, 3);
		a.mov(qword_ptr(rbx, rcx), rax);
	} else if (from_gp) {
		// Format: [opcode] [dst_xmm:1] [src_gp:1]
		a.movzx(ecx, byte_ptr(rsi));
		a.movzx(edx, byte_ptr(rsi, 1));
		a.add(rsi, 2);
		a.shl(rcx, 4);
		a.add(rcx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
		a.movups(xmm0, xmmword_ptr(rbx, rcx));
		a.shl(rdx, 3);
		a.mov(rax, qword_ptr(rbx, rdx));
		if (op == vm_op::VM_CVTSI2SS_REG_REG)
			a.cvtsi2ss(xmm0, rax);
		else
			a.cvtsi2sd(xmm0, rax);
		a.movups(xmmword_ptr(rbx, rcx), xmm0);
	} else {
		// xmm, xmm: CVTSS2SD, CVTSD2SS
		a.movzx(ecx, byte_ptr(rsi));
		a.movzx(edx, byte_ptr(rsi, 1));
		a.add(rsi, 2);
		a.shl(rcx, 4);
		a.add(rcx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
		a.shl(rdx, 4);
		a.add(rdx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
		a.movups(xmm0, xmmword_ptr(rbx, rcx));
		a.movups(xmm1, xmmword_ptr(rbx, rdx));
		if (op == vm_op::VM_CVTSS2SD_REG_REG)
			a.cvtss2sd(xmm0, xmm1);
		else
			a.cvtsd2ss(xmm0, xmm1);
		a.movups(xmmword_ptr(rbx, rcx), xmm0);
	}
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_sse_bitwise_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);

	bool is_mem = (op == vm_op::VM_XORPS_REG_MEM || op == vm_op::VM_XORPD_REG_MEM ||
		op == vm_op::VM_ANDPS_REG_MEM || op == vm_op::VM_ANDPD_REG_MEM ||
		op == vm_op::VM_ORPS_REG_MEM || op == vm_op::VM_ORPD_REG_MEM ||
		op == vm_op::VM_ANDNPS_REG_MEM || op == vm_op::VM_ANDNPD_REG_MEM);

	if (is_mem) {
		a.movzx(ecx, byte_ptr(rsi));
		a.movzx(edx, byte_ptr(rsi, 1));
		a.movsxd(r8, dword_ptr(rsi, 2));
		a.add(rsi, 6);
		a.shl(rcx, 4);
		a.add(rcx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
		a.movups(xmm0, xmmword_ptr(rbx, rcx));
		a.shl(rdx, 3);
		a.mov(rax, qword_ptr(rbx, rdx));
		a.add(rax, r8);
		a.movups(xmm1, xmmword_ptr(rax));
	} else {
		a.movzx(ecx, byte_ptr(rsi));
		a.movzx(edx, byte_ptr(rsi, 1));
		a.add(rsi, 2);
		a.shl(rcx, 4);
		a.add(rcx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
		a.shl(rdx, 4);
		a.add(rdx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
		a.movups(xmm0, xmmword_ptr(rbx, rcx));
		a.movups(xmm1, xmmword_ptr(rbx, rdx));
	}

	switch (op) {
	case vm_op::VM_XORPS_REG_REG:  case vm_op::VM_XORPS_REG_MEM:  a.xorps(xmm0, xmm1); break;
	case vm_op::VM_XORPD_REG_REG:  case vm_op::VM_XORPD_REG_MEM:  a.xorpd(xmm0, xmm1); break;
	case vm_op::VM_ANDPS_REG_REG:  case vm_op::VM_ANDPS_REG_MEM:  a.andps(xmm0, xmm1); break;
	case vm_op::VM_ANDPD_REG_REG:  case vm_op::VM_ANDPD_REG_MEM:  a.andpd(xmm0, xmm1); break;
	case vm_op::VM_ORPS_REG_REG:   case vm_op::VM_ORPS_REG_MEM:   a.orps(xmm0, xmm1); break;
	case vm_op::VM_ORPD_REG_REG:   case vm_op::VM_ORPD_REG_MEM:   a.orpd(xmm0, xmm1); break;
	case vm_op::VM_ANDNPS_REG_REG: case vm_op::VM_ANDNPS_REG_MEM: a.andnps(xmm0, xmm1); break;
	case vm_op::VM_ANDNPD_REG_REG: case vm_op::VM_ANDNPD_REG_MEM: a.andnpd(xmm0, xmm1); break;
	default: break;
	}
	a.movups(xmmword_ptr(rbx, rcx), xmm0);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_sse_packed_arith_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);
	bool is_mem = (op == vm_op::VM_ADDPS_REG_MEM || op == vm_op::VM_ADDPD_REG_MEM ||
		op == vm_op::VM_SUBPS_REG_MEM || op == vm_op::VM_SUBPD_REG_MEM ||
		op == vm_op::VM_MULPS_REG_MEM || op == vm_op::VM_MULPD_REG_MEM ||
		op == vm_op::VM_DIVPS_REG_MEM || op == vm_op::VM_DIVPD_REG_MEM);

	if (is_mem) {
		a.movzx(ecx, byte_ptr(rsi));
		a.movzx(edx, byte_ptr(rsi, 1));
		a.movsxd(r8, dword_ptr(rsi, 2));
		a.add(rsi, 6);
		a.shl(rcx, 4);
		a.add(rcx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
		a.movups(xmm0, xmmword_ptr(rbx, rcx));
		a.shl(rdx, 3);
		a.mov(rax, qword_ptr(rbx, rdx));
		a.add(rax, r8);
		a.movups(xmm1, xmmword_ptr(rax));
	} else {
		a.movzx(ecx, byte_ptr(rsi));
		a.movzx(edx, byte_ptr(rsi, 1));
		a.add(rsi, 2);
		a.shl(rcx, 4);
		a.add(rcx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
		a.shl(rdx, 4);
		a.add(rdx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
		a.movups(xmm0, xmmword_ptr(rbx, rcx));
		a.movups(xmm1, xmmword_ptr(rbx, rdx));
	}

	switch (op) {
	case vm_op::VM_ADDPS_REG_REG: case vm_op::VM_ADDPS_REG_MEM: a.addps(xmm0, xmm1); break;
	case vm_op::VM_ADDPD_REG_REG: case vm_op::VM_ADDPD_REG_MEM: a.addpd(xmm0, xmm1); break;
	case vm_op::VM_SUBPS_REG_REG: case vm_op::VM_SUBPS_REG_MEM: a.subps(xmm0, xmm1); break;
	case vm_op::VM_SUBPD_REG_REG: case vm_op::VM_SUBPD_REG_MEM: a.subpd(xmm0, xmm1); break;
	case vm_op::VM_MULPS_REG_REG: case vm_op::VM_MULPS_REG_MEM: a.mulps(xmm0, xmm1); break;
	case vm_op::VM_MULPD_REG_REG: case vm_op::VM_MULPD_REG_MEM: a.mulpd(xmm0, xmm1); break;
	case vm_op::VM_DIVPS_REG_REG: case vm_op::VM_DIVPS_REG_MEM: a.divps(xmm0, xmm1); break;
	case vm_op::VM_DIVPD_REG_REG: case vm_op::VM_DIVPD_REG_MEM: a.divpd(xmm0, xmm1); break;
	default: break;
	}
	a.movups(xmmword_ptr(rbx, rcx), xmm0);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_sse_minmax_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);
	// Format: [opcode] [dst_xmm:1] [src_xmm:1]
	a.movzx(ecx, byte_ptr(rsi));
	a.movzx(edx, byte_ptr(rsi, 1));
	a.add(rsi, 2);
	a.shl(rcx, 4);
	a.add(rcx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
	a.shl(rdx, 4);
	a.add(rdx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
	a.movups(xmm0, xmmword_ptr(rbx, rcx));
	a.movups(xmm1, xmmword_ptr(rbx, rdx));

	switch (op) {
	case vm_op::VM_MINSS_REG_REG: a.minss(xmm0, xmm1); break;
	case vm_op::VM_MAXSS_REG_REG: a.maxss(xmm0, xmm1); break;
	case vm_op::VM_MINSD_REG_REG: a.minsd(xmm0, xmm1); break;
	case vm_op::VM_MAXSD_REG_REG: a.maxsd(xmm0, xmm1); break;
	case vm_op::VM_SQRTSS_REG_REG: a.sqrtss(xmm0, xmm1); break;
	case vm_op::VM_SQRTSD_REG_REG: a.sqrtsd(xmm0, xmm1); break;
	default: break;
	}
	a.movups(xmmword_ptr(rbx, rcx), xmm0);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_sse_shuffle_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);

	bool has_imm = (op == vm_op::VM_SHUFPS_REG_REG_IMM || op == vm_op::VM_SHUFPD_REG_REG_IMM);

	if (has_imm) {
		// Format: [opcode] [dst:1] [src:1] [imm8:1]
		a.movzx(ecx, byte_ptr(rsi));
		a.movzx(edx, byte_ptr(rsi, 1));
		a.movzx(r8d, byte_ptr(rsi, 2));
		a.add(rsi, 3);
	} else {
		a.movzx(ecx, byte_ptr(rsi));
		a.movzx(edx, byte_ptr(rsi, 1));
		a.add(rsi, 2);
	}

	a.shl(rcx, 4);
	a.add(rcx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
	a.shl(rdx, 4);
	a.add(rdx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
	a.movups(xmm0, xmmword_ptr(rbx, rcx));
	a.movups(xmm1, xmmword_ptr(rbx, rdx));

	if (op == vm_op::VM_SHUFPS_REG_REG_IMM || op == vm_op::VM_SHUFPD_REG_REG_IMM) {
		Label done = a.newLabel();
		Label tbl[256];
		for (int i = 0; i < 256; i++) tbl[i] = a.newLabel();
		for (int i = 0; i < 256; i++) {
			a.cmp(r8d, i);
			a.je(tbl[i]);
		}
		a.jmp(done);
		for (int i = 0; i < 256; i++) {
			a.bind(tbl[i]);
			if (op == vm_op::VM_SHUFPS_REG_REG_IMM)
				a.shufps(xmm0, xmm1, Imm(i));
			else
				a.shufpd(xmm0, xmm1, Imm(i));
			a.jmp(done);
		}
		a.bind(done);
	} else {
		switch (op) {
		case vm_op::VM_UNPCKLPS_REG_REG: a.unpcklps(xmm0, xmm1); break;
		case vm_op::VM_UNPCKHPS_REG_REG: a.unpckhps(xmm0, xmm1); break;
		case vm_op::VM_UNPCKLPD_REG_REG: a.unpcklpd(xmm0, xmm1); break;
		case vm_op::VM_UNPCKHPD_REG_REG: a.unpckhpd(xmm0, xmm1); break;
		default: break;
		}
	}
	a.movups(xmmword_ptr(rbx, rcx), xmm0);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_sse_int_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);
	// Format: [opcode] [dst_xmm:1] [src_xmm:1]
	a.movzx(ecx, byte_ptr(rsi));
	a.movzx(edx, byte_ptr(rsi, 1));
	a.add(rsi, 2);
	a.shl(rcx, 4);
	a.add(rcx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
	a.shl(rdx, 4);
	a.add(rdx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
	a.movups(xmm0, xmmword_ptr(rbx, rcx));
	a.movups(xmm1, xmmword_ptr(rbx, rdx));

	switch (op) {
	case vm_op::VM_PXOR_REG_REG:    a.pxor(xmm0, xmm1); break;
	case vm_op::VM_PAND_REG_REG:    a.pand(xmm0, xmm1); break;
	case vm_op::VM_POR_REG_REG:     a.por(xmm0, xmm1); break;
	case vm_op::VM_PANDN_REG_REG:   a.pandn(xmm0, xmm1); break;
	case vm_op::VM_PCMPEQB_REG_REG: a.pcmpeqb(xmm0, xmm1); break;
	case vm_op::VM_PCMPEQD_REG_REG: a.pcmpeqd(xmm0, xmm1); break;
	case vm_op::VM_PCMPGTB_REG_REG: a.pcmpgtb(xmm0, xmm1); break;
	case vm_op::VM_PADDB_REG_REG:   a.paddb(xmm0, xmm1); break;
	case vm_op::VM_PADDW_REG_REG:   a.paddw(xmm0, xmm1); break;
	case vm_op::VM_PADDD_REG_REG:   a.paddd(xmm0, xmm1); break;
	case vm_op::VM_PADDQ_REG_REG:   a.paddq(xmm0, xmm1); break;
	case vm_op::VM_PSUBB_REG_REG:   a.psubb(xmm0, xmm1); break;
	case vm_op::VM_PSUBW_REG_REG:   a.psubw(xmm0, xmm1); break;
	case vm_op::VM_PSUBD_REG_REG:   a.psubd(xmm0, xmm1); break;
	case vm_op::VM_PSUBQ_REG_REG:   a.psubq(xmm0, xmm1); break;
	case vm_op::VM_PUNPCKLBW_REG_REG:  a.punpcklbw(xmm0, xmm1); break;
	case vm_op::VM_PUNPCKHBW_REG_REG:  a.punpckhbw(xmm0, xmm1); break;
	case vm_op::VM_PUNPCKLDQ_REG_REG:  a.punpckldq(xmm0, xmm1); break;
	case vm_op::VM_PUNPCKHDQ_REG_REG:  a.punpckhdq(xmm0, xmm1); break;
	case vm_op::VM_PUNPCKLQDQ_REG_REG: a.punpcklqdq(xmm0, xmm1); break;
	case vm_op::VM_PUNPCKHQDQ_REG_REG: a.punpckhqdq(xmm0, xmm1); break;
	case vm_op::VM_PSHUFB_REG_REG:  a.emit(x86::Inst::kIdPshufb, xmm0, xmm1); break;
	case vm_op::VM_PMAXSB_REG_REG:  a.emit(x86::Inst::kIdPmaxsb, xmm0, xmm1); break;
	case vm_op::VM_PMAXSD_REG_REG:  a.emit(x86::Inst::kIdPmaxsd, xmm0, xmm1); break;
	case vm_op::VM_PMINSB_REG_REG:  a.emit(x86::Inst::kIdPminsb, xmm0, xmm1); break;
	case vm_op::VM_PMINSD_REG_REG:  a.emit(x86::Inst::kIdPminsd, xmm0, xmm1); break;
	default: break;
	}
	a.movups(xmmword_ptr(rbx, rcx), xmm0);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_sse_shift_imm_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);
	// Format: [opcode] [xmm:1] [imm8:1]
	a.movzx(ecx, byte_ptr(rsi));
	a.movzx(edx, byte_ptr(rsi, 1));
	a.add(rsi, 2);
	a.shl(rcx, 4);
	a.add(rcx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
	a.movups(xmm0, xmmword_ptr(rbx, rcx));

	{
		Label done = a.newLabel();
		Label tbl[256];
		for (int i = 0; i < 256; i++) tbl[i] = a.newLabel();
		for (int i = 0; i < 256; i++) { a.cmp(edx, i); a.je(tbl[i]); }
		a.jmp(done);
		for (int i = 0; i < 256; i++) {
			a.bind(tbl[i]);
			switch (op) {
			case vm_op::VM_PSLLW_REG_IMM: a.psllw(xmm0, Imm(i)); break;
			case vm_op::VM_PSLLD_REG_IMM: a.pslld(xmm0, Imm(i)); break;
			case vm_op::VM_PSLLQ_REG_IMM: a.psllq(xmm0, Imm(i)); break;
			case vm_op::VM_PSRLW_REG_IMM: a.psrlw(xmm0, Imm(i)); break;
			case vm_op::VM_PSRLD_REG_IMM: a.psrld(xmm0, Imm(i)); break;
			case vm_op::VM_PSRLQ_REG_IMM: a.psrlq(xmm0, Imm(i)); break;
			case vm_op::VM_PSRAW_REG_IMM: a.psraw(xmm0, Imm(i)); break;
			case vm_op::VM_PSRAD_REG_IMM: a.psrad(xmm0, Imm(i)); break;
			default: break;
			}
			a.jmp(done);
		}
		a.bind(done);
	}
	a.movups(xmmword_ptr(rbx, rcx), xmm0);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_pmovmskb_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_PMOVMSKB_REG_REG)]);
	// Format: [opcode] [dst_gp:1] [src_xmm:1]
	a.movzx(ecx, byte_ptr(rsi));
	a.movzx(edx, byte_ptr(rsi, 1));
	a.add(rsi, 2);
	a.shl(edx, 4);
	a.add(rdx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
	a.movups(xmm0, xmmword_ptr(rbx, rdx));
	a.pmovmskb(eax, xmm0);
	a.shl(rcx, 3);
	a.mov(qword_ptr(rbx, rcx), rax);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_pshufd_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);
	// Format: [opcode] [dst_xmm:1] [src_xmm:1] [imm8:1]
	a.movzx(ecx, byte_ptr(rsi));
	a.movzx(edx, byte_ptr(rsi, 1));
	a.movzx(r8d, byte_ptr(rsi, 2));
	a.add(rsi, 3);
	a.shl(rdx, 4);
	a.add(rdx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
	a.movups(xmm1, xmmword_ptr(rbx, rdx));
	{
		Label done = a.newLabel();
		Label tbl[256];
		for (int i = 0; i < 256; i++) tbl[i] = a.newLabel();
		for (int i = 0; i < 256; i++) { a.cmp(r8d, i); a.je(tbl[i]); }
		a.jmp(done);
		for (int i = 0; i < 256; i++) {
			a.bind(tbl[i]);
			a.pshufd(xmm0, xmm1, Imm(i));
			a.jmp(done);
		}
		a.bind(done);
	}
	a.shl(rcx, 4);
	a.add(rcx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
	a.movups(xmmword_ptr(rbx, rcx), xmm0);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_sse_movd_movq_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);

	bool is_mem = (op == vm_op::VM_MOVD_XMM_MEM || op == vm_op::VM_MOVD_MEM_XMM ||
		op == vm_op::VM_MOVQ_XMM_MEM || op == vm_op::VM_MOVQ_MEM_XMM);

	if (op == vm_op::VM_MOVQ_XMM_XMM) {
		// Format: [opcode] [dst_xmm:1] [src_xmm:1]
		a.movzx(ecx, byte_ptr(rsi));
		a.movzx(edx, byte_ptr(rsi, 1));
		a.add(rsi, 2);
		a.shl(rdx, 4);
		a.add(rdx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
		a.movups(xmm1, xmmword_ptr(rbx, rdx));
		a.movq(xmm0, xmm1);
		a.shl(rcx, 4);
		a.add(rcx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
		a.movups(xmmword_ptr(rbx, rcx), xmm0);
	} else if (is_mem) {
		// Format: [opcode] [xmm_or_gp:1] [base_gp:1] [disp:4]
		a.movzx(ecx, byte_ptr(rsi));
		a.movzx(edx, byte_ptr(rsi, 1));
		a.movsxd(r8, dword_ptr(rsi, 2));
		a.add(rsi, 6);
		a.shl(rdx, 3);
		a.mov(rax, qword_ptr(rbx, rdx));
		a.add(rax, r8);
		if (op == vm_op::VM_MOVD_XMM_MEM) {
			a.movd(xmm0, dword_ptr(rax));
			a.shl(rcx, 4);
			a.add(rcx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
			a.movups(xmmword_ptr(rbx, rcx), xmm0);
		} else if (op == vm_op::VM_MOVD_MEM_XMM) {
			a.shl(rcx, 4);
			a.add(rcx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
			a.movups(xmm0, xmmword_ptr(rbx, rcx));
			a.movd(dword_ptr(rax), xmm0);
		} else if (op == vm_op::VM_MOVQ_XMM_MEM) {
			a.movq(xmm0, qword_ptr(rax));
			a.shl(rcx, 4);
			a.add(rcx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
			a.movups(xmmword_ptr(rbx, rcx), xmm0);
		} else { // VM_MOVQ_MEM_XMM
			a.shl(rcx, 4);
			a.add(rcx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
			a.movups(xmm0, xmmword_ptr(rbx, rcx));
			a.movq(qword_ptr(rax), xmm0);
		}
	} else if (op == vm_op::VM_MOVD_XMM_REG || op == vm_op::VM_MOVQ_XMM_REG) {
		// Format: [opcode] [dst_xmm:1] [src_gp:1]
		a.movzx(ecx, byte_ptr(rsi));
		a.movzx(edx, byte_ptr(rsi, 1));
		a.add(rsi, 2);
		a.shl(rdx, 3);
		a.mov(rax, qword_ptr(rbx, rdx));
		if (op == vm_op::VM_MOVD_XMM_REG)
			a.movd(xmm0, eax);
		else
			a.movq(xmm0, rax);
		a.shl(rcx, 4);
		a.add(rcx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
		a.movups(xmmword_ptr(rbx, rcx), xmm0);
	} else {
		// MOVD_REG_XMM or MOVQ_REG_XMM: [opcode] [dst_gp:1] [src_xmm:1]
		a.movzx(ecx, byte_ptr(rsi));
		a.movzx(edx, byte_ptr(rsi, 1));
		a.add(rsi, 2);
		a.shl(rdx, 4);
		a.add(rdx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
		a.movups(xmm0, xmmword_ptr(rbx, rdx));
		if (op == vm_op::VM_MOVD_REG_XMM)
			a.movd(eax, xmm0);
		else
			a.movq(rax, xmm0);
		a.shl(rcx, 3);
		a.mov(qword_ptr(rbx, rcx), rax);
	}
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_sse_pinsr_pextr_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);
	// Format: [opcode] [xmm_or_gp:1] [gp_or_xmm:1] [imm8:1]
	a.movzx(ecx, byte_ptr(rsi));
	a.movzx(edx, byte_ptr(rsi, 1));
	a.movzx(r8d, byte_ptr(rsi, 2));
	a.add(rsi, 3);

	bool is_insert = (op == vm_op::VM_PINSRB_REG_REG_IMM || op == vm_op::VM_PINSRD_REG_REG_IMM ||
		op == vm_op::VM_PINSRQ_REG_REG_IMM);

	if (is_insert) {
		a.shl(rcx, 4);
		a.add(rcx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
		a.movups(xmm0, xmmword_ptr(rbx, rcx));
		a.shl(rdx, 3);
		a.mov(rax, qword_ptr(rbx, rdx));
		{
			Label done = a.newLabel();
			Label tbl[256];
			for (int i = 0; i < 256; i++) tbl[i] = a.newLabel();
			for (int i = 0; i < 256; i++) { a.cmp(r8d, i); a.je(tbl[i]); }
			a.jmp(done);
			for (int i = 0; i < 256; i++) {
				a.bind(tbl[i]);
				switch (op) {
				case vm_op::VM_PINSRB_REG_REG_IMM: a.emit(x86::Inst::kIdPinsrb, xmm0, eax, Imm(i)); break;
				case vm_op::VM_PINSRD_REG_REG_IMM: a.emit(x86::Inst::kIdPinsrd, xmm0, eax, Imm(i)); break;
				case vm_op::VM_PINSRQ_REG_REG_IMM: a.emit(x86::Inst::kIdPinsrq, xmm0, rax, Imm(i)); break;
				default: break;
				}
				a.jmp(done);
			}
			a.bind(done);
		}
		a.movups(xmmword_ptr(rbx, rcx), xmm0);
	} else {
		a.shl(rdx, 4);
		a.add(rdx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
		a.movups(xmm0, xmmword_ptr(rbx, rdx));
		{
			Label done = a.newLabel();
			Label tbl[256];
			for (int i = 0; i < 256; i++) tbl[i] = a.newLabel();
			for (int i = 0; i < 256; i++) { a.cmp(r8d, i); a.je(tbl[i]); }
			a.jmp(done);
			for (int i = 0; i < 256; i++) {
				a.bind(tbl[i]);
				switch (op) {
				case vm_op::VM_PEXTRB_REG_REG_IMM: a.emit(x86::Inst::kIdPextrb, eax, xmm0, Imm(i)); break;
				case vm_op::VM_PEXTRD_REG_REG_IMM: a.emit(x86::Inst::kIdPextrd, eax, xmm0, Imm(i)); break;
				case vm_op::VM_PEXTRQ_REG_REG_IMM: a.emit(x86::Inst::kIdPextrq, rax, xmm0, Imm(i)); break;
				default: break;
				}
				a.jmp(done);
			}
			a.bind(done);
		}
		a.shl(rcx, 3);
		a.mov(qword_ptr(rbx, rcx), rax);
	}
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_sse_round_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);
	// Format: [opcode] [dst_xmm:1] [src_xmm:1] [imm8:1]
	a.movzx(ecx, byte_ptr(rsi));
	a.movzx(edx, byte_ptr(rsi, 1));
	a.movzx(r8d, byte_ptr(rsi, 2));
	a.add(rsi, 3);
	a.shl(rcx, 4);
	a.add(rcx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
	a.shl(rdx, 4);
	a.add(rdx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
	a.movups(xmm0, xmmword_ptr(rbx, rcx));
	a.movups(xmm1, xmmword_ptr(rbx, rdx));
	{
		Label done = a.newLabel();
		Label tbl[16];
		for (int i = 0; i < 16; i++) tbl[i] = a.newLabel();
		for (int i = 0; i < 16; i++) { a.cmp(r8d, i); a.je(tbl[i]); }
		a.jmp(done);
		for (int i = 0; i < 16; i++) {
			a.bind(tbl[i]);
			if (op == vm_op::VM_ROUNDSS_REG_REG_IMM)
				a.emit(x86::Inst::kIdRoundss, xmm0, xmm1, Imm(i));
			else
				a.emit(x86::Inst::kIdRoundsd, xmm0, xmm1, Imm(i));
			a.jmp(done);
		}
		a.bind(done);
	}
	a.movups(xmmword_ptr(rbx, rcx), xmm0);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_sse_ptest_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_PTEST_REG_REG)]);
	a.movzx(ecx, byte_ptr(rsi));
	a.movzx(edx, byte_ptr(rsi, 1));
	a.add(rsi, 2);
	a.shl(rcx, 4);
	a.add(rcx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
	a.shl(rdx, 4);
	a.add(rdx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
	a.movups(xmm0, xmmword_ptr(rbx, rcx));
	a.movups(xmm1, xmmword_ptr(rbx, rdx));
	a.emit(x86::Inst::kIdPtest, xmm0, xmm1);
	a.pushfq();
	a.pop(r9);
	a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_sse_movhilo_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);

	bool is_rr = (op == vm_op::VM_MOVHLPS_REG_REG || op == vm_op::VM_MOVLHPS_REG_REG);
	bool is_store = (op == vm_op::VM_MOVHPS_MEM_REG || op == vm_op::VM_MOVLPS_MEM_REG ||
		op == vm_op::VM_MOVHPD_MEM_REG || op == vm_op::VM_MOVLPD_MEM_REG);

	if (is_rr) {
		a.movzx(ecx, byte_ptr(rsi));
		a.movzx(edx, byte_ptr(rsi, 1));
		a.add(rsi, 2);
		a.shl(rcx, 4);
		a.add(rcx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
		a.shl(rdx, 4);
		a.add(rdx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
		a.movups(xmm0, xmmword_ptr(rbx, rcx));
		a.movups(xmm1, xmmword_ptr(rbx, rdx));
		if (op == vm_op::VM_MOVHLPS_REG_REG)
			a.movhlps(xmm0, xmm1);
		else
			a.movlhps(xmm0, xmm1);
		a.movups(xmmword_ptr(rbx, rcx), xmm0);
	} else if (is_store) {
		// Format: [opcode] [base_gp:1] [disp:4] [src_xmm:1]
		a.movzx(ecx, byte_ptr(rsi));
		a.movsxd(rdx, dword_ptr(rsi, 1));
		a.movzx(r8d, byte_ptr(rsi, 5));
		a.add(rsi, 6);
		a.shl(rcx, 3);
		a.mov(rax, qword_ptr(rbx, rcx));
		a.add(rax, rdx);
		a.shl(r8, 4);
		a.add(r8, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
		a.movups(xmm0, xmmword_ptr(rbx, r8));
		if (op == vm_op::VM_MOVHPS_MEM_REG || op == vm_op::VM_MOVHPD_MEM_REG)
			a.movhps(qword_ptr(rax), xmm0);
		else
			a.movlps(qword_ptr(rax), xmm0);
	} else {
		// Load: [opcode] [dst_xmm:1] [base_gp:1] [disp:4]
		a.movzx(ecx, byte_ptr(rsi));
		a.movzx(edx, byte_ptr(rsi, 1));
		a.movsxd(r8, dword_ptr(rsi, 2));
		a.add(rsi, 6);
		a.shl(rcx, 4);
		a.add(rcx, vm_xmm_offset(static_cast<int>(vm_reg::VXMM0)));
		a.movups(xmm0, xmmword_ptr(rbx, rcx));
		a.shl(rdx, 3);
		a.mov(rax, qword_ptr(rbx, rdx));
		a.add(rax, r8);
		if (op == vm_op::VM_MOVHPS_REG_MEM || op == vm_op::VM_MOVHPD_REG_MEM)
			a.movhps(xmm0, qword_ptr(rax));
		else
			a.movlps(xmm0, qword_ptr(rax));
		a.movups(xmmword_ptr(rbx, rcx), xmm0);
	}
	a.jmp(labels.dispatch_loop);
}

// === LOCK / ATOMIC HANDLERS ===

void vm_dispatcher::emit_cmpxchg_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_CMPXCHG_MEM_REG)]);
	// Format: [opcode] [base_gp:1] [disp:4] [src_gp:1] [size:1]
	a.movzx(ecx, byte_ptr(rsi));
	a.movsxd(rdx, dword_ptr(rsi, 1));
	a.movzx(r8d, byte_ptr(rsi, 5));
	a.movzx(r9d, byte_ptr(rsi, 6));
	a.add(rsi, 7);
	a.shl(rcx, 3);
	a.mov(rax, qword_ptr(rbx, rcx));
	a.add(rax, rdx); // rax = memory address
	a.shl(r8, 3);
	a.mov(r10, qword_ptr(rbx, r8)); // r10 = src reg value
	a.mov(rcx, qword_ptr(rbx, table.perm_gp_off(vm_reg::VRAX))); // rcx = comparand (RAX)
	a.push(rax); // save addr
	a.mov(rax, rcx); // rax = comparand for cmpxchg
	a.mov(rcx, r10);
	a.lock().cmpxchg(qword_ptr(rax), rcx);
	// Note: simplified to 64-bit. Real impl would check size.
	a.pop(rcx); // discard saved addr
	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VRAX)), rax);
	a.pushfq();
	a.pop(r9);
	a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_lock_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);

	bool is_unary = (op == vm_op::VM_LOCK_INC_MEM || op == vm_op::VM_LOCK_DEC_MEM);
	bool has_imm = (op == vm_op::VM_LOCK_ADD_MEM_IMM || op == vm_op::VM_LOCK_SUB_MEM_IMM ||
		op == vm_op::VM_LOCK_AND_MEM_IMM || op == vm_op::VM_LOCK_OR_MEM_IMM ||
		op == vm_op::VM_LOCK_XOR_MEM_IMM);

	if (is_unary) {
		// Format: [opcode] [base_gp:1] [disp:4]
		a.movzx(ecx, byte_ptr(rsi));
		a.movsxd(rdx, dword_ptr(rsi, 1));
		a.add(rsi, 5);
		a.shl(rcx, 3);
		a.mov(rax, qword_ptr(rbx, rcx));
		a.add(rax, rdx);
		if (op == vm_op::VM_LOCK_INC_MEM)
			a.lock().inc(qword_ptr(rax));
		else
			a.lock().dec(qword_ptr(rax));
	} else if (has_imm) {
		// Format: [opcode] [base_gp:1] [disp:4] [imm:4]
		a.movzx(ecx, byte_ptr(rsi));
		a.movsxd(rdx, dword_ptr(rsi, 1));
		a.movsxd(r8, dword_ptr(rsi, 5));
		a.add(rsi, 9);
		a.shl(rcx, 3);
		a.mov(rax, qword_ptr(rbx, rcx));
		a.add(rax, rdx);
		switch (op) {
		case vm_op::VM_LOCK_ADD_MEM_IMM: a.lock().add(qword_ptr(rax), r8d); break;
		case vm_op::VM_LOCK_SUB_MEM_IMM: a.lock().sub(qword_ptr(rax), r8d); break;
		case vm_op::VM_LOCK_AND_MEM_IMM: a.lock().and_(qword_ptr(rax), r8d); break;
		case vm_op::VM_LOCK_OR_MEM_IMM:  a.lock().or_(qword_ptr(rax), r8d); break;
		case vm_op::VM_LOCK_XOR_MEM_IMM: a.lock().xor_(qword_ptr(rax), r8d); break;
		default: break;
		}
	} else {
		// Format: [opcode] [base_gp:1] [disp:4] [src_gp:1]
		a.movzx(ecx, byte_ptr(rsi));
		a.movsxd(rdx, dword_ptr(rsi, 1));
		a.movzx(r8d, byte_ptr(rsi, 5));
		a.add(rsi, 6);
		a.shl(rcx, 3);
		a.mov(rax, qword_ptr(rbx, rcx));
		a.add(rax, rdx);
		a.shl(r8, 3);
		a.mov(r10, qword_ptr(rbx, r8));
		switch (op) {
		case vm_op::VM_LOCK_XADD_MEM_REG: a.lock().xadd(qword_ptr(rax), r10); a.mov(qword_ptr(rbx, r8), r10); break;
		case vm_op::VM_LOCK_ADD_MEM_REG: a.lock().add(qword_ptr(rax), r10); break;
		case vm_op::VM_LOCK_SUB_MEM_REG: a.lock().sub(qword_ptr(rax), r10); break;
		case vm_op::VM_LOCK_AND_MEM_REG: a.lock().and_(qword_ptr(rax), r10); break;
		case vm_op::VM_LOCK_OR_MEM_REG:  a.lock().or_(qword_ptr(rax), r10); break;
		case vm_op::VM_LOCK_XOR_MEM_REG: a.lock().xor_(qword_ptr(rax), r10); break;
		default: break;
		}
	}
	a.pushfq();
	a.pop(r9);
	a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
	a.jmp(labels.dispatch_loop);
}

// === MISC HANDLERS ===

void vm_dispatcher::emit_cpuid_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_CPUID)]);
	a.mov(eax, dword_ptr(rbx, table.perm_gp_off(vm_reg::VRAX)));
	a.mov(ecx, dword_ptr(rbx, table.perm_gp_off(vm_reg::VRCX)));
	a.cpuid();
	a.mov(dword_ptr(rbx, table.perm_gp_off(vm_reg::VRAX)), eax);
	a.mov(dword_ptr(rbx, table.perm_gp_off(vm_reg::VRBX)), ebx);
	a.mov(dword_ptr(rbx, table.perm_gp_off(vm_reg::VRCX)), ecx);
	a.mov(dword_ptr(rbx, table.perm_gp_off(vm_reg::VRDX)), edx);
	// Restore RBX (we clobbered it with cpuid)
	a.mov(rbx, rsp);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_rdtsc_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_RDTSC)]);
	a.rdtsc();
	a.mov(dword_ptr(rbx, table.perm_gp_off(vm_reg::VRAX)), eax);
	a.mov(dword_ptr(rbx, table.perm_gp_off(vm_reg::VRDX)), edx);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_fence_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);
	switch (op) {
	case vm_op::VM_PAUSE:  a.pause(); break;
	case vm_op::VM_MFENCE: a.mfence(); break;
	case vm_op::VM_LFENCE: a.lfence(); break;
	case vm_op::VM_SFENCE: a.sfence(); break;
	default: break;
	}
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_flag_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);
	a.push(qword_ptr(rbx, VRFLAGS_OFF));
	a.popfq();
	switch (op) {
	case vm_op::VM_CLC: a.clc(); break;
	case vm_op::VM_STC: a.stc(); break;
	case vm_op::VM_CMC: a.cmc(); break;
	default: break;
	}
	a.pushfq();
	a.pop(r9);
	a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_enter_frame_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_ENTER_FRAME)]);
	// Format: [opcode] [imm16:2]
	a.movzx(ecx, word_ptr(rsi));
	a.add(rsi, 2);
	// ENTER imm16,0: push rbp; mov rbp,rsp; sub rsp,imm16
	a.mov(rdi, qword_ptr(rbx, table.perm_gp_off(vm_reg::VRSP)));
	a.sub(rdi, 8);
	a.mov(rax, qword_ptr(rbx, table.perm_gp_off(vm_reg::VRBP)));
	a.mov(qword_ptr(rdi), rax);
	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VRBP)), rdi);
	a.sub(rdi, rcx);
	a.mov(qword_ptr(rbx, table.perm_gp_off(vm_reg::VRSP)), rdi);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_movbe_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);
	// Format: [opcode] [reg_or_base:1] [disp:4]  (for load: dst_gp, base_gp; for store: base_gp, src_gp... reuse)
	a.movzx(ecx, byte_ptr(rsi));
	a.movzx(edx, byte_ptr(rsi, 1));
	a.movsxd(r8, dword_ptr(rsi, 2));
	a.add(rsi, 6);
	if (op == vm_op::VM_MOVBE_REG_MEM) {
		a.shl(rdx, 3);
		a.mov(rax, qword_ptr(rbx, rdx));
		a.add(rax, r8);
		a.movbe(r9, qword_ptr(rax));
		a.shl(rcx, 3);
		a.mov(qword_ptr(rbx, rcx), r9);
	} else {
		a.shl(rcx, 3);
		a.mov(rax, qword_ptr(rbx, rcx));
		a.add(rax, r8);
		a.shl(rdx, 3);
		a.mov(r9, qword_ptr(rbx, rdx));
		a.movbe(qword_ptr(rax), r9);
	}
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_crc32_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_CRC32_REG_REG)]);
	// Format: [opcode] [dst:1] [src:1]
	a.movzx(ecx, byte_ptr(rsi));
	a.movzx(edx, byte_ptr(rsi, 1));
	a.add(rsi, 2);
	a.shl(rcx, 3);
	a.shl(rdx, 3);
	a.mov(eax, dword_ptr(rbx, rcx));
	a.mov(r8, qword_ptr(rbx, rdx));
	a.crc32(eax, r8d);
	a.mov(qword_ptr(rbx, rcx), rax);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_bmi_handler(x86::Assembler& a, handler_labels& labels, vm_op op) {
	a.bind(labels.handlers[static_cast<int>(op)]);

	bool is_three_op = (op == vm_op::VM_ANDN_REG_REG_REG || op == vm_op::VM_BEXTR_REG_REG_REG ||
		op == vm_op::VM_PDEP_REG_REG_REG || op == vm_op::VM_PEXT_REG_REG_REG ||
		op == vm_op::VM_BZHI_REG_REG_REG ||
		op == vm_op::VM_SARX_REG_REG_REG || op == vm_op::VM_SHLX_REG_REG_REG ||
		op == vm_op::VM_SHRX_REG_REG_REG);
	bool is_two_op = (op == vm_op::VM_BLSI_REG_REG || op == vm_op::VM_BLSMSK_REG_REG ||
		op == vm_op::VM_BLSR_REG_REG);

	if (is_three_op) {
		// Format: [opcode] [dst:1] [src1:1] [src2:1]
		a.movzx(ecx, byte_ptr(rsi));
		a.movzx(edx, byte_ptr(rsi, 1));
		a.movzx(r8d, byte_ptr(rsi, 2));
		a.add(rsi, 3);
		a.shl(rdx, 3);
		a.shl(r8, 3);
		a.mov(rax, qword_ptr(rbx, rdx));
		a.mov(r9, qword_ptr(rbx, r8));
		switch (op) {
		case vm_op::VM_ANDN_REG_REG_REG:  a.andn(rax, rax, r9); break;
		case vm_op::VM_BEXTR_REG_REG_REG: a.bextr(rax, rax, r9); break;
		case vm_op::VM_PDEP_REG_REG_REG:  a.pdep(rax, rax, r9); break;
		case vm_op::VM_PEXT_REG_REG_REG:  a.pext(rax, rax, r9); break;
		case vm_op::VM_BZHI_REG_REG_REG:  a.bzhi(rax, rax, r9); break;
		case vm_op::VM_SARX_REG_REG_REG:  a.sarx(rax, rax, r9); break;
		case vm_op::VM_SHLX_REG_REG_REG:  a.shlx(rax, rax, r9); break;
		case vm_op::VM_SHRX_REG_REG_REG:  a.shrx(rax, rax, r9); break;
		default: break;
		}
		a.shl(rcx, 3);
		a.mov(qword_ptr(rbx, rcx), rax);
	} else {
		// Format: [opcode] [dst:1] [src:1]
		a.movzx(ecx, byte_ptr(rsi));
		a.movzx(edx, byte_ptr(rsi, 1));
		a.add(rsi, 2);
		a.shl(rdx, 3);
		a.mov(rax, qword_ptr(rbx, rdx));
		switch (op) {
		case vm_op::VM_BLSI_REG_REG:   a.blsi(rax, rax); break;
		case vm_op::VM_BLSMSK_REG_REG: a.blsmsk(rax, rax); break;
		case vm_op::VM_BLSR_REG_REG:   a.blsr(rax, rax); break;
		default: break;
		}
		a.shl(rcx, 3);
		a.mov(qword_ptr(rbx, rcx), rax);
	}
	a.pushfq();
	a.pop(r9);
	a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
	a.jmp(labels.dispatch_loop);
}

void vm_dispatcher::emit_exit_handler(x86::Assembler& a, handler_labels& labels) {
	a.bind(labels.handlers[static_cast<int>(vm_op::VM_EXIT)]);
	a.bind(labels.exit_label);

	if (nested_mode) {
		// Inner VM exit: just return to outer VM's VM_NEST_ENTER handler
		a.ret();
		return;
	}

	// Restore XMM registers
	for (int i = 0; i < 16; i++) {
		int off = vm_xmm_offset(static_cast<int>(vm_reg::VXMM0) + i);
		a.movups(x86::Xmm(i), xmmword_ptr(rbx, off));
	}

	// Restore GP registers from VM context
	a.mov(rax, qword_ptr(rbx, table.perm_gp_off(vm_reg::VRAX)));
	a.mov(rcx, qword_ptr(rbx, table.perm_gp_off(vm_reg::VRCX)));
	a.mov(rdx, qword_ptr(rbx, table.perm_gp_off(vm_reg::VRDX)));
	a.mov(r8, qword_ptr(rbx, table.perm_gp_off(vm_reg::VR8)));
	a.mov(r9, qword_ptr(rbx, table.perm_gp_off(vm_reg::VR9)));
	a.mov(r10, qword_ptr(rbx, table.perm_gp_off(vm_reg::VR10)));
	a.mov(r11, qword_ptr(rbx, table.perm_gp_off(vm_reg::VR11)));

	// Restore RFLAGS
	a.push(qword_ptr(rbx, VRFLAGS_OFF));
	a.popfq();

	// Deallocate VM register file
	a.add(rsp, VM_REG_FILE_ALLOC);

	// Restore callee-saved registers (reverse order of push)
	a.pop(rdi);
	a.pop(rsi);
	a.add(rsp, 8); // skip pushfq slot
	a.pop(r15);
	a.pop(r14);
	a.pop(r13);
	a.pop(r12);
	a.pop(rbp);
	a.pop(rbx);

	a.ret();
}

// --- Opaque predicates ---
// These insert conditional jumps that always go one way at runtime,
// but static analysis cannot prove which branch is taken.
// The "dead" branch contains junk code to confuse disassemblers.

void vm_dispatcher::emit_junk_block(x86::Assembler& a) {
	// Emit plausible-looking but dead code
	uint32_t variant = opaque_rng() % 12;
	switch (variant) {
	case 0:
		a.xor_(rax, rdx);
		a.ror(rax, 13);
		a.add(rax, 0x41424344);
		a.mov(qword_ptr(rbx, 0x10), rax);
		break;
	case 1:
		a.mov(rcx, rsi);
		a.shl(rcx, 4);
		a.sub(rcx, rdi);
		a.xor_(rcx, 0xDEAD);
		break;
	case 2:
		a.lea(rax, qword_ptr(rbx, 0x38));
		a.mov(rdx, qword_ptr(rax));
		a.imul(rdx, 7);
		a.mov(qword_ptr(rax), rdx);
		break;
	case 3:
		a.push(rax);
		a.mov(rax, rsi);
		a.not_(rax);
		a.and_(rax, 0xFF);
		a.pop(rax);
		break;
	case 4:
		a.movzx(eax, byte_ptr(rsi));
		a.add(rax, 0x1337);
		a.xor_(rax, rbx);
		a.bswap(rax);
		break;
	case 5:
		a.mov(rax, rbx);
		a.sub(rax, rsi);
		a.sar(rax, 3);
		a.add(rax, 1);
		a.shl(rax, 3);
		break;
	case 6:
		a.mov(rcx, 0x55AA55AA);
		a.xor_(rcx, rax);
		a.rol(rcx, 7);
		a.test(rcx, rcx);
		break;
	case 7:
		a.mov(rdx, qword_ptr(rbx));
		a.xor_(rdx, qword_ptr(rbx, 8));
		a.and_(rdx, qword_ptr(rbx, 16));
		a.or_(rdx, 1);
		break;
	// New: MBA-looking dead blocks that confuse pattern matching
	case 8: {
		// Looks like x+y = (x^y) + 2*(x&y) computation
		a.mov(r10, rax);
		a.mov(r11, rax);
		a.xor_(r10, rdx);
		a.and_(r11, rdx);
		a.shl(r11, 1);
		a.lea(rax, qword_ptr(r10, r11));
		a.imul(rax, rax, 0x45d9f3b);
		break;
	}
	case 9: {
		// Looks like x-y = (x&~y) - (~x&y)
		a.mov(r10, rcx);
		a.not_(r10);
		a.and_(r10, rdx);
		a.mov(r11, rcx);
		a.mov(rcx, rdx);
		a.not_(rcx);
		a.and_(r11, rcx);
		a.sub(r11, r10);
		break;
	}
	case 10: {
		// Looks like handler dispatch code
		a.movzx(eax, byte_ptr(rsi));
		a.imul(eax, eax, 8);
		a.mov(r10, qword_ptr(rbx, rax));
		a.xor_(r10, r12);
		a.ror(r10, 13);
		break;
	}
	case 11: {
		// Hash mixing like Murmur/FNV
		a.mov(r10d, eax);
		a.imul(r10d, r10d, 0x1b873593);
		a.rol(r10d, 15);
		a.imul(r10d, r10d, 0xcc9e2d51);
		a.xor_(r10d, edx);
		break;
	}
	}
}

void vm_dispatcher::emit_opaque_predicate(x86::Assembler& a, handler_labels& labels) {
	Label real_path = a.newLabel();
	Label dead_path = a.newLabel();

	uint32_t variant = opaque_rng() % 6;

	switch (variant) {
	case 0:
		// x*(x+1) is always even → (x*(x+1)) & 1 == 0 always true
		// Use RSI (bytecode pointer) as x — always a valid address
		a.mov(rax, rsi);
		a.lea(rdx, qword_ptr(rax, 1));
		a.imul(rax, rdx);
		a.test(al, 1);
		a.jnz(dead_path); // never taken
		a.jmp(real_path);
		break;

	case 1:
		// x^2 + 1 > 0 for all integers (in unsigned sense, x^2+1 != 0)
		a.mov(rax, rbx);
		a.and_(rax, 0xFF);
		a.imul(rax, rax);
		a.inc(rax);
		a.test(rax, rax);
		a.jz(dead_path); // never taken (x^2+1 is never 0 for 8-bit values)
		a.jmp(real_path);
		break;

	case 2:
		// (x | 1) is always odd → & 1 == 1 always true
		a.mov(rax, rsi);
		a.or_(rax, 1);
		a.test(al, 1);
		a.jz(dead_path); // never taken
		a.jmp(real_path);
		break;

	case 3:
		// (x & ~x) == 0 always
		a.mov(rax, rbx);
		a.mov(rdx, rax);
		a.not_(rdx);
		a.and_(rax, rdx);
		a.test(rax, rax);
		a.jnz(dead_path); // never taken
		a.jmp(real_path);
		break;

	case 4:
		// x ^ x == 0 always, disguised with extra ops
		a.mov(rax, rsi);
		a.ror(rax, 13);
		a.mov(rdx, rsi);
		a.ror(rdx, 13);
		a.xor_(rax, rdx);
		a.test(rax, rax);
		a.jnz(dead_path); // never taken
		a.jmp(real_path);
		break;

	case 5:
		// 2*(x/2) <= x always (integer division rounds down)
		// So x - 2*(x/2) >= 0, and specifically it's 0 or 1
		// Therefore x - 2*(x/2) < 2 always
		a.mov(rax, rsi);
		a.and_(rax, 0xFFFF);
		a.mov(rdx, rax);
		a.shr(rdx, 1);
		a.add(rdx, rdx);
		a.sub(rax, rdx); // rax = x mod 2 = 0 or 1
		a.cmp(rax, 2);
		a.jge(dead_path); // never taken
		a.jmp(real_path);
		break;
	}

	// Dead path: junk code, then jump to real path to keep code valid
	a.bind(dead_path);
	emit_junk_block(a);
	emit_junk_block(a);
	a.jmp(real_path);

	a.bind(real_path);
}

void vm_dispatcher::maybe_emit_opaque(x86::Assembler& a, handler_labels& labels) {
	int pct = (settings ? settings->opaque_predicate_pct * 3 : 30);
	if ((opaque_rng() % 100) < pct)
		emit_opaque_predicate(a, labels);
}

void vm_dispatcher::emit_chain_dispatch(x86::Assembler& a, handler_labels& labels) {
	int chain_pct = (settings ? settings->chain_pct : 30);
	if ((opaque_rng() % 100) < chain_pct) {
		if (settings && settings->context_dependent_decoding) {
			a.mov(edx, esi);
			a.sub(edx, r13d);
			a.imul(edx, edx, 0x45D9F3B);
			a.add(edx, Imm(static_cast<int32_t>(context_seed)));
			a.mov(r10d, edx);
			a.shr(r10d, 16);
			a.xor_(edx, r10d);
			a.imul(edx, edx, Imm(static_cast<int32_t>(0x85EBCA6Bu)));
			a.mov(r10d, edx);
			a.shr(r10d, 13);
			a.xor_(edx, r10d);
			a.shr(edx, 16);
			a.movzx(eax, word_ptr(rsi));
			a.xor_(eax, edx);
			a.and_(eax, 0xFFFF);
			a.add(rsi, 2);
		} else {
			a.movzx(eax, word_ptr(rsi));
			a.add(rsi, 2);
		}
		a.cmp(eax, Imm(vm_opcode_table::TOTAL_ENCODED));
		a.jae(labels.dispatch_loop);

		int n = 2 + (opaque_rng() % 2);
		for (int i = 0; i < n; i++) {
			int idx = opaque_rng() % static_cast<int>(vm_op::VM_COUNT);
			uint16_t enc = table.encode(static_cast<vm_op>(idx));
			a.cmp(ax, Imm(enc));
			a.je(labels.handlers[idx]);
		}
		a.jmp(labels.dispatch_continue);
	} else {
		a.jmp(labels.dispatch_loop);
	}
}

void vm_dispatcher::emit_handler_entry_junk(x86::Assembler& a) {
	int junk_pct = (settings ? settings->junk_frequency : 25);
	if ((opaque_rng() % 100) >= junk_pct)
		return;

	int count = 2 + (opaque_rng() % 4); // 2-5 dead instructions
	for (int i = 0; i < count; i++) {
		uint32_t v = opaque_rng() % 16;
		uint32_t imm = opaque_rng();
		switch (v) {
		case 0:  a.xor_(eax, eax); break;
		case 1:  a.mov(eax, Imm(static_cast<int32_t>(imm))); break;
		case 2:  a.mov(ecx, Imm(static_cast<int32_t>(imm))); a.ror(ecx, static_cast<int>(imm & 15)); break;
		case 3:  a.lea(rax, qword_ptr(rsi, static_cast<int32_t>(imm & 0x7F))); break;
		case 4:  a.mov(edx, Imm(static_cast<int32_t>(imm))); a.not_(edx); break;
		case 5:  a.test(rax, rax); break;
		case 6:  a.bswap(eax); break;
		case 7:  a.mov(ecx, eax); a.xor_(ecx, edx); break;
		case 8:  a.push(rax); a.pop(rax); break;
		case 9:  a.lea(rdx, qword_ptr(rax, static_cast<int32_t>(imm & 0xFF))); break;
		case 10: a.mov(eax, Imm(static_cast<int32_t>(imm))); a.and_(eax, 0xFF); break;
		case 11: a.mov(rcx, rax); a.sub(rcx, rdx); break;
		// New: MBA-style junk that looks like real computation
		case 12: {
			// x ^ y + 2*(x & y) = x + y pattern (dead code)
			a.mov(r10, rax);
			a.mov(r11, rax);
			a.xor_(r10, rdx);
			a.and_(r11, rdx);
			a.shl(r11, 1);
			a.add(r10, r11);
			break;
		}
		case 13: {
			// ~(~x | ~y) = x & y pattern (dead code)
			a.mov(r10, rax);
			a.mov(r11, rdx);
			a.not_(r10);
			a.not_(r11);
			a.or_(r10, r11);
			a.not_(r10);
			break;
		}
		case 14: {
			// (x | y) - (x & y) = x ^ y pattern (dead code)
			a.mov(r10, rsi);
			a.mov(r11, rsi);
			a.or_(r10, rbx);
			a.and_(r11, rbx);
			a.sub(r10, r11);
			break;
		}
		case 15: {
			// Hash-like dead computation
			a.mov(r10d, Imm(static_cast<int32_t>(imm)));
			a.imul(r10d, r10d, 0x45d9f3b);
			a.xor_(r10d, Imm(static_cast<int32_t>(imm >> 16)));
			a.ror(r10d, 7);
			break;
		}
		}
	}

	// Inline opaque predicate inside handler entry (harder to pattern-match)
	int opaque_inline_pct = (settings ? settings->opaque_predicate_pct * 2 : 10);
	if ((opaque_rng() % 100) < opaque_inline_pct) {
		Label skip_dead = a.newLabel();
		Label dead_block = a.newLabel();
		uint32_t op_var = opaque_rng() % 4;
		switch (op_var) {
		case 0:
			// (rsi | 1) is always odd
			a.mov(r10, rsi);
			a.or_(r10, 1);
			a.test(r10b, 1);
			a.jz(dead_block);
			break;
		case 1:
			// x & ~x == 0 always
			a.mov(r10, rbx);
			a.mov(r11, rbx);
			a.not_(r11);
			a.and_(r10, r11);
			a.test(r10, r10);
			a.jnz(dead_block);
			break;
		case 2:
			// (x ^ x) == 0 always
			a.mov(r10, r13);
			a.xor_(r10, r13);
			a.test(r10, r10);
			a.jnz(dead_block);
			break;
		case 3:
			// x*(x+1) always even
			a.mov(r10, rsi);
			a.lea(r11, qword_ptr(r10, 1));
			a.imul(r10, r11);
			a.test(r10b, 1);
			a.jnz(dead_block);
			break;
		}
		a.jmp(skip_dead);
		a.bind(dead_block);
		// Dead code with MBA-looking patterns
		emit_junk_block(a);
		a.jmp(skip_dead);
		a.bind(skip_dead);
	}
}

void vm_dispatcher::emit_poly_index_to_offset(x86::Assembler& a, const x86::Gp& reg) {
	// reg * 8 — polymorphic alternatives to shl reg, 3
	uint32_t v = opaque_rng() % 4;
	switch (v) {
	case 0: a.shl(reg, 3); break;
	case 1: a.imul(reg, reg, 8); break;
	case 2: a.lea(reg, x86::ptr(0, reg, 3)); break;
	case 3: a.add(reg, reg); a.add(reg, reg); a.add(reg, reg); break;
	}
}

void vm_dispatcher::emit_poly_advance_ip(x86::Assembler& a, int n) {
	// rsi += n — polymorphic alternatives to add rsi, n
	uint32_t v = opaque_rng() % 3;
	switch (v) {
	case 0: if (n == 1) a.inc(rsi); else a.add(rsi, n); break;
	case 1: a.lea(rsi, qword_ptr(rsi, n)); break;
	case 2: a.sub(rsi, -n); break;
	}
}

void vm_dispatcher::emit_dup_trampoline(x86::Assembler& a, Label& dup_label, Label& original_label) {
	a.bind(dup_label);
	emit_junk_block(a);
	emit_junk_block(a);
	if ((opaque_rng() % 2) == 0)
		emit_junk_block(a);
	a.jmp(original_label);
}

void vm_dispatcher::emit_dup_handler_body(x86::Assembler& a, handler_labels& labels,
	Label& dup_label, vm_op original_op, int variant) {

	a.bind(dup_label);

	auto mul8 = [&](const x86::Gp& r64) {
		if (variant == 0)
			a.imul(r64, r64, 8);
		else
			a.lea(r64, x86::ptr(0, r64, 3));
	};

	auto adv = [&](int n) {
		if (variant == 0)
			a.lea(rsi, x86::ptr(rsi, n));
		else
			a.add(rsi, n);
	};

	auto adv1 = [&]() {
		if (variant == 0)
			a.add(rsi, 1);
		else
			a.lea(rsi, x86::ptr(rsi, 1));
	};

	auto dead = [&]() {
		auto& r = (opaque_rng() % 2) ? r10 : r11;
		switch (opaque_rng() % 4) {
		case 0: a.mov(r, Imm(opaque_rng())); break;
		case 1: a.lea(r, x86::ptr(r, 1)); break;
		case 2: a.lea(r, x86::ptr(r, -1)); break;
		case 3: a.mov(r, rbx); break;
		}
	};

	switch (original_op) {

	case vm_op::VM_MOV_REG_IMM64: {
		dead();
		a.movzx(ecx, byte_ptr(rsi));
		adv1();
		a.mov(rax, qword_ptr(rsi));
		a.xor_(rax, r12);
		adv(8);
		dead();
		mul8(rcx);
		a.mov(qword_ptr(rbx, rcx), rax);
		emit_chain_dispatch(a, labels);
		break;
	}

	case vm_op::VM_MOV_REG_REG: {
		dead();
		a.movzx(ecx, byte_ptr(rsi));
		a.movzx(edx, byte_ptr(rsi, 1));
		adv(2);
		mul8(rcx);
		mul8(rdx);
		dead();
		a.mov(rax, qword_ptr(rbx, rdx));
		a.mov(qword_ptr(rbx, rcx), rax);
		emit_chain_dispatch(a, labels);
		break;
	}

	case vm_op::VM_MOV_REG_MEM: {
		dead();
		a.movzx(ecx, byte_ptr(rsi));
		a.movzx(edx, byte_ptr(rsi, 1));
		a.movsxd(r8, dword_ptr(rsi, 2));
		a.movzx(r9d, byte_ptr(rsi, 6));
		adv(7);

		Label has_base = a.newLabel(), addr_ready = a.newLabel();
		a.cmp(dl, 0xFF);
		a.jne(has_base);
		a.mov(rax, r8);
		a.jmp(addr_ready);
		a.bind(has_base);
		mul8(rdx);
		a.mov(rax, qword_ptr(rbx, rdx));
		a.add(rax, r8);
		a.bind(addr_ready);

		Label sz8 = a.newLabel(), sz4 = a.newLabel(), sz2 = a.newLabel(), sz1 = a.newLabel(), done = a.newLabel();
		a.cmp(r9b, 8);
		a.je(sz8);
		a.cmp(r9b, 4);
		a.je(sz4);
		a.cmp(r9b, 2);
		a.je(sz2);
		a.bind(sz1);
		a.movzx(eax, byte_ptr(rax));
		a.jmp(done);
		a.bind(sz2);
		a.movzx(eax, word_ptr(rax));
		a.jmp(done);
		a.bind(sz4);
		a.mov(eax, dword_ptr(rax));
		a.jmp(done);
		a.bind(sz8);
		a.mov(rax, qword_ptr(rax));
		a.bind(done);

		dead();
		mul8(rcx);
		a.mov(qword_ptr(rbx, rcx), rax);
		a.jmp(labels.dispatch_loop);
		break;
	}

	case vm_op::VM_MOV_MEM_REG: {
		dead();
		a.movzx(ecx, byte_ptr(rsi));
		a.movsxd(rdx, dword_ptr(rsi, 1));
		a.movzx(r8d, byte_ptr(rsi, 5));
		a.movzx(r9d, byte_ptr(rsi, 6));
		adv(7);

		Label has_base = a.newLabel(), addr_ready = a.newLabel();
		a.cmp(cl, 0xFF);
		a.jne(has_base);
		a.mov(rdi, rdx);
		a.jmp(addr_ready);
		a.bind(has_base);
		mul8(rcx);
		a.mov(rdi, qword_ptr(rbx, rcx));
		a.add(rdi, rdx);
		a.bind(addr_ready);

		mul8(r8);
		a.mov(rax, qword_ptr(rbx, r8));
		dead();

		Label sz8 = a.newLabel(), sz4 = a.newLabel(), sz2 = a.newLabel(), sz1 = a.newLabel(), done = a.newLabel();
		a.cmp(r9b, 8);
		a.je(sz8);
		a.cmp(r9b, 4);
		a.je(sz4);
		a.cmp(r9b, 2);
		a.je(sz2);
		a.bind(sz1);
		a.mov(byte_ptr(rdi), al);
		a.jmp(done);
		a.bind(sz2);
		a.mov(word_ptr(rdi), ax);
		a.jmp(done);
		a.bind(sz4);
		a.mov(dword_ptr(rdi), eax);
		a.jmp(done);
		a.bind(sz8);
		a.mov(qword_ptr(rdi), rax);
		a.bind(done);
		a.jmp(labels.dispatch_loop);
		break;
	}

	case vm_op::VM_ADD_REG_REG:
	case vm_op::VM_SUB_REG_REG:
	case vm_op::VM_XOR_REG_REG:
	case vm_op::VM_AND_REG_REG:
	case vm_op::VM_OR_REG_REG: {
		dead();
		a.movzx(ecx, byte_ptr(rsi));
		a.movzx(edx, byte_ptr(rsi, 1));
		a.movzx(r9d, byte_ptr(rsi, 2));
		adv(3);
		mul8(rcx);
		mul8(rdx);
		a.mov(rax, qword_ptr(rbx, rcx));
		a.mov(r8, qword_ptr(rbx, rdx));

		int mba_pct = (settings ? settings->mba_pct : 50);
		bool use_mba = (opaque_rng() % 100) < mba_pct;
		Label do32 = a.newLabel(), do_op = a.newLabel();
		a.cmp(r9b, 4);
		a.je(do32);

		if (use_mba) {
			switch (original_op) {
			case vm_op::VM_ADD_REG_REG:
				a.mov(r10, rax); a.mov(r11, rax);
				a.and_(r11, r8); a.xor_(rax, r8);
				a.lea(rax, x86::ptr(rax, r11, 1));
				a.add(r10, r8);
				break;
			case vm_op::VM_SUB_REG_REG:
				a.mov(r10, rax); a.mov(r11, rax);
				a.not_(r11); a.and_(r11, r8);
				a.xor_(rax, r8); a.shl(r11, 1);
				a.sub(rax, r11);
				a.sub(r10, r8);
				break;
			case vm_op::VM_XOR_REG_REG:
				a.mov(r10, rax); a.mov(r11, rax);
				a.or_(r10, r8); a.and_(r11, r8);
				a.sub(r10, r11); a.mov(rax, r10);
				a.test(rax, rax);
				break;
			case vm_op::VM_AND_REG_REG:
				a.mov(r10, rax); a.mov(r11, rax);
				a.or_(r10, r8); a.xor_(r11, r8);
				a.sub(r10, r11); a.mov(rax, r10);
				a.test(rax, rax);
				break;
			case vm_op::VM_OR_REG_REG:
				a.mov(r10, rax); a.mov(r11, rax);
				a.xor_(r10, r8); a.and_(r11, r8);
				a.add(r10, r11); a.mov(rax, r10);
				a.test(rax, rax);
				break;
			default: break;
			}
		} else {
			switch (original_op) {
			case vm_op::VM_ADD_REG_REG: a.add(rax, r8); break;
			case vm_op::VM_SUB_REG_REG: a.sub(rax, r8); break;
			case vm_op::VM_XOR_REG_REG: a.xor_(rax, r8); break;
			case vm_op::VM_AND_REG_REG: a.and_(rax, r8); break;
			case vm_op::VM_OR_REG_REG:  a.or_(rax, r8); break;
			default: break;
			}
		}
		a.jmp(do_op);
		a.bind(do32);

		if (use_mba) {
			switch (original_op) {
			case vm_op::VM_ADD_REG_REG:
				a.mov(r10d, eax); a.mov(r11d, eax);
				a.and_(r11d, r8d); a.xor_(eax, r8d);
				a.lea(eax, x86::dword_ptr(rax, r11, 1));
				a.add(r10d, r8d);
				break;
			case vm_op::VM_SUB_REG_REG:
				a.mov(r10d, eax); a.mov(r11d, eax);
				a.not_(r11d); a.and_(r11d, r8d);
				a.xor_(eax, r8d); a.shl(r11d, 1);
				a.sub(eax, r11d);
				a.sub(r10d, r8d);
				break;
			case vm_op::VM_XOR_REG_REG:
				a.mov(r10d, eax); a.mov(r11d, eax);
				a.or_(r10d, r8d); a.and_(r11d, r8d);
				a.sub(r10d, r11d); a.mov(eax, r10d);
				a.test(eax, eax);
				break;
			case vm_op::VM_AND_REG_REG:
				a.mov(r10d, eax); a.mov(r11d, eax);
				a.or_(r10d, r8d); a.xor_(r11d, r8d);
				a.sub(r10d, r11d); a.mov(eax, r10d);
				a.test(eax, eax);
				break;
			case vm_op::VM_OR_REG_REG:
				a.mov(r10d, eax); a.mov(r11d, eax);
				a.xor_(r10d, r8d); a.and_(r11d, r8d);
				a.add(r10d, r11d); a.mov(eax, r10d);
				a.test(eax, eax);
				break;
			default: break;
			}
		} else {
			switch (original_op) {
			case vm_op::VM_ADD_REG_REG: a.add(eax, r8d); break;
			case vm_op::VM_SUB_REG_REG: a.sub(eax, r8d); break;
			case vm_op::VM_XOR_REG_REG: a.xor_(eax, r8d); break;
			case vm_op::VM_AND_REG_REG: a.and_(eax, r8d); break;
			case vm_op::VM_OR_REG_REG:  a.or_(eax, r8d); break;
			default: break;
			}
		}
		a.bind(do_op);
		a.pushfq();
		a.pop(r9);
		a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
		a.mov(qword_ptr(rbx, rcx), rax);
		emit_chain_dispatch(a, labels);
		break;
	}

	case vm_op::VM_ADD_REG_IMM:
	case vm_op::VM_SUB_REG_IMM: {
		dead();
		a.movzx(ecx, byte_ptr(rsi));
		a.movsxd(rdx, dword_ptr(rsi, 1));
		a.movzx(r9d, byte_ptr(rsi, 5));
		adv(6);
		mul8(rcx);
		a.mov(rax, qword_ptr(rbx, rcx));

		Label do32 = a.newLabel(), do_op = a.newLabel();
		a.cmp(r9b, 4);
		a.je(do32);
		switch (original_op) {
		case vm_op::VM_ADD_REG_IMM: a.add(rax, rdx); break;
		case vm_op::VM_SUB_REG_IMM: a.sub(rax, rdx); break;
		default: break;
		}
		a.jmp(do_op);
		a.bind(do32);
		switch (original_op) {
		case vm_op::VM_ADD_REG_IMM: a.add(eax, edx); break;
		case vm_op::VM_SUB_REG_IMM: a.sub(eax, edx); break;
		default: break;
		}
		a.bind(do_op);
		a.pushfq();
		a.pop(r9);
		a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
		a.mov(qword_ptr(rbx, rcx), rax);
		emit_chain_dispatch(a, labels);
		break;
	}

	case vm_op::VM_CMP_REG_REG: {
		dead();
		a.movzx(ecx, byte_ptr(rsi));
		a.movzx(edx, byte_ptr(rsi, 1));
		a.movzx(r9d, byte_ptr(rsi, 2));
		adv(3);
		mul8(rcx);
		mul8(rdx);
		a.mov(rax, qword_ptr(rbx, rcx));
		a.mov(r8, qword_ptr(rbx, rdx));
		Label cmp32 = a.newLabel(), done = a.newLabel();
		a.cmp(r9b, 4);
		a.je(cmp32);
		a.cmp(rax, r8);
		a.jmp(done);
		a.bind(cmp32);
		a.cmp(eax, r8d);
		a.bind(done);
		a.pushfq();
		a.pop(r9);
		a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
		a.jmp(labels.dispatch_loop);
		break;
	}

	case vm_op::VM_CMP_REG_IMM: {
		dead();
		a.movzx(ecx, byte_ptr(rsi));
		a.movsxd(rdx, dword_ptr(rsi, 1));
		a.movzx(r9d, byte_ptr(rsi, 5));
		adv(6);
		mul8(rcx);
		a.mov(rax, qword_ptr(rbx, rcx));
		Label cmp32 = a.newLabel(), done = a.newLabel();
		a.cmp(r9b, 4);
		a.je(cmp32);
		a.cmp(rax, rdx);
		a.jmp(done);
		a.bind(cmp32);
		a.cmp(eax, edx);
		a.bind(done);
		a.pushfq();
		a.pop(r9);
		a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
		a.jmp(labels.dispatch_loop);
		break;
	}

	case vm_op::VM_TEST_REG_REG: {
		dead();
		a.movzx(ecx, byte_ptr(rsi));
		a.movzx(edx, byte_ptr(rsi, 1));
		adv(2);
		mul8(rcx);
		mul8(rdx);
		dead();
		a.mov(rax, qword_ptr(rbx, rcx));
		a.mov(r8, qword_ptr(rbx, rdx));
		a.test(rax, r8);
		a.pushfq();
		a.pop(r9);
		a.mov(qword_ptr(rbx, VRFLAGS_OFF), r9);
		a.jmp(labels.dispatch_loop);
		break;
	}

	case vm_op::VM_JMP: {
		dead();
		a.movsxd(rax, dword_ptr(rsi));
		adv(4);
		dead();
		a.add(rsi, rax);
		a.jmp(labels.dispatch_loop);
		break;
	}

	case vm_op::VM_JZ:
	case vm_op::VM_JNZ: {
		dead();
		a.movsxd(rax, dword_ptr(rsi));
		adv(4);
		a.push(qword_ptr(rbx, VRFLAGS_OFF));
		a.popfq();
		Label taken = a.newLabel(), not_taken = a.newLabel();
		if (original_op == vm_op::VM_JZ)
			a.jz(taken);
		else
			a.jnz(taken);
		a.jmp(labels.dispatch_loop);
		a.bind(taken);
		a.add(rsi, rax);
		a.jmp(labels.dispatch_loop);
		break;
	}

	case vm_op::VM_PUSH_REG: {
		dead();
		a.movzx(ecx, byte_ptr(rsi));
		adv1();
		mul8(rcx);
		dead();
		a.mov(rax, qword_ptr(rbx, rcx));
		a.push(rax);
		a.jmp(labels.dispatch_loop);
		break;
	}

	case vm_op::VM_POP_REG: {
		dead();
		a.movzx(ecx, byte_ptr(rsi));
		adv1();
		mul8(rcx);
		a.pop(rax);
		dead();
		a.mov(qword_ptr(rbx, rcx), rax);
		a.jmp(labels.dispatch_loop);
		break;
	}

	case vm_op::VM_LEA_REG: {
		dead();
		a.movzx(ecx, byte_ptr(rsi));
		a.movzx(edx, byte_ptr(rsi, 1));
		a.movsxd(r8, dword_ptr(rsi, 2));
		adv(6);

		Label has_base = a.newLabel(), done = a.newLabel();
		a.cmp(dl, 0xFF);
		a.jne(has_base);
		a.mov(rax, r8);
		a.jmp(done);
		a.bind(has_base);
		mul8(rdx);
		a.mov(rax, qword_ptr(rbx, rdx));
		a.add(rax, r8);
		a.bind(done);

		dead();
		mul8(rcx);
		a.mov(qword_ptr(rbx, rcx), rax);
		a.jmp(labels.dispatch_loop);
		break;
	}

	default:
		emit_junk_block(a);
		emit_junk_block(a);
		a.jmp(labels.handlers[static_cast<int>(original_op)]);
		break;
	}
}

void vm_dispatcher::build_handler_list(x86::Assembler& a, handler_labels& labels,
	std::vector<std::function<void()>>& out) {

	// GP handlers
	out.push_back([&]() { emit_nop_handler(a, labels); });
	out.push_back([&]() { emit_mov_reg_imm64_handler(a, labels); });
	out.push_back([&]() { emit_mov_reg_reg_handler(a, labels); });
	out.push_back([&]() { emit_mov_reg_mem_handler(a, labels); });
	out.push_back([&]() { emit_mov_mem_reg_handler(a, labels); });

	// ALU reg,reg
	out.push_back([&]() { emit_alu_reg_reg_handler(a, labels, vm_op::VM_ADD_REG_REG); });
	out.push_back([&]() { emit_alu_reg_imm_handler(a, labels, vm_op::VM_ADD_REG_IMM); });
	out.push_back([&]() { emit_alu_reg_reg_handler(a, labels, vm_op::VM_SUB_REG_REG); });
	out.push_back([&]() { emit_alu_reg_imm_handler(a, labels, vm_op::VM_SUB_REG_IMM); });
	out.push_back([&]() { emit_alu_reg_reg_handler(a, labels, vm_op::VM_XOR_REG_REG); });
	out.push_back([&]() { emit_alu_reg_imm_handler(a, labels, vm_op::VM_XOR_REG_IMM); });
	out.push_back([&]() { emit_alu_reg_reg_handler(a, labels, vm_op::VM_AND_REG_REG); });
	out.push_back([&]() { emit_alu_reg_imm_handler(a, labels, vm_op::VM_AND_REG_IMM); });
	out.push_back([&]() { emit_alu_reg_reg_handler(a, labels, vm_op::VM_OR_REG_REG); });
	out.push_back([&]() { emit_alu_reg_imm_handler(a, labels, vm_op::VM_OR_REG_IMM); });

	// Unary
	out.push_back([&]() { emit_not_handler(a, labels); });
	out.push_back([&]() { emit_neg_handler(a, labels); });
	out.push_back([&]() { emit_shl_handler(a, labels); });
	out.push_back([&]() { emit_shr_handler(a, labels); });

	// Compare / test
	out.push_back([&]() { emit_cmp_reg_reg_handler(a, labels); });
	out.push_back([&]() { emit_cmp_reg_imm_handler(a, labels); });
	out.push_back([&]() { emit_test_handler(a, labels); });
	out.push_back([&]() { emit_test_reg_imm_handler(a, labels); });

	// Jumps
	out.push_back([&]() { emit_jmp_handler(a, labels); });
	for (auto jcc : { vm_op::VM_JZ, vm_op::VM_JNZ, vm_op::VM_JL, vm_op::VM_JLE,
		vm_op::VM_JG, vm_op::VM_JGE, vm_op::VM_JB, vm_op::VM_JBE,
		vm_op::VM_JA, vm_op::VM_JAE, vm_op::VM_JS, vm_op::VM_JNS,
		vm_op::VM_JP, vm_op::VM_JNP })
		out.push_back([&, jcc]() { emit_jcc_handler(a, labels, jcc); });

	// Push/pop/call/lea
	out.push_back([&]() { emit_push_handler(a, labels); });
	out.push_back([&]() { emit_pop_handler(a, labels); });
	out.push_back([&]() { emit_call_native_handler(a, labels); });
	out.push_back([&]() { emit_call_native_reloc_handler(a, labels); });
	out.push_back([&]() { emit_relocate_reg_handler(a, labels); });
	out.push_back([&]() { emit_call_import_handler(a, labels); });
	out.push_back([&]() { emit_nest_enter_handler(a, labels); });
	out.push_back([&]() { emit_lea_handler(a, labels); });
	out.push_back([&]() { emit_imul_reg_reg_handler(a, labels); });
	out.push_back([&]() { emit_mul_reg_imm_handler(a, labels); });

	// CDQ/CQO/DIV
	out.push_back([&]() { emit_cdq_handler(a, labels); });
	out.push_back([&]() { emit_cqo_handler(a, labels); });
	out.push_back([&]() { emit_div_handler(a, labels, vm_op::VM_DIV_REG); });
	out.push_back([&]() { emit_div_handler(a, labels, vm_op::VM_IDIV_REG); });

	// CMOV
	for (auto cm : { vm_op::VM_CMOVZ_REG_REG, vm_op::VM_CMOVNZ_REG_REG,
		vm_op::VM_CMOVL_REG_REG, vm_op::VM_CMOVLE_REG_REG,
		vm_op::VM_CMOVG_REG_REG, vm_op::VM_CMOVGE_REG_REG,
		vm_op::VM_CMOVB_REG_REG, vm_op::VM_CMOVBE_REG_REG,
		vm_op::VM_CMOVA_REG_REG, vm_op::VM_CMOVAE_REG_REG,
		vm_op::VM_CMOVS_REG_REG, vm_op::VM_CMOVNS_REG_REG,
		vm_op::VM_CMOVP_REG_REG, vm_op::VM_CMOVNP_REG_REG })
		out.push_back([&, cm]() { emit_cmov_handler(a, labels, cm); });

	// SETcc
	for (auto sc : { vm_op::VM_SETZ_REG, vm_op::VM_SETNZ_REG,
		vm_op::VM_SETL_REG, vm_op::VM_SETLE_REG,
		vm_op::VM_SETG_REG, vm_op::VM_SETGE_REG,
		vm_op::VM_SETB_REG, vm_op::VM_SETBE_REG,
		vm_op::VM_SETA_REG, vm_op::VM_SETAE_REG,
		vm_op::VM_SETP_REG, vm_op::VM_SETNP_REG,
		vm_op::VM_SETS_REG, vm_op::VM_SETNS_REG })
		out.push_back([&, sc]() { emit_setcc_handler(a, labels, sc); });

	// MOVZX/MOVSX
	out.push_back([&]() { emit_movzx_mem_handler(a, labels, vm_op::VM_MOVZX_REG_MEM8); });
	out.push_back([&]() { emit_movzx_mem_handler(a, labels, vm_op::VM_MOVZX_REG_MEM16); });
	out.push_back([&]() { emit_movsx_mem_handler(a, labels, vm_op::VM_MOVSX_REG_MEM8); });
	out.push_back([&]() { emit_movsx_mem_handler(a, labels, vm_op::VM_MOVSX_REG_MEM16); });
	out.push_back([&]() { emit_movsx_mem_handler(a, labels, vm_op::VM_MOVSXD_REG_MEM32); });

	// Sign extension
	out.push_back([&]() { emit_cbw_handler(a, labels); });
	out.push_back([&]() { emit_cwde_handler(a, labels); });
	out.push_back([&]() { emit_cdqe_handler(a, labels); });
	out.push_back([&]() { emit_mul_reg_handler(a, labels); });

	// Rotation
	for (auto rot : { vm_op::VM_ROL_REG_IMM, vm_op::VM_ROR_REG_IMM,
		vm_op::VM_RCL_REG_IMM, vm_op::VM_RCR_REG_IMM })
		out.push_back([&, rot]() { emit_rot_handler(a, labels, rot); });
	out.push_back([&]() { emit_rot_cl_handler(a, labels, vm_op::VM_ROL_REG_CL); });
	out.push_back([&]() { emit_rot_cl_handler(a, labels, vm_op::VM_ROR_REG_CL); });

	// Bit operations
	for (auto bt : { vm_op::VM_BT_REG_REG, vm_op::VM_BT_REG_IMM,
		vm_op::VM_BTS_REG_REG, vm_op::VM_BTS_REG_IMM,
		vm_op::VM_BTR_REG_REG, vm_op::VM_BTR_REG_IMM })
		out.push_back([&, bt]() { emit_bt_handler(a, labels, bt); });
	out.push_back([&]() { emit_bsf_bsr_handler(a, labels, vm_op::VM_BSF_REG_REG); });
	out.push_back([&]() { emit_bsf_bsr_handler(a, labels, vm_op::VM_BSR_REG_REG); });
	out.push_back([&]() { emit_popcnt_handler(a, labels, vm_op::VM_POPCNT_REG_REG); });
	out.push_back([&]() { emit_popcnt_handler(a, labels, vm_op::VM_LZCNT_REG_REG); });
	out.push_back([&]() { emit_popcnt_handler(a, labels, vm_op::VM_TZCNT_REG_REG); });

	// SAR / shift-by-CL
	out.push_back([&]() { emit_sar_imm_handler(a, labels); });
	for (auto sh : { vm_op::VM_SAR_REG_CL, vm_op::VM_SHL_REG_CL, vm_op::VM_SHR_REG_CL })
		out.push_back([&, sh]() { emit_shift_cl_handler(a, labels, sh); });

	// SIB
	out.push_back([&]() { emit_mov_reg_sib_handler(a, labels); });
	out.push_back([&]() { emit_mov_sib_reg_handler(a, labels); });
	out.push_back([&]() { emit_lea_sib_handler(a, labels); });

	// Carry arithmetic
	out.push_back([&]() { emit_adc_reg_reg_handler(a, labels); });
	out.push_back([&]() { emit_adc_reg_imm_handler(a, labels); });
	out.push_back([&]() { emit_sbb_reg_reg_handler(a, labels); });
	out.push_back([&]() { emit_sbb_reg_imm_handler(a, labels); });

	// Misc
	out.push_back([&]() { emit_xchg_handler(a, labels); });
	out.push_back([&]() { emit_leave_handler(a, labels); });
	out.push_back([&]() { emit_call_indirect_handler(a, labels); });
	out.push_back([&]() { emit_btc_handler(a, labels, vm_op::VM_BTC_REG_REG); });
	out.push_back([&]() { emit_btc_handler(a, labels, vm_op::VM_BTC_REG_IMM); });
	out.push_back([&]() { emit_bswap_handler(a, labels); });
	out.push_back([&]() { emit_cwd_handler(a, labels); });
	out.push_back([&]() { emit_jmp_reg_handler(a, labels); });
	out.push_back([&]() { emit_jmp_mem_handler(a, labels); });
	out.push_back([&]() { emit_imul_single_handler(a, labels); });
	for (auto sh : { vm_op::VM_SHLD_REG_REG_IMM, vm_op::VM_SHRD_REG_REG_IMM,
		vm_op::VM_SHLD_REG_REG_CL, vm_op::VM_SHRD_REG_REG_CL })
		out.push_back([&, sh]() { emit_shld_shrd_handler(a, labels, sh); });

	// String operations
	for (auto str : { vm_op::VM_REP_MOVSB, vm_op::VM_REP_MOVSW, vm_op::VM_REP_MOVSD, vm_op::VM_REP_MOVSQ,
		vm_op::VM_REP_STOSB, vm_op::VM_REP_STOSW, vm_op::VM_REP_STOSD, vm_op::VM_REP_STOSQ,
		vm_op::VM_MOVSB, vm_op::VM_MOVSQ, vm_op::VM_STOSB, vm_op::VM_STOSQ,
		vm_op::VM_REP_SCASB, vm_op::VM_REPE_CMPSB })
		out.push_back([&, str]() { emit_string_handler(a, labels, str); });

	// SSE mov
	for (auto sm : { vm_op::VM_MOVSS_REG_REG, vm_op::VM_MOVSS_REG_MEM, vm_op::VM_MOVSS_MEM_REG,
		vm_op::VM_MOVSD_REG_REG, vm_op::VM_MOVSD_REG_MEM, vm_op::VM_MOVSD_MEM_REG,
		vm_op::VM_MOVAPS_REG_REG, vm_op::VM_MOVAPS_REG_MEM, vm_op::VM_MOVAPS_MEM_REG,
		vm_op::VM_MOVUPS_REG_MEM, vm_op::VM_MOVUPS_MEM_REG,
		vm_op::VM_MOVDQA_REG_REG, vm_op::VM_MOVDQA_REG_MEM, vm_op::VM_MOVDQA_MEM_REG,
		vm_op::VM_MOVDQU_REG_MEM, vm_op::VM_MOVDQU_MEM_REG })
		out.push_back([&, sm]() { emit_sse_mov_handler(a, labels, sm); });

	// SSE arith
	for (auto sa : { vm_op::VM_ADDSS_REG_REG, vm_op::VM_ADDSS_REG_MEM,
		vm_op::VM_ADDSD_REG_REG, vm_op::VM_ADDSD_REG_MEM,
		vm_op::VM_SUBSS_REG_REG, vm_op::VM_SUBSS_REG_MEM,
		vm_op::VM_SUBSD_REG_REG, vm_op::VM_SUBSD_REG_MEM,
		vm_op::VM_MULSS_REG_REG, vm_op::VM_MULSS_REG_MEM,
		vm_op::VM_MULSD_REG_REG, vm_op::VM_MULSD_REG_MEM,
		vm_op::VM_DIVSS_REG_REG, vm_op::VM_DIVSS_REG_MEM,
		vm_op::VM_DIVSD_REG_REG, vm_op::VM_DIVSD_REG_MEM })
		out.push_back([&, sa]() { emit_sse_arith_handler(a, labels, sa); });

	// SSE compare
	for (auto sc : { vm_op::VM_COMISS_REG_REG, vm_op::VM_COMISS_REG_MEM,
		vm_op::VM_COMISD_REG_REG, vm_op::VM_COMISD_REG_MEM,
		vm_op::VM_UCOMISS_REG_REG, vm_op::VM_UCOMISS_REG_MEM,
		vm_op::VM_UCOMISD_REG_REG, vm_op::VM_UCOMISD_REG_MEM })
		out.push_back([&, sc]() { emit_sse_cmp_handler(a, labels, sc); });

	// SSE conversion
	for (auto cv : { vm_op::VM_CVTSI2SS_REG_REG, vm_op::VM_CVTSI2SD_REG_REG,
		vm_op::VM_CVTSS2SD_REG_REG, vm_op::VM_CVTSD2SS_REG_REG,
		vm_op::VM_CVTSS2SI_REG_REG, vm_op::VM_CVTSD2SI_REG_REG,
		vm_op::VM_CVTTSS2SI_REG_REG, vm_op::VM_CVTTSD2SI_REG_REG,
		vm_op::VM_CVTSI2SS_REG_MEM, vm_op::VM_CVTSI2SD_REG_MEM,
		vm_op::VM_CVTSS2SD_REG_MEM, vm_op::VM_CVTSD2SS_REG_MEM })
		out.push_back([&, cv]() { emit_sse_cvt_handler(a, labels, cv); });

	// SSE bitwise
	for (auto bw : { vm_op::VM_XORPS_REG_REG, vm_op::VM_XORPS_REG_MEM,
		vm_op::VM_XORPD_REG_REG, vm_op::VM_XORPD_REG_MEM,
		vm_op::VM_ANDPS_REG_REG, vm_op::VM_ANDPS_REG_MEM,
		vm_op::VM_ANDPD_REG_REG, vm_op::VM_ANDPD_REG_MEM,
		vm_op::VM_ORPS_REG_REG, vm_op::VM_ORPS_REG_MEM,
		vm_op::VM_ORPD_REG_REG, vm_op::VM_ORPD_REG_MEM,
		vm_op::VM_ANDNPS_REG_REG, vm_op::VM_ANDNPS_REG_MEM,
		vm_op::VM_ANDNPD_REG_REG, vm_op::VM_ANDNPD_REG_MEM })
		out.push_back([&, bw]() { emit_sse_bitwise_handler(a, labels, bw); });

	// SSE packed arith
	for (auto pa : { vm_op::VM_ADDPS_REG_REG, vm_op::VM_ADDPS_REG_MEM,
		vm_op::VM_ADDPD_REG_REG, vm_op::VM_ADDPD_REG_MEM,
		vm_op::VM_SUBPS_REG_REG, vm_op::VM_SUBPS_REG_MEM,
		vm_op::VM_SUBPD_REG_REG, vm_op::VM_SUBPD_REG_MEM,
		vm_op::VM_MULPS_REG_REG, vm_op::VM_MULPS_REG_MEM,
		vm_op::VM_MULPD_REG_REG, vm_op::VM_MULPD_REG_MEM,
		vm_op::VM_DIVPS_REG_REG, vm_op::VM_DIVPS_REG_MEM,
		vm_op::VM_DIVPD_REG_REG, vm_op::VM_DIVPD_REG_MEM })
		out.push_back([&, pa]() { emit_sse_packed_arith_handler(a, labels, pa); });

	// SSE min/max/sqrt
	for (auto mm : { vm_op::VM_MINSS_REG_REG, vm_op::VM_MAXSS_REG_REG,
		vm_op::VM_MINSD_REG_REG, vm_op::VM_MAXSD_REG_REG,
		vm_op::VM_SQRTSS_REG_REG, vm_op::VM_SQRTSD_REG_REG })
		out.push_back([&, mm]() { emit_sse_minmax_handler(a, labels, mm); });

	// SSE shuffle/unpack
	for (auto su : { vm_op::VM_SHUFPS_REG_REG_IMM, vm_op::VM_SHUFPD_REG_REG_IMM,
		vm_op::VM_UNPCKLPS_REG_REG, vm_op::VM_UNPCKHPS_REG_REG,
		vm_op::VM_UNPCKLPD_REG_REG, vm_op::VM_UNPCKHPD_REG_REG })
		out.push_back([&, su]() { emit_sse_shuffle_handler(a, labels, su); });

	// SSE integer
	for (auto si : { vm_op::VM_PXOR_REG_REG, vm_op::VM_PAND_REG_REG,
		vm_op::VM_POR_REG_REG, vm_op::VM_PANDN_REG_REG,
		vm_op::VM_PCMPEQB_REG_REG, vm_op::VM_PCMPEQD_REG_REG, vm_op::VM_PCMPGTB_REG_REG,
		vm_op::VM_PADDB_REG_REG, vm_op::VM_PADDW_REG_REG,
		vm_op::VM_PADDD_REG_REG, vm_op::VM_PADDQ_REG_REG,
		vm_op::VM_PSUBB_REG_REG, vm_op::VM_PSUBW_REG_REG,
		vm_op::VM_PSUBD_REG_REG, vm_op::VM_PSUBQ_REG_REG,
		vm_op::VM_PUNPCKLBW_REG_REG, vm_op::VM_PUNPCKHBW_REG_REG,
		vm_op::VM_PUNPCKLDQ_REG_REG, vm_op::VM_PUNPCKHDQ_REG_REG,
		vm_op::VM_PUNPCKLQDQ_REG_REG, vm_op::VM_PUNPCKHQDQ_REG_REG,
		vm_op::VM_PSHUFB_REG_REG,
		vm_op::VM_PMAXSB_REG_REG, vm_op::VM_PMAXSD_REG_REG,
		vm_op::VM_PMINSB_REG_REG, vm_op::VM_PMINSD_REG_REG })
		out.push_back([&, si]() { emit_sse_int_handler(a, labels, si); });

	out.push_back([&]() { emit_pmovmskb_handler(a, labels); });

	// SSE shift imm
	for (auto ss : { vm_op::VM_PSLLW_REG_IMM, vm_op::VM_PSLLD_REG_IMM, vm_op::VM_PSLLQ_REG_IMM,
		vm_op::VM_PSRLW_REG_IMM, vm_op::VM_PSRLD_REG_IMM, vm_op::VM_PSRLQ_REG_IMM,
		vm_op::VM_PSRAW_REG_IMM, vm_op::VM_PSRAD_REG_IMM })
		out.push_back([&, ss]() { emit_sse_shift_imm_handler(a, labels, ss); });

	out.push_back([&]() { emit_pshufd_handler(a, labels, vm_op::VM_PSHUFD_REG_REG_IMM); });

	// MOVD/MOVQ
	for (auto mq : { vm_op::VM_MOVD_XMM_REG, vm_op::VM_MOVD_REG_XMM,
		vm_op::VM_MOVQ_XMM_REG, vm_op::VM_MOVQ_REG_XMM,
		vm_op::VM_MOVD_XMM_MEM, vm_op::VM_MOVD_MEM_XMM,
		vm_op::VM_MOVQ_XMM_MEM, vm_op::VM_MOVQ_MEM_XMM, vm_op::VM_MOVQ_XMM_XMM })
		out.push_back([&, mq]() { emit_sse_movd_movq_handler(a, labels, mq); });

	// SSE4.1
	for (auto pe : { vm_op::VM_PINSRB_REG_REG_IMM, vm_op::VM_PINSRD_REG_REG_IMM,
		vm_op::VM_PINSRQ_REG_REG_IMM, vm_op::VM_PEXTRB_REG_REG_IMM,
		vm_op::VM_PEXTRD_REG_REG_IMM, vm_op::VM_PEXTRQ_REG_REG_IMM })
		out.push_back([&, pe]() { emit_sse_pinsr_pextr_handler(a, labels, pe); });
	out.push_back([&]() { emit_sse_round_handler(a, labels, vm_op::VM_ROUNDSS_REG_REG_IMM); });
	out.push_back([&]() { emit_sse_round_handler(a, labels, vm_op::VM_ROUNDSD_REG_REG_IMM); });
	out.push_back([&]() { emit_sse_ptest_handler(a, labels); });
	for (auto hl : { vm_op::VM_MOVHLPS_REG_REG, vm_op::VM_MOVLHPS_REG_REG,
		vm_op::VM_MOVHPS_REG_MEM, vm_op::VM_MOVHPS_MEM_REG,
		vm_op::VM_MOVLPS_REG_MEM, vm_op::VM_MOVLPS_MEM_REG,
		vm_op::VM_MOVHPD_REG_MEM, vm_op::VM_MOVHPD_MEM_REG,
		vm_op::VM_MOVLPD_REG_MEM, vm_op::VM_MOVLPD_MEM_REG })
		out.push_back([&, hl]() { emit_sse_movhilo_handler(a, labels, hl); });

	// LOCK / atomic
	out.push_back([&]() { emit_cmpxchg_handler(a, labels); });
	for (auto lk : { vm_op::VM_LOCK_XADD_MEM_REG, vm_op::VM_LOCK_INC_MEM, vm_op::VM_LOCK_DEC_MEM,
		vm_op::VM_LOCK_ADD_MEM_REG, vm_op::VM_LOCK_ADD_MEM_IMM,
		vm_op::VM_LOCK_SUB_MEM_REG, vm_op::VM_LOCK_SUB_MEM_IMM,
		vm_op::VM_LOCK_AND_MEM_REG, vm_op::VM_LOCK_AND_MEM_IMM,
		vm_op::VM_LOCK_OR_MEM_REG, vm_op::VM_LOCK_OR_MEM_IMM,
		vm_op::VM_LOCK_XOR_MEM_REG, vm_op::VM_LOCK_XOR_MEM_IMM })
		out.push_back([&, lk]() { emit_lock_handler(a, labels, lk); });

	// Misc
	out.push_back([&]() { emit_cpuid_handler(a, labels); });
	out.push_back([&]() { emit_rdtsc_handler(a, labels); });
	for (auto fn : { vm_op::VM_PAUSE, vm_op::VM_MFENCE, vm_op::VM_LFENCE, vm_op::VM_SFENCE })
		out.push_back([&, fn]() { emit_fence_handler(a, labels, fn); });
	for (auto fl : { vm_op::VM_CLC, vm_op::VM_STC, vm_op::VM_CMC })
		out.push_back([&, fl]() { emit_flag_handler(a, labels, fl); });
	out.push_back([&]() { emit_enter_frame_handler(a, labels); });
	out.push_back([&]() { emit_movbe_handler(a, labels, vm_op::VM_MOVBE_REG_MEM); });
	out.push_back([&]() { emit_movbe_handler(a, labels, vm_op::VM_MOVBE_MEM_REG); });
	out.push_back([&]() { emit_crc32_handler(a, labels); });
	for (auto bm : { vm_op::VM_ANDN_REG_REG_REG, vm_op::VM_BEXTR_REG_REG_REG,
		vm_op::VM_BLSI_REG_REG, vm_op::VM_BLSMSK_REG_REG, vm_op::VM_BLSR_REG_REG,
		vm_op::VM_PDEP_REG_REG_REG, vm_op::VM_PEXT_REG_REG_REG,
		vm_op::VM_BZHI_REG_REG_REG,
		vm_op::VM_SARX_REG_REG_REG, vm_op::VM_SHLX_REG_REG_REG, vm_op::VM_SHRX_REG_REG_REG })
		out.push_back([&, bm]() { emit_bmi_handler(a, labels, bm); });

	// Dup handlers: full mutated body copies
	for (int d = 0; d < vm_opcode_table::TOTAL_DUPS; d++) {
		int orig = table.dup_original[d];
		out.push_back([&, d, orig]() {
			emit_dup_handler_body(a, labels, labels.dup_handlers[d],
				static_cast<vm_op>(orig), d % vm_opcode_table::DUP_COPIES);
		});
	}
}
