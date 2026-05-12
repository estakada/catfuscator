#include "../obfuscator.h"

#include <random>

// Create an opaque junk instruction that:
// 1) Won't be relocated (has_relative = false, isjmpcall = false)
// 2) Has correct length in zyinstr.info.length = raw_bytes.size()
//    so that relocate() and compile() handle it properly.
static obfuscator::instruction_t make_junk_instr(int func_id, std::vector<uint8_t> bytes) {
	obfuscator::instruction_t inst{};
	inst.load(func_id, bytes);
	inst.zyinstr.info.length = (uint8_t)bytes.size();
	inst.isjmpcall = false;
	inst.has_relative = false;
	return inst;
}

// Same as make_junk_instr but also forces isjmpcall=false for fake CF blocks
// that contain embedded jmp/call opcodes (to prevent convert_relative_jmps
// from trying to resolve them as real branches).
static obfuscator::instruction_t make_fake_block_instr(int func_id, std::vector<uint8_t> bytes) {
	obfuscator::instruction_t inst{};
	inst.load(func_id, bytes);
	// Override after load: force isjmpcall=false so convert_relative_jmps
	// doesn't try to resolve any embedded jmp/call opcodes in the fake block.
	inst.zyinstr.info.length = (uint8_t)bytes.size();
	inst.isjmpcall = false;
	inst.has_relative = false;
	return inst;
}

// Insert anti-disassembly pattern before 0xFF instructions.
bool obfuscator::obfuscate_ff(std::vector<obfuscator::function_t>::iterator& function, std::vector<obfuscator::instruction_t>::iterator& instruction) {

	std::random_device rd;
	std::mt19937 gen(rd());
	int variant = gen() % 3;

	instruction_t junk{};
	switch (variant) {
	case 0:
		// EB 01 E8 = jmp $+2; db 0xE8 (fake CALL start)
		junk = make_junk_instr(function->func_id, { 0xEB, 0x01, 0xE8 });
		break;
	case 1:
		// EB 01 0F = jmp $+2; db 0x0F (two-byte opcode prefix)
		junk = make_junk_instr(function->func_id, { 0xEB, 0x01, 0x0F });
		break;
	case 2:
		// EB 02 F0 E9 = jmp $+4; db 0xF0, 0xE9 (LOCK + jmp prefix)
		junk = make_junk_instr(function->func_id, { 0xEB, 0x02, 0xF0, 0xE9 });
		break;
	}

	instruction = function->instructions.insert(instruction, junk);
	instruction++;
	return true;
}

// Insert junk blocks between instructions.
bool obfuscator::add_junk(std::vector<obfuscator::function_t>::iterator& function, std::vector<obfuscator::instruction_t>::iterator& instruction) {

	std::random_device rd;
	std::mt19937 gen(rd());
	int variant = gen() % 5;  // 5 variants (skip fake call)

	instruction_t junk{};
	switch (variant) {
	case 0:
		// EB 01 E8 = jmp $+2; db 0xE8 (fake CALL)
		junk = make_junk_instr(function->func_id, { 0xEB, 0x01, 0xE8 });
		break;
	case 1:
		// EB 02 0F 0B = jmp $+4; ud2 (crash trap)
		junk = make_junk_instr(function->func_id, { 0xEB, 0x02, 0x0F, 0x0B });
		break;
	case 2:
		// EB 01 F2 = jmp $+2; db 0xF2 (REPNE prefix — confuses SSE decoding)
		junk = make_junk_instr(function->func_id, { 0xEB, 0x01, 0xF2 });
		break;
	case 3:
		// EB 02 E9 FF = jmp $+4; db 0xE9, 0xFF (fake jmp rel32)
		junk = make_junk_instr(function->func_id, { 0xEB, 0x02, 0xE9, 0xFF });
		break;
	case 4: {
		// EB 01 XX = jmp $+2; db <random prefix>
		uint8_t prefixes[] = { 0xF0, 0xF2, 0xF3, 0x66, 0x48, 0x4C };
		junk = make_junk_instr(function->func_id, { 0xEB, 0x01, prefixes[gen() % 6] });
		break;
	}
	case 5:
		// EB 03 EB 01 E8 = jmp $+5; nested fake jmp
		junk = make_junk_instr(function->func_id, { 0xEB, 0x03, 0xEB, 0x01, 0xE8 });
		break;
	}

	instruction = function->instructions.insert(instruction, junk);
	instruction++;
	return true;
}

// Insert 1-2 junk instructions BEFORE and AFTER JMP/CALL instructions.
// Junk instructions have has_relative=false so they don't affect relocation math.
bool obfuscator::wrap_jmp_call_junk(
	std::vector<obfuscator::function_t>::iterator& function,
	std::vector<obfuscator::instruction_t>::iterator& instruction) {

	if (!instruction->isjmpcall)
		return true;

	std::random_device rd;
	std::mt19937 gen(rd());

	// How many junk instructions before the JMP/CALL
	int before_count = (gen() % 2) + 1; // 1 or 2
	// How many after
	int after_count = (gen() % 2) + 1;  // 1 or 2

	std::vector<std::vector<uint8_t>> pre_junk = {
		{ 0x90 },                                           // nop
		{ 0x66, 0x90 },                                    // xchg ax,ax (2-byte nop)
		{ 0x0F, 0x1F, 0x00 },                             // nop [rax]
		{ 0x0F, 0x1F, 0x40, 0x00 },                      // nop [rax+0]
		{ 0x40, 0x1F, 0x00 },                      // rex.nop [rax]
		{ 0x45, 0x0F, 0x1F, 0xC0 },                      // nop r8/r9/r10/r11
	};

	std::vector<std::vector<uint8_t>> post_junk = {
		{ 0x90 },                                           // nop
		{ 0x66, 0x90 },                                    // xchg ax,ax
		{ 0x0F, 0x1F, 0x44, 0x00, 0x00 },                // nop [rax+rax*1]
		{ 0x4D, 0x0F, 0x1F, 0xC0 },                       // nop r8
		{ 0x41, 0x0F, 0x1F, 0xC0 },                      // nop r8
		{ 0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00 },   // nop [rax+0]
	};

	// Insert junk BEFORE
	for (int i = 0; i < before_count; i++) {
		auto& pattern = pre_junk[gen() % pre_junk.size()];
		instruction_t junk = make_junk_instr(function->func_id, pattern);
		instruction = function->instructions.insert(instruction, junk);
		instruction++;
	}

	// Insert junk AFTER
	for (int i = 0; i < after_count; i++) {
		auto& pattern = post_junk[gen() % post_junk.size()];
		instruction_t junk = make_junk_instr(function->func_id, pattern);
		instruction++;
		instruction = function->instructions.insert(instruction, junk);
	}

	return true;
}

// Insert fake control flow blocks: unreachable code blocks with misleading jumps.
// These look like real code but are never reached, confusing static analysis.
bool obfuscator::add_fake_control_flow(
	std::vector<obfuscator::function_t>::iterator& function,
	std::vector<obfuscator::instruction_t>::iterator& instruction) {

	if (!instruction->isjmpcall)
		return true;

	std::random_device rd;
	std::mt19937 gen(rd());

	// Only insert sometimes
	if ((gen() % 3) != 0)
		return true;

	// Fake control flow: insert a block that looks like a real function prologue
	// followed by a jump that never executes
	std::vector<std::vector<uint8_t>> fake_blocks = {
		// Block 1: push rbp; mov rbp,rsp; sub rsp,20; jmp $+6
		{ 0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0xEB, 0x04 },
		// Block 2: xor eax,eax; inc eax; test eax,eax; jz $+4
		{ 0x31, 0xC0, 0x40, 0x85, 0xC0, 0x74, 0x02, 0xEB, 0xFE },
		// Block 3: mov rax,0; push rax; pop rax; jmp short $+2
		{ 0x48, 0x31, 0xC0, 0x50, 0x58, 0xEB, 0x00 },
		// Block 4: nop; nop; nop; jmp $-1 (infinite loop fake)
		{ 0x90, 0x90, 0x90, 0xEB, 0xFB },
		// Block 5: push rbx; xor ebx,ebx; pop rbx; jmp $+3
		{ 0x53, 0x31, 0xDB, 0x5B, 0xEB, 0x01 },
		// Block 6: mov rdi,0; mov rsi,0; jmp $+8
		{ 0x48, 0x31, 0xFF, 0x48, 0x31, 0xF6, 0xEB, 0x06 },
	};

	auto& block = fake_blocks[gen() % fake_blocks.size()];
	instruction_t fake = make_fake_block_instr(function->func_id, block);

	// Insert fake block BEFORE the real JMP/CALL
	instruction = function->instructions.insert(instruction, fake);
	instruction++;

	// Add a conditional jump that also never executes (for extra confusion)
	if ((gen() % 2) == 0) {
		std::vector<uint8_t> fake_cond = { 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00 }; // jz $+0 (never taken, offset = 0 means it points to itself)
		// Actually use a more realistic fake: jmp $+3; db garbage
		fake_cond = { 0xEB, 0x02, 0x0F, 0x84, 0x00, 0x00, 0x90 }; // jmp $+2; jz $+0; nop
		instruction_t fake_c = make_junk_instr(function->func_id, fake_cond);
		instruction = function->instructions.insert(instruction, fake_c);
		instruction++;
	}

	return true;
}

// Insert branch history obfuscation: dummy push/pop pairs, fake return addresses.
// Confuses ROP/JOP gadget detection by leaving fake return addresses on stack.
bool obfuscator::add_branch_history_obf(
	std::vector<obfuscator::function_t>::iterator& function,
	std::vector<obfuscator::instruction_t>::iterator& instruction) {

	if (!instruction->isjmpcall)
		return true;

	std::random_device rd;
	std::mt19937 gen(rd());

	// Only insert sometimes
	if ((gen() % 4) != 0)
		return true;

	// Patterns that leave garbage on stack / confuse return detection
	std::vector<std::vector<uint8_t>> hist_patterns = {
		// push rax; pop rcx; (garbles stack tracking)
		{ 0x50, 0x59 },
		// push rax; push rdx; pop rax; pop rdx (double swap)
		{ 0x50, 0x52, 0x58, 0x5A },
		// pushfq; pop rax (moves flags to reg)
		{ 0x9C, 0x58 },
		// mov qword ptr [rsp-8], rax; mov rax, [rsp-8] (stack frame confuse)
		{ 0x48, 0x89, 0x44, 0x24, 0xF8, 0x48, 0x8B, 0x44, 0x24, 0xF8 },
		// push rbp; mov rbp, rsp; pop rbp (standard prologue)
		{ 0x55, 0x48, 0x89, 0xE5, 0x5D },
		// sub rsp,8; add rsp,8 (stack alignment noise)
		{ 0x48, 0x83, 0xEC, 0x08, 0x48, 0x83, 0xC4, 0x08 },
		// mov rax, [rsp]; mov [rsp], rax (stack value swap)
		{ 0x48, 0x8B, 0x04, 0x24, 0x48, 0x89, 0x04, 0x24 },
		// pushfq; popfq; nop (flags confuse)
		{ 0x9C, 0x9D, 0x90 },
		// xchg rax, rdx; xchg rdx, rax (register swap)
		{ 0x92, 0x92 },
		// push rax; and eax, 0; pop rax (zeroing via stack)
		{ 0x50, 0x25, 0x00, 0x00, 0x00, 0x00, 0x58 },
	};

	auto& pattern = hist_patterns[gen() % hist_patterns.size()];
	instruction_t obf = make_junk_instr(function->func_id, pattern);

	// Insert before and after
	instruction = function->instructions.insert(instruction, obf);
	instruction++;

	// Also insert after the JMP/CALL
	if ((gen() % 2) == 0) {
		auto& pattern2 = hist_patterns[gen() % hist_patterns.size()];
		instruction_t obf2 = make_junk_instr(function->func_id, pattern2);
		instruction++;
		instruction = function->instructions.insert(instruction, obf2);
	}

	return true;
}
