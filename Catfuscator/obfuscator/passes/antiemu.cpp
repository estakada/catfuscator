#include "../obfuscator.h"

#include <random>

// Create an anti-emulation instruction block.
// The entire check is packed into a single "instruction" so the obfuscator
// keeps all bytes contiguous — internal relative jumps stay valid.
static obfuscator::instruction_t make_antiemu_instr(int func_id, std::vector<uint8_t> bytes) {
	obfuscator::instruction_t inst{};
	inst.load(func_id, bytes);
	inst.zyinstr.info.length = (uint8_t)bytes.size();
	inst.isjmpcall = false;
	inst.has_relative = false;
	return inst;
}

static void append_u32(std::vector<uint8_t>& v, uint32_t val) {
	v.push_back(val & 0xFF);
	v.push_back((val >> 8) & 0xFF);
	v.push_back((val >> 16) & 0xFF);
	v.push_back((val >> 24) & 0xFF);
}

// 7 diverse crash types — no single pattern to scan for
static std::pair<std::vector<uint8_t>, uint8_t> random_crash(std::mt19937& gen) {
	switch (gen() % 7) {
	case 0: return { {0x0F, 0x0B}, 2 };                       // ud2
	case 1: return { {0xCD, 0x2D}, 2 };                       // int 0x2d
	case 2: return { {0x48, 0x31, 0xE4, 0xC3}, 4 };          // xor rsp,rsp; ret
	case 3: return { {0xCC}, 1 };                              // int 3
	case 4: return { {0x6A, 0x00, 0x5C, 0xC3}, 4 };          // push 0; pop rsp; ret
	case 5: return { {0x31, 0xC0, 0xF7, 0xF0}, 4 };          // xor eax,eax; div eax
	case 6: return { {0x48, 0x83, 0xE4, 0x00, 0xC3}, 5 };    // and rsp,0; ret
	}
	return { {0x0F, 0x0B}, 2 };
}

// MBA-encode a KUSER_SHARED_DATA address into ECX.
// No literal 0x7FFE pattern in output — address computed at runtime.
// Appends: mov ecx, ENCODED; <decode ops> → ecx = addr
static void emit_dynamic_addr(std::mt19937& gen, uint32_t addr, std::vector<uint8_t>& b) {
	uint32_t k1 = gen(), k2 = gen();
	uint32_t enc;
	switch (gen() % 4) {
	default:
	case 0: // xor k1, add k2: addr = (enc ^ k1) + k2
		enc = (addr - k2) ^ k1;
		b.push_back(0xB9); append_u32(b, enc);
		b.insert(b.end(), { 0x81, 0xF1 }); append_u32(b, k1);  // xor ecx, k1
		b.insert(b.end(), { 0x81, 0xC1 }); append_u32(b, k2);  // add ecx, k2
		break;
	case 1: // add k2, xor k1: addr = (enc + k2) ^ k1
		enc = (addr ^ k1) - k2;
		b.push_back(0xB9); append_u32(b, enc);
		b.insert(b.end(), { 0x81, 0xC1 }); append_u32(b, k2);
		b.insert(b.end(), { 0x81, 0xF1 }); append_u32(b, k1);
		break;
	case 2: // sub k2, xor k1: addr = (enc - k2) ^ k1
		enc = (addr ^ k1) + k2;
		b.push_back(0xB9); append_u32(b, enc);
		b.insert(b.end(), { 0x81, 0xE9 }); append_u32(b, k2);  // sub ecx, k2
		b.insert(b.end(), { 0x81, 0xF1 }); append_u32(b, k1);
		break;
	case 3: // xor k1, sub k2: addr = (enc ^ k1) - k2
		enc = (addr + k2) ^ k1;
		b.push_back(0xB9); append_u32(b, enc);
		b.insert(b.end(), { 0x81, 0xF1 }); append_u32(b, k1);
		b.insert(b.end(), { 0x81, 0xE9 }); append_u32(b, k2);
		break;
	}
}

// MBA-encode a syscall SSN into EAX using short-form EAX opcodes.
// No literal SSN appears in binary — computed at runtime.
// Uses: B8=mov eax,imm32; 35=xor eax,imm32; 05=add eax,imm32; 2D=sub eax,imm32
// Each pattern is exactly 15 bytes (3 instructions × 5 bytes).
static void emit_dynamic_ssn(std::mt19937& gen, uint32_t ssn, std::vector<uint8_t>& b) {
	uint32_t k1 = gen(), k2 = gen();
	uint32_t enc;
	switch (gen() % 4) {
	default:
	case 0: // mov eax, enc; xor eax, k1; add eax, k2 → ssn = (enc ^ k1) + k2
		enc = (ssn - k2) ^ k1;
		b.push_back(0xB8); append_u32(b, enc);
		b.push_back(0x35); append_u32(b, k1);
		b.push_back(0x05); append_u32(b, k2);
		break;
	case 1: // mov eax, enc; add eax, k2; xor eax, k1 → ssn = (enc + k2) ^ k1
		enc = (ssn ^ k1) - k2;
		b.push_back(0xB8); append_u32(b, enc);
		b.push_back(0x05); append_u32(b, k2);
		b.push_back(0x35); append_u32(b, k1);
		break;
	case 2: // mov eax, enc; sub eax, k2; xor eax, k1 → ssn = (enc - k2) ^ k1
		enc = (ssn ^ k1) + k2;
		b.push_back(0xB8); append_u32(b, enc);
		b.push_back(0x2D); append_u32(b, k2);
		b.push_back(0x35); append_u32(b, k1);
		break;
	case 3: // mov eax, enc; xor eax, k1; sub eax, k2 → ssn = (enc ^ k1) - k2
		enc = (ssn + k2) ^ k1;
		b.push_back(0xB8); append_u32(b, enc);
		b.push_back(0x35); append_u32(b, k1);
		b.push_back(0x2D); append_u32(b, k2);
		break;
	}
}

// === Public API ===

// Generate a random self-contained anti-emu check as a single instruction_t.
// Uses pushfq (0x9C) consistently — same opcode as MBA, no distinguishing.
// KUSER addresses are dynamically computed via MBA — no static 0x7FFE pattern.
// allow_syscall: if false, only lightweight variants (0-8) are used (for MBA-embedded checks)
//                if true, all variants including syscall (0-10) are available
obfuscator::instruction_t obfuscator::make_inline_antiemu(int func_id, bool allow_syscall) {
	std::random_device rd;
	std::mt19937 gen(rd());
	auto [crash_bytes, crash_skip] = random_crash(gen);
	int variant = allow_syscall ? (gen() % 11) : (gen() % 9);
	std::vector<uint8_t> bytes;

	switch (variant) {
	case 0: {
		// KUSER NtMajorVersion (0x7FFE026C) >= 5, dynamic addr
		bytes = { 0x9C, 0x50, 0x51 };  // pushfq; push rax; push rcx
		emit_dynamic_addr(gen, 0x7FFE026C, bytes);
		bytes.insert(bytes.end(), { 0x8B, 0x01 });            // mov eax, [rcx]
		bytes.insert(bytes.end(), { 0x83, 0xF8, 0x05 });      // cmp eax, 5
		bytes.push_back(0x7D); bytes.push_back(crash_skip);   // jge over
		bytes.insert(bytes.end(), crash_bytes.begin(), crash_bytes.end());
		bytes.insert(bytes.end(), { 0x59, 0x58, 0x9D });      // pop rcx; pop rax; popfq
		break;
	}
	case 1: {
		// KUSER ActiveProcessorCount (0x7FFE02D4) > 0, dynamic addr
		bytes = { 0x9C, 0x50, 0x51 };
		emit_dynamic_addr(gen, 0x7FFE02D4, bytes);
		bytes.insert(bytes.end(), { 0x8B, 0x01 });            // mov eax, [rcx]
		bytes.insert(bytes.end(), { 0x85, 0xC0 });            // test eax, eax
		bytes.push_back(0x75); bytes.push_back(crash_skip);   // jnz over
		bytes.insert(bytes.end(), crash_bytes.begin(), crash_bytes.end());
		bytes.insert(bytes.end(), { 0x59, 0x58, 0x9D });
		break;
	}
	case 2: {
		// TEB self-pointer via gs:30h must be non-zero
		bytes = { 0x9C, 0x50 };  // pushfq; push rax
		bytes.insert(bytes.end(), { 0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00 }); // mov rax, gs:[0x30]
		bytes.insert(bytes.end(), { 0x48, 0x85, 0xC0 });      // test rax, rax
		bytes.push_back(0x75); bytes.push_back(crash_skip);
		bytes.insert(bytes.end(), crash_bytes.begin(), crash_bytes.end());
		bytes.insert(bytes.end(), { 0x58, 0x9D });            // pop rax; popfq
		break;
	}
	case 3: {
		// Timing: rdtscp with decoy rdtsc bytes (scanner for 0F 31 hits decoy, misses real 0F 01 F9)
		bytes = { 0x9C, 0x50, 0x51, 0x52 };  // pushfq; push rax; push rcx; push rdx
		// rdtscp #1 with decoy
		bytes.insert(bytes.end(), { 0xEB, 0x03 });             // jmp +3 (skip decoy)
		bytes.insert(bytes.end(), { 0x0F, 0x31, 0xCC });       // decoy: rdtsc + int3 (never executed)
		bytes.insert(bytes.end(), { 0x0F, 0x01, 0xF9 });       // rdtscp (real)
		bytes.push_back(0x50);                                  // push rax (save tsc1_low)
		// rdtscp #2 with decoy
		bytes.insert(bytes.end(), { 0xEB, 0x03 });
		bytes.insert(bytes.end(), { 0x0F, 0x31, 0xCC });
		bytes.insert(bytes.end(), { 0x0F, 0x01, 0xF9 });
		bytes.push_back(0x59);                                  // pop rcx (tsc1_low)
		bytes.insert(bytes.end(), { 0x29, 0xC8 });             // sub eax, ecx (delta)
		bytes.insert(bytes.end(), { 0x85, 0xC0 });             // test eax, eax
		bytes.push_back(0x75); bytes.push_back(crash_skip);    // jnz over (delta>0 = real)
		bytes.insert(bytes.end(), crash_bytes.begin(), crash_bytes.end());
		bytes.insert(bytes.end(), { 0x5A, 0x59, 0x58, 0x9D }); // pop rdx; pop rcx; pop rax; popfq
		break;
	}
	case 4: {
		// KUSER TickCountQuad (0x7FFE0320, 8 bytes) non-zero, dynamic addr
		bytes = { 0x9C, 0x50, 0x51 };
		emit_dynamic_addr(gen, 0x7FFE0320, bytes);
		bytes.insert(bytes.end(), { 0x48, 0x8B, 0x01 });      // mov rax, [rcx]
		bytes.insert(bytes.end(), { 0x48, 0x85, 0xC0 });      // test rax, rax
		bytes.push_back(0x75); bytes.push_back(crash_skip);
		bytes.insert(bytes.end(), crash_bytes.begin(), crash_bytes.end());
		bytes.insert(bytes.end(), { 0x59, 0x58, 0x9D });
		break;
	}
	case 5: {
		// KUSER SystemTime (0x7FFE0014, 8 bytes) non-zero, dynamic addr
		bytes = { 0x9C, 0x50, 0x51 };
		emit_dynamic_addr(gen, 0x7FFE0014, bytes);
		bytes.insert(bytes.end(), { 0x48, 0x8B, 0x01 });
		bytes.insert(bytes.end(), { 0x48, 0x85, 0xC0 });
		bytes.push_back(0x75); bytes.push_back(crash_skip);
		bytes.insert(bytes.end(), crash_bytes.begin(), crash_bytes.end());
		bytes.insert(bytes.end(), { 0x59, 0x58, 0x9D });
		break;
	}
	case 6: {
		// CPUID leaf 0: eax (max standard leaf) must be > 0
		bytes = { 0x9C, 0x50, 0x53, 0x51, 0x52 }; // pushfq; push rax; push rbx; push rcx; push rdx
		bytes.insert(bytes.end(), { 0x31, 0xC0 });            // xor eax, eax
		bytes.insert(bytes.end(), { 0x0F, 0xA2 });            // cpuid
		bytes.insert(bytes.end(), { 0x85, 0xC0 });            // test eax, eax
		bytes.push_back(0x75); bytes.push_back(crash_skip);   // jnz over (eax>0 = real)
		bytes.insert(bytes.end(), crash_bytes.begin(), crash_bytes.end());
		bytes.insert(bytes.end(), { 0x5A, 0x59, 0x5B, 0x58, 0x9D }); // pop rdx; pop rcx; pop rbx; pop rax; popfq
		break;
	}
	case 7: {
		// PEB via gs:60h (alternative to TEB, non-zero on real Windows)
		bytes = { 0x9C, 0x50 };
		bytes.insert(bytes.end(), { 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00 }); // mov rax, gs:[0x60]
		bytes.insert(bytes.end(), { 0x48, 0x85, 0xC0 });
		bytes.push_back(0x75); bytes.push_back(crash_skip);
		bytes.insert(bytes.end(), crash_bytes.begin(), crash_bytes.end());
		bytes.insert(bytes.end(), { 0x58, 0x9D });
		break;
	}
	case 8: {
		// Pure rdtscp (0F 01 F9) — completely different opcode from rdtsc (0F 31)
		// Scanners searching for 0F 31 won't find this
		bytes = { 0x9C, 0x50, 0x51, 0x52 };
		bytes.insert(bytes.end(), { 0x0F, 0x01, 0xF9 });      // rdtscp #1
		bytes.push_back(0x50);                                  // push rax (save tsc1)
		bytes.insert(bytes.end(), { 0x0F, 0x01, 0xF9 });      // rdtscp #2
		bytes.push_back(0x59);                                  // pop rcx (tsc1)
		bytes.insert(bytes.end(), { 0x29, 0xC8 });             // sub eax, ecx
		bytes.insert(bytes.end(), { 0x85, 0xC0 });             // test eax, eax
		bytes.push_back(0x75); bytes.push_back(crash_skip);
		bytes.insert(bytes.end(), crash_bytes.begin(), crash_bytes.end());
		bytes.insert(bytes.end(), { 0x5A, 0x59, 0x58, 0x9D });
		break;
	}
	case 9: {
		// NtQueryPerformanceCounter syscall (SSN 0x31, stable across Win10/11)
		// Calls syscall directly — emulators must implement full NT syscall ABI.
		// Uses push 0 as zero-init'd output buffer — minimal stack footprint.
		// r10 = arg1 (pointer to output LARGE_INTEGER), rdx = NULL (no frequency)
		// syscall clobbers rcx and r11, save/restore via push/pop.
		bytes = { 0x9C };                                       // pushfq
		bytes.push_back(0x50);                                  // push rax
		bytes.push_back(0x51);                                  // push rcx
		bytes.push_back(0x52);                                  // push rdx
		bytes.insert(bytes.end(), { 0x41, 0x52 });              // push r10
		bytes.insert(bytes.end(), { 0x41, 0x53 });              // push r11
		// Output buffer: push 0 twice = 16 bytes zeroed on stack (LARGE_INTEGER = 8 bytes)
		bytes.insert(bytes.end(), { 0x6A, 0x00 });              // push 0
		bytes.insert(bytes.end(), { 0x6A, 0x00 });              // push 0
		// r10 = rsp (pointer to output buffer)
		bytes.insert(bytes.end(), { 0x4C, 0x8D, 0x14, 0x24 }); // lea r10, [rsp]
		// rdx = NULL (frequency pointer, not needed)
		bytes.insert(bytes.end(), { 0x31, 0xD2 });              // xor edx, edx
		// MBA-encode SSN 0x31 into EAX
		emit_dynamic_ssn(gen, 0x31, bytes);
		// syscall
		bytes.insert(bytes.end(), { 0x0F, 0x05 });
		// Check output non-zero (performance counter always > 0 on real hardware)
		bytes.insert(bytes.end(), { 0x48, 0x8B, 0x04, 0x24 }); // mov rax, [rsp]
		bytes.insert(bytes.end(), { 0x48, 0x85, 0xC0 });       // test rax, rax
		bytes.push_back(0x75); bytes.push_back(crash_skip);    // jnz over (non-zero = real)
		bytes.insert(bytes.end(), crash_bytes.begin(), crash_bytes.end());
		// Restore: pop buffer, pop saved regs
		bytes.push_back(0x58);                                  // pop (discard buffer low)
		bytes.push_back(0x58);                                  // pop (discard buffer high)
		bytes.insert(bytes.end(), { 0x41, 0x5B });              // pop r11
		bytes.insert(bytes.end(), { 0x41, 0x5A });              // pop r10
		bytes.push_back(0x5A);                                  // pop rdx
		bytes.push_back(0x59);                                  // pop rcx
		bytes.push_back(0x58);                                  // pop rax
		bytes.push_back(0x9D);                                  // popfq
		break;
	}
	case 10: {
		// NtQuerySystemInformation syscall (SSN 0x36, stable across Win10/11)
		// Queries SystemBasicInformation (class 0) — always succeeds on real Windows.
		// Uses push-based buffer allocation for minimal stack footprint.
		// r10 = class(0), rdx = buffer ptr, r8 = buffer size, r9 = ReturnLength(NULL)
		// syscall doesn't need shadow space (kernel-mode call, not user-mode ABI).
		bytes = { 0x9C };                                       // pushfq
		bytes.push_back(0x50);                                  // push rax
		bytes.push_back(0x51);                                  // push rcx
		bytes.push_back(0x52);                                  // push rdx
		bytes.insert(bytes.end(), { 0x41, 0x50 });              // push r8
		bytes.insert(bytes.end(), { 0x41, 0x51 });              // push r9
		bytes.insert(bytes.end(), { 0x41, 0x52 });              // push r10
		bytes.insert(bytes.end(), { 0x41, 0x53 });              // push r11
		// Output buffer via pushes: 8 x push 0 = 64 bytes (SYSTEM_BASIC_INFORMATION is ~56 bytes on x64)
		for (int i = 0; i < 8; i++)
			bytes.insert(bytes.end(), { 0x6A, 0x00 });          // push 0
		// r10 = 0 (SystemBasicInformation class)
		bytes.insert(bytes.end(), { 0x45, 0x31, 0xD2 });       // xor r10d, r10d
		// rdx = rsp (buffer pointer)
		bytes.insert(bytes.end(), { 0x48, 0x89, 0xE2 });       // mov rdx, rsp
		// r8 = 64 (buffer size, fits SYSTEM_BASIC_INFORMATION which is ~56 bytes on x64)
		bytes.insert(bytes.end(), { 0x49, 0xC7, 0xC0, 0x40, 0x00, 0x00, 0x00 }); // mov r8, 0x40
		// r9 = 0 (no ReturnLength needed)
		bytes.insert(bytes.end(), { 0x4D, 0x31, 0xC9 });       // xor r9, r9
		// MBA-encode SSN 0x36 into EAX
		emit_dynamic_ssn(gen, 0x36, bytes);
		// syscall
		bytes.insert(bytes.end(), { 0x0F, 0x05 });
		// Check first 8 bytes of buffer non-zero (SystemBasicInformation always fills data)
		bytes.insert(bytes.end(), { 0x48, 0x8B, 0x04, 0x24 }); // mov rax, [rsp]
		bytes.insert(bytes.end(), { 0x48, 0x85, 0xC0 });       // test rax, rax
		bytes.push_back(0x75); bytes.push_back(crash_skip);    // jnz over
		bytes.insert(bytes.end(), crash_bytes.begin(), crash_bytes.end());
		// Restore: pop buffer (8 pops), pop saved regs
		for (int i = 0; i < 8; i++)
			bytes.push_back(0x58);                              // pop (discard buffer)
		bytes.insert(bytes.end(), { 0x41, 0x5B });              // pop r11
		bytes.insert(bytes.end(), { 0x41, 0x5A });              // pop r10
		bytes.insert(bytes.end(), { 0x41, 0x59 });              // pop r9
		bytes.insert(bytes.end(), { 0x41, 0x58 });              // pop r8
		bytes.push_back(0x5A);                                  // pop rdx
		bytes.push_back(0x59);                                  // pop rcx
		bytes.push_back(0x58);                                  // pop rax
		bytes.push_back(0x9D);                                  // popfq
		break;
	}
	}

	return make_antiemu_instr(func_id, bytes);
}

// Embed anti-emu checks and pushfq/popfq noise between MBA operations.
// Called after JIT-compiling MBA instructions, before inserting into function.
// This makes anti-emu indistinguishable from MBA — skipping it breaks the MBA decode.
void obfuscator::embed_antiemu_noise(std::vector<instruction_t>& instrs, int func_id, std::mt19937& gen) {
	// 40% chance to embed anti-emu check between MBA ops
	// Use lightweight variants only (no syscall) — syscall variants add stack usage
	// that can cause overflow in deeply nested calls with many MBA checks
	if (instrs.size() >= 3 && gen() % 5 < 2) {
		int pos = 1 + gen() % ((int)instrs.size() - 1);
		instrs.insert(instrs.begin() + pos, make_inline_antiemu(func_id, false));
	}
	// 33% chance to add pushfq/popfq noise pair (blends with MBA wrapper)
	if (instrs.size() >= 2 && gen() % 3 == 0) {
		int pos = gen() % ((int)instrs.size());
		instruction_t pf{}, ppf{};
		pf.load(func_id, std::vector<uint8_t>{0x9C});
		pf.zyinstr.info.length = 1; pf.isjmpcall = false; pf.has_relative = false;
		ppf.load(func_id, std::vector<uint8_t>{0x9D});
		ppf.zyinstr.info.length = 1; ppf.isjmpcall = false; ppf.has_relative = false;
		instrs.insert(instrs.begin() + pos, ppf);
		instrs.insert(instrs.begin() + pos, pf);
	}
}

bool obfuscator::anti_emu_check(std::vector<obfuscator::function_t>::iterator& function,
	std::vector<obfuscator::instruction_t>::iterator& instruction) {
	auto check = make_inline_antiemu(function->func_id);
	instruction = function->instructions.insert(instruction, check);
	instruction++;
	return true;
}
