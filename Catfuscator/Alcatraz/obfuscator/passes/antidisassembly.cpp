#include "../obfuscator.h"

#include <random>

// Create an opaque junk instruction that:
// 1) Won't be relocated (has_relative = false, isjmpcall = false)
// 2) Has correct length in zyinstr.info.length = raw_bytes.size()
//    so that relocate() and compile() handle it properly.
static obfuscator::instruction_t make_junk_instr(int func_id, std::vector<uint8_t> bytes) {
	obfuscator::instruction_t inst{};
	// Use a NOP as the base decoded instruction — we just need valid info.length
	uint8_t nop = 0x90;
	inst.load(func_id, bytes);
	// Override Zydis decode results: set length = actual raw size
	inst.zyinstr.info.length = (uint8_t)bytes.size();
	// Not a jump/call, don't relocate
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
