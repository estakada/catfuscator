#include "../obfuscator.h"
#include <random>

// Replace mov reg, imm with equivalent but obfuscated sequences.
// Unlike obfuscate_mov which uses JIT + mutation, this inserts
// decoded x86 instructions that compute the same constant.

static obfuscator::instruction_t make_const_instr(int func_id, std::vector<uint8_t> bytes) {
	obfuscator::instruction_t inst{};
	inst.load(func_id, bytes);
	inst.zyinstr.info.length = (uint8_t)bytes.size();
	inst.isjmpcall = false;
	inst.has_relative = false;
	return inst;
}

bool obfuscator::obfuscate_constant(
	std::vector<obfuscator::function_t>::iterator& function,
	std::vector<obfuscator::instruction_t>::iterator& instruction) {

	// Only handle: mov reg, imm
	if (instruction->zyinstr.info.mnemonic != ZYDIS_MNEMONIC_MOV)
		return false;
	if (instruction->zyinstr.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER)
		return false;
	if (instruction->zyinstr.operands[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE)
		return false;

	auto reg_map = lookupmap.find(instruction->zyinstr.operands[0].reg.value);
	if (reg_map == lookupmap.end())
		return false;

	auto reg = reg_map->second;
	uint64_t imm = 0;
	uint8_t imm_offset = instruction->zyinstr.info.raw.imm->offset;
	uint8_t imm_size = instruction->zyinstr.info.raw.imm->size;

	if (imm_size == 8)  imm = *(uint8_t*)(instruction->raw_bytes.data() + imm_offset);
	else if (imm_size == 16) imm = *(uint16_t*)(instruction->raw_bytes.data() + imm_offset);
	else if (imm_size == 32) imm = *(uint32_t*)(instruction->raw_bytes.data() + imm_offset);
	else if (imm_size == 64) imm = *(uint64_t*)(instruction->raw_bytes.data() + imm_offset);
	else return false;

	if (imm == 0) {
		// mov reg, 0 -> xor reg, reg (very common)
		std::vector<uint8_t> xor_bytes;
		if (reg.isGpq()) { xor_bytes = { 0x48, 0x31, 0xC0 }; }
		else if (reg.isGpd()) { xor_bytes = { 0x31, 0xC0 }; }
		else if (reg.isGpw()) { xor_bytes = { 0x66, 0x31, 0xC0 }; }
		else if (reg.isGpb()) { xor_bytes = { 0x30, 0xC0 }; }
		if (!xor_bytes.empty()) {
			instruction_t n = make_const_instr(function->func_id, xor_bytes);
			instruction = function->instructions.insert(instruction, n);
			instruction++;
			function->instructions.erase(instruction);
			return true;
		}
	}

	std::random_device rd;
	std::mt19937 gen(rd());

	// Choose obfuscation pattern (0=LEA_OBF, 1=XOR_ADD, 2=SUB_NEG, 3=LEA_LEA)
	int pattern = gen() % 4;

	if (pattern == 1) {
		// mov rX, K -> xor rX, rX; add rX, K
		std::vector<std::vector<uint8_t>> seq;
		if (reg.isGpq()) {
			seq.push_back(std::vector<uint8_t>{0x48, 0x31, 0xC0});
			if (imm <= 0xFFFFFFFF) {
				seq.push_back(std::vector<uint8_t>{
					0x48, 0x05,
					(uint8_t)(imm & 0xFF),
					(uint8_t)((imm >> 8) & 0xFF),
					(uint8_t)((imm >> 16) & 0xFF),
					(uint8_t)((imm >> 24) & 0xFF)
				});
			} else {
				seq.push_back(std::vector<uint8_t>{
					0x48, 0xB8,
					(uint8_t)(imm & 0xFF),
					(uint8_t)((imm >> 8) & 0xFF),
					(uint8_t)((imm >> 16) & 0xFF),
					(uint8_t)((imm >> 24) & 0xFF),
					(uint8_t)((imm >> 32) & 0xFF),
					(uint8_t)((imm >> 40) & 0xFF),
					(uint8_t)((imm >> 48) & 0xFF),
					(uint8_t)((imm >> 56) & 0xFF)
				});
			}
		} else if (reg.isGpd()) {
			seq.push_back(std::vector<uint8_t>{0x31, 0xC0});
			seq.push_back(std::vector<uint8_t>{
				0x05,
				(uint8_t)(imm & 0xFF),
				(uint8_t)((imm >> 8) & 0xFF),
				(uint8_t)((imm >> 16) & 0xFF),
				(uint8_t)((imm >> 24) & 0xFF)
			});
		} else if (reg.isGpw()) {
			seq.push_back(std::vector<uint8_t>{0x66, 0x31, 0xC0});
			seq.push_back(std::vector<uint8_t>{
				0x66, 0x05,
				(uint8_t)(imm & 0xFF),
				(uint8_t)((imm >> 8) & 0xFF)
			});
		} else {
			return false;
		}
		for (int i = (int)seq.size() - 1; i >= 0; i--) {
			instruction_t n = make_const_instr(function->func_id, seq[i]);
			instruction = function->instructions.insert(instruction, n);
			instruction++;
		}
		function->instructions.erase(instruction);
		return true;
	}

	if (pattern == 2) {
		// mov rX, K -> xor rX, rX; sub rX, -K
		std::vector<std::vector<uint8_t>> seq;
		uint64_t neg = (~imm) + 1;
		if (reg.isGpq()) {
			seq.push_back(std::vector<uint8_t>{0x48, 0x31, 0xC0});
			seq.push_back(std::vector<uint8_t>{
				0x48, 0x2D,
				(uint8_t)(neg & 0xFF),
				(uint8_t)((neg >> 8) & 0xFF),
				(uint8_t)((neg >> 16) & 0xFF),
				(uint8_t)((neg >> 24) & 0xFF)
			});
		} else if (reg.isGpd()) {
			uint32_t neg32 = (uint32_t)neg;
			seq.push_back(std::vector<uint8_t>{0x31, 0xC0});
			seq.push_back(std::vector<uint8_t>{
				0x2D,
				(uint8_t)(neg32 & 0xFF),
				(uint8_t)((neg32 >> 8) & 0xFF),
				(uint8_t)((neg32 >> 16) & 0xFF),
				(uint8_t)((neg32 >> 24) & 0xFF)
			});
		} else if (reg.isGpw()) {
			uint16_t neg16 = (uint16_t)neg;
			seq.push_back(std::vector<uint8_t>{0x66, 0x31, 0xC0});
			seq.push_back(std::vector<uint8_t>{
				0x66, 0x2D,
				(uint8_t)(neg16 & 0xFF),
				(uint8_t)((neg16 >> 8) & 0xFF)
			});
		} else {
			return false;
		}
		for (int i = (int)seq.size() - 1; i >= 0; i--) {
			instruction_t n = make_const_instr(function->func_id, seq[i]);
			instruction = function->instructions.insert(instruction, n);
			instruction++;
		}
		function->instructions.erase(instruction);
		return true;
	}

	if (pattern == 3) {
		// mov rX, K -> xor rX, rX; lea rX, [rX + K]
		std::vector<std::vector<uint8_t>> seq;
		if (reg.isGpq()) {
			uint32_t disp = (uint32_t)imm;
			seq.push_back(std::vector<uint8_t>{0x48, 0x31, 0xC0});
			seq.push_back(std::vector<uint8_t>{
				0x48, 0x8D, 0x80,
				(uint8_t)(disp & 0xFF),
				(uint8_t)((disp >> 8) & 0xFF),
				(uint8_t)((disp >> 16) & 0xFF),
				(uint8_t)((disp >> 24) & 0xFF)
			});
		} else if (reg.isGpd()) {
			uint32_t disp32 = (uint32_t)imm;
			seq.push_back(std::vector<uint8_t>{0x31, 0xC0});
			seq.push_back(std::vector<uint8_t>{
				0x8D, 0x80,
				(uint8_t)(disp32 & 0xFF),
				(uint8_t)((disp32 >> 8) & 0xFF),
				(uint8_t)((disp32 >> 16) & 0xFF),
				(uint8_t)((disp32 >> 24) & 0xFF)
			});
		} else {
			return false;
		}
		for (int i = (int)seq.size() - 1; i >= 0; i--) {
			instruction_t n = make_const_instr(function->func_id, seq[i]);
			instruction = function->instructions.insert(instruction, n);
			instruction++;
		}
		function->instructions.erase(instruction);
		return true;
	}

	// pattern == 0: LEA_OBF (default)
	// mov rX, K -> xor rX, rX; lea rX, [rX + K]
	{
		std::vector<std::vector<uint8_t>> seq;
		if (reg.isGpq()) {
			uint32_t disp = (uint32_t)imm;
			seq.push_back(std::vector<uint8_t>{0x48, 0x31, 0xC0});
			seq.push_back(std::vector<uint8_t>{
				0x48, 0x8D, 0x80,
				(uint8_t)(disp & 0xFF),
				(uint8_t)((disp >> 8) & 0xFF),
				(uint8_t)((disp >> 16) & 0xFF),
				(uint8_t)((disp >> 24) & 0xFF)
			});
		} else if (reg.isGpd()) {
			uint32_t disp32 = (uint32_t)imm;
			seq.push_back(std::vector<uint8_t>{0x31, 0xC0});
			seq.push_back(std::vector<uint8_t>{
				0x8D, 0x80,
				(uint8_t)(disp32 & 0xFF),
				(uint8_t)((disp32 >> 8) & 0xFF),
				(uint8_t)((disp32 >> 16) & 0xFF),
				(uint8_t)((disp32 >> 24) & 0xFF)
			});
		} else if (reg.isGpw()) {
			uint16_t disp16 = (uint16_t)imm;
			seq.push_back(std::vector<uint8_t>{0x66, 0x31, 0xC0});
			seq.push_back(std::vector<uint8_t>{
				0x66, 0x8D, 0x80,
				(uint8_t)(disp16 & 0xFF),
				(uint8_t)((disp16 >> 8) & 0xFF)
			});
		} else {
			return false;
		}
		for (int i = (int)seq.size() - 1; i >= 0; i--) {
			instruction_t n = make_const_instr(function->func_id, seq[i]);
			instruction = function->instructions.insert(instruction, n);
			instruction++;
		}
		function->instructions.erase(instruction);
		return true;
	}

	return false;
}
