#include "../obfuscator.h"

#include <random>

// Check if the next instruction reads CPU flags
static bool next_reads_flags(std::vector<obfuscator::instruction_t>::iterator instruction,
	std::vector<obfuscator::instruction_t>::iterator end) {
	auto next = instruction + 1;
	if (next == end) return true;
	auto m = next->zyinstr.info.mnemonic;

	switch (m) {
	case ZYDIS_MNEMONIC_JNBE: case ZYDIS_MNEMONIC_JB: case ZYDIS_MNEMONIC_JBE:
	case ZYDIS_MNEMONIC_JL: case ZYDIS_MNEMONIC_JLE: case ZYDIS_MNEMONIC_JNB:
	case ZYDIS_MNEMONIC_JNL: case ZYDIS_MNEMONIC_JNLE: case ZYDIS_MNEMONIC_JNO:
	case ZYDIS_MNEMONIC_JNP: case ZYDIS_MNEMONIC_JNS: case ZYDIS_MNEMONIC_JNZ:
	case ZYDIS_MNEMONIC_JO: case ZYDIS_MNEMONIC_JP: case ZYDIS_MNEMONIC_JS:
	case ZYDIS_MNEMONIC_JZ:
	case ZYDIS_MNEMONIC_CMOVB: case ZYDIS_MNEMONIC_CMOVBE: case ZYDIS_MNEMONIC_CMOVL:
	case ZYDIS_MNEMONIC_CMOVLE: case ZYDIS_MNEMONIC_CMOVNB: case ZYDIS_MNEMONIC_CMOVNBE:
	case ZYDIS_MNEMONIC_CMOVNL: case ZYDIS_MNEMONIC_CMOVNLE: case ZYDIS_MNEMONIC_CMOVNO:
	case ZYDIS_MNEMONIC_CMOVNP: case ZYDIS_MNEMONIC_CMOVNS: case ZYDIS_MNEMONIC_CMOVNZ:
	case ZYDIS_MNEMONIC_CMOVO: case ZYDIS_MNEMONIC_CMOVP: case ZYDIS_MNEMONIC_CMOVS:
	case ZYDIS_MNEMONIC_CMOVZ:
	case ZYDIS_MNEMONIC_SETB: case ZYDIS_MNEMONIC_SETBE: case ZYDIS_MNEMONIC_SETL:
	case ZYDIS_MNEMONIC_SETLE: case ZYDIS_MNEMONIC_SETNB: case ZYDIS_MNEMONIC_SETNBE:
	case ZYDIS_MNEMONIC_SETNL: case ZYDIS_MNEMONIC_SETNLE: case ZYDIS_MNEMONIC_SETNO:
	case ZYDIS_MNEMONIC_SETNP: case ZYDIS_MNEMONIC_SETNS: case ZYDIS_MNEMONIC_SETNZ:
	case ZYDIS_MNEMONIC_SETO: case ZYDIS_MNEMONIC_SETP: case ZYDIS_MNEMONIC_SETS:
	case ZYDIS_MNEMONIC_SETZ:
	case ZYDIS_MNEMONIC_ADC: case ZYDIS_MNEMONIC_SBB:
	case ZYDIS_MNEMONIC_RCL: case ZYDIS_MNEMONIC_RCR:
	case ZYDIS_MNEMONIC_PUSHF: case ZYDIS_MNEMONIC_PUSHFQ:
		return true;
	default:
		return false;
	}
}

bool obfuscator::obfuscate_xor(std::vector<obfuscator::function_t>::iterator& function, std::vector<obfuscator::instruction_t>::iterator& instruction) {

	if (instruction->zyinstr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && instruction->zyinstr.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {

		if (instruction->zyinstr.operands[0].size < 32)
			return true;

		auto first = lookupmap.find(instruction->zyinstr.operands[0].reg.value)->second;
		auto second = lookupmap.find(instruction->zyinstr.operands[1].reg.value)->second;

		// xor reg,reg is a zeroing idiom — don't mutate
		if (first == second)
			return true;

		if (first == x86::rsp || second == x86::rsp)
			return true;

		if (first.size() != second.size())
			return true;

		// Skip mutation if next instruction reads flags
		if (next_reads_flags(instruction, function->instructions.end()))
			return true;

		std::random_device rd;
		std::mt19937 gen(rd());
		int pattern = gen() % 7;

		switch (pattern) {
		case 0:
			// xor a,b = (a+b) - 2*(a&b), uses ecx/rcx scratch
			{
				x86::Gp scratch = (first.size() == 8) ? x86::Gp(x86::rcx) : x86::Gp(x86::ecx);

				if (first == x86::rcx || first == x86::ecx || second == x86::rcx || second == x86::ecx) {
					assm.xor_(first, second);
				}
				else {
					assm.push(scratch);
					assm.mov(scratch, first);
					assm.and_(scratch, second);
					assm.shl(scratch, 1);
					assm.add(first, second);
					assm.sub(first, scratch);
					assm.pop(scratch);
				}
			}
			break;

		case 1:
			// xor a,b = (~a & b) | (a & ~b), uses ecx/rcx scratch
			{
				x86::Gp scratch = (first.size() == 8) ? x86::Gp(x86::rcx) : x86::Gp(x86::ecx);

				if (first == x86::rcx || first == x86::ecx || second == x86::rcx || second == x86::ecx) {
					assm.xor_(first, second);
				}
				else {
					assm.push(scratch);
					assm.push(second);
					assm.mov(scratch, first);
					assm.not_(scratch);
					assm.and_(scratch, second);
					assm.not_(second);
					assm.and_(first, second);
					assm.pop(second);
					assm.or_(first, scratch);
					assm.pop(scratch);
				}
			}
			break;

		case 2:
			// Same as 0 but with edx/rdx scratch
			{
				x86::Gp scratch = (first.size() == 8) ? x86::Gp(x86::rdx) : x86::Gp(x86::edx);

				if (first == x86::rdx || first == x86::edx || second == x86::rdx || second == x86::edx) {
					assm.xor_(first, second);
				}
				else {
					assm.push(scratch);
					assm.mov(scratch, first);
					assm.and_(scratch, second);
					assm.shl(scratch, 1);
					assm.add(first, second);
					assm.sub(first, scratch);
					assm.pop(scratch);
				}
			}
			break;

		case 3:
			// ~a ^ ~b = a ^ b (complement identity)
			// push b; not a; not b; xor a,b; pop b
			assm.push(second);
			assm.not_(first);
			assm.not_(second);
			assm.xor_(first, second);
			assm.pop(second);
			break;

		case 4:
			// Constant noise: xor a,K; xor a,b; xor a,K
			{
				std::uniform_int_distribution<uint32_t> kdist(0x1000, 0x7FFFFFFF);
				uint32_t k = kdist(gen);
				assm.xor_(first, k);
				assm.xor_(first, second);
				assm.xor_(first, k);
			}
			break;

		case 5:
			// Noise + xor: sub a,b; add a,b; xor a,b (sub+add cancel)
			assm.sub(first, second);
			assm.add(first, second);
			assm.xor_(first, second);
			break;

		case 6:
			// Double neg cancels: push b; neg b; neg b; xor a,b; pop b
			assm.push(second);
			assm.neg(second);
			assm.neg(second);
			assm.xor_(first, second);
			assm.pop(second);
			break;
		}

		void* fn = nullptr;
		auto err = rt.add(&fn, &code);

		auto jitinstructions = this->instructions_from_jit((uint8_t*)fn, code.codeSize());
		int orig_id = instruction->inst_id;
		instruction = function->instructions.erase(instruction);
		instruction -= 1;
		jitinstructions.at(0).inst_id = orig_id;

		// Embed anti-emu checks between MBA operations
		embed_antiemu_noise(jitinstructions, function->func_id, gen);

		for (auto jit : jitinstructions) {
			instruction = function->instructions.insert(instruction + 1, jit);
		}

		code.reset();
		code.init(rt.environment());
		code.attach(&this->assm);
	}

	return true;
}
