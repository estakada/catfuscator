#include "../obfuscator.h"

#include <random>

// Check if the next instruction reads CPU flags (Jcc, SETcc, CMOVcc, ADC, SBB, etc.)
static bool next_reads_flags(std::vector<obfuscator::instruction_t>::iterator instruction,
	std::vector<obfuscator::instruction_t>::iterator end) {
	auto next = instruction + 1;
	if (next == end) return true; // conservatively assume yes at function end
	auto m = next->zyinstr.info.mnemonic;

	// Conditional jumps
	switch (m) {
	case ZYDIS_MNEMONIC_JNBE: case ZYDIS_MNEMONIC_JB: case ZYDIS_MNEMONIC_JBE:
	case ZYDIS_MNEMONIC_JL: case ZYDIS_MNEMONIC_JLE: case ZYDIS_MNEMONIC_JNB:
	case ZYDIS_MNEMONIC_JNL: case ZYDIS_MNEMONIC_JNLE: case ZYDIS_MNEMONIC_JNO:
	case ZYDIS_MNEMONIC_JNP: case ZYDIS_MNEMONIC_JNS: case ZYDIS_MNEMONIC_JNZ:
	case ZYDIS_MNEMONIC_JO: case ZYDIS_MNEMONIC_JP: case ZYDIS_MNEMONIC_JS:
	case ZYDIS_MNEMONIC_JZ:
	// CMOVcc
	case ZYDIS_MNEMONIC_CMOVB: case ZYDIS_MNEMONIC_CMOVBE: case ZYDIS_MNEMONIC_CMOVL:
	case ZYDIS_MNEMONIC_CMOVLE: case ZYDIS_MNEMONIC_CMOVNB: case ZYDIS_MNEMONIC_CMOVNBE:
	case ZYDIS_MNEMONIC_CMOVNL: case ZYDIS_MNEMONIC_CMOVNLE: case ZYDIS_MNEMONIC_CMOVNO:
	case ZYDIS_MNEMONIC_CMOVNP: case ZYDIS_MNEMONIC_CMOVNS: case ZYDIS_MNEMONIC_CMOVNZ:
	case ZYDIS_MNEMONIC_CMOVO: case ZYDIS_MNEMONIC_CMOVP: case ZYDIS_MNEMONIC_CMOVS:
	case ZYDIS_MNEMONIC_CMOVZ:
	// SETcc
	case ZYDIS_MNEMONIC_SETB: case ZYDIS_MNEMONIC_SETBE: case ZYDIS_MNEMONIC_SETL:
	case ZYDIS_MNEMONIC_SETLE: case ZYDIS_MNEMONIC_SETNB: case ZYDIS_MNEMONIC_SETNBE:
	case ZYDIS_MNEMONIC_SETNL: case ZYDIS_MNEMONIC_SETNLE: case ZYDIS_MNEMONIC_SETNO:
	case ZYDIS_MNEMONIC_SETNP: case ZYDIS_MNEMONIC_SETNS: case ZYDIS_MNEMONIC_SETNZ:
	case ZYDIS_MNEMONIC_SETO: case ZYDIS_MNEMONIC_SETP: case ZYDIS_MNEMONIC_SETS:
	case ZYDIS_MNEMONIC_SETZ:
	// Carry-dependent
	case ZYDIS_MNEMONIC_ADC: case ZYDIS_MNEMONIC_SBB:
	case ZYDIS_MNEMONIC_RCL: case ZYDIS_MNEMONIC_RCR:
	case ZYDIS_MNEMONIC_PUSHF: case ZYDIS_MNEMONIC_PUSHFQ:
		return true;
	default:
		return false;
	}
}

bool obfuscator::obfuscate_sub(std::vector<obfuscator::function_t>::iterator& function, std::vector<obfuscator::instruction_t>::iterator& instruction) {

	if (instruction->zyinstr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && instruction->zyinstr.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {

		if (instruction->zyinstr.operands[0].size < 32)
			return true;

		auto first = lookupmap.find(instruction->zyinstr.operands[0].reg.value)->second;
		auto second = lookupmap.find(instruction->zyinstr.operands[1].reg.value)->second;

		if (first == second)
			return true;

		if (first == x86::rsp || second == x86::rsp)
			return true;

		if (first.size() != second.size())
			return true;

		// Skip mutation if next instruction reads flags — our patterns don't preserve flags
		if (next_reads_flags(instruction, function->instructions.end()))
			return true;

		std::random_device rd;
		std::mt19937 gen(rd());
		int pattern = gen() % 7;

		switch (pattern) {
		case 0:
			// sub a,b = a + (-b): push b; neg b; add a,b; pop b
			assm.push(second);
			assm.neg(second);
			assm.add(first, second);
			assm.pop(second);
			break;

		case 1:
			// sub a,b = ~(~a + b): not a; add a,b; not a
			assm.not_(first);
			assm.add(first, second);
			assm.not_(first);
			break;

		case 2:
			// sub a,b via two's complement: push b; not b; add b,1; add a,b; pop b
			assm.push(second);
			assm.not_(second);
			assm.add(second, 1);
			assm.add(first, second);
			assm.pop(second);
			break;

		case 3:
			// sub a,b with constant noise: sub a,K; sub a,b; add a,K
			{
				std::uniform_int_distribution<uint32_t> kdist(0x1000, 0x7FFFFFFF);
				uint32_t k = kdist(gen);
				assm.sub(first, k);
				assm.sub(first, second);
				assm.add(first, k);
			}
			break;

		case 4:
			// sub a,b = a + b - 2*b: add a,b; push b; shl b,1; sub a,b; pop b
			assm.add(first, second);
			assm.push(second);
			assm.shl(second, 1);
			assm.sub(first, second);
			assm.pop(second);
			break;

		case 5:
			// sub a,b = -((-a) + b): neg a; add a,b; neg a
			assm.neg(first);
			assm.add(first, second);
			assm.neg(first);
			break;

		case 6:
			// sub a,b with add noise: add a,1; sub a,b; sub a,1
			assm.add(first, 1);
			assm.sub(first, second);
			assm.sub(first, 1);
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
