#include "../obfuscator.h"

#include <random>

bool obfuscator::obfuscate_add(std::vector<obfuscator::function_t>::iterator& function, std::vector<obfuscator::instruction_t>::iterator& instruction) {

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

		std::random_device rd;
		std::mt19937 gen(rd());
		int pattern = gen() % 4;

		switch (pattern) {
		case 0:
			// Original: add a,b = a - (~b) - 1 = a - (~b + 1) ... simplified:
			// push b; not b; sub a,b; pop b; sub a,1
			assm.push(second);
			assm.not_(second);
			assm.sub(first, second);
			assm.pop(second);
			assm.sub(first, 1);
			break;

		case 1:
			// add a,b = (a ^ b) + 2*(a & b)
			// Using: lea trick — push a; push b; and a,b; shl a,1; pop b; xor b, [rsp]; add a,b; pop b; (b had original a)
			// Too complex for raw bytes, simpler approach:
			// add a,b = not(not(a) - b) via: not a; sub a,b; not a
			assm.not_(first);
			assm.sub(first, second);
			assm.not_(first);
			break;

		case 2:
			// add a,b using neg: neg b; sub a,b; neg b
			// This works: a + b = a - (-b)
			assm.push(second);  // save original b
			assm.neg(second);
			assm.sub(first, second);
			assm.pop(second);   // restore b
			break;

		case 3:
			// add a,b = a - K + b + K (obfuscated with random constant noise)
			{
				std::uniform_int_distribution<uint32_t> kdist(0x1000, 0x7FFFFFFF);
				uint32_t k = kdist(gen);
				assm.sub(first, k);
				assm.add(first, second);
				assm.add(first, k);
			}
			break;
		}

		void* fn = nullptr;
		auto err = rt.add(&fn, &code);

		auto jitinstructions = this->instructions_from_jit((uint8_t*)fn, code.codeSize());
		int orig_id = instruction->inst_id;
		instruction = function->instructions.erase(instruction);
		instruction -= 1;
		jitinstructions.at(0).inst_id = orig_id;
		for (auto jit : jitinstructions) {
			instruction = function->instructions.insert(instruction + 1, jit);
		}

		code.reset();
		code.init(rt.environment());
		code.attach(&this->assm);


	}

	return true;
}
