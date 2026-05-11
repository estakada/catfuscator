#include "../obfuscator.h"

#include <random>
#include <algorithm>

bool obfuscator::obfuscate_mov(std::vector<obfuscator::function_t>::iterator& function, std::vector<obfuscator::instruction_t>::iterator& instruction) {

	if (instruction->zyinstr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && instruction->zyinstr.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {

		auto x86_register_map = lookupmap.find(instruction->zyinstr.operands[0].reg.value);

		if (x86_register_map != lookupmap.end()) {

			int bit_of_value = instruction->zyinstr.info.raw.imm->size;

			auto usingregister = x86_register_map->second;

			//If the datatype doesnt match the register we skip it due to our rotations. You could translate to that register but meh
			if (bit_of_value == 8 && !usingregister.isGpb())
				return false;

			if (bit_of_value == 16 && !usingregister.isGpw())
				return false;

			if (bit_of_value == 32 && !usingregister.isGpd())
				return false;

			if (bit_of_value == 64 && !usingregister.isGpq())
				return false;


			std::random_device rd;
			std::mt19937 gen(rd());

			uint32_t random_add_val, rand_xor_val, rand_rot_val, rand_sub_val;
			std::uniform_int_distribution<uint32_t> dist8(1, 255);
			std::uniform_int_distribution<uint16_t> dist16(INT16_MAX / 2, INT16_MAX);
			std::uniform_int_distribution<uint32_t> dist32(UINT32_MAX / 2, UINT32_MAX);
			// For 64-bit: must stay < 0x80000000 to avoid sign-extension mismatch
			// (x64 add/sub/xor rax,imm32 sign-extends, encode uses zero-extension)
			std::uniform_int_distribution<uint32_t> dist64(INT32_MAX / 2, INT32_MAX);

			switch (bit_of_value) {
			case 8:
				random_add_val = dist8(gen);
				rand_xor_val = dist8(gen);
				rand_rot_val = dist8(gen);
				rand_sub_val = dist8(gen);
				break;
			case 16:
				random_add_val = dist16(gen);
				rand_xor_val = dist16(gen);
				rand_rot_val = dist16(gen);
				rand_sub_val = dist16(gen);
				break;
			case 32:
				random_add_val = dist32(gen);
				rand_xor_val = dist32(gen);
				rand_rot_val = dist32(gen);
				rand_sub_val = dist32(gen);
				break;
			case 64:
			default:
				random_add_val = dist64(gen);
				rand_xor_val = dist64(gen);
				rand_rot_val = dist64(gen);
				rand_sub_val = dist64(gen);
				break;
			}

			// Choose one of 4 mutation patterns randomly
			int pattern = gen() % 4;

			// Each pattern applies a different sequence of reversible operations.
			// The immediate value is pre-encoded with the INVERSE of the chosen pattern.
			// At runtime the mutation code decodes it back to the original value.

			switch (pattern) {
			case 0: {
				// Pattern: not -> add -> xor -> rol  (original)
				// Encode: val = ~( rotr( (val ^ xor) - add ) )
				switch (bit_of_value) {
				case 8:  *(uint8_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.info.raw.imm->offset]) = ~((_rotr8(*(uint8_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.info.raw.imm->offset]), rand_rot_val) ^ rand_xor_val) - random_add_val); break;
				case 16: *(uint16_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.info.raw.imm->offset]) = ~((_rotr16(*(uint16_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.info.raw.imm->offset]), rand_rot_val) ^ rand_xor_val) - random_add_val); break;
				case 32: *(uint32_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.info.raw.imm->offset]) = ~((_rotr(*(uint32_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.info.raw.imm->offset]), rand_rot_val) ^ rand_xor_val) - random_add_val); break;
				case 64: *(uint64_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.info.raw.imm->offset]) = ~((_rotr64(*(uint64_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.info.raw.imm->offset]), rand_rot_val) ^ rand_xor_val) - random_add_val); break;
				}
				assm.pushf();
				assm.not_(usingregister);
				assm.add(usingregister, random_add_val);
				assm.xor_(usingregister, rand_xor_val);
				assm.rol(usingregister, rand_rot_val);
				assm.popf();
				break;
			}
			case 1: {
				// Pattern: xor -> rol -> add -> not
				// Decode sequence: xor K1, rol K2, add K3, not
				// Encode: val = ( ~(val) - K3 ) rotr K2 ) ^ K1
				switch (bit_of_value) {
				case 8:  { uint8_t v = *(uint8_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.info.raw.imm->offset]); v = _rotr8((uint8_t)(~v - (uint8_t)random_add_val), rand_rot_val) ^ (uint8_t)rand_xor_val; *(uint8_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.info.raw.imm->offset]) = v; break; }
				case 16: { uint16_t v = *(uint16_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.info.raw.imm->offset]); v = _rotr16((uint16_t)(~v - (uint16_t)random_add_val), rand_rot_val) ^ (uint16_t)rand_xor_val; *(uint16_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.info.raw.imm->offset]) = v; break; }
				case 32: { uint32_t v = *(uint32_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.info.raw.imm->offset]); v = _rotr((uint32_t)(~v - random_add_val), rand_rot_val) ^ rand_xor_val; *(uint32_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.info.raw.imm->offset]) = v; break; }
				case 64: { uint64_t v = *(uint64_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.info.raw.imm->offset]); v = _rotr64((uint64_t)(~v - random_add_val), rand_rot_val) ^ (uint64_t)rand_xor_val; *(uint64_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.info.raw.imm->offset]) = v; break; }
				}
				assm.pushf();
				assm.xor_(usingregister, rand_xor_val);
				assm.rol(usingregister, rand_rot_val);
				assm.add(usingregister, random_add_val);
				assm.not_(usingregister);
				assm.popf();
				break;
			}
			case 2: {
				// Pattern 2: sub K1, rol K2, xor K3, neg
				// Decode runtime: reg -= K1; reg = rol(reg, K2); reg ^= K3; reg = -reg
				// result = -(rol(encoded - K1, K2) ^ K3)
				// Encode: encoded = rotr((-V) ^ K3, K2) + K1
				switch (bit_of_value) {
				case 8:  { uint8_t v = *(uint8_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.info.raw.imm->offset]); v = _rotr8((uint8_t)(((uint8_t)(-v)) ^ (uint8_t)rand_xor_val), rand_rot_val) + (uint8_t)random_add_val; *(uint8_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.info.raw.imm->offset]) = v; break; }
				case 16: { uint16_t v = *(uint16_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.info.raw.imm->offset]); v = _rotr16((uint16_t)(((uint16_t)(-v)) ^ (uint16_t)rand_xor_val), rand_rot_val) + (uint16_t)random_add_val; *(uint16_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.info.raw.imm->offset]) = v; break; }
				case 32: { uint32_t v = *(uint32_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.info.raw.imm->offset]); v = _rotr(((uint32_t)(-(int32_t)v)) ^ rand_xor_val, rand_rot_val) + random_add_val; *(uint32_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.info.raw.imm->offset]) = v; break; }
				case 64: { uint64_t v = *(uint64_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.info.raw.imm->offset]); v = _rotr64(((uint64_t)(-(int64_t)v)) ^ (uint64_t)rand_xor_val, rand_rot_val) + (uint64_t)random_add_val; *(uint64_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.info.raw.imm->offset]) = v; break; }
				}
				assm.pushf();
				assm.sub(usingregister, random_add_val);
				assm.rol(usingregister, rand_rot_val);
				assm.xor_(usingregister, rand_xor_val);
				assm.neg(usingregister);
				assm.popf();
				break;
			}
			case 3: {
				// Pattern 3: ror K2, xor K3, add K1, not
				// Decode runtime: reg = ror(reg, K2); reg ^= K3; reg += K1; reg = ~reg
				// result = ~(ror(encoded, K2) ^ K3 + K1)
				// Encode: encoded = rotl((~V - K1) ^ K3, K2)
				switch (bit_of_value) {
				case 8:  { uint8_t v = *(uint8_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.info.raw.imm->offset]); v = _rotl8((uint8_t)((uint8_t)(~v - (uint8_t)random_add_val) ^ (uint8_t)rand_xor_val), rand_rot_val); *(uint8_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.info.raw.imm->offset]) = v; break; }
				case 16: { uint16_t v = *(uint16_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.info.raw.imm->offset]); v = _rotl16((uint16_t)((uint16_t)(~v - (uint16_t)random_add_val) ^ (uint16_t)rand_xor_val), rand_rot_val); *(uint16_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.info.raw.imm->offset]) = v; break; }
				case 32: { uint32_t v = *(uint32_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.info.raw.imm->offset]); v = _rotl((uint32_t)((~v - random_add_val) ^ rand_xor_val), rand_rot_val); *(uint32_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.info.raw.imm->offset]) = v; break; }
				case 64: { uint64_t v = *(uint64_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.info.raw.imm->offset]); v = _rotl64((uint64_t)((~v - (uint64_t)random_add_val) ^ (uint64_t)rand_xor_val), rand_rot_val); *(uint64_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.info.raw.imm->offset]) = v; break; }
				}
				assm.pushf();
				assm.ror(usingregister, rand_rot_val);
				assm.xor_(usingregister, rand_xor_val);
				assm.add(usingregister, random_add_val);
				assm.not_(usingregister);
				assm.popf();
				break;
			}
			}

			void* fn = nullptr;
			auto err = rt.add(&fn, &code);

			auto jitinstructions = this->instructions_from_jit((uint8_t*)fn, code.codeSize());
			instruction = function->instructions.insert(instruction + 1, jitinstructions.begin(), jitinstructions.end());
			instruction = instruction + jitinstructions.size() - 1;

			code.reset();
			code.init(rt.environment());
			code.attach(&this->assm);
			return true;

		}

	}

	return false;
}
