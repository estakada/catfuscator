#include "../obfuscator.h"

#include <random>
#include <numeric>
#include <algorithm>

bool is_jmp_conditional(ZydisDecodedInstruction instr) {
	switch (instr.mnemonic)
	{
	case ZYDIS_MNEMONIC_JNBE:
	case ZYDIS_MNEMONIC_JB:
	case ZYDIS_MNEMONIC_JBE:
	case ZYDIS_MNEMONIC_JCXZ:
	case ZYDIS_MNEMONIC_JECXZ:
	case ZYDIS_MNEMONIC_JKNZD:
	case ZYDIS_MNEMONIC_JKZD:
	case ZYDIS_MNEMONIC_JL:
	case ZYDIS_MNEMONIC_JLE:
	case ZYDIS_MNEMONIC_JNB:
	case ZYDIS_MNEMONIC_JNL:
	case ZYDIS_MNEMONIC_JNLE:
	case ZYDIS_MNEMONIC_JNO:
	case ZYDIS_MNEMONIC_JNP:
	case ZYDIS_MNEMONIC_JNS:
	case ZYDIS_MNEMONIC_JNZ:
	case ZYDIS_MNEMONIC_JO:
	case ZYDIS_MNEMONIC_JP:
	case ZYDIS_MNEMONIC_JRCXZ:
	case ZYDIS_MNEMONIC_JS:
	case ZYDIS_MNEMONIC_JZ:
		return true;
	default:
		return false;
	}
	return false;
}



bool obfuscator::flatten_control_flow(std::vector<obfuscator::function_t>::iterator& func) {

	struct block_t {
		int block_id;
		std::vector < obfuscator::instruction_t>instructions;

		int next_block;
		int dst_block = -1;

	};

	std::vector<block_t>blocks;
	std::vector<int>block_starts;
	block_t block;
	int block_iterator = 0;

	//In the first round we mark all jmp destinations that land back inside this func
	for (auto instruction = func->instructions.begin(); instruction != func->instructions.end(); instruction++) {

		if (is_jmp_conditional(instruction->zyinstr.info) || (instruction->zyinstr.info.mnemonic == ZYDIS_MNEMONIC_JMP && instruction->zyinstr.info.raw.imm->size == 8)) {

			if (instruction->relative.target_func_id == func->func_id) {
				block_starts.push_back(instruction->relative.target_inst_id);
			}
		}
	}

	//Now we create our blocks
	for (auto instruction = func->instructions.begin(); instruction != func->instructions.end(); instruction++) {

		block.instructions.push_back(*instruction);
		auto next_instruction = instruction + 1;

		if (next_instruction != func->instructions.end()) {

			if (std::find(block_starts.begin(), block_starts.end(), next_instruction->inst_id) != block_starts.end()) {
				block.block_id = block_iterator++;
				blocks.push_back(block);
				block.instructions.clear();
				continue;
			}
		}
		else {
			block.block_id = block_iterator++;
			blocks.push_back(block);
			block.instructions.clear();
			continue;
		}

		if (instruction->zyinstr.info.mnemonic == ZYDIS_MNEMONIC_RET || (instruction->isjmpcall && instruction->zyinstr.info.mnemonic != ZYDIS_MNEMONIC_CALL))
		{
			block.block_id = block_iterator++;
			blocks.push_back(block);
			block.instructions.clear();
		}
	}


	//Time to link them together
	for (auto current_block = blocks.begin(); current_block != blocks.end(); current_block++) {

		auto last_instruction = current_block->instructions.end() - 1;
		current_block->next_block = current_block->block_id + 1;


		if (last_instruction->isjmpcall && is_jmp_conditional(last_instruction->zyinstr.info)) {
			for (auto current_block2 = blocks.begin(); current_block2 != blocks.end(); current_block2++) {

				auto first_instruction = current_block2->instructions.begin();
				if (first_instruction->inst_id == last_instruction->relative.target_inst_id) {
					current_block->dst_block = current_block2->block_id;
					break;
				}
			}
		}
	}

	int first_inst_id = func->instructions.begin()->inst_id;
	int new_id = this->instruction_id++;
	func->instructions.begin()->inst_id = new_id;
	func->instructions.begin()->is_first_instruction = false;


	//Lets shuffle so they cant just strip our stuff
	auto rng = std::default_random_engine{};
	std::shuffle(blocks.begin(), blocks.end(), rng);

	// --- Indirect jump table dispatch (anti-pattern-matching) ---
	// Instead of linear cmp/jnz for each block, we use:
	//   push rax; pushf; mov eax, <scrambled_id>
	//   ... dispatch: xor eax, KEY; jmp qword [rip + table + rax*8]
	// The jump table contains relative offsets to each block.

	std::random_device cff_rd;
	std::mt19937 cff_rng(cff_rd());

	int num_blocks = (int)blocks.size();

	// Generate a random XOR key for block ID scrambling
	std::uniform_int_distribution<uint32_t> key_dist(0x10000, 0x7FFFFFFF);
	uint32_t xor_key = key_dist(cff_rng);

	// Create a mapping: real block_id -> table_index (randomized)
	std::vector<int> id_to_index(num_blocks);
	std::iota(id_to_index.begin(), id_to_index.end(), 0);

	// Build scrambled IDs: scrambled = block_id ^ xor_key
	// At dispatch: eax ^= xor_key -> recovers block_id -> used as index into jump table

	// Prologue: push rax; pushf; mov eax, scrambled_first_block_id
	uint32_t first_scrambled = 0 ^ xor_key;
	instruction_t push_rax{}; push_rax.load(func->func_id, { 0x50 });
	push_rax.inst_id = first_inst_id;
	push_rax.is_first_instruction = false;
	auto it = func->instructions.insert(func->instructions.begin(), push_rax);
	instruction_t push_f{}; push_f.load(func->func_id, { 0x66, 0x9C });
	it = func->instructions.insert(it + 1, push_f);
	instruction_t mov_eax_scrambled{}; mov_eax_scrambled.load(func->func_id, { 0xB8, 0x00,0x00,0x00,0x00 });
	*(uint32_t*)&mov_eax_scrambled.raw_bytes.data()[1] = first_scrambled;
	it = func->instructions.insert(it + 1, mov_eax_scrambled);

	// Dispatch block: xor eax, KEY; popf; pop rax
	// Then for each block we emit a separate cmp/je pair but with scrambled values
	// and add dummy arithmetic to obscure the pattern.
	//
	// We use a different approach: emit ADD+XOR+SUB chain to decode eax,
	// then use a series of scrambled comparisons with random ordering.

	// Generate random ADD/SUB constants for multi-step decode
	uint32_t add_key1 = key_dist(cff_rng);
	uint32_t xor_key2 = key_dist(cff_rng);
	// Encoding: scrambled = ((block_id + add_key1) ^ xor_key) + xor_key2
	// Decoding: block_id = ((scrambled - xor_key2) ^ xor_key) - add_key1

	// Re-encode first block
	first_scrambled = ((0 + add_key1) ^ xor_key) + xor_key2;
	*(uint32_t*)&mov_eax_scrambled.raw_bytes.data()[1] = first_scrambled;
	// Update in-place since we already inserted
	*(uint32_t*)&it->raw_bytes.data()[1] = first_scrambled;

	// Emit decode sequence: sub eax, xor_key2; xor eax, xor_key; sub eax, add_key1
	// 83 E8 xx or 2D xxxxxxxx  -> sub eax, imm32
	// 35 xxxxxxxx              -> xor eax, imm32
	instruction_t sub_key2{}; sub_key2.load(func->func_id, { 0x2D, 0x00,0x00,0x00,0x00 });
	*(uint32_t*)&sub_key2.raw_bytes.data()[1] = xor_key2;
	it = func->instructions.insert(it + 1, sub_key2);

	instruction_t xor_key_instr{}; xor_key_instr.load(func->func_id, { 0x35, 0x00,0x00,0x00,0x00 });
	*(uint32_t*)&xor_key_instr.raw_bytes.data()[1] = xor_key;
	it = func->instructions.insert(it + 1, xor_key_instr);

	instruction_t sub_key1{}; sub_key1.load(func->func_id, { 0x2D, 0x00,0x00,0x00,0x00 });
	*(uint32_t*)&sub_key1.raw_bytes.data()[1] = add_key1;
	it = func->instructions.insert(it + 1, sub_key1);

	// Now eax = real block_id. Emit scrambled cmp/jnz dispatch.
	// We randomize comparison order (blocks are already shuffled) and use
	// varied instruction patterns per block to defeat signature matching.

	for (auto current_block = blocks.begin(); current_block != blocks.end(); current_block++) {

		// Pick a random dispatch pattern for this block (3 variants)
		// All patterns use non-destructive comparison (cmp or push/sub/pop)
		// so eax is preserved for the next iteration if no match.
		int pattern = cff_rng() % 3;

		if (pattern == 0) {
			// Pattern 0: cmp eax, ID; jnz skip; popf; pop rax; jmp block
			instruction_t cmp_eax{}; cmp_eax.load(func->func_id, { 0x3D, 0x00,0x00,0x00,0x00 });
			*(uint32_t*)&cmp_eax.raw_bytes.data()[1] = current_block->block_id;

			instruction_t jne{}; jne.load(func->func_id, { 0x75, 0x08 });
			instruction_t pop_f{}; pop_f.load(func->func_id, { 0x66, 0x9D });
			instruction_t pop_rax{}; pop_rax.load(func->func_id, { 0x58 });

			instruction_t jmp{}; jmp.load(func->func_id, { 0xE9,0x00,0x00,0x00,0x00 });
			jmp.relative.target_inst_id = current_block->block_id == 0 ? new_id : current_block->instructions.begin()->inst_id;
			jmp.relative.target_func_id = func->func_id;

			it = func->instructions.insert(it + 1, { cmp_eax, jne, pop_f, pop_rax, jmp });
			it = it + 4;
		}
		else if (pattern == 1) {
			// Pattern 1: push eax; sub eax,ID; test eax,eax; pop eax; jnz skip; popf; pop rax; jmp block
			// (sub then test instead of cmp — different opcode, eax preserved via push/pop)
			uint32_t bid = current_block->block_id;

			instruction_t push_eax{}; push_eax.load(func->func_id, { 0x50 }); // push eax (save)

			instruction_t sub_id{}; sub_id.load(func->func_id, { 0x2D, 0x00,0x00,0x00,0x00 });
			*(uint32_t*)&sub_id.raw_bytes.data()[1] = bid;

			instruction_t test_eax{}; test_eax.load(func->func_id, { 0x85, 0xC0 }); // test eax, eax

			instruction_t pop_eax_restore{}; pop_eax_restore.load(func->func_id, { 0x58 }); // pop eax (restore)

			instruction_t jne{}; jne.load(func->func_id, { 0x75, 0x08 }); // skip popf+pop+jmp

			instruction_t pop_f{}; pop_f.load(func->func_id, { 0x66, 0x9D });
			instruction_t pop_rax{}; pop_rax.load(func->func_id, { 0x58 });

			instruction_t jmp{}; jmp.load(func->func_id, { 0xE9,0x00,0x00,0x00,0x00 });
			jmp.relative.target_inst_id = current_block->block_id == 0 ? new_id : current_block->instructions.begin()->inst_id;
			jmp.relative.target_func_id = func->func_id;

			it = func->instructions.insert(it + 1, { push_eax, sub_id, test_eax, pop_eax_restore, jne, pop_f, pop_rax, jmp });
			it = it + 7;
		}
		else {
			// Pattern 2: push eax; xor eax,ID; pop eax; jnz skip; popf; pop rax; jmp block
			// (xor sets ZF if matched, eax preserved via push/pop)
			uint32_t bid = current_block->block_id;

			instruction_t push_eax{}; push_eax.load(func->func_id, { 0x50 }); // push eax (save)

			instruction_t xor_id{}; xor_id.load(func->func_id, { 0x35, 0x00,0x00,0x00,0x00 });
			*(uint32_t*)&xor_id.raw_bytes.data()[1] = bid;

			instruction_t pop_eax_restore{}; pop_eax_restore.load(func->func_id, { 0x58 }); // pop eax (restore)

			instruction_t jne{}; jne.load(func->func_id, { 0x75, 0x08 }); // skip popf+pop+jmp

			instruction_t pop_f{}; pop_f.load(func->func_id, { 0x66, 0x9D });
			instruction_t pop_rax{}; pop_rax.load(func->func_id, { 0x58 });

			instruction_t jmp{}; jmp.load(func->func_id, { 0xE9,0x00,0x00,0x00,0x00 });
			jmp.relative.target_inst_id = current_block->block_id == 0 ? new_id : current_block->instructions.begin()->inst_id;
			jmp.relative.target_func_id = func->func_id;

			it = func->instructions.insert(it + 1, { push_eax, xor_id, pop_eax_restore, jne, pop_f, pop_rax, jmp });
			it = it + 6;
		}
	}

	// Fix JNZ targets: each JNZ must point to the next comparison block
	for (auto inst = func->instructions.begin(); inst != it + 1; inst++) {
		if (inst->zyinstr.info.mnemonic == ZYDIS_MNEMONIC_JNZ) {
			// Find the next dispatch entry: skip past the E9 jmp to find next push/cmp
			auto search = inst + 1;
			while (search != it + 1 && search != func->instructions.end()) {
				if (search->zyinstr.info.mnemonic == ZYDIS_MNEMONIC_JMP &&
					search->raw_bytes.data()[0] == 0xE9) {
					search++; // past the jmp = start of next entry
					break;
				}
				search++;
			}
			if (search != func->instructions.end() && search <= it) {
				inst->relative.target_func_id = func->func_id;
				inst->relative.target_inst_id = search->inst_id;
			}
		}
	}

	// Lambda to encode block_id -> scrambled value
	auto encode_block_id = [&](uint32_t bid) -> uint32_t {
		return ((bid + add_key1) ^ xor_key) + xor_key2;
	};

	for (auto current_block = blocks.begin(); current_block != blocks.end() - 1; current_block++) {

		auto last_instruction = std::find_if(func->instructions.begin(), func->instructions.end(), [&](obfuscator::instruction_t it) {
			return it.inst_id == (current_block->instructions.end() - 1)->inst_id;
			});

		auto next_block = std::find_if(blocks.begin(), blocks.end(), [&](const block_t block) {return block.block_id == current_block->next_block; });
		if (next_block == blocks.end()) continue;

		if (is_jmp_conditional(last_instruction->zyinstr.info) && current_block->dst_block != -1) {

			auto dst_block = std::find_if(blocks.begin(), blocks.end(), [&](const block_t block) {return block.block_id == current_block->dst_block; });

			//This happens if condition is not met
			{
				instruction_t push_rax{}; push_rax.load(func->func_id, { 0x50 });

				instruction_t push_f{}; push_f.load(func->func_id, { 0x66, 0x9C });

				instruction_t mov_eax{}; mov_eax.load(func->func_id, { 0xB8, 0x00,0x00,0x00,0x00 });
				*(uint32_t*)(&mov_eax.raw_bytes.data()[1]) = encode_block_id(next_block->block_id);

				instruction_t jmp{}; jmp.load(func->func_id, { 0xE9, 0x00,0x00,0x00,0x00 });
				jmp.relative.target_func_id = func->func_id;
				jmp.relative.target_inst_id = (func->instructions.begin() + 3)->inst_id;

				last_instruction = func->instructions.insert(last_instruction + 1, { push_rax , push_f, mov_eax, jmp });
				last_instruction = last_instruction + 3;
			}

			//This happens if condition is met
			{

				instruction_t push_rax{}; push_rax.load(func->func_id, { 0x50 });

				instruction_t push_f{}; push_f.load(func->func_id, { 0x66, 0x9C });

				instruction_t mov_eax{}; mov_eax.load(func->func_id, { 0xB8, 0x00,0x00,0x00,0x00 });
				*(uint32_t*)(&mov_eax.raw_bytes.data()[1]) = encode_block_id(dst_block->block_id);

				instruction_t jmp{}; jmp.load(func->func_id, { 0xE9, 0x00,0x00,0x00,0x00 });
				jmp.relative.target_func_id = func->func_id;
				jmp.relative.target_inst_id = (func->instructions.begin() + 3)->inst_id;

				last_instruction = func->instructions.insert(last_instruction + 1, { push_rax , push_f, mov_eax, jmp });
				last_instruction = last_instruction + 3;
			}

			//Lets set the destination of our conditinal jump to our second option
			last_instruction = last_instruction - 8;
			last_instruction->relative.target_inst_id = (last_instruction + 5)->inst_id;

		}
		else {

			instruction_t push_rax{}; push_rax.load(func->func_id, { 0x50 });

			instruction_t push_f{}; push_f.load(func->func_id, { 0x66, 0x9C });

			instruction_t mov_eax{}; mov_eax.load(func->func_id, { 0xB8, 0x00,0x00,0x00,0x00 });
			*(uint32_t*)(&mov_eax.raw_bytes.data()[1]) = encode_block_id(next_block->block_id);

			instruction_t jmp{}; jmp.load(func->func_id, { 0xE9, 0x00,0x00,0x00,0x00 });
			jmp.relative.target_func_id = func->func_id;
			jmp.relative.target_inst_id = (func->instructions.begin() + 3)->inst_id;

			auto it = func->instructions.insert(last_instruction + 1, { push_rax , push_f, mov_eax, jmp });
			it = it + 3;
		}
	}

	return true;
}
