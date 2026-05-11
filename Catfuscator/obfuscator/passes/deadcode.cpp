#include "../obfuscator.h"

#include <random>
#include <cstring>

static bool try_encode_lea_nop(std::vector<uint8_t>& out) {
	out.clear();
	out = { 0x48, 0x8D, 0x00 }; // lea rax, [rax]
	return true;
}

static bool try_encode_mov_reg_self(std::vector<uint8_t>& out, uint8_t reg_lo) {
	out.clear();
	// REX.B + 89: mov rXX, rXX (self-move = NOP on x64)
	// Register encoding: 1100 0000 | (reg_disp << 3) | reg
	uint8_t base = (reg_lo & 7);
	uint8_t modrm = 0xC0 | (base << 3) | base;
	out = { 0x48, modrm }; // REX.W + modrm
	return true;
}

static bool try_encode_nop_chain(std::vector<uint8_t>& out, int size) {
	out.clear();
	// Multi-byte NOPs (x64 canonical NOPs)
	if (size == 2) {
		out = { 0x66, 0x90 }; // 66 90 = 2-byte NOP
	} else if (size == 3) {
		out = { 0x0F, 0x1F, 0x00 }; // 3-byte NOP
	} else if (size == 4) {
		out = { 0x0F, 0x1F, 0x40, 0x00 }; // 4-byte NOP
	} else if (size == 5) {
		out = { 0x0F, 0x1F, 0x44, 0x00, 0x00 }; // 5-byte NOP
	} else if (size >= 6) {
		out = { 0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00 }; // 7-byte NOP
	} else {
		out = { 0x90 }; // 1-byte NOP
	}
	return true;
}

// Variant count kept in sync with the switch below
static constexpr int VARIANT_COUNT = 4;

// Try to create a dead code sequence of approximately the requested size
// Returns raw bytes of semantically-dead instructions
static std::vector<uint8_t> generate_dead_code(int approx_size) {
	std::random_device rd;
	std::mt19937 gen(rd());
	std::vector<uint8_t> result;

	while ((int)result.size() < approx_size) {
		int remaining = approx_size - (int)result.size();
		int variant = gen() % VARIANT_COUNT;
		std::vector<uint8_t> chunk;

		switch (variant) {
		case 0:
			// Self-move (2 bytes) — truly no-op
			{
				uint8_t regs[] = { 0, 1, 2, 3, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
				uint8_t r = regs[gen() % 14];
				try_encode_mov_reg_self(chunk, r);
			}
			break;
		case 1:
			// LEA NOP (3 bytes) — truly no-op
			try_encode_lea_nop(chunk);
			break;
		case 2:
			// Multi-byte NOP chain — truly no-op
			{
				int nop_sizes[] = { 2, 3, 4, 5, 6, 7 };
				int sz = nop_sizes[gen() % 6];
				if (sz > remaining) sz = remaining;
				try_encode_nop_chain(chunk, sz);
			}
			break;
		case 3:
			// LEA NOP chain — truly no-op
			{
				//lea rax, [rax] = 3 bytes
				chunk = { 0x48, 0x8D, 0x00 };
				// lea rax, [rax+rax] = 4 bytes
				if (remaining >= 7) {
					chunk.insert(chunk.end(), { 0x48, 0x8D, 0x04, 0x00 });
				}
				// fill remainder with 66 90 / 0F 1F ... if needed
				int rest = remaining - (int)chunk.size();
				if (rest > 0) {
					std::vector<uint8_t> filler;
					try_encode_nop_chain(filler, rest);
					chunk.insert(chunk.end(), filler.begin(), filler.end());
				}
			}
			break;
		}

		if (chunk.empty()) continue;
		if ((int)result.size() + (int)chunk.size() > approx_size + 4) {
			// Don't overflow — fill with canonical NOP
			try_encode_nop_chain(chunk, remaining > 7 ? 7 : remaining);
		}
		if (!chunk.empty()) {
			result.insert(result.end(), chunk.begin(), chunk.end());
		}
	}

	return result;
}

static obfuscator::instruction_t make_dead_instr(int func_id, std::vector<uint8_t> bytes) {
	obfuscator::instruction_t inst{};
	inst.load(func_id, bytes);
	inst.zyinstr.info.length = (uint8_t)bytes.size();
	inst.isjmpcall = false;
	inst.has_relative = false;
	return inst;
}

// Insert a dead code block — instructions that execute but have no observable effect
bool obfuscator::add_dead_code(std::vector<obfuscator::function_t>::iterator& function,
	std::vector<obfuscator::instruction_t>::iterator& instruction) {

	std::random_device rd;
	std::mt19937 gen(rd());

	// Density: 1-3 dead blocks inserted
	int num_blocks = (gen() % 3) + 1;

	// Size per block: 2-12 bytes (tries to match nearby instruction sizes)
	int base_size = (gen() % 10) + 2;

	for (int b = 0; b < num_blocks; b++) {
		int size = base_size + (gen() % 8);
		auto bytes = generate_dead_code(size);
		if (bytes.empty()) continue;

		auto dead = make_dead_instr(function->func_id, bytes);
		instruction = function->instructions.insert(instruction, dead);
		instruction++;
	}

	return true;
}

// Append dead code blocks after the last real instruction of a function.
// Uses index-based insertion to avoid iterator invalidation issues.
bool obfuscator::add_dead_code_after_last(std::vector<obfuscator::function_t>::iterator& function,
	int after_index) {

	std::random_device rd;
	std::mt19937 gen(rd());

	int num_blocks = (gen() % 3) + 1;
	int base_size = (gen() % 10) + 2;

	for (int b = 0; b < num_blocks; b++) {
		int size = base_size + (gen() % 8);
		auto bytes = generate_dead_code(size);
		if (bytes.empty()) continue;

		auto dead = make_dead_instr(function->func_id, bytes);
		// Insert at current end (after previously inserted dead code)
		function->instructions.insert(function->instructions.end(), dead);
	}

	return true;
}
