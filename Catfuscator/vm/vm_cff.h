#pragma once
#include "vm_opcodes.h"
#include <vector>
#include <cstdint>
#include <random>

class vm_cff {
public:
	vm_cff(const vm_opcode_table& table, uint32_t seed);

	bool flatten(std::vector<uint8_t>& bytecode);

	void set_fake_cfg_edges(bool enable, int chance_pct) {
		enable_fake_edges = enable;
		fake_edge_pct = chance_pct;
	}

private:
	const vm_opcode_table& table;
	std::mt19937 rng;

	int get_instruction_size(const std::vector<uint8_t>& bc, uint32_t offset);
	bool is_jump_op(vm_op op);
	bool is_unconditional_jump(vm_op op);
	bool is_exit_op(vm_op op);
	bool is_conditional_jump(vm_op op);

	struct output_block;

	void inject_fake_cfg_edges(std::vector<uint8_t>& bytecode, const std::vector<int>& block_position,
		const std::vector<uint32_t>& block_offsets, const std::vector<output_block>& out_blocks,
		const std::vector<int>& order, size_t block_count);

	struct bc_inst {
		uint32_t offset;
		uint32_t size;
		vm_op decoded_op;
	};

	struct basic_block {
		uint32_t id;
		std::vector<uint8_t> code;
		int fall_through_id;   // -1 if none
		int jump_target_id;    // -1 if none
		uint32_t last_inst_size;
		bool ends_with_uncond_jump;
		bool ends_with_cond_jump;
		bool ends_with_exit;
	};

	struct output_block {
		std::vector<uint8_t> code;
		struct patch { uint32_t offset; int target_block; };
		std::vector<patch> patches;
	};

	void emit_u16(std::vector<uint8_t>& bc, uint16_t val);
	void emit_i32(std::vector<uint8_t>& bc, int32_t val);

	bool enable_fake_edges = false;
	int fake_edge_pct = 10;
};
