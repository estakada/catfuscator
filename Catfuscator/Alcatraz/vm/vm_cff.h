#pragma once
#include "vm_opcodes.h"
#include <vector>
#include <cstdint>
#include <random>

class vm_cff {
public:
	vm_cff(const vm_opcode_table& table, uint32_t seed);

	bool flatten(std::vector<uint8_t>& bytecode);

private:
	const vm_opcode_table& table;
	std::mt19937 rng;

	int get_instruction_size(const std::vector<uint8_t>& bc, uint32_t offset);
	bool is_jump_op(vm_op op);
	bool is_unconditional_jump(vm_op op);
	bool is_exit_op(vm_op op);
	bool is_conditional_jump(vm_op op);

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

	void emit_u16(std::vector<uint8_t>& bc, uint16_t val);
	void emit_i32(std::vector<uint8_t>& bc, int32_t val);
};
