#include "vm_translator.h"
#include <cstring>
#include <map>

vm_translator::vm_translator(const vm_opcode_table& table) : table(table), settings(nullptr), junk_rng(0), imm_xor_key(0), buffer_base(0), image_base(0) {}

void vm_translator::emit_junk_bytecode(std::vector<uint8_t>& bc) {
	uint32_t variant = junk_rng() % 6;
	uint8_t rand_reg = static_cast<uint8_t>(junk_rng() % 16);

	switch (variant) {
	case 0:
		// Single NOP
		emit_u16(bc, table.encode_random(vm_op::VM_NOP, junk_rng));
		break;
	case 1:
		// PUSH/POP same register — no effect
		emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
		emit_byte(bc, rand_reg);
		emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
		emit_byte(bc, rand_reg);
		break;
	case 2:
		// Two NOPs
		emit_u16(bc, table.encode_random(vm_op::VM_NOP, junk_rng));
		emit_u16(bc, table.encode_random(vm_op::VM_NOP, junk_rng));
		break;
	case 3: {
		// PUSH/PUSH/POP/POP two different regs — no effect
		uint8_t reg2 = static_cast<uint8_t>(junk_rng() % 16);
		emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
		emit_byte(bc, rand_reg);
		emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
		emit_byte(bc, reg2);
		emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
		emit_byte(bc, reg2);
		emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
		emit_byte(bc, rand_reg);
		break;
	}
	case 4:
		// MOV VR15, VR15 (self-move, no-op) + NOP
		emit_u16(bc, table.encode_random(vm_op::VM_MOV_REG_REG, junk_rng));
		emit_byte(bc, table.gp_perm[static_cast<uint8_t>(vm_reg::VR15)]);
		emit_byte(bc, table.gp_perm[static_cast<uint8_t>(vm_reg::VR15)]);
		emit_u16(bc, table.encode_random(vm_op::VM_NOP, junk_rng));
		break;
	case 5:
		// NOP + PUSH/POP
		emit_u16(bc, table.encode_random(vm_op::VM_NOP, junk_rng));
		emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
		emit_byte(bc, rand_reg);
		emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
		emit_byte(bc, rand_reg);
		break;
	}
}

void vm_translator::emit_dead_branch(std::vector<uint8_t>& bc) {
	uint8_t flags_idx = static_cast<uint8_t>(vm_reg::VRFLAGS);
	uint8_t scratch = table.gp_perm[15];

	// PUSH VRFLAGS + PUSH scratch
	emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
	emit_byte(bc, flags_idx);
	emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
	emit_byte(bc, scratch);

	// MOV scratch, nonzero → TEST → JNZ (always taken)
	emit_u16(bc, table.encode_random(vm_op::VM_MOV_REG_IMM64, junk_rng));
	emit_byte(bc, scratch);
	emit_u64(bc, (junk_rng() | 1) ^ imm_xor_key);

	emit_u16(bc, table.encode_random(vm_op::VM_TEST_REG_REG, junk_rng));
	emit_byte(bc, scratch);
	emit_byte(bc, scratch);
	emit_byte(bc, 8);

	// Build dead code in temp buffer
	std::vector<uint8_t> dead;
	for (int i = 0, n = 1 + (junk_rng() % 3); i < n; i++)
		emit_junk_bytecode(dead);

	// JNZ +dead.size() (always taken, skips dead code)
	emit_u16(bc, table.encode_random(vm_op::VM_JNZ, junk_rng));
	emit_i32(bc, static_cast<int32_t>(dead.size()));

	// Dead code (never executed, but parseable by CFF)
	bc.insert(bc.end(), dead.begin(), dead.end());

	// POP scratch + POP VRFLAGS
	emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
	emit_byte(bc, scratch);
	emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
	emit_byte(bc, flags_idx);
}

void vm_translator::emit_opaque_branch(std::vector<uint8_t>& bc) {
	uint8_t flags_idx = static_cast<uint8_t>(vm_reg::VRFLAGS);
	uint8_t scratch = table.gp_perm[15];

	// PUSH VRFLAGS + PUSH scratch
	emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
	emit_byte(bc, flags_idx);
	emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
	emit_byte(bc, scratch);

	// CMP scratch, scratch → ZF=1 always
	emit_u16(bc, table.encode_random(vm_op::VM_CMP_REG_REG, junk_rng));
	emit_byte(bc, scratch);
	emit_byte(bc, scratch);
	emit_byte(bc, 8);

	// Build junk that will execute normally after POPs
	std::vector<uint8_t> junk;
	for (int i = 0, n = 1 + (junk_rng() % 2); i < n; i++)
		emit_junk_bytecode(junk);

	// JNZ +(POP scratch:3 + POP VRFLAGS:3 + junk) — never taken (ZF=1)
	// Creates fake CFG edge past the POPs + junk
	int32_t fake_offset = 3 + 3 + static_cast<int32_t>(junk.size());
	emit_u16(bc, table.encode_random(vm_op::VM_JNZ, junk_rng));
	emit_i32(bc, fake_offset);

	// POP scratch + POP VRFLAGS (always executes)
	emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
	emit_byte(bc, scratch);
	emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
	emit_byte(bc, flags_idx);

	// Normal junk (executed on fall-through)
	bc.insert(bc.end(), junk.begin(), junk.end());
}

void vm_translator::maybe_emit_junk(std::vector<uint8_t>& bc) {
	int dead_pct = settings ? settings->dead_branch_pct : 5;
	int opaque_pct = settings ? settings->opaque_predicate_pct : 5;
	int junk_freq = settings ? settings->junk_frequency : 25;
	int single_pct = junk_freq;
	int double_pct = junk_freq / 2;

	uint32_t roll = junk_rng() % 100;
	int threshold = 0;
	if (roll < (threshold += dead_pct)) {
		emit_dead_branch(bc);
	} else if (roll < (threshold += opaque_pct)) {
		emit_opaque_branch(bc);
	} else if (roll < (threshold += single_pct)) {
		emit_junk_bytecode(bc);
	} else if (roll < (threshold += double_pct)) {
		emit_junk_bytecode(bc);
		emit_junk_bytecode(bc);
	}
}

void vm_translator::emit_prefixes(std::vector<uint8_t>& bc) {
	// Garbage byte injection: insert fake prefix/opcode sequences that look like
	// valid VM instructions in disassembly but are consumed as harmless prefixes.
	// Each prefix is a valid but unused VM opcode that makes dispatch jump through
	// the instruction but land on the same handler (since prefixes don't change decode).
	// Inject more prefixes when junk_frequency is high.
	uint32_t count = junk_rng() % 5;
	if (count > 3) count = 0;
	// When junk_frequency >= 50, always inject at least 1 prefix
	if (settings && settings->junk_frequency >= 50 && count == 0) count = 1;
	// When junk_frequency >= 75, inject up to 3 (up from 2)
	if (settings && settings->junk_frequency >= 75) count = junk_rng() % 4;

	for (uint32_t i = 0; i < count; i++) {
		uint16_t pv = table.prefix_values[junk_rng() % vm_opcode_table::NUM_PREFIXES];
		emit_u16(bc, pv);
	}

	// Inject full fake instruction sequences (2+ byte pairs) between real instructions.
	// These are valid VM opcodes that decode and dispatch normally but perform no work.
	// Appear as executable code in disassembly, increasing analysis complexity.
	if (settings && settings->junk_frequency >= 40) {
		uint32_t fake_instr = junk_rng() % 3;
		for (uint32_t i = 0; i < fake_instr; i++) {
			uint16_t fake = table.prefix_values[junk_rng() % vm_opcode_table::NUM_PREFIXES];
			emit_u16(bc, fake);  // full 2-byte fake instruction
		}
	}
}

void vm_translator::emit_byte(std::vector<uint8_t>& bc, uint8_t val) {
	bc.push_back(val);
}

void vm_translator::emit_u16(std::vector<uint8_t>& bc, uint16_t val) {
	bc.push_back(val & 0xFF);
	bc.push_back((val >> 8) & 0xFF);
}

void vm_translator::emit_u32(std::vector<uint8_t>& bc, uint32_t val) {
	bc.push_back(val & 0xFF);
	bc.push_back((val >> 8) & 0xFF);
	bc.push_back((val >> 16) & 0xFF);
	bc.push_back((val >> 24) & 0xFF);
}

void vm_translator::emit_u64(std::vector<uint8_t>& bc, uint64_t val) {
	for (int i = 0; i < 8; i++)
		bc.push_back((val >> (i * 8)) & 0xFF);
}

void vm_translator::emit_i32(std::vector<uint8_t>& bc, int32_t val) {
	emit_u32(bc, static_cast<uint32_t>(val));
}

void vm_translator::emit_i64(std::vector<uint8_t>& bc, int64_t val) {
	emit_u64(bc, static_cast<uint64_t>(val));
}

void vm_translator::emit_mov_reg_imm64(std::vector<uint8_t>& bc, uint8_t vreg, int64_t val) {
	int opaque_pct = settings ? settings->opaque_constant_pct : 30;
	if ((junk_rng() % 100) < opaque_pct) {
		// Constants Pollution: replace raw immediate with arithmetic chain
		// VM bytecode has no native mov with arithmetic, so we build chains:
		// val = f(base) where base is a random constant we can encode directly
		// Then: vreg = base; vreg = f(vreg)

		// Choose obfuscation form randomly
		int form = junk_rng() % 5;

		uint8_t flags_idx = static_cast<uint8_t>(vm_reg::VRFLAGS);

		switch (form) {
		case 0: {
			// Form A: val = ((base ^ A) + B) where base = (val - B) ^ A
			// 3 ops: MOV base, XOR A, ADD B
			int32_t A = static_cast<int32_t>(junk_rng());
			int32_t B = static_cast<int32_t>(junk_rng());
			int64_t sA = static_cast<int64_t>(A);
			int64_t sB = static_cast<int64_t>(B);
			int64_t base = (val - sB) ^ sA;

			// PUSH VRFLAGS (save flags to native stack)
			emit_prefixes(bc);
			emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
			emit_byte(bc, flags_idx);

			// MOV vreg, base (encrypted)
			emit_prefixes(bc);
			emit_u16(bc, table.encode_random(vm_op::VM_MOV_REG_IMM64, junk_rng));
			emit_byte(bc, vreg);
			emit_i64(bc, base ^ static_cast<int64_t>(imm_xor_key));

			// XOR vreg, A (size=8 for 64-bit)
			emit_prefixes(bc);
			emit_u16(bc, table.encode_random(vm_op::VM_XOR_REG_IMM, junk_rng));
			emit_byte(bc, vreg);
			emit_i32(bc, A);
			emit_byte(bc, 8);

			// ADD vreg, B (size=8 for 64-bit)
			emit_prefixes(bc);
			emit_u16(bc, table.encode_random(vm_op::VM_ADD_REG_IMM, junk_rng));
			emit_byte(bc, vreg);
			emit_i32(bc, B);
			emit_byte(bc, 8);

			// POP VRFLAGS (restore flags from native stack)
			emit_prefixes(bc);
			emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
			emit_byte(bc, flags_idx);
			break;
		}

		case 1: {
			// Form B: val = ((base ^ A) - B) where base = (val + B) ^ A
			// 3 ops: MOV base, XOR A, SUB B
			int32_t A = static_cast<int32_t>(junk_rng());
			int32_t B = static_cast<int32_t>(junk_rng());
			int64_t sA = static_cast<int64_t>(A);
			int64_t sB = static_cast<int64_t>(B);
			int64_t base = (val + sB) ^ sA;

			emit_prefixes(bc);
			emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
			emit_byte(bc, flags_idx);

			emit_prefixes(bc);
			emit_u16(bc, table.encode_random(vm_op::VM_MOV_REG_IMM64, junk_rng));
			emit_byte(bc, vreg);
			emit_i64(bc, base ^ static_cast<int64_t>(imm_xor_key));

			emit_prefixes(bc);
			emit_u16(bc, table.encode_random(vm_op::VM_XOR_REG_IMM, junk_rng));
			emit_byte(bc, vreg);
			emit_i32(bc, A);
			emit_byte(bc, 8);

			emit_prefixes(bc);
			emit_u16(bc, table.encode_random(vm_op::VM_SUB_REG_IMM, junk_rng));
			emit_byte(bc, vreg);
			emit_i32(bc, B);
			emit_byte(bc, 8);

			emit_prefixes(bc);
			emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
			emit_byte(bc, flags_idx);
			break;
		}

		case 2: {
			// Form C: val = ((base ^ A) + B) ^ C  where base = ((val ^ C) - B) ^ A
			// 4 ops: MOV base, XOR A, ADD B, XOR C
			int32_t A = static_cast<int32_t>(junk_rng());
			int32_t B = static_cast<int32_t>(junk_rng());
			int32_t C = static_cast<int32_t>(junk_rng());
			int64_t base = ((val ^ static_cast<int64_t>(C)) - static_cast<int64_t>(B)) ^ static_cast<int64_t>(A);

			emit_prefixes(bc);
			emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
			emit_byte(bc, flags_idx);

			emit_prefixes(bc);
			emit_u16(bc, table.encode_random(vm_op::VM_MOV_REG_IMM64, junk_rng));
			emit_byte(bc, vreg);
			emit_i64(bc, base ^ static_cast<int64_t>(imm_xor_key));

			emit_prefixes(bc);
			emit_u16(bc, table.encode_random(vm_op::VM_XOR_REG_IMM, junk_rng));
			emit_byte(bc, vreg);
			emit_i32(bc, A);
			emit_byte(bc, 8);

			emit_prefixes(bc);
			emit_u16(bc, table.encode_random(vm_op::VM_ADD_REG_IMM, junk_rng));
			emit_byte(bc, vreg);
			emit_i32(bc, B);
			emit_byte(bc, 8);

			emit_prefixes(bc);
			emit_u16(bc, table.encode_random(vm_op::VM_XOR_REG_IMM, junk_rng));
			emit_byte(bc, vreg);
			emit_i32(bc, C);
			emit_byte(bc, 8);

			emit_prefixes(bc);
			emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
			emit_byte(bc, flags_idx);
			break;
		}

		case 3: {
			// Form D: val = ((base ^ A) ^ B) - C  where base = ((val + C) ^ B) ^ A
			// 4 ops: MOV base, XOR A, XOR B, SUB C
			int32_t A = static_cast<int32_t>(junk_rng());
			int32_t B = static_cast<int32_t>(junk_rng());
			int32_t C = static_cast<int32_t>(junk_rng());
			int64_t base = ((val + static_cast<int64_t>(C)) ^ static_cast<int64_t>(B)) ^ static_cast<int64_t>(A);

			emit_prefixes(bc);
			emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
			emit_byte(bc, flags_idx);

			emit_prefixes(bc);
			emit_u16(bc, table.encode_random(vm_op::VM_MOV_REG_IMM64, junk_rng));
			emit_byte(bc, vreg);
			emit_i64(bc, base ^ static_cast<int64_t>(imm_xor_key));

			emit_prefixes(bc);
			emit_u16(bc, table.encode_random(vm_op::VM_XOR_REG_IMM, junk_rng));
			emit_byte(bc, vreg);
			emit_i32(bc, A);
			emit_byte(bc, 8);

			emit_prefixes(bc);
			emit_u16(bc, table.encode_random(vm_op::VM_XOR_REG_IMM, junk_rng));
			emit_byte(bc, vreg);
			emit_i32(bc, B);
			emit_byte(bc, 8);

			emit_prefixes(bc);
			emit_u16(bc, table.encode_random(vm_op::VM_SUB_REG_IMM, junk_rng));
			emit_byte(bc, vreg);
			emit_i32(bc, C);
			emit_byte(bc, 8);

			emit_prefixes(bc);
			emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
			emit_byte(bc, flags_idx);
			break;
		}

		case 4:
		default: {
			// Form E: val = ((base + A) ^ B) - C  where base = ((val + C) ^ B) - A
			// 4 ops: MOV base, ADD A, XOR B, SUB C
			int32_t A = static_cast<int32_t>(junk_rng());
			int32_t B = static_cast<int32_t>(junk_rng());
			int32_t C = static_cast<int32_t>(junk_rng());
			int64_t base = ((val + static_cast<int64_t>(C)) ^ static_cast<int64_t>(B)) - static_cast<int64_t>(A);

			emit_prefixes(bc);
			emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
			emit_byte(bc, flags_idx);

			emit_prefixes(bc);
			emit_u16(bc, table.encode_random(vm_op::VM_MOV_REG_IMM64, junk_rng));
			emit_byte(bc, vreg);
			emit_i64(bc, base ^ static_cast<int64_t>(imm_xor_key));

			emit_prefixes(bc);
			emit_u16(bc, table.encode_random(vm_op::VM_ADD_REG_IMM, junk_rng));
			emit_byte(bc, vreg);
			emit_i32(bc, A);
			emit_byte(bc, 8);

			emit_prefixes(bc);
			emit_u16(bc, table.encode_random(vm_op::VM_XOR_REG_IMM, junk_rng));
			emit_byte(bc, vreg);
			emit_i32(bc, B);
			emit_byte(bc, 8);

			emit_prefixes(bc);
			emit_u16(bc, table.encode_random(vm_op::VM_SUB_REG_IMM, junk_rng));
			emit_byte(bc, vreg);
			emit_i32(bc, C);
			emit_byte(bc, 8);

			emit_prefixes(bc);
			emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
			emit_byte(bc, flags_idx);
			break;
		}
		}
	} else {
		emit_u16(bc, table.encode_random(vm_op::VM_MOV_REG_IMM64, junk_rng));
		emit_byte(bc, vreg);
		emit_i64(bc, val ^ static_cast<int64_t>(imm_xor_key));
	}
}

// emit_obfuscated_imm32: for i32 immediates in ALU ops
// Replaces raw immediate with arithmetic chain to defeat static analysis
//
// For ALU op like ADD/SUB/XOR/AND/OR vreg, imm:
//   We load vreg with (imm - A), then ADD A to recover imm, then do the real op.
//   But for XOR/AND/OR, the compensate value is different from A.
//
// Strategy:
//   1. Load vreg with base (encrypted): vreg = imm ^ A ^ B
//   2. XOR vreg, A then XOR vreg, B → vreg = imm  (XOR chain restores original)
//   3. Then do: ALU_op vreg, (imm + compensation) to get the correct final result
//
// Since XOR vreg, A ^ vreg, B already gives us vreg=imm, the ALU op just needs
// the original imm value. So we just do the real ALU op after the XOR chain.
//
// For commutative ops (ADD/OR/XOR/AND), we can also use ADD-compensate approach:
//   Load vreg = imm - A, then ADD vreg, A (gives imm), then ALU op with 0 (noop).
//   This lets us use ADD compensation as the chain. Or simpler: just do the XOR chain.
void vm_translator::emit_obfuscated_imm32(std::vector<uint8_t>& bc, uint8_t vreg, int32_t val, vm_op alu_op) {
	int form = junk_rng() % 5;
	uint8_t flags_idx = static_cast<uint8_t>(vm_reg::VRFLAGS);

	// Save flags since we modify them
	emit_prefixes(bc);
	emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
	emit_byte(bc, flags_idx);

	switch (form) {
	case 0: {
		// Form 0: Two-level XOR chain — most effective for hiding the constant
		// vreg = (imm ^ A) ^ B  → XOR A → XOR B → vreg = imm
		// Then do the real ALU op with the original immediate value
		int32_t A = static_cast<int32_t>(junk_rng());
		int32_t B = static_cast<int32_t>(junk_rng());
		int32_t base = (val ^ A) ^ B;

		// Load base via MOV_REG_IMM64 (with imm_xor_key encryption)
		emit_prefixes(bc);
		emit_u16(bc, table.encode_random(vm_op::VM_MOV_REG_IMM64, junk_rng));
		emit_byte(bc, vreg);
		emit_i64(bc, static_cast<int64_t>(base) ^ static_cast<int64_t>(imm_xor_key));

		// XOR chain to restore original value
		emit_prefixes(bc);
		emit_u16(bc, table.encode_random(vm_op::VM_XOR_REG_IMM, junk_rng));
		emit_byte(bc, vreg);
		emit_i32(bc, A);
		emit_byte(bc, 4);

		emit_prefixes(bc);
		emit_u16(bc, table.encode_random(vm_op::VM_XOR_REG_IMM, junk_rng));
		emit_byte(bc, vreg);
		emit_i32(bc, B);
		emit_byte(bc, 4);

		// Now do the real ALU op with the original immediate value
		// Since vreg == val, this is exactly vreg op val
		emit_prefixes(bc);
		emit_u16(bc, table.encode_random(alu_op, junk_rng));
		emit_byte(bc, vreg);
		emit_i32(bc, val);
		emit_byte(bc, 4);
		break;
	}

	case 1: {
		// Form 1: XOR + ADD compensation chain
		// vreg = val ^ A (opaque load), then XOR A, then ADD val to compensate
		// Since vreg already has the real value after XOR A, just do ALU op with val
		int32_t A = static_cast<int32_t>(junk_rng());
		int32_t base = val ^ A;

		emit_prefixes(bc);
		emit_u16(bc, table.encode_random(vm_op::VM_MOV_REG_IMM64, junk_rng));
		emit_byte(bc, vreg);
		emit_i64(bc, static_cast<int64_t>(base) ^ static_cast<int64_t>(imm_xor_key));

		emit_prefixes(bc);
		emit_u16(bc, table.encode_random(vm_op::VM_XOR_REG_IMM, junk_rng));
		emit_byte(bc, vreg);
		emit_i32(bc, A);
		emit_byte(bc, 4);

		// Now vreg == val; do the real ALU op
		emit_prefixes(bc);
		emit_u16(bc, table.encode_random(alu_op, junk_rng));
		emit_byte(bc, vreg);
		emit_i32(bc, val);
		emit_byte(bc, 4);
		break;
	}

	case 2: {
		// Form 2: ADD-sub compensation chain
		// vreg = val + A (load), then SUB A to recover val
		// Works for loading positive-ish values. For negative, ADD makes it.
		int32_t A = static_cast<int32_t>(junk_rng());
		int32_t base = val + A;

		emit_prefixes(bc);
		emit_u16(bc, table.encode_random(vm_op::VM_MOV_REG_IMM64, junk_rng));
		emit_byte(bc, vreg);
		emit_i64(bc, static_cast<int64_t>(base) ^ static_cast<int64_t>(imm_xor_key));

		emit_prefixes(bc);
		emit_u16(bc, table.encode_random(vm_op::VM_SUB_REG_IMM, junk_rng));
		emit_byte(bc, vreg);
		emit_i32(bc, A);
		emit_byte(bc, 4);

		// vreg == val now; do the real ALU op
		emit_prefixes(bc);
		emit_u16(bc, table.encode_random(alu_op, junk_rng));
		emit_byte(bc, vreg);
		emit_i32(bc, val);
		emit_byte(bc, 4);
		break;
	}

	case 3: {
		// Form 3: SUB-add compensation chain
		// vreg = val - A (load), then ADD A to recover val
		int32_t A = static_cast<int32_t>(junk_rng());
		int32_t base = val - A;

		emit_prefixes(bc);
		emit_u16(bc, table.encode_random(vm_op::VM_MOV_REG_IMM64, junk_rng));
		emit_byte(bc, vreg);
		emit_i64(bc, static_cast<int64_t>(base) ^ static_cast<int64_t>(imm_xor_key));

		emit_prefixes(bc);
		emit_u16(bc, table.encode_random(vm_op::VM_ADD_REG_IMM, junk_rng));
		emit_byte(bc, vreg);
		emit_i32(bc, A);
		emit_byte(bc, 4);

		// vreg == val now; do the real ALU op
		emit_prefixes(bc);
		emit_u16(bc, table.encode_random(alu_op, junk_rng));
		emit_byte(bc, vreg);
		emit_i32(bc, val);
		emit_byte(bc, 4);
		break;
	}

	case 4:
	default: {
		// Form 4: Three-level XOR chain with extra noise
		// vreg = ((val ^ A) ^ B) ^ A — XOR A twice to cancel, B in middle
		int32_t A = static_cast<int32_t>(junk_rng());
		int32_t B = static_cast<int32_t>(junk_rng());
		int32_t base = ((val ^ A) ^ B) ^ A;

		emit_prefixes(bc);
		emit_u16(bc, table.encode_random(vm_op::VM_MOV_REG_IMM64, junk_rng));
		emit_byte(bc, vreg);
		emit_i64(bc, static_cast<int64_t>(base) ^ static_cast<int64_t>(imm_xor_key));

		emit_prefixes(bc);
		emit_u16(bc, table.encode_random(vm_op::VM_XOR_REG_IMM, junk_rng));
		emit_byte(bc, vreg);
		emit_i32(bc, A);
		emit_byte(bc, 4);

		emit_prefixes(bc);
		emit_u16(bc, table.encode_random(vm_op::VM_XOR_REG_IMM, junk_rng));
		emit_byte(bc, vreg);
		emit_i32(bc, B);
		emit_byte(bc, 4);

		emit_prefixes(bc);
		emit_u16(bc, table.encode_random(vm_op::VM_XOR_REG_IMM, junk_rng));
		emit_byte(bc, vreg);
		emit_i32(bc, A);
		emit_byte(bc, 4);

		// vreg == val now; do the real ALU op
		emit_prefixes(bc);
		emit_u16(bc, table.encode_random(alu_op, junk_rng));
		emit_byte(bc, vreg);
		emit_i32(bc, val);
		emit_byte(bc, 4);
		break;
	}
	}

	// Restore flags
	emit_prefixes(bc);
	emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
	emit_byte(bc, flags_idx);
}

bool vm_translator::map_register(ZydisRegister reg, uint8_t& out_vreg, uint8_t& out_size) {
	out_size = 8;

	switch (reg) {
	case ZYDIS_REGISTER_RAX: case ZYDIS_REGISTER_EAX: case ZYDIS_REGISTER_AX: case ZYDIS_REGISTER_AL:
		out_vreg = static_cast<uint8_t>(vm_reg::VRAX); break;
	case ZYDIS_REGISTER_RCX: case ZYDIS_REGISTER_ECX: case ZYDIS_REGISTER_CX: case ZYDIS_REGISTER_CL:
		out_vreg = static_cast<uint8_t>(vm_reg::VRCX); break;
	case ZYDIS_REGISTER_RDX: case ZYDIS_REGISTER_EDX: case ZYDIS_REGISTER_DX: case ZYDIS_REGISTER_DL:
		out_vreg = static_cast<uint8_t>(vm_reg::VRDX); break;
	case ZYDIS_REGISTER_RBX: case ZYDIS_REGISTER_EBX: case ZYDIS_REGISTER_BX: case ZYDIS_REGISTER_BL:
		out_vreg = static_cast<uint8_t>(vm_reg::VRBX); break;
	case ZYDIS_REGISTER_RSP: case ZYDIS_REGISTER_ESP: case ZYDIS_REGISTER_SP:
		out_vreg = static_cast<uint8_t>(vm_reg::VRSP); break;
	case ZYDIS_REGISTER_RBP: case ZYDIS_REGISTER_EBP: case ZYDIS_REGISTER_BP:
		out_vreg = static_cast<uint8_t>(vm_reg::VRBP); break;
	case ZYDIS_REGISTER_RSI: case ZYDIS_REGISTER_ESI: case ZYDIS_REGISTER_SI:
		out_vreg = static_cast<uint8_t>(vm_reg::VRSI); break;
	case ZYDIS_REGISTER_RDI: case ZYDIS_REGISTER_EDI: case ZYDIS_REGISTER_DI:
		out_vreg = static_cast<uint8_t>(vm_reg::VRDI); break;
	case ZYDIS_REGISTER_R8: case ZYDIS_REGISTER_R8D: case ZYDIS_REGISTER_R8W: case ZYDIS_REGISTER_R8B:
		out_vreg = static_cast<uint8_t>(vm_reg::VR8); break;
	case ZYDIS_REGISTER_R9: case ZYDIS_REGISTER_R9D: case ZYDIS_REGISTER_R9W: case ZYDIS_REGISTER_R9B:
		out_vreg = static_cast<uint8_t>(vm_reg::VR9); break;
	case ZYDIS_REGISTER_R10: case ZYDIS_REGISTER_R10D: case ZYDIS_REGISTER_R10W: case ZYDIS_REGISTER_R10B:
		out_vreg = static_cast<uint8_t>(vm_reg::VR10); break;
	case ZYDIS_REGISTER_R11: case ZYDIS_REGISTER_R11D: case ZYDIS_REGISTER_R11W: case ZYDIS_REGISTER_R11B:
		out_vreg = static_cast<uint8_t>(vm_reg::VR11); break;
	case ZYDIS_REGISTER_R12: case ZYDIS_REGISTER_R12D: case ZYDIS_REGISTER_R12W: case ZYDIS_REGISTER_R12B:
		out_vreg = static_cast<uint8_t>(vm_reg::VR12); break;
	case ZYDIS_REGISTER_R13: case ZYDIS_REGISTER_R13D: case ZYDIS_REGISTER_R13W: case ZYDIS_REGISTER_R13B:
		out_vreg = static_cast<uint8_t>(vm_reg::VR13); break;
	case ZYDIS_REGISTER_R14: case ZYDIS_REGISTER_R14D: case ZYDIS_REGISTER_R14W: case ZYDIS_REGISTER_R14B:
		out_vreg = static_cast<uint8_t>(vm_reg::VR14); break;
	case ZYDIS_REGISTER_R15: case ZYDIS_REGISTER_R15D: case ZYDIS_REGISTER_R15W: case ZYDIS_REGISTER_R15B:
		out_vreg = static_cast<uint8_t>(vm_reg::VR15); break;
	default:
		return false;
	}

	// Apply per-region register permutation
	out_vreg = table.gp_perm[out_vreg];

	switch (reg) {
	case ZYDIS_REGISTER_EAX: case ZYDIS_REGISTER_ECX: case ZYDIS_REGISTER_EDX: case ZYDIS_REGISTER_EBX:
	case ZYDIS_REGISTER_ESP: case ZYDIS_REGISTER_EBP: case ZYDIS_REGISTER_ESI: case ZYDIS_REGISTER_EDI:
	case ZYDIS_REGISTER_R8D: case ZYDIS_REGISTER_R9D: case ZYDIS_REGISTER_R10D: case ZYDIS_REGISTER_R11D:
	case ZYDIS_REGISTER_R12D: case ZYDIS_REGISTER_R13D: case ZYDIS_REGISTER_R14D: case ZYDIS_REGISTER_R15D:
		out_size = 4; break;
	case ZYDIS_REGISTER_AX: case ZYDIS_REGISTER_CX: case ZYDIS_REGISTER_DX: case ZYDIS_REGISTER_BX:
	case ZYDIS_REGISTER_SP: case ZYDIS_REGISTER_BP: case ZYDIS_REGISTER_SI: case ZYDIS_REGISTER_DI:
	case ZYDIS_REGISTER_R8W: case ZYDIS_REGISTER_R9W: case ZYDIS_REGISTER_R10W: case ZYDIS_REGISTER_R11W:
	case ZYDIS_REGISTER_R12W: case ZYDIS_REGISTER_R13W: case ZYDIS_REGISTER_R14W: case ZYDIS_REGISTER_R15W:
		out_size = 2; break;
	case ZYDIS_REGISTER_AL: case ZYDIS_REGISTER_CL: case ZYDIS_REGISTER_DL: case ZYDIS_REGISTER_BL:
	case ZYDIS_REGISTER_R8B: case ZYDIS_REGISTER_R9B: case ZYDIS_REGISTER_R10B: case ZYDIS_REGISTER_R11B:
	case ZYDIS_REGISTER_R12B: case ZYDIS_REGISTER_R13B: case ZYDIS_REGISTER_R14B: case ZYDIS_REGISTER_R15B:
		out_size = 1; break;
	}

	return true;
}

bool vm_translator::translate_alu_reg_reg(vm_op op, const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& operands = inst.zyinstr.operands;
	uint8_t vreg1, vreg2, sz1, sz2;
	if (!map_register(operands[0].reg.value, vreg1, sz1)) return false;
	if (!map_register(operands[1].reg.value, vreg2, sz2)) return false;
	emit_u16(bc, table.encode_random(op, junk_rng));
	emit_byte(bc, vreg1);
	emit_byte(bc, vreg2);
	emit_byte(bc, sz1);
	return true;
}

bool vm_translator::translate_alu_reg_imm(vm_op op, const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& operands = inst.zyinstr.operands;
	uint8_t vreg, sz;
	if (!map_register(operands[0].reg.value, vreg, sz)) return false;
	int32_t imm_val = static_cast<int32_t>(operands[1].imm.value.s);

	// Constants Pollution for i32 immediates: with opaque_constant_pct probability,
	// replace the raw immediate with an arithmetic chain that computes the same value
	int opaque_pct = settings ? settings->opaque_constant_pct : 30;
	if ((junk_rng() % 100) < opaque_pct) {
		emit_obfuscated_imm32(bc, vreg, imm_val, op);
	} else {
		emit_u16(bc, table.encode_random(op, junk_rng));
		emit_byte(bc, vreg);
		emit_i32(bc, imm_val);
		emit_byte(bc, sz);
	}
	return true;
}

// emit_obfuscated_address: always applies polynomial chain to 64-bit addresses
// Defeats static analysis that looks for RVA/VA constants in disassembly
void vm_translator::emit_obfuscated_address(std::vector<uint8_t>& bc, uint8_t vreg, int64_t addr) {
	if (!settings || junk_rng() % 100 >= settings->opaque_constant_pct) {
		// Fallback: simple opaque MOV (already has some obfuscation)
		emit_mov_reg_imm64(bc, vreg, addr);
		return;
	}

	// Pick random form (same 5 forms as emit_mov_reg_imm64)
	uint32_t form = junk_rng() % 5;

	// Save flags
	uint8_t vrflags = table.gp_perm[static_cast<uint8_t>(vm_reg::VRFLAGS)];
	emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
	emit_byte(bc, vrflags);

	auto do_poly = [&](uint64_t base, uint32_t A, uint32_t B, uint32_t C, bool use_c) {
		// base = addr ^ A
		emit_u16(bc, table.encode_random(vm_op::VM_MOV_REG_IMM64, junk_rng));
		emit_byte(bc, vreg);
		emit_i64(bc, base ^ static_cast<int64_t>(A) ^ static_cast<int64_t>(imm_xor_key));
		// vreg ^= A
		emit_u16(bc, table.encode_random(vm_op::VM_XOR_REG_IMM, junk_rng));
		emit_byte(bc, vreg);
		emit_i32(bc, static_cast<int32_t>(A));
		emit_byte(bc, 8);
		// vreg += B
		emit_u16(bc, table.encode_random(vm_op::VM_ADD_REG_IMM, junk_rng));
		emit_byte(bc, vreg);
		emit_i32(bc, static_cast<int32_t>(B));
		emit_byte(bc, 8);
		if (use_c) {
			// vreg ^= C
			emit_u16(bc, table.encode_random(vm_op::VM_XOR_REG_IMM, junk_rng));
			emit_byte(bc, vreg);
			emit_i32(bc, static_cast<int32_t>(C));
			emit_byte(bc, 8);
		}
	};

	uint64_t uaddr = static_cast<uint64_t>(addr);
	switch (form) {
	case 0: {
		// Form A: addr = ((base ^ A) + B)
		uint32_t A = junk_rng() | 1;
		uint32_t B = static_cast<uint32_t>(addr) - (static_cast<uint32_t>(addr) ^ A);
		do_poly(uaddr, A, B, 0, false);
		break;
	}
	case 1: {
		// Form B: addr = ((base ^ A) - B)
		uint32_t A = junk_rng() | 1;
		uint32_t B = static_cast<uint32_t>(addr) - (static_cast<uint32_t>(addr) ^ A);
		emit_u16(bc, table.encode_random(vm_op::VM_MOV_REG_IMM64, junk_rng));
		emit_byte(bc, vreg);
		emit_i64(bc, uaddr ^ A ^ imm_xor_key);
		emit_u16(bc, table.encode_random(vm_op::VM_XOR_REG_IMM, junk_rng));
		emit_byte(bc, vreg);
		emit_i32(bc, A);
		emit_byte(bc, 8);
		emit_u16(bc, table.encode_random(vm_op::VM_SUB_REG_IMM, junk_rng));
		emit_byte(bc, vreg);
		emit_i32(bc, B);
		emit_byte(bc, 8);
		break;
	}
	case 2: {
		// Form C: addr = (((base ^ A) + B) ^ C)
		uint32_t A = junk_rng() | 1;
		uint32_t B = static_cast<uint32_t>(addr) - (static_cast<uint32_t>(addr) ^ A);
		uint32_t C = (junk_rng() | 0x11);
		do_poly(uaddr, A, B, C, true);
		break;
	}
	case 3: {
		// Form D: addr = (((base ^ A) ^ B) - C)
		uint32_t A = junk_rng() | 1;
		uint32_t B = junk_rng() | 1;
		uint32_t C = static_cast<uint32_t>(addr) - (static_cast<uint32_t>(addr) ^ A ^ B);
		uint32_t base = static_cast<uint32_t>(addr) ^ A ^ B;
		emit_u16(bc, table.encode_random(vm_op::VM_MOV_REG_IMM64, junk_rng));
		emit_byte(bc, vreg);
		emit_i64(bc, base ^ imm_xor_key);
		emit_u16(bc, table.encode_random(vm_op::VM_XOR_REG_IMM, junk_rng));
		emit_byte(bc, vreg);
		emit_i32(bc, A);
		emit_byte(bc, 8);
		emit_u16(bc, table.encode_random(vm_op::VM_XOR_REG_IMM, junk_rng));
		emit_byte(bc, vreg);
		emit_i32(bc, B);
		emit_byte(bc, 8);
		emit_u16(bc, table.encode_random(vm_op::VM_SUB_REG_IMM, junk_rng));
		emit_byte(bc, vreg);
		emit_i32(bc, C);
		emit_byte(bc, 8);
		break;
	}
	default: {
		// Form E: addr = (((base + A) ^ B) - C)
		uint32_t A = junk_rng() | 1;
		uint32_t B = (junk_rng() | 0x11);
		uint32_t C = static_cast<uint32_t>(addr) + A - (static_cast<uint32_t>(addr) ^ B);
		uint32_t base = static_cast<uint32_t>(addr) ^ B;
		emit_u16(bc, table.encode_random(vm_op::VM_MOV_REG_IMM64, junk_rng));
		emit_byte(bc, vreg);
		emit_i64(bc, base ^ imm_xor_key);
		emit_u16(bc, table.encode_random(vm_op::VM_ADD_REG_IMM, junk_rng));
		emit_byte(bc, vreg);
		emit_i32(bc, A);
		emit_byte(bc, 8);
		emit_u16(bc, table.encode_random(vm_op::VM_XOR_REG_IMM, junk_rng));
		emit_byte(bc, vreg);
		emit_i32(bc, B);
		emit_byte(bc, 8);
		emit_u16(bc, table.encode_random(vm_op::VM_SUB_REG_IMM, junk_rng));
		emit_byte(bc, vreg);
		emit_i32(bc, C);
		emit_byte(bc, 8);
		break;
	}
	}

	// Restore flags
	emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
	emit_byte(bc, vrflags);
}

bool vm_translator::translate_mov(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& operands = inst.zyinstr.operands;
	int op_count = inst.zyinstr.info.operand_count_visible;

	if (op_count < 2) return false;

	// MOV reg, reg
	if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
		uint8_t vreg1, vreg2, sz1, sz2;
		if (!map_register(operands[0].reg.value, vreg1, sz1)) return false;
		if (!map_register(operands[1].reg.value, vreg2, sz2)) return false;
		emit_u16(bc, table.encode_random(vm_op::VM_MOV_REG_REG, junk_rng));
		emit_byte(bc, vreg1);
		emit_byte(bc, vreg2);
		return true;
	}

	// MOV reg, imm
	if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
		uint8_t vreg, sz;
		if (!map_register(operands[0].reg.value, vreg, sz)) return false;
		emit_mov_reg_imm64(bc, vreg, operands[1].imm.value.s);
		return true;
	}

	// MOV reg, [mem]
	if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
		uint8_t vreg_dst, sz_dst;
		if (!map_register(operands[0].reg.value, vreg_dst, sz_dst)) return false;
		return emit_sib_load(operands[1], vreg_dst, sz_dst, bc, &inst);
	}

	// MOV [mem], imm — decompose to: mov scratch, imm; mov [mem], scratch
	if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
		uint8_t sz_dst = static_cast<uint8_t>(operands[0].size / 8);
		uint8_t scratch = table.gp_perm[static_cast<uint8_t>(vm_reg::VR15)];

		emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
		emit_byte(bc, scratch);
		emit_mov_reg_imm64(bc, scratch, operands[1].imm.value.s);
		if (!emit_sib_store(operands[0], scratch, sz_dst, bc, &inst)) return false;
		emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
		emit_byte(bc, scratch);
		return true;
	}

	// MOV [mem], reg
	if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
		uint8_t vreg_src, sz_src;
		if (!map_register(operands[1].reg.value, vreg_src, sz_src)) return false;
		return emit_sib_store(operands[0], vreg_src, sz_src, bc, &inst);
	}

	return false;
}

bool vm_translator::translate_alu_mem(vm_op reg_reg_op, vm_op reg_imm_op, const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& operands = inst.zyinstr.operands;
	uint8_t scratch = table.gp_perm[static_cast<uint8_t>(vm_reg::VR15)];

	// ALU reg, [mem] -> load scratch from mem, ALU reg, scratch
	if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
		uint8_t vreg_dst, sz_dst;
		if (!map_register(operands[0].reg.value, vreg_dst, sz_dst)) return false;

		emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
		emit_byte(bc, scratch);
		if (!emit_sib_load(operands[1], scratch, sz_dst, bc, &inst)) return false;
		emit_u16(bc, table.encode_random(reg_reg_op, junk_rng));
		emit_byte(bc, vreg_dst);
		emit_byte(bc, scratch);
		emit_byte(bc, sz_dst);
		emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
		emit_byte(bc, scratch);
		return true;
	}

	// ALU [mem], reg -> load scratch, ALU scratch reg, store scratch back
	if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
		uint8_t vreg_src, sz_src;
		if (!map_register(operands[1].reg.value, vreg_src, sz_src)) return false;

		uint8_t sz_dst = static_cast<uint8_t>(operands[0].size / 8);
		emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
		emit_byte(bc, scratch);
		if (!emit_sib_load(operands[0], scratch, sz_dst, bc, &inst)) return false;
		emit_u16(bc, table.encode_random(reg_reg_op, junk_rng));
		emit_byte(bc, scratch);
		emit_byte(bc, vreg_src);
		emit_byte(bc, sz_dst);
		if (!emit_sib_store(operands[0], scratch, sz_dst, bc, &inst)) return false;
		emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
		emit_byte(bc, scratch);
		return true;
	}

	// ALU [mem], imm -> load scratch, ALU scratch imm, store scratch back
	if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
		uint8_t sz_dst = static_cast<uint8_t>(operands[0].size / 8);
		emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
		emit_byte(bc, scratch);
		if (!emit_sib_load(operands[0], scratch, sz_dst, bc, &inst)) return false;
		emit_u16(bc, table.encode_random(reg_imm_op, junk_rng));
		emit_byte(bc, scratch);
		emit_i32(bc, static_cast<int32_t>(operands[1].imm.value.s));
		emit_byte(bc, sz_dst);
		if (!emit_sib_store(operands[0], scratch, sz_dst, bc, &inst)) return false;
		emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
		emit_byte(bc, scratch);
		return true;
	}

	return false;
}

bool vm_translator::translate_add(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& operands = inst.zyinstr.operands;
	if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
		return translate_alu_reg_reg(vm_op::VM_ADD_REG_REG, inst, bc);
	if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
		return translate_alu_reg_imm(vm_op::VM_ADD_REG_IMM, inst, bc);
	return translate_alu_mem(vm_op::VM_ADD_REG_REG, vm_op::VM_ADD_REG_IMM, inst, bc);
}

bool vm_translator::translate_sub(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& operands = inst.zyinstr.operands;
	if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
		return translate_alu_reg_reg(vm_op::VM_SUB_REG_REG, inst, bc);
	if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
		return translate_alu_reg_imm(vm_op::VM_SUB_REG_IMM, inst, bc);
	return translate_alu_mem(vm_op::VM_SUB_REG_REG, vm_op::VM_SUB_REG_IMM, inst, bc);
}

bool vm_translator::translate_xor(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& operands = inst.zyinstr.operands;
	if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
		return translate_alu_reg_reg(vm_op::VM_XOR_REG_REG, inst, bc);
	if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
		return translate_alu_reg_imm(vm_op::VM_XOR_REG_IMM, inst, bc);
	return translate_alu_mem(vm_op::VM_XOR_REG_REG, vm_op::VM_XOR_REG_IMM, inst, bc);
}

bool vm_translator::translate_and(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& operands = inst.zyinstr.operands;
	if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
		return translate_alu_reg_reg(vm_op::VM_AND_REG_REG, inst, bc);
	if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
		return translate_alu_reg_imm(vm_op::VM_AND_REG_IMM, inst, bc);
	return translate_alu_mem(vm_op::VM_AND_REG_REG, vm_op::VM_AND_REG_IMM, inst, bc);
}

bool vm_translator::translate_or(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& operands = inst.zyinstr.operands;
	if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
		return translate_alu_reg_reg(vm_op::VM_OR_REG_REG, inst, bc);
	if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
		return translate_alu_reg_imm(vm_op::VM_OR_REG_IMM, inst, bc);
	return translate_alu_mem(vm_op::VM_OR_REG_REG, vm_op::VM_OR_REG_IMM, inst, bc);
}

bool vm_translator::translate_cmp(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& operands = inst.zyinstr.operands;
	if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
		return translate_alu_reg_reg(vm_op::VM_CMP_REG_REG, inst, bc);
	if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
		return translate_alu_reg_imm(vm_op::VM_CMP_REG_IMM, inst, bc);
	return translate_alu_mem(vm_op::VM_CMP_REG_REG, vm_op::VM_CMP_REG_IMM, inst, bc);
}

bool vm_translator::translate_test(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& operands = inst.zyinstr.operands;
	if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
		uint8_t vreg1, vreg2, sz1, sz2;
		if (!map_register(operands[0].reg.value, vreg1, sz1)) return false;
		if (!map_register(operands[1].reg.value, vreg2, sz2)) return false;
		emit_u16(bc, table.encode_random(vm_op::VM_TEST_REG_REG, junk_rng));
		emit_byte(bc, vreg1);
		emit_byte(bc, vreg2);
		return true;
	}
	if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
		uint8_t vreg, sz;
		if (!map_register(operands[0].reg.value, vreg, sz)) return false;
		emit_u16(bc, table.encode_random(vm_op::VM_TEST_REG_IMM, junk_rng));
		emit_byte(bc, vreg);
		emit_i32(bc, static_cast<int32_t>(operands[1].imm.value.s));
		return true;
	}
	// TEST [mem], reg — load to scratch, TEST scratch, reg
	if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
		uint8_t vreg_src, sz_src;
		if (!map_register(operands[1].reg.value, vreg_src, sz_src)) return false;
		uint8_t scratch = table.gp_perm[static_cast<uint8_t>(vm_reg::VR15)];
		uint8_t sz_dst = static_cast<uint8_t>(operands[0].size / 8);
		emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
		emit_byte(bc, scratch);
		if (!emit_sib_load(operands[0], scratch, sz_dst, bc, &inst)) return false;
		emit_u16(bc, table.encode_random(vm_op::VM_TEST_REG_REG, junk_rng));
		emit_byte(bc, scratch);
		emit_byte(bc, vreg_src);
		emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
		emit_byte(bc, scratch);
		return true;
	}
	// TEST [mem], imm — load to scratch, TEST scratch, imm
	if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
		uint8_t scratch = table.gp_perm[static_cast<uint8_t>(vm_reg::VR15)];
		uint8_t sz_dst = static_cast<uint8_t>(operands[0].size / 8);
		emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
		emit_byte(bc, scratch);
		if (!emit_sib_load(operands[0], scratch, sz_dst, bc, &inst)) return false;
		emit_u16(bc, table.encode_random(vm_op::VM_TEST_REG_IMM, junk_rng));
		emit_byte(bc, scratch);
		emit_i32(bc, static_cast<int32_t>(operands[1].imm.value.s));
		emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
		emit_byte(bc, scratch);
		return true;
	}
	return false;
}

bool vm_translator::translate_push(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& operands = inst.zyinstr.operands;
	if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
		uint8_t vreg, sz;
		if (!map_register(operands[0].reg.value, vreg, sz)) return false;
		emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
		emit_byte(bc, vreg);
		return true;
	}
	if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
		uint8_t scratch = table.gp_perm[static_cast<uint8_t>(vm_reg::VR15)];
		emit_mov_reg_imm64(bc, scratch, operands[0].imm.value.s);
		emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
		emit_byte(bc, scratch);
		return true;
	}
	if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
		uint8_t scratch = table.gp_perm[static_cast<uint8_t>(vm_reg::VR15)];
		if (!emit_sib_load(operands[0], scratch, 8, bc, &inst)) return false;
		emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
		emit_byte(bc, scratch);
		return true;
	}
	return false;
}

bool vm_translator::translate_pop(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& operands = inst.zyinstr.operands;
	if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
		uint8_t vreg, sz;
		if (!map_register(operands[0].reg.value, vreg, sz)) return false;
		emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
		emit_byte(bc, vreg);
		return true;
	}
	if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
		uint8_t scratch = table.gp_perm[static_cast<uint8_t>(vm_reg::VR15)];
		emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
		emit_byte(bc, scratch);
		if (!emit_sib_store(operands[0], scratch, 8, bc, &inst)) return false;
		return true;
	}
	return false;
}

bool vm_translator::translate_lea(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& operands = inst.zyinstr.operands;
	if (operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER || operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY)
		return false;

	uint8_t vreg_dst, sz_dst;
	if (!map_register(operands[0].reg.value, vreg_dst, sz_dst)) return false;

	// LEA reg, [RIP + disp]: compute RVA and relocate at runtime
	if (operands[1].mem.base == ZYDIS_REGISTER_RIP && buffer_base) {
		uint64_t target_buf = inst.runtime_address + inst.zyinstr.info.length + operands[1].mem.disp.value;
		uint64_t target_rva = target_buf - buffer_base;
		emit_obfuscated_address(bc, vreg_dst, static_cast<int64_t>(target_rva));
		emit_u16(bc, table.encode_random(vm_op::VM_RELOCATE_REG, junk_rng));
		emit_byte(bc, vreg_dst);
		return true;
	}

	uint8_t vreg_base = 0xFF, vreg_index = 0xFF, sz_tmp;
	if (operands[1].mem.base != ZYDIS_REGISTER_NONE)
		if (!map_register(operands[1].mem.base, vreg_base, sz_tmp)) return false;
	if (operands[1].mem.index != ZYDIS_REGISTER_NONE)
		if (!map_register(operands[1].mem.index, vreg_index, sz_tmp)) return false;

	if (vreg_index == 0xFF) {
		emit_u16(bc, table.encode_random(vm_op::VM_LEA_REG, junk_rng));
		emit_byte(bc, vreg_dst);
		emit_byte(bc, vreg_base);
		emit_i32(bc, static_cast<int32_t>(operands[1].mem.disp.value));
	} else {
		uint8_t scale = static_cast<uint8_t>(operands[1].mem.scale);
		if (scale == 0) scale = 1;
		emit_u16(bc, table.encode_random(vm_op::VM_LEA_SIB, junk_rng));
		emit_byte(bc, vreg_dst);
		emit_byte(bc, vreg_base);
		emit_byte(bc, vreg_index);
		emit_byte(bc, scale);
		emit_i32(bc, static_cast<int32_t>(operands[1].mem.disp.value));
	}
	return true;
}

bool vm_translator::translate_jcc(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto mnemonic = inst.zyinstr.info.mnemonic;
	vm_op jmp_op;

	switch (mnemonic) {
	case ZYDIS_MNEMONIC_JMP: jmp_op = vm_op::VM_JMP; break;
	case ZYDIS_MNEMONIC_JZ:  jmp_op = vm_op::VM_JZ; break;
	case ZYDIS_MNEMONIC_JNZ: jmp_op = vm_op::VM_JNZ; break;
	case ZYDIS_MNEMONIC_JL:  jmp_op = vm_op::VM_JL; break;
	case ZYDIS_MNEMONIC_JLE: jmp_op = vm_op::VM_JLE; break;
	case ZYDIS_MNEMONIC_JNL: jmp_op = vm_op::VM_JGE; break;
	case ZYDIS_MNEMONIC_JNLE:jmp_op = vm_op::VM_JG; break;
	case ZYDIS_MNEMONIC_JB:  jmp_op = vm_op::VM_JB; break;
	case ZYDIS_MNEMONIC_JBE: jmp_op = vm_op::VM_JBE; break;
	case ZYDIS_MNEMONIC_JNB: jmp_op = vm_op::VM_JAE; break;
	case ZYDIS_MNEMONIC_JNBE:jmp_op = vm_op::VM_JA; break;
	case ZYDIS_MNEMONIC_JS:  jmp_op = vm_op::VM_JS; break;
	case ZYDIS_MNEMONIC_JNS: jmp_op = vm_op::VM_JNS; break;
	case ZYDIS_MNEMONIC_JP:  jmp_op = vm_op::VM_JP; break;
	case ZYDIS_MNEMONIC_JNP: jmp_op = vm_op::VM_JNP; break;
	default: return false;
	}

	emit_u16(bc, table.encode_random(jmp_op, junk_rng));
	// Placeholder offset — patched later during bytecode linking
	emit_i32(bc, 0);
	return true;
}

bool vm_translator::translate_not_neg(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& operands = inst.zyinstr.operands;
	vm_op op = (inst.zyinstr.info.mnemonic == ZYDIS_MNEMONIC_NOT) ? vm_op::VM_NOT_REG : vm_op::VM_NEG_REG;

	if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
		uint8_t vreg, sz;
		if (!map_register(operands[0].reg.value, vreg, sz)) return false;
		emit_u16(bc, table.encode_random(op, junk_rng));
		emit_byte(bc, vreg);
		return true;
	}

	// NOT/NEG [mem] — load scratch, NOT/NEG scratch, store back
	if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
		uint8_t scratch = table.gp_perm[static_cast<uint8_t>(vm_reg::VR15)];
		uint8_t sz_dst = static_cast<uint8_t>(operands[0].size / 8);
		emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
		emit_byte(bc, scratch);
		if (!emit_sib_load(operands[0], scratch, sz_dst, bc, &inst)) return false;
		emit_u16(bc, table.encode_random(op, junk_rng));
		emit_byte(bc, scratch);
		if (!emit_sib_store(operands[0], scratch, sz_dst, bc, &inst)) return false;
		emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
		emit_byte(bc, scratch);
		return true;
	}

	return false;
}

bool vm_translator::translate_shl_shr(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& operands = inst.zyinstr.operands;
	auto mnemonic = inst.zyinstr.info.mnemonic;

	if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
		uint8_t vreg, sz;
		if (!map_register(operands[0].reg.value, vreg, sz)) return false;

		// Shift by CL (register)
		if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
			vm_op op;
			if (mnemonic == ZYDIS_MNEMONIC_SHL)      op = vm_op::VM_SHL_REG_CL;
			else if (mnemonic == ZYDIS_MNEMONIC_SHR)  op = vm_op::VM_SHR_REG_CL;
			else                                       op = vm_op::VM_SAR_REG_CL;
			emit_u16(bc, table.encode_random(op, junk_rng));
			emit_byte(bc, vreg);
			return true;
		}

		// Shift by immediate
		vm_op op;
		if (mnemonic == ZYDIS_MNEMONIC_SHL)      op = vm_op::VM_SHL_REG_IMM;
		else if (mnemonic == ZYDIS_MNEMONIC_SHR)  op = vm_op::VM_SHR_REG_IMM;
		else                                       op = vm_op::VM_SAR_REG_IMM;

		uint8_t shift_amt = 1;
		if (operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
			shift_amt = static_cast<uint8_t>(operands[1].imm.value.u);

		emit_u16(bc, table.encode_random(op, junk_rng));
		emit_byte(bc, vreg);
		emit_byte(bc, shift_amt);
		return true;
	}

	// SHL/SHR/SAR [mem], imm — load to scratch, shift, store back
	if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
		uint8_t scratch = table.gp_perm[static_cast<uint8_t>(vm_reg::VR15)];
		uint8_t sz_dst = static_cast<uint8_t>(operands[0].size / 8);

		vm_op op;
		if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
			// shift by CL
			if (mnemonic == ZYDIS_MNEMONIC_SHL)      op = vm_op::VM_SHL_REG_CL;
			else if (mnemonic == ZYDIS_MNEMONIC_SHR)  op = vm_op::VM_SHR_REG_CL;
			else                                       op = vm_op::VM_SAR_REG_CL;

			emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
			emit_byte(bc, scratch);
			if (!emit_sib_load(operands[0], scratch, sz_dst, bc, &inst)) return false;
			emit_u16(bc, table.encode_random(op, junk_rng));
			emit_byte(bc, scratch);
			if (!emit_sib_store(operands[0], scratch, sz_dst, bc, &inst)) return false;
			emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
			emit_byte(bc, scratch);
			return true;
		}

		// shift by imm
		if (mnemonic == ZYDIS_MNEMONIC_SHL)      op = vm_op::VM_SHL_REG_IMM;
		else if (mnemonic == ZYDIS_MNEMONIC_SHR)  op = vm_op::VM_SHR_REG_IMM;
		else                                       op = vm_op::VM_SAR_REG_IMM;

		uint8_t shift_amt = 1;
		if (operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
			shift_amt = static_cast<uint8_t>(operands[1].imm.value.u);

		emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
		emit_byte(bc, scratch);
		if (!emit_sib_load(operands[0], scratch, sz_dst, bc, &inst)) return false;
		emit_u16(bc, table.encode_random(op, junk_rng));
		emit_byte(bc, scratch);
		emit_byte(bc, shift_amt);
		if (!emit_sib_store(operands[0], scratch, sz_dst, bc, &inst)) return false;
		emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
		emit_byte(bc, scratch);
		return true;
	}

	return false;
}

bool vm_translator::translate_imul(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& operands = inst.zyinstr.operands;
	int op_count = inst.zyinstr.info.operand_count_visible;

	// imul reg, reg
	if (op_count >= 2 && operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
		if (op_count == 3 && operands[2].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
			// imul reg, reg, imm -> mov dst, src; imul dst, imm
			uint8_t vreg_dst, vreg_src, sz1, sz2;
			if (!map_register(operands[0].reg.value, vreg_dst, sz1)) return false;
			if (!map_register(operands[1].reg.value, vreg_src, sz2)) return false;
			emit_u16(bc, table.encode_random(vm_op::VM_MOV_REG_REG, junk_rng));
			emit_byte(bc, vreg_dst);
			emit_byte(bc, vreg_src);
			emit_u16(bc, table.encode_random(vm_op::VM_MUL_REG_IMM, junk_rng));
			emit_byte(bc, vreg_dst);
			emit_i32(bc, static_cast<int32_t>(operands[2].imm.value.s));
			return true;
		}
		return translate_alu_reg_reg(vm_op::VM_IMUL_REG_REG, inst, bc);
	}

	// imul reg, mem, imm -> load mem into dst, imul dst, imm
	if (op_count == 3 && operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER
		&& operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY
		&& operands[2].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
		uint8_t vreg_dst, sz;
		if (!map_register(operands[0].reg.value, vreg_dst, sz)) return false;
		uint8_t load_sz = static_cast<uint8_t>(operands[1].size / 8);
		if (!emit_sib_load(operands[1], vreg_dst, load_sz, bc, &inst)) return false;
		emit_u16(bc, table.encode_random(vm_op::VM_MUL_REG_IMM, junk_rng));
		emit_byte(bc, vreg_dst);
		emit_i32(bc, static_cast<int32_t>(operands[2].imm.value.s));
		return true;
	}

	// imul reg, imm
	if (op_count >= 2 && operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
		uint8_t vreg, sz;
		if (!map_register(operands[0].reg.value, vreg, sz)) return false;
		emit_u16(bc, table.encode_random(vm_op::VM_MUL_REG_IMM, junk_rng));
		emit_byte(bc, vreg);
		emit_i32(bc, static_cast<int32_t>(operands[1].imm.value.s));
		return true;
	}

	// imul single-operand: imul r/m — RDX:RAX = RAX * operand (signed)
	if (op_count == 1) {
		if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
			uint8_t vreg, sz;
			if (!map_register(operands[0].reg.value, vreg, sz)) return false;
			emit_u16(bc, table.encode_random(vm_op::VM_IMUL_REG, junk_rng));
			emit_byte(bc, vreg);
			return true;
		}
		if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
			uint8_t scratch = table.gp_perm[static_cast<uint8_t>(vm_reg::VR15)];
			uint8_t sz_src = static_cast<uint8_t>(operands[0].size / 8);
			emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
			emit_byte(bc, scratch);
			if (!emit_sib_load(operands[0], scratch, sz_src, bc, &inst)) return false;
			emit_u16(bc, table.encode_random(vm_op::VM_IMUL_REG, junk_rng));
			emit_byte(bc, scratch);
			emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
			emit_byte(bc, scratch);
			return true;
		}
	}

	return false;
}

bool vm_translator::translate_call(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& operands = inst.zyinstr.operands;

	if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
		uint64_t target_buf = inst.runtime_address + inst.zyinstr.info.length + operands[0].imm.value.s;
		uint64_t target_rva = target_buf - buffer_base;
		emit_u16(bc, table.encode_random(vm_op::VM_CALL_NATIVE_RELOC, junk_rng));
		// Use obfuscated address - always applies polynomial chain
		uint8_t scratch = table.gp_perm[static_cast<uint8_t>(vm_reg::VR14)];
		emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
		emit_byte(bc, scratch);
		emit_obfuscated_address(bc, scratch, static_cast<int64_t>(target_rva));
		emit_u16(bc, table.encode_random(vm_op::VM_RELOCATE_REG, junk_rng));
		emit_byte(bc, scratch);
		emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
		emit_byte(bc, scratch);
		return true;
	}

	if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
		uint8_t vreg, sz;
		if (!map_register(operands[0].reg.value, vreg, sz)) return false;
		emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
		emit_byte(bc, vreg);
		emit_u16(bc, table.encode_random(vm_op::VM_CALL_NATIVE, junk_rng));
		emit_obfuscated_address(bc, table.gp_perm[static_cast<uint8_t>(vm_reg::VR14)], static_cast<int64_t>(imm_xor_key));
		return true;
	}

	// CALL [mem] — load target from memory, then call
	if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
		// RIP-relative CALL [RIP+disp]: load address using RVA + relocate
		if (operands[0].mem.base == ZYDIS_REGISTER_RIP && buffer_base) {
			uint64_t target_buf = inst.runtime_address + inst.zyinstr.info.length + operands[0].mem.disp.value;
			uint64_t target_rva = target_buf - buffer_base;

			auto it = import_map.find(static_cast<uint32_t>(target_rva));
			if (it != import_map.end()) {
				emit_u16(bc, table.encode_random(vm_op::VM_CALL_IMPORT, junk_rng));
				// Obfuscate hashes with imm_xor_key (same as bytecode encryption key)
				// xor with low 32 bits for dll_hash, high 32 bits for func_hash
				uint32_t dll_enc = it->second.dll_hash ^ static_cast<uint32_t>(imm_xor_key);
				uint32_t fn_enc = it->second.func_hash ^ static_cast<uint32_t>(imm_xor_key >> 32);
				emit_u32(bc, dll_enc);
				emit_u32(bc, fn_enc);
				return true;
			}

			uint8_t scratch = table.gp_perm[static_cast<uint8_t>(vm_reg::VR14)];
			emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
			emit_byte(bc, scratch);
			emit_obfuscated_address(bc, scratch, static_cast<int64_t>(target_rva));
			emit_u16(bc, table.encode_random(vm_op::VM_RELOCATE_REG, junk_rng));
			emit_byte(bc, scratch);
			emit_u16(bc, table.encode_random(vm_op::VM_CALL_REG_INDIRECT, junk_rng));
			emit_byte(bc, scratch);
			emit_i32(bc, 0);
			emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
			emit_byte(bc, scratch);
			return true;
		}
		uint8_t vreg_base = 0xFF, sz_base;
		if (operands[0].mem.base != ZYDIS_REGISTER_NONE)
			if (!map_register(operands[0].mem.base, vreg_base, sz_base)) return false;
		emit_u16(bc, table.encode_random(vm_op::VM_CALL_REG_INDIRECT, junk_rng));
		emit_byte(bc, vreg_base);
		emit_i32(bc, static_cast<int32_t>(operands[0].mem.disp.value));
		return true;
	}

	return false;
}

bool vm_translator::translate_inc_dec(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& operands = inst.zyinstr.operands;
	vm_op op = (inst.zyinstr.info.mnemonic == ZYDIS_MNEMONIC_INC) ? vm_op::VM_ADD_REG_IMM : vm_op::VM_SUB_REG_IMM;

	if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
		uint8_t vreg, sz;
		if (!map_register(operands[0].reg.value, vreg, sz)) return false;
		emit_u16(bc, table.encode_random(op, junk_rng));
		emit_byte(bc, vreg);
		emit_i32(bc, 1);
		emit_byte(bc, sz);
		return true;
	}

	// INC/DEC [mem]
	if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
		uint8_t scratch = table.gp_perm[static_cast<uint8_t>(vm_reg::VR15)];
		uint8_t sz_dst = static_cast<uint8_t>(operands[0].size / 8);
		emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
		emit_byte(bc, scratch);
		if (!emit_sib_load(operands[0], scratch, sz_dst, bc, &inst)) return false;
		emit_u16(bc, table.encode_random(op, junk_rng));
		emit_byte(bc, scratch);
		emit_i32(bc, 1);
		if (!emit_sib_store(operands[0], scratch, sz_dst, bc, &inst)) return false;
		emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
		emit_byte(bc, scratch);
		return true;
	}

	return false;
}

bool vm_translator::translate_cdq_cqo(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto mnemonic = inst.zyinstr.info.mnemonic;
	switch (mnemonic) {
	case ZYDIS_MNEMONIC_CDQ: emit_u16(bc, table.encode_random(vm_op::VM_CDQ, junk_rng)); break;
	case ZYDIS_MNEMONIC_CQO: emit_u16(bc, table.encode_random(vm_op::VM_CQO, junk_rng)); break;
	case ZYDIS_MNEMONIC_CWD: emit_u16(bc, table.encode_random(vm_op::VM_CWD, junk_rng)); break;
	default: return false;
	}
	return true;
}

bool vm_translator::translate_div_idiv(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& operands = inst.zyinstr.operands;
	vm_op op = (inst.zyinstr.info.mnemonic == ZYDIS_MNEMONIC_IDIV) ? vm_op::VM_IDIV_REG : vm_op::VM_DIV_REG;

	if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
		uint8_t vreg, sz;
		if (!map_register(operands[0].reg.value, vreg, sz)) return false;
		emit_u16(bc, table.encode_random(op, junk_rng));
		emit_byte(bc, vreg);
		return true;
	}

	// DIV/IDIV [mem] — load to scratch, then div scratch
	if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
		uint8_t scratch = table.gp_perm[static_cast<uint8_t>(vm_reg::VR15)];
		uint8_t vreg_base = 0xFF, sz_base;
		if (operands[0].mem.base != ZYDIS_REGISTER_NONE && operands[0].mem.base != ZYDIS_REGISTER_RIP)
			if (!map_register(operands[0].mem.base, vreg_base, sz_base)) return false;

		uint8_t sz_src = static_cast<uint8_t>(operands[0].size / 8);
		emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
		emit_byte(bc, scratch);
		emit_u16(bc, table.encode_random(vm_op::VM_MOV_REG_MEM, junk_rng));
		emit_byte(bc, scratch);
		emit_byte(bc, vreg_base);
		emit_i32(bc, static_cast<int32_t>(operands[0].mem.disp.value));
		emit_byte(bc, sz_src);
		emit_u16(bc, table.encode_random(op, junk_rng));
		emit_byte(bc, scratch);
		emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
		emit_byte(bc, scratch);
		return true;
	}

	return false;
}

bool vm_translator::translate_cmov(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& operands = inst.zyinstr.operands;
	if (operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER) return false;

	uint8_t vreg_dst, vreg_src, sz1, sz2;
	vm_op op;

	switch (inst.zyinstr.info.mnemonic) {
	case ZYDIS_MNEMONIC_CMOVZ:  op = vm_op::VM_CMOVZ_REG_REG; break;
	case ZYDIS_MNEMONIC_CMOVNZ: op = vm_op::VM_CMOVNZ_REG_REG; break;
	case ZYDIS_MNEMONIC_CMOVL:  op = vm_op::VM_CMOVL_REG_REG; break;
	case ZYDIS_MNEMONIC_CMOVLE: op = vm_op::VM_CMOVLE_REG_REG; break;
	case ZYDIS_MNEMONIC_CMOVNL: op = vm_op::VM_CMOVG_REG_REG; break;
	case ZYDIS_MNEMONIC_CMOVNLE:op = vm_op::VM_CMOVGE_REG_REG; break;
	case ZYDIS_MNEMONIC_CMOVB:  op = vm_op::VM_CMOVB_REG_REG; break;
	case ZYDIS_MNEMONIC_CMOVBE: op = vm_op::VM_CMOVBE_REG_REG; break;
	case ZYDIS_MNEMONIC_CMOVNBE:op = vm_op::VM_CMOVA_REG_REG; break;
	case ZYDIS_MNEMONIC_CMOVNB: op = vm_op::VM_CMOVAE_REG_REG; break;
	case ZYDIS_MNEMONIC_CMOVS:  op = vm_op::VM_CMOVS_REG_REG; break;
	case ZYDIS_MNEMONIC_CMOVNS: op = vm_op::VM_CMOVNS_REG_REG; break;
	case ZYDIS_MNEMONIC_CMOVP:  op = vm_op::VM_CMOVP_REG_REG; break;
	case ZYDIS_MNEMONIC_CMOVNP: op = vm_op::VM_CMOVNP_REG_REG; break;
	default: return false;
	}

	if (!map_register(operands[0].reg.value, vreg_dst, sz1)) return false;

	// CMOV reg, reg
	if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
		if (!map_register(operands[1].reg.value, vreg_src, sz2)) return false;
		emit_u16(bc, table.encode_random(op, junk_rng));
		emit_byte(bc, vreg_dst);
		emit_byte(bc, vreg_src);
		return true;
	}

	// CMOV reg, [mem] — load to scratch, then cmov
	if (operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
		uint8_t scratch = table.gp_perm[static_cast<uint8_t>(vm_reg::VR15)];
		uint8_t vreg_base = 0xFF, sz_base;
		if (operands[1].mem.base != ZYDIS_REGISTER_NONE && operands[1].mem.base != ZYDIS_REGISTER_RIP)
			if (!map_register(operands[1].mem.base, vreg_base, sz_base)) return false;

		emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
		emit_byte(bc, scratch);
		emit_u16(bc, table.encode_random(vm_op::VM_MOV_REG_MEM, junk_rng));
		emit_byte(bc, scratch);
		emit_byte(bc, vreg_base);
		emit_i32(bc, static_cast<int32_t>(operands[1].mem.disp.value));
		emit_byte(bc, sz1);
		emit_u16(bc, table.encode_random(op, junk_rng));
		emit_byte(bc, vreg_dst);
		emit_byte(bc, scratch);
		emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
		emit_byte(bc, scratch);
		return true;
	}

	return false;
}

bool vm_translator::translate_setcc(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& operands = inst.zyinstr.operands;
	if (operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER) return false;

	uint8_t vreg, sz;
	if (!map_register(operands[0].reg.value, vreg, sz)) return false;

	vm_op op;
	switch (inst.zyinstr.info.mnemonic) {
	case ZYDIS_MNEMONIC_SETZ:   op = vm_op::VM_SETZ_REG; break;
	case ZYDIS_MNEMONIC_SETNZ:  op = vm_op::VM_SETNZ_REG; break;
	case ZYDIS_MNEMONIC_SETL:   op = vm_op::VM_SETL_REG; break;
	case ZYDIS_MNEMONIC_SETLE:  op = vm_op::VM_SETLE_REG; break;
	case ZYDIS_MNEMONIC_SETNL:  op = vm_op::VM_SETG_REG; break;
	case ZYDIS_MNEMONIC_SETNLE: op = vm_op::VM_SETGE_REG; break;
	case ZYDIS_MNEMONIC_SETB:   op = vm_op::VM_SETB_REG; break;
	case ZYDIS_MNEMONIC_SETBE:  op = vm_op::VM_SETBE_REG; break;
	case ZYDIS_MNEMONIC_SETNBE: op = vm_op::VM_SETA_REG; break;
	case ZYDIS_MNEMONIC_SETNB:  op = vm_op::VM_SETAE_REG; break;
	case ZYDIS_MNEMONIC_SETS:   op = vm_op::VM_SETS_REG; break;
	case ZYDIS_MNEMONIC_SETNS:  op = vm_op::VM_SETNS_REG; break;
	case ZYDIS_MNEMONIC_SETP:   op = vm_op::VM_SETP_REG; break;
	case ZYDIS_MNEMONIC_SETNP:  op = vm_op::VM_SETNP_REG; break;
	default: return false;
	}

	emit_u16(bc, table.encode_random(op, junk_rng));
	emit_byte(bc, vreg);
	return true;
}

bool vm_translator::translate_movzx_movsx(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& operands = inst.zyinstr.operands;
	auto mnemonic = inst.zyinstr.info.mnemonic;

	if (operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER) return false;

	uint8_t vreg_dst, sz_dst;
	if (!map_register(operands[0].reg.value, vreg_dst, sz_dst)) return false;

	// reg, reg — use existing MOV_REG_REG (VM handles full 64-bit)
	if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
		uint8_t vreg_src, sz_src;
		if (!map_register(operands[1].reg.value, vreg_src, sz_src)) return false;
		emit_u16(bc, table.encode_random(vm_op::VM_MOV_REG_REG, junk_rng));
		emit_byte(bc, vreg_dst);
		emit_byte(bc, vreg_src);
		return true;
	}

	// reg, [mem]
	if (operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
		uint8_t src_size = static_cast<uint8_t>(operands[1].size / 8);
		bool has_index = (operands[1].mem.index != ZYDIS_REGISTER_NONE);

		if (has_index) {
			// SIB: LEA scratch = address, then movzx/movsx dst, [scratch+0]
			uint8_t scratch = table.gp_perm[static_cast<uint8_t>(vm_reg::VR15)];
			uint8_t vreg_base_s = 0xFF, vreg_index_s = 0xFF, sz_tmp;
			uint8_t scale = static_cast<uint8_t>(operands[1].mem.scale);
			if (scale == 0) scale = 1;
			if (operands[1].mem.base != ZYDIS_REGISTER_NONE && operands[1].mem.base != ZYDIS_REGISTER_RIP)
				if (!map_register(operands[1].mem.base, vreg_base_s, sz_tmp)) return false;
			if (!map_register(operands[1].mem.index, vreg_index_s, sz_tmp)) return false;

			emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
			emit_byte(bc, scratch);
			emit_u16(bc, table.encode_random(vm_op::VM_LEA_SIB, junk_rng));
			emit_byte(bc, scratch);
			emit_byte(bc, vreg_base_s);
			emit_byte(bc, vreg_index_s);
			emit_byte(bc, scale);
			emit_i32(bc, static_cast<int32_t>(operands[1].mem.disp.value));

			vm_op op;
			if (mnemonic == ZYDIS_MNEMONIC_MOVZX)
				op = (src_size == 1) ? vm_op::VM_MOVZX_REG_MEM8 : vm_op::VM_MOVZX_REG_MEM16;
			else if (mnemonic == ZYDIS_MNEMONIC_MOVSX)
				op = (src_size == 1) ? vm_op::VM_MOVSX_REG_MEM8 : vm_op::VM_MOVSX_REG_MEM16;
			else
				op = vm_op::VM_MOVSXD_REG_MEM32;

			emit_u16(bc, table.encode_random(op, junk_rng));
			emit_byte(bc, vreg_dst);
			emit_byte(bc, scratch);
			emit_i32(bc, 0);
			emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
			emit_byte(bc, scratch);
			return true;
		}

		uint8_t vreg_base = 0xFF, sz_base;
		if (operands[1].mem.base != ZYDIS_REGISTER_NONE && operands[1].mem.base != ZYDIS_REGISTER_RIP)
			if (!map_register(operands[1].mem.base, vreg_base, sz_base)) return false;

		vm_op op;
		if (mnemonic == ZYDIS_MNEMONIC_MOVZX)
			op = (src_size == 1) ? vm_op::VM_MOVZX_REG_MEM8 : vm_op::VM_MOVZX_REG_MEM16;
		else if (mnemonic == ZYDIS_MNEMONIC_MOVSX)
			op = (src_size == 1) ? vm_op::VM_MOVSX_REG_MEM8 : vm_op::VM_MOVSX_REG_MEM16;
		else
			op = vm_op::VM_MOVSXD_REG_MEM32;

		emit_u16(bc, table.encode_random(op, junk_rng));
		emit_byte(bc, vreg_dst);
		emit_byte(bc, vreg_base);
		emit_i32(bc, static_cast<int32_t>(operands[1].mem.disp.value));
		return true;
	}

	return false;
}

bool vm_translator::translate_cbw_cwde_cdqe(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto mnemonic = inst.zyinstr.info.mnemonic;
	switch (mnemonic) {
	case ZYDIS_MNEMONIC_CBW:  emit_u16(bc, table.encode_random(vm_op::VM_CBW, junk_rng)); break;
	case ZYDIS_MNEMONIC_CWDE: emit_u16(bc, table.encode_random(vm_op::VM_CWDE, junk_rng)); break;
	case ZYDIS_MNEMONIC_CDQE: emit_u16(bc, table.encode_random(vm_op::VM_CDQE, junk_rng)); break;
	default: return false;
	}
	return true;
}

bool vm_translator::translate_mul(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& operands = inst.zyinstr.operands;
	if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
		uint8_t vreg, sz;
		if (!map_register(operands[0].reg.value, vreg, sz)) return false;
		emit_u16(bc, table.encode_random(vm_op::VM_MUL_REG, junk_rng));
		emit_byte(bc, vreg);
		return true;
	}
	if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
		uint8_t scratch = table.gp_perm[static_cast<uint8_t>(vm_reg::VR15)];
		uint8_t vreg_base = 0xFF, sz_base;
		if (operands[0].mem.base != ZYDIS_REGISTER_NONE && operands[0].mem.base != ZYDIS_REGISTER_RIP)
			if (!map_register(operands[0].mem.base, vreg_base, sz_base)) return false;
		uint8_t sz_src = static_cast<uint8_t>(operands[0].size / 8);
		emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
		emit_byte(bc, scratch);
		emit_u16(bc, table.encode_random(vm_op::VM_MOV_REG_MEM, junk_rng));
		emit_byte(bc, scratch);
		emit_byte(bc, vreg_base);
		emit_i32(bc, static_cast<int32_t>(operands[0].mem.disp.value));
		emit_byte(bc, sz_src);
		emit_u16(bc, table.encode_random(vm_op::VM_MUL_REG, junk_rng));
		emit_byte(bc, scratch);
		emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
		emit_byte(bc, scratch);
		return true;
	}
	return false;
}

bool vm_translator::translate_rol_ror(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& operands = inst.zyinstr.operands;
	if (operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER) return false;

	uint8_t vreg, sz;
	if (!map_register(operands[0].reg.value, vreg, sz)) return false;

	auto mnemonic = inst.zyinstr.info.mnemonic;

	// ROL/ROR by CL
	if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
		vm_op op;
		if (mnemonic == ZYDIS_MNEMONIC_ROL) op = vm_op::VM_ROL_REG_CL;
		else if (mnemonic == ZYDIS_MNEMONIC_ROR) op = vm_op::VM_ROR_REG_CL;
		else return false; // RCL/RCR by CL not common
		emit_u16(bc, table.encode_random(op, junk_rng));
		emit_byte(bc, vreg);
		return true;
	}

	vm_op op;
	switch (mnemonic) {
	case ZYDIS_MNEMONIC_ROL: op = vm_op::VM_ROL_REG_IMM; break;
	case ZYDIS_MNEMONIC_ROR: op = vm_op::VM_ROR_REG_IMM; break;
	case ZYDIS_MNEMONIC_RCL: op = vm_op::VM_RCL_REG_IMM; break;
	case ZYDIS_MNEMONIC_RCR: op = vm_op::VM_RCR_REG_IMM; break;
	default: return false;
	}

	uint8_t amt = 1;
	if (operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
		amt = static_cast<uint8_t>(operands[1].imm.value.u);

	emit_u16(bc, table.encode_random(op, junk_rng));
	emit_byte(bc, vreg);
	emit_byte(bc, amt);
	return true;
}

bool vm_translator::translate_bt(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& operands = inst.zyinstr.operands;
	if (operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER) return false;

	uint8_t vreg1, sz1;
	if (!map_register(operands[0].reg.value, vreg1, sz1)) return false;

	vm_op op_rr, op_ri;
	switch (inst.zyinstr.info.mnemonic) {
	case ZYDIS_MNEMONIC_BT:  op_rr = vm_op::VM_BT_REG_REG;  op_ri = vm_op::VM_BT_REG_IMM; break;
	case ZYDIS_MNEMONIC_BTS: op_rr = vm_op::VM_BTS_REG_REG; op_ri = vm_op::VM_BTS_REG_IMM; break;
	case ZYDIS_MNEMONIC_BTR: op_rr = vm_op::VM_BTR_REG_REG; op_ri = vm_op::VM_BTR_REG_IMM; break;
	default: return false;
	}

	if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
		uint8_t vreg2, sz2;
		if (!map_register(operands[1].reg.value, vreg2, sz2)) return false;
		emit_u16(bc, table.encode_random(op_rr, junk_rng));
		emit_byte(bc, vreg1);
		emit_byte(bc, vreg2);
		return true;
	}
	if (operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
		emit_u16(bc, table.encode_random(op_ri, junk_rng));
		emit_byte(bc, vreg1);
		emit_byte(bc, static_cast<uint8_t>(operands[1].imm.value.u));
		return true;
	}
	return false;
}

bool vm_translator::translate_bsf_bsr(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& operands = inst.zyinstr.operands;
	if (operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER || operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER)
		return false;

	uint8_t vreg_dst, vreg_src, sz1, sz2;
	if (!map_register(operands[0].reg.value, vreg_dst, sz1)) return false;
	if (!map_register(operands[1].reg.value, vreg_src, sz2)) return false;

	vm_op op = (inst.zyinstr.info.mnemonic == ZYDIS_MNEMONIC_BSF) ? vm_op::VM_BSF_REG_REG : vm_op::VM_BSR_REG_REG;
	emit_u16(bc, table.encode_random(op, junk_rng));
	emit_byte(bc, vreg_dst);
	emit_byte(bc, vreg_src);
	return true;
}

bool vm_translator::translate_popcnt_lzcnt_tzcnt(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& operands = inst.zyinstr.operands;
	if (operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER || operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER)
		return false;

	uint8_t vreg_dst, vreg_src, sz1, sz2;
	if (!map_register(operands[0].reg.value, vreg_dst, sz1)) return false;
	if (!map_register(operands[1].reg.value, vreg_src, sz2)) return false;

	vm_op op;
	switch (inst.zyinstr.info.mnemonic) {
	case ZYDIS_MNEMONIC_POPCNT: op = vm_op::VM_POPCNT_REG_REG; break;
	case ZYDIS_MNEMONIC_LZCNT:  op = vm_op::VM_LZCNT_REG_REG; break;
	case ZYDIS_MNEMONIC_TZCNT:  op = vm_op::VM_TZCNT_REG_REG; break;
	default: return false;
	}

	emit_u16(bc, table.encode_random(op, junk_rng));
	emit_byte(bc, vreg_dst);
	emit_byte(bc, vreg_src);
	return true;
}

bool vm_translator::translate_string_op(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto mnemonic = inst.zyinstr.info.mnemonic;
	bool has_rep = (inst.zyinstr.info.attributes & ZYDIS_ATTRIB_HAS_REP) != 0;
	bool has_repne = (inst.zyinstr.info.attributes & ZYDIS_ATTRIB_HAS_REPNE) != 0;
	bool has_repe = (inst.zyinstr.info.attributes & ZYDIS_ATTRIB_HAS_REPE) != 0;

	vm_op op;
	switch (mnemonic) {
	case ZYDIS_MNEMONIC_MOVSB:
		op = has_rep ? vm_op::VM_REP_MOVSB : vm_op::VM_MOVSB;
		break;
	case ZYDIS_MNEMONIC_MOVSW:
		if (!has_rep) return false;
		op = vm_op::VM_REP_MOVSW;
		break;
	case ZYDIS_MNEMONIC_MOVSD:
		if (!has_rep) return false;
		op = vm_op::VM_REP_MOVSD;
		break;
	case ZYDIS_MNEMONIC_MOVSQ:
		op = has_rep ? vm_op::VM_REP_MOVSQ : vm_op::VM_MOVSQ;
		break;
	case ZYDIS_MNEMONIC_STOSB:
		op = has_rep ? vm_op::VM_REP_STOSB : vm_op::VM_STOSB;
		break;
	case ZYDIS_MNEMONIC_STOSW:
		if (!has_rep) return false;
		op = vm_op::VM_REP_STOSW;
		break;
	case ZYDIS_MNEMONIC_STOSD:
		if (!has_rep) return false;
		op = vm_op::VM_REP_STOSD;
		break;
	case ZYDIS_MNEMONIC_STOSQ:
		op = has_rep ? vm_op::VM_REP_STOSQ : vm_op::VM_STOSQ;
		break;
	case ZYDIS_MNEMONIC_SCASB:
		if (!has_rep && !has_repne) return false;
		op = vm_op::VM_REP_SCASB;
		break;
	case ZYDIS_MNEMONIC_CMPSB:
		if (!has_repe) return false;
		op = vm_op::VM_REPE_CMPSB;
		break;
	default: return false;
	}

	emit_u16(bc, table.encode_random(op, junk_rng));
	return true;
}

bool vm_translator::emit_sib_load(const ZydisDecodedOperand& mem_op, uint8_t dst_vreg, uint8_t load_size, std::vector<uint8_t>& bc, const obfuscator::instruction_t* inst) {
	uint8_t vreg_base = 0xFF, vreg_index = 0xFF, sz_tmp;
	uint8_t scale = static_cast<uint8_t>(mem_op.mem.scale);
	if (scale == 0) scale = 1;

	// RIP-relative: emit RVA + relocate for ASLR support
	if (mem_op.mem.base == ZYDIS_REGISTER_RIP && inst && buffer_base) {
		uint64_t target_buf = inst->runtime_address + inst->zyinstr.info.length + mem_op.mem.disp.value;
		uint64_t target_rva = target_buf - buffer_base;
		uint8_t scratch = table.gp_perm[static_cast<uint8_t>(vm_reg::VR14)];
		emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
		emit_byte(bc, scratch);
		emit_mov_reg_imm64(bc, scratch, static_cast<int64_t>(target_rva));
		emit_u16(bc, table.encode_random(vm_op::VM_RELOCATE_REG, junk_rng));
		emit_byte(bc, scratch);
		emit_u16(bc, table.encode_random(vm_op::VM_MOV_REG_MEM, junk_rng));
		emit_byte(bc, dst_vreg);
		emit_byte(bc, scratch);
		emit_i32(bc, 0);
		emit_byte(bc, load_size);
		emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
		emit_byte(bc, scratch);
		return true;
	}

	if (mem_op.mem.base != ZYDIS_REGISTER_NONE && mem_op.mem.base != ZYDIS_REGISTER_RIP)
		if (!map_register(mem_op.mem.base, vreg_base, sz_tmp)) return false;
	if (mem_op.mem.index != ZYDIS_REGISTER_NONE)
		if (!map_register(mem_op.mem.index, vreg_index, sz_tmp)) return false;

	if (vreg_index == 0xFF) {
		emit_u16(bc, table.encode_random(vm_op::VM_MOV_REG_MEM, junk_rng));
		emit_byte(bc, dst_vreg);
		emit_byte(bc, vreg_base);
		emit_i32(bc, static_cast<int32_t>(mem_op.mem.disp.value));
		emit_byte(bc, load_size);
	} else {
		emit_u16(bc, table.encode_random(vm_op::VM_MOV_REG_SIB, junk_rng));
		emit_byte(bc, dst_vreg);
		emit_byte(bc, vreg_base);
		emit_byte(bc, vreg_index);
		emit_byte(bc, scale);
		emit_i32(bc, static_cast<int32_t>(mem_op.mem.disp.value));
		emit_byte(bc, load_size);
	}
	return true;
}

bool vm_translator::emit_sib_store(const ZydisDecodedOperand& mem_op, uint8_t src_vreg, uint8_t store_size, std::vector<uint8_t>& bc, const obfuscator::instruction_t* inst) {
	uint8_t vreg_base = 0xFF, vreg_index = 0xFF, sz_tmp;
	uint8_t scale = static_cast<uint8_t>(mem_op.mem.scale);
	if (scale == 0) scale = 1;

	// RIP-relative: emit RVA + relocate for ASLR support
	if (mem_op.mem.base == ZYDIS_REGISTER_RIP && inst && buffer_base) {
		uint64_t target_buf = inst->runtime_address + inst->zyinstr.info.length + mem_op.mem.disp.value;
		uint64_t target_rva = target_buf - buffer_base;
		uint8_t scratch = table.gp_perm[static_cast<uint8_t>(vm_reg::VR14)];
		emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
		emit_byte(bc, scratch);
		emit_mov_reg_imm64(bc, scratch, static_cast<int64_t>(target_rva));
		emit_u16(bc, table.encode_random(vm_op::VM_RELOCATE_REG, junk_rng));
		emit_byte(bc, scratch);
		emit_u16(bc, table.encode_random(vm_op::VM_MOV_MEM_REG, junk_rng));
		emit_byte(bc, scratch);
		emit_i32(bc, 0);
		emit_byte(bc, src_vreg);
		emit_byte(bc, store_size);
		emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
		emit_byte(bc, scratch);
		return true;
	}

	if (mem_op.mem.base != ZYDIS_REGISTER_NONE && mem_op.mem.base != ZYDIS_REGISTER_RIP)
		if (!map_register(mem_op.mem.base, vreg_base, sz_tmp)) return false;
	if (mem_op.mem.index != ZYDIS_REGISTER_NONE)
		if (!map_register(mem_op.mem.index, vreg_index, sz_tmp)) return false;

	if (vreg_index == 0xFF) {
		emit_u16(bc, table.encode_random(vm_op::VM_MOV_MEM_REG, junk_rng));
		emit_byte(bc, vreg_base);
		emit_i32(bc, static_cast<int32_t>(mem_op.mem.disp.value));
		emit_byte(bc, src_vreg);
		emit_byte(bc, store_size);
	} else {
		emit_u16(bc, table.encode_random(vm_op::VM_MOV_SIB_REG, junk_rng));
		emit_byte(bc, vreg_base);
		emit_byte(bc, vreg_index);
		emit_byte(bc, scale);
		emit_i32(bc, static_cast<int32_t>(mem_op.mem.disp.value));
		emit_byte(bc, src_vreg);
		emit_byte(bc, store_size);
	}
	return true;
}

bool vm_translator::translate_adc_sbb(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& operands = inst.zyinstr.operands;
	bool is_adc = (inst.zyinstr.info.mnemonic == ZYDIS_MNEMONIC_ADC);
	vm_op rr_op = is_adc ? vm_op::VM_ADC_REG_REG : vm_op::VM_SBB_REG_REG;
	vm_op ri_op = is_adc ? vm_op::VM_ADC_REG_IMM : vm_op::VM_SBB_REG_IMM;

	if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
		return translate_alu_reg_reg(rr_op, inst, bc);
	if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
		return translate_alu_reg_imm(ri_op, inst, bc);
	return translate_alu_mem(rr_op, ri_op, inst, bc);
}

bool vm_translator::translate_xchg(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& operands = inst.zyinstr.operands;
	if (operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER || operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER)
		return false;

	uint8_t vreg1, vreg2, sz1, sz2;
	if (!map_register(operands[0].reg.value, vreg1, sz1)) return false;
	if (!map_register(operands[1].reg.value, vreg2, sz2)) return false;
	emit_u16(bc, table.encode_random(vm_op::VM_XCHG_REG_REG, junk_rng));
	emit_byte(bc, vreg1);
	emit_byte(bc, vreg2);
	return true;
}

bool vm_translator::translate_leave(std::vector<uint8_t>& bc) {
	emit_u16(bc, table.encode_random(vm_op::VM_LEAVE, junk_rng));
	return true;
}

bool vm_translator::translate_btc(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& operands = inst.zyinstr.operands;
	if (operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER) return false;

	uint8_t vreg1, sz1;
	if (!map_register(operands[0].reg.value, vreg1, sz1)) return false;

	if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
		uint8_t vreg2, sz2;
		if (!map_register(operands[1].reg.value, vreg2, sz2)) return false;
		emit_u16(bc, table.encode_random(vm_op::VM_BTC_REG_REG, junk_rng));
		emit_byte(bc, vreg1);
		emit_byte(bc, vreg2);
		return true;
	}
	if (operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
		emit_u16(bc, table.encode_random(vm_op::VM_BTC_REG_IMM, junk_rng));
		emit_byte(bc, vreg1);
		emit_byte(bc, static_cast<uint8_t>(operands[1].imm.value.u));
		return true;
	}
	return false;
}

bool vm_translator::translate_bswap(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& operands = inst.zyinstr.operands;
	if (operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER) return false;

	uint8_t vreg, sz;
	if (!map_register(operands[0].reg.value, vreg, sz)) return false;
	emit_u16(bc, table.encode_random(vm_op::VM_BSWAP_REG, junk_rng));
	emit_byte(bc, vreg);
	return true;
}

bool vm_translator::translate_shld_shrd(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& operands = inst.zyinstr.operands;
	if (operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER || operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER)
		return false;

	uint8_t vreg_dst, vreg_src, sz1, sz2;
	if (!map_register(operands[0].reg.value, vreg_dst, sz1)) return false;
	if (!map_register(operands[1].reg.value, vreg_src, sz2)) return false;

	bool is_shld = (inst.zyinstr.info.mnemonic == ZYDIS_MNEMONIC_SHLD);

	// SHLD/SHRD dst, src, imm8
	if (operands[2].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
		vm_op op = is_shld ? vm_op::VM_SHLD_REG_REG_IMM : vm_op::VM_SHRD_REG_REG_IMM;
		emit_u16(bc, table.encode_random(op, junk_rng));
		emit_byte(bc, vreg_dst);
		emit_byte(bc, vreg_src);
		emit_byte(bc, static_cast<uint8_t>(operands[2].imm.value.u));
		return true;
	}

	// SHLD/SHRD dst, src, CL
	if (operands[2].type == ZYDIS_OPERAND_TYPE_REGISTER) {
		vm_op op = is_shld ? vm_op::VM_SHLD_REG_REG_CL : vm_op::VM_SHRD_REG_REG_CL;
		emit_u16(bc, table.encode_random(op, junk_rng));
		emit_byte(bc, vreg_dst);
		emit_byte(bc, vreg_src);
		return true;
	}

	return false;
}

bool vm_translator::translate_jmp_indirect(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& operands = inst.zyinstr.operands;

	// JMP reg
	if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
		uint8_t vreg, sz;
		if (!map_register(operands[0].reg.value, vreg, sz)) return false;
		emit_u16(bc, table.encode_random(vm_op::VM_JMP_REG, junk_rng));
		emit_byte(bc, vreg);
		return true;
	}

	// JMP [mem]
	if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
		// RIP-relative JMP [RIP+disp]: compute RVA, relocate, then jump
		if (operands[0].mem.base == ZYDIS_REGISTER_RIP && buffer_base) {
			uint64_t target_buf = inst.runtime_address + inst.zyinstr.info.length + operands[0].mem.disp.value;
			uint64_t target_rva = target_buf - buffer_base;
			uint8_t scratch = table.gp_perm[static_cast<uint8_t>(vm_reg::VR14)];
			emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
			emit_byte(bc, scratch);
			emit_obfuscated_address(bc, scratch, static_cast<int64_t>(target_rva));
			emit_u16(bc, table.encode_random(vm_op::VM_RELOCATE_REG, junk_rng));
			emit_byte(bc, scratch);
			emit_u16(bc, table.encode_random(vm_op::VM_JMP_MEM, junk_rng));
			emit_byte(bc, scratch);
			emit_i32(bc, 0);
			emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
			emit_byte(bc, scratch);
			return true;
		}
		uint8_t vreg_base = 0xFF, sz_base;
		if (operands[0].mem.base != ZYDIS_REGISTER_NONE)
			if (!map_register(operands[0].mem.base, vreg_base, sz_base)) return false;
		emit_u16(bc, table.encode_random(vm_op::VM_JMP_MEM, junk_rng));
		emit_byte(bc, vreg_base);
		emit_i32(bc, static_cast<int32_t>(operands[0].mem.disp.value));
		return true;
	}

	return false;
}

bool vm_translator::translate_nop(std::vector<uint8_t>& bc) {
	emit_u16(bc, table.encode_random(vm_op::VM_NOP, junk_rng));
	return true;
}

bool vm_translator::translate(const std::vector<obfuscator::instruction_t>& instructions,
	std::vector<uint8_t>& bytecode) {

	// Maps for jump offset patching
	std::map<uint64_t, uint32_t> addr_to_bc; // x86 runtime_address → bytecode offset
	struct patch_entry { uint32_t bc_offset; uint64_t target_x86_addr; };
	std::vector<patch_entry> patches;

	// Seed junk RNG from opcode table for deterministic output
	junk_rng.seed(table.mapping[0] ^ (table.mapping[2] << 16) ^ 0xDEADFACE);

	// VM_ENTER prologue
	emit_u16(bytecode, table.encode_random(vm_op::VM_ENTER, junk_rng));

	for (size_t inst_idx = 0; inst_idx < instructions.size(); inst_idx++) {
		const auto& inst = instructions[inst_idx];
		auto mnemonic = inst.zyinstr.info.mnemonic;
		bool ok = false;
		bool is_jump = false;

		addr_to_bc[inst.runtime_address] = static_cast<uint32_t>(bytecode.size());

		// Insert random prefix bytes before each instruction
		emit_prefixes(bytecode);

		// Try jump table pattern detection (LEA __ImageBase + MOVSXD + ADD + JMP)
		{
			std::vector<std::pair<uint32_t, uint64_t>> switch_patches;
			int consumed = try_translate_switch(instructions, inst_idx, bytecode, switch_patches);
			if (consumed > 0) {
				for (auto& sp : switch_patches)
					patches.push_back({ sp.first, sp.second });
				// Map addresses of consumed instructions
				for (int ci = 1; ci < consumed && inst_idx + ci < instructions.size(); ci++)
					addr_to_bc[instructions[inst_idx + ci].runtime_address] = static_cast<uint32_t>(bytecode.size());
				inst_idx += consumed - 1;
				continue;
			}
		}

		switch (mnemonic) {
		case ZYDIS_MNEMONIC_MOV:
			ok = translate_mov(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_MOVZX:
		case ZYDIS_MNEMONIC_MOVSX:
		case ZYDIS_MNEMONIC_MOVSXD:
			ok = translate_movzx_movsx(inst, bytecode);
			if (!ok) ok = translate_mov(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_ADD:
			ok = translate_add(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_SUB:
			ok = translate_sub(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_XOR:
			ok = translate_xor(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_AND:
			ok = translate_and(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_OR:
			ok = translate_or(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_CMP:
			ok = translate_cmp(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_TEST:
			ok = translate_test(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_PUSH:
			ok = translate_push(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_POP:
			ok = translate_pop(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_LEA:
			ok = translate_lea(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_JMP:
			// Try indirect JMP first (reg/mem operand)
			if (inst.zyinstr.operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE) {
				ok = translate_jmp_indirect(inst, bytecode);
			} else {
				ok = translate_jcc(inst, bytecode);
				if (ok) {
					uint64_t target = inst.runtime_address + inst.zyinstr.info.length +
						static_cast<int64_t>(inst.zyinstr.operands[0].imm.value.s);
					patches.push_back({ static_cast<uint32_t>(bytecode.size() - 4), target });
					is_jump = true;
				}
			}
			break;
		case ZYDIS_MNEMONIC_JZ:
		case ZYDIS_MNEMONIC_JNZ:
		case ZYDIS_MNEMONIC_JL:
		case ZYDIS_MNEMONIC_JLE:
		case ZYDIS_MNEMONIC_JNL:
		case ZYDIS_MNEMONIC_JNLE:
		case ZYDIS_MNEMONIC_JB:
		case ZYDIS_MNEMONIC_JBE:
		case ZYDIS_MNEMONIC_JNB:
		case ZYDIS_MNEMONIC_JNBE:
		case ZYDIS_MNEMONIC_JS:
		case ZYDIS_MNEMONIC_JNS:
		case ZYDIS_MNEMONIC_JP:
		case ZYDIS_MNEMONIC_JNP:
			ok = translate_jcc(inst, bytecode);
			if (ok) {
				uint64_t target = inst.runtime_address + inst.zyinstr.info.length +
					static_cast<int64_t>(inst.zyinstr.operands[0].imm.value.s);
				patches.push_back({ static_cast<uint32_t>(bytecode.size() - 4), target });
				is_jump = true;
			}
			break;
		case ZYDIS_MNEMONIC_INC:
		case ZYDIS_MNEMONIC_DEC:
			ok = translate_inc_dec(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_NOT:
		case ZYDIS_MNEMONIC_NEG:
			ok = translate_not_neg(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_SHL:
		case ZYDIS_MNEMONIC_SHR:
		case ZYDIS_MNEMONIC_SAR:
			ok = translate_shl_shr(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_IMUL:
			ok = translate_imul(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_CALL:
			ok = translate_call(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_CDQ:
		case ZYDIS_MNEMONIC_CQO:
		case ZYDIS_MNEMONIC_CWD:
			ok = translate_cdq_cqo(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_DIV:
		case ZYDIS_MNEMONIC_IDIV:
			ok = translate_div_idiv(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_CMOVZ:
		case ZYDIS_MNEMONIC_CMOVNZ:
		case ZYDIS_MNEMONIC_CMOVL:
		case ZYDIS_MNEMONIC_CMOVLE:
		case ZYDIS_MNEMONIC_CMOVNL:
		case ZYDIS_MNEMONIC_CMOVNLE:
		case ZYDIS_MNEMONIC_CMOVB:
		case ZYDIS_MNEMONIC_CMOVBE:
		case ZYDIS_MNEMONIC_CMOVNB:
		case ZYDIS_MNEMONIC_CMOVNBE:
		case ZYDIS_MNEMONIC_CMOVS:
		case ZYDIS_MNEMONIC_CMOVNS:
		case ZYDIS_MNEMONIC_CMOVP:
		case ZYDIS_MNEMONIC_CMOVNP:
			ok = translate_cmov(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_SETZ:
		case ZYDIS_MNEMONIC_SETNZ:
		case ZYDIS_MNEMONIC_SETL:
		case ZYDIS_MNEMONIC_SETLE:
		case ZYDIS_MNEMONIC_SETNL:
		case ZYDIS_MNEMONIC_SETNLE:
		case ZYDIS_MNEMONIC_SETB:
		case ZYDIS_MNEMONIC_SETBE:
		case ZYDIS_MNEMONIC_SETNB:
		case ZYDIS_MNEMONIC_SETNBE:
		case ZYDIS_MNEMONIC_SETS:
		case ZYDIS_MNEMONIC_SETNS:
		case ZYDIS_MNEMONIC_SETP:
		case ZYDIS_MNEMONIC_SETNP:
			ok = translate_setcc(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_CBW:
		case ZYDIS_MNEMONIC_CWDE:
		case ZYDIS_MNEMONIC_CDQE:
			ok = translate_cbw_cwde_cdqe(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_MUL:
			ok = translate_mul(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_ROL:
		case ZYDIS_MNEMONIC_ROR:
		case ZYDIS_MNEMONIC_RCL:
		case ZYDIS_MNEMONIC_RCR:
			ok = translate_rol_ror(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_BT:
		case ZYDIS_MNEMONIC_BTS:
		case ZYDIS_MNEMONIC_BTR:
			ok = translate_bt(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_BSF:
		case ZYDIS_MNEMONIC_BSR:
			ok = translate_bsf_bsr(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_POPCNT:
		case ZYDIS_MNEMONIC_LZCNT:
		case ZYDIS_MNEMONIC_TZCNT:
			ok = translate_popcnt_lzcnt_tzcnt(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_MOVSB:
		case ZYDIS_MNEMONIC_MOVSW:
		case ZYDIS_MNEMONIC_MOVSQ:
		case ZYDIS_MNEMONIC_STOSB:
		case ZYDIS_MNEMONIC_STOSW:
		case ZYDIS_MNEMONIC_STOSD:
		case ZYDIS_MNEMONIC_STOSQ:
		case ZYDIS_MNEMONIC_SCASB:
		case ZYDIS_MNEMONIC_CMPSB:
			ok = translate_string_op(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_MOVSD:
			// MOVSD is both string op (rep movsd) and SSE scalar double
			if (inst.zyinstr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
				inst.zyinstr.operands[0].reg.value >= ZYDIS_REGISTER_XMM0 &&
				inst.zyinstr.operands[0].reg.value <= ZYDIS_REGISTER_XMM15) {
				ok = translate_sse_mov(inst, bytecode);
			} else if (inst.zyinstr.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
				inst.zyinstr.operands[1].reg.value >= ZYDIS_REGISTER_XMM0 &&
				inst.zyinstr.operands[1].reg.value <= ZYDIS_REGISTER_XMM15) {
				ok = translate_sse_mov(inst, bytecode);
			} else if (inst.zyinstr.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
				inst.zyinstr.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
				inst.zyinstr.operands[1].reg.value >= ZYDIS_REGISTER_XMM0) {
				ok = translate_sse_mov(inst, bytecode);
			} else {
				ok = translate_string_op(inst, bytecode);
			}
			break;
		case ZYDIS_MNEMONIC_ADC:
			ok = translate_adc_sbb(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_SBB:
			ok = translate_adc_sbb(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_XCHG:
			ok = translate_xchg(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_LEAVE:
			ok = translate_leave(bytecode);
			break;
		case ZYDIS_MNEMONIC_BTC:
			ok = translate_btc(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_BSWAP:
			ok = translate_bswap(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_SHLD:
		case ZYDIS_MNEMONIC_SHRD:
			ok = translate_shld_shrd(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_NOP:
			ok = translate_nop(bytecode);
			break;
		case ZYDIS_MNEMONIC_RET:
			emit_u16(bytecode, table.encode_random(vm_op::VM_EXIT, junk_rng));
			ok = true;
			is_jump = true;
			break;
		// SSE scalar mov
		case ZYDIS_MNEMONIC_MOVSS:
		case ZYDIS_MNEMONIC_MOVAPS:
		case ZYDIS_MNEMONIC_MOVUPS:
		case ZYDIS_MNEMONIC_MOVDQA:
		case ZYDIS_MNEMONIC_MOVDQU:
			ok = translate_sse_mov(inst, bytecode);
			break;
		// SSE scalar arith
		case ZYDIS_MNEMONIC_ADDSS:
		case ZYDIS_MNEMONIC_ADDSD:
		case ZYDIS_MNEMONIC_SUBSS:
		case ZYDIS_MNEMONIC_SUBSD:
		case ZYDIS_MNEMONIC_MULSS:
		case ZYDIS_MNEMONIC_MULSD:
		case ZYDIS_MNEMONIC_DIVSS:
		case ZYDIS_MNEMONIC_DIVSD:
			ok = translate_sse_arith(inst, bytecode);
			break;
		// SSE compare
		case ZYDIS_MNEMONIC_COMISS:
		case ZYDIS_MNEMONIC_COMISD:
		case ZYDIS_MNEMONIC_UCOMISS:
		case ZYDIS_MNEMONIC_UCOMISD:
			ok = translate_sse_cmp(inst, bytecode);
			break;
		// SSE conversion
		case ZYDIS_MNEMONIC_CVTSI2SS:
		case ZYDIS_MNEMONIC_CVTSI2SD:
		case ZYDIS_MNEMONIC_CVTSS2SD:
		case ZYDIS_MNEMONIC_CVTSD2SS:
		case ZYDIS_MNEMONIC_CVTSS2SI:
		case ZYDIS_MNEMONIC_CVTSD2SI:
		case ZYDIS_MNEMONIC_CVTTSS2SI:
		case ZYDIS_MNEMONIC_CVTTSD2SI:
			ok = translate_sse_cvt(inst, bytecode);
			break;
		// SSE bitwise
		case ZYDIS_MNEMONIC_XORPS:
		case ZYDIS_MNEMONIC_XORPD:
		case ZYDIS_MNEMONIC_ANDPS:
		case ZYDIS_MNEMONIC_ANDPD:
		case ZYDIS_MNEMONIC_ORPS:
		case ZYDIS_MNEMONIC_ORPD:
		case ZYDIS_MNEMONIC_ANDNPS:
		case ZYDIS_MNEMONIC_ANDNPD:
			ok = translate_sse_bitwise(inst, bytecode);
			break;
		// SSE packed arith
		case ZYDIS_MNEMONIC_ADDPS:
		case ZYDIS_MNEMONIC_ADDPD:
		case ZYDIS_MNEMONIC_SUBPS:
		case ZYDIS_MNEMONIC_SUBPD:
		case ZYDIS_MNEMONIC_MULPS:
		case ZYDIS_MNEMONIC_MULPD:
		case ZYDIS_MNEMONIC_DIVPS:
		case ZYDIS_MNEMONIC_DIVPD:
			ok = translate_sse_packed_arith(inst, bytecode);
			break;
		// SSE min/max/sqrt
		case ZYDIS_MNEMONIC_MINSS:
		case ZYDIS_MNEMONIC_MAXSS:
		case ZYDIS_MNEMONIC_MINSD:
		case ZYDIS_MNEMONIC_MAXSD:
		case ZYDIS_MNEMONIC_SQRTSS:
		case ZYDIS_MNEMONIC_SQRTSD:
			ok = translate_sse_minmax_sqrt(inst, bytecode);
			break;
		// SSE shuffle
		case ZYDIS_MNEMONIC_SHUFPS:
		case ZYDIS_MNEMONIC_SHUFPD:
		case ZYDIS_MNEMONIC_UNPCKLPS:
		case ZYDIS_MNEMONIC_UNPCKHPS:
		case ZYDIS_MNEMONIC_UNPCKLPD:
		case ZYDIS_MNEMONIC_UNPCKHPD:
			ok = translate_sse_shuffle(inst, bytecode);
			break;
		// SSE integer ops
		case ZYDIS_MNEMONIC_PXOR:
		case ZYDIS_MNEMONIC_PAND:
		case ZYDIS_MNEMONIC_POR:
		case ZYDIS_MNEMONIC_PANDN:
		case ZYDIS_MNEMONIC_PCMPEQB:
		case ZYDIS_MNEMONIC_PCMPEQD:
		case ZYDIS_MNEMONIC_PCMPGTB:
		case ZYDIS_MNEMONIC_PADDB:
		case ZYDIS_MNEMONIC_PADDW:
		case ZYDIS_MNEMONIC_PADDD:
		case ZYDIS_MNEMONIC_PADDQ:
		case ZYDIS_MNEMONIC_PSUBB:
		case ZYDIS_MNEMONIC_PSUBW:
		case ZYDIS_MNEMONIC_PSUBD:
		case ZYDIS_MNEMONIC_PSUBQ:
		case ZYDIS_MNEMONIC_PUNPCKLBW:
		case ZYDIS_MNEMONIC_PUNPCKHBW:
		case ZYDIS_MNEMONIC_PUNPCKLDQ:
		case ZYDIS_MNEMONIC_PUNPCKHDQ:
		case ZYDIS_MNEMONIC_PUNPCKLQDQ:
		case ZYDIS_MNEMONIC_PUNPCKHQDQ:
		case ZYDIS_MNEMONIC_PSHUFB:
		case ZYDIS_MNEMONIC_PMAXSB:
		case ZYDIS_MNEMONIC_PMAXSD:
		case ZYDIS_MNEMONIC_PMINSB:
		case ZYDIS_MNEMONIC_PMINSD:
			ok = translate_sse_int(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_PMOVMSKB:
			ok = translate_pmovmskb(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_PSLLW:
		case ZYDIS_MNEMONIC_PSLLD:
		case ZYDIS_MNEMONIC_PSLLQ:
		case ZYDIS_MNEMONIC_PSRLW:
		case ZYDIS_MNEMONIC_PSRLD:
		case ZYDIS_MNEMONIC_PSRLQ:
		case ZYDIS_MNEMONIC_PSRAW:
		case ZYDIS_MNEMONIC_PSRAD:
			ok = translate_sse_shift_imm(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_PSHUFD:
			ok = translate_pshufd(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_MOVD:
		case ZYDIS_MNEMONIC_MOVQ:
			ok = translate_movd_movq(inst, bytecode);
			break;
		// SSE4.1
		case ZYDIS_MNEMONIC_PINSRB:
		case ZYDIS_MNEMONIC_PINSRD:
		case ZYDIS_MNEMONIC_PINSRQ:
		case ZYDIS_MNEMONIC_PEXTRB:
		case ZYDIS_MNEMONIC_PEXTRD:
		case ZYDIS_MNEMONIC_PEXTRQ:
			ok = translate_pinsr_pextr(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_ROUNDSS:
		case ZYDIS_MNEMONIC_ROUNDSD:
			ok = translate_roundss_sd(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_PTEST:
			ok = translate_ptest(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_MOVHLPS:
		case ZYDIS_MNEMONIC_MOVLHPS:
		case ZYDIS_MNEMONIC_MOVHPS:
		case ZYDIS_MNEMONIC_MOVLPS:
		case ZYDIS_MNEMONIC_MOVHPD:
		case ZYDIS_MNEMONIC_MOVLPD:
			ok = translate_sse_movhilo(inst, bytecode);
			break;
		// LOCK / atomic
		case ZYDIS_MNEMONIC_CMPXCHG:
			ok = translate_cmpxchg(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_XADD:
			ok = translate_lock_op(inst, bytecode);
			break;
		// Misc
		case ZYDIS_MNEMONIC_CPUID:
			ok = translate_cpuid(bytecode);
			break;
		case ZYDIS_MNEMONIC_RDTSC:
			ok = translate_rdtsc(bytecode);
			break;
		case ZYDIS_MNEMONIC_PAUSE:
		case ZYDIS_MNEMONIC_MFENCE:
		case ZYDIS_MNEMONIC_LFENCE:
		case ZYDIS_MNEMONIC_SFENCE:
			ok = translate_fence(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_CLC:
		case ZYDIS_MNEMONIC_STC:
		case ZYDIS_MNEMONIC_CMC:
			ok = translate_flag_op(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_MOVBE:
			ok = translate_movbe(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_CRC32:
			ok = translate_crc32(inst, bytecode);
			break;
		case ZYDIS_MNEMONIC_ANDN:
		case ZYDIS_MNEMONIC_BEXTR:
		case ZYDIS_MNEMONIC_BLSI:
		case ZYDIS_MNEMONIC_BLSMSK:
		case ZYDIS_MNEMONIC_BLSR:
		case ZYDIS_MNEMONIC_PDEP:
		case ZYDIS_MNEMONIC_PEXT:
		case ZYDIS_MNEMONIC_BZHI:
		case ZYDIS_MNEMONIC_SARX:
		case ZYDIS_MNEMONIC_SHLX:
		case ZYDIS_MNEMONIC_SHRX:
			ok = translate_bmi(inst, bytecode);
			break;
		default:
			printf("[vm_translator] unsupported mnemonic: %s\n", inst.zyinstr.text);
			return false;
		}

		if (!ok) {
			printf("[vm_translator] failed to translate: %s\n", inst.zyinstr.text);
			return false;
		}

		// Insert junk bytecode after non-jump instructions
		if (!is_jump)
			maybe_emit_junk(bytecode);
	}

	// Also map the address just past the last instruction (for jumps targeting the end)
	if (!instructions.empty()) {
		auto& last = instructions.back();
		addr_to_bc[last.runtime_address + last.zyinstr.info.length] = static_cast<uint32_t>(bytecode.size());
	}

	// Patch jump offsets
	for (auto& p : patches) {
		auto it = addr_to_bc.find(p.target_x86_addr);
		if (it == addr_to_bc.end()) {
			printf("[vm_translator] jump target 0x%llx not found in bytecode map\n", p.target_x86_addr);
			return false;
		}
		// offset = target_bc - (patch_pos + 4), since RSI is already past the 4-byte operand when offset is applied
		int32_t offset = static_cast<int32_t>(it->second) - static_cast<int32_t>(p.bc_offset + 4);
		memcpy(&bytecode[p.bc_offset], &offset, 4);
	}

	// VM_EXIT epilogue (in case no RET was found)
	emit_u16(bytecode, table.encode_random(vm_op::VM_EXIT, junk_rng));
	return true;
}

// === JUMP TABLE (SWITCH) SUPPORT ===

int vm_translator::try_translate_switch(const std::vector<obfuscator::instruction_t>& instructions,
	size_t idx, std::vector<uint8_t>& bc,
	std::vector<std::pair<uint32_t, uint64_t>>& patches) {
	// Detect MSVC x64 switch pattern:
	//   [i]   lea REG_BASE, [rip + __ImageBase]
	//   [i+1] movsxd REG_OFF, dword [REG_BASE + REG_IDX*4 + table_rva]
	//   [i+2] add REG_OFF, REG_BASE
	//   [i+3] jmp REG_OFF
	// Optionally preceded by:
	//   [i-2] cmp REG_IDX, N
	//   [i-1] ja default_label
	//
	// Returns number of instructions consumed (0 if not a switch pattern)

	if (idx + 3 >= instructions.size()) return 0;

	auto& lea_inst = instructions[idx];
	auto& movsxd_inst = instructions[idx + 1];
	auto& add_inst = instructions[idx + 2];
	auto& jmp_inst = instructions[idx + 3];

	// Check: LEA reg, [rip + X] where X resolves to image base
	if (lea_inst.zyinstr.info.mnemonic != ZYDIS_MNEMONIC_LEA) return 0;
	auto& lea_ops = lea_inst.zyinstr.operands;
	if (lea_ops[1].type != ZYDIS_OPERAND_TYPE_MEMORY) return 0;
	if (lea_ops[1].mem.base != ZYDIS_REGISTER_RIP) return 0;

	uint64_t resolved = lea_inst.runtime_address + lea_inst.zyinstr.info.length + lea_ops[1].mem.disp.value;
	if (resolved != buffer_base) return 0;

	auto base_reg = lea_ops[0].reg.value;

	// Check: MOVSXD reg, dword [base_reg + idx_reg*4 + disp]
	auto movsxd_mn = movsxd_inst.zyinstr.info.mnemonic;
	if (movsxd_mn != ZYDIS_MNEMONIC_MOVSXD && movsxd_mn != ZYDIS_MNEMONIC_MOV) return 0;
	auto& mx_ops = movsxd_inst.zyinstr.operands;
	if (mx_ops[1].type != ZYDIS_OPERAND_TYPE_MEMORY) return 0;
	if (mx_ops[1].mem.base != base_reg) return 0;
	if (mx_ops[1].mem.scale != 4) return 0;
	auto idx_reg = mx_ops[1].mem.index;
	auto off_reg = mx_ops[0].reg.value;
	int64_t table_disp = mx_ops[1].mem.disp.value;

	// Check: ADD off_reg, base_reg
	if (add_inst.zyinstr.info.mnemonic != ZYDIS_MNEMONIC_ADD) return 0;
	auto& add_ops = add_inst.zyinstr.operands;
	if (add_ops[0].reg.value != off_reg || add_ops[1].reg.value != base_reg) return 0;

	// Check: JMP off_reg
	if (jmp_inst.zyinstr.info.mnemonic != ZYDIS_MNEMONIC_JMP) return 0;
	if (jmp_inst.zyinstr.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER) return 0;
	if (jmp_inst.zyinstr.operands[0].reg.value != off_reg) return 0;

	// Look back for CMP + JA bounds check
	uint32_t case_count = 0;
	uint64_t default_target = 0;
	bool has_bounds_check = false;

	if (idx >= 2) {
		auto& cmp_inst = instructions[idx - 2];
		auto& ja_inst = instructions[idx - 1];
		if (cmp_inst.zyinstr.info.mnemonic == ZYDIS_MNEMONIC_CMP &&
			(ja_inst.zyinstr.info.mnemonic == ZYDIS_MNEMONIC_JNBE || ja_inst.zyinstr.info.mnemonic == ZYDIS_MNEMONIC_JNB)) {
			auto& cmp_ops = cmp_inst.zyinstr.operands;
			if (cmp_ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
				case_count = static_cast<uint32_t>(cmp_ops[1].imm.value.u) + 1;
				default_target = ja_inst.runtime_address + ja_inst.zyinstr.info.length +
					static_cast<int64_t>(ja_inst.zyinstr.operands[0].imm.value.s);
				has_bounds_check = true;
			}
		}
	}

	// Read jump table entries from the binary
	uint32_t table_rva = static_cast<uint32_t>(table_disp);
	if (!has_bounds_check) {
		// Try to infer count: scan entries until we hit one outside the function
		uint64_t func_start = instructions.front().runtime_address;
		uint64_t func_end = instructions.back().runtime_address + instructions.back().zyinstr.info.length;
		for (uint32_t i = 0; i < 4096; i++) {
			uint32_t off = table_rva + i * 4;
			if (off + 4 > static_cast<uint32_t>(image_base)) break;
			int32_t entry = *reinterpret_cast<int32_t*>(
				reinterpret_cast<uint8_t*>(buffer_base) + off);
			uint64_t target_va = buffer_base + entry;
			if (target_va < func_start || target_va >= func_end) {
				case_count = i;
				break;
			}
		}
		if (case_count == 0) return 0;
	}

	// Map index register to VM register
	uint8_t vreg_idx, sz_idx;
	if (!map_register(idx_reg, vreg_idx, sz_idx)) return 0;

	// Emit CMP + JZ chain for each case
	for (uint32_t i = 0; i < case_count; i++) {
		uint32_t off = table_rva + i * 4;
		int32_t entry_rva = *reinterpret_cast<int32_t*>(
			reinterpret_cast<uint8_t*>(buffer_base) + off);
		uint64_t target_x86 = buffer_base + entry_rva;

		emit_u16(bc, table.encode_random(vm_op::VM_CMP_REG_IMM, junk_rng));
		emit_byte(bc, vreg_idx);
		emit_i32(bc, static_cast<int32_t>(i));
		emit_byte(bc, 4); // size = dword (switch index is 32-bit)

		emit_u16(bc, table.encode_random(vm_op::VM_JZ, junk_rng));
		patches.push_back({ static_cast<uint32_t>(bc.size()), target_x86 });
		emit_i32(bc, 0); // placeholder, patched later
	}

	// Default: JMP to default target (or fall through)
	if (has_bounds_check && default_target) {
		emit_u16(bc, table.encode_random(vm_op::VM_JMP, junk_rng));
		patches.push_back({ static_cast<uint32_t>(bc.size()), default_target });
		emit_i32(bc, 0);
	}

	return 4; // consumed 4 instructions (lea + movsxd + add + jmp)
}

// === SSE TRANSLATOR IMPLEMENTATIONS ===

bool vm_translator::map_xmm_register(ZydisRegister reg, uint8_t& out_xmm_idx) {
	if (reg >= ZYDIS_REGISTER_XMM0 && reg <= ZYDIS_REGISTER_XMM15) {
		out_xmm_idx = static_cast<uint8_t>(reg - ZYDIS_REGISTER_XMM0);
		return true;
	}
	return false;
}

// Helper: if `mem_op` is RIP-relative, emit PUSH+MOV_IMM64+RELOCATE for a scratch
// vreg holding the runtime absolute address. Caller then uses `out_base` as the
// base register (with disp=0) and must call rip_relative_pop afterwards.
// Returns true if RIP-relative setup was emitted (caller uses disp=0), false if
// not RIP-relative (caller uses normal mapping).
bool vm_translator::rip_relative_setup(const ZydisDecodedOperand& mem_op,
	const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc, uint8_t& out_base) {
	if (mem_op.mem.base != ZYDIS_REGISTER_RIP) return false;

	// RVA in the image = abs_target_in_buffer - buffer_base
	uint64_t target_rva = inst.location_of_data - buffer_base;
	out_base = table.gp_perm[15]; // permuted index for VR15 (safe scratch — push/pop saves original)

	emit_u16(bc, table.encode_random(vm_op::VM_PUSH_REG, junk_rng));
	emit_byte(bc, out_base);

	emit_u16(bc, table.encode_random(vm_op::VM_MOV_REG_IMM64, junk_rng));
	emit_byte(bc, out_base);
	emit_u64(bc, target_rva ^ imm_xor_key);

	// RELOCATE_REG adds R14 (runtime image base) → out_base now holds runtime abs addr
	emit_u16(bc, table.encode_random(vm_op::VM_RELOCATE_REG, junk_rng));
	emit_byte(bc, out_base);
	return true;
}

void vm_translator::rip_relative_pop(uint8_t base, std::vector<uint8_t>& bc) {
	emit_u16(bc, table.encode_random(vm_op::VM_POP_REG, junk_rng));
	emit_byte(bc, base);
}

bool vm_translator::translate_sse_mov(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& ops = inst.zyinstr.operands;
	auto mn = inst.zyinstr.info.mnemonic;

	vm_op rr_op, rm_op, mr_op;
	switch (mn) {
	case ZYDIS_MNEMONIC_MOVSS:  rr_op = vm_op::VM_MOVSS_REG_REG; rm_op = vm_op::VM_MOVSS_REG_MEM; mr_op = vm_op::VM_MOVSS_MEM_REG; break;
	case ZYDIS_MNEMONIC_MOVSD:  rr_op = vm_op::VM_MOVSD_REG_REG; rm_op = vm_op::VM_MOVSD_REG_MEM; mr_op = vm_op::VM_MOVSD_MEM_REG; break;
	case ZYDIS_MNEMONIC_MOVAPS: rr_op = vm_op::VM_MOVAPS_REG_REG; rm_op = vm_op::VM_MOVAPS_REG_MEM; mr_op = vm_op::VM_MOVAPS_MEM_REG; break;
	case ZYDIS_MNEMONIC_MOVUPS: rr_op = vm_op::VM_MOVAPS_REG_REG; rm_op = vm_op::VM_MOVUPS_REG_MEM; mr_op = vm_op::VM_MOVUPS_MEM_REG; break;
	case ZYDIS_MNEMONIC_MOVDQA: rr_op = vm_op::VM_MOVDQA_REG_REG; rm_op = vm_op::VM_MOVDQA_REG_MEM; mr_op = vm_op::VM_MOVDQA_MEM_REG; break;
	case ZYDIS_MNEMONIC_MOVDQU: rr_op = vm_op::VM_MOVDQA_REG_REG; rm_op = vm_op::VM_MOVDQU_REG_MEM; mr_op = vm_op::VM_MOVDQU_MEM_REG; break;
	default: return false;
	}

	if (ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
		uint8_t dst, src;
		if (!map_xmm_register(ops[0].reg.value, dst) || !map_xmm_register(ops[1].reg.value, src)) return false;
		emit_u16(bc, table.encode_random(rr_op, junk_rng));
		emit_byte(bc, dst);
		emit_byte(bc, src);
	} else if (ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
		uint8_t dst;
		if (!map_xmm_register(ops[0].reg.value, dst)) return false;
		uint8_t base_vreg, sz;
		uint8_t rip_scratch;
		bool rip_rel = rip_relative_setup(ops[1], inst, bc, rip_scratch);
		if (rip_rel) {
			base_vreg = rip_scratch;
		} else if (!map_register(ops[1].mem.base, base_vreg, sz)) {
			return false;
		}
		emit_u16(bc, table.encode_random(rm_op, junk_rng));
		emit_byte(bc, dst);
		emit_byte(bc, base_vreg);
		emit_i32(bc, rip_rel ? 0 : static_cast<int32_t>(ops[1].mem.disp.value));
		if (rip_rel) rip_relative_pop(rip_scratch, bc);
	} else if (ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY && ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
		uint8_t src;
		if (!map_xmm_register(ops[1].reg.value, src)) return false;
		uint8_t base_vreg, sz;
		uint8_t rip_scratch;
		bool rip_rel = rip_relative_setup(ops[0], inst, bc, rip_scratch);
		if (rip_rel) {
			base_vreg = rip_scratch;
		} else if (!map_register(ops[0].mem.base, base_vreg, sz)) {
			return false;
		}
		emit_u16(bc, table.encode_random(mr_op, junk_rng));
		emit_byte(bc, base_vreg);
		emit_i32(bc, rip_rel ? 0 : static_cast<int32_t>(ops[0].mem.disp.value));
		emit_byte(bc, src);
		if (rip_rel) rip_relative_pop(rip_scratch, bc);
	} else return false;
	return true;
}

bool vm_translator::translate_sse_arith(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& ops = inst.zyinstr.operands;
	auto mn = inst.zyinstr.info.mnemonic;

	vm_op rr_op, rm_op;
	switch (mn) {
	case ZYDIS_MNEMONIC_ADDSS: rr_op = vm_op::VM_ADDSS_REG_REG; rm_op = vm_op::VM_ADDSS_REG_MEM; break;
	case ZYDIS_MNEMONIC_ADDSD: rr_op = vm_op::VM_ADDSD_REG_REG; rm_op = vm_op::VM_ADDSD_REG_MEM; break;
	case ZYDIS_MNEMONIC_SUBSS: rr_op = vm_op::VM_SUBSS_REG_REG; rm_op = vm_op::VM_SUBSS_REG_MEM; break;
	case ZYDIS_MNEMONIC_SUBSD: rr_op = vm_op::VM_SUBSD_REG_REG; rm_op = vm_op::VM_SUBSD_REG_MEM; break;
	case ZYDIS_MNEMONIC_MULSS: rr_op = vm_op::VM_MULSS_REG_REG; rm_op = vm_op::VM_MULSS_REG_MEM; break;
	case ZYDIS_MNEMONIC_MULSD: rr_op = vm_op::VM_MULSD_REG_REG; rm_op = vm_op::VM_MULSD_REG_MEM; break;
	case ZYDIS_MNEMONIC_DIVSS: rr_op = vm_op::VM_DIVSS_REG_REG; rm_op = vm_op::VM_DIVSS_REG_MEM; break;
	case ZYDIS_MNEMONIC_DIVSD: rr_op = vm_op::VM_DIVSD_REG_REG; rm_op = vm_op::VM_DIVSD_REG_MEM; break;
	default: return false;
	}

	uint8_t dst;
	if (!map_xmm_register(ops[0].reg.value, dst)) return false;

	if (ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
		uint8_t src;
		if (!map_xmm_register(ops[1].reg.value, src)) return false;
		emit_u16(bc, table.encode_random(rr_op, junk_rng));
		emit_byte(bc, dst);
		emit_byte(bc, src);
	} else {
		uint8_t base_vreg, sz;
		if (!map_register(ops[1].mem.base, base_vreg, sz)) return false;
		emit_u16(bc, table.encode_random(rm_op, junk_rng));
		emit_byte(bc, dst);
		emit_byte(bc, base_vreg);
		emit_i32(bc, static_cast<int32_t>(ops[1].mem.disp.value));
	}
	return true;
}

bool vm_translator::translate_sse_cmp(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& ops = inst.zyinstr.operands;
	auto mn = inst.zyinstr.info.mnemonic;

	vm_op rr_op, rm_op;
	switch (mn) {
	case ZYDIS_MNEMONIC_COMISS:  rr_op = vm_op::VM_COMISS_REG_REG;  rm_op = vm_op::VM_COMISS_REG_MEM; break;
	case ZYDIS_MNEMONIC_COMISD:  rr_op = vm_op::VM_COMISD_REG_REG;  rm_op = vm_op::VM_COMISD_REG_MEM; break;
	case ZYDIS_MNEMONIC_UCOMISS: rr_op = vm_op::VM_UCOMISS_REG_REG; rm_op = vm_op::VM_UCOMISS_REG_MEM; break;
	case ZYDIS_MNEMONIC_UCOMISD: rr_op = vm_op::VM_UCOMISD_REG_REG; rm_op = vm_op::VM_UCOMISD_REG_MEM; break;
	default: return false;
	}

	uint8_t dst;
	if (!map_xmm_register(ops[0].reg.value, dst)) return false;

	if (ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
		uint8_t src;
		if (!map_xmm_register(ops[1].reg.value, src)) return false;
		emit_u16(bc, table.encode_random(rr_op, junk_rng));
		emit_byte(bc, dst);
		emit_byte(bc, src);
	} else {
		uint8_t base_vreg, sz;
		if (!map_register(ops[1].mem.base, base_vreg, sz)) return false;
		emit_u16(bc, table.encode_random(rm_op, junk_rng));
		emit_byte(bc, dst);
		emit_byte(bc, base_vreg);
		emit_i32(bc, static_cast<int32_t>(ops[1].mem.disp.value));
	}
	return true;
}

bool vm_translator::translate_sse_cvt(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& ops = inst.zyinstr.operands;
	auto mn = inst.zyinstr.info.mnemonic;

	bool to_gp = (mn == ZYDIS_MNEMONIC_CVTSS2SI || mn == ZYDIS_MNEMONIC_CVTSD2SI ||
		mn == ZYDIS_MNEMONIC_CVTTSS2SI || mn == ZYDIS_MNEMONIC_CVTTSD2SI);
	bool from_gp = (mn == ZYDIS_MNEMONIC_CVTSI2SS || mn == ZYDIS_MNEMONIC_CVTSI2SD);

	if (to_gp) {
		vm_op op;
		switch (mn) {
		case ZYDIS_MNEMONIC_CVTSS2SI:  op = vm_op::VM_CVTSS2SI_REG_REG; break;
		case ZYDIS_MNEMONIC_CVTSD2SI:  op = vm_op::VM_CVTSD2SI_REG_REG; break;
		case ZYDIS_MNEMONIC_CVTTSS2SI: op = vm_op::VM_CVTTSS2SI_REG_REG; break;
		case ZYDIS_MNEMONIC_CVTTSD2SI: op = vm_op::VM_CVTTSD2SI_REG_REG; break;
		default: return false;
		}
		uint8_t dst_gp, sz;
		if (!map_register(ops[0].reg.value, dst_gp, sz)) return false;
		uint8_t src_xmm;
		if (!map_xmm_register(ops[1].reg.value, src_xmm)) return false;
		emit_u16(bc, table.encode_random(op, junk_rng));
		emit_byte(bc, dst_gp);
		emit_byte(bc, src_xmm);
	} else if (from_gp) {
		vm_op rr_op = (mn == ZYDIS_MNEMONIC_CVTSI2SS) ? vm_op::VM_CVTSI2SS_REG_REG : vm_op::VM_CVTSI2SD_REG_REG;
		vm_op rm_op = (mn == ZYDIS_MNEMONIC_CVTSI2SS) ? vm_op::VM_CVTSI2SS_REG_MEM : vm_op::VM_CVTSI2SD_REG_MEM;
		uint8_t dst_xmm;
		if (!map_xmm_register(ops[0].reg.value, dst_xmm)) return false;
		if (ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
			uint8_t src_gp, sz;
			if (!map_register(ops[1].reg.value, src_gp, sz)) return false;
			emit_u16(bc, table.encode_random(rr_op, junk_rng));
			emit_byte(bc, dst_xmm);
			emit_byte(bc, src_gp);
		} else {
			uint8_t base_vreg, sz;
			if (!map_register(ops[1].mem.base, base_vreg, sz)) return false;
			emit_u16(bc, table.encode_random(rm_op, junk_rng));
			emit_byte(bc, dst_xmm);
			emit_byte(bc, base_vreg);
			emit_i32(bc, static_cast<int32_t>(ops[1].mem.disp.value));
		}
	} else {
		// xmm->xmm: cvtss2sd, cvtsd2ss
		vm_op rr_op, rm_op;
		switch (mn) {
		case ZYDIS_MNEMONIC_CVTSS2SD: rr_op = vm_op::VM_CVTSS2SD_REG_REG; rm_op = vm_op::VM_CVTSS2SD_REG_MEM; break;
		case ZYDIS_MNEMONIC_CVTSD2SS: rr_op = vm_op::VM_CVTSD2SS_REG_REG; rm_op = vm_op::VM_CVTSD2SS_REG_MEM; break;
		default: return false;
		}
		uint8_t dst;
		if (!map_xmm_register(ops[0].reg.value, dst)) return false;
		if (ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
			uint8_t src;
			if (!map_xmm_register(ops[1].reg.value, src)) return false;
			emit_u16(bc, table.encode_random(rr_op, junk_rng));
			emit_byte(bc, dst);
			emit_byte(bc, src);
		} else {
			uint8_t base_vreg, sz;
			if (!map_register(ops[1].mem.base, base_vreg, sz)) return false;
			emit_u16(bc, table.encode_random(rm_op, junk_rng));
			emit_byte(bc, dst);
			emit_byte(bc, base_vreg);
			emit_i32(bc, static_cast<int32_t>(ops[1].mem.disp.value));
		}
	}
	return true;
}

bool vm_translator::translate_sse_bitwise(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& ops = inst.zyinstr.operands;
	vm_op rr_op, rm_op;
	switch (inst.zyinstr.info.mnemonic) {
	case ZYDIS_MNEMONIC_XORPS:  rr_op = vm_op::VM_XORPS_REG_REG;  rm_op = vm_op::VM_XORPS_REG_MEM; break;
	case ZYDIS_MNEMONIC_XORPD:  rr_op = vm_op::VM_XORPD_REG_REG;  rm_op = vm_op::VM_XORPD_REG_MEM; break;
	case ZYDIS_MNEMONIC_ANDPS:  rr_op = vm_op::VM_ANDPS_REG_REG;  rm_op = vm_op::VM_ANDPS_REG_MEM; break;
	case ZYDIS_MNEMONIC_ANDPD:  rr_op = vm_op::VM_ANDPD_REG_REG;  rm_op = vm_op::VM_ANDPD_REG_MEM; break;
	case ZYDIS_MNEMONIC_ORPS:   rr_op = vm_op::VM_ORPS_REG_REG;   rm_op = vm_op::VM_ORPS_REG_MEM; break;
	case ZYDIS_MNEMONIC_ORPD:   rr_op = vm_op::VM_ORPD_REG_REG;   rm_op = vm_op::VM_ORPD_REG_MEM; break;
	case ZYDIS_MNEMONIC_ANDNPS: rr_op = vm_op::VM_ANDNPS_REG_REG; rm_op = vm_op::VM_ANDNPS_REG_MEM; break;
	case ZYDIS_MNEMONIC_ANDNPD: rr_op = vm_op::VM_ANDNPD_REG_REG; rm_op = vm_op::VM_ANDNPD_REG_MEM; break;
	default: return false;
	}
	uint8_t dst;
	if (!map_xmm_register(ops[0].reg.value, dst)) return false;
	if (ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
		uint8_t src;
		if (!map_xmm_register(ops[1].reg.value, src)) return false;
		emit_u16(bc, table.encode_random(rr_op, junk_rng));
		emit_byte(bc, dst);
		emit_byte(bc, src);
	} else {
		uint8_t base_vreg, sz;
		if (!map_register(ops[1].mem.base, base_vreg, sz)) return false;
		emit_u16(bc, table.encode_random(rm_op, junk_rng));
		emit_byte(bc, dst);
		emit_byte(bc, base_vreg);
		emit_i32(bc, static_cast<int32_t>(ops[1].mem.disp.value));
	}
	return true;
}

bool vm_translator::translate_sse_packed_arith(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& ops = inst.zyinstr.operands;
	vm_op rr_op, rm_op;
	switch (inst.zyinstr.info.mnemonic) {
	case ZYDIS_MNEMONIC_ADDPS: rr_op = vm_op::VM_ADDPS_REG_REG; rm_op = vm_op::VM_ADDPS_REG_MEM; break;
	case ZYDIS_MNEMONIC_ADDPD: rr_op = vm_op::VM_ADDPD_REG_REG; rm_op = vm_op::VM_ADDPD_REG_MEM; break;
	case ZYDIS_MNEMONIC_SUBPS: rr_op = vm_op::VM_SUBPS_REG_REG; rm_op = vm_op::VM_SUBPS_REG_MEM; break;
	case ZYDIS_MNEMONIC_SUBPD: rr_op = vm_op::VM_SUBPD_REG_REG; rm_op = vm_op::VM_SUBPD_REG_MEM; break;
	case ZYDIS_MNEMONIC_MULPS: rr_op = vm_op::VM_MULPS_REG_REG; rm_op = vm_op::VM_MULPS_REG_MEM; break;
	case ZYDIS_MNEMONIC_MULPD: rr_op = vm_op::VM_MULPD_REG_REG; rm_op = vm_op::VM_MULPD_REG_MEM; break;
	case ZYDIS_MNEMONIC_DIVPS: rr_op = vm_op::VM_DIVPS_REG_REG; rm_op = vm_op::VM_DIVPS_REG_MEM; break;
	case ZYDIS_MNEMONIC_DIVPD: rr_op = vm_op::VM_DIVPD_REG_REG; rm_op = vm_op::VM_DIVPD_REG_MEM; break;
	default: return false;
	}
	uint8_t dst;
	if (!map_xmm_register(ops[0].reg.value, dst)) return false;
	if (ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
		uint8_t src;
		if (!map_xmm_register(ops[1].reg.value, src)) return false;
		emit_u16(bc, table.encode_random(rr_op, junk_rng));
		emit_byte(bc, dst);
		emit_byte(bc, src);
	} else {
		uint8_t base_vreg, sz;
		if (!map_register(ops[1].mem.base, base_vreg, sz)) return false;
		emit_u16(bc, table.encode_random(rm_op, junk_rng));
		emit_byte(bc, dst);
		emit_byte(bc, base_vreg);
		emit_i32(bc, static_cast<int32_t>(ops[1].mem.disp.value));
	}
	return true;
}

bool vm_translator::translate_sse_minmax_sqrt(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& ops = inst.zyinstr.operands;
	vm_op op;
	switch (inst.zyinstr.info.mnemonic) {
	case ZYDIS_MNEMONIC_MINSS:  op = vm_op::VM_MINSS_REG_REG; break;
	case ZYDIS_MNEMONIC_MAXSS:  op = vm_op::VM_MAXSS_REG_REG; break;
	case ZYDIS_MNEMONIC_MINSD:  op = vm_op::VM_MINSD_REG_REG; break;
	case ZYDIS_MNEMONIC_MAXSD:  op = vm_op::VM_MAXSD_REG_REG; break;
	case ZYDIS_MNEMONIC_SQRTSS: op = vm_op::VM_SQRTSS_REG_REG; break;
	case ZYDIS_MNEMONIC_SQRTSD: op = vm_op::VM_SQRTSD_REG_REG; break;
	default: return false;
	}
	uint8_t dst, src;
	if (!map_xmm_register(ops[0].reg.value, dst)) return false;
	if (!map_xmm_register(ops[1].reg.value, src)) return false;
	emit_u16(bc, table.encode_random(op, junk_rng));
	emit_byte(bc, dst);
	emit_byte(bc, src);
	return true;
}

bool vm_translator::translate_sse_shuffle(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& ops = inst.zyinstr.operands;
	vm_op op;
	bool has_imm = false;
	switch (inst.zyinstr.info.mnemonic) {
	case ZYDIS_MNEMONIC_SHUFPS:   op = vm_op::VM_SHUFPS_REG_REG_IMM; has_imm = true; break;
	case ZYDIS_MNEMONIC_SHUFPD:   op = vm_op::VM_SHUFPD_REG_REG_IMM; has_imm = true; break;
	case ZYDIS_MNEMONIC_UNPCKLPS: op = vm_op::VM_UNPCKLPS_REG_REG; break;
	case ZYDIS_MNEMONIC_UNPCKHPS: op = vm_op::VM_UNPCKHPS_REG_REG; break;
	case ZYDIS_MNEMONIC_UNPCKLPD: op = vm_op::VM_UNPCKLPD_REG_REG; break;
	case ZYDIS_MNEMONIC_UNPCKHPD: op = vm_op::VM_UNPCKHPD_REG_REG; break;
	default: return false;
	}
	uint8_t dst, src;
	if (!map_xmm_register(ops[0].reg.value, dst)) return false;
	if (!map_xmm_register(ops[1].reg.value, src)) return false;
	emit_u16(bc, table.encode_random(op, junk_rng));
	emit_byte(bc, dst);
	emit_byte(bc, src);
	if (has_imm) emit_byte(bc, static_cast<uint8_t>(ops[2].imm.value.u));
	return true;
}

bool vm_translator::translate_sse_int(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& ops = inst.zyinstr.operands;
	vm_op op;
	switch (inst.zyinstr.info.mnemonic) {
	case ZYDIS_MNEMONIC_PXOR:       op = vm_op::VM_PXOR_REG_REG; break;
	case ZYDIS_MNEMONIC_PAND:       op = vm_op::VM_PAND_REG_REG; break;
	case ZYDIS_MNEMONIC_POR:        op = vm_op::VM_POR_REG_REG; break;
	case ZYDIS_MNEMONIC_PANDN:      op = vm_op::VM_PANDN_REG_REG; break;
	case ZYDIS_MNEMONIC_PCMPEQB:    op = vm_op::VM_PCMPEQB_REG_REG; break;
	case ZYDIS_MNEMONIC_PCMPEQD:    op = vm_op::VM_PCMPEQD_REG_REG; break;
	case ZYDIS_MNEMONIC_PCMPGTB:    op = vm_op::VM_PCMPGTB_REG_REG; break;
	case ZYDIS_MNEMONIC_PADDB:      op = vm_op::VM_PADDB_REG_REG; break;
	case ZYDIS_MNEMONIC_PADDW:      op = vm_op::VM_PADDW_REG_REG; break;
	case ZYDIS_MNEMONIC_PADDD:      op = vm_op::VM_PADDD_REG_REG; break;
	case ZYDIS_MNEMONIC_PADDQ:      op = vm_op::VM_PADDQ_REG_REG; break;
	case ZYDIS_MNEMONIC_PSUBB:      op = vm_op::VM_PSUBB_REG_REG; break;
	case ZYDIS_MNEMONIC_PSUBW:      op = vm_op::VM_PSUBW_REG_REG; break;
	case ZYDIS_MNEMONIC_PSUBD:      op = vm_op::VM_PSUBD_REG_REG; break;
	case ZYDIS_MNEMONIC_PSUBQ:      op = vm_op::VM_PSUBQ_REG_REG; break;
	case ZYDIS_MNEMONIC_PUNPCKLBW:  op = vm_op::VM_PUNPCKLBW_REG_REG; break;
	case ZYDIS_MNEMONIC_PUNPCKHBW:  op = vm_op::VM_PUNPCKHBW_REG_REG; break;
	case ZYDIS_MNEMONIC_PUNPCKLDQ:  op = vm_op::VM_PUNPCKLDQ_REG_REG; break;
	case ZYDIS_MNEMONIC_PUNPCKHDQ:  op = vm_op::VM_PUNPCKHDQ_REG_REG; break;
	case ZYDIS_MNEMONIC_PUNPCKLQDQ: op = vm_op::VM_PUNPCKLQDQ_REG_REG; break;
	case ZYDIS_MNEMONIC_PUNPCKHQDQ: op = vm_op::VM_PUNPCKHQDQ_REG_REG; break;
	case ZYDIS_MNEMONIC_PSHUFB:     op = vm_op::VM_PSHUFB_REG_REG; break;
	case ZYDIS_MNEMONIC_PMAXSB:     op = vm_op::VM_PMAXSB_REG_REG; break;
	case ZYDIS_MNEMONIC_PMAXSD:     op = vm_op::VM_PMAXSD_REG_REG; break;
	case ZYDIS_MNEMONIC_PMINSB:     op = vm_op::VM_PMINSB_REG_REG; break;
	case ZYDIS_MNEMONIC_PMINSD:     op = vm_op::VM_PMINSD_REG_REG; break;
	default: return false;
	}
	uint8_t dst, src;
	if (!map_xmm_register(ops[0].reg.value, dst)) return false;
	if (!map_xmm_register(ops[1].reg.value, src)) return false;
	emit_u16(bc, table.encode_random(op, junk_rng));
	emit_byte(bc, dst);
	emit_byte(bc, src);
	return true;
}

bool vm_translator::translate_pmovmskb(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& ops = inst.zyinstr.operands;
	uint8_t dst_gp, sz;
	if (!map_register(ops[0].reg.value, dst_gp, sz)) return false;
	uint8_t src_xmm;
	if (!map_xmm_register(ops[1].reg.value, src_xmm)) return false;
	emit_u16(bc, table.encode_random(vm_op::VM_PMOVMSKB_REG_REG, junk_rng));
	emit_byte(bc, dst_gp);
	emit_byte(bc, src_xmm);
	return true;
}

bool vm_translator::translate_sse_shift_imm(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& ops = inst.zyinstr.operands;
	vm_op op;
	switch (inst.zyinstr.info.mnemonic) {
	case ZYDIS_MNEMONIC_PSLLW: op = vm_op::VM_PSLLW_REG_IMM; break;
	case ZYDIS_MNEMONIC_PSLLD: op = vm_op::VM_PSLLD_REG_IMM; break;
	case ZYDIS_MNEMONIC_PSLLQ: op = vm_op::VM_PSLLQ_REG_IMM; break;
	case ZYDIS_MNEMONIC_PSRLW: op = vm_op::VM_PSRLW_REG_IMM; break;
	case ZYDIS_MNEMONIC_PSRLD: op = vm_op::VM_PSRLD_REG_IMM; break;
	case ZYDIS_MNEMONIC_PSRLQ: op = vm_op::VM_PSRLQ_REG_IMM; break;
	case ZYDIS_MNEMONIC_PSRAW: op = vm_op::VM_PSRAW_REG_IMM; break;
	case ZYDIS_MNEMONIC_PSRAD: op = vm_op::VM_PSRAD_REG_IMM; break;
	default: return false;
	}
	uint8_t xmm;
	if (!map_xmm_register(ops[0].reg.value, xmm)) return false;
	emit_u16(bc, table.encode_random(op, junk_rng));
	emit_byte(bc, xmm);
	emit_byte(bc, static_cast<uint8_t>(ops[1].imm.value.u));
	return true;
}

bool vm_translator::translate_pshufd(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& ops = inst.zyinstr.operands;
	uint8_t dst, src;
	if (!map_xmm_register(ops[0].reg.value, dst)) return false;
	if (!map_xmm_register(ops[1].reg.value, src)) return false;
	emit_u16(bc, table.encode_random(vm_op::VM_PSHUFD_REG_REG_IMM, junk_rng));
	emit_byte(bc, dst);
	emit_byte(bc, src);
	emit_byte(bc, static_cast<uint8_t>(ops[2].imm.value.u));
	return true;
}

bool vm_translator::translate_movd_movq(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& ops = inst.zyinstr.operands;
	bool is_movq = (inst.zyinstr.info.mnemonic == ZYDIS_MNEMONIC_MOVQ);

	if (ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
		uint8_t xmm0_idx, xmm1_idx;
		bool op0_xmm = map_xmm_register(ops[0].reg.value, xmm0_idx);
		bool op1_xmm = map_xmm_register(ops[1].reg.value, xmm1_idx);

		if (op0_xmm && op1_xmm) {
			emit_u16(bc, table.encode_random(vm_op::VM_MOVQ_XMM_XMM, junk_rng));
			emit_byte(bc, xmm0_idx);
			emit_byte(bc, xmm1_idx);
		} else if (op0_xmm) {
			uint8_t gp, sz;
			if (!map_register(ops[1].reg.value, gp, sz)) return false;
			emit_u16(bc, table.encode_random(is_movq ? vm_op::VM_MOVQ_XMM_REG : vm_op::VM_MOVD_XMM_REG, junk_rng));
			emit_byte(bc, xmm0_idx);
			emit_byte(bc, gp);
		} else if (op1_xmm) {
			uint8_t gp, sz;
			if (!map_register(ops[0].reg.value, gp, sz)) return false;
			emit_u16(bc, table.encode_random(is_movq ? vm_op::VM_MOVQ_REG_XMM : vm_op::VM_MOVD_REG_XMM, junk_rng));
			emit_byte(bc, gp);
			emit_byte(bc, xmm1_idx);
		} else return false;
	} else if (ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
		uint8_t xmm;
		if (!map_xmm_register(ops[0].reg.value, xmm)) return false;
		uint8_t base_vreg, sz;
		if (!map_register(ops[1].mem.base, base_vreg, sz)) return false;
		emit_u16(bc, table.encode_random(is_movq ? vm_op::VM_MOVQ_XMM_MEM : vm_op::VM_MOVD_XMM_MEM, junk_rng));
		emit_byte(bc, xmm);
		emit_byte(bc, base_vreg);
		emit_i32(bc, static_cast<int32_t>(ops[1].mem.disp.value));
	} else if (ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY && ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
		uint8_t xmm;
		if (!map_xmm_register(ops[1].reg.value, xmm)) return false;
		uint8_t base_vreg, sz;
		if (!map_register(ops[0].mem.base, base_vreg, sz)) return false;
		emit_u16(bc, table.encode_random(is_movq ? vm_op::VM_MOVQ_MEM_XMM : vm_op::VM_MOVD_MEM_XMM, junk_rng));
		emit_byte(bc, xmm);
		emit_byte(bc, base_vreg);
		emit_i32(bc, static_cast<int32_t>(ops[0].mem.disp.value));
	} else return false;
	return true;
}

bool vm_translator::translate_pinsr_pextr(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& ops = inst.zyinstr.operands;
	vm_op op;
	switch (inst.zyinstr.info.mnemonic) {
	case ZYDIS_MNEMONIC_PINSRB: op = vm_op::VM_PINSRB_REG_REG_IMM; break;
	case ZYDIS_MNEMONIC_PINSRD: op = vm_op::VM_PINSRD_REG_REG_IMM; break;
	case ZYDIS_MNEMONIC_PINSRQ: op = vm_op::VM_PINSRQ_REG_REG_IMM; break;
	case ZYDIS_MNEMONIC_PEXTRB: op = vm_op::VM_PEXTRB_REG_REG_IMM; break;
	case ZYDIS_MNEMONIC_PEXTRD: op = vm_op::VM_PEXTRD_REG_REG_IMM; break;
	case ZYDIS_MNEMONIC_PEXTRQ: op = vm_op::VM_PEXTRQ_REG_REG_IMM; break;
	default: return false;
	}
	bool is_insert = (op == vm_op::VM_PINSRB_REG_REG_IMM || op == vm_op::VM_PINSRD_REG_REG_IMM || op == vm_op::VM_PINSRQ_REG_REG_IMM);
	if (is_insert) {
		uint8_t xmm;
		if (!map_xmm_register(ops[0].reg.value, xmm)) return false;
		uint8_t gp, sz;
		if (!map_register(ops[1].reg.value, gp, sz)) return false;
		emit_u16(bc, table.encode_random(op, junk_rng));
		emit_byte(bc, xmm);
		emit_byte(bc, gp);
		emit_byte(bc, static_cast<uint8_t>(ops[2].imm.value.u));
	} else {
		uint8_t gp, sz;
		if (!map_register(ops[0].reg.value, gp, sz)) return false;
		uint8_t xmm;
		if (!map_xmm_register(ops[1].reg.value, xmm)) return false;
		emit_u16(bc, table.encode_random(op, junk_rng));
		emit_byte(bc, gp);
		emit_byte(bc, xmm);
		emit_byte(bc, static_cast<uint8_t>(ops[2].imm.value.u));
	}
	return true;
}

bool vm_translator::translate_roundss_sd(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& ops = inst.zyinstr.operands;
	vm_op op = (inst.zyinstr.info.mnemonic == ZYDIS_MNEMONIC_ROUNDSS) ?
		vm_op::VM_ROUNDSS_REG_REG_IMM : vm_op::VM_ROUNDSD_REG_REG_IMM;
	uint8_t dst, src;
	if (!map_xmm_register(ops[0].reg.value, dst)) return false;
	if (!map_xmm_register(ops[1].reg.value, src)) return false;
	emit_u16(bc, table.encode_random(op, junk_rng));
	emit_byte(bc, dst);
	emit_byte(bc, src);
	emit_byte(bc, static_cast<uint8_t>(ops[2].imm.value.u));
	return true;
}

bool vm_translator::translate_ptest(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& ops = inst.zyinstr.operands;
	uint8_t dst, src;
	if (!map_xmm_register(ops[0].reg.value, dst)) return false;
	if (!map_xmm_register(ops[1].reg.value, src)) return false;
	emit_u16(bc, table.encode_random(vm_op::VM_PTEST_REG_REG, junk_rng));
	emit_byte(bc, dst);
	emit_byte(bc, src);
	return true;
}

bool vm_translator::translate_sse_movhilo(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& ops = inst.zyinstr.operands;
	auto mn = inst.zyinstr.info.mnemonic;

	if (mn == ZYDIS_MNEMONIC_MOVHLPS || mn == ZYDIS_MNEMONIC_MOVLHPS) {
		uint8_t dst, src;
		if (!map_xmm_register(ops[0].reg.value, dst)) return false;
		if (!map_xmm_register(ops[1].reg.value, src)) return false;
		emit_u16(bc, table.encode_random(mn == ZYDIS_MNEMONIC_MOVHLPS ? vm_op::VM_MOVHLPS_REG_REG : vm_op::VM_MOVLHPS_REG_REG, junk_rng));
		emit_byte(bc, dst);
		emit_byte(bc, src);
	} else if (ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
		uint8_t xmm;
		if (!map_xmm_register(ops[0].reg.value, xmm)) return false;
		uint8_t base_vreg, sz;
		if (!map_register(ops[1].mem.base, base_vreg, sz)) return false;
		vm_op op;
		switch (mn) {
		case ZYDIS_MNEMONIC_MOVHPS: op = vm_op::VM_MOVHPS_REG_MEM; break;
		case ZYDIS_MNEMONIC_MOVLPS: op = vm_op::VM_MOVLPS_REG_MEM; break;
		case ZYDIS_MNEMONIC_MOVHPD: op = vm_op::VM_MOVHPD_REG_MEM; break;
		case ZYDIS_MNEMONIC_MOVLPD: op = vm_op::VM_MOVLPD_REG_MEM; break;
		default: return false;
		}
		emit_u16(bc, table.encode_random(op, junk_rng));
		emit_byte(bc, xmm);
		emit_byte(bc, base_vreg);
		emit_i32(bc, static_cast<int32_t>(ops[1].mem.disp.value));
	} else {
		uint8_t xmm;
		if (!map_xmm_register(ops[1].reg.value, xmm)) return false;
		uint8_t base_vreg, sz;
		if (!map_register(ops[0].mem.base, base_vreg, sz)) return false;
		vm_op op;
		switch (mn) {
		case ZYDIS_MNEMONIC_MOVHPS: op = vm_op::VM_MOVHPS_MEM_REG; break;
		case ZYDIS_MNEMONIC_MOVLPS: op = vm_op::VM_MOVLPS_MEM_REG; break;
		case ZYDIS_MNEMONIC_MOVHPD: op = vm_op::VM_MOVHPD_MEM_REG; break;
		case ZYDIS_MNEMONIC_MOVLPD: op = vm_op::VM_MOVLPD_MEM_REG; break;
		default: return false;
		}
		emit_u16(bc, table.encode_random(op, junk_rng));
		emit_byte(bc, base_vreg);
		emit_i32(bc, static_cast<int32_t>(ops[0].mem.disp.value));
		emit_byte(bc, xmm);
	}
	return true;
}

// === LOCK / ATOMIC ===

bool vm_translator::translate_cmpxchg(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& ops = inst.zyinstr.operands;
	uint8_t base_vreg, sz;
	if (!map_register(ops[0].mem.base, base_vreg, sz)) return false;
	uint8_t src_gp, sz2;
	if (!map_register(ops[1].reg.value, src_gp, sz2)) return false;
	emit_u16(bc, table.encode_random(vm_op::VM_CMPXCHG_MEM_REG, junk_rng));
	emit_byte(bc, base_vreg);
	emit_i32(bc, static_cast<int32_t>(ops[0].mem.disp.value));
	emit_byte(bc, src_gp);
	emit_byte(bc, sz2);
	return true;
}

bool vm_translator::translate_lock_op(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& ops = inst.zyinstr.operands;
	uint8_t base_vreg, sz;
	if (!map_register(ops[0].mem.base, base_vreg, sz)) return false;
	uint8_t src_gp, sz2;
	if (!map_register(ops[1].reg.value, src_gp, sz2)) return false;
	emit_u16(bc, table.encode_random(vm_op::VM_LOCK_XADD_MEM_REG, junk_rng));
	emit_byte(bc, base_vreg);
	emit_i32(bc, static_cast<int32_t>(ops[0].mem.disp.value));
	emit_byte(bc, src_gp);
	return true;
}

// === MISC ===

bool vm_translator::translate_cpuid(std::vector<uint8_t>& bc) {
	emit_u16(bc, table.encode_random(vm_op::VM_CPUID, junk_rng));
	return true;
}

bool vm_translator::translate_rdtsc(std::vector<uint8_t>& bc) {
	emit_u16(bc, table.encode_random(vm_op::VM_RDTSC, junk_rng));
	return true;
}

bool vm_translator::translate_fence(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	vm_op op;
	switch (inst.zyinstr.info.mnemonic) {
	case ZYDIS_MNEMONIC_PAUSE:  op = vm_op::VM_PAUSE; break;
	case ZYDIS_MNEMONIC_MFENCE: op = vm_op::VM_MFENCE; break;
	case ZYDIS_MNEMONIC_LFENCE: op = vm_op::VM_LFENCE; break;
	case ZYDIS_MNEMONIC_SFENCE: op = vm_op::VM_SFENCE; break;
	default: return false;
	}
	emit_u16(bc, table.encode_random(op, junk_rng));
	return true;
}

bool vm_translator::translate_flag_op(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	vm_op op;
	switch (inst.zyinstr.info.mnemonic) {
	case ZYDIS_MNEMONIC_CLC: op = vm_op::VM_CLC; break;
	case ZYDIS_MNEMONIC_STC: op = vm_op::VM_STC; break;
	case ZYDIS_MNEMONIC_CMC: op = vm_op::VM_CMC; break;
	default: return false;
	}
	emit_u16(bc, table.encode_random(op, junk_rng));
	return true;
}

bool vm_translator::translate_enter_frame(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& ops = inst.zyinstr.operands;
	emit_u16(bc, table.encode_random(vm_op::VM_ENTER_FRAME, junk_rng));
	emit_u16(bc, static_cast<uint16_t>(ops[0].imm.value.u));
	return true;
}

bool vm_translator::translate_movbe(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& ops = inst.zyinstr.operands;
	if (ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
		uint8_t dst, sz, base, bsz;
		if (!map_register(ops[0].reg.value, dst, sz)) return false;
		if (!map_register(ops[1].mem.base, base, bsz)) return false;
		emit_u16(bc, table.encode_random(vm_op::VM_MOVBE_REG_MEM, junk_rng));
		emit_byte(bc, dst);
		emit_byte(bc, base);
		emit_i32(bc, static_cast<int32_t>(ops[1].mem.disp.value));
	} else {
		uint8_t src, sz, base, bsz;
		if (!map_register(ops[1].reg.value, src, sz)) return false;
		if (!map_register(ops[0].mem.base, base, bsz)) return false;
		emit_u16(bc, table.encode_random(vm_op::VM_MOVBE_MEM_REG, junk_rng));
		emit_byte(bc, base);
		emit_byte(bc, src);
		emit_i32(bc, static_cast<int32_t>(ops[0].mem.disp.value));
	}
	return true;
}

bool vm_translator::translate_crc32(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& ops = inst.zyinstr.operands;
	uint8_t dst, sz, src, sz2;
	if (!map_register(ops[0].reg.value, dst, sz)) return false;
	if (!map_register(ops[1].reg.value, src, sz2)) return false;
	emit_u16(bc, table.encode_random(vm_op::VM_CRC32_REG_REG, junk_rng));
	emit_byte(bc, dst);
	emit_byte(bc, src);
	return true;
}

bool vm_translator::translate_bmi(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc) {
	auto& ops = inst.zyinstr.operands;
	auto mn = inst.zyinstr.info.mnemonic;

	bool is_two_op = (mn == ZYDIS_MNEMONIC_BLSI || mn == ZYDIS_MNEMONIC_BLSMSK || mn == ZYDIS_MNEMONIC_BLSR);
	vm_op op;
	switch (mn) {
	case ZYDIS_MNEMONIC_ANDN:   op = vm_op::VM_ANDN_REG_REG_REG; break;
	case ZYDIS_MNEMONIC_BEXTR:  op = vm_op::VM_BEXTR_REG_REG_REG; break;
	case ZYDIS_MNEMONIC_BLSI:   op = vm_op::VM_BLSI_REG_REG; break;
	case ZYDIS_MNEMONIC_BLSMSK: op = vm_op::VM_BLSMSK_REG_REG; break;
	case ZYDIS_MNEMONIC_BLSR:   op = vm_op::VM_BLSR_REG_REG; break;
	case ZYDIS_MNEMONIC_PDEP:   op = vm_op::VM_PDEP_REG_REG_REG; break;
	case ZYDIS_MNEMONIC_PEXT:   op = vm_op::VM_PEXT_REG_REG_REG; break;
	case ZYDIS_MNEMONIC_BZHI:   op = vm_op::VM_BZHI_REG_REG_REG; break;
	case ZYDIS_MNEMONIC_SARX:   op = vm_op::VM_SARX_REG_REG_REG; break;
	case ZYDIS_MNEMONIC_SHLX:   op = vm_op::VM_SHLX_REG_REG_REG; break;
	case ZYDIS_MNEMONIC_SHRX:   op = vm_op::VM_SHRX_REG_REG_REG; break;
	default: return false;
	}

	if (is_two_op) {
		uint8_t dst, sz, src, sz2;
		if (!map_register(ops[0].reg.value, dst, sz)) return false;
		if (!map_register(ops[1].reg.value, src, sz2)) return false;
		emit_u16(bc, table.encode_random(op, junk_rng));
		emit_byte(bc, dst);
		emit_byte(bc, src);
	} else {
		uint8_t dst, sz, src1, sz2, src2, sz3;
		if (!map_register(ops[0].reg.value, dst, sz)) return false;
		if (!map_register(ops[1].reg.value, src1, sz2)) return false;
		if (!map_register(ops[2].reg.value, src2, sz3)) return false;
		emit_u16(bc, table.encode_random(op, junk_rng));
		emit_byte(bc, dst);
		emit_byte(bc, src1);
		emit_byte(bc, src2);
	}
	return true;
}
