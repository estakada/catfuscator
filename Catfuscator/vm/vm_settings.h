#pragma once
#include <cstdint>

enum class vm_profile {
	OPTIMIZED,
	ULTRA
};

struct vm_settings {
	// Bytecode-level noise (percentages 0-100)
	int junk_frequency = 25;
	int dead_branch_pct = 5;
	int opaque_predicate_pct = 5;
	int opaque_constant_pct = 30;

	// Dispatcher-level
	int mba_pct = 0;
	int chain_pct = 0;
	bool handler_duplication = true;
	bool dispatch_polymorphism = true;

	// Encryption
	bool encrypted_immediates = true;
	bool per_region_encryption = true;
	bool per_region_register_rename = true;

	// Control flow
	bool control_flow_flattening = true;
	bool context_dependent_decoding = false;
	bool fake_cfg_edges = false;  // Insert unreachable conditional jumps in bytecode
	int fake_edge_pct = 10;      // Chance to add fake edge per block

	// Self-modifying bytecode: periodically re-XOR bytecode in memory
	bool self_modifying_bytecode = false;
	int self_modify_interval = 16;  // Re-XOR every N instructions

	// Indirect dispatch: compute handler addresses via polynomial instead of jump table
	bool indirect_dispatch = false;

	static vm_settings from_profile(vm_profile profile) {
		vm_settings s;
		switch (profile) {
		case vm_profile::OPTIMIZED:
			// Noise knobs (junk_frequency, opaque_predicate_pct, dead_branch_pct,
			// opaque_constant_pct) still need handler-side cleanup: junk_block
			// has more memory-writing variants to audit (cases 0 and 2 are fixed)
			// and the constant-pollution chain in emit_mov_reg_imm64 is flaky on
			// stage 10. Forced to 0 until the audit is done; the VIRTUALIZE-side
			// protection knobs below are independently strong.
			s.junk_frequency = 0;
			s.dead_branch_pct = 0;
			s.opaque_predicate_pct = 0;
			s.opaque_constant_pct = 0;
			s.mba_pct = 0;
			s.chain_pct = 0;
			s.handler_duplication = true;
			s.dispatch_polymorphism = false; // dead field, no implementation
			s.encrypted_immediates = true;
			s.per_region_encryption = true;
			s.per_region_register_rename = true;
			s.control_flow_flattening = true;
			s.context_dependent_decoding = false;
			break;
		case vm_profile::ULTRA:
			s.junk_frequency = 0;       // See OPTIMIZED comment.
			s.dead_branch_pct = 0;
			s.opaque_predicate_pct = 0;
			s.opaque_constant_pct = 0;
			s.mba_pct = 15;
			s.chain_pct = 20;
			s.handler_duplication = true;
			s.dispatch_polymorphism = false;
			s.encrypted_immediates = true;
			s.per_region_encryption = true;
			s.per_region_register_rename = true;
			s.control_flow_flattening = true;
			s.context_dependent_decoding = false;
			s.fake_cfg_edges = true;
			s.fake_edge_pct = 15;
			s.self_modifying_bytecode = true;
			s.self_modify_interval = 16;
			s.indirect_dispatch = true;
			break;
		}
		return s;
	}
};
