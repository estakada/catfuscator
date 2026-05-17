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
			// All noise knobs forced off pending VIRTUALIZE handler audit.
			// Even MUTATE-side junk_frequency drives VM handler junk
			// emission (emit_handler_entry_junk reads it) and turned out
			// to be enough to corrupt stage 10's [rsp+disp] computations.
			s.junk_frequency = 0;
			s.dead_branch_pct = 0;
			s.opaque_predicate_pct = 0;
			s.opaque_constant_pct = 0;
			s.mba_pct = 0;
			s.chain_pct = 0;
			// VIRTUALIZE-side toggles: temporarily forced off after the
			// zero-stack-frame VM refactor. The translator-vs-handler
			// invariants for these features were tuned against the OLD
			// stack-frame layout and need to be re-validated against the
			// new buffer-based ctx (TODO follow-up). With them all off
			// stages 1-12 of test_takopi_cipher pass 60/60 across 5 trials.
			s.handler_duplication = false;
			s.dispatch_polymorphism = false;
			s.encrypted_immediates = false;
			s.per_region_encryption = false;
			s.per_region_register_rename = false;
			s.control_flow_flattening = false;
			s.context_dependent_decoding = false;
			break;
		case vm_profile::ULTRA:
			s.junk_frequency = 40;
			s.dead_branch_pct = 10;
			s.opaque_predicate_pct = 10;
			s.opaque_constant_pct = 40;
			s.mba_pct = 15;
			s.chain_pct = 20;
			// See OPTIMIZED for why these are off pending follow-up.
			s.handler_duplication = false;
			s.dispatch_polymorphism = false;
			s.encrypted_immediates = false;
			s.per_region_encryption = false;
			s.per_region_register_rename = false;
			s.control_flow_flattening = false;
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
