#pragma once
#include "vm_opcodes.h"
#include "vm_settings.h"
#include "vm_mba.h"
#include "../pe/pe.h"

#include <vector>
#include <cstdint>
#include <random>
#include <functional>
#include <asmjit/asmjit.h>

class vm_dispatcher {
public:
	vm_dispatcher(const vm_opcode_table& table);

	bool generate(std::vector<uint8_t>& dispatcher_code,
		const uint8_t* key = nullptr, int key_size = 0, uint32_t bytecode_size = 0,
		uint64_t imm_xor_key = 0, const vm_settings* settings = nullptr,
		uint32_t context_seed = 0, uint64_t image_base = 0,
		bool nested_mode = false, const uint8_t* bytecode_data = nullptr);

	uint32_t get_dispatcher_size() const;

private:
	const vm_opcode_table& table;
	uint32_t dispatcher_size;
	std::mt19937 opaque_rng;
	vm_mba mba;
	const vm_settings* settings;
	uint32_t context_seed;
	uint64_t compile_image_base;
	bool nested_mode;
	uint64_t inner_dispatcher_rva;
	const uint8_t* dispatch_key = nullptr;
	int dispatch_key_size = 0;
	const uint8_t* bytecode_data = nullptr;
	uint32_t bytecode_checksum = 0;
	uint32_t bytecode_size_for_checksum = 0;
public:
	void set_inner_dispatcher_rva(uint64_t rva) { inner_dispatcher_rva = rva; }
private:

	struct handler_labels {
		asmjit::Label entry;
		asmjit::Label dispatch_loop;
		asmjit::Label dispatch_continue;
		asmjit::Label handler_table;
		asmjit::Label exit_label;
		asmjit::Label handlers[static_cast<int>(vm_op::VM_COUNT)];
		asmjit::Label dup_handlers[vm_opcode_table::TOTAL_DUPS];
		// Jump table dispatch: resolved handler offsets (populated post-assembly)
		std::vector<uint32_t> handler_offsets;
		// jt_table label (needed for post-processing offset resolution)
		asmjit::Label jt_table_label;
		// Junk handlers: fake opcode handlers that are never dispatched to
		std::vector<asmjit::Label> junk_handlers;
	};

	void emit_enter_handler(asmjit::x86::Assembler& a, handler_labels& labels,
		const uint8_t* key, int key_size, uint32_t bytecode_size, uint64_t imm_xor_key);
	void emit_exit_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_exit_to_rva_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_dispatch_loop(asmjit::x86::Assembler& a, handler_labels& labels,
		const uint8_t* key, int key_size);

	// Junk handlers: fake opcode handlers never dispatched to, pollute RE analysis
	void emit_junk_handler(asmjit::x86::Assembler& a, handler_labels& labels, int idx);

	// Opcode handlers
	void emit_nop_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_mov_reg_imm64_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_mov_reg_reg_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_mov_reg_mem_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_mov_mem_reg_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_alu_reg_reg_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);
	void emit_alu_reg_imm_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);
	void emit_not_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_neg_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_shl_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_shr_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_cmp_reg_reg_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_cmp_reg_imm_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_test_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_jmp_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_jcc_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);
	void emit_push_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_pop_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_call_native_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_call_native_reloc_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_relocate_reg_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_call_import_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_nest_enter_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_lea_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_imul_reg_reg_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_mul_reg_imm_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_cdq_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_cqo_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_div_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);
	void emit_cmov_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);
	void emit_setcc_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);
	void emit_movzx_mem_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);
	void emit_movsx_mem_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);
	void emit_test_reg_imm_handler(asmjit::x86::Assembler& a, handler_labels& labels);

	// Sign extension
	void emit_cbw_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_cwde_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_cdqe_handler(asmjit::x86::Assembler& a, handler_labels& labels);

	// Unsigned multiply
	void emit_mul_reg_handler(asmjit::x86::Assembler& a, handler_labels& labels);

	// Rotation
	void emit_rot_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);

	// Bit operations
	void emit_bt_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);
	void emit_bsf_bsr_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);
	void emit_popcnt_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);

	// String operations
	void emit_string_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);

	// SAR / shift-by-CL
	void emit_sar_imm_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_shift_cl_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);

	// SIB addressing
	void emit_mov_reg_sib_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_mov_sib_reg_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_lea_sib_handler(asmjit::x86::Assembler& a, handler_labels& labels);

	// Carry arithmetic
	void emit_adc_reg_reg_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_adc_reg_imm_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_sbb_reg_reg_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_sbb_reg_imm_handler(asmjit::x86::Assembler& a, handler_labels& labels);

	// Misc
	void emit_xchg_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_leave_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_call_indirect_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_btc_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);
	void emit_bswap_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_rot_cl_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);
	void emit_cwd_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_jmp_reg_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_jmp_mem_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_imul_single_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_shld_shrd_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);

	// SSE handlers
	void emit_sse_mov_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);
	void emit_sse_arith_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);
	void emit_sse_cmp_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);
	void emit_sse_cvt_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);
	void emit_sse_bitwise_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);
	void emit_sse_packed_arith_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);
	void emit_sse_minmax_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);
	void emit_sse_shuffle_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);
	void emit_sse_int_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);
	void emit_sse_shift_imm_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);
	void emit_sse_movd_movq_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);
	void emit_sse_pinsr_pextr_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);
	void emit_sse_round_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);
	void emit_sse_ptest_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_sse_movhilo_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);
	void emit_pmovmskb_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_pshufd_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);

	// LOCK / atomic handlers
	void emit_lock_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);
	void emit_cmpxchg_handler(asmjit::x86::Assembler& a, handler_labels& labels);

	// Misc handlers
	void emit_cpuid_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_rdtsc_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_fence_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);
	void emit_flag_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);
	void emit_enter_frame_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_movbe_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);
	void emit_crc32_handler(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_bmi_handler(asmjit::x86::Assembler& a, handler_labels& labels, vm_op op);

	// Opaque predicates
	void emit_opaque_predicate(asmjit::x86::Assembler& a, handler_labels& labels);
	void emit_junk_block(asmjit::x86::Assembler& a);
	void maybe_emit_opaque(asmjit::x86::Assembler& a, handler_labels& labels);

	// Handler chaining: inline dispatch instead of jmp dispatch_loop
	void emit_chain_dispatch(asmjit::x86::Assembler& a, handler_labels& labels);

	// Indirect dispatch: polynomial handler lookup without plaintext jump table
	bool emit_indirect_dispatch(asmjit::x86::Assembler& a, handler_labels& labels,
		const uint8_t* key, int key_size);

	// Handler mutation: per-region polymorphism
	void emit_handler_entry_junk(asmjit::x86::Assembler& a);
	void emit_poly_index_to_offset(asmjit::x86::Assembler& a, const asmjit::x86::Gp& reg);
	void emit_poly_advance_ip(asmjit::x86::Assembler& a, int n);

	// Polymorphic dispatch: shuffled handler order + dup trampolines
	void build_handler_list(asmjit::x86::Assembler& a, handler_labels& labels,
		std::vector<std::function<void()>>& out);
	void emit_dup_trampoline(asmjit::x86::Assembler& a, asmjit::Label& dup_label,
		asmjit::Label& original_label);
	void emit_dup_handler_body(asmjit::x86::Assembler& a, handler_labels& labels,
		asmjit::Label& dup_label, vm_op original_op, int variant);
};
