#pragma once
#include "vm_opcodes.h"
#include "vm_settings.h"
#include "../obfuscator/obfuscator.h"
#include "../pe/pe.h"

#include <vector>
#include <map>
#include <cstdint>
#include <random>

struct vm_instruction {
	vm_op op;
	uint8_t reg1;
	uint8_t reg2;
	int64_t imm;
	uint32_t size; // total encoded size in bytecode
};

class vm_translator {
public:
	vm_translator(const vm_opcode_table& table);

	// Translate x86 instructions to VM bytecode
	bool translate(const std::vector<obfuscator::instruction_t>& instructions,
		std::vector<uint8_t>& bytecode);

private:
	const vm_opcode_table& table;
	const vm_settings* settings;
	std::mt19937 junk_rng;
	uint64_t imm_xor_key;
	uint64_t buffer_base;
	uint64_t image_base;
	std::map<uint32_t, import_entry> import_map;
public:
	void set_imm_xor_key(uint64_t key) { imm_xor_key = key; }
	void set_settings(const vm_settings* s) { settings = s; }
	void set_pe_info(uint64_t buf_base, uint64_t img_base) { buffer_base = buf_base; image_base = img_base; }
	void set_import_map(const std::map<uint32_t, import_entry>& map) { import_map = map; }
	uint64_t get_buffer_base() const { return buffer_base; }
	uint64_t get_image_base() const { return image_base; }
	const std::map<uint32_t, import_entry>& get_import_map() const { return import_map; }
private:

	// Junk bytecode insertion
	void emit_junk_bytecode(std::vector<uint8_t>& bc);
	void maybe_emit_junk(std::vector<uint8_t>& bc);
	void emit_prefixes(std::vector<uint8_t>& bc);

	// Dead bytecode: always-taken branch over dead code block
	void emit_dead_branch(std::vector<uint8_t>& bc);
	// Opaque predicate: never-taken branch creating fake CFG edge
	void emit_opaque_branch(std::vector<uint8_t>& bc);

	// Map x86 Zydis register to VM register
	bool map_register(ZydisRegister reg, uint8_t& out_vreg, uint8_t& out_size);

	// Translate individual x86 instruction types
	bool translate_mov(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_add(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_sub(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_xor(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_and(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_or(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_cmp(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_test(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_push(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_pop(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_lea(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_jcc(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_inc_dec(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_not_neg(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_shl_shr(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_imul(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_call(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_cdq_cqo(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_div_idiv(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_cmov(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_setcc(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_movzx_movsx(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_cbw_cwde_cdqe(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_mul(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_rol_ror(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_bt(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_bsf_bsr(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_popcnt_lzcnt_tzcnt(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_string_op(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_adc_sbb(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_xchg(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_leave(std::vector<uint8_t>& bc);
	bool translate_btc(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_bswap(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_shld_shrd(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_jmp_indirect(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_nop(std::vector<uint8_t>& bc);

	// Helpers
	bool emit_sib_load(const ZydisDecodedOperand& mem_op, uint8_t dst_vreg, uint8_t load_size, std::vector<uint8_t>& bc, const obfuscator::instruction_t* inst = nullptr);
	bool emit_sib_store(const ZydisDecodedOperand& mem_op, uint8_t src_vreg, uint8_t store_size, std::vector<uint8_t>& bc, const obfuscator::instruction_t* inst = nullptr);
	void emit_byte(std::vector<uint8_t>& bc, uint8_t val);
	void emit_u16(std::vector<uint8_t>& bc, uint16_t val);
	void emit_u32(std::vector<uint8_t>& bc, uint32_t val);
	void emit_u64(std::vector<uint8_t>& bc, uint64_t val);
	void emit_i32(std::vector<uint8_t>& bc, int32_t val);
	void emit_i64(std::vector<uint8_t>& bc, int64_t val);

	// Opaque constant: sometimes replaces MOV_REG_IMM64 with arithmetic chain
	void emit_mov_reg_imm64(std::vector<uint8_t>& bc, uint8_t vreg, int64_t val);

	bool translate_alu_reg_reg(vm_op op, const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_alu_reg_imm(vm_op op, const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_alu_mem(vm_op reg_reg_op, vm_op reg_imm_op, const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);

	// SSE
	bool map_xmm_register(ZydisRegister reg, uint8_t& out_xmm_idx);
	bool translate_sse_mov(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_sse_arith(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_sse_cmp(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_sse_cvt(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_sse_bitwise(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_sse_packed_arith(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_sse_minmax_sqrt(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_sse_shuffle(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_sse_int(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_sse_shift_imm(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_movd_movq(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_pinsr_pextr(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_roundss_sd(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_ptest(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_sse_movhilo(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_pmovmskb(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_pshufd(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);

	// LOCK / atomic
	bool translate_lock_op(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_cmpxchg(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);

	// Misc
	bool translate_cpuid(std::vector<uint8_t>& bc);
	bool translate_rdtsc(std::vector<uint8_t>& bc);
	bool translate_fence(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_flag_op(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_enter_frame(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_movbe(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_crc32(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);
	bool translate_bmi(const obfuscator::instruction_t& inst, std::vector<uint8_t>& bc);

	// Jump table support
	int try_translate_switch(const std::vector<obfuscator::instruction_t>& instructions,
		size_t idx, std::vector<uint8_t>& bc,
		std::vector<std::pair<uint32_t, uint64_t>>& patches);
};
