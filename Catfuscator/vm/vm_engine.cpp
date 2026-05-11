#include "vm_engine.h"
#include <ctime>
#include <random>

vm_engine::vm_engine(uint32_t seed, vm_profile profile)
	: settings(vm_settings::from_profile(profile)),
	  translator(opcode_table), dispatcher(opcode_table),
	  bytecode_size(0), seed_value(0), region_counter(0), image_base(0) {
	if (seed == 0)
		seed = static_cast<uint32_t>(time(nullptr));
	seed_value = seed;
	opcode_table.randomize(seed);
}

void vm_engine::generate_key(uint32_t region_seed) {
	std::mt19937 rng(region_seed ^ 0xB16B00B5);
	for (int i = 0; i < ENCRYPT_KEY_SIZE; i++)
		encrypt_key[i] = static_cast<uint8_t>(rng());
}

void vm_engine::encrypt_bytecode(std::vector<uint8_t>& bytecode) {
	rc4_crypt(bytecode.data(), bytecode.size(), encrypt_key, ENCRYPT_KEY_SIZE);
}

void vm_engine::rc4_crypt(uint8_t* data, size_t len, const uint8_t* key, int key_len) {
	// RC4 Key Scheduling Algorithm
	uint8_t S[256];
	for (int i = 0; i < 256; i++) S[i] = static_cast<uint8_t>(i);
	int j = 0;
	for (int i = 0; i < 256; i++) {
		j = (j + S[i] + key[i % key_len]) & 0xFF;
		std::swap(S[i], S[j]);
	}
	// RC4 Pseudo-Random Generation Algorithm + XOR
	int ii = 0, jj = 0;
	for (size_t k = 0; k < len; k++) {
		ii = (ii + 1) & 0xFF;
		jj = (jj + S[ii]) & 0xFF;
		std::swap(S[ii], S[jj]);
		int t = (S[ii] + S[jj]) & 0xFF;
		data[k] ^= S[t];
	}
}

static int get_opcode_operand_size(uint16_t opcode, const vm_opcode_table& table) {
	vm_op op = table.decode(opcode);
	switch (op) {
	case vm_op::VM_NOP: return 0;
	case vm_op::VM_ENTER: return 0;
	case vm_op::VM_EXIT: return 0;
	case vm_op::VM_MOV_REG_IMM64: return 1 + 8;
	case vm_op::VM_MOV_REG_REG: return 2;
	case vm_op::VM_MOV_REG_MEM: return 7;
	case vm_op::VM_MOV_MEM_REG: return 7;
	case vm_op::VM_ADD_REG_REG: case vm_op::VM_SUB_REG_REG:
	case vm_op::VM_XOR_REG_REG: case vm_op::VM_AND_REG_REG:
	case vm_op::VM_OR_REG_REG: case vm_op::VM_CMP_REG_REG:
	case vm_op::VM_TEST_REG_REG:
		return 3;
	case vm_op::VM_ADD_REG_IMM: case vm_op::VM_SUB_REG_IMM:
	case vm_op::VM_XOR_REG_IMM: case vm_op::VM_AND_REG_IMM:
	case vm_op::VM_OR_REG_IMM: case vm_op::VM_CMP_REG_IMM:
		return 6;
	case vm_op::VM_NOT_REG: case vm_op::VM_NEG_REG:
		return 1;
	case vm_op::VM_SHL_REG_IMM: case vm_op::VM_SHR_REG_IMM:
	case vm_op::VM_SAR_REG_IMM:
		return 2;
	case vm_op::VM_JMP: return 4;
	case vm_op::VM_JZ: case vm_op::VM_JNZ:
	case vm_op::VM_JB: case vm_op::VM_JAE:
	case vm_op::VM_JBE: case vm_op::VM_JA:
	case vm_op::VM_JL: case vm_op::VM_JGE:
	case vm_op::VM_JLE: case vm_op::VM_JG:
	case vm_op::VM_JS: case vm_op::VM_JNS:
	case vm_op::VM_JP: case vm_op::VM_JNP:
		return 4;
	case vm_op::VM_PUSH_REG: case vm_op::VM_POP_REG:
		return 1;
	case vm_op::VM_CALL_NATIVE: return 8;
	case vm_op::VM_LEA_REG: return 6;
	case vm_op::VM_IMUL_REG_REG: return 3;
	case vm_op::VM_MUL_REG_IMM: return 1 + 4;
	case vm_op::VM_CDQ: case vm_op::VM_CQO: case vm_op::VM_CWD:
		return 0;
	case vm_op::VM_DIV_REG: case vm_op::VM_IDIV_REG:
		return 1;
	case vm_op::VM_TEST_REG_IMM: return 6;
	case vm_op::VM_MOVZX_REG_MEM8: case vm_op::VM_MOVZX_REG_MEM16:
	case vm_op::VM_MOVSX_REG_MEM8: case vm_op::VM_MOVSX_REG_MEM16:
	case vm_op::VM_MOVSXD_REG_MEM32:
		return 6;
	case vm_op::VM_CBW: case vm_op::VM_CWDE: case vm_op::VM_CDQE:
		return 0;
	case vm_op::VM_MUL_REG: return 1;
	case vm_op::VM_ROL_REG_IMM: case vm_op::VM_ROR_REG_IMM:
	case vm_op::VM_RCL_REG_IMM: case vm_op::VM_RCR_REG_IMM:
		return 2;
	case vm_op::VM_BT_REG_REG: case vm_op::VM_BT_REG_IMM:
	case vm_op::VM_BTS_REG_REG: case vm_op::VM_BTS_REG_IMM:
	case vm_op::VM_BTR_REG_REG: case vm_op::VM_BTR_REG_IMM:
		return 2;
	case vm_op::VM_BSF_REG_REG: case vm_op::VM_BSR_REG_REG:
		return 2;
	case vm_op::VM_POPCNT_REG_REG: case vm_op::VM_LZCNT_REG_REG: case vm_op::VM_TZCNT_REG_REG:
		return 2;
	case vm_op::VM_MOV_REG_SIB: case vm_op::VM_MOV_SIB_REG:
		return 10;
	case vm_op::VM_LEA_SIB: return 9;
	case vm_op::VM_ADC_REG_REG: case vm_op::VM_SBB_REG_REG:
		return 3;
	case vm_op::VM_ADC_REG_IMM: case vm_op::VM_SBB_REG_IMM:
		return 6;
	case vm_op::VM_XCHG_REG_REG: return 2;
	case vm_op::VM_LEAVE: return 0;
	case vm_op::VM_CALL_REG_INDIRECT: return 5;
	case vm_op::VM_BTC_REG_REG: case vm_op::VM_BTC_REG_IMM:
		return 2;
	case vm_op::VM_BSWAP_REG: return 1;
	case vm_op::VM_SHL_REG_CL: case vm_op::VM_SHR_REG_CL:
	case vm_op::VM_SAR_REG_CL:
		return 1;
	case vm_op::VM_ROL_REG_CL: case vm_op::VM_ROR_REG_CL:
		return 1;
	case vm_op::VM_JMP_REG: return 1;
	case vm_op::VM_JMP_MEM: return 6;
	case vm_op::VM_IMUL_REG: return 1;
	case vm_op::VM_SHLD_REG_REG_IMM: case vm_op::VM_SHRD_REG_REG_IMM:
		return 3;
	case vm_op::VM_SHLD_REG_REG_CL: case vm_op::VM_SHRD_REG_REG_CL:
		return 2;
	case vm_op::VM_CMOVZ_REG_REG: case vm_op::VM_CMOVNZ_REG_REG:
	case vm_op::VM_CMOVB_REG_REG: case vm_op::VM_CMOVAE_REG_REG:
	case vm_op::VM_CMOVBE_REG_REG: case vm_op::VM_CMOVA_REG_REG:
	case vm_op::VM_CMOVL_REG_REG: case vm_op::VM_CMOVGE_REG_REG:
	case vm_op::VM_CMOVLE_REG_REG: case vm_op::VM_CMOVG_REG_REG:
	case vm_op::VM_CMOVS_REG_REG: case vm_op::VM_CMOVNS_REG_REG:
	case vm_op::VM_CMOVP_REG_REG: case vm_op::VM_CMOVNP_REG_REG:
		return 2;
	case vm_op::VM_SETZ_REG: case vm_op::VM_SETNZ_REG:
	case vm_op::VM_SETB_REG: case vm_op::VM_SETAE_REG:
	case vm_op::VM_SETBE_REG: case vm_op::VM_SETA_REG:
	case vm_op::VM_SETL_REG: case vm_op::VM_SETGE_REG:
	case vm_op::VM_SETLE_REG: case vm_op::VM_SETG_REG:
	case vm_op::VM_SETS_REG: case vm_op::VM_SETNS_REG:
	case vm_op::VM_SETP_REG: case vm_op::VM_SETNP_REG:
		return 1;
	case vm_op::VM_MOVSB: case vm_op::VM_MOVSQ:
	case vm_op::VM_STOSB: case vm_op::VM_STOSQ:
	case vm_op::VM_REP_MOVSB: case vm_op::VM_REP_MOVSW:
	case vm_op::VM_REP_MOVSD: case vm_op::VM_REP_MOVSQ:
	case vm_op::VM_REP_STOSB: case vm_op::VM_REP_STOSW:
	case vm_op::VM_REP_STOSD: case vm_op::VM_REP_STOSQ:
	case vm_op::VM_REP_SCASB:
	case vm_op::VM_REPE_CMPSB:
		return 0;
	// SSE mov load/store (xmm, [mem]) = 7 bytes operand
	case vm_op::VM_MOVSS_REG_MEM: case vm_op::VM_MOVSS_MEM_REG:
	case vm_op::VM_MOVSD_REG_MEM: case vm_op::VM_MOVSD_MEM_REG:
	case vm_op::VM_MOVAPS_REG_MEM: case vm_op::VM_MOVAPS_MEM_REG:
	case vm_op::VM_MOVUPS_REG_MEM: case vm_op::VM_MOVUPS_MEM_REG:
	case vm_op::VM_MOVDQA_REG_MEM: case vm_op::VM_MOVDQA_MEM_REG:
	case vm_op::VM_MOVDQU_REG_MEM: case vm_op::VM_MOVDQU_MEM_REG:
		return 7;
	// SSE mov reg-reg (xmm, xmm) = 2 bytes operand
	case vm_op::VM_MOVSS_REG_REG: case vm_op::VM_MOVSD_REG_REG:
	case vm_op::VM_MOVAPS_REG_REG:
	case vm_op::VM_MOVDQA_REG_REG:
		return 2;
	// SSE scalar arith reg-reg = 2
	case vm_op::VM_ADDSS_REG_REG: case vm_op::VM_ADDSD_REG_REG:
	case vm_op::VM_SUBSS_REG_REG: case vm_op::VM_SUBSD_REG_REG:
	case vm_op::VM_MULSS_REG_REG: case vm_op::VM_MULSD_REG_REG:
	case vm_op::VM_DIVSS_REG_REG: case vm_op::VM_DIVSD_REG_REG:
		return 2;
	// SSE compare reg-reg = 2
	case vm_op::VM_UCOMISS_REG_REG: case vm_op::VM_UCOMISD_REG_REG:
		return 2;
	// SSE conversion reg-reg = 2
	case vm_op::VM_CVTSI2SS_REG_REG: case vm_op::VM_CVTSI2SD_REG_REG:
	case vm_op::VM_CVTSS2SI_REG_REG: case vm_op::VM_CVTSD2SI_REG_REG:
	case vm_op::VM_CVTSS2SD_REG_REG: case vm_op::VM_CVTSD2SS_REG_REG:
	case vm_op::VM_CVTTSS2SI_REG_REG: case vm_op::VM_CVTTSD2SI_REG_REG:
		return 2;
	// SSE bitwise reg-reg = 2
	case vm_op::VM_XORPS_REG_REG: case vm_op::VM_XORPD_REG_REG:
	case vm_op::VM_ANDPS_REG_REG: case vm_op::VM_ANDPD_REG_REG:
	case vm_op::VM_ORPS_REG_REG: case vm_op::VM_ORPD_REG_REG:
	case vm_op::VM_ANDNPS_REG_REG: case vm_op::VM_ANDNPD_REG_REG:
	case vm_op::VM_PXOR_REG_REG: case vm_op::VM_PAND_REG_REG:
	case vm_op::VM_POR_REG_REG: case vm_op::VM_PANDN_REG_REG:
		return 2;
	// SSE packed integer reg-reg = 2
	case vm_op::VM_PADDB_REG_REG: case vm_op::VM_PADDW_REG_REG:
	case vm_op::VM_PADDD_REG_REG: case vm_op::VM_PADDQ_REG_REG:
	case vm_op::VM_PSUBB_REG_REG: case vm_op::VM_PSUBW_REG_REG:
	case vm_op::VM_PSUBD_REG_REG: case vm_op::VM_PSUBQ_REG_REG:
	case vm_op::VM_PCMPEQB_REG_REG: case vm_op::VM_PCMPEQD_REG_REG:
	case vm_op::VM_PCMPGTB_REG_REG:
	case vm_op::VM_PUNPCKLBW_REG_REG: case vm_op::VM_PUNPCKHBW_REG_REG:
	case vm_op::VM_PUNPCKLDQ_REG_REG: case vm_op::VM_PUNPCKHDQ_REG_REG:
	case vm_op::VM_PUNPCKLQDQ_REG_REG: case vm_op::VM_PUNPCKHQDQ_REG_REG:
		return 2;
	// SSE min/max/sqrt reg-reg = 2
	case vm_op::VM_MINSS_REG_REG: case vm_op::VM_MINSD_REG_REG:
	case vm_op::VM_MAXSS_REG_REG: case vm_op::VM_MAXSD_REG_REG:
	case vm_op::VM_SQRTSS_REG_REG: case vm_op::VM_SQRTSD_REG_REG:
	// SSE packed arith reg-reg = 2
	case vm_op::VM_ADDPS_REG_REG: case vm_op::VM_ADDPD_REG_REG:
	case vm_op::VM_SUBPS_REG_REG: case vm_op::VM_SUBPD_REG_REG:
	case vm_op::VM_MULPS_REG_REG: case vm_op::VM_MULPD_REG_REG:
	case vm_op::VM_DIVPS_REG_REG: case vm_op::VM_DIVPD_REG_REG:
	case vm_op::VM_UNPCKLPS_REG_REG: case vm_op::VM_UNPCKHPS_REG_REG:
	case vm_op::VM_UNPCKLPD_REG_REG: case vm_op::VM_UNPCKHPD_REG_REG:
		return 2;
	// SSE shuffle = 3
	case vm_op::VM_SHUFPS_REG_REG_IMM: case vm_op::VM_SHUFPD_REG_REG_IMM:
		return 3;
	// SSE shift imm = 2
	case vm_op::VM_PSLLW_REG_IMM: case vm_op::VM_PSLLD_REG_IMM:
	case vm_op::VM_PSLLQ_REG_IMM: case vm_op::VM_PSRLW_REG_IMM:
	case vm_op::VM_PSRLD_REG_IMM: case vm_op::VM_PSRLQ_REG_IMM:
	case vm_op::VM_PSRAW_REG_IMM: case vm_op::VM_PSRAD_REG_IMM:
		return 2;
	// MOVD/MOVQ
	case vm_op::VM_MOVD_XMM_REG: case vm_op::VM_MOVD_REG_XMM:
	case vm_op::VM_MOVQ_XMM_REG: case vm_op::VM_MOVQ_REG_XMM:
	case vm_op::VM_MOVQ_XMM_XMM:
		return 2;
	// PINSR/PEXTR = 3
	case vm_op::VM_PINSRB_REG_REG_IMM: case vm_op::VM_PINSRD_REG_REG_IMM:
	case vm_op::VM_PINSRQ_REG_REG_IMM: case vm_op::VM_PEXTRB_REG_REG_IMM:
	case vm_op::VM_PEXTRD_REG_REG_IMM: case vm_op::VM_PEXTRQ_REG_REG_IMM:
		return 3;
	// ROUND = 3
	case vm_op::VM_ROUNDSS_REG_REG_IMM: case vm_op::VM_ROUNDSD_REG_REG_IMM:
		return 3;
	case vm_op::VM_PTEST_REG_REG: return 2;
	// MOVHPS/MOVLPS load/store = 7
	case vm_op::VM_MOVHPS_REG_MEM: case vm_op::VM_MOVHPS_MEM_REG:
	case vm_op::VM_MOVLPS_REG_MEM: case vm_op::VM_MOVLPS_MEM_REG:
	case vm_op::VM_MOVHPD_REG_MEM: case vm_op::VM_MOVHPD_MEM_REG:
	case vm_op::VM_MOVLPD_REG_MEM: case vm_op::VM_MOVLPD_MEM_REG:
		return 7;
	case vm_op::VM_PMOVMSKB_REG_REG: return 2;
	case vm_op::VM_PSHUFD_REG_REG_IMM:
		return 3;
	// LOCK / atomic
	case vm_op::VM_LOCK_ADD_MEM_REG: case vm_op::VM_LOCK_ADD_MEM_IMM:
	case vm_op::VM_LOCK_SUB_MEM_REG: case vm_op::VM_LOCK_SUB_MEM_IMM:
	case vm_op::VM_LOCK_XOR_MEM_REG: case vm_op::VM_LOCK_XOR_MEM_IMM:
	case vm_op::VM_LOCK_AND_MEM_REG: case vm_op::VM_LOCK_AND_MEM_IMM:
	case vm_op::VM_LOCK_OR_MEM_REG: case vm_op::VM_LOCK_OR_MEM_IMM:
	case vm_op::VM_LOCK_INC_MEM: case vm_op::VM_LOCK_DEC_MEM:
	case vm_op::VM_LOCK_XADD_MEM_REG:
		return 7;
	case vm_op::VM_CMPXCHG_MEM_REG: return 8;
	// Misc
	case vm_op::VM_CPUID: return 0;
	case vm_op::VM_RDTSC: return 0;
	case vm_op::VM_MFENCE: case vm_op::VM_LFENCE: case vm_op::VM_SFENCE:
		return 0;
	case vm_op::VM_CLC: case vm_op::VM_STC: case vm_op::VM_CMC:
		return 0;
	case vm_op::VM_ENTER_FRAME: return 2;
	case vm_op::VM_MOVBE_REG_MEM: case vm_op::VM_MOVBE_MEM_REG:
		return 7;
	case vm_op::VM_CRC32_REG_REG: return 2;
	case vm_op::VM_BLSI_REG_REG: case vm_op::VM_BLSMSK_REG_REG:
	case vm_op::VM_BLSR_REG_REG:
		return 2;
	case vm_op::VM_ANDN_REG_REG_REG: case vm_op::VM_BEXTR_REG_REG_REG:
	case vm_op::VM_BZHI_REG_REG_REG:
	case vm_op::VM_PDEP_REG_REG_REG: case vm_op::VM_PEXT_REG_REG_REG:
	case vm_op::VM_SARX_REG_REG_REG: case vm_op::VM_SHLX_REG_REG_REG: case vm_op::VM_SHRX_REG_REG_REG:
		return 3;
	case vm_op::VM_RELOCATE_REG: return 1;
	case vm_op::VM_CALL_NATIVE_RELOC: return 8;
	case vm_op::VM_CALL_IMPORT: return 8;
	case vm_op::VM_NEST_ENTER: return 4;
	default: return 0;
	}
}

static const char* vm_op_name(vm_op op) {
	switch (op) {
	case vm_op::VM_NOP: return "NOP";
	case vm_op::VM_ENTER: return "ENTER";
	case vm_op::VM_EXIT: return "EXIT";
	case vm_op::VM_MOV_REG_IMM64: return "MOV_REG_IMM64";
	case vm_op::VM_MOV_REG_REG: return "MOV_REG_REG";
	case vm_op::VM_MOV_REG_MEM: return "MOV_REG_MEM";
	case vm_op::VM_MOV_MEM_REG: return "MOV_MEM_REG";
	case vm_op::VM_ADD_REG_REG: return "ADD_REG_REG";
	case vm_op::VM_ADD_REG_IMM: return "ADD_REG_IMM";
	case vm_op::VM_SUB_REG_REG: return "SUB_REG_REG";
	case vm_op::VM_SUB_REG_IMM: return "SUB_REG_IMM";
	case vm_op::VM_NOT_REG: return "NOT_REG";
	case vm_op::VM_NEG_REG: return "NEG_REG";
	case vm_op::VM_SHL_REG_IMM: return "SHL_REG_IMM";
	case vm_op::VM_SHR_REG_IMM: return "SHR_REG_IMM";
	case vm_op::VM_CMP_REG_REG: return "CMP_REG_REG";
	case vm_op::VM_CMP_REG_IMM: return "CMP_REG_IMM";
	case vm_op::VM_JMP: return "JMP";
	case vm_op::VM_LEA_REG: return "LEA_REG";
	case vm_op::VM_PUSH_REG: return "PUSH_REG";
	case vm_op::VM_POP_REG: return "POP_REG";
	case vm_op::VM_RELOCATE_REG: return "RELOCATE_REG";
	case vm_op::VM_CALL_NATIVE_RELOC: return "CALL_NATIVE_RELOC";
	case vm_op::VM_CALL_IMPORT: return "CALL_IMPORT";
	case vm_op::VM_NEST_ENTER: return "NEST_ENTER";
	default: {
		static char buf[32];
		snprintf(buf, sizeof(buf), "OP_%d", (int)op);
		return buf;
	}
	}
}

static void dump_bytecode(const std::vector<uint8_t>& bytecode, const vm_opcode_table& table) {
	printf("[bytecode_dump] total %zu bytes:\n", bytecode.size());
	size_t pos = 0;
	int inst_num = 0;
	while (pos + 1 < bytecode.size()) {
		uint16_t raw = bytecode[pos] | (bytecode[pos + 1] << 8);
		if (raw >= vm_opcode_table::TOTAL_ENCODED) {
			printf("  [%04zu] PREFIX 0x%04X\n", pos, raw);
			pos += 2;
			continue;
		}
		vm_op op = table.decode(raw);
		int opsz = get_opcode_operand_size(raw, table);
		printf("  [%04zu] #%d %-20s (enc=0x%04X, opsz=%d)", pos, inst_num, vm_op_name(op), raw, opsz);
		for (int i = 0; i < opsz && (pos + 2 + i) < bytecode.size(); i++)
			printf(" %02X", bytecode[pos + 2 + i]);
		printf("\n");
		pos += 2 + opsz;
		inst_num++;
	}
	printf("[bytecode_dump] done, %d instructions\n", inst_num);
	fflush(stdout);
}

static void apply_context_encoding(std::vector<uint8_t>& bytecode, uint32_t seed,
	const vm_opcode_table& table) {
	size_t pos = 0;
	while (pos + 1 < bytecode.size()) {
		uint16_t original = bytecode[pos] | (bytecode[pos + 1] << 8);

		// Multi-round hash: harder for symbolic execution to invert
		uint32_t h = static_cast<uint32_t>(pos) * 0x45D9F3Bu + seed;
		h ^= h >> 16;
		h *= 0x85EBCA6Bu;
		h ^= h >> 13;
		uint16_t key = static_cast<uint16_t>(h >> 16);
		uint16_t encoded = original ^ key;
		bytecode[pos] = encoded & 0xFF;
		bytecode[pos + 1] = (encoded >> 8) & 0xFF;

		if (original >= vm_opcode_table::TOTAL_ENCODED) {
			pos += 2;
		} else {
			int operand_sz = get_opcode_operand_size(original, table);
			pos += 2 + operand_sz;
		}
	}
}

bool vm_engine::virtualize(const std::vector<obfuscator::instruction_t>& instructions,
	std::vector<uint8_t>& output, bool nested) {

	uint32_t region_seed = seed_value ^ (++region_counter * 0x9E3779B9);

	if (settings.per_region_register_rename)
		opcode_table.reshuffle_gp_perm(region_seed);

	if (settings.per_region_encryption)
		generate_key(region_seed);

	uint64_t imm_xor_key = 0;
	if (settings.encrypted_immediates) {
		std::mt19937_64 imm_rng(region_seed ^ 0x1337CAFE);
		imm_xor_key = imm_rng();
	}
	translator.set_imm_xor_key(imm_xor_key);
	translator.set_settings(&settings);

	// --- Inner VM setup (if nested) ---
	vm_opcode_table inner_table;
	uint8_t inner_key[ENCRYPT_KEY_SIZE] = {};
	uint64_t inner_imm_xor_key = 0;
	uint32_t inner_context_seed = 0;
	std::vector<uint8_t> inner_bytecode;
	std::vector<uint8_t> inner_dispatcher_code;

	if (nested) {
		uint32_t inner_seed = region_seed ^ 0x7E57AB1E;
		inner_table.randomize(inner_seed);
		inner_table.reshuffle_gp_perm(inner_seed ^ 0xFACEFEED);

		// Inner encryption key
		{
			std::mt19937 ik_rng(inner_seed ^ 0xB16B00B5);
			for (int i = 0; i < ENCRYPT_KEY_SIZE; i++)
				inner_key[i] = static_cast<uint8_t>(ik_rng());
		}

		// Inner imm XOR key
		{
			std::mt19937_64 iimm_rng(inner_seed ^ 0x1337CAFE);
			inner_imm_xor_key = iimm_rng();
		}

		// Translate x86 -> inner VM bytecode
		vm_translator inner_translator(inner_table);
		inner_translator.set_imm_xor_key(inner_imm_xor_key);
		inner_translator.set_settings(&settings);
		inner_translator.set_pe_info(
			(uint64_t)translator.get_buffer_base(),
			(uint64_t)translator.get_image_base());
		inner_translator.set_import_map(translator.get_import_map());

		if (!inner_translator.translate(instructions, inner_bytecode)) {
			printf("[vm_engine] inner VM translation failed, falling back to single VM\n");
			nested = false;
		}
	}

	if (nested) {
		// Apply CFF to inner bytecode
		if (settings.control_flow_flattening) {
			vm_cff inner_cff(inner_table, seed_value ^ 0x12345678);
			inner_cff.flatten(inner_bytecode);
		}

		// Context-dependent encoding for inner bytecode
		if (settings.context_dependent_decoding) {
			std::mt19937 ictx_rng(region_seed ^ 0xFEEDFACE);
			inner_context_seed = ictx_rng();
			apply_context_encoding(inner_bytecode, inner_context_seed, inner_table);
		}

		uint32_t inner_bc_size = static_cast<uint32_t>(inner_bytecode.size());

		// Encrypt inner bytecode
		if (settings.per_region_encryption) {
			for (size_t i = 0; i < inner_bytecode.size(); i++)
				inner_bytecode[i] ^= inner_key[i % ENCRYPT_KEY_SIZE];
		}

		// Generate inner dispatcher (nested mode)
		vm_dispatcher inner_dispatcher(inner_table);
		inner_dispatcher.generate(inner_dispatcher_code, inner_key, ENCRYPT_KEY_SIZE,
			inner_bc_size, inner_imm_xor_key, &settings, inner_context_seed, image_base,
			true);
	}

	// --- Outer bytecode ---
	std::vector<uint8_t> bytecode;
	if (nested) {
		// Outer bytecode = [VM_ENTER] [VM_NEST_ENTER(inner_bc_offset)] [VM_EXIT]
		// The inner_bc_offset will be patched after we know the layout
		uint16_t enter_enc = opcode_table.encode(vm_op::VM_ENTER);
		bytecode.push_back(enter_enc & 0xFF);
		bytecode.push_back((enter_enc >> 8) & 0xFF);

		uint16_t nest_enc = opcode_table.encode(vm_op::VM_NEST_ENTER);
		bytecode.push_back(nest_enc & 0xFF);
		bytecode.push_back((nest_enc >> 8) & 0xFF);
		// Placeholder for inner_bc_offset (4 bytes, will be patched)
		size_t nest_offset_pos = bytecode.size();
		bytecode.push_back(0); bytecode.push_back(0);
		bytecode.push_back(0); bytecode.push_back(0);

		uint16_t exit_enc = opcode_table.encode(vm_op::VM_EXIT);
		bytecode.push_back(exit_enc & 0xFF);
		bytecode.push_back((exit_enc >> 8) & 0xFF);

		// Apply context encoding to outer bytecode
		uint32_t context_seed_outer = 0;
		if (settings.context_dependent_decoding) {
			std::mt19937 ctx_rng(region_seed ^ 0xDEADC0DE);
			context_seed_outer = ctx_rng();
			apply_context_encoding(bytecode, context_seed_outer, opcode_table);
		}

		bytecode_size = static_cast<uint32_t>(bytecode.size());

		if (settings.per_region_encryption)
			encrypt_bytecode(bytecode);

		// Generate outer dispatcher
		uint32_t context_seed_val = 0;
		if (settings.context_dependent_decoding) {
			std::mt19937 ctx_rng(region_seed ^ 0xDEADC0DE);
			context_seed_val = ctx_rng();
		}

		// Layout: [stub:12] [outer_disp] [inner_disp] [outer_bc] [inner_bc]
		// We need to compute inner_dispatcher_rva relative to image base
		// But we don't know the section RVA yet. Instead, we use the RVA relative
		// to the output blob start, and the stub will set up addressing.
		// Actually, the inner dispatcher is called via: mov rax, <inner_rva>; add rax, r14; call rax
		// So inner_rva must be the RVA of the inner dispatcher within the PE.
		// We don't know the PE section RVA here. But the obfuscator knows.
		// Simpler: store inner dispatcher offset relative to the output blob start,
		// and at runtime compute: blob_rva + offset. But we don't have blob_rva.
		//
		// Best approach: make inner_dispatcher_rva relative to the outer bytecode base (R13).
		// At runtime: R13 = outer bytecode start. Inner dispatcher is at R13 + delta.
		// But R13 points to bytecode, and the dispatcher is before bytecode.
		// We need a negative offset. Let's use a different approach:
		// Store inner_dispatcher as a position relative to outer dispatcher start.
		// The stub at offset 0 sets RCX = bytecode address. The outer dispatcher starts at offset 12.
		// So bytecode_addr - (bytecode_offset_abs) = stub_start.
		// inner_disp is at stub_start + 12 + outer_disp_size.
		// At runtime: R13 = bytecode ptr. blob_start = R13 - bytecode_offset_in_blob.
		// inner_disp_addr = blob_start + (12 + outer_disp_size).
		//
		// Actually, the simplest is to place inner dispatcher AFTER the outer bytecode,
		// so inner_disp is at R13 + outer_bc_size. That's a positive offset from R13.

		// Revised layout: [stub:12] [outer_disp] [outer_bc] [inner_disp] [inner_bc]
		// inner_disp is at R13 + outer_bc_size
		// inner_bc is at R13 + outer_bc_size + inner_disp_size

		// Patch inner_bc_offset in outer bytecode (before encryption):
		// inner_bc_offset = outer_bc_size + inner_disp_size
		// But bytecode is already encrypted... Need to re-decrypt, patch, re-encrypt.
		// Or better: patch before encryption.

		// Let me redo the sequence: build outer bytecode with placeholder,
		// then patch, then context-encode, then encrypt.

		// Restart outer bytecode construction:
		bytecode.clear();
		enter_enc = opcode_table.encode(vm_op::VM_ENTER);
		bytecode.push_back(enter_enc & 0xFF);
		bytecode.push_back((enter_enc >> 8) & 0xFF);

		nest_enc = opcode_table.encode(vm_op::VM_NEST_ENTER);
		bytecode.push_back(nest_enc & 0xFF);
		bytecode.push_back((nest_enc >> 8) & 0xFF);

		// inner_bc_offset from outer bytecode base (R13) =
		//   outer_bc_size + inner_dispatcher_code.size()
		uint32_t outer_bc_size_est = 2 + 2 + 4 + 2; // ENTER(2) + NEST(2+4) + EXIT(2) = 10
		int32_t inner_bc_off = static_cast<int32_t>(
			outer_bc_size_est + inner_dispatcher_code.size());
		bytecode.push_back(inner_bc_off & 0xFF);
		bytecode.push_back((inner_bc_off >> 8) & 0xFF);
		bytecode.push_back((inner_bc_off >> 16) & 0xFF);
		bytecode.push_back((inner_bc_off >> 24) & 0xFF);

		exit_enc = opcode_table.encode(vm_op::VM_EXIT);
		bytecode.push_back(exit_enc & 0xFF);
		bytecode.push_back((exit_enc >> 8) & 0xFF);

		// Context-dependent encoding
		uint32_t outer_ctx_seed = 0;
		if (settings.context_dependent_decoding) {
			std::mt19937 ctx_rng(region_seed ^ 0xDEADC0DE);
			outer_ctx_seed = ctx_rng();
			apply_context_encoding(bytecode, outer_ctx_seed, opcode_table);
		}

		bytecode_size = static_cast<uint32_t>(bytecode.size());

		if (settings.per_region_encryption)
			encrypt_bytecode(bytecode);

		// Set inner dispatcher RVA for the VM_NEST_ENTER handler
		// At runtime: inner dispatcher address = R13 + outer_bc_size
		// But we store it as a RVA from image base for the handler to use.
		// We don't know the absolute RVA here, so let's use a relative scheme.
		// Actually we can make the handler compute: R13 + bytecode_size = inner_disp_addr
		// and call it directly. Let me change the handler to use R13-relative addressing.

		// Wait — the outer VM_NEST_ENTER handler uses: mov rax, <inner_dispatcher_rva>; add rax, r14
		// We need the absolute RVA. But we don't know it here.
		// Let's change the approach: inner dispatcher RVA = bytecode_size offset from R13.
		// Change handler to: lea rax, [r13 + bytecode_size]; call rax
		// But bytecode_size varies... We need it baked into the outer dispatcher.
		// Actually, we can embed it in the VM_NEST_ENTER instruction format.
		//
		// New format: [VM_NEST_ENTER:2] [inner_bc_offset:4]
		// Handler: reads inner_bc_offset, computes inner_bc_addr = R13 + inner_bc_offset
		// But the inner dispatcher is BEFORE the inner bytecode.
		// So we need the inner dispatcher address too.
		//
		// Simplest: change the format to include both:
		// [VM_NEST_ENTER:2] [inner_disp_offset:4] [inner_bc_offset:4]
		// But that changes operand size to 8...
		//
		// Even simpler: call the inner dispatcher entry directly from the inner bytecode.
		// Place the inner dispatcher entry at a known offset from the inner bytecode.
		// Make inner bytecode = [inner_dispatcher_code] + [inner_bytecode]
		// So inner_bc_offset points to: inner_disp_code + inner_bytecode
		// The outer handler does: lea rax, [r13 + inner_bc_offset]; call rax
		// The inner dispatcher entry starts executing, and RSI needs to point past
		// the dispatcher code to the actual inner bytecode.
		//
		// Actually best approach: the inner dispatcher is callable. Its entry point
		// is at the start. It expects RSI = inner bytecode pointer.
		// So we store: inner_disp at R13+disp_off, inner_bc at R13+bc_off
		// The handler sets RSI = R13 + bc_off, then calls R13 + disp_off.
		//
		// New format: [VM_NEST_ENTER:2] [inner_disp_off:4] [inner_bc_off:4] = 10 bytes operand
		// Nah, let's keep it simple with one offset.
		// Just concatenate: [inner_disp][inner_bc] and the offset points to the start.
		// The inner dispatcher's entry knows to skip to bytecode at RSI = entry + disp_size.
		// But the inner dispatcher doesn't know its own size...
		//
		// OK let me just use two offsets. Change operand size to 8.

		// Actually, the cleanest solution: the inner dispatcher code is self-contained.
		// Place it right before the inner bytecode:
		// [inner_disp_code][inner_bytecode]
		// The VM_NEST_ENTER handler:
		//   1. Reads inner_bc_offset (offset to inner bytecode from R13)
		//   2. Sets RSI = R13 + inner_bc_offset (inner bytecode start)
		//   3. Computes inner_disp_addr = RSI - inner_disp_size
		//   4. Calls inner_disp_addr
		// But we don't know inner_disp_size at the handler level...
		//
		// SIMPLEST: embed the inner dispatcher size in the operand.
		// [VM_NEST_ENTER:2] [combined_offset:4]
		// combined_offset points to inner_disp_code. RSI = combined_offset + inner_disp_size.
		// The inner dispatcher entry: RSI is already set by caller.
		// Handler: lea rax, [r13 + combined_offset]; push rsi; lea rsi, [rax + inner_disp_size]; call rax; pop rsi
		// But we still need inner_disp_size somewhere...
		//
		// OK I'll use the format: [VM_NEST_ENTER:2] [inner_blob_offset:4]
		// inner_blob = [JMP skip_disp] [inner_disp_code] [skip_disp:] [inner_bc]
		// The inner blob starts with: lea rsi, [rip + inner_bc_start]; jmp inner_disp_entry
		// No, this gets messy with two separate code blobs.
		//
		// Let me just store inner disp and bc as consecutive data after outer bc,
		// with a small 12-byte trampoline:
		// [trampoline: lea rsi,[rip+inner_bc_rel]; jmp inner_disp_rel]
		// [inner_disp_code]
		// [inner_bytecode]
		// VM_NEST_ENTER points to the trampoline.
		// Handler: lea rax, [r13+offset]; save state; call rax; restore state

		// Let me reconsider. The handler pushes outer state and sets RSI.
		// What if the handler does:
		//   1. Read inner_blob_offset
		//   2. lea rdi, [r13 + inner_blob_offset]  ; start of inner blob
		//   3. Save outer state (push rsi, r12, r13)
		//   4. Set RSI = rdi + inner_disp_size (the inner bytecode)
		//      But inner_disp_size is embedded as the first 4 bytes of the blob!
		//   5. mov eax, [rdi]  ; inner_disp_size
		//   6. lea rsi, [rdi + rax + 4]  ; skip the size field + dispatcher = inner bytecode
		//   7. lea rax, [rdi + 4]  ; inner dispatcher entry
		//   8. call rax

		// Inner blob layout: [inner_disp_size:4] [inner_disp_code] [inner_bytecode]

		// This is clean! Let me implement this.

		// Rebuild outer bytecode with correct layout
		bytecode.clear();
		enter_enc = opcode_table.encode(vm_op::VM_ENTER);
		bytecode.push_back(enter_enc & 0xFF);
		bytecode.push_back((enter_enc >> 8) & 0xFF);

		nest_enc = opcode_table.encode(vm_op::VM_NEST_ENTER);
		bytecode.push_back(nest_enc & 0xFF);
		bytecode.push_back((nest_enc >> 8) & 0xFF);

		// inner_blob starts at: outer_bc_size from R13
		// outer_bc = ENTER(2) + NEST(2+4) + EXIT(2) = 10 bytes
		outer_bc_size_est = 10;
		int32_t inner_blob_offset = static_cast<int32_t>(outer_bc_size_est);
		bytecode.push_back(inner_blob_offset & 0xFF);
		bytecode.push_back((inner_blob_offset >> 8) & 0xFF);
		bytecode.push_back((inner_blob_offset >> 16) & 0xFF);
		bytecode.push_back((inner_blob_offset >> 24) & 0xFF);

		exit_enc = opcode_table.encode(vm_op::VM_EXIT);
		bytecode.push_back(exit_enc & 0xFF);
		bytecode.push_back((exit_enc >> 8) & 0xFF);

		// Context-dependent encoding for outer
		outer_ctx_seed = 0;
		if (settings.context_dependent_decoding) {
			std::mt19937 ctx_rng(region_seed ^ 0xDEADC0DE);
			outer_ctx_seed = ctx_rng();
			apply_context_encoding(bytecode, outer_ctx_seed, opcode_table);
		}

		bytecode_size = static_cast<uint32_t>(bytecode.size());

		if (settings.per_region_encryption)
			encrypt_bytecode(bytecode);

		// Build inner blob: [inner_disp_size:4] [inner_disp_code] [inner_bytecode]
		std::vector<uint8_t> inner_blob;
		uint32_t idisp_sz = static_cast<uint32_t>(inner_dispatcher_code.size());
		inner_blob.push_back(idisp_sz & 0xFF);
		inner_blob.push_back((idisp_sz >> 8) & 0xFF);
		inner_blob.push_back((idisp_sz >> 16) & 0xFF);
		inner_blob.push_back((idisp_sz >> 24) & 0xFF);
		inner_blob.insert(inner_blob.end(), inner_dispatcher_code.begin(), inner_dispatcher_code.end());
		inner_blob.insert(inner_blob.end(), inner_bytecode.begin(), inner_bytecode.end());

		// Outer dispatcher doesn't need inner_dispatcher_rva anymore (handler reads from blob)
		// Generate outer dispatcher
		std::vector<uint8_t> dispatcher_code;
		if (!dispatcher.generate(dispatcher_code, encrypt_key, ENCRYPT_KEY_SIZE, bytecode_size,
			imm_xor_key, &settings, outer_ctx_seed, image_base)) {
			printf("[vm_engine] failed to generate outer dispatcher\n");
			return false;
		}

		// Output layout: [stub:12] [outer_disp] [outer_bc] [inner_blob]
		output.clear();
		uint32_t stub_size = 12;
		uint32_t bytecode_offset_abs = stub_size + static_cast<uint32_t>(dispatcher_code.size());

		int32_t lea_disp = static_cast<int32_t>(bytecode_offset_abs - 7);
		output.push_back(0x48); output.push_back(0x8D); output.push_back(0x0D);
		output.push_back(lea_disp & 0xFF); output.push_back((lea_disp >> 8) & 0xFF);
		output.push_back((lea_disp >> 16) & 0xFF); output.push_back((lea_disp >> 24) & 0xFF);

		int32_t call_disp = static_cast<int32_t>(stub_size - (7 + 5));
		output.push_back(0xE9);
		output.push_back(call_disp & 0xFF); output.push_back((call_disp >> 8) & 0xFF);
		output.push_back((call_disp >> 16) & 0xFF); output.push_back((call_disp >> 24) & 0xFF);

		output.insert(output.end(), dispatcher_code.begin(), dispatcher_code.end());
		output.insert(output.end(), bytecode.begin(), bytecode.end());
		output.insert(output.end(), inner_blob.begin(), inner_blob.end());

		printf("[vm_engine] region #%u [%s+NESTED]: stub=%u outer_disp=%zu outer_bc=%zu inner_disp=%zu inner_bc=%zu total=%zu\n",
			region_counter,
			settings.context_dependent_decoding ? "ULTRA" : "OPTIMIZED",
			stub_size, dispatcher_code.size(), bytecode.size(),
			inner_dispatcher_code.size(), inner_bytecode.size(), output.size());

		return true;
	}

	// --- Normal (non-nested) path ---
	bytecode.clear();
	if (!translator.translate(instructions, bytecode)) {
		printf("[vm_engine] failed to translate instructions\n");
		return false;
	}

	if (settings.control_flow_flattening) {
		vm_cff cff(opcode_table, seed_value);
		if (!cff.flatten(bytecode)) {
			printf("[vm_engine] failed to flatten CFG\n");
			return false;
		}
	}

	// Context-dependent encoding (position-based XOR, after CFF)
	uint32_t context_seed = 0;
	if (settings.context_dependent_decoding) {
		std::mt19937 ctx_rng(region_seed ^ 0xDEADC0DE);
		context_seed = ctx_rng();
		apply_context_encoding(bytecode, context_seed, opcode_table);
	}

	bytecode_size = static_cast<uint32_t>(bytecode.size());

	if (settings.per_region_encryption)
		encrypt_bytecode(bytecode);

	std::vector<uint8_t> dispatcher_code;
	if (!dispatcher.generate(dispatcher_code, encrypt_key, ENCRYPT_KEY_SIZE, bytecode_size,
		imm_xor_key, &settings, context_seed, image_base)) {
		printf("[vm_engine] failed to generate dispatcher\n");
		return false;
	}

	output.clear();

	uint32_t stub_size = 12;
	uint32_t dispatcher_offset = stub_size;
	uint32_t bytecode_offset_abs = stub_size + static_cast<uint32_t>(dispatcher_code.size());

	int32_t lea_disp = static_cast<int32_t>(bytecode_offset_abs - 7);
	// lea rcx, [rip+disp] — load bytecode pointer into RCX.
	// RCX is caller-saved, so for partial regions (entered via CALL) the compiler
	// already assumes RCX was clobbered by the call to CatfuscatorUltra*Begin.
	// NOTE: For future PDB full-function VM (entered via JMP at function start),
	// this clobbers the first parameter. That mode will need a different stub
	// that saves RCX first or uses a scratch register + fixup in the entry handler.
	output.push_back(0x48);
	output.push_back(0x8D);
	output.push_back(0x0D);
	output.push_back(lea_disp & 0xFF);
	output.push_back((lea_disp >> 8) & 0xFF);
	output.push_back((lea_disp >> 16) & 0xFF);
	output.push_back((lea_disp >> 24) & 0xFF);

	int32_t call_disp = static_cast<int32_t>(dispatcher_offset - (7 + 5));
	output.push_back(0xE9);
	output.push_back(call_disp & 0xFF);
	output.push_back((call_disp >> 8) & 0xFF);
	output.push_back((call_disp >> 16) & 0xFF);
	output.push_back((call_disp >> 24) & 0xFF);

	output.insert(output.end(), dispatcher_code.begin(), dispatcher_code.end());
	output.insert(output.end(), bytecode.begin(), bytecode.end());

	printf("[vm_engine] region #%u [%s]: stub=%u dispatcher=%zu bytecode=%zu total=%zu bytes\n",
		region_counter,
		settings.context_dependent_decoding ? "ULTRA" : "OPTIMIZED",
		stub_size, dispatcher_code.size(), bytecode.size(), output.size());

	return true;
}

uint32_t vm_engine::get_dispatcher_size() const {
	return dispatcher.get_dispatcher_size();
}

uint32_t vm_engine::get_bytecode_size() const {
	return bytecode_size;
}
