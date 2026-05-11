#include "vm_cff.h"
#include <algorithm>
#include <map>
#include <set>
#include <cstring>

vm_cff::vm_cff(const vm_opcode_table& table, uint32_t seed)
	: table(table), rng(seed ^ 0xF1A77E40) {}

void vm_cff::emit_u16(std::vector<uint8_t>& bc, uint16_t val) {
	bc.push_back(val & 0xFF);
	bc.push_back((val >> 8) & 0xFF);
}

void vm_cff::emit_i32(std::vector<uint8_t>& bc, int32_t val) {
	uint32_t u = static_cast<uint32_t>(val);
	bc.push_back(u & 0xFF);
	bc.push_back((u >> 8) & 0xFF);
	bc.push_back((u >> 16) & 0xFF);
	bc.push_back((u >> 24) & 0xFF);
}

bool vm_cff::is_jump_op(vm_op op) {
	switch (op) {
	case vm_op::VM_JMP: case vm_op::VM_JZ: case vm_op::VM_JNZ:
	case vm_op::VM_JL: case vm_op::VM_JLE: case vm_op::VM_JG: case vm_op::VM_JGE:
	case vm_op::VM_JB: case vm_op::VM_JBE: case vm_op::VM_JA: case vm_op::VM_JAE:
	case vm_op::VM_JS: case vm_op::VM_JNS: case vm_op::VM_JP: case vm_op::VM_JNP:
		return true;
	default:
		return false;
	}
}

bool vm_cff::is_unconditional_jump(vm_op op) {
	return op == vm_op::VM_JMP;
}

bool vm_cff::is_conditional_jump(vm_op op) {
	return is_jump_op(op) && !is_unconditional_jump(op);
}

bool vm_cff::is_exit_op(vm_op op) {
	return op == vm_op::VM_EXIT || op == vm_op::VM_JMP_REG || op == vm_op::VM_JMP_MEM;
}

int vm_cff::get_instruction_size(const std::vector<uint8_t>& bc, uint32_t offset) {
	if (offset + 2 > bc.size()) return -1;

	// Skip variable-length prefix bytes
	uint32_t pos = offset;
	while (pos + 2 <= bc.size()) {
		uint16_t val = bc[pos] | (bc[pos + 1] << 8);
		if (table.is_prefix(val)) {
			pos += 2;
			continue;
		}
		break;
	}
	if (pos + 2 > bc.size()) return -1;
	int prefix_size = static_cast<int>(pos - offset);

	uint16_t encoded = bc[pos] | (bc[pos + 1] << 8);
	vm_op op = table.decode(encoded);

	int base_size = 0;
	switch (op) {
	// 2 bytes: opcode only
	case vm_op::VM_NOP:
	case vm_op::VM_CDQ: case vm_op::VM_CQO:
	case vm_op::VM_CBW: case vm_op::VM_CWDE: case vm_op::VM_CDQE:
	case vm_op::VM_CWD:
	case vm_op::VM_REP_MOVSB: case vm_op::VM_REP_MOVSW: case vm_op::VM_REP_MOVSD: case vm_op::VM_REP_MOVSQ:
	case vm_op::VM_REP_STOSB: case vm_op::VM_REP_STOSW: case vm_op::VM_REP_STOSD: case vm_op::VM_REP_STOSQ:
	case vm_op::VM_MOVSB: case vm_op::VM_MOVSQ: case vm_op::VM_STOSB: case vm_op::VM_STOSQ:
	case vm_op::VM_REP_SCASB: case vm_op::VM_REPE_CMPSB:
	case vm_op::VM_LEAVE:
	case vm_op::VM_CPUID: case vm_op::VM_RDTSC:
	case vm_op::VM_PAUSE: case vm_op::VM_MFENCE: case vm_op::VM_LFENCE: case vm_op::VM_SFENCE:
	case vm_op::VM_CLC: case vm_op::VM_STC: case vm_op::VM_CMC:
	case vm_op::VM_EXIT:
	case vm_op::VM_ENTER:
		base_size = 2; break;

	// 3 bytes: opcode + reg
	case vm_op::VM_PUSH_REG: case vm_op::VM_POP_REG:
	case vm_op::VM_BSWAP_REG:
	case vm_op::VM_NOT_REG: case vm_op::VM_NEG_REG:
	case vm_op::VM_JMP_REG:
	case vm_op::VM_RELOCATE_REG:
	case vm_op::VM_SETZ_REG: case vm_op::VM_SETNZ_REG:
	case vm_op::VM_SETL_REG: case vm_op::VM_SETLE_REG:
	case vm_op::VM_SETG_REG: case vm_op::VM_SETGE_REG:
	case vm_op::VM_SETB_REG: case vm_op::VM_SETBE_REG:
	case vm_op::VM_SETA_REG: case vm_op::VM_SETAE_REG:
	case vm_op::VM_SETP_REG: case vm_op::VM_SETNP_REG:
	case vm_op::VM_SETS_REG: case vm_op::VM_SETNS_REG:
		base_size = 3; break;

	// 3 bytes: opcode + reg (no size byte)
	case vm_op::VM_IDIV_REG: case vm_op::VM_DIV_REG:
	case vm_op::VM_MUL_REG:
	case vm_op::VM_IMUL_REG:
	case vm_op::VM_SAR_REG_CL: case vm_op::VM_SHL_REG_CL: case vm_op::VM_SHR_REG_CL:
	case vm_op::VM_ROL_REG_CL: case vm_op::VM_ROR_REG_CL:
		base_size = 3; break;

	// 4 bytes: opcode + reg + reg (no size)
	case vm_op::VM_BT_REG_REG: case vm_op::VM_BTS_REG_REG: case vm_op::VM_BTR_REG_REG:
	case vm_op::VM_BTC_REG_REG:
	case vm_op::VM_CRC32_REG_REG:
	case vm_op::VM_BLSI_REG_REG: case vm_op::VM_BLSMSK_REG_REG: case vm_op::VM_BLSR_REG_REG:
	case vm_op::VM_MOV_REG_REG:
	case vm_op::VM_XCHG_REG_REG:
	case vm_op::VM_CMOVZ_REG_REG: case vm_op::VM_CMOVNZ_REG_REG:
	case vm_op::VM_CMOVL_REG_REG: case vm_op::VM_CMOVLE_REG_REG:
	case vm_op::VM_CMOVG_REG_REG: case vm_op::VM_CMOVGE_REG_REG:
	case vm_op::VM_CMOVB_REG_REG: case vm_op::VM_CMOVBE_REG_REG:
	case vm_op::VM_CMOVA_REG_REG: case vm_op::VM_CMOVAE_REG_REG:
	case vm_op::VM_CMOVS_REG_REG: case vm_op::VM_CMOVNS_REG_REG:
	case vm_op::VM_CMOVP_REG_REG: case vm_op::VM_CMOVNP_REG_REG:
	case vm_op::VM_BSF_REG_REG: case vm_op::VM_BSR_REG_REG:
	case vm_op::VM_POPCNT_REG_REG: case vm_op::VM_LZCNT_REG_REG: case vm_op::VM_TZCNT_REG_REG:
	case vm_op::VM_SHLD_REG_REG_CL: case vm_op::VM_SHRD_REG_REG_CL:
		base_size = 4; break;

	// 4 bytes: opcode + reg + imm8 (no size)
	case vm_op::VM_BT_REG_IMM: case vm_op::VM_BTS_REG_IMM: case vm_op::VM_BTR_REG_IMM:
	case vm_op::VM_BTC_REG_IMM:
		base_size = 4; break;

	// 4 bytes: opcode + imm16
	case vm_op::VM_ENTER_FRAME:
		base_size = 4; break;

	// 4 bytes: SSE reg,reg (xmm,xmm or gpr,xmm etc)
	case vm_op::VM_MOVSS_REG_REG: case vm_op::VM_MOVSD_REG_REG:
	case vm_op::VM_MOVAPS_REG_REG: case vm_op::VM_MOVDQA_REG_REG:
	case vm_op::VM_ADDSS_REG_REG: case vm_op::VM_ADDSD_REG_REG:
	case vm_op::VM_SUBSS_REG_REG: case vm_op::VM_SUBSD_REG_REG:
	case vm_op::VM_MULSS_REG_REG: case vm_op::VM_MULSD_REG_REG:
	case vm_op::VM_DIVSS_REG_REG: case vm_op::VM_DIVSD_REG_REG:
	case vm_op::VM_COMISS_REG_REG: case vm_op::VM_COMISD_REG_REG:
	case vm_op::VM_UCOMISS_REG_REG: case vm_op::VM_UCOMISD_REG_REG:
	case vm_op::VM_CVTSI2SS_REG_REG: case vm_op::VM_CVTSI2SD_REG_REG:
	case vm_op::VM_CVTSS2SD_REG_REG: case vm_op::VM_CVTSD2SS_REG_REG:
	case vm_op::VM_CVTSS2SI_REG_REG: case vm_op::VM_CVTSD2SI_REG_REG:
	case vm_op::VM_CVTTSS2SI_REG_REG: case vm_op::VM_CVTTSD2SI_REG_REG:
	case vm_op::VM_XORPS_REG_REG: case vm_op::VM_XORPD_REG_REG:
	case vm_op::VM_ANDPS_REG_REG: case vm_op::VM_ANDPD_REG_REG:
	case vm_op::VM_ORPS_REG_REG: case vm_op::VM_ORPD_REG_REG:
	case vm_op::VM_ANDNPS_REG_REG: case vm_op::VM_ANDNPD_REG_REG:
	case vm_op::VM_ADDPS_REG_REG: case vm_op::VM_ADDPD_REG_REG:
	case vm_op::VM_SUBPS_REG_REG: case vm_op::VM_SUBPD_REG_REG:
	case vm_op::VM_MULPS_REG_REG: case vm_op::VM_MULPD_REG_REG:
	case vm_op::VM_DIVPS_REG_REG: case vm_op::VM_DIVPD_REG_REG:
	case vm_op::VM_MINSS_REG_REG: case vm_op::VM_MAXSS_REG_REG:
	case vm_op::VM_MINSD_REG_REG: case vm_op::VM_MAXSD_REG_REG:
	case vm_op::VM_SQRTSS_REG_REG: case vm_op::VM_SQRTSD_REG_REG:
	case vm_op::VM_UNPCKLPS_REG_REG: case vm_op::VM_UNPCKHPS_REG_REG:
	case vm_op::VM_UNPCKLPD_REG_REG: case vm_op::VM_UNPCKHPD_REG_REG:
	case vm_op::VM_PXOR_REG_REG: case vm_op::VM_PAND_REG_REG:
	case vm_op::VM_POR_REG_REG: case vm_op::VM_PANDN_REG_REG:
	case vm_op::VM_PCMPEQB_REG_REG: case vm_op::VM_PCMPEQD_REG_REG: case vm_op::VM_PCMPGTB_REG_REG:
	case vm_op::VM_PMOVMSKB_REG_REG:
	case vm_op::VM_PADDB_REG_REG: case vm_op::VM_PADDW_REG_REG:
	case vm_op::VM_PADDD_REG_REG: case vm_op::VM_PADDQ_REG_REG:
	case vm_op::VM_PSUBB_REG_REG: case vm_op::VM_PSUBW_REG_REG:
	case vm_op::VM_PSUBD_REG_REG: case vm_op::VM_PSUBQ_REG_REG:
	case vm_op::VM_PUNPCKLBW_REG_REG: case vm_op::VM_PUNPCKHBW_REG_REG:
	case vm_op::VM_PUNPCKLDQ_REG_REG: case vm_op::VM_PUNPCKHDQ_REG_REG:
	case vm_op::VM_PUNPCKLQDQ_REG_REG: case vm_op::VM_PUNPCKHQDQ_REG_REG:
	case vm_op::VM_PSHUFB_REG_REG:
	case vm_op::VM_MOVD_XMM_REG: case vm_op::VM_MOVD_REG_XMM:
	case vm_op::VM_MOVQ_XMM_REG: case vm_op::VM_MOVQ_REG_XMM:
	case vm_op::VM_MOVQ_XMM_XMM:
	case vm_op::VM_PMAXSB_REG_REG: case vm_op::VM_PMAXSD_REG_REG:
	case vm_op::VM_PMINSB_REG_REG: case vm_op::VM_PMINSD_REG_REG:
	case vm_op::VM_PTEST_REG_REG:
	case vm_op::VM_MOVHLPS_REG_REG: case vm_op::VM_MOVLHPS_REG_REG:
		base_size = 4; break;

	// 4 bytes: SSE shift imm: xmm + imm8
	case vm_op::VM_PSLLW_REG_IMM: case vm_op::VM_PSLLD_REG_IMM: case vm_op::VM_PSLLQ_REG_IMM:
	case vm_op::VM_PSRLW_REG_IMM: case vm_op::VM_PSRLD_REG_IMM: case vm_op::VM_PSRLQ_REG_IMM:
	case vm_op::VM_PSRAW_REG_IMM: case vm_op::VM_PSRAD_REG_IMM:
		base_size = 4; break;

	// 5 bytes: opcode + reg + reg + size (ALU reg,reg with size byte)
	case vm_op::VM_ADD_REG_REG: case vm_op::VM_SUB_REG_REG:
	case vm_op::VM_XOR_REG_REG: case vm_op::VM_AND_REG_REG: case vm_op::VM_OR_REG_REG:
	case vm_op::VM_CMP_REG_REG: case vm_op::VM_TEST_REG_REG:
	case vm_op::VM_IMUL_REG_REG:
	case vm_op::VM_ADC_REG_REG: case vm_op::VM_SBB_REG_REG:
		base_size = 5; break;

	// 4 bytes: opcode + reg + imm8 (shift/rotate by immediate, no size byte)
	case vm_op::VM_SHL_REG_IMM: case vm_op::VM_SHR_REG_IMM:
	case vm_op::VM_SAR_REG_IMM:
	case vm_op::VM_ROL_REG_IMM: case vm_op::VM_ROR_REG_IMM:
	case vm_op::VM_RCL_REG_IMM: case vm_op::VM_RCR_REG_IMM:
		base_size = 4; break;

	// 5 bytes: SSE xmm + xmm + imm8
	case vm_op::VM_SHUFPS_REG_REG_IMM: case vm_op::VM_SHUFPD_REG_REG_IMM:
	case vm_op::VM_PSHUFD_REG_REG_IMM:
	case vm_op::VM_PINSRB_REG_REG_IMM: case vm_op::VM_PINSRD_REG_REG_IMM: case vm_op::VM_PINSRQ_REG_REG_IMM:
	case vm_op::VM_PEXTRB_REG_REG_IMM: case vm_op::VM_PEXTRD_REG_REG_IMM: case vm_op::VM_PEXTRQ_REG_REG_IMM:
	case vm_op::VM_ROUNDSS_REG_REG_IMM: case vm_op::VM_ROUNDSD_REG_REG_IMM:
		base_size = 5; break;

	// 5 bytes: BMI 3-operand: dst + src1 + src2
	case vm_op::VM_ANDN_REG_REG_REG: case vm_op::VM_BEXTR_REG_REG_REG:
	case vm_op::VM_PDEP_REG_REG_REG: case vm_op::VM_PEXT_REG_REG_REG:
	case vm_op::VM_BZHI_REG_REG_REG:
	case vm_op::VM_SARX_REG_REG_REG: case vm_op::VM_SHLX_REG_REG_REG: case vm_op::VM_SHRX_REG_REG_REG:
		base_size = 5; break;

	// 6 bytes: opcode + offset32
	case vm_op::VM_NEST_ENTER:
	case vm_op::VM_JMP:
	case vm_op::VM_JZ: case vm_op::VM_JNZ:
	case vm_op::VM_JL: case vm_op::VM_JLE: case vm_op::VM_JG: case vm_op::VM_JGE:
	case vm_op::VM_JB: case vm_op::VM_JBE: case vm_op::VM_JA: case vm_op::VM_JAE:
	case vm_op::VM_JS: case vm_op::VM_JNS: case vm_op::VM_JP: case vm_op::VM_JNP:
		base_size = 6; break;

	// 5 bytes: SHLD/SHRD reg,reg,imm8 (no size byte)
	case vm_op::VM_SHLD_REG_REG_IMM: case vm_op::VM_SHRD_REG_REG_IMM:
		base_size = 5; break;

	// 7 bytes: JMP_MEM: reg + disp32
	case vm_op::VM_JMP_MEM:
		base_size = 7; break;

	// 7 bytes: LOCK unary (INC/DEC): base + disp32
	case vm_op::VM_LOCK_INC_MEM: case vm_op::VM_LOCK_DEC_MEM:
		base_size = 7; break;

	// 7 bytes: CALL_REG_INDIRECT: reg + disp32
	case vm_op::VM_CALL_REG_INDIRECT:
		base_size = 7; break;

	// 7 bytes: opcode + reg + imm32 (no size byte)
	case vm_op::VM_MUL_REG_IMM:
		base_size = 7; break;

	// 8 bytes: opcode + reg + imm32 + size (ALU reg,imm / CMP / TEST)
	case vm_op::VM_ADD_REG_IMM: case vm_op::VM_SUB_REG_IMM:
	case vm_op::VM_XOR_REG_IMM: case vm_op::VM_AND_REG_IMM: case vm_op::VM_OR_REG_IMM:
	case vm_op::VM_CMP_REG_IMM: case vm_op::VM_TEST_REG_IMM:
	case vm_op::VM_ADC_REG_IMM: case vm_op::VM_SBB_REG_IMM:
		base_size = 8; break;

	// 8 bytes: opcode + dst + base + disp32 (LEA, MOVZX, MOVSX, MOVSXD)
	case vm_op::VM_LEA_REG:
	case vm_op::VM_MOVZX_REG_MEM8: case vm_op::VM_MOVZX_REG_MEM16:
	case vm_op::VM_MOVSX_REG_MEM8: case vm_op::VM_MOVSX_REG_MEM16:
	case vm_op::VM_MOVSXD_REG_MEM32:
		base_size = 8; break;

	// 8 bytes: LOCK MEM_REG: base + disp32 + src
	case vm_op::VM_LOCK_XADD_MEM_REG:
	case vm_op::VM_LOCK_ADD_MEM_REG: case vm_op::VM_LOCK_SUB_MEM_REG:
	case vm_op::VM_LOCK_AND_MEM_REG: case vm_op::VM_LOCK_OR_MEM_REG:
	case vm_op::VM_LOCK_XOR_MEM_REG:
		base_size = 8; break;

	// 8 bytes: MOVBE: dst + base + disp32 or base + src + disp32
	case vm_op::VM_MOVBE_REG_MEM: case vm_op::VM_MOVBE_MEM_REG:
		base_size = 8; break;

	// 8 bytes: SSE reg,mem: xmm + base + disp32
	case vm_op::VM_MOVSS_REG_MEM: case vm_op::VM_MOVSD_REG_MEM:
	case vm_op::VM_MOVSS_MEM_REG: case vm_op::VM_MOVSD_MEM_REG:
	case vm_op::VM_MOVAPS_REG_MEM: case vm_op::VM_MOVAPS_MEM_REG:
	case vm_op::VM_MOVUPS_REG_MEM: case vm_op::VM_MOVUPS_MEM_REG:
	case vm_op::VM_MOVDQA_REG_MEM: case vm_op::VM_MOVDQA_MEM_REG:
	case vm_op::VM_MOVDQU_REG_MEM: case vm_op::VM_MOVDQU_MEM_REG:
	case vm_op::VM_ADDSS_REG_MEM: case vm_op::VM_ADDSD_REG_MEM:
	case vm_op::VM_SUBSS_REG_MEM: case vm_op::VM_SUBSD_REG_MEM:
	case vm_op::VM_MULSS_REG_MEM: case vm_op::VM_MULSD_REG_MEM:
	case vm_op::VM_DIVSS_REG_MEM: case vm_op::VM_DIVSD_REG_MEM:
	case vm_op::VM_COMISS_REG_MEM: case vm_op::VM_COMISD_REG_MEM:
	case vm_op::VM_UCOMISS_REG_MEM: case vm_op::VM_UCOMISD_REG_MEM:
	case vm_op::VM_CVTSI2SS_REG_MEM: case vm_op::VM_CVTSI2SD_REG_MEM:
	case vm_op::VM_CVTSS2SD_REG_MEM: case vm_op::VM_CVTSD2SS_REG_MEM:
	case vm_op::VM_XORPS_REG_MEM: case vm_op::VM_XORPD_REG_MEM:
	case vm_op::VM_ANDPS_REG_MEM: case vm_op::VM_ANDPD_REG_MEM:
	case vm_op::VM_ORPS_REG_MEM: case vm_op::VM_ORPD_REG_MEM:
	case vm_op::VM_ANDNPS_REG_MEM: case vm_op::VM_ANDNPD_REG_MEM:
	case vm_op::VM_ADDPS_REG_MEM: case vm_op::VM_ADDPD_REG_MEM:
	case vm_op::VM_SUBPS_REG_MEM: case vm_op::VM_SUBPD_REG_MEM:
	case vm_op::VM_MULPS_REG_MEM: case vm_op::VM_MULPD_REG_MEM:
	case vm_op::VM_DIVPS_REG_MEM: case vm_op::VM_DIVPD_REG_MEM:
	case vm_op::VM_MOVD_XMM_MEM: case vm_op::VM_MOVD_MEM_XMM:
	case vm_op::VM_MOVQ_XMM_MEM: case vm_op::VM_MOVQ_MEM_XMM:
	case vm_op::VM_MOVHPS_REG_MEM: case vm_op::VM_MOVHPS_MEM_REG:
	case vm_op::VM_MOVLPS_REG_MEM: case vm_op::VM_MOVLPS_MEM_REG:
	case vm_op::VM_MOVHPD_REG_MEM: case vm_op::VM_MOVHPD_MEM_REG:
	case vm_op::VM_MOVLPD_REG_MEM: case vm_op::VM_MOVLPD_MEM_REG:
		base_size = 8; break;

	// 9 bytes: MOV_REG_MEM / MOV_MEM_REG: dst/base + base/disp32 + disp32/src + size
	case vm_op::VM_MOV_REG_MEM: case vm_op::VM_MOV_MEM_REG:
		base_size = 9; break;

	// 9 bytes: CMPXCHG: base + disp32 + src + size
	case vm_op::VM_CMPXCHG_MEM_REG:
		base_size = 9; break;

	// 10 bytes: CALL_NATIVE / CALL_NATIVE_RELOC / CALL_IMPORT: addr64
	case vm_op::VM_CALL_NATIVE:
	case vm_op::VM_CALL_NATIVE_RELOC:
	case vm_op::VM_CALL_IMPORT:
		base_size = 10; break;

	// 10 bytes: LEA_SIB: dst + base + index + scale + disp32
	case vm_op::VM_LEA_SIB:
		base_size = 10; break;

	// 11 bytes: MOV_REG_IMM64: reg + imm64
	case vm_op::VM_MOV_REG_IMM64:
		base_size = 11; break;

	// 11 bytes: MOV_REG_SIB / MOV_SIB_REG: various + scale + disp32 + size
	case vm_op::VM_MOV_REG_SIB: case vm_op::VM_MOV_SIB_REG:
		base_size = 11; break;

	// 11 bytes: LOCK MEM_IMM: base + disp32 + imm32
	case vm_op::VM_LOCK_ADD_MEM_IMM: case vm_op::VM_LOCK_SUB_MEM_IMM:
	case vm_op::VM_LOCK_AND_MEM_IMM: case vm_op::VM_LOCK_OR_MEM_IMM:
	case vm_op::VM_LOCK_XOR_MEM_IMM:
		base_size = 11; break;

	default:
		printf("[vm_cff] unhandled op=%d encoded=0x%04x at pos=%u (prefix=%d)\n",
			static_cast<int>(op), encoded, pos, prefix_size);
		return -1;
	}
	return prefix_size + base_size;
}

bool vm_cff::flatten(std::vector<uint8_t>& bytecode) {
	if (bytecode.size() < 4) return true; // too small to bother

	// Step 1: Parse all instructions
	std::vector<bc_inst> instructions;
	uint32_t pos = 0;
	while (pos < bytecode.size()) {
		int sz = get_instruction_size(bytecode, pos);
		if (sz <= 0) {
			printf("[vm_cff] unknown instruction at offset %u\n", pos);
			return false;
		}
		uint32_t op_pos = pos;
		while (op_pos + 2 <= bytecode.size()) {
			uint16_t v = bytecode[op_pos] | (bytecode[op_pos + 1] << 8);
			if (table.is_prefix(v)) { op_pos += 2; continue; }
			break;
		}
		uint16_t encoded = bytecode[op_pos] | (bytecode[op_pos + 1] << 8);
		instructions.push_back({ pos, static_cast<uint32_t>(sz), table.decode(encoded) });
		pos += sz;
	}

	if (instructions.size() < 4) return true;

	// Step 2: Find all jump targets to identify block boundaries
	std::set<uint32_t> block_starts;
	block_starts.insert(0);

	for (auto& inst : instructions) {
		if (is_jump_op(inst.decoded_op)) {
			int32_t rel;
			memcpy(&rel, &bytecode[inst.offset + inst.size - 4], 4);
			uint32_t target = inst.offset + inst.size + rel;
			block_starts.insert(target);

			// Instruction after the jump starts a new block
			uint32_t after = inst.offset + inst.size;
			if (after < bytecode.size())
				block_starts.insert(after);
		}
		if (is_exit_op(inst.decoded_op) || inst.decoded_op == vm_op::VM_CALL_REG_INDIRECT ||
			inst.decoded_op == vm_op::VM_JMP_REG || inst.decoded_op == vm_op::VM_JMP_MEM) {
			uint32_t after = inst.offset + inst.size;
			if (after < bytecode.size())
				block_starts.insert(after);
		}
	}

	// Step 3: Build basic blocks
	std::vector<uint32_t> starts(block_starts.begin(), block_starts.end());
	std::sort(starts.begin(), starts.end());

	// Map: original bytecode offset → block index
	std::map<uint32_t, int> offset_to_block;
	for (int i = 0; i < static_cast<int>(starts.size()); i++)
		offset_to_block[starts[i]] = i;

	std::vector<basic_block> blocks(starts.size());
	for (int i = 0; i < static_cast<int>(starts.size()); i++) {
		uint32_t start = starts[i];
		uint32_t end = (i + 1 < static_cast<int>(starts.size())) ? starts[i + 1] : static_cast<uint32_t>(bytecode.size());

		blocks[i].id = i;
		blocks[i].code.assign(bytecode.begin() + start, bytecode.begin() + end);
		blocks[i].fall_through_id = -1;
		blocks[i].jump_target_id = -1;
		blocks[i].last_inst_size = 0;
		blocks[i].ends_with_uncond_jump = false;
		blocks[i].ends_with_cond_jump = false;
		blocks[i].ends_with_exit = false;

		// Find the last instruction in this block
		bc_inst* last_inst = nullptr;
		for (auto& inst : instructions) {
			if (inst.offset >= start && inst.offset < end)
				last_inst = &inst;
		}
		if (!last_inst) continue;
		blocks[i].last_inst_size = last_inst->size;

		if (is_unconditional_jump(last_inst->decoded_op)) {
			blocks[i].ends_with_uncond_jump = true;
			int32_t rel;
			memcpy(&rel, &bytecode[last_inst->offset + last_inst->size - 4], 4);
			uint32_t target = last_inst->offset + last_inst->size + rel;
			auto it = offset_to_block.find(target);
			if (it != offset_to_block.end())
				blocks[i].jump_target_id = it->second;
		} else if (is_conditional_jump(last_inst->decoded_op)) {
			blocks[i].ends_with_cond_jump = true;
			int32_t rel;
			memcpy(&rel, &bytecode[last_inst->offset + last_inst->size - 4], 4);
			uint32_t target = last_inst->offset + last_inst->size + rel;
			auto it = offset_to_block.find(target);
			if (it != offset_to_block.end())
				blocks[i].jump_target_id = it->second;
			// Fall-through = next block
			if (i + 1 < static_cast<int>(starts.size()))
				blocks[i].fall_through_id = i + 1;
		} else if (is_exit_op(last_inst->decoded_op) || last_inst->decoded_op == vm_op::VM_CALL_REG_INDIRECT ||
			last_inst->decoded_op == vm_op::VM_JMP_REG || last_inst->decoded_op == vm_op::VM_JMP_MEM) {
			blocks[i].ends_with_exit = true;
		} else {
			// Falls through to next block
			if (i + 1 < static_cast<int>(starts.size()))
				blocks[i].fall_through_id = i + 1;
		}
	}

	if (blocks.size() < 3) return true; // not enough blocks to shuffle

	// Step 4: Create shuffled order (keep block 0 first for entry)
	std::vector<int> order(blocks.size());
	for (int i = 0; i < static_cast<int>(order.size()); i++)
		order[i] = i;
	// Shuffle everything except the first block
	if (order.size() > 2)
		std::shuffle(order.begin() + 1, order.end(), rng);

	// Map: original block id → position in shuffled output
	std::vector<int> block_position(blocks.size());
	for (int i = 0; i < static_cast<int>(order.size()); i++)
		block_position[order[i]] = i;

	// Step 5: Build new bytecode
	// First pass: determine the new code for each block (original code + added JMPs)
	// We need to:
	// a) For blocks ending with unconditional JMP: keep the JMP but fix the offset
	// b) For blocks ending with conditional JCC: keep the JCC (fix offset) + add JMP for fall-through
	// c) For blocks with fall-through only: add JMP to successor

	uint16_t jmp_opcode = table.encode(vm_op::VM_JMP);

	struct output_block {
		std::vector<uint8_t> code;
		// Patches: offset within this block's code → target block id
		struct patch { uint32_t offset; int target_block; };
		std::vector<patch> patches;
	};

	std::vector<output_block> out_blocks(blocks.size());

	for (int i = 0; i < static_cast<int>(blocks.size()); i++) {
		auto& blk = blocks[i];
		auto& out = out_blocks[i];
		out.code = blk.code;

		if (blk.ends_with_uncond_jump && blk.jump_target_id >= 0) {
			if (out.code.size() >= blk.last_inst_size) {
				out.code.resize(out.code.size() - blk.last_inst_size);
			}
			uint32_t patch_off = static_cast<uint32_t>(out.code.size()) + 2;
			emit_u16(out.code, jmp_opcode);
			emit_i32(out.code, 0); // placeholder
			out.patches.push_back({ patch_off, blk.jump_target_id });
		} else if (blk.ends_with_cond_jump) {
			// Keep conditional JMP but fix its offset
			if (out.code.size() >= 6 && blk.jump_target_id >= 0) {
				uint32_t jcc_patch = static_cast<uint32_t>(out.code.size()) - 4;
				out.patches.push_back({ jcc_patch, blk.jump_target_id });
				// Zero out old offset
				memset(&out.code[jcc_patch], 0, 4);
			}
			// Add unconditional JMP for fall-through
			if (blk.fall_through_id >= 0) {
				uint32_t patch_off = static_cast<uint32_t>(out.code.size()) + 2;
				emit_u16(out.code, jmp_opcode);
				emit_i32(out.code, 0);
				out.patches.push_back({ patch_off, blk.fall_through_id });
			}
		} else if (blk.fall_through_id >= 0 && !blk.ends_with_exit) {
			// Add JMP to successor
			uint32_t patch_off = static_cast<uint32_t>(out.code.size()) + 2;
			emit_u16(out.code, jmp_opcode);
			emit_i32(out.code, 0);
			out.patches.push_back({ patch_off, blk.fall_through_id });
		}
	}

	// Step 6: Compute final offsets and assemble
	// Layout blocks in shuffled order
	std::vector<uint32_t> block_offsets(blocks.size());
	uint32_t total = 0;
	for (int i = 0; i < static_cast<int>(order.size()); i++) {
		block_offsets[order[i]] = total;
		total += static_cast<uint32_t>(out_blocks[order[i]].code.size());
	}

	// Step 7: Patch all jump offsets
	for (int i = 0; i < static_cast<int>(blocks.size()); i++) {
		auto& out = out_blocks[i];
		uint32_t my_base = block_offsets[i];
		for (auto& p : out.patches) {
			uint32_t target_abs = block_offsets[p.target_block];
			uint32_t patch_abs = my_base + p.offset;
			int32_t rel = static_cast<int32_t>(target_abs) - static_cast<int32_t>(patch_abs + 4);
			memcpy(&out.code[p.offset], &rel, 4);
		}
	}

	// Step 8: Assemble final bytecode
	std::vector<uint8_t> result;
	result.reserve(total);
	for (int i = 0; i < static_cast<int>(order.size()); i++) {
		auto& code = out_blocks[order[i]].code;
		result.insert(result.end(), code.begin(), code.end());
	}

	printf("[vm_cff] flattened: %zu blocks, %zu -> %zu bytes\n",
		blocks.size(), bytecode.size(), result.size());
	bytecode = std::move(result);
	return true;
}
