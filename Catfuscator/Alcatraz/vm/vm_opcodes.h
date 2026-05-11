#pragma once
#include <cstdint>
#include <vector>
#include <random>
#include <algorithm>
#include <numeric>

// VM opcode definitions
// At build time, opcode values are shuffled so each protected binary has a unique encoding

enum class vm_op : uint16_t {
	VM_NOP = 0,
	VM_MOV_REG_IMM64,    // mov vreg, imm64
	VM_MOV_REG_REG,      // mov vreg, vreg
	VM_MOV_REG_MEM,      // mov vreg, [vreg + disp]
	VM_MOV_MEM_REG,      // mov [vreg + disp], vreg
	VM_ADD_REG_REG,      // add vreg, vreg
	VM_ADD_REG_IMM,      // add vreg, imm32
	VM_SUB_REG_REG,      // sub vreg, vreg
	VM_SUB_REG_IMM,      // sub vreg, imm32
	VM_XOR_REG_REG,      // xor vreg, vreg
	VM_XOR_REG_IMM,      // xor vreg, imm32
	VM_AND_REG_REG,      // and vreg, vreg
	VM_AND_REG_IMM,      // and vreg, imm32
	VM_OR_REG_REG,       // or vreg, vreg
	VM_OR_REG_IMM,       // or vreg, imm32
	VM_NOT_REG,          // not vreg
	VM_NEG_REG,          // neg vreg
	VM_SHL_REG_IMM,      // shl vreg, imm8
	VM_SHR_REG_IMM,      // shr vreg, imm8
	VM_CMP_REG_REG,      // cmp vreg, vreg (sets VM flags)
	VM_CMP_REG_IMM,      // cmp vreg, imm32
	VM_TEST_REG_REG,     // test vreg, vreg
	VM_JMP,              // jmp vm_offset
	VM_JZ,               // jz vm_offset
	VM_JNZ,              // jnz vm_offset
	VM_JL,               // jl vm_offset (signed <)
	VM_JLE,              // jle vm_offset
	VM_JG,               // jg vm_offset (signed >)
	VM_JGE,              // jge vm_offset
	VM_JB,               // jb vm_offset (unsigned <)
	VM_JBE,              // jbe vm_offset
	VM_JA,               // ja vm_offset (unsigned >)
	VM_JAE,              // jae vm_offset
	VM_PUSH_REG,         // push vreg onto real stack
	VM_POP_REG,          // pop from real stack into vreg
	VM_CALL_NATIVE,      // call native address (imm64)
	VM_LEA_REG,          // lea vreg, [vreg + disp]
	VM_IMUL_REG_REG,     // imul vreg, vreg
	VM_MUL_REG_IMM,      // imul vreg, imm32
	VM_CDQ,              // sign-extend EAX → EDX:EAX
	VM_CQO,              // sign-extend RAX → RDX:RAX
	VM_IDIV_REG,         // idiv vreg (RDX:RAX / vreg)
	VM_DIV_REG,          // div vreg (RDX:RAX / vreg)
	VM_CMOVZ_REG_REG,   // cmovz dst, src
	VM_CMOVNZ_REG_REG,
	VM_CMOVL_REG_REG,
	VM_CMOVLE_REG_REG,
	VM_CMOVG_REG_REG,
	VM_CMOVGE_REG_REG,
	VM_CMOVB_REG_REG,
	VM_CMOVBE_REG_REG,
	VM_CMOVA_REG_REG,
	VM_CMOVAE_REG_REG,
	VM_CMOVS_REG_REG,
	VM_CMOVNS_REG_REG,
	VM_SETZ_REG,         // setz vreg (set byte)
	VM_SETNZ_REG,
	VM_SETL_REG,
	VM_SETLE_REG,
	VM_SETG_REG,
	VM_SETGE_REG,
	VM_SETB_REG,
	VM_SETBE_REG,
	VM_SETA_REG,
	VM_SETAE_REG,
	VM_MOVZX_REG_MEM8,  // movzx vreg, byte [vreg + disp]
	VM_MOVZX_REG_MEM16, // movzx vreg, word [vreg + disp]
	VM_MOVSX_REG_MEM8,  // movsx vreg, byte [vreg + disp]
	VM_MOVSX_REG_MEM16, // movsx vreg, word [vreg + disp]
	VM_MOVSXD_REG_MEM32,// movsxd vreg, dword [vreg + disp]
	VM_TEST_REG_IMM,     // test vreg, imm32
	// Sign extension
	VM_CBW,              // AL → AX
	VM_CWDE,             // AX → EAX
	VM_CDQE,             // EAX → RAX
	// Unsigned multiply
	VM_MUL_REG,          // mul vreg (RDX:RAX = RAX * vreg)
	// Rotation
	VM_ROL_REG_IMM,      // rol vreg, imm8
	VM_ROR_REG_IMM,      // ror vreg, imm8
	VM_RCL_REG_IMM,      // rcl vreg, imm8
	VM_RCR_REG_IMM,      // rcr vreg, imm8
	// Bit operations
	VM_BT_REG_REG,       // bt vreg, vreg
	VM_BT_REG_IMM,       // bt vreg, imm8
	VM_BTS_REG_REG,      // bts vreg, vreg
	VM_BTS_REG_IMM,      // bts vreg, imm8
	VM_BTR_REG_REG,      // btr vreg, vreg
	VM_BTR_REG_IMM,      // btr vreg, imm8
	VM_BSF_REG_REG,      // bsf vreg, vreg
	VM_BSR_REG_REG,      // bsr vreg, vreg
	VM_POPCNT_REG_REG,   // popcnt vreg, vreg
	VM_LZCNT_REG_REG,    // lzcnt vreg, vreg
	VM_TZCNT_REG_REG,    // tzcnt vreg, vreg
	// String operations (use VRSI, VRDI, VRCX implicitly)
	VM_REP_MOVSB,        // rep movsb
	VM_REP_MOVSW,        // rep movsw
	VM_REP_MOVSD,        // rep movsd
	VM_REP_MOVSQ,        // rep movsq
	VM_REP_STOSB,        // rep stosb
	VM_REP_STOSW,        // rep stosw
	VM_REP_STOSD,        // rep stosd
	VM_REP_STOSQ,        // rep stosq
	VM_MOVSB,            // movsb (single)
	VM_MOVSQ,            // movsq (single)
	VM_STOSB,            // stosb (single)
	VM_STOSQ,            // stosq (single)
	VM_REP_SCASB,        // rep scasb / repne scasb
	VM_REPE_CMPSB,       // repe cmpsb
	// Arithmetic shift right (distinct from logical SHR)
	VM_SAR_REG_IMM,      // sar vreg, imm8
	VM_SAR_REG_CL,       // sar vreg (shift by VRCX low byte)
	VM_SHL_REG_CL,       // shl vreg (shift by VRCX low byte)
	VM_SHR_REG_CL,       // shr vreg (shift by VRCX low byte)
	// SIB addressing: [base + index*scale + disp]
	VM_MOV_REG_SIB,      // mov vreg, [base + index*scale + disp] (size)
	VM_MOV_SIB_REG,      // mov [base + index*scale + disp], vreg (size)
	VM_LEA_SIB,          // lea vreg, [base + index*scale + disp]
	// Carry arithmetic
	VM_ADC_REG_REG,      // adc vreg, vreg
	VM_ADC_REG_IMM,      // adc vreg, imm32
	VM_SBB_REG_REG,      // sbb vreg, vreg
	VM_SBB_REG_IMM,      // sbb vreg, imm32
	// Misc
	VM_XCHG_REG_REG,     // xchg vreg, vreg
	VM_LEAVE,            // mov rsp,rbp; pop rbp
	VM_CALL_REG_INDIRECT,// call [vreg + disp] (memory indirect)
	VM_BTC_REG_REG,      // btc vreg, vreg
	VM_BTC_REG_IMM,      // btc vreg, imm8
	VM_BSWAP_REG,        // bswap vreg
	// Sign jumps
	VM_JS,               // js vm_offset
	VM_JNS,              // jns vm_offset
	// Rotation by CL
	VM_ROL_REG_CL,       // rol vreg (by CL)
	VM_ROR_REG_CL,       // ror vreg (by CL)
	// Parity
	VM_JP,               // jp vm_offset
	VM_JNP,              // jnp vm_offset
	VM_CMOVP_REG_REG,    // cmovp dst, src
	VM_CMOVNP_REG_REG,   // cmovnp dst, src
	VM_SETP_REG,         // setp vreg
	VM_SETNP_REG,        // setnp vreg
	VM_SETS_REG,         // sets vreg
	VM_SETNS_REG,        // setns vreg
	// CWD (16-bit sign extend AX → DX:AX)
	VM_CWD,
	// Indirect jumps
	VM_JMP_REG,          // jmp vreg
	VM_JMP_MEM,          // jmp [vreg + disp]
	// Single-operand signed multiply
	VM_IMUL_REG,         // imul vreg (RDX:RAX = RAX * vreg, signed)
	// Double-precision shift
	VM_SHLD_REG_REG_IMM, // shld dst, src, imm8
	VM_SHRD_REG_REG_IMM, // shrd dst, src, imm8
	VM_SHLD_REG_REG_CL,  // shld dst, src, cl
	VM_SHRD_REG_REG_CL,  // shrd dst, src, cl
	// === SSE scalar float ===
	VM_MOVSS_REG_REG,    // movss xmm, xmm
	VM_MOVSS_REG_MEM,    // movss xmm, [vreg + disp]
	VM_MOVSS_MEM_REG,    // movss [vreg + disp], xmm
	VM_MOVSD_REG_REG,    // movsd xmm, xmm
	VM_MOVSD_REG_MEM,    // movsd xmm, [vreg + disp]
	VM_MOVSD_MEM_REG,    // movsd [vreg + disp], xmm
	VM_ADDSS_REG_REG,    // addss xmm, xmm
	VM_ADDSS_REG_MEM,    // addss xmm, [vreg + disp]
	VM_ADDSD_REG_REG,    // addsd xmm, xmm
	VM_ADDSD_REG_MEM,    // addsd xmm, [vreg + disp]
	VM_SUBSS_REG_REG,
	VM_SUBSS_REG_MEM,
	VM_SUBSD_REG_REG,
	VM_SUBSD_REG_MEM,
	VM_MULSS_REG_REG,
	VM_MULSS_REG_MEM,
	VM_MULSD_REG_REG,
	VM_MULSD_REG_MEM,
	VM_DIVSS_REG_REG,
	VM_DIVSS_REG_MEM,
	VM_DIVSD_REG_REG,
	VM_DIVSD_REG_MEM,
	// SSE compare
	VM_COMISS_REG_REG,   // comiss xmm, xmm (sets EFLAGS)
	VM_COMISS_REG_MEM,
	VM_COMISD_REG_REG,   // comisd xmm, xmm
	VM_COMISD_REG_MEM,
	VM_UCOMISS_REG_REG,
	VM_UCOMISS_REG_MEM,
	VM_UCOMISD_REG_REG,
	VM_UCOMISD_REG_MEM,
	// SSE conversion
	VM_CVTSI2SS_REG_REG, // cvtsi2ss xmm, reg
	VM_CVTSI2SD_REG_REG, // cvtsi2sd xmm, reg
	VM_CVTSS2SD_REG_REG, // cvtss2sd xmm, xmm
	VM_CVTSD2SS_REG_REG, // cvtsd2ss xmm, xmm
	VM_CVTSS2SI_REG_REG, // cvtss2si reg, xmm
	VM_CVTSD2SI_REG_REG, // cvtsd2si reg, xmm
	VM_CVTTSS2SI_REG_REG,// cvttss2si reg, xmm (truncate)
	VM_CVTTSD2SI_REG_REG,// cvttsd2si reg, xmm (truncate)
	VM_CVTSI2SS_REG_MEM, // cvtsi2ss xmm, [mem]
	VM_CVTSI2SD_REG_MEM, // cvtsi2sd xmm, [mem]
	VM_CVTSS2SD_REG_MEM,
	VM_CVTSD2SS_REG_MEM,
	// SSE packed
	VM_MOVAPS_REG_REG,   // movaps xmm, xmm
	VM_MOVAPS_REG_MEM,   // movaps xmm, [mem]
	VM_MOVAPS_MEM_REG,   // movaps [mem], xmm
	VM_MOVUPS_REG_MEM,   // movups xmm, [mem]
	VM_MOVUPS_MEM_REG,   // movups [mem], xmm
	VM_MOVDQA_REG_REG,
	VM_MOVDQA_REG_MEM,
	VM_MOVDQA_MEM_REG,
	VM_MOVDQU_REG_MEM,
	VM_MOVDQU_MEM_REG,
	// SSE bitwise
	VM_XORPS_REG_REG,    // xorps xmm, xmm
	VM_XORPS_REG_MEM,
	VM_XORPD_REG_REG,
	VM_XORPD_REG_MEM,
	VM_ANDPS_REG_REG,
	VM_ANDPS_REG_MEM,
	VM_ANDPD_REG_REG,
	VM_ANDPD_REG_MEM,
	VM_ORPS_REG_REG,
	VM_ORPS_REG_MEM,
	VM_ORPD_REG_REG,
	VM_ORPD_REG_MEM,
	VM_ANDNPS_REG_REG,
	VM_ANDNPS_REG_MEM,
	VM_ANDNPD_REG_REG,
	VM_ANDNPD_REG_MEM,
	// SSE packed arithmetic
	VM_ADDPS_REG_REG,
	VM_ADDPS_REG_MEM,
	VM_ADDPD_REG_REG,
	VM_ADDPD_REG_MEM,
	VM_SUBPS_REG_REG,
	VM_SUBPS_REG_MEM,
	VM_SUBPD_REG_REG,
	VM_SUBPD_REG_MEM,
	VM_MULPS_REG_REG,
	VM_MULPS_REG_MEM,
	VM_MULPD_REG_REG,
	VM_MULPD_REG_MEM,
	VM_DIVPS_REG_REG,
	VM_DIVPS_REG_MEM,
	VM_DIVPD_REG_REG,
	VM_DIVPD_REG_MEM,
	// SSE min/max/sqrt
	VM_MINSS_REG_REG,
	VM_MAXSS_REG_REG,
	VM_MINSD_REG_REG,
	VM_MAXSD_REG_REG,
	VM_SQRTSS_REG_REG,
	VM_SQRTSD_REG_REG,
	// SSE shuffle/unpack
	VM_SHUFPS_REG_REG_IMM,
	VM_SHUFPD_REG_REG_IMM,
	VM_UNPCKLPS_REG_REG,
	VM_UNPCKHPS_REG_REG,
	VM_UNPCKLPD_REG_REG,
	VM_UNPCKHPD_REG_REG,
	// SSE integer
	VM_PXOR_REG_REG,
	VM_PAND_REG_REG,
	VM_POR_REG_REG,
	VM_PANDN_REG_REG,
	VM_PCMPEQB_REG_REG,
	VM_PCMPEQD_REG_REG,
	VM_PCMPGTB_REG_REG,
	VM_PMOVMSKB_REG_REG, // pmovmskb gpr, xmm
	VM_PADDB_REG_REG,
	VM_PADDW_REG_REG,
	VM_PADDD_REG_REG,
	VM_PADDQ_REG_REG,
	VM_PSUBB_REG_REG,
	VM_PSUBW_REG_REG,
	VM_PSUBD_REG_REG,
	VM_PSUBQ_REG_REG,
	VM_PSLLW_REG_IMM,
	VM_PSLLD_REG_IMM,
	VM_PSLLQ_REG_IMM,
	VM_PSRLW_REG_IMM,
	VM_PSRLD_REG_IMM,
	VM_PSRLQ_REG_IMM,
	VM_PSRAW_REG_IMM,
	VM_PSRAD_REG_IMM,
	VM_PUNPCKLBW_REG_REG,
	VM_PUNPCKHBW_REG_REG,
	VM_PUNPCKLDQ_REG_REG,
	VM_PUNPCKHDQ_REG_REG,
	VM_PUNPCKLQDQ_REG_REG,
	VM_PUNPCKHQDQ_REG_REG,
	VM_PSHUFD_REG_REG_IMM,
	VM_PSHUFB_REG_REG,
	VM_MOVD_XMM_REG,     // movd xmm, gpr32
	VM_MOVD_REG_XMM,     // movd gpr32, xmm
	VM_MOVQ_XMM_REG,     // movq xmm, gpr64
	VM_MOVQ_REG_XMM,     // movq gpr64, xmm
	VM_MOVD_XMM_MEM,     // movd xmm, [mem]
	VM_MOVD_MEM_XMM,     // movd [mem], xmm
	VM_MOVQ_XMM_MEM,     // movq xmm, [mem]
	VM_MOVQ_MEM_XMM,     // movq [mem], xmm
	VM_MOVQ_XMM_XMM,     // movq xmm, xmm
	// SSE4.1
	VM_PINSRB_REG_REG_IMM,
	VM_PINSRD_REG_REG_IMM,
	VM_PINSRQ_REG_REG_IMM,
	VM_PEXTRB_REG_REG_IMM,
	VM_PEXTRD_REG_REG_IMM,
	VM_PEXTRQ_REG_REG_IMM,
	VM_ROUNDSS_REG_REG_IMM,
	VM_ROUNDSD_REG_REG_IMM,
	VM_PMAXSB_REG_REG,
	VM_PMAXSD_REG_REG,
	VM_PMINSB_REG_REG,
	VM_PMINSD_REG_REG,
	VM_PTEST_REG_REG,    // ptest xmm, xmm (sets ZF/CF)
	VM_MOVHLPS_REG_REG,
	VM_MOVLHPS_REG_REG,
	VM_MOVHPS_REG_MEM,
	VM_MOVHPS_MEM_REG,
	VM_MOVLPS_REG_MEM,
	VM_MOVLPS_MEM_REG,
	VM_MOVHPD_REG_MEM,
	VM_MOVHPD_MEM_REG,
	VM_MOVLPD_REG_MEM,
	VM_MOVLPD_MEM_REG,
	// CMPXCHG / LOCK prefix
	VM_CMPXCHG_MEM_REG,  // lock cmpxchg [mem], reg
	VM_LOCK_XADD_MEM_REG,// lock xadd [mem], reg
	VM_LOCK_INC_MEM,     // lock inc [mem]
	VM_LOCK_DEC_MEM,     // lock dec [mem]
	VM_LOCK_ADD_MEM_REG, // lock add [mem], reg
	VM_LOCK_ADD_MEM_IMM, // lock add [mem], imm
	VM_LOCK_SUB_MEM_REG,
	VM_LOCK_SUB_MEM_IMM,
	VM_LOCK_AND_MEM_REG,
	VM_LOCK_AND_MEM_IMM,
	VM_LOCK_OR_MEM_REG,
	VM_LOCK_OR_MEM_IMM,
	VM_LOCK_XOR_MEM_REG,
	VM_LOCK_XOR_MEM_IMM,
	// Misc
	VM_CPUID,
	VM_RDTSC,
	VM_PAUSE,
	VM_MFENCE,
	VM_LFENCE,
	VM_SFENCE,
	VM_CLC,
	VM_STC,
	VM_CMC,
	VM_ENTER_FRAME,       // enter imm16, 0
	VM_MOVBE_REG_MEM,    // movbe reg, [mem]
	VM_MOVBE_MEM_REG,    // movbe [mem], reg
	VM_CRC32_REG_REG,    // crc32 reg, reg
	// BMI
	VM_ANDN_REG_REG_REG, // andn dst, src1, src2
	VM_BEXTR_REG_REG_REG,
	VM_BLSI_REG_REG,
	VM_BLSMSK_REG_REG,
	VM_BLSR_REG_REG,
	VM_PDEP_REG_REG_REG,
	VM_PEXT_REG_REG_REG,
	VM_BZHI_REG_REG_REG,
	VM_SARX_REG_REG_REG,
	VM_SHLX_REG_REG_REG,
	VM_SHRX_REG_REG_REG,

	// ASLR relocation support
	VM_RELOCATE_REG,     // vreg += runtime image base (R14)
	VM_CALL_NATIVE_RELOC,// call native by RVA: target = (imm64 ^ key) + image_base

	// Import obfuscation
	VM_CALL_IMPORT,      // call by hash: [dll_hash:4] [func_hash:4] — PEB-walk resolve

	// VM nesting
	VM_NEST_ENTER,       // enter inner VM: [inner_bc_offset:4] — offset from outer bytecode base

	VM_ENTER,            // save real registers -> VM context
	VM_EXIT,             // restore real registers <- VM context, return to native
	VM_COUNT
};

// Virtual register indices (map to x86-64 registers)
enum class vm_reg : uint8_t {
	// GP registers (8 bytes each, offsets 0..16 * 8)
	VRAX = 0, VRCX, VRDX, VRBX,
	VRSP, VRBP, VRSI, VRDI,
	VR8,  VR9,  VR10, VR11,
	VR12, VR13, VR14, VR15,
	VRFLAGS,
	GP_COUNT, // 17 GP regs

	// XMM registers (128-bit / 16 bytes each)
	VXMM0 = GP_COUNT, VXMM1, VXMM2, VXMM3,
	VXMM4, VXMM5, VXMM6, VXMM7,
	VXMM8, VXMM9, VXMM10, VXMM11,
	VXMM12, VXMM13, VXMM14, VXMM15,
	VREG_COUNT // 17 GP + 16 XMM = 33
};

// GP reg offset: reg_index * 8 (0..136)
// XMM reg offset: GP_COUNT * 8 + (xmm_index - GP_COUNT) * 16
inline constexpr int vm_gp_offset(int reg_idx) { return reg_idx * 8; }
inline constexpr int vm_xmm_offset(int xmm_idx) {
	return static_cast<int>(vm_reg::GP_COUNT) * 8 + (xmm_idx - static_cast<int>(vm_reg::GP_COUNT)) * 16;
}
// Total register file size: 17*8 + 16*16 = 136 + 256 = 392 bytes (round to 400 for alignment)
inline constexpr int VM_REG_FILE_TOTAL = static_cast<int>(vm_reg::GP_COUNT) * 8 + 16 * 16;

struct vm_opcode_table {
	static constexpr int OP_COUNT = static_cast<int>(vm_op::VM_COUNT);

	static constexpr int DUP_COPIES = 2;
	static constexpr int NUM_DUP_OPS = 20;
	static constexpr int TOTAL_DUPS = NUM_DUP_OPS * DUP_COPIES;
	static constexpr int TOTAL_ENCODED = OP_COUNT + TOTAL_DUPS;

	uint16_t mapping[OP_COUNT];
	uint16_t reverse[TOTAL_ENCODED];
	uint8_t gp_perm[16];
	static constexpr int NUM_PREFIXES = 16;
	uint16_t prefix_values[NUM_PREFIXES];

	uint16_t dup_encoded[TOTAL_DUPS];
	int dup_original[TOTAL_DUPS];

	static constexpr int dup_op_list[NUM_DUP_OPS] = {
		(int)vm_op::VM_MOV_REG_IMM64, (int)vm_op::VM_MOV_REG_REG,
		(int)vm_op::VM_MOV_REG_MEM,   (int)vm_op::VM_MOV_MEM_REG,
		(int)vm_op::VM_ADD_REG_REG,   (int)vm_op::VM_ADD_REG_IMM,
		(int)vm_op::VM_SUB_REG_REG,   (int)vm_op::VM_SUB_REG_IMM,
		(int)vm_op::VM_XOR_REG_REG,   (int)vm_op::VM_AND_REG_REG,
		(int)vm_op::VM_OR_REG_REG,
		(int)vm_op::VM_CMP_REG_REG,   (int)vm_op::VM_CMP_REG_IMM,
		(int)vm_op::VM_TEST_REG_REG,
		(int)vm_op::VM_JMP,            (int)vm_op::VM_JZ,
		(int)vm_op::VM_JNZ,
		(int)vm_op::VM_PUSH_REG,       (int)vm_op::VM_POP_REG,
		(int)vm_op::VM_LEA_REG,
	};

	void randomize(uint32_t seed) {
		std::mt19937 rng(seed);

		for (int d = 0; d < TOTAL_DUPS; d++)
			dup_original[d] = dup_op_list[d / DUP_COPIES];

		std::vector<uint16_t> pool(TOTAL_ENCODED);
		std::iota(pool.begin(), pool.end(), static_cast<uint16_t>(0));
		std::shuffle(pool.begin(), pool.end(), rng);

		for (int i = 0; i < OP_COUNT; i++)
			mapping[i] = pool[i];
		for (int i = 0; i < TOTAL_DUPS; i++)
			dup_encoded[i] = pool[OP_COUNT + i];

		memset(reverse, 0xFF, sizeof(reverse));
		for (int i = 0; i < OP_COUNT; i++)
			reverse[mapping[i]] = static_cast<uint16_t>(i);
		for (int i = 0; i < TOTAL_DUPS; i++)
			reverse[dup_encoded[i]] = static_cast<uint16_t>(dup_original[i]);

		for (int i = 0; i < 16; i++) gp_perm[i] = static_cast<uint8_t>(i);
		std::shuffle(gp_perm, gp_perm + 16, rng);

		int prange = 65536 - TOTAL_ENCODED;
		std::vector<uint16_t> ppool(prange);
		std::iota(ppool.begin(), ppool.end(), static_cast<uint16_t>(TOTAL_ENCODED));
		std::shuffle(ppool.begin(), ppool.end(), rng);
		for (int i = 0; i < NUM_PREFIXES; i++)
			prefix_values[i] = ppool[i];
	}

	bool is_prefix(uint16_t val) const {
		return val >= TOTAL_ENCODED;
	}

	uint16_t encode(vm_op op) const {
		return mapping[static_cast<int>(op)];
	}

	uint16_t encode_random(vm_op op, std::mt19937& rng) const {
		int idx = static_cast<int>(op);
		uint16_t options[1 + DUP_COPIES];
		int count = 1;
		options[0] = mapping[idx];
		for (int d = 0; d < TOTAL_DUPS; d++) {
			if (dup_original[d] == idx)
				options[count++] = dup_encoded[d];
		}
		return options[rng() % count];
	}

	vm_op decode(uint16_t encoded) const {
		if (encoded >= TOTAL_ENCODED) return vm_op::VM_COUNT;
		return static_cast<vm_op>(reverse[encoded]);
	}

	void reshuffle_gp_perm(uint32_t region_seed) {
		std::mt19937 rng(region_seed ^ 0xABCD1234);
		for (int i = 0; i < 16; i++) gp_perm[i] = static_cast<uint8_t>(i);
		std::shuffle(gp_perm, gp_perm + 16, rng);
	}

	int perm_gp_off(vm_reg r) const {
		int idx = static_cast<int>(r);
		return (idx < 16) ? gp_perm[idx] * 8 : idx * 8;
	}

	int perm_gp_off(int idx) const {
		return (idx < 16) ? gp_perm[idx] * 8 : idx * 8;
	}
};
