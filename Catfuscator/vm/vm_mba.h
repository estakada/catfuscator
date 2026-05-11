#pragma once
#include <asmjit/asmjit.h>
#include <random>
#include <cstdint>

// Mixed Boolean-Arithmetic (MBA) expression generator
// Replaces simple ALU operations with equivalent but hard-to-simplify expressions
// These defeat LLVM-based deobfuscation (Mergen, Triton, etc.)

class vm_mba {
public:
	vm_mba(std::mt19937& rng) : rng(rng) {}

	// MBA substitutions for binary operations
	// All take: dst = op(rax, r8), result in rax. Clobbers rdx, r10, r11.

	// x + y = (x ^ y) + 2*(x & y)
	// x + y = (x | y) + (x & y)
	// x + y = 2*(x | y) - (x ^ y)
	void emit_mba_add_64(asmjit::x86::Assembler& a);
	void emit_mba_add_32(asmjit::x86::Assembler& a);

	// x - y = (x ^ y) - 2*(~x & y)
	// x - y = (x & ~y) - (~x & y)
	// x - y = 2*(x & ~y) - (x ^ y)
	void emit_mba_sub_64(asmjit::x86::Assembler& a);
	void emit_mba_sub_32(asmjit::x86::Assembler& a);

	// x ^ y = (x | y) - (x & y)
	// x ^ y = (x | y) & (~x | ~y)
	// x ^ y = (x & ~y) | (~x & y)
	void emit_mba_xor_64(asmjit::x86::Assembler& a);
	void emit_mba_xor_32(asmjit::x86::Assembler& a);

	// x & y = (x + y) - (x | y)
	// x & y = ((x ^ y) ^ x) & ((x ^ y) ^ y)  -- not useful
	// x & y = ~(~x | ~y)
	void emit_mba_and_64(asmjit::x86::Assembler& a);
	void emit_mba_and_32(asmjit::x86::Assembler& a);

	// x | y = (x + y) - (x & y)
	// x | y = (x ^ y) + (x & y)
	// x | y = ~(~x & ~y)
	void emit_mba_or_64(asmjit::x86::Assembler& a);
	void emit_mba_or_32(asmjit::x86::Assembler& a);

	// Linear MBA: wraps result in a + c*f(x,y) - c*f(x,y) identity layer
	// f(x,y) is a random boolean expression
	void emit_identity_layer_64(asmjit::x86::Assembler& a);
	void emit_identity_layer_32(asmjit::x86::Assembler& a);

private:
	std::mt19937& rng;
};
