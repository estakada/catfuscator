#include "vm_mba.h"

using namespace asmjit;
using namespace asmjit::x86;

// ============================================================================
// MBA ADD: rax = rax + r8
// ============================================================================
void vm_mba::emit_mba_add_64(Assembler& a) {
	uint32_t v = rng() % 3;
	switch (v) {
	case 0:
		// x + y = (x ^ y) + 2*(x & y)
		a.mov(r10, rax);
		a.mov(r11, rax);
		a.xor_(r10, r8);      // r10 = x ^ y
		a.and_(r11, r8);      // r11 = x & y
		a.shl(r11, 1);        // r11 = 2*(x & y)
		a.lea(rax, qword_ptr(r10, r11));
		break;
	case 1:
		// x + y = (x | y) + (x & y)
		a.mov(r10, rax);
		a.mov(r11, rax);
		a.or_(r10, r8);       // r10 = x | y
		a.and_(r11, r8);      // r11 = x & y
		a.lea(rax, qword_ptr(r10, r11));
		break;
	case 2:
		// x + y = 2*(x | y) - (x ^ y)
		a.mov(r10, rax);
		a.mov(r11, rax);
		a.or_(r10, r8);       // r10 = x | y
		a.shl(r10, 1);        // r10 = 2*(x | y)
		a.xor_(r11, r8);      // r11 = x ^ y
		a.mov(rax, r10);
		a.sub(rax, r11);
		break;
	}
	emit_identity_layer_64(a);
}

void vm_mba::emit_mba_add_32(Assembler& a) {
	uint32_t v = rng() % 3;
	switch (v) {
	case 0:
		a.mov(r10d, eax);
		a.mov(r11d, eax);
		a.xor_(r10d, r8d);
		a.and_(r11d, r8d);
		a.shl(r11d, 1);
		a.lea(eax, dword_ptr(r10, r11));
		break;
	case 1:
		a.mov(r10d, eax);
		a.mov(r11d, eax);
		a.or_(r10d, r8d);
		a.and_(r11d, r8d);
		a.lea(eax, dword_ptr(r10, r11));
		break;
	case 2:
		a.mov(r10d, eax);
		a.mov(r11d, eax);
		a.or_(r10d, r8d);
		a.shl(r10d, 1);
		a.xor_(r11d, r8d);
		a.mov(eax, r10d);
		a.sub(eax, r11d);
		break;
	}
	emit_identity_layer_32(a);
}

// ============================================================================
// MBA SUB: rax = rax - r8
// ============================================================================
void vm_mba::emit_mba_sub_64(Assembler& a) {
	uint32_t v = rng() % 3;
	switch (v) {
	case 0:
		// x - y = (x ^ y) - 2*(~x & y)
		a.mov(r10, rax);
		a.mov(r11, rax);
		a.xor_(r10, r8);      // r10 = x ^ y
		a.not_(r11);
		a.and_(r11, r8);      // r11 = ~x & y
		a.shl(r11, 1);        // r11 = 2*(~x & y)
		a.mov(rax, r10);
		a.sub(rax, r11);
		break;
	case 1:
		// x - y = (x & ~y) - (~x & y)
		a.mov(r10, r8);
		a.not_(r10);
		a.and_(r10, rax);     // r10 = x & ~y
		a.mov(r11, rax);
		a.not_(r11);
		a.and_(r11, r8);      // r11 = ~x & y
		a.mov(rax, r10);
		a.sub(rax, r11);
		break;
	case 2:
		// x - y = 2*(x & ~y) - (x ^ y)
		a.mov(r10, r8);
		a.not_(r10);
		a.and_(r10, rax);     // r10 = x & ~y
		a.shl(r10, 1);        // r10 = 2*(x & ~y)
		a.mov(r11, rax);
		a.xor_(r11, r8);      // r11 = x ^ y
		a.mov(rax, r10);
		a.sub(rax, r11);
		break;
	}
	emit_identity_layer_64(a);
}

void vm_mba::emit_mba_sub_32(Assembler& a) {
	uint32_t v = rng() % 3;
	switch (v) {
	case 0:
		a.mov(r10d, eax);
		a.mov(r11d, eax);
		a.xor_(r10d, r8d);
		a.not_(r11d);
		a.and_(r11d, r8d);
		a.shl(r11d, 1);
		a.mov(eax, r10d);
		a.sub(eax, r11d);
		break;
	case 1:
		a.mov(r10d, r8d);
		a.not_(r10d);
		a.and_(r10d, eax);
		a.mov(r11d, eax);
		a.not_(r11d);
		a.and_(r11d, r8d);
		a.mov(eax, r10d);
		a.sub(eax, r11d);
		break;
	case 2:
		a.mov(r10d, r8d);
		a.not_(r10d);
		a.and_(r10d, eax);
		a.shl(r10d, 1);
		a.mov(r11d, eax);
		a.xor_(r11d, r8d);
		a.mov(eax, r10d);
		a.sub(eax, r11d);
		break;
	}
	emit_identity_layer_32(a);
}

// ============================================================================
// MBA XOR: rax = rax ^ r8
// ============================================================================
void vm_mba::emit_mba_xor_64(Assembler& a) {
	uint32_t v = rng() % 3;
	switch (v) {
	case 0:
		// x ^ y = (x | y) - (x & y)
		a.mov(r10, rax);
		a.mov(r11, rax);
		a.or_(r10, r8);
		a.and_(r11, r8);
		a.mov(rax, r10);
		a.sub(rax, r11);
		break;
	case 1:
		// x ^ y = (x & ~y) | (~x & y)
		a.mov(r10, r8);
		a.not_(r10);
		a.and_(r10, rax);     // r10 = x & ~y
		a.mov(r11, rax);
		a.not_(r11);
		a.and_(r11, r8);      // r11 = ~x & y
		a.or_(r10, r11);
		a.mov(rax, r10);
		break;
	case 2:
		// x ^ y = (x + y) - 2*(x & y)
		a.mov(r10, rax);
		a.mov(r11, rax);
		a.add(r10, r8);       // r10 = x + y
		a.and_(r11, r8);      // r11 = x & y
		a.shl(r11, 1);
		a.mov(rax, r10);
		a.sub(rax, r11);
		break;
	}
	emit_identity_layer_64(a);
}

void vm_mba::emit_mba_xor_32(Assembler& a) {
	uint32_t v = rng() % 3;
	switch (v) {
	case 0:
		a.mov(r10d, eax);
		a.mov(r11d, eax);
		a.or_(r10d, r8d);
		a.and_(r11d, r8d);
		a.mov(eax, r10d);
		a.sub(eax, r11d);
		break;
	case 1:
		a.mov(r10d, r8d);
		a.not_(r10d);
		a.and_(r10d, eax);
		a.mov(r11d, eax);
		a.not_(r11d);
		a.and_(r11d, r8d);
		a.or_(r10d, r11d);
		a.mov(eax, r10d);
		break;
	case 2:
		a.mov(r10d, eax);
		a.mov(r11d, eax);
		a.add(r10d, r8d);
		a.and_(r11d, r8d);
		a.shl(r11d, 1);
		a.mov(eax, r10d);
		a.sub(eax, r11d);
		break;
	}
	emit_identity_layer_32(a);
}

// ============================================================================
// MBA AND: rax = rax & r8
// ============================================================================
void vm_mba::emit_mba_and_64(Assembler& a) {
	uint32_t v = rng() % 3;
	switch (v) {
	case 0:
		// x & y = (x + y) - (x | y)
		a.mov(r10, rax);
		a.mov(r11, rax);
		a.add(r10, r8);
		a.or_(r11, r8);
		a.mov(rax, r10);
		a.sub(rax, r11);
		break;
	case 1:
		// x & y = ~(~x | ~y)
		a.mov(r10, rax);
		a.mov(r11, r8);
		a.not_(r10);
		a.not_(r11);
		a.or_(r10, r11);
		a.not_(r10);
		a.mov(rax, r10);
		break;
	case 2:
		// x & y = ((x ^ y) ^ y)  -- simplifies to x & y via: x&y = x - (x & ~y)
		// Better: x & y = (x | y) - (x ^ y)
		a.mov(r10, rax);
		a.mov(r11, rax);
		a.or_(r10, r8);
		a.xor_(r11, r8);
		a.mov(rax, r10);
		a.sub(rax, r11);
		break;
	}
	emit_identity_layer_64(a);
}

void vm_mba::emit_mba_and_32(Assembler& a) {
	uint32_t v = rng() % 3;
	switch (v) {
	case 0:
		a.mov(r10d, eax);
		a.mov(r11d, eax);
		a.add(r10d, r8d);
		a.or_(r11d, r8d);
		a.mov(eax, r10d);
		a.sub(eax, r11d);
		break;
	case 1:
		a.mov(r10d, eax);
		a.mov(r11d, r8d);
		a.not_(r10d);
		a.not_(r11d);
		a.or_(r10d, r11d);
		a.not_(r10d);
		a.mov(eax, r10d);
		break;
	case 2:
		a.mov(r10d, eax);
		a.mov(r11d, eax);
		a.or_(r10d, r8d);
		a.xor_(r11d, r8d);
		a.mov(eax, r10d);
		a.sub(eax, r11d);
		break;
	}
	emit_identity_layer_32(a);
}

// ============================================================================
// MBA OR: rax = rax | r8
// ============================================================================
void vm_mba::emit_mba_or_64(Assembler& a) {
	uint32_t v = rng() % 3;
	switch (v) {
	case 0:
		// x | y = (x + y) - (x & y)
		a.mov(r10, rax);
		a.mov(r11, rax);
		a.add(r10, r8);
		a.and_(r11, r8);
		a.mov(rax, r10);
		a.sub(rax, r11);
		break;
	case 1:
		// x | y = (x ^ y) + (x & y)
		// But use MBA for the sub-parts too
		a.mov(r10, rax);
		a.mov(r11, rax);
		a.xor_(r10, r8);
		a.and_(r11, r8);
		a.lea(rax, qword_ptr(r10, r11));
		break;
	case 2:
		// x | y = ~(~x & ~y)
		a.mov(r10, rax);
		a.mov(r11, r8);
		a.not_(r10);
		a.not_(r11);
		a.and_(r10, r11);
		a.not_(r10);
		a.mov(rax, r10);
		break;
	}
	emit_identity_layer_64(a);
}

void vm_mba::emit_mba_or_32(Assembler& a) {
	uint32_t v = rng() % 3;
	switch (v) {
	case 0:
		a.mov(r10d, eax);
		a.mov(r11d, eax);
		a.add(r10d, r8d);
		a.and_(r11d, r8d);
		a.mov(eax, r10d);
		a.sub(eax, r11d);
		break;
	case 1:
		a.mov(r10d, eax);
		a.mov(r11d, eax);
		a.xor_(r10d, r8d);
		a.and_(r11d, r8d);
		a.lea(eax, dword_ptr(r10, r11));
		break;
	case 2:
		a.mov(r10d, eax);
		a.mov(r11d, r8d);
		a.not_(r10d);
		a.not_(r11d);
		a.and_(r10d, r11d);
		a.not_(r10d);
		a.mov(eax, r10d);
		break;
	}
	emit_identity_layer_32(a);
}

// ============================================================================
// Identity layer: adds noise that cancels out — result += c*f(x) - c*f(x)
// Applied after every MBA substitution for extra confusion
// ============================================================================
void vm_mba::emit_identity_layer_64(Assembler& a) {
	// 50% chance to add an identity layer
	if ((rng() % 2) == 0) return;

	uint32_t c = rng() | 1; // odd constant, never zero
	uint32_t v = rng() % 4;

	// Save current result
	a.mov(rdx, rax);

	switch (v) {
	case 0:
		// result += c*(rsi & 0xFF) - c*(rsi & 0xFF)
		a.mov(r10, rsi);
		a.and_(r10, 0xFF);
		a.imul(r10, r10, static_cast<int32_t>(c));
		a.add(rax, r10);
		a.sub(rax, r10);
		break;
	case 1:
		// result += c*(rbx ^ rbx) = result += 0  but obfuscated
		a.mov(r10, rbx);
		a.xor_(r10, rbx);
		a.imul(r10, r10, static_cast<int32_t>(c));
		a.add(rax, r10);
		break;
	case 2:
		// result ^= (r13 & ~r13) = result ^= 0
		a.mov(r10, r13);
		a.mov(r11, r13);
		a.not_(r11);
		a.and_(r10, r11);
		a.xor_(rax, r10);
		break;
	case 3:
		// result += ((rsi | ~rsi) + 1) & 0 = 0
		// ~rsi | rsi = 0xFFF...F, +1 = 0, &0 still 0
		a.mov(r10, rsi);
		a.mov(r11, rsi);
		a.not_(r11);
		a.or_(r10, r11);    // 0xFFFF...
		a.inc(r10);          // 0
		a.and_(r10, Imm(static_cast<int32_t>(c)));
		a.xor_(rax, r10);   // but wait: 0 & c = 0. Wrong: ~x|x = all 1s, +1 = 0. 0 & c = 0. OK.
		break;
	}
}

void vm_mba::emit_identity_layer_32(Assembler& a) {
	if ((rng() % 2) == 0) return;

	uint32_t c = rng() | 1;
	uint32_t v = rng() % 3;

	switch (v) {
	case 0:
		a.mov(r10d, esi);
		a.and_(r10d, 0xFF);
		a.imul(r10d, r10d, static_cast<int32_t>(c));
		a.add(eax, r10d);
		a.sub(eax, r10d);
		break;
	case 1:
		a.mov(r10d, ebx);
		a.xor_(r10d, ebx);
		a.imul(r10d, r10d, static_cast<int32_t>(c));
		a.add(eax, r10d);
		break;
	case 2:
		a.mov(r10d, r13d);
		a.mov(r11d, r13d);
		a.not_(r11d);
		a.and_(r10d, r11d);
		a.xor_(eax, r10d);
		break;
	}
}
