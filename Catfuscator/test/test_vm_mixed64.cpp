#include <stdio.h>
#include <stdint.h>

extern "C" void CatfuscatorVirtualizeBegin(void);
extern "C" void CatfuscatorVirtualizeEnd(void);

volatile uint64_t g_val = 0xFEDCBA9876543210ull;
volatile int g_ok = 0;

// Test: 64-bit operations — MOVSXD, 64-bit arithmetic, CDQE
void __declspec(noinline) vm_mixed64() {
    CatfuscatorVirtualizeBegin();

    uint64_t v = g_val;
    int ok = 1;

    // 64-bit shifts
    uint64_t hi = v >> 32;           // 0xFEDCBA98
    uint64_t lo = v & 0xFFFFFFFF;   // 0x76543210

    if (hi != 0xFEDCBA98ull) ok = 0;
    if (lo != 0x76543210ull) ok = 0;

    // 64-bit multiplication
    uint64_t prod = hi * lo;
    uint64_t expected_prod = 0xFEDCBA98ull * 0x76543210ull;
    if (prod != expected_prod) ok = 0;

    // Sign extension: int32 -> int64
    int32_t neg = -42;
    int64_t ext = (int64_t)neg;
    if (ext != -42LL) ok = 0;

    // Large 64-bit value manipulation
    uint64_t x = 0x0123456789ABCDEFull;
    x = (x << 8) | (x >> 56);  // rotate left by 8
    uint64_t expected_rot = 0x23456789ABCDEF01ull;
    if (x != expected_rot) ok = 0;

    // 64-bit XOR / AND / OR chain
    uint64_t y = 0;
    y |= 0xFF00000000000000ull;
    y |= 0x00FF000000000000ull;
    y &= 0xFFFF000000000000ull;
    y ^= 0xAAAA000000000000ull;
    // y = 0xFFFF^0xAAAA = 0x5555 in top 16 bits
    uint64_t expected_y = 0x5555000000000000ull;
    if (y != expected_y) ok = 0;

    g_ok = ok;
    CatfuscatorVirtualizeEnd();
}

int main() {
    printf("Before\n"); fflush(stdout);
    vm_mixed64();
    printf("ok=%d (expected 1)\n", g_ok); fflush(stdout);
    return (g_ok == 1) ? 0 : 1;
}
