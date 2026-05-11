#include <stdio.h>
#include <stdint.h>

extern "C" void CatfuscatorVirtualizeBegin(void);
extern "C" void CatfuscatorVirtualizeEnd(void);

volatile uint64_t g_val = 0xDEADBEEFCAFEBABEull;
volatile uint64_t g_r1 = 0, g_r2 = 0, g_r3 = 0, g_r4 = 0, g_r5 = 0;

// Test: bitwise ops, shifts, rotations, NOT, NEG
void __declspec(noinline) vm_bitops() {
    CatfuscatorVirtualizeBegin();
    uint64_t v = g_val;

    // XOR, AND, OR
    uint64_t r1 = (v ^ 0x1234567890ABCDEFull) & 0xFFFFFFFF00000000ull;
    r1 |= 0x42;
    g_r1 = r1;

    // Shifts
    uint64_t r2 = (v << 4) ^ (v >> 8);
    g_r2 = r2;

    // NOT, NEG
    uint64_t r3 = ~v;
    int64_t r3s = -static_cast<int64_t>(v);
    g_r3 = r3;
    g_r4 = static_cast<uint64_t>(r3s);

    // Mix: shift + xor + and
    uint64_t r5 = v;
    r5 ^= (r5 >> 16);
    r5 &= 0xFFFF;
    r5 = (r5 << 3) | (r5 >> 61);
    g_r5 = r5;

    CatfuscatorVirtualizeEnd();
}

int main() {
    printf("Before\n"); fflush(stdout);
    vm_bitops();

    // Compute expected values
    uint64_t v = 0xDEADBEEFCAFEBABEull;
    uint64_t e1 = ((v ^ 0x1234567890ABCDEFull) & 0xFFFFFFFF00000000ull) | 0x42;
    uint64_t e2 = (v << 4) ^ (v >> 8);
    uint64_t e3 = ~v;
    uint64_t e4 = static_cast<uint64_t>(-static_cast<int64_t>(v));
    uint64_t e5 = v;
    e5 ^= (e5 >> 16);
    e5 &= 0xFFFF;
    e5 = (e5 << 3) | (e5 >> 61);

    int pass = 1;
    if (g_r1 != e1) { printf("FAIL r1: 0x%llX vs 0x%llX\n", g_r1, e1); pass = 0; }
    if (g_r2 != e2) { printf("FAIL r2: 0x%llX vs 0x%llX\n", g_r2, e2); pass = 0; }
    if (g_r3 != e3) { printf("FAIL r3: 0x%llX vs 0x%llX\n", g_r3, e3); pass = 0; }
    if (g_r4 != e4) { printf("FAIL r4: 0x%llX vs 0x%llX\n", g_r4, e4); pass = 0; }
    if (g_r5 != e5) { printf("FAIL r5: 0x%llX vs 0x%llX\n", g_r5, e5); pass = 0; }

    if (pass) printf("ALL PASSED\n");
    return pass ? 0 : 1;
}
