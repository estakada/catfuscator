#include <stdio.h>
#include <stdint.h>

extern "C" void CatfuscatorVirtualizeBegin(void);
extern "C" void CatfuscatorVirtualizeEnd(void);

volatile int g_ok = 0;

// Edge case: mixed operand sizes — 8-bit, 16-bit, 32-bit, 64-bit in one function
void __declspec(noinline) vm_mixed_sizes() {
    CatfuscatorVirtualizeBegin();
    int ok = 1;

    // 8-bit
    uint8_t byte_val = 0xAB;
    byte_val ^= 0xFF;
    if (byte_val != 0x54) ok = 0;

    byte_val += 0x10;
    if (byte_val != 0x64) ok = 0;

    // 16-bit
    uint16_t word_val = 0xBEEF;
    word_val &= 0xFF00;
    if (word_val != 0xBE00) ok = 0;

    word_val |= byte_val;
    if (word_val != 0xBE64) ok = 0;

    // 32-bit
    uint32_t dword_val = 0xDEADBEEF;
    dword_val >>= 16;
    if (dword_val != 0xDEAD) ok = 0;

    dword_val = (dword_val << 16) | word_val;
    if (dword_val != 0xDEADBE64u) ok = 0;

    // 64-bit
    uint64_t qword_val = (uint64_t)dword_val << 32;
    qword_val |= 0xCAFEBABEull;
    if (qword_val != 0xDEADBE64CAFEBABE) ok = 0;

    // Cross-size operations
    uint64_t mixed = (uint64_t)byte_val + (uint64_t)word_val + (uint64_t)dword_val + qword_val;
    uint64_t expected = 0x64ull + 0xBE64ull + 0xDEADBE64ull + 0xDEADBE64CAFEBABEull;
    if (mixed != expected) ok = 0;

    g_ok = ok;
    CatfuscatorVirtualizeEnd();
}

int main() {
    printf("Before\n"); fflush(stdout);
    vm_mixed_sizes();
    printf("ok=%d (expected 1)\n", g_ok); fflush(stdout);
    return (g_ok == 1) ? 0 : 1;
}
