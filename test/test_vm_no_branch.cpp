#include <stdio.h>
#include <stdint.h>

extern "C" void CatfuscatorVirtualizeBegin(void);
extern "C" void CatfuscatorVirtualizeEnd(void);

volatile uint64_t g_in = 0xABCDEF0123456789ull;
volatile uint64_t g_out = 0;

// Edge case: zero branches — CFF has only one basic block, nothing to flatten
void __declspec(noinline) vm_no_branch() {
    CatfuscatorVirtualizeBegin();
    uint64_t x = g_in;
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdull;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ull;
    x ^= x >> 33;
    g_out = x;
    CatfuscatorVirtualizeEnd();
}

int main() {
    printf("Before\n"); fflush(stdout);
    vm_no_branch();

    // Compute expected (splitmix64 finalizer)
    uint64_t x = 0xABCDEF0123456789ull;
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdull;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ull;
    x ^= x >> 33;

    printf("out=0x%016llX exp=0x%016llX\n", g_out, x);
    fflush(stdout);
    return (g_out == x) ? 0 : 1;
}
