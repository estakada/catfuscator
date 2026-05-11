#include <stdio.h>
#include <stdint.h>

extern "C" void CatfuscatorVirtualizeBegin(void);
extern "C" void CatfuscatorVirtualizeEnd(void);

volatile uint32_t g_seed = 0x12345678;
volatile uint32_t g_hash = 0;

// Stress test: large function with many different instruction patterns
// Tests CFF with many basic blocks, loops, branches, and various ALU ops
uint32_t __declspec(noinline) vm_stress(uint32_t seed) {
    CatfuscatorVirtualizeBegin();

    uint32_t state = seed;
    uint32_t hash = 0;

    // Phase 1: PRNG loop (tests loop, XOR, shift, add)
    for (int i = 0; i < 64; i++) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        hash += state;
    }

    // Phase 2: Conditional accumulation (many branches)
    uint32_t acc = hash;
    for (int i = 0; i < 32; i++) {
        if (acc & 1) {
            acc = acc * 3 + 1;
        } else {
            acc = acc >> 1;
        }
        if ((acc & 0xF) > 8) {
            acc ^= 0xDEADBEEF;
        } else if ((acc & 0xF) > 4) {
            acc += 0x1337;
        } else {
            acc -= 0x42;
        }
        hash ^= acc;
    }

    // Phase 3: Bit manipulation
    uint32_t bits = hash;
    bits = ((bits >> 16) ^ bits) * 0x45d9f3b;
    bits = ((bits >> 16) ^ bits) * 0x45d9f3b;
    bits = (bits >> 16) ^ bits;
    hash = bits;

    // Phase 4: Nested loop with array-like access via stack
    uint32_t table[16];
    for (int i = 0; i < 16; i++) {
        table[i] = hash ^ (uint32_t)(i * 0x9E3779B9);
    }
    for (int round = 0; round < 4; round++) {
        for (int i = 0; i < 16; i++) {
            table[i] ^= table[(i + 1) & 0xF];
            table[i] += table[(i + 7) & 0xF];
            table[i] ^= (table[i] >> 11);
        }
    }
    hash = 0;
    for (int i = 0; i < 16; i++) {
        hash ^= table[i];
    }

    CatfuscatorVirtualizeEnd();
    return hash;
}

int main() {
    printf("Before\n"); fflush(stdout);

    // Run the same computation 3 times to check consistency
    uint32_t r1 = vm_stress(0x12345678);
    uint32_t r2 = vm_stress(0x12345678);
    uint32_t r3 = vm_stress(0x12345678);

    printf("r1=0x%08X r2=0x%08X r3=0x%08X\n", r1, r2, r3);

    if (r1 != r2 || r2 != r3) {
        printf("CONSISTENCY FAIL\n");
        fflush(stdout);
        return 1;
    }

    // Different seed should produce different result
    uint32_t r4 = vm_stress(0xABCDEF01);
    if (r4 == r1) {
        printf("UNIQUENESS FAIL: same result for different seed\n");
        fflush(stdout);
        return 1;
    }

    printf("ALL PASSED (hash=0x%08X)\n", r1);
    fflush(stdout);
    return 0;
}
