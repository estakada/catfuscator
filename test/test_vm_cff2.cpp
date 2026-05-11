#include <stdio.h>
#include <stdint.h>

extern "C" void CatfuscatorVirtualizeBegin(void);
extern "C" void CatfuscatorVirtualizeEnd(void);

// Big enough function to exercise CFF with multiple basic blocks
int __declspec(noinline) vm_test(int x) {
    CatfuscatorVirtualizeBegin();

    int acc = x;
    acc += 0x1337;
    acc ^= 0xDEAD;
    acc = (acc * 7) + 13;
    acc ^= (acc >> 16);
    acc &= 0xFFFF;

    // Add branching to create multiple basic blocks
    int result = 0;
    if (acc > 0x5000) {
        result = acc - 0x1000;
    } else {
        result = acc + 0x2000;
    }

    // More arithmetic
    result ^= 0xBEEF;
    result = (result << 3) | (result >> 29);
    result &= 0xFFFFFF;
    result += x;

    // Another branch
    if (result & 1) {
        result = result * 3 + 1;
    } else {
        result = result / 2;
    }

    result ^= 0xCAFE;
    result &= 0xFFFF;

    CatfuscatorVirtualizeEnd();
    return result;
}

int main() {
    printf("Before\n"); fflush(stdout);
    int r = vm_test(42);
    printf("Result: 0x%04X (expected 0x73BF)\n", r); fflush(stdout);

    int r2 = vm_test(42);
    int r3 = vm_test(42);
    if (r == r2 && r2 == r3 && r == 0x73BF) {
        printf("ALL PASSED\n");
        return 0;
    } else {
        printf("FAILED: 0x%X 0x%X 0x%X\n", r, r2, r3);
        return 1;
    }
}
