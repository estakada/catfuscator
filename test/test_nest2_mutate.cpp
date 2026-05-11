#include <stdio.h>
#include <stdint.h>

extern "C" void CatfuscatorMutateBegin(void);
extern "C" void CatfuscatorMutateEnd(void);

int __declspec(noinline) compute2(int x) {
    CatfuscatorMutateBegin();
    int acc = x;
    acc += 0x1337;
    acc ^= 0xDEAD;
    acc = (acc * 7) + 13;
    acc ^= (acc >> 16);
    acc &= 0xFFFF;
    CatfuscatorMutateEnd();
    return acc;
}

int main() {
    printf("Before\n"); fflush(stdout);
    int r = compute2(42);
    printf("Result: 0x%04X (expected 0xA0A4)\n", r); fflush(stdout);
    return (r == 0xA0A4) ? 0 : 1;
}
