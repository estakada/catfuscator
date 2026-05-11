#include <stdio.h>
#include <stdint.h>

extern "C" void CatfuscatorUltraBegin(void);
extern "C" void CatfuscatorUltraEnd(void);

int __declspec(noinline) compute2(int x) {
    CatfuscatorUltraBegin();
    int acc = x;
    acc += 0x1337;
    acc ^= 0xDEAD;
    acc = (acc * 7) + 13;
    acc ^= (acc >> 16);
    acc &= 0xFFFF;
    CatfuscatorUltraEnd();
    return acc;
}

int main() {
    printf("Before\n"); fflush(stdout);
    int r = compute2(42);
    printf("Result: 0x%04X\n", r); fflush(stdout);
    return 0;
}
