#include <stdio.h>
#include <stdint.h>

extern "C" void CatfuscatorUltraBegin(void);
extern "C" void CatfuscatorUltraEnd(void);

int compute(int a, int b) {
    CatfuscatorUltraBegin();

    int result = 0;
    for (int i = 0; i < 10; i++) {
        result += a * (i + 1);
        result ^= b;
        result = (result << 3) | (result >> 29);
    }
    result &= 0xFFFF;

    CatfuscatorUltraEnd();
    return result;
}

int compute2(int x) {
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
    int r1 = compute(42, 0x55);
    int r2 = compute2(r1);
    printf("Result: 0x%04X -> 0x%04X\n", r1, r2);

    if (r1 == 0 && r2 == 0)
        printf("ZERO\n");
    else
        printf("OK: non-zero results\n");

    return 0;
}
