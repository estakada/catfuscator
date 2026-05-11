#include <stdio.h>

extern "C" void CatfuscatorUltraBegin(void);
extern "C" void CatfuscatorUltraEnd(void);

int compute(int a, int b) {
    CatfuscatorUltraBegin();

    int result = a + b;
    result = result * 2;
    result = result - 10;

    CatfuscatorUltraEnd();
    return result;
}

int main() {
    int r = compute(15, 25);
    printf("Result: %d (expected 70)\n", r);
    return r == 70 ? 0 : 1;
}
