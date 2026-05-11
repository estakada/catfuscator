#include <stdio.h>
#include <stdint.h>

extern "C" void CatfuscatorUltraBegin(void);
extern "C" void CatfuscatorUltraEnd(void);

int __declspec(noinline) compute2(int x) {
    int acc;
    CatfuscatorUltraBegin();
    acc = x + 1;
    CatfuscatorUltraEnd();
    return acc;
}

int main() {
    printf("Before\n"); fflush(stdout);
    int r = compute2(41);
    printf("Result: %d (expected 42)\n", r); fflush(stdout);
    return 0;
}
