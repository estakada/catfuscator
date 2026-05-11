#include <stdio.h>
#include <stdint.h>

extern "C" void CatfuscatorUltraBegin(void);
extern "C" void CatfuscatorUltraEnd(void);

volatile int g_result = 0;

void __declspec(noinline) compute() {
    CatfuscatorUltraBegin();
    g_result = 42;
    CatfuscatorUltraEnd();
}

int main() {
    printf("Before compute\n");
    fflush(stdout);
    compute();
    printf("After compute: g_result=%d\n", g_result);
    fflush(stdout);
    return 0;
}
