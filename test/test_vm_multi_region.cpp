#include <stdio.h>
#include <stdint.h>

extern "C" void CatfuscatorVirtualizeBegin(void);
extern "C" void CatfuscatorVirtualizeEnd(void);
extern "C" void CatfuscatorUltraBegin(void);
extern "C" void CatfuscatorUltraEnd(void);

volatile int g_r1 = 0, g_r2 = 0, g_r3 = 0;

// Edge case: multiple VM regions in the same binary, different protection levels
void __declspec(noinline) region1() {
    CatfuscatorVirtualizeBegin();
    int x = 10;
    int y = 20;
    g_r1 = x * y + 5;  // 205
    CatfuscatorVirtualizeEnd();
}

void __declspec(noinline) region2() {
    CatfuscatorUltraBegin();
    int a = g_r1;       // 205
    g_r2 = a ^ 0xFF;    // 205 ^ 255 = 50
    CatfuscatorUltraEnd();
}

void __declspec(noinline) region3() {
    CatfuscatorVirtualizeBegin();
    int b = g_r2;       // 50
    g_r3 = b * 3 + 1;   // 151
    CatfuscatorVirtualizeEnd();
}

int main() {
    printf("Before\n"); fflush(stdout);
    region1();
    region2();
    region3();
    printf("r1=%d r2=%d r3=%d (expected 205, 50, 151)\n", g_r1, g_r2, g_r3);
    fflush(stdout);
    return (g_r1 == 205 && g_r2 == 50 && g_r3 == 151) ? 0 : 1;
}
