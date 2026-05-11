#include <stdio.h>
#include <stdint.h>

extern "C" void CatfuscatorVirtualizeBegin(void);
extern "C" void CatfuscatorVirtualizeEnd(void);

volatile int g_a = 15;
volatile int g_b = 7;
volatile int g_result = 0;

// Test: nested if/else + multiple comparison types
void __declspec(noinline) vm_nested() {
    CatfuscatorVirtualizeBegin();
    int a = g_a;
    int b = g_b;
    int r = 0;

    if (a > 10) {
        if (b < 10) {
            r = a + b;       // 15 + 7 = 22
        } else {
            r = a - b;
        }
    } else {
        if (b == 5) {
            r = 100;
        } else {
            r = 200;
        }
    }

    // r should be 22 here
    if (r >= 20 && r <= 30) {
        r = r * 3;  // 22 * 3 = 66
    }

    g_result = r;
    CatfuscatorVirtualizeEnd();
}

int main() {
    printf("Before\n"); fflush(stdout);
    vm_nested();
    printf("g_result = %d (expected 66)\n", g_result); fflush(stdout);
    return (g_result == 66) ? 0 : 1;
}
