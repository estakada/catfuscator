#include <stdio.h>
#include <stdint.h>

extern "C" void CatfuscatorVirtualizeBegin(void);
extern "C" void CatfuscatorVirtualizeEnd(void);

volatile int g_n = 10;
volatile int g_sum = 0;

// Test: loop with accumulator
void __declspec(noinline) vm_loop() {
    CatfuscatorVirtualizeBegin();
    int n = g_n;
    int sum = 0;
    for (int i = 1; i <= n; i++) {
        sum += i;
    }
    g_sum = sum;
    CatfuscatorVirtualizeEnd();
}

int main() {
    printf("Before\n"); fflush(stdout);
    vm_loop();
    // sum(1..10) = 55
    printf("g_sum = %d (expected 55)\n", g_sum); fflush(stdout);
    return (g_sum == 55) ? 0 : 1;
}
