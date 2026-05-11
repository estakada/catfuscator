#include <stdio.h>
#include <stdint.h>

extern "C" void CatfuscatorVirtualizeBegin(void);
extern "C" void CatfuscatorVirtualizeEnd(void);

volatile int g_ok = 0;

// Test: stack-heavy operations — local arrays, deep call chains
__declspec(noinline) int fib(int n) {
    if (n <= 1) return n;
    return fib(n - 1) + fib(n - 2);
}

void __declspec(noinline) vm_stack() {
    CatfuscatorVirtualizeBegin();

    // Local array on stack
    int arr[16];
    for (int i = 0; i < 16; i++) {
        arr[i] = i * i;
    }

    // Sum the array
    int sum = 0;
    for (int i = 0; i < 16; i++) {
        sum += arr[i];
    }
    // sum = 0+1+4+9+16+25+36+49+64+81+100+121+144+169+196+225 = 1240

    // Call recursive function
    int f10 = fib(10);  // 55

    g_ok = (sum == 1240 && f10 == 55) ? 1 : 0;

    CatfuscatorVirtualizeEnd();
}

int main() {
    printf("Before\n"); fflush(stdout);
    vm_stack();
    printf("ok=%d (expected 1)\n", g_ok); fflush(stdout);
    return (g_ok == 1) ? 0 : 1;
}
