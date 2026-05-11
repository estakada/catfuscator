#include <stdio.h>
#include <stdint.h>
#include <string.h>

extern "C" void CatfuscatorVirtualizeBegin(void);
extern "C" void CatfuscatorVirtualizeEnd(void);

volatile int g_ok = 0;

// External functions called from VM region
__declspec(noinline) int helper_add(int a, int b) { return a + b; }
__declspec(noinline) int helper_mul(int a, int b) { return a * b; }

// Test: calling functions from inside VM region
void __declspec(noinline) vm_call() {
    CatfuscatorVirtualizeBegin();

    int a = helper_add(10, 20);       // 30
    int b = helper_mul(a, 3);          // 90
    int c = helper_add(b, helper_mul(2, 5)); // 90 + 10 = 100

    // Also test CRT call
    char buf[32];
    memset(buf, 0, sizeof(buf));
    buf[0] = 'O';
    buf[1] = 'K';

    g_ok = (a == 30 && b == 90 && c == 100 && buf[0] == 'O' && buf[2] == 0) ? 1 : 0;

    CatfuscatorVirtualizeEnd();
}

int main() {
    printf("Before\n"); fflush(stdout);
    vm_call();
    printf("ok=%d (expected 1)\n", g_ok); fflush(stdout);
    return (g_ok == 1) ? 0 : 1;
}
