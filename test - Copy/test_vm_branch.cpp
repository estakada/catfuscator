#include <stdio.h>
#include <stdint.h>

extern "C" void CatfuscatorVirtualizeBegin(void);
extern "C" void CatfuscatorVirtualizeEnd(void);

volatile int g_x = 42;
volatile int g_result = 0;

void __declspec(noinline) vm_branch() {
    CatfuscatorVirtualizeBegin();
    int x = g_x;
    if (x > 20) {
        g_result = x + 100;
    } else {
        g_result = x - 100;
    }
    CatfuscatorVirtualizeEnd();
}

int main() {
    printf("Before\n"); fflush(stdout);
    vm_branch();
    printf("g_result = %d (expected 142)\n", g_result); fflush(stdout);
    return (g_result == 142) ? 0 : 1;
}
