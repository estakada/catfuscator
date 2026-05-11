#include <stdio.h>
#include <stdint.h>

extern "C" void CatfuscatorVirtualizeBegin(void);
extern "C" void CatfuscatorVirtualizeEnd(void);

// Use volatile to prevent optimization
volatile int g_x = 42;
volatile int g_y = 0;

void __declspec(noinline) vm_add() {
    CatfuscatorVirtualizeBegin();
    // Simple operations that should produce non-trivial bytecode
    int a = g_x;
    int b = a + 10;
    int c = b * 2;
    g_y = c;
    CatfuscatorVirtualizeEnd();
}

int main() {
    printf("Before\n"); fflush(stdout);
    vm_add();
    printf("g_y = %d (expected 104)\n", g_y); fflush(stdout);
    return (g_y == 104) ? 0 : 1;
}
