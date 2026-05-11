#include <stdio.h>
#include <stdint.h>

extern "C" void CatfuscatorVirtualizeBegin(void);
extern "C" void CatfuscatorVirtualizeEnd(void);

volatile int g_val = 42;

// Edge case: minimal code between markers
void __declspec(noinline) vm_empty() {
    CatfuscatorVirtualizeBegin();
    g_val = 99;
    CatfuscatorVirtualizeEnd();
}

// Edge case: only a single load+store
void __declspec(noinline) vm_tiny() {
    CatfuscatorVirtualizeBegin();
    int x = g_val;
    g_val = x + 1;
    CatfuscatorVirtualizeEnd();
}

int main() {
    printf("Before\n"); fflush(stdout);
    vm_empty();
    if (g_val != 99) { printf("FAIL empty: %d\n", g_val); return 1; }

    vm_tiny();
    if (g_val != 100) { printf("FAIL tiny: %d\n", g_val); return 1; }

    printf("ALL PASSED\n"); fflush(stdout);
    return 0;
}
