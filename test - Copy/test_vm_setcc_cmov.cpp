#include <stdio.h>
#include <stdint.h>

extern "C" void CatfuscatorVirtualizeBegin(void);
extern "C" void CatfuscatorVirtualizeEnd(void);

volatile int g_ok = 0;

// Edge case: SETcc and CMOVcc — branchless conditionals
void __declspec(noinline) vm_setcc_cmov() {
    CatfuscatorVirtualizeBegin();
    int ok = 1;

    // Ternary via CMOVcc (compiler generates CMOV with /O2)
    int a = 10, b = 20;
    int max_ab = (a > b) ? a : b;  // cmovl or cmovg
    if (max_ab != 20) ok = 0;

    int min_ab = (a < b) ? a : b;
    if (min_ab != 10) ok = 0;

    // Absolute value via branchless
    int neg = -42;
    int pos = (neg < 0) ? -neg : neg;
    if (pos != 42) ok = 0;

    // Clamp to range [0, 100]
    int val = 150;
    int clamped = val;
    if (clamped > 100) clamped = 100;
    if (clamped < 0) clamped = 0;
    if (clamped != 100) ok = 0;

    val = -50;
    clamped = val;
    if (clamped > 100) clamped = 100;
    if (clamped < 0) clamped = 0;
    if (clamped != 0) ok = 0;

    // Multiple comparisons chain
    int x = 42;
    int category;
    if (x < 10) category = 0;
    else if (x < 20) category = 1;
    else if (x < 50) category = 2;
    else if (x < 100) category = 3;
    else category = 4;
    if (category != 2) ok = 0;

    g_ok = ok;
    CatfuscatorVirtualizeEnd();
}

int main() {
    printf("Before\n"); fflush(stdout);
    vm_setcc_cmov();
    printf("ok=%d (expected 1)\n", g_ok); fflush(stdout);
    return (g_ok == 1) ? 0 : 1;
}
