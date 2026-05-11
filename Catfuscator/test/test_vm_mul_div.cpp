#include <stdio.h>
#include <stdint.h>

extern "C" void CatfuscatorVirtualizeBegin(void);
extern "C" void CatfuscatorVirtualizeEnd(void);

volatile int64_t g_a = 1000;
volatile int64_t g_b = 7;
volatile int64_t g_mul = 0, g_div = 0, g_mod = 0;
volatile uint64_t g_umul = 0, g_udiv = 0, g_umod = 0;

// Test: multiplication and division (MUL, IMUL, DIV, IDIV, CDQ/CQO)
void __declspec(noinline) vm_mul_div() {
    CatfuscatorVirtualizeBegin();
    int64_t a = g_a;
    int64_t b = g_b;

    // Signed
    g_mul = a * b;          // 7000
    g_div = a / b;          // 142
    g_mod = a % b;          // 6

    // Unsigned
    uint64_t ua = static_cast<uint64_t>(a);
    uint64_t ub = static_cast<uint64_t>(b);
    g_umul = ua * ub;       // 7000
    g_udiv = ua / ub;       // 142
    g_umod = ua % ub;       // 6

    CatfuscatorVirtualizeEnd();
}

int main() {
    printf("Before\n"); fflush(stdout);
    vm_mul_div();

    int pass = 1;
    if (g_mul != 7000) { printf("FAIL mul: %lld\n", g_mul); pass = 0; }
    if (g_div != 142)  { printf("FAIL div: %lld\n", g_div); pass = 0; }
    if (g_mod != 6)    { printf("FAIL mod: %lld\n", g_mod); pass = 0; }
    if (g_umul != 7000) { printf("FAIL umul: %llu\n", g_umul); pass = 0; }
    if (g_udiv != 142)  { printf("FAIL udiv: %llu\n", g_udiv); pass = 0; }
    if (g_umod != 6)    { printf("FAIL umod: %llu\n", g_umod); pass = 0; }

    if (pass) printf("ALL PASSED\n");
    fflush(stdout);
    return pass ? 0 : 1;
}
