#include <stdio.h>
#include <stdint.h>
#include <math.h>

extern "C" void CatfuscatorVirtualizeBegin(void);
extern "C" void CatfuscatorVirtualizeEnd(void);

volatile double g_a = 3.14159265;
volatile double g_b = 2.71828182;
volatile float  g_fa = 1.5f;
volatile float  g_fb = 2.5f;
volatile double g_rd1 = 0, g_rd2 = 0, g_rd3 = 0, g_rd4 = 0;
volatile float  g_rf1 = 0, g_rf2 = 0;
volatile int    g_ri = 0;

// Test: SSE floating point operations
void __declspec(noinline) vm_float() {
    CatfuscatorVirtualizeBegin();

    double a = g_a;
    double b = g_b;

    g_rd1 = a + b;          // ~5.86
    g_rd2 = a * b;          // ~8.54
    g_rd3 = a - b;          // ~0.42
    g_rd4 = a / b;          // ~1.155

    float fa = g_fa;
    float fb = g_fb;
    g_rf1 = fa + fb;        // 4.0
    g_rf2 = fa * fb;        // 3.75

    // Float to int conversion
    g_ri = (int)(a + 0.5);  // 3 (rounded)

    CatfuscatorVirtualizeEnd();
}

int main() {
    printf("Before\n"); fflush(stdout);
    vm_float();

    int pass = 1;
    double eps = 1e-6;
    double a = 3.14159265, b = 2.71828182;

    if (fabs(g_rd1 - (a + b)) > eps) { printf("FAIL rd1: %.10f\n", g_rd1); pass = 0; }
    if (fabs(g_rd2 - (a * b)) > eps) { printf("FAIL rd2: %.10f\n", g_rd2); pass = 0; }
    if (fabs(g_rd3 - (a - b)) > eps) { printf("FAIL rd3: %.10f\n", g_rd3); pass = 0; }
    if (fabs(g_rd4 - (a / b)) > eps) { printf("FAIL rd4: %.10f\n", g_rd4); pass = 0; }
    if (g_rf1 != 4.0f)   { printf("FAIL rf1: %f\n", g_rf1); pass = 0; }
    if (g_rf2 != 3.75f)  { printf("FAIL rf2: %f\n", g_rf2); pass = 0; }
    if (g_ri != 3)        { printf("FAIL ri: %d\n", g_ri); pass = 0; }

    if (pass) printf("ALL PASSED\n");
    fflush(stdout);
    return pass ? 0 : 1;
}
