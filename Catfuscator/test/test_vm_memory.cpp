#include <stdio.h>
#include <stdint.h>
#include <string.h>

extern "C" void CatfuscatorVirtualizeBegin(void);
extern "C" void CatfuscatorVirtualizeEnd(void);

volatile int g_ok = 0;

struct TestData {
    int32_t a;
    int32_t b;
    int64_t c;
    uint8_t d[8];
};

volatile TestData g_data = { 100, 200, 300, { 1, 2, 3, 4, 5, 6, 7, 8 } };
volatile TestData g_out = {};

// Test: memory loads/stores through pointers, struct access, byte-level ops
void __declspec(noinline) vm_memory() {
    CatfuscatorVirtualizeBegin();

    // Read from struct
    int32_t a = g_data.a;
    int32_t b = g_data.b;
    int64_t c = g_data.c;

    // Write to output struct
    g_out.a = a + b;       // 300
    g_out.b = a * 2;       // 200
    g_out.c = c + a + b;   // 600

    // Byte-level copy
    for (int i = 0; i < 8; i++) {
        g_out.d[i] = g_data.d[i] + 10;
    }

    // Verify
    g_ok = (g_out.a == 300 && g_out.b == 200 && g_out.c == 600 &&
            g_out.d[0] == 11 && g_out.d[7] == 18) ? 1 : 0;

    CatfuscatorVirtualizeEnd();
}

int main() {
    printf("Before\n"); fflush(stdout);
    vm_memory();
    printf("a=%d b=%d c=%lld d[0]=%d d[7]=%d ok=%d\n",
           g_out.a, g_out.b, g_out.c, g_out.d[0], g_out.d[7], g_ok);
    fflush(stdout);
    return (g_ok == 1) ? 0 : 1;
}
