#include <stdio.h>
#include <stdint.h>

extern "C" void CatfuscatorVirtualizeBegin(void);
extern "C" void CatfuscatorVirtualizeEnd(void);

volatile int g_sel = 3;
volatile int g_result = 0;

// Test: switch statement (generates jump table or if-chain)
int __declspec(noinline) vm_switch(int sel) {
    CatfuscatorVirtualizeBegin();
    int r;
    switch (sel) {
    case 0: r = 100; break;
    case 1: r = 200; break;
    case 2: r = 300; break;
    case 3: r = 400; break;
    case 4: r = 500; break;
    case 5: r = 600; break;
    case 6: r = 700; break;
    case 7: r = 800; break;
    default: r = -1; break;
    }
    CatfuscatorVirtualizeEnd();
    return r;
}

int main() {
    printf("Before\n"); fflush(stdout);
    int pass = 1;
    for (int i = 0; i <= 8; i++) {
        int r = vm_switch(i);
        int expected = (i <= 7) ? (i + 1) * 100 : -1;
        if (r != expected) {
            printf("FAIL: switch(%d) = %d, expected %d\n", i, r, expected);
            pass = 0;
        }
    }
    if (pass) printf("ALL PASSED\n");
    fflush(stdout);
    return pass ? 0 : 1;
}
