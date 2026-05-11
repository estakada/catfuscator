#include <stdio.h>
#include <stdint.h>
#include <string.h>

extern "C" void CatfuscatorVirtualizeBegin(void);
extern "C" void CatfuscatorVirtualizeEnd(void);

volatile int g_ok = 0;

// Test: string operations — memcpy, memset, strlen, strcmp
void __declspec(noinline) vm_string() {
    CatfuscatorVirtualizeBegin();

    char src[] = "Hello, Catfuscator VM!";
    char dst[32];
    memset(dst, 0, sizeof(dst));
    memcpy(dst, src, strlen(src) + 1);

    int len = (int)strlen(dst);
    int cmp = strcmp(dst, "Hello, Catfuscator VM!");

    // Simple string transformation
    char upper[32];
    memset(upper, 0, sizeof(upper));
    for (int i = 0; i < len; i++) {
        char c = dst[i];
        if (c >= 'a' && c <= 'z') {
            upper[i] = c - 32;
        } else {
            upper[i] = c;
        }
    }

    int cmp2 = strcmp(upper, "HELLO, Catfuscator VM!");

    g_ok = (len == 19 && cmp == 0 && cmp2 == 0) ? 1 : 0;

    CatfuscatorVirtualizeEnd();
}

int main() {
    printf("Before\n"); fflush(stdout);
    vm_string();
    printf("ok=%d (expected 1)\n", g_ok); fflush(stdout);
    return (g_ok == 1) ? 0 : 1;
}
