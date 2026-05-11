#include <stdio.h>

extern "C" void CatfuscatorVirtualizeBegin(void);
extern "C" void CatfuscatorVirtualizeEnd(void);

int protected_add(int a, int b) {
    CatfuscatorVirtualizeBegin();

    int c = a + b;
    int d = c * 2;

    CatfuscatorVirtualizeEnd();
    return d;
}

int main() {
    int result = protected_add(15, 25);
    printf("Result: %d (expected 80)\n", result);
    return result == 80 ? 0 : 1;
}
