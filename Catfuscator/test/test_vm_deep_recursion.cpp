#include <stdio.h>
#include <stdint.h>

extern "C" void CatfuscatorVirtualizeBegin(void);
extern "C" void CatfuscatorVirtualizeEnd(void);

volatile int g_result = 0;

// Edge case: recursive function called from VM region — heavy stack usage
__declspec(noinline) int ackermann(int m, int n) {
    if (m == 0) return n + 1;
    if (n == 0) return ackermann(m - 1, 1);
    return ackermann(m - 1, ackermann(m, n - 1));
}

void __declspec(noinline) vm_deep_recursion() {
    CatfuscatorVirtualizeBegin();

    // ackermann(3,4) = 125 — deep recursion but manageable
    int r = ackermann(3, 4);
    g_result = r;

    CatfuscatorVirtualizeEnd();
}

int main() {
    printf("Before\n"); fflush(stdout);
    vm_deep_recursion();
    printf("ackermann(3,4) = %d (expected 125)\n", g_result); fflush(stdout);
    return (g_result == 125) ? 0 : 1;
}
