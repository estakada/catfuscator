#include <stdio.h>
#include <stdint.h>

extern "C" void CatfuscatorVirtualizeBegin(void);
extern "C" void CatfuscatorVirtualizeEnd(void);

volatile int g_ok = 0;

// Edge case: extreme values — INT_MIN, INT_MAX, UINT64_MAX, zero, negatives
void __declspec(noinline) vm_extreme() {
    CatfuscatorVirtualizeBegin();
    int ok = 1;

    // Zero
    uint64_t zero = 0;
    if (zero != 0) ok = 0;
    if (~zero != 0xFFFFFFFFFFFFFFFFull) ok = 0;

    // INT32 boundaries
    int32_t max32 = 0x7FFFFFFF;
    int32_t min32 = (int32_t)0x80000000;
    if (max32 + 1 != min32) ok = 0;  // overflow wraps
    if (min32 - 1 != max32) ok = 0;

    // UINT64 max
    uint64_t umax = 0xFFFFFFFFFFFFFFFFull;
    if (umax + 1 != 0) ok = 0;
    if ((umax ^ umax) != 0) ok = 0;
    if ((umax & 0) != 0) ok = 0;
    if ((umax | 0) != umax) ok = 0;

    // Negative numbers
    int64_t neg1 = -1;
    int64_t neg_big = -0x7FFFFFFFFFFFFFFFll;
    if ((uint64_t)neg1 != 0xFFFFFFFFFFFFFFFFull) ok = 0;
    if (neg1 * neg1 != 1) ok = 0;
    if (neg_big + 0x7FFFFFFFFFFFFFFFll != 0) ok = 0;

    // Shift edge cases
    uint64_t one = 1;
    if ((one << 63) != 0x8000000000000000ull) ok = 0;
    if ((one << 0) != 1) ok = 0;
    uint32_t one32 = 1;
    if ((one32 << 31) != 0x80000000u) ok = 0;

    // XOR self = 0
    uint64_t big = 0xDEADBEEFCAFEBABEull;
    if ((big ^ big) != 0) ok = 0;

    // AND/OR identity
    if ((big & umax) != big) ok = 0;
    if ((big | 0) != big) ok = 0;

    g_ok = ok;
    CatfuscatorVirtualizeEnd();
}

int main() {
    printf("Before\n"); fflush(stdout);
    vm_extreme();
    printf("ok=%d (expected 1)\n", g_ok); fflush(stdout);
    return (g_ok == 1) ? 0 : 1;
}
