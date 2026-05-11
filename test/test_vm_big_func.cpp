#include <stdio.h>
#include <stdint.h>

extern "C" void CatfuscatorVirtualizeBegin(void);
extern "C" void CatfuscatorVirtualizeEnd(void);

volatile uint32_t g_input = 0x42;
volatile uint32_t g_result = 0;

// Edge case: very long function — many instructions, many blocks for CFF
uint32_t __declspec(noinline) vm_big_func(uint32_t x) {
    CatfuscatorVirtualizeBegin();

    uint32_t a = x;
    uint32_t b = x ^ 0x12345678;
    uint32_t c = x + 0xDEADBEEF;
    uint32_t d = x * 7;

    // Phase 1: lots of ALU
    a = (a << 3) ^ (b >> 5);
    b = (b + c) ^ (d << 2);
    c = (c * 5) - (a >> 1);
    d = (d ^ a) + (b & 0xFF00FF00);

    a += b ^ c;
    b -= c & d;
    c ^= d | a;
    d = (d << 7) | (d >> 25);

    a = a * 0x9E3779B9;
    b = b ^ (a >> 16);
    c = c + (b << 8);
    d = d ^ (c >> 4);

    // Phase 2: branches
    if (a > b) {
        a += 0x1111;
        if (c > d) {
            c -= 0x2222;
        } else {
            d += 0x3333;
        }
    } else {
        b -= 0x4444;
        if (c < d) {
            c += 0x5555;
        } else {
            d -= 0x6666;
        }
    }

    // Phase 3: more ALU mixing
    uint32_t e = a ^ b ^ c ^ d;
    e = ((e >> 16) ^ e) * 0x45d9f3b;
    e = ((e >> 16) ^ e) * 0x45d9f3b;
    e = (e >> 16) ^ e;

    uint32_t f = e;
    for (int i = 0; i < 8; i++) {
        f ^= f << 13;
        f ^= f >> 17;
        f ^= f << 5;
        e += f;
    }

    // Phase 4: more branches
    if (e & 1) {
        e = e * 3 + 1;
    } else {
        e = e >> 1;
    }
    if ((e & 0xF0) == 0x30) {
        e ^= 0xCAFEBABE;
    } else if ((e & 0xF0) == 0x70) {
        e += 0xBAADF00D;
    } else {
        e -= 0x8BADF00D;
    }

    // Phase 5: array on stack
    uint32_t arr[8];
    for (int i = 0; i < 8; i++) {
        arr[i] = e ^ (uint32_t)(i * 0x9E3779B9);
    }
    for (int i = 0; i < 8; i++) {
        arr[i] = arr[i] ^ arr[(i + 3) & 7];
    }
    uint32_t final_hash = 0;
    for (int i = 0; i < 8; i++) {
        final_hash ^= arr[i];
    }

    final_hash ^= (final_hash >> 11);
    final_hash *= 0x1b873593;
    final_hash ^= (final_hash >> 15);

    CatfuscatorVirtualizeEnd();
    return final_hash;
}

int main() {
    printf("Before\n"); fflush(stdout);

    uint32_t r1 = vm_big_func(0x42);
    uint32_t r2 = vm_big_func(0x42);
    uint32_t r3 = vm_big_func(0x42);

    if (r1 != r2 || r2 != r3) {
        printf("CONSISTENCY FAIL: 0x%08X 0x%08X 0x%08X\n", r1, r2, r3);
        return 1;
    }

    uint32_t r4 = vm_big_func(0x43);
    if (r4 == r1) {
        printf("UNIQUENESS FAIL\n");
        return 1;
    }

    printf("ALL PASSED (0x%08X)\n", r1);
    fflush(stdout);
    return 0;
}
