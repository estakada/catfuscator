#include <stdio.h>
#include <stdint.h>

extern "C" void CatfuscatorVirtualizeBegin(void);
extern "C" void CatfuscatorVirtualizeEnd(void);

volatile uint8_t  g_byte  = 0xAB;
volatile uint16_t g_word  = 0xCDEF;
volatile int8_t   g_sbyte = -50;
volatile int16_t  g_sword = -1000;
volatile uint64_t g_r1 = 0, g_r2 = 0;
volatile int64_t  g_r3 = 0, g_r4 = 0;
volatile uint64_t g_lea = 0;

// Test: MOVZX, MOVSX, LEA
void __declspec(noinline) vm_movzx_lea() {
    CatfuscatorVirtualizeBegin();

    // MOVZX
    g_r1 = g_byte;         // 0xAB = 171
    g_r2 = g_word;         // 0xCDEF = 52719

    // MOVSX (sign extension)
    g_r3 = g_sbyte;        // -50 sign-extended to 64-bit
    g_r4 = g_sword;        // -1000 sign-extended to 64-bit

    // LEA — compiler uses this for address calculations
    // Force LEA by computing base+index*scale+disp via array
    volatile int arr[4] = { 10, 20, 30, 40 };
    int idx = 2;
    g_lea = arr[idx];      // should be 30

    CatfuscatorVirtualizeEnd();
}

int main() {
    printf("Before\n"); fflush(stdout);
    vm_movzx_lea();

    int pass = 1;
    if (g_r1 != 0xAB)    { printf("FAIL r1: 0x%llX\n", g_r1); pass = 0; }
    if (g_r2 != 0xCDEF)  { printf("FAIL r2: 0x%llX\n", g_r2); pass = 0; }
    if (g_r3 != -50)      { printf("FAIL r3: %lld\n", g_r3); pass = 0; }
    if (g_r4 != -1000)    { printf("FAIL r4: %lld\n", g_r4); pass = 0; }
    if (g_lea != 30)       { printf("FAIL lea: %llu\n", g_lea); pass = 0; }

    if (pass) printf("ALL PASSED\n");
    fflush(stdout);
    return pass ? 0 : 1;
}
