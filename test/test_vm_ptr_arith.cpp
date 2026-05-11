#include <stdio.h>
#include <stdint.h>
#include <string.h>

extern "C" void CatfuscatorVirtualizeBegin(void);
extern "C" void CatfuscatorVirtualizeEnd(void);

volatile int g_ok = 0;

struct Node {
    int value;
    int next_idx;  // -1 = end
};

// Edge case: pointer arithmetic, struct array traversal, indirect memory access
void __declspec(noinline) vm_ptr_arith() {
    CatfuscatorVirtualizeBegin();
    int ok = 1;

    // Build a linked list via indices
    Node nodes[5];
    nodes[0] = { 10, 1 };
    nodes[1] = { 20, 2 };
    nodes[2] = { 30, 3 };
    nodes[3] = { 40, 4 };
    nodes[4] = { 50, -1 };

    // Traverse and sum
    int sum = 0;
    int idx = 0;
    int count = 0;
    while (idx >= 0 && idx < 5) {
        sum += nodes[idx].value;
        idx = nodes[idx].next_idx;
        count++;
    }
    if (sum != 150) ok = 0;
    if (count != 5) ok = 0;

    // Reverse traversal test with array indexing
    int arr[10] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    int rev_sum = 0;
    for (int i = 9; i >= 0; i--) {
        rev_sum += arr[i] * (i + 1);
    }
    // 0*1 + 1*2 + 2*3 + ... + 9*10 = 0+2+6+12+20+30+42+56+72+90 = 330
    if (rev_sum != 330) ok = 0;

    // 2D array
    int matrix[3][3] = { {1,2,3}, {4,5,6}, {7,8,9} };
    int trace = 0;
    for (int i = 0; i < 3; i++) {
        trace += matrix[i][i];
    }
    if (trace != 15) ok = 0;  // 1+5+9

    g_ok = ok;
    CatfuscatorVirtualizeEnd();
}

int main() {
    printf("Before\n"); fflush(stdout);
    vm_ptr_arith();
    printf("ok=%d (expected 1)\n", g_ok); fflush(stdout);
    return (g_ok == 1) ? 0 : 1;
}
