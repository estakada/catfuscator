#include <stdio.h>
#include <stdint.h>

extern "C" void CatfuscatorVirtualizeBegin(void);
extern "C" void CatfuscatorVirtualizeEnd(void);

// Edge case: large switch — many basic blocks for CFF
int __declspec(noinline) vm_big_switch(int sel) {
    CatfuscatorVirtualizeBegin();
    int r;
    switch (sel) {
    case 0:  r = 1000; break;
    case 1:  r = 1001; break;
    case 2:  r = 1002; break;
    case 3:  r = 1003; break;
    case 4:  r = 1004; break;
    case 5:  r = 1005; break;
    case 6:  r = 1006; break;
    case 7:  r = 1007; break;
    case 8:  r = 1008; break;
    case 9:  r = 1009; break;
    case 10: r = 1010; break;
    case 11: r = 1011; break;
    case 12: r = 1012; break;
    case 13: r = 1013; break;
    case 14: r = 1014; break;
    case 15: r = 1015; break;
    case 16: r = 1016; break;
    case 17: r = 1017; break;
    case 18: r = 1018; break;
    case 19: r = 1019; break;
    case 20: r = 1020; break;
    case 21: r = 1021; break;
    case 22: r = 1022; break;
    case 23: r = 1023; break;
    case 24: r = 1024; break;
    case 25: r = 1025; break;
    case 26: r = 1026; break;
    case 27: r = 1027; break;
    case 28: r = 1028; break;
    case 29: r = 1029; break;
    case 30: r = 1030; break;
    case 31: r = 1031; break;
    default: r = -1; break;
    }
    CatfuscatorVirtualizeEnd();
    return r;
}

int main() {
    printf("Before\n"); fflush(stdout);
    int pass = 1;
    for (int i = 0; i <= 32; i++) {
        int r = vm_big_switch(i);
        int expected = (i <= 31) ? 1000 + i : -1;
        if (r != expected) {
            printf("FAIL: switch(%d) = %d, expected %d\n", i, r, expected);
            pass = 0;
        }
    }
    if (pass) printf("ALL PASSED\n");
    fflush(stdout);
    return pass ? 0 : 1;
}
