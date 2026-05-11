#include <stdio.h>

extern "C" void CatfuscatorUltraBegin(void);
extern "C" void CatfuscatorUltraEnd(void);

int classify(int x) {
    CatfuscatorUltraBegin();

    int result;
    if (x > 100) {
        result = 3;
    } else if (x > 50) {
        result = 2;
    } else if (x > 0) {
        result = 1;
    } else {
        result = 0;
    }

    CatfuscatorUltraEnd();
    return result;
}

int main() {
    int r1 = classify(200);
    int r2 = classify(75);
    int r3 = classify(25);
    int r4 = classify(-5);

    printf("classify(200)=%d (exp 3)\n", r1);
    printf("classify(75)=%d (exp 2)\n", r2);
    printf("classify(25)=%d (exp 1)\n", r3);
    printf("classify(-5)=%d (exp 0)\n", r4);

    return (r1 == 3 && r2 == 2 && r3 == 1 && r4 == 0) ? 0 : 1;
}
