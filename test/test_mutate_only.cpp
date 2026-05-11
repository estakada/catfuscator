#include <stdio.h>

extern "C" void CatfuscatorMutateBegin(void);
extern "C" void CatfuscatorMutateEnd(void);

int compute(int a, int b) {
    CatfuscatorMutateBegin();

    int result = a + b;
    result = result * 3;
    result = result - 10;

    CatfuscatorMutateEnd();
    return result;
}

int main() {
    int val = compute(10, 20);
    printf("Result: %d\n", val);
    printf("Expected: %d\n", (10 + 20) * 3 - 10);
    return val == 80 ? 0 : 1;
}
