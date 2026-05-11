#include <stdio.h>

extern "C" void CatfuscatorUltraBegin(void);
extern "C" void CatfuscatorUltraEnd(void);

int sum_range(int start, int end) {
    CatfuscatorUltraBegin();

    int total = 0;
    for (int i = start; i <= end; i++) {
        total += i;
    }

    CatfuscatorUltraEnd();
    return total;
}

int main() {
    int r = sum_range(1, 10);
    printf("Sum 1..10: %d (expected 55)\n", r);

    int r2 = sum_range(5, 15);
    printf("Sum 5..15: %d (expected 110)\n", r2);

    return (r == 55 && r2 == 110) ? 0 : 1;
}
