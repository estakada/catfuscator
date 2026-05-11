#include <stdio.h>

extern "C" void CatfuscatorUltraBegin(void);
extern "C" void CatfuscatorUltraEnd(void);

int divide_and_mod(int a, int b, int* remainder) {
    CatfuscatorUltraBegin();

    int quotient = a / b;
    *remainder = a % b;

    CatfuscatorUltraEnd();
    return quotient;
}

int abs_diff(int a, int b) {
    CatfuscatorUltraBegin();

    int result;
    if (a > b)
        result = a - b;
    else
        result = b - a;

    CatfuscatorUltraEnd();
    return result;
}

int clamp(int val, int lo, int hi) {
    CatfuscatorUltraBegin();

    int result = val;
    if (result < lo) result = lo;
    if (result > hi) result = hi;

    CatfuscatorUltraEnd();
    return result;
}

int main() {
    int rem = 0;
    int q = divide_and_mod(17, 5, &rem);
    printf("17/5 = %d rem %d (exp 3 rem 2)\n", q, rem);

    int d1 = abs_diff(30, 10);
    int d2 = abs_diff(10, 30);
    printf("abs_diff(30,10)=%d abs_diff(10,30)=%d (exp 20, 20)\n", d1, d2);

    int c1 = clamp(50, 0, 100);
    int c2 = clamp(-10, 0, 100);
    int c3 = clamp(200, 0, 100);
    printf("clamp(50,0,100)=%d (exp 50)\n", c1);
    printf("clamp(-10,0,100)=%d (exp 0)\n", c2);
    printf("clamp(200,0,100)=%d (exp 100)\n", c3);

    int ok = (q == 3 && rem == 2 && d1 == 20 && d2 == 20 &&
              c1 == 50 && c2 == 0 && c3 == 100);
    return ok ? 0 : 1;
}
