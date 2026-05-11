#include <stdio.h>
#include <math.h>

extern "C" void CatfuscatorUltraBegin(void);
extern "C" void CatfuscatorUltraEnd(void);

double dot_product(double x1, double y1, double x2, double y2) {
    CatfuscatorUltraBegin();
    double result = x1 * x2 + y1 * y2;
    CatfuscatorUltraEnd();
    return result;
}

float lerp(float a, float b, float t) {
    CatfuscatorUltraBegin();
    float result = a + (b - a) * t;
    CatfuscatorUltraEnd();
    return result;
}

double distance(double x1, double y1, double x2, double y2) {
    CatfuscatorUltraBegin();
    double dx = x2 - x1;
    double dy = y2 - y1;
    double result = sqrt(dx * dx + dy * dy);
    CatfuscatorUltraEnd();
    return result;
}

int float_compare(double a, double b) {
    CatfuscatorUltraBegin();
    int result;
    if (a > b)
        result = 1;
    else if (a < b)
        result = -1;
    else
        result = 0;
    CatfuscatorUltraEnd();
    return result;
}

int main() {
    int ok = 1;

    double dp = dot_product(3.0, 4.0, 1.0, 2.0);
    printf("dot(3,4).(1,2) = %.1f (exp 11.0)\n", dp);
    if (dp != 11.0) ok = 0;

    float lr = lerp(0.0f, 100.0f, 0.25f);
    printf("lerp(0,100,0.25) = %.1f (exp 25.0)\n", lr);
    if (lr != 25.0f) ok = 0;

    double dist = distance(0.0, 0.0, 3.0, 4.0);
    printf("dist(0,0,3,4) = %.1f (exp 5.0)\n", dist);
    if (dist != 5.0) ok = 0;

    int c1 = float_compare(3.14, 2.71);
    int c2 = float_compare(1.0, 2.0);
    int c3 = float_compare(5.0, 5.0);
    printf("cmp(3.14,2.71)=%d cmp(1,2)=%d cmp(5,5)=%d (exp 1,-1,0)\n", c1, c2, c3);
    if (c1 != 1 || c2 != -1 || c3 != 0) ok = 0;

    return ok ? 0 : 1;
}
