#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern "C" void CatfuscatorUltraBegin(void);
extern "C" void CatfuscatorUltraEnd(void);

// --- 1. Recursion: fibonacci ---
int fib(int n) {
    CatfuscatorUltraBegin();
    int result;
    if (n <= 1)
        result = n;
    else
        result = fib(n - 1) + fib(n - 2);
    CatfuscatorUltraEnd();
    return result;
}

// --- 2. String manipulation ---
int string_hash(const char* s) {
    CatfuscatorUltraBegin();
    unsigned int hash = 5381;
    while (*s) {
        hash = hash * 33 + (unsigned char)*s;
        s++;
    }
    CatfuscatorUltraEnd();
    return (int)hash;
}

int string_length(const char* s) {
    CatfuscatorUltraBegin();
    int len = 0;
    while (s[len] != '\0')
        len++;
    CatfuscatorUltraEnd();
    return len;
}

// --- 3. Structs and pointers ---
struct vec3 {
    double x, y, z;
};

double vec3_dot(const vec3* a, const vec3* b) {
    CatfuscatorUltraBegin();
    double result = a->x * b->x + a->y * b->y + a->z * b->z;
    CatfuscatorUltraEnd();
    return result;
}

void vec3_cross(const vec3* a, const vec3* b, vec3* out) {
    CatfuscatorUltraBegin();
    out->x = a->y * b->z - a->z * b->y;
    out->y = a->z * b->x - a->x * b->z;
    out->z = a->x * b->y - a->y * b->x;
    CatfuscatorUltraEnd();
}

// --- 4. Array processing ---
void bubble_sort(int* arr, int n) {
    CatfuscatorUltraBegin();
    for (int i = 0; i < n - 1; i++) {
        for (int j = 0; j < n - 1 - i; j++) {
            if (arr[j] > arr[j + 1]) {
                int tmp = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = tmp;
            }
        }
    }
    CatfuscatorUltraEnd();
}

// --- 5. Nested calls ---
int square(int x) {
    CatfuscatorUltraBegin();
    int r = x * x;
    CatfuscatorUltraEnd();
    return r;
}

int sum_of_squares(int n) {
    CatfuscatorUltraBegin();
    int total = 0;
    for (int i = 1; i <= n; i++)
        total += square(i);
    CatfuscatorUltraEnd();
    return total;
}

// --- 6. Bitwise operations ---
unsigned int bit_reverse(unsigned int v) {
    CatfuscatorUltraBegin();
    unsigned int r = 0;
    for (int i = 0; i < 32; i++) {
        r = (r << 1) | (v & 1);
        v >>= 1;
    }
    CatfuscatorUltraEnd();
    return r;
}

int popcount_manual(unsigned int v) {
    CatfuscatorUltraBegin();
    int count = 0;
    while (v) {
        count += v & 1;
        v >>= 1;
    }
    CatfuscatorUltraEnd();
    return count;
}

// --- 7. Mixed int/float with branching ---
double safe_divide(double a, double b, double fallback) {
    CatfuscatorUltraBegin();
    double result;
    if (b == 0.0)
        result = fallback;
    else
        result = a / b;
    CatfuscatorUltraEnd();
    return result;
}

int main() {
    int ok = 1;
    int test = 0;
    int pass = 0;

    // 1. Recursion
    test++;
    int f10 = fib(10);
    printf("[%d] fib(10) = %d (exp 55)\n", test, f10);
    if (f10 == 55) pass++; else ok = 0;

    test++;
    int f0 = fib(0);
    int f1 = fib(1);
    printf("[%d] fib(0)=%d fib(1)=%d (exp 0, 1)\n", test, f0, f1);
    if (f0 == 0 && f1 == 1) pass++; else ok = 0;

    // 2. Strings
    test++;
    int len = string_length("Hello, VM!");
    printf("[%d] strlen(\"Hello, VM!\") = %d (exp 10)\n", test, len);
    if (len == 10) pass++; else ok = 0;

    test++;
    int h1 = string_hash("abc");
    int h2 = string_hash("abc");
    int h3 = string_hash("xyz");
    printf("[%d] hash(abc)=%d hash(abc)=%d hash(xyz)=%d same=%d diff=%d\n",
           test, h1, h2, h3, h1 == h2, h1 != h3);
    if (h1 == h2 && h1 != h3) pass++; else ok = 0;

    // 3. Structs
    test++;
    vec3 a = {1.0, 2.0, 3.0};
    vec3 b = {4.0, 5.0, 6.0};
    double dp = vec3_dot(&a, &b);
    printf("[%d] dot((1,2,3),(4,5,6)) = %.1f (exp 32.0)\n", test, dp);
    if (dp == 32.0) pass++; else ok = 0;

    test++;
    vec3 cr;
    vec3 i = {1.0, 0.0, 0.0};
    vec3 j = {0.0, 1.0, 0.0};
    vec3_cross(&i, &j, &cr);
    printf("[%d] cross(i,j) = (%.0f,%.0f,%.0f) (exp 0,0,1)\n", test, cr.x, cr.y, cr.z);
    if (cr.x == 0.0 && cr.y == 0.0 && cr.z == 1.0) pass++; else ok = 0;

    // 4. Array sort
    test++;
    int arr[] = {5, 3, 8, 1, 9, 2, 7, 4, 6, 0};
    bubble_sort(arr, 10);
    int sorted = 1;
    for (int idx = 0; idx < 9; idx++)
        if (arr[idx] > arr[idx + 1]) sorted = 0;
    printf("[%d] bubble_sort: %s [%d,%d,%d,...,%d,%d]\n", test,
           sorted ? "OK" : "FAIL", arr[0], arr[1], arr[2], arr[8], arr[9]);
    if (sorted) pass++; else ok = 0;

    // 5. Nested calls
    test++;
    int ss = sum_of_squares(10);
    printf("[%d] sum_of_squares(10) = %d (exp 385)\n", test, ss);
    if (ss == 385) pass++; else ok = 0;

    // 6. Bitwise
    test++;
    unsigned int rev = bit_reverse(0x80000000u);
    printf("[%d] bit_reverse(0x80000000) = 0x%08X (exp 0x00000001)\n", test, rev);
    if (rev == 0x00000001u) pass++; else ok = 0;

    test++;
    int pc = popcount_manual(0xDEADBEEF);
    printf("[%d] popcount(0xDEADBEEF) = %d (exp 24)\n", test, pc);
    if (pc == 24) pass++; else ok = 0;

    // 7. Mixed float/int
    test++;
    double d1 = safe_divide(10.0, 3.0, -1.0);
    double d2 = safe_divide(10.0, 0.0, -1.0);
    printf("[%d] safe_div(10,3)=%.4f safe_div(10,0)=%.1f (exp 3.3333, -1.0)\n",
           test, d1, d2);
    if (d1 > 3.333 && d1 < 3.334 && d2 == -1.0) pass++; else ok = 0;

    printf("\n=== %d/%d tests passed ===\n", pass, test);
    return ok ? 0 : 1;
}
