#include <cstdio>
#include <cstdint>

extern "C" __declspec(noinline) int __ultra_begin() { return 0xA1CA0005; }
extern "C" __declspec(noinline) int __ultra_end()   { return 0xA1CA0006; }
extern "C" __declspec(noinline) int __virt_begin()  { return 0xA1CA0001; }
extern "C" __declspec(noinline) int __virt_end()    { return 0xA1CA0002; }

#pragma optimize("", off)

volatile int sink;

int test_ultra() {
    sink = __ultra_begin();
    volatile int x = 10;
    volatile int y = 20;
    int result = x + y;
    result = result ^ 0x55;
    result = result - 5;
    sink = __ultra_end();
    return result;
}

int test_optimized() {
    sink = __virt_begin();
    volatile int a = 42;
    volatile int b = 13;
    int sum = a + b;
    sum = sum + 7;
    sink = __virt_end();
    return sum;
}

#pragma optimize("", on)

int main() {
    int r1 = test_ultra();
    int r2 = test_optimized();
    printf("ultra=%d optimized=%d\n", r1, r2);
    return (r1 == 0 && r2 == 0) ? 1 : 0;
}
