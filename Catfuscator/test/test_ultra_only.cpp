#include <cstdio>
#include <cstdint>

extern "C" __declspec(noinline) int __ultra_begin() { return 0xA1CA0005; }
extern "C" __declspec(noinline) int __ultra_end()   { return 0xA1CA0006; }

#pragma optimize("", off)

volatile int sink;

int test_ultra() {
    sink = __ultra_begin();
    int result = 42;
    sink = __ultra_end();
    return result;
}

#pragma optimize("", on)

int main() {
    int r = test_ultra();
    printf("result=%d\n", r);
    return (r == 42) ? 0 : 1;
}
