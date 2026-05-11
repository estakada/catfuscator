#include <cstdio>
#include <cstdint>

extern "C" __declspec(noinline) int __virt_begin()  { return 0xA1CA0001; }
extern "C" __declspec(noinline) int __virt_end()    { return 0xA1CA0002; }

#pragma optimize("", off)

volatile int sink;

__declspec(noinline) int test_add() {
    sink = __virt_begin();
    int result = 42;
    sink = __virt_end();
    return result;
}

#pragma optimize("", on)

int main() {
    int r = test_add();
    printf("result=%d\n", r);
    return (r == 42) ? 0 : 1;
}
