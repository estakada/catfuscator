#include <cstdio>
#include <cstdint>
#include <cstring>
#include <windows.h>

void run_test(const char* name, uint8_t* buf, size_t size, DWORD protect) {
    DWORD old;
    VirtualProtect(buf, 4096, protect, &old);
    buf[size] = 0xC3;
    printf("Testing %s with prot=0x%X...\n", name, protect);
    fflush(stdout);
    auto fn = (void(*)())buf;
    __try {
        fn();
        printf("  PASS\n");
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        printf("  CRASH: 0x%08X\n", GetExceptionCode());
    }
}

int main() {
    auto buf = (uint8_t*)VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // Variant 9: NtQueryPerformanceCounter
    uint8_t code[] = {
        0x9C,
        0x50, 0x51, 0x52,
        0x41, 0x52, 0x41, 0x53,
        0x6A, 0x00, 0x6A, 0x00,
        0x4C, 0x8D, 0x14, 0x24,
        0x31, 0xD2,
        0xB8, 0x31, 0x00, 0x00, 0x00,
        0x0F, 0x05,
        0x48, 0x8B, 0x04, 0x24,
        0x48, 0x85, 0xC0,
        0x75, 0x02,
        0x0F, 0x0B,
        0x58, 0x58,
        0x41, 0x5B, 0x41, 0x5A,
        0x5A, 0x59, 0x58,
        0x9D,
    };

    memcpy(buf, code, sizeof(code));

    // Test with different page protections
    run_test("PAGE_EXECUTE_READWRITE", buf, sizeof(code), PAGE_EXECUTE_READWRITE);
    run_test("PAGE_EXECUTE_READ", buf, sizeof(code), PAGE_EXECUTE_READ);
    run_test("PAGE_EXECUTE_WRITECOPY", buf, sizeof(code), PAGE_EXECUTE_WRITECOPY);

    VirtualFree(buf, 0, MEM_RELEASE);
    return 0;
}
