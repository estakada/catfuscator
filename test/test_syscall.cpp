#include <cstdio>
#include <cstdint>
#include <windows.h>

// Test NtQuerySystemTime via direct syscall
// SSN 0x5B on Win10/11
extern "C" uint64_t test_syscall_time();

int main() {
    // Instead of inline asm (not available in MSVC x64),
    // let's test via ntdll directly
    typedef NTSTATUS (NTAPI *NtQuerySystemTime_t)(PLARGE_INTEGER);
    auto ntdll = GetModuleHandleA("ntdll.dll");
    auto NtQuerySystemTime = (NtQuerySystemTime_t)GetProcAddress(ntdll, "NtQuerySystemTime");

    LARGE_INTEGER time = {};
    NTSTATUS status = NtQuerySystemTime(&time);
    printf("NtQuerySystemTime: status=0x%08X, value=0x%016llX\n", status, time.QuadPart);

    if (status != 0) {
        printf("FAIL: NtQuerySystemTime returned error\n");
        return 1;
    }
    if (time.QuadPart == 0) {
        printf("FAIL: time is zero\n");
        return 2;
    }
    printf("PASS: time is non-zero\n");

    // Also test NtQueryPerformanceCounter
    typedef NTSTATUS (NTAPI *NtQueryPerformanceCounter_t)(PLARGE_INTEGER, PLARGE_INTEGER);
    auto NtQueryPerformanceCounter = (NtQueryPerformanceCounter_t)GetProcAddress(ntdll, "NtQueryPerformanceCounter");

    LARGE_INTEGER perf = {};
    status = NtQueryPerformanceCounter(&perf, nullptr);
    printf("NtQueryPerformanceCounter: status=0x%08X, value=0x%016llX\n", status, perf.QuadPart);

    if (perf.QuadPart == 0) {
        printf("FAIL: perf counter is zero\n");
        return 3;
    }
    printf("PASS: perf counter is non-zero\n");
    return 0;
}
