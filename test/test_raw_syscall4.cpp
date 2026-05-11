#include <cstdio>
#include <cstdint>
#include <cstring>
#include <windows.h>

int main() {
    auto buf = (uint8_t*)VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // First, find the real SSN by reading ntdll
    auto ntdll = GetModuleHandleA("ntdll.dll");
    auto pNtQuerySystemTime = (uint8_t*)GetProcAddress(ntdll, "NtQuerySystemTime");
    auto pNtQueryPerformanceCounter = (uint8_t*)GetProcAddress(ntdll, "NtQueryPerformanceCounter");

    if (pNtQuerySystemTime) {
        printf("NtQuerySystemTime bytes: ");
        for (int i = 0; i < 16; i++) printf("%02X ", pNtQuerySystemTime[i]);
        printf("\n");
        // SSN is at offset 4 (after mov eax, SSN which is B8 xx xx xx xx or 4C 8B D1 B8 xx)
        if (pNtQuerySystemTime[0] == 0x4C && pNtQuerySystemTime[3] == 0xB8) {
            uint32_t ssn = *(uint32_t*)(pNtQuerySystemTime + 4);
            printf("NtQuerySystemTime SSN = 0x%X\n", ssn);
        } else if (pNtQuerySystemTime[0] == 0xB8) {
            uint32_t ssn = *(uint32_t*)(pNtQuerySystemTime + 1);
            printf("NtQuerySystemTime SSN = 0x%X\n", ssn);
        }
    }

    if (pNtQueryPerformanceCounter) {
        printf("NtQueryPerformanceCounter bytes: ");
        for (int i = 0; i < 16; i++) printf("%02X ", pNtQueryPerformanceCounter[i]);
        printf("\n");
        if (pNtQueryPerformanceCounter[0] == 0x4C && pNtQueryPerformanceCounter[3] == 0xB8) {
            uint32_t ssn = *(uint32_t*)(pNtQueryPerformanceCounter + 4);
            printf("NtQueryPerformanceCounter SSN = 0x%X\n", ssn);
        }
    }

    // Test with dynamically-read SSN
    if (pNtQuerySystemTime && pNtQuerySystemTime[0] == 0x4C && pNtQuerySystemTime[3] == 0xB8) {
        uint32_t ssn = *(uint32_t*)(pNtQuerySystemTime + 4);

        // Also test via function pointer
        typedef NTSTATUS(NTAPI* fn_t)(PLARGE_INTEGER);
        LARGE_INTEGER time = {};
        NTSTATUS st = ((fn_t)pNtQuerySystemTime)(&time);
        printf("Via function ptr: status=0x%X, time=0x%llX\n", st, time.QuadPart);

        // Now test via direct syscall with correct SSN
        uint8_t code[64];
        int off = 0;
        code[off++] = 0x51;                                     // push rcx
        code[off++] = 0x52;                                     // push rdx
        code[off++] = 0x41; code[off++] = 0x52;                 // push r10
        code[off++] = 0x41; code[off++] = 0x53;                 // push r11
        code[off++] = 0x48; code[off++] = 0x83; code[off++] = 0xEC; code[off++] = 0x10; // sub rsp, 0x10
        code[off++] = 0x48; code[off++] = 0xC7; code[off++] = 0x04; code[off++] = 0x24; // mov qword [rsp], 0
        code[off++] = 0x00; code[off++] = 0x00; code[off++] = 0x00; code[off++] = 0x00;
        code[off++] = 0x4C; code[off++] = 0x8D; code[off++] = 0x14; code[off++] = 0x24; // lea r10, [rsp]
        code[off++] = 0xB8;                                     // mov eax, SSN
        *(uint32_t*)(code + off) = ssn; off += 4;
        code[off++] = 0x0F; code[off++] = 0x05;                 // syscall
        // Save status, load buffer
        code[off++] = 0x48; code[off++] = 0x89; code[off++] = 0xC2; // mov rdx, rax (save status)
        code[off++] = 0x48; code[off++] = 0x8B; code[off++] = 0x04; code[off++] = 0x24; // mov rax, [rsp]
        code[off++] = 0x48; code[off++] = 0x83; code[off++] = 0xC4; code[off++] = 0x10; // add rsp, 0x10
        code[off++] = 0x41; code[off++] = 0x5B;                 // pop r11
        code[off++] = 0x41; code[off++] = 0x5A;                 // pop r10
        code[off++] = 0x5A;                                     // pop rdx
        code[off++] = 0x59;                                     // pop rcx
        code[off++] = 0xC3;                                     // ret

        memcpy(buf, code, off);
        auto fn = (uint64_t(*)())buf;
        uint64_t result = fn();
        printf("Direct syscall SSN=0x%X: time=0x%016llX\n", ssn, result);
    }

    VirtualFree(buf, 0, MEM_RELEASE);
    return 0;
}
