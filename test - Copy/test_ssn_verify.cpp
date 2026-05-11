#include <cstdio>
#include <cstdint>
#include <cstring>
#include <windows.h>

void run_test(const char* name, uint8_t* buf, size_t size) {
    buf[size] = 0xC3;
    printf("Testing %s (%zu bytes)...\n", name, size);
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

    // Test NtQueryPerformanceCounter (SSN=0x31)
    // r10 = ptr to output LARGE_INTEGER, rdx = NULL
    {
        uint8_t code[] = {
            0x9C,                                           // pushfq
            0x50,                                           // push rax
            0x51,                                           // push rcx
            0x52,                                           // push rdx
            0x41, 0x52,                                     // push r10
            0x41, 0x53,                                     // push r11
            0x48, 0x83, 0xEC, 0x10,                         // sub rsp, 0x10
            0x48, 0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00, // mov qword [rsp], 0
            0x4C, 0x8D, 0x14, 0x24,                         // lea r10, [rsp]
            0x31, 0xD2,                                     // xor edx, edx (NULL 2nd arg)
            0xB8, 0x31, 0x00, 0x00, 0x00,                   // mov eax, 0x31
            0x0F, 0x05,                                      // syscall
            0x48, 0x8B, 0x04, 0x24,                         // mov rax, [rsp]
            0x48, 0x85, 0xC0,                               // test rax, rax
            0x75, 0x02,                                     // jnz +2
            0x0F, 0x0B,                                     // ud2
            0x48, 0x83, 0xC4, 0x10,                         // add rsp, 0x10
            0x41, 0x5B,                                     // pop r11
            0x41, 0x5A,                                     // pop r10
            0x5A,                                           // pop rdx
            0x59,                                           // pop rcx
            0x58,                                           // pop rax
            0x9D,                                           // popfq
        };
        memcpy(buf, code, sizeof(code));
        run_test("NtQueryPerformanceCounter SSN=0x31", buf, sizeof(code));
    }

    // Test NtQuerySystemInformation (SSN=0x36)
    // r10 = SystemBasicInformation (class 0)
    // rdx = ptr to output buffer
    // r8 = buffer size (0x40 should be enough)
    // r9 = ptr to ReturnLength (can be NULL via stack slot)
    {
        uint8_t code[] = {
            0x9C,                                           // pushfq
            0x50,                                           // push rax
            0x51,                                           // push rcx
            0x52,                                           // push rdx
            0x41, 0x50,                                     // push r8
            0x41, 0x51,                                     // push r9
            0x41, 0x52,                                     // push r10
            0x41, 0x53,                                     // push r11
            0x48, 0x83, 0xEC, 0x60,                         // sub rsp, 0x60 (buffer + shadow)
            // Zero first 8 bytes of buffer as canary
            0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00, // mov qword [rsp+0x20], 0
            // r10 = 0 (SystemBasicInformation class)
            0x49, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00,       // mov r10, 0
            // rdx = rsp + 0x20 (buffer after shadow space)
            0x48, 0x8D, 0x54, 0x24, 0x20,                   // lea rdx, [rsp+0x20]
            // r8 = 0x40 (buffer size)
            0x49, 0xC7, 0xC0, 0x40, 0x00, 0x00, 0x00,       // mov r8, 0x40
            // r9 = 0 (don't need ReturnLength)
            0x4D, 0x31, 0xC9,                               // xor r9, r9
            0xB8, 0x36, 0x00, 0x00, 0x00,                   // mov eax, 0x36
            0x0F, 0x05,                                      // syscall
            // Check: buffer[0] should be non-zero after successful query
            0x48, 0x8B, 0x44, 0x24, 0x20,                   // mov rax, [rsp+0x20]
            0x48, 0x85, 0xC0,                               // test rax, rax
            0x75, 0x02,                                     // jnz +2
            0x0F, 0x0B,                                     // ud2
            0x48, 0x83, 0xC4, 0x60,                         // add rsp, 0x60
            0x41, 0x5B,                                     // pop r11
            0x41, 0x5A,                                     // pop r10
            0x41, 0x59,                                     // pop r9
            0x41, 0x58,                                     // pop r8
            0x5A,                                           // pop rdx
            0x59,                                           // pop rcx
            0x58,                                           // pop rax
            0x9D,                                           // popfq
        };
        memcpy(buf, code, sizeof(code));
        run_test("NtQuerySystemInformation SSN=0x36", buf, sizeof(code));
    }

    VirtualFree(buf, 0, MEM_RELEASE);
    return 0;
}
