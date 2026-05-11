#include <cstdio>
#include <cstdint>
#include <cstring>
#include <windows.h>

void run_test(const char* name, uint8_t* buf, size_t size) {
    buf[size] = 0xC3; // ret
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

    // Test 1: minimal NtQuerySystemTime syscall (SSN=0x5B)
    // sub rsp, 0x10; mov qword [rsp], 0; lea r10, [rsp]; mov eax, 0x5B; syscall; add rsp, 0x10
    {
        uint8_t code[] = {
            0x48, 0x83, 0xEC, 0x10,                         // sub rsp, 0x10
            0x48, 0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00, // mov qword [rsp], 0
            0x4C, 0x8D, 0x14, 0x24,                         // lea r10, [rsp]
            0xB8, 0x5B, 0x00, 0x00, 0x00,                   // mov eax, 0x5B
            0x0F, 0x05,                                      // syscall
            0x48, 0x83, 0xC4, 0x10,                         // add rsp, 0x10
        };
        memcpy(buf, code, sizeof(code));
        run_test("raw NtQuerySystemTime syscall", buf, sizeof(code));
    }

    // Test 2: with pushfq/popfq + register saves
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
            0xB8, 0x5B, 0x00, 0x00, 0x00,                   // mov eax, 0x5B
            0x0F, 0x05,                                      // syscall
            0x48, 0x8B, 0x04, 0x24,                         // mov rax, [rsp]
            0x48, 0x83, 0xC4, 0x10,                         // add rsp, 0x10
            0x41, 0x5B,                                     // pop r11
            0x41, 0x5A,                                     // pop r10
            0x5A,                                           // pop rdx
            0x59,                                           // pop rcx
            0x58,                                           // pop rax
            0x9D,                                           // popfq
        };
        memcpy(buf, code, sizeof(code));
        run_test("full NtQuerySystemTime with save/restore", buf, sizeof(code));
    }

    VirtualFree(buf, 0, MEM_RELEASE);
    return 0;
}
