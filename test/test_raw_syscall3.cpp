#include <cstdio>
#include <cstdint>
#include <cstring>
#include <windows.h>

int main() {
    auto buf = (uint8_t*)VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // Test: do syscall, return rax from [rsp]
    {
        uint8_t code[] = {
            0x51,                                           // push rcx
            0x52,                                           // push rdx
            0x41, 0x52,                                     // push r10
            0x41, 0x53,                                     // push r11
            0x48, 0x83, 0xEC, 0x10,                         // sub rsp, 0x10
            0x48, 0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00, // mov qword [rsp], 0
            0x4C, 0x8D, 0x14, 0x24,                         // lea r10, [rsp]
            0xB8, 0x5B, 0x00, 0x00, 0x00,                   // mov eax, 0x5B
            0x0F, 0x05,                                      // syscall
            // rax now = NTSTATUS, save it
            0x48, 0x89, 0xC1,                               // mov rcx, rax (save status)
            0x48, 0x8B, 0x04, 0x24,                         // mov rax, [rsp] (load time)
            0x48, 0x83, 0xC4, 0x10,                         // add rsp, 0x10
            0x41, 0x5B,                                     // pop r11
            0x41, 0x5A,                                     // pop r10
            0x5A,                                           // pop rdx
            0x59,                                           // pop rcx  <-- wait, this pops into rcx, clobbering our status
            0xC3,                                           // ret (rax = time value)
        };
        memcpy(buf, code, sizeof(code));
        auto fn = (uint64_t(*)())buf;
        uint64_t result = fn();
        printf("Result (time value from [rsp]): 0x%016llX\n", result);
        printf("Is non-zero: %s\n", result != 0 ? "YES" : "NO");
    }

    VirtualFree(buf, 0, MEM_RELEASE);
    return 0;
}
