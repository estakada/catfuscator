#include <cstdio>
#include <cstdint>
#include <windows.h>

int main() {
    auto ntdll = (uint8_t*)GetModuleHandleA("ntdll.dll");
    auto dos = (PIMAGE_DOS_HEADER)ntdll;
    auto nt = (PIMAGE_NT_HEADERS)(ntdll + dos->e_lfanew);
    auto exp_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    auto exports = (PIMAGE_EXPORT_DIRECTORY)(ntdll + exp_dir->VirtualAddress);

    auto names = (DWORD*)(ntdll + exports->AddressOfNames);
    auto ordinals = (WORD*)(ntdll + exports->AddressOfNameOrdinals);
    auto functions = (DWORD*)(ntdll + exports->AddressOfFunctions);

    // Find all Nt* functions that have the syscall stub pattern
    printf("Functions with syscall stubs (4C 8B D1 B8):\n");
    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        auto name = (const char*)(ntdll + names[i]);
        if (name[0] == 'N' && name[1] == 't') {
            auto func = ntdll + functions[ordinals[i]];
            if (func[0] == 0x4C && func[1] == 0x8B && func[2] == 0xD1 && func[3] == 0xB8) {
                uint32_t ssn = *(uint32_t*)(func + 4);
                if (ssn == 0x5B || ssn == 0x31 || ssn == 0x36) {
                    printf("  SSN 0x%04X = %s\n", ssn, name);
                }
            }
        }
    }

    // Also check what NtQuerySystemTime redirects to
    auto pNtQST = (uint8_t*)GetProcAddress((HMODULE)ntdll, "NtQuerySystemTime");
    if (pNtQST) {
        printf("\nNtQuerySystemTime @ %p:\n  ", pNtQST);
        for (int i = 0; i < 32; i++) printf("%02X ", pNtQST[i]);
        printf("\n");
        if (pNtQST[0] == 0xE9) {
            int32_t rel = *(int32_t*)(pNtQST + 1);
            uint8_t* target = pNtQST + 5 + rel;
            printf("  JMP target @ %p:\n  ", target);
            for (int i = 0; i < 16; i++) printf("%02X ", target[i]);
            printf("\n");
        }
    }

    // Find ALL functions that use SSN range 0x50-0x60
    printf("\nAll SSNs in range 0x50-0x65:\n");
    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        auto name = (const char*)(ntdll + names[i]);
        if (name[0] == 'N' && name[1] == 't') {
            auto func = ntdll + functions[ordinals[i]];
            if (func[0] == 0x4C && func[1] == 0x8B && func[2] == 0xD1 && func[3] == 0xB8) {
                uint32_t ssn = *(uint32_t*)(func + 4);
                if (ssn >= 0x50 && ssn <= 0x65) {
                    printf("  SSN 0x%04X = %s\n", ssn, name);
                }
            }
        }
    }

    return 0;
}
