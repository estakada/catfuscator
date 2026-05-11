#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cctype>
#include <intrin.h>
#include <windows.h>
#include <winternl.h>

// Same hash function as pe.cpp
static uint32_t hash_api_string(const char* str) {
    uint32_t h = 0x811C9DC5;
    while (*str) {
        h ^= static_cast<uint8_t>(tolower(static_cast<unsigned char>(*str++)));
        h *= 0x01000193;
    }
    return h;
}

// Hash on wide string (simulates resolver shellcode)
static uint32_t hash_api_wide(const wchar_t* str, int len) {
    uint32_t h = 0x811C9DC5;
    for (int i = 0; i < len; i++) {
        uint32_t c = (uint32_t)str[i];
        if (c >= 'A' && c <= 'Z') c += 32;
        h ^= c;
        h *= 0x01000193;
    }
    return h;
}

int main() {
    const char* dll_name = "KERNEL32.dll";
    uint32_t build_hash = hash_api_string(dll_name);
    printf("hash_api_string(\"%s\") = 0x%08X\n", dll_name, build_hash);

    // Walk PEB manually using same offsets as resolver
    uint64_t peb_addr = __readgsqword(0x60);
    uint64_t ldr = *(uint64_t*)(peb_addr + 0x18);
    uint8_t* list_head = (uint8_t*)(ldr + 0x20);
    uint8_t* entry = *(uint8_t**)(list_head); // Flink

    printf("\nPEB walk (list_head=%p):\n", list_head);
    while (entry != list_head) {
        uint16_t name_len = *(uint16_t*)(entry + 0x48);
        wchar_t* name_buf = *(wchar_t**)(entry + 0x50);
        void* dll_base = *(void**)(entry + 0x20);

        if (name_len > 0 && name_buf) {
            int char_count = name_len / 2;
            uint32_t runtime_hash = hash_api_wide(name_buf, char_count);
            printf("  %.*S  base=%p  hash=0x%08X%s\n",
                char_count, name_buf, dll_base, runtime_hash,
                (runtime_hash == build_hash) ? " <-- MATCH" : "");
        }
        entry = *(uint8_t**)(entry); // Flink
    }

    // Check function hashes match
    printf("\nFunction hash comparison:\n");
    const char* test_funcs[] = { "ExitProcess", "GetProcessHeap", "VirtualProtect", "WriteFile", "GetLastError" };
    for (auto tf : test_funcs) {
        uint32_t h1 = hash_api_string(tf);
        // The resolver also lowercases, but export names are case-sensitive and typically mixed case
        // The resolver should still match because it lowercases both
        printf("  \"%s\" -> 0x%08X\n", tf, h1);
    }

    printf("\nDone.\n");
    return 0;
}
