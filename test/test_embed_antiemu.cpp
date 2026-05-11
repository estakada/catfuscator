#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <random>
#include <windows.h>

// Reproduce what make_antiemu_instr + make_inline_antiemu does
// and test execution in a realistic context

static void append_u32(std::vector<uint8_t>& v, uint32_t val) {
    v.push_back(val & 0xFF);
    v.push_back((val >> 8) & 0xFF);
    v.push_back((val >> 16) & 0xFF);
    v.push_back((val >> 24) & 0xFF);
}

static void emit_dynamic_ssn(std::mt19937& gen, uint32_t ssn, std::vector<uint8_t>& b) {
    uint32_t k1 = gen(), k2 = gen();
    uint32_t enc;
    switch (gen() % 4) {
    default:
    case 0: enc = (ssn - k2) ^ k1;
        b.push_back(0xB8); append_u32(b, enc);
        b.push_back(0x35); append_u32(b, k1);
        b.push_back(0x05); append_u32(b, k2);
        break;
    case 1: enc = (ssn ^ k1) - k2;
        b.push_back(0xB8); append_u32(b, enc);
        b.push_back(0x05); append_u32(b, k2);
        b.push_back(0x35); append_u32(b, k1);
        break;
    case 2: enc = (ssn ^ k1) + k2;
        b.push_back(0xB8); append_u32(b, enc);
        b.push_back(0x2D); append_u32(b, k2);
        b.push_back(0x35); append_u32(b, k1);
        break;
    case 3: enc = (ssn + k2) ^ k1;
        b.push_back(0xB8); append_u32(b, enc);
        b.push_back(0x35); append_u32(b, k1);
        b.push_back(0x2D); append_u32(b, k2);
        break;
    }
}

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
    std::random_device rd;
    std::mt19937 gen(rd());

    // Run variant 9 many times with different random seeds
    printf("=== Variant 9 (NtQueryPerformanceCounter) ===\n");
    for (int trial = 0; trial < 100; trial++) {
        std::vector<uint8_t> crash_bytes = {0x0F, 0x0B}; // ud2
        uint8_t crash_skip = 2;

        std::vector<uint8_t> bytes;
        bytes = { 0x9C };
        bytes.push_back(0x50);
        bytes.push_back(0x51);
        bytes.push_back(0x52);
        bytes.insert(bytes.end(), { 0x41, 0x52 });
        bytes.insert(bytes.end(), { 0x41, 0x53 });
        bytes.insert(bytes.end(), { 0x48, 0x83, 0xEC, 0x10 });
        bytes.insert(bytes.end(), { 0x48, 0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00 });
        bytes.insert(bytes.end(), { 0x4C, 0x8D, 0x14, 0x24 });
        bytes.insert(bytes.end(), { 0x31, 0xD2 });
        emit_dynamic_ssn(gen, 0x31, bytes);
        bytes.insert(bytes.end(), { 0x0F, 0x05 });
        bytes.insert(bytes.end(), { 0x48, 0x8B, 0x04, 0x24 });
        bytes.insert(bytes.end(), { 0x48, 0x85, 0xC0 });
        bytes.push_back(0x75); bytes.push_back(crash_skip);
        bytes.insert(bytes.end(), crash_bytes.begin(), crash_bytes.end());
        bytes.insert(bytes.end(), { 0x48, 0x83, 0xC4, 0x10 });
        bytes.insert(bytes.end(), { 0x41, 0x5B });
        bytes.insert(bytes.end(), { 0x41, 0x5A });
        bytes.push_back(0x5A);
        bytes.push_back(0x59);
        bytes.push_back(0x58);
        bytes.push_back(0x9D);

        memcpy(buf, bytes.data(), bytes.size());
        buf[bytes.size()] = 0xC3;

        auto fn = (void(*)())buf;
        __try {
            fn();
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            printf("Trial %d CRASH (size=%zu): 0x%08X\n", trial, bytes.size(), GetExceptionCode());
            printf("Bytes: ");
            for (size_t i = 0; i < bytes.size(); i++) printf("%02X ", bytes[i]);
            printf("\n");
            VirtualFree(buf, 0, MEM_RELEASE);
            return 1;
        }
    }
    printf("All 100 trials PASSED\n");

    // Same for variant 10
    printf("\n=== Variant 10 (NtQuerySystemInformation) ===\n");
    for (int trial = 0; trial < 100; trial++) {
        std::vector<uint8_t> crash_bytes = {0x0F, 0x0B};
        uint8_t crash_skip = 2;

        std::vector<uint8_t> bytes;
        bytes = { 0x9C };
        bytes.push_back(0x50);
        bytes.push_back(0x51);
        bytes.push_back(0x52);
        bytes.insert(bytes.end(), { 0x41, 0x50 });
        bytes.insert(bytes.end(), { 0x41, 0x51 });
        bytes.insert(bytes.end(), { 0x41, 0x52 });
        bytes.insert(bytes.end(), { 0x41, 0x53 });
        bytes.insert(bytes.end(), { 0x48, 0x83, 0xEC, 0x60 });
        bytes.insert(bytes.end(), { 0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00 });
        bytes.insert(bytes.end(), { 0x49, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00 });
        bytes.insert(bytes.end(), { 0x48, 0x8D, 0x54, 0x24, 0x20 });
        bytes.insert(bytes.end(), { 0x49, 0xC7, 0xC0, 0x40, 0x00, 0x00, 0x00 });
        bytes.insert(bytes.end(), { 0x4D, 0x31, 0xC9 });
        emit_dynamic_ssn(gen, 0x36, bytes);
        bytes.insert(bytes.end(), { 0x0F, 0x05 });
        bytes.insert(bytes.end(), { 0x48, 0x8B, 0x44, 0x24, 0x20 });
        bytes.insert(bytes.end(), { 0x48, 0x85, 0xC0 });
        bytes.push_back(0x75); bytes.push_back(crash_skip);
        bytes.insert(bytes.end(), crash_bytes.begin(), crash_bytes.end());
        bytes.insert(bytes.end(), { 0x48, 0x83, 0xC4, 0x60 });
        bytes.insert(bytes.end(), { 0x41, 0x5B });
        bytes.insert(bytes.end(), { 0x41, 0x5A });
        bytes.insert(bytes.end(), { 0x41, 0x59 });
        bytes.insert(bytes.end(), { 0x41, 0x58 });
        bytes.push_back(0x5A);
        bytes.push_back(0x59);
        bytes.push_back(0x58);
        bytes.push_back(0x9D);

        memcpy(buf, bytes.data(), bytes.size());
        buf[bytes.size()] = 0xC3;

        auto fn = (void(*)())buf;
        __try {
            fn();
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            printf("Trial %d CRASH (size=%zu): 0x%08X\n", trial, bytes.size(), GetExceptionCode());
            VirtualFree(buf, 0, MEM_RELEASE);
            return 1;
        }
    }
    printf("All 100 trials PASSED\n");

    VirtualFree(buf, 0, MEM_RELEASE);
    return 0;
}
