#include <cstdio>
#include <cstdint>
#include <vector>
#include <random>
#include <windows.h>

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
    case 0:
        enc = (ssn - k2) ^ k1;
        b.push_back(0xB8); append_u32(b, enc);
        b.push_back(0x35); append_u32(b, k1);
        b.push_back(0x05); append_u32(b, k2);
        break;
    case 1:
        enc = (ssn ^ k1) - k2;
        b.push_back(0xB8); append_u32(b, enc);
        b.push_back(0x05); append_u32(b, k2);
        b.push_back(0x35); append_u32(b, k1);
        break;
    case 2:
        enc = (ssn ^ k1) + k2;
        b.push_back(0xB8); append_u32(b, enc);
        b.push_back(0x2D); append_u32(b, k2);
        b.push_back(0x35); append_u32(b, k1);
        break;
    case 3:
        enc = (ssn + k2) ^ k1;
        b.push_back(0xB8); append_u32(b, enc);
        b.push_back(0x35); append_u32(b, k1);
        b.push_back(0x2D); append_u32(b, k2);
        break;
    }
}

void run_test(uint8_t* buf, size_t size) {
    buf[size] = 0xC3; // ret
    printf("Executing %zu bytes...\n", size);
    fflush(stdout);
    auto fn = (void(*)())buf;
    __try {
        fn();
        printf("PASS: survived!\n");
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        printf("CRASH: exception 0x%08X\n", GetExceptionCode());
    }
}

int main() {
    std::random_device rd;
    std::mt19937 gen(rd());

    // Simulate variant 9
    auto crash_bytes = std::vector<uint8_t>{0x0F, 0x0B}; // ud2
    uint8_t crash_skip = 2;

    std::vector<uint8_t> bytes;
    bytes = { 0x9C };                                       // pushfq
    bytes.push_back(0x50);                                  // push rax
    bytes.push_back(0x51);                                  // push rcx
    bytes.push_back(0x52);                                  // push rdx
    bytes.insert(bytes.end(), { 0x41, 0x52 });              // push r10
    bytes.insert(bytes.end(), { 0x41, 0x53 });              // push r11
    bytes.insert(bytes.end(), { 0x48, 0x83, 0xEC, 0x10 }); // sub rsp, 0x10
    bytes.insert(bytes.end(), { 0x48, 0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00 }); // mov qword [rsp], 0
    bytes.insert(bytes.end(), { 0x4C, 0x8D, 0x14, 0x24 }); // lea r10, [rsp]
    emit_dynamic_ssn(gen, 0x5B, bytes);
    bytes.insert(bytes.end(), { 0x0F, 0x05 });              // syscall
    bytes.insert(bytes.end(), { 0x48, 0x8B, 0x04, 0x24 }); // mov rax, [rsp]
    bytes.insert(bytes.end(), { 0x48, 0x85, 0xC0 });       // test rax, rax
    bytes.push_back(0x75); bytes.push_back(crash_skip);    // jnz over
    bytes.insert(bytes.end(), crash_bytes.begin(), crash_bytes.end());
    bytes.insert(bytes.end(), { 0x48, 0x83, 0xC4, 0x10 }); // add rsp, 0x10
    bytes.insert(bytes.end(), { 0x41, 0x5B });              // pop r11
    bytes.insert(bytes.end(), { 0x41, 0x5A });              // pop r10
    bytes.push_back(0x5A);                                  // pop rdx
    bytes.push_back(0x59);                                  // pop rcx
    bytes.push_back(0x58);                                  // pop rax
    bytes.push_back(0x9D);                                  // popfq

    printf("Total size: %zu bytes\n", bytes.size());
    for (size_t i = 0; i < bytes.size(); i++) {
        printf("%02X ", bytes[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");

    // Now try to execute it
    auto buf = (uint8_t*)VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(buf, bytes.data(), bytes.size());
    run_test(buf, bytes.size());
    VirtualFree(buf, 0, MEM_RELEASE);
    return 0;
}
