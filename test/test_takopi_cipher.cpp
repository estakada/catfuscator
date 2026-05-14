// Per-stage regression test: TAKOPI-like decrypt under Catfuscator MUTATE.
//
//   test_takopi_cipher.exe N            - run stage N (1..5), exits 0/N
//   test_takopi_cipher.exe --print      - print expected outputs of all stages
//
// Per-stage exit codes:
//   0   - this stage matched its expected output
//   N   - mismatch (N == stage number)
//   crash (0xC0000005, 0xC000001D, ...) - mutation generated broken code

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <intrin.h>

#include "../sdk/Catfuscator_sdk.h"

__declspec(noinline) uint64_t stage1(uint64_t v) {
    MUTATE_BEGIN;
    v = _rotl64(v, 13);
    MUTATE_END;
    return v;
}

__declspec(noinline) uint64_t stage2(uint64_t v) {
    MUTATE_BEGIN;
    v = _rotl64(v, 7);
    v ^= 0xDEADBEEFCAFEBABEULL;
    v = _rotr64(v, 11);
    v ^= 0x0123456789ABCDEFULL;
    v = _rotl64(v, 17);
    MUTATE_END;
    return v;
}

__declspec(noinline) uint64_t stage3(uint64_t v) {
    MUTATE_BEGIN;
    v ^= v >> 3;
    v ^= v >> 6;
    v ^= v >> 12;
    v ^= v >> 24;
    v ^= v >> 48;
    v = (v ^ 0xDEADBEEFULL) + 2 * (v & 0xDEADBEEFULL);
    v = ((v | 0xCAFEBABEULL) - (v & 0xCAFEBABEULL)) + 0xCAFEBABEULL;
    MUTATE_END;
    return v;
}

__declspec(noinline) uint64_t stage4(uint64_t v) {
    MUTATE_BEGIN;
    v *= 0x9E3779B97F4A7C15ULL;
    v ^= v >> 32;
    v *= 0xBF58476D1CE4E5B9ULL;
    v ^= v >> 27;
    v *= 0x94D049BB133111EBULL;
    v ^= v >> 31;
    MUTATE_END;
    return v;
}

__declspec(noinline) uint64_t stage5(uint64_t v) {
    MUTATE_BEGIN;
    v = _rotl64(v, 11);
    v *= 0x9E3779B97F4A7C15ULL;
    v ^= v >> 23;
    v = (v ^ 0x1234567890ABCDEFULL) + 2 * (v & 0x1234567890ABCDEFULL);
    v = _rotr64(v, 17);
    v ^= v >> 13;
    v *= 0xCAFEBABEDEADBEEFULL;
    v = _rotl64(v, 5);
    MUTATE_END;
    return v;
}

// === Stage 6: function call inside MUTATE region (like TAKOPI's takopi_index_unmix) ===
__declspec(noinline) uint64_t helper_unmix(uint64_t v, uint64_t idx) {
    return v ^ (idx * 0x9E3779B97F4A7C15ULL);
}

__declspec(noinline) uint64_t stage6(uint64_t v) {
    MUTATE_BEGIN;
    uint64_t a = helper_unmix(v, 7);
    a = _rotl64(a, 11);
    a = helper_unmix(a, 13);
    a ^= 0xDEADBEEFCAFEBABEULL;
    a = helper_unmix(a, 19);
    MUTATE_END;
    return a;
}

// === Stage 7: memory access (mimics cfs->get_u8_fast() + buffer reads) ===
__declspec(noinline) uint64_t stage7(uint64_t v, const uint8_t* buf) {
    MUTATE_BEGIN;
    uint64_t a = v;
    a ^= (uint64_t)buf[0] << 0;
    a ^= (uint64_t)buf[1] << 8;
    a ^= (uint64_t)buf[2] << 16;
    a ^= (uint64_t)buf[3] << 24;
    a = _rotl64(a, 13);
    a += (uint64_t)buf[4];
    a *= 0x9E3779B97F4A7C15ULL;
    MUTATE_END;
    return a;
}

// === Stage 8: long MBA chain (mimics ~3KB TAKOPI_CLASSFILE_N_DECRYPT) ===
__declspec(noinline) uint64_t stage8(uint64_t v) {
    MUTATE_BEGIN;
    // Mimics the giant MBA chain in real TAKOPI: many XOR/AND/ADD/SUB/MUL ops
    v ^= v >> 3;  v = (v ^ 0xA1B2C3D4ULL) + 2 * (v & 0xA1B2C3D4ULL);
    v ^= v >> 7;  v = ((v | 0x5566778899AABBCCULL) - (v & 0x5566778899AABBCCULL)) + 0x5566778899AABBCCULL;
    v ^= v >> 11; v *= 0x9E3779B97F4A7C15ULL;
    v ^= v >> 13; v = (v ^ 0xDEADBEEFULL) + 2 * (v & 0xDEADBEEFULL);
    v ^= v >> 17; v = ((v | 0xCAFEBABEULL) - (v & 0xCAFEBABEULL)) + 0xCAFEBABEULL;
    v ^= v >> 19; v *= 0xBF58476D1CE4E5B9ULL;
    v ^= v >> 23; v = (v ^ 0x123456789ABCDEF0ULL) + 2 * (v & 0x123456789ABCDEF0ULL);
    v ^= v >> 29; v = ((v | 0x11223344ULL) - (v & 0x11223344ULL)) + 0x11223344ULL;
    v ^= v >> 31; v *= 0x94D049BB133111EBULL;
    v ^= v >> 37; v = (v ^ 0xFEDCBA98ULL) + 2 * (v & 0xFEDCBA98ULL);
    v ^= v >> 41; v = ((v | 0xAABBCCDDEEFF0011ULL) - (v & 0xAABBCCDDEEFF0011ULL)) + 0xAABBCCDDEEFF0011ULL;
    v ^= v >> 43; v *= 0xC6BC279692B5C323ULL;
    v ^= v >> 47; v = (v ^ 0x0F0F0F0FULL) + 2 * (v & 0x0F0F0F0FULL);
    MUTATE_END;
    return v;
}

int main(int argc, char** argv) {
    const uint64_t INPUT = 0xDEADBEEFCAFEBABEULL;
    static const uint8_t BUF[8] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    const uint64_t EXP[8] = {
        0xB7DDF95FD757DBD5ULL,
        0x967D51FAF3277624ULL,
        0xC6618F0EEBC26FE2ULL,
        0xFD7AA07186FA32C6ULL,
        0x2A0C4DDEEB143BA9ULL,
        0x273575CF7040AE49ULL,
        0x67390A6811160772ULL,
        0x4127EE0E690A7C64ULL,
    };

    if (argc > 1 && strcmp(argv[1], "--print") == 0) {
        printf("stage1: 0x%016llX\n", (unsigned long long)stage1(INPUT));
        printf("stage2: 0x%016llX\n", (unsigned long long)stage2(INPUT));
        printf("stage3: 0x%016llX\n", (unsigned long long)stage3(INPUT));
        printf("stage4: 0x%016llX\n", (unsigned long long)stage4(INPUT));
        printf("stage5: 0x%016llX\n", (unsigned long long)stage5(INPUT));
        printf("stage6: 0x%016llX\n", (unsigned long long)stage6(INPUT));
        printf("stage7: 0x%016llX\n", (unsigned long long)stage7(INPUT, BUF));
        printf("stage8: 0x%016llX\n", (unsigned long long)stage8(INPUT));
        return 0;
    }

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <stage_index 1..8 | --print>\n", argv[0]);
        return 99;
    }

    int idx = atoi(argv[1]);
    uint64_t out = 0;
    switch (idx) {
        case 1: out = stage1(INPUT); break;
        case 2: out = stage2(INPUT); break;
        case 3: out = stage3(INPUT); break;
        case 4: out = stage4(INPUT); break;
        case 5: out = stage5(INPUT); break;
        case 6: out = stage6(INPUT); break;
        case 7: out = stage7(INPUT, BUF); break;
        case 8: out = stage8(INPUT); break;
        default:
            fprintf(stderr, "bad stage index %d\n", idx);
            return 99;
    }

    if (out != EXP[idx - 1]) {
        fprintf(stderr,
                "stage%d FAIL: got 0x%016llX expected 0x%016llX\n",
                idx,
                (unsigned long long)out,
                (unsigned long long)EXP[idx - 1]);
        return idx;
    }

    return 0;
}
