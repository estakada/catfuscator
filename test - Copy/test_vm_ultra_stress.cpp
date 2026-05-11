#include <stdio.h>
#include <stdint.h>

extern "C" void CatfuscatorUltraBegin(void);
extern "C" void CatfuscatorUltraEnd(void);

// Ultra stress test: CFF + mutation + VM on complex code
uint32_t __declspec(noinline) ultra_hash(const uint8_t* data, int len) {
    CatfuscatorUltraBegin();

    uint32_t h = 0x811c9dc5;
    for (int i = 0; i < len; i++) {
        h ^= data[i];
        h *= 0x01000193;
    }

    // Additional mixing
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;

    CatfuscatorUltraEnd();
    return h;
}

uint32_t __declspec(noinline) ultra_crc(const uint8_t* data, int len) {
    CatfuscatorUltraBegin();

    uint32_t crc = 0xFFFFFFFF;
    for (int i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xEDB88320;
            else
                crc >>= 1;
        }
    }
    crc ^= 0xFFFFFFFF;

    CatfuscatorUltraEnd();
    return crc;
}

int main() {
    printf("Before\n"); fflush(stdout);

    const char* test_str = "Hello, Catfuscator Ultra!";
    int len = 0;
    while (test_str[len]) len++;

    uint32_t h1 = ultra_hash((const uint8_t*)test_str, len);
    uint32_t h2 = ultra_hash((const uint8_t*)test_str, len);

    uint32_t c1 = ultra_crc((const uint8_t*)test_str, len);
    uint32_t c2 = ultra_crc((const uint8_t*)test_str, len);

    printf("hash=0x%08X crc=0x%08X\n", h1, c1);

    int pass = 1;
    if (h1 != h2) { printf("FAIL: hash inconsistent\n"); pass = 0; }
    if (c1 != c2) { printf("FAIL: crc inconsistent\n"); pass = 0; }

    // Known CRC32 of "123456789" = 0xCBF43926
    const char* crc_test = "123456789";
    uint32_t crc_check = ultra_crc((const uint8_t*)crc_test, 9);
    if (crc_check != 0xCBF43926) {
        printf("FAIL: CRC32('123456789') = 0x%08X, expected 0xCBF43926\n", crc_check);
        pass = 0;
    }

    if (pass) printf("ALL PASSED\n");
    fflush(stdout);
    return pass ? 0 : 1;
}
