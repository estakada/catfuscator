#include <stdio.h>
#include <stdint.h>

extern "C" void CatfuscatorVirtualizeBegin(void);
extern "C" void CatfuscatorVirtualizeEnd(void);
extern "C" void CatfuscatorMutateBegin(void);
extern "C" void CatfuscatorMutateEnd(void);

int check_serial(const char* serial) {
    CatfuscatorVirtualizeBegin();

    int sum = 0;
    for (int i = 0; serial[i] != '\0'; i++) {
        sum += serial[i];
        sum ^= (i * 0x1337);
    }

    int result = (sum & 0xFFFF) == 0x4242;

    CatfuscatorVirtualizeEnd();
    return result;
}

void decode_message(char* msg, int len) {
    CatfuscatorMutateBegin();

    for (int i = 0; i < len; i++) {
        msg[i] ^= 0x55;
        msg[i] += 3;
    }

    CatfuscatorMutateEnd();
}

int main() {
    const char* serial = "TEST-1234-ABCD";

    printf("Checking serial: %s\n", serial);

    if (check_serial(serial))
        printf("Serial is VALID\n");
    else
        printf("Serial is INVALID\n");

    char secret[] = "Hello World!";
    decode_message(secret, 12);
    printf("Decoded: ");
    for (int i = 0; i < 12; i++)
        printf("%02X ", (unsigned char)secret[i]);
    printf("\n");

    return 0;
}
