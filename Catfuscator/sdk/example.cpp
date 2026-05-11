// Example: How to use Catfuscator markers in your project
//
// 1. Include Catfuscator_sdk.h
// 2. Assemble Catfuscator_markers.asm:  ml64 /c Catfuscator_markers.asm
// 3. Link Catfuscator_markers.obj into your project
// 4. Place VIRTUALIZE_BEGIN / VIRTUALIZE_END around code you want to protect
// 5. Build your project normally (with PDB or without)
// 6. Run:  Catfuscator.exe your_app.exe --markers

#include "Catfuscator_sdk.h"
#include <stdio.h>

int check_license(const char* key) {
    VIRTUALIZE_BEGIN;

    int sum = 0;
    for (int i = 0; key[i]; i++)
        sum += key[i];

    int valid = (sum % 256 == 0x42);

    VIRTUALIZE_END;
    return valid;
}

void decrypt_data(unsigned char* data, int size) {
    MUTATE_BEGIN;

    for (int i = 0; i < size; i++)
        data[i] ^= 0xAA;

    MUTATE_END;
}

int main() {
    const char* license = "test-key-12345";

    if (check_license(license))
        printf("License valid\n");
    else
        printf("License invalid\n");

    unsigned char secret[] = { 0xCA, 0xCB, 0xCC, 0xCD };
    decrypt_data(secret, sizeof(secret));

    return 0;
}
