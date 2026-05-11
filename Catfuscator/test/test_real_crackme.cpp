#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern "C" void CatfuscatorUltraBegin(void);
extern "C" void CatfuscatorUltraEnd(void);

// --- RC4 implementation (protected) ---
struct rc4_state {
    unsigned char S[256];
    int i, j;
};

void rc4_init(rc4_state* state, const unsigned char* key, int keylen) {
    CatfuscatorUltraBegin();
    for (int i = 0; i < 256; i++)
        state->S[i] = (unsigned char)i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + state->S[i] + key[i % keylen]) & 0xFF;
        unsigned char tmp = state->S[i];
        state->S[i] = state->S[j];
        state->S[j] = tmp;
    }
    state->i = 0;
    state->j = 0;
    CatfuscatorUltraEnd();
}

void rc4_crypt(rc4_state* state, unsigned char* data, int len) {
    CatfuscatorUltraBegin();
    for (int n = 0; n < len; n++) {
        state->i = (state->i + 1) & 0xFF;
        state->j = (state->j + state->S[state->i]) & 0xFF;
        unsigned char tmp = state->S[state->i];
        state->S[state->i] = state->S[state->j];
        state->S[state->j] = tmp;
        int k = (state->S[state->i] + state->S[state->j]) & 0xFF;
        data[n] ^= state->S[k];
    }
    CatfuscatorUltraEnd();
}

// --- CRC32 (protected) ---
unsigned int crc32_compute(const unsigned char* data, int len) {
    CatfuscatorUltraBegin();
    unsigned int crc = 0xFFFFFFFF;
    for (int i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xEDB88320;
            else
                crc >>= 1;
        }
    }
    CatfuscatorUltraEnd();
    return crc ^ 0xFFFFFFFF;
}

// --- License key validation (protected) ---
// Format: XXXX-XXXX-XXXX-XXXX (hex digits)
// Validation: CRC32 of first 3 groups must match 4th group (as hex)
int validate_license(const char* key) {
    CatfuscatorUltraBegin();
    int result = 0;

    // Check format: 19 chars, dashes at positions 4, 9, 14
    int len = 0;
    while (key[len]) len++;
    if (len != 19) { CatfuscatorUltraEnd(); return 0; }
    if (key[4] != '-' || key[9] != '-' || key[14] != '-') { CatfuscatorUltraEnd(); return 0; }

    // Extract first 14 chars (3 groups + dashes)
    unsigned char buf[14];
    for (int i = 0; i < 14; i++)
        buf[i] = (unsigned char)key[i];

    // CRC32 of first 3 groups
    unsigned int crc = crc32_compute(buf, 14);

    // Parse 4th group as hex
    unsigned int check = 0;
    for (int i = 15; i < 19; i++) {
        char c = key[i];
        unsigned int digit;
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
        else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
        else { CatfuscatorUltraEnd(); return 0; }
        check = (check << 4) | digit;
    }

    // Last 4 hex digits must match lower 16 bits of CRC
    result = ((crc & 0xFFFF) == check) ? 1 : 0;
    CatfuscatorUltraEnd();
    return result;
}

// --- Matrix multiply 4x4 (protected, uses lots of FP) ---
struct mat4 {
    double m[4][4];
};

void mat4_multiply(const mat4* a, const mat4* b, mat4* out) {
    CatfuscatorUltraBegin();
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            double sum = 0.0;
            for (int k = 0; k < 4; k++)
                sum += a->m[i][k] * b->m[k][j];
            out->m[i][j] = sum;
        }
    }
    CatfuscatorUltraEnd();
}

int mat4_is_identity(const mat4* m) {
    CatfuscatorUltraBegin();
    int ok = 1;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            double expected = (i == j) ? 1.0 : 0.0;
            double diff = m->m[i][j] - expected;
            if (diff < -0.0001 || diff > 0.0001)
                ok = 0;
        }
    }
    CatfuscatorUltraEnd();
    return ok;
}

// --- Simple hash table (protected, pointer-heavy) ---
struct hash_entry {
    const char* key;
    int value;
    hash_entry* next;
};

#define HT_SIZE 16
struct hash_table {
    hash_entry* buckets[HT_SIZE];
};

unsigned int ht_hash(const char* key) {
    CatfuscatorUltraBegin();
    unsigned int h = 0;
    while (*key) {
        h = h * 31 + (unsigned char)*key;
        key++;
    }
    CatfuscatorUltraEnd();
    return h % HT_SIZE;
}

void ht_init(hash_table* ht) {
    for (int i = 0; i < HT_SIZE; i++)
        ht->buckets[i] = nullptr;
}

void ht_put(hash_table* ht, const char* key, int value, hash_entry* storage) {
    CatfuscatorUltraBegin();
    unsigned int idx = ht_hash(key);
    storage->key = key;
    storage->value = value;
    storage->next = ht->buckets[idx];
    ht->buckets[idx] = storage;
    CatfuscatorUltraEnd();
}

int ht_get(hash_table* ht, const char* key, int default_val) {
    CatfuscatorUltraBegin();
    unsigned int idx = ht_hash(key);
    hash_entry* e = ht->buckets[idx];
    while (e) {
        const char* a = e->key;
        const char* b = key;
        int match = 1;
        while (*a && *b) {
            if (*a != *b) { match = 0; break; }
            a++; b++;
        }
        if (match && *a == 0 && *b == 0) {
            int v = e->value;
            CatfuscatorUltraEnd();
            return v;
        }
        e = e->next;
    }
    CatfuscatorUltraEnd();
    return default_val;
}

// --- Quicksort (protected, recursive) ---
void quicksort(int* arr, int lo, int hi) {
    CatfuscatorUltraBegin();
    if (lo < hi) {
        int pivot = arr[hi];
        int i = lo - 1;
        for (int j = lo; j < hi; j++) {
            if (arr[j] <= pivot) {
                i++;
                int tmp = arr[i];
                arr[i] = arr[j];
                arr[j] = tmp;
            }
        }
        int tmp = arr[i + 1];
        arr[i + 1] = arr[hi];
        arr[hi] = tmp;
        int pi = i + 1;

        CatfuscatorUltraEnd();
        quicksort(arr, lo, pi - 1);
        quicksort(arr, pi + 1, hi);
    } else {
        CatfuscatorUltraEnd();
    }
}

int main() {
    int ok = 1;
    int test = 0;
    int pass = 0;

    // === 1. RC4 encrypt/decrypt ===
    test++;
    {
        unsigned char plaintext[] = "Hello, Catfuscator VM!";
        unsigned char ciphertext[20];
        unsigned char decrypted[20];
        int len = 19;
        memcpy(ciphertext, plaintext, len);
        memcpy(decrypted, plaintext, len);

        unsigned char key[] = "SecretKey123";
        rc4_state enc, dec;
        rc4_init(&enc, key, 12);
        rc4_crypt(&enc, ciphertext, len);

        // Verify ciphertext differs from plaintext
        int differs = 0;
        for (int i = 0; i < len; i++)
            if (ciphertext[i] != plaintext[i]) differs++;

        rc4_init(&dec, key, 12);
        rc4_crypt(&dec, ciphertext, len);

        // Verify decrypted matches original
        int matches = (memcmp(ciphertext, plaintext, len) == 0);
        printf("[%d] RC4: differs=%d decrypt_ok=%d\n", test, differs > 0, matches);
        if (differs > 0 && matches) pass++; else ok = 0;
    }

    // === 2. CRC32 ===
    test++;
    {
        unsigned int c1 = crc32_compute((const unsigned char*)"", 0);
        unsigned int c2 = crc32_compute((const unsigned char*)"123456789", 9);
        printf("[%d] CRC32: empty=0x%08X (exp 0x00000000) '123456789'=0x%08X (exp 0xCBF43926)\n",
               test, c1, c2);
        if (c1 == 0x00000000 && c2 == 0xCBF43926) pass++; else ok = 0;
    }

    // === 3. License validation ===
    test++;
    {
        // Generate a valid key: take "DEAD-BEEF-CAFE" and compute CRC
        unsigned int crc = crc32_compute((const unsigned char*)"DEAD-BEEF-CAFE", 14);
        char valid_key[20];
        sprintf(valid_key, "DEAD-BEEF-CAFE-%04X", crc & 0xFFFF);

        int v1 = validate_license(valid_key);
        int v2 = validate_license("DEAD-BEEF-CAFE-0000");
        int v3 = validate_license("too-short");
        printf("[%d] License: valid=%d invalid=%d short=%d (exp 1,0,0) key=%s\n",
               test, v1, v2, v3, valid_key);
        if (v1 == 1 && v2 == 0 && v3 == 0) pass++; else ok = 0;
    }

    // === 4. Matrix multiply (A * A^-1 = I for rotation) ===
    test++;
    {
        // Rotation matrix 90 degrees around Z
        mat4 rot = {{{0,-1,0,0},{1,0,0,0},{0,0,1,0},{0,0,0,1}}};
        // Its inverse: -90 degrees
        mat4 inv = {{{0,1,0,0},{-1,0,0,0},{0,0,1,0},{0,0,0,1}}};
        mat4 result;
        mat4_multiply(&rot, &inv, &result);
        int is_id = mat4_is_identity(&result);
        printf("[%d] Matrix rot*inv=identity: %d (exp 1)\n", test, is_id);
        if (is_id) pass++; else ok = 0;
    }

    // === 5. Hash table ===
    test++;
    {
        hash_table ht;
        ht_init(&ht);
        hash_entry entries[5];
        ht_put(&ht, "alpha", 10, &entries[0]);
        ht_put(&ht, "beta", 20, &entries[1]);
        ht_put(&ht, "gamma", 30, &entries[2]);
        ht_put(&ht, "delta", 40, &entries[3]);
        ht_put(&ht, "epsilon", 50, &entries[4]);

        int a = ht_get(&ht, "alpha", -1);
        int b = ht_get(&ht, "gamma", -1);
        int c = ht_get(&ht, "epsilon", -1);
        int d = ht_get(&ht, "missing", -1);
        printf("[%d] HashTable: alpha=%d gamma=%d epsilon=%d missing=%d (exp 10,30,50,-1)\n",
               test, a, b, c, d);
        if (a == 10 && b == 30 && c == 50 && d == -1) pass++; else ok = 0;
    }

    // === 6. Quicksort ===
    test++;
    {
        int arr[] = {42, 17, 93, 5, 28, 76, 61, 34, 89, 12, 50, 3, 67, 21, 85, 8};
        int n = 16;
        quicksort(arr, 0, n - 1);
        int sorted = 1;
        for (int i = 0; i < n - 1; i++)
            if (arr[i] > arr[i + 1]) sorted = 0;
        printf("[%d] Quicksort 16 elements: %s [%d,%d,%d,...,%d,%d]\n",
               test, sorted ? "OK" : "FAIL", arr[0], arr[1], arr[2], arr[14], arr[15]);
        if (sorted && arr[0] == 3 && arr[15] == 93) pass++; else ok = 0;
    }

    // === 7. RC4 stream consistency ===
    test++;
    {
        unsigned char stream1[256], stream2[256];
        memset(stream1, 0, 256);
        memset(stream2, 0, 256);
        unsigned char key[] = "TestKey";
        rc4_state s1, s2;
        rc4_init(&s1, key, 7);
        rc4_crypt(&s1, stream1, 256);
        rc4_init(&s2, key, 7);
        rc4_crypt(&s2, stream2, 256);
        int match = (memcmp(stream1, stream2, 256) == 0);
        int nonzero = 0;
        for (int i = 0; i < 256; i++) if (stream1[i]) nonzero++;
        printf("[%d] RC4 stream: consistent=%d nonzero=%d (exp 1, >200)\n",
               test, match, nonzero);
        if (match && nonzero > 200) pass++; else ok = 0;
    }

    printf("\n=== %d/%d tests passed ===\n", pass, test);
    return ok ? 0 : 1;
}
