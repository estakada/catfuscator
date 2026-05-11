#include <stdio.h>

extern "C" void CatfuscatorVirtualizeBegin(void);
extern "C" void CatfuscatorVirtualizeEnd(void);
extern "C" void CatfuscatorMutateBegin(void);
extern "C" void CatfuscatorMutateEnd(void);

int sum_array(int* arr, int n) {
    CatfuscatorMutateBegin();

    int total = 0;
    for (int i = 0; i < n; i++) {
        total += arr[i];
    }

    CatfuscatorMutateEnd();
    return total;
}

int main() {
    int arr[] = {10, 20, 30, 40, 50};
    int result = sum_array(arr, 5);
    printf("Sum: %d (expected 150)\n", result);
    return result == 150 ? 0 : 1;
}
