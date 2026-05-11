#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__declspec(noinline) int classify(int x) {
    switch (x) {
    case 0: return 100;
    case 1: return 200;
    case 2: return 300;
    case 3: return 400;
    case 4: return 500;
    case 5: return 600;
    case 6: return 700;
    case 7: return 800;
    case 8: return 900;
    case 9: return 1000;
    default: return -1;
    }
}

__declspec(noinline) const char* day_name(int d) {
    switch (d) {
    case 0: return "Sunday";
    case 1: return "Monday";
    case 2: return "Tuesday";
    case 3: return "Wednesday";
    case 4: return "Thursday";
    case 5: return "Friday";
    case 6: return "Saturday";
    default: return "Unknown";
    }
}

__declspec(noinline) int fib(int n) {
    int a = 0, b = 1;
    for (int i = 0; i < n; i++) {
        int t = a + b;
        a = b;
        b = t;
    }
    return a;
}

int main() {
    int ok = 1;

    // Test classify
    if (classify(0) != 100) ok = 0;
    if (classify(5) != 600) ok = 0;
    if (classify(9) != 1000) ok = 0;
    if (classify(10) != -1) ok = 0;
    if (classify(-1) != -1) ok = 0;
    printf("[1] classify: %s\n", ok ? "OK" : "FAIL");

    // Test day_name
    int ok2 = 1;
    if (strcmp(day_name(0), "Sunday") != 0) ok2 = 0;
    if (strcmp(day_name(3), "Wednesday") != 0) ok2 = 0;
    if (strcmp(day_name(6), "Saturday") != 0) ok2 = 0;
    if (strcmp(day_name(7), "Unknown") != 0) ok2 = 0;
    printf("[2] day_name: %s\n", ok2 ? "OK" : "FAIL");

    // Test fib (no switch, sanity check)
    int ok3 = (fib(10) == 55) ? 1 : 0;
    printf("[3] fib(10)=%d: %s\n", fib(10), ok3 ? "OK" : "FAIL");

    int total = ok + ok2 + ok3;
    printf("\n=== %d/3 tests passed ===\n", total);
    return (total == 3) ? 0 : 1;
}
