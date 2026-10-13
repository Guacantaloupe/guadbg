#include <stdio.h>
#include <windows.h>

volatile int g_counter = 0;

int main(void) {
    printf("test_target: started (pid=%lu)\n", GetCurrentProcessId());
    for (int i = 0; i < 100000; i++) {
        g_counter++;
        Sleep(10);
    }
    printf("test_target: done counter=%d\n", g_counter);
    return 0;
}
