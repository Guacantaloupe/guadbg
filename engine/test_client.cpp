// test_client.cpp — guadbg 引擎管道的最小 CLI 客户端（冒烟测试用）
// 用法: test_client.exe <cmd> [json_args]
// 退出码: 0=ok 1=引擎返回错误 2=连接/通信失败
// 输出: stdout 收到与请求 id 匹配的响应 JSON（单行）
//       stderr 收到的引擎事件（调试用）
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const char* ID_MARK = "\"id\":1";

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: test_client.exe <cmd> [json_args]\n");
        return 2;
    }
    const char* cmd = argv[1];
    const char* args = argc > 2 ? argv[2] : "{}";

    HANDLE h = INVALID_HANDLE_VALUE;
    for (int i = 0; i < 40; i++) {
        h = CreateFileW(L"\\\\.\\pipe\\guadbg",
            GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) break;
        Sleep(250);
    }
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "connect failed err=%lu\n", GetLastError());
        return 2;
    }

    char req[8192];
    _snprintf_s(req, sizeof(req), _TRUNCATE,
        "{\"id\":1,\"cmd\":\"%s\",\"args\":%s}", cmd, args);
    DWORD w = 0;
    if (!WriteFile(h, req, (DWORD)strlen(req), &w, NULL)) {
        fprintf(stderr, "write failed err=%lu\n", GetLastError());
        return 2;
    }

    static char buf[4 * 1024 * 1024];
    for (;;) {
        DWORD r = 0;
        if (!ReadFile(h, buf, sizeof(buf) - 1, &r, NULL) || r == 0) {
            fprintf(stderr, "read failed/err, engine closed pipe\n");
            return 2;
        }
        buf[r] = 0;
        // 客户端句柄默认字节读模式，一次 ReadFile 可能返回多条 NUL 分隔报文
        char* s = buf;
        while (*s) {
            if (strstr(s, ID_MARK)) {
                printf("%s\n", s);
                return strstr(s, "\"ok\":true") ? 0 : 1;
            }
            fprintf(stderr, "event: %s\n", s);
            s += strlen(s) + 1;
        }
    }
}
