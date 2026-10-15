// guadbg_core.cpp —— Guadbg 核心引擎 v1
// 在 PEL_ref（寄生线程加载器）之上叠加一个进程内 VEH 调试器。
//
// 架构：
//   [目标 EXE（寄生线程，被调试者）]
//        │  异常（int3 / 单步 /  guard page / AV …）
//        ▼
//   VEH 引擎（本文件）—— 断点/单步/跟踪/条件表达式/补丁/标记
//        │  命名管道  \\.\pipe\guadbg  （JSON 报文）
//        ▼
//   broker.py —— MCP(stdio) + HTTP/Web UI 中继
//
// 隐藏性设计（对照 PEL_ref 的五条原则，全部保持）：
//   * 不使用 DebugActiveProcess / WaitForDebugEvent —— 无调试对象，
//     NtQueryInformationProcess(ProcessDebugPort/DebugFlags/ObjectHandle)
//     全部返回"未被调试"，PEB->BeingDebugged 恒为 0。
//   * 断点用 VEH 处理 int3，不依赖内核调试端口；进程映像伪装
//     （QueryFullProcessImageNameW / K32GetProcessImageFileNameW 钩子）
//     原样保留。
//   * 补丁落点约束：只偷 >=5 字节完整指令且 12 字节窗口全为 CC/90 填充，
//     kernelbase/ntdll 仍零改动。
//   * 手动 pause 用 SuspendThread 而非调试器挂起 —— 内核无 NtDebugActiveProcess 痕迹。
//
// 已知限制（研究级实现，见 README）：
//   * 硬件断点只能作用于本进程线程（Dr 寄存器按线程生效）。
//   * 手动 pause 期间不做指令级"安全点"对齐。
//   * DLL 加载/线程创建系统断点未实现（可用 VEH+Ldr 轮询扩展）。

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <vector>
#include <string>
#include <cstdint>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")

typedef LONG NTSTATUS;
#define NT_SUCCESS(st) ((NTSTATUS)(st) >= 0)

// ======================================================================
// 基础结构（与 PEL_ref 相同）
// ======================================================================
typedef struct _X_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} X_UNICODE_STRING;

typedef struct _X_RTL_USER_PROCESS_PARAMETERS {
    BYTE Reserved[0x60];
    X_UNICODE_STRING ImagePathName;
    X_UNICODE_STRING CommandLine;
} X_RTL_USER_PROCESS_PARAMETERS;

typedef struct _X_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    X_UNICODE_STRING FullDllName;
    X_UNICODE_STRING BaseDllName;
    // 下面这些字段在真实结构里也是存在的，而这个结构原先到此为止。
    //
    // 后果是实测的：只分配到 BaseDllName 就把条目插进链表，ntdll 走到它之后会读
    // `[rax+0x38]` 并与 9 比较——那是一条链表遍历里的版本/类型检查，而 rax 是
    // 从**未定义字段**里取出来的零。异常记录里 info2 = 0x38 正是这一点的直接证据：
    // 出错地址等于 0x38 说明基址寄存器是 0，指令读的就是 [0+0x38]。
    //
    // HashLinks 尤其要紧：ntdll 的按名查找会顺着它走，全零等于把一个 NULL 交给遍历。
    // 未使用的 LIST_ENTRY 必须是**自指的空链表**，不是零。
    ULONG Flags;
    ULONG LoadCount;
    ULONG TlsIndex;
    LIST_ENTRY HashLinks;
    PVOID SectionPointer;
    ULONG CheckSum;
    ULONG TimeDateStamp;
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
    PVOID ContextInformation;
    ULONG_PTR OriginalBase;
    LARGE_INTEGER LoadTime;
} X_LDR_DATA_TABLE_ENTRY;

typedef struct _X_PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} X_PEB_LDR_DATA;

typedef struct _X_PEB {
    BYTE Reserved1[0x10];
    PVOID ImageBaseAddress;
    PVOID Ldr;
    X_RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
} X_PEB;

static X_PEB* x_peb(void) { return (X_PEB*)__readgsqword(0x60); }

// ======================================================================
// 手动映射目标映像（不运行入口点，按段属性设置保护）
// ======================================================================
static void logf(const char* fmt, ...);   // 定义在下面，映射器要先用到
//
// 为什么必须自己映射，而不是找一个系统 API：
//
//   LoadLibraryW 会把 EXE 的入口点当 DllMain(hinstDLL, DLL_PROCESS_ATTACH, NULL) 调用，
//   于是目标自己的启动代码在**装载期间**就跑起来，而那一刻 PEB 还在描述引擎。
//   在 Sky.exe 上实测：0xC0000005 @ 0x7ffdd9da6df0（ntdll 内），两次运行地址完全相同。
//
//   LoadLibraryExW(..., LOAD_LIBRARY_AS_IMAGE_RESOURCE) 不调用入口点，这是对的，
//   但它**把所有段映射成只读**，于是一个想写自己 .data 的程序立刻访问违例——
//   这是实测的：换成它之后 test_target.exe 在系统地址上抛 0xC0000005，
//   而模块列表里也找不到它，因为这种映射不是一次真正的模块装载。
//
//   所以这里自己做：按映像头分配、逐段拷贝、按段特性设置页保护、按需重定位。
//   「不运行入口点」这个要求排除了所有现成 API，只能自己来。
static PVOID map_image_manually(const WCHAR* path, PVOID* out_ep, ULONG* out_size) {
    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        logf("[-] 打不开映像: %lu\n", GetLastError());
        return NULL;
    }
    LARGE_INTEGER fileSize{};
    GetFileSizeEx(hFile, &fileSize);
    std::vector<BYTE> raw(static_cast<std::size_t>(fileSize.QuadPart));
    DWORD got = 0;
    const BOOL readOk = ReadFile(hFile, raw.data(), static_cast<DWORD>(raw.size()), &got, NULL);
    CloseHandle(hFile);
    if (!readOk || got != raw.size()) {
        logf("[-] 读映像失败 (%lu, %lu/%zu)\n", GetLastError(), got, raw.size());
        return NULL;
    }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)raw.data();
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(raw.data() + dos->e_lfanew);
    const ULONG sizeOfImage = nt->OptionalHeader.SizeOfImage;
    PVOID preferred = (PVOID)(ULONG_PTR)nt->OptionalHeader.ImageBase;

    // 先试首选基址。映像里所有绝对地址都按这个基址写死，落在别处就要处理重定位；
    // 而 Sky.exe 只有 3 条重定位，说明它基本是按固定基址构建的。
    PVOID base = VirtualAlloc(preferred, sizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    bool relocated = false;
    if (!base) {
        base = VirtualAlloc(NULL, sizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        relocated = true;
        logf("[!] 首选基址 %p 不可用，改在 %p 映射（需要重定位）\n", preferred, base);
    }
    if (!base) {
        logf("[-] VirtualAlloc(%lu) 失败 %lu\n", sizeOfImage, GetLastError());
        return NULL;
    }

    // 头 + 段。按 VirtualSize 清零、按 SizeOfRawData 拷贝，两者不等时以小的为准，
    // 这是装载器对未初始化数据的处理方式。
    memcpy(base, raw.data(), nt->OptionalHeader.SizeOfHeaders);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (sec->SizeOfRawData == 0 || sec->VirtualAddress == 0) continue;
        BYTE* dst = (BYTE*)base + sec->VirtualAddress;
        const std::size_t copy = (sec->SizeOfRawData < sec->Misc.VirtualSize)
                                     ? sec->SizeOfRawData
                                     : sec->Misc.VirtualSize;
        if (copy) memcpy(dst, raw.data() + sec->PointerToRawData, copy);
    }

    // 重定位。只有在没拿到首选基址时才需要，但代码照写——一个不肯处理它的映射器
    // 会在基址被占用的机器上产生一堆无法解释的崩溃。
    if (relocated) {
        const auto delta = (ULONG_PTR)base - nt->OptionalHeader.ImageBase;
        const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        std::size_t applied = 0;
        if (dir.VirtualAddress && dir.Size) {
            BYTE* p = (BYTE*)base + dir.VirtualAddress;
            BYTE* end = p + dir.Size;
            while (p + sizeof(IMAGE_BASE_RELOCATION) <= end) {
                PIMAGE_BASE_RELOCATION block = (PIMAGE_BASE_RELOCATION)p;
                if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) break;
                const std::size_t count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
                WORD* entries = (WORD*)(block + 1);
                for (std::size_t k = 0; k < count; ++k) {
                    const WORD type = entries[k] >> 12;
                    const WORD off = entries[k] & 0xFFF;
                    BYTE* target = (BYTE*)base + block->VirtualAddress + off;
                    if (type == IMAGE_REL_BASED_DIR64) {
                        *(ULONG_PTR*)target += delta;
                        ++applied;
                    } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                        *(ULONG*)target += (ULONG)delta;
                        ++applied;
                    } else if (type == IMAGE_REL_BASED_ABSOLUTE) {
                        // padding
                    } else {
                        logf("[!] 未处理的基址重定位类型 %u\n", type);
                    }
                }
                p += block->SizeOfBlock;
            }
        }
        logf("[*] 已应用基址重定位: %zu 条\n", applied);
    }

    // 段保护。这一步是 LOAD_LIBRARY_AS_IMAGE_RESOURCE 缺的那一步，也是它不可用的原因：
    // 一个想写自己 .data 的程序在只读映射上立刻违例。
    sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        DWORD prot = PAGE_READONLY;
        const DWORD ch = sec->Characteristics;
        const bool x = (ch & IMAGE_SCN_MEM_EXECUTE) != 0;
        const bool r = (ch & IMAGE_SCN_MEM_READ) != 0;
        const bool w = (ch & IMAGE_SCN_MEM_WRITE) != 0;
        if (x && w) prot = PAGE_EXECUTE_READWRITE;
        else if (x) prot = r ? PAGE_EXECUTE_READ : PAGE_EXECUTE;
        else if (w) prot = PAGE_READWRITE;
        else if (r) prot = PAGE_READONLY;
        else prot = PAGE_NOACCESS;
        DWORD old = 0;
        VirtualProtect((BYTE*)base + sec->VirtualAddress,
                       sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData,
                       prot, &old);
    }

    *out_ep = (PVOID)((BYTE*)base + nt->OptionalHeader.AddressOfEntryPoint);
    *out_size = sizeOfImage;

    // 注册异常表。手动映射的映像不在加载器的表里，`.pdata` 因此对系统不可见，
    // 而 x64 的异常展开、`__C_specific_handler`、以及 CRT 的部分启动路径都依赖它。
    // 不注册的后果不是"异常处理差一点"，而是目标一进自己的代码就可能炸在 ntdll 里——
    // 这是实测：寄生线程跳到入口点之后立刻 0xC0000005 @ ntdll，info2 = 0xffffffffffffffff。
    {
        const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (dir.VirtualAddress && dir.Size) {
            const ULONG count = dir.Size / sizeof(RUNTIME_FUNCTION);
            auto* table = (RUNTIME_FUNCTION*)((BYTE*)base + dir.VirtualAddress);
            // 函数表里 BeginAddress/EndAddress 是 RVA；RtlAddFunctionTable 期望的就是这种形式。
            if (RtlAddFunctionTable(table, count, (DWORD64)base)) {
                logf("[*] 已注册异常表: %lu 个函数条目\n", count);
            } else {
                logf("[!] RtlAddFunctionTable 失败 (%lu)，异常展开可能不正确\n", GetLastError());
            }
        }
    }

    logf("[*] 手动映射完成: base=%p size=0x%lx ep=%p（入口点尚未运行）\n",
         base, sizeOfImage, *out_ep);
    return base;
}

// ======================================================================
// 日志
// ======================================================================
static void logf(const char* fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    printf("%s", buf);
    fflush(stdout);
}

// ======================================================================
// 极简 JSON（解析 + 构造）—— 足够请求/响应/事件报文使用
// ======================================================================
typedef struct jval {
    int type;                 // 0 null 1 bool 2 num 3 str 4 arr 5 obj
    int boolean;
    double num;
    char* str;                // type 3
    struct jval** items;      // type 4/5
    char** keys;              // type 5
    int n;
} jval;

static jval* jv_new(int type) {
    jval* v = (jval*)calloc(1, sizeof(jval));
    v->type = type;
    return v;
}
static jval* jv_bool(int b) { jval* v = jv_new(1); v->boolean = b; return v; }
static jval* jv_num(double d) { jval* v = jv_new(2); v->num = d; return v; }
static jval* jv_str(const char* s) {
    jval* v = jv_new(3);
    v->str = _strdup(s ? s : "");
    return v;
}
static void jv_add(jval* arr, jval* item) {
    arr->items = (jval**)realloc(arr->items, (arr->n + 1) * sizeof(jval*));
    arr->items[arr->n++] = item;
}
static void jv_put(jval* obj, const char* key, jval* item) {
    obj->items = (jval**)realloc(obj->items, (obj->n + 1) * sizeof(jval*));
    obj->keys = (char**)realloc(obj->keys, (obj->n + 1) * sizeof(char*));
    obj->items[obj->n] = item;
    obj->keys[obj->n] = _strdup(key);
    obj->n++;
}
static jval* jv_get(jval* obj, const char* key) {
    if (!obj || obj->type != 5) return NULL;
    for (int i = 0; i < obj->n; i++)
        if (_stricmp(obj->keys[i], key) == 0) return obj->items[i];
    return NULL;
}
static const char* jv_strval(jval* obj, const char* key, const char* def) {
    jval* v = jv_get(obj, key);
    if (v && v->type == 3) return v->str;
    return def;
}
static unsigned long long jv_numval(jval* obj, const char* key, unsigned long long def) {
    jval* v = jv_get(obj, key);
    if (v && v->type == 2) return (unsigned long long)v->num;
    if (v && v->type == 1) return (unsigned long long)v->boolean;
    if (v && v->type == 3) return _strtoui64(v->str, NULL, 0);
    return def;
}
static void jv_free(jval* v) {
    if (!v) return;
    if (v->str) free(v->str);
    for (int i = 0; i < v->n; i++) jv_free(v->items[i]);
    if (v->items) free(v->items);
    if (v->keys) {
        for (int i = 0; i < v->n; i++) free(v->keys[i]);
        free(v->keys);
    }
    free(v);
}

// ---- 解析器 ----
typedef struct { const char* p; } jparse;

static void jp_ws(jparse* j) {
    while (*j->p == ' ' || *j->p == '\t' || *j->p == '\r' || *j->p == '\n') j->p++;
}
static jval* jp_value(jparse* j);

static jval* jp_string(jparse* j) {
    jparse s = *j;
    if (*s.p != '"') return NULL;
    s.p++;
    size_t cap = strlen(s.p) + 1;
    char* out = (char*)malloc(cap);
    size_t o = 0;
    while (*s.p && *s.p != '"') {
        if (*s.p == '\\' && s.p[1]) {
            s.p++;
            switch (*s.p) {
            case 'n': out[o++] = '\n'; break;
            case 't': out[o++] = '\t'; break;
            case 'r': out[o++] = '\r'; break;
            case 'b': out[o++] = '\b'; break;
            case 'f': out[o++] = '\f'; break;
            case 'u': {
                // 仅处理 ASCII 转义；其余折叠为 '?'
                unsigned code = 0;
                for (int k = 0; k < 4 && isxdigit((unsigned char)s.p[1 + k]); k++) {
                    int d = s.p[1 + k];
                    code = code * 16 + (unsigned)(d <= '9' ? d - '0' : (d | 32) - 'a' + 10);
                }
                s.p += 4;
                out[o++] = code < 128 ? (char)code : '?';
                break;
            }
            default: out[o++] = *s.p; break;
            }
            s.p++;
        }
        else out[o++] = *s.p++;
    }
    out[o] = 0;
    if (*s.p == '"') s.p++;
    jval* v = jv_str(out);
    free(out);
    *j = s;
    return v;
}

static jval* jp_number(jparse* j) {
    const char* s = j->p;
    char* end = NULL;
    double d = strtod(s, &end);
    if (end == s) return NULL;
    j->p = end;
    return jv_num(d);
}

static jval* jp_value(jparse* j) {
    jp_ws(j);
    if (*j->p == '"') return jp_string(j);
    if (*j->p == '{') {
        j->p++;
        jval* obj = jv_new(5);
        jp_ws(j);
        if (*j->p == '}') { j->p++; return obj; }
        for (;;) {
            jp_ws(j);
            jval* k = jp_string(j);
            if (!k) { jv_free(obj); return NULL; }
            jp_ws(j);
            if (*j->p == ':') j->p++;
            jval* v = jp_value(j);
            if (!v) { jv_free(k); jv_free(obj); return NULL; }
            jv_put(obj, k->str, v);
            jv_free(k);
            jp_ws(j);
            if (*j->p == ',') { j->p++; continue; }
            if (*j->p == '}') { j->p++; break; }
            jv_free(obj); return NULL;
        }
        return obj;
    }
    if (*j->p == '[') {
        j->p++;
        jval* arr = jv_new(4);
        jp_ws(j);
        if (*j->p == ']') { j->p++; return arr; }
        for (;;) {
            jval* v = jp_value(j);
            if (!v) { jv_free(arr); return NULL; }
            jv_add(arr, v);
            jp_ws(j);
            if (*j->p == ',') { j->p++; continue; }
            if (*j->p == ']') { j->p++; break; }
            jv_free(arr); return NULL;
        }
        return arr;
    }
    if (!strncmp(j->p, "true", 4)) { j->p += 4; return jv_bool(1); }
    if (!strncmp(j->p, "false", 5)) { j->p += 5; return jv_bool(0); }
    if (!strncmp(j->p, "null", 4)) { j->p += 4; return jv_new(0); }
    return jp_number(j);
}

static jval* json_parse(const char* text) {
    jparse j = { text };
    jval* v = jp_value(&j);
    return v;
}

// ---- 构造器（动态字符串缓冲） ----
typedef struct { char* p; size_t len, cap; } jsb;
static void jsb_init(jsb* b) { b->cap = 4096; b->len = 0; b->p = (char*)malloc(b->cap); b->p[0] = 0; }
static void jsb_grow(jsb* b, size_t need) {
    if (b->len + need + 1 <= b->cap) return;
    while (b->len + need + 1 > b->cap) b->cap *= 2;
    b->p = (char*)realloc(b->p, b->cap);
}
static void jsb_put(jsb* b, const char* s) {
    size_t n = strlen(s);
    jsb_grow(b, n);
    memcpy(b->p + b->len, s, n + 1);
    b->len += n;
}
static void jsb_putn(jsb* b, const char* s, size_t n) {
    jsb_grow(b, n);
    memcpy(b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = 0;
}
static void jsb_printf(jsb* b, const char* fmt, ...) {
    char tmp[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(tmp, sizeof(tmp), _TRUNCATE, fmt, ap);
    va_end(ap);
    jsb_put(b, tmp);
}
static void jsb_esc(jsb* b, const char* s) {
    jsb_put(b, "\"");
    for (const char* p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '"' || c == '\\') jsb_printf(b, "\\%c", c);
        else if (c == '\n') jsb_put(b, "\\n");
        else if (c == '\r') jsb_put(b, "\\r");
        else if (c == '\t') jsb_put(b, "\\t");
        else if (c < 0x20) jsb_printf(b, "\\u%04x", c);
        else jsb_putn(b, (const char*)&c, 1);
    }
    jsb_put(b, "\"");
}


// ======================================================================
// 手动补完静态导入（IAT snap）—— 原样保留 PEL_ref 实现
// ======================================================================
// 解析后的导入清单。**必须在 snap_imports 打补丁之前记下来**：
// IAT 一旦被覆盖成真实地址，"名字在哪"这件事就永久丢失了。
// 定义放在**最早的使用者（snap_imports）之前**——本文件里同一个顺序错误
// 已经犯过两次（g_target_base、g_imps），所以这里显式写在 L505 之前。
#define MAX_IMP 512
static struct { char dll[64]; char name[128]; } g_imps[MAX_IMP];
static int g_imps_n = 0;
static int g_imps_truncated = 0;

static int snap_imports(PVOID base) {
    logf("[*] snap_imports 进入 base=%p\n", base);
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)base + dos->e_lfanew);
    ULONG impRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    logf("[*]   导入目录 RVA=0x%lx\n", impRva);
    if (!impRva) return 0;
    PIMAGE_IMPORT_DESCRIPTOR desc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)base + impRva);
    int snapped = 0;
    int ndesc = 0;
    for (; desc->Name; desc++) {
        // 每个描述符都记录，包括 Name 的读取本身——若故障发生在读取 desc->Name 上，
        // 那么连这行都不会出现，这本身就是定位信息。
        ++ndesc;
        logf("[*]   描述符 %d: Name RVA=0x%lx\n", ndesc, (unsigned long)desc->Name);
        char* dllName = (char*)((BYTE*)base + desc->Name);
        WCHAR wname[64];
        MultiByteToWideChar(CP_ACP, 0, dllName, -1, wname, 64);
        HMODULE hdll = GetModuleHandleW(wname);
        if (!hdll) {
            // 逐个记录。这里会**运行依赖 DLL 自己的 DllMain**——那是装载它们不可避免的一部分，
            // 而 Sky.exe 的依赖里有 fmod、fmodstudio、steam_api64、vulkan-1、igvk64，
            // 其中任何一个的初始化都可能失败。没有这行日志，一次失败只表现为
            // "在导入补完之前崩了"，看不出是哪一个。
            logf("[*] 加载依赖: %s\n", dllName);
            hdll = LoadLibraryA(dllName);
            logf("[*]   已加载: %s -> %p\n", dllName, (void*)hdll);
        }
        if (!hdll) { logf("[-] 导入模块缺失: %s\n", dllName); return -1; }

        PIMAGE_THUNK_DATA64 ft = (PIMAGE_THUNK_DATA64)((BYTE*)base + desc->FirstThunk);
        // OriginalFirstThunk 为 0 表示"没有单独的导入名表，名字在 FirstThunk 里"，
        // 而 `desc->FirstThunk` 此时是 IAT 的 RVA，那里的值就是指向 IMAGE_IMPORT_BY_NAME 的。
        //
        // 判断必须看 **RVA 是不是 0**，不能看指针是不是 NULL：
        //   `(BYTE*)base + 0` 是一个**非空**指针，所以 `if (!ilt)` 永远不成立，
        //   于是循环从映像基址（MZ 头）开始，把整个映像当作 thunk 数组一路走下去，
        //   直到越过页边界触发访问违例。
        //
        // 这个 bug 只在 OriginalFirstThunk 为 0 的映像上发作，而 Sky.exe 正是如此——
        // 它的导入表是「27 项、每个 DLL 一条、OriginalFirstThunk == 0、名字在 FirstThunk」，
        // 这是本项目静态分析早就记录过的事实。实测表现：引擎在第一个描述符上崩在 ntdll 内
        // 0x7ffdd9da6df0，与最初 LoadLibraryW 崩溃的地址完全相同。
        PIMAGE_THUNK_DATA64 ilt =
            desc->OriginalFirstThunk ? (PIMAGE_THUNK_DATA64)((BYTE*)base + desc->OriginalFirstThunk)
                                     : ft;
        SIZE_T span = 0;
        if (!ilt) { ilt = ft; }
        for (PIMAGE_THUNK_DATA64 t = ilt; t->u1.AddressOfData; t++) span++;
        if (!span) continue;

        PVOID pageStart = (PVOID)((ULONG_PTR)ft & ~(ULONG_PTR)0xFFF);
        SIZE_T pageLen = (((ULONG_PTR)(ft + span) - (ULONG_PTR)pageStart) + 0xFFF) & ~(SIZE_T)0xFFF;
        DWORD oldProt = 0;
        if (!VirtualProtect(pageStart, pageLen, PAGE_READWRITE, &oldProt)) {
            logf("[-] VirtualProtect(IAT) 失败 %lu\n", GetLastError());
            return -1;
        }
        for (SIZE_T i = 0; i < span; i++) {
            FARPROC addr = NULL;
            if (IMAGE_SNAP_BY_ORDINAL64(ilt[i].u1.Ordinal)) {
                addr = GetProcAddress(hdll, (LPCSTR)IMAGE_ORDINAL64(ilt[i].u1.Ordinal));
            }
            else {
                PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)((BYTE*)base + ilt[i].u1.AddressOfData);
                addr = GetProcAddress(hdll, (LPCSTR)ibn->Name);
            }
            if (!addr) {
                logf("[-] 导入解析失败: %s #%zu\n", dllName, i);
                VirtualProtect(pageStart, pageLen, oldProt, &oldProt);
                return -1;
            }
            // 记下 (dll, name)——**必须在这一行之前**，因为下一行就把 IAT 覆盖了。
            if (g_imps_n < MAX_IMP) {
                strncpy(g_imps[g_imps_n].dll, dllName, sizeof(g_imps[0].dll) - 1);
                g_imps[g_imps_n].dll[sizeof(g_imps[0].dll) - 1] = 0;
                if (IMAGE_SNAP_BY_ORDINAL64(ilt[i].u1.Ordinal)) {
                    _snprintf_s(g_imps[g_imps_n].name, sizeof(g_imps[0].name), _TRUNCATE,
                               "#%llu", (unsigned long long)IMAGE_ORDINAL64(ilt[i].u1.Ordinal));
                } else {
                    PIMAGE_IMPORT_BY_NAME rbn =
                        (PIMAGE_IMPORT_BY_NAME)((BYTE*)base + ilt[i].u1.AddressOfData);
                    strncpy(g_imps[g_imps_n].name, (const char*)rbn->Name,
                                sizeof(g_imps[0].name) - 1);
                    g_imps[g_imps_n].name[sizeof(g_imps[0].name) - 1] = 0;
                }
                g_imps_n++;
            } else {
                g_imps_truncated = 1;
            }
            ft[i].u1.Function = (ULONG_PTR)addr;
            snapped++;
        }
        VirtualProtect(pageStart, pageLen, oldProt, &oldProt);
    }
    logf("[*] 已补完静态导入: %d 项\n", snapped);
    return 0;
}

// ======================================================================
// 极简 x64 长度反汇编器（LDE）—— 原样保留 PEL_ref 实现
// ======================================================================
typedef struct { BYTE len; BYTE dummy[3]; } lde_t;

static int lde_opcode_has_modrm(BYTE op) {
    switch (op) {
    case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55:
    case 0x56: case 0x57: case 0x58: case 0x59: case 0x5A: case 0x5B:
    case 0x5C: case 0x5D: case 0x5E: case 0x5F:
    case 0x90: case 0x98: case 0x99: case 0x9C: case 0x9D:
    case 0xC3: case 0xCB: case 0xCC: case 0xC9:
    case 0xF4: case 0xFA: case 0xFB: case 0xFC: case 0xFD:
    case 0x06: case 0x07: case 0x0F: case 0x27: case 0x2F:
    case 0x37: case 0x3F: case 0x60: case 0x61: case 0x6C: case 0x6D:
    case 0x6E: case 0x6F: case 0x9E: case 0x9F:
    case 0xC2: case 0xCA:
    case 0xEC: case 0xED: case 0xEE: case 0xEF:
    case 0xF1: case 0xF8: case 0xF9:
        return 0;
    case 0x68: case 0x6A:
    case 0xA8: case 0xA9:
    case 0xB0: case 0xB1: case 0xB2: case 0xB3:
    case 0xB4: case 0xB5: case 0xB6: case 0xB7:
    case 0xE8: case 0xE9: case 0xEB:
        return 0;
    default:
        break;
    }
    if (op >= 0xB8 && op <= 0xBF) return 0;
    return 1;
}

static lde_t lde_decode(const BYTE* p) {
    lde_t r = { 0 };
    int rex_w = 0;
    SIZE_T i = 0;
    BYTE op;

    for (;;) {
        BYTE b = p[i];
        if (b == 0xF0 || b == 0xF2 || b == 0xF3 ||
            b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
            b == 0x64 || b == 0x65) {
            i++; continue;
        }
        if (b == 0x66) { i++; continue; }
        if (b == 0x67) { i++; continue; }
        if (b >= 0x40 && b <= 0x4F) { rex_w = (b & 8) != 0; i++; continue; }
        break;
    }

    op = p[i++];

    if (op == 0x0F) {
        BYTE op2 = p[i++];
        int modrm = 1;
        switch (op2) {
        case 0x05: case 0x0B: case 0x31: case 0xA2:
        case 0xA0: case 0xA1: case 0xA8: case 0xA9:
        case 0xC8: case 0xC9: case 0xCA: case 0xCB:
        case 0xCC: case 0xCD: case 0xCE: case 0xCF:
            modrm = 0; break;
        default: break;
        }
        if (modrm) {
            BYTE m = p[i++];
            int mod = m >> 6, rm = m & 7;
            if (mod != 3 && rm == 4) {
                BYTE sib = p[i++];
                if (mod == 0 && (sib & 7) == 5) i += 4;
            }
            else if (mod == 0 && rm == 5) i += 4;
            else if (mod == 1) i += 1;
            else if (mod == 2) i += 4;
            if (op2 == 0x3A) i++;
        }
        r.len = (BYTE)i;
        return r;
    }

    if (op == 0xC2 || op == 0xCA) { i += 2; r.len = (BYTE)i; return r; }
    if (op >= 0x70 && op <= 0x7F) { i += 1; r.len = (BYTE)i; return r; }
    if (op == 0x68) { i += 4; r.len = (BYTE)i; return r; }
    if (op == 0x6A) { i += 1; r.len = (BYTE)i; return r; }
    if (op == 0xA8) { i += 1; r.len = (BYTE)i; return r; }
    if (op == 0xA9) { i += (rex_w ? 8 : 4); r.len = (BYTE)i; return r; }
    if (op >= 0xB0 && op <= 0xB7) { i += 1; r.len = (BYTE)i; return r; }
    if (op >= 0xB8 && op <= 0xBF) { i += (rex_w ? 8 : 4); r.len = (BYTE)i; return r; }
    if (op == 0xE8 || op == 0xE9) { i += 4; r.len = (BYTE)i; return r; }
    if (op == 0xEB) { i += 1; r.len = (BYTE)i; return r; }

    if (lde_opcode_has_modrm(op)) {
        BYTE m = p[i++];
        int mod = m >> 6, rm = m & 7;
        if (mod != 3 && rm == 4) {
            BYTE sib = p[i++];
            if (mod == 0 && (sib & 7) == 5) i += 4;
            else if (mod == 1) i += 1;
            else if (mod == 2) i += 4;
        }
        else if (mod == 0 && rm == 5) i += 4;
        else if (mod == 1) i += 1;
        else if (mod == 2) i += 4;
        int modrm_reg = (m >> 3) & 7;
        switch (op) {
        case 0x80: case 0x82: case 0x83: case 0xC0: case 0xC1:
        case 0xC6:
            i += 1; break;
        case 0x81:
            i += 4; break;
        case 0xC7:
            i += 4; break;
        case 0xF6:
            if (modrm_reg == 0 || modrm_reg == 1) i += 1;
            break;
        case 0xF7:
            if (modrm_reg == 0 || modrm_reg == 1) i += 4;
            break;
        default:
            break;
        }
    }
    r.len = (BYTE)i;
    return r;
}

// ======================================================================
// 跳板池与钩子（PEL_ref 机制，泛化为"任何带 CC 填充的函数"）
// ======================================================================
#define HOOK_MAX 24
#define MAX_HOOKS 16
typedef struct _hook_t {
    PVOID target;
    PVOID handler;
    BYTE  orig[HOOK_MAX];
    BYTE  stolen_len;
    BYTE* tramp;
    const char* func_name;
} hook_t;

#pragma section("gua_tramp", read, write, execute)
__declspec(allocate("gua_tramp")) static BYTE g_tramp_section[0x10000];
static BYTE* g_tramp_pool = g_tramp_section;
static SIZE_T g_tramp_used = 0;
static hook_t g_hooks[MAX_HOOKS];
static int g_hook_count = 0;

#define EMIT_ABS_JMP_AT(pos, abs_addr) do { \
    ((BYTE*)(pos))[0] = 0x48; ((BYTE*)(pos))[1] = 0xB8; \
    memcpy((BYTE*)(pos) + 2, &(abs_addr), 8); \
    ((BYTE*)(pos))[10] = 0xFF; ((BYTE*)(pos))[11] = 0xE0; \
} while (0)

static int fix_rip_relative(BYTE* instr, int len, ULONG_PTR orig_addr, ULONG_PTR new_addr) {
    int p = 0;
    while (p < len && ((instr[p] & 0xF0) == 0x40 || instr[p] == 0x66 ||
        instr[p] == 0x67 || instr[p] == 0xF2 || instr[p] == 0xF3)) p++;
    if (p >= len) return 0;
    int op = instr[p++];
    if (op == 0x0F) { if (p >= len) return 0; op = instr[p++]; }
    if (p >= len) return 0;
    int m = instr[p];
    int mod = m >> 6, rm = m & 7;
    if (mod == 3) return 0;
    p++;
    if (rm == 4) return 0;
    if (!(mod == 0 && rm == 5)) return 0;
    if (p + 4 > len) return 0;
    INT32 disp;
    memcpy(&disp, instr + p, 4);
    ULONG_PTR abs_target = orig_addr + len + disp;
    LONG new_disp = (LONG)(abs_target - (new_addr + len));
    memcpy(instr + p, &new_disp, 4);
    return 1;
}

// 安装 12 字节绝对跳转补丁（48 B8 imm64; FF E0）。
// 安全约束：窃取 >=5 字节完整指令；patch 窗口 [stolen,12) 必须全为 CC/90 填充。
static BOOL install_hook_abs(PVOID target, PVOID handler, const char* func_name) {
    if (g_hook_count >= MAX_HOOKS) return FALSE;
    hook_t* hk = &g_hooks[g_hook_count];
    DWORD old_prot;
    BYTE buf[32];
    memcpy(buf, target, sizeof(buf));

    SIZE_T stolen = 0;
    while (stolen < 5) {
        lde_t d = lde_decode(buf + stolen);
        if (d.len == 0 || d.len > 15 || stolen + d.len > HOOK_MAX) return FALSE;
        stolen += d.len;
    }
    for (SIZE_T i = stolen; i < 12; i++) {
        if (buf[i] != 0xCC && buf[i] != 0x90) {
            logf("[-] %s 补丁窗口无足够 CC/90 填充，拒绝安装\n", func_name);
            return FALSE;
        }
    }

    BYTE* tramp = g_tramp_pool + g_tramp_used;
    SIZE_T o = 0;
    for (SIZE_T i = 0; i < stolen; ) {
        BYTE op = buf[i];
        if (op == 0xE9 || op == 0xEB) {
            LONG rel = (op == 0xE9) ? *(INT32*)(buf + i + 1) : *(INT8*)(buf + i + 1);
            ULONG_PTR abs_target = (ULONG_PTR)target + i + ((op == 0xE9) ? 5 : 2) + rel;
            EMIT_ABS_JMP_AT(tramp + o, abs_target);
            o += 12; i += (op == 0xE9) ? 5 : 2;
        }
        else if (op >= 0x70 && op <= 0x7F) {
            INT8 rel = (INT8)buf[i + 1];
            ULONG_PTR abs_target = (ULONG_PTR)target + i + 2 + rel;
            tramp[o] = (BYTE)((op ^ 1) & 0x7F);
            tramp[o + 1] = 0x0C;
            EMIT_ABS_JMP_AT(tramp + o + 2, abs_target);
            o += 14; i += 2;
        }
        else if (op == 0x0F && buf[i + 1] >= 0x80 && buf[i + 1] <= 0x8F) {
            INT32 rel;
            memcpy(&rel, buf + i + 2, 4);
            ULONG_PTR abs_target = (ULONG_PTR)target + i + 6 + rel;
            tramp[o] = 0x0F;
            tramp[o + 1] = (BYTE)(buf[i + 1] ^ 1);
            LONG skip = 12;
            memcpy(tramp + o + 2, &skip, 4);
            EMIT_ABS_JMP_AT(tramp + o + 6, abs_target);
            o += 18; i += 6;
        }
        else {
            lde_t d = lde_decode(buf + i);
            memcpy(tramp + o, buf + i, d.len);
            fix_rip_relative(tramp + o, d.len, (ULONG_PTR)target + i, (ULONG_PTR)tramp + o);
            o += d.len; i += d.len;
        }
    }
    ULONG_PTR back = (ULONG_PTR)target + stolen;
    EMIT_ABS_JMP_AT(tramp + o, back);
    o += 12;
    g_tramp_used += (o + 15) & ~15UL;

    if (!VirtualProtect(target, 12, PAGE_EXECUTE_READWRITE, &old_prot))
        return FALSE;
    memcpy(hk->orig, buf, stolen);
    hk->stolen_len = (BYTE)stolen;
    hk->target = target;
    hk->handler = handler;
    hk->tramp = tramp;
    hk->func_name = func_name;

    BYTE patch[HOOK_MAX];
    patch[0] = 0x48;
    patch[1] = 0xB8;
    memcpy(patch + 2, &handler, 8);
    patch[10] = 0xFF;
    patch[11] = 0xE0;
    memcpy(target, patch, 12);
    VirtualProtect(target, 12, old_prot, &old_prot);
    FlushInstructionCache(GetCurrentProcess(), target, 12);
    FlushInstructionCache(GetCurrentProcess(), tramp, o);
    g_hook_count++;
    return TRUE;
}

// ======================================================================
// 导出查找 / NT API
// ======================================================================
static PVOID mem_find_export(PVOID mod, const char* name) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)mod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    IMAGE_DATA_DIRECTORY ed = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!ed.VirtualAddress) return NULL;
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)mod + ed.VirtualAddress);
    DWORD* names = (DWORD*)((BYTE*)mod + exp->AddressOfNames);
    WORD* ords = (WORD*)((BYTE*)mod + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)((BYTE*)mod + exp->AddressOfFunctions);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        if (strcmp((const char*)((BYTE*)mod + names[i]), name) == 0)
            return (BYTE*)mod + funcs[ords[i]];
    }
    return NULL;
}

typedef NTSTATUS(NTAPI* PFN_NtQueryVirtualMemory)(
    HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);

static PFN_NtQueryVirtualMemory g_ntqvm = NULL;

// ======================================================================
// 内存工具
// ======================================================================
static int mem_readable(ULONG_PTR addr, SIZE_T len) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((PVOID)addr, &mbi, sizeof(mbi))) return 0;
    if (mbi.State != MEM_COMMIT) return 0;
    if (mbi.Protect == PAGE_NOACCESS || mbi.Protect == PAGE_GUARD) return 0;
    // 粗略：只验证首页（研究级，逐页校验在 mem_map 中提供）
    (void)len;
    return 1;
}

static SIZE_T mem_read_safe(ULONG_PTR addr, void* out, SIZE_T len) {
    //
    // 这里原来是**直接 memcpy**（第 919 行），而保护检查只做两个精确比较：
    //     mbi.Protect == PAGE_NOACCESS || mbi.Protect == PAGE_GUARD
    //
    // 两个缺陷叠在一起就会**打死整个进程**：
    //   ① `mbi.Protect` 可以是带修饰位的值（例如 PAGE_NOACCESS|PAGE_NOCACHE
    //      是 0x40000001），精确比较匹配不上，于是"不可读"这一个判断漏过；
    //   ② 一旦漏过就直接 memcpy，页不可读时是**致命异常**，而引擎的 VEH
    //      不接管搜索路径，所以表现是 "engine closed pipe" ——
    //      调用者只看到连接断开，看不到原因。
    //
    // 实测：在 Sky.exe（521 MB 工作集）上 search_str **每次**都打死引擎。
    //
    // 修法用系统自己的接口：`ReadProcessMemory` 在不可读时**返回 FALSE**，
    // 而不是抛异常。它是同一个进程句柄，所以没有任何权限问题。
    // 这样"读了但读不到"变成一个可以通过返回值处理的正常情况。
    SIZE_T done = 0;
    HANDLE h = GetCurrentProcess();
    while (done < len) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery((PVOID)(addr + done), &mbi, sizeof(mbi))) break;
        if (mbi.State != MEM_COMMIT) break;
        // 用掩码判断，而不是精确相等 —— 修饰位（NOCACHE / WRITECOMBINE /
        // GUARD 组合）不应让"不可读"这个结论失效。
        DWORD prot = mbi.Protect & 0xFF;
        if (prot == PAGE_NOACCESS || prot == PAGE_EXECUTE ||
            (mbi.Protect & PAGE_GUARD)) break;
        SIZE_T chunk = (SIZE_T)mbi.BaseAddress + mbi.RegionSize - (addr + done);
        if (chunk > len - done) chunk = len - done;
        SIZE_T got = 0;
        if (!ReadProcessMemory(h, (PVOID)(addr + done), (BYTE*)out + done, chunk, &got))
            break;                      // 读不到就停在这里，把已读到的量报回去
        if (!got) break;
        done += got;
        if (got < chunk) break;
    }
    return done;
}

static SIZE_T mem_write_safe(ULONG_PTR addr, const void* in, SIZE_T len) {
    SIZE_T done = 0;
    while (done < len) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery((PVOID)(addr + done), &mbi, sizeof(mbi))) break;
        if (mbi.State != MEM_COMMIT) break;
        SIZE_T chunk = (SIZE_T)mbi.BaseAddress + mbi.RegionSize - (addr + done);
        if (chunk > len - done) chunk = len - done;
        DWORD oldProt;
        if (VirtualProtect((PVOID)(addr + done), chunk, PAGE_EXECUTE_READWRITE, &oldProt)) {
            memcpy((PVOID)(addr + done), (const BYTE*)in + done, chunk);
            VirtualProtect((PVOID)(addr + done), chunk, oldProt, &oldProt);
            done += chunk;
        }
        else {
            // 只读页（如映射镜像）：放弃本页
            break;
        }
    }
    FlushInstructionCache(GetCurrentProcess(), (PVOID)addr, done);
    return done;
}

// 十六进制工具
static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static size_t hex2bin(const char* hex, BYTE* out, size_t maxn) {
    size_t n = 0;
    while (hex[0] && n < maxn) {
        int h = hexval(hex[0]);
        if (h < 0) { hex++; continue; }      // 跳过分隔符
        int l = hex[1] ? hexval(hex[1]) : 0;
        if (l < 0) break;
        out[n++] = (BYTE)((h << 4) | l);
        hex += 2;
    }
    return n;
}
static void bin2hex(const BYTE* in, size_t n, char* out) {
    static const char* H = "0123456789ABCDEF";
    for (size_t i = 0; i < n; i++) {
        out[i * 2] = H[in[i] >> 4];
        out[i * 2 + 1] = H[in[i] & 15];
    }
    out[n * 2] = 0;
}


// ======================================================================
// 迷你 x64 反汇编器（覆盖 MSVC 常见指令子集，未识别回退 db）
// ======================================================================
static const char* g_reg64[16] = {
    "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
    "r8","r9","r10","r11","r12","r13","r14","r15" };
static const char* g_reg32[16] = {
    "eax","ecx","edx","ebx","esp","ebp","esi","edi",
    "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d" };
static const char* g_reg16[16] = {
    "ax","cx","dx","bx","sp","bp","si","di",
    "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w" };
static const char* g_reg8[16] = {
    "al","cl","dl","bl","spl","bpl","sil","dil",
    "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b" };
static const char* g_xmm[16] = {
    "xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7",
    "xmm8","xmm9","xmm10","xmm11","xmm12","xmm13","xmm14","xmm15" };

typedef struct {
    int len;
    BYTE rex;           // 0 = 无 REX
    int p66, pf2, pf3;
    BYTE op, op2;
    int has_op2;
    int has_modrm;
    int mod, reg, rm;   // modrm 拆分（has_modrm 时有效）
    int has_sib;
    int sib_scale, sib_index, sib_base;
    long long disp;
    int disp_size;      // 0/1/4
    int is_rip;         // mod==0 && rm==5（RIP 相对）
    long long imm;      // 符号扩展后的立即数
    int imm_size;       // 0/1/2/4/8
    ULONG_PTR rel_target;
    int is_rel;         // 相对跳转/调用目标有效
} dctx;

static int dctx_rexw(dctx* c) { return c->rex ? (c->rex & 8) != 0 : 0; }
static int dctx_rexr(dctx* c) { return c->rex ? (c->rex & 4) != 0 : 0; }
static int dctx_rexx(dctx* c) { return c->rex ? (c->rex & 2) != 0 : 0; }
static int dctx_rexb(dctx* c) { return c->rex ? (c->rex & 1) != 0 : 0; }

// 解析 ModRM/SIB/Disp，返回 r/m 文本（buf 需 >= 96 字节）
static void dctx_modrm_rm(dctx* c, ULONG_PTR at, char* buf) {
    int mod = c->mod, rm = c->rm;
    int base = rm + (dctx_rexb(c) ? 8 : 0);
    if (mod == 3) {
        strcpy_s(buf, 96, g_reg64[base]);
        return;
    }
    char inner[80] = { 0 };
    const char* basereg = NULL;
    if (c->is_rip) {
        if (c->disp < 0)
            sprintf_s(buf, 96, "[rip-0x%llx]", -(long long)c->disp);
        else
            sprintf_s(buf, 96, "[rip+0x%llx]", (long long)c->disp);
        return;
    }
    if (c->has_sib) {
        int idx = c->sib_index + (dctx_rexx(c) ? 8 : 0);
        int b = c->sib_base + (dctx_rexb(c) ? 8 : 0);
        int sc = 1 << c->sib_scale;
        int nobase = (c->mod == 0 && c->sib_base == 5);
        char bpart[40] = { 0 };
        if (!nobase) sprintf_s(bpart, "%s", g_reg64[b]);
        if (c->sib_index == 4 && !dctx_rexx(c)) {
            // index 无（rsp 编码）
            if (nobase) sprintf_s(inner, "0x%llx", (long long)c->disp);
            else if (c->disp_size) sprintf_s(inner, "%s%c0x%llx", bpart,
                c->disp < 0 ? '-' : '+', c->disp < 0 ? -(long long)c->disp : (long long)c->disp);
            else strcpy_s(inner, bpart);
        }
        else {
            const char* ipart = g_reg64[idx];
            if (nobase) {
                if (sc != 1) sprintf_s(inner, "%s*%d%c0x%llx", ipart, sc,
                    c->disp < 0 ? '-' : '+', c->disp < 0 ? -(long long)c->disp : (long long)c->disp);
                else sprintf_s(inner, "%s%c0x%llx", ipart,
                    c->disp < 0 ? '-' : '+', c->disp < 0 ? -(long long)c->disp : (long long)c->disp);
            }
            else if (c->disp_size) {
                sprintf_s(inner, "%s+%s*%d%c0x%llx", bpart, ipart, sc,
                    c->disp < 0 ? '-' : '+', c->disp < 0 ? -(long long)c->disp : (long long)c->disp);
            }
            else sprintf_s(inner, "%s+%s*%d", bpart, ipart, sc);
        }
        sprintf_s(buf, 96, "[%s]", inner);
        return;
    }
    basereg = g_reg64[base];
    if (c->disp_size == 0) sprintf_s(buf, 96, "[%s]", basereg);
    else sprintf_s(buf, 96, "[%s%c0x%llx]", basereg,
        c->disp < 0 ? '-' : '+', c->disp < 0 ? -(long long)c->disp : (long long)c->disp);
}

static const char* dctx_reg_name(dctx* c, int size, int idx) {
    static char rbuf[16];
    if (idx >= 16) idx = 15;
    if (size == 8) return g_reg64[idx];
    if (size == 4) return g_reg32[idx];
    if (size == 2) return g_reg16[idx];
    if (size == 1) return g_reg8[idx];
    if (size == 16) return g_xmm[idx];
    sprintf_s(rbuf, "r?%d", idx);
    return rbuf;
}

static void dctx_modrm_reg(dctx* c, int size, char* buf) {
    strcpy_s(buf, 96, dctx_reg_name(c, size, c->reg + (dctx_rexr(c) ? 8 : 0)));
}

// 主解码：返回 dctx；调用方负责按 opcode 填文本
static int dctx_decode(dctx* c, ULONG_PTR at, const BYTE* p) {
    memset(c, 0, sizeof(*c));
    SIZE_T i = 0;
    // 前缀
    for (;;) {
        BYTE b = p[i];
        if (b == 0xF0 || b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
            b == 0x64 || b == 0x65) { i++; continue; }
        if (b == 0xF2) { c->pf2 = 1; i++; continue; }
        if (b == 0xF3) { c->pf3 = 1; i++; continue; }
        if (b == 0x66) { c->p66 = 1; i++; continue; }
        if (b == 0x67) { i++; continue; }           // 地址大小前缀忽略（按64位处理）
        if (b >= 0x40 && b <= 0x4F) { c->rex = b; i++; continue; }
        break;
    }
    c->op = p[i++];
    if (c->op == 0x0F) {
        c->op2 = p[i++];
        c->has_op2 = 1;
    }
    // ModRM（按 opcode 家族粗分：除白名单外默认解析）
    int parse_modrm = 1;
    int op = c->op;
    if (!c->has_op2) {
        switch (op) {
        case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55:
        case 0x56: case 0x57: case 0x58: case 0x59: case 0x5A: case 0x5B:
        case 0x5C: case 0x5D: case 0x5E: case 0x5F:
        case 0x90: case 0x98: case 0x99: case 0x9C: case 0x9D: case 0x9E: case 0x9F:
        case 0xC3: case 0xCB: case 0xC9: case 0xCC: case 0xCE: case 0xF1: case 0xF4:
        case 0xF8: case 0xF9: case 0xFA: case 0xFB: case 0xFC: case 0xFD: case 0xF5:
        case 0xA4: case 0xA5: case 0xA6: case 0xA7:
        case 0x6C: case 0x6D: case 0x6E: case 0x6F:
        case 0xEC: case 0xED: case 0xEE: case 0xEF:
        case 0x06: case 0x07: case 0x27: case 0x2F: case 0x37: case 0x3F:
        case 0x60: case 0x61: case 0xD4: case 0xD5: case 0xD7:
            parse_modrm = 0; break;
        case 0x04: case 0x0C: case 0x14: case 0x1C:
        case 0x24: case 0x2C: case 0x34: case 0x3C:
        case 0xA8:
            c->imm_size = 1; parse_modrm = 0; break;
        case 0x05: case 0x0D: case 0x15: case 0x1D:
        case 0x25: case 0x2D: case 0x35: case 0x3D:
        case 0xA9:
            c->imm_size = dctx_rexw(c) ? 8 : 4; parse_modrm = 0; break;
        case 0xC2: case 0xCA:
            c->imm_size = 2; parse_modrm = 0; break;
        case 0xCD:
            c->imm_size = 1; parse_modrm = 0; break;
        case 0xE4: case 0xE5: case 0xE6: case 0xE7:
            c->imm_size = 1; parse_modrm = 0; break;
        case 0x68: c->imm_size = 4; parse_modrm = 0; break;
        case 0x69: c->imm_size = 4; break;        // imul r,r/m,imm32
        case 0x6A: c->imm_size = 1; parse_modrm = 0; break;
        case 0x6B: c->imm_size = 1; break;        // imul r,r/m,imm8
        case 0xA0: case 0xA1: case 0xA2: case 0xA3: // mov moffs
            parse_modrm = 0; c->imm_size = 8; break;
        case 0xB0: case 0xB1: case 0xB2: case 0xB3:
        case 0xB4: case 0xB5: case 0xB6: case 0xB7:
            c->imm_size = 1; parse_modrm = 0; break;
        case 0xB8: case 0xB9: case 0xBA: case 0xBB:
        case 0xBC: case 0xBD: case 0xBE: case 0xBF:
            c->imm_size = dctx_rexw(c) ? 8 : 4; parse_modrm = 0; break;
        case 0xC8: c->imm_size = 3; parse_modrm = 0; break; // enter
        case 0xE8: case 0xE9:
            c->is_rel = 1; c->imm_size = 4; parse_modrm = 0; break;
        case 0xEB:
            c->is_rel = 1; c->imm_size = 1; parse_modrm = 0; break;
        case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75:
        case 0x76: case 0x77: case 0x78: case 0x79: case 0x7A: case 0x7B:
        case 0x7C: case 0x7D: case 0x7E: case 0x7F:
            c->is_rel = 1; c->imm_size = 1; parse_modrm = 0; break;
        case 0xE0: case 0xE1: case 0xE2: case 0xE3:
            c->is_rel = 1; c->imm_size = 1; parse_modrm = 0; break;
        default: break;
        }
    }
    else {
        switch (c->op2) {
        case 0x05: case 0x0B: case 0x31: case 0xA2: case 0xA0: case 0xA1:
        case 0xA8: case 0xA9:
        case 0xC8: case 0xC9: case 0xCA: case 0xCB: case 0xCC: case 0xCD:
        case 0xCE: case 0xCF:
            parse_modrm = 0; break;
        case 0x80: case 0x82: case 0x83: case 0x84: case 0x85: case 0x86: case 0x87:
        case 0x88: case 0x89: case 0x8A: case 0x8B: case 0x8C: case 0x8D: case 0x8E: case 0x8F:
            c->is_rel = 1; c->imm_size = 4; parse_modrm = 0; break;
        case 0x3A: case 0x38:
            c->imm_size = 1; break;               // 结尾 imm8（0F 38/3A 三字节族）
        default: break;
        }
    }
    if (parse_modrm) {
        // 有无 ModRM 的最终裁决（与本家族 LDE 白名单一致）
        if (!c->has_op2) {
            int skip = 0;
            switch (op) {
            case 0x68: case 0x6A: case 0xA8: case 0xA9:
            case 0xB0: case 0xB1: case 0xB2: case 0xB3: case 0xB4:
            case 0xB5: case 0xB6: case 0xB7: case 0xE8: case 0xE9: case 0xEB:
                skip = 1; break;
            default: break;
            }
            if (op >= 0xB8 && op <= 0xBF) skip = 1;
            if (op >= 0x70 && op <= 0x7F) skip = 1;
            if (!skip) {
                c->has_modrm = 1;
                BYTE m = p[i++];
                c->mod = m >> 6; c->reg = (m >> 3) & 7; c->rm = m & 7;
                if (c->mod != 3 && c->rm == 4) {
                    c->has_sib = 1;
                    BYTE s = p[i++];
                    c->sib_scale = s >> 6;
                    c->sib_index = (s >> 3) & 7;
                    c->sib_base = s & 7;
                }
                if (c->mod == 0 && c->rm == 5 && !c->has_sib) {
                    c->is_rip = 1;
                    INT32 d32; memcpy(&d32, p + i, 4); i += 4;
                    c->disp = d32; c->disp_size = 4;
                }
                else if (c->has_sib && c->mod == 0 && c->sib_base == 5) {
                    INT32 d32; memcpy(&d32, p + i, 4); i += 4;
                    c->disp = d32; c->disp_size = 4;
                }
                else if (c->mod == 1) {
                    c->disp = (char)p[i++]; c->disp_size = 1;
                }
                else if (c->mod == 2) {
                    INT32 d32; memcpy(&d32, p + i, 4); i += 4;
                    c->disp = d32; c->disp_size = 4;
                }
                // 组指令尾部立即数
                int g = c->reg;
                if (!c->has_op2) {
                    switch (op) {
                    case 0x80: case 0x82: case 0x83: case 0xC0: case 0xC1: case 0xC6:
                        c->imm_size = 1; break;
                    case 0x81: case 0xC7:
                        c->imm_size = 4; break;
                    case 0xF6: if (g == 0 || g == 1) c->imm_size = 1; break;
                    case 0xF7: if (g == 0 || g == 1) c->imm_size = 4; break;
                    default: break;
                    }
                }
            }
        }
        else {
            c->has_modrm = 1;
            BYTE m = p[i++];
            c->mod = m >> 6; c->reg = (m >> 3) & 7; c->rm = m & 7;
            if (c->mod != 3 && c->rm == 4) {
                c->has_sib = 1;
                BYTE s = p[i++];
                c->sib_scale = s >> 6;
                c->sib_index = (s >> 3) & 7;
                c->sib_base = s & 7;
            }
            if (c->mod == 0 && c->rm == 5 && !c->has_sib) {
                c->is_rip = 1;
                INT32 d32; memcpy(&d32, p + i, 4); i += 4;
                c->disp = d32; c->disp_size = 4;
            }
            else if (c->has_sib && c->mod == 0 && c->sib_base == 5) {
                INT32 d32; memcpy(&d32, p + i, 4); i += 4;
                c->disp = d32; c->disp_size = 4;
            }
            else if (c->mod == 1) {
                c->disp = (char)p[i++]; c->disp_size = 1;
            }
            else if (c->mod == 2) {
                INT32 d32; memcpy(&d32, p + i, 4); i += 4;
                c->disp = d32; c->disp_size = 4;
            }
        }
    }
    // 立即数
    if (c->imm_size) {
        switch (c->imm_size) {
        case 1: c->imm = (char)p[i]; i += 1; break;
        case 2: { SHORT v; memcpy(&v, p + i, 2); c->imm = v; i += 2; break; }
        case 3: i += 3; break; // enter 不读
        case 4: { INT32 v; memcpy(&v, p + i, 4); c->imm = v; i += 4; break; }
        case 8: { long long v; memcpy(&v, p + i, 8); c->imm = v; i += 8; break; }
        }
    }
    if (c->is_rel) {
        ULONG_PTR base = at + (i);
        c->rel_target = base + c->imm;
    }
    c->len = (int)i;
    return c->len;
}


// ======================================================================
// 指令文本生成（dis_one）+ 符号解析
// ======================================================================
typedef struct {
    ULONG_PTR addr;
    int size;
    BYTE bytes[15];
    char text[160];
    ULONG_PTR target;        // 跳转/调用目标（0 表示无）
    int is_call, is_jump, is_ret, is_bp;
} dinst;

// 前向声明：调试引擎符号表（定义在引擎一节）
static const char* sym_name_for(ULONG_PTR addr, char* buf, size_t n);
static ULONG_PTR sym_resolve(const char* name);

static const char* jcc_names[16] = {
    "jo","jno","jb","jae","jz","jnz","jbe","ja",
    "js","jns","jp","jnp","jl","jge","jle","jg" };

// 读取内存操作数指向的指针值（用于注释）
static ULONG_PTR dctx_deref_target(dctx* c, ULONG_PTR at) {
    if (c->is_rip) return at + c->len + (long long)c->disp;
    if (!c->has_modrm || c->mod == 3) return 0;
    // 仅处理纯 disp32 与 rip 相对（其余需完整寄存器上下文）
    if (!c->is_rip && !(c->mod == 0 && !c->has_sib)) return 0;
    if (!c->is_rip && c->mod == 0 && !c->has_sib) {
        ULONG_PTR a = (ULONG_PTR)(long long)c->disp;
        ULONG_PTR v = 0;
        if (mem_read_safe(a, &v, 8) == 8) return v;
    }
    return 0;
}

static void fmt_imm(dctx* c, int size, char* buf) {
    unsigned long long m = size == 1 ? 0xFF : size == 2 ? 0xFFFF :
        size == 4 ? 0xFFFFFFFFULL : ~0ULL;
    sprintf_s(buf, 48, "0x%llx", (unsigned long long)c->imm & m);
}

static int dis_one(ULONG_PTR at, dinst* out) {
    memset(out, 0, sizeof(*out));
    out->addr = at;
    BYTE buf[15] = { 0 };
    if (mem_read_safe(at, buf, sizeof(buf)) != sizeof(buf)) {
        SIZE_T got = mem_read_safe(at, buf, sizeof(buf));
        if (!got) { sprintf_s(out->text, "???"); return 1; }
    }
    dctx c;
    int len = dctx_decode(&c, at, buf);
    if (len <= 0 || len > 15) { sprintf_s(out->text, "db 0x%02X", buf[0]); out->size = 1; memcpy(out->bytes, buf, 1); return 1; }
    out->size = len;
    memcpy(out->bytes, buf, len);
    char rm[96], rg[96];
    int opsize = dctx_rexw(&c) ? 8 : (c.p66 ? 2 : 4);
    const char* op = NULL;
    char tmp[192];

    if (!c.has_op2) {
        switch (c.op) {
        case 0xCC: op = "int3"; out->is_bp = 1; break;
        case 0x90: op = "nop"; break;
        case 0xC3: op = "ret"; out->is_ret = 1; break;
        case 0xCB: op = "retf"; out->is_ret = 1; break;
        case 0xC2: sprintf_s(tmp, "ret 0x%llx", (unsigned long long)c.imm); op = NULL; strcpy_s(out->text, tmp); break;
        case 0xC9: op = "leave"; break;
        case 0x98: op = dctx_rexw(&c) ? "cdqe" : (c.p66 ? "cbw" : "cwde"); break;
        case 0x99: op = dctx_rexw(&c) ? "cqo" : (c.p66 ? "cwd" : "cdq"); break;
        case 0x9C: op = "pushfq"; break;
        case 0x9D: op = "popfq"; break;
        case 0x9E: op = "sahf"; break;
        case 0x9F: op = "lahf"; break;
        case 0xF4: op = "hlt"; break;
        case 0xF8: op = "clc"; break;
        case 0xF9: op = "stc"; break;
        case 0xFC: op = "cld"; break;
        case 0xFD: op = "std"; break;
        case 0xFA: op = "cli"; break;
        case 0xFB: op = "sti"; break;
        case 0xF5: op = "cmc"; break;
        case 0xF1: op = "int1"; break;
        case 0xCE: op = "into"; break;
        case 0xCD: sprintf_s(tmp, "int 0x%llx", (unsigned long long)c.imm); strcpy_s(out->text, tmp); break;
        case 0x50: case 0x51: case 0x52: case 0x53: case 0x54:
        case 0x55: case 0x56: case 0x57:
            sprintf_s(tmp, "push %s", dctx_reg_name(&c, 8, (c.op & 7) + (dctx_rexb(&c) ? 8 : 0)));
            strcpy_s(out->text, tmp); break;
        case 0x58: case 0x59: case 0x5A: case 0x5B: case 0x5C:
        case 0x5D: case 0x5E: case 0x5F:
            sprintf_s(tmp, "pop %s", dctx_reg_name(&c, 8, (c.op & 7) + (dctx_rexb(&c) ? 8 : 0)));
            strcpy_s(out->text, tmp); break;
        case 0x68: sprintf_s(tmp, "push 0x%llx", (unsigned long long)c.imm); strcpy_s(out->text, tmp); break;
        case 0x6A: sprintf_s(tmp, "push 0x%llx", (unsigned long long)c.imm); strcpy_s(out->text, tmp); break;
        case 0xB8: case 0xB9: case 0xBA: case 0xBB: case 0xBC: case 0xBD: case 0xBE: case 0xBF: {
            int idx = (c.op & 7) + (dctx_rexb(&c) ? 8 : 0);
            sprintf_s(tmp, "mov %s, 0x%llx", dctx_reg_name(&c, dctx_rexw(&c) ? 8 : (c.p66 ? 2 : 4), idx),
                (unsigned long long)c.imm);
            strcpy_s(out->text, tmp); break;
        }
        case 0xB0: case 0xB1: case 0xB2: case 0xB3: case 0xB4:
        case 0xB5: case 0xB6: case 0xB7:
            sprintf_s(tmp, "mov %s, 0x%llx", dctx_reg_name(&c, 1, (c.op & 7) + (dctx_rexb(&c) ? 8 : 0)),
                (unsigned long long)c.imm);
            strcpy_s(out->text, tmp); break;
        case 0x88: case 0x89: {
            int sz = c.op == 0x88 ? 1 : opsize;
            dctx_modrm_rm(&c, at, rm); dctx_modrm_reg(&c, sz, rg);
            sprintf_s(tmp, "mov %s, %s", rm, rg); strcpy_s(out->text, tmp); break;
        }
        case 0x8A: case 0x8B: {
            int sz = c.op == 0x8A ? 1 : opsize;
            dctx_modrm_rm(&c, at, rm); dctx_modrm_reg(&c, sz, rg);
            sprintf_s(tmp, "mov %s, %s", rg, rm); strcpy_s(out->text, tmp); break;
        }
        case 0x8D:
            dctx_modrm_rm(&c, at, rm); dctx_modrm_reg(&c, opsize, rg);
            sprintf_s(tmp, "lea %s, %s", rg, rm); strcpy_s(out->text, tmp); break;
        case 0x8F:
            dctx_modrm_rm(&c, at, rm);
            sprintf_s(tmp, "pop %s", rm); strcpy_s(out->text, tmp); break;
        case 0xC6: case 0xC7:
            dctx_modrm_rm(&c, at, rm);
            sprintf_s(tmp, "mov %s, 0x%llx", rm, (unsigned long long)c.imm);
            strcpy_s(out->text, tmp); break;
        case 0xA0: case 0xA1: case 0xA2: case 0xA3: {
            int sz = (c.op & 1) ? opsize : 1;
            sprintf_s(tmp, "mov %s, [0x%llx]",
                c.op <= 0xA1 ? dctx_reg_name(&c, sz, 0) : "?", (unsigned long long)c.imm);
            if (c.op >= 0xA2) sprintf_s(tmp, "mov [0x%llx], %s",
                (unsigned long long)c.imm, dctx_reg_name(&c, sz, 0));
            strcpy_s(out->text, tmp); break;
        }
        case 0x63:
            dctx_modrm_rm(&c, at, rm); dctx_modrm_reg(&c, 8, rg);
            sprintf_s(tmp, "movsxd %s, %s", rg, rm); strcpy_s(out->text, tmp); break;
        case 0xE8: {
            char sym[128]; sym_name_for(c.rel_target, sym, sizeof(sym));
            if (sym[0]) sprintf_s(tmp, "call %s", sym);
            else sprintf_s(tmp, "call 0x%llx", (unsigned long long)c.rel_target);
            strcpy_s(out->text, tmp); out->target = c.rel_target; out->is_call = 1; break;
        }
        case 0xE9: {
            char sym[128]; sym_name_for(c.rel_target, sym, sizeof(sym));
            if (sym[0]) sprintf_s(tmp, "jmp %s", sym);
            else sprintf_s(tmp, "jmp 0x%llx", (unsigned long long)c.rel_target);
            strcpy_s(out->text, tmp); out->target = c.rel_target; out->is_jump = 1; break;
        }
        case 0xEB: {
            sprintf_s(tmp, "jmp 0x%llx", (unsigned long long)c.rel_target);
            strcpy_s(out->text, tmp); out->target = c.rel_target; out->is_jump = 1; break;
        }
        case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75:
        case 0x76: case 0x77: case 0x78: case 0x79: case 0x7A: case 0x7B:
        case 0x7C: case 0x7D: case 0x7E: case 0x7F:
            sprintf_s(tmp, "%s 0x%llx", jcc_names[c.op & 15], (unsigned long long)c.rel_target);
            strcpy_s(out->text, tmp); out->target = c.rel_target; out->is_jump = 1; break;
        case 0xE0:
            sprintf_s(tmp, "loopne 0x%llx", (unsigned long long)c.rel_target);
            strcpy_s(out->text, tmp); out->target = c.rel_target; out->is_jump = 1; break;
        case 0xE1:
            sprintf_s(tmp, "loope 0x%llx", (unsigned long long)c.rel_target);
            strcpy_s(out->text, tmp); out->target = c.rel_target; out->is_jump = 1; break;
        case 0xE2:
            sprintf_s(tmp, "loop 0x%llx", (unsigned long long)c.rel_target);
            strcpy_s(out->text, tmp); out->target = c.rel_target; out->is_jump = 1; break;
        case 0xE3:
            sprintf_s(tmp, "jrcxz 0x%llx", (unsigned long long)c.rel_target);
            strcpy_s(out->text, tmp); out->target = c.rel_target; out->is_jump = 1; break;
        case 0x84: case 0x85: {
            int sz = c.op == 0x84 ? 1 : opsize;
            dctx_modrm_rm(&c, at, rm); dctx_modrm_reg(&c, sz, rg);
            sprintf_s(tmp, "test %s, %s", rm, rg); strcpy_s(out->text, tmp); break;
        }
        case 0x86: case 0x87: {
            int sz = c.op == 0x86 ? 1 : opsize;
            dctx_modrm_rm(&c, at, rm); dctx_modrm_reg(&c, sz, rg);
            sprintf_s(tmp, "xchg %s, %s", rm, rg); strcpy_s(out->text, tmp); break;
        }
        case 0x91: case 0x92: case 0x93: case 0x94: case 0x95: case 0x96: case 0x97:
            sprintf_s(tmp, "xchg %s, %s", dctx_reg_name(&c, 8, 0),
                dctx_reg_name(&c, 8, (c.op & 7) + (dctx_rexb(&c) ? 8 : 0)));
            strcpy_s(out->text, tmp); break;
        case 0x38: case 0x39: case 0x3A: case 0x3B: {
            int sz = (c.op & 1) ? opsize : 1;
            dctx_modrm_rm(&c, at, rm); dctx_modrm_reg(&c, sz, rg);
            sprintf_s(tmp, "cmp %s, %s", (c.op & 2) ? rg : rm, (c.op & 2) ? rm : rg);
            strcpy_s(out->text, tmp); break;
        }
        case 0x3C: case 0x3D:
            sprintf_s(tmp, "cmp %s, 0x%llx", dctx_reg_name(&c, c.op == 0x3C ? 1 : opsize, 0),
                (unsigned long long)c.imm);
            strcpy_s(out->text, tmp); break;
        case 0x00: case 0x01: case 0x02: case 0x03:
            dctx_modrm_rm(&c, at, rm); dctx_modrm_reg(&c, (c.op & 1) ? opsize : 1, rg);
            sprintf_s(tmp, "add %s, %s", (c.op & 2) ? rg : rm, (c.op & 2) ? rm : rg);
            strcpy_s(out->text, tmp); break;
        case 0x08: case 0x09: case 0x0A: case 0x0B:
            dctx_modrm_rm(&c, at, rm); dctx_modrm_reg(&c, (c.op & 1) ? opsize : 1, rg);
            sprintf_s(tmp, "or %s, %s", (c.op & 2) ? rg : rm, (c.op & 2) ? rm : rg);
            strcpy_s(out->text, tmp); break;
        case 0x10: case 0x11: case 0x12: case 0x13:
            dctx_modrm_rm(&c, at, rm); dctx_modrm_reg(&c, (c.op & 1) ? opsize : 1, rg);
            sprintf_s(tmp, "adc %s, %s", (c.op & 2) ? rg : rm, (c.op & 2) ? rm : rg);
            strcpy_s(out->text, tmp); break;
        case 0x18: case 0x19: case 0x1A: case 0x1B:
            dctx_modrm_rm(&c, at, rm); dctx_modrm_reg(&c, (c.op & 1) ? opsize : 1, rg);
            sprintf_s(tmp, "sbb %s, %s", (c.op & 2) ? rg : rm, (c.op & 2) ? rm : rg);
            strcpy_s(out->text, tmp); break;
        case 0x20: case 0x21: case 0x22: case 0x23:
            dctx_modrm_rm(&c, at, rm); dctx_modrm_reg(&c, (c.op & 1) ? opsize : 1, rg);
            sprintf_s(tmp, "and %s, %s", (c.op & 2) ? rg : rm, (c.op & 2) ? rm : rg);
            strcpy_s(out->text, tmp); break;
        case 0x28: case 0x29: case 0x2A: case 0x2B:
            dctx_modrm_rm(&c, at, rm); dctx_modrm_reg(&c, (c.op & 1) ? opsize : 1, rg);
            sprintf_s(tmp, "sub %s, %s", (c.op & 2) ? rg : rm, (c.op & 2) ? rm : rg);
            strcpy_s(out->text, tmp); break;
        case 0x30: case 0x31: case 0x32: case 0x33:
            dctx_modrm_rm(&c, at, rm); dctx_modrm_reg(&c, (c.op & 1) ? opsize : 1, rg);
            sprintf_s(tmp, "xor %s, %s", (c.op & 2) ? rg : rm, (c.op & 2) ? rm : rg);
            strcpy_s(out->text, tmp); break;
        case 0x80: case 0x81: case 0x83: {
            static const char* g1[8] = { "add","or","adc","sbb","and","sub","xor","cmp" };
            int sz = (c.op == 0x80) ? 1 : opsize;
            dctx_modrm_rm(&c, at, rm);
            sprintf_s(tmp, "%s %s, 0x%llx", g1[c.reg], rm, (unsigned long long)c.imm);
            strcpy_s(out->text, tmp); break;
        }
        case 0xF6: case 0xF7: {
            static const char* g3[8] = { "test","test","not","neg","mul","imul","div","idiv" };
            dctx_modrm_rm(&c, at, rm);
            if (c.reg == 0) sprintf_s(tmp, "test %s, 0x%llx", rm, (unsigned long long)c.imm);
            else sprintf_s(tmp, "%s %s", g3[c.reg], rm);
            strcpy_s(out->text, tmp); break;
        }
        case 0xFE: case 0xFF: {
            static const char* g4[8] = { "inc","dec" };
            static const char* g5[8] = { "inc","dec","call","callf","jmp","jmpf","push","?" };
            dctx_modrm_rm(&c, at, rm);
            if (c.op == 0xFE) sprintf_s(tmp, "%s %s", g4[c.reg & 1], rm);
            else {
                sprintf_s(tmp, "%s %s", g5[c.reg & 7], rm);
                if (c.reg == 2 || c.reg == 3) out->is_call = 1;
                if (c.reg == 4 || c.reg == 5) out->is_jump = 1;
            }
            strcpy_s(out->text, tmp); break;
        }
        case 0x69: case 0x6B:
            dctx_modrm_rm(&c, at, rm); dctx_modrm_reg(&c, opsize, rg);
            sprintf_s(tmp, "imul %s, %s, 0x%llx", rg, rm, (unsigned long long)c.imm);
            strcpy_s(out->text, tmp); break;
        case 0xC0: case 0xC1: case 0xD0: case 0xD1: case 0xD2: case 0xD3: {
            static const char* g2[8] = { "rol","ror","rcl","rcr","shl","shr","sal","sar" };
            int sz = (c.op == 0xC0 || c.op == 0xD0 || c.op == 0xD2) ? 1 : opsize;
            dctx_modrm_rm(&c, at, rm);
            sprintf_s(tmp, "%s %s, %s", g2[c.reg & 7], rm,
                (c.op == 0xD0 || c.op == 0xD1) ? "1" : (c.op == 0xD2 || c.op == 0xD3) ? "cl" : "0x0");
            strcpy_s(out->text, tmp); break;
        }
        case 0xA8: case 0xA9:
            sprintf_s(tmp, "test %s, 0x%llx", dctx_reg_name(&c, c.op == 0xA8 ? 1 : opsize, 0),
                (unsigned long long)c.imm);
            strcpy_s(out->text, tmp); break;
        case 0x04: case 0x0C: case 0x14: case 0x1C: case 0x24: case 0x2C: case 0x34: {
            static const char* acc[8] = { "add","or","adc","sbb","and","sub","xor","cmp" };
            sprintf_s(tmp, "%s al, 0x%llx", acc[(c.op >> 3) & 7], (unsigned long long)c.imm);
            strcpy_s(out->text, tmp); break;
        }
        case 0xE4: sprintf_s(tmp, "in al, 0x%llx", (unsigned long long)c.imm); strcpy_s(out->text, tmp); break;
        case 0xE6: sprintf_s(tmp, "out 0x%llx, al", (unsigned long long)c.imm); strcpy_s(out->text, tmp); break;
        case 0xA4: op = "movsb"; break;
        case 0xA5: op = dctx_rexw(&c) ? "movsq" : "movsd"; break;
        case 0xA6: op = "cmpsb"; break;
        case 0xA7: op = "cmpsd"; break;
        case 0xAA: op = "stosb"; break;
        case 0xAB: op = dctx_rexw(&c) ? "stosq" : "stosd"; break;
        case 0xAC: op = "lodsb"; break;
        case 0xAD: op = dctx_rexw(&c) ? "lodsq" : "lodsd"; break;
        case 0xAE: op = "scasb"; break;
        case 0xAF: op = "scasd"; break;
        case 0x8C:
            dctx_modrm_rm(&c, at, rm);
            sprintf_s(tmp, "mov %s, sreg", rm); strcpy_s(out->text, tmp); break;
        case 0x8E:
            dctx_modrm_rm(&c, at, rm);
            sprintf_s(tmp, "mov sreg, %s", rm); strcpy_s(out->text, tmp); break;
        case 0xC8: strcpy_s(out->text, "enter"); break;
        case 0xD7: op = "xlat"; break;
        default:
            sprintf_s(tmp, "db 0x%02X", c.op);
            strcpy_s(out->text, tmp);
            break;
        }
    }
    else {
        switch (c.op2) {
        case 0x05: op = "syscall"; break;
        case 0x0B: op = "ud2"; break;
        case 0x31: op = "rdtsc"; break;
        case 0xA2: op = "cpuid"; break;
        case 0xA0: op = "push fs"; break;
        case 0xA1: op = "pop fs"; break;
        case 0xA8: op = "push gs"; break;
        case 0xA9: op = "pop gs"; break;
        case 0xC8: case 0xC9: case 0xCA: case 0xCB: case 0xCC: case 0xCD: case 0xCE: case 0xCF:
            sprintf_s(tmp, "bswap %s", dctx_reg_name(&c, 8, c.op2 & 7));
            strcpy_s(out->text, tmp); break;
        case 0x1F:
            dctx_modrm_rm(&c, at, rm);
            sprintf_s(tmp, "nop %s", rm); strcpy_s(out->text, tmp); break;
        case 0x80: case 0x81: case 0x82: case 0x83: case 0x84: case 0x85:
        case 0x86: case 0x87: case 0x88: case 0x89: case 0x8A: case 0x8B:
        case 0x8C: case 0x8D: case 0x8E: case 0x8F:
            sprintf_s(tmp, "%s 0x%llx", jcc_names[c.op2 & 15], (unsigned long long)c.rel_target);
            strcpy_s(out->text, tmp); out->target = c.rel_target; out->is_jump = 1; break;
        case 0xB6: case 0xB7: case 0xBE: case 0xBF: {
            const char* mn = (c.op2 == 0xB6 || c.op2 == 0xBE) ? "movzx" : "movsx";
            int ssz = (c.op2 == 0xB6 || c.op2 == 0xBE) ? 1 : 2;
            dctx_modrm_rm(&c, at, rm); dctx_modrm_reg(&c, opsize, rg);
            sprintf_s(tmp, "%s %s, %s", mn, rg, rm); strcpy_s(out->text, tmp); break;
        }
        case 0xAF:
            dctx_modrm_rm(&c, at, rm); dctx_modrm_reg(&c, opsize, rg);
            sprintf_s(tmp, "imul %s, %s", rg, rm); strcpy_s(out->text, tmp); break;
        case 0xA4: case 0xA5: case 0xAC: case 0xAD: {
            dctx_modrm_rm(&c, at, rm); dctx_modrm_reg(&c, opsize, rg);
            const char* mn = (c.op2 & 8) ? "shrd" : "shld";
            if (c.op2 & 1) sprintf_s(tmp, "%s %s, %s, cl", mn, rm, rg);
            else sprintf_s(tmp, "%s %s, %s, 0x%llx", mn, rm, rg, (unsigned long long)c.imm);
            strcpy_s(out->text, tmp); break;
        }
        case 0xAB: case 0xB3: case 0xBB: {
            const char* mn = c.op2 == 0xAB ? "bts" : c.op2 == 0xB3 ? "btr" : "btc";
            dctx_modrm_rm(&c, at, rm); dctx_modrm_reg(&c, opsize, rg);
            sprintf_s(tmp, "%s %s, %s", mn, rm, rg); strcpy_s(out->text, tmp); break;
        }
        case 0xBA: {
            dctx_modrm_rm(&c, at, rm);
            sprintf_s(tmp, "bt%s %s, 0x%llx", c.reg == 4 ? "" : c.reg == 5 ? "s" : c.reg == 6 ? "r" : "c",
                rm, (unsigned long long)c.imm);
            strcpy_s(out->text, tmp); break;
        }
        case 0xBC: case 0xBD: {
            dctx_modrm_rm(&c, at, rm); dctx_modrm_reg(&c, opsize, rg);
            sprintf_s(tmp, "%s %s, %s", c.op2 == 0xBC ? "bsf" : "bsr", rg, rm);
            strcpy_s(out->text, tmp); break;
        }
        // SSE 常见族
        case 0x10: case 0x11: {
            const char* mn = c.pf2 ? "movsd" : c.pf3 ? "movss" : "movups";
            dctx_modrm_rm(&c, at, rm); dctx_modrm_reg(&c, 16, rg);
            if (c.op2 == 0x10) sprintf_s(tmp, "%s %s, %s", mn, rg, rm);
            else sprintf_s(tmp, "%s %s, %s", mn, rm, rg);
            strcpy_s(out->text, tmp); break;
        }
        case 0x28: case 0x29: {
            dctx_modrm_rm(&c, at, rm); dctx_modrm_reg(&c, 16, rg);
            if (c.p66) sprintf_s(tmp, "movapd %s, %s", c.op2 == 0x28 ? rg : rm, c.op2 == 0x28 ? rm : rg);
            else sprintf_s(tmp, "movaps %s, %s", c.op2 == 0x28 ? rg : rm, c.op2 == 0x28 ? rm : rg);
            strcpy_s(out->text, tmp); break;
        }
        case 0x6F: case 0x7F: {
            const char* mn = c.pf3 ? "movdqu" : "movdqa";
            dctx_modrm_rm(&c, at, rm); dctx_modrm_reg(&c, 16, rg);
            if (c.op2 == 0x6F) sprintf_s(tmp, "%s %s, %s", mn, rg, rm);
            else sprintf_s(tmp, "%s %s, %s", mn, rm, rg);
            strcpy_s(out->text, tmp); break;
        }
        case 0x6E: case 0x7E: {
            dctx_modrm_rm(&c, at, rm); dctx_modrm_reg(&c, 16, rg);
            if (c.op2 == 0x6E) sprintf_s(tmp, "movd %s, %s", rg, rm);
            else sprintf_s(tmp, "movd %s, %s", rm, rg);
            strcpy_s(out->text, tmp); break;
        }
        case 0x57: case 0x54: case 0x55: case 0x58: case 0x59: case 0x5C: case 0x5D: case 0x5E: {
            static const char* fp[16] = { "?","?","?","?", "andps","andnps","orps","xorps",
                                          "addps","mulps","?","?","subps","minps","divps","maxps" };
            dctx_modrm_rm(&c, at, rm); dctx_modrm_reg(&c, 16, rg);
            sprintf_s(tmp, "%s %s, %s", fp[c.op2 & 15], rg, rm);
            strcpy_s(out->text, tmp); break;
        }
        case 0xEF:
            dctx_modrm_rm(&c, at, rm); dctx_modrm_reg(&c, 16, rg);
            sprintf_s(tmp, "pxor %s, %s", rg, rm); strcpy_s(out->text, tmp); break;
        case 0x76: case 0x63: {
            // 0F76 pshufd / 0F63 packsswb（简写）
            dctx_modrm_rm(&c, at, rm); dctx_modrm_reg(&c, 16, rg);
            sprintf_s(tmp, "%s %s, %s", c.op2 == 0x76 ? "pshufd" : "packsswb", rg, rm);
            strcpy_s(out->text, tmp); break;
        }
        case 0x73:
            dctx_modrm_rm(&c, at, rm);
            sprintf_s(tmp, "psrlq/pslldq/psrldq %s, 0x%llx", rm, (unsigned long long)c.imm);
            strcpy_s(out->text, tmp); break;
        case 0xB1:
            dctx_modrm_rm(&c, at, rm); dctx_modrm_reg(&c, opsize, rg);
            sprintf_s(tmp, "cmpxchg %s, %s", rm, rg); strcpy_s(out->text, tmp); break;
        case 0xC7:
            dctx_modrm_rm(&c, at, rm); dctx_modrm_reg(&c, opsize, rg);
            sprintf_s(tmp, "cmpxchg16b/8b %s", rm); strcpy_s(out->text, tmp); break;
        case 0xC3:
            dctx_modrm_rm(&c, at, rm); dctx_modrm_reg(&c, opsize, rg);
            sprintf_s(tmp, "movnti %s, %s", rm, rg); strcpy_s(out->text, tmp); break;
        case 0x38: case 0x3A:
            sprintf_s(tmp, "three-byte 0F %02X %02X", c.op2, buf[2]);
            strcpy_s(out->text, tmp); break;
        default:
            sprintf_s(tmp, "db 0x0F, 0x%02X", c.op2);
            strcpy_s(out->text, tmp);
            break;
        }
    }
    if (op && !out->text[0]) strcpy_s(out->text, op);
    // 栈操作数目标解析（FF /2 /4 间接跳转/调用给出注释目标）
    if (!out->target && c.has_modrm && c.op == 0xFF && (c.reg == 2 || c.reg == 4)) {
        ULONG_PTR t = dctx_deref_target(&c, at);
        if (t) out->target = t;
    }
    return out->size;
}


// ======================================================================
// 标记（标签/注释/书签）+ 模块符号解析
// ======================================================================
typedef struct { ULONG_PTR addr; char* text; } mark_t;

static mark_t g_labels[512];    static int g_nlabels;
static mark_t g_comments[512];  static int g_ncomments;
static mark_t g_bookmarks[256]; static int g_nbookmarks;

static const char* mark_find(mark_t* arr, int n, ULONG_PTR addr) {
    for (int i = 0; i < n; i++) if (arr[i].addr == addr) return arr[i].text;
    return NULL;
}
static int mark_set(mark_t* arr, int* pn, int max, ULONG_PTR addr, const char* text) {
    for (int i = 0; i < *pn; i++) {
        if (arr[i].addr == addr) {
            if (!text || !*text) {          // 删除
                free(arr[i].text);
                arr[i] = arr[--(*pn)];
                return 1;
            }
            free(arr[i].text);              // 替换
            arr[i].text = _strdup(text);
            return 1;
        }
    }
    if (!text || !*text) return 0;
    if (*pn >= max) return -1;
    arr[*pn].addr = addr;
    arr[*pn].text = _strdup(text);
    (*pn)++;
    return 1;
}

static const char* label_find(ULONG_PTR addr) { return mark_find(g_labels, g_nlabels, addr); }

// 模块信息（PEB Ldr 遍历）
typedef struct {
    ULONG_PTR base;
    ULONG size;
    char name[64];          // BaseDllName（ANSI）
    WCHAR path[MAX_PATH];
} modinfo_t;

static int list_modules(modinfo_t* out, int maxn) {
    X_PEB* peb = x_peb();
    X_PEB_LDR_DATA* ldr = (X_PEB_LDR_DATA*)peb->Ldr;
    int n = 0;
    if (!ldr) return 0;
    LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
    for (LIST_ENTRY* cur = head->Flink; cur && cur != head; cur = cur->Flink) {
        X_LDR_DATA_TABLE_ENTRY* e = (X_LDR_DATA_TABLE_ENTRY*)cur;
        if (!e->DllBase) continue;
        if (n >= maxn) break;
        out[n].base = (ULONG_PTR)e->DllBase;
        out[n].size = e->SizeOfImage;
        out[n].name[0] = 0;
        out[n].path[0] = 0;
        if (e->BaseDllName.Buffer)
            WideCharToMultiByte(CP_ACP, 0, e->BaseDllName.Buffer, e->BaseDllName.Length / 2,
                out[n].name, sizeof(out[n].name) - 1, NULL, NULL);
        if (e->FullDllName.Buffer)
            wcsncpy_s(out[n].path, e->FullDllName.Buffer, _TRUNCATE);
        n++;
    }
    return n;
}

// 主目标的映射基址。mod_find_by_name 用它把**空模块名**解析成主模块。
// 原来是 main 里的局部变量，于是"默认模块"这个约定根本无法实现——
// 而那正是 exports 用默认参数时一直返回"模块不存在"的原因。

static PVOID g_target_base = NULL;
static int mod_find_by_name(const char* name, modinfo_t* mi) {
    modinfo_t mods[128];
    int n = list_modules(mods, 128);
    // 空名字 = 主模块。
    //
    // 原来空名字**匹配不到任何东西**：第一条比较是 _stricmp(name, "")，
    // 第二条要求 strlen(name) == blen，而 strlen("") 恒为 0、模块名的
    // basename 长度恒大于 0。所以两个条件都永远为假。
    //
    // 后果：`exports` 用默认参数（module 省略）时**从来就没工作过**，
    // 一直返回"模块不存在"；而新加的 `list_imports` 继承了同一个毛病。
    // 而调用方看到的错误是"模块不存在"——听起来像调用方给错了名字，
    // 不像"空名字这个约定根本没实现"。
    //
    // 判据：空名字返回主模块（基址等于目标基址的那个）。
    if (name && !*name) {
        for (int i = 0; i < n; i++) {
            if (g_target_base && mods[i].base == (ULONG_PTR)g_target_base) {
                if (mi) *mi = mods[i];
                return 1;
            }
        }
        // 退路：主可执行文件是唯一以 .exe 结尾且不是调试器自身的那个；
        // 找不到就取第一个，总比返回"不存在"有用。
        for (int i = 0; i < n; i++) {
            size_t l = strlen(mods[i].name);
            if (l > 4 && _stricmp(mods[i].name + l - 4, ".exe") == 0) {
                if (mi) *mi = mods[i];
                return 1;
            }
        }
        if (n > 0) { if (mi) *mi = mods[0]; return 1; }
        return 0;
    }
    for (int i = 0; i < n; i++) {
        if (_stricmp(mods[i].name, name) == 0) { if (mi) *mi = mods[i]; return 1; }
        // 允许不带 .dll/.exe 后缀匹配
        const char* dot = strchr(mods[i].name, '.');
        size_t blen = dot ? (size_t)(dot - mods[i].name) : strlen(mods[i].name);
        if (strlen(name) == blen && _strnicmp(mods[i].name, name, blen) == 0) {
            if (mi) *mi = mods[i]; return 1;
        }
    }
    return 0;
}

// 在模块导出表中反查地址 -> 名称（精确匹配）
static const char* mod_export_name(ULONG_PTR modbase, ULONG_PTR addr) {
    static __declspec(thread) char tbuf[128];
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)modbase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)modbase + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY ed = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!ed.VirtualAddress) return NULL;
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)modbase + ed.VirtualAddress);
    DWORD* names = (DWORD*)((BYTE*)modbase + exp->AddressOfNames);
    WORD* ords = (WORD*)((BYTE*)modbase + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)((BYTE*)modbase + exp->AddressOfFunctions);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        ULONG_PTR fa = modbase + funcs[ords[i]];
        if (fa == addr) {
            sprintf_s(tbuf, "%s", (const char*)((BYTE*)modbase + names[i]));
            return tbuf;
        }
    }
    return NULL;
}

static modinfo_t g_sym_mods[128];
static int g_sym_mods_n = -1;   // -1 = 需刷新
static void sym_refresh_modules(void) {
    g_sym_mods_n = list_modules(g_sym_mods, 128);
}
static const char* g_sym_mod_name = NULL; // 当前反查模块名（线程内使用）

static const char* sym_name_for(ULONG_PTR addr, char* buf, size_t n) {
    buf[0] = 0;
    const char* lab = label_find(addr);
    if (lab) { sprintf_s(buf, n, "%s", lab); return buf; }
    if (g_sym_mods_n < 0) sym_refresh_modules();
    for (int i = 0; i < g_sym_mods_n; i++) {
        if (addr >= g_sym_mods[i].base && addr < g_sym_mods[i].base + g_sym_mods[i].size) {
            const char* en = mod_export_name(g_sym_mods[i].base, addr);
            if (en) {
                const char* dot = strchr(g_sym_mods[i].name, '.');
                size_t blen = dot ? (size_t)(dot - g_sym_mods[i].name) : strlen(g_sym_mods[i].name);
                sprintf_s(buf, n, "%.*s.%s", (int)blen, g_sym_mods[i].name, en);
                return buf;
            }
            return buf; // 模块内但无导出符号：留空（调用处回退地址文本）
        }
    }
    return buf;
}

static ULONG_PTR sym_resolve(const char* name) {
    if (!name || !*name) return 0;
    // 数字地址
    if (isdigit((unsigned char)name[0]) || name[0] == '0') {
        char* end = NULL;
        unsigned long long v = _strtoui64(name, &end, 0);
        if (end && *end == 0) return (ULONG_PTR)v;
    }
    // 标签
    for (int i = 0; i < g_nlabels; i++)
        if (_stricmp(g_labels[i].text, name) == 0) return g_labels[i].addr;
    for (int i = 0; i < g_nbookmarks; i++)
        if (_stricmp(g_bookmarks[i].text, name) == 0) return g_bookmarks[i].addr;
    // module!export
    const char* bang = strchr(name, '!');
    if (bang) {
        char modn[64];
        size_t ml = bang - name;
        if (ml >= sizeof(modn)) ml = sizeof(modn) - 1;
        memcpy(modn, name, ml); modn[ml] = 0;
        modinfo_t mi;
        if (mod_find_by_name(modn, &mi)) {
            PVOID p = mem_find_export((PVOID)mi.base, bang + 1);
            if (p) return (ULONG_PTR)p;
        }
        return 0;
    }
    // 裸导出名：全模块搜索
    if (g_sym_mods_n < 0) sym_refresh_modules();
    for (int i = 0; i < g_sym_mods_n; i++) {
        PVOID p = mem_find_export((PVOID)g_sym_mods[i].base, name);
        if (p) return (ULONG_PTR)p;
    }
    return 0;
}

// ======================================================================
// 条件表达式求值器
//   支持：数字（0x/十进制）、寄存器名、字符串 "..."、
//   运算符 || && == != <= >= << >> < > + - * / % & | ^ ! ~ 括号
//   函数：mem.valid(a) utf16(a) utf8(a) strstr(a,b) tid()
//   变量：$breakpointcounter
// ======================================================================
typedef struct { double num; char str[512]; int is_str; } xval;

typedef struct {
    const char* p;
    const CONTEXT* ctx;
    unsigned long long bpcounter;
    DWORD tid;
    int err;
} xparser;

static void xp_ws(xparser* x) {
    while (*x->p == ' ' || *x->p == '\t') x->p++;
}

static unsigned long long xreg_get(const CONTEXT* c, const char* name, int* ok) {
    *ok = 1;
#define R(n, f) if (_stricmp(name, n) == 0) return c->f;
    R("rax", Rax) R("rcx", Rcx) R("rdx", Rdx) R("rbx", Rbx)
    R("rsp", Rsp) R("rbp", Rbp) R("rsi", Rsi) R("rdi", Rdi)
    R("r8", R8) R("r9", R9) R("r10", R10) R("r11", R11)
    R("r12", R12) R("r13", R13) R("r14", R14) R("r15", R15)
    R("rip", Rip)
#undef R
    if (_stricmp(name, "eflags") == 0 || _stricmp(name, "rflags") == 0) return c->EFlags;
    if (_stricmp(name, "cs") == 0) return c->SegCs;
    if (_stricmp(name, "ds") == 0) return c->SegDs;
    if (_stricmp(name, "es") == 0) return c->SegEs;
    if (_stricmp(name, "fs") == 0) return c->SegFs;
    if (_stricmp(name, "gs") == 0) return c->SegGs;
    if (_stricmp(name, "ss") == 0) return c->SegSs;
    // 32/16 位别名
    if (name[0] == 'e' && name[3] == 0) {
        char r4[4] = { 'r', name[1], name[2], 0 };
        int ok2; unsigned long long v = xreg_get(c, r4, &ok2);
        if (ok2) return v & 0xFFFFFFFFULL;
    }
    *ok = 0;
    return 0;
}

static xval xp_expr(xparser* x);

static xval xv_num(double n) { xval v; memset(&v, 0, sizeof(v)); v.num = n; return v; }
static xval xv_str(const char* s) { xval v; memset(&v, 0, sizeof(v)); v.is_str = 1; strncpy_s(v.str, s, _TRUNCATE); return v; }
static double xv_numof(xval v) { return v.is_str ? 0 : v.num; }

static xval xp_primary(xparser* x) {
    xp_ws(x);
    if (*x->p == '(') {
        x->p++;
        xval v = xp_expr(x);
        xp_ws(x);
        if (*x->p == ')') x->p++;
        return v;
    }
    if (*x->p == '"') {
        x->p++;
        char buf[512]; size_t o = 0;
        while (*x->p && *x->p != '"' && o < sizeof(buf) - 1) {
            if (*x->p == '\\' && x->p[1]) x->p++;
            buf[o++] = *x->p++;
        }
        buf[o] = 0;
        if (*x->p == '"') x->p++;
        return xv_str(buf);
    }
    if (isdigit((unsigned char)*x->p) || (*x->p == '0' && (x->p[1] == 'x' || x->p[1] == 'X'))) {
        char* end = NULL;
        unsigned long long v = _strtoui64(x->p, &end, 0);
        if (end == x->p) { // 可能是 "1234abcdh" 风格
            while (isxdigit((unsigned char)*x->p)) x->p++;
            if (*x->p == 'h' || *x->p == 'H') { x->p++; x->err = 1; return xv_num(0); }
        }
        else x->p = end;
        return xv_num((double)v);
    }
    if (isalpha((unsigned char)*x->p) || *x->p == '_' || *x->p == '$') {
        char id[64]; size_t o = 0;
        while ((isalnum((unsigned char)*x->p) || *x->p == '_' || *x->p == '$' || *x->p == '.') && o < sizeof(id) - 1)
            id[o++] = *x->p++;
        id[o] = 0;
        xp_ws(x);
        if (*x->p == '(') { // 函数
            x->p++;
            xval args[4]; int na = 0;
            xp_ws(x);
            if (*x->p != ')') {
                for (;;) {
                    if (na < 4) args[na++] = xp_expr(x);
                    else xp_expr(x);
                    xp_ws(x);
                    if (*x->p == ',') { x->p++; continue; }
                    break;
                }
            }
            xp_ws(x);
            if (*x->p == ')') x->p++;
            if (_stricmp(id, "mem.valid") == 0 && na >= 1) {
                ULONG_PTR a = (ULONG_PTR)xv_numof(args[0]);
                MEMORY_BASIC_INFORMATION mbi;
                int ok = VirtualQuery((PVOID)a, &mbi, sizeof(mbi))
                    && mbi.State == MEM_COMMIT
                    && mbi.Protect != PAGE_NOACCESS && mbi.Protect != PAGE_GUARD;
                return xv_num(ok ? 1 : 0);
            }
            if ((_stricmp(id, "utf16") == 0 || _stricmp(id, "utf8") == 0) && na >= 1) {
                ULONG_PTR a = (ULONG_PTR)xv_numof(args[0]);
                char buf[512]; buf[0] = 0;
                if (id[0] == 'u' || id[0] == 'U') {
                    WCHAR w[256]; w[0] = 0;
                    mem_read_safe(a, w, sizeof(w));
                    w[255] = 0;
                    WideCharToMultiByte(CP_UTF8, 0, w, -1, buf, sizeof(buf) - 1, NULL, NULL);
                }
                else {
                    mem_read_safe(a, buf, sizeof(buf) - 1);
                    buf[sizeof(buf) - 1] = 0;
                }
                return xv_str(buf);
            }
            if (_stricmp(id, "strstr") == 0 && na >= 2)
                return xv_num(strstr(args[0].str, args[1].str) ? 1 : 0);
            if (_stricmp(id, "tid") == 0)
                return xv_num((double)(x->tid ? x->tid : GetCurrentThreadId()));
            if (_stricmp(id, "mod.match") == 0 && na >= 2)
                return xv_num(0); // 预留
            x->err = 1;
            return xv_num(0);
        }
        if (*id == '$') {
            if (_stricmp(id, "$breakpointcounter") == 0) return xv_num((double)x->bpcounter);
            x->err = 1;
            return xv_num(0);
        }
        int ok = 0;
        unsigned long long rv = x->ctx ? xreg_get(x->ctx, id, &ok) : 0;
        if (ok) return xv_num((double)rv);
        ULONG_PTR sv = sym_resolve(id);
        if (sv) return xv_num((double)sv);
        x->err = 1;
        return xv_num(0);
    }
    x->err = 1;
    return xv_num(0);
}

static xval xp_unary(xparser* x) {
    xp_ws(x);
    if (*x->p == '!') { x->p++; return xv_num(!xv_numof(xp_unary(x))); }
    if (*x->p == '~') { x->p++; return xv_num((double)(~(unsigned long long)xv_numof(xp_unary(x)))); }
    if (*x->p == '-') { x->p++; return xv_num(-xv_numof(xp_unary(x))); }
    return xp_primary(x);
}

static xval xp_mul(xparser* x) {
    xval v = xp_unary(x);
    for (;;) {
        xp_ws(x);
        if (*x->p == '*') { x->p++; v = xv_num(xv_numof(v) * xv_numof(xp_unary(x))); }
        else if (*x->p == '/') { x->p++; double d = xv_numof(xp_unary(x)); v = xv_num(d ? xv_numof(v) / d : 0); }
        else if (*x->p == '%') { x->p++; double d = xv_numof(xp_unary(x));
            v = xv_num(d ? (double)((long long)xv_numof(v) % (long long)d) : 0); }
        else break;
    }
    return v;
}
static xval xp_add(xparser* x) {
    xval v = xp_mul(x);
    for (;;) {
        xp_ws(x);
        if (*x->p == '+') { x->p++; v = xv_num(xv_numof(v) + xv_numof(xp_mul(x))); }
        else if (*x->p == '-') { x->p++; v = xv_num(xv_numof(v) - xv_numof(xp_mul(x))); }
        else break;
    }
    return v;
}
static xval xp_shift(xparser* x) {
    xval v = xp_add(x);
    for (;;) {
        xp_ws(x);
        if (x->p[0] == '<' && x->p[1] == '<') { x->p += 2;
            v = xv_num((double)((unsigned long long)xv_numof(v) << (int)xv_numof(xp_add(x)))); }
        else if (x->p[0] == '>' && x->p[1] == '>') { x->p += 2;
            v = xv_num((double)((unsigned long long)xv_numof(v) >> (int)xv_numof(xp_add(x)))); }
        else break;
    }
    return v;
}
static xval xp_rel(xparser* x) {
    xval v = xp_shift(x);
    for (;;) {
        xp_ws(x);
        if (x->p[0] == '<' && x->p[1] == '=') { x->p += 2; v = xv_num(xv_numof(v) <= xv_numof(xp_shift(x))); }
        else if (x->p[0] == '>' && x->p[1] == '=') { x->p += 2; v = xv_num(xv_numof(v) >= xv_numof(xp_shift(x))); }
        else if (*x->p == '<') { x->p++; v = xv_num(xv_numof(v) < xv_numof(xp_shift(x))); }
        else if (*x->p == '>') { x->p++; v = xv_num(xv_numof(v) > xv_numof(xp_shift(x))); }
        else break;
    }
    return v;
}
static xval xp_eq(xparser* x) {
    xval v = xp_rel(x);
    for (;;) {
        xp_ws(x);
        if (x->p[0] == '=' && x->p[1] == '=') { x->p += 2;
            xval r = xp_rel(x);
            if (v.is_str || r.is_str) v = xv_num(_stricmp(v.str, r.str) == 0);
            else v = xv_num(xv_numof(v) == xv_numof(r)); }
        else if (x->p[0] == '!' && x->p[1] == '=') { x->p += 2;
            xval r = xp_rel(x);
            if (v.is_str || r.is_str) v = xv_num(_stricmp(v.str, r.str) != 0);
            else v = xv_num(xv_numof(v) != xv_numof(r)); }
        else break;
    }
    return v;
}
static xval xp_and(xparser* x) {
    xval v = xp_eq(x);
    for (;;) {
        xp_ws(x);
        if (x->p[0] == '&' && x->p[1] != '&') { x->p++;
            v = xv_num((double)((unsigned long long)xv_numof(v) & (unsigned long long)xv_numof(xp_eq(x)))); }
        else break;
    }
    return v;
}
static xval xp_xor(xparser* x) {
    xval v = xp_and(x);
    for (;;) {
        xp_ws(x);
        if (*x->p == '^') { x->p++;
            v = xv_num((double)((unsigned long long)xv_numof(v) ^ (unsigned long long)xv_numof(xp_and(x)))); }
        else break;
    }
    return v;
}
static xval xp_bitor(xparser* x) {
    xval v = xp_xor(x);
    for (;;) {
        xp_ws(x);
        if (*x->p == '|' && x->p[1] != '|') { x->p++;
            v = xv_num((double)((unsigned long long)xv_numof(v) | (unsigned long long)xv_numof(xp_xor(x)))); }
        else break;
    }
    return v;
}
static xval xp_land(xparser* x) {
    xval v = xp_bitor(x);
    for (;;) {
        xp_ws(x);
        if (x->p[0] == '&' && x->p[1] == '&') { x->p += 2;
            double r = xv_numof(xp_bitor(x));
            v = xv_num((xv_numof(v) != 0 && r != 0) ? 1 : 0); }
        else break;
    }
    return v;
}
static xval xp_expr(xparser* x) {
    xval v = xp_land(x);
    for (;;) {
        xp_ws(x);
        if (x->p[0] == '|' && x->p[1] == '|') { x->p += 2;
            double r = xv_numof(xp_land(x));
            v = xv_num((xv_numof(v) != 0 || r != 0) ? 1 : 0); }
        else break;
    }
    return v;
}

static xval eval_expr(const char* expr, const CONTEXT* ctx, unsigned long long bpc, DWORD tid, int* err) {
    xparser x = { expr, ctx, bpc, tid, 0 };
    xval v = xp_expr(&x);
    xp_ws(&x);
    if (*x.p) x.err = 1;
    if (err) *err = x.err;
    return v;
}


// ======================================================================
// 调试引擎核心：断点 / 补丁 / 跟踪 / 日志 / VEH
// ======================================================================
#define MAX_BP 256
#define BP_SW 0
#define BP_HW 1
#define BP_MEM 2

typedef struct {
    int used;
    int id;
    int type;               // BP_SW / BP_HW / BP_MEM
    int enabled;
    int once;               // 一次性
    int silent;             // 静默（不停下）
    ULONG_PTR addr;
    int size;               // hw: 1/2/4/8；mem: 字节长度；sw: 1
    int hwmode;             // hw: 0 exec 1 write 2 read(rw) 3 rw
    int hwslot;             // hw: 0..3（-1 未分配）
    BYTE orig;              // sw 原始字节
    ULONG_PTR orig_prot;    // mem：原保护（按页记录，简化单页）
    char cond[256];
    char logmsg[256];
    unsigned long long hits;
} bp_t;

static bp_t g_bps[MAX_BP];
static int g_bp_next_id = 1;
static CRITICAL_SECTION g_bp_lock;

static bp_t* bp_by_id(int id) {
    for (int i = 0; i < MAX_BP; i++)
        if (g_bps[i].used && g_bps[i].id == id) return &g_bps[i];
    return NULL;
}
static bp_t* bp_by_addr_sw(ULONG_PTR addr) {
    for (int i = 0; i < MAX_BP; i++)
        if (g_bps[i].used && g_bps[i].type == BP_SW && g_bps[i].addr == addr) return &g_bps[i];
    return NULL;
}
static bp_t* bp_alloc(void) {
    for (int i = 0; i < MAX_BP; i++)
        if (!g_bps[i].used) {
            memset(&g_bps[i], 0, sizeof(bp_t));
            g_bps[i].used = 1;
            g_bps[i].id = g_bp_next_id++;
            g_bps[i].hwslot = -1;
            return &g_bps[i];
        }
    return NULL;
}
static void bp_free(bp_t* bp) {
    if (bp->hwslot >= 0) { /* Dr 槽在下一次 apply 时重建 */ }
    bp->used = 0;
}

// 补丁
#define MAX_PATCH 128
typedef struct { int used, id, enabled; ULONG_PTR addr; int len; BYTE orig[16]; } patch_t;
static patch_t g_patches[MAX_PATCH];
static int g_patch_next_id = 1;

// 跟踪环形缓冲
typedef struct {
    ULONG_PTR addr, rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15, rip;
    DWORD tid;
    BYTE nb;
    BYTE bytes[15];
    char text[160];
} trc_t;

#define TRACEMAX 65536
static trc_t g_trc[TRACEMAX];
static unsigned g_trc_n;
static unsigned long long g_trc_total;
static int g_trace_on;
static int g_trace_mode;                 // 0 into 1 over
static char g_trace_cond[256];
static unsigned long long g_trace_max;
static int g_trace_stopflag;

// 日志环形缓冲
#define LOGMAX 1024
static char* g_logring[LOGMAX];
static unsigned long long g_logseq[LOGMAX];
static unsigned g_loghead, g_logtail;
static unsigned long long g_lognext;
static CRITICAL_SECTION g_log_lock;

// 事件广播钩子（由管道服务器注入）
static void (*g_evt_hook)(const char* json) = NULL;
static void evt_send(const char* json) { if (g_evt_hook) g_evt_hook(json); }

static void dbg_logf(const char* fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    EnterCriticalSection(&g_log_lock);
    unsigned long long seq = g_lognext++;
    unsigned slot = g_logtail % LOGMAX;
    if (g_logring[slot]) free(g_logring[slot]);
    g_logring[slot] = _strdup(buf);
    g_logseq[slot] = seq;
    g_logtail++;
    if (g_logtail - g_loghead > LOGMAX) g_loghead = g_logtail - LOGMAX;
    LeaveCriticalSection(&g_log_lock);
    if (g_evt_hook) {
        jsb b; jsb_init(&b);
        jsb_put(&b, "{\"event\":\"log\",\"seq\":"); jsb_printf(&b, "%llu", seq);
        jsb_put(&b, ",\"line\":"); jsb_esc(&b, buf); jsb_put(&b, "}");
        evt_send(b.p);
        free(b.p);
    }
}

// ---- 调试状态机 ----
#define DS_RUN 0
#define DS_PAUSE 1
static volatile LONG g_state = DS_RUN;

enum { CMD_NONE = 0, CMD_GO = 1, CMD_STEP_IN = 2, CMD_STEP_OVER = 3, CMD_STEP_OUT = 4 };

static CONTEXT* g_pctx = NULL;           // VEH 暂停线程的 ContextRecord（暂停期间有效）
static DWORD g_paused_tid;
static char g_pause_reason[128];
static HANDLE g_go;                      // manual-reset
static volatile LONG g_cmd = CMD_NONE;
static volatile LONG g_rearm; static ULONG_PTR g_rearm_addr;
static volatile LONG g_step_pause;
static HANDLE g_par_thread = NULL;       // 寄生（目标）线程
static DWORD g_par_tid = 0;

// 手动暂停：挂起全部线程并快照上下文
#define SUSMAX 512
static HANDLE g_sus_h[SUSMAX];
static DWORD g_sus_tid[SUSMAX];
static CONTEXT g_sus_ctx[SUSMAX];
static int g_sus_n;

// 引擎自身线程（管道服务器/客户端）：绝不能挂起——它们可能正持有引擎锁，
// 挂起后会造成永久死锁（如 broadcast_evt 的 cli_lock）。
#define ENG_TIDS_MAX 24
static DWORD g_eng_tids[ENG_TIDS_MAX];
static int g_eng_tids_n;
static void eng_tid_add(DWORD tid) {
    if (g_eng_tids_n < ENG_TIDS_MAX) g_eng_tids[g_eng_tids_n++] = tid;
}
static int eng_tid_is(DWORD tid) {
    for (int i = 0; i < g_eng_tids_n; i++) if (g_eng_tids[i] == tid) return 1;
    return 0;
}

static int snapshot_threads(DWORD* tids, int maxn) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    int n = 0;
    DWORD pid = GetCurrentProcessId();
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid && te.th32ThreadID != GetCurrentThreadId()) {
                if (n < maxn) tids[n++] = te.th32ThreadID;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return n;
}

static int suspend_all(void) {
    DWORD self = GetCurrentThreadId();
    DWORD tids[SUSMAX];
    int n = snapshot_threads(tids, SUSMAX);
    int k = 0;
    for (int i = 0; i < n; i++) {
        if (tids[i] == self || eng_tid_is(tids[i])) continue;   // 挂起发起方与引擎线程会死锁
        HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
            THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tids[i]);
        if (!h) continue;
        if (SuspendThread(h) == (DWORD)-1) { CloseHandle(h); continue; }
        CONTEXT c;
        memset(&c, 0, sizeof(c));
        c.ContextFlags = CONTEXT_ALL;
        if (!GetThreadContext(h, &c)) { ResumeThread(h); CloseHandle(h); continue; }
        g_sus_h[k] = h; g_sus_tid[k] = tids[i]; g_sus_ctx[k] = c;
        k++;
    }
    g_sus_n = k;
    return k;
}

static void resume_all(void) {
    for (int i = 0; i < g_sus_n; i++) {
        // 合并挂起期间新设置的硬件断点（Dr0-3/Dr7），否则恢复时会被旧快照抹掉
        CONTEXT dc;
        memset(&dc, 0, sizeof(dc));
        dc.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(g_sus_h[i], &dc)) {
            g_sus_ctx[i].Dr0 = dc.Dr0; g_sus_ctx[i].Dr1 = dc.Dr1;
            g_sus_ctx[i].Dr2 = dc.Dr2; g_sus_ctx[i].Dr3 = dc.Dr3;
            g_sus_ctx[i].Dr6 = dc.Dr6; g_sus_ctx[i].Dr7 = dc.Dr7;
        }
        SetThreadContext(g_sus_h[i], &g_sus_ctx[i]);
        ResumeThread(g_sus_h[i]);
        CloseHandle(g_sus_h[i]);
    }
    g_sus_n = 0;
}

// ---- 硬件断点：把 Dr0-3/Dr7 应用到所有线程 ----
static void hw_apply_all(void) {
    DWORD tids[SUSMAX];
    int n = snapshot_threads(tids, SUSMAX);
    // 逐线程记录。这里在 Sky.exe 上会挂住而在单线程目标上不会，所以需要知道停在哪一个上：
    // suspend_all 的注释已经指出引擎线程被挂起会永久死锁，而这段代码同样的风险在于
    // SuspendThread 的目标线程此刻可能正持有某个锁。没有这行日志，一次挂起只表现为
    // "set_hw_bp 不返回"，看不出是哪个线程、停在哪一步。
    logf("[*] hw_apply_all: %d 个线程\n", n);
    for (int i = 0; i < n; i++) {
        if (eng_tid_is(tids[i])) continue;   // 引擎线程不设 Dr（也避免与引擎锁交互）
        logf("[*]   tid %lu: OpenThread\n", (unsigned long)tids[i]);
        HANDLE h = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, tids[i]);
        if (!h) { logf("[*]   tid %lu: 打不开\n", (unsigned long)tids[i]); continue; }
        logf("[*]   tid %lu: SuspendThread\n", (unsigned long)tids[i]);
        SuspendThread(h);
        CONTEXT c;
        memset(&c, 0, sizeof(c));
        c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(h, &c)) {
            int slot = 0;
            for (int b = 0; b < MAX_BP && slot < 4; b++) {
                if (!g_bps[b].used || g_bps[b].type != BP_HW || !g_bps[b].enabled) continue;
                ULONG_PTR* dr = (slot == 0) ? &c.Dr0 : (slot == 1) ? &c.Dr1 :
                    (slot == 2) ? &c.Dr2 : &c.Dr3;
                *dr = g_bps[b].addr;
                c.Dr7 &= ~(3ULL << (slot * 2));               // 清局部+全局使能
                c.Dr7 &= ~(0xFULL << (16 + slot * 4));        // 清 RW/LEN
                int rw = g_bps[b].hwmode;                      // 0 exec 1 write 3 rw  (2=read 不可用)
                if (rw == 2) rw = 3;
                int ln = (g_bps[b].size == 1) ? 0 : (g_bps[b].size == 2) ? 1 :
                    (g_bps[b].size == 8) ? 2 : 3;
                c.Dr7 |= (1ULL << (slot * 2));                 // 局部使能
                c.Dr7 |= ((ULONG_PTR)(rw | (ln << 2))) << (16 + slot * 4);
                g_bps[b].hwslot = slot;
                slot++;
            }
            // 剩余槽位关闭
            for (; slot < 4; slot++) {
                c.Dr7 &= ~(3ULL << (slot * 2));
                c.Dr7 &= ~(0xFULL << (16 + slot * 4));
            }
            c.Dr6 = 0;
            SetThreadContext(h, &c);
            // **关键**：如果这个线程正是"停在 VEH 里"的那一个，只写 SetThreadContext 是不够的 ——
            // 从异常恢复时，内核会用 ep->ContextRecord（即 g_pctx）来安装上下文，
            // 把刚写进去的 Dr 全部抹回旧值（旧值是 0）。
            //
            // 实测（第 139 轮）：在**入口**挂硬件执行断点，30 秒**零命中**而进程照常运行 ——
            // 入口是恢复后执行的第一条指令，所以那次零命中不可能是"没执行到"，
            // 只能是"断点没生效"。原因就是这条"写进去又被覆盖"。
            if (g_pctx && tids[i] == g_paused_tid) {
                g_pctx->Dr0 = c.Dr0; g_pctx->Dr1 = c.Dr1;
                g_pctx->Dr2 = c.Dr2; g_pctx->Dr3 = c.Dr3;
                g_pctx->Dr6 = c.Dr6; g_pctx->Dr7 = c.Dr7;
                logf("[*]   tid %lu: 已同时写入暂停上下文（否则 resume 会抹掉 Dr）\n",
                     (unsigned long)tids[i]);
            }
        }
        ResumeThread(h);
        CloseHandle(h);
        logf("[*]   tid %lu: 完成\n", (unsigned long)tids[i]);
    }
    logf("[*] hw_apply_all: 结束\n");
}

// guard page 内存断点重保护队列
static ULONG_PTR g_reguard[64]; static int g_reguard_n;

// ---- 断点 API（须持有 g_bp_lock；外部命令包装负责加锁与挂起） ----

static int bp_sw_enable(bp_t* bp) {
    if (!mem_read_safe(bp->addr, &bp->orig, 1)) return 0;
    BYTE cc = 0xCC;
    return mem_write_safe(bp->addr, &cc, 1) == 1;
}
static void bp_sw_disable(bp_t* bp) {
    mem_write_safe(bp->addr, &bp->orig, 1);
}

// 在可能运行的线程上安全写内存：挂起→写→恢复（VEH 暂停时线程已停，直接写）
static void safe_mem_write(ULONG_PTR addr, const void* data, SIZE_T len) {
    if (g_state == DS_PAUSE) { mem_write_safe(addr, data, len); return; }
    suspend_all();
    mem_write_safe(addr, data, len);
    resume_all();
}

static void bp_delete(bp_t* bp) {
    EnterCriticalSection(&g_bp_lock);
    if (bp->type == BP_SW && bp->enabled) {
        bp_sw_disable(bp);
        // 若正停在该断点处（RIP 指向断点地址），内存须立即恢复原始字节，
        // 否则恢复执行会撞上 0xCC
        if (g_pctx && (ULONG_PTR)g_pctx->Rip == bp->addr)
            mem_write_safe(bp->addr, &bp->orig, 1);
    }
    if (bp->type == BP_HW) { bp->enabled = 0; LeaveCriticalSection(&g_bp_lock); hw_apply_all(); EnterCriticalSection(&g_bp_lock); }
    if (bp->type == BP_MEM && bp->enabled) {
        DWORD op;
        VirtualProtect((PVOID)bp->addr, bp->size, (DWORD)bp->orig_prot, &op);
    }
    bp_free(bp);
    LeaveCriticalSection(&g_bp_lock);
}

// ---- 事件 ----
static void evt_paused(void) {
    if (!g_evt_hook) return;
    jsb b; jsb_init(&b);
    jsb_put(&b, "{\"event\":\"paused\",\"tid\":"); jsb_printf(&b, "%lu", g_paused_tid);
    jsb_put(&b, ",\"reason\":"); jsb_esc(&b, g_pause_reason);
    jsb_put(&b, ",\"rip\":"); jsb_printf(&b, "%llu", g_pctx ? (unsigned long long)g_pctx->Rip : 0ULL);
    jsb_put(&b, "}");
    evt_send(b.p);
    free(b.p);
}
static void evt_resumed(void) {
    evt_send("{\"event\":\"resumed\"}");
}

// ---- 暂停（在 VEH 中被调试线程上执行，阻塞至 UI/AI 下指令） ----
static int tid_is_parasite(DWORD tid) { return tid != 0 && tid == g_par_tid; }
// 返回被下达的命令码
static int pause_here(PEXCEPTION_POINTERS ep, DWORD tid, const char* reason) {
    g_pctx = ep->ContextRecord;
    g_paused_tid = tid;
    strncpy_s(g_pause_reason, reason, _TRUNCATE);
    InterlockedExchange(&g_state, DS_PAUSE);
    InterlockedExchange(&g_cmd, CMD_NONE);
    evt_paused();
    dbg_logf("[*] 暂停: %s (tid=%lx rip=%llx)", reason, tid,
        (unsigned long long)ep->ContextRecord->Rip);
    WaitForSingleObject(g_go, INFINITE);
    ResetEvent(g_go);
    int cmd = (int)InterlockedExchange(&g_cmd, CMD_NONE);
    InterlockedExchange(&g_state, DS_RUN);
    // 恢复时必须**清空 reason**，否则 get_state 会自相矛盾。
    //
    // 不清的后果是实测到的：断点还没命中时查询，得到
    //     {"state":"running", "reason":"断点 #2 @ 0x7ffdd9da1444"}
    // ——两个字段互相打架，而调用方无法判断哪个是真的。
    // smoke_test.py 因此以约 17% 的概率失败（10 次里 1~2 次），
    // 而失败信息表现为"断点命中暂停"这一项不通过，
    // 看起来像断点没命中，实际是**上一次**的原因字符串还挂在那里。
    //
    // 判据：暂停期间 reason 有意义；一旦 g_state 不再是 DS_PAUSE，
    // reason 必须为空串。这样两个字段永远不冲突。
    g_pause_reason[0] = '\0';
    g_pctx = NULL;
    evt_resumed();
    return cmd;
}

// 断点命中后按命令恢复（在被调试线程的 VEH 内执行）
static void resume_after_bp(bp_t* bp, PEXCEPTION_POINTERS ep, int cmd) {
    CONTEXT* c = ep->ContextRecord;
    int need_step = 0;
    int do_rearm = 1;
    if (bp && bp->once) {
        // 一次性：不写回 CC，直接继续
        do_rearm = 0;
        EnterCriticalSection(&g_bp_lock);
        bp_free(bp);
        LeaveCriticalSection(&g_bp_lock);
    }
    if (do_rearm) {
        if (bp) {
            bp_sw_disable(bp);          // 恢复原字节
            g_rearm_addr = bp->addr;
            InterlockedExchange(&g_rearm, 1);
        }
        else do_rearm = 0;              // 暂停期间被删除
        need_step = do_rearm;
    }
    switch (cmd) {
    case CMD_STEP_IN:
        InterlockedExchange(&g_step_pause, 1);
        c->EFlags |= 0x100;         // TF
        break;
    case CMD_STEP_OVER: {
        dinst di;
        ULONG_PTR rip = (ULONG_PTR)c->Rip;
        bp_t* tb = NULL;
        if (dis_one(rip, &di) && di.is_call && di.size >= 5 &&
            di.bytes[0] == 0xE8) {   // 相对 call：下一条指令临时断点
            EnterCriticalSection(&g_bp_lock);
            tb = bp_alloc();
            if (tb) {
                tb->type = BP_SW; tb->addr = rip + di.size; tb->once = 1; tb->enabled = 1;
                bp_sw_enable(tb);
            }
            LeaveCriticalSection(&g_bp_lock);
            if (tb) { c->EFlags &= ~0x100UL; break; }
        }
        // 间接 call 或失败：退化为 step into
        InterlockedExchange(&g_step_pause, 1);
        c->EFlags |= 0x100;
        break;
    }
    case CMD_STEP_OUT: {
        ULONG_PTR ra = 0;
        bp_t* tb = NULL;
        if (mem_read_safe((ULONG_PTR)c->Rsp, &ra, 8) == 8 && ra) {
            EnterCriticalSection(&g_bp_lock);
            tb = bp_alloc();
            if (tb) {
                tb->type = BP_SW; tb->addr = ra; tb->once = 1; tb->enabled = 1;
                bp_sw_enable(tb);
            }
            LeaveCriticalSection(&g_bp_lock);
            if (tb) { c->EFlags &= ~0x100UL; break; }
        }
        InterlockedExchange(&g_step_pause, 1);
        c->EFlags |= 0x100;
        break;
    }
    default:                        // CMD_GO / 跟踪中
        if (g_trace_on && tid_is_parasite(GetCurrentThreadId())) {
            c->EFlags |= 0x100;     // 跟踪：单步继续
        }
        else c->EFlags &= ~0x100UL;
        break;
    }
    (void)need_step;
}


// ---- 跟踪记录 ----
static void trace_record(CONTEXT* c) {
    trc_t* t = &g_trc[g_trc_n % TRACEMAX];
    memset(t, 0, sizeof(*t));
    t->addr = (ULONG_PTR)c->Rip;
    t->rip = c->Rip; t->rax = c->Rax; t->rcx = c->Rcx; t->rdx = c->Rdx;
    t->rbx = c->Rbx; t->rsp = c->Rsp; t->rbp = c->Rbp; t->rsi = c->Rsi;
    t->rdi = c->Rdi; t->r8 = c->R8; t->r9 = c->R9; t->r10 = c->R10;
    t->r11 = c->R11; t->r12 = c->R12; t->r13 = c->R13; t->r14 = c->R14;
    t->r15 = c->R15; t->tid = GetCurrentThreadId();
    dinst di;
    if (dis_one(t->addr, &di)) {
        t->nb = (BYTE)di.size;
        memcpy(t->bytes, di.bytes, di.size > 15 ? 15 : di.size);
        strncpy_s(t->text, di.text, _TRUNCATE);
    }
    else strncpy_s(t->text, "???", _TRUNCATE);
    g_trc_n++;
    g_trc_total++;
}

// ---- VEH ----

// 栈上取一段 qword 落进日志。**单独一个函数**，理由有两条：
//   1) __try 不能出现在"需要对象展开"的函数里（MSVC C2712），而 VEH 那个大函数里有
//      带析构的局部量，所以把 __try 挪到这里；
//   2) 栈已经溢出时，读 [rsp+..] 可能再次违例，必须有 __except 兜住，
//      否则引擎会在处理异常的路上再抛一次异常。
static void dump_stack_window(unsigned long long rsp, int n) {
    __try {
        const unsigned long long* sp = (const unsigned long long*)rsp;
        for (int i = 0; i < n; i++) {
            if ((i % 4) == 0) logf("[!]   [rsp+%03x]", i * 8);
            logf(" %016llx", sp[i]);
            if ((i % 4) == 3) logf("\n");
        }
        if (n % 4) logf("\n");
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        logf("\n[!]   读栈时又违例 —— 现场只记到那一个 qword 为止\n");
    }
}

static LONG NTAPI gua_veh(PEXCEPTION_POINTERS ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    DWORD tid = GetCurrentThreadId();
    CONTEXT* c = ep->ContextRecord;

    switch (code) {
    case EXCEPTION_BREAKPOINT: {
        // 不同 Windows 版本对 int3 的 Rip 语义不同：有的在 int3 之后（+1），
        // 有的正好指向 int3 本身（如本机）。两种都兼容：优先看 Rip 处是否为 CC。
        ULONG_PTR addr;
        {
            BYTE cb = 0;
            if (mem_read_safe(c->Rip, &cb, 1) && cb == 0xCC) addr = (ULONG_PTR)c->Rip;
            else addr = (ULONG_PTR)c->Rip - 1;
        }
        int bid = 0, once = 0, has_cond = 0, is_silent = 0;
        char cond[256] = { 0 }, logmsg[256] = { 0 };
        unsigned long long hits = 0;
        BYTE orig = 0;
        int ours;
        EnterCriticalSection(&g_bp_lock);
        {
            bp_t* bp = bp_by_addr_sw(addr);
            ours = bp && bp->enabled;
            if (ours) {
                bid = bp->id; once = bp->once; has_cond = bp->cond[0] != 0;
                is_silent = bp->silent; hits = ++bp->hits; orig = bp->orig;
                strncpy_s(cond, bp->cond, _TRUNCATE);
                strncpy_s(logmsg, bp->logmsg, _TRUNCATE);
            }
        }
        LeaveCriticalSection(&g_bp_lock);
        if (!ours) return EXCEPTION_CONTINUE_SEARCH;   // 非我方 int3，交还原异常链
        if (logmsg[0]) dbg_logf("[bp#%d] %s", bid, logmsg);
        int skip = 0;
        if (has_cond) {
            int err = 0;
            xval v = eval_expr(cond, c, hits, tid, &err);
            if (err) dbg_logf("[!] 断点 #%d 条件表达式解析失败: %s", bid, cond);
            if (err || xv_numof(v) == 0) skip = 1;
        }
        if (is_silent) skip = 1;
        if (skip) {
            // 条件不满足 / 静默：恢复原字节 + TF + 待重打
            mem_write_safe(addr, &orig, 1);
            g_rearm_addr = addr;
            InterlockedExchange(&g_rearm, 1);
            c->EFlags |= 0x100;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        if (once) {
            EnterCriticalSection(&g_bp_lock);
            bp_t* bp = bp_by_addr_sw(addr);
            if (bp) bp_free(bp);
            LeaveCriticalSection(&g_bp_lock);
            mem_write_safe(addr, &orig, 1);   // 恢复原始字节，避免继续执行 0xCC
        }
        c->Rip = (ULONG_PTR)addr;       // 撤销 int3 预取
        char reason[160];
        sprintf_s(reason, "断点 #%d @ 0x%llx", bid, (unsigned long long)addr);
        int cmd = pause_here(ep, tid, reason);
        // 重新取断点（暂停期间可能被删除/修改）
        EnterCriticalSection(&g_bp_lock);
        bp_t* bp = bp_by_id(bid);
        if (bp && !once && bp->type == BP_SW) { bp->enabled = 1; }
        else bp = NULL;
        LeaveCriticalSection(&g_bp_lock);
        resume_after_bp(bp, ep, cmd);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    case EXCEPTION_SINGLE_STEP: {
        // 硬件断点命中（DR6 低 4 位）
        if (c->Dr6 & 0xF) {
            int hid = 0, has_cond = 0;
            char cond[256] = { 0 };
            EnterCriticalSection(&g_bp_lock);
            for (int i = 0; i < MAX_BP; i++) {
                if (!g_bps[i].used || g_bps[i].type != BP_HW || !g_bps[i].enabled) continue;
                int s = g_bps[i].hwslot;
                if (s >= 0 && (c->Dr6 & (1ULL << s))) {
                    hid = g_bps[i].id;
                    has_cond = g_bps[i].cond[0] != 0;
                    strncpy_s(cond, g_bps[i].cond, _TRUNCATE);
                    g_bps[i].hits++;
                    break;
                }
            }
            LeaveCriticalSection(&g_bp_lock);
            c->Dr6 = 0;
            if (!hid) return EXCEPTION_CONTINUE_EXECUTION;  // 非我方硬件断点
            dbg_logf("[hwbp#%d] 命中", hid);
            int dopause = 1;
            if (has_cond) {
                int err = 0;
                xval v = eval_expr(cond, c, 0, tid, &err);
                if (!err && xv_numof(v) == 0) dopause = 0;
            }
            if (dopause) {
                char reason[160];
                sprintf_s(reason, "硬件断点 #%d", hid);
                int cmd2 = pause_here(ep, tid, reason);
                (void)cmd2;
                // 硬件断点天然保持启用，直接继续即可
            }
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        // 软件断点重打 / guard page 重保护
        if (InterlockedCompareExchange(&g_rearm, 0, 1)) {
            BYTE cc = 0xCC;
            mem_write_safe(g_rearm_addr, &cc, 1);
        }
        // 这一条单步是不是**我们自己**为了重装 PAGE_GUARD 而设的 TF 产生的？
        // 见下面的 guard page 分支：那里设了 `c->EFlags |= 0x100`，内核随后会送来一次单步。
        int self_step = 0;
        if (g_reguard_n) {
            EnterCriticalSection(&g_bp_lock);
            for (int i = 0; i < MAX_BP && g_reguard_n; i++) {
                if (!g_bps[i].used || g_bps[i].type != BP_MEM || !g_bps[i].enabled) continue;
                for (int r = 0; r < g_reguard_n; r++) {
                    if (g_reguard[r] >= g_bps[i].addr &&
                        g_reguard[r] < g_bps[i].addr + (ULONG_PTR)g_bps[i].size) {
                        DWORD op;
                        VirtualProtect((PVOID)g_bps[i].addr, g_bps[i].size,
                            ((DWORD)g_bps[i].orig_prot) | PAGE_GUARD, &op);
                    }
                }
            }
            g_reguard_n = 0;
            self_step = 1;   // 队列非空 ⇒ 这一次单步是我们自己排的
            LeaveCriticalSection(&g_bp_lock);
        }
        // 跟踪（仅寄生线程）
        if (g_trace_on && tid_is_parasite(tid)) {
            trace_record(c);
            int stop = 0;
            if (g_trace_max && g_trc_total >= g_trace_max) stop = 1;
            if (g_trace_cond[0]) {
                int err = 0;
                xval v = eval_expr(g_trace_cond, c, g_trc_total, tid, &err);
                if (!err && xv_numof(v) != 0) stop = 1;
            }
            if (g_trace_stopflag) { g_trace_stopflag = 0; stop = 1; }
            if (stop) {
                g_trace_on = 0;
                pause_here(ep, tid, "跟踪停止");
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            // trace over：call 用临时断点跨过
            dinst di;
            if (g_trace_mode == 1 && dis_one((ULONG_PTR)c->Rip, &di) && di.is_call && di.size >= 5 && di.bytes[0] == 0xE8) {
                EnterCriticalSection(&g_bp_lock);
                bp_t* tb = bp_alloc();
                if (tb) {
                    tb->type = BP_SW; tb->addr = (ULONG_PTR)c->Rip + di.size;
                    tb->once = 1; tb->silent = 1; tb->enabled = 1;
                    bp_sw_enable(tb);
                }
                LeaveCriticalSection(&g_bp_lock);
                c->EFlags &= ~0x100UL;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            c->EFlags |= 0x100;   // 继续单步
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        if (InterlockedCompareExchange(&g_step_pause, 0, 1)) {
            int cmd = pause_here(ep, tid, "单步");
            switch (cmd) {
            case CMD_STEP_IN:
                InterlockedExchange(&g_step_pause, 1);
                c->EFlags |= 0x100;
                break;
            case CMD_STEP_OVER: {
                dinst di;
                ULONG_PTR rip = (ULONG_PTR)c->Rip;
                if (dis_one(rip, &di) && di.is_call && di.size >= 5 && di.bytes[0] == 0xE8) {
                    EnterCriticalSection(&g_bp_lock);
                    bp_t* tb = bp_alloc();
                    if (tb) {
                        tb->type = BP_SW; tb->addr = rip + di.size;
                        tb->once = 1; tb->enabled = 1;
                        bp_sw_enable(tb);
                    }
                    LeaveCriticalSection(&g_bp_lock);
                    if (tb) { c->EFlags &= ~0x100UL; break; }
                }
                InterlockedExchange(&g_step_pause, 1);
                c->EFlags |= 0x100;
                break;
            }
            default:
                c->EFlags &= ~0x100UL;
                break;
            }
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        // 单步同时满足 trace over 临时断点（silent 已处理）。
        //
        // 而**我们自己排的那一次单步必须被消费掉**（CONTINUE_EXECUTION）：它是 guard page
        // 分支设 TF 产生的，唯一用途是让内核把控制权交回来以便重装保护页。若在这里透传，
        // 它就成了"无人处理的单步"，内核直接终止进程 —— 退出码正是 0x80000004
        // （STATUS_SINGLE_STEP）。第 137 轮实测：保护页 + 硬件断点跑到 16 秒时进程消失，
        // eng.poll() = 2147483652 = 0x80000004，而引擎日志在死前完全静默（logf 每行都
        // fflush，所以那不是缓冲丢失，是真的什么都没做就成了这样）。
        if (self_step) return EXCEPTION_CONTINUE_EXECUTION;
        return EXCEPTION_CONTINUE_SEARCH;
    }
    case EXCEPTION_GUARD_PAGE: {
        ULONG_PTR fa = (ULONG_PTR)ep->ExceptionRecord->ExceptionInformation[1];
        bp_t* hit = NULL;
        EnterCriticalSection(&g_bp_lock);
        for (int i = 0; i < MAX_BP; i++) {
            if (!g_bps[i].used || g_bps[i].type != BP_MEM || !g_bps[i].enabled) continue;
            if (fa >= g_bps[i].addr && fa < g_bps[i].addr + (ULONG_PTR)g_bps[i].size) {
                hit = &g_bps[i];
                break;
            }
        }
        LeaveCriticalSection(&g_bp_lock);
        if (!hit) return EXCEPTION_CONTINUE_SEARCH;
        hit->hits++;
        dbg_logf("[membp#%d] 访问 0x%llx", hit->id, (unsigned long long)fa);
        int pause = 1;
        if (hit->cond[0]) {
            int err = 0;
            xval v = eval_expr(hit->cond, c, hit->hits, tid, &err);
            if (!err && xv_numof(v) == 0) pause = 0;
        }
        // 排队重保护（本指令执行完后由 single-step 路径恢复 GUARD）
        if (g_reguard_n < 64) g_reguard[g_reguard_n++] = fa;
        c->EFlags |= 0x100;
        if (pause) {
            char reason[160];
            sprintf_s(reason, "内存断点 #%d @ 0x%llx", hit->id, (unsigned long long)fa);
            int cmd2 = pause_here(ep, tid, reason);
            (void)cmd2;
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    case 0xE06D7363:   // C++ 异常：不拦截
        return EXCEPTION_CONTINUE_SEARCH;
    case EXCEPTION_STACK_OVERFLOW: {
        // 栈溢出**不能**走下面那条"暂停然后放行"的路。理由不是推理，是实测：
        // 放行之后 OS 因无人处理而终止进程 —— 而引擎与被调试者**在同一个进程里**
        // （寄生架构的固有代价），于是引擎跟着一起死。第 131 轮观测到的结局正是
        // "探针那一头只拿到 engine closed pipe"，之后再也问不出任何东西。
        //
        // 所以这里先把**现场**落进日志（探针会把引擎 stdout 收进 probe_*_engine.log），
        // 这样即使进程随后仍然死掉，至少留下一份可读的记录。本轮只求这一件事。
        //
        // 另注：第 131 轮那次 info2 = 0xde4ac03000 落在**堆区**而不是线程栈，
        // 与前面观测到的栈枢轴（xchg [rsp],r9 / pop rsp）一致。那条线索记在文档里，
        // 这里不据它下任何结论。
        logf("[!] ==== 栈溢出 现场 ====\n");
        logf("[!] code=%08X addr=%llx 是否保护页=%llu 触到的地址=%llx\n",
             code,
             (unsigned long long)ep->ExceptionRecord->ExceptionAddress,
             (unsigned long long)ep->ExceptionRecord->ExceptionInformation[0],
             (unsigned long long)ep->ExceptionRecord->ExceptionInformation[1]);
        logf("[!] rip=%016llx rsp=%016llx rbp=%016llx\n",
             (unsigned long long)c->Rip, (unsigned long long)c->Rsp,
             (unsigned long long)c->Rbp);
        logf("[!] rax=%016llx rbx=%016llx rcx=%016llx rdx=%016llx\n",
             (unsigned long long)c->Rax, (unsigned long long)c->Rbx,
             (unsigned long long)c->Rcx, (unsigned long long)c->Rdx);
        logf("[!] rsi=%016llx rdi=%016llx r8 =%016llx r9 =%016llx\n",
             (unsigned long long)c->Rsi, (unsigned long long)c->Rdi,
             (unsigned long long)c->R8, (unsigned long long)c->R9);
        logf("[!] r10=%016llx r11=%016llx r12=%016llx r13=%016llx\n",
             (unsigned long long)c->R10, (unsigned long long)c->R11,
             (unsigned long long)c->R12, (unsigned long long)c->R13);
        logf("[!] r14=%016llx r15=%016llx\n",
             (unsigned long long)c->R14, (unsigned long long)c->R15);
        logf("[!] 栈窗口 32 个 qword：\n");
        dump_stack_window((unsigned long long)c->Rsp, 32);
        logf("[!] ==== 现场结束 ====\n");
        // 仍然让探针看到这次命中（与规格里的"首过暂停"一致），然后放行。
        {
            char sreason[192];
            sprintf_s(sreason, "栈溢出 @ 0x%llx",
                      (unsigned long long)ep->ExceptionRecord->ExceptionAddress);
            pause_here(ep, tid, sreason);
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }
    case EXCEPTION_ACCESS_VIOLATION:
    case EXCEPTION_ILLEGAL_INSTRUCTION:
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
    case EXCEPTION_PRIV_INSTRUCTION:
    default: {
        if (code == DBG_PRINTEXCEPTION_C || code == DBG_PRINTEXCEPTION_WIDE_C)
            return EXCEPTION_CONTINUE_SEARCH;
        // 系统在**派发/展开异常**时的记账码，不是被调试者自己的故障：
        //   0xC0000026 STATUS_INVALID_DISPOSITION · 0xC0000027 STATUS_UNWIND
        //   0xC0000028 STATUS_BAD_STACK · 0xC0000029 STATUS_INVALID_UNWIND_TARGET
        //
        // 为什么放行而不暂停（这是**实测**出来的，不是推理）：第 131 轮有一个实验只挂了一页
        // 保护页去抓改写者，而它拿到的 3 次命中里，第 1 次是真正想看的那次保护页命中，
        // 第 2、3 次**全是同一个 ntdll 地址上反复出现的 0xC0000026**——
        // 也就是说这类暂停把实验的剩余次数整个吃掉了。
        // 而"反复出现在同一个系统地址"本身就说明它不是目标自己的故障：目标随后照常运行。
        if (code == 0xC0000026u || code == 0xC0000027u ||
            code == 0xC0000028u || code == 0xC0000029u) {
            logf("[i] VEH 放行系统记账异常 code=0x%08X addr=%llx（不暂停）\n", code,
                (unsigned long long)ep->ExceptionRecord->ExceptionAddress);
            return EXCEPTION_CONTINUE_SEARCH;
        }
        logf("[!] VEH 捕获异常 code=0x%08X addr=%llx rip=%llx info1=%llx info2=%llx\n", code,
            (unsigned long long)ep->ExceptionRecord->ExceptionAddress,
            (unsigned long long)ep->ContextRecord->Rip,
            (unsigned long long)ep->ExceptionRecord->ExceptionInformation[0],
            (unsigned long long)ep->ExceptionRecord->ExceptionInformation[1]);
        char reason[192];
        sprintf_s(reason, "异常 0x%08X @ 0x%llx", code,
            (unsigned long long)ep->ExceptionRecord->ExceptionAddress);
        // 广播异常事件
        if (g_evt_hook) {
            jsb b; jsb_init(&b);
            jsb_put(&b, "{\"event\":\"exception\",\"code\":"); jsb_printf(&b, "%lu", code);
            jsb_put(&b, ",\"address\":"); jsb_printf(&b, "%llu",
                (unsigned long long)ep->ExceptionRecord->ExceptionAddress);
            jsb_put(&b, "}");
            evt_send(b.p);
            free(b.p);
        }
        int cmd2 = pause_here(ep, tid, reason);
        (void)cmd2;
        // 致命异常在恢复之后必须**继续传播**，不能 CONTINUE_EXECUTION。
        //
        // CONTINUE_EXECUTION 的语义是"重试引起异常的那条指令"。对一次未修复的访问违例，
        // 重试必然立刻再违例，于是 VEH 陷入 暂停→恢复→再违例 的循环。这是实测的：日志里
        // info2 每次运行都不同（0xffffffffffffffff、0x38、0x240785a4f），正是一次次全新故障的痕迹。
        //
        // 而暂停本身在这里也是有害的：寄生线程在 VEH 里等待 g_go，而管道线程没能把命令送到，
        // 于是引擎活着、CPU 为 0、却不再回答任何查询——这正是实测到的状态。
        //
        // 所以对未处理的致命异常：记录位置、广播事件、然后**直接放行**。停下也检查不出更多
        // 东西——位置已经写进日志了——而停下会让整台引擎不可用，那才是真正的代价。
        return EXCEPTION_CONTINUE_SEARCH;
    }
    }
}


// ======================================================================
// 命令层
// ======================================================================
static CONTEXT* cur_ctx(void) {
    if (g_pctx) return g_pctx;
    for (int i = 0; i < g_sus_n; i++)
        if (g_sus_tid[i] == g_paused_tid) return &g_sus_ctx[i];
    return g_sus_n ? &g_sus_ctx[0] : NULL;
}

static int xreg_set(CONTEXT* c, const char* name, unsigned long long v, int* ok) {
    int dummy;
    if (!ok) ok = &dummy;
    *ok = 1;
#define W(n, f) if (_stricmp(name, n) == 0) { c->f = v; return 1; }
    W("rax", Rax) W("rcx", Rcx) W("rdx", Rdx) W("rbx", Rbx)
    W("rsp", Rsp) W("rbp", Rbp) W("rsi", Rsi) W("rdi", Rdi)
    W("r8", R8) W("r9", R9) W("r10", R10) W("r11", R11)
    W("r12", R12) W("r13", R13) W("r14", R14) W("r15", R15)
    W("rip", Rip)
#undef W
    if (_stricmp(name, "eflags") == 0 || _stricmp(name, "rflags") == 0) { c->EFlags = (DWORD)v; return 1; }
    *ok = 0;
    return 0;
}

static void ctx_to_json(jsb* b, CONTEXT* c) {
    jsb_put(b, "{");
    jsb_printf(b, "\"rax\":\"%llx\",\"rcx\":\"%llx\",\"rdx\":\"%llx\",\"rbx\":\"%llx\",",
        c->Rax, c->Rcx, c->Rdx, c->Rbx);
    jsb_printf(b, "\"rsp\":\"%llx\",\"rbp\":\"%llx\",\"rsi\":\"%llx\",\"rdi\":\"%llx\",",
        c->Rsp, c->Rbp, c->Rsi, c->Rdi);
    jsb_printf(b, "\"r8\":\"%llx\",\"r9\":\"%llx\",\"r10\":\"%llx\",\"r11\":\"%llx\",",
        c->R8, c->R9, c->R10, c->R11);
    jsb_printf(b, "\"r12\":\"%llx\",\"r13\":\"%llx\",\"r14\":\"%llx\",\"r15\":\"%llx\",",
        c->R12, c->R13, c->R14, c->R15);
    jsb_printf(b, "\"rip\":\"%llx\",\"eflags\":\"%llx\",",
        c->Rip, (unsigned long long)c->EFlags);
    jsb_printf(b, "\"cf\":%d,\"pf\":%d,\"af\":%d,\"zf\":%d,\"sf\":%d,\"tf\":%d,\"if\":%d,\"df\":%d,\"of\":%d",
        (c->EFlags & 1) ? 1 : 0, (c->EFlags & 4) ? 1 : 0, (c->EFlags & 0x10) ? 1 : 0,
        (c->EFlags & 0x40) ? 1 : 0, (c->EFlags & 0x80) ? 1 : 0, (c->EFlags & 0x100) ? 1 : 0,
        (c->EFlags & 0x200) ? 1 : 0, (c->EFlags & 0x400) ? 1 : 0, (c->EFlags & 0x800) ? 1 : 0);
    jsb_put(b, "}");
}

static int need_pause(jval* result) {
    if (g_state != DS_PAUSE) {
        jv_put(result, "error", jv_str("目标正在运行，请先 pause 或在断点处停下"));
        return 0;
    }
    return 1;
}

// 恢复统一入口
static jval* cmd_resume_with(int cmd, jval* result) {
    if (g_state != DS_PAUSE) { jv_put(result, "error", jv_str("目标未暂停")); return result; }
    if (g_pctx) {
        InterlockedExchange(&g_cmd, cmd);
        SetEvent(g_go);
    }
    else {
        // 手动暂停：应用上下文并恢复全部线程；单步类退化为直接继续
        resume_all();
        InterlockedExchange(&g_state, DS_RUN);
        evt_resumed();
    }
    jv_put(result, "ok", jv_bool(1));
    return result;
}

static jval* cmd_dispatch(const char* cmd, jval* args, jval* result) {
    unsigned long long u;

    if (!strcmp(cmd, "ping")) {
        jv_put(result, "pong", jv_str("guadbg"));
    }
    else if (!strcmp(cmd, "get_state")) {
        jv_put(result, "state", jv_str(g_state == DS_PAUSE ? "paused" : "running"));
        jv_put(result, "paused_tid", jv_num((double)g_paused_tid));
        jv_put(result, "reason", jv_str(g_pause_reason));
        CONTEXT* c = cur_ctx();
        if (c) jv_put(result, "rip", jv_num((double)c->Rip));
    }
    else if (!strcmp(cmd, "pause")) {
        if (g_state == DS_PAUSE) { jv_put(result, "ok", jv_bool(1)); jv_put(result, "note", jv_str("已暂停")); return result; }
        int n = suspend_all();
        if (!n) { jv_put(result, "error", jv_str("无可挂起线程")); return result; }
        int cur = 0;
        for (int i = 0; i < g_sus_n; i++) if (g_sus_tid[i] == g_par_tid) cur = i;
        g_paused_tid = g_sus_tid[cur];
        g_pctx = NULL;
        strncpy_s(g_pause_reason, "手动暂停", _TRUNCATE);
        InterlockedExchange(&g_state, DS_PAUSE);
        InterlockedExchange(&g_cmd, CMD_NONE);
        evt_paused();
        dbg_logf("[*] 手动暂停（挂起 %d 线程，当前 tid=%lx）", n, g_paused_tid);
        jv_put(result, "ok", jv_bool(1));
        jv_put(result, "threads", jv_num((double)n));
    }
    else if (!strcmp(cmd, "resume")) {
        return cmd_resume_with(CMD_GO, result);
    }
    else if (!strcmp(cmd, "step_into")) {
        return cmd_resume_with(CMD_STEP_IN, result);
    }
    else if (!strcmp(cmd, "step_over")) {
        return cmd_resume_with(CMD_STEP_OVER, result);
    }
    else if (!strcmp(cmd, "step_out")) {
        return cmd_resume_with(CMD_STEP_OUT, result);
    }
    else if (!strcmp(cmd, "run_to")) {
        u = jv_numval(args, "addr", 0);
        if (!u) { jv_put(result, "error", jv_str("缺少 addr")); return result; }
        if (g_state != DS_PAUSE) { jv_put(result, "error", jv_str("目标未暂停")); return result; }
        EnterCriticalSection(&g_bp_lock);
        bp_t* tb = bp_alloc();
        int okid = 0;
        if (tb) {
            tb->type = BP_SW; tb->addr = (ULONG_PTR)u; tb->once = 1; tb->enabled = 1;
            okid = bp_sw_enable(tb) ? tb->id : 0;
            if (!okid) bp_free(tb);
        }
        LeaveCriticalSection(&g_bp_lock);
        if (!okid) { jv_put(result, "error", jv_str("临时断点创建失败")); return result; }
        jv_put(result, "temp_bp", jv_num((double)okid));
        return cmd_resume_with(CMD_GO, result);
    }
    else if (!strcmp(cmd, "set_rip")) {
        if (!need_pause(result)) return result;
        CONTEXT* c = cur_ctx();
        if (!c) { jv_put(result, "error", jv_str("无上下文")); return result; }
        u = jv_numval(args, "addr", 0);
        if (!u) { jv_put(result, "error", jv_str("缺少 addr")); return result; }
        c->Rip = (ULONG_PTR)u;
        jv_put(result, "ok", jv_bool(1));
    }
    else if (!strcmp(cmd, "get_regs")) {
        if (!need_pause(result)) return result;
        CONTEXT* c = cur_ctx();
        if (!c) { jv_put(result, "error", jv_str("无上下文")); return result; }
        jsb b; jsb_init(&b);
        ctx_to_json(&b, c);
        jv_put(result, "regs", json_parse(b.p));
        jv_put(result, "tid", jv_num((double)g_paused_tid));
        free(b.p);
    }
    else if (!strcmp(cmd, "set_reg")) {
        if (!need_pause(result)) return result;
        CONTEXT* c = cur_ctx();
        if (!c) { jv_put(result, "error", jv_str("无上下文")); return result; }
        const char* name = jv_strval(args, "name", "");
        u = jv_numval(args, "value", 0);
        int ok = 0;
        xreg_set(c, name, u, &ok);
        if (!ok) { jv_put(result, "error", jv_str("未知寄存器")); return result; }
        jv_put(result, "ok", jv_bool(1));
    }
    else if (!strcmp(cmd, "read_mem")) {
        u = jv_numval(args, "addr", 0);
        unsigned long long len = jv_numval(args, "len", 128);
        if (len > 65536) len = 65536;
        if (!u && !jv_get(args, "addr")) { jv_put(result, "error", jv_str("缺少 addr")); return result; }
        BYTE* buf = (BYTE*)malloc((size_t)len + 1);
        SIZE_T got = mem_read_safe((ULONG_PTR)u, buf, (SIZE_T)len);
        char* hex = (char*)malloc(got * 2 + 1);
        bin2hex(buf, got, hex);
        jv_put(result, "addr", jv_num((double)u));
        jv_put(result, "len", jv_num((double)got));
        jv_put(result, "hex", jv_str(hex));
        free(hex); free(buf);
    }
    else if (!strcmp(cmd, "write_mem")) {
        u = jv_numval(args, "addr", 0);
        const char* hex = jv_strval(args, "hex", "");
        BYTE buf[65536];
        size_t n = hex2bin(hex, buf, sizeof(buf));
        if (!u || !n) { jv_put(result, "error", jv_str("参数无效")); return result; }
        safe_mem_write((ULONG_PTR)u, buf, n);
        jv_put(result, "ok", jv_bool(1));
        jv_put(result, "written", jv_num((double)n));
    }
    else if (!strcmp(cmd, "fill_mem")) {
        u = jv_numval(args, "addr", 0);
        unsigned long long len = jv_numval(args, "len", 0);
        unsigned long long val = jv_numval(args, "val", 0) & 0xFF;
        if (!u || !len || len > 65536) { jv_put(result, "error", jv_str("参数无效")); return result; }
        BYTE* buf = (BYTE*)malloc((size_t)len);
        memset(buf, (int)val, (size_t)len);
        safe_mem_write((ULONG_PTR)u, buf, (SIZE_T)len);
        free(buf);
        jv_put(result, "ok", jv_bool(1));
    }
    else if (!strcmp(cmd, "search_bytes")) {
        const char* pat = jv_strval(args, "pattern", "");
        unsigned long long start = jv_numval(args, "start", 0);
        unsigned long long end = jv_numval(args, "end", 0x00007FFF00000000ULL);
        BYTE pb[64]; int wild[64];
        int pn = 0;
        const char* q = pat;
        while (*q && pn < 64) {
            while (*q == ' ' || *q == ',') q++;
            if (!*q) break;
            if (q[0] == '?' ) { wild[pn] = 1; pb[pn] = 0; pn++; q += 2; continue; }
            int h = hexval(q[0]), l = (q[1] && q[1] != ' ' && q[1] != ',') ? hexval(q[1]) : -1;
            if (h < 0) { q++; continue; }
            if (l < 0) break;
            wild[pn] = 0; pb[pn] = (BYTE)((h << 4) | l); pn++;
            q += 2;
        }
        if (!pn) { jv_put(result, "error", jv_str("模式为空")); return result; }
        jval* hits = jv_new(4);
        unsigned long long total = 0;
        ULONG_PTR a = (ULONG_PTR)start;
        MEMORY_BASIC_INFORMATION mbi;
        while (a < (ULONG_PTR)end) {
            if (!VirtualQuery((PVOID)a, &mbi, sizeof(mbi))) break;
            if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS && mbi.Protect != PAGE_GUARD &&
                (mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY |
                    PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY)) != 0) {
                SIZE_T rlen = mbi.RegionSize > 64 * 1024 * 1024 ? 64 * 1024 * 1024 : mbi.RegionSize;
                BYTE* buf = (BYTE*)malloc(rlen);
                SIZE_T got = mem_read_safe((ULONG_PTR)mbi.BaseAddress, buf, rlen);
                for (SIZE_T i = 0; i + pn <= got; i++) {
                    int m = 1;
                    for (int k = 0; k < pn; k++) if (!wild[k] && buf[i + k] != pb[k]) { m = 0; break; }
                    if (m) {
                        jv_add(hits, jv_num((double)((ULONG_PTR)mbi.BaseAddress + i)));
                        if (hits->n >= 512) break;
                    }
                }
                free(buf);
                total += rlen;
                if (total > 1024ULL * 1024 * 1024) break;
                if (hits->n >= 512) break;
            }
            if (!mbi.RegionSize) break;
            a = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        }
        jv_put(result, "hits", hits);
    }
    else if (!strcmp(cmd, "search_str")) {
        // 参数名原来只认 "s"，而 search_bytes 认 "pattern" —— 两个同类命令用不同的键，
        // 而报错写的是内部变量名 "s 为空"，从调用侧看像"我明明给了串"。
        // 后果不是难用，而是**危险的**：调用者会把它读成"内存里没有这个串"，
        // 于是一个参数名不匹配变成了一条关于目标的否定结论。
        // （本项目在 Sky.exe 上正是这样得到过一次"0 命中"。）
        //
        // 现在两个键都收：s 保持兼容，pattern 与 search_bytes 对齐。
        const char* s = jv_strval(args, "s", "");
        if (!s || !*s) s = jv_strval(args, "pattern", "");
        int uni = jv_get(args, "unicode") ? (jv_get(args, "unicode")->boolean) : 0;
        unsigned long long start = jv_numval(args, "start", 0);
        unsigned long long end = jv_numval(args, "end", 0x00007FFF00000000ULL);
        BYTE pat[512]; size_t pn;
        if (uni) {
            pn = 0;
            for (const char* p = s; *p && pn < sizeof(pat) - 2; p++) { pat[pn++] = (BYTE)*p; pat[pn++] = 0; }
        }
        else { strncpy_s((char*)pat, sizeof(pat), s, _TRUNCATE); pn = strlen(s); }
        // 报错要说出**调用者该给什么**，而不是内部变量叫什么。
        if (!pn) { jv_put(result, "error", jv_str("缺少参数：请给 \"s\"（或 \"pattern\"）")); return result; }
        //
        // 这一段原来每个区域 malloc 最多 64 MB，而且**不检查 malloc 的返回值**。
        // 在空闲内存只有几百 MB 的机器上，第一次失败就写空指针 —— 实测表现为
        // "engine closed pipe"：引擎整个崩掉，而调用者只看到连接断开。
        //
        // 更要紧的是**结果的可信度**：原来无论扫了多少内存，返回的都只是 hits。
        // 于是"0 命中"无法区分下面两件事：
        //     a) 目标内存里真的没有这个串
        //     b) 一个区域都没扫成（分配失败、读失败、范围给错）
        // 本项目已经因为这种不可审计的否定吃过亏（Sky.exe 上一次"0 命中"，
        // 实际是参数名不匹配导致的错误返回）。所以现在把覆盖量一起报出来：
        //     regions_scanned / regions_skipped / bytes_scanned / truncated
        // 有了它们，"0 命中"才是一个可以判断的结论。
        const SIZE_T WINDOW = 1u << 20;      // 1 MB：小到不会分配失败
        jval* hits = jv_new(4);
        ULONG_PTR a = (ULONG_PTR)start;
        MEMORY_BASIC_INFORMATION mbi;
        unsigned long long nreg = 0, nskip = 0, nbytes = 0, ntrunc = 0;
        while (a < (ULONG_PTR)end) {
            if (!VirtualQuery((PVOID)a, &mbi, sizeof(mbi))) break;
            ULONG_PTR rbase = (ULONG_PTR)mbi.BaseAddress;
            SIZE_T rsize = mbi.RegionSize;
            if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS && mbi.Protect != PAGE_GUARD) {
                BYTE* buf = (BYTE*)malloc(WINDOW + 1);
                if (!buf) { nskip++; }
                else {
                    nreg++;
                    SIZE_T done = 0;
                    while (done < rsize && hits->n < 512) {
                        SIZE_T want = rsize - done;
                        if (want > WINDOW) { want = WINDOW; ntrunc++; }
                        SIZE_T got = mem_read_safe(rbase + done, buf, want);
                        if (got) {
                            nbytes += got;
                            for (SIZE_T i = 0; i + pn <= got; i++) {
                                if (memcmp(buf + i, pat, pn) == 0) {
                                    jv_add(hits, jv_num((double)(rbase + done + i)));
                                    if (hits->n >= 512) break;
                                }
                            }
                        }
                        else { nskip++; }
                        done += want;
                    }
                    free(buf);
                }
            }
            if (hits->n >= 512) break;
            if (!rsize) break;
            a = rbase + rsize;
        }
        jv_put(result, "hits", hits);
        jv_put(result, "regions_scanned", jv_num((double)nreg));
        jv_put(result, "regions_skipped", jv_num((double)nskip));
        jv_put(result, "bytes_scanned", jv_num((double)nbytes));
        jv_put(result, "windows_scanned", jv_num((double)ntrunc));
    }

    else if (!strcmp(cmd, "mem_map")) {
        jval* arr = jv_new(4);
        ULONG_PTR a = 0;
        MEMORY_BASIC_INFORMATION mbi;
        while (VirtualQuery((PVOID)a, &mbi, sizeof(mbi))) {
            jval* e = jv_new(5);
            jv_put(e, "base", jv_num((double)(ULONG_PTR)mbi.BaseAddress));
            jv_put(e, "size", jv_num((double)mbi.RegionSize));
            jv_put(e, "state", jv_num((double)mbi.State));
            jv_put(e, "protect", jv_num((double)mbi.Protect));
            jv_put(e, "type", jv_num((double)mbi.Type));
            if (mbi.State == MEM_COMMIT) {
                WCHAR fn[MAX_PATH];
                if (GetMappedFileNameW(GetCurrentProcess(), mbi.BaseAddress, fn, MAX_PATH)) {
                    char fa[MAX_PATH];
                    WideCharToMultiByte(CP_ACP, 0, fn, -1, fa, sizeof(fa) - 1, NULL, NULL);
                    jv_put(e, "file", jv_str(fa));
                }
            }
            jv_add(arr, e);
            if (!mbi.RegionSize) break;
            a = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        }
        jv_put(result, "regions", arr);
    }
    else if (!strcmp(cmd, "disasm")) {
        u = jv_numval(args, "addr", 0);
        unsigned long long count = jv_numval(args, "count", 32);
        if (!u && !jv_get(args, "addr")) { jv_put(result, "error", jv_str("缺少 addr")); return result; }
        if (count > 256) count = 256;
        jval* arr = jv_new(4);
        ULONG_PTR a = (ULONG_PTR)u;
        for (unsigned long long i = 0; i < count; i++) {
            dinst di;
            if (!dis_one(a, &di)) break;
            jval* e = jv_new(5);
            jv_put(e, "addr", jv_num((double)a));
            jv_put(e, "size", jv_num((double)di.size));
            char hex[32]; bin2hex(di.bytes, di.size, hex);
            jv_put(e, "bytes", jv_str(hex));
            jv_put(e, "text", jv_str(di.text));
            if (di.target) jv_put(e, "target", jv_num((double)di.target));
            jv_put(e, "call", jv_bool(di.is_call));
            jv_put(e, "jump", jv_bool(di.is_jump));
            jv_put(e, "bp_here", jv_bool(bp_by_addr_sw(a) != NULL));
            const char* cm = mark_find(g_comments, g_ncomments, a);
            if (cm) jv_put(e, "comment", jv_str(cm));
            const char* lb = mark_find(g_labels, g_nlabels, a);
            if (lb) jv_put(e, "label", jv_str(lb));
            jv_add(arr, e);
            a += di.size;
        }
        jv_put(result, "lines", arr);
    }
    else if (!strcmp(cmd, "windows")) {
        // 列出本进程的顶层窗口。
        //
        // 为什么这个命令值得单独加：实测 Sky.exe 在引擎里"跑起来了"却停住——
        // 55 个模块里 40 个是它自己加载的（媒体、存储、网络、UI 栈都初始化了），
        // 但 vulkan-1.dll 从未加载，CPU 只有 0.1 秒，入口点线程停在 win32u.dll 的
        // 窗口内部函数上。那个组合的特征是**一个模态对话框的消息泵在等**，
        // 而对话框的标题和文本会直接说出真正的原因。
        //
        // 引擎与目标在**同一个进程**里（寄生线程架构），所以 EnumWindows 直接就能看到，
        // 不需要跨进程读取，也就**不碰目标一个字节**——vulkan-1.dll 的完整性校验不受影响。
        struct WinRow { HWND hwnd; DWORD tid; };
        static WinRow g_win_rows[256];
        static int g_win_n;
        g_win_n = 0;
        EnumWindows([](HWND hwnd, LPARAM) -> BOOL {
            DWORD pid = 0;
            GetWindowThreadProcessId(hwnd, &pid);
            if (pid != GetCurrentProcessId()) return TRUE;      // 只看本进程的
            if (g_win_n < 256) {
                g_win_rows[g_win_n].hwnd = hwnd;
                g_win_rows[g_win_n].tid = GetWindowThreadProcessId(hwnd, NULL);
                ++g_win_n;
            }
            return TRUE;
        }, 0);

        jval* arr = jv_new(4);
        for (int i = 0; i < g_win_n; i++) {
            HWND hwnd = g_win_rows[i].hwnd;
            jval* e = jv_new(5);   // 5 = 对象（0 null / 1 bool / 2 num / 3 str / 4 arr / 5 obj）
            jv_put(e, "hwnd", jv_num((double)(ULONG_PTR)hwnd));
            jv_put(e, "tid", jv_num((double)g_win_rows[i].tid));
            char cls[256] = {0}, txt[512] = {0};
            GetClassNameA(hwnd, cls, sizeof(cls));
            WCHAR wtxt[512] = {0};
            int wlen = GetWindowTextW(hwnd, wtxt, 511);
            if (wlen > 0) WideCharToMultiByte(CP_UTF8, 0, wtxt, -1, txt, sizeof(txt), NULL, NULL);
            jv_put(e, "class", jv_str(cls));
            jv_put(e, "title", jv_str(txt));
            jv_put(e, "visible", jv_bool(IsWindowVisible(hwnd) != 0));
            jv_put(e, "enabled", jv_bool(IsWindowEnabled(hwnd) != 0));
            // 模态判断：对话框自己启用、而它的属主被禁用——那正是模态框的形状。
            HWND owner = GetWindow(hwnd, GW_OWNER);
            jv_put(e, "has_owner", jv_bool(owner != NULL));
            jv_put(e, "owner_enabled", jv_bool(owner ? (IsWindowEnabled(owner) != 0) : true));
            RECT rc = {0,0,0,0};
            GetWindowRect(hwnd, &rc);
            jv_put(e, "rect", jv_num((double)rc.left * 1e6 + (double)rc.top));
            jv_add(arr, e);
        }
        jv_put(result, "windows", arr);
        jv_put(result, "count", jv_num((double)g_win_n));
    }
    else if (!strcmp(cmd, "list_threads")) {        DWORD tids[256];
        int n = snapshot_threads(tids, 256);
        jval* arr = jv_new(4);
        for (int i = 0; i < n; i++) {
            HANDLE h = OpenThread(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT, FALSE, tids[i]);
            jval* e = jv_new(5);
            jv_put(e, "tid", jv_num((double)tids[i]));
            jv_put(e, "current", jv_bool(tids[i] == g_paused_tid));
            jv_put(e, "parasite", jv_bool(tids[i] == g_par_tid));
            if (h) {
                CONTEXT c2;
                memset(&c2, 0, sizeof(c2));
                c2.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
                if (GetThreadContext(h, &c2)) {
                    jv_put(e, "rip", jv_num((double)c2.Rip));
                    jv_put(e, "rsp", jv_num((double)c2.Rsp));
                }
                int prio = GetThreadPriority(h);
                jv_put(e, "priority", jv_num((double)prio));
                CloseHandle(h);
            }
            jv_add(arr, e);
        }
        jv_put(result, "threads", arr);
    }
    else if (!strcmp(cmd, "get_ctx")) {
        u = jv_numval(args, "tid", 0);
        if (!u) { jv_put(result, "error", jv_str("缺少 tid")); return result; }
        HANDLE h = OpenThread(THREAD_GET_CONTEXT, FALSE, (DWORD)u);
        if (!h) { jv_put(result, "error", jv_str("打开线程失败")); return result; }
        CONTEXT c2;
        memset(&c2, 0, sizeof(c2));
        c2.ContextFlags = CONTEXT_ALL;
        if (!GetThreadContext(h, &c2)) { CloseHandle(h); jv_put(result, "error", jv_str("取上下文失败")); return result; }
        CloseHandle(h);
        jsb b; jsb_init(&b);
        ctx_to_json(&b, &c2);
        jv_put(result, "regs", json_parse(b.p));
        free(b.p);
    }
    else if (!strcmp(cmd, "set_thread_reg")) {
        u = jv_numval(args, "tid", 0);
        const char* name = jv_strval(args, "name", "");
        unsigned long long v = jv_numval(args, "value", 0);
        int done = 0;
        for (int i = 0; i < g_sus_n; i++) {
            if (g_sus_tid[i] == (DWORD)u) {
                int ok;
                xreg_set(&g_sus_ctx[i], name, v, &ok);
                done = ok;
                break;
            }
        }
        if (!done) {
            HANDLE h = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, (DWORD)u);
            if (h) {
                SuspendThread(h);
                CONTEXT c2;
                memset(&c2, 0, sizeof(c2));
                c2.ContextFlags = CONTEXT_ALL;
                if (GetThreadContext(h, &c2)) {
                    int ok;
                    xreg_set(&c2, name, v, &ok);
                    if (ok) done = SetThreadContext(h, &c2);
                }
                ResumeThread(h);
                CloseHandle(h);
            }
        }
        if (!done) { jv_put(result, "error", jv_str("设置失败")); return result; }
        jv_put(result, "ok", jv_bool(1));
    }
    else if (!strcmp(cmd, "suspend_thread")) {
        u = jv_numval(args, "tid", 0);
        HANDLE h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, (DWORD)u);
        if (!h) { jv_put(result, "error", jv_str("打开线程失败")); return result; }
        SuspendThread(h);
        CloseHandle(h);
        jv_put(result, "ok", jv_bool(1));
    }
    else if (!strcmp(cmd, "resume_thread")) {
        u = jv_numval(args, "tid", 0);
        HANDLE h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, (DWORD)u);
        if (!h) { jv_put(result, "error", jv_str("打开线程失败")); return result; }
        ResumeThread(h);
        CloseHandle(h);
        jv_put(result, "ok", jv_bool(1));
    }
    else if (!strcmp(cmd, "set_bp")) {
        u = jv_numval(args, "addr", 0);
        if (!u) { jv_put(result, "error", jv_str("缺少 addr")); return result; }
        EnterCriticalSection(&g_bp_lock);
        bp_t* bp = bp_alloc();
        int ok = 0, bid = 0;
        if (bp) {
            bp->type = BP_SW;
            bp->addr = (ULONG_PTR)u;
            bp->enabled = 1;
            bp->once = jv_numval(args, "once", 0) != 0;
            bp->silent = jv_numval(args, "silent", 0) != 0;
            strncpy_s(bp->cond, jv_strval(args, "cond", ""), _TRUNCATE);
            strncpy_s(bp->logmsg, jv_strval(args, "log", ""), _TRUNCATE);
            ok = bp_sw_enable(bp);
            if (ok) bid = bp->id;
            else bp_free(bp);
        }
        LeaveCriticalSection(&g_bp_lock);
        if (!ok) { jv_put(result, "error", jv_str("断点写入失败（地址不可写?）")); return result; }
        jv_put(result, "id", jv_num((double)bid));
        jv_put(result, "addr", jv_num((double)u));
    }
    else if (!strcmp(cmd, "set_hw_bp")) {
        // 这段在 Sky.exe 上会挂住（入口点处于断点暂停状态时），而在单线程目标上不会。
        // 日志用来区分三种可能：命令根本没到、卡在 g_bp_lock 上、还是卡在 hw_apply_all 里。
        logf("[*] set_hw_bp: 进入\n");
        u = jv_numval(args, "addr", 0);
        unsigned long long sz = jv_numval(args, "size", 8);
        const char* mode = jv_strval(args, "mode", "exec");
        if (!u) { jv_put(result, "error", jv_str("缺少 addr")); return result; }
        if (sz != 1 && sz != 2 && sz != 4 && sz != 8) sz = 8;
        int hwcount = 0;
        logf("[*] set_hw_bp: 取 g_bp_lock\n");
        EnterCriticalSection(&g_bp_lock);
        logf("[*] set_hw_bp: 已取到锁\n");
        for (int i = 0; i < MAX_BP; i++)
            if (g_bps[i].used && g_bps[i].type == BP_HW) hwcount++;
        if (hwcount >= 4) { LeaveCriticalSection(&g_bp_lock); jv_put(result, "error", jv_str("硬件断点槽已满(4)")); return result; }
        bp_t* bp = bp_alloc();
        int bid = 0;
        if (!bp) { LeaveCriticalSection(&g_bp_lock); jv_put(result, "error", jv_str("断点表满")); return result; }
        bp->type = BP_HW;
        bp->addr = (ULONG_PTR)u;
        bp->size = (int)sz;
        bp->enabled = 1;
        bp->hwmode = !strcmp(mode, "write") ? 1 : (!strcmp(mode, "read") ? 2 : (!strcmp(mode, "rw") ? 3 : 0));
        strncpy_s(bp->cond, jv_strval(args, "cond", ""), _TRUNCATE);
        bid = bp->id;
        LeaveCriticalSection(&g_bp_lock);
        hw_apply_all();
        jv_put(result, "id", jv_num((double)bid));
    }
    else if (!strcmp(cmd, "set_mem_bp")) {
        u = jv_numval(args, "addr", 0);
        unsigned long long sz = jv_numval(args, "size", 1);
        if (!u || !sz) { jv_put(result, "error", jv_str("参数无效")); return result; }
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery((PVOID)u, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT) {
            jv_put(result, "error", jv_str("地址未提交")); return result;
        }
        if (sz > mbi.RegionSize) sz = mbi.RegionSize;
        EnterCriticalSection(&g_bp_lock);
        bp_t* bp = bp_alloc();
        int bid = 0;
        if (!bp) { LeaveCriticalSection(&g_bp_lock); jv_put(result, "error", jv_str("断点表满")); return result; }
        DWORD op = 0;
        int ok = VirtualProtect((PVOID)u, (SIZE_T)sz,
            (mbi.Protect & ~PAGE_GUARD) | PAGE_GUARD, &op);
        if (ok) bp->orig_prot = op;
        bp->type = BP_MEM;
        bp->addr = (ULONG_PTR)u;
        bp->size = (int)sz;
        bp->enabled = ok;
        strncpy_s(bp->cond, jv_strval(args, "cond", ""), _TRUNCATE);
        bid = bp->id;
        LeaveCriticalSection(&g_bp_lock);
        if (!ok) { jv_put(result, "error", jv_str("VirtualProtect 失败")); return result; }
        jv_put(result, "id", jv_num((double)bid));
    }
    else if (!strcmp(cmd, "del_bp")) {
        int id = (int)jv_numval(args, "id", 0);
        EnterCriticalSection(&g_bp_lock);
        bp_t* bp = bp_by_id(id);
        int found = bp != NULL;
        LeaveCriticalSection(&g_bp_lock);
        if (!found) { jv_put(result, "error", jv_str("断点不存在")); return result; }
        bp_delete(bp);
        jv_put(result, "ok", jv_bool(1));
    }
    else if (!strcmp(cmd, "toggle_bp")) {
        int id = (int)jv_numval(args, "id", 0);
        int en = jv_numval(args, "enabled", 1) != 0;
        EnterCriticalSection(&g_bp_lock);
        bp_t* bp = bp_by_id(id);
        if (!bp) { LeaveCriticalSection(&g_bp_lock); jv_put(result, "error", jv_str("断点不存在")); return result; }
        int need_hw = 0;
        if (bp->type == BP_SW) {
            if (en && !bp->enabled) { bp->enabled = bp_sw_enable(bp); }
            else if (!en && bp->enabled) {
                bp_sw_disable(bp);
                bp->enabled = 0;
                if (g_pctx && (ULONG_PTR)g_pctx->Rip == bp->addr)
                    mem_write_safe(bp->addr, &bp->orig, 1);
            }
        }
        else if (bp->type == BP_HW) { bp->enabled = en; need_hw = 1; }
        else if (bp->type == BP_MEM) {
            if (en != bp->enabled) {
                DWORD op;
                if (en) VirtualProtect((PVOID)bp->addr, bp->size, ((DWORD)bp->orig_prot) | PAGE_GUARD, &op);
                else VirtualProtect((PVOID)bp->addr, bp->size, (DWORD)bp->orig_prot, &op);
                bp->enabled = en;
            }
        }
        LeaveCriticalSection(&g_bp_lock);
        if (need_hw) hw_apply_all();
        jv_put(result, "ok", jv_bool(1));
    }
    else if (!strcmp(cmd, "list_bps")) {
        jval* arr = jv_new(4);
        EnterCriticalSection(&g_bp_lock);
        for (int i = 0; i < MAX_BP; i++) {
            if (!g_bps[i].used) continue;
            jval* e = jv_new(5);
            jv_put(e, "id", jv_num((double)g_bps[i].id));
            jv_put(e, "type", jv_str(g_bps[i].type == BP_SW ? "sw" : g_bps[i].type == BP_HW ? "hw" : "mem"));
            jv_put(e, "addr", jv_num((double)g_bps[i].addr));
            jv_put(e, "enabled", jv_bool(g_bps[i].enabled));
            jv_put(e, "once", jv_bool(g_bps[i].once));
            jv_put(e, "silent", jv_bool(g_bps[i].silent));
            jv_put(e, "hits", jv_num((double)g_bps[i].hits));
            if (g_bps[i].cond[0]) jv_put(e, "cond", jv_str(g_bps[i].cond));
            if (g_bps[i].logmsg[0]) jv_put(e, "log", jv_str(g_bps[i].logmsg));
            if (g_bps[i].type == BP_HW) {
                jv_put(e, "size", jv_num((double)g_bps[i].size));
                jv_put(e, "hwmode", jv_num((double)g_bps[i].hwmode));
            }
            if (g_bps[i].type == BP_MEM) jv_put(e, "size", jv_num((double)g_bps[i].size));
            char sym[128];
            sym_name_for(g_bps[i].addr, sym, sizeof(sym));
            if (sym[0]) jv_put(e, "symbol", jv_str(sym));
            jv_add(arr, e);
        }
        LeaveCriticalSection(&g_bp_lock);
        jv_put(result, "breakpoints", arr);
    }

    else if (!strcmp(cmd, "list_modules")) {
        modinfo_t mods[128];
        int n = list_modules(mods, 128);
        jval* arr = jv_new(4);
        for (int i = 0; i < n; i++) {
            jval* e = jv_new(5);
            jv_put(e, "name", jv_str(mods[i].name));
            jv_put(e, "base", jv_num((double)mods[i].base));
            jv_put(e, "size", jv_num((double)mods[i].size));
            char pa[MAX_PATH];
            WideCharToMultiByte(CP_ACP, 0, mods[i].path, -1, pa, sizeof(pa) - 1, NULL, NULL);
            jv_put(e, "path", jv_str(pa));
            char ep[64]; sprintf_s(ep, "%llx", (unsigned long long)(mods[i].base + mods[i].size));
            jv_put(e, "end", jv_str(ep));
            jv_add(arr, e);
        }
        jv_put(result, "modules", arr);
        g_sym_mods_n = -1;
    }
    else if (!strcmp(cmd, "exports")) {
        const char* mn = jv_strval(args, "module", "");
        modinfo_t mi;
        if (!mod_find_by_name(mn, &mi)) { jv_put(result, "error", jv_str("模块不存在")); return result; }
        jval* arr = jv_new(4);
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mi.base;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)mi.base + dos->e_lfanew);
        IMAGE_DATA_DIRECTORY ed = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (ed.VirtualAddress) {
            PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)mi.base + ed.VirtualAddress);
            DWORD* names = (DWORD*)((BYTE*)mi.base + exp->AddressOfNames);
            WORD* ords = (WORD*)((BYTE*)mi.base + exp->AddressOfNameOrdinals);
            DWORD* funcs = (DWORD*)((BYTE*)mi.base + exp->AddressOfFunctions);
            for (DWORD i = 0; i < exp->NumberOfNames; i++) {
                jval* e = jv_new(5);
                jv_put(e, "name", jv_str((const char*)((BYTE*)mi.base + names[i])));
                jv_put(e, "addr", jv_num((double)(mi.base + funcs[ords[i]])));
                jv_add(arr, e);
            }
        }
        jv_put(result, "exports", arr);
    }
    else if (!strcmp(cmd, "list_imports")) {
        // 倾倒 snap_imports 在打补丁之前记下的清单。
        //
        // **不要在这里重新遍历导入表。** 第一版就是这么做的，理由是
        // "不新增状态更安全"，而那个判断是错的：这个引擎的加载路径是
        // LoadLibraryExW(DONT_RESOLVE_DLL_REFERENCES) 加上 snap_imports
        // **手工覆盖 IAT**，而 Sky.exe 的 OriginalFirstThunk 恰好为 0，
        // 于是只能回退去读那个已被覆盖的 IAT——里面的值全是真实地址、
        // 永远不为 0，遍历失控，引擎访问违例崩溃。
        // **当既有状态是破坏性的时候，"不新增状态"并不更安全。**
        //
        // 顺带：这也说明返回值必须能区分"没有导入"和"读不到"，
        // 所以同时报 captured 与 truncated。
        jval* arr = jv_new(4);
        for (int i = 0; i < g_imps_n; i++) {
            jval* e = jv_new(5);
            jv_put(e, "dll", jv_str(g_imps[i].dll));
            jv_put(e, "name", jv_str(g_imps[i].name));
            jv_add(arr, e);
        }
        jv_put(result, "imports", arr);
        jv_put(result, "count", jv_num((double)g_imps_n));
        jv_put(result, "captured", jv_bool(g_imps_n > 0 ? 1 : 0));
        jv_put(result, "truncated", jv_bool(g_imps_truncated));
    }
    else if (!strcmp(cmd, "read_stack")) {
        unsigned long long count = jv_numval(args, "count", 32);
        if (count > 512) count = 512;
        CONTEXT* c = cur_ctx();
        ULONG_PTR sp = c ? (ULONG_PTR)c->Rsp : 0;
        if (!sp) { jv_put(result, "error", jv_str("无栈上下文")); return result; }
        jval* arr = jv_new(4);
        for (unsigned long long i = 0; i < count; i++) {
            ULONG_PTR v = 0;
            if (mem_read_safe(sp + i * 8, &v, 8) != 8) break;
            jval* e = jv_new(5);
            jv_put(e, "addr", jv_num((double)(sp + i * 8)));
            jv_put(e, "value", jv_num((double)v));
            char sym[128];
            sym_name_for(v, sym, sizeof(sym));
            if (sym[0]) jv_put(e, "symbol", jv_str(sym));
            jv_add(arr, e);
        }
        jv_put(result, "stack", arr);
    }
    else if (!strcmp(cmd, "call_stack")) {
        CONTEXT* c = cur_ctx();
        if (!c) { jv_put(result, "error", jv_str("无上下文")); return result; }
        jval* arr = jv_new(4);
        // RBP 链回溯
        ULONG_PTR rbp = (ULONG_PTR)c->Rbp;
        ULONG_PTR ripv = (ULONG_PTR)c->Rip;
        for (int i = 0; i < 64 && rbp; i++) {
            ULONG_PTR ra = 0, nbp = 0;
            if (mem_read_safe(rbp, &nbp, 8) != 8) break;
            if (mem_read_safe(rbp + 8, &ra, 8) != 8) break;
            jval* e = jv_new(5);
            jv_put(e, "rbp", jv_num((double)rbp));
            jv_put(e, "ret", jv_num((double)ra));
            char sym[128];
            sym_name_for(ra, sym, sizeof(sym));
            if (sym[0]) jv_put(e, "symbol", jv_str(sym));
            jv_add(arr, e);
            if (nbp <= rbp) break;   // 链断裂防御
            rbp = nbp;
        }
        // 栈扫描候选返回地址（启发式）
        jval* cand = jv_new(4);
        ULONG_PTR sp = (ULONG_PTR)c->Rsp;
        for (unsigned long long i = 0; i < 128 && cand->n < 32; i++) {
            ULONG_PTR v = 0;
            if (mem_read_safe(sp + i * 8, &v, 8) != 8) break;
            if (g_sym_mods_n < 0) sym_refresh_modules();
            int inmod = 0;
            for (int m = 0; m < g_sym_mods_n; m++)
                if (v >= g_sym_mods[m].base && v < g_sym_mods[m].base + g_sym_mods[m].size) { inmod = 1; break; }
            if (inmod) jv_add(cand, jv_num((double)v));
        }
        jv_put(result, "frames", arr);
        jv_put(result, "candidates", cand);
    }
    else if (!strcmp(cmd, "set_patch")) {
        u = jv_numval(args, "addr", 0);
        const char* hex = jv_strval(args, "hex", "");
        BYTE buf[16];
        size_t n = hex2bin(hex, buf, sizeof(buf));
        // 报错要说清**缺哪个键**。
        // 原来只说 "参数无效"，而调用者从外部看到的只有这一句——
        // 于是"键名不对"和"地址为 0"和"十六进制串不合法"三种情况无法区分。
        // 本项目已经因为这一类吃过四次（search_str 的 s/pattern、list_bps 的
        // breakpoints/bps、read_mem 的 len/size、以及这里的 hex/bytes）。
        // 生成 docs/COMMAND_SCHEMA.md 是第一步，把错误消息说清楚是第二步。
        if (!u) { jv_put(result, "error", jv_str("缺少或无效参数：addr（补丁地址，非 0）")); return result; }
        if (!n) { jv_put(result, "error", jv_str("缺少或无效参数：hex（十六进制字节串，如 \"31 C0 C3\"）")); return result; }
        int id = 0;
        for (int i = 0; i < MAX_PATCH; i++) {
            if (!g_patches[i].used) {
                memset(&g_patches[i], 0, sizeof(patch_t));
                g_patches[i].used = 1;
                g_patches[i].id = g_patch_next_id++;
                g_patches[i].addr = (ULONG_PTR)u;
                g_patches[i].len = (int)n;
                mem_read_safe((ULONG_PTR)u, g_patches[i].orig, n);
                id = g_patches[i].id;
                break;
            }
        }
        if (!id) { jv_put(result, "error", jv_str("补丁表满")); return result; }
        safe_mem_write((ULONG_PTR)u, buf, n);
        jv_put(result, "id", jv_num((double)id));
    }
    else if (!strcmp(cmd, "list_patches")) {
        jval* arr = jv_new(4);
        for (int i = 0; i < MAX_PATCH; i++) {
            if (!g_patches[i].used) continue;
            jval* e = jv_new(5);
            jv_put(e, "id", jv_num((double)g_patches[i].id));
            jv_put(e, "addr", jv_num((double)g_patches[i].addr));
            jv_put(e, "enabled", jv_bool(g_patches[i].enabled));
            char hex[33];
            bin2hex(g_patches[i].orig, g_patches[i].len, hex);
            jv_put(e, "orig", jv_str(hex));
            char sym[128];
            sym_name_for(g_patches[i].addr, sym, sizeof(sym));
            if (sym[0]) jv_put(e, "symbol", jv_str(sym));
            jv_add(arr, e);
        }
        jv_put(result, "patches", arr);
    }
    else if (!strcmp(cmd, "restore_patch")) {
        int id = (int)jv_numval(args, "id", 0);
        int done = 0;
        for (int i = 0; i < MAX_PATCH; i++) {
            if (g_patches[i].used && g_patches[i].id == id) {
                safe_mem_write(g_patches[i].addr, g_patches[i].orig, g_patches[i].len);
                g_patches[i].used = 0;
                done = 1;
                break;
            }
        }
        if (!done) { jv_put(result, "error", jv_str("补丁不存在")); return result; }
        jv_put(result, "ok", jv_bool(1));
    }
    else if (!strcmp(cmd, "toggle_patch")) {
        int id = (int)jv_numval(args, "id", 0);
        int en = jv_numval(args, "enabled", 1) != 0;
        int done = 0;
        for (int i = 0; i < MAX_PATCH; i++) {
            if (g_patches[i].used && g_patches[i].id == id) {
                BYTE cur[16];
                if (mem_read_safe(g_patches[i].addr, cur, g_patches[i].len) == (SIZE_T)g_patches[i].len) {
                    if (!en && g_patches[i].enabled) {
                        safe_mem_write(g_patches[i].addr, g_patches[i].orig, g_patches[i].len);
                        g_patches[i].enabled = 0; done = 1;
                    }
                    else if (en && !g_patches[i].enabled) {
                        // 重新应用需要保存当前新字节为补丁内容——简化：仅恢复开关语义，
                        // 重新启用时把"非原始"的当前内容再写一次（研究级）
                        safe_mem_write(g_patches[i].addr, cur, g_patches[i].len);
                        g_patches[i].enabled = 1; done = 1;
                    }
                    else done = 1;
                }
                break;
            }
        }
        if (!done) { jv_put(result, "error", jv_str("补丁不存在或未变化")); return result; }
        jv_put(result, "ok", jv_bool(1));
    }
    else if (!strcmp(cmd, "set_label") || !strcmp(cmd, "set_comment") || !strcmp(cmd, "set_bookmark")) {
        const char* as = jv_strval(args, "addr", "");
        ULONG_PTR addr = sym_resolve(as);
        if (!addr && isdigit((unsigned char)as[0])) addr = (ULONG_PTR)_strtoui64(as, NULL, 0);
        if (!addr) { jv_put(result, "error", jv_str("无法解析 addr")); return result; }
        const char* text = jv_strval(args, "text", "");
        int r;
        if (!strcmp(cmd, "set_label")) r = mark_set(g_labels, &g_nlabels, 512, addr, text);
        else if (!strcmp(cmd, "set_comment")) r = mark_set(g_comments, &g_ncomments, 512, addr, text);
        else r = mark_set(g_bookmarks, &g_nbookmarks, 256, addr, text);
        if (r < 0) { jv_put(result, "error", jv_str("标记表满")); return result; }
        jv_put(result, "ok", jv_bool(1));
    }
    else if (!strcmp(cmd, "get_mark")) {
        const char* as = jv_strval(args, "addr", "");
        ULONG_PTR addr = sym_resolve(as);
        if (!addr) addr = (ULONG_PTR)_strtoui64(as, NULL, 0);
        const char* l = mark_find(g_labels, g_nlabels, addr);
        const char* c2 = mark_find(g_comments, g_ncomments, addr);
        const char* b = mark_find(g_bookmarks, g_nbookmarks, addr);
        if (l) jv_put(result, "label", jv_str(l));
        if (c2) jv_put(result, "comment", jv_str(c2));
        if (b) jv_put(result, "bookmark", jv_str(b));
    }
    else if (!strcmp(cmd, "list_marks")) {
        const char* kind = jv_strval(args, "kind", "all");
        jval* arr = jv_new(4);
        if (!strcmp(kind, "all") || !strcmp(kind, "label"))
            for (int i = 0; i < g_nlabels; i++) {
                jval* e = jv_new(5);
                jv_put(e, "addr", jv_num((double)g_labels[i].addr));
                jv_put(e, "kind", jv_str("label"));
                jv_put(e, "text", jv_str(g_labels[i].text));
                jv_add(arr, e);
            }
        if (!strcmp(kind, "all") || !strcmp(kind, "comment"))
            for (int i = 0; i < g_ncomments; i++) {
                jval* e = jv_new(5);
                jv_put(e, "addr", jv_num((double)g_comments[i].addr));
                jv_put(e, "kind", jv_str("comment"));
                jv_put(e, "text", jv_str(g_comments[i].text));
                jv_add(arr, e);
            }
        if (!strcmp(kind, "all") || !strcmp(kind, "bookmark"))
            for (int i = 0; i < g_nbookmarks; i++) {
                jval* e = jv_new(5);
                jv_put(e, "addr", jv_num((double)g_bookmarks[i].addr));
                jv_put(e, "kind", jv_str("bookmark"));
                jv_put(e, "text", jv_str(g_bookmarks[i].text));
                jv_add(arr, e);
            }
        jv_put(result, "marks", arr);
    }
    else if (!strcmp(cmd, "resolve_name")) {
        const char* name = jv_strval(args, "name", "");
        ULONG_PTR a = sym_resolve(name);
        if (!a) { jv_put(result, "error", jv_str("未解析")); return result; }
        jv_put(result, "addr", jv_num((double)a));
    }
    else if (!strcmp(cmd, "start_trace")) {
        if (g_state != DS_PAUSE) { jv_put(result, "error", jv_str("请先暂停再启动跟踪")); return result; }
        g_trace_mode = (int)jv_numval(args, "mode", 0);   // 0 into 1 over
        g_trace_max = jv_numval(args, "max", 0);
        strncpy_s(g_trace_cond, jv_strval(args, "cond", ""), _TRUNCATE);
        g_trace_on = 1;
        g_trace_stopflag = 0;
        dbg_logf("[*] 跟踪启动 mode=%s max=%llu cond=%s",
            g_trace_mode ? "over" : "into", g_trace_max, g_trace_cond);
        return cmd_resume_with(CMD_GO, result);
    }
    else if (!strcmp(cmd, "stop_trace")) {
        g_trace_stopflag = 1;
        g_trace_on = 0;
        jv_put(result, "ok", jv_bool(1));
        jv_put(result, "total", jv_num((double)g_trc_total));
    }
    else if (!strcmp(cmd, "get_trace")) {
        unsigned long long want_from = jv_numval(args, "from", 0);
        unsigned long long count = jv_numval(args, "count", 256);
        jval* arr = jv_new(4);
        unsigned long long avail_begin = g_trc_total > TRACEMAX ? g_trc_total - TRACEMAX : 0;
        if (want_from < avail_begin) want_from = avail_begin;
        unsigned long long n = g_trc_total - want_from;
        if (n > count) n = count;
        for (unsigned long long i = 0; i < n; i++) {
            unsigned long long idx = want_from + i;
            trc_t* t = &g_trc[idx % TRACEMAX];
            jval* e = jv_new(5);
            jv_put(e, "idx", jv_num((double)idx));
            jv_put(e, "tid", jv_num((double)t->tid));
            jv_put(e, "addr", jv_num((double)t->addr));
            char hex[32]; bin2hex(t->bytes, t->nb, hex);
            jv_put(e, "bytes", jv_str(hex));
            jv_put(e, "text", jv_str(t->text));
            jv_put(e, "rax", jv_num((double)t->rax));
            jv_put(e, "rdx", jv_num((double)t->rdx));
            jv_put(e, "rcx", jv_num((double)t->rcx));
            jv_put(e, "rsp", jv_num((double)t->rsp));
            jv_add(arr, e);
        }
        jv_put(result, "total", jv_num((double)g_trc_total));
        jv_put(result, "entries", arr);
    }
    else if (!strcmp(cmd, "eval")) {
        const char* expr = jv_strval(args, "expr", "");
        CONTEXT* c = cur_ctx();
        int err = 0;
        xval v = eval_expr(expr, c, 0, g_paused_tid, &err);
        if (err) { jv_put(result, "error", jv_str("表达式解析失败")); return result; }
        if (v.is_str) jv_put(result, "str", jv_str(v.str));
        else jv_put(result, "num", jv_num(v.num));
    }
    else if (!strcmp(cmd, "get_log")) {
        unsigned long long since = jv_numval(args, "since", 0);
        jval* arr = jv_new(4);
        EnterCriticalSection(&g_log_lock);
        for (unsigned i = g_loghead; i < g_logtail; i++) {
            unsigned slot = i % LOGMAX;
            if (g_logseq[slot] < since) continue;
            jval* e = jv_new(5);
            jv_put(e, "seq", jv_num((double)g_logseq[slot]));
            jv_put(e, "line", jv_str(g_logring[slot] ? g_logring[slot] : ""));
            jv_add(arr, e);
        }
        LeaveCriticalSection(&g_log_lock);
        jv_put(result, "next", jv_num((double)g_lognext));
        jv_put(result, "entries", arr);
    }
    else if (!strcmp(cmd, "clear_log")) {
        EnterCriticalSection(&g_log_lock);
        for (unsigned i = 0; i < LOGMAX; i++) { if (g_logring[i]) free(g_logring[i]); g_logring[i] = NULL; }
        g_loghead = g_logtail = 0;
        LeaveCriticalSection(&g_log_lock);
        jv_put(result, "ok", jv_bool(1));
    }
    else if (!strcmp(cmd, "terminate")) {
        unsigned long long code = jv_numval(args, "code", 0);
        dbg_logf("[*] 终止进程 code=%llu", code);
        // 延迟 300ms 退出，让响应先送达客户端
        static UINT s_exit_code;
        static DWORD s_exit_tid;
        s_exit_code = (UINT)code;
        CreateThread(NULL, 0, [](PVOID) -> DWORD {
            Sleep(300);
            ExitProcess(s_exit_code);
            return 0;
        }, NULL, 0, &s_exit_tid);
    }
    else {
        jv_put(result, "error", jv_str("未知命令"));
    }
    return result;
}


// ======================================================================
// JSON 序列化 + 命名管道服务器
// ======================================================================
static void jv_to_json(jsb* b, jval* v) {
    switch (v->type) {
    case 0: jsb_put(b, "null"); break;
    case 1: jsb_put(b, v->boolean ? "true" : "false"); break;
    case 2: jsb_printf(b, "%llu", (unsigned long long)v->num); break;
    case 3: jsb_esc(b, v->str); break;
    case 4:
        jsb_put(b, "[");
        for (int i = 0; i < v->n; i++) {
            if (i) jsb_put(b, ",");
            jv_to_json(b, v->items[i]);
        }
        jsb_put(b, "]");
        break;
    case 5:
        jsb_put(b, "{");
        for (int i = 0; i < v->n; i++) {
            if (i) jsb_put(b, ",");
            jsb_esc(b, v->keys[i]);
            jsb_put(b, ":");
            jv_to_json(b, v->items[i]);
        }
        jsb_put(b, "}");
        break;
    }
}

#define PIPE_NAME L"\\\\.\\pipe\\guadbg"
#define MAX_CLIENTS 8

static HANDLE g_clients[MAX_CLIENTS];
static int g_client_n;
static CRITICAL_SECTION g_cli_lock;

static void broadcast_evt(const char* json) {
    EnterCriticalSection(&g_cli_lock);
    for (int i = 0; i < g_client_n; i++) {
        const char* p = json;
        SIZE_T left = strlen(json) + 1;   // 含 NUL：消息模式边界
        while (left) {
            DWORD w = 0;
            if (!WriteFile(g_clients[i], p, (DWORD)left, &w, NULL)) break;
            left -= w; p += w;
        }
    }
    LeaveCriticalSection(&g_cli_lock);
}

static void client_remove(HANDLE h) {
    EnterCriticalSection(&g_cli_lock);
    for (int i = 0; i < g_client_n; i++) {
        if (g_clients[i] == h) {
            g_clients[i] = g_clients[--g_client_n];
            break;
        }
    }
    LeaveCriticalSection(&g_cli_lock);
}

static DWORD WINAPI pipe_client_thread(PVOID arg) {
    HANDLE h = (HANDLE)arg;
    eng_tid_add(GetCurrentThreadId());
    char buf[65536];
    for (;;) {
        DWORD r = 0;
        if (!ReadFile(h, buf, sizeof(buf) - 1, &r, NULL) || r == 0) break;
        buf[r] = 0;
        jval* req = json_parse(buf);
        if (!req) {
            // 解析失败必须**回一个错误**，不能静默丢弃。
            //
            // 原来的 `continue` 让调用者永久等下去：实测中一次引号被 shell 吃掉的参数
            // （`{addr:...,mode:exec}` 而不是 `{"addr":...,"mode":"exec"}`）表现成
            // "set_hw_bp 挂死"，而引擎其实健康——get_state 照常返回。
            // 一个不回应的失败看起来像死锁，而它其实是一句话就能说清的错误。
            char errbuf[512];
            int shown = r > 200 ? 200 : (int)r;
            sprintf_s(errbuf, "请求不是合法 JSON（收到 %lu 字节，前 %d 字节：%.*s）",
                (unsigned long)r, shown, shown, buf);
            jsb eb; jsb_init(&eb);
            jsb_put(&eb, "{\"id\":0,\"ok\":false,\"error\":");
            jsb_put(&eb, "\"");
            for (const char* q = errbuf; *q; ++q) {
                if (*q == '"' || *q == '\\') jsb_put(&eb, "\\");
                if ((unsigned char)*q < 0x20) jsb_put(&eb, " ");
                else { char one[2] = { *q, 0 }; jsb_put(&eb, one); }
            }
            jsb_put(&eb, "\"}\n");
            DWORD wrote = 0;
            WriteFile(h, eb.p, (DWORD)eb.len, &wrote, NULL);
            free(eb.p);
            continue;
        }
        jval* jcmd = jv_get(req, "cmd");
        jval* jargs = jv_get(req, "args");
        jval* jid = jv_get(req, "id");
        unsigned long long id = jid ? (unsigned long long)jid->num : 0;
        jval* result = jv_new(5);
        if (jcmd && jcmd->type == 3) {
            cmd_dispatch(jcmd->str, jargs && jargs->type == 5 ? jargs : NULL, result);
        }
        else jv_put(result, "error", jv_str("缺少 cmd"));
        jval* resp = jv_new(5);
        jv_put(resp, "id", jv_num((double)id));
        jval* err = jv_get(result, "error");
        if (err) {
            jv_put(resp, "ok", jv_bool(0));
            jv_put(resp, "error", jv_str(err->str));
        }
        else {
            jv_put(resp, "ok", jv_bool(1));
            jv_put(resp, "result", result);
        }
        jsb b; jsb_init(&b);
        jv_to_json(&b, resp);
        SIZE_T left = b.len + 1;
        const char* p = b.p;
        while (left) {
            DWORD w = 0;
            if (!WriteFile(h, p, (DWORD)left, &w, NULL)) break;
            left -= w; p += w;
        }
        free(b.p);
        jv_free(resp);
        jv_free(req);
    }
    client_remove(h);
    DisconnectNamedPipe(h);
    CloseHandle(h);
    return 0;
}

static DWORD WINAPI pipe_server_thread(PVOID) {
    eng_tid_add(GetCurrentThreadId());
    for (;;) {
        HANDLE h = CreateNamedPipeW(PIPE_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES, 1 << 20, 1 << 20, 0, NULL);
        if (h == INVALID_HANDLE_VALUE) {
            logf("[-] CreateNamedPipe 失败 err=%lu\n", GetLastError());
            Sleep(500); continue;
        }
        if (!ConnectNamedPipe(h, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
            CloseHandle(h);
            continue;
        }
        EnterCriticalSection(&g_cli_lock);
        if (g_client_n < MAX_CLIENTS) g_clients[g_client_n++] = h;
        else {
            LeaveCriticalSection(&g_cli_lock);
            const char* full = "{\"event\":\"log\",\"seq\":0,\"line\":\"客户端已满\"}";
            DWORD w = 0;
            WriteFile(h, full, (DWORD)strlen(full) + 1, &w, NULL);
            DisconnectNamedPipe(h);
            CloseHandle(h);
            continue;
        }
        LeaveCriticalSection(&g_cli_lock);
        DWORD tid;
        CreateThread(NULL, 0, pipe_client_thread, h, 0, &tid);
    }
    return 0;
}

static void engine_init(void) {
    // MSVC 14.44 的 #pragma section 会丢弃 write 属性（C4330），运行时补 RWX
    {
        DWORD _op = 0;
        VirtualProtect(g_tramp_section, sizeof(g_tramp_section),
            PAGE_EXECUTE_READWRITE, &_op);
    }
    InitializeCriticalSection(&g_bp_lock);
    InitializeCriticalSection(&g_log_lock);
    InitializeCriticalSection(&g_cli_lock);
    g_go = CreateEventW(NULL, TRUE, FALSE, NULL);   // manual-reset
    g_evt_hook = broadcast_evt;
    AddVectoredExceptionHandler(1, gua_veh);
    DWORD tid;
    CreateThread(NULL, 0, pipe_server_thread, NULL, 0, &tid);
    dbg_logf("[*] guadbg 引擎就绪，管道 \\\\.\\pipe\\guadbg");
}

// ======================================================================
// 主流程（PEL_ref 寄生加载 + 引擎初始化）
// ======================================================================
static WCHAR g_target_path[MAX_PATH];
static WCHAR g_target_device[520];
static HANDLE g_self_handle = NULL;

typedef BOOL(WINAPI* PFN_QueryFullProcessImageNameW)(HANDLE, DWORD, LPWSTR, PDWORD);
typedef DWORD(WINAPI* PFN_K32GetProcessImageFileNameW)(HANDLE, LPWSTR, DWORD);

static PFN_QueryFullProcessImageNameW g_orig_qfpinw = NULL;
static PFN_K32GetProcessImageFileNameW g_orig_k32gpifn = NULL;

static int is_self_handle(HANDLE h) {
    return h == (HANDLE)-1 || h == g_self_handle || h == GetCurrentProcess();
}

static BOOL WINAPI hk_queryfullprocessimagenamew(HANDLE hProcess, DWORD dwFlags,
    LPWSTR lpExeName, PDWORD pdwSize) {
    if (lpExeName && pdwSize && is_self_handle(hProcess)) {
        const WCHAR* src = (dwFlags & 1) ? g_target_device : g_target_path;
        SIZE_T n = wcslen(src);
        if (n + 1 > *pdwSize) { *pdwSize = (DWORD)n; SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        memcpy(lpExeName, src, (n + 1) * sizeof(WCHAR));
        *pdwSize = (DWORD)n;
        return TRUE;
    }
    if (g_orig_qfpinw) return g_orig_qfpinw(hProcess, dwFlags, lpExeName, pdwSize);
    SetLastError(ERROR_INVALID_HANDLE);
    return FALSE;
}

static DWORD WINAPI hk_k32getprocessimagefilenamew(HANDLE hProcess, LPWSTR lpFilename, DWORD nSize) {
    if (lpFilename && is_self_handle(hProcess)) {
        SIZE_T n = wcslen(g_target_device);
        if (n + 1 > nSize) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return 0; }
        memcpy(lpFilename, g_target_device, (n + 1) * sizeof(WCHAR));
        return (DWORD)n;
    }
    if (g_orig_k32gpifn) return g_orig_k32gpifn(hProcess, lpFilename, nSize);
    SetLastError(ERROR_INVALID_HANDLE);
    return 0;
}

static void hook_pair_k32(HMODULE k32, const char* name, PVOID handler, PVOID* tramp_slot) {
    PVOID p = mem_find_export(k32, name);
    if (!p) { logf("[-] kernel32!%s 未导出\n", name); return; }
    if (!install_hook_abs(p, handler, name)) {
        logf("[-] 钩子安装失败 %s\n", name);
        return;
    }
    *tramp_slot = g_hooks[g_hook_count - 1].tramp;
    logf("[*] 已钩 kernel32!%s @ %p\n", name, p);
}

// ---- 诊断开关：逐项关掉"引擎的加载与正常加载不同"的地方 ----
//
// 为什么需要：目标每次运行到约 16 秒都会弹出一个模态对话框（标题 Sky、标准 #32770、
// 带「确定」按钮），随后**停在那里不再执行任何东西**（CPU 平坦、页面访问归零）。
// 那说明它的检查发现了什么。把下面几项逐个关掉，就知道**是哪一项被它看到了**：
//     GUADBG_SKIP_IAT=1    不补静态导入（这样 .idata 就不会与磁盘不同）
//     GUADBG_SKIP_LDR=1    不补 PEB 的 Ldr 主模块条目
//     GUADBG_SKIP_PEB=1    不改 PEB 的 ImageBase / ProcessParameters
//     GUADBG_SKIP_HOOK=1   不钩 kernel32 的两个映像路径函数
// 判据：关掉某一项之后那个对话框**不再出现**，则该项就是被它看到的差别。
static int env_on(const char* name) {
    char buf[8] = { 0 };
    DWORD n = GetEnvironmentVariableA(name, buf, (DWORD)sizeof(buf));
    return n > 0 && buf[0] != '0';
}

int main(int argc, char** argv) {
    if (argc < 2) {
        logf("usage: guadbg.exe <target.exe>\n");
        return 1;
    }

    WCHAR argW[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, argv[1], -1, argW, MAX_PATH);
    if (!GetFullPathNameW(argW, MAX_PATH, g_target_path, NULL)) {
        logf("[-] GetFullPathNameW 失败 %lu\n", GetLastError());
        return 1;
    }
    logf("[*] 目标路径: %ls\n", g_target_path);

    X_PEB* peb = x_peb();
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hNtdll || !hKernel32) { logf("[-] 系统模块缺失\n"); return 1; }
    g_ntqvm = (PFN_NtQueryVirtualMemory)GetProcAddress(hNtdll, "NtQueryVirtualMemory");
    if (!g_ntqvm) { logf("[-] ntdll API 缺失\n"); return 1; }
    DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(),
        &g_self_handle, 0, FALSE, DUPLICATE_SAME_ACCESS);

    // ---- 引擎先行初始化（VEH/管道），以便目标入口前即可下断 ----
    engine_init();

    // ---- 1. 让真正的加载器映射映像，但不解析导入、也不运行入口点 ----
    //
    // 三条路都试过了，都是实测：
    //
    //   LoadLibraryW
    //       入口点被当 DllMain(hinstDLL, DLL_PROCESS_ATTACH, NULL) 调用，而那一刻 PEB 还在
    //       描述引擎自己 —— Sky.exe 上崩在 ntdll 的偏移 0x166df0。
    //
    //   LOAD_LIBRARY_AS_IMAGE_RESOURCE
    //       不跑入口点，但**所有段映射成只读**（写自己 .data 的程序立刻违例），
    //       而且**不进 Ldr 列表** —— 那不是一次真正的模块装载。
    //
    //   手工映射 + 自己造 Ldr 条目
    //       不跑入口点、段保护也对，但**伪造的条目过不了加载器自己的遍历**：
    //       ntdll 在 0x180010849 处 `mov 0x98(%rdi),%rax` 之后**无判空**地
    //       `cmp dword ptr [rax+0x38], 9`，期望那个字段是真实装载填好的；伪造条目给 0，
    //       于是解引用 0x38 —— 异常记录里的 **info2 = 0x38** 正是这一点的直接证据。
    //
    // DONT_RESOLVE_DLL_REFERENCES 把前两条的长处合起来：它是**真正的模块装载**
    // （加载器建条目、按段特性设保护、进三个链表），但**不解析导入、不调用入口点**。
    // 导入由 snap_imports 自己补 —— 那本来就是这个引擎已经在做的事。
    HMODULE hTarget = LoadLibraryExW(g_target_path, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!hTarget) {
        logf("[-] LoadLibraryEx(DONT_RESOLVE_DLL_REFERENCES) 失败 %lu\n", GetLastError());
        return 1;
    }
    PVOID target_base = (PVOID)hTarget;
    g_target_base = target_base;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)target_base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)target_base + dos->e_lfanew);
    PVOID ep = (PVOID)((BYTE*)target_base + nt->OptionalHeader.AddressOfEntryPoint);
    logf("[*] 目标已映射: base=%p ep=%p size=0x%lx（入口点尚未运行）\n",
         target_base, ep, nt->OptionalHeader.SizeOfImage);

    // ---- 1c. 把目标的目录加进 DLL 搜索路径 ----
    //
    // 这一步是实测需要的，而且是这个工具跑真实游戏时**唯一**挡路的东西：
    // Sky.exe 的导入表里有 steam_api64.dll、fmod.dll、fmodstudio.dll、vulkan-1.dll、igvk64.dll，
    // 它们都在**游戏目录**里，而引擎进程叫 guadbg.exe、住在自己的工作区目录，
    // 于是默认搜索路径找不到它们——实测 `LoadLibraryA("steam_api64.dll")` 返回 NULL，
    // 引擎以"导入模块缺失"退出，在第 16 个描述符上。
    //
    // SetDllDirectoryW 把该目录插进搜索顺序（在系统目录之后、当前目录之前），
    // 这正是系统加载器为一个住在该目录里的 exe 所做的事。用绝对路径取目录，
    // 因为映像路径可能来自任意位置。
    {
        WCHAR dir[MAX_PATH];
        wcsncpy_s(dir, g_target_path, _TRUNCATE);
        PWSTR slash = wcsrchr(dir, L'\\');
        if (slash) {
            *slash = 0;
            if (SetDllDirectoryW(dir)) {
                logf("[*] DLL 搜索目录已设为: %ls\n", dir);
            } else {
                logf("[!] SetDllDirectoryW 失败 (%lu)，依赖 DLL 可能找不到\n", GetLastError());
            }
        }
    }

    if (env_on("GUADBG_SKIP_IAT")) {
        logf("[!] GUADBG_SKIP_IAT：跳过静态导入补完（诊断用）\n");
    } else if (snap_imports(target_base) != 0) return 1;
    // PLACEHOLDER_REMOVED
    // ---- 1b. 补一个 Ldr 条目，并采用映像头里的路径 ----
    //
    // 以映像资源方式映射的模块不在加载器列表里，所以这里**自己补一条**，而不是去找一条。
    // 补的理由不是好看：目标代码会调用 GetModuleHandle(NULL)、EnumProcessModules、
    // 以及遍历 PEB->Ldr 的反调试检查，缺了条目它们看到的是一台没有主模块的进程。
    //
    // EntryPoint 填的是真正的入口点。这一点要紧：某些反篡改逻辑用
    // `((PIMAGE_NT_HEADERS)base)->OptionalHeader.AddressOfEntryPoint` 交叉核对 Ldr 条目，
    // 而系统装载的 EXE 那条记录里 EntryPoint 指向的是**运行时包装**（kernel32!BaseThreadInitThunk
    // 附近），不是映像入口。填映像入口是与本引擎"寄生线程直接跳入口点"的执行模型一致的。
    if (!env_on("GUADBG_SKIP_LDR")) {
        X_PEB_LDR_DATA* ldr = (X_PEB_LDR_DATA*)peb->Ldr;
        LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
        bool present = false;
        for (LIST_ENTRY* cur = head->Flink; cur && cur != head; cur = cur->Flink) {
            if (((X_LDR_DATA_TABLE_ENTRY*)cur)->DllBase == target_base) { present = true; break; }
        }
        if (present) {
            logf("[*] Ldr 已含该模块（退化路径）\n");
        } else {
            // 复用映像头里的 FullDllName 需要一块自己的缓冲：Ldr 条目在模块生命周期内有效，
            // 所以用进程堆分配并把映像路径写进去。
            SIZE_T plen = (wcslen(g_target_path) + 1) * sizeof(WCHAR);
            X_LDR_DATA_TABLE_ENTRY* e =
                (X_LDR_DATA_TABLE_ENTRY*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*e));
            PWSTR nbuf = (PWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, plen + 16);
            if (e && nbuf) {
                memcpy(nbuf, g_target_path, plen);
                e->DllBase = target_base;
                e->EntryPoint = ep;
                e->SizeOfImage = nt->OptionalHeader.SizeOfImage;
                e->FullDllName.Buffer = nbuf;
                e->FullDllName.Length = (USHORT)(plen - 2);
                e->FullDllName.MaximumLength = (USHORT)plen;
                // BaseDllName 取路径最后一段
                PWSTR leaf = nbuf;
                for (PWSTR q = nbuf; *q; ++q) if (*q == L'\\' || *q == L'/') leaf = q + 1;
                e->BaseDllName.Buffer = leaf;
                e->BaseDllName.Length = (USHORT)(wcslen(leaf) * sizeof(WCHAR));
                e->BaseDllName.MaximumLength = e->BaseDllName.Length + sizeof(WCHAR);
                // 自指的空链表，而不是零。未使用的 LIST_ENTRY 在全零时会把 NULL 交给
                // 任何顺着它走的遍历——而 ntdll 正是这样用 HashLinks 和 ForwarderLinks 的。
                e->HashLinks.Flink = e->HashLinks.Blink = &e->HashLinks;
                e->ForwarderLinks.Flink = e->ForwarderLinks.Blink = &e->ForwarderLinks;
                e->ServiceTagLinks.Flink = e->ServiceTagLinks.Blink = &e->ServiceTagLinks;
                e->StaticLinks.Flink = e->StaticLinks.Blink = &e->StaticLinks;
                e->LoadCount = 0xFFFF;          // 加载器对"不可卸载"的模块用的哨兵值
                e->TlsIndex = 0xFFFFFFFF;       // 无 TLS
                e->Flags = 0;
                e->OriginalBase = (ULONG_PTR)target_base;
                e->EntryPointActivationContext = NULL;
                // Insert all THREE lists. Windows walks InLoadOrder for module enumeration,
                // InMemoryOrder for the GetModuleHandle family, and InInitializationOrder when it
                // needs dependency order. An entry present in only one of them is a shape no real
                // loader produces, and a check that compares the lists against each other would
                // see it immediately.
                //
                // InsertHeadList is written out rather than called: it lives in ntdll and is not
                // declared by the headers available here, and it is three pointer assignments.
                auto insert_head = [](LIST_ENTRY* head, LIST_ENTRY* entry) {
                    entry->Flink = head->Flink;
                    entry->Blink = head;
                    head->Flink->Blink = entry;
                    head->Flink = entry;
                };
                insert_head(head, &e->InLoadOrderLinks);
                insert_head(&ldr->InMemoryOrderModuleList, &e->InMemoryOrderLinks);
                insert_head(&ldr->InInitializationOrderModuleList, &e->InInitializationOrderLinks);
                logf("[*] 已补 Ldr 条目: base=%p ep=%p name=%ls\n",
                     (void*)e->DllBase, (void*)e->EntryPoint, e->BaseDllName.Buffer);
            } else {
                logf("[-] Ldr 条目分配失败，继续（部分反调试查询会看到缺少主模块）\n");
            }
        }
    }

    // ---- 2. PEB 指向目标 ----
    if (!env_on("GUADBG_SKIP_PEB")) {
    peb->ImageBaseAddress = target_base;
    {
        X_RTL_USER_PROCESS_PARAMETERS* pp = peb->ProcessParameters;
        SIZE_T plen = (wcslen(g_target_path) + 1) * sizeof(WCHAR);
        PWSTR pbuf = (PWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, plen + 16);
        memcpy(pbuf, g_target_path, plen);
        pp->ImagePathName.Buffer = pbuf;
        pp->ImagePathName.Length = (USHORT)(plen - 2);
        pp->ImagePathName.MaximumLength = (USHORT)plen;
        WCHAR cmdline[600];
        swprintf_s(cmdline, L"\"%s\"", g_target_path);
        SIZE_T clen = (wcslen(cmdline) + 1) * sizeof(WCHAR);
        PWSTR cbuf = (PWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, clen + 16);
        memcpy(cbuf, cmdline, clen);
        pp->CommandLine.Buffer = cbuf;
        pp->CommandLine.Length = (USHORT)(clen - 2);
        pp->CommandLine.MaximumLength = (USHORT)clen;
        logf("[*] PEB ImageBase/ProcessParameters 已指向目标\n");
    }
    }   // GUADBG_SKIP_PEB

    // ---- 3. 目标设备路径 ----
    //
    // 这里**不能**再用 NtQueryVirtualMemory(..., MemoryMappedFilenameInformation, ...)：
    // 它要求那段内存是一次文件映射，而手动映射用的是 VirtualAlloc，没有文件名。
    // 实测：在手动映射之后这一步返回 st=c0000141，引擎就此退出。
    //
    // 路径本来就已知，所以改成从 DOS 路径构造设备路径：取出盘符，用 QueryDosDeviceW
    // 换成 \Device\HarddiskVolumeN。这正是内核对映像路径做的那件事，结果与
    // NtQueryVirtualMemory 给出的一致。
    {
        g_target_device[0] = 0;
        if (g_target_path[0] && g_target_path[1] == L':') {
            WCHAR drive[3] = { g_target_path[0], L':', 0 };
            WCHAR devName[512] = { 0 };
            if (QueryDosDeviceW(drive, devName, 512)) {
                _snwprintf_s(g_target_device, 520, _TRUNCATE, L"%ls%ls", devName,
                             g_target_path + 2);
            }
        }
        if (!g_target_device[0]) {
            // 盘符查询失败（UNC 路径等）时退回原路径：伪装的目的地是"看起来像目标"，
            // 而一条与 ImagePathName 一致的路径仍比空字符串好。
            wcsncpy_s(g_target_device, g_target_path, _TRUNCATE);
            logf("[!] QueryDosDevice 未给出设备路径，退回原路径\n");
        }
        logf("[*] 目标设备路径: %ls\n", g_target_device);
    }

    // ---- 4. kernel32 转发 stub 钩子（映像路径伪装） ----
    if (env_on("GUADBG_SKIP_HOOK")) {
        logf("[!] GUADBG_SKIP_HOOK：跳过 kernel32 钩子（诊断用）\n");
    } else {
    hook_pair_k32(hKernel32, "QueryFullProcessImageNameW",
        hk_queryfullprocessimagenamew, (PVOID*)&g_orig_qfpinw);
    hook_pair_k32(hKernel32, "K32GetProcessImageFileNameW",
        hk_k32getprocessimagefilenamew, (PVOID*)&g_orig_k32gpifn);
    logf("[*] 钩子安装完成（kernelbase/ntdll 全程未动）\n");
    }

    // ---- 5. 系统断点（入口点断点）：默认在入口下一次性断点，便于附加即停 ----
    {
        EnterCriticalSection(&g_bp_lock);
        bp_t* bp = bp_alloc();
        if (bp) {
            bp->type = BP_SW;
            bp->addr = (ULONG_PTR)ep;
            bp->enabled = 1;
            bp->once = 1;
            strncpy_s(bp->logmsg, "入口点断点（系统断点）", _TRUNCATE);
            if (!bp_sw_enable(bp)) { bp_free(bp); logf("[-] 入口断点写入失败\n"); }
            else logf("[*] 系统断点 @ %p（一次性）\n", ep);
        }
        LeaveCriticalSection(&g_bp_lock);
    }

    // ---- 6. 寄生线程：创建时起点即目标 EP，主线程随后退出 ----
    //
    // dwStackSize 必须是**目标自己声明的** SizeOfStackReserve，**不能传 0**。
    // 传 0 的语义是"用宿主映像的默认值"，而宿主是 guadbg.exe。
    // 第 132 轮实测的两个数：
    //     Sky.exe     SizeOfStackReserve = 0x200000（2 MB）
    //     guadbg.exe  SizeOfStackReserve = 0x100000（1 MB）
    // ⇒ 传 0 等于让游戏在**只有它要的一半**的栈上跑，深度稍大就
    //   STATUS_STACK_OVERFLOW（0xC00000FD，保护页命中，实测 rsp=…51f8 而触到 …3000）。
    const SIZE_T want_stack = (SIZE_T)nt->OptionalHeader.SizeOfStackReserve;
    logf("[*] 创建寄生线程 @ %p（栈 %llu MB，取自目标声明的 SizeOfStackReserve）\n",
         ep, (unsigned long long)(want_stack / (1024 * 1024)));
    g_par_thread = CreateThread(NULL, want_stack, (LPTHREAD_START_ROUTINE)ep, NULL, 0, &g_par_tid);
    if (!g_par_thread) { logf("[-] CreateThread 失败 %lu\n", GetLastError()); return 1; }

    logf("[*] 宿主主线程退出\n");
    ExitThread(0);
    return 0;
}
