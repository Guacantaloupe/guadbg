// PEL_ref.cpp —— 参考加载器 v3：寄生线程架构
// 研究用途：针对自研检测程序 test.exe 的对抗研究。
//
// 架构要点（对照检测程序的六层检查）：
//  1. test.exe 由系统加载器经 LoadLibraryW 正式装载 —— Ldr 条目、基址索引
//     (LdrpModuleBaseAddressIndex 红黑树)、导入解析、磁盘基线全部天然真实。
//  2. PEB ImageBaseAddress / ProcessParameters 改写指向 test.exe，
//     GetModuleHandleW(NULL) 即目标映像 —— 第一层 11 项全绿。
//  3. Win11 26200 禁止为已启动线程设置 Win32StartAddress
//     （NtSetInformationThread class 9 对任意线程返回 0xC000000D，实证）。
//     因此检测器跑在一条 CreateThread 原生创建的线程上：起点在创建时
//     即写定为目标 EP（合法路径），线程栈是系统原生形态（RtlUserThreadStart/
//     BaseThreadInitThunk 底部帧），宿主主线程随即 ExitThread 退出 ——
//     进程内只剩检测器线程，"最老线程"启发式自然满足。
//  4. 唯一钩子：kernel32 的两个 FF25 转发 stub —
//     QueryFullProcessImageNameW / K32GetProcessImageFileNameW —— 把"进程映像
//     路径"伪装成目标路径。本进程查询直接返回假路径（不发系统调用，天然规避
//     内核调用链校验）；kernelbase/ntdll 全程零改动，磁盘 stub 基线校验全过。
//  5. 不隐藏任何内存：无影子 section、无 VQ 虚拟化、无临时还原。

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#pragma comment(lib, "ntdll.lib")

typedef LONG NTSTATUS;
#define NT_SUCCESS(st) ((NTSTATUS)(st) >= 0)

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

static void dump_bytes(const char* tag, const BYTE* p, int n) {
    char line[256] = { 0 };
    char tmp[8];
    for (int i = 0; i < n; i++) {
        sprintf_s(tmp, "%02X ", p[i]);
        strcat_s(line, tmp);
    }
    logf("[dbg] %s: %s\n", tag, line);
}

// ======================================================================
// 手动补完静态导入（IAT snap）
// ======================================================================
// 实证（probe_iat2）：系统加载器对以 LoadLibrary 装载、未置 IMAGE_FILE_DLL
// 特征的映像（EXE）跳过 IAT 解析 —— 映像映射成功、Ldr 条目齐全，但全部
// IAT 槽位仍是磁盘静态值（指向 hint/name 的 RVA），首次经 IAT 调用即崩。
// 这里按加载器语义补完：从 ILT 取导入名，GetProcAddress 解析（转发导出
// 自动落到 ntdll，结果与基线逐字节一致），写回 IAT 后恢复原页保护。
static int snap_imports(PVOID base) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)base + dos->e_lfanew);
    ULONG impRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!impRva) return 0;
    PIMAGE_IMPORT_DESCRIPTOR desc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)base + impRva);
    int snapped = 0;
    for (; desc->Name; desc++) {
        char* dllName = (char*)((BYTE*)base + desc->Name);
        WCHAR wname[64];
        MultiByteToWideChar(CP_ACP, 0, dllName, -1, wname, 64);
        HMODULE hdll = GetModuleHandleW(wname);
        if (!hdll) hdll = LoadLibraryA(dllName);
        if (!hdll) { logf("[-] 导入模块缺失: %s\n", dllName); return -1; }

        PIMAGE_THUNK_DATA64 ilt = (PIMAGE_THUNK_DATA64)((BYTE*)base + desc->OriginalFirstThunk);
        PIMAGE_THUNK_DATA64 ft = (PIMAGE_THUNK_DATA64)((BYTE*)base + desc->FirstThunk);
        SIZE_T span = 0;
        if (!ilt) { ilt = ft; }                       // 无 ILT 时直接用 IAT 当名字表
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
            ft[i].u1.Function = (ULONG_PTR)addr;
            snapped++;
        }
        VirtualProtect(pageStart, pageLen, oldProt, &oldProt);
    }
    logf("[*] 已补完静态导入: %d 项\n", snapped);
    return 0;
}

// ======================================================================
// 极简 x64 长度反汇编器（LDE）
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
// 跳板池（.tramp 映像节）
// ======================================================================
#define HOOK_MAX 24
#define MAX_HOOKS 8
typedef struct _hook_t {
    PVOID target;
    PVOID handler;
    BYTE  orig[HOOK_MAX];
    BYTE  stolen_len;
    BYTE* tramp;
    const char* func_name;
} hook_t;

#pragma section(".tramp", read, write, execute)
__declspec(allocate(".tramp")) static BYTE g_tramp_section[0x10000];
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

// E9 rel32 跳板：窃取 >=5 字节的完整指令（FF25 转发 stub 恰好 6 字节），
// 跳板 = 重定位后的窃取指令 + 绝对跳回。
static BOOL install_hook_e9(PVOID target, PVOID handler, const char* func_name) {
    if (g_hook_count >= MAX_HOOKS) return FALSE;
    hook_t* hk = &g_hooks[g_hook_count];
    DWORD old_prot;
    BYTE buf[32];
    memcpy(buf, target, sizeof(buf));
    dump_bytes(func_name, buf, 16);

    // stub 形态：FF 25 disp32（kernel32 转发器常带 REX.W 前缀：48 FF 25）
    int rex = 0;
    if (buf[0] >= 0x40 && buf[0] <= 0x4F) rex = 1;
    if (!(buf[rex] == 0xFF && buf[rex + 1] == 0x25)) {
        logf("[-] %s 不是 FF25 转发 stub，放弃（避免破坏真实代码）\n", func_name);
        return FALSE;
    }

    SIZE_T stolen = 0;
    while (stolen < 5) {
        lde_t d = lde_decode(buf + stolen);
        if (d.len == 0 || d.len > 15 || stolen + d.len > HOOK_MAX) return FALSE;
        stolen += d.len;
    }
    logf("[dbg] %s 窃取 %zu 字节\n", func_name, stolen);

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
    // E9 rel32 的射程仅 ±2GB，而主 EXE 映像（~0x7FF6xxxxxxxx）与系统 DLL
    // （~0x7FFDxxxxxxxx）相距约 30GB，永远无法够到 —— 必须打绝对跳转：
    // 48 B8 imm64; FF E0（12 字节，落在 stub 的 CC 填充区，不越界到下一函数）。
    for (SIZE_T i = stolen; i < 12; i++) {
        if (buf[i] != 0xCC && buf[i] != 0x90) {
            logf("[-] %s stub 后无足够填充，拒绝打补丁\n", func_name);
            VirtualProtect(target, 12, old_prot, &old_prot);
            return FALSE;
        }
    }
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
// 进程映像路径伪装（kernel32 转发 stub 钩子处理函数）
// ======================================================================
static WCHAR g_target_path[MAX_PATH];
static WCHAR g_target_device[520];
static HANDLE g_self_handle = NULL;

typedef BOOL(WINAPI* PFN_QueryFullProcessImageNameW)(HANDLE, DWORD, LPWSTR, PDWORD);
typedef DWORD(WINAPI* PFN_K32GetProcessImageFileNameW)(HANDLE, LPWSTR, DWORD);

static PFN_QueryFullProcessImageNameW g_orig_qfpinw = NULL;
static PFN_K32GetProcessImageFileNameW g_orig_k32gpifn = NULL;

static int is_self_handle(HANDLE h) {
    return h == (HANDLE)-1 || h == g_self_handle;
}

static BOOL WINAPI hk_queryfullprocessimagenamew(HANDLE hProcess, DWORD dwFlags,
    LPWSTR lpExeName, PDWORD pdwSize) {
    if (lpExeName && pdwSize && is_self_handle(hProcess)) {
        const WCHAR* src = (dwFlags & 1 /*PROCESS_NAME_NATIVE*/) ? g_target_device : g_target_path;
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

// ======================================================================
// 主流程
// ======================================================================
static void hook_pair_k32(HMODULE k32, const char* name, PVOID handler, PVOID* tramp_slot) {
    PVOID p = mem_find_export(k32, name);
    if (!p) { logf("[-] kernel32!%s 未导出\n", name); return; }
    if (!install_hook_e9(p, handler, name)) {
        logf("[-] 钩子安装失败 %s\n", name);
        return;
    }
    *tramp_slot = g_hooks[g_hook_count - 1].tramp;
    logf("[*] 已钩 kernel32!%s @ %p（跳板 %p）\n", name, p, *tramp_slot);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        logf("usage: PEL_ref.exe <target.exe>\n");
        return 1;
    }

    // ---- 0. 目标绝对路径 / NT API ----
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

    // ---- 1. 由系统加载器正式装载目标（Ldr/基址红黑树/导入全部天然真实） ----
    HMODULE hTarget = LoadLibraryW(g_target_path);
    if (!hTarget) { logf("[-] LoadLibrary 失败 %lu\n", GetLastError()); return 1; }
    PVOID target_base = (PVOID)hTarget;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)target_base + ((PIMAGE_DOS_HEADER)target_base)->e_lfanew);
    PVOID ep = (PVOID)((BYTE*)target_base + nt->OptionalHeader.AddressOfEntryPoint);
    logf("[*] 目标已装载: base=%p ep=%p size=0x%lx\n",
        target_base, ep, nt->OptionalHeader.SizeOfImage);

    // LoadLibrary 装载 EXE 时加载器跳过 IAT 解析，此处按加载器语义补完
    if (snap_imports(target_base) != 0) return 1;

    // 以真实 Ldr 条目的 FullDllName 为准（大小写/表示形式与系统完全一致）
    {
        X_PEB_LDR_DATA* ldr = (X_PEB_LDR_DATA*)peb->Ldr;
        LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
        LIST_ENTRY* cur = head->Flink;
        while (cur && cur != head) {
            X_LDR_DATA_TABLE_ENTRY* e = (X_LDR_DATA_TABLE_ENTRY*)((BYTE*)cur - 0);
            if (e->DllBase == target_base) {
                // LoadLibrary 装载 EXE 时 Ldr 条目的 EntryPoint 记为 0（加载器
                // 不会调用 EXE 入口），而主映像条目的 EntryPoint 应为真实 EP ——
                // 补正为 PE 头声明值，消除 ldr_consistency 不一致。
                e->EntryPoint = ep;
                if (e->FullDllName.Buffer && e->FullDllName.Length) {
                    SIZE_T chars = e->FullDllName.Length / sizeof(WCHAR);
                    if (chars < MAX_PATH) {
                        memcpy(g_target_path, e->FullDllName.Buffer, e->FullDllName.Length);
                        g_target_path[chars] = 0;
                    }
                }
                break;
            }
            cur = cur->Flink;
        }
        logf("[*] 采用 Ldr FullDllName: %ls\n", g_target_path);
    }

    // ---- 2. PEB 指向目标 ----
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

    // ---- 3. 目标设备路径（K32GetProcessImageFileNameW 伪装用） ----
    {
        WCHAR namebuf[520]; SIZE_T rl = 0;
        NTSTATUS st = g_ntqvm(GetCurrentProcess(), target_base, 2 /*MemoryMappedFilenameInformation*/,
            namebuf, sizeof(namebuf), &rl);
        if (!NT_SUCCESS(st) || !rl) { logf("[-] 目标设备路径失败 st=%lx\n", st); return 1; }
        X_UNICODE_STRING* us = (X_UNICODE_STRING*)namebuf;
        wcsncpy_s(g_target_device, us->Buffer, _TRUNCATE);
        logf("[*] 目标设备路径: %ls\n", g_target_device);
    }

    // ---- 4. 安装 kernel32 转发 stub 钩子（本进程查询返回目标路径，不发系统调用） ----
    hook_pair_k32(hKernel32, "QueryFullProcessImageNameW",
        hk_queryfullprocessimagenamew, (PVOID*)&g_orig_qfpinw);
    hook_pair_k32(hKernel32, "K32GetProcessImageFileNameW",
        hk_k32getprocessimagefilenamew, (PVOID*)&g_orig_k32gpifn);
    logf("[*] 钩子安装完成（kernelbase/ntdll 全程未动）\n");

    // ---- 5. 寄生线程：创建时起点即目标 EP，主线程随后退出 ----
    // Win11 26200 禁止对已启动线程设置 Win32StartAddress（0xC000000D），
    // 而 CreateThread 的起点在创建时写定，是系统认可的合法路径。
    logf("[*] 创建寄生线程 @ %p\n", ep);
    DWORD tid = 0;
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ep, NULL, 0, &tid);
    if (!hThread) { logf("[-] CreateThread 失败 %lu\n", GetLastError()); return 1; }
    CloseHandle(hThread);

    // 主线程退出：进程内只剩检测器线程（最老线程 == 当前线程自然成立），
    // 检测器 CRT 结束时自行 ExitProcess。
    logf("[*] 宿主主线程退出\n");
    ExitThread(0);
    return 0;
}