// guadbg_ui.cpp —— x64dbg 风格 ImGui + DX11 前端
// 通过命名管道 \\.\pipe\guadbg 连接 guadbg 引擎（JSON 报文）。
//
// 依赖：Dear ImGui（core + win32 + dx11 后端），置于 third_party/imgui。
// 布局模仿 x64dbg 经典主题：CPU（反汇编 + 寄存器 + Dump + 栈）、
// Log / Breakpoints / Memory Map / Call Stack / Modules / Trace 标签页、命令栏。
//
// 快捷键：F2 断点开关  F7 步入  F8 步过  F9 运行  Ctrl+G 跳转  Backspace 返回

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"
#include <d3d11.h>
#include <dxgi.h>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")

// ======================================================================
// 迷你 JSON（与服务端协议对齐）
// ======================================================================
typedef struct jval {
    int type;                 // 0 null 1 bool 2 num 3 str 4 arr 5 obj
    int boolean;
    double num;
    char* str;
    jval** items;
    char** keys;
    int n;
} jval;

static jval* jv_new(int t) { jval* v = (jval*)calloc(1, sizeof(jval)); v->type = t; return v; }
static jval* jv_bool(int b) { jval* v = jv_new(1); v->boolean = b; return v; }
static jval* jv_num(double d) { jval* v = jv_new(2); v->num = d; return v; }
static jval* jv_str(const char* s) { jval* v = jv_new(3); v->str = _strdup(s ? s : ""); return v; }
static void jv_add(jval* a, jval* i) { a->items = (jval**)realloc(a->items, (a->n + 1) * sizeof(jval*)); a->items[a->n++] = i; }
static void jv_put(jval* o, const char* k, jval* i) {
    o->items = (jval**)realloc(o->items, (o->n + 1) * sizeof(jval*));
    o->keys = (char**)realloc(o->keys, (o->n + 1) * sizeof(char*));
    o->items[o->n] = i; o->keys[o->n] = _strdup(k); o->n++;
}
static jval* jv_get(jval* o, const char* k) {
    if (!o || o->type != 5) return NULL;
    for (int i = 0; i < o->n; i++) if (_stricmp(o->keys[i], k) == 0) return o->items[i];
    return NULL;
}
static const char* jv_s(jval* o, const char* k, const char* d) {
    jval* v = jv_get(o, k); return (v && v->type == 3) ? v->str : d;
}
static unsigned long long jv_u(jval* o, const char* k, unsigned long long d) {
    jval* v = jv_get(o, k);
    if (v && v->type == 2) return (unsigned long long)v->num;
    if (v && v->type == 1) return (unsigned long long)v->boolean;
    if (v && v->type == 3) return _strtoui64(v->str, NULL, 0);
    return d;
}
static void jv_free(jval* v) {
    if (!v) return;
    if (v->str) free(v->str);
    for (int i = 0; i < v->n; i++) jv_free(v->items[i]);
    if (v->items) free(v->items);
    if (v->keys) { for (int i = 0; i < v->n; i++) free(v->keys[i]); free(v->keys); }
    free(v);
}

typedef struct { const char* p; } jparse;
static void jp_ws(jparse* j) { while (*j->p == ' ' || *j->p == '\t' || *j->p == '\r' || *j->p == '\n') j->p++; }
static jval* jp_value(jparse* j) {
    jp_ws(j);
    if (*j->p == '"') {
        j->p++;
        char* out = (char*)malloc(strlen(j->p) + 1);
        size_t o = 0;
        while (*j->p && *j->p != '"') {
            if (*j->p == '\\' && j->p[1]) { j->p++; if (*j->p == 'n') out[o++] = '\n'; else if (*j->p == 't') out[o++] = '\t'; else out[o++] = *j->p; j->p++; }
            else out[o++] = *j->p++;
        }
        out[o] = 0;
        if (*j->p == '"') j->p++;
        jval* v = jv_str(out); free(out); return v;
    }
    if (*j->p == '{') {
        j->p++; jval* obj = jv_new(5); jp_ws(j);
        if (*j->p == '}') { j->p++; return obj; }
        for (;;) {
            jp_ws(j);
            jval* k = jp_value(j);
            if (!k) { jv_free(obj); return NULL; }
            jp_ws(j);
            if (*j->p == ':') j->p++;
            jval* v = jp_value(j);
            if (!v) { jv_free(k); jv_free(obj); return NULL; }
            jv_put(obj, k->str, v); jv_free(k);
            jp_ws(j);
            if (*j->p == ',') { j->p++; continue; }
            if (*j->p == '}') { j->p++; break; }
            jv_free(obj); return NULL;
        }
        return obj;
    }
    if (*j->p == '[') {
        j->p++; jval* arr = jv_new(4); jp_ws(j);
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
    char* end = NULL;
    double d = strtod(j->p, &end);
    if (end == j->p) return NULL;
    j->p = end;
    return jv_num(d);
}
static jval* json_parse(const char* s) { jparse j = { s }; return jp_value(&j); }

typedef struct { char* p; size_t len, cap; } jsb;
static void jsb_init(jsb* b) { b->cap = 4096; b->len = 0; b->p = (char*)malloc(b->cap); b->p[0] = 0; }
static void jsb_grow(jsb* b, size_t n) { while (b->len + n + 1 > b->cap) b->cap *= 2; b->p = (char*)realloc(b->p, b->cap); }
static void jsb_put(jsb* b, const char* s) { size_t n = strlen(s); jsb_grow(b, n); memcpy(b->p + b->len, s, n + 1); b->len += n; }
static void jsb_printf(jsb* b, const char* f, ...) {
    char t[1024]; va_list ap; va_start(ap, f);
    _vsnprintf_s(t, sizeof(t), _TRUNCATE, f, ap); va_end(ap);
    jsb_put(b, t);
}
static void jsb_esc(jsb* b, const char* s) {
    jsb_put(b, "\"");
    for (const char* p = s; *p; p++) {
        if (*p == '"' || *p == '\\') jsb_printf(b, "\\%c", *p);
        else if (*p == '\n') jsb_put(b, "\\n");
        else if (*p == '\t') jsb_put(b, "\\t");
        else { jsb_grow(b, 1); b->p[b->len++] = *p; b->p[b->len] = 0; }
    }
    jsb_put(b, "\"");
}
static void jv_to_json(jsb* b, jval* v) {
    switch (v->type) {
    case 0: jsb_put(b, "null"); break;
    case 1: jsb_put(b, v->boolean ? "true" : "false"); break;
    case 2: jsb_printf(b, "%llu", (unsigned long long)v->num); break;
    case 3: jsb_esc(b, v->str); break;
    case 4: jsb_put(b, "["); for (int i = 0; i < v->n; i++) { if (i) jsb_put(b, ","); jv_to_json(b, v->items[i]); } jsb_put(b, "]"); break;
    case 5: jsb_put(b, "{"); for (int i = 0; i < v->n; i++) { if (i) jsb_put(b, ","); jsb_esc(b, v->keys[i]); jsb_put(b, ":"); jv_to_json(b, v->items[i]); } jsb_put(b, "}"); break;
    }
}

// ======================================================================
// 引擎管道客户端
// ======================================================================
#define PIPE_NAME L"\\\\.\\pipe\\guadbg"

static HANDLE g_pipe = NULL;
static CRITICAL_SECTION g_pipe_lock;
static unsigned long long g_req_next = 1;

typedef struct pending_req {
    unsigned long long id;
    HANDLE evt;
    jval* response;
    struct pending_req* next;
} pending_req;
static pending_req* g_pending = NULL;

typedef struct ui_event {
    jval* obj;
    struct ui_event* next;
} ui_event;
static ui_event* g_events_head = NULL, * g_events_tail = NULL;
static CRITICAL_SECTION g_evt_lock;

static void push_event(jval* obj) {
    EnterCriticalSection(&g_evt_lock);
    ui_event* e = (ui_event*)calloc(1, sizeof(ui_event));
    e->obj = obj;
    if (g_events_tail) g_events_tail->next = e; else g_events_head = e;
    g_events_tail = e;
    LeaveCriticalSection(&g_evt_lock);
}

static DWORD WINAPI pipe_reader(PVOID) {
    char buf[4 * 1024 * 1024];
    for (;;) {
        DWORD r = 0;
        if (!ReadFile(g_pipe, buf, sizeof(buf) - 1, &r, NULL) || !r) {
            jval* o = jv_new(5);
            jv_put(o, "event", jv_str("engine_disconnected"));
            push_event(o);
            return 0;
        }
        buf[r] = 0;
        // 客户端句柄默认字节读模式：一次 ReadFile 可能含多条 NUL 分隔报文
        char* s = buf;
        while (*s) {
            char* msg = s;
            s += strlen(s) + 1;
            jval* obj = json_parse(msg);
            if (!obj) continue;
            jval* jid = jv_get(obj, "id");
            if (jid) {
                unsigned long long id = jv_u(obj, "id", 0);
                EnterCriticalSection(&g_pipe_lock);
                for (pending_req** pp = &g_pending; *pp; pp = &(*pp)->next) {
                    if ((*pp)->id == id) {
                        pending_req* pr = *pp;
                        *pp = pr->next;
                        pr->response = obj;
                        SetEvent(pr->evt);
                        LeaveCriticalSection(&g_pipe_lock);
                        goto done;
                    }
                }
                LeaveCriticalSection(&g_pipe_lock);
                jv_free(obj);
            done:;
            }
            else push_event(obj);
        }
    }
    return 0;
}

// 发送命令并等待响应（UI 线程调用；超时返回 NULL）
static jval* engine_call(const char* cmd, jval* args, DWORD timeout_ms) {
    if (!g_pipe) return NULL;
    jval* req = jv_new(5);
    unsigned long long id;
    EnterCriticalSection(&g_pipe_lock);
    id = g_req_next++;
    LeaveCriticalSection(&g_pipe_lock);
    jv_put(req, "id", jv_num((double)id));
    jv_put(req, "cmd", jv_str(cmd));
    jv_put(req, "args", args ? args : jv_new(5));

    pending_req pr;
    memset(&pr, 0, sizeof(pr));
    pr.id = id;
    pr.evt = CreateEventW(NULL, FALSE, FALSE, NULL);
    EnterCriticalSection(&g_pipe_lock);
    pr.next = g_pending;
    g_pending = &pr;
    LeaveCriticalSection(&g_pipe_lock);

    jsb b; jsb_init(&b);
    jv_to_json(&b, req);
    jv_free(req);
    EnterCriticalSection(&g_pipe_lock);
    DWORD w = 0;
    BOOL ok = WriteFile(g_pipe, b.p, (DWORD)b.len + 1, &w, NULL);
    LeaveCriticalSection(&g_pipe_lock);
    free(b.p);
    if (!ok) {
        EnterCriticalSection(&g_pipe_lock);
        for (pending_req** pp = &g_pending; *pp; pp = &(*pp)->next)
            if (*pp == &pr) { *pp = pr.next; break; }
        LeaveCriticalSection(&g_pipe_lock);
        CloseHandle(pr.evt);
        return NULL;
    }
    DWORD wr = WaitForSingleObject(pr.evt, timeout_ms);
    EnterCriticalSection(&g_pipe_lock);
    if (!pr.response)  // 超时：摘除
        for (pending_req** pp = &g_pending; *pp; pp = &(*pp)->next)
            if (*pp == &pr) { *pp = pr.next; break; }
    LeaveCriticalSection(&g_pipe_lock);
    CloseHandle(pr.evt);
    return wr == WAIT_OBJECT_0 ? pr.response : NULL;
}

static int engine_cmd(const char* cmd, jval* args) {
    jval* r = engine_call(cmd, args, 15000);
    if (!r) return 0;
    int ok = jv_u(r, "ok", 0) != 0;
    jv_free(r);
    return ok;
}

static int ui_connect_pipe(void) {
    for (int tries = 0; tries < 40 && !g_pipe; tries++) {
        HANDLE h = CreateFileW(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL,
            OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) { g_pipe = h; break; }
        WaitNamedPipeW(PIPE_NAME, 500);
    }
    if (!g_pipe) return 0;
    DWORD tid;
    CreateThread(NULL, 0, pipe_reader, NULL, 0, &tid);
    return 1;
}

// ======================================================================
// UI 状态
// ======================================================================
struct DisLine {
    unsigned long long addr;
    int size;
    char bytes[32];
    char text[160];
    unsigned long long target;
    int is_call, is_jump, bp_here;
    char comment[128];
    char label[64];
};
struct Regs {
    unsigned long long r[17];   // rax rcx rdx rbx rsp rbp rsi rdi r8..r15 rip
    unsigned long long rflags;
};
static const char* g_reg_names[17] = {
    "RAX","RCX","RDX","RBX","RSP","RBP","RSI","RDI",
    "R8","R9","R10","R11","R12","R13","R14","R15","RIP" };

static char g_status[128] = "Running";
static int g_paused = 0;
static unsigned long long g_rip = 0, g_sel_addr = 0, g_dump_addr = 0;
static unsigned long long g_hist[256];
static int g_hist_n = 0;

static DisLine g_dis[512];
static int g_dis_n = 0;
static Regs g_regs, g_regs_prev;
static int g_have_regs = 0;

struct StackRow { unsigned long long addr, value; char sym[96]; };
static StackRow g_stack[256];
static int g_stack_n = 0;

static BYTE g_dump[16 * 1024];
static unsigned long long g_dump_base = 0;
static SIZE_T g_dump_len = 0;

struct BpRow { int id; char type[8]; unsigned long long addr; int enabled, once, silent; unsigned long long hits; char cond[128]; };
static BpRow g_bps[256];
static int g_bps_n = 0;

struct MapRow { unsigned long long base, size; unsigned state, protect, type; char file[160]; };
static MapRow g_maps[512];
static int g_maps_n = 0;

struct ModRow { char name[64]; unsigned long long base, size; char path[200]; };
static ModRow g_mods[128];
static int g_mods_n = 0;

struct FrameRow { unsigned long long rbp, ret; char sym[96]; };
static FrameRow g_frames[64];
static int g_frames_n = 0;

static char g_loglines[4096][256];
static int g_loghead = 0, g_logtail = 0;

struct TraceRow { unsigned long long idx, addr, rax, rdx, rcx, rsp; char bytes[32], text[120]; };
static TraceRow g_trace[1024];
static int g_trace_n = 0;
static unsigned long long g_trace_total = 0;

static int g_tab = 0;   // 0 CPU 1 Log 2 BPs 3 MemMap 4 CallStack 5 Modules 6 Trace

static char g_cmdbuf[256] = "";
static char g_goto_buf[64] = "";
static int g_goto_open = 0;
static char g_editreg[8] = "";
static unsigned long long g_editval = 0;
static int g_editreg_open = 0;
static unsigned long long g_editmem_addr = 0;
static int g_editmem_open = 0;

static void log_line(const char* s) {
    strncpy_s(g_loglines[g_logtail % 4096], s, _TRUNCATE);
    g_logtail++;
    if (g_logtail - g_loghead > 4096) g_loghead = g_logtail - 4096;
}

// ---- 数据刷新 ----
static void refresh_disasm(unsigned long long addr) {
    jval* a = jv_new(5);
    jv_put(a, "addr", jv_num((double)addr));
    jv_put(a, "count", jv_num(64));
    jval* r = engine_call("disasm", a, 5000);
    jv_free(a);
    g_dis_n = 0;
    if (!r) return;
    jval* lines = jv_get(jv_get(r, "result"), "lines");
    if (lines) {
        for (int i = 0; i < lines->n && g_dis_n < 512; i++) {
            jval* e = lines->items[i];
            DisLine* d = &g_dis[g_dis_n++];
            d->addr = jv_u(e, "addr", 0);
            d->size = (int)jv_u(e, "size", 1);
            strncpy_s(d->bytes, jv_s(e, "bytes", ""), _TRUNCATE);
            strncpy_s(d->text, jv_s(e, "text", ""), _TRUNCATE);
            d->target = jv_u(e, "target", 0);
            d->is_call = (int)jv_u(e, "call", 0);
            d->is_jump = (int)jv_u(e, "jump", 0);
            d->bp_here = (int)jv_u(e, "bp_here", 0);
            strncpy_s(d->comment, jv_s(e, "comment", ""), _TRUNCATE);
            strncpy_s(d->label, jv_s(e, "label", ""), _TRUNCATE);
        }
    }
    jv_free(r);
}

static void refresh_regs(void) {
    jval* r = engine_call("get_regs", NULL, 5000);
    if (!r) return;
    jval* rg = jv_get(jv_get(r, "result"), "regs");
    if (rg) {
        g_regs_prev = g_regs;
        static const char* names[17] = {
            "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
            "r8","r9","r10","r11","r12","r13","r14","r15","rip" };
        for (int i = 0; i < 17; i++) g_regs.r[i] = jv_u(rg, names[i], 0);
        g_regs.rflags = jv_u(rg, "eflags", 0);
        g_have_regs = 1;
        g_rip = g_regs.r[16];
    }
    jv_free(r);
}

static void refresh_stack(void) {
    jval* a = jv_new(5);
    jv_put(a, "count", jv_num(48));
    jval* r = engine_call("read_stack", a, 5000);
    jv_free(a);
    g_stack_n = 0;
    if (!r) return;
    jval* st = jv_get(jv_get(r, "result"), "stack");
    if (st) {
        for (int i = 0; i < st->n && g_stack_n < 256; i++) {
            jval* e = st->items[i];
            StackRow* s = &g_stack[g_stack_n++];
            s->addr = jv_u(e, "addr", 0);
            s->value = jv_u(e, "value", 0);
            strncpy_s(s->sym, jv_s(e, "symbol", ""), _TRUNCATE);
        }
    }
    jv_free(r);
}

static void refresh_dump(unsigned long long addr) {
    jval* a = jv_new(5);
    jv_put(a, "addr", jv_num((double)addr));
    jv_put(a, "len", jv_num((double)sizeof(g_dump)));
    jval* r = engine_call("read_mem", a, 5000);
    jv_free(a);
    g_dump_len = 0;
    if (!r) return;
    const char* hex = jv_s(jv_get(r, "result"), "hex", "");
    SIZE_T hn = strlen(hex);
    g_dump_base = addr;
    for (SIZE_T i = 0; i + 1 < hn && i / 2 < sizeof(g_dump); i += 2) {
        int h = hex[i] <= '9' ? hex[i] - '0' : (hex[i] | 32) - 'a' + 10;
        int l = hex[i + 1] <= '9' ? hex[i + 1] - '0' : (hex[i + 1] | 32) - 'a' + 10;
        g_dump[i / 2] = (BYTE)((h << 4) | l);
        g_dump_len = i / 2 + 1;
    }
    jv_free(r);
}

static void refresh_bps(void) {
    jval* r = engine_call("list_bps", NULL, 5000);
    g_bps_n = 0;
    if (!r) return;
    jval* arr = jv_get(jv_get(r, "result"), "breakpoints");
    if (arr) {
        for (int i = 0; i < arr->n && g_bps_n < 256; i++) {
            jval* e = arr->items[i];
            BpRow* b = &g_bps[g_bps_n++];
            b->id = (int)jv_u(e, "id", 0);
            strncpy_s(b->type, jv_s(e, "type", ""), _TRUNCATE);
            b->addr = jv_u(e, "addr", 0);
            b->enabled = (int)jv_u(e, "enabled", 0);
            b->once = (int)jv_u(e, "once", 0);
            b->silent = (int)jv_u(e, "silent", 0);
            b->hits = jv_u(e, "hits", 0);
            strncpy_s(b->cond, jv_s(e, "cond", ""), _TRUNCATE);
        }
    }
    jv_free(r);
}

static void refresh_maps(void) {
    jval* r = engine_call("mem_map", NULL, 8000);
    g_maps_n = 0;
    if (!r) return;
    jval* arr = jv_get(jv_get(r, "result"), "regions");
    if (arr) {
        for (int i = 0; i < arr->n && g_maps_n < 512; i++) {
            jval* e = arr->items[i];
            MapRow* m = &g_maps[g_maps_n++];
            m->base = jv_u(e, "base", 0);
            m->size = jv_u(e, "size", 0);
            m->state = (unsigned)jv_u(e, "state", 0);
            m->protect = (unsigned)jv_u(e, "protect", 0);
            m->type = (unsigned)jv_u(e, "type", 0);
            strncpy_s(m->file, jv_s(e, "file", ""), _TRUNCATE);
        }
    }
    jv_free(r);
}

static void refresh_mods(void) {
    jval* r = engine_call("list_modules", NULL, 5000);
    g_mods_n = 0;
    if (!r) return;
    jval* arr = jv_get(jv_get(r, "result"), "modules");
    if (arr) {
        for (int i = 0; i < arr->n && g_mods_n < 128; i++) {
            jval* e = arr->items[i];
            ModRow* m = &g_mods[g_mods_n++];
            strncpy_s(m->name, jv_s(e, "name", ""), _TRUNCATE);
            m->base = jv_u(e, "base", 0);
            m->size = jv_u(e, "size", 0);
            strncpy_s(m->path, jv_s(e, "path", ""), _TRUNCATE);
        }
    }
    jv_free(r);
}

static void refresh_frames(void) {
    jval* r = engine_call("call_stack", NULL, 5000);
    g_frames_n = 0;
    if (!r) return;
    jval* arr = jv_get(jv_get(r, "result"), "frames");
    if (arr) {
        for (int i = 0; i < arr->n && g_frames_n < 64; i++) {
            jval* e = arr->items[i];
            FrameRow* f = &g_frames[g_frames_n++];
            f->rbp = jv_u(e, "rbp", 0);
            f->ret = jv_u(e, "ret", 0);
            strncpy_s(f->sym, jv_s(e, "symbol", ""), _TRUNCATE);
        }
    }
    jv_free(r);
}

static void refresh_trace(void) {
    jval* a = jv_new(5);
    unsigned long long from = g_trace_total > 512 ? g_trace_total - 512 : 0;
    jv_put(a, "from", jv_num((double)from));
    jv_put(a, "count", jv_num(512));
    jval* r = engine_call("get_trace", a, 5000);
    jv_free(a);
    g_trace_n = 0;
    if (!r) return;
    jval* res = jv_get(r, "result");
    g_trace_total = jv_u(res, "total", 0);
    jval* arr = jv_get(res, "entries");
    if (arr) {
        for (int i = 0; i < arr->n && g_trace_n < 1024; i++) {
            jval* e = arr->items[i];
            TraceRow* t = &g_trace[g_trace_n++];
            t->idx = jv_u(e, "idx", 0);
            t->addr = jv_u(e, "addr", 0);
            t->rax = jv_u(e, "rax", 0);
            t->rdx = jv_u(e, "rdx", 0);
            t->rcx = jv_u(e, "rcx", 0);
            t->rsp = jv_u(e, "rsp", 0);
            strncpy_s(t->bytes, jv_s(e, "bytes", ""), _TRUNCATE);
            strncpy_s(t->text, jv_s(e, "text", ""), _TRUNCATE);
        }
    }
    jv_free(r);
}

static void refresh_all_paused(void) {
    refresh_regs();
    refresh_disasm(g_rip);
    refresh_stack();
    if (!g_dump_base) g_dump_base = g_regs.r[4];
    refresh_dump(g_dump_base);
    refresh_bps();
    refresh_frames();
    sprintf_s(g_status, "Paused @ %llX", g_rip);
    g_paused = 1;
}

static void hist_push(unsigned long long a) {
    if (g_hist_n < 256) g_hist[g_hist_n++] = a;
}
static int hist_pop(unsigned long long* a) {
    if (!g_hist_n) return 0;
    *a = g_hist[--g_hist_n];
    return 1;
}

// ======================================================================
// DX11 基础
// ======================================================================
static ID3D11Device* g_pd3dDevice = NULL;
static ID3D11DeviceContext* g_pd3dDeviceContext = NULL;
static IDXGISwapChain* g_pSwapChain = NULL;
static ID3D11RenderTargetView* g_mainRenderTargetView = NULL;
static HWND g_hwnd = NULL;

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return TRUE;
    switch (msg) {
    case WM_SIZE:
        if (g_pd3dDevice && wParam != SIZE_MINIMIZED) {
            if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = NULL; }
            g_pSwapChain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
            ID3D11Texture2D* pBackBuffer;
            g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
            if (pBackBuffer) {
                g_pd3dDevice->CreateRenderTargetView(pBackBuffer, NULL, &g_mainRenderTargetView);
                pBackBuffer->Release();
            }
        }
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

static int create_device(void) {
    WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L,
        GetModuleHandleW(NULL), NULL, NULL, NULL, NULL, L"guadbg_ui", NULL };
    RegisterClassExW(&wc);
    g_hwnd = CreateWindowW(wc.lpszClassName, L"guadbg - x64dbg style",
        WS_OVERLAPPEDWINDOW, 100, 100, 1280, 800, NULL, NULL, wc.hInstance, NULL);

    DXGI_SWAP_CHAIN_DESC sd;
    ZeroMemory(&sd, sizeof(sd));
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = g_hwnd;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createFlags = 0;
    D3D_FEATURE_LEVEL fl;
    const D3D_FEATURE_LEVEL levels[] = { D3D_FEATURE_LEVEL_11_0 };
    HRESULT hr = D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL,
        createFlags, levels, 1, D3D11_SDK_VERSION, &sd,
        &g_pSwapChain, &g_pd3dDevice, &fl, &g_pd3dDeviceContext);
    if (FAILED(hr))
        hr = D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_WARP, NULL,
            createFlags, levels, 1, D3D11_SDK_VERSION, &sd,
            &g_pSwapChain, &g_pd3dDevice, &fl, &g_pd3dDeviceContext);
    if (FAILED(hr)) return 0;
    ID3D11Texture2D* pBackBuffer;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, NULL, &g_mainRenderTargetView);
    pBackBuffer->Release();
    ShowWindow(g_hwnd, SW_SHOWDEFAULT);
    UpdateWindow(g_hwnd);
    return 1;
}

static void cleanup_device(void) {
    if (g_mainRenderTargetView) g_mainRenderTargetView->Release();
    if (g_pSwapChain) g_pSwapChain->Release();
    if (g_pd3dDeviceContext) g_pd3dDeviceContext->Release();
    if (g_pd3dDevice) g_pd3dDevice->Release();
}

// ======================================================================
// x64dbg 经典配色
// ======================================================================
static void apply_x64dbg_style(void) {
    ImGuiStyle& s = ImGui::GetStyle();
    ImVec4* c = s.Colors;
    s.WindowRounding = 0.0f;
    s.FrameRounding = 0.0f;
    s.WindowBorderSize = 1.0f;
    c[ImGuiCol_WindowBg] = ImVec4(0.94f, 0.94f, 0.94f, 1.00f);
    c[ImGuiCol_ChildBg] = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
    c[ImGuiCol_Text] = ImVec4(0.00f, 0.00f, 0.00f, 1.00f);
    c[ImGuiCol_Header] = ImVec4(0.55f, 0.72f, 0.95f, 1.00f);
    c[ImGuiCol_HeaderHovered] = ImVec4(0.65f, 0.80f, 1.00f, 1.00f);
    c[ImGuiCol_HeaderActive] = ImVec4(0.45f, 0.65f, 0.95f, 1.00f);
    c[ImGuiCol_TitleBg] = ImVec4(0.80f, 0.80f, 0.83f, 1.00f);
    c[ImGuiCol_TitleBgActive] = ImVec4(0.65f, 0.78f, 0.96f, 1.00f);
    c[ImGuiCol_MenuBarBg] = ImVec4(0.74f, 0.74f, 0.77f, 1.00f);
    c[ImGuiCol_Button] = ImVec4(0.85f, 0.85f, 0.88f, 1.00f);
    c[ImGuiCol_ButtonHovered] = ImVec4(0.90f, 0.90f, 0.95f, 1.00f);
    c[ImGuiCol_FrameBg] = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
    c[ImGuiCol_FrameBgHovered] = ImVec4(0.85f, 0.90f, 1.00f, 1.00f);
}

#define COL_ADDR   ImVec4(0.35f, 0.35f, 0.35f, 1.0f)
#define COL_BYTES  ImVec4(0.50f, 0.50f, 0.50f, 1.0f)
#define COL_TEXT   ImVec4(0.00f, 0.00f, 0.00f, 1.0f)
#define COL_CALL   ImVec4(0.00f, 0.00f, 0.80f, 1.0f)
#define COL_JUMP   ImVec4(0.55f, 0.25f, 0.05f, 1.0f)
#define COL_BP     ImVec4(0.90f, 0.00f, 0.00f, 1.0f)
#define COL_CUR    ImVec4(0.85f, 0.85f, 0.85f, 1.0f)
#define COL_CHG    ImVec4(0.85f, 0.65f, 0.00f, 1.0f)

// ======================================================================
// 面板渲染
// ======================================================================
static void toggle_bp_at(unsigned long long addr) {
    refresh_bps();
    for (int i = 0; i < g_bps_n; i++) {
        if (g_bps[i].addr == addr && g_bps[i].type[0] == 's') {
            char idb[32]; sprintf_s(idb, "%d", g_bps[i].id);
            jval* a = jv_new(5);
            jv_put(a, "id", jv_num((double)g_bps[i].id));
            engine_cmd("del_bp", a);
            jv_free(a);
            return;
        }
    }
    jval* a = jv_new(5);
    jv_put(a, "addr", jv_num((double)addr));
    engine_cmd("set_bp", a);
    jv_free(a);
}

static void draw_cpu_panel(float w, float h) {
    ImGui::BeginChild("cpu", ImVec2(w, h), true);
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(6, 1));

    // 列头
    ImGui::TextColored(COL_ADDR, "Address");
    ImGui::SameLine(110);
    ImGui::TextColored(COL_BYTES, "Bytes");
    ImGui::SameLine(330);
    ImGui::TextColored(COL_TEXT, "Disassembly");

    for (int i = 0; i < g_dis_n; i++) {
        DisLine* d = &g_dis[i];
        bool is_cur = (d->addr == g_rip);
        bool is_sel = (d->addr == g_sel_addr);
        if (is_cur) {
            ImGui::PushStyleColor(ImGuiCol_ChildBg, COL_CUR);
            ImGui::GetWindowDrawList()->AddRectFilled(
                ImGui::GetCursorScreenPos(),
                ImVec2(ImGui::GetCursorScreenPos().x + ImGui::GetContentRegionAvail().x,
                    ImGui::GetCursorScreenPos().y + ImGui::GetTextLineHeightWithSpacing()),
                IM_COL32(210, 210, 210, 255));
        }
        if (is_sel) {
            ImGui::GetWindowDrawList()->AddRectFilled(
                ImVec2(ImGui::GetCursorScreenPos().x + 100, ImGui::GetCursorScreenPos().y),
                ImVec2(ImGui::GetCursorScreenPos().x + ImGui::GetContentRegionAvail().x,
                    ImGui::GetCursorScreenPos().y + ImGui::GetTextLineHeightWithSpacing()),
                IM_COL32(150, 185, 245, 255));
        }

        char addrbuf[64];
        sprintf_s(addrbuf, "%llX", d->addr);
        if (d->bp_here) {
            ImGui::TextColored(COL_BP, "*");
            ImGui::SameLine();
        }
        ImGui::TextColored(COL_ADDR, "%s:", addrbuf);
        if (ImGui::IsItemClicked()) g_sel_addr = d->addr;
        if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0) && d->target) {
            hist_push(g_dis_n ? g_dis[0].addr : 0);
            refresh_disasm(d->target);
        }
        ImGui::SameLine(110);
        ImGui::TextColored(COL_BYTES, "%-18s", d->bytes);
        ImGui::SameLine(330);
        ImVec4 tc = d->is_call ? COL_CALL : d->is_jump ? COL_JUMP : COL_TEXT;
        ImGui::TextColored(tc, "%s", d->text);
        ImGui::SameLine(640);
        if (d->comment[0]) ImGui::TextColored(COL_ADDR, "; %s", d->comment);
        else if (d->label[0]) ImGui::TextColored(COL_ADDR, "<%s>", d->label);
        if (is_cur) ImGui::PopStyleColor();
        // 行内点击（覆盖整行区域）
        if (ImGui::IsItemClicked()) g_sel_addr = d->addr;
    }
    ImGui::PopStyleVar();
    // 滚轮翻页 → 重新反汇编
    if (ImGui::GetIO().MouseWheel != 0 && g_dis_n > 0) {
        unsigned long long na = g_dis[0].addr;
        if (ImGui::GetIO().MouseWheel < 0) na = g_dis[g_dis_n - 1].addr;
        else na -= 32;
        refresh_disasm(na);
    }
    ImGui::EndChild();
}

static void draw_regs_panel(float w, float h) {
    ImGui::BeginChild("regs", ImVec2(w, h), true);
    if (!g_have_regs) { ImGui::TextDisabled("（未暂停）"); ImGui::EndChild(); return; }
    for (int i = 0; i < 17; i++) {
        bool changed = g_regs.r[i] != g_regs_prev.r[i];
        ImGui::TextColored(changed ? COL_CHG : COL_TEXT, "%-4s", g_reg_names[i]);
        ImGui::SameLine(48);
        ImGui::PushID(i);
        ImGui::TextColored(changed ? COL_CHG : COL_TEXT, "%016llX", g_regs.r[i]);
        if (ImGui::IsItemClicked()) {
            strncpy_s(g_editreg, g_reg_names[i], _TRUNCATE);
            g_editval = g_regs.r[i];
            g_editreg_open = 1;
        }
        ImGui::PopID();
    }
    ImGui::Separator();
    unsigned long long f = g_regs.rflags;
    ImGui::Text("RFLAGS %016llX", f);
    ImGui::Text("CF=%llu PF=%llu AF=%llu ZF=%llu SF=%llu TF=%llu IF=%llu DF=%llu OF=%llu",
        f & 1, (f >> 2) & 1, (f >> 4) & 1, (f >> 6) & 1, (f >> 7) & 1,
        (f >> 8) & 1, (f >> 9) & 1, (f >> 10) & 1, (f >> 11) & 1);
    ImGui::EndChild();
}

static void draw_dump_panel(float w, float h) {
    ImGui::BeginChild("dump", ImVec2(w, h), true);
    char hd[64];
    sprintf_s(hd, "Dump @ %llX", g_dump_base);
    ImGui::TextColored(COL_ADDR, "%s", hd);
    ImGui::SameLine();
    if (ImGui::SmallButton("<<")) { g_dump_base -= 0x100; refresh_dump(g_dump_base); }
    ImGui::SameLine();
    if (ImGui::SmallButton(">>")) { g_dump_base += 0x100; refresh_dump(g_dump_base); }
    ImGui::SameLine();
    if (ImGui::SmallButton("RSP")) { g_dump_base = g_regs.r[4]; refresh_dump(g_dump_base); }
    ImGui::Separator();
    int rows = (int)(g_dump_len / 16);
    if (rows > 40) rows = 40;
    for (int r = 0; r < rows; r++) {
        unsigned long long a = g_dump_base + r * 16;
        ImGui::PushID(r);
        ImGui::TextColored(COL_ADDR, "%016llX", a);
        for (int k = 0; k < 16; k++) {
            ImGui::SameLine();
            ImGui::PushID(k);
            ImGui::TextColored(COL_BYTES, "%02X", g_dump[r * 16 + k]);
            if (ImGui::IsItemClicked()) { g_editmem_addr = a + k; g_editmem_open = 1; }
            ImGui::PopID();
        }
        ImGui::SameLine();
        char asc[17];
        for (int k = 0; k < 16; k++) {
            BYTE b = g_dump[r * 16 + k];
            asc[k] = (b >= 0x20 && b < 0x7F) ? (char)b : '.';
        }
        asc[16] = 0;
        ImGui::TextColored(COL_TEXT, " %s", asc);
        ImGui::PopID();
    }
    ImGui::EndChild();
}

static void draw_stack_panel(float w, float h) {
    ImGui::BeginChild("stack", ImVec2(w, h), true);
    ImGui::TextColored(COL_ADDR, "Stack (RSP=%016llX)", g_regs.r[4]);
    ImGui::Separator();
    for (int i = 0; i < g_stack_n; i++) {
        ImGui::PushID(i);
        ImGui::TextColored(COL_ADDR, "%016llX", g_stack[i].addr);
        ImGui::SameLine(150);
        ImGui::TextColored(COL_TEXT, "%016llX", g_stack[i].value);
        if (g_stack[i].sym[0]) {
            ImGui::SameLine(340);
            ImGui::TextColored(COL_CALL, "%s", g_stack[i].sym);
        }
        if (ImGui::IsItemClicked()) { g_dump_base = g_stack[i].value; refresh_dump(g_dump_base); }
        ImGui::PopID();
    }
    ImGui::EndChild();
}

static void draw_log_tab(void) {
    if (ImGui::Button("清空")) {
        engine_cmd("clear_log", NULL);
        g_loghead = g_logtail = 0;
    }
    ImGui::Separator();
    ImGui::BeginChild("logview");
    for (int i = g_loghead; i < g_logtail; i++) {
        const char* l = g_loglines[i % 4096];
        ImVec4 c = COL_TEXT;
        if (l[0] == '[' && l[1] == '*') c = COL_CALL;
        else if (l[0] == '[' && l[1] == '!') c = COL_BP;
        ImGui::TextColored(c, "%s", l);
    }
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) ImGui::SetScrollHereY(1.0f);
    ImGui::EndChild();
}

static void draw_bps_tab(void) {
    if (ImGui::Button("刷新")) refresh_bps();
    ImGui::SameLine();
    ImGui::TextDisabled("双击地址跳转；右键删除");
    ImGui::Separator();
    ImGui::Columns(7, "bpcols");
    ImGui::Text("ID"); ImGui::NextColumn();
    ImGui::Text("类型"); ImGui::NextColumn();
    ImGui::Text("地址"); ImGui::NextColumn();
    ImGui::Text("启用"); ImGui::NextColumn();
    ImGui::Text("命中"); ImGui::NextColumn();
    ImGui::Text("条件"); ImGui::NextColumn();
    ImGui::Text(""); ImGui::NextColumn();
    ImGui::Separator();
    for (int i = 0; i < g_bps_n; i++) {
        BpRow* b = &g_bps[i];
        ImGui::Text("%d", b->id); ImGui::NextColumn();
        ImGui::Text("%s", b->type); ImGui::NextColumn();
        ImGui::Text("%llX", b->addr);
        if (ImGui::IsItemClicked()) { hist_push(g_dis_n ? g_dis[0].addr : 0); refresh_disasm(b->addr); g_tab = 0; }
        ImGui::NextColumn();
        bool en = b->enabled != 0;
        if (ImGui::Checkbox("##en", &en)) {
            jval* a = jv_new(5);
            jv_put(a, "id", jv_num((double)b->id));
            jv_put(a, "enabled", jv_bool(en));
            engine_cmd("toggle_bp", a);
            jv_free(a);
            b->enabled = en;
        }
        ImGui::NextColumn();
        ImGui::Text("%llu", b->hits); ImGui::NextColumn();
        ImGui::Text("%s", b->cond); ImGui::NextColumn();
        if (ImGui::SmallButton("X")) {
            jval* a = jv_new(5);
            jv_put(a, "id", jv_num((double)b->id));
            engine_cmd("del_bp", a);
            jv_free(a);
            refresh_bps();
        }
        ImGui::NextColumn();
    }
    ImGui::Columns(1);
}

static void draw_map_tab(void) {
    if (ImGui::Button("刷新")) refresh_maps();
    ImGui::Separator();
    ImGui::BeginChild("mapview");
    ImGui::Columns(5, "mapcols");
    ImGui::Text("基址"); ImGui::NextColumn();
    ImGui::Text("大小"); ImGui::NextColumn();
    ImGui::Text("状态"); ImGui::NextColumn();
    ImGui::Text("保护"); ImGui::NextColumn();
    ImGui::Text("映射文件"); ImGui::NextColumn();
    ImGui::Separator();
    for (int i = 0; i < g_maps_n; i++) {
        MapRow* m = &g_maps[i];
        if (m->state != 0x1000) continue;   // MEM_COMMIT
        ImGui::Text("%llX", m->base);
        if (ImGui::IsItemClicked()) { g_dump_base = m->base; refresh_dump(g_dump_base); g_tab = 0; }
        ImGui::NextColumn();
        ImGui::Text("%llX", m->size); ImGui::NextColumn();
        ImGui::Text("%X", m->state); ImGui::NextColumn();
        ImGui::Text("%X", m->protect); ImGui::NextColumn();
        ImGui::Text("%s", m->file); ImGui::NextColumn();
    }
    ImGui::Columns(1);
    ImGui::EndChild();
}

static void draw_frames_tab(void) {
    if (ImGui::Button("刷新")) refresh_frames();
    ImGui::Separator();
    for (int i = 0; i < g_frames_n; i++) {
        ImGui::TextColored(COL_ADDR, "%016llX", g_frames[i].rbp);
        ImGui::SameLine(150);
        ImGui::Text("%016llX", g_frames[i].ret);
        ImGui::SameLine(340);
        if (g_frames[i].sym[0]) ImGui::TextColored(COL_CALL, "%s", g_frames[i].sym);
        if (ImGui::IsItemClicked()) { hist_push(g_dis_n ? g_dis[0].addr : 0); refresh_disasm(g_frames[i].ret); g_tab = 0; }
    }
}

static void draw_mods_tab(void) {
    if (ImGui::Button("刷新")) refresh_mods();
    ImGui::Separator();
    ImGui::Columns(4, "modcols");
    ImGui::Text("模块"); ImGui::NextColumn();
    ImGui::Text("基址"); ImGui::NextColumn();
    ImGui::Text("大小"); ImGui::NextColumn();
    ImGui::Text("路径"); ImGui::NextColumn();
    ImGui::Separator();
    for (int i = 0; i < g_mods_n; i++) {
        ModRow* m = &g_mods[i];
        ImGui::Text("%s", m->name);
        if (ImGui::IsItemClicked()) { hist_push(g_dis_n ? g_dis[0].addr : 0); refresh_disasm(m->base); g_tab = 0; }
        ImGui::NextColumn();
        ImGui::Text("%llX", m->base); ImGui::NextColumn();
        ImGui::Text("%llX", m->size); ImGui::NextColumn();
        ImGui::Text("%s", m->path); ImGui::NextColumn();
    }
    ImGui::Columns(1);
}

static void draw_trace_tab(void) {
    if (ImGui::Button("刷新")) refresh_trace();
    ImGui::SameLine();
    if (ImGui::Button("停止跟踪")) engine_cmd("stop_trace", NULL);
    ImGui::SameLine();
    ImGui::Text("总条数: %llu", g_trace_total);
    ImGui::Separator();
    ImGui::BeginChild("traceview");
    for (int i = 0; i < g_trace_n; i++) {
        TraceRow* t = &g_trace[i];
        ImGui::TextColored(COL_ADDR, "%8llu  %016llX  %-18s %s",
            t->idx, t->addr, t->bytes, t->text);
        if (ImGui::IsItemClicked()) { hist_push(g_dis_n ? g_dis[0].addr : 0); refresh_disasm(t->addr); g_tab = 0; }
    }
    ImGui::EndChild();
}

// ======================================================================
// 命令栏（x64dbg 命令子集）
// ======================================================================
static void run_ui_command(const char* c) {
    char buf[256];
    strncpy_s(buf, c, _TRUNCATE);
    char* ctx = NULL;
    char* t = strtok_s(buf, " \t", &ctx);
    if (!t) return;
    if (!_stricmp(t, "go")) engine_cmd("resume", NULL);
    else if (!_stricmp(t, "pause")) engine_cmd("pause", NULL);
    else if (!_stricmp(t, "sti") || !_stricmp(t, "step")) engine_cmd("step_into", NULL);
    else if (!_stricmp(t, "sto")) engine_cmd("step_over", NULL);
    else if (!_stricmp(t, "rtr")) engine_cmd("step_out", NULL);
    else if (!_stricmp(t, "rtu")) {   // run till user code 简化：跳到 rip
        if (g_rip) {
            jval* a = jv_new(5);
            jv_put(a, "addr", jv_num((double)g_rip));
            engine_cmd("run_to", a);
            jv_free(a);
        }
    }
    else if (!_stricmp(t, "bp")) {
        char* s = strtok_s(NULL, " \t", &ctx);
        if (s) {
            jval* a = jv_new(5);
            char* end = NULL;
            unsigned long long v = _strtoui64(s, &end, 16);
            if (end == s || *end) {   // 符号：先解析再下断点
                jval* ra = jv_new(5);
                jv_put(ra, "name", jv_str(s));
                jval* rr = engine_call("resolve_name", ra, 3000);
                jv_free(ra);
                if (rr) {
                    unsigned long long addr = jv_u(jv_get(rr, "result"), "addr", 0);
                    if (addr) {
                        jval* ba = jv_new(5);
                        jv_put(ba, "addr", jv_num((double)addr));
                        engine_cmd("set_bp", ba);
                        jv_free(ba);
                    }
                    jv_free(rr);
                }
            }
            else {
                jv_put(a, "addr", jv_num((double)v));
                engine_cmd("set_bp", a);
                jv_free(a);
            }
        }
    }
    else if (!_stricmp(t, "bc")) {
        char* s = strtok_s(NULL, " \t", &ctx);
        if (s) {
            jval* a = jv_new(5);
            jv_put(a, "id", jv_num((double)atoi(s)));
            engine_cmd("del_bp", a);
            jv_free(a);
            refresh_bps();
        }
    }
    else if (!_stricmp(t, "bl")) { refresh_bps(); g_tab = 2; }
    else if (!_stricmp(t, "db")) {
        char* s = strtok_s(NULL, " \t", &ctx);
        if (s) {
            unsigned long long v = _strtoui64(s, NULL, 16);
            g_dump_base = v;
            refresh_dump(v);
        }
    }
    else if (!_stricmp(t, "e")) {   // e addr=bytes
        char* s = strtok_s(NULL, " \t", &ctx);
        if (s) {
            char* eq = strchr(s, '=');
            if (eq) {
                *eq = 0;
                unsigned long long v = _strtoui64(s, NULL, 16);
                jval* a = jv_new(5);
                jv_put(a, "addr", jv_num((double)v));
                jv_put(a, "hex", jv_str(eq + 1));
                engine_cmd("write_mem", a);
                jv_free(a);
                refresh_dump(g_dump_base);
            }
        }
    }
    else log_line("未知命令");
}

// ======================================================================
// 主循环
// ======================================================================
static void process_events(void) {
    for (;;) {
        EnterCriticalSection(&g_evt_lock);
        ui_event* e = g_events_head;
        if (e) { g_events_head = e->next; if (!g_events_head) g_events_tail = NULL; }
        LeaveCriticalSection(&g_evt_lock);
        if (!e) break;
        jval* o = e->obj;
        const char* ev = jv_s(o, "event", "");
        if (!strcmp(ev, "paused")) {
            log_line("[*] 已暂停");
            refresh_all_paused();
        }
        else if (!strcmp(ev, "resumed")) {
            g_paused = 0;
            sprintf_s(g_status, "Running");
        }
        else if (!strcmp(ev, "log")) {
            log_line(jv_s(o, "line", ""));
        }
        else if (!strcmp(ev, "exception")) {
            char b[128];
            sprintf_s(b, "[!] 异常 0x%llX @ %llX", jv_u(o, "code", 0), jv_u(o, "address", 0));
            log_line(b);
        }
        else if (!strcmp(ev, "engine_disconnected")) {
            log_line("[!] 引擎连接断开");
            sprintf_s(g_status, "Disconnected");
        }
        jv_free(o);
        free(e);
    }
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    InitializeCriticalSection(&g_pipe_lock);
    InitializeCriticalSection(&g_evt_lock);

    if (!ui_connect_pipe()) {
        MessageBoxW(NULL, L"无法连接引擎管道 \\\\.\\pipe\\guadbg\n请先启动 guadbg.exe <target.exe>",
            L"guadbg", MB_ICONERROR);
        return 1;
    }
    log_line("[*] 已连接 guadbg 引擎");
    engine_cmd("get_state", NULL);   // 预热

    if (!create_device()) return 1;

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = NULL;
    io.LogFilename = NULL;
    io.FontGlobalScale = 1.0f;

    ImGui_ImplWin32_Init(g_hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);
    apply_x64dbg_style();

    ImVec4 clear_color = ImVec4(0.94f, 0.94f, 0.94f, 1.0f);
    bool running = true;
    while (running) {
        MSG msg;
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            if (msg.message == WM_QUIT) running = false;
        }
        if (!running) break;

        process_events();

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        ImGuiViewport* vp = ImGui::GetMainViewport();
        ImGui::SetNextWindowPos(vp->WorkPos);
        ImGui::SetNextWindowSize(vp->WorkSize);
        ImGui::Begin("guadbg", NULL,
            ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
            ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus);

        // 菜单栏
        if (ImGui::BeginMenuBar()) {
            if (ImGui::BeginMenu("File")) {
                if (ImGui::MenuItem("刷新模块", "F5")) refresh_mods();
                if (ImGui::MenuItem("退出", "Alt+F4")) PostQuitMessage(0);
                ImGui::EndMenu();
            }
            if (ImGui::BeginMenu("Debug")) {
                if (ImGui::MenuItem("运行", "F9", false, g_paused)) engine_cmd("resume", NULL);
                if (ImGui::MenuItem("暂停", "F12", false, !g_paused)) engine_cmd("pause", NULL);
                ImGui::Separator();
                if (ImGui::MenuItem("步入", "F7", false, g_paused)) engine_cmd("step_into", NULL);
                if (ImGui::MenuItem("步过", "F8", false, g_paused)) engine_cmd("step_over", NULL);
                if (ImGui::MenuItem("步出", "Ctrl+F9", false, g_paused)) engine_cmd("step_out", NULL);
                if (ImGui::MenuItem("运行到", "F4", false, g_paused)) {
                    if (g_sel_addr) {
                        jval* a = jv_new(5);
                        jv_put(a, "addr", jv_num((double)g_sel_addr));
                        engine_cmd("run_to", a);
                        jv_free(a);
                    }
                }
                ImGui::EndMenu();
            }
            if (ImGui::BeginMenu("View")) {
                const char* tabs[] = { "CPU","Log","Breakpoints","Memory Map","Call Stack","Modules","Trace" };
                for (int i = 0; i < 7; i++)
                    if (ImGui::MenuItem(tabs[i])) g_tab = i;
                ImGui::EndMenu();
            }
            ImGui::EndMenuBar();
        }

        // 快捷键（输入框激活时不触发）
        if (!io.WantCaptureKeyboard) {
            if (ImGui::IsKeyPressed(ImGuiKey_F2)) { if (g_sel_addr) toggle_bp_at(g_sel_addr); refresh_bps(); refresh_disasm(g_dis_n ? g_dis[0].addr : g_rip); }
            if (ImGui::IsKeyPressed(ImGuiKey_F9) && g_paused) engine_cmd("resume", NULL);
            if (ImGui::IsKeyPressed(ImGuiKey_F12) && !g_paused) engine_cmd("pause", NULL);
            if (ImGui::IsKeyPressed(ImGuiKey_F7) && g_paused) engine_cmd("step_into", NULL);
            if (ImGui::IsKeyPressed(ImGuiKey_F8) && g_paused) engine_cmd("step_over", NULL);
            if (ImGui::IsKeyPressed(ImGuiKey_G) && io.KeyCtrl) g_goto_open = 1;
            if (ImGui::IsKeyPressed(ImGuiKey_Backspace) && g_tab == 0) {
                unsigned long long a;
                if (hist_pop(&a)) refresh_disasm(a);
            }
        }

        // 状态条
        ImGui::TextColored(g_paused ? COL_BP : ImVec4(0, 0.5f, 0, 1), "%s", g_status);
        ImGui::SameLine();
        ImGui::TextDisabled("| guadbg | x64dbg style");

        // 标签页
        ImGui::BeginTabBar("tabs");
        if (ImGui::BeginTabItem("CPU")) { g_tab = 0; ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Log")) { g_tab = 1; ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Breakpoints")) { g_tab = 2; ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Memory Map")) { g_tab = 3; ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Call Stack")) { g_tab = 4; ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Modules")) { g_tab = 5; ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Trace")) { g_tab = 6; ImGui::EndTabItem(); }
        ImGui::EndTabBar();

        float avail_h = ImGui::GetContentRegionAvail().y - 30;
        if (g_tab == 0) {
            float w = ImGui::GetContentRegionAvail().x;
            float dis_h = avail_h * 0.55f;
            float mid_h = avail_h - dis_h;
            draw_cpu_panel(w - 260, dis_h);
            ImGui::SameLine();
            draw_regs_panel(260, dis_h);
            draw_dump_panel((w - 260) * 0.55f, mid_h);
            ImGui::SameLine();
            draw_stack_panel((w - 260) * 0.45f, mid_h);
        }
        else if (g_tab == 1) draw_log_tab();
        else if (g_tab == 2) draw_bps_tab();
        else if (g_tab == 3) draw_map_tab();
        else if (g_tab == 4) draw_frames_tab();
        else if (g_tab == 5) draw_mods_tab();
        else if (g_tab == 6) draw_trace_tab();

        // 命令栏
        ImGui::Separator();
        ImGui::Text("Command:");
        ImGui::SameLine(90);
        ImGui::SetNextItemWidth(-1);
        if (ImGui::InputTextWithHint("##cmd", "go / pause / sti / sto / rtr / bp <addr> / bc <id> / db <addr> / e <addr>=<hex>",
            g_cmdbuf, sizeof(g_cmdbuf),
            ImGuiInputTextFlags_EnterReturnsTrue)) {
            log_line(g_cmdbuf);
            run_ui_command(g_cmdbuf);
            g_cmdbuf[0] = 0;
        }

        // 跳转弹窗
        if (g_goto_open) {
            ImGui::OpenPopup("Goto");
            g_goto_open = 0;
        }
        if (ImGui::BeginPopupModal("Goto", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
            ImGui::Text("地址 (hex):");
            ImGui::SameLine();
            ImGui::SetKeyboardFocusHere(0);
            bool enter = ImGui::InputText("##goto", g_goto_buf, sizeof(g_goto_buf),
                ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CharsHexadecimal);
            if (enter && g_goto_buf[0]) {
                unsigned long long v = _strtoui64(g_goto_buf, NULL, 16);
                hist_push(g_dis_n ? g_dis[0].addr : 0);
                refresh_disasm(v);
                g_goto_buf[0] = 0;
                ImGui::CloseCurrentPopup();
            }
            if (ImGui::Button("取消")) { g_goto_buf[0] = 0; ImGui::CloseCurrentPopup(); }
            ImGui::EndPopup();
        }

        // 寄存器编辑弹窗
        if (g_editreg_open) { ImGui::OpenPopup("EditReg"); g_editreg_open = 0; }
        if (ImGui::BeginPopupModal("EditReg", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
            ImGui::Text("%s =", g_editreg);
            ImGui::SameLine();
            char vb[32]; sprintf_s(vb, "%llX", g_editval);
            bool enter = ImGui::InputText("##reg", vb, sizeof(vb),
                ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CharsHexadecimal);
            if (enter) {
                jval* a = jv_new(5);
                char ln[8]; strncpy_s(ln, g_editreg, _TRUNCATE);
                for (char* p = ln; *p; p++) *p = (char)tolower(*p);
                jv_put(a, "name", jv_str(ln));
                jv_put(a, "value", jv_num((double)_strtoui64(vb, NULL, 16)));
                engine_cmd("set_reg", a);
                jv_free(a);
                refresh_regs();
                refresh_disasm(g_rip);
                ImGui::CloseCurrentPopup();
            }
            if (ImGui::Button("取消")) ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
        }

        // 内存编辑弹窗
        if (g_editmem_open) { ImGui::OpenPopup("EditMem"); g_editmem_open = 0; }
        if (ImGui::BeginPopupModal("EditMem", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
            ImGui::Text("%llX =", g_editmem_addr);
            ImGui::SameLine();
            static char mb[8] = "";
            bool enter = ImGui::InputText("##mem", mb, sizeof(mb),
                ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CharsHexadecimal);
            if (enter && mb[0]) {
                jval* a = jv_new(5);
                jv_put(a, "addr", jv_num((double)g_editmem_addr));
                jv_put(a, "hex", jv_str(mb));
                engine_cmd("write_mem", a);
                jv_free(a);
                refresh_dump(g_dump_base);
                mb[0] = 0;
                ImGui::CloseCurrentPopup();
            }
            if (ImGui::Button("取消")) ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
        }

        ImGui::End();

        ImGui::Render();
        const float clearc[4] = { clear_color.x, clear_color.y, clear_color.z, clear_color.w };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, NULL);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clearc);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_pSwapChain->Present(1, 0);
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    cleanup_device();
    DestroyWindow(g_hwnd);
    return 0;
}
