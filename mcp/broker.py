#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
guadbg MCP 桥（AI 用）—— stdio MCP 服务器。

协议拓扑：
    MCP 客户端（AI，stdio JSON-RPC，换行分隔）
        │  tools/list, tools/call
        ▼
    broker.py（本文件）
        │  命名管道  \\.\pipe\guadbg  （JSON 报文，ctypes 直连内核32）
        ▼
    guadbg 引擎（被调试进程内 VEH 调试器）

用法：
    在 MCP 客户端配置中注册：
        command: python broker.py
    环境变量 GUADBG_PIPE 可覆盖管道名。

引擎报文：
    请求  → {"id": N, "cmd": "<命令>", "args": {...}}
    响应  → {"id": N, "ok": true, "result": {...}}  或  {"id": N, "ok": false, "error": "..."}
    事件  → {"event": "paused"|"resumed"|"log"|"exception", ...}
"""
import ctypes
import json
import os
import sys
import threading
import time

PIPE_NAME = os.environ.get("GUADBG_PIPE", r"\\.\pipe\guadbg")

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_FLAG_OVERLAPPED = 0x40000000
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

kernel32 = ctypes.windll.kernel32
ReadFile = kernel32.ReadFile
WriteFile = kernel32.WriteFile
CreateFileW = kernel32.CreateFileW
WaitNamedPipeW = kernel32.WaitNamedPipeW
CloseHandle = kernel32.CloseHandle

ReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong,
                     ctypes.POINTER(ctypes.c_ulong), ctypes.c_void_p]
WriteFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong,
                      ctypes.POINTER(ctypes.c_ulong), ctypes.c_void_p]
CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong,
                        ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p]
CreateFileW.restype = ctypes.c_void_p   # 关键：默认 c_int 会截断 64 位句柄


class PipeError(Exception):
    pass


class EnginePipe:
    """到 guadbg 引擎的命名管道连接（消息模式，一读一条报文）。"""

    def __init__(self, name: str, timeout: float = 30.0):
        self.name = name
        self.pipe = None
        self.lock = threading.Lock()          # 串行化请求（引擎按序响应）
        self.rlock = threading.Lock()         # 保护读循环
        self.pending = {}                     # id -> Event/response
        self.events = []                      # 事件回调队列
        self.event_subscribers = []
        self._next_id = 1
        deadline = time.time() + timeout
        while True:
            h = CreateFileW(name, GENERIC_READ | GENERIC_WRITE,
                            0, None, OPEN_EXISTING, 0, None)
            if h and h != INVALID_HANDLE_VALUE:
                self.pipe = h
                break
            if time.time() > deadline:
                raise PipeError(
                    f"无法连接引擎管道 {name} —— 请先启动 guadbg.exe <target.exe>")
            WaitNamedPipeW(name, 500)
        self.reader = threading.Thread(target=self._read_loop, daemon=True)
        self.reader.start()

    def _read_loop(self):
        buf = ctypes.create_string_buffer(4 * 1024 * 1024)
        n = ctypes.c_ulong(0)
        while True:
            ok = ReadFile(self.pipe, buf, len(buf) - 1, ctypes.byref(n), None)
            if not ok or n.value == 0:
                self._notify_event({"event": "engine_disconnected"})
                return
            data = buf.raw[:n.value]
            # 客户端句柄默认字节读模式：一次 ReadFile 可能含多条 NUL 分隔报文
            for chunk in data.split(b"\x00"):
                if not chunk:
                    continue
                msg = chunk.decode("utf-8", "replace")
                try:
                    obj = json.loads(msg)
                except json.JSONDecodeError:
                    continue
                if "id" in obj and obj["id"] in self.pending:
                    ev = self.pending.pop(obj["id"])
                    ev["response"] = obj
                    ev["event"].set()
                else:
                    self._notify_event(obj)

    def _notify_event(self, obj):
        for cb in list(self.event_subscribers):
            try:
                cb(obj)
            except Exception:
                pass

    def on_event(self, cb):
        self.event_subscribers.append(cb)

    def call(self, cmd: str, args: dict = None, timeout: float = 30.0) -> dict:
        with self.lock:
            rid = self._next_id
            self._next_id += 1
            slot = {"event": threading.Event(), "response": None}
            self.pending[rid] = slot
            payload = json.dumps({"id": rid, "cmd": cmd, "args": args or {}}).encode("utf-8")
            w = ctypes.c_ulong(0)
            ok = WriteFile(self.pipe, payload, len(payload), ctypes.byref(w), None)
            if not ok:
                self.pending.pop(rid, None)
                raise PipeError("写入管道失败")
            if not slot["event"].wait(timeout):
                self.pending.pop(rid, None)
                raise PipeError(f"引擎响应超时 ({cmd})")
            resp = slot["response"]
            if not resp.get("ok"):
                raise PipeError(resp.get("error", "引擎错误"))
            return resp.get("result", {})

    def close(self):
        if self.pipe:
            CloseHandle(self.pipe)
            self.pipe = None


# ----------------------------------------------------------------------
# MCP 工具清单
# ----------------------------------------------------------------------
def T(name, desc, props=None, required=None):
    return {
        "name": name,
        "description": desc,
        "inputSchema": {
            "type": "object",
            "properties": props or {},
            "required": required or [],
        },
    }


ADDR = {"addr": {"type": "integer", "description": "地址（整数或 0x 形式；也接受符号名，仅部分工具）"}}
TID = {"tid": {"type": "integer", "description": "线程 ID"}}

TOOLS = [
    # ---- 进程控制 ----
    T("get_state", "获取调试状态（running/paused、暂停原因、当前 RIP）"),
    T("pause", "暂停目标进程（挂起全部线程）"),
    T("resume", "继续运行"),
    T("step_into", "单步步入（F7）"),
    T("step_over", "单步步过（F8，call 用临时断点跨过）"),
    T("step_out", "步出当前函数（F9 run till return）"),
    T("run_to", "运行到指定地址（一次性断点）", ADDR, ["addr"]),
    T("set_rip", "修改下一条执行地址（RIP）", ADDR, ["addr"]),
    T("terminate", "终止被调试进程", {"code": {"type": "integer"}}),
    # ---- 寄存器 ----
    T("get_regs", "读取当前暂停线程的全部寄存器与标志位"),
    T("set_reg", "修改寄存器（rax..r15/rip/rsp/rbp/eflags）",
      {"name": {"type": "string"}, "value": {"type": "integer"}}, ["name", "value"]),
    T("get_ctx", "读取任意线程上下文", TID, ["tid"]),
    T("set_thread_reg", "修改任意线程的寄存器",
      {"tid": {"type": "integer"}, "name": {"type": "string"}, "value": {"type": "integer"}},
      ["tid", "name", "value"]),
    T("list_threads", "线程列表（tid/rip/rsp/优先级/是否当前）"),
    T("suspend_thread", "挂起线程", TID, ["tid"]),
    T("resume_thread", "恢复线程", TID, ["tid"]),
    # ---- 内存 ----
    T("read_mem", "读取内存（hex 返回）",
      {"addr": {"type": "integer"}, "len": {"type": "integer"}}, ["addr"]),
    T("write_mem", "写入内存（hex 字符串）",
      {"addr": {"type": "integer"}, "hex": {"type": "string"}}, ["addr", "hex"]),
    T("fill_mem", "填充内存",
      {"addr": {"type": "integer"}, "len": {"type": "integer"}, "val": {"type": "integer"}},
      ["addr", "len", "val"]),
    T("mem_map", "内存映射列表（base/size/protect/type/映射文件）"),
    T("search_bytes", "字节模式搜索，支持 ?? 通配，如 \"48 8B ?? 00\"",
      {"pattern": {"type": "string"}, "start": {"type": "integer"}, "end": {"type": "integer"}},
      ["pattern"]),
    T("search_str", "字符串搜索（ASCII 或 Unicode）",
      {"s": {"type": "string"}, "unicode": {"type": "boolean"},
       "start": {"type": "integer"}, "end": {"type": "integer"}}, ["s"]),
    # ---- 反汇编 / 模块 / 栈 ----
    T("disasm", "反汇编（内置迷你 x64 反汇编器，含符号解析/注释/标签）",
      {"addr": {"type": "integer"}, "count": {"type": "integer"}}, ["addr"]),
    T("list_modules", "模块列表（base/size/path）"),
    T("exports", "模块导出表",
      {"module": {"type": "string", "description": "模块名，如 kernel32 或 test"}}),
    T("read_stack", "读取栈（RSP 起 count 个 qword，含符号解析）",
      {"count": {"type": "integer"}}),
    T("call_stack", "调用栈（RBP 链回溯 + 栈扫描候选返回地址）"),
    # ---- 断点 ----
    T("set_bp", "软件断点",
      {"addr": {"type": "integer"}, "cond": {"type": "string"},
       "log": {"type": "string"}, "once": {"type": "boolean"}, "silent": {"type": "boolean"}},
      ["addr"]),
    T("set_hw_bp", "硬件断点（执行/写入/读写，1/2/4/8 字节）",
      {"addr": {"type": "integer"}, "size": {"type": "integer"},
       "mode": {"type": "string", "enum": ["exec", "write", "read", "rw"]},
       "cond": {"type": "string"}}, ["addr"]),
    T("set_mem_bp", "内存断点（guard page，访问即触发）",
      {"addr": {"type": "integer"}, "size": {"type": "integer"}, "cond": {"type": "string"}},
      ["addr"]),
    T("del_bp", "删除断点", {"id": {"type": "integer"}}, ["id"]),
    T("toggle_bp", "启用/禁用断点",
      {"id": {"type": "integer"}, "enabled": {"type": "boolean"}}, ["id"]),
    T("list_bps", "断点列表（含命中次数/条件）"),
    # ---- 表达式 / 条件 ----
    T("eval", "求值条件表达式（寄存器/mem.valid/utf16/strstr/tid/$breakpointcounter）",
      {"expr": {"type": "string"}}, ["expr"]),
    # ---- 跟踪 ----
    T("start_trace", "条件跟踪（需先暂停；mode: 0=into 1=over；cond 满足即停；max 上限）",
      {"mode": {"type": "integer"}, "cond": {"type": "string"}, "max": {"type": "integer"}}),
    T("stop_trace", "停止跟踪并返回总条数"),
    T("get_trace", "读取跟踪记录（from 起 count 条，含指令/寄存器快照）",
      {"from": {"type": "integer"}, "count": {"type": "integer"}}),
    # ---- 补丁 ----
    T("set_patch", "打补丁（保存原始字节，可恢复）",
      {"addr": {"type": "integer"}, "hex": {"type": "string"}}, ["addr", "hex"]),
    T("list_patches", "补丁列表"),
    T("restore_patch", "恢复补丁原始字节", {"id": {"type": "integer"}}, ["id"]),
    # ---- 标记 ----
    T("set_label", "设置/删除标签（text 为空则删除）",
      {"addr": {"type": "integer"}, "text": {"type": "string"}}, ["addr"]),
    T("set_comment", "设置/删除注释",
      {"addr": {"type": "integer"}, "text": {"type": "string"}}, ["addr"]),
    T("set_bookmark", "设置/删除书签",
      {"addr": {"type": "integer"}, "text": {"type": "string"}}, ["addr"]),
    T("list_marks", "标记列表（kind: all/label/comment/bookmark）",
      {"kind": {"type": "string"}}),
    T("resolve_name", "符号名解析为地址",
      {"name": {"type": "string", "description": "标签、book!export 或裸导出名"}}, ["name"]),
    # ---- 日志 ----
    T("get_log", "调试日志（since 序号起增量拉取）", {"since": {"type": "integer"}}),
    T("clear_log", "清空日志"),
]

TOOL_MAP = {t["name"]: t for t in TOOLS}


class McpServer:
    def __init__(self, engine: EnginePipe):
        self.engine = engine
        self._stdin_buf = sys.stdin.buffer

    def _send(self, obj: dict):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8") + b"\n"
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()

    def _reply(self, rid, result):
        self._send({"jsonrpc": "2.0", "id": rid, "result": result})

    def _reply_err(self, rid, code, message):
        self._send({"jsonrpc": "2.0", "id": rid,
                    "error": {"code": code, "message": message}})

    def _notification(self, method, params):
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    def _call_tool(self, name, arguments):
        if name not in TOOL_MAP:
            raise PipeError(f"未知工具 {name}")
        args = dict(arguments or {})
        # 符号名解析友好：接受 addr 为字符串符号
        for key in ("addr", "start", "end"):
            v = args.get(key)
            if isinstance(v, str):
                r = self.engine.call("resolve_name", {"name": v})
                args[key] = int(r.get("addr", 0))
        return self.engine.call(name, args)

    def run(self):
        # 引擎事件 → MCP 通知（AI 客户端可借此感知暂停/恢复）
        def on_evt(obj):
            self._notification("notifications/guadbg/event", obj)

        self.engine.on_event(on_evt)

        while True:
            line = self._stdin_buf.readline()
            if not line:
                break
            try:
                msg = json.loads(line.decode("utf-8", "replace"))
            except json.JSONDecodeError:
                continue
            method = msg.get("method")
            rid = msg.get("id")
            if method == "initialize":
                self._reply(rid, {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "guadbg", "version": "1.0.0"},
                })
            elif method == "notifications/initialized":
                pass
            elif method == "ping":
                self._reply(rid, {})
            elif method == "tools/list":
                self._reply(rid, {"tools": TOOLS})
            elif method == "tools/call":
                params = msg.get("params") or {}
                name = params.get("name")
                try:
                    result = self._call_tool(name, params.get("arguments"))
                    self._reply(rid, {
                        "content": [{
                            "type": "text",
                            "text": json.dumps(result, ensure_ascii=False, indent=2),
                        }],
                        "isError": False,
                    })
                except PipeError as e:
                    self._reply(rid, {
                        "content": [{"type": "text", "text": str(e)}],
                        "isError": True,
                    })
                except Exception as e:  # noqa: BLE001
                    self._reply_err(rid, -32603, f"内部错误: {e}")
            else:
                if rid is not None:
                    self._reply_err(rid, -32601, f"未知方法 {method}")


def main():
    try:
        engine = EnginePipe(PIPE_NAME)
    except PipeError as e:
        # 按 MCP 惯例先等 initialize 再报错：直接打印到 stderr 并退出非零
        print(str(e), file=sys.stderr)
        sys.exit(2)
    srv = McpServer(engine)
    srv.run()


if __name__ == "__main__":
    main()
