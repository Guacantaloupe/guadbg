# guadbg —— 寄生线程架构上的进程内隐藏调试器（MCP + ImGui/DX11）

在 `PEL_ref.cpp`（寄生线程加载器）之上叠加完整的 VEH 调试引擎：
**不使用任何内核调试设施**（无 DebugActiveProcess / 无调试对象），
因此 `NtQueryInformationProcess(ProcessDebugPort/DebugFlags/ObjectHandle)`、
`PEB->BeingDebugged`、内核调用链等所有反调试探测全部呈现"未被调试"，
同时保留 PEL_ref 的全部映像伪装能力（PEB / Ldr / 进程映像路径）。

```
┌─────────────────────────────────────────────────────┐
│ guadbg.exe（寄生进程：对外伪装成 target.exe）          │
│                                                     │
│  target.exe（寄生线程，被调试者）                      │
│     │ int3 / 单步 / guard page / AV                  │
│     ▼                                               │
│  guadbg_core.cpp  VEH 引擎（断点/跟踪/表达式/补丁）   │
│     │ 命名管道 \\.\pipe\guadbg（JSON 报文）          │
└─────┼───────────────────────────────────────────────┘
      │
      ├─► mcp/broker.py  —— MCP stdio 服务器（给 AI 用）
      │     tools/list + tools/call，事件走 notification
      │
      └─► ui/guadbg_ui.exe —— Dear ImGui + DX11（x64dbg 风格界面）
```

## 构建

需要 Windows + VS（x64 Native Tools Command Prompt）：

```bat
git clone --depth 1 https://github.com/ocornut/imgui third_party\imgui
build.bat
```

- `guadbg.exe`：引擎（单文件，无第三方依赖）
- `guadbg_ui.exe`：界面（依赖 third_party/imgui）
- `test_client.exe`：管道 CLI 客户端（`test_client.exe <cmd> [json_args]`，调试/脚本用）

## 冒烟测试

```bat
_build_test.bat    :: 编 test_target.exe
_build_client.bat  :: 编 test_client.exe
python smoke_test.py
```

12 步端到端：入口系统断点 → 寄存器/反汇编/模块 → 单步 → 表达式 →
内存/寄存器写 → 软断点命中 → resume/pause → 日志/调用栈/补丁 → 硬件断点 → 终止。

注意：引擎的命名管道客户端必须是普通进程（如 test_client.exe / broker.py 所在
的 MCP 宿主）。若 python 运行在禁止命名管道的沙箱里（ERROR_INVALID_NAME），
`smoke_test.py` 经 test_client.exe 中转不受影响，broker.py 请在用户桌面的
MCP 客户端中加载。另：客户端管道句柄默认字节读模式，一次 ReadFile 可能返回
多条 NUL 分隔报文（test_client/broker/UI 均已按 NUL 切分处理）。

## 使用

```bat
guadbg.exe C:\path\target.exe        :: 引擎启动，目标停在入口（系统断点）
python mcp\broker.py                 :: AI 经 MCP 接入（stdio）
guadbg_ui.exe                        :: 原生界面（任意时刻可连/断开）
```

MCP 客户端配置示例（stdio）：

```json
{ "mcpServers": { "guadbg": { "command": "python", "args": ["C:\\…\\guadbg\\mcp\\broker.py"] } } }
```

## 功能映射（对照 22 类规格）

| 类别 | 状态 | 入口（MCP 工具 / 命令） |
|---|---|---|
| 1 进程管理 | ✅ | `pause` `resume` `step_into/over/out` `run_to` `set_rip` `terminate`（启动参数=guadbg 命令行） |
| 2 CPU 反汇编 | ✅ | `disasm`（迷你 x64 反汇编器，符号/注释/标签内联）、`resolve_name`、`list_marks` |
| 3 单步执行 | ✅ | `step_into/over/out`，call 用临时断点跨过，步出用返回地址断点 |
| 4 断点系统 | ✅ | `set_bp`（软件/条件/日志/一次性/静默）、`set_hw_bp`（执行/写/读写，1/2/4/8B，4 槽）、`set_mem_bp`（guard page）、`toggle_bp` `del_bp` `list_bps`（命中计数） |
| 5 条件表达式 | ✅ | `eval`：`RAX==1`、`mem.valid(RCX)`、`strstr(utf16(RCX),"foo")`、`$breakpointcounter==3`、`tid()==1C0`、全运算符/寄存器/符号 |
| 6 条件跟踪 | ✅ | `start_trace`（into/over、条件停止、max 上限）`get_trace`（指令+寄存器快照）`stop_trace` |
| 7 寄存器/CPU 状态 | ✅ | `get_regs`（全 GPR+标志位）`set_reg` `get_ctx` `set_thread_reg` `list_threads` |
| 8 内存/Dump | ✅ | `read_mem` `write_mem` `fill_mem` `mem_map`（映射文件）`search_bytes`（`??` 通配）`search_str`（ASCII/Unicode） |
| 9 栈/调用栈 | ✅ | `read_stack`（符号解析）`call_stack`（RBP 回溯 + 栈扫描候选） |
| 10 线程管理 | ✅ | `list_threads` `suspend_thread` `resume_thread` `set_thread_reg` |
| 11 模块/PE/符号 | ✅ | `list_modules` `exports`（导出表遍历） |
| 12 字符串/引用 | ✅ | `search_str` + 引用地址跳转（disasm 目标/符号） |
| 13 搜索/静态分析 | ✅ | `search_bytes` 通配模式 |
| 14 系统事件 | ◐ | 入口点系统断点（一次性，启动即停）；线程/DLL 事件见"限制" |
| 15 异常处理 | ✅ | VEH 首过暂停：AV/除零/非法指令/栈溢出；C++ 异常(0xE06D7363)透传 |
| 16 注释/标签/书签 | ✅ | `set_label` `set_comment` `set_bookmark` `get_mark` `list_marks` |
| 17 补丁 | ✅ | `set_patch`（自动存原始字节）`list_patches` `restore_patch` |
| 18 脚本自动化 | ✅（经 AI） | MCP 工具组合即脚本；条件断点 log 字段支持命中日志 |
| 19 日志 | ✅ | `get_log`（seq 增量拉取）`clear_log`；UI Log 页实时滚动 |
| 20 界面窗口 | ✅ | ImGui/DX11：CPU（反汇编+寄存器+Dump+栈）、Log、Breakpoints、Memory Map、Call Stack、Modules、Trace |
| 21 插件扩展 | ✅（经 AI/MCP） | broker.py 的 TOOLS 表即扩展点 |
| 22 文件/会话 | ○ | 会话持久化未实现（标记/补丁在进程生命周期内有效） |

## 隐藏性设计（关键）

1. **零内核调试痕迹**：全程 VEH（`AddVectoredExceptionHandler`），不创建调试对象 →
   `ProcessDebugPort` / `ProcessDebugFlags` / `DebugObjectHandle` 全零，`BeingDebugged=0`。
2. **手动暂停用 `SuspendThread`** 而非调试器挂起，内核无调试关联。
3. **PEL_ref 映像伪装原样保留**：PEB `ImageBaseAddress`/`ProcessParameters` 指向目标；
   `kernel32!QueryFullProcessImageNameW` / `K32GetProcessImageFileNameW` 两个 FF25
   转发 stub 钩子使进程映像路径查询返回目标路径（不发起系统调用）。
4. **补丁落点约束**：只偷 ≥5 字节完整指令，12 字节补丁窗口必须全为 CC/90 填充；
   `kernelbase/ntdll` 零改动（磁盘 stub 基线校验全过）。
5. **软件断点即 0xCC + VEH**，与正常代码路径无差异；条件不命中走
   恢复原字节→单步→重打 CC，不停顿、无痕迹。

## 已知限制（研究级实现）

- **硬件断点按线程生效**：Dr 寄存器应用到创建时已知的全部线程；目标新建线程
  不会自动继承（可在引擎里加线程创建通知补齐）。
- **运行中设置软件断点**采用"挂起全部线程→写字节→恢复"，存在理论上的竞态窗口
  （生产级应改 APC/原子写）。
- **手动暂停**抓取的是任意指令边界（非内核调试器的线程安全点）。
- **DLL 加载/线程创建/系统断点**中的后两者未实现（入口点系统断点已提供；
  DLL 事件可用 Ldr 轮询扩展）。
- 迷你反汇编器覆盖 MSVC 常见指令子集，未识别指令回退 `db 0x..`（可替换为 Zydis/capstone）。
- 跟踪缓冲 65536 条环形；搜索命中上限 512；内存读取单命令上限 64KB。

## 协议（管道报文）

```
请求  → {"id":N,"cmd":"<命令>","args":{...}}
响应  → {"id":N,"ok":true,"result":{...}} | {"id":N,"ok":false,"error":"..."}
事件  → {"event":"paused"|"resumed"|"log"|"exception", ...}
```

命令全集即上表 MCP 工具名（引擎命令与 MCP 工具一一对应）。

## 工程注记（联调中修复的关键点）

- **跳板池节区**：MSVC 14.44 的 `#pragma section(name, read, write, execute)` 会
  丢弃 write 属性（C4330，节标志落成 Execute-Read），运行时
  `VirtualProtect(gua_tram, ..., PAGE_EXECUTE_READWRITE)` 补齐。
- **int3 的 Rip 语义**：本机（Windows 11 24H2）投递的 CONTEXT.Rip 指向 0xCC
  本身而非下一条指令，VEH 断点分支按"Rip 处是否为 CC"自适应判定断点地址。
- **暂停/恢复**：`suspend_all` 必须跳过发起方线程与全部引擎管道线程（它们可能
  正持有 cli_lock 等引擎锁，挂起即死锁）；`resume_all` 合并挂起期间新设置的
  Dr0-3/Dr7，避免硬件断点被旧上下文快照抹掉。
- **单步暂停路径**：VEH 单步分支里 `pause_here` 返回的命令码必须像
  `resume_after_bp` 一样处理（置 TF/临时断点），否则连续第二次单步退化为继续运行。
