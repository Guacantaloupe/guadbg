# -*- coding: utf-8 -*-
"""看目标有没有弹出那个模态对话框 —— 这是第 141 轮之前**所有仪器都看不见**的东西。

为什么需要它
    第 141 轮才发现：目标每次运行到约 16 秒都会弹出一个 #32770 模态对话框（标题 Sky、
    带「确定」按钮），然后停在那里不再执行任何东西。而之前四轮我一直用"页访问"和
    "断点命中"来判断目标是否在跑 —— 一个模态对话框对这两样仪器**都是隐形的**：
    游戏停住时页面当然不再被访问，于是我把"卡在对话框上"读成了"那段代码没被用到"。

所以这个探针存在的意义是当**对照**：任何一次运行时实验都应该顺便报告它。

用法
    python tools/probe_sky_dialog.py --secs 40
    （引擎的诊断开关通过环境变量传入，本探针会原样继承，例如
      $env:GUADBG_SKIP_IAT='1'; python tools/probe_sky_dialog.py）

判据
    * `对话框出现` → 这次运行时实验里目标**没有真正在跑**，任何"零命中/零访问"都不成立；
    * `窗口期内没有对话框` → 目标至少在跑，测量才有意义。
"""
import ctypes
import json
import os
import subprocess
import sys
import time
from ctypes import wintypes

sys.stdout.reconfigure(encoding="utf-8")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT = os.path.join(ROOT, "test_client.exe")
ENGINE = os.path.join(ROOT, "guadbg.exe")
SKY = os.environ.get(
    "SKY_EXE",
    r"C:\Program Files (x86)\Steam\steamapps\common\Sky Children of the Light\Sky.exe")
OUT = os.path.join(ROOT, "out_sky_dialog.json")

user32 = ctypes.WinDLL("user32", use_last_error=True)
WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
user32.EnumWindows.argtypes = [WNDENUMPROC, wintypes.LPARAM]
user32.EnumChildWindows.argtypes = [wintypes.HWND, WNDENUMPROC, wintypes.LPARAM]
user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]

problems = []


def call(cmd, args=None, timeout=60):
    p = subprocess.run([CLIENT, cmd, json.dumps(args or {})],
                       capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=timeout)
    line = p.stdout.strip().splitlines()[0] if p.stdout.strip() else ""
    if p.returncode != 0 or not line:
        return {}
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        problems.append("%s: 非 JSON %r" % (cmd, line[:120]))
        return {}


def windows_of(pid):
    """返回该进程所有顶层窗口：(类名, 标题, [(子类名, 子文本), ...])"""
    out = []

    def cb(h, _l):
        p = wintypes.DWORD()
        user32.GetWindowThreadProcessId(h, ctypes.byref(p))
        if p.value == pid:
            cls = ctypes.create_unicode_buffer(256)
            user32.GetClassNameW(h, cls, 256)
            txt = ctypes.create_unicode_buffer(512)
            user32.GetWindowTextW(h, txt, 512)
            kids = []

            def cb2(ch, _l2):
                c2 = ctypes.create_unicode_buffer(256)
                user32.GetClassNameW(ch, c2, 256)
                t2 = ctypes.create_unicode_buffer(2048)
                user32.GetWindowTextW(ch, t2, 2048)
                kids.append([c2.value, t2.value])
                return True

            user32.EnumChildWindows(h, WNDENUMPROC(cb2), 0)
            out.append([cls.value, txt.value, kids])
        return True

    user32.EnumWindows(WNDENUMPROC(cb), 0)
    return out


def is_dialog(w):
    """我们要找的是那个模态对话框：#32770，标题 Sky。"""
    cls, txt, kids = w
    if cls == "#32770":
        return True
    if txt == "Sky" and any(k[0] == "Button" for k in kids):
        return True
    return False


def as_int(v):
    return v if isinstance(v, int) else int(str(v).strip(), 16)


def is_return_address(addr, mods):
    """这个值像不像「某条 call 的下一条指令」？

    为什么要验证：栈上绝大多数值不是返回地址（局部变量、指针、参数都会混进来）。
    只有"前面几字节里能解出一条 call、而且那条 call 正好**结束**在这个地址"的值，
    才真的是调用点。做法：读它前面 24 字节，从每个可能的起点(1..15)试着反汇编一条指令。
    """
    mo = None
    for m in mods:
        b = as_int(m.get("base", 0))
        sz = as_int(m.get("size", 0))
        if b and sz and b <= addr < b + sz:
            mo = m
            break
    if mo is None:
        return False
    start = addr - 24
    m = call("read_mem", {"addr": start, "len": 32}).get("result", {})
    hx = str(m.get("hex", "")).replace(" ", "")
    if len(hx) < 64:
        return False
    raw = bytes.fromhex(hx)
    try:
        import capstone
    except Exception:
        return False
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    # 起点要一直试到 24：一条 `call rel32` 是 **5 字节**，若返回地址在 addr、call 就在 addr-5，
    # 对应 start=addr-24 时的 off=19 —— 第 166 轮我只试到 15，于是**真返回地址全被判成"不是"**。
    for off in range(1, 25):
        try:
            it = next(md.disasm(raw[off:off + 15], start + off))
        except Exception:
            continue
        if it.mnemonic == "call" and it.address + it.size == addr:
            return True
    return False


def print_stack_chain(regs, mods, nbytes):
    """从 rsp 往上扫，只打印**验证过**的返回地址 —— 也就是调用链。

    第 165 轮第一次跑：`[rsp]=0`、整个 0x600 窗口里**一个验证过的返回地址都没有**。
    这有两种可能：① rsp 不是"帧顶"（引擎报的寄存器可能不是我们以为的那个）；
    ② 栈被保护层打乱过（有些壳会加密栈上的返回地址）。
    所以这里改成：**从 rsp-0x200 开始**扫 nbytes 字节，并在找不到时打印原始字节 —— 让数据自己说话。
    """
    rsp = as_int(regs.get("rsp", 0))
    if not rsp:
        print("          （拿不到 rsp，跳过调用链扫描）")
        return []
    start = rsp - 0x200
    print("          —— 调用链：从 %#x（rsp-0x200）往上扫 %#x 字节，只列**验证过的返回地址** ——"
          % (start, nbytes))
    chain = []
    dumped = False
    step = 0x100
    off = 0
    while off < nbytes:
        n = min(step, nbytes - off)
        m = call("read_mem", {"addr": start + off, "len": n}).get("result", {})
        hx = str(m.get("hex", "")).replace(" ", "")
        if len(hx) < 32:
            off += n
            continue
        raw = bytes.fromhex(hx)
        if not dumped:
            dumped = True
            print("            原始字节（开头 0x80）: %s" % raw[:0x80].hex())
        for i in range(0, len(raw) - 7, 8):
            q = int.from_bytes(raw[i:i + 8], "little")
            if not q:
                continue
            w = where(q, mods)
            if not w:
                continue
            if is_return_address(q, mods):
                chain.append((start + off + i, q, w))
        off += n
    for slot, q, w in chain:
        print("            [+%#05x 相对 rsp] %#x  %s   ← **返回地址**" % (slot - rsp, q, w))
    if not chain:
        print("            （这一窗口里没有验证过的返回地址）")
    return chain


def where(addr, mods):
    """把地址标成「模块+偏移」。"""
    for mo in mods:
        b = as_int(mo.get("base", 0))
        sz = as_int(mo.get("size", 0))
        if b and sz and b <= addr < b + sz:
            return "%s+%#x" % (mo.get("name"), addr - b)
    return None


def read_wstr(addr, maxbytes=0x400):
    """读一段 UTF-16LE 字符串（到第一个 NUL 为止）。返回 (原文, 字节数, 错误)。"""
    if not addr:
        return None, 0, "地址为 0"
    m = call("read_mem", {"addr": addr, "len": maxbytes}).get("result", {})
    if m.get("error") is not None:
        return None, 0, str(m.get("error"))
    hx = str(m.get("hex", "")).replace(" ", "")
    got = m.get("len")
    if not hx:
        return None, 0, "读回空"
    raw = bytes.fromhex(hx)
    end = None
    for i in range(0, len(raw) - 1, 2):
        if raw[i] == 0 and raw[i + 1] == 0:
            end = i
            break
    body = raw[:end] if end is not None else raw
    try:
        s = body.decode("utf-16-le", errors="replace")
    except Exception as ex:
        return None, len(raw), "解码失败 %s" % ex
    return s, len(body), ("len=%s" % got)


def dump_wstrings(center, span=0x4000, minlen=6, chunk=0x800):
    """把 center 附近 span 字节里的 UTF-16 串都找出来，返回 [(相对 center 的偏移, 原文)]。

    动机：第 145 轮发现那句话是**运行时在堆上拼出来**的。既然是一次拼出来的，
    附近很可能还有同一批的其它串（它在比较哪个文件、哪一段失败、格式串等）——
    那是最可能直接告诉"它在查什么"的东西。
    """
    start = center - span // 2
    raw = bytearray()
    off = 0
    while off < span:
        n = min(chunk, span - off)
        m = call("read_mem", {"addr": start + off, "len": n}).get("result", {})
        hx = str(m.get("hex", "")).replace(" ", "")
        if not hx:
            break
        raw.extend(bytes.fromhex(hx))
        off += len(hx) // 2
        if len(hx) // 2 < n:
            break
    out = []
    i = 0
    while i + 1 < len(raw):
        j = i
        chars = []
        while j + 1 < len(raw):
            cp = raw[j] | (raw[j + 1] << 8)
            if 32 <= cp < 0x7F or cp in (0x09, 0x0A, 0x0D) or 0x4E00 <= cp <= 0x9FFF:
                chars.append(chr(cp))
                j += 2
            else:
                break
        if len(chars) >= minlen:
            out.append((start + i - center, "".join(chars)))
            i = j
        else:
            i += 2
    return out


def read_u64(addr):
    m = call("read_mem", {"addr": addr, "len": 8}).get("result", {})
    hx = str(m.get("hex", "")).replace(" ", "")
    if len(hx) != 16:
        return None
    return int.from_bytes(bytes.fromhex(hx), "little")


def path_from_hit(bpname, regs):
    """从命中时的寄存器里取出被打开的文件路径。

    CreateFileW(lpFileName, ...)               → rcx 是 UTF-16 路径
    NtCreateFile(..., POBJECT_ATTRIBUTES, ...) → r8 是 OBJECT_ATTRIBUTES*，
        其中 ObjectName 在 +0x10；UNICODE_STRING 的 Buffer 在 +0x8、Length(字节) 在 +0x0。
    """
    if bpname.endswith("CreateFileW"):
        p = as_int(regs.get("rcx", 0))
        s, _nb, _note = read_wstr(p)
        return s
    if bpname.endswith("NtCreateFile"):
        oa = as_int(regs.get("r8", 0))
        us = read_u64(oa + 0x10)
        if not us:
            return None
        ln = read_u64(us)          # 低 2 字节是 Length（字节数）
        buf = read_u64(us + 0x8)
        if not buf:
            return None
        n = (ln & 0xFFFF) if ln else 0x200
        n = max(2, min(n, 0x400))
        m = call("read_mem", {"addr": buf, "len": n}).get("result", {})
        hx = str(m.get("hex", "")).replace(" ", "")
        if not hx:
            return None
        return bytes.fromhex(hx).decode("utf-16-le", errors="replace")
    return None


def main():
    secs = 40.0
    if "--secs" in sys.argv:
        secs = float(sys.argv[sys.argv.index("--secs") + 1])
    # 轮询间隔同时**就是**目标每次命中断点后被停住的时长 —— 所以它直接决定插桩的扰动大小。
    # 默认 1.5 秒太粗：文件访问可能几十次，每次停 1.5 秒足以让目标的行为整个变形。
    poll = 1.5
    if "--poll" in sys.argv:
        poll = float(sys.argv[sys.argv.index("--poll") + 1])
    # --del-after N：某个断点命中 N 次之后就把它删掉，让目标自由跑。
    # 用途：拿一个**与检查无关**的函数当对照 —— 只挨几次陷阱，
    # 这样"被拖慢"与"这个调用被停过"两件事就不会混在一起。
    del_after = 0
    if "--del-after" in sys.argv:
        del_after = int(sys.argv[sys.argv.index("--del-after") + 1])
    # --read-at <addr>:<len>（可重复）：**每次暂停时**把这几处内存读出来。
    #
    # 用途：崩溃暂停时顺手看几个全局 —— 例如 CRT 的 per-thread 数据 TLS 索引、
    # 以及两个候选锁对象。若索引是无效值（0 或 0xFFFFFFFF）或锁对象全零，
    # 就能直接说"该初始化它的那一步没跑"，而不是继续猜。
    read_at = []
    stack_chain = 0
    log_bps = set()
    log_since = 0
    threads_at = []
    thread_walk = 0x200
    if "--thread-walk" in sys.argv:
        i = sys.argv.index("--thread-walk")
        thread_walk = int(sys.argv[i + 1], 0) if i + 1 < len(sys.argv) else 0x200
    if "--threads-at" in sys.argv:
        i = sys.argv.index("--threads-at")
        # 支持**多个时刻**（逗号分隔，如 8,18）：用两次快照区分"短暂竞争"与"一直不放"
        if i + 1 < len(sys.argv):
            threads_at = [float(x) for x in sys.argv[i + 1].split(",") if x.strip()]
    if "--stack-chain" in sys.argv:
        i = sys.argv.index("--stack-chain")
        stack_chain = int(sys.argv[i + 1], 0) if (i + 1 < len(sys.argv)
                                                  and not sys.argv[i + 1].startswith("--")) else 0x400
    for i, a0 in enumerate(sys.argv):
        if a0 == "--read-at" and i + 1 < len(sys.argv) and not sys.argv[i + 1].startswith("--"):
            spec = sys.argv[i + 1]
            if ":" in spec:
                a_s, l_s = spec.split(":", 1)
                read_at.append((int(a_s, 0), int(l_s, 0)))
            else:
                read_at.append((int(spec, 0), 8))

    switches = {k: v for k, v in os.environ.items()
                if k.startswith("GUADBG_SKIP_")}
    print("  引擎诊断开关: %s" % (switches if switches else "（无，这是基线）"))

    log = open(os.path.join(ROOT, "probe_dialog_engine.log"), "w", encoding="utf-8")
    eng = subprocess.Popen([ENGINE, SKY], stdout=log, stderr=subprocess.STDOUT)
    result = {"switches": switches, "secs": secs}
    try:
        time.sleep(8.0)
        st = call("get_state").get("result", {})
        print("  入口暂停: state=%s" % st.get("state"))
        if st.get("state") != "paused":
            problems.append("没停在入口: %r" % st.get("state"))
            for p in problems:
                print("    - %s" % p)
            return 1
        # --fix-prot：放行之前，把我们留下的两处"放宽的写权限"恢复成加载器的值。
        #
        # 依据第 143 轮的逐段对照：正常装载下 .idata 是 WC、.sky[1] 入口页是 WCX，
        # 而我们这边分别是 RW 与 RWX（入口页那处来自引擎每次都要下的 0xCC 系统断点）。
        # WCX 本来就是写时复制、允许写，所以写 0xCC 并不需要把页放宽成 RWX。
        # 这次实验就是用 set_prot 把这两页先恢复，再放行，看对话框还在不在。
        if "--fix-prot" in sys.argv:
            for a, sz, pr, label in ((0x142B60000, 0x1000, 0x08, ".idata -> WC"),
                                     (0x142B64000, 0x1000, 0x80, "入口页 -> WCX")):
                r = call("set_prot", {"addr": a, "size": sz, "protect": pr}).get("result", {})
                old = r.get("old_protect")
                print("    set_prot %#x（%s）: 旧值=%s%s"
                      % (a, label,
                         ("%#x" % int(old)) if isinstance(old, (int, float)) else "?",
                         "" if r.get("error") is None else "  **失败: %s**" % r.get("error")))

        # --hw-msgbox：在 user32 的三个 MessageBox 出口上挂**硬件执行**断点（不改一个字节）。
        #
        # 这是第 144 轮的正路：不再猜"关掉哪一步能躲过检查"，而是**直接抓做决定的那段代码** ——
        # 它要弹框就必然经过 MessageBoxW / MessageBoxA / MessageBoxIndirectW 之一，
        # 命中时的返回地址就是"判定游戏文件已损坏"的调用点（第 139 轮修好 Dr 之后才可行）。
        # 模块表**总是**取：这样连"异常暂停"的 rip 也能被解析成 模块+偏移。
        # （第 149 轮那次崩溃只报了一个裸地址 0x7ff79a5fc040，看不出属于谁。）
        mods = call("list_modules").get("result", {}).get("modules", []) or []
        if "--hw-msgbox" in sys.argv or "--hw-candidates" in sys.argv:
            # --hw-candidates：三个 MessageBox 出口**没有命中**（第 144 轮实测），说明这个对话框
            # 不是由它们创建的。所以改堵"任何窗口都得经过"的那几个咽喉：
            #   ntdll!NtRaiseHardError      —— 系统硬错误对话框就是 #32770 带确定按钮（很像）
            #   user32!MessageBoxTimeoutW   —— 未文档化的 MessageBox 变体
            #   user32!SoftModalMessageBox  —— user32 内部弹框
            #   win32u!NtUserCreateWindowEx —— **所有**窗口创建的系统调用入口
            if "--hw-candidates" in sys.argv:
                want = [("ntdll.dll", ["NtRaiseHardError"]),
                        ("user32.dll", ["MessageBoxTimeoutW", "SoftModalMessageBox"]),
                        ("win32u.dll", ["NtUserCreateWindowEx"])]
            else:
                want = [("user32.dll", ["MessageBoxW", "MessageBoxA", "MessageBoxIndirectW"])]
            mods = call("list_modules").get("result", {}).get("modules", []) or []
            for mod, names in want:
                ex = call("exports", {"module": mod}).get("result", {})
                byname = {str(e.get("name", "")): e for e in (ex.get("exports") or [])
                          if e.get("name")}
                if not byname:
                    print("    %s 取不到导出表（err=%s）" % (mod, ex.get("error")))
                    continue
                for nm in names:
                    e = byname.get(nm)
                    if not e:
                        print("    %s 没有导出 %s" % (mod, nm))
                        continue
                    a = as_int(e.get("addr", e.get("address", 0)))
                    r = call("set_hw_bp", {"addr": a, "size": 1, "mode": "execute"}).get("result", {})
                    print("    硬件执行断点 %s!%s @ %#x -> %s"
                          % (mod, nm, a, "id=%s" % r.get("id") if r.get("id") is not None
                             else "**失败: %s**" % r.get("error")))

        # --hw-file：抓**输入** —— 它到底在读哪些文件。
        #
        # 动机：第 145 轮拿到了它"说什么"（那句解密后的原文，堆上拼出来的），但那只是结论。
        # 要知道它在查什么，就得看它**读了什么**：若在校验磁盘文件，就会看到一串打开路径，
        # 以及"哪一个之后紧接着弹了框"；若一个文件都没开，那它校验的是内存/映像 —— 同样是收获。
        bpname = {}
        bpid = {}
        hitcount = {}
        if "--hw-file" in sys.argv:
            if not mods:
                mods = call("list_modules").get("result", {}).get("modules", []) or []
            for mod, nm in (("kernelbase.dll", "CreateFileW"),
                            ("ntdll.dll", "NtCreateFile")):
                ex = call("exports", {"module": mod}).get("result", {})
                byname = {str(e.get("name", "")): e for e in (ex.get("exports") or [])
                          if e.get("name")}
                e = byname.get(nm)
                if not e:
                    print("    %s 没有导出 %s" % (mod, nm))
                    continue
                a = as_int(e.get("addr", e.get("address", 0)))
                r = call("set_hw_bp", {"addr": a, "size": 1, "mode": "execute"}).get("result", {})
                print("    硬件执行断点 %s!%s @ %#x -> %s"
                      % (mod, nm, a, "id=%s" % r.get("id") if r.get("id") is not None
                         else "**失败: %s**" % r.get("error")))
                if r.get("id") is not None:
                    bpname[a] = "%s!%s" % (mod, nm)
                    bpid[a] = r.get("id")

        # --hw-one <模块!函数>（可重复多次）：每个都挂一个。
        # 把"哪一个陷阱"与"任何陷阱"分开；也用来同时观察"取路径的 API"与"打开文件的 API"的先后。
        for i, a0 in enumerate(sys.argv):
            if a0 != "--hw-one" or i + 1 >= len(sys.argv):
                continue
            spec = sys.argv[i + 1]
            if spec.startswith("--"):
                continue
            mod, _sep, nm = spec.partition("!")
            if not _sep:
                # **必须吵**：第 161 轮我把裸地址传给了 --hw-one，它去"查模块 0x141d7ab48 的导出"，
                # 结果什么都没挂上，而报错行又被我自己的输出过滤器吃掉了 —— 白跑一次。
                print("    **--hw-one 需要『模块!函数』格式，收到的是 %r；"
                      "裸地址请用 --hw-exec-addr**" % spec)
                problems.append("--hw-one 格式错: %r" % spec)
                continue
            if not mods:
                mods = call("list_modules").get("result", {}).get("modules", []) or []
            ex = call("exports", {"module": mod}).get("result", {})
            byname = {str(e.get("name", "")): e for e in (ex.get("exports") or [])
                      if e.get("name")}
            e = byname.get(nm)
            if not e:
                print("    %s 没有导出 %s" % (mod, nm))
                continue
            a = as_int(e.get("addr", e.get("address", 0)))
            r = call("set_hw_bp", {"addr": a, "size": 1, "mode": "execute"}).get("result", {})
            print("    硬件执行断点 %s!%s @ %#x -> %s"
                  % (mod, nm, a, "id=%s" % r.get("id") if r.get("id") is not None
                     else "**失败: %s**" % r.get("error")))
            if r.get("id") is not None:
                bpname[a] = "%s!%s" % (mod, nm)
                bpid[a] = r.get("id")

        # --hw-rw <addr>（可重复）：在给定地址挂**读写**断点（Dr 的 mode=rw）。
        #
        # 用途：第 154 轮证明"线性反汇编答不了'谁读了 .sky[1] 里那张 .pdata 副本表'"
        # （混淆代码跳进指令中间，97% 覆盖率全是垃圾解码）。于是改问运行时：
        # 在那张表的几个位置上挂读写断点，命中时的**返回地址**就是读它的代码。
        # 注意 x86 的 Dr 没有"只读"这一档：RW=11 是读或写，所以写也会命中（表一般是只读的）。
        for i, a0 in enumerate(sys.argv):
            if a0 != "--hw-rw" or i + 1 >= len(sys.argv):
                continue
            spec = sys.argv[i + 1]
            if spec.startswith("--"):
                continue
            a = int(spec, 0)
            if not mods:
                mods = call("list_modules").get("result", {}).get("modules", []) or []
            r = call("set_hw_bp", {"addr": a, "size": 8, "mode": "rw"}).get("result", {})
            print("    硬件读写断点 @ %#x -> %s"
                  % (a, "id=%s" % r.get("id") if r.get("id") is not None
                     else "**失败: %s**" % r.get("error")))
            if r.get("id") is not None:
                bpname[a] = "rw@%#x" % a
                bpid[a] = r.get("id")

        # --hw-exec-addr <addr>（可重复）：在**裸地址**上挂硬件执行断点。
        # 有了它才能问"这段代码到底有没有被执行"（例如 CRT 启动 0x141d7ab48）——
        # 这类地址不属于任何可解析的"模块!函数"，所以 --hw-one 用不了。
        for i, a0 in enumerate(sys.argv):
            if a0 != "--hw-exec-addr" or i + 1 >= len(sys.argv):
                continue
            spec = sys.argv[i + 1]
            if spec.startswith("--"):
                continue
            a = int(spec, 0)
            if not mods:
                mods = call("list_modules").get("result", {}).get("modules", []) or []
            r = call("set_hw_bp", {"addr": a, "size": 1, "mode": "execute"}).get("result", {})
            print("    硬件执行断点（裸地址）@ %#x -> %s"
                  % (a, "id=%s" % r.get("id") if r.get("id") is not None
                     else "**失败: %s**" % r.get("error")))
            if r.get("id") is not None:
                bpname[a] = "exec@%#x" % a
                bpid[a] = r.get("id")
            else:
                problems.append("set_hw_bp(裸地址) 失败 @ %#x: %s" % (a, r.get("error")))

        # --sw-bp <addr>（可重复）：挂**软件**断点（写 0xCC）。
        #
        # 为什么此时该用它：硬件执行断点只有 4 个槽，而且第 141/144/161 轮都看到
        # "同一地址重复命中、寄存器一模一样" —— 那更像目标**没跨过那条指令**。
        # 而软件断点这条路在本项目里一直是能"停一次、继续跑"的（第 136 轮起多次验证），
        # 且 MAX_BP=256，可以一次把整条调用链都挂上。
        # 代价：它改字节（0xCC），所以在会被完整性检查盯上的配置里可能被抹掉 —— 那也算信息。
        for i, a0 in enumerate(sys.argv):
            if a0 != "--sw-bp" or i + 1 >= len(sys.argv):
                continue
            spec = sys.argv[i + 1]
            if spec.startswith("--"):
                continue
            # 支持 "地址@条件"：第 165 轮用它只在**传 NULL** 的那次调用上停下 ——
            # 否则 EnterCriticalSection 太热，会在崩溃之前就被打爆。
            # （先拆 '@' 再 int()；第 165 轮我把顺序写反了，直接 ValueError 崩在启动阶段。）
            cond = None
            a_s = spec
            if "@" in spec:
                a_s, _at, cond = spec.partition("@")
            a = int(a_s, 0)
            if not mods:
                mods = call("list_modules").get("result", {}).get("modules", []) or []
            args_bp = {"addr": a}
            if cond:
                args_bp["cond"] = cond
            r = call("set_bp", args_bp).get("result", {})
            if r.get("error") is None and r.get("id") is not None:
                print("    软件断点 @ %#x%s -> id=%s"
                      % (a, ("  条件: %s" % cond) if cond else "", r.get("id")))
                bpname[a] = "sw@%#x" % a
                bpid[a] = r.get("id")
            else:
                print("    软件断点 @ %#x **失败: %s**" % (a, r.get("error")))
                problems.append("set_bp 失败 @ %#x: %s" % (a, r.get("error")))

        # --sw-bp-log <地址[@条件]>（可重复）：**日志型**断点（set_bp 的 log 模式）。
        #
        # 为什么需要：第 165 轮证明，在热函数（EnterCriticalSection 的 thunk）上挂**会停下**的
        # 条件断点，会把引擎自己打死（code=0x80000004=STATUS_SINGLE_STEP）。
        # 日志型不停下、只记录，正是为这种"必须观测但不能打断"的场合准备的。
        for i, a0 in enumerate(sys.argv):
            if a0 != "--sw-bp-log" or i + 1 >= len(sys.argv):
                continue
            spec = sys.argv[i + 1]
            if spec.startswith("--"):
                continue
            cond = None
            a_s = spec
            if "@" in spec:
                a_s, _at, cond = spec.partition("@")
            a = int(a_s, 0)
            if not mods:
                mods = call("list_modules").get("result", {}).get("modules", []) or []
            args_bp = {"addr": a, "log": 1}
            if cond:
                args_bp["cond"] = cond
            r = call("set_bp", args_bp).get("result", {})
            if r.get("error") is None and r.get("id") is not None:
                print("    **日志型**断点 @ %#x%s -> id=%s（不停下，只记录）"
                      % (a, ("  条件: %s" % cond) if cond else "", r.get("id")))
                log_bps.add(a)
            else:
                print("    日志型断点 @ %#x **失败: %s**" % (a, r.get("error")))
                problems.append("set_bp(log) 失败 @ %#x: %s" % (a, r.get("error")))

        # --read-at-mod <模块名>+<RVA>[:<长度>]（可重复）：读**模块内**的地址。
        #
        # 为什么需要：引擎自己的全局在它的 .data 里（RVA 形式，静态可算），
        # 但运行时整个模块被 ASLR 挪走（例如基址 0x7ff7079e0000），绝对地址必须**当场算**。
        # 第 167 轮定位到：引擎 HeapFree 包装第一条指令是
        # `mov rcx, qword ptr [rip + 0x159487a]` ⇒ 全局在引擎 RVA **0x15b9d90**。
        for i, a0 in enumerate(sys.argv):
            if a0 != "--read-at-mod" or i + 1 >= len(sys.argv):
                continue
            spec = sys.argv[i + 1]
            if spec.startswith("--"):
                continue
            core, _c, l_s = spec.partition(":")
            modname, _p, rva_s = core.partition("+")
            if not _p:
                print("    **--read-at-mod 需要『模块名+RVA』格式，收到 %r**" % spec)
                problems.append("--read-at-mod 格式错: %r" % spec)
                continue
            if not mods:
                mods = call("list_modules").get("result", {}).get("modules", []) or []
            basev = None
            for mo in mods:
                if str(mo.get("name", "")).lower() == modname.lower():
                    basev = as_int(mo.get("base", 0))
                    break
            ln = int(l_s, 0) if l_s else 8
            if basev is None:
                print("    **--read-at-mod 找不到模块 %r（现有: %s）**"
                      % (modname, ", ".join(str(m.get("name")) for m in mods[:6])))
                problems.append("--read-at-mod 找不到模块 %r" % modname)
                continue
            va = basev + int(rva_s, 0)
            print("    --read-at-mod %s+%s → 运行期 %#x（模块基址 %#x）" % (modname, rva_s, va, basev))
            read_at.append((va, ln))

        # --manual-pause：**对照实验** —— 不用任何断点，只像陷阱那样把目标停一小会儿。
        #
        # 目的：把"挂住那次 CreateFileW 之后对话框就不出现"的两种解释分开：
        #   若**任何暂停**都足以抑制对话框 ⇒ 之前那些"零命中/零访问"都被这个效应污染了；
        #   若手动暂停后对话框照弹 ⇒ 抑制是**那一次调用**特有的（说明它在检查路径上）。
        if "--manual-pause" in sys.argv:
            tp = time.time()
            for when in (0.2, 1.0):
                while time.time() - tp < when:
                    time.sleep(0.02)
                r = call("pause").get("result", {})
                time.sleep(0.15)
                call("resume")
                print("    %.1f 秒: 手动暂停 0.15 秒（无断点，纯对照）%s"
                      % (when, "" if r.get("error") is None
                         else "  **pause 失败: %s**" % r.get("error")))
        # --write-at <地址>:<十六进制>（可重复）：在**入口暂停时**先写内存，再放行。
        #
        # 用途（第 169 轮）：正常加载里 Sky.exe 的 `.data+0x3bd7b0` 是 **1**，我们这边是 **0**；
        # 而 0 会让 CRT 分配包装走 `mov edi, 8` 那一支 ⇒ `EnterCriticalSection((CS*)8)`
        # ⇒ `lock btr [rdi+8]` 写 0x10 ⇒ 崩。把这一字节补成 1，就能**因果地**验证
        # 那个 AV 到底是不是"那一步初始化没跑"造成的。
        #
        # **时机很重要（第 178 轮实测）**：同样的三个值，如果在**映射时**写（引擎那边做），
        # 会被随后清零 —— 崩溃照旧（info2=0x10）；只有在**入口暂停之后、放行之前**写才有效。
        # 所以这个开关的正确落点就在**这里**。
        #
        # GUADBG_SKY_INIT=1 时，自动补上这几处（默认不补）：
        #   .data+0x3bd7b0 ← 01                       （锁开关字节）
        #   .data+0x3bd788 ← 正规 CRITICAL_SECTION     （DebugInfo=0, LockCount=-1, RecursionCount=0, OwningThread=0）
        #   .data+0x3bd7d0 ← 0100008000000000          （计数器）
        #
        # **第 181 轮的重要修正**：原来这里是照抄"正常加载"的字节
        # （`0000000000000000ffffffffffffffff` 写在 +0x780），但把它当 CRITICAL_SECTION 看时
        # DebugInfo = 0xffffffffffffffff（-1）—— 一把**畸形的锁**。后果是：目标不崩，
        # 但**四条线程全部死等在那把锁上**（8 秒与 18 秒两次快照逐帧相同 ⇒ 是真停住，不是竞争）。
        # 改成**正规初始化**之后，停等消失，目标前进到**游戏自己的代码**里再崩
        # （Sky.exe+0x13dcd43，`call qword ptr [rax+8]` 把数据指针当函数调）。
        if os.environ.get("GUADBG_SKY_INIT", "0") not in ("", "0"):
            for a_s, hx in (("0x1424e97b0", "01"),
                            ("0x1424e9788", "0000000000000000ffffffff000000000000000000000000"),
                            ("0x1424e97d0", "0100008000000000")):
                sys.argv += ["--write-at", "%s:%s" % (a_s, hx)]
            print("  [GUADBG_SKY_INIT=1] 自动补三处初值（入口暂停时写；锁按正规 CRITICAL_SECTION 初始化）")
        for i, a0 in enumerate(sys.argv):
            if a0 != "--write-at" or i + 1 >= len(sys.argv):
                continue
            spec = sys.argv[i + 1]
            if spec.startswith("--"):
                continue
            a_s, _c, hx = spec.partition(":")
            r = call("write_mem", {"addr": int(a_s, 0), "hex": hx}).get("result", {})
            ok = r.get("ok")
            print("    **写入** %s ← %s  → %s"
                  % (a_s, hx, ("ok，写了 %s 字节" % r.get("written")) if ok
                     else "**失败: %s**" % r.get("error")))
            if not ok:
                problems.append("write_mem 失败 @ %s: %s" % (a_s, r.get("error")))
            else:
                result.setdefault("writes", []).append({"addr": a_s, "hex": hx})

        call("resume")

        t0 = time.time()
        first = None
        seen = None
        while time.time() - t0 < secs:
            time.sleep(poll)
            # --threads-at <秒>：到了那个时刻，把**每条线程**的 Rip 打出来并归属到模块+偏移。
            #
            # 用途（第 172 轮）：第 171 轮测出"目标跑约 2.5 秒 CPU 之后转入空闲"。
            # 空闲时它到底停在哪？——直接看各线程 Rip 落在哪个模块/函数，比猜可靠。
            for _ta in [t for t in threads_at if time.time() - t0 >= t
                        and t not in result.get("threads_done_at", [])]:
                result.setdefault("threads_done_at", []).append(_ta)
                print("    —— %.1f 秒时的线程状态（--threads-at %g）——" % (time.time() - t0, _ta))
                tl = call("list_threads").get("result", {}).get("threads") or []
                print("      线程数 %d" % len(tl))
                for t in tl[:12]:
                    tid = t.get("tid") if isinstance(t, dict) else t
                    g = call("get_ctx", {"tid": as_int(tid)}).get("result", {})
                    r = g.get("regs") or {}
                    rip = as_int(r.get("rip", 0)) if r.get("rip") is not None else 0
                    w = where(rip, mods) if (rip and mods) else None
                    print("        tid=%-8s rip=%#-14x %s   susp=%s"
                          % (tid, rip, w or "（不在已知模块里）",
                             (t.get("suspended") if isinstance(t, dict) else "?")))
                    # 寄存器：syscall 返回点上 rcx/r10 仍持有第一个参数（句柄），
                    # 而 x64 系统调用的第 5 个及以后的参数在**栈**上（[rsp+0x28] 起）
                    print("            rcx=%s rdx=%s r8=%s r9=%s rsp=%s"
                          % (r.get("rcx"), r.get("rdx"), r.get("r8"), r.get("r9"), r.get("rsp")))
                    rsp = as_int(r.get("rsp", 0)) if r.get("rsp") is not None else 0
                    if rsp:
                        mm = call("read_mem", {"addr": rsp, "len": 0x40}).get("result", {})
                        hx = str(mm.get("hex", "")).replace(" ", "")
                        if len(hx) >= 0x20:
                            raw = bytes.fromhex(hx)
                            qs = [int.from_bytes(raw[i:i + 8].ljust(8, b"\0"), "little")
                                  for i in range(0, len(raw), 8)]
                            print("            栈上 8 个 qword（syscall 的栈参数从这里看）: %s"
                                  % " ".join("%#x" % x for x in qs))
                    # **哪儿的代码在跑**：直接走这条线程的栈，只列验证过的返回地址并归属模块
                    if r:
                        ch = print_stack_chain(r, mods, thread_walk)
                        for slot, q, wq in ch:
                            txt = wq
                            if wq and wq.lower().startswith("sky.exe"):
                                txt += "   ← **游戏模块**"
                            print("              · %s" % txt)
                    result.setdefault("threads", []).append(
                        {"tid": str(tid), "rip": "%#x" % rip, "where": w})
            # 日志型断点：不停下，条目落在引擎的日志里 —— 每轮把新增的取出来打掉
            if log_bps:
                lg = call("get_log", {"since": log_since}).get("result", {}) or {}
                ents = lg.get("entries") or []
                if ents:
                    try:
                        log_since = int(lg.get("next", log_since))
                    except Exception:
                        pass
                    for e in ents[:20]:
                        print("    [引擎日志] %s" % (e,))
                    result.setdefault("engine_log", []).extend(ents[:200])
            # 先看是不是命中了我们挂的断点（命中时引擎会停在 paused）
            st2 = call("get_state").get("result", {})
            if st2.get("state") == "paused":
                rip = st2.get("rip", 0)
                reason = str(st2.get("reason", ""))[:70]
                regs = call("get_regs").get("result", {}).get("regs", {}) or {}
                # **第 166 轮的重要怀疑**：两次不同运行的"栈"字节**逐字节相同** ——
                # 活着的栈不可能这样。最可能的原因是我读的**不是出错线程的寄存器**
                # （引擎暂停时会暂停所有线程，get_regs 不带 tid 可能返回别的线程）。
                # 所以这里把两个 tid 都打出来；若引擎报的 tid 与 get_regs 的不一致，
                # 就用 get_ctx 取**出错线程**的上下文来做栈分析。
                tid_state = st2.get("paused_tid")      # 字段名是 paused_tid（我原先写 tid，一直是 None）
                tid_regs = regs.get("tid")
                if not result.get("tid_checked"):
                    result["tid_checked"] = True
                    print("          [tid 检查] get_state.paused_tid=%r  get_regs.tid=%r"
                          % (tid_state, tid_regs))
                if tid_state:
                    g2 = call("get_ctx", {"tid": as_int(tid_state)}).get("result", {})
                    r2 = g2.get("regs") or {}
                    if r2 and as_int(r2.get("rsp", 0)) != as_int(regs.get("rsp", 0)):
                        print("          [tid 检查] **rsp 不一致**：get_regs→%s；出错线程 %s→%s"
                              " ⇒ 改用**出错线程**的上下文（这才是栈分析该用的）"
                              % (regs.get("rsp"), tid_state, r2.get("rsp")))
                        regs = r2
                        result["ctx_tid_used"] = tid_state
                if rip in bpname:
                    # 文件/对照断点：记下路径（若取得出）就继续，不走下面 MessageBox 那套
                    nhit = hitcount.get(rip, 0) + 1
                    hitcount[rip] = nhit
                    pth = path_from_hit(bpname[rip], regs)
                    if pth:
                        tr = result.setdefault("file_trace", [])
                        if (not tr or tr[-1] != pth) and len(tr) < 200:
                            tr.append(pth)
                            print("    %5.2f 秒: %-26s %s"
                                  % (time.time() - t0, bpname[rip], pth[:150]))
                    else:
                        # 没有路径可取（例如挂在 RtlEnterCriticalSection 或表地址上）：
                        # 把参数打出来，并把**立即返回地址**解析成模块+偏移 —— 那才是"谁"。
                        print("    %5.2f 秒: %-26s （第 %d 次命中）rcx=%s rdx=%s"
                              % (time.time() - t0, bpname[rip], nhit,
                                 regs.get("rcx"), regs.get("rdx")))
                        if regs.get("rsp") is not None and mods:
                            try:
                                rspv = as_int(regs["rsp"])
                                m0 = call("read_mem", {"addr": rspv, "len": 0x40}).get("result", {})
                                hx0 = str(m0.get("hex", "")).replace(" ", "")
                                if m0.get("len") == 0x40 and len(hx0) == 0x80:
                                    r0 = bytes.fromhex(hx0)
                                    ra0 = int.from_bytes(r0[:8], "little")
                                    print("          立即返回 %#x → %s"
                                          % (ra0, where(ra0, mods) or "（不在已知模块里）"))
                                    if ra0:
                                        dd = call("disasm", {"addr": ra0 - 0x20,
                                                             "count": 6}).get("result", {})
                                        for ln in (dd.get("lines") or []):
                                            print("            %s" % ln.get("text", ln))
                            except Exception as ex:
                                print("          读栈失败: %s" % ex)
                        if nhit <= 60:
                            result.setdefault("bp_args", []).append(
                                {"t": round(time.time() - t0, 2), "bp": bpname[rip],
                                 "rcx": regs.get("rcx"), "rdx": regs.get("rdx"),
                                 "rip": "%#x" % rip})
                    # **谁发的这次打开？** 立即返回地址 + 栈上前几个模块地址。
                    # 这一条直接决定下一步该钩什么：若调用者是保护层自己（栈在 .sky 里），
                    # 那"打开自己的映像文件来校验"这个假设就成立；若在 steam_api64 里，
                    # 那就是 Steam 在校验，方向完全不同。
                    if mods and regs.get("rsp") is not None:
                        try:
                            rspv = as_int(regs["rsp"])
                            m = call("read_mem", {"addr": rspv, "len": 0x100}).get("result", {})
                            hx = str(m.get("hex", "")).replace(" ", "")
                            if m.get("len") == 0x100 and len(hx) == 0x200:
                                raw = bytes.fromhex(hx)
                                ret = int.from_bytes(raw[:8], "little")
                                print("          调用者: 立即返回 %#x → %s"
                                      % (ret, where(ret, mods) or "（不在已知模块里）"))
                                seen = []
                                for i in range(8, 0x100 - 8, 8):
                                    q = int.from_bytes(raw[i:i + 8], "little")
                                    wq = where(q, mods)
                                    if wq and len(seen) < 5:
                                        seen.append((i, q, wq))
                                for i, q, wq in seen:
                                    print("            [栈+%#x] %#x → %s" % (i, q, wq))
                                if nhit == 1:
                                    result.setdefault("file_caller", []).append(
                                        {"ret": "%#x" % ret, "where": where(ret, mods),
                                         "stack": [{"slot": i, "addr": "%#x" % q, "where": wq}
                                                   for i, q, wq in seen]})
                        except Exception as ex:
                            print("          读栈失败: %s" % ex)
                    if del_after and nhit >= del_after and bpid.get(rip):
                        call("del_bp", {"id": bpid[rip]})
                        print("          已删除该断点（--del-after %d），目标就此自由跑"
                              % del_after)
                    call("resume")
                    continue
                ins = call("disasm", {"addr": rip, "count": 3}).get("result", {}).get("lines", [])
                # --read-at：暂停时把这几个地址读出来。
                # 默认**只读第一次**（避免刷屏）；加 `--read-at-each` 则**每次暂停都读** ——
                # 第 187 轮要用它：崩溃那一次暂停时的值，才是我们想知道的"当时值"
                # （第一次暂停读到的可能只是我们刚写进去的值）。
                if read_at and ("--read-at-each" in sys.argv or not result.get("read_at_done")):
                    if "--read-at-each" not in sys.argv:
                        result["read_at_done"] = True
                    print("          —— 顺带读几个全局（暂停原因: %s）——" % reason[:40])
                    for a_r, l_r in read_at:
                        m = call("read_mem", {"addr": a_r, "len": l_r}).get("result", {})
                        hx = str(m.get("hex", "")).replace(" ", "")
                        if not hx:
                            print("            %#x (%d 字节): **读不到** %s"
                                  % (a_r, l_r, m.get("error", "")))
                            continue
                        raw = bytes.fromhex(hx)
                        qs = [int.from_bytes(raw[i:i + 8].ljust(8, b"\0"), "little")
                              for i in range(0, len(raw), 8)]
                        print("            %#x (%d 字节): %s" % (a_r, l_r, hx))
                        print("               按 qword 看: %s" % ["%#x" % q for q in qs])
                        if all(b == 0 for b in raw):
                            print("               ⇒ **全零**")
                        result.setdefault("read_at", []).append(
                            {"addr": "%#x" % a_r, "len": l_r, "hex": hx})
                # --stack-chain：把**验证过的返回地址**列出来（问"谁调用到这里"）
                if stack_chain and not result.get("chain_done") and mods:
                    result["chain_done"] = True
                    ch = print_stack_chain(regs, mods, stack_chain)
                    result["stack_chain"] = [{"slot": "%#x" % s, "ret": "%#x" % q,
                                              "where": w} for s, q, w in ch]
                print("    %5.1f 秒: **命中断点** rip=%#x (%s) reason=%s"
                      % (time.time() - t0, rip, where(rip, mods) or "不在已知模块里", reason))
                # 第 182 轮：**所有停止点**都打一遍通用寄存器。
                # 为什么：出问题的指针往往不在 rcx/rdx/r8/r9 里，而在 rax/rbx/rsi/rdi
                # （例如 `call qword ptr [rax+8]` 这种间接调用）。只打前四个会漏掉真凶。
                _r = ["%s=%s" % (k, regs.get(k))
                      for k in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                                "r8", "r9", "r10", "r11")
                      if regs.get(k) is not None]
                if _r:
                    print("          全寄存器: %s" % " ".join(_r))
                for i in ins:
                    print("          %s" % i.get("text", i))

                # ---- 取参数：这是本轮的正题 ----
                #
                # MessageBoxTimeoutW(HWND, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType,
                #                    WORD wLanguageId, DWORD dwMilliseconds)
                # x64 约定：rcx / rdx / r8 / r9 / [rsp+0x28] / [rsp+0x30]
                # （断点落在函数第一条指令上，所以 [rsp] 是返回地址、[rsp+8..0x20] 是影子空间。）
                # get_regs 给的是**小写十六进制字符串、不带 0x**，所以要经 as_int。
                args = {}
                if "lpText" in result:
                    args = {}      # 参数只取第一次（后面 18 次是同一个循环，重复打印没意义）
                for rn in ("rcx", "rdx", "r8", "r9"):
                    if regs.get(rn) is not None:
                        args[rn] = as_int(regs[rn])
                # 第 182 轮：把所有通用寄存器打出来。
                # 为什么：崩溃时出问题的指针往往**不在** rcx/rdx/r8/r9 里，而在 rax/rbx/rsi/rdi 里
                # （例如 `call qword ptr [rax+8]` 这种间接调用）。只打前四个会漏掉真凶。
                _r = ["%s=%s" % (k, regs.get(k))
                      for k in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11")
                      if regs.get(k) is not None]
                if _r:
                    print("          全寄存器: %s" % " ".join(_r))
                if args:
                    print("          参数："
                          + "  ".join("%s=%#x" % (k, v) for k, v in args.items()))
                for rn, label in (("rdx", "lpText"), ("r8", "lpCaption")):
                    v = args.get(rn)
                    if not v:
                        continue
                    s, nb, note = read_wstr(v)
                    if s is None:
                        print("          %s（%s）@ %#x 读不到：%s" % (label, rn, v, note))
                    else:
                        print("          %s（%s）@ %#x = %r  [%d 字节]" % (label, rn, v, s[:120], nb))
                        result[label] = s
                        result[label + "_ptr"] = "%#x" % v
                        if mods:
                            w = where(v, mods)
                            result[label + "_where"] = w or "（不在已知模块里 —— 可能是堆）"
                            print("              落在: %s" % (w or "（不在已知模块里 —— 可能是堆）"))
                        # --dump-near：把这支串附近的**同一批**串都列出来
                        if "--dump-near" in sys.argv and rn == "rdx":
                            near = dump_wstrings(v)
                            print("              附近 %d 字节里找到 %d 支串："
                                  % (0x4000, len(near)))
                            for doff, ds in near[:40]:
                                mark = "  ← lpText 本身" if doff == 0 else ""
                                print("                [%+#7x] %r%s" % (doff, ds[:100], mark))
                            result["near_strings"] = [{"off": doff, "s": ds}
                                                      for doff, ds in near[:40]]
                # 第 5、6 个参数在栈上：影子空间之后
                if regs.get("rsp") is not None and "dwTimeout_ms" not in result:
                    try:
                        rspv = as_int(regs["rsp"])
                        m2 = call("read_mem", {"addr": rspv, "len": 0x40}).get("result", {})
                        hx2 = str(m2.get("hex", "")).replace(" ", "")
                        if m2.get("len") == 0x40 and len(hx2) == 0x80:
                            r2 = bytes.fromhex(hx2)
                            fifth = int.from_bytes(r2[0x28:0x30], "little")
                            sixth = int.from_bytes(r2[0x30:0x38], "little")
                            print("          栈上第 5/6 个参数: wLanguageId=%#x  dwTimeout=%#x (%d ms)"
                                  % (fifth, sixth, sixth))
                            result["dwTimeout_ms"] = sixth
                    except Exception as ex:
                        print("          读栈参数失败: %s" % ex)
                rsp = regs.get("rsp")
                if rsp is not None:
                    try:
                        rsp = as_int(rsp)
                        m = call("read_mem", {"addr": rsp, "len": 0x200}).get("result", {})
                        hx = str(m.get("hex", "")).replace(" ", "")
                        if m.get("len") == 0x200 and len(hx) == 0x400:
                            raw = bytes.fromhex(hx)
                            ra = int.from_bytes(raw[:8], "little")
                            w = where(ra, mods) if mods else None
                            print("          返回地址 = %#x  →  %s" % (ra, w or "（不在已知模块里）"))
                            result["caller_return"] = "%#x" % ra
                            result["caller_where"] = w
                            # 更重要的：在整段栈里找**落在 Sky.exe 里的**返回地址 ——
                            # 那才是"游戏自己的代码在哪儿决定弹这个框"。
                            # （如果命中点是 user32/win32u 内部，直接返回地址只会指向 user32。）
                            # 先来一份**任意模块**的栈扫描：'谁调进了这把锁'要看全栈，
                            # 只过滤 Sky.exe 太窄 —— 第 150 轮那次崩溃栈顶是 0，什么也没看出来。
                            mods_seen = []
                            for i in range(0, 0x200 - 8, 8):
                                q = int.from_bytes(raw[i:i + 8], "little")
                                ww = where(q, mods) if mods else None
                                if ww and len(mods_seen) < 8:
                                    mods_seen.append((i, q, ww))
                            if mods_seen:
                                print("          栈上任意模块地址（前 8 个）：")
                                for i, q, ww in mods_seen:
                                    print("            [栈+%#x] %#x → %s" % (i, q, ww))
                                result.setdefault("stack_any_mod", []).append(
                                    [{"slot": i, "addr": "%#x" % q, "where": ww}
                                     for i, q, ww in mods_seen])
                            game = []
                            for i in range(0, 0x200 - 8, 8):
                                q = int.from_bytes(raw[i:i + 8], "little")
                                ww = where(q, mods) if mods else None
                                if ww and ww.lower().startswith("sky.exe"):
                                    game.append((i, q, ww))
                            if game:
                                print("          栈上落在 Sky.exe 里的地址 %d 个：" % len(game))
                                for i, q, ww in game[:6]:
                                    print("            [栈+%#x] %#x → %s" % (i, q, ww))
                                result["stack_game"] = [{"slot": i, "addr": "%#x" % q,
                                                         "where": ww} for i, q, ww in game[:6]]
                                d = call("disasm", {"addr": game[0][1] - 0x20,
                                                    "count": 10}).get("result", {})
                                print("            第一个调用点附近：")
                                for ln in (d.get("lines") or []):
                                    print("              %s" % ln.get("text", ln))
                    except Exception as ex:
                        print("          读栈失败: %s" % ex)
                result.setdefault("hits", []).append({"t": round(time.time() - t0, 1),
                                                      "rip": "%#x" % rip, "reason": reason})
                call("resume")
                continue
            if eng.poll() is not None:
                print("    %5.1f 秒: **引擎进程已退出**（code=%r）" % (time.time() - t0, eng.poll()))
                result["end"] = "process-exited"
                result["exit_code"] = eng.poll()
                break
            ws = windows_of(eng.pid)
            dlg = [w for w in ws if is_dialog(w)]
            if dlg and first is None:
                first = time.time() - t0
                seen = dlg
                print("    %5.1f 秒: **对话框出现**" % first)
                for cls, txt, kids in dlg:
                    print("        顶层 class=%s text=[%s]" % (cls, txt[:60]))
                    for kc, kt in kids:
                        print("           子 class=%s text=[%s]" % (kc, kt[:90]))
                break
        if first is None and "end" not in result:
            result["end"] = "no-dialog-in-window"
            print("    %.0f 秒窗口期内**没有**对话框" % secs)
            ws = windows_of(eng.pid)
            print("    当时的顶层窗口 %d 个: %s"
                  % (len(ws), "; ".join("%s[%s]" % (w[0], w[1][:20]) for w in ws) or "（无）"))
            result["windows_at_end"] = ws
        result["dialog_first_seen"] = round(first, 1) if first is not None else None
        if seen:
            result["dialog"] = seen
    finally:
        try:
            call("terminate", timeout=15)
        except Exception:
            pass
        time.sleep(0.5)
        if eng.poll() is None:
            eng.terminate()
        try:
            eng.wait(timeout=10)
        except Exception:
            eng.kill()
        log.close()

    json.dump(result, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print()
    if result.get("dialog_first_seen") is not None:
        print("  ⇒ **对话框出现**（%.1f 秒）：这次运行里目标没有真正在跑，"
              "任何'零命中/零访问'都不成立。" % result["dialog_first_seen"])
    elif result.get("end") == "process-exited":
        print("  ⇒ 引擎进程退出了（这不是'没有对话框'，要单独看待）。")
    else:
        print("  ⇒ 窗口期内**没有对话框**：这次运行里目标至少在跑，测量才有意义。")
    print("  -> %s" % OUT)
    if problems:
        print("  **%d 个问题**" % len(problems))
        for p in problems:
            print("    - %s" % p)
        return 1
    return 0


sys.exit(main())
