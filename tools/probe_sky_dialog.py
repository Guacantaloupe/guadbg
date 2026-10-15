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


def where(addr, mods):
    """把地址标成「模块+偏移」。"""
    for mo in mods:
        b = as_int(mo.get("base", 0))
        sz = as_int(mo.get("size", 0))
        if b and sz and b <= addr < b + sz:
            return "%s+%#x" % (mo.get("name"), addr - b)
    return None


def main():
    secs = 40.0
    if "--secs" in sys.argv:
        secs = float(sys.argv[sys.argv.index("--secs") + 1])

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
        mods = []
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
        call("resume")

        t0 = time.time()
        first = None
        seen = None
        while time.time() - t0 < secs:
            time.sleep(1.5)
            # 先看是不是命中了我们挂的断点（命中时引擎会停在 paused）
            st2 = call("get_state").get("result", {})
            if st2.get("state") == "paused":
                rip = st2.get("rip", 0)
                reason = str(st2.get("reason", ""))[:70]
                regs = call("get_regs").get("result", {}).get("regs", {}) or {}
                ins = call("disasm", {"addr": rip, "count": 3}).get("result", {}).get("lines", [])
                print("    %5.1f 秒: **命中断点** rip=%#x reason=%s"
                      % (time.time() - t0, rip, reason))
                for i in ins:
                    print("          %s" % i.get("text", i))
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
