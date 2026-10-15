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
        call("resume")

        t0 = time.time()
        first = None
        seen = None
        while time.time() - t0 < secs:
            time.sleep(1.5)
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
