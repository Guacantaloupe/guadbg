# -*- coding: utf-8 -*-
"""guadbg 对 Sky.exe 的冒烟测试——smoke_test.py 的 Sky 变体。

为什么需要它
    smoke_test.py 只跑 test_target.exe（140 KB 的玩具目标）。而本项目要做的
    运行时观察是对 **Sky.exe**（45 MB、经 WinLicense 处理、入口在 RWX 的 .sky 段里）
    做的。两者在加载路径上的差别正是最容易出事的地方：
        * test_target.exe 是普通 EXE；Sky.exe 的入口不在 .text 而在 .sky
        * Sky.exe 的入口不是 CRT 启动代码，所以"停在入口"依赖异常条目注册成功
        * Sky.exe 的导入表只有 27 项（每 DLL 一项），是 Oreans 剥过的
    所以玩具目标 12/12 通过**不能**推出 Sky.exe 能跑。

判据分两类，都不靠"看起来对"：
    ① 已知事实必须复现（这些值是 sky-re 项目独立量出来的，不是本测试算的）
       映射基址 0x140000000、入口 0x142b649f6、异常条目 62,027、
       steam_api64.dll 已加载、导入 27 项、暂停原因指向入口断点
    ② 命令必须真的能用（返回结构而非错误）
       get_regs / list_modules / list_threads / read_mem / disasm /
       exports / mem_map / windows

用法
    python sky_smoke.py            跑全部
    python sky_smoke.py --quick    只跑 ①（不加载完整的命令面）

Sky.exe 的路径可用 SKY_EXE 环境变量覆盖。
"""
import json
import os
import subprocess
import sys
import time

sys.stdout.reconfigure(encoding="utf-8")

ROOT = os.path.dirname(os.path.abspath(__file__))
CLIENT = os.path.join(ROOT, "test_client.exe")
ENGINE = os.path.join(ROOT, "guadbg.exe")
SKY = os.environ.get(
    "SKY_EXE",
    r"C:\Program Files (x86)\Steam\steamapps\common\Sky Children of the Light\Sky.exe")

# sky-re 项目独立量出来的已知值。**不是本测试算出来的**——
# 这一点很重要：自检若只用自己推导的值，一个一致地错误的实现会全部通过。
KNOWN_BASE = 0x140000000
KNOWN_ENTRY = 0x142B649F6
KNOWN_EXC_ENTRIES = 62027
KNOWN_IMPORTS = 27

fails = []


def call(cmd, args=None, note=""):
    p = subprocess.run([CLIENT, cmd, json.dumps(args or {})],
                       capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=60)
    line = p.stdout.strip().splitlines()[0] if p.stdout.strip() else ""
    if p.returncode != 0 or not line:
        fails.append("%s %s: rc=%d out=%s err=%s"
                     % (cmd, note, p.returncode, line[:100], p.stderr[:160]))
        return {}
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        fails.append("%s %s: bad json %s" % (cmd, note, line[:120]))
        return {}


def check(name, cond, extra=""):
    print(("  [PASS] " if cond else "  [FAIL] ") + name
          + ("  " + str(extra)[:90] if extra else ""))
    if not cond:
        fails.append(name)


def main():
    quick = "--quick" in sys.argv
    if not os.path.exists(SKY):
        print("  **找不到 Sky.exe: %s**" % SKY)
        return 1
    print("  目标 %s  (%s 字节)" % (SKY, format(os.path.getsize(SKY), ",")))
    print()

    log = open(os.path.join(ROOT, "sky_smoke_engine.log"), "w", encoding="utf-8")
    eng = subprocess.Popen([ENGINE, SKY], stdout=log, stderr=subprocess.STDOUT)
    try:
        # Sky.exe 45 MB，加载器遍历 + 62k 异常条目注册比玩具目标慢得多
        time.sleep(8.0)

        print("  [1] 加载与入口")
        st = call("get_state").get("result", {})
        check("状态为 paused", st.get("state") == "paused", st.get("state"))
        rip = st.get("rip", 0)
        check("停在**已知入口** %#x" % KNOWN_ENTRY, rip == KNOWN_ENTRY, hex(rip) if rip else 0)
        reason = str(st.get("reason", ""))
        check("暂停原因指向断点", "断点" in reason or "breakpoint" in reason.lower(), reason[:60])

        print()
        print("  [2] 模块")
        mods = call("list_modules").get("result", {})
        arr = mods.get("modules", [])
        check("模块表非空", len(arr) > 0, "%d 个" % len(arr))
        by_name = {}
        for m in arr:
            n = str(m.get("name", "")).lower()
            if n:
                by_name[n] = m
        base = None
        for k, m in by_name.items():
            if "sky" in k and k.endswith(".exe"):
                base = m.get("base")
        check("Sky.exe 映射在**已知基址** %#x" % KNOWN_BASE, base == KNOWN_BASE,
              hex(base) if base else 0)
        check("steam_api64.dll 已加载", any("steam_api64" in k for k in by_name),
              [k for k in by_name if "steam" in k][:3])
        check("fmod.dll 已加载", any("fmod" in k for k in by_name))

        print()
        print("  [3] 导入")
        imps = call("list_imports").get("result", {})
        ia = imps.get("imports", [])
        check("导入项数 == **已知的 %d**" % KNOWN_IMPORTS, len(ia) == KNOWN_IMPORTS,
              "%d 项" % len(ia))

        if quick:
            print()
            print("  --quick：跳过命令面")
        else:
            print()
            print("  [4] 命令面（RE 要用的那几条）")
            r = call("get_regs").get("result", {})
            check("get_regs 返回寄存器", "regs" in r or "rip" in r, list(r.keys())[:6])

            r = call("list_threads").get("result", {})
            check("list_threads 返回线程表",
                  len(r.get("threads", [])) > 0, "%d 个" % len(r.get("threads", [])))

            # 键名是 len 不是 size（见 docs/COMMAND_SCHEMA.md）。传错键**不会报错**——
            # 引擎回退默认值 128，于是"读了 32 字节"这句话是假的。所以长度也要断言。
            r = call("read_mem", {"addr": KNOWN_ENTRY, "len": 32}).get("result", {})
            got_hex = str(r.get("hex", "")).replace(" ", "")
            check("read_mem 读得到入口字节", bool(got_hex), list(r.keys())[:6])
            check("read_mem 真的读了 32 字节（不是回退的默认 128）",
                  r.get("len") == 32 and len(got_hex) == 64,
                  "len=%s hex_chars=%d" % (r.get("len"), len(got_hex)))

            r = call("disasm", {"addr": KNOWN_ENTRY, "count": 8}).get("result", {})
            check("disasm 反汇编得了入口", "insns" in r or "lines" in r, list(r.keys())[:6])

            r = call("exports", {"module": "Sky.exe"}).get("result", {})
            check("exports 返回结构（Sky.exe 可能为空，这是正常的）",
                  "exports" in r, "%d 项" % len(r.get("exports", [])))

            r = call("mem_map").get("result", {})
            check("mem_map 返回区域表", len(r.get("regions", [])) > 0,
                  "%d 个区域" % len(r.get("regions", [])))

            r = call("windows").get("result", {})
            check("windows 返回窗口表（Sky 的窗口应当可见）",
                  "windows" in r, "%d 个窗口" % len(r.get("windows", [])))

            print()
            print("  [5] guard page —— 区域A 运行时观察依赖这一条")
            r = call("set_mem_bp", {"addr": KNOWN_BASE + 0x1DCC000, "size": 0x1000}).get("result", {})
            has_err = "error" in r
            check("set_mem_bp 被接受（返回结果而非错误）", not has_err, r.get("error", "")[:70])
            # 结果键是 breakpoints 不是 bps；而 `len(...) >= 0` 恒真——
            # 那是"因为没在检查所以通过"。既然上面刚设了一个，就必须能列出至少一个。
            r2 = call("list_bps").get("result", {})
            bps = r2.get("breakpoints", [])
            check("设置后 list_bps 能列出至少那一个断点", len(bps) >= 1,
                  "%d 个断点" % len(bps))

    finally:
        try:
            call("terminate")
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

    print()
    if fails:
        print("  **%d 项失败**" % len(fails))
        for f in fails:
            print("    - %s" % f)
        return 1
    print("  全部通过")
    return 0


sys.exit(main())
