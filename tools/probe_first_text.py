# -*- coding: utf-8 -*-
"""找**真正的 OEP**：用跟踪的条件把目标停在"第一次执行 .text 代码"的那条指令上。

为什么这么做
    目标的 PE 入口（0x142B649F6）在 `.sky[1]` 里 —— 也就是说入口被保护层 stub 改掉了，
    真正的 CRT 启动（OEP）是它之后才跳过去的。第 151 轮已经证明 `.text` 真代码在跑，
    但"它从哪儿开始跑"还不知道。与其去猜 `mainCRTStartup` 的字节特征，
    不如让引擎**自己停在那一刻**。

做法
    `start_trace {cond: "rip >= .text 起点 && rip < .text 终点", mode: 0}`：
    引擎在第 2842 行会逐指令求值这个条件，成立就 `pause_here("跟踪停止")`。
    于是目标会**停在第一条落在 .text 里的指令**上 —— 那条指令的地址就是 OEP 候选。
    再用 `get_trace` 把停下来之前的最后几条指令打出来，就能看到"从哪里跳进来的"。

判据
    拿到一个具体的 .text 地址 + 跳转来源；若跟踪因条件写错而报错，就把错误原文记下来
    （而不是把它读成"没有发生"）。

用法
    python tools/probe_first_text.py
"""
import json
import os
import subprocess
import sys
import time

sys.stdout.reconfigure(encoding="utf-8")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT = os.path.join(ROOT, "test_client.exe")
ENGINE = os.path.join(ROOT, "guadbg.exe")
SKY = os.environ.get(
    "SKY_EXE",
    r"C:\Program Files (x86)\Steam\steamapps\common\Sky Children of the Light\Sky.exe")

# .text 的区间（第 143 轮从节区表量到：VA 0x140001000，VirtualSize 0x1dcab76）
TEXT_LO, TEXT_HI = 0x140001000, 0x140001000 + 0x1DCAB76

problems = []


def call(cmd, args=None, timeout=60):
    p = subprocess.run([CLIENT, cmd, json.dumps(args or {})],
                       capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=timeout)
    line = p.stdout.strip().splitlines()[0] if p.stdout.strip() else ""
    if p.returncode != 0 or not line:
        problems.append("%s: rc=%d out=%r err=%r"
                        % (cmd, p.returncode, line[:150], p.stderr[:200]))
        return {}
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        problems.append("%s: 非 JSON %r" % (cmd, line[:150]))
        return {}


def as_int(v):
    return v if isinstance(v, int) else int(str(v).strip(), 16)


def where(addr, mods):
    for mo in mods:
        b = as_int(mo.get("base", 0))
        sz = as_int(mo.get("size", 0))
        if b and sz and b <= addr < b + sz:
            return "%s+%#x" % (mo.get("name"), addr - b)
    return None


def main():
    log = open(os.path.join(ROOT, "probe_firsttext_engine.log"), "w", encoding="utf-8")
    eng = subprocess.Popen([ENGINE, SKY], stdout=log, stderr=subprocess.STDOUT)
    try:
        time.sleep(8.0)
        st = call("get_state").get("result", {})
        print("  入口暂停: state=%s rip=%#x" % (st.get("state"), st.get("rip", 0)))
        if st.get("state") != "paused":
            problems.append("没停在入口: %r" % st.get("state"))
            for p in problems:
                print("    - %s" % p)
            return 1
        mods = call("list_modules").get("result", {}).get("modules", []) or []

        cond = "rip >= %#x && rip < %#x" % (TEXT_LO, TEXT_HI)
        # --arm-at <addr>：先在那个地址下**软件断点**，命中之后再 start_trace。
        #
        # 为什么必须这样：跟踪靠的是单步（TF）。在钩子里直接把 g_trace_on 置 1 **不会**设置 TF，
        # 于是根本没有单步发生 —— 第 152 轮那次"跟踪 0 条"就是这么来的。
        # 而 `start_trace` 内部会 resume（并设置 TF），所以要在**暂停状态下**调它。
        # 触发点取"保护层第二次问映像路径"的返回地址（0x142E3B9AA，映像基址固定所以跨运行稳定）。
        arm_id = None
        if "--arm-at" in sys.argv:
            arm_at = int(sys.argv[sys.argv.index("--arm-at") + 1], 0)
            r = call("set_bp", {"addr": arm_at}).get("result", {})
            arm_id = r.get("id")
            print("  在 %#x 下软件断点 -> id=%s（命中后再开跟踪，这样 TF 才会被设置）"
                  % (arm_at, arm_id))
            if arm_id is None:
                problems.append("set_bp 失败: %s" % r.get("error"))
                for p in problems:
                    print("    - %s" % p)
                return 1
            call("resume")
        else:
            print("  启动跟踪，条件: %s" % cond)
            r = call("start_trace", {"cond": cond, "mode": 0}).get("result", {})
        if r.get("error") is not None:
            print("  **start_trace 报错: %s**" % r.get("error"))
            problems.append("start_trace 被拒: %s" % r.get("error"))
            for p in problems:
                print("    - %s" % p)
            return 1

        t0 = time.time()
        s = {}
        while time.time() - t0 < 120:
            time.sleep(0.2)
            s = call("get_state").get("result", {})
            if s.get("state") == "paused":
                rr = str(s.get("reason", ""))
                if arm_id is not None and ("断点 #%d" % arm_id) in rr:
                    print("  命中触发点，开跟踪（start_trace 会设置 TF 并恢复）")
                    st = call("start_trace", {"cond": cond, "mode": 0}).get("result", {})
                    print("    start_trace -> %s" % json.dumps(st, ensure_ascii=False)[:140])
                    arm_id = None      # 只做一次
                    continue
                break
            if eng.poll() is not None:
                print("  **引擎进程已退出** code=%r" % eng.poll())
                return 1
        rip = s.get("rip", 0)
        print()
        print("  停下来: state=%r  rip=%#x (%s)" % (s.get("state"), rip, where(rip, mods)))
        print("  reason=%s" % str(s.get("reason", ""))[:90])
        if s.get("state") != "paused":
            problems.append("30 秒内没有因条件停下（state=%r）" % s.get("state"))

        # 停下来之前最后几条指令：看它是从哪儿跳进 .text 的
        tr = call("get_trace", {"from": 0, "count": 40}).get("result", {})
        print("  get_trace 原始返回（前 600 字）:")
        print("    %s" % json.dumps(tr, ensure_ascii=False)[:600])
        items = tr.get("items") or tr.get("trace") or tr.get("lines") or tr.get("records") or []
        print("  get_trace 返回 %d 条（字段: %s）"
              % (len(items), sorted(items[0].keys()) if items else "无"))
        for e in items[-12:]:
            print("    %s" % json.dumps(e, ensure_ascii=False)[:150])
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
    return 0


sys.exit(main())
