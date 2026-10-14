# -*- coding: utf-8 -*-
"""恢复 Sky 并采样每个线程的位置，把 Sky 地址空间里的帧标出来。

用途：引擎报告目标在"运行"，但工作集只有 20 MB、CPU 0.2 秒，
vulkan-1.dll 从未加载。要弄清它停在哪，光看"运行中"不够——
需要看入口点线程此刻在哪个模块、以及栈上有没有 Sky 自己的返回地址。
"""
import json
import subprocess
import sys
import time

sys.stdout.reconfigure(encoding="utf-8")

ROOT = r"C:\Users\m4a1_\Documents\deepseek-harness\default-workspace\guadbg-public"
CLIENT = ROOT + r"\test_client.exe"

SKY_LO, SKY_HI = 0x140000000, 0x14313F000


def call(cmd, args=None, t=25):
    p = subprocess.run([CLIENT, cmd, json.dumps(args or {})],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=t)
    lines = [x for x in p.stdout.strip().splitlines() if x.strip()]
    return json.loads(lines[0]) if lines else {}


def label(addr, mods):
    for m in mods:
        if m["base"] <= addr < int(m["end"], 16):
            return "%s+%#x" % (m["name"], addr - m["base"])
    return "?"


def main():
    print("  状态:", call("get_state")["result"]["state"])
    print("  resume ->", call("resume").get("ok"))
    time.sleep(18)

    st = call("get_state")["result"]
    print("  18 秒后: state=%s tid=%s" % (st["state"], st.get("paused_tid")))

    mods = call("list_modules")["result"]["modules"]
    threads = call("list_threads")["result"]["threads"]
    print("  线程 %d 个:" % len(threads))
    for t in threads:
        rip = t["rip"]
        mark = "  <- 寄生（目标入口点）" if t.get("parasite") else ""
        print("    tid %-7s rip %#014x  %s%s" % (t["tid"], rip, label(rip, mods), mark))

    # 入口点线程的栈：扫 Sky 地址空间里的返回地址，那是它自己的调用链
    par = [t for t in threads if t.get("parasite")]
    if par:
        tid = par[0]["tid"]
        rsp = par[0]["rsp"]
        print("\n  寄生线程 tid=%s rsp=%#x" % (tid, rsp))
        got = call("read_stack", {"tid": tid, "count": 256}, t=40)
        frames = got.get("result", {}).get("frames") or got.get("result", {}).get("qwords") or []
        if not frames:
            print("  read_stack 返回:", json.dumps(got)[:300])
        sky_hits = []
        for f in frames:
            v = f if isinstance(f, int) else f.get("value", 0)
            if SKY_LO <= v < SKY_HI:
                sky_hits.append(v)
        print("  栈上落在 Sky 地址空间的 %d 个值:" % len(sky_hits))
        for v in sky_hits[:24]:
            print("    %#x  Sky+%#x" % (v, v - SKY_LO))
        open(ROOT + r"\stack_hits.json", "w").write(json.dumps([hex(v) for v in sky_hits]))


main()
