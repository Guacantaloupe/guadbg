# -*- coding: utf-8 -*-
"""手动暂停后读栈，找出 Sky 自己的调用链。

read_stack 需要"栈上下文"，而那只在暂停状态下存在——直接对一个 running 的目标
调用会得到"无栈上下文"。所以顺序是 resume → 等运行 → pause → read_stack。
"""
import json
import subprocess
import sys

sys.stdout.reconfigure(encoding="utf-8")

ROOT = r"C:\Users\m4a1_\Documents\deepseek-harness\default-workspace\guadbg-public"
CLIENT = ROOT + r"\test_client.exe"

SKY_LO, SKY_HI = 0x140000000, 0x14313F000


def call(cmd, args=None, t=40):
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
    st = call("get_state")["result"]
    print("  当前:", st["state"])
    if st["state"] == "running":
        print("  pause ->", call("pause"))
    st = call("get_state")["result"]
    print("  暂停后:", st["state"], "tid", st.get("paused_tid"),
          "rip", hex(st.get("rip", 0)))

    mods = call("list_modules")["result"]["modules"]
    tid = st.get("paused_tid")
    print("  暂停线程 %s 在 %s" % (tid, label(st.get("rip", 0), mods)))

    got = call("read_stack", {"tid": tid, "count": 512}, t=60)
    res = got.get("result", {})
    if not res:
        print("  read_stack:", json.dumps(got, ensure_ascii=False)[:300])
        return
    print("  read_stack 字段:", list(res.keys()))
    frames = res.get("frames") or res.get("stack") or []
    if frames and isinstance(frames[0], dict):
        print("  返回的帧格式样例:", json.dumps(frames[0])[:200])

    # 兼容几种可能的返回形状，统一取出一串地址
    addrs = []
    for f in frames:
        if isinstance(f, int):
            addrs.append(f)
        elif isinstance(f, dict):
            for k in ("value", "addr", "qword", "v"):
                if k in f:
                    addrs.append(f[k])
                    break
    print("  取到 %d 个栈值" % len(addrs))
    hits = [a for a in addrs if SKY_LO <= a < SKY_HI]
    print("  **其中落在 Sky 地址空间: %d 个**" % len(hits))
    for a in hits[:30]:
        print("    %#x   Sky+%#x" % (a, a - SKY_LO))
    open(ROOT + r"\stack_hits.json", "w").write(json.dumps([hex(a) for a in hits]))


main()
