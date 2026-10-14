# -*- coding: utf-8 -*-
"""找 Sky 的入口线程自旋的那把锁。

链条跟到最后是一个自旋锁，形状是
    xor eax,eax; lock cmpxchg %ecx,(%rbx,%rbp,1); je done; ... pause; jmp retry
所以锁地址 = rbx + rbp，两个都来自 VM 的寄存器状态。

这一步要做的是：让目标跑起来，看寄生线程是不是停在那段自旋里，
如果是，读 rbx/rbp 算出锁地址，再读那个地址的内容。
内容是不是 0 决定了两种完全不同的修复方向。
"""
import json
import subprocess
import sys
import time

sys.stdout.reconfigure(encoding="utf-8")

ROOT = r"C:\Users\m4a1_\Documents\deepseek-harness\default-workspace\guadbg-public"
CLIENT = ROOT + r"\test_client.exe"

SKY_LO, SKY_HI = 0x140000000, 0x14313F000
LOOP_LO, LOOP_HI = 0x142C0428F, 0x142C04360   # 自旋锁区间（VA）


def call(cmd, args=None, t=40):
    p = subprocess.run([CLIENT, cmd, json.dumps(args or {})],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=t)
    lines = [x for x in p.stdout.strip().splitlines() if x.strip()]
    return json.loads(lines[0]) if lines else {}


def main():
    st = call("get_state")["result"]
    print("  状态:", st["state"])
    if st["state"] == "paused":
        print("  resume ->", call("resume").get("ok"))
        time.sleep(12)

    threads = call("list_threads")["result"]["threads"]
    par = [t for t in threads if t.get("parasite")]
    print("  寄生线程 %d 个" % len(par))
    if not par:
        print("  没有寄生线程")
        return
    t = par[0]
    rip, rsp = t["rip"], t["rsp"]
    print("  tid %s  rip %#x  rsp %#x" % (t["tid"], rip, rsp))
    print("  在自旋锁区间内: %s" % (LOOP_LO <= rip < LOOP_HI))

    regs = call("get_regs", {"tid": t["tid"]}).get("result", {}).get("regs", {})
    if not regs:
        print("  get_regs:", json.dumps(call("get_regs", {"tid": t["tid"]}))[:200])
        return
    show = ("rip", "rsp", "rbx", "rbp", "rax", "rcx", "rdx", "rdi", "r8", "rsi")
    print("  寄存器:")
    for k in show:
        if k in regs:
            print("    %-4s %s" % (k, regs[k]))

    rbx = int(regs.get("rbx", "0"), 16)
    rbp = int(regs.get("rbp", "0"), 16)
    lock = rbx + rbp
    print("\n  锁地址 = rbx + rbp = %#x + %#x = **%#x**" % (rbx, rbp, lock))

    if lock:
        got = call("read_mem", {"addr": lock, "size": 16}, t=30)
        res = got.get("result", {})
        print("  锁处内容:", json.dumps(res, ensure_ascii=False)[:200])
        hexs = res.get("hex") or res.get("bytes") or ""
        if hexs:
            raw = bytes.fromhex(hexs.replace(" ", ""))
            import struct
            print("    u32 = %#x   u64 = %#x" % (
                struct.unpack_from("<I", raw)[0], struct.unpack_from("<Q", raw)[0]))
            print("    **锁是自由的（0）**" if struct.unpack_from("<I", raw)[0] == 0
                  else "    **锁被持有（非 0）**")


main()
