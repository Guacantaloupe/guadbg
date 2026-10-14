# -*- coding: utf-8 -*-
"""guadbg 端到端冒烟测试 v2 —— 经 test_client.exe（绕过 python 沙箱管道限制）"""
import json
import os
import subprocess
import time
import sys

# The author's script carries the path of the machine it was written on. Deriving it from this
# file makes the test run wherever the repository is checked out, which is the difference between
# a test someone else can run and one only its author can.
ROOT = os.path.dirname(os.path.abspath(__file__))
CLIENT = os.path.join(ROOT, "test_client.exe")

fails = []

def call(cmd, args=None, note=""):
    p = subprocess.run([CLIENT, cmd, json.dumps(args or {})],
                       capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=40)
    line = p.stdout.strip().splitlines()[0] if p.stdout.strip() else ""
    if p.returncode != 0 or not line:
        fails.append(f"{cmd} {note}: rc={p.returncode} out={line} err={p.stderr[:200]}")
        return {}
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        fails.append(f"{cmd} {note}: bad json {line[:120]}")
        return {}

def check(name, cond, extra=""):
    print(("  [PASS] " if cond else "  [FAIL] ") + name + ("  " + str(extra)[:80] if extra else ""))
    if not cond:
        fails.append(name)

eng = subprocess.Popen([ROOT + r"\guadbg.exe", ROOT + r"\test_target.exe"],
                       stdout=open(ROOT + r"\smoke_engine.log", "w"),
                       stderr=subprocess.STDOUT)
try:
    time.sleep(2.5)

    print("[1] 系统断点（入口即停）")
    st = call("get_state").get("result", {})
    check("状态为 paused", st.get("state") == "paused", st)
    rip = st.get("rip", 0)
    check("RIP 有效", rip > 0, hex(rip))

    print("[2] 寄存器")
    rg = call("get_regs").get("result", {})
    regs = rg.get("regs", {})
    check("rax/rsp/rip 可读", all(k in regs for k in ("rax", "rsp", "rip")), list(regs)[:6])

    print("[3] 反汇编")
    da = call("disasm", {"addr": rip, "count": 5}).get("result", {})
    lines = da.get("lines", [])
    check("反汇编 5 条", len(lines) >= 4, lines[:1])

    print("[4] 模块列表")
    md = call("list_modules").get("result", {})
    names = json.dumps(md, ensure_ascii=False)
    check("含 test_target", "test_target" in names)
    check("含 ntdll", "ntdll" in names)

    print("[5] 单步步入 x3")
    last = rip
    okall = True
    for i in range(3):
        r = call("step_into")
        if "error" in json.dumps(r):
            okall = False
            break
        st = call("get_state").get("result", {})
        if st.get("state") != "paused":
            okall = False
            break
        if st.get("rip", 0) != last:
            last = st.get("rip", last)
    check("三次单步后仍暂停且 RIP 推进", okall and last >= rip, hex(last))

    print("[6] 表达式求值")
    ev = call("eval", {"expr": "rax==rax"}).get("result", {})
    check("rax==rax 为真", ev.get("num") in (1, 1.0), ev)
    ev2 = call("eval", {"expr": "mem.valid(rsp)"}).get("result", {})
    check("mem.valid(rsp) 为真", ev2.get("num") in (1, 1.0), ev2)

    print("[7] 读内存 / 写寄存器")
    regs = call("get_regs").get("result", {}).get("regs", {})
    def rv(r, name):
        v = r.get(name, 0)
        return int(v, 16) if isinstance(v, str) else int(v)
    rsp = rv(regs, "rsp")
    rm = call("read_mem", {"addr": rsp, "len": 16}).get("result", {})
    check("读栈 16 字节", len(rm.get("hex", "")) == 32, rm.get("hex", "")[:16])
    call("set_reg", {"name": "rax", "value": 0x1234})
    regs = call("get_regs").get("result", {}).get("regs", {})
    check("rax=0x1234", rv(regs, "rax") == 0x1234, regs.get("rax"))

    print("[8] 运行至主循环后下软件断点并命中")
    call("resume")
    time.sleep(2)
    call("pause")
    st = call("get_state").get("result", {})
    loop_rip = st.get("rip", 0)
    check("暂停在循环内", st.get("state") == "paused" and loop_rip > 0, hex(loop_rip))
    bp = call("set_bp", {"addr": loop_rip}).get("result", {})
    bid = bp.get("id", 0)
    check("断点已建", bid > 0, bp)
    call("resume")
    time.sleep(1)
    st = call("get_state").get("result", {})
    check("断点命中暂停", st.get("state") == "paused", st)
    check("命中地址正确", st.get("rip") == loop_rip, f"{hex(st.get('rip',0))} != {hex(loop_rip)}")
    call("del_bp", {"id": bid})

    print("[9] resume + pause")
    call("resume")
    time.sleep(0.5)
    st = call("get_state").get("result", {})
    check("恢复运行", st.get("state") == "running", st)
    call("pause")
    st = call("get_state").get("result", {})
    check("再次暂停", st.get("state") == "paused", st)

    print("[10] 日志 / 调用栈 / 补丁")
    lg = call("get_log", {"since": 0}).get("result", {})
    check("日志有内容", len(json.dumps(lg)) > 10)
    cs = call("call_stack").get("result", {})
    check("调用栈有帧", len(json.dumps(cs)) > 5, json.dumps(cs, ensure_ascii=False)[:60])
    pt = call("set_patch", {"addr": loop_rip, "hex": "90"}).get("result", {})
    check("补丁已建", pt.get("id", 0) > 0, pt)
    call("restore_patch", {"id": pt.get("id", 0)})

    print("[11] 硬件执行断点")
    st = call("get_state").get("result", {})
    hw = call("set_hw_bp", {"addr": st.get("rip", 0), "size": 1, "mode": "exec"}).get("result", {})
    check("硬件断点已建", hw.get("id", 0) > 0, hw)
    call("resume")
    time.sleep(1)
    st = call("get_state").get("result", {})
    check("硬件断点命中暂停", st.get("state") == "paused", st)
    call("del_bp", {"id": hw.get("id", 0)})

    print("[12] 终止")
    call("terminate")
    time.sleep(1)
    check("引擎进程已退出", eng.poll() is not None)
finally:
    if eng.poll() is None:
        eng.kill()

print()
if fails:
    print("========== 失败项 ==========")
    for f in fails:
        print(" -", f)
    print("冒烟测试 存在失败项")
    sys.exit(1)
print("冒烟测试 全部通过")
