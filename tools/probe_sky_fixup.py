# -*- coding: utf-8 -*-
"""把 .sky[0] 改写循环跑多次，逐次记下 (槽位, 旧值, 新值) —— 用数据反推变换。

为什么这样做
    第 128~129 轮已经确定：写者在 0x142c0473a，指令是 mov [rcx+rbx], r10，
    rcx=映像基址、rbx=RVA。而 r10 由一条很长的**自抵消常量链**算出，
    靠眼睛读反汇编解不出来（第 129 轮把这条限制写进了文档）。
    所以换一条路：**不去读它的算法，而是让循环跑很多次，把每次的
    旧值与新值都记下来**，再从数据里看规律。

判据（可证伪）
    对每一次命中都能算出 delta = new - old（64 位）与 new == r10。
    若 r10 恒等于 base+RVA 那类值，就不该出现"某些槽位 delta==0 而另一些 delta==base"。
    这条与"r10 不等于 base+RVA"的既有观察放在一起，两者必须自洽 —— 不自洽就是哪里错了。

为什么在写入指令上放**软件断点**而不是沿用保护页
    保护页是一次性的（第一次违反后该页不再受保护），所以它只能抓到"第一次"。
    而软件断点（0xCC + VEH）在这条指令上每次执行都会停 —— 这才拿得到序列。

用法
    python tools/probe_sky_fixup.py                 # 记 30 次
    python tools/probe_sky_fixup.py --n 120
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
OUT = os.path.join(ROOT, "out_sky_fixup.json")

WRITER = 0x142C0473A     # mov qword ptr [rcx+rbx], r10（第 128 轮运行时定位、第 129 轮静态验证）
BASE = 0x140000000

problems = []


def call(cmd, args=None, timeout=60):
    p = subprocess.run([CLIENT, cmd, json.dumps(args or {})],
                       capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=timeout)
    line = p.stdout.strip().splitlines()[0] if p.stdout.strip() else ""
    if p.returncode != 0 or not line:
        problems.append("%s: rc=%d out=%r err=%r"
                        % (cmd, p.returncode, line[:120], p.stderr[:160]))
        return {}
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        problems.append("%s: 非 JSON %r" % (cmd, line[:120]))
        return {}


def as_int(v):
    """get_regs 给的是**不带 0x 的十六进制字符串**（如 '140000000'），不是整数。
    直接把两个拼起来会得到字符串拼接 —— 上一版就是这么错的（幸好长度检查把它拦住了）。"""
    if isinstance(v, int):
        return v
    return int(str(v).strip(), 16)


def read_qword(addr):
    r = call("read_mem", {"addr": addr, "len": 8}).get("result", {})
    hx = str(r.get("hex", "")).replace(" ", "")
    if r.get("len") != 8 or len(hx) != 16:
        raise RuntimeError("read_mem 短读 @%#x: len=%r hex=%d 字符"
                           % (addr, r.get("len"), len(hx)))
    return int.from_bytes(bytes.fromhex(hx), "little"), hx


def main():
    n_want = 30
    if "--n" in sys.argv:
        n_want = int(sys.argv[sys.argv.index("--n") + 1])

    log = open(os.path.join(ROOT, "probe_fixup_engine.log"), "w", encoding="utf-8")
    eng = subprocess.Popen([ENGINE, SKY], stdout=log, stderr=subprocess.STDOUT)
    rows = []
    try:
        time.sleep(8.0)
        st = call("get_state").get("result", {})
        print("  入口暂停: state=%s rip=%#x" % (st.get("state"), st.get("rip", 0)))
        if st.get("state") != "paused":
            problems.append("没停在入口: %r" % st.get("state"))
            return 1

        r = call("set_bp", {"addr": WRITER}).get("result", {})
        if r.get("error") is not None or r.get("id") is None:
            problems.append("set_bp 失败: %s" % r.get("error"))
            return 1
        print("  写者断点 id=%s @ %#x（软件断点，每次执行都停）" % (r.get("id"), WRITER))
        print()

        for i in range(n_want):
            call("resume")
            t0 = time.time()
            s = {}
            while time.time() - t0 < 12:
                time.sleep(0.2)
                s = call("get_state").get("result", {})
                if s.get("state") == "paused":
                    break
            if s.get("state") != "paused":
                print("  [%d] 12 秒内没命中（state=%s）—— 循环已结束或换路径"
                      % (i + 1, s.get("state")))
                break

            regs = call("get_regs").get("result", {}).get("regs", {}) or {}
            rcx = regs.get("rcx")
            rbx = regs.get("rbx")
            r10 = regs.get("r10")
            if rcx is None or rbx is None or r10 is None:
                problems.append("第 %d 次命中缺寄存器: %s" % (i + 1, list(regs)[:8]))
                break
            try:
                rcx = as_int(rcx)
                rbx = as_int(rbx)
                r10 = as_int(r10)
            except ValueError as ex:
                problems.append("第 %d 次命中的寄存器不是十六进制: %s"
                                % (i + 1, {"rcx": regs.get("rcx"), "rbx": regs.get("rbx"),
                                           "r10": regs.get("r10")}))
                break
            target = rcx + rbx
            old, old_hex = read_qword(target)
            call("step_over")           # 执行这条 store
            time.sleep(0.15)
            new, new_hex = read_qword(target)

            row = {"n": i + 1, "rcx": "%#x" % rcx, "rbx": "%#x" % rbx,
                   "target": "%#x" % target, "r10": "%#x" % r10,
                   "old": "%#x" % old, "new": "%#x" % new,
                   "old_hex": old_hex, "new_hex": new_hex,
                   "stored_matches_r10": (new == r10),
                   "delta": "%#x" % ((new - old) & 0xFFFFFFFFFFFFFFFF)}
            rows.append(row)
            print("  [%2d] slot=%#x  old=%#018x  new=%#018x  delta=%#x  new==r10:%s"
                  % (i + 1, rbx, old, new, (new - old) & 0xFFFFFFFFFFFFFFFF,
                     "是" if new == r10 else "**否**"))

        # ---- 从数据里看规律 ----
        print()
        print("  == 从序列里能读到的 ==")
        if rows:
            slots = [int(r["rbx"], 16) for r in rows]
            deltas = [int(r["delta"], 16) for r in rows]
            print("  命中 %d 次 · 不同槽位 %d 个" % (len(rows), len(set(slots))))
            strides = [slots[i + 1] - slots[i] for i in range(len(slots) - 1)]
            if strides:
                from collections import Counter
                c = Counter(strides)
                print("  相邻槽位步距分布: %s" % dict(c.most_common(6)))
            from collections import Counter as C2
            dc = C2(deltas)
            print("  delta 分布: %s" % dict(dc.most_common(6)))
            nz = [d for d in deltas if d != 0]
            print("  delta==0 的次数: %d / %d" % (len(deltas) - len(nz), len(deltas)))
            if nz:
                print("  非零 delta 的值: %s" % ["%#x" % d for d in nz[:8]])
            ok = sum(1 for r in rows if r["stored_matches_r10"])
            print("  存进去的确实等于 r10: %d / %d" % (ok, len(rows)))
            if ok != len(rows):
                problems.append("有 %d 次存进去的不等于 r10 —— 说明 step_over 的语义"
                                "或读取时机有问题，结论不可用" % (len(rows) - ok))
        else:
            print("  **一次都没记到** —— 这不等于'没有改写'："
                  "可能写者只执行一次就再不复返，也可能断点没生效。")
            problems.append("没记到任何一次命中")
    finally:
        try:
            call("terminate", timeout=20)
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

    json.dump({"writer": "%#x" % WRITER, "rows": rows},
              open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print()
    print("  -> %s  （%d 行）" % (OUT, len(rows)))
    if problems:
        print("  **%d 个问题**" % len(problems))
        for p in problems:
            print("    - %s" % p)
        return 1
    return 0


sys.exit(main())
