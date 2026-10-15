# -*- coding: utf-8 -*-
"""抓"是谁在改写 .sky" —— 用硬件**写**断点，命中处就是改写者。

背景
    tools/probe_sky_sections.py 已经量到：运行 10 秒后
      .sky[0]（48KB）有 1954 字节被改写（871 段，首差 +0x2f3b）
      .sky[1] 第一页有 5 字节被改写（首差 +0x36c）
    而对照节区 .text / .rdata 全程与文件相同。
    但那只回答了"被改了"，没回答"**谁改的**"。这一条就是去抓那个写者。

判据
    停下时的 RIP 与它那条指令必须是**写指令**（mov [mem],reg / stos 等），
    而且写地址要落在我们挂的那个窗口里。只报 RIP 不验指令形状的话，
    一个"碰巧停在这里"的暂停会被当成写者 —— 所以 disasm 与地址两条都要对。

已知限制（写清楚，不让它变成沉默的漏报）
    硬件断点按线程生效：Dr 寄存器只应用到**设置时已知的**线程。
    入口暂停时只有 3 个线程；若改写发生在一个**之后新建**的线程里，这里会**抓不到**。
    所以"没命中"输出里会明确写出来，而不是打印一个空的成功。

用法
    python tools/probe_sky_writer.py
    python tools/probe_sky_writer.py --hits 6 --wait 20
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
OUT = os.path.join(ROOT, "out_sky_writer.json")

BASE = 0x140000000
SKY0 = 0x2B54000      # 第一个 .sky：49,152 字节，W 不可执行
SKY1 = 0x2B62000      # 第二个 .sky：6,144,000 字节，RWX，装着 PE 入口

# 窗口按 4 字节对齐（硬件断点在 LEN>1 时要求对齐）
WATCH = [
    ("sky0+0x2f38 (覆盖首差 +0x2f3b)", BASE + SKY0 + 0x2F38),
    ("sky1+0x36c (首差本身)",          BASE + SKY1 + 0x36C),
    ("sky1+0x370 (那个字段的第 5 字节)", BASE + SKY1 + 0x370),
]

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


def main():
    hits_wanted = 6
    wait_s = 15.0
    if "--hits" in sys.argv:
        hits_wanted = int(sys.argv[sys.argv.index("--hits") + 1])
    if "--wait" in sys.argv:
        wait_s = float(sys.argv[sys.argv.index("--wait") + 1])

    log = open(os.path.join(ROOT, "probe_writer_engine.log"), "w", encoding="utf-8")
    eng = subprocess.Popen([ENGINE, SKY], stdout=log, stderr=subprocess.STDOUT)
    result = {"watches": [], "hits": [], "threads_at_setup": None}
    try:
        time.sleep(8.0)
        st = call("get_state").get("result", {})
        print("  入口暂停: state=%s rip=%#x" % (st.get("state"), st.get("rip", 0)))
        if st.get("state") != "paused":
            problems.append("没有停在入口：state=%r" % st.get("state"))
            return 1

        th = call("list_threads").get("result", {}).get("threads", [])
        result["threads_at_setup"] = [t.get("tid") for t in th]
        print("  设置时的线程: %s" % result["threads_at_setup"])
        if not th:
            problems.append("线程表为空，硬件断点无法应用")

        ids = []
        for label, addr in WATCH:
            r = call("set_hw_bp", {"addr": addr, "size": 4, "mode": "write"}).get("result", {})
            err = r.get("error")
            ok = (err is None) and r.get("id") is not None
            print("  %-34s %#x -> %s" % (label, addr, "id=%s" % r.get("id") if ok
                                         else "**失败: %s**" % err))
            result["watches"].append({"label": label, "addr": "%#x" % addr,
                                      "id": r.get("id"), "error": err})
            if ok:
                ids.append(r.get("id"))
            else:
                problems.append("set_hw_bp 失败 %s: %s" % (label, err))
        if not ids:
            problems.append("一个硬件写断点都没挂上，后面的'没命中'没有意义")
            return 1

        print()
        # --guard <VA>：只挂给定的一页保护页，跳过硬件断点。
        # 用途：第 130 轮量到 0x142c0473a 只写 .sky[0]+0x38 两次，**不是**那 871 个字段的
        # 批量改写者（首个变化字节在 +0x2f3b）。所以要去抓真正做批量的那一个。
        only_guard = None
        if "--guard" in sys.argv:
            only_guard = int(sys.argv[sys.argv.index("--guard") + 1], 0)
        if only_guard is not None:
            r = call("set_mem_bp", {"addr": only_guard, "size": 0x1000}).get("result", {})
            ok = (r.get("error") is None) and r.get("id") is not None
            print("  只挂一页保护页 %#x -> %s" % (only_guard,
                                              "id=%s" % r.get("id") if ok
                                              else "**失败: %s**" % r.get("error")))
            result["watches"].append({"label": "only-guard", "addr": "%#x" % only_guard,
                                      "id": r.get("id"), "error": r.get("error"),
                                      "kind": "guard"})
            if not ok:
                problems.append("set_mem_bp 失败: %s" % r.get("error"))
                return 1
            result["guard_ids"] = [r.get("id")]
            print()

        for n in range(hits_wanted):
            call("resume")
            t0 = time.time()
            st = {}
            while time.time() - t0 < wait_s:
                time.sleep(0.3)
                st = call("get_state").get("result", {})
                if st.get("state") == "paused":
                    break
            if st.get("state") != "paused":
                print("  [%d] %.0f 秒内没有命中（state=%s）" % (n + 1, wait_s, st.get("state")))
                break

            rip = st.get("rip", 0)
            reason = str(st.get("reason", ""))
            regs = call("get_regs").get("result", {}).get("regs", {})
            if n == 0:
                # 寄存器名字段到底长什么样，先打一次 —— 上一版按 RAX 取，结果一行都没打出来
                print("        （get_regs 的键样本: %s）" % list(regs)[:14])
            ins = call("disasm", {"addr": rip, "count": 4}).get("result", {}).get("lines", [])
            cs = call("call_stack").get("result", {})
            frames = cs.get("frames", []) or cs.get("candidates", [])
            # 哪一条写指令、写地址是多少、写的值是什么
            stores = [k for k in ("RIP", "rip") if k in (regs or {})]
            hit = {"n": n + 1, "rip": "%#x" % rip, "reason": reason,
                   "insns": [i.get("text", str(i)) for i in ins][:4],
                   "regs_key_sample": stores,
                   "frames": frames[:8]}
            # VEH 命中的常见写法：写目标在 RCX/RDX/RDI 之一，值在另一个寄存器
            # 寄存器名是**小写**（rax/rcx/...）—— 上一版按 RAX 取，一个都没存下来
            for rn in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                       "r8", "r9", "r10", "r11", "rsp", "rbp", "rip"):
                if rn in (regs or {}):
                    hit[rn] = regs[rn]
            result["hits"].append(hit)

            print("  [%d] **命中** rip=%#x  reason=%s" % (n + 1, rip, reason[:40]))
            # 是哪张网抓到的：硬件写断点只有写会命中；保护页读也会。
            # 这一步不能省 —— 否则"读到那张表"会被当成"写那张表"。
            # 引擎的实际措辞是「内存断点 #N」（保护页）与「断点 #N」（软件）。
            # 先按原文匹配，避免把"读到那张表"当成"写那张表"。
            if "内存断点" in reason or "guard" in reason.lower():
                net = "guard-page"
            elif "硬件" in reason or "hw" in reason.lower():
                net = "hardware-write"
            elif "断点" in reason or "breakpoint" in reason.lower():
                net = "software"
            else:
                net = "unknown(reason=%s)" % reason[:30]
            hit["net"] = net
            print("        net=%s" % net)
            for i in hit["insns"]:
                print("        %s" % i)
            for rn in ("rax", "rcx", "rdx", "rdi", "rbx", "r10"):
                if rn in hit:
                    print("        %s=%s" % (rn, hit[rn]))
            if frames:
                print("        调用栈前几帧:")
                for f in frames[:5]:
                    print("           %s" % (f,))

        if not result["hits"]:
            print()
            print("  **一个写断点都没命中** —— 而这不是'没有改写'。")
            print("  已量到确实改写了（probe_sky_sections.py），所以只可能是：")
            print("    * 改写发生在**设置断点之后新建**的线程里（Dr 不继承，见文件头限制）")
            print("    * 或改写用的指令宽度/地址落在三个窗口之外")
            print("  这两条都写在这里，好让下一步是从它们出发，而不是从'没命中'出发。")
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

    json.dump(result, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print()
    print("  -> %s   （命中 %d 次）" % (OUT, len(result["hits"])))
    if problems:
        print("  **%d 个问题**" % len(problems))
        for p in problems:
            print("    - %s" % p)
        return 1
    return 0


sys.exit(main())
