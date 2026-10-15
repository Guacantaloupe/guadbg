# -*- coding: utf-8 -*-
"""`.sky[1]` 被访问的热力图 —— 用保护页的**命中计数**，不停顿、不改字节。

为什么不用 get_ctx 采样
    `get_ctx` 直接对**运行中**的线程调 GetThreadContext（不挂起）。在 x64 上那返回的是
    "该线程上次进内核时的上下文"，可能很旧。用它画热力图会得到一个**看不出错的错图** ——
    正是本项目反复栽的那一类。所以改用保护页的命中计数：那是真实发生的访问次数。

为什么带 cond="0"
    guard page 分支里，条件表达式求值为 0 时**不暂停**、但仍然 `hit->hits++`。
    于是可以用 250 页的采样跑几分钟而几乎全部时间都花在目标上，而不是花在管道往返上。
    （这就是"热力图"能成立的关键；不带 cond 的话，热页每次都要停一下，根本跑不动。）

判据（**带必须命中的对照**）
    对照页取 `.sky[0]` 的第 0 页与第 +0x2000 页 —— 第 138 轮已经证明它们被高频访问
    （0x142b54000 与 0x142b54038 分别被访问 29 与 30 次；871 个槽位都在 +0x2000 起的页里）。
    **若对照页的计数是 0，说明这套计数根本没在工作，本次热力图一律作废。**

采样方式
    `.sky[1]` 是 6,144,000 字节 = 1500 页，而 MAX_BP 是 256。所以**均匀抽样**：
    每 6 页取 1 页（250 页），加上 2 个对照页 = 252。若执行集中在少数区域，
    1/6 的抽样足以看出来；若铺得很开，也足以看出来。

用法
    python tools/probe_sky_heat.py
    python tools/probe_sky_heat.py --secs 120
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
OUT = os.path.join(ROOT, "out_sky_heat.json")

BASE = 0x140000000
SKY0, SKY0_LEN = 0x2B54000, 0xC000
SKY1, SKY1_LEN = 0x2B62000, 0x5DC000
PG = 0x1000

# 对照：第 138 轮已证明这两页被高频访问，所以它们**必须**有计数
CONTROLS = [BASE + SKY0 + 0x0000, BASE + SKY0 + 0x2000]

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
    secs = 60.0
    if "--secs" in sys.argv:
        secs = float(sys.argv[sys.argv.index("--secs") + 1])
    stride = 6   # 每 stride 页取 1 页
    if "--stride" in sys.argv:
        stride = int(sys.argv[sys.argv.index("--stride") + 1])
    phase = 0    # 抽样起点在被取样的 stride 里的相位（配合不同的 --phase 可补洞）
    if "--phase" in sys.argv:
        phase = int(sys.argv[sys.argv.index("--phase") + 1])
    # --base / --len：采样**任意区域**（默认 .sky[1]）。
    # 需要它是因为一个关键假设必须被检验：.sky 可能只是早期 stub，之后游戏从 .text 跑。
    region = BASE + SKY1
    rlen = SKY1_LEN
    if "--base" in sys.argv:
        region = int(sys.argv[sys.argv.index("--base") + 1], 0)
    if "--len" in sys.argv:
        rlen = int(sys.argv[sys.argv.index("--len") + 1], 0)
    max_pages = 250
    if "--max-pages" in sys.argv:
        max_pages = int(sys.argv[sys.argv.index("--max-pages") + 1])

    log = open(os.path.join(ROOT, "probe_heat_engine.log"), "w", encoding="utf-8")
    eng = subprocess.Popen([ENGINE, SKY], stdout=log, stderr=subprocess.STDOUT)
    result = {"controls": {}, "pages": {}}
    try:
        time.sleep(8.0)
        st = call("get_state").get("result", {})
        print("  入口暂停: state=%s" % st.get("state"))
        if st.get("state") != "paused":
            problems.append("没停在入口: %r" % st.get("state"))
            return 1

        # 采样页：.sky[1] 每 stride 页取一页（--max-pages 可限流，用于**按规模二分**）
        sample = [region + off for off in range(phase * PG, rlen, PG * stride)][:max_pages]
        print("  区域 %#x 共 %d 页中抽样 %d 页（每 %d 页取 1）" % (region, rlen // PG, len(sample), stride))
        print("  对照页 %d 个（第 138 轮已证明它们必然被访问）" % len(CONTROLS))

        addr2id = {}
        for a in CONTROLS + sample:
            # cond="0" ⇒ 求值为 0 ⇒ **不暂停**，但仍然计数
            r = call("set_mem_bp", {"addr": a, "size": PG, "cond": "0"}).get("result", {})
            if r.get("error") is None and r.get("id") is not None:
                addr2id[a] = r.get("id")
            else:
                problems.append("set_mem_bp 失败 @ %#x: %s" % (a, r.get("error")))
        print("  挂上 %d 页保护页（cond=0，不暂停）" % len(addr2id))
        if len(addr2id) < 0.9 * (len(CONTROLS) + len(sample)):
            problems.append("有超过 10% 的页没挂上，热力图会缺一块")
        if not addr2id:
            for p in problems:
                print("    - %s" % p)
            return 1

        # --write-at <地址>:<十六进制>（可重复）：入口暂停时先写内存再放行（走引擎 write_mem）。
        #
        # 用途（第 171 轮）：第 170 轮发现，把正常加载里的三个初值补上之后目标 22 秒不再崩。
        # 这里要回答的是"**它是不是在推进**" —— 而本项目衡量推进的老办法就是
        # 「`.text` / `.sky` 的页面到底有没有被访问」（当年卡在对话框时是**零访问**）。
        # 所以热力图工具必须也能补那三个值，否则测的还是"崩不崩"，不是"走不走"。
        for i, a0 in enumerate(sys.argv):
            if a0 != "--write-at" or i + 1 >= len(sys.argv):
                continue
            spec = sys.argv[i + 1]
            if spec.startswith("--"):
                continue
            a_s, _c, hx = spec.partition(":")
            r = call("write_mem", {"addr": int(a_s, 0), "hex": hx}).get("result", {})
            ok = r.get("ok")
            print("    **写入** %s ← %s → %s"
                  % (a_s, hx, ("ok，%s 字节" % r.get("written")) if ok
                     else "**失败: %s**" % r.get("error")))
            if not ok:
                problems.append("write_mem 失败 @ %s: %s" % (a_s, r.get("error")))

        print("  让它跑 %.0f 秒…" % secs)
        call("resume")
        t0 = time.time()
        while time.time() - t0 < secs:
            time.sleep(5)
            s = call("get_state").get("result", {})
            if s.get("state") is None:
                # 分清"进程死了"与"活着但不应答" —— 上一轮的教训，这个探针一开始忘了带上
                time.sleep(3)
                alive = eng.poll()
                if alive is None:
                    print("    %5.0f 秒: 管道断了，而 eng.poll()=None ⇒ **引擎活着但不应答**"
                          % (time.time() - t0))
                    result["end"] = "alive-but-mute"
                else:
                    print("    %5.0f 秒: 管道断了，eng.poll()=%r ⇒ **引擎进程已退出**"
                          % (time.time() - t0, alive))
                    result["end"] = "process-exited"
                    result["exit_code"] = alive
                break
        print("  跑完 %.0f 秒，读命中计数" % (time.time() - t0))

        lb = call("list_bps").get("result", {})
        bps = lb.get("breakpoints", []) or []
        print("  list_bps 返回 %d 条" % len(bps))
        if not bps:
            problems.append("list_bps 为空，读不到计数")
            for p in problems:
                print("    - %s" % p)
            return 1

        byid = {}
        for e in bps:
            i = e.get("id")
            if i is not None:
                byid[i] = e
        got = {}
        for a, i in addr2id.items():
            e = byid.get(i) or {}
            h = e.get("hits")
            got[a] = int(h) if isinstance(h, (int, float)) else None

        print()
        print("  == 对照（**必须 > 0**，否则本次作废）==")
        ctl_ok = True
        for a in CONTROLS:
            h = got.get(a)
            print("    %#x : %s" % (a, h))
            result["controls"]["%#x" % a] = h
            if not h:
                ctl_ok = False
        if not ctl_ok:
            problems.append("对照页计数为 0 或读不到 ⇒ **保护页计数没有在工作，本次热力图作废**")

        vals = [(a, got.get(a)) for a in sample if got.get(a)]
        hit_pages = len(vals)
        print()
        print("  == 区域 %#x 抽样 %d 页中，被访问过的 %d 页 ==" % (region, len(sample), hit_pages))
        print("     （抽样是每 %d 页取 1，所以全段被访问页的估计 ≈ %d 页 / %d 页）"
              % (stride, hit_pages * stride, rlen // PG))
        tot = sum(v for _, v in vals) or 0
        print("     抽样命中总数 %d" % tot)
        if vals:
            print("     最热的 10 页：")
            for a, v in sorted(vals, key=lambda kv: -kv[1])[:10]:
                off = a - region
                print("       区域+%#08x  %6d  (页 %d)" % (off, v, off // PG))
            offs = sorted(a - region for a, _ in vals)
            print("     被访问页的偏移范围: %#x .. %#x" % (offs[0], offs[-1]))
        result["pages"] = {"%#x" % (a - region): v for a, v in vals}
        result["sampled"] = len(sample)
        result["hit_pages"] = hit_pages
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
    print("  -> %s" % OUT)
    if problems:
        print("  **%d 个问题**" % len(problems))
        for p in problems:
            print("    - %s" % p)
        return 1
    print("  对照通过，热力图可用")
    return 0


sys.exit(main())
