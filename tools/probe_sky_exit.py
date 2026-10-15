# -*- coding: utf-8 -*-
"""判定引擎为什么退出：在**退出路径**上打断点，看目标是不是自己终止的。

背景
    第 132 轮把寄生线程的栈改成目标声明的 2 MB 之后，0xC00000FD 消失了，
    但进程**仍然**会退出 —— 而引擎日志里没有任何致命异常，末尾只有 629 次
    「VEH 放行系统记账异常 code=0xC0000026」然后管道就断了。
    所以现在要回答的是一个二选一：**目标自己终止了进程**，还是那阵风暴的结局？

判据
    在 kernel32!ExitProcess · kernel32!TerminateProcess ·
    ntdll!RtlExitUserProcess · ntdll!NtTerminateProcess 上各下一个软件断点。
      * 若命中 → 是**目标自己**要求退出，而且断点的调用栈就是"谁要求的"。
      * 若一个都不命中，而进程仍然消失 → 那就不是目标主动退出，答案偏向另一边。
    两种结果都有意义，所以这个实验**不会**给出"没结论"。

为什么覆盖四个
    只挂 ExitProcess 不够：目标可能直接调 ntdll（WinLicense 这类保护层常这么干）。
    所以 kernel32 与 ntdll 两边都挂，两层都堵。

已知限制
    软件断点是 0xCC 补丁。若目标对自己进程的内存做校验（保护层会），它可能察觉；
    这一点在本实验里**不作假设**，只把命中的事实记下来。

用法
    python tools/probe_sky_exit.py
    python tools/probe_sky_exit.py --wait 20 --hits 4
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
OUT = os.path.join(ROOT, "out_sky_exit.json")

WANT = [
    ("kernel32.dll", ["ExitProcess", "TerminateProcess"]),
    # kernelbase 也要挂：kernel32 里那两个是**转发 stub**，而调用者可能直接走 kernelbase。
    # 第 133 轮第一次跑时只有 ntdll!NtTerminateProcess 命中，而 kernel32 的两个都没命中 ——
    # 那正是"要么直接调 ntdll，要么走 kernelbase"这个岔口，必须两边都堵。
    ("kernelbase.dll", ["ExitProcess", "TerminateProcess"]),
    ("ntdll.dll", ["RtlExitUserProcess", "NtTerminateProcess", "RtlExitUserThread"]),
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


def as_int(v):
    return v if isinstance(v, int) else int(str(v).strip(), 16)


def main():
    wait_s = 15.0
    hits_want = 4
    if "--wait" in sys.argv:
        wait_s = float(sys.argv[sys.argv.index("--wait") + 1])
    if "--hits" in sys.argv:
        hits_want = int(sys.argv[sys.argv.index("--hits") + 1])

    log = open(os.path.join(ROOT, "probe_exit_engine.log"), "w", encoding="utf-8")
    eng = subprocess.Popen([ENGINE, SKY], stdout=log, stderr=subprocess.STDOUT)
    result = {"resolved": [], "bps": [], "hits": []}
    try:
        time.sleep(8.0)
        st = call("get_state").get("result", {})
        print("  入口暂停: state=%s rip=%#x" % (st.get("state"), st.get("rip", 0)))
        if st.get("state") != "paused":
            problems.append("没停在入口: %r" % st.get("state"))
            return 1

        # 先把导出表查出来，再按名字挑 —— 不猜 resolve_name 的入参格式
        mods = call("list_modules").get("result", {}).get("modules", []) or []
        print("  模块表 %d 项（用来把栈上的返回地址标成 模块+偏移）" % len(mods))
        for mod, names in WANT:
            ex = call("exports", {"module": mod}).get("result", {})
            arr = ex.get("exports", []) or []
            if not arr:
                print("  [%s] 导出表为空或取不到（err=%s）" % (mod, ex.get("error")))
                problems.append("%s 导出表取不到" % mod)
                continue
            byname = {}
            for e in arr:
                nm = str(e.get("name", ""))
                if nm:
                    byname[nm] = e
            sample = list(byname)[:3]
            for nm in names:
                e = byname.get(nm)
                if not e:
                    # ntdll 的部分函数不带名字导出，这一条要如实记下来
                    print("  [%s] 找不到导出 %s（该模块导出 %d 项，样本 %s）"
                          % (mod, nm, len(arr), sample))
                    result["resolved"].append({"module": mod, "name": nm, "addr": None})
                    continue
                addr = as_int(e.get("addr", e.get("address", 0)))
                result["resolved"].append({"module": mod, "name": nm, "addr": "%#x" % addr})
                r = call("set_bp", {"addr": addr}).get("result", {})
                ok = (r.get("error") is None) and r.get("id") is not None
                print("  [%s] %-20s %#x -> %s" % (mod, nm, addr,
                                                  "bp id=%s" % r.get("id") if ok
                                                  else "**失败: %s**" % r.get("error")))
                if ok:
                    result["bps"].append({"module": mod, "name": nm,
                                          "addr": "%#x" % addr, "id": r.get("id")})
                else:
                    problems.append("set_bp 失败 %s!%s: %s" % (mod, nm, r.get("error")))
        if not result["bps"]:
            problems.append("一个退出路径断点都没挂上，后面的'没命中'没有意义")
            return 1

        print()
        for n in range(hits_want):
            call("resume")
            t0 = time.time()
            s = {}
            while time.time() - t0 < wait_s:
                time.sleep(0.25)
                s = call("get_state").get("result", {})
                if s.get("state") == "paused":
                    break
            if s.get("state") != "paused":
                print("  [%d] %.0f 秒内没有命中（state=%r）" % (n + 1, wait_s, s.get("state")))
                break
            rip = s.get("rip", 0)
            regs = call("get_regs").get("result", {}).get("regs", {}) or {}
            cs = call("call_stack").get("result", {})
            frames = cs.get("frames", []) or cs.get("candidates", [])
            ins = call("disasm", {"addr": rip, "count": 3}).get("result", {}).get("lines", [])
            hit = {"n": n + 1, "rip": "%#x" % rip, "reason": str(s.get("reason", ""))[:80],
                   "frames": frames[:8], "insns": [i.get("text", str(i)) for i in ins][:3]}
            # engine 的 call_stack 给的是裸数字（不可读），所以自己去栈上取返回地址：
            # 谁调用 NtTerminateProcess，返回地址就在 [rsp] 上。再按模块区间把它标成
            # "模块+偏移"，这样"是保护层还是 CRT"就成了可读的事实而不是猜测。
            rsp = regs.get("rsp")
            if rsp is not None:
                try:
                    rsp = as_int(rsp)
                    m = call("read_mem", {"addr": rsp, "len": 0x80}).get("result", {})
                    hx = str(m.get("hex", "")).replace(" ", "")
                    if m.get("len") == 0x80 and len(hx) == 0x100:
                        raw = bytes.fromhex(hx)
                        qs = [int.from_bytes(raw[i:i + 8], "little") for i in range(0, 0x80, 8)]
                        hit["stack_qwords"] = ["%016x" % q for q in qs]
                        labelled = []
                        for q in qs:
                            for mo in mods:
                                b = as_int(mo.get("base", 0))
                                sz = as_int(mo.get("size", 0))
                                if b and sz and b <= q < b + sz:
                                    labelled.append({"slot": "%016x" % q,
                                                     "where": "%s+%#x" % (mo.get("name"), q - b)})
                                    break
                        hit["stack_in_modules"] = labelled[:8]
                except Exception as ex:
                    hit["stack_error"] = str(ex)
            result["hits"].append(hit)
            print("  [%d] **命中** rip=%#x  reason=%s" % (n + 1, rip, hit["reason"]))
            for i in hit["insns"]:
                print("        %s" % i)
            if hit.get("stack_in_modules"):
                print("        栈上落在模块里的返回地址（谁调用的）：")
                for e in hit["stack_in_modules"][:5]:
                    print("           %s  →  %s" % (e["slot"], e["where"]))
            elif "stack_error" in hit:
                print("        读栈失败: %s" % hit["stack_error"])
            else:
                print("        栈上没有落在已知模块里的地址")
        if not result["hits"]:
            print()
            print("  **四个退出路径断点一个都没命中，而进程仍然消失**")
            print("  ⇒ 按本文件的判据，这**不是**无结论：它意味着目标**没有**主动调用")
            print("     ExitProcess/TerminateProcess/RtlExitUserProcess/NtTerminateProcess。")
            print("     那就要往另外两个方向查：进程被外部终止，或保护层用了别的路径。")
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
    print("  -> %s  （挂上 %d 个断点，命中 %d 次）"
          % (OUT, len(result["bps"]), len(result["hits"])))
    if problems:
        print("  **%d 个问题**" % len(problems))
        for p in problems:
            print("    - %s" % p)
        return 1
    return 0


sys.exit(main())
