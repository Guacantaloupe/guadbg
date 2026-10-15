# -*- coding: utf-8 -*-
"""找那个完整性检查：只用**硬件断点**（Dr 寄存器），一个字节都不改。

为什么必须"不改字节"
    第 133 轮的结论：Sky.exe 有进程内的完整性检查，而把 0xCC 软件断点打进
    kernel32/kernelbase/ntdll 当场被它检出（用户看到的对话框
    "Core game files have been corrupted!"），随后它直接调 ntdll!NtTerminateProcess 自杀。
    所以这次的规矩是：**不写任何模块的字节，也不下软件断点**，只用 Dr 寄存器。

找它的思路
    第 133 轮的静态扫描已经排除"搜字符串"那条路（那句话在 Sky.exe 与所有游戏文件里
    都不存在，且 MessageBoxW 也不在导入表里）。所以只能从**行为**上抓：
    它要弹对话框就必然经过 user32!MessageBoxW/A/IndirectW；
    它要自杀就必然经过 ntdll!NtTerminateProcess。
    在这四个地址上挂**硬件执行**断点，命中时的**返回地址**就是"做决定的代码"。

判据（两种结果都有信息量）
    命中  → 返回地址落在哪个模块/哪个 RVA，那就是检查的位置；再由它静态逆推。
    不命中而进程照常跑 → 说明"只用 Dr"这套插桩**没有被检出**，那本身就是重要结论。
    不命中而进程消失   → 说明它没走这四条路径之一，或者 Dr 也被检出（那也是一种结论）。

风险（写下来，不藏）
    硬件断点是经典反调试信号：保护层会查 Dr0–Dr3。所以这次**也可能**被检出。
    若被检出，那么连 Dr 都不能用，只剩保护页与纯静态。

用法
    python tools/probe_sky_integrity.py
    python tools/probe_sky_integrity.py --wait 25 --hits 4
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
OUT = os.path.join(ROOT, "out_sky_integrity.json")

# 四个槽刚好用满：三个 MessageBox + 一个终止路径
WANT = [
    ("user32.dll", ["MessageBoxW", "MessageBoxA", "MessageBoxIndirectW"]),
    ("ntdll.dll", ["NtTerminateProcess"]),
]

# Sky.exe 的两个 .sky 段（RVA），用来判断返回地址是不是落在混淆区里
SKY_RANGES = [(0x2B54000, 0xC000, ".sky[0] (W)"),
              (0x2B62000, 0x5DC000, ".sky[1] (RWX, 装入口)")]

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


def where(addr, mods, base):
    """把地址标成「模块+偏移」，并特别指出它是否落在 Sky 的 .sky 段里。"""
    for mo in mods:
        b = as_int(mo.get("base", 0))
        sz = as_int(mo.get("size", 0))
        if b and sz and b <= addr < b + sz:
            nm = str(mo.get("name"))
            off = addr - b
            note = ""
            if b == base:
                for rva, ln, label in SKY_RANGES:
                    if rva <= off < rva + ln:
                        note = "  ← **在 %s 里**" % label
                        break
            return "%s+%#x%s" % (nm, off, note)
    return None


def main():
    wait_s = 20.0
    hits_want = 4
    if "--wait" in sys.argv:
        wait_s = float(sys.argv[sys.argv.index("--wait") + 1])
    if "--hits" in sys.argv:
        hits_want = int(sys.argv[sys.argv.index("--hits") + 1])

    log = open(os.path.join(ROOT, "probe_integrity_engine.log"), "w", encoding="utf-8")
    eng = subprocess.Popen([ENGINE, SKY], stdout=log, stderr=subprocess.STDOUT)
    result = {"bps": [], "hits": [], "misses": []}
    try:
        time.sleep(8.0)
        st = call("get_state").get("result", {})
        print("  入口暂停: state=%s rip=%#x" % (st.get("state"), st.get("rip", 0)))
        if st.get("state") != "paused":
            problems.append("没停在入口: %r" % st.get("state"))
            return 1

        mods = call("list_modules").get("result", {}).get("modules", []) or []
        base = None
        for mo in mods:
            if str(mo.get("name", "")).lower().endswith("sky.exe"):
                base = as_int(mo.get("base", 0))
        print("  模块 %d 项 · Sky.exe base=%s" % (len(mods), hex(base) if base else "?"))
        if base is None:
            problems.append("模块表里找不到 Sky.exe，返回地址将无法归属")
        result["sky_base"] = hex(base) if base else None

        # ---- --bare：什么都不挂，只让它跑 ----
        #
        # 这是最干净的判别实验：**引擎的常规操作**（手动映射 + 补完 27 项导入 +
        # 钩两个 kernel32 函数 + 改 PEB）本身就会写映像字节（.idata 必然与磁盘不同）。
        # 若那个完整性检查查的是映像字节，那么**任何** guadbg 运行都会在某个时刻被检出 ——
        # 与"我下了 0xCC"无关。所以先跑这一个：不挂任何断点，看它会不会自己弹对话/退出。
        if "--bare" in sys.argv:
            print()
            print("  === --bare：不挂任何断点，只让它跑 %.0f 秒 ===" % wait_s)
            call("resume")
            t0 = time.time()
            last = None
            while time.time() - t0 < wait_s:
                time.sleep(5)
                s = call("get_state").get("result", {})
                st = s.get("state")
                if st != last:
                    print("    %5.0f 秒: state=%r%s"
                          % (time.time() - t0, st,
                             ("  rip=%#x reason=%s" % (s.get("rip", 0),
                                                      str(s.get("reason", ""))[:60]))
                             if st == "paused" else ""))
                    last = st
                if st is None:
                    print("    %5.0f 秒: 引擎已不应答（管道断了）" % (time.time() - t0))
                    break
                if st == "paused":
                    call("resume")
            s = call("get_state").get("result", {})
            print("    结束时 state=%r" % s.get("state"))
            result["bare_end_state"] = s.get("state")
            print("    对照：若它自己弹了「Core game files have been corrupted!」，")
            print("    那就说明**是引擎的常规操作**被检出，而不是我下的断点。")
            raise SystemExit(0)

        print("  --- 只用硬件执行断点（不改任何字节）---")
        for mod, names in WANT:
            ex = call("exports", {"module": mod}).get("result", {})
            arr = ex.get("exports", []) or []
            if not arr:
                print("  [%s] 导出表取不到（err=%s）" % (mod, ex.get("error")))
                problems.append("%s 导出表取不到" % mod)
                continue
            byname = {str(e.get("name", "")): e for e in arr if e.get("name")}
            for nm in names:
                e = byname.get(nm)
                if not e:
                    print("  [%s] 没有导出 %s" % (mod, nm))
                    result["bps"].append({"module": mod, "name": nm, "error": "no export"})
                    continue
                addr = as_int(e.get("addr", e.get("address", 0)))
                # mode 传 "execute"（引擎里非 write/read/rw 一律当执行），size=1
                r = call("set_hw_bp", {"addr": addr, "size": 1, "mode": "execute"}).get("result", {})
                ok = (r.get("error") is None) and r.get("id") is not None
                print("  %-10s %-22s %#x -> %s"
                      % (mod, nm, addr, "hw bp id=%s" % r.get("id") if ok
                         else "**失败: %s**" % r.get("error")))
                result["bps"].append({"module": mod, "name": nm, "addr": "%#x" % addr,
                                      "id": r.get("id"), "error": r.get("error")})
                if not ok:
                    problems.append("set_hw_bp 失败 %s!%s" % (mod, nm))
        if not any(b.get("id") for b in result["bps"]):
            problems.append("一个硬件断点都没挂上，后面的'没命中'没有意义")
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
            cur = s.get("state")
            if cur != "paused":
                print("  [%d] %.0f 秒内没有命中（state=%r）" % (n + 1, wait_s, cur))
                result["misses"].append({"n": n + 1, "state": cur})
                break

            rip = s.get("rip", 0)
            reason = str(s.get("reason", ""))[:80]
            regs = call("get_regs").get("result", {}).get("regs", {}) or {}
            ins = call("disasm", {"addr": rip, "count": 3}).get("result", {}).get("lines", [])
            hit = {"n": n + 1, "rip": "%#x" % rip, "reason": reason,
                   "insns": [i.get("text", str(i)) for i in ins][:3]}
            # 返回地址：[/rsp] 就是 call 压进去的那个
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
                        for idx, q in enumerate(qs[:10]):
                            w = where(q, mods, base) if base else None
                            if w:
                                labelled.append({"slot_index": idx, "addr": "%016x" % q,
                                                 "where": w,
                                                 "is_return": idx == 0})
                        hit["stack_in_modules"] = labelled
                except Exception as ex:
                    hit["stack_error"] = str(ex)
            result["hits"].append(hit)

            print("  [%d] **命中** rip=%#x  reason=%s" % (n + 1, rip, reason))
            for i in hit["insns"]:
                print("        %s" % i)
            if hit.get("stack_in_modules"):
                print("        栈上落在模块里的地址（第 1 个 = 返回地址）：")
                for e in hit["stack_in_modules"][:6]:
                    print("           [%d] %s → %s%s"
                          % (e["slot_index"], e["addr"], e["where"],
                             "   **← 这就是'做决定的代码'**" if e["is_return"] else ""))
            elif "stack_error" in hit:
                print("        读栈失败: %s" % hit["stack_error"])
            else:
                print("        栈上没有被识别的模块地址（可能是 .sky 里的地址或数据）")

        if not result["hits"]:
            st2 = call("get_state").get("result", {})
            print()
            print("  **四个硬件断点一个都没命中。** 而 state=%r" % st2.get("state"))
            print("  按本文件的判据，两种解释都要记，不挑一个当答案：")
            print("    * 若进程仍在跑 → '只用 Dr'这套插桩没有被检出（这本身是重要结论）")
            print("    * 若进程已消失 → 它没走这四条路径，或者 Dr 也被检出了")

        # ---- 可选：**故意触发**检查，而 Dr 网已经张好 ----
        #
        # 上面的结果已经说明"只用 Dr"不会被检出，所以检查根本不会启动 —— 那也就抓不到它。
        # 要抓它，只能**主动去踩那条已知的触发线**：像第 133 轮那样把 0xCC 软件断点
        # 打进系统模块。这一次不同的是 Dr 网已经挂好，于是它一旦反应就会命中，
        # 命中时的返回地址就是"做决定的代码"。
        if "--provoke" in sys.argv:
            print()
            print("  === 故意触发（--provoke）：在系统模块下 0xCC，同时 Dr 网已张好 ===")
            print("  说明：这会再现第 133 轮那个对话框，并且进程随后会自杀。")
            prov = []
            for mod, names in (("kernel32.dll", ["ExitProcess", "TerminateProcess"]),
                               ("kernelbase.dll", ["ExitProcess", "TerminateProcess"]),
                               ("ntdll.dll", ["RtlExitUserProcess", "NtTerminateProcess",
                                              "RtlExitUserThread"])):
                ex = call("exports", {"module": mod}).get("result", {})
                byname = {str(e.get("name", "")): e for e in (ex.get("exports") or [])
                          if e.get("name")}
                for nm in names:
                    e = byname.get(nm)
                    if not e:
                        continue
                    a = as_int(e.get("addr", e.get("address", 0)))
                    r = call("set_bp", {"addr": a}).get("result", {})
                    ok = (r.get("error") is None) and r.get("id") is not None
                    print("    0xCC @ %-10s %-22s %#x -> %s"
                          % (mod, nm, a, "id=%s" % r.get("id") if ok
                             else "**失败: %s**" % r.get("error")))
                    if ok:
                        prov.append({"module": mod, "name": nm, "addr": "%#x" % a})
            result["provoked"] = prov
            if not prov:
                problems.append("--provoke 一个 0xCC 都没下成，触发不了检查")
            else:
                print("  已下 %d 个 0xCC；继续跑，等它反应：" % len(prov))
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
                        print("    [%d] %.0f 秒内没有命中（state=%r）"
                              % (n + 1, wait_s, s.get("state")))
                        break
                    rip = s.get("rip", 0)
                    reason = str(s.get("reason", ""))[:80]
                    regs = call("get_regs").get("result", {}).get("regs", {}) or {}
                    ins = call("disasm", {"addr": rip, "count": 3}).get("result", {}).get("lines", [])
                    hit = {"n": n + 1, "phase": "provoked", "rip": "%#x" % rip,
                           "reason": reason,
                           "insns": [i.get("text", str(i)) for i in ins][:3]}
                    rsp = regs.get("rsp")
                    if rsp is not None:
                        try:
                            rsp = as_int(rsp)
                            m = call("read_mem", {"addr": rsp, "len": 0x80}).get("result", {})
                            hx = str(m.get("hex", "")).replace(" ", "")
                            if m.get("len") == 0x80 and len(hx) == 0x100:
                                raw = bytes.fromhex(hx)
                                qs = [int.from_bytes(raw[i:i + 8], "little")
                                      for i in range(0, 0x80, 8)]
                                lb = []
                                for idx, q in enumerate(qs[:10]):
                                    w = where(q, mods, base) if base else None
                                    if w:
                                        lb.append({"slot_index": idx, "addr": "%016x" % q,
                                                   "where": w, "is_return": idx == 0})
                                hit["stack_in_modules"] = lb
                        except Exception as ex:
                            hit["stack_error"] = str(ex)
                    result["hits"].append(hit)
                    print("    [%d] **命中** rip=%#x  reason=%s" % (n + 1, rip, reason))
                    for i in hit["insns"]:
                        print("          %s" % i)
                    for e in (hit.get("stack_in_modules") or [])[:6]:
                        print("          [%d] %s → %s%s"
                              % (e["slot_index"], e["addr"], e["where"],
                                 "   **← 返回地址（做决定的代码）**" if e["is_return"] else ""))
                if not any(h.get("phase") == "provoked" for h in result["hits"]):
                    print("    **触发了 0xCC 之后仍然没有命中任何一个 Dr 断点** ——")
                    print("    那就说明它的反应不经过这四个入口（例如它自己解析导出表、")
                    print("    或直接系统调用），而不是'没有反应'。")
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
    print("  -> %s  （挂上 %d，命中 %d）"
          % (OUT, sum(1 for b in result["bps"] if b.get("id")), len(result["hits"])))
    if problems:
        print("  **%d 个问题**" % len(problems))
        for p in problems:
            print("    - %s" % p)
        return 1
    return 0


sys.exit(main())
