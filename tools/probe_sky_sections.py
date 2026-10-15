# -*- coding: utf-8 -*-
"""判定 Sky.exe 的混淆区（.sky）在运行时是否被改写 —— 自解密 / 解包。

为什么需要它
    sky-re 的静态结论是：.sky 那两段（0x2b54000 长 49152、0x2b62000 长 6144000）
    是被处理过的，而 .pdata 对它们的覆盖只有约 1%。而"运行时它是否被换掉"
    这件事，**静态方法原理上看不到**，只能停下来读内存。
    这一条决定了后面是静态硬啃，还是"停在某处把解密后的代码 dump 出来"。

判据（可证伪，而且**带对照**）
    对照：.text 与 .rdata 的窗口，**必须**与文件逐字节相同。
          若对照就不相同，说明是我的 RVA->文件偏移算错了，或映射不是映像映射，
          那么**本次关于 .sky 的结论一律作废** —— 而不是"顺便也记下来"。
    被测：.sky 两段在**入口暂停时**与**运行 N 秒后**分别与文件比较。
          两种结果都有意义：
            相同 => 没有运行时改写，混淆是静态的（那 .pdata 的空洞要另找解释）
            不同 => 存在运行时改写，且差异的位置与长度就是下一步的入口

为什么不能只看"有没有差别"
    入口暂停时导入表已被 guadbg 补完，所以 .idata **本来就该**与文件不同。
    没有对照的话，把 .idata 的必然差异误读成"自解密"是很容易犯的错。

用法
    python tools/probe_sky_sections.py            # 入口暂停 + 运行 10 秒后各测一次
    python tools/probe_sky_sections.py --run 20   # 改运行时长
"""
import hashlib
import json
import os
import struct
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
OUT = os.path.join(ROOT, "out_sky_sections.json")

READ_CAP = 0x10000          # 引擎单条 read_mem 上限 64KB
problems = []


def call(cmd, args=None, timeout=90):
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


def read_mem(addr, size):
    """按 64KB 分块读；返回 bytes，任何一块失败就抛。"""
    out = bytearray()
    off = 0
    while off < size:
        n = min(READ_CAP, size - off)
        r = call("read_mem", {"addr": addr + off, "len": n}).get("result", {})
        hx = str(r.get("hex", "")).replace(" ", "")
        # 长度必须与请求一致：否则就是又踩了默认值回退（见 COMMAND_SCHEMA.md）
        if r.get("len") != n or len(hx) != n * 2:
            raise RuntimeError("read_mem 短读 @%#x: 要 %d 得 %r(hex %d 字符)"
                               % (addr + off, n, r.get("len"), len(hx)))
        out += bytes.fromhex(hx)
        off += n
    return bytes(out)


def pe_sections(path):
    d = open(path, "rb").read()
    e = struct.unpack_from("<I", d, 0x3C)[0]
    if d[e:e + 4] != b"PE\0\0":
        raise RuntimeError("不是 PE")
    coff = e + 4
    nsec = struct.unpack_from("<H", d, coff + 2)[0]
    optsz = struct.unpack_from("<H", d, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", d, opt)[0]
    base = (struct.unpack_from("<Q", d, opt + 24)[0] if magic == 0x20B
            else struct.unpack_from("<I", d, opt + 28)[0])
    sec = opt + optsz
    out = []
    for i in range(nsec):
        o = sec + i * 40
        name = d[o:o + 8].rstrip(b"\0").decode("latin-1")
        vsz, va, rawsz, raw = struct.unpack_from("<IIII", d, o + 8)
        chars = struct.unpack_from("<I", d, o + 36)[0]
        out.append(dict(name=name, va=va, vsize=vsz, raw=raw, rawsize=rawsz,
                        exec_=bool(chars & 0x20000000), write=bool(chars & 0x80000000)))
    return d, base, out


def sha(b):
    return hashlib.sha256(b).hexdigest()[:16]


def diff_summary(mem, disk, max_pairs=128):
    if mem == disk:
        return None
    n = min(len(mem), len(disk))
    first = next((i for i in range(n) if mem[i] != disk[i]), n)
    ndiff = sum(1 for i in range(n) if mem[i] != disk[i])
    # 差异的**字节本身**才是证据：只有计数的话，下一步没法判断
    # 它是"改成了跳转"还是"填了常量"。
    pairs = []
    for i in range(n):
        if mem[i] != disk[i]:
            pairs.append(["%#x" % i, "%02x" % disk[i], "%02x" % mem[i]])
            if len(pairs) >= max_pairs:
                break
    return dict(first_diff=first, n_diff=ndiff, n=n, pairs=pairs)


def main():
    if not os.path.exists(SKY):
        print("  找不到 Sky.exe: %s" % SKY)
        return 1
    run_secs = 10
    if "--run" in sys.argv:
        run_secs = int(sys.argv[sys.argv.index("--run") + 1])

    disk, img_base, secs = pe_sections(SKY)
    print("  映像基址 %#x · %d 个节区" % (img_base, len(secs)))

    # 取样表：(标签, 节区名, 节区内偏移, 长度, 是否对照)
    def find(nm, occurrence=0):
        hits = [s for s in secs if s["name"] == nm]
        return hits[occurrence]

    samples = []
    t = find(".text")
    samples.append(("对照 .text+0x1000", t, 0x1000, 0x1000, True))
    r = find(".rdata")
    samples.append(("对照 .rdata+0x1000", r, 0x1000, 0x1000, True))
    s1 = find(".sky", 0)
    samples.append((".sky[0] 全长", s1, 0, min(s1["vsize"], 0xC000), False))
    s2 = find(".sky", 1)
    for off in (0x0, 0x100000, 0x300000, 0x5D0000):
        if off < s2["vsize"]:
            samples.append((".sky[1]+%#x" % off, s2, off, 0x1000, False))

    for lbl, s, off, size, is_ctl in samples:
        print("    %-22s VA %#x size %#x %s"
              % (lbl, img_base + s["va"] + off, size, "对照" if is_ctl else ""))

    log = open(os.path.join(ROOT, "probe_sections_engine.log"), "w", encoding="utf-8")
    eng = subprocess.Popen([ENGINE, SKY], stdout=log, stderr=subprocess.STDOUT)
    result = {"phase": {}, "sections": []}
    try:
        time.sleep(8.0)
        st = call("get_state").get("result", {})
        print()
        print("  [入口暂停] state=%s rip=%#x" % (st.get("state"), st.get("rip", 0)))
        result["entry_rip"] = st.get("rip", 0)

        snapshots = {}
        for phase in ("entry", "running"):
            if phase == "running":
                call("resume")
                time.sleep(run_secs)
                call("pause")
                time.sleep(0.5)
                st2 = call("get_state").get("result", {})
                result["phase"]["after_run"] = {"state": st2.get("state")}
                print("  [运行 %ds 后] state=%s" % (run_secs, st2.get("state")))
            rows = []
            for lbl, s, off, size, is_ctl in samples:
                va = img_base + s["va"] + off
                try:
                    mem = read_mem(va, size)
                except Exception as ex:
                    rows.append(dict(label=lbl, error=str(ex)))
                    continue
                dsk = disk[s["raw"] + off: s["raw"] + off + size]
                d = diff_summary(mem, dsk)
                # 把被改写窗口的**运行时字节**落盘：那才是能离线分析的东西
                if not is_ctl and d is not None and phase == "running":
                    dd = os.path.join(ROOT, "out_mem")
                    os.makedirs(dd, exist_ok=True)
                    fn = os.path.join(dd, lbl.replace(" ", "_").replace("+", "_")
                                      .replace("[", "").replace("]", "") + ".bin")
                    open(fn, "wb").write(mem)
                    open(fn + ".disk", "wb").write(dsk)
                rows.append(dict(label=lbl, va="%#x" % va, size=size,
                                 control=is_ctl, mem_sha=sha(mem), disk_sha=sha(dsk),
                                 same=(d is None), diff=d))
                if is_ctl and d is not None:
                    problems.append("对照节区 %s 与文件不同 —— 偏移算错或非映像映射，"
                                    "本次 .sky 结论作废" % lbl)
            snapshots[phase] = rows
            print()
            print("  == %s ==" % ("入口暂停" if phase == "entry" else "运行后"))
            for row in rows:
                if "error" in row:
                    print("    %-22s 读取失败: %s" % (row["label"], row["error"]))
                    continue
                tag = ("相同" if row["same"]
                       else "**不同** 首差 +%#x (%d/%d 字节)"
                            % (row["diff"]["first_diff"], row["diff"]["n_diff"], row["diff"]["n"]))
                print("    %-22s %-2s %s" % (row["label"],
                                             "CTL" if row["control"] else "   ", tag))
            result["sections"].append({phase: rows})

        # 运行前后 .sky 自己有没有变
        print()
        print("  == 运行前 vs 运行后（内存对内存）==")
        a = {r["label"]: r for r in snapshots["entry"] if "mem_sha" in r}
        b = {r["label"]: r for r in snapshots["running"] if "mem_sha" in r}
        changed = []
        for k in a:
            if k in b and a[k]["mem_sha"] != b[k]["mem_sha"]:
                changed.append(k)
        result["changed_between_phases"] = changed
        if changed:
            print("    **这些窗口在运行中被改写了**: %s" % ", ".join(changed))
        else:
            print("    没有任何窗口在运行中改变（含 .sky 两段）")
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
    print("  对照通过，结论可用于 .sky")
    return 0


sys.exit(main())
