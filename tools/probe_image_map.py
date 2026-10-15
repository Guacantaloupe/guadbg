# -*- coding: utf-8 -*-
"""我们这边：把目标映像的内存属性（Type/State/Protect）读出来，与 ref_image_map.py 对照。

做法：起引擎、停在入口，然后调 mem_map 命令，挑出与目标映像区间重叠的区域并打印。
引擎与目标同进程，所以它给的 VirtualQuery 结果就是**目标映像真实的映射属性**。

用法
    python tools/probe_image_map.py
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

IMG_LO, IMG_HI = 0x140000000, 0x14313F000


def call(cmd, args=None, timeout=60):
    p = subprocess.run([CLIENT, cmd, json.dumps(args or {})],
                       capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=timeout)
    line = p.stdout.strip().splitlines()[0] if p.stdout.strip() else ""
    if p.returncode != 0 or not line:
        return {}
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return {}


def as_int(v):
    return v if isinstance(v, int) else int(str(v).strip(), 16)


def main():
    log = open(os.path.join(ROOT, "probe_imagemap_engine.log"), "w", encoding="utf-8")
    eng = subprocess.Popen([ENGINE, SKY], stdout=log, stderr=subprocess.STDOUT)
    try:
        time.sleep(8.0)
        st = call("get_state").get("result", {})
        if st.get("state") != "paused":
            print("  没停在入口: %r" % st.get("state"))
            return 1
        mm = call("mem_map").get("result", {})
        regions = mm.get("regions") or mm.get("map") or []
        print("  mem_map 返回 %d 个区域（字段示例: %s）"
              % (len(regions), sorted(regions[0].keys()) if regions else "无"))
        if not regions:
            print("  mem_map 结构: %s" % json.dumps(mm, ensure_ascii=False)[:400])
            return 1
        sel = []
        for r in regions:
            b = as_int(r.get("base", 0))
            sz = r.get("size", 0)
            sz = sz if isinstance(sz, int) else int(str(sz), 0)
            if b < IMG_HI and b + sz > IMG_LO:
                sel.append(r)
        print("  与目标映像区间重叠的区域 %d 个：" % len(sel))
        for r in sel:
            print("    base=%s size=%s state=%s protect=%s type=%s"
                  % (r.get("base"), r.get("size"), r.get("state"),
                     r.get("protect"), r.get("type", "（无该字段）")))
        types = sorted({str(r.get("type")) for r in sel})
        print()
        print("  ⇒ 我们这边出现的 type 值: %s" % types)
        print("    与 ref_image_map.py 的 MEM_IMAGE(0x1000000) 对照即可。")
    finally:
        try:
            call("terminate", timeout=15)
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
    return 0


sys.exit(main())
