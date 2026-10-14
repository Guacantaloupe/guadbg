# -*- coding: utf-8 -*-
"""构建 guadbg —— 不调 vcvars64.bat，不依赖作者机器上的路径。

为什么需要它：仓库里两个构建脚本在这台机器上都用不了。

    `_build_engine.bat`
        cd /d "C:\\Users\\scree\\kimi\\tasks\\2026-10-13\\08-46-14-4e459719\\guadbg"
        call "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat"
      —— 第一行是**上游作者自己机器的 checkout 路径**；第二行调的 Community 版
      在这里不存在，而 BuildTools 版的 vcvars64.bat 会打印横幅然后**永不返回**
      （120 秒超时验证过）。这和 smoke_test.py 里那个写死的路径是同一个毛病。

    `build.bat`
      要求已在 "x64 Native Tools Command Prompt" 里（靠 DevEnvDir 判断），
      而这台机器进不去那个环境。

所以本脚本直接定位工具链并复刻 vcvars 会设的 INCLUDE/LIB。
Paper 那边用同样的办法，两边踩到的坑也一样：

    * 漏 `MSVC\\<ver>\\include` -> `#include <array>` 报 C1083
      （MSVC 自己的标准库头不在 Windows SDK 里）
    * 必须 /utf-8 —— 源码里有 UTF-8 中文注释

用法
    python build_engine.py              构建 guadbg.exe
    python build_engine.py --all        连 test_client.exe 与 test_target.exe 一起
"""
import glob
import os
import subprocess
import sys

sys.stdout.reconfigure(encoding="utf-8")

ROOT = os.path.dirname(os.path.abspath(__file__))


def find_cl():
    for r in (r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools",
              r"C:\Program Files\Microsoft Visual Studio\2022\BuildTools",
              r"C:\Program Files\Microsoft Visual Studio\2022\Community",
              r"C:\Program Files\Microsoft Visual Studio\2022\Professional",
              r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise"):
        base = os.path.join(r, "VC", "Tools", "MSVC")
        if not os.path.isdir(base):
            continue
        for ver in sorted(os.listdir(base), reverse=True):
            cl = os.path.join(base, ver, "bin", "Hostx64", "x64", "cl.exe")
            if os.path.exists(cl):
                return cl, os.path.join(base, ver)
    return None, None


def find_sdk():
    for r in (r"C:\Program Files (x86)\Windows Kits\10",
              r"C:\Program Files\Windows Kits\10"):
        inc = os.path.join(r, "Include")
        if not os.path.isdir(inc):
            continue
        for v in sorted(os.listdir(inc), reverse=True):
            if os.path.isdir(os.path.join(inc, v, "um")):
                return r, v
    return None, None


TARGETS = {
    "guadbg.exe": (["engine/guadbg_core.cpp"], ["user32.lib"]),
    "test_client.exe": (["test_client.cpp"], []),
    "test_target.exe": (["test_target.c"], []),
}


def main():
    cl, msvc = find_cl()
    sdk, sdkver = find_sdk()
    if not cl or not sdk:
        print("  找不到工具链: cl=%s sdk=%s" % (cl, sdk))
        return 1
    print("  cl   %s" % cl)
    print("  sdk  %s %s" % (sdk, sdkver))

    vc_inc = os.path.join(msvc, "include")
    incdirs = [vc_inc, os.path.join(vc_inc, "..", "atlmfc", "include"),
               os.path.join(sdk, "Include", sdkver, "ucrt"),
               os.path.join(sdk, "Include", sdkver, "shared"),
               os.path.join(sdk, "Include", sdkver, "um")]
    incdirs = [os.path.normpath(p) for p in incdirs if os.path.isdir(p)]
    libdirs = [os.path.join(msvc, "lib", "x64"),
               os.path.join(sdk, "Lib", sdkver, "ucrt", "x64"),
               os.path.join(sdk, "Lib", sdkver, "um", "x64")]
    libdirs = [p for p in libdirs if os.path.isdir(p)]

    env = dict(os.environ)
    env["PATH"] = os.path.dirname(cl) + os.pathsep + env.get("PATH", "")
    env["INCLUDE"] = os.pathsep.join(incdirs)
    env["LIB"] = os.pathsep.join(libdirs)

    want = list(TARGETS) if "--all" in sys.argv else ["guadbg.exe"]
    rc = 0
    for out in want:
        srcs, libs = TARGETS[out]
        missing = [s for s in srcs if not os.path.exists(os.path.join(ROOT, s))]
        if missing:
            print("  %s: 缺源文件 %s，跳过" % (out, missing))
            continue
        cmd = [cl, "/nologo", "/utf-8", "/EHsc", "/O2", "/MT", "/W3",
               "/Fo" + os.path.join(ROOT, "engine") + "\\",
               "/Fe" + os.path.join(ROOT, out)]
        cmd += [os.path.join(ROOT, s) for s in srcs]
        cmd += libs
        print()
        print("  === 构建 %s ===" % out)
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True)
        o = (r.stdout + r.stderr).decode("utf-8", "replace")
        if r.returncode != 0:
            print("    **失败**")
            for ln in o.strip().split("\n")[-16:]:
                print("      %s" % ln)
            rc = 1
        else:
            p = os.path.join(ROOT, out)
            print("    成功 -> %s  (%s 字节)" % (out, format(os.path.getsize(p), ",")))
            if o.strip():
                for ln in o.strip().split("\n")[:6]:
                    print("      %s" % ln)
    return rc


sys.exit(main())
