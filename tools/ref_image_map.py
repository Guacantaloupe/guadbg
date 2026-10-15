# -*- coding: utf-8 -*-
"""参照物：让**正常加载器**把 Sky.exe 作为映像装载，然后报出每个段的内存属性。

为什么需要它
    目标每次跑 1.5 秒就弹「Core game files have been corrupted!」。关掉 Ldr/PEB/钩子都不管用，
    而 IAT 那一格无效（目标会先死于 .idata 的执行故障）。所以我们与"正常启动"究竟差在哪，
    还是没有答案。

    最可疑的一条是**映射方式**：正常加载器把映像映射成 MEM_IMAGE（文件映射 + 节对象），
    而 GuaDbg 是 VirtualAlloc + 逐段拷贝 ⇒ 那会得到 **MEM_PRIVATE**。
    任何 `VirtualQuery` 型的自校验一眼就能看出区别，而这在字节层面**完全看不出来**
    （第 127 轮量过：.text/.rdata 与磁盘逐字节相同）。

本工具
    在本进程里用 LoadLibraryExW(..., DONT_RESOLVE_DLL_REFERENCES) 装载 Sky.exe ——
    它只映射、不解析导入、不跑入口，所以没有副作用。
    然后对头部与每个段调 VirtualQuery，打印 Type / State / Protect。

判据
    正常装载必须是 MEM_IMAGE（0x1000000）。若我们手动映射出来的是 MEM_PRIVATE（0x20000），
    那这条就是"我们与正常启动的一处硬差别"，而且要修就得改成 SEC_IMAGE 节映射。

用法
    python tools/ref_image_map.py [Sky.exe 路径]
"""
import ctypes
import os
import struct
import sys
from ctypes import wintypes

sys.stdout.reconfigure(encoding="utf-8")

DEFAULT = r"C:\Program Files (x86)\Steam\steamapps\common\Sky Children of the Light\Sky.exe"
DONT_RESOLVE_DLL_REFERENCES = 0x00000001

MEM_TYPES = {0x1000000: "MEM_IMAGE", 0x40000: "MEM_MAPPED", 0x20000: "MEM_PRIVATE"}
MEM_STATE = {0x1000: "MEM_COMMIT", 0x2000: "MEM_RESERVE", 0x10000: "MEM_FREE"}
PROT = {0x01: "NOACCESS", 0x02: "R", 0x04: "RW", 0x08: "WC", 0x10: "X", 0x20: "RX",
        0x40: "RWX", 0x80: "WCX"}


class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD),
                ("PartitionId", wintypes.WORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD)]


k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.LoadLibraryExW.restype = wintypes.HMODULE
k32.LoadLibraryExW.argtypes = [wintypes.LPCWSTR, wintypes.HANDLE, wintypes.DWORD]
k32.VirtualQuery.restype = ctypes.c_size_t
k32.VirtualQuery.argtypes = [ctypes.c_void_p, ctypes.POINTER(MBI), ctypes.c_size_t]


def q(addr):
    mbi = MBI()
    if k32.VirtualQuery(ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
        return None
    return mbi


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT
    base = k32.LoadLibraryExW(path, None, DONT_RESOLVE_DLL_REFERENCES)
    if not base:
        print("LoadLibraryExW 失败 err=%d" % ctypes.get_last_error())
        return 1
    print("正常装载（DONT_RESOLVE_DLL_REFERENCES）base=%#x  %s" % (base, os.path.basename(path)))

    hdr = ctypes.string_at(base, 0x1000)
    e_lfanew = struct.unpack_from("<I", hdr, 0x3C)[0]
    nsec = struct.unpack_from("<H", hdr, e_lfanew + 4 + 2)[0]
    optsz = struct.unpack_from("<H", hdr, e_lfanew + 4 + 16)[0]
    opt = e_lfanew + 4 + 20
    imagesize = struct.unpack_from("<I", hdr, opt + 56)[0]
    sec = opt + optsz
    print("SizeOfImage=%#x · %d 个段" % (imagesize, nsec))
    print()
    print("  %-10s %-14s %-12s %-12s %-11s %s" % ("段", "VA", "大小", "Type", "State", "Protect"))
    rows = []
    for i in range(nsec):
        o = sec + i * 40
        name = hdr[o:o + 8].rstrip(b"\0").decode("latin-1")
        vsz, va, rawsz, raw = struct.unpack_from("<IIII", hdr, o + 8)
        a = base + va
        mbi = q(a)
        if not mbi:
            print("  %-10s %#-14x VirtualQuery 失败" % (name, a))
            continue
        t = MEM_TYPES.get(mbi.Type, hex(mbi.Type))
        s = MEM_STATE.get(mbi.State, hex(mbi.State))
        p = PROT.get(mbi.Protect & 0xFF, hex(mbi.Protect))
        print("  %-10s %#-14x %#-12x %-12s %-11s %s" % (name, a, vsz, t, s, p))
        rows.append({"section": name, "va": hex(a), "vsize": hex(vsz),
                     "type": t, "state": s, "protect": p})
    hdrm = q(base)
    if hdrm:
        print()
        print("  映像头        %#-14x %#-12x %-12s %-11s %s"
              % (base, 0x1000, MEM_TYPES.get(hdrm.Type, hex(hdrm.Type)),
                 MEM_STATE.get(hdrm.State, hex(hdrm.State)),
                 PROT.get(hdrm.Protect & 0xFF, hex(hdrm.Protect))))
    print()
    print("  ⇒ 正常装载的段类型应为 MEM_IMAGE(0x1000000)。")
    print("    若我们的手动映射给出 MEM_PRIVATE(0x20000)，那就是与正常启动的一处硬差别。")
    return 0


sys.exit(main())
