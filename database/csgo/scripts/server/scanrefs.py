#!/usr/bin/env python3
"""Linear sweep of .text for rip-relative references. Writes refs2.json."""
import json, os, sys
import capstone
from srv import Mod

m = Mod()
idx = {}
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
md.skipdata = True
for name, va, vsz, praw, rsz in m.secs:
    if name != '.text':
        continue
    code = m.data[praw:praw + vsz]
    n = 0
    for ins in md.disasm(code, va):
        n += 1
        if ins.id == 0:
            continue
        try:
            ops = ins.operands
        except Exception:
            continue
        for op in ops:
            if op.type == 3 and op.mem.base == 41:
                tgt = (ins.address + ins.size + op.mem.disp) & 0xFFFFFFFFFFFFFFFF
                if 0 <= tgt < 0x3000000:
                    idx.setdefault(tgt, []).append(ins.address)
    print(name, n, 'insns', len(idx), 'targets', flush=True)

json.dump({str(k): v for k, v in idx.items()}, open('srvcache/refs2.json', 'w'))
print('done', len(idx), flush=True)
