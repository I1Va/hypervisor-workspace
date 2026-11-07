#!/usr/bin/env python3
"""Dump a class's vtables with slot RVAs, sizes and nearest strings."""
import json, sys
from srv import Mod

m = Mod()
MF = m.mfuncs()
S = {int(k): v for k, v in m.strings().items()}
M = json.load(open('/tmp/opencode/csgo-analysis/srvcache/methods2.json'))


def strings_in(rva, size):
    """string literals referenced by a function body"""
    out = []
    o = m.rva2off(rva)
    if o is None:
        return out
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    for ins in md.disasm(m.data[o:o + size], rva):
        for op in ins.operands:
            if op.type == 3 and op.mem.base == 41:
                t = (ins.address + ins.size + op.mem.disp) & 0xFFFFFFFFFFFFFFFF
                if t in S and len(S[t]) > 4:
                    out.append(S[t])
    return out[:6]


def dump(cls, maxslots=1000):
    for e in M.get(cls, []):
        print(f'--- {cls} vt={e["vt"]:#x} col={e["col"]:#x} slots={len(e["slots"])}')
        for s in e['slots'][:maxslots]:
            r = s['rva']
            ss = strings_in(r, min(s['size'] or 96, 400)) if s['size'] else []
            print(f'  [{s["idx"]:3d}] {r:#08x} sz={s["size"]:6d} {"|".join(ss)[:120]}')


if __name__ == '__main__':
    dump(sys.argv[1])
