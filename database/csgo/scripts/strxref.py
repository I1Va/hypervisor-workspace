#!/usr/bin/env python3
"""Global string-xref index for client.dll.

Linear-sweeps .text once, resolves every RIP-relative LEA whose target lies in
.rdata/.data, and maps the site to its enclosing .pdata function.

Writes /tmp/opencode/csgo-analysis/strxref.json:
  { "<func_rva>": { "size": n, "strings": ["...", ...], "data_refs": [...] } }
"""
import bisect
import json
import struct

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_REG_RIP

PATH = '/tmp/opencode/csgo/csgo/bin/win64/client.dll'
OUT = '/tmp/opencode/csgo-analysis/strxref.json'


def main():
    pe = pefile.PE(PATH, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXCEPTION']])
    img = open(PATH, 'rb').read()
    secs = [(s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData) for s in pe.sections]

    def rva2off(r):
        for va, vs, pr, rs in secs:
            if va <= r < va + vs and r - va < rs:
                return pr + r - va
        return None

    def cstr(r, maxlen=300):
        o = rva2off(r)
        if o is None:
            return None
        e = img.find(b'\0', o, o + maxlen)
        if e < 0:
            return None
        b = img[o:e]
        if len(b) < 4:
            return None
        if not all(32 <= c < 127 or c in (9, 10) for c in b):
            return None
        return b.decode('ascii')

    fs = sorted((f.struct.BeginAddress, f.struct.EndAddress) for f in pe.DIRECTORY_ENTRY_EXCEPTION)
    starts = [f[0] for f in fs]

    def owner(a):
        i = bisect.bisect_right(starts, a) - 1
        if i >= 0 and fs[i][0] <= a < fs[i][1]:
            return fs[i]
        return None

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    res = {}
    va, vs, pr, rs = secs[0]
    buf = img[pr:pr + min(vs, rs)]
    pos = 0
    n = len(buf)
    while pos < n:
        got = list(md.disasm(buf[pos:pos + 0x400], va + pos))
        if not got:
            pos += 1
            continue
        for ins in got:
            if ins.mnemonic not in ('lea', 'mov', 'movzx', 'movsxd', 'cmp', 'push'):
                continue
            try:
                ops = ins.operands
            except Exception:
                continue
            for op in ops:
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    t = ins.address + ins.size + op.mem.disp
                    s = cstr(t)
                    if s:
                        f = owner(ins.address)
                        key = hex(f[0]) if f else hex(ins.address)
                        ent = res.setdefault(key, {'size': (f[1] - f[0]) if f else 0, 'strings': []})
                        if s not in ent['strings']:
                            ent['strings'].append(s)
        pos = got[-1].address + got[-1].size - va
    json.dump(res, open(OUT, 'w'))
    print('functions with strings', len(res))


if __name__ == '__main__':
    main()
