#!/usr/bin/env python3
"""Annotate a function: strings referenced, direct callees, size."""
import net, sys, capstone, struct

m = net.Mod()
IDX = m.refs_index()
STR = m.strings()
B = m.base

def annotate(rva):
    fa = m.mfunc_at(rva)
    if not fa:
        print(f'{hex(rva)}: no function'); return
    st, sz = fa
    print(f'=== func {hex(st)} size={sz} ({sz} bytes) ===')
    strs = []
    calls = set()
    for ins in m.disasm(st, sz):
        if ins.mnemonic == 'call' and ins.op_str.startswith('0x'):
            calls.add(int(ins.op_str, 16))
        for op in ins.operands:
            if op.type == 3 and op.mem.base == 41:
                tgt = (ins.address + ins.size + op.mem.disp) & 0xFFFFFFFFFFFFFFFF
                if tgt in STR:
                    strs.append((ins.address, tgt, STR[tgt]))
    seen = set()
    for a, t, s in strs:
        if s in seen: continue
        seen.add(s)
        print(f'  str {hex(a)} -> {hex(t)}  {s[:160]!r}')
    print('  callees:')
    for c in sorted(calls):
        f = m.mfunc_at(c)
        print(f'    {hex(c)}  size={f[1] if f else 0}')

if __name__ == '__main__':
    for a in sys.argv[1:]:
        annotate(int(a, 16))
