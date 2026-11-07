#!/usr/bin/env python3
"""Disassemble with rip-relative targets resolved to rva + annotation."""
import net, sys
m = net.Mod(); STR = m.strings(); B = m.base

def dump(rva, size=None, maxn=4000):
    fa = m.mfunc_at(rva)
    if size is None:
        if not fa: print('no func'); return
        rva, size = fa
    print(f'--- {hex(rva)} size={size} ---')
    for ins in m.disasm(rva, size, maxn):
        note = ''
        for op in ins.operands:
            if op.type == 3 and op.mem.base == 41:
                t = (ins.address + ins.size + op.mem.disp) & 0xFFFFFFFFFFFFFFFF
                if t in STR:
                    note = f'   ; "{STR[t][:90]}"'
                else:
                    fa2 = m.mfunc_at(t)
                    tag = f' ; func {hex(fa2[0])}' if fa2 else ''
                    note = f'   ; -> {hex(t)}{tag}'
                break
        print(f'{ins.address:#08x}  {ins.mnemonic:8s} {ins.op_str}{note}')

if __name__ == '__main__':
    a = int(sys.argv[1], 16)
    sz = int(sys.argv[2], 0) if len(sys.argv) > 2 else None
    dump(a, sz)
