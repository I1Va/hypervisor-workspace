#!/usr/bin/env python3
"""Annotated disassembly over merged function boundaries."""
import sys
from srv import Mod

m = Mod()
MF = m.mfuncs()
S = {int(k): v for k, v in m.strings().items()}


def annot(ins):
    tgt = None
    for op in ins.operands:
        if op.type == 3 and op.mem.base == 41:
            tgt = (ins.address + ins.size + op.mem.disp) & 0xFFFFFFFFFFFFFFFF
    note = ''
    if tgt is not None:
        note = f'   ; {hex(tgt)}'
        if tgt in S:
            note += f' "{S[tgt][:100]}"'
        elif tgt in MF:
            note += f' <func size {MF[tgt]}>'
        else:
            for n, va, vsz, praw, rsz in m.secs:
                if va <= tgt < va + max(vsz, rsz):
                    note += f' [{n}]'
                    break
    elif ins.mnemonic in ('call', 'jmp') and ins.operands and ins.operands[0].type == 2:
        t = ins.operands[0].imm
        if t in MF:
            note = f'   ; func size {MF[t]}'
    return note


def show(rva, size=None):
    if size is None:
        fa = m.mfunc_at(rva)
        if not fa:
            print('not in a function')
            return
        rva, size = fa
    for ins in m.disasm(rva, size):
        print(f'{ins.address:#08x}  {ins.mnemonic} {ins.op_str}{annot(ins)}')


if __name__ == '__main__':
    a = int(sys.argv[1], 16)
    n = int(sys.argv[2], 16) if len(sys.argv) > 2 else None
    show(a, n)
