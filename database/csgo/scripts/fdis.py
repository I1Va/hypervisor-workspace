#!/usr/bin/env python3
"""Annotated function disassembler for client.dll.

Resolves, per instruction:
  * call/jmp targets -> <rva> plus a symbolic name when the target is a known
    .pdata function start, an import thunk, or a named export
  * RIP-relative memory operands -> string literal, IAT slot name, or address

usage:
  python3 fdis.py 0x<rva> [0x<rva> ...]           # disassemble functions
  python3 fdis.py --size 0x300 0x<rva>            # override length
  python3 fdis.py --brief 0x<rva>                 # calls + strings only
"""
import bisect
import json
import struct
import sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_OP_IMM, X86_REG_RIP

PATH = '/tmp/opencode/csgo/csgo/bin/win64/client.dll'
BASE = 0x180000000

_cache = {}


def load():
    if 'ctx' in _cache:
        return _cache['ctx']
    pe = pefile.PE(PATH, fast_load=True)
    pe.parse_data_directories()
    img = open(PATH, 'rb').read()
    secs = [(s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData) for s in pe.sections]

    def rva2off(r):
        for va, vs, pr, rs in secs:
            if va <= r < va + vs and r - va < rs:
                return pr + r - va
        return None

    def off2rva(o):
        for va, vs, pr, rs in secs:
            if pr <= o < pr + rs:
                return va + o - pr
        return None

    def cstr(r, maxlen=400):
        o = rva2off(r)
        if o is None:
            return None
        e = img.find(b'\0', o, o + maxlen)
        if e < 0 or e - o < 3:
            return None
        b = img[o:e]
        if not all(32 <= c < 127 or c in (9, 10) for c in b):
            return None
        return b.decode('ascii')

    fs = sorted((f.struct.BeginAddress, f.struct.EndAddress) for f in pe.DIRECTORY_ENTRY_EXCEPTION)
    starts = [f[0] for f in fs]

    # imports: rva of IAT slot -> name
    iat = {}
    for entry in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []):
        for imp in entry.imports:
            if imp.name:
                iat[imp.address - BASE] = imp.name.decode(errors='replace')
    # exports
    exp = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if e.name:
                exp[e.address] = e.name.decode()

    ctx = dict(pe=pe, img=img, secs=secs, rva2off=rva2off, off2rva=off2rva, cstr=cstr,
               fs=fs, starts=starts, iat=iat, exp=exp)
    _cache['ctx'] = ctx
    return ctx


def owner(ctx, a):
    i = bisect.bisect_right(ctx['starts'], a) - 1
    if i >= 0 and ctx['fs'][i][0] <= a < ctx['fs'][i][1]:
        return ctx['fs'][i]
    return None


def funcname(ctx, rva):
    if rva in ctx['exp']:
        return ctx['exp'][rva]
    if rva in ctx['iat']:
        return 'IAT:' + ctx['iat'][rva]
    return None


def annotate(ctx, rva, size=None, brief=False):
    if size is None:
        f = owner(ctx, rva)
        size = (f[1] - f[0]) if f else 0x100
    off = ctx['rva2off'](rva)
    if off is None:
        return 'bad rva'
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    out = []
    for ins in md.disasm(ctx['img'][off:off + size], rva):
        notes = []
        try:
            ops = ins.operands
        except Exception:
            ops = []
        for op in ops:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                t = ins.address + ins.size + op.mem.disp
                s = ctx['cstr'](t)
                if s is not None:
                    notes.append(f'"{s}"')
                elif t in ctx['iat']:
                    notes.append('IAT:' + ctx['iat'][t])
                else:
                    f = owner(ctx, t)
                    if f and f[0] == t:
                        notes.append(f'func_{t:#x}')
                    else:
                        notes.append(f'data_{t:#x}')
            if op.type == X86_OP_IMM and ins.mnemonic in ('call', 'jmp') and ins.size <= 6:
                t = op.imm
                nm = funcname(ctx, t)
                f = owner(ctx, t)
                if nm:
                    notes.append(nm)
                elif f:
                    notes.append(f'sub_{t:x}')
        line = f'{ins.address:>10x}  {ins.mnemonic:<7} {ins.op_str}'
        if notes:
            line += '   ; ' + ' | '.join(notes)
        out.append(line)
    if brief:
        keep = [l for l in out if '; ' in l or 'call' in l or 'ret' in l]
        return '\n'.join(keep)
    return '\n'.join(out)


if __name__ == '__main__':
    args = sys.argv[1:]
    brief = '--brief' in args
    args = [a for a in args if a != '--brief']
    size = None
    if '--size' in args:
        i = args.index('--size')
        size = int(args[i + 1], 16)
        del args[i:i + 2]
    ctx = load()
    for a in args:
        r = int(a, 16)
        f = owner(ctx, r)
        hdr = f'=== {r:#x}' + (f'  size={f[1]-f[0]}  [{f[0]:#x}-{f[1]:#x}]' if f else '  (no .pdata entry)')
        print(hdr)
        print(annotate(ctx, r, size, brief))
