#!/usr/bin/env python3
"""Complete ConVar/ConCommand registry extraction.

Registrars
  0x19b2280  CConVarBase::Register(rcx=obj, rdx=name, r8=flags, r9=help,
                                   [rsp+0x110]=ConVarDesc*, xmm0=default)
  0x15a380   CConVar<T>::Init  (thin wrapper that calls 0x19b2280)
  0x19cce10  ConCommand registrar (rcx=obj, rdx=name, r8=cb desc, r9=help,
                                   [rsp+0x20]=flags)

The name is the last `lea rdx,[rip+X]` before the call; help is the last
`lea r9,[rip+X]`, or the value moved into [rsp+0x110].

Output: /tmp/opencode/csgo-analysis/cvars_all.json
"""
import bisect
import json

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import (X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP,
                          X86_REG_RSP, X86_REG_RDX, X86_REG_R9)

PATH = '/tmp/opencode/csgo/csgo/bin/win64/client.dll'
OUT = '/tmp/opencode/csgo-analysis/cvars_all.json'
CONVAR_GENERIC = 0x19b2280
CONVAR_WRAPPER = 0x15a380
CONCMD = 0x19cce10


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

    def cstr(r, maxlen=800):
        if r is None:
            return None
        o = rva2off(r)
        if o is None:
            return None
        e = img.find(b'\0', o, o + maxlen)
        if e < 0 or e - o < 2:
            return None
        b = img[o:e]
        if not all(32 <= c < 127 or c in (9, 10) for c in b):
            return None
        return b.decode('ascii')

    fs = sorted((f.struct.BeginAddress, f.struct.EndAddress) for f in pe.DIRECTORY_ENTRY_EXCEPTION)
    starts = [a for a, _ in fs]

    def owner(a):
        i = bisect.bisect_right(starts, a) - 1
        return fs[i] if i >= 0 and starts[i] <= a < fs[i][1] else None

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    va, vs, pr, rs = secs[0]
    buf = img[pr:pr + min(vs, rs)]
    pos, n = 0, len(buf)
    sites = []
    while pos < n:
        got = list(md.disasm(buf[pos:pos + 0x200], va + pos))
        if not got:
            pos += 1
            continue
        for ins in got:
            if ins.mnemonic == 'call' and ins.op_str.startswith('0x'):
                t = int(ins.op_str, 16)
                if t in (CONVAR_GENERIC, CONVAR_WRAPPER, CONCMD):
                    sites.append((ins.address, t))
        pos = got[-1].address + got[-1].size - va

    out = []
    for site, kind in sites:
        cs = max(0, rva2off(site) - 0x200)
        chunk = img[cs:rva2off(site)]
        start_rva = site - len(chunk)
        reg = {}
        stack = {}
        imm = {}
        for ins in md.disasm(chunk, start_rva):
            try:
                ops = ins.operands
            except Exception:
                continue
            if ins.mnemonic == 'lea' and len(ops) == 2:
                d, s = ops
                if d.type == X86_OP_REG and s.type == X86_OP_MEM and s.mem.base == X86_REG_RIP:
                    reg[d.reg] = ins.address + ins.size + s.mem.disp
            elif ins.mnemonic == 'mov' and len(ops) == 2:
                d, s = ops
                if d.type == X86_OP_MEM and d.mem.base == X86_REG_RSP and s.type == X86_OP_REG:
                    stack[d.mem.disp] = reg.get(s.reg)
                elif d.type == X86_OP_REG and s.type == X86_OP_IMM:
                    imm[d.reg] = s.imm
        name = cstr(reg.get(X86_REG_RDX))
        if kind == CONCMD:
            help_ = cstr(reg.get(X86_REG_R9))
            flags = imm.get(X86_REG_R9)
        else:
            help_ = cstr(stack.get(0x110)) or cstr(reg.get(X86_REG_R9))
            flags = imm.get(0)
        f = owner(site)
        out.append({
            'site': hex(site),
            'func': hex(f[0]) if f else None,
            'reg': 'ConVar' if kind != CONCMD else 'ConCommand',
            'via': hex(kind),
            'name': name,
            'help': help_,
            'flags_imm': flags,
        })
    json.dump(out, open(OUT, 'w'), indent=0)
    cvs = [x for x in out if x['reg'] == 'ConVar' and x['name']]
    cms = [x for x in out if x['reg'] == 'ConCommand' and x['name']]
    print(f'ConVar sites {len(cvs)} unique {len(set(x["name"] for x in cvs))}')
    print(f'ConCommand sites {len(cms)} unique {len(set(x["name"] for x in cms))}')
    print('with help', sum(1 for x in cvs if x['help']))
    for x in cvs[:10]:
        print(f"  {x['name']:48s} {(x['help'] or '')[:60]}")


if __name__ == '__main__':
    main()
