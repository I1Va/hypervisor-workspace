#!/usr/bin/env python3
"""ConVar census: walk every call site of the ConVar constructors and recover the
name / default / help / flags operands from the preceding instructions."""
import json, struct
import capstone
from srv import Mod

m = Mod()
S = {int(k): v for k, v in m.strings().items()}
F = m.mfuncs()

CTOR = 0x169f430          # generic ConVar ctor (name, default, flags, help, ...)
FLOAT = 0x17ba50          # float-typed wrapper -> CTOR
CONCMD = 0x16b5788        # ConCommand registration tail-jump target

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
md.skipdata = True

TEXT = (0x1000, 0x1000 + 24546592)
o = m.rva2off(TEXT[0])
code = m.data[o:o + TEXT[1] - TEXT[0]]


def rip_target(ins):
    for op in ins.operands:
        if op.type == 3 and op.mem.base == 41:
            return (ins.address + ins.size + op.mem.disp) & 0xFFFFFFFFFFFFFFFF
    return None


def calls_to(target):
    """direct call sites, no capstone needed"""
    out = []
    for i in range(len(code) - 5):
        if code[i] == 0xE8:
            rel = struct.unpack_from('<i', code, i + 1)[0]
            if TEXT[0] + i + 5 + rel == target:
                out.append(TEXT[0] + i)
    return out


def preceding(call_rva, span=0x80):
    """decode the window before a call and collect rip-relative lea/mov targets
    per register."""
    start = max(TEXT[0], call_rva - span)
    raw = m.data[m.rva2off(start):m.rva2off(call_rva)]
    regs = {}
    for ins in md.disasm(raw, start):
        if ins.address >= call_rva:
            break
        if ins.mnemonic in ('lea', 'mov') and 'rip' in ins.op_str:
            t = rip_target(ins)
            reg = ins.op_str.split(',')[0].strip()
            regs[reg] = t
    return regs


rows = []
for call in calls_to(CTOR):
    r = preceding(call)
    rows.append({'site': call, 'name': r.get('rdx'), 'flags': r.get('r8'),
                 'help': r.get('rax') or r.get('r9')})

for call in calls_to(FLOAT):
    r = preceding(call)
    rows.append({'site': call, 'name': r.get('rdx'), 'float': True})

out = []
for row in rows:
    n = S.get(row.get('name'))
    if not n:
        continue
    out.append({'name': n, 'site': row['site'],
                'help': S.get(row.get('help')) if row.get('help') else None,
                'float': row.get('float', False)})

seen = {}
for e in out:
    seen.setdefault(e['name'], e)
print('call sites:', len(rows), 'named:', len(out), 'unique:', len(seen))
json.dump(list(seen.values()), open('cvars.json', 'w'), indent=1)
sv = sorted(k for k in seen if k.startswith('sv_'))
mp = sorted(k for k in seen if k.startswith('mp_'))
print('sv_', len(sv), 'mp_', len(mp))
print(sv[:40])
