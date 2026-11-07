#!/usr/bin/env python3
"""Find interface-registration stubs: lea r8,name / lea rdx,factory / lea rcx,node / jmp registrar."""
import json
import capstone
from srv import Mod

m = Mod()
S = {int(k): v for k, v in m.strings().items()}
F = m.funcs()
REG = 0x16a10b0

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
md.skipdata = True

out = []
for name, va, vsz, praw, rsz in m.secs:
    if name != '.text':
        continue
    code = m.data[praw:praw + vsz]
    ins = list(md.disasm(code, va))
    for i, x in enumerate(ins):
        if x.id == 0:
            continue
        if x.mnemonic not in ('jmp', 'call'):
            continue
        try:
            ops = x.operands
        except Exception:
            continue
        if not ops or ops[0].type != 2 or ops[0].imm != REG:
            continue
        # walk back up to 4 insns collecting lea reg, [rip+x]
        regs = {}
        for y in ins[max(0, i - 4):i]:
            if y.mnemonic == 'lea' and 'rip' in y.op_str:
                for op in y.operands:
                    if op.type == 3 and op.mem.base == 41:
                        t = (y.address + y.size + op.mem.disp) & 0xFFFFFFFFFFFFFFFF
                        regs[y.op_str.split(',')[0].strip()] = t
        out.append({
            'stub': x.address, 'kind': x.mnemonic,
            'name': S.get(regs.get('r8')),
            'name_rva': regs.get('r8'),
            'factory': regs.get('rdx'),
            'node': regs.get('rcx'),
        })

print(len(out), 'registration stubs')
for r in out:
    f = F.get(r['factory'])
    print(f"stub {r['stub']:#08x} {r['kind']:4s} name={r['name']!r:42s} "
          f"name@{r['name_rva']:#08x} factory={r['factory']:#08x} (sz {f}) node={r['node']:#08x}")
json.dump(out, open('iface_stubs.json', 'w'), indent=1)
