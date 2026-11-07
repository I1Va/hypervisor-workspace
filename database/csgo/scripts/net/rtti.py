#!/usr/bin/env python3
"""Relaxed MSVC RTTI vtable recovery for networksystem.dll."""
import net, struct, json, sys

m = net.Mod()
B = m.base
D = m.data

def off2rva(o): return m.off2rva(o)
def rva2off(r): return m.rva2off(r)

# Build the set of valid .text RVAs for sanity
text_ranges = [(va, va+vsz) for n,va,vsz,praw,rsz in m.secs if n == '.text']
def in_text(r):
    return any(a <= r < b for a,b in text_ranges)

# 1. locate type descriptors: ".?AV<Name>@@" strings, and the RTTITypeDescriptor
#    that points to them. MSVC x64 layout:
#      TypeDescriptor: vfptr, spare, name[]
#    so the string starts at TD+0x10.
s = m.strings()
td_by_name = {}
for r,t in s.items():
    if not t.startswith('.?AV'): continue
    # TD struct begins 0x10 before the name
    cand = r - 0x10
    # check the vfptr points into .rdata and spare==0
    vf = m.u64(cand)
    spare = m.u64(cand+8)
    if vf and B <= vf < B+0x300000 and spare == 0:
        td_by_name[t] = cand

print(f'{len(td_by_name)} type descriptors recovered', file=sys.stderr)

# 2. CompleteObjectLocator references the TD at +0xC (signature=1 x64)
#    COL layout x64: sig(4) offset(4) cdOffset(4) pTypeDescriptor(4, image-rel) ...
#    In x64 the TD pointer is a 4-byte RVA at COL+0xC.
td_rva_to_col = {}
for name, td in td_by_name.items():
    td_rva = td
    # scan .rdata for 4-byte value == td_rva within COL structs
    for n,va,vsz,praw,rsz in m.secs:
        if n not in ('.rdata','.data'): continue
        for o in range(praw, praw+rsz-4, 4):
            v = struct.unpack_from('<I', D, o)[0]
            if v != td_rva: continue
            col = off2rva(o) - 0xC
            if col is None or col < 0: continue
            sig = m.u32(col)
            if sig != 1: continue
            td_rva_to_col.setdefault(name, []).append(col)

print(f'{len(td_rva_to_col)} classes with COL', file=sys.stderr)

# 3. find vtables: array of pointers whose [-1] slot points at a COL
col_set = {}
for name, cols in td_rva_to_col.items():
    for c in cols:
        col_set[B + c] = name

vtables = {}
for n,va,vsz,praw,rsz in m.secs:
    if n not in ('.rdata','.data'): continue
    for o in range(praw, praw+rsz-8, 8):
        v = struct.unpack_from('<Q', D, o)[0]
        if v in col_set:
            vt = off2rva(o+8)
            if vt is None: continue
            vtables.setdefault(col_set[v], []).append(vt)

out = {}
for name, vts in vtables.items():
    for vt in vts:
        slots = []
        o = rva2off(vt)
        if o is None: continue
        while o+8 <= len(D):
            p = struct.unpack_from('<Q', D, o)[0]
            r = p - B
            if not in_text(r): break
            slots.append(r); o += 8
        if slots:
            out.setdefault(name, []).append({'vtable': vt, 'slots': slots})

json.dump(out, open('/tmp/opencode/netcache/vtables.json','w'), indent=1)
print(f'{sum(len(v) for v in out.values())} vtables, {len(out)} classes')
for k in sorted(out, key=lambda x: -len(out[x][0]['slots']))[:25]:
    print(f'{k:60s} vt@{hex(out[k][0]["vtable"])} slots={len(out[k][0]["slots"])}')
