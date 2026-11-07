#!/usr/bin/env python3
"""Minimal protobuf wire-format decoder, enough to pull the embedded
EnumDescriptorProto tables (svc_/clc_/net_ message catalogue) out of .rdata."""
import net, json

m = net.Mod()
D = m.data

def rv(b, i):
    """read varint"""
    r = 0; s = 0
    while True:
        x = b[i]; i += 1
        r |= (x & 0x7f) << s
        if not (x & 0x80): return r, i
        s += 7

def fields(b, i, end):
    """yield (field_no, wire_type, payload_or_value, start, next_i)"""
    while i < end:
        key, i = rv(b, i)
        fn, wt = key >> 3, key & 7
        if wt == 0:
            v, i = rv(b, i)
            yield fn, wt, v, i, i
        elif wt == 2:
            ln, i = rv(b, i)
            yield fn, wt, b[i:i+ln], i, i+ln
            i += ln
        elif wt == 1:
            yield fn, wt, b[i:i+8], i, i+8; i += 8
        elif wt == 5:
            yield fn, wt, b[i:i+4], i, i+4; i += 4
        else:
            return

def parse_enum(b, i, end):
    name = None; values = []
    for fn, wt, v, s, n in fields(b, i, end):
        if fn == 1 and wt == 2:
            name = v.decode('utf-8', 'replace')
        elif fn == 2 and wt == 2:
            vn = None; vnum = None
            for f2, w2, v2, s2, n2 in fields(v, 0, len(v)):
                if f2 == 1 and w2 == 2: vn = v2.decode('utf-8', 'replace')
                elif f2 == 2 and w2 == 0: vnum = v2
            if vn is not None:
                values.append((vn, vnum))
    return name, values

def find_enums():
    """Scan for field-5 (enum_type) tags followed by a valid EnumDescriptorProto."""
    out = {}
    n = len(D)
    for i in range(n - 8):
        if D[i] != 0x2a:      # field 5, wiretype 2
            continue
        try:
            ln, j = rv(D, i+1)
        except Exception:
            continue
        if ln < 8 or ln > 8000 or j+ln > n:
            continue
        name, vals = parse_enum(D, j, j+ln)
        if not name or not vals:
            continue
        if not all(c.isalnum() or c == '_' for c in name):
            continue
        # require at least one value that looks like a message name
        if sum(1 for vn,_ in vals if vn and ('_' in vn or vn.isalnum())) < 2:
            continue
        if name in out:
            # keep the richest
            if len(vals) <= len(out[name][1]):
                continue
        out[name] = (m.off2rva(i), vals)
    return out

if __name__ == '__main__':
    e = find_enums()
    print(len(e), 'enums')
    res = {}
    for name, (rva, vals) in sorted(e.items()):
        print(f'== {name} @ {rva:#x}  ({len(vals)} values)')
        res[name] = {'rva': rva, 'values': vals}
        for vn, vnum in vals:
            print(f'   {vnum:6d}  {vn}')
    json.dump(res, open('/tmp/opencode/netcache/enums.json','w'), indent=1)
