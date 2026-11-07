#!/usr/bin/env python3
"""Extract networksystem ConVars.

Registration in this module uses adjacent aligned string blocks rather than the
{name*, default*, help*} pointer triple the generic scanner expects. Records are
16-byte aligned; each ConVar contributes a name and a help string. We pair every
cvar-name literal with the nearest preceding descriptive literal.
"""
import net, re, json

m = net.Mod()
D = m.data

NAME = re.compile(rb'(?:\x00|^)(net_|sv_|sdr|ip|hostip|hostport|host|clientport)[a-z0-9_]{1,60}\x00')

def sec_off_ranges():
    out = []
    for n, va, vsz, praw, rsz in m.secs:
        out.append((n, va, praw, rsz))
    return out

cands = []
for n, va, praw, rsz in sec_off_ranges():
    blob = D[praw:praw+rsz]
    for mo in NAME.finditer(blob):
        off = praw + mo.start()
        rva = m.off2rva(off)
        cands.append((rva, off, mo.group()[:-1].decode()))

# Also catch cvars whose names don't match the prefix set but sit in the same cluster
extra = re.compile(rb'(?:\x00|^)[a-z][a-z0-9_]{3,60}\x00')
cluster_lo, cluster_hi = 0x236000, 0x23f000
for n, va, praw, rsz in sec_off_ranges():
    if not (va <= cluster_lo < va+rsz):
        continue
    blob = D[praw:praw+rsz]
    base = praw
    for mo in extra.finditer(blob):
        off = base + mo.start()
        rva = m.off2rva(off)
        if rva is None or not (cluster_lo <= rva < cluster_hi):
            continue
        s = mo.group()[:-1].decode()
        if '_' not in s and not s.startswith(('net', 'sv_', 'sdr')):
            continue
        cands.append((rva, off, s))

# Dedup by rva
seen = {}
for rva, off, name in cands:
    seen.setdefault(rva, name)

def prev_string(off):
    """nearest NUL-terminated printable literal ending before off (within 400B)"""
    lo = max(0, off-400)
    blk = D[lo:off]
    # split on NUL, take last non-empty printable chunk
    parts = blk.split(b'\x00')
    for p in reversed(parts):
        if len(p) < 4:
            continue
        try:
            s = p.decode('ascii')
        except UnicodeDecodeError:
            continue
        if all(31 < ord(c) < 127 or c in '\n\t' for c in s):
            return s
    return None

res = {}
for rva, name in sorted(seen.items()):
    off = m.rva2off(rva)
    res[name] = {'rva': hex(rva), 'help': prev_string(off)}

json.dump(res, open('/tmp/opencode/netcache/cvars.json','w'), indent=1)
print(len(res), 'names')
for k in sorted(res):
    h = res[k]['help'] or ''
    print(f'{k:55s} {h[:90]}')
