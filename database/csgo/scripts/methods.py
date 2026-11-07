#!/usr/bin/env python3
"""Strict vtable->method attribution: a slot must be a .pdata function start.

Produces /tmp/opencode/csgo-analysis/methods.json:
  { "Class": [ {"vt":rva, "col":rva, "slots":[{"idx":n,"rva":rva,"size":n}] } ] }
"""
import json
import re
import struct

import pefile

PATH = '/tmp/opencode/csgo/csgo/bin/win64/client.dll'
OUT = '/tmp/opencode/csgo-analysis/methods.json'
BASE = 0x180000000


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

    def off2rva(o):
        for va, vs, pr, rs in secs:
            if pr <= o < pr + rs:
                return va + o - pr
        return None

    def u32(r):
        o = rva2off(r)
        return struct.unpack_from('<I', img, o)[0] if o is not None else None

    def u64(r):
        o = rva2off(r)
        return struct.unpack_from('<Q', img, o)[0] if o is not None else None

    fs = {f.struct.BeginAddress: f.struct.EndAddress - f.struct.BeginAddress
          for f in pe.DIRECTORY_ENTRY_EXCEPTION}

    tds = {}
    start = 0
    while True:
        c = [x for x in (img.find(b'.?AV', start), img.find(b'.?AU', start)) if x >= 0]
        if not c:
            break
        k = min(c)
        start = k + 1
        e = img.find(b'@@', k)
        if e < 0 or e - k > 260:
            continue
        raw = img[k:e + 2]
        if not all(32 <= x < 127 for x in raw):
            continue
        tr = off2rva(k)
        if tr is not None:
            tds[tr - 16] = raw.decode('ascii')

    cols = {}
    for tr in tds:
        pat = struct.pack('<I', tr)
        i = 0
        while True:
            o = img.find(pat, i)
            if o < 0:
                break
            i = o + 1
            r = off2rva(o)
            if r is None or r < 12:
                continue
            c = r - 12
            if u32(c) != 1:
                continue
            if u32(c + 20) not in (0, c):
                continue
            cols.setdefault(tds[tr], set()).add(c)

    out = {}
    for name, cl in cols.items():
        for c in cl:
            pat = struct.pack('<Q', BASE + c)
            i = 0
            while True:
                o = img.find(pat, i)
                if o < 0:
                    break
                i = o + 1
                r = off2rva(o)
                if r is None:
                    continue
                vt = r + 8
                slots = []
                for k in range(0, 600):
                    p = u64(vt + 8 * k)
                    if p is None:
                        break
                    rr = p - BASE
                    if rr not in fs:
                        break
                    slots.append({'idx': k, 'rva': rr, 'size': fs[rr]})
                if slots:
                    m = re.match(r'^\.\?A[VU](.+?)@@$', name)
                    key = m.group(1) if m else name
                    out.setdefault(key, []).append({'vt': vt, 'col': c, 'slots': slots})
    json.dump(out, open(OUT, 'w'))
    print('classes', len(out), 'vtables', sum(len(v) for v in out.values()))
    for c in ('C_CSPlayerPawn', 'CCSPlayerController', 'C_BaseEntity', 'CGameEntitySystem', 'CPrediction'):
        v = out.get(c, [])
        print(c, [(hex(e['vt']), len(e['slots'])) for e in v])


if __name__ == '__main__':
    main()
