#!/usr/bin/env python3
"""CS2 corpus: extract ConVars/ConCommands with their help text.

ConVar registration in Source 2 references three adjacent string literals:
name, default value, help string. Scanning .rdata for the known cvar-name
pattern and pulling the following pointers recovers most of the registry
without any disassembly.
"""
import pefile, re, json, pathlib, struct, sys

CVAR_NAME = re.compile(rb'(cl_|sv_|mp_|r_|net_|host_|fps_|ai_|weapon_|voice_|snd_|mat_|'
                       rb'ui_|con_|demo_|engine_|game_|g_|c_|sk_|vj_|zoom_)[a-z0-9_]{2,48}\x00')

def extract(path):
    pe = pefile.PE(path, fast_load=True)
    data = pe.__data__
    image_base = pe.OPTIONAL_HEADER.ImageBase
    secs = [(s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData)
            for s in pe.sections]
    def rva2off(rva):
        for va, vsz, praw, rsz in secs:
            if va <= rva < va + max(vsz, rsz):
                return praw + (rva - va)
        return None
    def off2rva(off):
        for va, vsz, praw, rsz in secs:
            if praw <= off < praw + rsz:
                return va + (off - praw)
        return None
    # find all cvar-name strings with their file offsets
    found = []
    for m in CVAR_NAME.finditer(data):
        off = m.start()
        rva = off2rva(off)
        if rva is None:
            continue
        found.append((rva, off, m.group()[:-1].decode()))
    # for each name, look at pointers that reference it anywhere in the image
    # (a pointer table entry or inline lea). We scan .data and .rdata for the VA.
    results = {}
    name_by_va = {image_base + rva: name for rva, off, name in found}
    # build a pointer index: scan all sections for 8-byte values matching these VAs
    ptr_targets = {}
    for va in name_by_va:
        pat = struct.pack('<Q', va)
        start = 0
        while True:
            i = data.find(pat, start)
            if i < 0: break
            start = i + 1
            ptr_targets.setdefault(va, []).append(i)
    for va, name in sorted(name_by_va.items(), key=lambda kv: kv[1]):
        refs = ptr_targets.get(va)
        if not refs:
            continue
        # Source2 ConVarData: {name*, desc*, flags, default*...} — try to read the
        # next pointer as the help string when it resolves to ASCII.
        entry = {"name": name}
        off = refs[0]
        # try the next 3 qwords for pointers to strings
        for k in range(1, 4):
            if off + 8 * (k + 1) > len(data): break
            cand = struct.unpack_from('<Q', data, off + 8 * k)[0]
            o2 = rva2off(cand - image_base) if cand > image_base else None
            if o2 is None: continue
            end = data.find(b'\x00', o2, o2 + 400)
            if end < 0: continue
            try: s = data[o2:end].decode('ascii')
            except UnicodeDecodeError: continue
            if 3 <= len(s) <= 300 and all(31 < ord(c) < 127 or c in '\n\t' for c in s):
                entry[f"str{k}"] = s
        results.setdefault(name, entry)
    return results

if __name__ == '__main__':
    r = extract(sys.argv[1])
    json.dump(r, open(sys.argv[2], 'w'), indent=1)
    print(len(r), 'cvars')
