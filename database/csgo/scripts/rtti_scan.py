#!/usr/bin/env python3
"""MSVC x64 RTTI reconstruction for client.dll.

Layout:
  vftable[-1] -> RTTICompleteObjectLocator
  COL { sig=1, off, cdOff, pTypeDescriptor(RVA), pClassDescriptor(RVA), pSelf(RVA) }
  TypeDescriptor { vftable, spare, name[] = ".?AV<Class>@@" }
  ClassDescriptor { sig, off, cdOff, nBase, pBaseArray(RVA), ... }
"""
import struct
import pefile

PATH = '/tmp/opencode/csgo/csgo/bin/win64/client.dll'
BASE = 0x180000000


def load():
    pe = pefile.PE(PATH, fast_load=True)
    img = open(PATH, 'rb').read()
    secs = [(s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData) for s in pe.sections]
    return pe, img, secs


def mk(secs, img):
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

    def q(r):
        o = rva2off(r)
        return struct.unpack_from('<Q', img, o)[0] if o is not None else None

    def d(r):
        o = rva2off(r)
        return struct.unpack_from('<I', img, o)[0] if o is not None else None

    def cstr(r):
        o = rva2off(r)
        if o is None:
            return None
        e = img.find(b'\0', o)
        try:
            return img[o:e].decode('ascii')
        except Exception:
            return None

    return rva2off, off2rva, q, d, cstr


def build():
    pe, img, secs = load()
    rva2off, off2rva, q, d, cstr = mk(secs, img)
    # 1. find type descriptors by scanning for ".?AV" / ".?AU" strings
    td = {}  # rva of TypeDescriptor -> name
    names = {}
    start = 0
    while True:
        i = img.find(b'.?AV', start)
        j = img.find(b'.?AU', start)
        if i < 0 and j < 0:
            break
        k = i if (i >= 0 and (j < 0 or i < j)) else j
        start = k + 1
        # must be preceded by 16 bytes header; string starts at TypeDescriptor+16
        e = img.find(b'@@', k)
        if e < 0 or e - k > 300:
            continue
        nm = img[k:e + 2]
        if not all(32 <= c < 127 for c in nm):
            continue
        try:
            nm = nm.decode()
        except Exception:
            continue
        trva = off2rva(k)
        if trva is None:
            continue
        td[trva - 16] = nm
        names[nm] = trva - 16
    # 2. find COLs: sig==1, pTypeDescriptor points into td
    cols = {}
    for trva in list(td):
        pass
    # scan .rdata and .data for COL structures by looking for pSelf back-reference
    out = {}
    for name, trva in names.items():
        # search for the RVA of trva as a 4-byte value
        pat = struct.pack('<I', trva)
        idx = 0
        while True:
            o = img.find(pat, idx)
            if o < 0:
                break
            idx = o + 1
            colrva = off2rva(o) - 12
            if colrva is None or colrva < 0:
                continue
            if d(colrva) != 1:
                continue
            if d(colrva + 20) != colrva:
                continue
            out.setdefault(name, []).append(colrva)
    return out, td, names, (rva2off, off2rva, q, d, cstr)


if __name__ == '__main__':
    out, td, names, h = build()
    print('type descriptors', len(td), 'classes with COL', len(out))
    for k in list(out)[:10]:
        print(k, [hex(x) for x in out[k]])
