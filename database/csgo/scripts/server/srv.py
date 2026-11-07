#!/usr/bin/env python3
"""Analysis helper for server.dll. Caches parsed PE, functions, strings, xrefs."""
import json, os, struct, re, sys
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

PATH = '/home/iabrutin/Work/agent-projects/.corpus/cs2/csgo/bin/win64/server.dll'
CACHE = '/tmp/opencode/csgo-analysis/srvcache'
os.makedirs(CACHE, exist_ok=True)

class Mod:
    def __init__(self, path=PATH):
        self.path = path
        self.pe = pefile.PE(path, fast_load=True)
        self.pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXCEPTION'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
        ])
        self.data = open(path, 'rb').read()
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.secs = [(s.Name.rstrip(b'\0').decode(), s.VirtualAddress,
                      s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData)
                     for s in self.pe.sections]
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True
        self._funcs = None
        self._fmap = None

    # ---- address helpers
    def rva2off(self, rva):
        for n, va, vsz, praw, rsz in self.secs:
            if va <= rva < va + max(vsz, rsz):
                d = rva - va
                if d < rsz:
                    return praw + d
                return None
        return None

    def off2rva(self, off):
        for n, va, vsz, praw, rsz in self.secs:
            if praw <= off < praw + rsz:
                return va + off - praw
        return None

    def read(self, rva, n):
        o = self.rva2off(rva)
        return self.data[o:o+n] if o is not None else b''

    def u8(self, rva):  b = self.read(rva, 1);  return b[0] if b else None
    def u16(self, rva):
        b = self.read(rva, 2); return struct.unpack('<H', b)[0] if len(b) == 2 else None
    def u32(self, rva):
        b = self.read(rva, 4); return struct.unpack('<I', b)[0] if len(b) == 4 else None
    def i32(self, rva):
        b = self.read(rva, 4); return struct.unpack('<i', b)[0] if len(b) == 4 else None
    def u64(self, rva):
        b = self.read(rva, 8); return struct.unpack('<Q', b)[0] if len(b) == 8 else None

    def cstr(self, rva, maxlen=400):
        o = self.rva2off(rva)
        if o is None: return None
        e = self.data.find(b'\0', o, o + maxlen)
        if e < 0: return None
        try: return self.data[o:e].decode('utf-8')
        except UnicodeDecodeError: return None

    # ---- functions
    def funcs(self):
        if self._funcs is None:
            fs = {}
            for f in self.pe.DIRECTORY_ENTRY_EXCEPTION:
                st = f.struct.BeginAddress; en = f.struct.EndAddress
                if en > st: fs[st] = en - st
            self._funcs = fs
        return self._funcs

    def mfuncs(self):
        """Merged function map. server.dll's .pdata is chunked: a single function
        is emitted as several RUNTIME_FUNCTION records (hot/cold splitting), and
        only the first chunk is 16-byte aligned. Merging on that boundary
        collapses 108,977 records into the real function count."""
        if getattr(self, '_mfuncs', None) is not None:
            return self._mfuncs
        out = {}
        cur = None
        for k in sorted(self.funcs()):
            end = k + self.funcs()[k]
            if cur is None:
                cur = [k, end]
            elif k % 16 == 0:
                out[cur[0]] = cur[1] - cur[0]
                cur = [k, end]
            else:
                cur[1] = end
        if cur:
            out[cur[0]] = cur[1] - cur[0]
        self._mfuncs = out
        return out

    def mfunc_at(self, rva):
        f = self.mfuncs()
        if rva in f: return rva, f[rva]
        best = None
        for st, sz in f.items():
            if st <= rva < st + sz:
                if best is None or st > best[0]: best = (st, sz)
        return best

    def func_at(self, rva):
        """innermost .pdata function containing rva"""
        f = self.funcs()
        if rva in f: return rva, f[rva]
        best = None
        for st, sz in f.items():
            if st <= rva < st + sz:
                if best is None or st > best[0]: best = (st, sz)
        return best

    def disasm(self, rva, size=None, max_ins=200000):
        if size is None:
            fa = self.func_at(rva)
            if not fa: return []
            rva, size = fa
        o = self.rva2off(rva)
        if o is None: return []
        out = []
        for i, ins in enumerate(self.md.disasm(self.data[o:o+size], rva)):
            out.append(ins)
            if i >= max_ins: break
        return out

    def text(self, rva, size=None):
        return "\n".join(f"{i.address:#x}  {i.mnemonic} {i.op_str}"
                         for i in self.disasm(rva, size))

    # ---- strings
    def strings(self, minlen=5):
        p = os.path.join(CACHE, 'strings.json')
        if os.path.exists(p): return json.load(open(p))
        out = {}
        i = 0; d = self.data
        while True:
            m = re.compile(rb'[\x20-\x7e]{%d,}' % minlen).search(d, i)
            if not m: break
            i = m.end()
            r = self.off2rva(m.start())
            if r is not None:
                out[r] = m.group().decode('ascii')
        json.dump(out, open(p, 'w'))
        return out

    # ---- xrefs
    def xrefs_to(self, target_rva, funcs_only=True):
        """find rip-relative references to target_rva. returns list of insn rvas"""
        out = []
        for st, sz in self.funcs().items():
            for ins in self.disasm(st, sz):
                if 'rip' not in ins.op_str: continue
                for op in ins.operands:
                    if op.type == 3 and op.mem.base == 41:  # X86_OP_MEM, RIP
                        tgt = (ins.address + ins.size + op.mem.disp) & 0xFFFFFFFFFFFFFFFF
                        if tgt == target_rva:
                            out.append(ins.address)
        return out

    def refs_index(self):
        """single sweep of .text (linear, includes leaf functions missing from
        .pdata): map target_rva -> [insn rva] for all rip-relative refs."""
        p = os.path.join(CACHE, 'refs2.json')
        if os.path.exists(p):
            d = json.load(open(p))
            return {int(k): v for k, v in d.items()}
        idx = {}
        md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
        md.skipdata = True
        for name, va, vsz, praw, rsz in self.secs:
            if name != '.text': continue
            code = self.data[praw:praw+vsz]
            for ins in md.disasm(code, va):
                if ins.id == 0:
                    continue
                try:
                    ops = ins.operands
                except Exception:
                    continue
                for op in ops:
                    if op.type == 3 and op.mem.base == 41:
                        tgt = (ins.address + ins.size + op.mem.disp) & 0xFFFFFFFFFFFFFFFF
                        if 0 <= tgt < 0x3000000:
                            idx.setdefault(tgt, []).append(ins.address)
        json.dump({str(k): v for k, v in idx.items()}, open(p, 'w'))
        return idx


if __name__ == '__main__':
    m = Mod()
    print(len(m.funcs()), 'functions')
    print(len(m.strings()), 'strings')
