#!/usr/bin/env python3
"""Batch function extraction for the CS2 corpus, parsing each PE once.

Emits per-function disassembly (.asm) plus a manifest carrying size, callees and
the string literals referenced from the function body. The .pdata table gives
exact function boundaries, so nothing here is heuristic.
"""
import json, pathlib, re, sys
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64


class Module:
    def __init__(self, path: str):
        self.path = path
        self.pe = pefile.PE(path, fast_load=True)
        self.pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXCEPTION']])
        self.data = bytes(self.pe.__data__)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.secs = [(s.VirtualAddress, s.Misc_VirtualSize,
                      s.PointerToRawData, s.SizeOfRawData) for s in self.pe.sections]
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.skipdata = True

    def rva2off(self, rva):
        for va, vsz, praw, rsz in self.secs:
            if va <= rva < va + max(vsz, rsz):
                return praw + (rva - va)
        return None

    def functions(self):
        out = []
        try:
            entries = self.pe.DIRECTORY_ENTRY_EXCEPTION
        except AttributeError:
            return out
        for f in entries:
            st, en = f.struct.BeginAddress, f.struct.EndAddress
            if en > st:
                out.append((st, en))
        out.sort()
        return out

    def disasm(self, rva, size, max_ins=12000):
        off = self.rva2off(rva)
        if off is None:
            return ""
        code = self.data[off:off + size]
        lines = []
        for i, ins in enumerate(self.md.disasm(code, rva)):
            lines.append(f"{ins.address:#x}  {ins.mnemonic} {ins.op_str}")
            if i >= max_ins:
                lines.append("... truncated")
                break
        return "\n".join(lines)

    def strings(self, minlen=6, limit=200000):
        """ASCII strings with RVA, found in one pass."""
        out = []
        cur = bytearray()
        start = 0
        for i, b in enumerate(self.data):
            if 32 <= b < 127:
                if not cur:
                    start = i
                cur.append(b)
            else:
                if len(cur) >= minlen:
                    rva = None
                    for va, vsz, praw, rsz in self.secs:
                        if praw <= start < praw + rsz:
                            rva = va + (start - praw)
                            break
                    if rva is not None:
                        out.append((rva, cur.decode('ascii')))
                        if len(out) >= limit:
                            return out
                cur = bytearray()
        return out


def report(path: str, outdir: pathlib.Path, top: int = 400):
    outdir.mkdir(parents=True, exist_ok=True)
    m = Module(path)
    funcs = m.functions()
    strings = m.strings()
    strings.sort()
    import bisect
    srv = [s[0] for s in strings]

    def strings_in(start, end):
        i = bisect.bisect_left(srv, start)
        out = []
        while i < len(strings) and strings[i][0] < end:
            out.append(strings[i][1])
            i += 1
            if len(out) >= 25:
                break
        return out

    funcs.sort(key=lambda f: -(f[1] - f[0]))
    manifest = []
    for st, en in funcs[:top]:
        body = m.disasm(st, en - st)
        calls = sorted(set(re.findall(r"call\s+(0x[0-9a-f]+)", body)))[:60]
        manifest.append({
            "rva": hex(st), "end": hex(en), "size": en - st,
            "calls": calls, "strings": strings_in(st, en),
        })
        (outdir / f"{st:x}.asm").write_text(body)
    (outdir / "_manifest.json").write_text(json.dumps(manifest, indent=1))
    print(f"{pathlib.Path(path).name}: {len(funcs)} functions total, "
          f"wrote top {len(manifest)} to {outdir}")


if __name__ == "__main__":
    report(sys.argv[1], pathlib.Path(sys.argv[2]), int(sys.argv[3]) if len(sys.argv) > 3 else 400)
