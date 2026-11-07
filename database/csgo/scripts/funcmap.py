#!/usr/bin/env python3
"""Function map + disassembly helper for the CS2 corpus.

x64 PE images carry .pdata: an array of RUNTIME_FUNCTION (start/end RVA of
every non-leaf function). That is exact function discovery without heuristics -
the same source the Windows unwinder uses. This tool turns it into a JSON map
and can disassemble any function by RVA.
"""
import json, pathlib, struct, sys
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

def load(path):
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXCEPTION']])
    return pe

def function_map(path: str) -> list[dict]:
    """Every function from .pdata: (start_rva, end_rva, size)."""
    pe = load(path)
    base = pe.OPTIONAL_HEADER.ImageBase
    out = []
    try:
        funcs = pe.DIRECTORY_ENTRY_EXCEPTION
    except AttributeError:
        return []
    for f in funcs:
        st = f.struct.BeginAddress
        en = f.struct.EndAddress
        out.append({"start": st, "end": en, "size": en - st})
    out.sort(key=lambda d: d["start"])
    return out

def disassemble(path: str, rva: int, size: int, max_ins=20000) -> str:
    pe = load(path)
    code = pe.get_data(rva, size)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.skipdata = True
    lines = []
    for i, ins in enumerate(md.disasm(code, rva)):
        lines.append(f"{ins.address:#x}  {ins.mnemonic} {ins.op_str}")
        if i >= max_ins:
            lines.append("... truncated")
            break
    return "\n".join(lines)

def strings_with_rva(path: str, minlen=6, limit=200000):
    """Strings with their RVA (mapped through the section table)."""
    pe = load(path)
    image = pe.__data__
    base = pe.OPTIONAL_HEADER.ImageBase
    secs = [(s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData, s.Name.decode(errors='replace').rstrip('\x00')) for s in pe.sections]
    def off2rva(off):
        for va, vsz, praw, rsz, _ in secs:
            if praw <= off < praw + rsz:
                return va + (off - praw)
        return None
    out = []
    data = open(path, 'rb').read()
    cur = bytearray(); start = 0
    for i, b in enumerate(data):
        if 32 <= b < 127:
            if not cur: start = i
            cur.append(b)
        else:
            if len(cur) >= minlen:
                rva = off2rva(start)
                if rva is not None:
                    out.append({"rva": rva, "s": cur.decode('ascii')})
                    if len(out) >= limit: break
            cur = bytearray()
    return out

if __name__ == "__main__":
    cmd = sys.argv[1]
    path = sys.argv[2]
    if cmd == "map":
        m = function_map(path)
        print(json.dumps(m))
    elif cmd == "disasm":  # disasm <path> <rva_hex> <size>
        print(disassemble(path, int(sys.argv[3], 16), int(sys.argv[4], 16)))
    elif cmd == "strings":
        for r in strings_with_rva(path, minlen=int(sys.argv[3]) if len(sys.argv) > 3 else 6):
            print(f"{r['rva']:x}  {r['s']}")
    elif cmd == "summary":
        m = function_map(path)
        total = sum(f["size"] for f in m)
        big = sorted(m, key=lambda f: -f["size"])[:15]
        print(f"functions: {len(m)}  total code bytes: {total/1e6:.1f}MB")
        for f in big:
            print(f"  {f['start']:#x}-{f['end']:#x}  {f['size']/1024:.1f}KB")
