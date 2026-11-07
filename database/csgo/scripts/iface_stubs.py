#!/usr/bin/env python3
"""Find the interfaces a module ACTUALLY registers.

The `ifaces/*.txt` index is a string scan, so it is a superset: it includes every
name-shaped literal in the image, most of which are imported or merely mentioned.
A module's own registrations are the small stubs that end in a `jmp` to the local
CreateInterface. Detecting them gives the real list.

    python3 iface_stubs.py <module>
"""
import argparse, pathlib, re, struct
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

HERE = pathlib.Path(__file__).resolve().parent
CSGO = HERE.parent
CORPUS = pathlib.Path('/home/iabrutin/Work/agent-projects/.corpus/cs2')
VALVE = HERE / '..' / 'index' / 'ifaces'


def find(path):
    pe = pefile.PE(str(path), fast_load=True)
    data = bytes(pe.__data__)
    base = pe.OPTIONAL_HEADER.ImageBase
    secs = [(s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData,
             s.Name.decode(errors='replace').rstrip('\x00').lstrip('.'))
            for s in pe.sections]
    text = next((s for s in secs if s[3] == 'text'), None)
    if text is None:
        raise SystemExit('no .text')
    va, praw, rsz, _ = text
    code = data[praw:praw + rsz]

    def rva2off(r):
        for v, p, z, _ in secs:
            if v <= r < v + max(z, 1):
                return p + (r - v)
        return None

    # Strings for name resolution.
    rdata = [(v, p, z) for v, p, z, n in secs if n in ('rdata', 'data')]
    strings = {}
    cur = bytearray()
    start = 0
    for i, b in enumerate(data):
        if 32 <= b < 127:
            if not cur:
                start = i
            cur.append(b)
        elif cur:
            if len(cur) >= 4:
                for v, p, z in rdata:
                    if p <= start < p + z:
                        strings[v + (start - p)] = cur.decode('ascii')
                        break
            cur = bytearray()

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.skipdata = True
    insns = list(md.disasm(code, va))

    # Find CreateInterface first. The export gives its RVA exactly, which removes
    # the guesswork: every genuine registration stub jumps to that address.
    create_iface = None
    try:
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
        for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if sym.name and sym.name.decode() == 'CreateInterface':
                create_iface = sym.address
    except AttributeError:
        pass

    stubs = []
    for i, ins in enumerate(insns):
        if ins.mnemonic != 'jmp' or not ins.op_str.startswith('0x'):
            continue
        try:
            target = int(ins.op_str, 16)
        except ValueError:
            continue
        # A registration stub jumps at the shared registrar or a small local
        # thunk that does. Accept the export address, or any target within 0x200
        # of it (compilers emit a thin forwarder).
        if create_iface is not None:
            # Exact export address, or the import thunk that sits just before it
            # (Observed: stubs jump to CreateInterface-0x20, a resolved IAT slot).
            if not (create_iface - 0x30 <= target <= create_iface):
                continue
        window = insns[max(0, i - 14):i]
        leas = [w for w in window if w.mnemonic == 'lea' and 'rip' in w.op_str]
        if len(leas) < 2:
            continue
        names = []
        for w in leas:
            frag = w.op_str.split('rip')[1]
            try:
                disp = int(frag.lstrip(' +-').rstrip(']'), 16)
            except ValueError:
                continue
            if '-' in frag:
                disp = -disp
            t = w.address + w.size + disp
            if t in strings:
                names.append(strings[t])
        if not names:
            continue
        name = next((n for n in names
                     if re.match(r'^[A-Za-z_][A-Za-z0-9_]{2,60}\d{3}$', n)), None)
        if name:
            stubs.append({'name': name, 'stub_rva': hex(ins.address),
                          'target_rva': hex(target),
                          'other_strings': [n for n in names if n != name]})
    return stubs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('module')
    args = ap.parse_args()
    path = None
    for d in (CORPUS / 'bin/win64', CORPUS / 'csgo/bin/win64'):
        for ext in ('.dll', '.exe'):
            if (d / f'{args.module}{ext}').is_file():
                path = d / f'{args.module}{ext}'
    if path is None:
        raise SystemExit('no binary')
    stubs = find(path)
    seen = set()
    uniq = []
    for s in stubs:
        if s['name'] in seen:
            continue
        seen.add(s['name'])
        uniq.append(s)
    print(f'{args.module}: {len(uniq)} self-registered interfaces')
    for s in uniq:
        print(f"  {s['name']:44s} stub {s['stub_rva']:>10s} -> {s['target_rva']}")


if __name__ == '__main__':
    main()
