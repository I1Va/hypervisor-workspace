#!/usr/bin/env python3
"""Evidence collector for writing a module document.

Gathers, in one pass and without disassembly: identity, sections, exports,
imports, RTTI, interfaces, `__FILE__` provenance (which tells you the real
source directories, and therefore the subsystem), and the largest functions
with their referenced strings.

    python3 module_evidence.py <module> [--json]
"""
import argparse, json, pathlib, re, sys
import pefile

HERE = pathlib.Path(__file__).resolve().parent
CSGO = HERE.parent
CORPUS = pathlib.Path('/home/iabrutin/Work/agent-projects/.corpus/cs2')
DOCS = pathlib.Path('/tmp/opencode/csgo-analysis/docs')

# Merged function boundaries: .pdata is hot/cold chunks, so adjacent records that
# are not 16-byte-aligned starts belong to the same function.
def functions(pe):
    out = []
    try:
        for f in pe.DIRECTORY_ENTRY_EXCEPTION:
            st, en = f.struct.BeginAddress, f.struct.EndAddress
            if en > st:
                out.append((st, en))
    except AttributeError:
        return []
    out.sort()
    merged = []
    for st, en in out:
        if merged and st % 16 and st >= merged[-1][0] and st < merged[-1][1] + 16:
            merged[-1] = (merged[-1][0], max(merged[-1][1], en))
        else:
            merged.append((st, en))
    return merged


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('module')
    ap.add_argument('--json', action='store_true')
    args = ap.parse_args()

    path = None
    for d in (CORPUS / 'bin/win64', CORPUS / 'csgo/bin/win64'):
        for ext in ('.dll', '.exe'):
            if (d / f'{args.module}{ext}').is_file():
                path = d / f'{args.module}{ext}'
    if path is None:
        raise SystemExit(f'no binary for {args.module}')

    pe = pefile.PE(str(path), fast_load=True)
    pe.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXCEPTION'],
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG'],
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG'],
    ])
    data = bytes(pe.__data__)
    h = pe.OPTIONAL_HEADER

    # ASCII strings with RVA, from .rdata and .data only: .text bytes decode as
    # plausible "strings" constantly, which is pure noise in a function summary.
    secs = [(s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData,
             s.Name.decode(errors='replace').rstrip('\x00').lstrip('.')) for s in pe.sections]
    def off2rva(o):
        for va, praw, rsz, _ in secs:
            if praw <= o < praw + rsz:
                return va + (o - praw)
        return None
    allowed = {va: (praw, rsz) for va, praw, rsz, nm in secs
               if nm in ('rdata', 'data', 'rsrc')}
    strings = []
    cur = bytearray()
    start = 0

    def record(start_off, run_bytes):
        if len(run_bytes) < 5:
            return
        for va, (praw, rsz) in allowed.items():
            if praw <= start_off < praw + rsz:
                strings.append((va + (start_off - praw), run_bytes.decode('ascii')))
                return

    for i, b in enumerate(data):
        if 32 <= b < 127:
            if not cur:
                start = i
            cur.append(b)
        elif cur:
            record(start, cur)
            cur = bytearray()

    # __FILE__ provenance: the strongest evidence of what a module is.
    src_files = sorted({s for _, s in strings
                        if re.search(r'\.(cpp|c|h|hpp|inl)$', s)
                        and ('\\' in s or '/' in s)
                        and not s.startswith('C:\\')})

    funcs = functions(pe)
    srv = sorted(strings)
    import bisect
    rvas = [r for r, _ in srv]
    str_at = {r: s for r, s in srv}

    def str_near(rva):
        """A `lea` usually targets the string start, but sometimes mid-string."""
        i = bisect.bisect_right(rvas, rva) - 1
        if i >= 0:
            r, s = srv[i]
            if 0 <= rva - r < len(s) + 1:
                return s
        return None

    # Functions do not *contain* strings: .text holds code and the literals are
    # in .rdata, reached by RIP-relative `lea`. So resolve each function's actual
    # references instead of testing address containment (which can never match).
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.skipdata = True
    raw = data

    def refs_for(lo, hi, cap=14):
        off = None
        for s in pe.sections:
            va, praw, rsz = s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData
            if va <= lo < va + max(rsz, 1):
                off = praw + (lo - va)
                break
        if off is None:
            return []
        out, seen = [], set()
        try:
            for ins in md.disasm(raw[off:off + min(hi - lo, 60000)], lo):
                if ins.mnemonic != 'lea' or 'rip' not in ins.op_str:
                    continue
                # Capstone prints the displacement, not the target: the string is
                # at the end of the instruction plus that displacement.
                try:
                    disp = int(ins.op_str.split('rip')[1].lstrip(' +-').rstrip(']'), 16)
                except (IndexError, ValueError):
                    continue
                if '-' in ins.op_str.split('rip')[1]:
                    disp = -disp
                tgt = ins.address + ins.size + disp
                s = str_at.get(tgt) or str_near(tgt)
                if s and s not in seen:
                    seen.add(s)
                    out.append(s)
                if len(out) >= cap:
                    break
        except Exception:
            pass
        return out

    scored = []
    for lo, hi in funcs:
        scored.append((lo, hi, refs_for(lo, hi)))
    scored.sort(key=lambda x: (-len(x[2]), -(x[1] - x[0])))
    funcs_ranked = [(lo, hi) for lo, hi, _ in scored]
    refs_by_rva = {lo: r for lo, _, r in scored}

    def strings_in(lo, hi, cap=12):
        return refs_by_rva.get(lo, [])[:cap]

    export_names = []
    try:
        export_names = [s.name.decode() if s.name else f'ord{s.ordinal}'
                        for s in pe.DIRECTORY_ENTRY_EXPORT.symbols]
    except AttributeError:
        pass

    imports = []
    try:
        imports = [{'dll': e.dll.decode(),
                    'count': len(e.imports),
                    'names': [(i.name.decode() if i.name else f'ord{i.ordinal}')
                              for i in e.imports]}
                   for e in pe.DIRECTORY_ENTRY_IMPORT]
    except AttributeError:
        pass

    pdb = []
    try:
        pdb = [(getattr(d.entry, 'PdbFileName', b'') or b'').decode(errors='replace').rstrip('\x00')
               for d in pe.DIRECTORY_ENTRY_DEBUG if d.struct.Type == 2]
    except AttributeError:
        pass

    rtti_file = CSGO / 'index' / 'rtti' / f'{args.module}.txt'
    rtti = rtti_file.read_text().splitlines() if rtti_file.is_file() else []
    iface_file = CSGO / 'index' / 'ifaces' / f'{args.module}.txt'
    ifaces = iface_file.read_text().splitlines() if iface_file.is_file() else []

    # ConVar catalogue: the name and its help string sit close together in
    # .rdata, because the registration call is given both as adjacent literals.
    cvars = []
    name_re = re.compile(r'^[a-z][a-z0-9_]{2,48}$')
    prefixes = ('cl_', 'sv_', 'mp_', 'mm_', 'r_', 'net_', 'host_', 'snd_',
                'ui_', 'mat_', 'ai_', 'phys_', 'joy_', 'key_', 'in_', 'sc_',
                'tv_', 'spec_', 'fps_', 'engine_', 'panorama_', 'cs_', 'bot_',
                'vgui_', 'voice_', 'steam_')
    for i, (r, s) in enumerate(srv):
        if not name_re.match(s) or not s.startswith(prefixes):
            continue
        help_text = None
        for r2, s2 in srv[i + 1:i + 5]:
            if r2 - r < 400 and len(s2) > 12 and s2[0].isupper() \
                    and ' ' in s2:
                help_text = s2
                break
        cvars.append({'name': s, 'rva': hex(r), 'help': help_text})

    doc = {
        'module': args.module,
        'path': str(path),
        'size': path.stat().st_size,
        'size_of_image': h.SizeOfImage,
        'imagebase': hex(h.ImageBase),
        'entrypoint_rva': hex(h.AddressOfEntryPoint),
        'timestamp': pe.FILE_HEADER.TimeDateStamp,
        'pdb': pdb,
        'sections': [{'name': s.Name.decode(errors='replace').rstrip('\x00').lstrip('.'),
                      'vsize': s.Misc_VirtualSize, 'rawsize': s.SizeOfRawData,
                      'chars': hex(s.Characteristics)} for s in pe.sections],
        'pdata_records': len(functions(pe)) and sum(1 for _ in (pe.DIRECTORY_ENTRY_EXCEPTION or [])),
        'merged_functions': len(funcs),
        'exports': export_names,
        'imports': imports,
        'source_files': src_files,
        'rtti_count': len(rtti),
        'rtti_sample': rtti[:60],
        'interfaces': ifaces,
        'cvar_count': len(cvars),
        'cvars': cvars,
        'top_functions': [{'rva': hex(a), 'size': b - a, 'strings': strings_in(a, b)}
                          for a, b in funcs[:40]],
    }
    if args.json:
        print(json.dumps(doc, indent=1))
        return

    print(f"== {args.module}  {doc['size']:,} bytes ({doc['size_of_image']:,} mapped)")
    print(f"   imagebase {doc['imagebase']}  entry {doc['entrypoint_rva']}  ts {doc['timestamp']}")
    print(f"   merged functions: {doc['merged_functions']}  (from {doc['pdata_records']} .pdata records)")
    print(f"   pdb: {pdb[0] if pdb else '-'}")
    print(f"\n-- sections")
    for s in doc['sections']:
        print(f"   {s['name']:10s} vsize {s['vsize']:>9,}  raw {s['rawsize']:>9,}")
    print(f"\n-- exports ({len(export_names)})")
    for e in export_names[:30]:
        print('  ', e)
    print(f"\n-- imports ({len(imports)} dlls, {sum(i['count'] for i in imports)} symbols)")
    for i in imports:
        print(f"   {i['dll']:28s} {i['count']:5d}")
    print(f"\n-- RTTI: {len(rtti)} entries; interfaces: {len(ifaces)}; cvars: {len(cvars)}")
    for c in cvars[:15]:
        print(f"   {c['name']:42s} {c['rva']:>9s}  {(c['help'] or '')[:60]}")
    print(f"\n-- source provenance ({len(src_files)} files)")
    for s in src_files[:25]:
        print('  ', s)
    print(f"\n-- 15 functions with the most string references")
    for f in doc["top_functions"][:15]:
        print(f"   {f['rva']:>10s}  {f['size']:>6,}B  {', '.join(f['strings'][:3])[:110]}")


if __name__ == '__main__':
    main()
