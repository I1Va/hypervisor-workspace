#!/usr/bin/env python3
"""Static PE inventory for the CS2/CS:GO binary corpus.

Produces one JSON per module: headers, sections, exports, imports, load config,
digital signature presence, and basic packer heuristics. No execution, no
disassembly at this stage - this is the map for the reversing subagents.
"""
import json, pathlib, pefile, sys, hashlib, math

def entropy(data: bytes) -> float:
    if not data: return 0.0
    freq = [0]*256
    for b in data: freq[b]+=1
    n = len(data)
    return -sum((c/n)*math.log2(c/n) for c in freq if c)

def analyze(path: pathlib.Path) -> dict:
    out = {"path": str(path), "name": path.name, "size": path.stat().st_size,
           "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    try:
        pe = pefile.PE(str(path), fast_load=True)
    except pefile.PEFormatError as e:
        out["error"] = f"not a parseable PE: {e}"
        return out
    pe.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'],
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY'],
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG'],
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG'],
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS'],
    ])
    h = pe.OPTIONAL_HEADER
    out.update({
        "machine": hex(pe.FILE_HEADER.Machine),
        "subsystem": h.Subsystem,
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
        "entrypoint_va": h.AddressOfEntryPoint + h.ImageBase,
        "imagebase": h.ImageBase,
        "size_image": h.SizeOfImage,
        "checksum_ok": (h.CheckSum == 0) or (h.CheckSum == pe.generate_checksum()),
        "dll_characteristics": hex(h.DllCharacteristics),
        "aslr": bool(h.DllCharacteristics & 0x0040),
        "dep": bool(h.DllCharacteristics & 0x0100),
        "cfg": bool(h.DllCharacteristics & 0x4000),
        "sections": [
            {"name": s.Name.decode(errors='replace').rstrip('\x00'),
             "vaddr": hex(s.VirtualAddress), "vsize": s.Misc_VirtualSize,
             "rawsize": s.SizeOfRawData,
             "entropy": round(entropy(s.get_data()), 2)}
            for s in pe.sections
        ],
    })
    # exports
    try:
        exp = pe.DIRECTORY_ENTRY_EXPORT
        out["exports"] = {
            "dll_name": exp.name.decode() if exp.name else None,
            "count": len(exp.symbols),
            "names": [s.name.decode() if s.name else f"ord_{s.ordinal}" for s in exp.symbols],
        }
    except AttributeError:
        out["exports"] = None
    # imports
    try:
        out["imports"] = [
            {"dll": e.dll.decode(), "count": len(e.imports),
             "names": [i.name.decode() if i.name else f"ord_{i.ordinal}" for i in e.imports]}
            for e in pe.DIRECTORY_ENTRY_IMPORT
        ]
    except AttributeError:
        out["imports"] = []
    # signature
    try:
        sec = pe.DIRECTORY_ENTRY_SECURITY
        out["signed"] = True
    except AttributeError:
        out["signed"] = False
    # debug directory (PDB paths are gold for attribution)
    try:
        out["pdb"] = [
            (getattr(d.entry, 'PdbFileName', b'') or b'').decode(errors='replace').rstrip('\x00')
            for d in pe.DIRECTORY_ENTRY_DEBUG
            if d.struct.Type == 2  # CODEVIEW
        ]
    except AttributeError:
        out["pdb"] = []
    # TLS callbacks (initialization code worth reversing)
    try:
        tls = pe.DIRECTORY_ENTRY_TLS.struct
        cb = tls.AddressOfCallBacks
        if cb:
            n = 0
            rva = cb - h.ImageBase
            data = pe.get_qword_at_rva(rva)
            ptrs = []
            while data and n < 32:
                ptrs.append(hex(data)); n += 1
                rva += 8
                try: data = pe.get_qword_at_rva(rva)
                except Exception: break
            out["tls_callbacks"] = ptrs
    except AttributeError:
        pass
    return out

if __name__ == "__main__":
    root = pathlib.Path(sys.argv[1]); outdir = pathlib.Path(sys.argv[2])
    outdir.mkdir(parents=True, exist_ok=True)
    targets = sorted([p for p in root.rglob("*") if p.suffix.lower() in (".exe", ".dll")])
    index = []
    for i, p in enumerate(targets):
        r = analyze(p)
        (outdir / (p.stem + ".json")).write_text(json.dumps(r, indent=1))
        index.append({"name": p.name, "rel": str(p.relative_to(root)),
                      "size": r.get("size"), "error": r.get("error"),
                      "exports": (r.get("exports") or {}).get("count") if r.get("exports") else 0})
        print(f"[{i+1}/{len(targets)}] {p.name}: exports={index[-1]['exports']}")
    (outdir / "_index.json").write_text(json.dumps(index, indent=1))
    print(f"done: {len(targets)} modules")
