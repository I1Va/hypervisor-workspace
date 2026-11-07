#!/usr/bin/env python3
"""Demangle the C++ exports recorded in the committed PE inventory.

The binaries themselves are not in the repository, but `index/inv/*.json` holds
every export name. Most of them are MSVC-mangled, and a mangled name is a
complete symbol: demangling recovers the exact class, method, parameters and
calling convention. That makes a usable API catalogue recoverable offline.

`c++filt` is Itanium-only and does nothing here; `llvm-undname` is the tool that
reads MSVC mangling.

    python3 demangle_exports.py                     # write index/symbols/
    python3 demangle_exports.py --module tier0      # one module to stdout
"""
import argparse, json, pathlib, subprocess, sys

HERE = pathlib.Path(__file__).resolve().parent
CSGO = HERE.parent
INV = CSGO / 'index' / 'inv'
OUT = CSGO / 'index' / 'symbols'

VALVE = {
    'cs2', 'client', 'server', 'engine2', 'tier0', 'matchmaking', 'host',
    'materialsystem2', 'vphysics2', 'scenesystem', 'animationsystem', 'particles',
    'networksystem', 'soundsystem', 'panorama', 'panoramauiclient',
    'filesystem_stdio', 'inputsystem', 'localize', 'worldrenderer', 'meshsystem',
    'navsystem', 'scenefilecache', 'resourcesystem', 'rendersystemdx11',
    'rendersystemvulkan', 'rendersystemempty', 'video64', 'pulse_system',
    'toolframework2', 'physicsbuilder', 'helpsystem', 'schemasystem',
    'resourcecompiler',
}


def undname(names: list[str]) -> list[str]:
    """Batch demangle. llvm-undname echoes the mangled name then the demangled
    form on the next line, separated by a blank line."""
    if not names:
        return []
    p = subprocess.run(['llvm-undname'], input='\n'.join(names), text=True,
                       capture_output=True)
    if p.returncode != 0:
        raise SystemExit(f'llvm-undname failed: {p.stderr[:300]}')
    out, cur = [], []
    for line in p.stdout.splitlines():
        if not line.strip():
            if len(cur) == 2:
                out.append(cur[1])
            cur = []
        else:
            cur.append(line.strip())
    if len(cur) == 2:
        out.append(cur[1])
    # A name that failed to demangle is echoed once, so pad to keep alignment.
    while len(out) < len(names):
        out.append('')
    return out[:len(names)]


def module_symbols(path: pathlib.Path) -> dict:
    d = json.loads(path.read_text())
    ex = d.get('exports') or {}
    names = ex.get('names') or []
    mangled = [n for n in names if n.startswith('?')]
    plain = [n for n in names if not n.startswith('?')]
    demangled = undname(mangled)
    return {
        'module': path.stem,
        'file': d.get('name'),
        'sha256': d.get('sha256'),
        'dll_name': ex.get('dll_name'),
        'export_count': len(names),
        'plain': plain,
        'mangled': [{'mangled': m, 'demangled': s}
                    for m, s in zip(mangled, demangled) if s],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--module', help='one module name (stem), print to stdout')
    args = ap.parse_args()

    if args.module:
        p = INV / f'{args.module}.json'
        if not p.is_file():
            raise SystemExit(f'no inventory for {args.module!r}')
        print(json.dumps(module_symbols(p), indent=1))
        return

    OUT.mkdir(parents=True, exist_ok=True)
    index, total = [], 0
    for p in sorted(INV.glob('*.json')):
        if p.name.startswith('_'):
            continue
        sym = module_symbols(p)
        n = len(sym['mangled'])
        total += n
        if n:
            (OUT / f'{p.stem}.txt').write_text(
                '\n'.join(s['demangled'] for s in sym['mangled']) + '\n')
        index.append({'module': p.stem, 'valve': p.stem in VALVE,
                      'exports': sym['export_count'], 'demangled': n,
                      'plain': len(sym['plain'])})
    (OUT / 'index.json').write_text(json.dumps(
        {'total_demangled': total, 'modules': index}, indent=1))
    valve = sum(m['demangled'] for m in index if m['valve'])
    print(f'demangled {total} symbols ({valve} in Valve modules) -> {OUT}')
    for m in sorted([m for m in index if m['valve']], key=lambda m: -m['demangled'])[:8]:
        print(f"  {m['module']:22s} {m['demangled']:5d}")


if __name__ == '__main__':
    main()
