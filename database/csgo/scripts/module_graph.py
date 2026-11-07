#!/usr/bin/env python3
"""Cross-module dependency and interface analysis from the committed inventory.

Every module's imports are recorded in index/inv/*.json, so the module graph,
the third-party surface, and the ABI each module presents can all be derived
without the binaries.

    python3 module_graph.py            # write index/graph.json + print summary
    python3 module_graph.py --layers   # dependency layers, load order
"""
import argparse, json, pathlib
from collections import defaultdict

HERE = pathlib.Path(__file__).resolve().parent
CSGO = HERE.parent
INV = CSGO / 'index' / 'inv'
MANIFEST = CSGO / 'index' / 'manifest.json'

VALVE = {
    'cs2', 'client', 'server', 'engine2', 'tier0', 'matchmaking', 'host',
    'materialsystem2', 'vphysics2', 'scenesystem', 'animationsystem', 'particles',
    'networksystem', 'soundsystem', 'panorama', 'panoramauiclient',
    'filesystem_stdio', 'inputsystem', 'localize', 'worldrenderer', 'meshsystem',
    'navsystem', 'scenefilecache', 'resourcesystem', 'rendersystemdx11',
    'rendersystemvulkan', 'rendersystemempty', 'video64', 'pulse_system',
    'toolframework2', 'physicsbuilder', 'helpsystem', 'schemasystem',
    'resourcecompiler', 'assetpreview', 'vconsole2',
}

SYSTEM_DLLS = {
    'KERNEL32.dll', 'USER32.dll', 'ADVAPI32.dll', 'WS2_32.dll', 'ole32.dll',
    'SHELL32.dll', 'GDI32.dll', 'OLEAUT32.dll', 'CRYPT32.dll', 'WINMM.dll',
    'IMM32.dll', 'COMCTL32.dll', 'DWMAPI.dll', 'SETUPAPI.dll', 'VERSION.dll',
    'bcrypt.dll', 'ncrypt.dll', 'WINTRUST.dll', 'PSAPI.dll', 'dbghelp.dll',
    'IPHLPAPI.dll', 'DNSAPI.dll', 'Secur32.dll', 'SSPICLI.dll', 'MPR.dll',
    'SHLWAPI.dll', 'COMDLG32.dll', 'WININET.dll', 'URLMON.dll', 'UxTheme.dll',
    'RPCRT4.dll', 'CRYPTBASE.dll', 'ntdll.dll', 'api-ms-win-core-synch-l1-2-0.dll',
}


def load():
    mods = {}
    for p in sorted(INV.glob('*.json')):
        if p.name.startswith('_'):
            continue
        d = json.loads(p.read_text())
        mods[p.stem] = d
    return mods


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--layers', action='store_true')
    args = ap.parse_args()

    mods = load()
    manifest = {m['module']: m for m in
                json.loads(MANIFEST.read_text())['modules']}

    deps = {}
    for name, d in mods.items():
        imps = d.get('imports') or []
        deps[name] = {i['dll'].replace('.dll', '').replace('.DLL', ''): i['count']
                      for i in imps}

    # Reverse graph: who imports each module.
    importers = defaultdict(dict)
    for name, ds in deps.items():
        for target, count in ds.items():
            importers[target][name] = count

    # Third-party surface per Valve module.
    third_party = defaultdict(dict)
    for name, ds in deps.items():
        if name not in VALVE:
            continue
        for target, count in ds.items():
            if target in VALVE or f'{target}.dll' in SYSTEM_DLLS \
                    or target in {s.replace('.dll', '') for s in SYSTEM_DLLS}:
                continue
            third_party[name][target] = count

    # A dependency layer: modules that import nothing Valve-internal are layer 0.
    valve_deps = {n: {t for t in ds if t in VALVE and t != n}
                  for n, ds in deps.items() if n in VALVE}
    layer, remaining = {}, set(valve_deps)
    depth = 0
    while remaining and depth < 20:
        ready = [n for n in remaining
                 if all(d not in remaining for d in valve_deps[n])]
        if not ready:
            break
        for n in ready:
            layer[n] = depth
        remaining -= set(ready)
        depth += 1
    for n in remaining:
        layer[n] = -1  # cycle

    graph = {
        'modules': {n: {'valve': n in VALVE,
                        'imports': deps[n],
                        'imported_by': dict(importers.get(n, {})),
                        'layer': layer.get(n),
                        'role': manifest.get(n, {}).get('role', '')}
                    for n in mods},
        'third_party_surface': {k: dict(sorted(v.items(), key=lambda x: -x[1]))
                                for k, v in third_party.items()},
    }
    out = CSGO / 'index' / 'graph.json'
    out.write_text(json.dumps(graph, indent=1))

    valve = sorted([n for n in mods if n in VALVE],
                   key=lambda n: layer.get(n, 99))
    print(f'{len(mods)} modules, {len(valve)} Valve')
    print('\nValve load layers (0 = imports no other Valve module):')
    cur = None
    for n in valve:
        l = layer.get(n)
        if l != cur:
            print(f'  -- layer {l} --')
            cur = l
        ins = len([t for t in deps[n] if t in VALVE])
        print(f'     {n:20s} valve_deps={ins:2d}  imports={sum(deps[n].values()):5d}')
    print(f'\nwrote {out}')

    if args.layers:
        print('\nMost-imported Valve modules:')
        for t, c in sorted(((t, len(v)) for t, v in importers.items()
                            if t in VALVE), key=lambda x: -x[1])[:12]:
            print(f'  {t:20s} imported by {c} modules')


if __name__ == '__main__':
    main()
