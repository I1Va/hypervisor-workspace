#!/usr/bin/env python3
"""Build the corpus manifest committed to the repository.

The 520 MB binary corpus and the 164 MB of per-function disassembly stay on the
machine that produced them. What must survive a move to another PC is the
identity of every module (size, hash, function count) plus the per-module
analysis state, so the next machine can tell what is done, what is partial, and
what it has to re-extract.
"""
import json, os, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from funcmap import function_map

ROOT = pathlib.Path(os.environ.get('CSGO_CORPUS', '/tmp/opencode/csgo'))
ANALYSIS = pathlib.Path(os.environ.get('CSGO_ANALYSIS', '/tmp/opencode/csgo-analysis'))

# What each module is, for a reader who has never seen the tree.
ROLES = {
    'cs2': 'Source 2 launcher: verifies the install, then calls engine2!Source2Main',
    'client': 'Client game module: entities, prediction, HUD, weapons, input',
    'server': 'Authoritative game module: tick, snapshot, game rules, hit reg',
    'engine2': 'Engine core: Source2Main, module bootstrap, frame loop',
    'tier0': 'Platform layer: allocators, threads, logging, crash handler',
    'tier1': 'Utility layer: containers, string, keyvalues',
    'matchmaking': 'Steam matchmaking and lobby glue',
    'host': 'Host state: cvar/command registry, game UI state',
    'materialsystem2': 'Material and shader binding',
    'vphysics2': 'Rigid body physics (VPhysics2)',
    'scenesystem': 'Render scene graph and draw lists',
    'animationsystem': 'Skeletal animation and anim graph',
    'particles': 'Particle systems',
    'networksystem': 'Network channel, delta compression, Steam networking',
    'soundsystem': 'Audio mixing and spatialisation',
    'panorama': 'Panorama UI engine (HTML/CSS-like)',
    'panoramauiclient': 'Client-side Panorama bindings',
    'filesystem_stdio': 'Filesystem layer over stdio and VPK',
    'inputsystem': 'Input device handling',
    'localize': 'Localisation token tables',
    'worldrenderer': 'World geometry renderer',
    'meshsystem': 'Mesh and LOD management',
    'navsystem': 'Navigation mesh and AI pathing',
    'scenefilecache': 'Compiled scene file cache',
    'resourcesystem': 'Resource compiler runtime',
    'rendersystemdx11': 'D3D11 render backend',
    'rendersystemvulkan': 'Vulkan render backend',
    'rendersystemempty': 'Null render backend (dedicated server / headless)',
    'video64': 'Video playback',
    'pulse_system': 'Pulse graph (Source 2 scripting)',
    'toolframework2': 'Editor/tool framework',
    'physicsbuilder': 'Physics shape building (tool)',
    'helpsystem': 'Help system',
    'schemasystem': 'Schema type system',
    'resourcecompiler': 'Resource compiler tool',
    'assetpreview': 'Asset preview tool',
    'vconsole2': 'External console application',
}

def module_path(name):
    """Locate a module by stem anywhere in the corpus (some live in subdirs)."""
    for p in ROOT.rglob(f'{name}.dll'):
        return p
    for p in ROOT.rglob(f'{name}.exe'):
        return p
    return None

def main():
    if not ROOT.is_dir():
        raise SystemExit(f'corpus not found at {ROOT}; set CSGO_CORPUS or run '
                         'bootstrap.py first')
    inv_dir = ANALYSIS / 'inv'
    entries = []
    for j in sorted(inv_dir.glob('*.json')):
        if j.name.startswith('_'):
            continue
        d = json.loads(j.read_text())
        name = j.stem
        p = module_path(name)
        nfuncs = len(function_map(str(p))) if p else 0
        asm_dir = ANALYSIS / 'docs' / name
        asm_count = len(list(asm_dir.glob('*.asm'))) if asm_dir.is_dir() else 0
        # Documents live in the repository, not in the scratch analysis tree.
        doc = (pathlib.Path(__file__).resolve().parents[1] / 'documents' / f'{name}.md')
        doc_exists = doc.exists()
        entries.append({
            'module': name,
            'file': p.name if p else None,
            'relpath': str(p.relative_to(ROOT)) if p else None,
            'role': ROLES.get(name, ''),
            'size': d.get('size'),
            'sha256': d.get('sha256'),
            'pdb': (d.get('pdb') or [None])[0],
            'timestamp': d.get('timestamp'),
            'functions': nfuncs,
            'exports': ((d.get('exports') or {}).get('count')
                        if d.get('exports') else 0),
            'sections': [s['name'] for s in d.get('sections', [])],
            'analysis': {
                'disassembly_functions': asm_count,
                'document': f'documents/{name}.md' if doc_exists else None,
                'status': ('documented' if doc_exists
                           else 'extracted, not documented' if asm_count
                           else 'inventory only'),
            },
        })
    entries.sort(key=lambda e: -(e['size'] or 0))
    out = {
        'corpus': 'Counter-Strike 2 (CS:GO appid 730 install, Source 2 build)',
        'location_on_dtb': ('C:\\Program Files (x86)\\Steam\\steamapps\\common\\'
                            'Counter-Strike Global Offensive'),
        'module_count': len(entries),
        'total_bytes': sum(e['size'] or 0 for e in entries),
        'total_functions': sum(e['functions'] for e in entries),
        'modules': entries,
    }
    dest = pathlib.Path('/home/iabrutin/Work/agent-projects/workspace/database/csgo/index/manifest.json')
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(out, indent=1))
    done = [e['module'] for e in entries if e['analysis']['status'] == 'documented']
    partial = [e['module'] for e in entries if e['analysis']['status'] == 'extracted, not documented']
    print(f'{len(entries)} modules, {out["total_functions"]} functions, '
          f'{out["total_bytes"]/1e6:.0f} MB')
    print('documented:', done)
    print('extracted only:', len(partial), 'modules')

if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--filelist', help='also write a DepotDownloader filelist '
                    'of the modules (paths relative to the Steam game root)')
    args = ap.parse_args()
    if args.filelist:
        import pathlib as _p
        d = json.loads((_p.Path(__file__).resolve().parents[1]
                        / 'index' / 'manifest.json').read_text())
        lines = sorted({'game/' + m['relpath'] for m in d['modules']
                        if m.get('relpath')})
        _p.Path(args.filelist).write_text('\n'.join(lines) + '\n')
        print(f'wrote {len(lines)} paths to {args.filelist}')
    main()
