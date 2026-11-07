#!/usr/bin/env python3
"""Extract the CS2 corpus from the DTB and prepare a reversing workspace.

This is the whole "how do I start" path on a fresh machine. It assumes the DTB
is reachable through the daemon (`control/dtb/dtbctl`) and that nothing has been
extracted yet.

    python3 database/csgo/scripts/bootstrap.py --dest /path/to/workspace

Steps:
  1. verify the stand is reachable and the game is installed,
  2. tar the two bin trees on the guest,
  3. pull the archive with `dbg_fetch` (HTTP POST, not scp - scp fails on this
     guest with the Cyrillic username),
  4. extract and verify every module against the committed manifest,
  5. write a corpus.json the analysis scripts read.

Nothing is executed from the game. All analysis is static.
"""
import argparse, json, pathlib, subprocess, sys, tarfile

# scripts/ -> csgo/ -> database/ -> workspace/ -> agent-projects/
REPO = pathlib.Path(__file__).resolve().parents[4]
DTBCTL = REPO / 'control' / 'dtb' / 'dtbctl'
MANIFEST = pathlib.Path(__file__).resolve().parents[1] / 'index' / 'manifest.json'
GUEST_ROOT = ('C:\\Program Files (x86)\\Steam\\steamapps\\common\\'
              'Counter-Strike Global Offensive')
GUEST_TAR = 'C:\\Users\\Арсений\\csgo_bin.tar'


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def dtb(*args, timeout=3600):
    p = run([str(DTBCTL), *args], timeout=timeout)
    if p.returncode != 0:
        raise SystemExit(f'dtbctl {args[0]} failed: {p.stderr.strip()[:400]}')
    return p.stdout


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dest', default='/tmp/opencode/csgo',
                    help='where to put the extracted corpus (default /tmp/opencode/csgo)')
    ap.add_argument('--skip-pull', action='store_true',
                    help='corpus already present; only verify')
    args = ap.parse_args()
    dest = pathlib.Path(args.dest)

    manifest = json.loads(MANIFEST.read_text())
    print(f'manifest: {manifest["module_count"]} modules, '
          f'{manifest["total_bytes"]/1e6:.0f} MB')

    if not args.skip_pull:
        status = dtb('status')
        if 'verdict=ready' not in status:
            raise SystemExit('stand is not ready:\n' + status[:400])
        print('stand ready; creating archive on the guest')
        cmd = ('powershell -NoProfile -Command "'
               f'$r=\'{GUEST_ROOT}\\game\'; '
               f'tar -cf {GUEST_TAR} -C $r bin csgo\\bin; '
               'exit $LASTEXITCODE"')
        dtb('run', cmd, '900')
        print('pulling archive')
        out = dtb('fetch', GUEST_TAR, timeout=3600)
        path = None
        for line in out.splitlines():
            if line.startswith('path: '):
                path = line[6:].strip()
        if not path:
            raise SystemExit('fetch did not report a path:\n' + out[:400])
        print('extracting', path)
        dest.mkdir(parents=True, exist_ok=True)
        with tarfile.open(path) as tf:
            tf.extractall(dest)

    # Verify: every manifest module must be present with the recorded size.
    missing, bad, found = [], [], {}
    for m in manifest['modules']:
        name = m['module']
        rel = m.get('relpath') or m.get('file') or ''
        p = dest / rel
        if not p.is_file():
            missing.append(name)
            continue
        if p.stat().st_size != m['size']:
            bad.append((name, p.stat().st_size, m['size']))
        found[name] = {'path': str(p), 'relpath': rel, 'size': m['size'],
                       'sha256': m['sha256'], 'functions': m['functions'],
                       'role': m['role']}
    corpus = {'root': str(dest), 'modules': found}
    (dest / 'corpus.json').write_text(json.dumps(corpus, indent=1))
    print(f'verified: {len(found)}/{manifest["module_count"]} modules')
    if missing:
        print('MISSING:', missing)
    if bad:
        print('SIZE MISMATCH:', bad)
    if missing or bad:
        sys.exit(1)
    print('corpus ready at', dest)


if __name__ == '__main__':
    main()
