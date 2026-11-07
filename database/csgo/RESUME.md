# CS2 / CS:GO binary reversal — resume instructions

Read this first. It is written so a fresh machine, with no memory of the session
that produced it, can continue the work without redoing it.

## What this work is

Static reverse engineering of the Counter-Strike 2 binaries installed on the DTB
under `C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike Global
Offensive`. **102 modules, 544 MB, 1,126,183 functions.** Nothing is executed;
the DTB is only used to *copy* the files out.

This is the target corpus for the hypervisor detection work: the stand exists to
run Windows guests under a UEFI hypervisor, and VMAware is the detector. This
corpus is the other side of that — what a real, hardened, commercially shipped
anti-cheat-adjacent codebase does that the guest's test binaries do not.

## Where things are

| What | Where | In git |
|---|---|---|
| This file | `database/csgo/RESUME.md` | yes |
| Corpus manifest (identity, size, hash, function count per module) | `database/csgo/index/manifest.json` | yes |
| PE inventory, one JSON per module | `database/csgo/index/inv/*.json` | yes |
| RTTI class names, one file per module | `database/csgo/index/rtti/*.txt` | yes |
| Interface name candidates | `database/csgo/index/ifaces/*.txt` | yes |
| Finished documents | `database/csgo/documents/*.md` | yes |
| Analysis scripts | `database/csgo/scripts/*.py` | yes |
| The binaries themselves | **not in git** — 544 MB, re-fetched on demand | no |
| Per-function disassembly | **not in git** — 164 MB, regenerated in ~15 s/module | no |

The two "not in git" rows are deliberate. Both are reproducible from the DTB plus
the committed manifest, and neither belongs in a repository.

## State at hand-off

**Complete: all 34 Valve modules are documented.** 12,335 lines across
`documents/`. The corpus manifest marks every Valve module `documented`.

Remaining optional work:

- Third-party modules (Qt, V8, ffmpeg, Embree, OpenSSL, phonon) — out of scope
  except `v8.dll` and `steamnetworkingsockets.dll`, which Valve configures itself.
- Depth: every document has an **Unknowns** section naming what would resolve it.
  Those are the highest-value next targets, and most are vtable walks or wire-format
  reversals that the `scripts/server/ad2.py` toolkit supports.

### The DTB is not required

The corpus was recovered without it, from Steam. Depot **2347771** of appid 730
holds every module, anonymously downloadable:

```sh
DepotDownloader -app 730 -depot 2347771 -manifest 3019944380727688040 \
                -filelist filelist.txt -dir ./cs2
```

172 MB downloaded for 544 MB uncompressed, and all 102 modules matched the
committed SHA256 exactly. `scripts/build_manifest.py` regenerates
`filelist.txt` from `index/manifest.json`. Depot 2347770 holds only VPKs and
signatures — the DLLs are not there.

## Step 1 — bring up the stand

```sh
control/dtb/dtbctl status          # want: verdict=ready
control/dtb/dtbctl serve status    # want: serve: True
```

If `serve: False`, the machine cannot netboot and will sit in firmware for ever:

```sh
control/dtb/dtbctl serve start
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:6767/PulverizedDXE.efi   # want 200
```

`dbg_boot` / `dtbctl boot` also starts the server. A reset does nothing to a
powered-off machine; the tool now checks the LED first.

## Step 2 — get the corpus

Two routes. Prefer the first when the DTB is reachable; use the second when it is
not, or when the corpus must survive a reboot.

### From Steam (no DTB needed)

Depot **2347771** of appid 730 carries every module and allows anonymous access:

```sh
python3 database/csgo/scripts/build_manifest.py --filelist /tmp/filelist.txt
DepotDownloader -app 730 -depot 2347771 -manifest 3019944380727688040 \
                -filelist /tmp/filelist.txt -dir /tmp/cs2dl
```

172 MB of download for 544 MB uncompressed. Verify against `index/manifest.json`
— all 102 modules matched byte-for-byte when this route was first used.

Depot 2347770 looks like the obvious choice and is **wrong**: it holds only VPKs
and signature files. The DLLs are in 2347771.

### From the DTB

```sh
python3 database/csgo/scripts/bootstrap.py --dest /tmp/opencode/csgo
```

This tars `game\bin` and `game\csgo\bin` on the guest, pulls the archive with
`dbg_fetch`, extracts it, and verifies every module against the manifest. Expect
about 15 s for the transfer (~43 MB/s).

`--skip-pull` verifies an existing extraction instead.

### Why not scp

`scp` and `sftp` fail against this guest with `invalid user name` because the
account name is Cyrillic (`Арсений`). `dbg_fetch` exists for this reason: the
guest POSTs the file to a one-shot HTTP receiver on the host. Verified
byte-exact against `Get-FileHash` on the guest.

## Step 3 — rebuild the analysis index

```sh
cd database/csgo/scripts
python3 pe_inventory.py /tmp/opencode/csgo /tmp/opencode/csgo-analysis/inv
python3 batch_decomp.py <module.dll> /tmp/opencode/csgo-analysis/docs/<module> 250
```

`batch_decomp.py` parses each PE **once** and emits per-function `.asm` plus a
manifest with size, callees, and referenced strings. It handles ~128k functions
in 14 s. An earlier version re-parsed the PE per function and did not finish in
30 minutes — do not reintroduce that.

## Step 4 — document a module

One module per subagent, in parallel. Each needs: the binary path, its
`docs/<module>/` disassembly directory, `index/inv/<module>.json`,
`index/rtti/<module>.txt`, `index/ifaces/<module>.txt`, and the role from
`index/manifest.json`.

Requirements for every document:

1. Identity — hash, PDB path, timestamp, sections, exports.
2. `CreateInterface` reversal and the interfaces that module registers.
3. The module's actual job, from evidence (strings, call graph, decompiled
   functions), not from its name.
4. A table of the most significant functions: RVA, size, purpose.
5. An explicit **unknowns** section.

Two hard rules, both learned the hard way:

- **Cite the RVA for every claim.** A claim without an address is unverifiable
  and will be repeated as fact later.
- **Never invent a symbol name.** If the name is inferred, say "inferred" and
  give the evidence. The corpus has real PDB paths but no symbols, so most names
  are inferred.

### Traps that cost time

- `CreateInterface` in `client.dll` is a 36-byte leaf **with no `.pdata` entry**,
  so `.pdata`-based function discovery misses it. Scan the code for
  `lea r8/rdx/rcx; jmp` stubs instead.
- `.pdata` gives exact function boundaries — use it, never heuristics.
- `pefile.__data__` is an `mmap`, and iterating it yields `int`, not `bytes`.
  Wrap with `bytes(...)`.
- A raw string cannot end in a backslash (`r'C:\path\'` is a syntax error). Use
  escaped strings for Windows paths.
- `r2 -A` on a 39 MB DLL is slow. Use `-q -e scr.color=0 -A -c "pdg @ 0x<rva>"`
  per function, or prefer the pre-extracted `.asm` files.
- **A function does not contain its strings.** The code is in `.text` and the
  literals are in `.rdata`, reached by RIP-relative `lea`. Testing "is this string
  inside the function's address range" can never match — resolve the `lea` target
  instead (`next_ip + displacement`). Capstone prints the displacement, not the
  target, for `[rip + 0x...]`.
- **Section names carry NUL padding.** `s.Name` is `b'.rdata\x00\x00'`, so
  comparing to `'.rdata'` silently fails. Strip and lowercase first.
- **`ifaces/*.txt` is a superset, not a list of registrations.** It is a string
  scan, so it includes names the module merely imports. Use `scripts/iface_stubs.py`
  to find stubs that `jmp` to the module's own `CreateInterface` export.
- **The stub target is not the export address.** Stubs jump to a thunk ~0x20
  *before* the export. Compare against `export - 0x30 .. export`.
- **Verify sizes and counts against `index/manifest.json`, never from memory.**
  Several documents in this corpus were first drafted with invented byte counts and
  function counts; all were caught only by re-reading the manifest.

## Step 5 — record what you learn

Follow `database/policies/documentation.md`. Reference facts about the corpus go
in `database/csgo/`; a *measurement* goes in `database/experiments/`; a trap that
cost time goes in `database/experience/`. Add every new document to
`database/index.md` — an unlisted file is invisible to retrieval.

## Environment that is known to work

- `radare2 6.2.2` + `r2ghidra` (Ghidra decompiler): `sudo pacman -S radare2 r2ghidra`
- `python3 -m pip install --user --break-system-packages pefile capstone`
- Decompiling a function: `r2 -q -e scr.color=0 -A -c "pdg @ 0x<rva>" <binary>`
  (about 1–2 s per function; ImageBase is `0x140000000` for `cs2.exe` and
  `0x180000000` for the DLLs, but the `.asm` files use RVAs).

## What "done" means

All 34 Valve modules documented to the standard of `cs2.md` and `client.md`.
Third-party modules (Qt, V8, ffmpeg, Embree, OpenSSL) are out of scope except
where Valve has patched them — `v8.dll` and `steamnetworkingsockets.dll` are
worth a look, `Qt5Core.dll` is not.

## Moving to another machine — checklist

The two repositories are `I1Va/hypervisor-workspace` and
`I1Va/hypervisor-controll`. Everything needed to resume is in them.

On the new machine:

```sh
git clone git@github.com:I1Va/hypervisor-workspace.git
git clone git@github.com:I1Va/hypervisor-controll.git   # sibling of workspace/
```

`control/` **must** sit next to `workspace/`, because `bootstrap.py` resolves
`../../control/dtb/dtbctl` from `workspace/database/csgo/scripts/`.

Then:

1. `control/dtb/dtbctl status` — needs `verdict=ready`. If the daemon is not
   running it starts on first use; if the boot server is down, `serve start`.
2. `python3 database/csgo/scripts/bootstrap.py` — 20 s, verifies 102/102.
3. Install the tooling: `radare2`, `r2ghidra`, `pefile`, `capstone`.
4. Read `index/manifest.json` to pick the next module, then follow step 4 above.

You do **not** need this session's history, the `/tmp` tree, or the 164 MB of
disassembly. Everything in `/tmp` is reproducible from the two repositories plus
the DTB.

### What will not survive the move

- The disassembly in `/tmp/opencode/csgo-analysis/docs/<module>/` — regenerate
  with `batch_decomp.py` (14 s for `client.dll`).
- `corpus.json` in the extraction directory — `bootstrap.py` writes it.
- The DTB's own state: `boot_id`, the login session, the serial log. Check
  `dbg_status` before trusting any earlier observation.
