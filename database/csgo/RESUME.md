# CS2 / CS:GO binary reversal — resume instructions

Read this first. It is written so a fresh machine, with no memory of the session
that produced it, can continue the work without redoing it.

## What this work is

Static reverse engineering of the Counter-Strike 2 binaries installed on the DTB
under `C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike Global
Offensive`. **102 modules, 544 MB, 1,111,969 functions.** Nothing is executed;
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

Two of 34 Valve modules are documented:

| Module | Document | Lines | Notes |
|---|---|---|---|
| `cs2.exe` | `documents/cs2.md` | 1,246 | Complete. Launcher + trust subsystem. |
| `client.dll` | `documents/client.md` | 1,585 | Complete. Entities, prediction, HUD, cvars. |

The remaining 30 Valve modules have full PE inventory and RTTI extracted, plus
disassembly on the machine that did the work, but **no document**. `server.dll`
and `engine2.dll` were in progress and produced nothing — restart them from
scratch.

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

## Step 2 — pull the corpus

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
