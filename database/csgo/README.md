# CS2 / CS:GO corpus — reference

Static reverse engineering of the Counter-Strike 2 binaries installed on the DTB.
This is the largest real codebase the stand has access to, and the counterpart to
the VMAware work: what shipped, hardened, anti-cheat-adjacent software does.

**Start at `RESUME.md`** — it has the state, the bootstrap path, and the traps.

## Corpus

- **102 modules, 544 MB, 1,126,183 functions.**
- 34 Valve modules (the target) and 68 third-party (Qt, V8, ffmpeg, Embree,
  OpenSSL, SDL3 — out of scope except where Valve patched them).
- Build: Source 2, `csgo_rel_win64`, module timestamps 2026-10-14 to 2026-11-04.
- Source: `C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike Global
  Offensive` on the DTB guest.

The binaries are **not** committed. They are re-fetched with
`scripts/bootstrap.py`, which verifies each module against
`index/manifest.json`.

## Layout

| Path | Holds |
|---|---|
| `RESUME.md` | state, bootstrap, per-module procedure, traps |
| `index/manifest.json` | every module: size, SHA256, PDB, function count, doc status |
| `index/inv/` | PE inventory per module: sections, imports, exports, TLS, signatures |
| `index/rtti/` | MSVC RTTI class names per module (34k names total) |
| `index/ifaces/` | Source 2 interface-name candidates per module |
| `documents/` | the finished documents |
| `scripts/` | the extraction and analysis toolkit |

## Documented so far

| Module | Document | Covers |
|---|---|---|
| `cs2.exe` | `documents/cs2.md` | Source 2 launcher; install trust subsystem; RSA manifest verification; inline detours on `NtOpenFile`/`LoadLibraryExW`/`PeekMessageW` |
| `client.dll` | `documents/client.md` | Interface registry, entity system, prediction/reconciliation, HUD, 1,695 ConVars, weapon and player paths |
| `server.dll` | `documents/server.md` | Authoritative tick loop, 10 interfaces, game-mode rules, sub-tick movement, fire path, lag compensation, 1,545 ConVars |
| `engine2.dll` | `documents/engine2.md` | `Source2Main`, 8-phase bootstrap, 34 interfaces, main loop and sleep scheduler, hashed command-line flags, bundled codecs |

Derived indexes, usable without the binaries:

| Path | Holds |
|---|---|
| `index/graph.json` | Cross-module dependency graph, load layers, third-party surface |
| `index/symbols/tier0.txt` | 1,528 demangled MSVC C++ signatures from `tier0.dll` exports |
| `index/vtables/server.json` | 3,990 classes / 4,897 vtables with slot RVAs (`server.dll`) |
| `index/cvars/server.json` | 1,545 ConVars/ConCommands with help text (`server.dll`) |

## Facts worth knowing before opening a module

- `cs2.exe` is **not** the game. It verifies the install and then calls
  `engine2.dll!Source2Main` in-process — the launcher process becomes the game.
- Module PDB paths survive in the binaries (`C:\buildworker\csgo_rel_win64\...`),
  which is what makes subsystem attribution possible without symbols.
- `.pdata` gives exact function boundaries for every non-leaf function. This is
  the reliable function inventory; do not use heuristics.
- The corpus is **not** Authenticode-signed in the usual sense, but `cs2.exe`
  carries an intact embedded signature and its own RSA-signed manifest database.
  `pefile`'s `signed` flag reports `False`; that is a pefile limitation.
- `client.dll` and `server.dll` export the same six entry points
  (`CreateInterface`, `Source2Main` is engine2's, `BinaryProperties_GetValue`,
  `ExtractModuleMetadata`, `GetResourceManifestCount`, `GetResourceManifests`,
  `InstallSchemaBindings`) — the Source 2 module ABI.

## Method

Static only. `r2` + `r2ghidra` for decompilation, `pefile`/`capstone` for
structure, the committed inventory for orientation. Nothing from the game is
executed, and the DTB is used only to copy files.

Two rules that every document follows: cite the RVA for each claim, and never
invent a symbol name — mark inferred names as inferred and give the evidence.
