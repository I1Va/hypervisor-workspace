# `scenefilecache.dll` — compiled scene cache and response rules

Addresses are RVAs in `bin/win64/scenefilecache.dll`,
`ImageBase = 0x180000000`.

## 1. Identity

| Property | Value |
|---|---|
| Size on disk | **1,297,048** bytes |
| `SizeOfImage` | 1,437,696 (`0x15F000`) |
| SHA256 | `index/manifest.json` |
| ImageBase | `0x180000000` |
| Entry point | `0xa358c` |
| Timestamp | 1793662454 |
| PDB | `...\scenefilecache\_vpc_scenefilecache\default\win64\_msvc_\Retail\scenefilecache.pdb` |
| `.pdata` records | 3,692 |
| Merged functions | **1,903** |
| Exports | 6 (module ABI) |
| Imports | 2 DLLs: `tier0` 147, `KERNEL32` 81 |
| RTTI types | 304 |

Only `tier0` and KERNEL32 — no filesystem, no render DLLs. It operates on data
already in memory.

## 2. What it is

Despite the name, this module is primarily the **choreography ("choreo") scene
system** — the scripted actor animation and **response rules** that drive NPC
dialogue and behaviour:

| Class | Role |
|---|---|
| `CChoreoActor`, `CChoreoChannel`, `CChoreoEvent` | the choreo scene graph: actors, channels, timed events |
| `CChoreoEvent_ANIMGRAPH_CONTROLLER` | an event type that drives an anim graph |
| `CBaseToolAttr`, `CBaseUndoable` | editor-side attributes and undo (a **tool** surface) |
| `ResponseRulesCache001` | interface (see below) |

The `CChoreo*` triple is the classic Source 1/2 choreography format: a scene has
actors, each actor has channels, and events are timed across channels. This is how
scripted sequences were authored.

`CBaseUndoable` in a runtime DLL means part of the module is editor support — the
same pattern as `helpsystem.dll` linking Qt.

## 3. Interfaces registered — two

`CreateInterface` export at `0x9ca40`; stubs target thunk `0x9ca20`.

| Interface | Stub RVA | Role |
|---|---|---|
| `SceneFileCache002` | `0x10e5` | the compiled-scene cache itself |
| `ResponseRulesCache001` | `0x1075` | response-rules cache |

The name now makes sense: the module caches two *kinds* of compiled data — scene
files and response rules — both being expensive-to-parse authored content loaded
as a unit. `SceneFileCache002` is revision 2, `ResponseRulesCache001` revision 1.

## 4. Unknowns

1. Both vtables not walked.
2. The on-disk cache format is not reversed.
3. Whether response rules are still used in CS2 (which has no NPC dialogue) or the
   module ships for shared-code reasons is not established. Given CS2's design,
   the latter is likely, but the binary alone does not prove it.
4. `CBaseUndoable`/`CBaseToolAttr` consumers were not traced.
