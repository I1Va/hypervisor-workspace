# `host.dll` — Source 2 host layer

Reverse-engineering notes. Every address is an RVA in
`csgo/bin/win64/host.dll`, `ImageBase = 0x180000000`.

Where a name is not proven by an RTTI type descriptor, a `__FILE__` literal, a
`Source2Host001` interface string, or a vtable layout, it is marked **inferred**
with the evidence that produced it.

---

## 1. Identity

| Property | Value |
|---|---|
| File | `host.dll` |
| Size on disk | **1,389,208** bytes |
| `SizeOfImage` | 1,441,792 (`0x160000`) |
| SHA256 | see `index/manifest.json` (authoritative) |
| ImageBase | `0x180000000` |
| Entry point RVA | `0xcf774` |
| PE timestamp | 1793662605 |
| PDB | `C:\buildworker\csgo_rel_win64\build\_build_\game\host\_vpc_host_csgo\default\win64\_msvc_\Retail\host.pdb` |
| `.pdata` records | 4,085 |
| Merged real functions | **2,644** |
| Exports | 6 |
| Import DLLs | 2 (`tier0.dll` 82, `KERNEL32.dll` 83) |

### Sections

| Name | Virtual size | Raw size | Entropy |
|---|---|---|---|
| `.text` | 1,021,376 | 1,021,440 | 6.47 |
| `.rdata` | 264,142 | 264,192 | 5.50 |
| `.data` | 82,052 | 32,768 | 3.59 |
| `.pdata` | 49,020 | 49,152 | 6.05 |
| `.reloc` | 9,164 | 9,216 | 5.44 |

Entropy in the normal range for compiled C++ throughout; no packing.

### Function counting

The 4,085 `.pdata` `RUNTIME_FUNCTION` records are **hot/cold chunks**, not
functions. MSVC emits one record per fragment and only the first is 16-byte
aligned, so merging non-aligned continuations gives 2,644 real functions. Any
figure quoted as "4,085 functions" is wrong by 35%. This is the same correction
documented in `server.md` §0.

---

## 2. What this module is

`host.dll` is unusually self-contained: **two import DLLs only**, and one of them
is `tier0`. It does not import `filesystem_stdio`, `resourcesystem`,
`schemasystem`, or any render/module DLL. Everything it needs, it gets through
`tier0`'s platform layer and KERNEL32.

That, plus its interface set, defines its job: it is the **host-side glue between
the engine and the game systems** — the command/cvar registry's home, the
game-UI (main menu) state machine, save/restore, model info, and the host-side
event dispatcher.

Provenance confirms a `_vpc_host_csgo` build under `src/game/host/`.

---

## 3. Exports — the Source 2 module ABI

All six are the standard Source 2 module surface:

| Export | Role |
|---|---|
| `CreateInterface` | Interface registry factory; every self-registered interface resolves through it |
| `BinaryProperties_GetValue` | Module identity/metadata responder |
| `ExtractModuleMetadata` | Resource manifest metadata |
| `GetResourceManifestCount` / `GetResourceManifests` | Resource manifests this module ships |
| `InstallSchemaBindings` | Registers this module's schema types |

`host` exports the same six as `client.dll`, `server.dll`, `engine2.dll` and every
other Valve module. This is the Source 2 **module ABI**: any DLL that wants to be
a Source 2 module implements exactly this surface, which is why `CreateInterface`
can be located mechanically in every binary.

---

## 4. Interfaces actually registered

The `index/ifaces/host.txt` list (85 names) is a **string scan** and therefore a
superset: it contains names the module merely imports or mentions. The real
registrations are found by locating the small stubs that end in a `jmp` to this
module's `CreateInterface`, which is the export at RVA `0xc4520`. The stubs target
`0xc4500`, an import thunk 0x20 bytes *before* the export address.

**Seven self-registered interfaces** (`scripts/iface_stubs.py host`):

| Interface | Stub RVA |
|---|---|
| `DebugDrawQueueManager001` | `0x15f5` |
| `GameModelInfo001` | `0x1625` |
| `HostUtils001` | `0x1695` |
| `PredictionDiffManager001` | `0x1d65` |
| `SaveRestoreDataVersion001` | `0x1d95` |
| `SinglePlayerSharedMemory001` | `0x1dc5` |
| `Source2Host001` | `0x1e35` |

These seven read as a coherent set: host utilities, the debug draw queue, model
info, prediction **diff** state (the client/server divergence the host
coordinates), save/restore, shared memory, and the host root interface itself.
`Source2Host001` is the entry point the engine holds.

---

## 5. The command and cvar registry

`host.dll` imports only `tier0` and KERNEL32, and its RTTI includes
`CGameSystem2HostHook` and `CGameSystemEventDispatcher`. The command buffer and
the ConVar/ConCommand tables are `tier0` objects (`CCommandBuffer`,
`CConCommand`, `CConVar` are all exported from `tier0` — see
`index/symbols/tier0.txt`); `host` owns the *host-side* policy over them rather
than the storage itself.

The cvar scan finds only four host-local cvars:

| cvar | RVA | Note |
|---|---|---|
| `host_computationtime` | `0x11b74c` | per-frame compute time |
| `host_unfiltered_frametime` | `0x11b7b0` | raw frame delta |
| `host_frame_dropped_pct_x10` | `0x11b82d` | dropped-frame percentage ×10 |
| `key_t` | `0x11ba09` | (likely a `KeyValues` key name, not a cvar) |

That is a low count for a module this size, consistent with `host` being
consumers of other modules' registries rather than a registry owner.

---

## 6. Notable classes (from RTTI, 239 entries)

Names are exact MSVC RTTI type names, not inferred.

| Class | Inferred role |
|---|---|
| `CHostUtils` | `HostUtils001` implementation |
| `CDebugDrawQueueMgr` | `DebugDrawQueueManager001` implementation |
| `CGameModelInfo` | `GameModelInfo001` implementation |
| `CGameSystem2HostHook` | hooks game systems into the host lifecycle |
| `CGameSystemEventDispatcher` | dispatches game-system events |
| `CBaseVModuleMetadataProvider`, `CModuleMetadataProvider_ResourceManifests` | module metadata / manifests |
| `CMsgPlayerInfo`, `CMsgQAngle`, `CMsgQuaternion`, `CMsgRGBA`, `CMsgTransform`, `CEntityMsg` | user-message types |
| `CFootstepSoundsTable` | footstep sound lookup |
| `CAnimScriptBase`, `CAnimScriptFactoryBase`, `CEmptySequence` | anim script plumbing |
| `CDontUseThisGameSystem` | explicit guard class |

The `CMsg*` family is the user-message type set the host dispatches — these are
the messages `CGameMessageDelegateHook` (documented in `client.md`) routes.

---

## 7. Most significant functions

Ranked by resolved string references (`lea` operands, RIP-relative — see the
methodology note), because size alone does not identify purpose.

| RVA | Note |
|---|---|
| `0x15f5`, `0x1625`, `0x1695`, `0x1d65`, `0x1d95`, `0x1dc5`, `0x1e35` | interface registration stubs (§4) |
| `0x11b74c`–`0x11ba09` | host cvar registration sites (§5) |
| `0xc4520` | `CreateInterface` (export; stubs target `0xc4500`) |
| `0xcf774` | entry point / module startup |

Function-level attribution below this line needs the disassembly pass, which has
not been done for this module.

---

## 8. Unknowns

1. **`HostUtils001` vtable** — not walked. Its slot count and method purposes are
   not established.
2. **`PredictionDiffManager001`** — the diff algorithm (what is compared between
   predicted and authoritative state) is not reversed.
3. **`SinglePlayerSharedMemory001`** — the shared-memory layout is not mapped.
4. **The two missing stubs** — `server.md` reports 10 interfaces where this
   detector finds 8 of the same shape, and `client.dll` has 9 vs 6 found here.
   Some stubs use a different prologue (register setup differs when an interface
   takes extra arguments); the detector is conservative and does not report them.
5. **`CDontUseThisGameSystem`** — the name is deliberate; what triggers it is not
   traced.
6. **Save/restore format** — `SaveRestoreDataVersion001` exists, but the
   serialization format is not reversed.

Each would be resolved by full decompilation of the four interface vtables and a
`CreateInterface` caller sweep, which the `scripts/server/ad2.py` toolkit
supports.
