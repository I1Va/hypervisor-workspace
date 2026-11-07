# `resourcecompiler.dll` — the asset build tool

Addresses are RVAs in `bin/win64/resourcecompiler.dll`,
`ImageBase = 0x180000000`.

## 1. Identity

| Property | Value |
|---|---|
| Size on disk | **56,351,896** bytes (the largest file in the corpus) |
| `SizeOfImage` | 66,252,800 (`0x3F2C000`) |
| SHA256 | `index/manifest.json` |
| ImageBase | `0x180000000` |
| PDB | `...\resourcecompiler\_vpc_resourcecompiler\default\win64\_msvc_\Retail\resourcecompiler.pdb` |
| `.pdata` records | **147,822** (most in the corpus) |
| Merged functions | **78,667** |
| Exports | 6 (module ABI) |
| RTTI types | **11,659** (most in the corpus) |

### Imports

| DLL | Symbols | Note |
|---|---|---|
| `tier0.dll` | 705 | |
| `KERNEL32.dll` | 140 | |
| **`v8.dll`** | **33** | JavaScript |
| `embree3.dll` | 14 | Intel Embree ray tracing |
| `WS2_32.dll` | 8 | sockets |
| `steam_api64.dll` | 9 | |
| `USER32.dll`, `ADVAPI32.dll` | 9, 3 | |
| `libfbxsdk_2020_3_1.dll` | 2 | FBX model import |

No Qt — so it is a **command-line tool**, not a GUI, unlike `toolframework2`.

**Embree** is the notable dependency: Intel's ray-tracing library is used here for
**baking** — lightmap ray casting, ambient occlusion, and visibility. That is a
build-time use of ray tracing, distinct from the runtime use in
`rendersystemvulkan` (`CBLASVulkan`).

**V8** means parts of the asset pipeline are scripted in JavaScript, so content
authors can write processing steps.

## 2. What it is

The asset compiler: it turns source assets (models, materials, maps, particles,
animations) into the compiled formats the game loads. It is the tool that runs
before a build ships.

Two interfaces:

| Interface | Stub RVA |
|---|---|
| `ResourceCompilerSystem001` | `0x4be95` |
| `MODEL_PROCESSING_SERVICES_INTERFACE_001` | `0x4c315` |

`CreateInterface` export at `0x1ec7a50`. Both stubs are unaligned and far into
`.text` (around `0x4bxxx`), the same late-registration pattern seen in
`filesystem_stdio`, `panorama` and `toolframework2`.

`MODEL_PROCESSING_SERVICES_INTERFACE_001` uses all-caps snake case rather than the
usual CamelCase — the naming inconsistency is real and marks it as a service
interface rather than a system interface.

## 3. Why 78,667 functions and 11,659 types

A single tool that can process every asset type must link the **complete** type
registry of the engine — every particle operator (`CAddPoseOperation`,
`CAddUpdateNode`, `CActionComponent*` from `animationsystem`), every material
node, every model format — because it deserialises and re-serialises all of them.

This is why it is 56 MB and why its RTTI count is three times `toolframework2`'s.
It is not 78,667 functions of *unique* logic; it is the whole engine's content code
plus the compiler on top.

## 4. Position in the corpus

| Module | Role | Size |
|---|---|---|
| `resourcecompiler` (this) | build-time: assets → compiled data | 56.4 MB |
| `physicsbuilder` | build-time: geometry → collision | 14.0 MB |
| `toolframework2` | build-time: shared tool shell (Qt) | 13.7 MB |
| `resourcesystem` | **runtime**: serves the compiled data | 0.5 MB |
| `vphysics2`, `particles`, etc. | runtime consumers | |

The asymmetry is stark: compiling assets is 56 MB; serving them at runtime is
0.5 MB. That is a real property of Source 2's design — all the expensive work is
moved offline, and the shipping game only reads the results.

## 5. Unknowns

1. Both vtables not walked.
2. The complete asset-type list is not enumerated.
3. How the V8 scripting hooks into pipeline stages is not reversed.
4. Whether Embree baking is lightmaps, AO, or both is not established (both are
   plausible and both use this library).
5. The 78,667 merged functions were not individually examined; the count is from
   `.pdata` merging only.
6. It is not established whether this module is loaded by the game at all, or only
   by the SDK/tools — the presence of `steam_api64` suggests it can run under Steam.
