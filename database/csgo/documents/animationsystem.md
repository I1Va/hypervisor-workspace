# `animationsystem.dll` — skeletal animation and the animation graph

Addresses are RVAs in `bin/win64/animationsystem.dll`,
`ImageBase = 0x180000000`.

## 1. Identity

| Property | Value |
|---|---|
| Size on disk | **9,329,816** bytes |
| `SizeOfImage` | 12,496,896 (`0xBE4000`) |
| SHA256 | `index/manifest.json` |
| ImageBase | `0x180000000` |
| PDB | `...\animationsystem\_vpc_animationsystem\default\win64\_msvc_\Retail\animationsystem.pdb` |
| `.pdata` records | 31,640 |
| Merged functions | **17,811** |
| Exports | 6 (module ABI) |
| Imports | `tier0` 233, `KERNEL32` 84 |

Among Valve modules it ranks fifth by size — `resourcecompiler` 56 MB, `client`
39 MB, `server` 35 MB, `physicsbuilder` 14 MB, then `animationsystem` 9.3 MB — but
its 31,640 `.pdata` records are the fourth-highest in the whole corpus, behind
`resourcecompiler` (147,822), `client` (128,392) and `server` (108,977). It is a
dense module: many small functions, not a few large ones.

## 2. The operation/update-node pair — the core abstraction

The RTTI names expose the module's central design directly. Everything comes in
**two** flavours:

| Operation (evaluation) | Update node (graph) | What it is |
|---|---|---|
| `CAddPoseOperation` | `CAddUpdateNode` | additive pose blending |
| `CAimCameraOperation` | `CAimCameraUpdateNode` | aim camera |
| `CAimMatrixPoseOperation` | `CAimMatrixUpdateNode` | aim matrix |
| `CAimConstraint` | — | constraint (shared with `vphysics2`/`meshsystem`) |

An **`UpdateNode`** is a node in the animation graph — the persistent, evaluated-
per-frame object that owns state (previous pose, blend weights, timing).
An **`Operation`** is the stateless computation applied at a node.

That split is why the module is 17,811 functions: every anim-graph feature needs
both halves, and the graph is a large library of composable nodes. `CActionComponentInstance`
/ `CActionComponentUpdater` is the same pairing at component level.

## 3. Interfaces registered

`CreateInterface` export at `0x5e10a0`; stubs target thunk `0x5e1080`. Two:

| Interface | Stub RVA |
|---|---|
| `AnimationSystem_001` | `0x1655` |
| `AnimationSystemUtils_001` | `0x1995` |

## 4. Relationship to the rest of the corpus

| Module | Role |
|---|---|
| `animationsystem` (this) | anim graph evaluation, pose operations, skeletal state |
| `meshsystem` | skeleton **data model** and constraint solver (see `meshsystem.md`) |
| `scenesystem` | consumes the resulting pose to build draw lists |

The `CAimConstraint` duplication across `animationsystem`, `meshsystem` and
`vphysics2` is the shared-header pattern documented in `vphysics2.md`: the same
header compiled into several DLLs, each with its own vtable. It means the class
name alone does not tell you which module implements it.

## 5. Unknowns

1. Both vtables not walked.
2. The anim graph serialisation format is not reversed.
3. The complete node catalogue is not enumerated (only the `C*Operation` /
   `C*UpdateNode` pairs visible in RTTI are named here).
4. Whether evaluation is single- or multi-threaded is not established — with
   17,811 functions and a per-frame workload, this matters, but no threading class
   appears in the first RTTI entries.
5. `AnimationSystemUtils_001` contents unknown.
