# `navsystem.dll` — navigation mesh generation and pathfinding

Addresses are RVAs in `bin/win64/navsystem.dll`, `ImageBase = 0x180000000`.

## 1. Identity

| Property | Value |
|---|---|
| Size on disk | **1,314,968** bytes |
| `SizeOfImage` | 1,380,352 (`0x151000`) |
| SHA256 | `index/manifest.json` |
| ImageBase | `0x180000000` |
| Entry point | `0xd6508` |
| Timestamp | 1793662339 |
| PDB | `...\navsystem\_vpc_navsystem\default\win64\_msvc_\Retail\navsystem.pdb` |
| `.pdata` records | 3,594 |
| Merged functions | **1,681** |
| Exports | 6 (module ABI) |
| RTTI types | 132 |

## 2. Recast is statically linked

This is the module's clearest finding. The RTTI set is a Recast pipeline:

| Class | Recast concept |
|---|---|
| `CNavGenRecastTile` | the rasterised tile |
| `CNavGenOrientedMeshTile` | the Recast "detail mesh" |
| `CNavGenPoly`, `CNavGenPolyProcessorStage1`, `...Stage2`, `...StageBase` | polygonisation passes |
| `CNavGenDebugData` | Recast's debug output |
| `CNavGenOutput` | the generation result |

[Recast](https://github.com/recastnavigation/recastnavigation) is the standard
open-source navmesh generator (zlib licence) used across the industry. Its presence
means navmesh **generation** (from level geometry) is compiled into the shipped
binary, not just pathfinding over a precomputed mesh.

The `Stage1`/`Stage2`/`StageBase` polymorphic split is Recast's `rcBuildPolyMesh`
followed by `rcBuildPolyMeshDetail`, restructured into classes.

## 3. Interface registered

`CreateInterface` export at `0xc0b10`; stubs target thunk `0xc0af0`. One:

| Interface | Stub RVA |
|---|---|
| `NavSystem001` | `0x1345` |

## 4. Other classes

| Class | Role |
|---|---|
| `CNavBlock` | navmesh block (spatial subdivision) |
| `CNavPathCost`, `CNavPathCostVDataFileManager` | path cost data |
| `CNavHullPresetVDataFileManager`, `CNavHullVDataFileManager` | agent hull presets (the shape an agent needs to fit through) |
| `CBaseVDataFileManager` | the `.vdata` loader base |
| `CKV3TransferLoadContext`, `...SaveContext`, `..._AssertAlreadyLoadedResourceLoadInterface` | KV3 serialisation of nav data |

The `VDataFileManager` classes show navmesh parameters live in **`.vdata` files**
(Valve's data format), loadable per-map or per-agent-preset, rather than being
compile-time constants. That is why generation can run at build time on the
`resourcecompiler` side and again at runtime if needed.

## 5. Unknowns

1. `NavSystem001` vtable not walked.
2. Whether runtime generation is actually used in shipping CS2, or generation
   happens offline and only pathfinding ships, is not established from the binary
   alone (both code paths exist).
3. The pathfinding query algorithm (A*, hierarchical, or Recast's `rcFindPath`) is
   not identified.
4. The `.vdata` nav parameter schema is not extracted.
