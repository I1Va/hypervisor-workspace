# `vphysics2.dll` — rigid body physics

Addresses are RVAs in `bin/win64/vphysics2.dll`, `ImageBase = 0x180000000`.

## 1. Identity

| Property | Value |
|---|---|
| Size on disk | **4,829,848** bytes |
| `SizeOfImage` | 5,857,280 (`0x596000` — see `video64.md` for why this matches) |
| SHA256 | `index/manifest.json` |
| ImageBase | `0x180000000` |
| PDB | `...\vphysics2\_vpc_vphysics2\default\win64\_msvc_\Retail\vphysics2.pdb` |
| `.pdata` records | 14,814 |
| Merged functions | **6,735** |
| Exports | **25** |
| Imports | `tier0` 195, `KERNEL32` 75 |

25 exports is more than the six-symbol ABI: this module publishes a real physics
API on top of the module surface.

## 2. Interface registered

`CreateInterface` export at `0x350120`; stubs target thunk `0x350100`. One:

| Interface | Stub RVA |
|---|---|
| `VPhysics2_Interface_001` | `0x17b5` |

## 3. What it is

The rigid-body simulation: collision shapes, integration, constraints, contact
solving. The RTTI overlap with `meshsystem` (`CAimConstraint`, `CBaseConstraint`,
`CBoneConstraintBase`, `CAnimSkeleton`, `CAllocatorUtils`,
`CBaseIntrospectedToKV3TypeManager`) is the clearest structural fact here.

**Shared headers, not a shared library.** `meshsystem.dll` imports only `tier0`
and KERNEL32 — it does not import `vphysics2` — yet both contain the same
constraint and skeleton classes. The explanation is that these are header-defined
types compiled separately into each DLL, so each has its own copy of the class and
its vtable. This is why `server.md`'s RTTI walk found duplicate type descriptors
across modules, and it means **a class name does not identify which module owns the
implementation** — a real trap when reading these docs.

`CAtomicMutex` in the RTTI set confirms the physics solver is multithreaded.

## 4. The exports name the engine: Rubikon

The 25 exports split into two groups. Six are the standard module ABI
(`CreateInterface`, `BinaryProperties_GetValue`, the resource-manifest pair,
`InstallSchemaBindings`, `ExtractModuleMetadata`). The other **19 are the physics
API**, and they name the engine:

```
RnStartup   RnShutdown   RnUnitTest
RnHullCreate  RnHullCreateBox  RnHullCreateCone  RnHullCreateCylinder
RnHullCreateRuntime  RnHullCreateRuntimeFromPlanes  RnHullClone  RnHullDestroy
RnMeshCreate  RnMeshClone  RnMeshDestroy  RnMeshHideTriangles
RnMeshUpdateChangedVertices  RnMeshUpdateTriangleAABBs
RnCompoundClone  RnCompoundDestroy
```

`Rn` = **Rubikon**, Valve's in-house rigid-body engine. This is concrete, not
inferred: the engine's own name is in its export table, and the API surface shows
its decomposition — **hulls** (collision primitives: box, cone, cylinder, arbitrary
from planes), **meshes** (triangle soups with mutable vertex/AABB updates), and
**compounds** (hulls/meshes grouped into one body).

`RnMeshUpdateTriangleAABBs` and `RnMeshUpdateChangedVertices` are the incremental
path for deforming or moving geometry without rebuilding the acceleration
structure. `RnUnitTest` is a shipped test entry point — the same pattern as
`CExampleSchemaVData_*` in `schemasystem`.

Because these are plain C exports rather than interface methods, a caller can bind
to Rubikon directly without going through `CreateInterface`.

## 5. Why 6,735 functions

Physics is the one system where both the code *and* the tuning are large: shape
generation, broadphase, narrowphase, contact manifolds, constraint solvers,
sleeping/deactivation, and raycast sweeps. `physicsbuilder.dll` (13.95 MB, not yet
documented) is the build-time counterpart that cooks collision data offline.

## 6. Unknowns

1. `VPhysics2_Interface_001` vtable not walked.
2. The 19 physics exports are named above but not individually reversed.
3. Which solver is used (sequential impulse, or a custom scheme) is not established.
4. The threading model (`CAtomicMutex` is present) is not mapped.
5. The split of responsibility with `physicsbuilder` is not verified.
