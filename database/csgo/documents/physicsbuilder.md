# `physicsbuilder.dll` — offline collision cooking

Addresses are RVAs in `bin/win64/physicsbuilder.dll`, `ImageBase = 0x180000000`.

## 1. Identity

| Property | Value |
|---|---|
| Size on disk | **13,950,616** bytes |
| `SizeOfImage` | 16,171,008 (`0xF6D000`) |
| SHA256 | `index/manifest.json` |
| ImageBase | `0x180000000` |
| PDB | `...\physicsbuilder\_vpc_physicsbuilder\default\win64\_msvc_\Retail\physicsbuilder.pdb` |
| `.pdata` records | 33,042 |
| Merged functions | **17,543** |
| Exports | 6 (module ABI) |
| RTTI types | **3,705** |
| Imports | `tier0` 320, `KERNEL32` 100, `USER32` 6 |

Notably **no Qt** — unlike `toolframework2`. So this is a builder that runs
headless or under another tool, not a GUI application itself.

## 2. What it is

The **offline collision-data cooker**. It takes source geometry (models, brushes)
and produces the collision representations the physics engine uses at runtime.

Evidence: it registers `PhysicsBuilderMgr001`, it carries the shared
`CAimConstraint` / `CAnimSkeleton` / `CAuthClothChain` / `CAuthClothDataTable`
headers, and its export surface is the ordinary module ABI — so the builder is
driven through its interface, not through bespoke exports.

`CAuthClothDataTable` is the interesting one: **cloth** collision data is baked
here too. Cloth is a distinct solver from rigid bodies, and having its data cooked
by the same builder explains why this module is 17,543 functions.

## 3. Runtime pairing

| Module | Role |
|---|---|
| `physicsbuilder` (this) | offline: geometry → collision hulls/meshes/cloth |
| `vphysics2` | runtime: Rubikon integrates those shapes (see `vphysics2.md`) |
| `meshsystem` | runtime: skeleton and constraints |

The export names in `vphysics2` (`RnHullCreate*`, `RnMeshCreate`,
`RnCompoundClone`) are the *runtime* constructors; `physicsbuilder` is what
produces the data those constructors consume. That is why `meshsystem` and
`physicsbuilder` still need the shared headers: both must agree on the shape
representation.

## 4. Interface registered

`CreateInterface` export at `0x628000`; stubs target thunk `0x627fe0`. One:

| Interface | Stub RVA |
|---|---|
| `PhysicsBuilderMgr001` | `0x1045` |

## 5. Why 3,705 RTTI types

Because it is a **builder**, it instantiates the document model for every asset
type it can cook. Its type count is close to `resourcecompiler`'s (11,659), which is
the same phenomenon at larger scale: a tool that must understand every asset format
links the type registry for all of them.
## 6. Unknowns

1. `PhysicsBuilderMgr001` vtable not walked.
2. The cooking pipeline stages are not reversed.
3. Which hull-generation algorithm is used (convex decomposition method) is not
   established.
4. How it is invoked (part of `resourcecompiler`, or standalone) is not determined
   from the binary alone.
