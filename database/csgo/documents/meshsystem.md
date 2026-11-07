# `meshsystem.dll` — skeletons, constraints and mesh data

Addresses are RVAs in `bin/win64/meshsystem.dll`, `ImageBase = 0x180000000`.

## 1. Identity

| Property | Value |
|---|---|
| Size on disk | **1,664,664** bytes |
| `SizeOfImage` | 2,211,840 (`0x21C000`) |
| SHA256 | `index/manifest.json` |
| ImageBase | `0x180000000` |
| PDB | `...\meshsystem\_vpc_meshsystem\default\win64\_msvc_\Retail\meshsystem.pdb` |
| `.pdata` records | 5,583 |
| Merged functions | **2,561** |
| Exports | 6 (module ABI) |
| Imports | `tier0` 160, `KERNEL32` 75 |

`.data` is 604,968 virtual against 60,928 raw — a 544 KB BSS region, consistent
with pooled mesh data allocated once rather than per asset.

## 2. What it is

The **skeleton and constraint** layer: bone hierarchies, and the constraints that
make bones follow other bones.

| Class | Role |
|---|---|
| `CAnimSkeleton` | the bone hierarchy |
| `CBaseConstraint` | constraint base |
| `CBoneConstraintBase`, `CBoneConstraintDotToMorph`, `CBoneConstraintPoseSpaceBone` | bone-follows-bone constraints |
| `CAimConstraint` | aim-at constraint |
| `CBaseIntrospectedToKV3TypeManager` | KV3 conversion |

`CBoneConstraintDotToMorph` is notably specific: it drives a **morph target** from
a bone's dot product, which is facial/corrective deformation driven by skeletal
pose. `CBoneConstraintPoseSpaceBone` is a pose-space deformation driver. Together
they place this module in the animation-deformation pipeline rather than in static
mesh storage.

## 3. Interface registered

`CreateInterface` export at `0x101e80`; stubs target thunk `0x101e60`. One:

| Interface | Stub RVA |
|---|---|
| `MeshSystem001` | `0x1185` |

## 4. Relationship to animationsystem

`animationsystem.dll` is 9.3 MB with 31,640 `.pdata` records and holds the anim
graph and skeletal evaluation; `meshsystem` (1.66 MB) holds the skeleton *data
model* and constraint solver. The split is data model vs. evaluation.

## 5. Unknowns

1. `MeshSystem001` vtable not walked.
2. The skeleton data format is not reversed.
3. Whether the constraint solver runs per-frame on CPU or feeds GPU skinning is not
   established.
4. The `.data` BSS partition is not mapped.
