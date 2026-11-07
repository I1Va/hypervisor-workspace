# `particles.dll` — particle systems

Addresses are RVAs in `bin/win64/particles.dll`, `ImageBase = 0x180000000`.

## 1. Identity

| Property | Value |
|---|---|
| Size on disk | **6,460,568** bytes |
| `SizeOfImage` | 8,892,416 (`0x87B000`) |
| SHA256 | `index/manifest.json` |
| ImageBase | `0x180000000` |
| PDB | `...\particles\_vpc_particles\default\win64\_msvc_\Retail\particles.pdb` |
| `.pdata` records | 14,331 |
| Merged functions | **8,407** |
| Exports | 6 (module ABI) |
| Imports | `tier0` 236, `KERNEL32` 75 |

## 2. What it is

The particle system: effect definitions, emitters, and the renderer abstraction
that turns a particle simulation into draw calls.

| Class | Role |
|---|---|
| `CBaseRendererSource2` | the renderer abstraction root (Source 2) |
| `CBaseTrailRenderer` | trail-style rendering |
| `CChildFunctionDefinition` | a particle function that itself instantiates child systems |
| `CDefaultParticleSystemQuery` | the query interface for a system's state |

`CChildFunctionDefinition` is the interesting one: particles can spawn child
particle systems, so effects compose recursively rather than being flat emitter
lists.

`CBaseRendererSource2` having a `Source2` suffix marks it as the rewritten particle
renderer (Source 1 had a different particle system); the naming is how Valve
distinguishes the generations in shared code.

## 3. Interface registered

`CreateInterface` export at `0x4253e0`; stubs target thunk `0x4253c0`. One:

| Interface | Stub RVA |
|---|---|
| `ParticleSystemMgr003` | `0x48f5` |

Revision **003** — this interface has been changed three times, more than most.

## 4. Size note

8,407 functions and 8.9 MB mapped for particle effects. The size comes from the
large number of **particle operators** (each operator — gravity, vortex, turbulence,
colour fade, etc. — is a class with its own evaluation), plus the renderer
abstraction covering every particle render mode.

`.data` is 2,806,924 virtual against 373,760 raw — a 2.4 MB BSS region, the largest
such region in the corpus after `scenesystem`. Both are simulation systems holding
per-instance pools, which is consistent: particles allocate their runtime state
from a fixed arena.

## 5. Unknowns

1. `ParticleSystemMgr003` vtable not walked.
2. The particle definition format (`.vpcf` files) is not reversed.
3. The complete operator catalogue is not enumerated.
4. Whether simulation runs on CPU or GPU compute is not established.
5. The `.data` arena (2.4 MB BSS) is not partitioned among operator types.
