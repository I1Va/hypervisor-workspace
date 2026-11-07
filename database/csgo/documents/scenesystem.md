# `scenesystem.dll` — render scene graph and draw list construction

Reverse-engineering notes. Addresses are RVAs in `bin/win64/scenesystem.dll`,
`ImageBase = 0x180000000`. Names marked **inferred** where not proven by RTTI,
interface string, or `__FILE__`.

---

## 1. Identity

| Property | Value |
|---|---|
| File | `scenesystem.dll` |
| Size on disk | **7,094,936** bytes |
| `SizeOfImage` | 9,928,704 (`0x97A000`) |
| SHA256 | see `index/manifest.json` |
| ImageBase | `0x180000000` |
| Entry point RVA | `0x4cc16c` |
| PE timestamp | 1793662621 |
| PDB | `...\scenesystem\_vpc_scenesystem\default\win64\_msvc_\Retail\scenesystem.pdb` |
| `.pdata` records | 20,232 |
| Merged real functions | **10,248** |
| Exports | 6 (standard Source 2 module ABI) |
| RTTI types | 413 |

Sections: `.text` 5,718,192 virtual / 5,718,528 raw; `.rdata` 977,176;
`.data` **2,950,804 virtual but only 120,320 raw** — a 2.8 MB BSS region, i.e.
large statically-allocated pools rather than initialised data. This is the
rendering system's fixed memory arena, and its size is a design statement: the
scene graph does not heap-allocate per frame.

---

## 2. What this module is

`scenesystem.dll` builds the **scene graph and the draw lists** that a render
backend consumes. It is the layer between the game/engine (which says "this
entity is here, with this model and these materials") and the RHI backend (which
says "issue these GPU commands").

The class structure makes the split explicit: nearly every class comes in a
`C...Object` / `C...ObjectDesc` pair.

---

## 3. Interfaces actually registered

`index/ifaces/scenesystem.txt` is a superset. The real stubs jump to
`CreateInterface` at `0x4c7960` (export table; stubs target the thunk at `0x4c7940`). Three:

| Interface | Stub RVA |
|---|---|
| `RenderingPipelines_001` | `0x60e5` |
| `SceneSystem_002` | `0x76b5` |
| `SceneUtils_001` | `0xcae5` |

`SceneSystem_002` is the root — the `002` suffix marks it as the second major
revision of the scene-system interface, which is why older Source 2 titles expose
`SceneSystem_001`.

---

## 4. The Object/Desc pattern

| Class pair | Meaning |
|---|---|
| `CAggregateSceneObject` / `CAggregateSceneObjectDesc` | batched instance groups |
| `C6FaceSkyboxObject` / `...Desc` | six-face cubemap skybox |
| `CAggregateRTProxySceneObject` / `...Desc` | ray-tracing proxy geometry |
| `CAmbientOcclusionProxySceneObject` / `...Desc` | AO proxy |
| `CBarnLightObjectDesc`, `CBarnLightObjectDescGPU` | barn (area) lights; the `GPU` variant is the uploaded form |
| `CAnimatableSceneObjectDesc` | objects with an anim graph |
| `CBaseSceneObjectDesc` | root descriptor |

The pattern is: the `Desc` is the CPU-side description the game submits, and the
`Object` is the derived, GPU-ready form the pipeline builds. Separating them lets
the renderer re-derive objects without the game resubmitting.

`CBaseRenderingPipelineFactory` is the pipeline construction point — this is where
a render pass declares its shaders and state.

---

## 5. Data flow (inferred from class set)

```
game/engine submits  Desc  (aggregates, lights, proxies, skybox)
        |
        v
pipeline factory  ->  Object  (derived, cached)
        |
        v
draw list  ->  render backend (rendersystemdx11 / rendersystemvulkan)
```

This ordering is **inferred** from the class pairs and interface names. It is
consistent with `rendersystemdx11.md`'s device-manager design, but the exact draw
list structure was not decompiled.

---

## 6. Unknowns

1. **Draw list layout** — not reversed.
2. **`SceneSystem_002` vtable** — slot count and purposes unknown.
3. **Culling** — no frustum/occlusion class appears in the first 14 RTTI entries;
   culling may live in `worldrenderer` or in the pipeline classes.
4. **`.data` arena** — the 2.8 MB virtual/120 KB raw region is statically
   allocated, but its partition among subsystems is not mapped.
5. **`RenderingPipelines_001` vs `SceneSystem_002`** — which owns pipeline
   lifetime is not established.

---

## 7. Method note

Function counts here use merged `.pdata` boundaries (10,248) rather than raw
records (20,232). See `server.md` §0 for why the raw count is nearly 2× too high.
