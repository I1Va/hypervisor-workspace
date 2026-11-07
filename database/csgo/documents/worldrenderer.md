# `worldrenderer.dll` — world geometry rendering

Reverse-engineering notes. Addresses are RVAs in
`bin/win64/worldrenderer.dll`, `ImageBase = 0x180000000`.

---

## 1. Identity

| Property | Value |
|---|---|
| File | `worldrenderer.dll` |
| Size on disk | **2,029,720** bytes |
| `SizeOfImage` | 2,535,424 (`0x26B000`) |
| SHA256 | see `index/manifest.json` |
| ImageBase | `0x180000000` |
| Entry point RVA | `0x104250` |
| PE timestamp | 1793662489 |
| PDB | `...\worldrenderer\_vpc_worldrenderer\default\win64\_msvc_\Retail\worldrenderer.pdb` |
| `.pdata` records | 6,037 |
| Merged real functions | **3,020** |
| Exports | 6 (standard Source 2 module ABI) |
| RTTI types | 210 |

`.data` is 569,060 virtual against 61,440 raw — a 507 KB BSS region, so the world
renderer works from statically allocated world-scale pools rather than per-frame
allocation, like `scenesystem`.

---

## 2. What this module is

`worldrenderer.dll` handles **world geometry**: the static level itself rather
than arbitrary scene objects. In Source 2 terms that is the world BSP data, brush
models, and the world's lightmap/visibility data.

It is deliberately small (3,020 functions) compared with `scenesystem` (10,248)
because it consumes the generic scene pipeline rather than duplicating it.

---

## 3. Interface registered

Stubs jump to `CreateInterface` at `0xfd440` (export; stubs target the thunk at `0xfd420`). One:

| Interface | Stub RVA |
|---|---|
| `WorldRendererMgr001` | `0x1fb5` |

A single interface is the correct shape for this module: the engine holds
`WorldRendererMgr001` and everything else is internal.

---

## 4. Entity and schema plumbing

The RTTI set is dominated by entity-model classes, not render classes:

| Class | Note |
|---|---|
| `CEntityInstance`, `CEntityIdentity`, `CEntityComponent`, `CEntityComponentHelper` | the engine entity model |
| `CEntityIOOutput` | entity I/O (inputs/outputs) |
| `CEntityClassInfoModuleMetadataProvider`, `CEntityAPIModuleMetadataProvider` | entity schema registration |
| `CBaseIntrospectedToKV3TypeManager`, `CDefScriptAccessorBase` | KeyValues3 / script binding |

This is worth stating plainly: `worldrenderer` carries a substantial **entity and
schema-binding** surface. In Source 2 the world is an entity graph, so the world
renderer needs entity identity and component access to know what to draw and
where — but these classes being *here* rather than in `server`/`client` suggests
this module also provides the entity model used by tooling (`resourcecompiler`,
`assetpreview`), which link against it.

`CAllocatorUtils` / `CDeallocatorUtils` are the module's allocation helpers.

---

## 5. Unknowns

1. **`WorldRendererMgr001` vtable** — not walked.
2. **World data format** — how the BSP/brush data is laid out and streamed is not
   reversed.
3. **Lightmaps and visibility** — no lightmap class appears in the first RTTI
   entries; they may be in `scenesystem` or in the compiled `.vpk` world data.
4. **The entity classes** — whether they are this module's own or linked-in shared
   code was not determined; the duplicate `CBaseVModuleMetadataProvider` and
   `CBufferString` entries across modules suggest shared header code compiled into
   each DLL rather than a shared library.
5. **The 507 KB BSS region** — partition not mapped.

---

## 6. Method note

3,020 merged functions from 6,037 `.pdata` records; see `server.md` §0.
