# `rendersystemempty.dll` — the null render backend

Addresses are RVAs in `bin/win64/rendersystemempty.dll`,
`ImageBase = 0x180000000`.

## 1. Identity

| Property | Value |
|---|---|
| Size on disk | **1,774,744** bytes |
| `SizeOfImage` | 2,158,592 (`0x20F000`) |
| SHA256 | `index/manifest.json` |
| ImageBase | `0x180000000` |
| PDB | `...\rendersystem\_vpc_rendersystemempty\default\win64\_msvc_\Retail\rendersystemempty.pdb` |
| `.pdata` records | 4,465 |
| Merged functions | **2,306** |
| Exports | 6 (module ABI) |
| Imports | `tier0` 201, `KERNEL32` 90, `ADVAPI32` 5 |

## 2. What it is — and why it is 1.7 MB

A **null renderer**: it implements the RHI so the engine can run with no GPU
output. This is what a dedicated server uses, and what headless tools use.

The striking fact is the size. A null renderer conceptually does nothing, yet it
is 1.77 MB with 2,306 functions — 39% of the real D3D11 backend (4.55 MB). That is
the cost of the RHI being a wide interface: most of the code exists to satisfy
every method, track state consistently, and keep the engine's assumptions intact
even though no pixels are produced.

## 3. Interfaces registered

`CreateInterface` export at `0xf91d0`; stubs target thunk `0xf91b0`. Two — the
**same two names** as the D3D11 backend:

| Interface | Stub RVA |
|---|---|
| `RenderDeviceMgr001` | `0x16a5` |
| `RenderUtils_001` | `0x1b65` |

Identical interface names across backends is the design: the engine loads whichever
backend it needs and asks for `RenderDeviceMgr001` without knowing which one it
got. That is polymorphism at the module boundary.

## 4. Class set — the null implementations

| Class | Role |
|---|---|
| `CDeviceFence`, `CDeviceFenceBase` | the abstract fence (shared base with the real backends) |
| `CEmptyShaderBuffer` | a buffer object that holds no GPU memory |
| `CPooledIndexBuffer`, `CPooledVertexBuffer` | pooled geometry, allocated but never uploaded |

`CEmptyShaderBuffer` is the honest naming: the object exists to keep the engine's
bookkeeping valid, and its contents are irrelevant.

Note `rendersystemempty` has `CDeviceFenceBase` but **not** `CDeviceFenceDx11` —
confirming the base/implementation split documented in `rendersystemdx11.md`.

## 5. Use in this corpus

Since the DTB runs CS2, the null backend is loaded only in headless operation. Its
presence in the install is required because the dedicated-server path and the
`resourcecompiler`/`assetpreview` tools may run without a display.

## 6. Unknowns

1. Both vtables not walked.
2. What, if anything, it actually computes (some null backends still track metrics).
3. Whether the dedicated server in CS2 uses this or the Vulkan backend with a null
   swapchain is not established.
