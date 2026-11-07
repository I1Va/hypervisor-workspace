# `rendersystemdx11.dll` — D3D11 render backend

Reverse-engineering notes. Addresses are RVAs in `bin/win64/rendersystemdx11.dll`,
`ImageBase = 0x180000000`.

---

## 1. Identity

| Property | Value |
|---|---|
| File | `rendersystemdx11.dll` |
| Size on disk | **4,545,688** bytes |
| `SizeOfImage` | 4,931,584 (`0x4B4000`) |
| SHA256 | see `index/manifest.json` |
| ImageBase | `0x180000000` |
| Entry point RVA | `0x1ad118` |
| PE timestamp | 1793662329 |
| PDB | `...\rendersystem\_vpc_rendersystemdx11\...\rendersystemdx11.pdb` |
| `.pdata` records | 7,327 |
| Merged real functions | **3,647** |
| Exports | 6 (standard Source 2 module ABI) |
| RTTI types | 234 |

Unusual for this corpus: `.rdata` (2,358,180) is **larger** than `.text`
(2,001,808). A 2.3 MB read-only data section in a 4.5 MB DLL means large static
tables — shader bytecode, state-object descriptions, or feature tables — compiled
in rather than loaded from disk.

---

## 2. What this module is

One of four interchangeable render backends (`rendersystemdx11`,
`rendersystemvulkan`, `rendersystemempty`, and the D3D12-era path). It implements
the Source 2 RHI (render hardware interface) over D3D11, so the scene system
above it is backend-agnostic.

Evidence: it registers `RenderDeviceMgr001` and every class is D3D11-specific
(`CDx11Fsr2Upscaler`, `CDeviceFenceDx11`, `CAftermathDx11`, `CAMDAntiLagDx11`).

---

## 3. Interfaces actually registered

Stubs jump to `CreateInterface` at `0x15f940` (export; stubs target the thunk at `0x15f920`). Two:

| Interface | Stub RVA |
|---|---|
| `RenderDeviceMgr001` | `0x7105` |
| `RenderUtils_001` | `0x7d45` |

`RenderDeviceMgr001` is the RHI entry point: it creates the device and exposes
the resource/fence/command surface. `RenderUtils_001` is the helper set.

---

## 4. Vendor and upscaling integration

The RTTI set shows this backend is where **vendor middleware** is integrated:

| Class | Role |
|---|---|
| `CDxDlssUpscaler` | NVIDIA DLSS |
| `CDx11Fsr2Upscaler` | AMD FSR 2 |
| `CAftermathDx11` | NVIDIA Aftermath (GPU crash dumps) |
| `CAMDAntiLagDx11` | AMD Anti-Lag |
| `CDeviceFence`, `CDeviceFenceBase`, `CDeviceFenceDx11` | GPU fence abstraction and its D3D11 implementation |
| `CBarrierHelperEmpty` | a no-op barrier helper — D3D11 has implicit barriers, unlike Vulkan, so the "empty" implementation is the correct one here |

`gfsdk_aftermath_lib.x64.dll`, `amd_ags_x64.dll` and `nvapi`-style helpers appear
as sibling modules in the install, which matches this class set.

The `CDeviceFence` / `CDeviceFenceDx11` split is the RHI pattern: an abstract
fence with a per-API implementation, so `rendersystemvulkan` supplies its own
`CDeviceFenceVk` against the same base.

---

## 5. Shader compilation

`CDxInclude` and the `CCompileTargetExpr*` classes mark the D3DCompiler
integration: `CDxInclude` implements the `ID3DInclude` interface for `#include`
resolution, and the expression classes are the shader-target expression evaluator
(e.g. `ps_5_0` / `cs_5_0` selection).

---

## 6. Unknowns

1. **The `.rdata` tables** — 2.3 MB of read-only data, contents not classified.
   Distinguishing embedded shader blobs from state tables would need a scan.
2. **`RenderDeviceMgr001` vtable** — not walked.
3. **Command list path** — how deferred contexts are used (if at all) is not
   established; D3D11 supports both immediate and deferred.
4. **Swapchain chain** — DXGI factory/swapchain creation is not located.
5. **`RenderUtils_001`** — contents unknown.

---

## 7. Method note

3,647 merged functions from 7,327 `.pdata` records; see `server.md` §0 for the
merging rule.
