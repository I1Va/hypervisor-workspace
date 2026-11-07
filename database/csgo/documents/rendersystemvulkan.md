# `rendersystemvulkan.dll` — the Vulkan render backend

Addresses are RVAs in `bin/win64/rendersystemvulkan.dll`,
`ImageBase = 0x180000000`.

## 1. Identity

| Property | Value |
|---|---|
| Size on disk | **6,249,624** bytes |
| `SizeOfImage` | 6,639,616 (`0x655000`) |
| SHA256 | `index/manifest.json` |
| ImageBase | `0x180000000` |
| PDB | `...\rendersystem\_vpc_rendersystemvulkan\...\rendersystemvulkan.pdb` |
| `.pdata` records | 10,455 |
| Merged functions | **5,044** |
| Exports | **58** |

### Imports

| DLL | Symbols | Note |
|---|---|---|
| `tier0.dll` | 325 | |
| `KERNEL32.dll` | 134 | |
| **`GFSDK_Aftermath_Lib.x64.dll`** | **18** | NVIDIA Aftermath |
| `ADVAPI32.dll` | 7 | |
| `USER32.dll` | 6 | |

There is **no `vulkan-1.dll` import**. That is the key structural fact: Vulkan is
loaded dynamically (through `vkGetInstanceProcAddr` resolved at runtime), not linked
statically. This is standard for a Vulkan application — it lets the loader pick an
ICD, and it means the module runs (and fails gracefully) on machines with no Vulkan
driver at all.

Aftermath is imported **statically** here (18 symbols), unlike in the D3D11 backend
where it is a sibling DLL. So GPU crash-dump support is version-split between the
two backends.

## 2. Interfaces registered

`CreateInterface` export at `0x240f20`; stubs target thunk `0x240f00`. Two — **the
same two names as both other backends**:

| Interface | Stub RVA |
|---|---|
| `RenderDeviceMgr001` | `0x1f45` |
| `RenderUtils_001` | `0x3105` |

Three backends (DX11, Vulkan, empty) all register `RenderDeviceMgr001` +
`RenderUtils_001`. The engine loads one and never knows which. This is the module-
boundary polymorphism described in `rendersystemempty.md`.

## 3. Where Vulkan differs — explicit synchronisation

The class set is where the API differences show:

| Class | Why it exists in Vulkan but not D3D11 |
|---|---|
| `CBarrierHelperVulkan` | Vulkan requires explicit pipeline/memory barriers |
| `CBarrierHelperEmpty` | the D3D11-equivalent no-op, kept for the shared abstraction |
| `CBufferBarrierTracker` | tracks which buffers need a barrier before next use |
| `CAsyncCompileHelperVulkan` | pipeline compilation is genuinely asynchronous in Vulkan |
| `CBLASVulkan`, `CBaseAccelerationStructureVulkan` | **ray tracing** — BLAS = bottom-level acceleration structure |
| `CAftermathVulkan`, `CAMDAntiLagVulkan` | vendor middleware, Vulkan variants |

The presence of `CBarrierHelperEmpty` *and* `CBarrierHelperVulkan` in the same
binary is informative: the abstraction base class is shared, and the empty helper
is the fallback used where a barrier is provably unnecessary (or in a null path).

`CBLASVulkan` + `CBaseAccelerationStructureVulkan` mean this backend supports
**hardware ray tracing**, which the D3D11 backend cannot (DXR requires D3D12). That
is a real capability difference between the two shipped backends, not just an API
translation.

## 4. Size comparison across the three backends

| Backend | Size on disk | `.pdata` | Merged functions |
|---|---|---|---|
| `rendersystemdx11` | 4,545,688 | 7,327 | 3,647 |
| `rendersystemvulkan` | 6,249,624 | 10,455 | 5,044 |
| `rendersystemempty` | 1,774,744 | 4,465 | 2,306 |

Vulkan is the largest, which fits the API: every object has explicit creation,
destruction and lifetime management that D3D11 handles through COM reference
counting. The null backend still reaches 2,306 functions, which is the cost of
satisfying a wide RHI (see `rendersystemempty.md`).

## 5. Unknowns

1. Both vtables not walked.
2. The 58 exports are not individually documented.
3. Which Vulkan version is targeted is not established from imports (it is
   runtime-resolved).
4. Whether ray tracing is enabled by default or gated on hardware support is not
   determined.
5. `CBufferBarrierTracker`'s tracking granularity is not reversed.
