# `materialsystem2.dll` — materials, text layout and post-processing

Addresses are RVAs in `bin/win64/materialsystem2.dll`, `ImageBase = 0x180000000`.

## 1. Identity

| Property | Value |
|---|---|
| Size on disk | **1,428,632** bytes |
| `SizeOfImage` | 1,597,440 (`0x186000`) |
| SHA256 | `index/manifest.json` |
| ImageBase | `0x180000000` |
| Entry point | `0xdc438` |
| Timestamp | 1793662330 |
| PDB | `...\materialsystem2\_vpc_materialsystem2\default\win64\_msvc_\Retail\materialsystem2.pdb` |
| `.pdata` records | 4,121 |
| Merged functions | **1,941** |
| Exports | 6 (module ABI) |
| RTTI types | 119 |

## 2. Interfaces registered — five

`CreateInterface` export at `0x990e0`; stubs target thunk `0x990c0`.

| Interface | Stub RVA | Role |
|---|---|---|
| `VMaterialSystem2_001` | `0x24b5` | materials and shaders |
| `FontManager_001` | `0x2fc5` | font loading and glyph data |
| `TextLayout_001` | `0x3345` | text shaping and layout |
| `PostProcessingSystem_001` | `0x3155` | post-processing stack |
| `MaterialUtils_001` | `0x3505` | helpers |

Five interfaces is high for a module this size, and the set is thematically mixed:
**materials**, **text rendering**, and **post-processing** in one DLL. That is a
real structural observation — these three are grouped because they share the same
GPU resource and shader infrastructure, not because they are one concern.

`TextLayout_001` next to `FontManager_001` means text shaping (line breaking,
glyph placement) is a first-class engine service here, not something each UI layer
does itself. `panorama` consumes these rather than implementing its own text.

## 3. Notable classes

| Class | Role |
|---|---|
| `CBaseQueuedRenderable` | a renderable queued for submission |
| `CCompileTargetExprOpCodeHandler`, `CCompileTargetExprStackMachineBuilder` | shader-target expression evaluation, shared with the render backends |
| `CBaseIntrospectedToKV3TypeManager` | KV3 type conversion |
| `CAllocatorUtils`, `CDeallocatorUtils` | allocation helpers |

## 4. Unknowns

1. All five vtables not walked.
2. The material/shader cache format is not reversed.
3. Post-processing pass ordering is not established.
4. Whether `TextLayout_001` implements the shaping itself or wraps
   `panorama_text_pango`/`harfbuzz` is not determined — `panorama_text_pango.dll`
   exists in the install, which suggests wrapping, but the link is not traced.
