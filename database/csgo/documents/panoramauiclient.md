# `panoramauiclient.dll` — Panorama's JavaScript/browser bindings

Addresses are RVAs in `bin/win64/panoramauiclient.dll`,
`ImageBase = 0x180000000`.

## 1. Identity

| Property | Value |
|---|---|
| Size on disk | **2,748,056** bytes |
| `SizeOfImage` | 2,850,816 (`0x2B8000`) |
| SHA256 | `index/manifest.json` |
| ImageBase | `0x180000000` |
| PDB | `...\panoramauiclient\_vpc_panoramauiclient\default\win64\_msvc_\Retail\panoramauiclient.pdb` |
| `.pdata` records | 10,241 |
| Merged functions | **5,976** |
| Exports | 6 (module ABI) |

### Imports

| DLL | Symbols | Note |
|---|---|---|
| `tier0.dll` | 206 | |
| `KERNEL32.dll` | 88 | |
| **`v8.dll`** | **47** | the JavaScript engine |
| `steam_api64.dll` | 7 | |
| `video64.dll` | 2 | video playback in UI |

`v8.dll` is the finding: Panorama UI is HTML/CSS-like, and this module binds the
V8 JavaScript engine into it. 5,976 functions for a client-side UI module is
consistent with V8 glue — every DOM-like object and every exposed game API needs a
V8 template.

## 2. What it is

The **client half** of Panorama: it exposes game state and calls into JavaScript,
and takes calls back. `panorama.dll` (6.1 MB, not yet documented) is the UI engine
itself; this module is the bridge.

RTTI is sparse (the `rtti` index has no dedicated file for this module, so the
class extraction found none) — V8 bindings are largely template-generated and do
not leave MSVC RTTI descriptors, which explains the absence.

## 3. Interface registered

`CreateInterface` export at `0x1ab300`; stubs target thunk `0x1ab2e0`. One:

| Interface | Stub RVA |
|---|---|
| `PanoramaUIClient001` | `0x1315` |

## 4. Why this matters for the corpus

Panorama + V8 means the game runs a **full JavaScript engine** in-process for its
UI. `v8.dll` in this install is 48 MB and is **V8 11.9.169.6** (Chrome 119-era), so
the UI's JavaScript feature set is pinned to that release. Any UI panel is
potentially scripted code, and the JS heap is a large, dynamic region of the
process — relevant when reasoning about what a process-scanning detector sees.

`video64.dll` being imported here (2 symbols) means UI can embed video, closing the
chain to `video64.md`'s FFmpeg/RTMP stack.

## 5. Unknowns

1. `PanoramaUIClient001` vtable not walked.
2. Which game APIs are exposed to JavaScript, and with what capability, is not
   enumerated — this is the security-relevant surface of the module.
3. **V8 version is 11.9.169.6** — recovered from `v8.dll`'s embedded version
   strings. That pins the JavaScript feature set to Chrome 119-era.
4. Whether JS runs sandboxed or with full process privileges is not determined.
