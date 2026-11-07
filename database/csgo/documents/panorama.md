# `panorama.dll` — the Panorama UI engine

Addresses are RVAs in `bin/win64/panorama.dll`, `ImageBase = 0x180000000`.

## 1. Identity

| Property | Value |
|---|---|
| Size on disk | **6,108,312** bytes |
| `SizeOfImage` | 6,488,064 (`0x62F000`) |
| SHA256 | `index/manifest.json` |
| ImageBase | `0x180000000` |
| PDB | `...\panorama\_vpc_panorama\default\win64\_msvc_\Retail\panorama.pdb` |
| `.pdata` records | 17,349 |
| Merged functions | **9,601** |
| Exports | 7 |
| RTTI types | 498 |

### Imports

| DLL | Symbols | Note |
|---|---|---|
| `tier0.dll` | 287 | |
| `KERNEL32.dll` | 122 | |
| **`v8.dll`** | **96** | JavaScript |
| **`SDL3.dll`** | **31** | windowing and input |
| `USER32.dll` | 10 | |
| `WS2_32.dll` | 6 | sockets |
| `steam_api64.dll` | 5 | |
| `video64.dll` | 5 | video in UI |
| `WINMM.dll` | 2 | timers |

The `SDL3` dependency is the significant one: Panorama gets its window and input
events from SDL3 rather than from Win32 directly. That is why the same UI code can
also run on other platforms, and it means input reaching Panorama passes through
SDL3 first (relevant given `inputsystem.dll` also exists — the two are separate
paths).

## 2. What it is

Panorama is Source 2's UI system: HTML/CSS-like markup, styled with CSS-like
declarations, scripted in JavaScript, rendered by the engine. It replaced VGUI
(vgui2 is legacy).

`panoramauiclient.dll` is the *client* bindings half; this module is the engine:
layout, styling, animation, and the JS integration core.

Note the `WS2_32` import: even the UI engine has sockets. Combined with
`CContentSourceMap`, this is consistent with Panorama's **developer/debug** mode
serving UI content remotely.

## 3. Notable classes

| Class | Role |
|---|---|
| `CContentSourceMap` | maps a UI "content source" — this is how UI content can come from disk *or* a remote/debug source |
| `CDebuggerInputHandler`, `CDebuggerInputHandler` | a **JS debugger** input path |
| `CDragStartCallbacks` | drag-and-drop |
| `CChunkAllocator` | arena allocation for UI objects |
| `CCallbackBase` | V8 callback binding base |

`CDebuggerInputHandler` plus `CContentSourceMap` together mean the shipped game
contains a working **JavaScript debugger interface** for UI development. It is not
a stub: there is an input handler for it.

## 4. Interface registered

`CreateInterface` export at `0x3dbd80`; stubs target thunk `0x3dbd60`. One:

| Interface | Stub RVA |
|---|---|
| `PanoramaUIEngine001` | `0x48d85` |

Like `filesystem_stdio`, this stub is unaligned and far into `.text`
(`0x48d85`), not in the low-address bootstrap block — the same late-registration
pattern.

## 5. Why 9,601 functions

A UI engine is deceptively large: a CSS cascade and layout solver (flexbox-like
positioning, text flow, styling inheritance), an animation/tween system, a render
command buffer that feeds `scenesystem`, event routing, and the V8 binding layer.
Panorama implements all of it in-process.

## 6. Unknowns

1. `PanoramaUIEngine001` vtable not walked.
2. Whether the JS debugger is reachable in shipping builds or gated behind a launch
   flag is not established — this is the most security-relevant question about the
   module.
3. `CContentSourceMap`'s remote source mechanism is not reversed (the WS2_32
   imports suggest it, but the protocol is not identified).
4. The CSS-like language's supported subset is not enumerated.
