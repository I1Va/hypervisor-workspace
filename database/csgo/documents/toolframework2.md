# `toolframework2.dll` — the editor/tool framework

Addresses are RVAs in `bin/win64/toolframework2.dll`,
`ImageBase = 0x180000000`.

## 1. Identity

| Property | Value |
|---|---|
| Size on disk | **13,708,952** bytes |
| `SizeOfImage` | 16,125,952 (`0xF61000`) |
| SHA256 | `index/manifest.json` |
| ImageBase | `0x180000000` |
| PDB | `...\toolframework2\_vpc_toolframework2\default\win64\_msvc_\Retail\toolframework2.pdb` |
| `.pdata` records | 28,070 |
| Merged functions | **15,443** |
| Exports | 6 (module ABI) |
| RTTI types | **3,542** |
| Imports | Qt5 (1,806 total), `tier0` 339, `KERNEL32` 107, `libfbxsdk` 57, `WS2_32` 13, `USER32` 11 |

### Imports make the classification unambiguous

| DLL | Symbols |
|---|---|
| `Qt5Widgets.dll` | 1,270 |
| `Qt5Core.dll` | 301 |
| `Qt5Gui.dll` | 235 |
| `libfbxsdk_2020_3_1.dll` | 57 |
| `WS2_32.dll` | 13 |
| `SHLWAPI.dll` | 1 |

**1,806 Qt symbols** and an FBX SDK link. This module is not part of the game
runtime; it is the framework every Valve authoring tool is built on. A running
copy of CS2 never loads it.

## 2. What it is

The shared base for the editor tools that ship alongside the game:
`resourcecompiler`, `assetpreview`, `physicsbuilder`, `vconcomm`, and the
`*_subtool` executables (`soundviewer_subtool`, `netgraph_subtool`,
`vprof_subtool`, `convarhelper_subtool`, `dashboard_subtool`).

It provides: the tool application shell, Qt widget plumbing, document/model
abstraction, and the bridge between a tool and the engine (which still needs
`tier0` and therefore the Source 2 runtime underneath).

## 3. Interface registered

`CreateInterface` export at `0x58f5b0`; stubs target thunk `0x58f590`. One:

| Interface | Stub RVA |
|---|---|
| `ToolFramework2_002` | `0x1eb5` |

Revision **002**, and the stub is unaligned / mid-`.text` — the same
late-registration pattern as `filesystem_stdio` and `panorama`.

## 4. RTTI overlap is shared headers, again

The first RTTI entries include `CAimConstraint`, `CAnimSkeleton`,
`CAuthClothChain`, `CAuthClothDataTable` — the same classes seen in
`animationsystem`, `meshsystem`, `vphysics2` and `physicsbuilder`. This is the
header-duplication pattern documented in `vphysics2.md` §3, at its most extreme:
3,542 type descriptors, most of which are types this module *uses* rather than
defines.

The one name that identifies the module specifically is
`CAdapter_ModelDocErrorHandler_As_ErrorListener` — the adapter that feeds model-
document errors into the framework's error listener. It appears in
`toolframework2`, `physicsbuilder` and `resourcecompiler` together, confirming all
three are tool-side consumers of one model-document layer.

## 5. The WS2_32 imports

13 socket imports in an editor framework means the tools support a **remote
connection** — the standard pattern is a tool connecting to a running game
(`-tools` launch mode, documented in `engine2.md` as a hashed command-line flag)
and editing live. That is how the Source 2 editor works.

## 6. Unknowns

1. `ToolFramework2_002` vtable not walked.
2. Whether the socket path is the live-edit link or something else is inferred from
   the `-tools` flag, not proven.
3. The document/model abstraction is not reversed.
4. The Qt widget set (which custom widgets exist) is not enumerated.
