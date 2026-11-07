# `helpsystem.dll` — in-game help and bindable commands

Addresses are RVAs in `bin/win64/helpsystem.dll`, `ImageBase = 0x180000000`.

## 1. Identity

| Property | Value |
|---|---|
| Size on disk | **755,864** bytes |
| `SizeOfImage` | 765,952 (`0xBB000`) |
| SHA256 | `index/manifest.json` |
| ImageBase | `0x180000000` |
| Entry point | `0x57ce8` |
| Timestamp | 1793662364 |
| PDB | `...\helpsystem\_vpc_helpsystem\default\win64\_msvc_\Retail\helpsystem.pdb` |
| `.pdata` records | 2,031 |
| Merged functions | **1,091** |
| Exports | 6 (module ABI) |
| RTTI types | 289 |

## 2. What it is

A larger module than its name suggests (1,091 functions), and the RTTI set shows
it is not just a help viewer — it owns the **bindable command** framework:

| Class | Role |
|---|---|
| `CHelpSystem` | the interface implementation |
| `CBaseBindableCommand`, `CBindableCommand` | a command that can be bound to a key |
| `CBaseBindTargetDescriptor`, `CBindableTargetDescriptorInstance` | what a bind targets |
| `CGlobalHotkeyCommands` | global hotkey registry |
| `CQHelpDisplayWidget`, `CQHelpEditorWidget`, `CQDynamicWidgetHelper` | Qt-based UI (note the `CQ` prefix, matching the Qt modules in the install) |
| `CBaseDynamicWidgetFactory` | widget construction |

`CGlobalHotkeyCommands` is the interesting one: global hotkeys are system-wide
keyboard hooks, which is a capability that matters beyond the game.

## 3. Interface registered

`CreateInterface` export at `0x42540`; stubs target thunk `0x42520`. One:

| Interface | Stub RVA |
|---|---|
| `HelpSystem_001` | `0x10b5` |

## 4. Tooling dependency

The `CQ*` classes are confirmed Qt by the import table — this module imports
`Qt5Widgets.dll` (1,063 symbols), `Qt5Gui.dll` (174) and `Qt5Core.dll` (249), plus
`USER32.dll` (5). That is **1,486 Qt imports**, more than every non-Qt import
combined.

Since Qt widgets appear in a *game* module, this DLL is part of the **tool**
surface (editor/help UI) rather than the runtime game loop — consistent with the
install shipping `vconsole2.exe`, `assetpreview` and other tools alongside the
game. It will not be loaded during normal play.

## 5. Unknowns

1. `HelpSystem_001` vtable not walked.
2. **Global key polling**: USER32 is imported for exactly five functions —
   `GetAsyncKeyState`, `GetCursorPos`, `SetCursorPos`, `GetActiveWindow`,
   `GetSystemMetrics`. `GetAsyncKeyState` reads key state **system-wide, regardless
   of focus**, which is the primitive behind global hotkeys. This is not
   `RegisterHotKey` (which needs a window and message loop); it is polling, so it
   works while another application is focused. What consumes it is not traced.
3. The bind-target descriptor layout is not reversed.
