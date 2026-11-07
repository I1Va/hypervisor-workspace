# `inputsystem.dll` — input device handling

Addresses are RVAs in `bin/win64/inputsystem.dll`, `ImageBase = 0x180000000`.

## 1. Identity

| Property | Value |
|---|---|
| Size on disk | **302,232** bytes |
| `SizeOfImage` | 339,968 (`0x53000`) |
| SHA256 | `index/manifest.json` |
| ImageBase | `0x180000000` |
| Entry point | `0x207a8` |
| Timestamp | 1793662277 |
| PDB | `...\inputsystem\_vpc_inputsystem\default\win64\_msvc_\Retail\inputsystem.pdb` |
| `.pdata` records | 849 |
| Merged functions | **398** |
| Exports | 6 (module ABI) |
| Imports | `USER32` 29, `ADVAPI32` 1, `IMM32` 1, `tier0` 101, `KERNEL32` 73 |

The `IMM32` import is the Input Method Editor (IME) API, and `USER32` supplies raw
input and window messages. Both fit an input module.

## 2. What it is

The input layer: it translates Windows input messages (keyboard, mouse, joystick)
into Source 2 input events, and owns the input stack that other systems push/pop
(for UI focus, console, game).

Two classes carry this:

| Class | Role |
|---|---|
| `CInputSystem` | the device layer — raw input, joystick, cursor |
| `CInputStackSystem` | the *stack* — contexts that can capture or swallow input |

`CUtlSymbol` is the symbol-table type used for binding names (every keybind is
resolved through it), and `CPostConnectCallback` / `CSchemaInstallCallback` are the
standard module lifecycle callbacks every Valve module provides.

## 3. Interfaces registered

`CreateInterface` export at `0x16f00`; stubs target the thunk `0x16ee0`. Two:

| Interface | Stub RVA |
|---|---|
| `InputStackSystemVersion001` | `0x10e5` |
| `InputSystemVersion001` | `0x1425` |

The two-interface split mirrors the two classes exactly: `InputSystemVersion001`
is the device/event surface, `InputStackSystemVersion001` is the stack that
decides which consumer receives an event.

## 4. ConVars (6 recovered)

| cvar | RVA | Help |
|---|---|---|
| `cl_cursor_scale` | `0x11c0` | Cursor size scaling factor. |
| `cl_auto_cursor_scale` | `0x1280` | Automatic cursor size scaling. |
| `cl_input_enable_raw_keyboard` | `0x1340` | Enable raw keyboard input |
| `cl_joystick_enabled` | `0x1430` | Enable joystick input |
| `joy_axisbutton_threshold` | `0x14e0` | Analog axis range before a button press is registered. |
| `key_updatelayout` | `0x1590` | Updates game keyboard layout to current windows keyboard setting. |

`key_updatelayout` is the notable one: it is a **command**, not a setting — it
re-reads the Windows keyboard layout, which is why it appears with a help string
and no default value.

## 5. Unknowns

1. `InputSystemVersion001` vtable not walked.
2. Raw-input registration (`RegisterRawInputDevices`) not located explicitly; it
   is present in `USER32`'s import list but the call site is not identified.
3. Controller/gamepad support beyond `cl_joystick_enabled` is not mapped
   (`XInput` does not appear in the import table, so gamepads are either
   `HID`-level or handled in another module).
4. The input event struct layout is not reversed.
    