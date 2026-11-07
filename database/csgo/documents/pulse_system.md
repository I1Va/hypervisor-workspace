# `pulse_system.dll` — the Pulse scripting graph

Addresses are RVAs in `bin/win64/pulse_system.dll`, `ImageBase = 0x180000000`.

## 1. Identity

| Property | Value |
|---|---|
| Size on disk | **2,032,792** bytes |
| `SizeOfImage` | 2,588,672 (`0x278000`) |
| SHA256 | `index/manifest.json` |
| ImageBase | `0x180000000` |
| Entry point | `0x101f60` |
| PDB | `...\pulse_system\_vpc_pulse_system\default\win64\_msvc_\Retail\pulse_system.pdb` |
| `.pdata` records | 6,354 |
| Merged functions | **3,949** |
| Exports | 6 (module ABI) |
| Imports | `tier0` 166, `KERNEL32` 73 |

## 2. What it is

Pulse is Source 2's **visual scripting / logic graph** system — the successor to
Source 1's entity I/O logic. It ships a full expression language:

| Class | Role |
|---|---|
| `CBasePulseGraphInstance` | an instantiated graph |
| `CGenericExpr_IntLiteral`, `..._FloatLiteral`, `..._BoolLiteral` | literals |
| `CGenericExpr_Binary`, `CGenericExpr_FunctionCall` | operators and calls |
| `CGenericExprPart` | expression node base |
| `IPulseSystem_001` | the interface |

11 `CGenericExpr*` classes in total. This is a real expression evaluator — parse,
then evaluate — not a fixed set of logic opcodes.

## 3. Interface registered

`CreateInterface` export at `0xfdef0`; stubs target thunk `0xfded0`. One:

| Interface | Stub RVA |
|---|---|
| `IPulseSystem_001` | `0x1315` |

The `I` prefix is unusual — most Source 2 interfaces are named without it. It
marks Pulse as a newer subsystem added after the naming convention settled.

## 4. Design note

The expression classes being `CGenericExpr_*` rather than type-specific means the
evaluator is generic over value types, resolved at evaluation time. Combined with
`CBasePulseGraphInstance`, the shape is: a graph is instantiated, expressions are
parsed into a node tree, and evaluation walks the tree.

## 5. Unknowns

1. `IPulseSystem_001` vtable not walked.
2. The graph serialisation format is not reversed.
3. How Pulse binds to game entities (the connection to `CGameEntitySystem`) is not
   traced, though `client.md` documents Pulse-adjacent graph controllers.
4. The remaining expression node types beyond the 11 named are not enumerated.
