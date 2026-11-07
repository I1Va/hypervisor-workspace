# `resourcesystem.dll` — resource manifest and compilation runtime

Addresses are RVAs in `bin/win64/resourcesystem.dll`, `ImageBase = 0x180000000`.

## 1. Identity

| Property | Value |
|---|---|
| Size on disk | **532,632** bytes |
| `SizeOfImage` | 614,400 (`0x96000`) |
| SHA256 | `index/manifest.json` |
| ImageBase | `0x180000000` |
| Entry point | `0x484d0` |
| Timestamp | 1793662327 |
| PDB | `...\resourcesystem\_vpc_resourcesystem\default\win64\_msvc_\Retail\resourcesystem.pdb` |
| `.pdata` records | 1,864 |
| Merged functions | **856** |
| Exports | 6 (module ABI) |
| Imports | 3 DLLs, 196 symbols |

## 2. What it is

Owns the **resource manifest**: the list of compiled resources a module ships, and
the runtime that serves and asynchronously loads them.

| Class | Role |
|---|---|
| `CCodeResourceManifestManager` | the compiled-in manifest of code resources |
| `CAsyncResourceDataRequest` | asynchronous load request |
| `CKV3Arena`, `CKV3ResourceBlockHelper` | KV3 resource storage |
| `CKV3TransferContextBase` | (shared with `schemasystem`) |

`CAsyncResourceDataRequest` is the key class: resources load **asynchronously**,
so a request object tracks a load in flight rather than blocking.

## 3. Interfaces registered

`CreateInterface` export at `0x46f40`; stubs target thunk `0x46f20`. One:

| Interface | Stub RVA |
|---|---|
| `ResourceSystem013` | `0x13b5` |

The `013` suffix is the highest minor revision seen in this corpus (most
interfaces are `001`–`003`), which marks the resource system as the most frequently
revised interface in the engine.

## 4. Connection to the module ABI

Two of the six standard exports — `GetResourceManifestCount` and
`GetResourceManifests` — exist precisely so this system can enumerate what each
module ships. 24 of the 34 Valve modules export exactly these six; this module
consumes them. That
is the mechanism by which the engine discovers resources without a central
registry file.

## 5. Unknowns

1. `ResourceSystem013` vtable not walked.
2. The manifest data format is not reversed.
3. How `GetResourceManifests` output is keyed (by hash, path, or type) is not
   established.
4. The async completion/callback path is not traced.
5. `resourcecompiler.dll` (56 MB, the largest module) is the build-time
   counterpart and is not yet documented; the relationship between the two is
   therefore not established.
