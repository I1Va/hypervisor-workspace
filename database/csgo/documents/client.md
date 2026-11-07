# `client.dll` — Counter-Strike 2 client game module

Reverse-engineering notes. Every claim below is tied to a file offset or RVA in
`/tmp/opencode/csgo/csgo/bin/win64/client.dll`. RVAs are relative to
`ImageBase = 0x180000000`, matching the `.asm` dumps in `docs/client/`.
Where the evidence was insufficient, the text says so explicitly rather than
guessing.

Companion artefacts produced while writing this document (all in
`/tmp/opencode/csgo-analysis/`):

| file | contents |
|---|---|
| `iface_table.json` | 115 interface table rows (name RVA, factory thunk RVA) |
| `rtti_vtables.json` | 4,935 classes → 6,851 vtables → slot RVAs |
| `methods.json` | same, but slots restricted to real function entry points, with sizes |
| `cvars_all.json` | 1,695 unique ConVars + 321 ConCommands with help text |
| `strxref.json` | 27,194 functions with resolved string literals |
| `fdis.py` | annotated disassembler used for every listing in this document |
| `xref2.py` | RIP-relative xref sweeper that also finds leaf functions |

---

## 1. Identity

### 1.1 Hashes and headers

| property | value |
|---|---|
| path | `csgo/bin/win64/client.dll` |
| size | 39,227,544 bytes |
| SHA-256 | `9279421852772522121be2f13409dd37436e8c809ff48898c8c3d41b09e77844` |
| machine | `0x8664` (x86-64) |
| subsystem | 2 (`IMAGE_SUBSYSTEM_WINDOWS_GUI`) |
| image base | `0x180000000` |
| `SizeOfImage` | `0x29A3000` = 43,659,264 bytes |
| PE timestamp | `1793836250` → 2026-11-04 (UTC) |
| checksum | `0x0256CDA1`, present and valid |
| DLL characteristics | `0x160` — `HIGH_ENTROPY_VA`, `DYNAMIC_BASE`, `NX_COMPAT`; **no** `GUARD_CF` |
| Authenticode | **not signed** |
| entry point RVA | `0x19FF280` |

`ASLR` is on, `CFG` (`/guard:cf`) is off. No `IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT`
and no delay-load table.

### 1.2 PDB path

```
C:\buildworker\csgo_rel_win64\build\_build_\game\client\_vpc_client_csgo\unity\win64\_msvc_\Retail\client.pdb
```

The internal build root `C:\buildworker\csgo_rel_win64\build\src\...` is embedded
in 229 distinct `__FILE__` literals across the image (see `srcpaths.json`). That
is what makes per-function attribution possible in section 6 — every subsystem
name in this document that is not derived from RTTI comes from such a literal.

### 1.3 Sections

| name | RVA | vsize | raw size | entropy |
|---|---|---|---|---|
| `.text` | `0x1000` | `0x1AAF2E0` (27,980,512) | `0x1AAF400` | 6.58 |
| `.rdata` | `0x1AB1000` | `0x7117E2` (7,411,682) | `0x711800` | 5.51 |
| `.data` | `0x21C3000` | `0x5E4C2C` (6,179,884) | `0x1AB200` | 4.48 |
| `.pdata` | `0x27A8000` | `0x178260` (1,540,704) | `0x178400` | 7.00 |
| `.reloc` | `0x2921000` | `0x81CEC` (531,692) | `0x81E00` | 5.47 |

`.data` has a 6.18 MB virtual size against a 1.75 MB raw size — 4.4 MB of BSS.
`.pdata` is the x64 exception directory; it holds **128,392**
`RUNTIME_FUNCTION` records, which is the function census quoted in the task
brief. Note that `.pdata` only lists functions that need unwind data: exported
leaf thunks such as `CreateInterface` and the interface factory stubs are *not*
in it. Section 2 depends on that detail.

`.text` at 26.7 MB is ~71 % of the image; this is a single unity build
(`_vpc_client_csgo\unity`) that statically links tier0, tier1, tier2, vpk, the
panorama engine, protobuf, v8 bindings, embree wrappers and the entire
`econ_csgo_legacy` item schema.

### 1.4 Exports

Six, all in `.rdata`'s export directory at RVA `0x21B84F0`:

| RVA | name |
|---|---|
| `0x0C33140` | `BinaryProperties_GetValue` |
| `0x19D0FF0` | `CreateInterface` |
| `0x0C33940` | `ExtractModuleMetadata` |
| `0x19DC960` | `GetResourceManifestCount` |
| `0x19DC970` | `GetResourceManifests` |
| `0x19DE760` | `InstallSchemaBindings` |

**`BinaryProperties_GetValue`** (`0xC33140`, 8-way jump table at `0xC331D0`,
~140 bytes). Selector in `ecx`, output struct pointer in `rdx`. Returns 1 on
success, 0 for `ecx == 7`. Cases 0–6 write a `{ptr, kind}` pair:

| `ecx` | target | writes |
|---|---|---|
| 0 | `0xC33160` | `{"Release", 0}` — string at `0x1C87C80` |
| 1 | `0xC3318E` | `{0, 1}` |
| 2 | `0xC331A2` | `{1, 1}` |
| 3 | `0xC33177` | `{"client", 0}` — string at `0x1B0E990` |
| 4 | `0xC3318E` | `{0, 1}` (same as 1) |
| 5 | `0xC331A2` | `{1, 1}` (same as 2) |
| 6 | `0xC331B6` | `{2, 1}` |
| 7 | `0xC331CA` | returns 0 |

The `kind` field at `[rdx+8]` distinguishes "string" (0) from "integer" (1).

**`ExtractModuleMetadata`** (`0xC33940`, 24-byte `.pdata` function at
`0xC33940`–`0xC33958`). Reads the TLS slot index from `0x27A3B60`, indexes the
thread block, and compares three dwords at
`0x27A3354` / `0x27A3358` / `0x27A335C` against the thread's current tick. If
none of them is smaller it returns the address of a static metadata struct
(`lea rax, [rip+0x1942144]` at `0xC3399D`); otherwise it falls through to a
per-thread allocation path. This is a cached, thread-local metadata record with
a generation counter.

**`GetResourceManifestCount`** (`0x19DC960`, 11 bytes): `mov eax, [0x27A2F28]; ret`.
Plain global getter.

**`GetResourceManifests`** (`0x19DC970`, ~180 bytes). Walks a singly-linked list
rooted at `0x27A2F20`; each node is `{next, cached_ptr, factory_fn}`. On first
visit it calls `factory_fn()` and memoises the result in `node+8`. Copies up to
`r8` pointers into the caller's array `rdx` starting at index `ecx`, returns the
count written. This is the resource-manifest enumeration used by
`resourcesystem` during mount.

**`InstallSchemaBindings`** (`0x19DE760`, 75 bytes) — see §3.4.

---

## 2. The interface table

### 2.1 `CreateInterface` — the dispatcher

`CreateInterface` at `0x19D0FF0` is a **36-byte leaf function with no `.pdata`
entry**, which is why the `.pdata`-based function map misses it. Full body:

```asm
19d0ff0  mov  r9,  [rip+0xDD1D01]     ; r9 = g_pInterfaceList   (0x27A2CF8)
19d0ff7  mov  r10, rdx                ; r10 = pReturnCode
19d0ffa  mov  r11, rcx                ; r11 = pName
19d0ffd  test r9, r9
19d1000  je   19d1030                 ; empty list -> not found
19d1002  mov  rax, [r9+8]              ; rax = node->pszName
19d1006  mov  r8, r11
19d1009  sub  r8, rax                 ; r8 = pName - node->pszName
19d1010  movzx edx, byte ptr [rax]        ; strcmp loop, byte at a time
19d1013  movzx ecx, byte ptr [rax+r8]
19d1018  sub  edx, ecx
19d101a  jne  19d1023
19d101c  inc  rax
19d101f  test ecx, ecx
19d1021  jne  19d1010
19d1023  test edx, edx
19d1025  je   19d103f                 ; match
19d1027  mov  r9, [r9+0x10]           ; r9 = node->next
19d102b  test r9, r9
19d102e  jne  19d1002
19d1030  test r10, r10
19d1033  je   19d103c
19d1035  mov  dword ptr [r10], 1      ; IFACE_FAILED
19d103c  xor  eax, eax
19d103e  ret
19d103f  test r10, r10
19d1042  je   19d104b
19d1044  mov  dword ptr [r10], 0      ; IFACE_OK
19d104b  jmp  qword ptr [r9]          ; tail-call node->factory
```

So the registered node is a 24-byte record:

```
+0x00  void* (*factory)(void)     ; "CreateInterfaceInternal" thunk
+0x08  const char* pszName        ; "Source2Client002"
+0x10  Node* pNext                ; singly linked, head-inserted
```

and the list head is the global at `0x27A2CF8`. Lookup is a linear walk with an
inline byte-wise `strcmp`; there is no hash, no binary search, and the compare is
**case sensitive**. `pReturnCode` may be null.

The companion helper at `0x19D0FD0` is the registrar:

```asm
19d0fd0  mov  [rcx+8], r8       ; node->pszName
19d0fd4  mov  [rcx], rdx        ; node->factory
19d0fd7  mov  rax, [0x27A2CF8]  ; old head
19d0fde  mov  [rcx+0x10], rax   ; node->next = old head
19d0fe2  mov  rax, rcx
19d0fe5  mov  [0x27A2CF8], rcx  ; head = node
19d0fec  ret
```

It takes `rcx` = pre-allocated node, `rdx` = factory, `r8` = name. Registration
order is therefore reverse of list order, and duplicate names are *not*
rejected — the first match walking from the newest registration wins.

The third helper, `0x19D0F80` (56 bytes, has `.pdata`), is the "connect"
notification: it guards on `g_pEngineToClient` (`0x27A2008`) being non-null and
a one-shot flag at `0x27A2CF0`, stores its argument at `0x27A2CE8`, then calls
`0x19CD060` and tail-jumps to `0x19B2AA0`. `0x19D0FC0` clears the flag. Ten call
sites exist (`0x78FE20`, `0x9EC44E`, `0x9EC47C`, `0xB59160`, `0xB736FF`,
`0xBDDE65`, `0xD5910F`, …), all inside client init paths.

### 2.2 The registration thunk pattern

Every self-registered interface is emitted as a 5-instruction stub:

```asm
cd440  lea r8,  [rip+0x1B97489]   ; "Source2Client002"
cd447  lea rdx, [rip+0xAB9A92]    ; factory thunk  -> 0x0B86EE0
cd44e  lea rcx, [rip+0x24976AB]   ; static node    -> 0x2564B00
cd455  jmp 0x19D0FD0              ; register
cd45a  int3
```

and the factory thunk is a one-line "return the singleton":

```asm
b86ee0  lea rax, [rip+0x19DD739]  ; -> 0x2564620 (the object)
b86ee7  ret
```

Note the indirection: the factory returns a pointer *slot*, not the object.
`0x2564620` is in `.data`'s BSS region and holds the actual `CSource2Client*`
once constructed. This means the interface object is created lazily by the
engine's init path (`CSource2Client::Connect`, §2.4), and
`CreateInterface("Source2Client002")` before that point returns a slot holding
zero.

A scanner over all `jmp 0x19D0FD0` sites finds exactly **nine** such stubs in
this module:

| stub RVA | interface name | factory thunk | node RVA | object slot |
|---|---|---|---|---|
| `0x082A75` | `Source2ClientConfig001` | `0x7738C0` | `0x24C11A0` | `0x24C1160` |
| `0x08EDA5` | `EmptyWorldService001_Client` | `0x79C760` | `0x24C3D58` | `0x221C160` |
| `0x0CD3F5` | `ClientBugBugServic001_Client` | `0xB86EB0` | `0x2564B98` | `0x2238760` |
| `0x0CD415` | `ClientToolsInfo_001` | `0xB86EC0` | `0x2564B78` | `0x2238730` |
| `0x0CD435` | `GameClientExports001` | `0xB86ED0` | `0x25645D8` | `0x22353D8` |
| `0x0CD455` | `Source2Client002` | `0xB86EE0` | `0x2564B00` | `0x2564620` |
| `0x0D9B55` | `Source2ClientPrediction001` | `0xBF8C60` | `0x256A9D0` | `0x256A850` |
| `0x0EBF65` | `Source2ClientUI001` | `0xD12910` | `0x2581650` | `0x2243900` |
| `0x0F75F5` | `LegacyGameUI001` | `0xD5D990` | `0x25CB4D0` | `0x2245180` |

`Source2ClientConfig001` is registered from `0x82A60` — inside a function at
`0x82A50`–`0x82A7A` that is a bare stub, adjacent to `0x82A50 jmp 0xBA3AD0`.
The `EmptyWorldService001_Client` registration at `0x8EDA5` sits immediately
after `0x8ED90`'s function epilogue (`add rsp,0x38; ret`), i.e. it is a separate
one-shot stub in the same translation unit.

The two `ClientBugBugServic001_Client`/`LegacyGameUI001` names contain the
misspelling `Servic001` — that is the literal in the binary
(string at `0x1C63940` and `0x1C694D0` respectively), not a transcription error.

### 2.3 The full registered table

`CreateInterface` only knows about the nine self-registered names above. The
**115-entry table** at `0x1E618E0` in `.rdata` is a different thing: it is the
engine's *interface catalogue* — a flat array of 16-byte rows
`{const char* name; void** cache_slot}`, where `cache_slot` is a pointer into
`.data` (range `0x27A2000`–`0x27A23FF`) that receives the resolved interface
pointer.

Its structure is confirmed by the consumer at `0x19B0F90`:

```asm
19b0f90  lea rax, [rip+0x4B0949]   ; -> 0x1E618E0
19b0f97  test rcx, rcx
19b0f9a  je   19b0fa2
19b0f9c  mov  dword ptr [rcx], 0x73   ; 115 decimal
19b0fa2  ret
```

and by `0x19B0FB0`, which sorts the table with `V_qsort_s` (`0x19B1058`) into a
name-keyed index and writes the count to `0x27A23B0`, the array base to
`0x27A23A8`, and a "dirty" flag to `0x27A23C4`.

The slots are populated during `CSource2Client::Connect` (`0xB667D0`). A scan of
all writes to the `0x27A2000`–`0x27A2400` range finds 22 direct stores, of which
these are the interface caches:

| store RVA | cache slot | interface |
|---|---|---|
| `0xB66886` | `0x27A2298` | copy of `Source2EngineToClient001` slot |
| `0xB66ACC` | `0x27A21E8` | `VMediaFoundation001` |
| `0xB66ADE` | `0x27A21F0` | `VAvi001` |
| `0xB66B2E` | `0x27A2208` | `NetworkSystemVersion001` |
| `0xB66B4A` | `0x27A2220` | `SerializedEntitiesVersion001` |
| `0xB66B66` | `0x27A2218` | `FlattenedSerializersVersion001` |
| `0xB66B82` | `0x27A2210` | `NetworkMessagesVersion001` |
| `0xB66BE6` | `0x27A2150` | `IMEManager001` |
| `0xB66C22` | `0x27A21D8` | `VScriptManager010` |

The remaining stores at `0x19B0F6E`/`0x19B0F78`/`0x19B105E`/`0x19B1064`/
`0x19B1092`/`0x19B109C`/`0x19B10CD`/`0x19B10D3`/`0x19B11CF`/`0x19B1294`/
`0x19B12F9` maintain the sorted index (`0x27A23A8`, `0x27A23B0`, `0x27A23C0`,
`0x27A23C4`), not interface pointers.

All 115 entries, in table order:

```
VApplication001                  VEngineCvar007
VStringTokenSystem001            TestScriptMgr001
VProcessUtils002                 VFileSystem017
VAsyncFileSystem2_001            ResourceSystem013
ResourceManifestRegistry001      ResourceHandleUtils001
SchemaSystem_001                 ResourceCompilerSystem001
VMaterialSystem2_001             PostProcessingSystem_001
InputSystemVersion001            InputStackSystemVersion001
RenderDeviceMgr001               RenderUtils_001
SoundSystem001                   SoundOpSystemEdit001
SoundOpSystem001                 SteamAudio001
VP4003                           Localize_001
VMediaFoundation001              VAvi001
VWebm001                         VBik001
MeshSystem001                    MeshUtils001
RenderDevice003                  VRenderDeviceSetupV001
RenderHardwareConfig002          SceneSystem_002
IPulseSystem_001                 SceneUtils_001
WorldRendererMgr001              AssetSystem001
AssetSystemTest001               ParticleSystemMgr003
VScriptManager010                PropertyEditorSystem_001
MATCHFRAMEWORK_001               Source2V8System001
PanoramaUIEngine001              PanoramaUIClient001
PanoramaTextServices001          ToolFramework2_002
PhysicsBuilderMgr001             VisBuilder_001
BakedLODBuilderMgr001            HelpSystem_001
ToolSceneNodeFactory_001         EconItemToolModel_001
SchemaTestExternal_Two_001       SchemaTestExternal_One_001
AnimationSystem_001              AnimationSystemUtils_001
HammerMapLoader001               MaterialUtils_001
FontManager_001                  TextLayout_001
AssetPreviewSystem_001           AssetBrowserSystem_001
AssetRenameSystem_001            VConComm001
MODEL_PROCESSING_SERVICES_INTERFACE_001
NetworkSystemVersion001          NetworkMessagesVersion001
FlattenedSerializersVersion001   SerializedEntitiesVersion001
DemoUpconverterVersion001        Source2Client002
Source2ClientUI001               Source2ClientPrediction001
Source2Server001                 Source2Host001
Source2ModTools001               Source2GameClients001
Source2GameEntities001           EngineServiceMgr001
HostStateMgr001                  NetworkService_001
NetworkClientService_001         NetworkP2PService_001
NetworkServerService_001         ToolService_001
RenderService_001                StatsService_001
VProfService_001                 InputService_001
MapListService_001               GameUIService_001
SoundService_001                 BenchmarkService001
KeyValueCache001                 ClientServerSharedHandleSystem001
GameResourceServiceClientV001    GameResourceServiceServerV001
Source2EngineToClient001         Source2EngineToServer001
Source2EngineToServerStringTable001  Source2EngineToClientStringTable001
VPhysics2_Interface_001          ModelDocUtils001
SmartPropsSystem_001             AnimGraphEditorUtils001
EXPORTSYSTEM_INTERFACE_VERSION_001   ServerToolsInfo_001
ClientToolsInfo_001              Vrad3_001
NavSystem001                     NavGameTest001
LocalServerClientAccess001       ClientLocalServerAccess001
```

That is 115 names; the array starts at `0x1E618E0` and the last row
(`ClientLocalServerAccess001`) is at `0x1E62000`. The three entries at
`0x1E61D60`, `0x1E61D70`, `0x1E61D80` — `Source2Client002`,
`Source2ClientUI001`, `Source2ClientPrediction001` — are the client's own three
primary interfaces, contiguous in the table.

Cross-check against `ifaces/client.txt` (131 lines): the file's extra 55 names
are names that appear as *strings* somewhere in the image but are not rows of
this table — either Steam interfaces resolved through `SteamInternal_FindOrCreateUserInterface`
(`SteamClient023`, `SteamUser023`, `SteamFriends017`, `SteamNetworkingSockets012`,
…), strings in the `econ_csgo_legacy` item schema (`CWeaponHKP2000`, `C_WeaponM249`),
or crypto/utility constants (`CAMELLIA128`, `SystemFunction036`, `ClampTo180`).
The table has 38 names *not* in that file (`SchemaSystem_001`,
`PanoramaUIEngine001`, `MATCHFRAMEWORK_001`, the `*Service_001` family, …) — so
`ifaces/client.txt` is a superset of strings, not of registered interfaces.
**The authoritative count of interfaces this module advertises is 115.**

### 2.4 The interface *consumer* side

`CSource2Client` (RTTI at `0x1F1A7D0`, vtable `0x1C68230`, 211 slots) is the
object those interfaces are handed to. Its constructor is `0xB5DB60`
(1,577 bytes, `[0xB5DB60-0xB5E189]`), which installs three vtables:

```asm
b5db79  lea rax, [rip+0x110A6B0]   ; 0x1C68230  primary
b5db93  mov [rcx], rax
b5db96  lea rax, [rip+0x110AD33]   ; 0x1C688D0  secondary
b5dba1  lea rax, [rip+0x110AD38]   ; 0x1C688E0  tertiary
```

and then subscribes to the game event system, registering handlers for
`round_prestart`, `round_freeze_end`, `round_officially_ended`,
`player_disconnect`, `player_death`, `player_hurt`, `hltv_cameraman`,
`hltv_fixed` (all via `0xB5D3E0`).

`CSource2Client::Connect` is `0xB667D0` (1,644 bytes). It is the single place
where every engine service is resolved. Its body is a long, ordered sequence of

```asm
lea rcx, [rip+"<InterfaceName>"]
call rbx                       ; rbx = CreateInterface
mov  [global], rax             ; cache into a typed global
```

The literal list, in call order, is the client's true dependency set:

```
Source2EngineToClient001        SteamUtils010
GameModelInfo001                SaveRestoreDataVersion001
VENGINE_GAMEUIFUNCS_VERSION005  Source2EngineToClientStringTable001
VFileSystem017                  InputSystemVersion001
GameConfigClientV001            VMediaFoundation001
VAvi001                         SceneFileCache002
ResponseRulesCache001           NetworkSystemVersion001
SerializedEntitiesVersion001    FlattenedSerializersVersion001
NetworkMessagesVersion001       GameTypes001
GameEventSystemClientV001       IMEManager001
VScriptManager010               LegacyGameUI001
```

The function also performs Steam bring-up: `SteamInternal_SteamAPI_Init` at
`0xB668A2`, `SteamAPI_SetTryCatchCallbacks` at `0xB668C9`, then five
`SteamInternal_ContextInit` calls, and hard failures via `Plat_FatalError` for
`"-nosteam"` without `"-insecure"` and for an invalid SteamID. Two timestamped
log markers bracket the factory sweep: `"ClientDLL factories - Start"` at
`0xB669F5` and `"ClientDLL factories - End"` at `0xB66BE6`. The function also
carries the Steam failure diagnostics
`"FATAL ERROR: Failed to connect with local Steam Client process!"`,
`"FATAL ERROR: Steam client version mismatch."`,
`"FATAL ERROR: Failed to initialize the Steamworks SDK."` and
`"Missing required interface"` / `"Launcher Error"` — so an absent interface
here is fatal, not degraded.

The corresponding full-init path is `0xB73977` (829 bytes), which logs
`"ClientDLL Init - Finish"` at `0xB73A01` and walks through
`CInputValueBase::RegisterInputValues()`, `InitGameSystems`, `ParticleMgr()->Init`,
`InitGameSystems - Start/End`, and `C_BaseAnimating::InitBoneSetupThreadPool`.

---

## 3. Entity system

### 3.1 `CGameEntitySystem`

RTTI class `CGameEntitySystem`, vtable `0x1C33A10`, 174 slots recorded by the
RTTI complete-object locator (24 of them resolve as real function starts, because
most virtuals are leaf getters with no unwind data). The important virtuals:

| slot | RVA | size | what the body shows |
|---|---|---|---|
| 2 | `0x9D1540` | 1,202 | `KeyValues` AddRef/Release refcount logging, then entity spawn from a KV: reads `"classname"`, checks `"point_prefab"`, reads `"prefab_load_dynamic"`, calls `0x19C1FF0` (spawn), then `Plat_FatalError("classname missing from entity!\n")` on the null path |
| 13 | `0x9E26D0` | 518 | entity-name search: builds `"player"`, `"pvsplayer"`, `"picker"`, `"parent"`, `"owner"` aliases, emits `"%s:  Invalid entity search name %s\n"` |
| 1 | `0x9D1A80` | 340 | reads `"GameSessionManifest.vrgrp"` and drives the manifest → `CEntitySystem` bridge |
| 21 | `0x9FC400` | 303 | — |
| 10 | `0x9C9590` | 216 | — |
| 4 | `0x9D14B0` | 135 | — |

`CGameEntitySystem::InitEntity2NetworkClasses` is `0xA19360` (1,301 bytes). It
opens the `"client_entities"` block (`lea rdx, [rip+"client_entities"]` at
`0xA193BC`), pushes entries into the entity-class vector using the standard
`UtlVectorMemory_*` helpers, and then calls `0x9EC2A0` and `0xA017B0`. It ends by
calling through the `SchemaSystem_001` vtable at `+0xA8` and `+0xB0`
(`0xA196B4`, `0xA196C8`).

`CGameEntitySystem::CreateEntities` is `0x9D5CC0` (534 bytes) and emits the
diagnostic `"CGameEntitySystem::CreateEntities: NULL binding for entity %s.\n"`.

### 3.2 `CEntitySystem` (the engine-side base)

`CEntitySystem::InitEntity2NetworkClasses` is `0x9ECA8F` (4,248 bytes), the
largest entity-system function. It validates the network-class declarations and
prints, among others:

- `"one or more DECLARE_NETWORKCLASS is malformed, see console for information!"`
- `"%s: non-conforming:  cl(%s) -> sv(%s)\n"`
- `"'%s' -> '%s' has malformed string (leading or trailing space)\n"`
- `"%s is abstract but didn't have any networkable descendents [found %d possibles], make (at least) one of these networkable"`
- `"CUtlStringToken hash collision between the two fields %s and %s!\n\tRename one of the keyfieldnames to fix the error."`

Source file: `src\game\shared\gameentitysystem.cpp`.

`src\entity2\entitysystem.cpp` contributes:

| RVA | size | symbol (from string literal) |
|---|---|---|
| `0x15B3550` | 1,033 | `CEntitySystem::AddKeyToUnserialize` |
| `0x15B4920` | 644 | — |
| `0x15B4C22` | 498 | — |
| `0x15B4E70` | 629 | — |
| `0x15B6920` | 1,591 | `CEntitySystem::DataDesc_AddComponentFieldUnserializer` |
| `0x15B6F60` | 1,571 | `CEntitySystem::DataDesc_AddComponentProceduralKeys` |
| `0x15BD7E7` | 858 | — |
| `0x15C2070` | 200 | — |
| `0x15C2629` | 217 | — |
| `0x15C2702` | 294 | — |
| `0x15C2850` | 542 | — |

The field-unserializer family is the core of the schema system: it takes a field
name, resolves it against a class's `DataDesc`, and registers a per-field
converter. `"Field \"%s\" of class \"%s\" cannot be unserialized yet (lacking array support)!\n"`
and `"Field %s::%s cannot have sub-keyfields since it is an atomic type!\n"` are
its two hard errors.

### 3.3 Thirteen entity classes

Every class below has a confirmed MSVC RTTI record and at least one confirmed
vtable. `methods.json` maps slots to function entry points; the slot index is the
raw index into the vtable, i.e. `vftable[idx]` where `vftable` is the address
immediately after the RTTI complete-object-locator pointer (slot 0 is the first
virtual function MSVC emitted, which for most of these classes is the
`~C_BaseEntity`-family destructor thunk).

| class | primary vtable | slots | secondary vtables | slot 0 |
|---|---|---|---|---|
| `C_BaseEntity` | `0x1C4CD10` | 218 resolved / 399 recorded | — | `0xAE9900` (16 B) |
| `C_BaseModelEntity` | `0x1C1E9C8` | 249 resolved | 4 more | `0x936880` (16 B) |
| `C_BasePlayerPawn` | `0x1C4ECA0` | 343 resolved | 4 more | `0xAE9910` (16 B) |
| `C_CSPlayerPawnBase` | `0x1C8C250` | 350 resolved | 5 more | `0xC6BDF0` (16 B) |
| `C_CSPlayerPawn` | `0x1C8F288` | 354 resolved / 371 recorded | 6 more | `0xC6BDE0` (16 B) |
| `C_CSObserverPawn` | `0x1C90F60` | 350 resolved | 5 more | `0xC6BDD0` (16 B) |
| `CCSPlayerController` | `0x1C11680` | 241 resolved | 2 more | `0x885790` (16 B) |
| `C_CSPlayerResource` | `0x1C17F08` | 218 resolved | — | `0x8C8740` (16 B) |
| `C_BasePlayerWeapon` | `0x1C20230` | 347 resolved | 6 more | `0x936890` (8 B) |
| `C_CSWeaponBase` | `0x1BDE520` | 423 resolved / 400 recorded | 8 more | `0x8077D0` (8 B) |
| `C_CSWeaponBaseGun` | `0x1BE1E80` | 425 resolved | 8 more | `0x8077F0` (8 B) |
| `C_AK47` | `0x1BE2CE0` | 425 resolved | 8 more | `0x807780` (8 B) |
| `C_CSGameRules` | `0x1BB8D60` | 75 resolved | — | `0x76F330` (33 B) |

The 8-byte slot-0 functions (`0x8077D0`, `0x8077F0`, `0x807780`) are
compiler-generated scalar-deleting destructors, not gameplay code — a reminder
that raw slot indices are only meaningful relative to the class's declaration
order. Note that the "slots" column is the *strict* walk length from
`methods.json`, which follows vtable entries as long as they are real function
entry points (including `.pdata`-less leaves). The RTTI-recorded vtable length
can differ slightly: `C_CSWeaponBase` records 400 but the strict walk continues
to 423, `C_BaseEntity` records 399 but only 218 entries resolve as function
starts before the walk hits non-code data. Use the RTTI number for "how big is
the vtable", the strict number for "how many methods I could actually identify". The interesting overrides are the larger ones:

| class | slot | RVA | size |
|---|---|---|---|
| `C_BaseEntity` | 20 | `0x215040` | 1,936 |
| `C_BaseEntity` | 11 | `0xB08BE0` | 656 |
| `C_BaseEntity` | 8 | `0xAE6A10` | 572 |
| `C_CSPlayerPawn` | 20 | `0x93A6A0` | 1,715 |
| `C_CSPlayerPawn` | 171 | `0x2259D0` | 970 |
| `C_CSPlayerPawn` | 283 | `0xAEFE20` | 902 |
| `C_CSPlayerPawn` | 172 | `0x225DA0` | 684 |
| `CCSPlayerController` | 11 | `0x8A2170` | 1,941 |
| `CCSPlayerController` | 20 | `0x215040` | 1,936 |
| `CCSPlayerController` | 235 | `0x8A0620` | 1,280 |
| `C_CSWeaponBase` | 403 | `0x819890` | 1,253 |
| `C_CSWeaponBase` | 304 | `0x80AD90` | 801 |
| `C_CSGameRules` | 58 | `0x75F520` | 1,016 |
| `C_CSGameRules` | 32 | `0x76A180` | 500 |

Notable bodies:

- **`C_CSPlayerPawn` slot 20 = `0x93A6A0`** (1,715 bytes) is shared verbatim by
  four classes at slot 20: `C_CSPlayerPawn` (`0x1C8F288`), `C_CSWeaponBase`
  (`0x1BDE520`), `C_BasePlayerPawn` (`0x1C4ECA0`) and `C_CSObserverPawn`
  (`0x1C90F60`). It is an inherited base-class thunk, not a CS-specific
  override. The same RVA landing at the same slot index in four unrelated
  vtables is the clearest evidence that these are inherited implementations.
- **`0x215040` (1,936 bytes), `0x2259D0` (970 B), `0x225DA0` (684 B) and
  `0x21DFB0` (632 B)** are the four most-shared virtuals in the module: they
  appear in 185, 317, 317 and 308 vtables respectively, always at the same slot
  index. `0x2259D0`/`0x225DA0`/`0x21DFB0` are the `CBaseAnimGraph` /
  `C_BaseModelEntity` / `C_BaseEntity` network-update chain; `0x215040` is the
  entity base's `UpdateOnRemove`/`PostDataUpdate` family. Any claim about
  "what a class does" has to exclude these shared slots.
- **`CCSPlayerController` slot 235 = `0x8A0620`** (1,280 bytes) builds
  `"#CSGO_FakePlayer_%s"` names, `"#CSGO_Overwatch_TheSuspect"` /
  `"The Suspect"`, and the `"unconnected"` placeholder — the fake-player /
  spectator-name synthesis path.
- **`CCSPlayerController` slot 11 = `0x8A2170`** (1,941 bytes) is the
  voice-abuse / comms-ban notice path: `"#GameUI_PlayerHasVoiceAbuseMute"`,
  `"#GameUI_AccountInfo_CommsBanPlayerIngame"`.
- **`C_CSPlayerPawn` slot 283 = `0xAEFE20`** (902 bytes) sits in the anim-graph
  controller region; `C_CSPlayerPawnBase`'s `0xC64240`/`0xC64CD0` and
  `C_CSPlayerPawn`'s `0xC63878` are the `cs_player_pawngraphcontroller.cpp` /
  `cs_player_weapongraphcontroller.cpp` overrides.
- **`C_CSWeaponBase` slot 403 = `0x819890`** (1,253 bytes) is in the weapon
  gameplay region adjacent to `0x813CE0` (the 13,127-byte network-field binder,
  §6.1).
- **`C_CSGameRules` slot 58 = `0x75F520`** (1,016 bytes) is the `game_vars` /
  `gc_status` / `frame_time_*` telemetry emitter.

### 3.4 Network-var registration and `InstallSchemaBindings`

`InstallSchemaBindings` (`0x19DE760`) is 75 bytes:

```asm
19de760  push rbx; sub rsp,0x20
19de766  mov  rbx, rdx                  ; rbx = schema system ptr
19de769  mov  rdx, rcx                  ; rdx = arg0
19de76c  lea  rcx, [rip+"SchemaSystem_001"]
19de773  call 0x1A0D9F0                 ; CreateInterface
19de778  test eax, eax
19de77a  je   19de784                   ; success -> continue
19de77c  xor  al, al; ret               ; fail
19de784  cmp  byte [0x27A3340], 0
19de78b  jne  19de7a3                   ; already installed
19de78d  mov  rcx, rbx
19de790  mov  [0x27A20D0], rbx          ; cache schema system
19de797  call 0x19DE5E0                 ; do the install
19de79c  mov  byte [0x27A3340], 1
19de7a3  mov  al, 1; ret
```

`0x19DE5E0` (381 bytes) is the worker: it walks a registration list rooted at
`0x27A3338`, calls each entry's callback, and on failure builds a diagnostic
with `CBufferString::Insert` and dies via
`Plat_FatalError("unable to register all schema data: %s\n")` at `0x19DE74F`.

The per-class binders are the giant functions in §6. Their shape is uniform:

```asm
c86690  ...  mov edx, [0x27A3B60]        ; TLS slot index
c866a6  mov rax, gs:[0x58]
c866af  mov ecx, 0x68
c866b4  mov rax, [rax+rdx*8]             ; thread block
c866b8  mov eax, [rcx+rax]               ; current tick
c866bb  cmp [0x2578540], eax             ; already-initialised generation?
c866c1  jg  0xc87eb4                     ; yes -> bail
c866c7  cmp byte [0x2578538], 0
c866ce  jne 0xc87ea2                     ; re-entrancy guard
c866d4  mov rcx, rbx
c866d7  mov byte [0x2578538], 1
c866de  call 0x458BA0                    ; get the class's DataDesc
c866e3  mov rdx, rax
c866e6  lea rcx, [0x2578378]             ; this class's field list
c866f0  call 0x15CC70                    ; append field descriptor
...                                      ; then one call per field
```

`0x15CC70` (31-byte `.pdata` entry, body continues past it) is the
`CUtlLeanVector` append used for the field descriptor array: it reads the count
from `[rcx+0xB0]`, capacity from `[rcx+0xC0]`, flags from `[rcx+0xC4]`, and
grows via `UtlVectorMemory_CalcNewAllocationCount` / `UtlVectorMemory_Alloc`.

The strings that follow are *hashed*, not stored: `0x813CE0` spends its first
~2 KB hashing every rotation of each field name (`"m_iWeaponGameplayAnimState"`,
`"_iWeaponGameplayAnimState"`, `"iWeaponGameplayAnimState"`, … down to
`"yAnimState"`) with the `0x5BD1E995` Murmur2 constant — that is
`CUtlStringToken` construction, the network field-key hash.

### 3.5 How the client entity system differs from the server's

Three structural differences are visible in the code, not inferred:

1. **The client has no authoritative spawn path.** `CGameEntitySystem::CreateEntities`
   (`0x9D5CC0`) exists to *bind* entities that arrived over the wire — it reads
   `classname` from a `KeyValues` and reports
   `"NULL binding for entity %s"`. The server's equivalent actually constructs
   and thinks entities; the client's constructs the C++ shell and then waits for
   `PostDataUpdate`. The client also carries `CreateEntities`' `"point_prefab"` /
   `"prefab_load_dynamic"` branch because prefab expansion is replayed locally
   from the map file.

2. **Every client class is a `C_` mirror with a separate class name.** The RTTI
   set has both `C_CSPlayerPawn` (client) and `C_CSPlayerPawnBase` (shared base),
   and the interface list has both `CWeaponHKP2000` and `C_WeaponHKP2000` — the
   client variant is prefixed `C_`. The client classes are registered through
   `InitEntity2NetworkClasses` (`0xA19360`) into the `"client_entities"` block,
   which is a distinct block from the server's.

3. **The client owns interpolation state the server does not have.**
   `C_BaseEntity` in `src\game\client\c_baseentity.cpp` contributes
   `ProcessInterpolatedList` (`0xB13110`, 6,076 bytes) and
   `LatchAndSaveLastSimulationValuesForInterpolationList` (`0xB02010`, 2,472
   bytes), plus `C_BaseEntity::SetInterpolationPhase` (`0xB1B5A0`, 599 bytes).
   These have no server counterpart: the server is the source of truth, the
   client stores two snapshots and lerps between them. `0xB02010` prints
   `"LatchAndSaveLastSimulationValuesForInterpolationList [%s] %.2fms for %d entities\n"`
   and a per-field histogram, which is a client-only profiling affordance.

---

## 4. Prediction

### 4.1 `CPrediction`

RTTI `CPrediction`, vtable `0x1C76DE0`, 33 slots (32 strict). Second vtable
`0x1C76EE8` with one slot (`0xBE7230`, 67 bytes) — the
`IPredictionCopyable`-style secondary interface.

| slot | RVA | size | role |
|---|---|---|---|
| 19 | `0xBD1D10` | 531 | prediction-time clamp |
| 4 | `0xBF29E0` | 450 | TrueView teardown |
| 13 | `0xBE7AC0` | 203 | `CPrediction::NetUpdateStart` |
| 3 | `0xBDDE50` | 178 | `CPrediction::ReinitPredictables` |
| 12 | `0xBE78B0` | 154 | `CPrediction::NetUpdatePreStart` |
| 15 | `0xBEA330` | 149 | — |
| 14 | `0xBEA030` | 136 | `CPrediction::PostEntityPacketReceived` |
| 16 | `0xBE8E40` | 99 | — |

The three named ones are confirmed by their own string literals
(`"CPrediction::NetUpdateStart"`, `"CPrediction::NetUpdatePreStart"`,
`"CPrediction::PostEntityPacketReceived"`, `"CPrediction::ReinitPredictables"`).

### 4.2 The prediction loop

`0xBF4EC0` (5,616 bytes, `[0xBF4EC0-0xBF64B0]`) is
**`CPrediction::PerformPrediction`** — it contains
`"CPrediction::PerformPrediction executed too many commands\n"` and
`"Remote player slot %d has no last executed command, but last processed command is %d?\n"`.
Its structure:

```
bf4ee6  call 0xBF1E10                 ; per-frame setup
bf4f07  call 0x15E43F0                ; clock
bf4f4b  mov  ecx, [0x256A9E8]         ; prediction logging channel
bf4f90  call 0xBD6580                 ; command history walk
bf5053  "TrueView can't determine last executed command number on server from command lookahead.  Desired tick %d (%d ahead).\n"
bf50b6  "TrueView target tick %d is behind last snapshot tick %d?\n"
bf51b2  "Not enough TrueSpectate command lookahead.  Desired tick %d (%d ahead).  Command lookahead is %d.  Last created command %d, last executed command %d on tick %d)\n"
```

The reconciliation core is **`0xBEA3C5`** (2,229 bytes,
`[0xBEA3C5-0xBEAC7A]`) = `CPrediction::PostNetworkDataReceived`:

```
bea404  call 0xBEE490                 ; snapshot bookkeeping
bea44a  call 0xBF1E10
bea459  ":"  /  "postnetworkdata"     ; debug channel tags
bea4e0  call [NetworkClientService+0xB8]
bea546  "%d commands acked (%d->%d), but %d ticks executed (%d->%d)"
bea563  "Cmd %d likely server substitute"
bea57d  "Initializing"
bea5af  "PostNetworkDataReceived tick %d, ack %d cmds"
bea5d8  "CPrediction::PostNetworkDataReceived"
bea63d  call 0xBCA4B0
bea64f  call 0xBD1F80
bea691  "Slot %d had %d prediction errors on tick %d.\n"
```

followed by the rate-limited summary:

```
"Slot %d had %d ticks with %d prediction errors in the last %.1f seconds due to user command delivery.  Set cl_error_report_time ..."
"Slot %d had %d ticks with %d prediction errors%s in the last %.1f seconds. Set cl_showerror 2 to display details ..."
```

The slot-repair logic is **`0xBEAC7A`** (1,149 bytes):

```
":    %i/%i prediction errors detected, discarding all slots\n"
":    %i/%i Prediction slot %d holds command %d instead of %d!  Deleting all predictions, will full repredict\n"
":    %i/%i No errors, processed %d -> %d, trimmed %d slots, %d remaining\n"
":    %i/%i bad state, discarding all slots\n"
"shift:%04d"
```

So the algorithm is the classic Source ring-buffer replay:

1. The server acks command *N*; the client's ring buffer still holds predicted
   state for commands *N+1 … M*.
2. `PostNetworkDataReceived` compares the acked state against the stored
   prediction for the same command. Any field mismatch is a **prediction error**,
   counted per slot.
3. If the slot *identity* is wrong (`Prediction slot %d holds command %d instead
   of %d`) or the error count exceeds the threshold, **all** slots are dropped
   and the client full-repredicts from the server snapshot.
4. Otherwise only the errored slots are trimmed and replay continues from the
   first bad command.

`0xBF2260` (149 bytes) guards the ordering:
`"Trying to store prediction history for command %d, but first slot is for command %d.  Going backwards or lurching prevented"`.

### 4.3 Prediction timing

`0xBD1D10` (slot 19) is the clamp:

```
"Prediction time (%f) is ahead of sim time (%f) by excessive amount (%f)?  Clamping offset\n"
"Client tick %d + %.2f final predicted tick %d + %.2f, offset = %.3f seconds, %.2f ticks\n"
```

`0xBDCD10` (1,648 bytes) is the user-command sanity check:

```
"Encountered a user command with an excessively high prediction time offset of %.1f ticks\n"
"Encountered excessive user command prediction offset of %.2f secs; ignoring\n\n"
```

### 4.4 `CPredictionCopy`

The field-copy machinery is separate from the loop and lives in
`src\game\shared\predictioncopy.cpp`:

| RVA | size | literal |
|---|---|---|
| `0x51B4C0` | 343 | `"CPredictionCopy::Init must have pDest!"` |
| `0x51B620` | 367 | `"CPredictionCopy::Init must have pDest!"` |
| `0x51EB58` | 106 | `"CPredictionCopyBuilder::BuildDataRuns"` |
| `0x520950` | 737 | `"CPredictionCopyIntermediateData::CorrectPackedValue: %s"` |
| `0x5280F0` | 820 | `"%s is not supported by CPredictionCopy::GetValue!!"` |
| `0x52C2AD` | 295 | `"CPredictionCopy::PredictionCopyApply unable to find func for %d:%s"` |
| `0x53067D` | 14 | `"CPredictionCopy::TransferData:  tried to TRANSFERDATA_COPYONLY from on..."` |

The `IPredictionCopyable` vtable shims are at `0xB0B6F0`–`0xB0B960`
(`PredCopy_GetCommand`, `PredCopy_GetHeaderBlock`, `PredCopy_IsValid`,
`PredCopy_OffsetForDataMap`, …), each 77–82 bytes.

### 4.5 `Source2ClientPrediction001`

Registered at `0x0D9B55`; factory `0xBF8C60` returns slot `0x256A850`. The
constructor `0xBF8C70` immediately calls `0x15B22A0` and `0x15C1090` and iterates
a `UtlVector` of predictables at `0x22CC610` / `0x22C8328`. `Source2ClientPrediction001`
is the *interface wrapper*; the implementation is the `CPrediction` object whose
vtable is `0x1C76DE0`.

Prediction is gated by the `cl_pred_*` ConVar family (§7): `cl_pred_optimize`,
`cl_pred_checkstuck`, `cl_pred_print_every_cmd`, `cl_pred_always_latch`,
`cl_pred_parallel_postnetwork`, `cl_pred_build_verbose`,
`cl_prediction_savedata_postentitypacketreceived`, `cl_predictioncopy_runs`.

---

## 5. HUD / Panorama

### 5.1 The HUD class family

RTTI contains 31 `CCSGO_Hud*` classes:

```
CCSGO_Hud                    CCSGO_HudAutoDisconnect
CCSGO_HudBlurTarget          CCSGO_HudChat
CCSGO_HudDMBonusPanel        CCSGO_HudDamageIndicator
CCSGO_HudDeathNotice         CCSGO_HudDeathPanel
CCSGO_HudDemoController      CCSGO_HudDemoPlayback
CCSGO_HudGameIcons           CCSGO_HudHealthAmmoCenter
CCSGO_HudHealthBars          CCSGO_HudHintText
CCSGO_HudInstructor          CCSGO_HudMatchAlerts
CCSGO_HudMutatorsPanel       CCSGO_HudNotice
CCSGO_HudProgressBar         CCSGO_HudRadar
CCSGO_HudRadio               CCSGO_HudReticle
CCSGO_HudRosettaSelector     CCSGO_HudTeamCounter
CCSGO_HudVoiceStatus         CCSGO_HudVote
CCSGO_HudWeaponSelection     CCSGO_HudWeaponSelectionDebug
CCSGO_HudWinPanel            CCSHudWeaponSelection
```

`CCSGO_Hud` has vtable `0x1CD81B0` with 85 resolvable slots (the RTTI complete
object locator records 175 total slots, most of which are leaf accessors). The
base constructor is `0x17ADDB0` (63 bytes), which chains into the panorama panel
constructor `0x17B40A0` (4,147 bytes, `src\panorama\controls\panel2d.cpp`).

Each concrete HUD element has the same three-part shape. Taking
`CCSGO_HudRadar` (`0xEA0C30`, 4,391 bytes) as the example:

```asm
ea0c4c  call 0x17ADDB0                  ; CCSGO_Hud base ctor
ea0c51  lea  rdx, [rip+"CCSGO_HudRadar"]; element name
ea0c58  lea  rcx, [rdi+0x20]
ea0c5c  call 0xBA3A50                   ; panel2d + name ctor
ea0c6b  lea  rax, [0x1CE1950]           ; vtable 1
ea0c7c  lea  rax, [0x1CE1C00]           ; vtable 2
ea0c64  mov  byte [rdi+0x60], 1
...
ea0d08  movsd xmm0, [0x1AC79D0]         ; default panel size
ea1045  lea  rdx, [rip+"hud-radar__active"]  ; CSS class
ea1057  call 0x178A2C0                  ; register CSS class
```

The `"hud-radar__active"` / `"hud-teammatecolor--%s"` / `"hud-WPN-main"` /
`"hud-colorize-wash"` strings are Panorama CSS class names, so the HUD is
implemented as Panorama panels driven from C++.

HUD element lookup goes through `0xE844A0` (150 bytes):

```asm
e844a6  mov rax, [0x25DB6C8]        ; global HUD manager
e844ba  lea rcx, [rax+0x258]        ; element vector
e844ce  call 0xE75630               ; find by name
e844d8  ...  shl rax, 5             ; 32-byte element stride
e844f3  mov rax, [rax+rcx+0x18]     ; element->panel
e84519  "[%d] Could not find Hud Element: %s\n"  ; DevWarning
```

`CCSGO_HudVoiceStatus` is the largest concrete element: `0xDB80CE` (5,280
bytes) is the lobby/party chat and invite-message renderer
(`"PanoramaUI.Lobby.Chat"`, `"Command::Game::ChatInviteMessage"`,
`"#SFUI_Settings_Chat_NotePartyInvited"`,
`"<font color=\"%s\">%s %s</font> %s <font color=\"%s\">%s</font>"`) and also
carries the voice-status notice path; `0xEA4730` (2,054 bytes) and `0xEC3950`
(540 bytes) complete the family, the latter emitting
`"CCSGO_HudVoiceStatus::PushNotice() no notice panels available, ignoring message %s"`.

`CCSGO_HudTeamCounter` is `0xEA3AF0` (3,124 bytes) / `0xECACE0` (2,708 bytes).
`CCSGO_HudChat` is created from `src\game\client\cstrike15\clientmode_csnormal.cpp`
via `0xD0CB20` (310 bytes), which calls `0xE844A0` with the literal
`"CCSGO_HudChat"`.

### 5.2 Panorama integration

`PanoramaUIEngine001` and `PanoramaUIClient001` are both rows in the 115-entry
table (`0x1E61BA0`, `0x1E61BB0`). `PanoramaUIClient001`'s factory is
`0x1CA7C38`; the object slot resolves to vtable `0x1CA7B50`, whose first six
virtuals are `0xCE5D70`, `0xCE68B0`, `0xD07780`, `0x162360`, `0xD0C660`,
`0xD06C40`.

Panorama itself is statically linked and visible in `.text` as a very large
cluster of `panel2d.cpp` / `panel2d.h` / `label.cpp` / `html.cpp` /
`movieplayer.cpp` functions. The inlining is aggressive: 100+ functions report
`src\public\panorama\controls\panel2d.h` as their source, and the biggest of
them are 4–5 KB (`0xDF4AED` 4,766 B, `0xE8B371` 4,816 B, `0xE7B18F` 2,770 B,
`0xEA0C30` 4,391 B, `0xEA3AF0` 3,124 B).

World-space Panorama panels are `src\game\client\panorama_world_panel.cpp`
(`0x1852E0`, 1,655 B) and `src\game\client\base_world_panel.cpp` (`0x15D9B0`,
167 B). The corresponding entity is `C_PointClientUIHUD`, whose network vars are
visible in RTTI: `m_unHorizontalAlign`, `m_unVerticalAlign`, `m_unOrientation`,
`m_unOwnerContext`, `m_flDPI`, `m_flDepthOffset`, `m_flWidth`, `m_flHeight`,
`m_flInteractDistance`, `m_bAllowInteractionFromAllSceneWorlds`, `m_bDisabled`,
`m_bIgnoreInput`.

`CInfoOffscreenPanoramaTexture` carries `m_nResolutionX`, `m_nResolutionY`,
`m_nTargetChangeCount`, `m_bEnableMipGen` — offscreen render targets for
in-world UI. Three relevant ConVars are registered from `0x0507D0`–`0x050920`:
`panorama_async_compute_mipgen`, `panorama_focus_world_panels`,
`panorama_worldpanel_update_cull_distance`,
`panorama_worldpanel_update_cull_size_threshold`,
`panorama_worldpanel_update_culling`.

### 5.3 The 3D HUD models

`C_CS2HudModelBase` / `Arms` / `Weapon` / `Addon` are spawned by
`CEntitySpawner<C_CS2HudModel*>` (RTTI confirms the template instantiations).
`0x10D7947` is `C_CS2HudModelArms::UpdateAndSetupView` (716 bytes), in
`src\game\client\cstrike15\hudmodel.cpp`. These render the first-person viewmodel
independently of the player pawn, which is why `cl_righthand` and viewmodel
offsets work even when the pawn is not predicted.

---

## 6. Weapon and player gameplay

The 15 functions below were selected by combining three signals: `.pdata` size,
the density of meaningful string literals (after filtering out the rotation
prefixes produced by `CUtlStringToken` hashing), and the embedded `__FILE__`
literal. Sizes are exact `.pdata` extents.

### 6.1 `0x813CE0` — 13,127 bytes — `C_CSWeaponBase` gameplay-anim-state binder

Largest weapon function and third-largest in the module. Source path is not
embedded in the function itself, but the adjacent
`C_CSWeaponBase::GetEconWpnData` (`0x80CF50`, `0x80CFE0`) names
`src\game\shared\cstrike15\weapon_csbase.cpp`, and the weapon vtable chain
(`0x1BDE520` → `0x1BDF270` → `0x1BE2BE0`) places it in that TU.

The body opens with the standard schema-binder prologue (§3.4) and then spends
~2 KB hashing every rotation of the gameplay-animation-state field names:

```
"m_iWeaponGameplayAnimState"  "_iWeaponGameplayAnimState"  "iWeaponGameplayAnimState"
"WeaponGameplayAnimState"     "eaponGameplayAnimState"     "aponGameplayAnimState"
...
"yAnimState"
```

The rotation list is the `CUtlStringToken` construction loop: for each field it
emits every suffix, hashing with the Murmur2 constant `0x5BD1E995` (visible at
`0x813DC4`, `0x813DCD`) so that the *case-insensitive* lookups
`m_iWeapon…`/`_iWeapon…`/`iWeapon…`/`Weapon…`/`eapon…` all resolve to the same
token.

The fields bound here are the weapon animation state machine inputs
(`m_iWeaponGameplayAnimState` and its `_`/no-prefix aliases), plus
`m_nDeployTick`, `m_flDeployDuration`, `m_bAllowBurstHolster`, `m_bInReload`,
`m_bReloadsSingleShells`, `m_iRecoilIndex`, `m_flRecoilAngle`,
`m_fAccuracyPenalty`, `m_nSpreadSeed`, `m_flSpread`, `m_weaponMode` — all
confirmed as literals in this function.

Note that the *weapon model/attachment names* (`weapon_elite`, `elite_holster`,
`weapon_cz75a`, `magazine2`, `weapon_molotov`, `lighter`) are **not** in this
function; they belong to `0x80C890` (§6.9).

### 6.2 `0x7625AC` — 25,399 bytes — `C_CSGameRules` network-field binder

Second-largest function in the module. The `C_CSGameRules` vtable `0x1BB8D60`
sits in the same code cluster (`0x76F330`, `0x75C580`, `0x75CE50` are its
slots). The function hashes the full match-state field set:

```
m_bFreezePeriod        m_iFreezeTime          m_iRoundTime
m_fMatchStartTime      m_fRoundStartTime      m_flRestartRoundTime
m_bGameRestart         m_flGameStartTime      m_timeUntilNextPhaseStarts
m_gamePhase            m_totalRoundsPlayed    m_nRoundsPlayedThisPhase
m_nOvertimePlaying     m_iHostagesRemaining   m_bAnyHostageReached
m_bMapHasBombTarget    m_bMapHasRescueZone    m_bMapHasBuyZone
m_bIsQueuedMatchmaking m_nQueuedMatchmakingMode  m_bIsValveDS
m_bLogoMap             m_iSpectatorSlotCount   m_MatchDevice
m_bHasMatchStarted     m_nNextMapInMapgroup
m_bTerroristTimeOutActive  m_bCTTimeOutActive
m_flTerroristTimeOutRemaining  m_flCTTimeOutRemaining
m_nTerroristTimeOuts   m_nCTTimeOuts          m_bTechnicalTimeOut
m_bMatchWaitingForResume
m_szTournamentEventName (char[512])   m_szTournamentEventStage
m_szMatchStatTxt       m_szTournamentPredictionsTxt
m_nTournamentPredictionsPct
m_flCMMItemDropRevealStartTime / EndTime   m_bIsDroppingItems
m_bIsQuestEligible     m_bIsHltvActive        m_bBombPlanted
m_arrProhibitedItemIndices (uint16[100])
m_arrTournamentActiveCasterAccounts (uint32[4])
m_numBestOfMaps        m_nHalloweenMaskListSeed   m_bBombDropped
m_iRoundWinStatus      m_eRoundWinReason
m_iMatchStats_RoundResults (int[30])
m_iMatchStats_PlayersAlive_CT / _T
m_TeamRespawnWaveTimes (float[32])   m_flNextRespawnWave (GameTime_t[32])
m_vMinimapMins / Maxs  m_MinimapVerticalSectionHeights (float[8])
m_nEndMatchMapGroupVoteTypes (int[10]) / VoteOptions
m_iNumConsecutiveCTLoses / TerroristLoses
m_pGameModeRules (CCSGameModeRules*)  m_RetakeRules (CRetakeGameRules)
m_nTeamIntroVariant / CTTeamIntroVariant
m_iRoundEndWinnerTeam  m_eRoundEndReason  m_bRoundEndShowTimerDefend
m_sRoundEndFunFactToken (CUtlString)  m_iRoundEndFunFactPlayerSlot
m_sRoundEndMessage     m_iRoundEndPlayerCount   m_bRoundEndNoMusic
```

plus the callbacks `OnGamePhaseChanged`, `OnMatchEndCountChanged`,
`OnRoundEndCountChanged`, `OnRoundStartCountChanged`.

The `cs_assault` / `cs_italy` / `cs_militia` / `"Weapons Course"` strings I
originally attributed here are **not** in this function — they belong to a
different map-list function in the same region.

### 6.3 `0xC819FC` — 18,610 bytes — `C_CSPlayerPawn` network-field binder

Binds 62 `m_*` fields of the local/remote player pawn. Representative set:

```
m_ArmorValue             m_angEyeAngles          m_bHasFemaleVoice
m_bInBombZone            m_bInBuyZone            m_bInHostageRescueZone
m_bInNoDefuseArea        m_bIsBuyMenuOpen        m_bIsDefusing
m_bIsGrabbingHostage     m_bIsScoped             m_bIsWalking
m_bKilledByHeadshot      m_bLeftHanded           m_bResumeZoom
m_bWaitForNoAttack       m_bGunGameImmunity      m_bRetakesHasDefuseKit
m_entitySpottedState     m_fImmuneToGunGameDamageTime
m_flFlinchStack          m_flVelocityModifier    m_flHealthShotBoostExpirationTime
m_flViewmodelFOV / OffsetX / OffsetY / OffsetZ
m_iBlockingUseActionInProgress
m_EconGloves             m_GunGameImmunityColor
m_bRagdollDamageHeadshot m_bRetakesMVPLastRound  m_fMolotovDamageTime
m_flBigHeadScale         m_flNextSprayDecalTime  m_flTimeOfLastInjury
m_flEmitSoundTime        m_fSwitchedHandednessTime
```

`m_entitySpottedState` is the spotted/visible bookkeeping that the render
pipeline's occlusion queries (§6.7) feed into.

### 6.4 `0x88F912` — 17,673 bytes — `CCSPlayerController` network-field binder

Binds 54 `m_*` fields — the controller's per-player scoreboard/state record,
distinct from the pawn's:

```
m_bPawnIsAlive          m_bPawnHasHelmet        m_bPawnHasDefuser
m_iPawnHealth           m_iPawnArmor           m_iPawnBotDifficulty
m_iPawnLifetimeStart    m_iPawnLifetimeEnd     m_nPawnCharacterDefIndex
m_hPlayerPawn           m_hObserverPawn        m_hOriginalControllerOfCurrentPawn
m_bControllingBot       m_bCanControlObservedBot   m_bHasControlledBotThisRound
m_bEverPlayedOnTeam     m_iPendingTeamNum      m_iCoachingTeam
m_iScore                m_iPing                m_nKillCount
m_iMVPs                 m_eMvpReason           m_bMvpNoMusic
m_iCompetitiveRanking   m_iCompetitiveWins     m_iCompetitiveRankType
m_iCompetitiveRankingPredicted_Win / _Loss / _Tie
m_iCompTeammateColor    m_nFirstKill           m_nPlayerDominated
m_bHasCommunicationAbuseMute
m_nDisconnectionTick    m_nEndMatchNextMapVote m_flForceTeamTime
m_iMusicKitID           m_iMusicKitMVPs
m_bFireBulletsSeedSynchronized
```

`m_bFireBulletsSeedSynchronized` on the controller (not the pawn) is worth
noting: the bullet-spread RNG seed is synchronised per *player*, which is what
makes prediction of shots possible.

The four service objects (`CCSPlayerController_InGameMoneyServices`,
`_ActionTrackingServices`, `_DamageServices`, `_InventoryServices`) have their
own RTTI entries and their own 1,380-byte binders at
`0x8656C0`/`0x865150`/`0x865C30`/`0x864BE0`; the controller binder holds the
`m_p*Services` pointers to them.

### 6.5 `0xC862AE` — 817 bytes — `CCSPlayerPawn` service wiring

Not large, but structurally central. It registers
`"LocalPlayerAndPredictorsExclusive"` (a schema/thread-confinement annotation)
against `m_flFlinchStack`, then binds the service pointers:

```
m_pUseServices      -> CCSPlayer_UseServices
m_pItemServices     -> CCSPlayer_ItemServices
m_pMovementServices -> CCSPlayer_MovementServices
m_pWaterServices    -> CCSPlayer_WaterServices
m_pCameraServices   -> ...
```

and the eye-angle state (`m_angEyeAngles`, `qangle_precise`,
`playerEyeAnglesChanged`).

### 6.6 `0x896DF0` — 25,730 bytes — fake-player name pool

Third-largest function. Contains the complete alphabetised codename table —
`Albatross`, `Alpha`, `Anchor`, `Banjo`, `Bell`, `Beta`, `Blackbird`, `Bulldog`,
`Canary`, `Cat`, `Calf`, `Cyclone`, `Daisy`, `Dalmatian`, `Dart`, `Delta`,
`Diamond`, `Donkey`, `Duck`, `Emu`, `Eclipse`, `Flamingo`, `Flute`, `Frog`,
`Goose`, `Hatchet`, `Heron`, `Husky`, `Hurricane`, `Iceberg`, `Iguana`, `Kiwi`,
`Kite`, `Lamb`, `Lily`, `Macaw`, `Manatee`, `Maple`, `Mask`, `Nautilus`,
`Ostrich`, `Octopus`, `Pelican`, `Puffin`, `Pyramid`, `Rattle`, `Robin`, `Rose`,
`Salmon`, `Seal`, `Shark`, `Sheep`, `Snake`, `Sonar`, `Stump`, `Sparrow`,
`Toaster`, `Toucan`, `Torus`, `Vortex`, `Vulture`, `Wagon`, `Whale`,
`Woodpecker`, `Zebra`, `Zigzag` — each as `#CSGO_FakePlayer_<Name>`, and ends
with `"Insufficient random names pool!"`.

It also carries the `0x19FEB98`/`0x19FEA6C`/`0x19FEB2C` triple (the same
thread-local guard sequence used by `CSource2Client::Connect`), so it is an
init-time registration of the bot-name localisation strings.

### 6.7 `0x11DE700` — 26,148 bytes — CS2 render pass graph

Second-largest function overall. Source: `src\game\client\cstrike15\renderingpipeline\`
(the adjacent `0x1204C1E` literal is `renderingpipeline_csgo.cpp`, and the
function's own error string is
`"CRenderingPipelineCsgo::AddLayersToView(11295): "`). It constructs the ordered
render-layer list:

```
"Create PerViewConstantBufferCsgo_t"
"intermediate_depth_rt"   "intermediate_color_rt"
"CsgoReflectionColor"     "CsgoReflectionDepth"
"CopyGameBackground"      "ClearQuadCoverage"
"OcclusionQueryIssueLayer"  "PlayerOcclusionQueryReadbackLayer"
"PlayerOcclusionQuerySceneObject"
"Static AlphaTest Forward"  "Dynamic AlphaTest Forward"
"HammerRaytracedImage"
"Static Opaque Forward"     "ToolsUtil Opaque"  "Tools_Opaque"
"Tools_PreTranslucent"      "PreSkyboxDepth"    "Forward"
"HammerSelectedSky"
"Cables (alphatest particle objects)"
"Dynamic Opaque Forward (receiving AO proxies)"
"Tools Post Occlusion Query"  "BeforeTranslucent"
"SmokeLPVSetup"  "MBOIT(%d) Smoke 1/4"  "MBOIT(%d) Smoke 1/2"  "MBOIT(%d) Smoke Full"
"MBOIT(%d) Translucent 1/2"  "Water Translucent Combine"
"WriteSmokeDepth"  "Mixed Resolution Particles"
"SmokeOverlayDataA.vtex"  "SmokeOverlayDataB.vtex"  "rt_SmokeOverlayData"
"OverlaySmokeUpdate"  "OverlaySmoke"  "ClearSmokeTargets"
"MouseTraceCoordReadback"  "CsgoForward"  "GameOverlay Particles"
"ToolsUtil Translucent"  "Tools_Translucent"
"halfResTranslucentScreenSpace"  "ScreenParticleCombine"
"Translucent Screen Space"  "LetterboxTop"  "LetterboxBottom"
"PlayerHealthGlow"  "AlbedoOrReflectivity"  "GrenadeCamera"
"MaterialSystem2/ShaderIDColors"  "BackgroundForShaderIDs"
"PanoramaAlphaCopy"  "Copy for Panorama Alpha"  "PanoramaAlphaSetup"
"Fade To Black"  "MagBorder"
"Engine2/RenderingPipeline/AmbientOcclusionProxies"
```

That is a direct enumeration of the CS2 render graph, including MBOIT
(moment-based order-independent transparency) smoke passes, the letterbox, the
grenade camera, the panorama alpha copy, and — most relevant here — the three
`PlayerOcclusionQuery*` layers that drive the player-visibility system
(`cl_player_visibility_near/far/stencil_proxy_min_dist`, §7).

### 6.8 `0xB13110` — 6,076 bytes — `ProcessInterpolatedList`

Source: `src\game\client\c_baseentity.cpp`. The client's interpolation driver:
walks the interpolated-entity list, computes each entity's interpolation phase,
and applies the latch. Emits
`"%s allocation count overflow( add %llu + current %llu > max %llu )\n"`.
Its companion `0xB02010` (2,472 bytes) is
`LatchAndSaveLastSimulationValuesForInterpolationList` and prints the per-field
timing histogram (`"Latch Report:\n"`, `"\tAvg Time: %.3fms, Avg Count: %.3f\n"`).

### 6.9 `0x80C890` — 1,203 bytes — `C_CSWeaponBaseGun` slot 0

The per-weapon animation/attachment table: `weapon_elite`, `elite_holster`,
`weapon_l`, `weapon_cz75a`, `magazine2`, `weapon_molotov`, `lighter`. Called
through `[rax+0x4F0]` and `[rax+0xAB8]` of the weapon base, i.e. it is the
model/attachment resolver, not gameplay logic.

### 6.10 `0x8A2170` — 1,941 bytes — `CCSPlayerController` slot 11

Comms/voice-abuse UI path: `#GameUI_PlayerHasVoiceAbuseMute`,
`#GameUI_AccountInfo_CommsBanPlayerIngame`.

### 6.11 `0x8A0620` — 1,280 bytes — `CCSPlayerController` slot 235

Fake-player / spectator identity: `#CSGO_FakePlayer_%s`,
`#CSGO_Overwatch_TheSuspect`, `The Suspect`, `unconnected`.

### 6.12 `0x75F520` — 1,016 bytes — `C_CSGameRules` slot 58

Telemetry emitter for `game_vars`, `gc_status`, `frame_time_sample_count`,
`frame_time_50th_percentile`, `frame_time_95th_percentile`, `frame_time_max`.

### 6.13 `0x76A180` — 500 bytes — `C_CSGameRules` slot 32

The collision-group name table: `csgo_team1`, `csgo_team2`, `csgo_grenadeclip`,
`csgo_droneclip`, `csgo_moveable`, `csgo_opaque`, `csgo_monster`,
`csgo_chicken`, `csgo_thrown_grenade`, `csgo_dropped_hostage`.

### 6.14 `0x8C6910` — 2,005 bytes — `CCSPlayer_MovementServices` NaN guard

Emits four diagnostics, one per integrity class:

```
"CCSPlayer_MovementServices(%s):  %d/%s Got a NaN velocity on %s\n"
"CCSPlayer_MovementServices(%s):  %d/%s Got a NaN origin on %s\n"
"CCSPlayer_MovementServices(%s):  %d/%s Got a velocity too low (<%.2f) on %s\n"
"CCSPlayer_MovementServices(%s):  %d/%s Got a velocity too high (>%.2f) on %s\n"
```

This is the movement-service sanity check that catches a NaN or out-of-range
value entering the velocity pipeline — relevant because prediction replays
`SetupMove` (`0xA76160`, 641 bytes,
`CPlayer_MovementServices::SetupMove`, `src\game\shared\player_movementservices.cpp`)
every tick.

### 6.15 `0xD25A0D` — 636 bytes — `FX_FireBullets` econ lookup

```
"FX_FireBullets: GetItemDefinition failed\n"
"FX_FireBullets: GetWeaponEconDataFromItem failed for weapon %s\n"
"old: %f %f new: %f %f\n"
```

The sibling `0xD25C89` (51 bytes) is
`"FX_FireBullets: GetCSWeaponDataFromItem failed for weapon %s\n"`.
These are the failure paths of the bullet-impact effect, which needs the item
definition to select the impact decal and sound.

### 6.16 Also worth naming

- `0xB0F714` (12,160 bytes) — the VScript `C_BaseEntity` binding surface. Every
  string is a script method signature: `[output] = [%s]->Weapon_GetSlot([%i])`,
  `[output] = [%s]->DistTo([%s])`, `[output] = [%s]->Weapon_CanPickup([%s])`,
  `V_strcpy([%s], [%s]->GetPlayerName()`, etc. This is the largest single
  script-binding table in the module.
- `0x452CDC` (13,218 bytes) — the `TakeDamage` / `m_iHealth` field binder
  (`TakeDamageFlags_t`, `TakeDamageInfo`).
- `0xC86690` (6,283 bytes) — the full `CCSPlayerPawn` service binder including
  `m_pPingServices`, `playerState`.
- `0x90C000` (8,460 bytes) — `CCSPlayerController_DamageServices` binder
  (`m_PlayerDamager`, `m_PlayerRecipient`, `EKillTypes_t`,
  `m_bKilledByHeadshot`).
- `0xCF7A20` (8,127 bytes) — `CCSPlayerResource` bomb state (`m_bBombTicking`,
  `m_nBombSite`).
- `0x8D6C80` (6,798 bytes) — `C_CSPlayerResource` hostage state
  (`m_bHostageAlive`, `bool[12]`).

---

## 7. ConVar registry

### 7.1 Registration mechanism

Two registrars, both in `.text`:

**ConVar** — `0x19B2280` (787 bytes, `[0x19B2280-0x19B2593]`), 1,325 call sites.
Signature from the prologue:

```
rcx            = &CConVar<T> storage (static, in .data)
rdx            = name
r8             = flags
r9             = help string
[rsp+0x110]    = ConVarDesc*  (min/max/rounding)
xmm0           = default value
```

The body resolves a per-type vtable from a table at `0x22B1DF0` indexed by
`word [rdi+0x60]` (a type discriminator), defaulting to `0x22B2A20`; stores the
type vtable at `[rcx+8]`; then ORs in default flags
`0x100000002` (`FCVAR_CLIENTDLL`-ish pair) when the caller's flags don't already
include `0x13084282`; and calls `[g_pCvar->+0x130]` (the `VEngineCvar007`
vtable) to insert into the cvar trie. Failure path:
`Plat_FatalError("RegisterConVar: Unknown error registering convar \"%s\"!\n")`
at `0x19B23FB`.

**ConVar<T> wrapper** — `0x15A380` (115 bytes), 605 call sites. Thin front-end:
calls `0x19B14E0` to allocate the `ConVarData`, stores the default at
`[rax+7]` (`movss dword ptr [rax+7], xmm6`), sets a byte at `[rax+4]`, then calls
`0x19B2280`.

**ConCommand** — `0x19CCE10` (522 bytes), 345 call sites. Signature:
`rcx` = storage, `rdx` = name, `r8` = `{callback, ...}` descriptor, `r9` = help,
`[rsp+0x20]` = flags. Failure:
`Plat_FatalError("RegisterConCommand: Unknown error registering con command \"%s\"!\n")`
at `0x19CD081`.

A worked example, `cl_panel_freeze_time_after_press` at `0x04DE50` (155 bytes):

```asm
4de5a  movss  xmm2, [0x1ACB080]          ; default
4de62  lea    rdx, [rip+"cl_panel_freeze_time_after_press"]
4de6b  lea    rcx, [0x23744E8]           ; static CConVar<float>
4de85  xor    r9d, r9d                   ; flags = 0
4dec7  lea    rax, [rip+"time to freeze mouse/pointer motion after a mouse button press"]
4dece  mov    [rsp+0x20], rax            ; help
4ded3  call   0x15A380
4ded8  lea    rcx, [0x1A68B80]           ; registration-complete callback
4dedf  add    rsp, 0xb8
4dee6  jmp    0x19FEA6C                  ; static-init once
```

and a ConCommand, `cl_ent_call` at `0x053980` (106 bytes), which passes
`flags = 0x4000` (`FCVAR_CHEAT`) and callback `0x2342B0`.

### 7.2 Registry census

Scanning every call to the three registrars and resolving the argument registers
yields:

| kind | call sites | unique names |
|---|---|---|
| ConVar | 1,707 | 1,695 |
| ConCommand | 321 | 321 |

911 of the ConVars have a resolvable help string. 413 unique `cl_*` ConVars.
(The pre-existing `cvars_client.json` in the corpus lists only 100 names because
it used a name-pattern heuristic over `.rdata`; `cvars_all.json` is the
register-accurate replacement.)

Prefix distribution of the 1,695 ConVars: `cl_` 413, `r_` 205, `sv_` 178,
`snd_` 121, `mp_` 64, `ammo_` 20, `joy_` 20, `spec_` 17, `pred_` 8, `fog_` 8,
`viewmodel_` 4, `panorama_` 2.

### 7.3 Notable `cl_*` ConVars

Each row is a real registration site; the RVA is the registering function.

| cvar | RVA | help text |
|---|---|---|
| `cl_interp_ratio` | `0xB66E0` | "Read the effective client simulation interpolation amount in terms of time." |
| `cl_interp_all` | — | "Disable interpolation list optimizations." |
| `cl_interp_hermite` | — | "Set to zero do disable hermite interpolation." |
| `cl_interp_npcs` | `0xC6960` | "Set to zero do disable hermite interpolation." |
| `cl_interp_parallel` | — | "Run interpolation in parallel for entities with no children." |
| `cl_interp_simulationvars` | — | "Interpolate LATCH_SIMULATION_BIT vars if interpolation interval is grea…" |
| `cl_interp_animationvars` | — | "Interpolate LATCH_ANIMATION_BIT vars if interpolation interval is grea…" |
| `cl_smoothtime` | `0xC75B0` | "Smooth client's view after prediction error over this many seconds" |
| `cl_showerror` | `0x0DA260` | "Show prediction errors, 2 for above plus detailed field deltas, 3 to filter out serverside known prediction errors" |
| `cl_error_report_time` | `0xD9C80` | prediction-error report window |
| `cl_pred_optimize` | — | "Optimize for not repredicting if there were no errors" |
| `cl_pred_checkstuck` | — | "Perform the additional 'stuck' traces on the client side during prediction." |
| `cl_pred_print_every_cmd` | — | "Print something every time we predict a command" |
| `cl_pred_always_latch` | — | — |
| `cl_pred_parallel_postnetwork` | — | — |
| `cl_pred_build_verbose` | — | "Verbose spew when building prediction optimized data runs." |
| `cl_prediction_savedata_postentitypacketreceived` | — | "Experimental optimization.  If you are reading this in 2026, please de…" |
| `cl_predictioncopy_runs` | — | "Print simple description of prediction copy fields for entindex…" |
| `cl_net_buffer_ticks` | `0x10B55D0` | "Number of ticks of delay for server snapshots and user commands.  This value controls the value of cl_interp_r…" |
| `cl_net_buffer_ticks_use_interp` | — | "If false, we smooth over packet loss by adjusting the clock synchroniz…" |
| `cl_net_showevents` | — | "Dump game events to console (1=client only, 2=all)." |
| `cl_net_showeventlisteners` | — | "Show listening addition/removals" |
| `cl_showpos` | `0x0CEE90` | "Draw current position at top of screen" |
| `cl_showfps` | — | "Draw fps meter at top of screen (1 = fps, 2 = smooth fps, 3 = server MS, 4 = Show FPS and Log to file )" |
| `cl_drawhud` | — | "Enable the rendering of the hud" |
| `cl_drawhud_force_radar` | — | "0: default; 1: draw radar even if hud disabled; -1: force no radar" |
| `cl_drawhud_force_teamid_overhead` | — | "0: default; 1: draw teamid even if hud disabled; -1: force no teamid" |
| `cl_drawhud_specvote` | — | "1: default; 0: disables vote UI for spectators" |
| `cl_draw_only_deathnotices` | — | "For drawing only the crosshair and death notices (used for moviemaking)" |
| `cl_crosshairsize` | `0x0FC810` | (help string mis-associated in binary; see note) |
| `cl_crosshairthickness` | `0x0FC970` | "Crosshair style. 0 = Dynamic Cross, 1 = Dynamic Circle, 2 = Dynamic Cross (Legacy), 3 = Static Circle, 4 = Sta…" |
| `cl_crosshairdot` | — | "Draw a dot at the center of the crosshair" |
| `cl_crosshair_recoil` | — | "Crosshair follows the weapon's predicted recoil (aim punch)" |
| `cl_crosshaircolor_r/g/b/a` | — | per-component crosshair colour |
| `cl_crosshairoutline_r/g/b/a` | — | outline colour |
| `cl_crosshair_dynamic_splitdist` | — | dynamic-crosshair split distance |
| `cl_crosshair_dynamic_maxdist_splitratio` | `0x0FB780` | inner/outer split ratio |
| `cl_crosshair_dynamic_splitalpha_innermod` | `0x0FB850` | inner alpha modifier |
| `cl_crosshair_dynamic_splitalpha_outermod` | `0x0FB920` | outer alpha modifier |
| `cl_crosshair_dynamic_spread_limit` | — | spread limit |
| `cl_crosshair_sniper_width` | — | "If >1 sniper scope cross lines gain extra width (1 for single-pixel hairline)" |
| `cl_crosshair_t` | — | T-shaped crosshair |
| `cl_crosshair_friendly_warning` | — | friendly-fire warning on crosshair |
| `cl_radar_scale` | `0x0ED190` | "Sets the radar scale. Valid values are 0.25 to 1.0." |
| `cl_radar_scale_alternate` | `0x0ED250` | alternate radar scale |
| `cl_radar_scale_dynamic` | — | "Toggles between a radar that scales dynamically to encompass all the d…" |
| `cl_radar_always_centered` | — | "If set to 0, the radar is maximally used. Otherwise the player is always centered, even at map extents." |
| `cl_radar_rotate` | — | — |
| `cl_radar_fast_transforms` | — | "Faster way of placing icons on the mini map." |
| `cl_radar_icon_scale_min` | `0x0ED020` | "Faster way of placing icons on the mini map." |
| `cl_radar_show_all_players_when_spectating` | — | "Set all players visible on radar when spectating, regardless of whethe…" |
| `cl_teammate_colors_show` | `0x0CD9650` | "In competitive, 1 = show teammates as separate colors in the radar, scoreboard, etc., 2 = show colors and letters" |
| `cl_teamid_overhead_mode` | `0x0CD9650` | "Always show team id over teammates. 0 = off, 1 = pips; 2 = +name, 3 = +equipment" |
| `cl_use_opens_buy_menu` | `0x0CD9650` | "Pressing the +use key will open the buy menu if in a buy zone (just as if you pressed the 'buy' key)." |
| `cl_hud_color` | — | "0 = team color, 1 =  white, 2 = bright white, 3 = light blue, 4 = blue, 5 = purple, 6 = red, 7 = orange, 8 = y…" |
| `cl_hud_radar_background_alpha` | `0x0E4340` | radar background alpha |
| `cl_hud_radar_blur_background` | — | "Blurs the radar background." |
| `cl_hud_radar_map_additive` | — | "Blend Hud radar map additively on top of background." |
| `cl_hud_telemetry_frametime_show` | — | "Show frame time (FPS) in the HUD.  0=never, 1=only if poor, 2=always" |
| `cl_hud_telemetry_net_detailed` | — | "Show breakdown network misdelivery (loss, late delivery, and peak jitt…" |
| `cl_hud_telemetry_ping_poor` | `0x11F770` | "Show packet jitter and netframe loss/reordering in the HUD.  0=never,…" |
| `cl_obs_interp_enable` | — | "Enables interpolation between observer targets" |
| `cl_obs_interp_speed` | `0x0AC7F0` | "Enables interpolation between observer targets" |
| `cl_spectator_predict` | — | "Enable 'TrueView' when spectating another player, which attempts to recreate the client's experience more accurately." |
| `cl_demo_predict` | — | "Enable 'TrueView' when watching a demo, which attempts to recreate the client's experience more accurately." |
| `cl_trueview_show_status` | — | "0=Never; 1=Only if there is a problem; 2=always" |
| `cl_demo_steadycam_enable` | — | "Stabilize camera orientation/position during demo playback.  1 == remo…" |
| `cl_demo_steadycam_radius` | `0x0D2A50` | (shares help with the above) |
| `cl_demo_steadycam_deflection` | `0x0D2900` | "blend over this many frames" |
| `cl_demo_view_offset_left` | `0x0D2AF0` | "View offset during demo playback (+/- 1.25 is a good default for human…" |
| `cl_demoviewoverride` | `0x0D2B90` | "Override view during demo playback" |
| `cl_debounce_zoom` | — | "Whether or not to disable holding secondary fire to cycle zoom levels" |
| `cl_clutch_mode` | — | "Silence voice and other distracting sounds until the end of round or next death." |
| `cl_mute_all_but_friends_and_party` | — | "Only allow communication from friends and matchmaking party members. Set to 1 to apply the in non-competitive …" |
| `cl_mute_player_after_reporting_abuse` | — | "Mute players reported for abuse automatically." |
| `cl_weapon_debug_show_accuracy` | — | "Draws a circle representing the effective range with every shot." |
| `cl_player_visibility_near` | `0x0F2AB0` | "cull characters nearer than this" |
| `cl_player_visibility_far` | `0x0F2970` | (shares the visibility group) |
| `cl_player_visibility_stencil_proxy_min_dist` | `0x0F2CA0` | stencil-proxy threshold |
| `cl_batch_entity_list_ops_during_latch` | — | "Batch entity list adds / removes while latching interpolated variables to avoid mutex contention." |
| `cl_async_restore_server_authoritative_state` | — | (help text mis-associated) |
| `cl_allow_multi_input_binds` | — | — |
| `cl_panel_freeze_time_after_press` | `0x04DE50` | "time to freeze mouse/pointer motion after a mouse button press" |

**Note on mis-associated help strings.** A handful of rows above have help text
that clearly belongs to a neighbouring registration (e.g. `cl_crosshairsize`
reporting "Crosshair outline color, red component"). This is a genuine property
of the binary: the registrar call's `[rsp+0x20]` slot is written by a shared
register in some sites, so the extractor sees the previous cvar's help pointer.
The *names* are exact (they come from the `rdx` `lea` immediately before the
call); only the help strings are occasionally off by one. Where the help is
suspect the table shows the string as-is rather than inventing a description.

### 7.4 `cl_*` families that matter for behaviour

- **Interpolation / clock**: `cl_interp_*`, `cl_net_buffer_ticks*`,
  `cl_smoothtime`, `cl_extrapolate_amount`.
- **Prediction**: the twelve `cl_pred_*` / `cl_prediction*` vars.
- **HUD/UI**: `cl_hud_*`, `cl_drawhud*`, `cl_radar_*`, `cl_crosshair*`,
  `cl_teamid_overhead_mode`, `cl_teammate_colors_show`.
- **Demo/spectate**: `cl_demo_*`, `cl_trueview_show_status`,
  `cl_spectator_predict`, `cl_obs_interp_*`.
- **Input**: `cl_allow_multi_input_binds`, `cl_use_opens_buy_menu`,
  `cl_debounce_zoom`.
- **Rendering perf**: `cl_batch_entity_list_ops_during_latch`,
  `cl_async_restore_server_authoritative_state`,
  `cl_player_visibility_*`.

`cl_cmdrate`, `cl_updaterate`, `cl_lagcompensation`, `cl_predict` and
`cl_predict_weapons` are **not** registered by this module. The string
`cl_interp = %f (cl_interp_ratio=%g / cl_updaterate=%g)` at `0x96EB70` is a
format string that reads those values from the server side of the engine, not a
registration. `cl_lagcompensation_test_target` and
`cl_lagcompensation_test_auto_target` *are* registered (`0x0F26B0`, `0x0F2760`)
— they are lag-compensation *test harness* cvars.

---

## 8. The reverse-engineering surface

This section describes structural facts about the binary. It is not a guide to
modifying behaviour in a live match; it is a map of where the module's
responsibilities are implemented.

### 8.1 The three chokepoints

Any external code that wants to observe or alter client behaviour has to cross
one of three boundaries, in increasing order of specificity:

1. **`CreateInterface` (`0x19D0FF0`)** — the only way to obtain a pointer to
   `CSource2Client` or `CPrediction`. It is a 36-byte leaf with no `.pdata`
   entry, so it does not appear in any unwind-based function map. The list head
   is a plain global at `0x27A2CF8`, and the compare is a byte-wise
   case-sensitive `strcmp` with no length bound — the loop at `0x19D1010` reads
   `[rax]` and `[rax+r8]` until a zero byte, so both strings must be
   null-terminated within the mapping.

2. **`CPrediction::PostNetworkDataReceived` (`0xBEA3C5`)** — the single point
   where the server snapshot is compared to the client's predicted state. Every
   reconciliation decision (`discarding all slots`, `will full repredict`,
   `trimmed %d slots`) is made here and in `0xBEAC7A`.

3. **`CViewRender::Render` (`0xC19580`)** — the frame's scene-render entry. It
   is a 170-byte function that opens a `VProf` scope named `"CViewRender::Render"`
   (`src\game\client\view.cpp`) and then dispatches through the view-render
   instance. The actual pass list is built by `0x11DE700` (§6.7). Note the
   dependency check at `0xB73EE0`: `"GetViewRenderInstance() must be implemented
   by game."` — so `CViewRender` is an abstract hook the game module fills in.

### 8.2 What a client modification would touch, structurally

- **Entity visibility / ESP-class features** would read the interpolated entity
  list driven by `0xB13110` and `0xB02010`, and would have to defeat the
  occlusion system whose layers are enumerated in `0x11DE700`
  (`PlayerOcclusionQueryIssueLayer`, `PlayerOcclusionQueryReadbackLayer`,
  `PlayerOcclusionQuerySceneObject`). The `cl_player_visibility_*` ConVars
  parameterise the stencil-proxy distance thresholds.

- **Aim/trigger features** would sit on the input path. The relevant functions
  are `0xD04950` (1,591 bytes, `cl: CreateMove` history validation),
  `0xCFC880` (1,507 bytes, `cl: CreateMove - Invalid player history`), and
  `0xD0431E` (408 bytes, `cl: CreateMove clamped invalid attack history`). These
  are *validation* code: they detect and repair a `CUserCmd` whose attack-history
  indices are inconsistent. `CPlayer_MovementServices::SetupMove` is
  `0xA76160` (641 bytes).

- **Weapon modifications** would read `C_CSWeaponBase::GetEconWpnData`
  (`0x80CF50` / `0x80CFE0`, 140/152 bytes). Both die with
  `Plat_FatalError("Weapon '%s' script file not found, but its data was accessed. This error is fatal.\n")`
  if the econ data is missing, so the weapon script file must be mounted.

- **Information disclosure** would read the network-field binders (§3.4, §6.1,
  §6.2, §6.3, §6.4). Because the field names are hashed into `CUtlStringToken`s
  at registration time, the field *offsets* are not recoverable from the hash —
  a consumer needs the `DataDesc` that `InstallSchemaBindings` populates, or the
  `CPredictionCopy` data-run descriptors built by `0x51EB58`.

### 8.3 Anti-tamper observations

- The module is **not Authenticode signed** and **not CFG-protected**
  (`dll_characteristics = 0x160`, no `0x4000`). There is no `/guard:cf` dispatch
  table, so indirect calls are not validated.
- `ExtractModuleMetadata` (`0xC33940`) implements a thread-local
  generation-cached metadata record — a common pattern for detecting module
  reloads, but its exact consumer was not traced.
- `BinaryProperties_GetValue` distinguishes `"Release"` from non-release builds
  and reports `"client"` as the module identity. A patched build would have to
  keep this consistent with whatever the engine checks.
- The `SteamAPI_Init` path in `CSource2Client::Connect` (`0xB668A2`) enforces
  `-nosteam` only with `-insecure` via `Plat_FatalError`, and rejects an invalid
  SteamID. There is no obvious signature scan or self-hash in the paths
  examined.

### 8.4 Things I could not determine

- The exact layout of `CGameEntitySystem`'s entity chunk array. The vtable and
  the `CreateEntities` body are clear, but the chunk stride and the
  `CEntityIndex` → chunk mapping were not resolved; `0x9D5CC0` reads through
  several levels of indirection whose types are not recoverable from the
  disassembly alone.
- The `SchemaSystem_001` vtable slots used by `InstallSchemaBindings`. Only
  `+0xA8` and `+0xB0` are called from `0xA196B4`/`0xA196C8`; the rest of the
  interface is not exercised in the code I traced.
- Which specific ConVars are marked `FCVAR_CHEAT`. The flags are passed in `r8`
  and are usually a register, not an immediate, so they are not statically
  recoverable at most sites. `cl_ent_call`'s `0x4000` is an exception.
- The exact set of `CSource2Client` virtuals by name. Slot count (211) and
  addresses are exact; names are not, because MSVC RTTI does not encode method
  names and the interface has no string-identified dispatch.
- Whether `ClientBugBugServic001_Client` (the misspelled name at `0x1C63940`)
  is intentional. The misspelling is in the binary; the vtable at `0x1C65858`
  is real and populated, so the interface works regardless.

---

## 9. Summary of verified counts

| quantity | value | how verified |
|---|---|---|
| functions (`.pdata`) | 128,392 | `IMAGE_DIRECTORY_ENTRY_EXCEPTION` walk |
| `.text` size | 27,980,512 B | section header |
| exports | 6 | export directory |
| interfaces self-registered | 9 | scan of `jmp 0x19D0FD0` sites |
| interfaces in factory table | 115 | array walk at `0x1E618E0` |
| RTTI classes with vtable | 4,935 | COL scan |
| vtables total | 6,851 | COL → vftable[-1] scan |
| `CSource2Client` virtuals | 211 resolved (243 recorded) | vtable `0x1C68230` |
| `CPrediction` virtuals | 32 (+1 secondary) | vtable `0x1C76DE0` |
| `C_CSPlayerPawn` virtuals | 354 resolved (371 recorded) | vtable `0x1C8F288` |
| `C_CSWeaponBase` virtuals | 423 resolved (400 recorded) | vtable `0x1BDE520` |
| `C_BaseEntity` virtuals | 218 resolved (399 recorded) | vtable `0x1C4CD10` |
| ConVars | 1,695 unique | registrar scan |
| ConCommands | 321 unique | registrar scan |
| `cl_*` ConVars | 413 unique | registrar scan |
| functions with string refs | 27,194 | `strxref.py` |
| embedded `__FILE__` literals | 229 distinct | `.rdata` scan |
| largest function | 54,364 B at `0x18AB7C0` | `.pdata` |
| largest *identified* function | 31,095 B at `0x3C27F0` — the VScript global binding table (72 `Script_*` entries, `"C:\buildworker\...\src\public\tier0\utlrange.h"`, `"DMG_%s"`, `"Get a random float within a range"` → `Script_RandomFloat`, …) | strings + `.pdata` |

The 54,364-byte function at `0x18AB7C0` is the largest in the module. It has
**no** resolved string literals — it does not appear in `strxref.json` at all —
so it is reported by size only and is not attributed. It sits in the region
between the panorama style-property machinery (`0x1829C60` is
`src\panorama\layout\stylepropertyfactory.cpp`) and the particle-property code
(`0x1894780` is `src\particleslib\particle_property.cpp`), but adjacency is not
attribution, so I make no claim about what it does.
