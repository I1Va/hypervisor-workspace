# `networksystem.dll` — Source 2 networking, delta compression, and the snapshot encoder

Reverse-engineering notes for `csgo/bin/win64/networksystem.dll`, the module that
implements the Source 2 netchannel, the flattened-serializer delta encoder, and
the SteamNetworkingSockets transport for CS2.

Every claim is tied to an RVA in `networksystem.dll` with
`ImageBase = 0x180000000`. All sizes use the **merged chunk map** described in
§0, not raw `.pdata` record sizes. Names come from one of: an RTTI type
descriptor, a `__FILE__` literal, a `LoggingSystem`/`Error` format string, a
vtable slot, or a protobuf descriptor. Anything not proven that way is marked
**inferred** with the evidence that produced it.

Helper tooling written for this document lives in `scripts/net/`:

| file | contents |
|---|---|
| `net.py` | PE/capstone helper: `funcs()`, `mfuncs()`, `text()`, `strings()`, `refs_index()` |
| `rtti.py` | relaxed MSVC RTTI walk → 302 classes / 322 vtables (`/tmp/opencode/netcache/vtables.json`) |
| `ann.py` | per-function annotation: referenced strings + direct callees |
| `ndis.py` | annotated disassembly with rip-relative targets resolved |
| `pbenum.py` | protobuf `EnumDescriptorProto` extractor → `svc_`/`clc_`/`net_` IDs |
| `pbfull.py` | protobuf `FileDescriptorProto` extractor → full message/field schema |
| `cvars2.py` | ConVar name/help recovery |

---

## 0. Function boundaries in this image

The brief quotes **8,478 `.pdata` records** and a file size of 2,027,520 bytes.
Both need correction:

* the file on disk is **2,841,752 bytes**, SHA-256
  `94adbbf6bdbfeb047ea1bbbc0d8b155cc3e990e365c3beaedf5b09cb6c01d0d1`;
* 8,478 is exactly `101,736 / 12`, i.e. the `RUNTIME_FUNCTION` count in
  `.pdata`, **not** a function count.

As in `server.dll`, `.pdata` records are hot/cold **chunks**. The merge rule
(only the first chunk of a function starts 16-byte aligned; collapse each
contiguous non-aligned chunk onto its aligned head) gives:

| quantity | value |
|---|---|
| `.pdata` records | 8,478 |
| records starting 16-byte aligned | 4,678 |
| records exactly contiguous with predecessor | 4,103 |
| **merged functions** | **4,678** |
| median merged size | 209 bytes |
| total bytes covered | 2,012,678 |
| largest merged function | 12,481 bytes (`0xD5FD0`) |

So **4,678** is the real function count. Every size below is a merged size.
Note the converse trap too: many small virtual thunks and static initialisers
have **no** `.pdata` record at all (e.g. `CreateInterface` at `0x1C27E0`,
`0x1C27C0`, and all four interface-registrar thunks in §2). Their sizes are
measured to the `int3` padding instead.

---

## 1. Identity

### 1.1 Header facts

| property | value |
|---|---|
| path | `csgo/bin/win64/networksystem.dll` |
| size | 2,841,752 bytes |
| SHA-256 | `94adbbf6bdbfeb047ea1bbbc0d8b155cc3e990e365c3beaedf5b09cb6c01d0d1` |
| machine | `0x8664` (x86-64) |
| subsystem | 2 (`IMAGE_SUBSYSTEM_WINDOWS_GUI`) |
| image base | `0x180000000` |
| `SizeOfImage` | `0x2C5000` = 2,904,064 bytes |
| PE timestamp | `1793662329` → **2026-11-02 23:32:09 UTC** |
| checksum | `0x2C311D`, present and valid |
| DLL characteristics | `0x160` — `HIGH_ENTROPY_VA`, `DYNAMIC_BASE`, `NX_COMPAT`; **no** `GUARD_CF` |
| entry point RVA | `0x1DD050` |
| TLS callbacks | `0x1DCCC8`, `0x1DD5BC` |
| Authenticode | **present**, 11,416 bytes at RVA `0x2B3000` |

The timestamp is 2 days before `server.dll` (`1793836289`, 2026-11-04). Both
carry the same `0x160` characteristic mask and the same
`C:\buildworker\csgo_rel_win64\...` build root, so they are from the same
release train, but this DLL is a separate build job.

### 1.2 PDB

`RSDS` record at file offset `0x24A7F0` (RVA `0x23EB20` debug directory):

| field | value |
|---|---|
| GUID | `7593B982-A75F-4DD0-BB30-FEB3373B655A` |
| age | 13 |
| path | `C:\buildworker\csgo_rel_win64\build\_build_\networksystem\_vpc_networksystem\default\win64\_msvc_\Retail\networksystem.pdb` |

The PDB is **not** in the corpus and the DTB is offline, so no public symbols
are available. Every name in this document is recovered from in-image evidence.

### 1.3 Sections

| name | VA | vsize | rawsize | entropy |
|---|---|---|---|---|
| `.text` | `0x001000` | `0x203FAC` | `0x204000` | 6.53 |
| `.rdata` | `0x205000` | `0x06ACFA` | `0x06AE00` | 5.65 |
| `.data` | `0x270000` | `0x036568` | `0x026E00` | 1.47 |
| `.pdata` | `0x2A7000` | `0x018D68` | `0x018E00` | 6.25 |
| `.reloc` | `0x2C0000` | `0x004048` | `0x004200` | 5.42 |

`.rdata` is unusually large relative to `.text` (0.21 vs the 0.13 typical of
`server.dll`) because it carries the serialized **protobuf descriptor blobs** —
the full wire schema of every `svc_`/`clc_`/`net_` message is embedded as
`FileDescriptorProto` bytes (§3.2).

### 1.4 Exports

Six exports, all `extern "C"`:

| RVA | name | purpose |
|---|---|---|
| `0x112170` | `BinaryProperties_GetValue` | jump-table property getter (8 cases) |
| `0x1C27E0` | `CreateInterface` | interface factory, §2 |
| `0x112650` | `ExtractModuleMetadata` | TLS-slot keyed metadata extraction |
| `0x1DA960` | `GetResourceManifestCount` | returns `[rip+0xC76BA]` |
| `0x1DA970` | `GetResourceManifests` | manifest list walk |
| `0x1DA550` | `InstallSchemaBindings` | schema binding install, calls `0x1EC910` |

`CreateInterface` is the only export with networking significance.

### 1.5 Imports

204 from `tier0.dll`, 86 from `KERNEL32.dll`, 13 from
`steamnetworkingsockets.dll`, 12 from `steam_api64.dll`, 3 from `WS2_32.dll`,
1 from `ADVAPI32.dll`.

The `tier0` surface is dominated by `CUtlString`/`CBufferString`/`KeyValues`
and the bit-buffer primitives — notably `g_BitBuf_BitWriteMasks`, which is the
shared bit-writer mask table, confirming this module owns the bit-level wire
encoding rather than borrowing `engine2.dll`'s.

The `steamnetworkingsockets.dll` imports are the **flat C API vtable
accessors**, not the C++ classes:

```
SteamNetworkingSockets_LibV12          SteamDatagramServer_Init
SteamGameServerNetworkingSockets_LibV12 SteamDatagramServer_Kill
SteamNetworkingMessages_LibV2           SteamDatagramClient_Init
SteamNetworkingUtils_LibV4              SteamDatagramClient_InitSteam_InternalV1
SteamDatagram_SetAppID                  SteamDatagramServer_InitSteam_InternalV1
SteamDatagram_SetUniverse               SteamDatagram_Internal_SteamAPIKludge
```

`V_LZ4_compress_fast` / `V_LZ4_decompress_safe` come from `tier0`, which is how
`net_use_packet_compression` is implemented (§7).

---

## 2. `CreateInterface` and the interface registry

### 2.1 The lookup function

`CreateInterface` at `0x1C27E0` (94 bytes, no `.pdata` entry) is a textbook
Source 2 name lookup against a singly-linked list:

```
0x1c27e0  mov r9, [rip + 0xDF7A9]      ; r9 = g_pInterfaceList  (0x2A1F90)
0x1c27ed  test r9, r9
0x1c27f0  je 0x1c2820                  ; empty -> return NULL
0x1c27f2  mov rax, [r9 + 8]            ; node->name
0x1c27f6  mov r8, r11                  ; r11 = requested name
0x1c27f9  sub r8, rax
0x1c2800  movzx edx, byte [rax]        ; inline strcmp(name, requested)
0x1c2803  movzx ecx, byte [rax + r8]
0x1c2808  sub edx, ecx
0x1c280a  jne 0x1c2813
0x1c280c  inc rax
0x1c280f  test ecx, ecx
0x1c2811  jne 0x1c2800
0x1c2815  je 0x1c282f                  ; match -> tail-call factory
0x1c2817  mov r9, [r9 + 0x10]          ; next
0x1c282f  jmp qword ptr [r9]           ; call node->factory()
```

Node layout is `{ factory @+0x00, name @+0x08, next @+0x10 }`. The registrar at
`0x1C27C0` (29 bytes) allocates and pushes a node:

```
0x1c27c0  mov [rcx + 8], r8    ; name
0x1c27c4  mov [rcx], rdx       ; factory
0x1c27c7  mov rax, [rip + 0xDF7C2]  ; old head
0x1c27ce  mov [rcx + 0x10], rax     ; next = old head
0x1c27d5  mov [rip + 0xDF7B4], rcx  ; g_pInterfaceList = node
0x1c27dc  ret
```

`rdx` is an `int*` out-param for `IFACE_OK`/`IFACE_FAILED` (written `0` on
success, `1` on failure at `0x1C2825`/`0x1C2834`).

### 2.2 How interfaces get registered

There are **two** registration paths, and distinguishing them matters.

**Path A — the four core singletons.** Four static-initialiser thunks each
`jmp 0x1C27C0` with a name, a factory and a BSS singleton address:

| thunk | name (RVA of literal) | factory | singleton |
|---|---|---|---|
| `0x29A0` | `FlattenedSerializersVersion001` (`0x234078`) | `0xA1F40` | `0x277A50` |
| `0x3A30` | `NetworkMessagesVersion001` (`0x2385B0`) | `0xDDC20` | `0x2A3F30` |
| `0x3E70` | `NetworkSystemVersion001` (`0x23AFA8`) | `0xF2130` | `0x2911A0` |
| `0x4BF0` | `SerializedEntitiesVersion001` (`0x23BDF8`) | `0x10C770` | `0x291290` |

Each factory is the canonical `lea rax,[vtable]; ret` singleton accessor. The
returned object's first qword is the vtable, which closes the loop:

* `0x277A50` → `0x233A18` = `CFlattenedSerializers` vtable
* `0x2911A0` → `0x23A7A8` = `CNetworkSystem` vtable
* `0x291290` → `0x23E1F8` = `CSerializedEntities` vtable
* `0x2A3F30` is BSS; its ctor `0xDDC30` writes the `CNetworkMessages` vtable
  (`0x239A48`) at `[rip+0x1C62D0]` — see `0xDDC59`.

All four thunks sit in the `.CRT$XCU` static-initialiser array, which spans
`0x206000`–`0x206490` and holds **146** entries. The rest of that array is
module-level static construction (logging channels, allocators, small
`CUtlDict`/`CUtlRBTree` inits — the 46-byte stubs at `0x2010`, `0x2040`, …
that call `0x13ECE0`), **not** ConVar registration; see §7.5 for the actual
ConVar mechanism.

**Path B — the 115-entry factory table.** A `{name, factory}` array at
`0x2128C0`, consumed by the module init at `0x1BDB90`/`0x1BDD10`:

```
0x1bddca  cmp esi, 0x73        ; 0x73 = 115 entries
0x1bddc6  add rbx, 0x10        ; 16-byte stride
0x1bdd94  call qword ptr [r15 + rbp*8]   ; r15 = array of factory-fn pointers
0x1bdd98  mov [rdi], rax                 ; store created interface
```

`0x1BDB90` is driven from `0xF61C0` (243 bytes), which is `CNetworkSystem`
vtable slot 0 — i.e. the AppSystem `Connect`/init entry. The other driver,
`0x1BDF10`, walks the same table by name for `CreateInterface`-style lookups.

This 115-entry table is the module's **complete** `CreateInterface` surface —
`index/ifaces/networksystem.txt` lists exactly these names plus the four core
singletons. Note the table contains interfaces owned by *other* modules
(`Source2Server001`, `VEngineCvar007`, `ResourceSystem013`, …); networksystem
publishes them because it is the module that pulls the whole AppSystem graph
up, and `0x1BDB90` is what creates them.

Full table (`0x2128C0` + 16·i):

| # | name | factory |
|---|---|---|
| 0 | `VApplication001` | `0x2A1450` |
| 1 | `VEngineCvar007` | `0x2A1458` |
| 2 | `VStringTokenSystem001` | `0x2A1460` |
| 3 | `TestScriptMgr001` | `0x2A14A8` |
| 4 | `VProcessUtils002` | `0x2A1468` |
| 5 | `VFileSystem017` | `0x2A14F8` |
| 6 | `VAsyncFileSystem2_001` | `0x2A1500` |
| 7 | `ResourceSystem013` | `0x2A1530` |
| 8 | `ResourceManifestRegistry001` | `0x2A1540` |
| 9 | `ResourceHandleUtils001` | `0x2A1538` |
| 10 | `SchemaSystem_001` | `0x2A1520` |
| 11 | `ResourceCompilerSystem001` | `0x2A1528` |
| 12 | `VMaterialSystem2_001` | `0x2A1548` |
| 13 | `PostProcessingSystem_001` | `0x2A1550` |
| 14 | `InputSystemVersion001` | `0x2A1558` |
| 15 | `InputStackSystemVersion001` | `0x2A1560` |
| 16 | `RenderDeviceMgr001` | `0x2A14F0` |
| 17 | `RenderUtils_001` | `0x2A15D8` |
| 18 | `SoundSystem001` | `0x2A15E0` |
| 19 | `SoundOpSystemEdit001` | `0x2A15E8` |
| 20 | `SoundOpSystem001` | `0x2A15F0` |
| 21 | `SteamAudio001` | `0x2A15F8` |
| 22 | `VP4003` | `0x2A1568` |
| 23 | `Localize_001` | `0x2A14B8` |
| 24 | `VMediaFoundation001` | `0x2A1638` |
| 25 | `VAvi001` | `0x2A1640` |
| 26 | `VWebm001` | `0x2A1630` |
| 27 | `VBik001` | `0x2A1648` |
| 28 | `MeshSystem001` | `0x2A1600` |
| 29 | `MeshUtils001` | `0x2A1608` |
| 30 | `RenderDevice003` | `0x2A15C0` |
| 31 | `VRenderDeviceSetupV001` | `0x2A15C8` |
| 32 | `RenderHardwareConfig002` | `0x2A15D0` |
| 33 | `SceneSystem_002` | `0x2A1610` |
| 34 | `IPulseSystem_001` | `0x2A1618` |
| 35 | `SceneUtils_001` | `0x2A1620` |
| 36 | `WorldRendererMgr001` | `0x2A1650` |
| 37 | `AssetSystem001` | `0x2A1508` |
| 38 | `AssetSystemTest001` | `0x2A1510` |
| 39 | `ParticleSystemMgr003` | `0x2A1680` |
| 40 | `VScriptManager010` | `0x2A1628` |
| 41 | `PropertyEditorSystem_001` | `0x2A1518` |
| 42 | `MATCHFRAMEWORK_001` | `0x2A1570` |
| 43 | `Source2V8System001` | `0x2A1580` |
| 44 | `PanoramaUIEngine001` | `0x2A1588` |
| 45 | `PanoramaUIClient001` | `0x2A1590` |
| 46 | `PanoramaTextServices001` | `0x2A1598` |
| 47 | `ToolFramework2_002` | `0x2A1688` |
| 48 | `PhysicsBuilderMgr001` | `0x2A16A0` |
| 49 | `VisBuilder_001` | `0x2A1698` |
| 50 | `BakedLODBuilderMgr001` | `0x2A16A8` |
| 51 | `HelpSystem_001` | `0x2A1470` |
| 52 | `ToolSceneNodeFactory_001` | `0x2A1478` |
| 53 | `EconItemToolModel_001` | `0x2A1480` |
| 54 | `SchemaTestExternal_Two_001` | `0x2A1488` |
| 55 | `SchemaTestExternal_One_001` | `0x2A1490` |
| 56 | `AnimationSystem_001` | `0x2A1498` |
| 57 | `AnimationSystemUtils_001` | `0x2A14A0` |
| 58 | `HammerMapLoader001` | `0x2A1690` |
| 59 | `MaterialUtils_001` | `0x2A14C0` |
| 60 | `FontManager_001` | `0x2A14C8` |
| 61 | `TextLayout_001` | `0x2A14D0` |
| 62 | `AssetPreviewSystem_001` | `0x2A14E0` |
| 63 | `AssetBrowserSystem_001` | `0x2A14E8` |
| 64 | `AssetRenameSystem_001` | `0x2A14D8` |
| 65 | `VConComm001` | `0x2A1578` |
| 66 | `MODEL_PROCESSING_SERVICES_INTERFACE_001` | `0x2A14B0` |
| 67 | `NetworkSystemVersion001` | `0x2A1658` |
| 68 | `NetworkMessagesVersion001` | `0x2A1660` |
| 69 | `FlattenedSerializersVersion001` | `0x2A1668` |
| 70 | `SerializedEntitiesVersion001` | `0x2A1670` |
| 71 | `DemoUpconverterVersion001` | `0x2A1678` |
| 72 | `Source2Client002` | `0x2A16D8` |
| 73 | `Source2ClientUI001` | `0x2A16E0` |
| 74 | `Source2ClientPrediction001` | `0x2A1738` |
| 75 | `Source2Server001` | `0x2A16F0` |
| 76 | `Source2Host001` | `0x2A1708` |
| 77 | `Source2ModTools001` | `0x2A1710` |
| 78 | `Source2GameClients001` | `0x2A16F8` |
| 79 | `Source2GameEntities001` | `0x2A1700` |
| 80 | `EngineServiceMgr001` | `0x2A1740` |
| 81 | `HostStateMgr001` | `0x2A1748` |
| 82 | `NetworkService_001` | `0x2A1750` |
| 83 | `NetworkClientService_001` | `0x2A1758` |
| 84 | `NetworkP2PService_001` | `0x2A1760` |
| 85 | `NetworkServerService_001` | `0x2A1768` |
| 86 | `ToolService_001` | `0x2A1770` |
| 87 | `RenderService_001` | `0x2A1788` |
| 88 | `StatsService_001` | `0x2A1790` |
| 89 | `VProfService_001` | `0x2A1798` |
| 90 | `InputService_001` | `0x2A17A0` |
| 91 | `MapListService_001` | `0x2A17A8` |
| 92 | `GameUIService_001` | `0x2A17B0` |
| 93 | `SoundService_001` | `0x2A17B8` |
| 94 | `BenchmarkService001` | `0x2A17C0` |
| 95 | `KeyValueCache001` | `0x2A17C8` |
| 96 | `ClientServerSharedHandleSystem001` | `0x2A17D0` |
| 97 | `GameResourceServiceClientV001` | `0x2A17E8` |
| 98 | `GameResourceServiceServerV001` | `0x2A17F0` |
| 99 | `Source2EngineToClient001` | `0x2A1718` |
| 100 | `Source2EngineToServer001` | `0x2A1720` |
| 101 | `Source2EngineToServerStringTable001` | `0x2A1728` |
| 102 | `Source2EngineToClientStringTable001` | `0x2A1730` |
| 103 | `VPhysics2_Interface_001` | `0x2A16B0` |
| 104 | `ModelDocUtils001` | `0x2A15A8` |
| 105 | `SmartPropsSystem_001` | `0x2A15B0` |
| 106 | `AnimGraphEditorUtils001` | `0x2A15B8` |
| 107 | `EXPORTSYSTEM_INTERFACE_VERSION_001` | `0x2A16B8` |
| 108 | `ServerToolsInfo_001` | `0x2A1778` |
| 109 | `ClientToolsInfo_001` | `0x2A1780` |
| 110 | `Vrad3_001` | `0x2A16D0` |
| 111 | `NavSystem001` | `0x2A16C0` |
| 112 | `NavGameTest001` | `0x2A16C8` |
| 113 | `LocalServerClientAccess001` | `0x2A17D8` |
| 114 | `ClientLocalServerAccess001` | `0x2A17E0` |

The factory slots live in `.data` at `0x2A1450`–`0x2A17F0`, each holding an
absolute VA to a factory function.

---

## 3. The wire protocol

### 3.1 Message classes

Source 2 uses three independent protobuf enums, all present in the `.rdata`
descriptor blobs:

| enum | id range | direction |
|---|---|---|
| `NET_Messages` | 0–15 | connection-control, both directions |
| `CLC_Messages` | 20–37 | client → server |
| `SVC_Messages` | 40–78 | server → client |
| `Bidirectional_Messages` | 16–19 | either (rebroadcast/prediction) |

Extracted verbatim from the embedded `EnumDescriptorProto` (see `pbenum.py`):

**`NET_Messages`** (`0x22BDFA`)

| id | name |
|---|---|
| 0 | `net_NOP` |
| 1 | `net_Disconnect_Legacy` |
| 3 | `net_SplitScreenUser` |
| 4 | `net_Tick` |
| 5 | `net_StringCmd` |
| 6 | `net_SetConVar` |
| 7 | `net_SignonState` |
| 8 | `net_SpawnGroup_Load` |
| 9 | `net_SpawnGroup_ManifestUpdate` |
| 11 | `net_SpawnGroup_SetCreationTick` |
| 12 | `net_SpawnGroup_Unload` |
| 13 | `net_SpawnGroup_LoadCompleted` |
| 15 | `net_DebugOverlay` |

**`CLC_Messages`** (`0x22398B`)

| id | name |
|---|---|
| 20 | `clc_ClientInfo` |
| 21 | `clc_Move` |
| 22 | `clc_VoiceData` |
| 23 | `clc_BaselineAck` |
| 25 | `clc_RespondCvarValue` |
| 27 | `clc_LoadingProgress` |
| 28 | `clc_SplitPlayerConnect` |
| 30 | `clc_SplitPlayerDisconnect` |
| 31 | `clc_ServerStatus` |
| 33 | `clc_RequestPause` |
| 34 | `clc_CmdKeyValues` |
| 35 | `clc_RconServerDetails` |
| 36 | `clc_HltvReplay` |
| 37 | `clc_Diagnostic` |

**`SVC_Messages`** (`0x223AD9`)

| id | name | | id | name |
|---|---|---|---|---|
| 40 | `svc_ServerInfo` | | 60 | `svc_PeerList` |
| 41 | `svc_FlattenedSerializer` | | 61 | `svc_PacketReliable` |
| 42 | `svc_ClassInfo` | | 62 | `svc_HLTVStatus` |
| 43 | `svc_SetPause` | | 63 | `svc_ServerSteamID` |
| 44 | `svc_CreateStringTable` | | 70 | `svc_FullFrameSplit` |
| 45 | `svc_UpdateStringTable` | | 71 | `svc_RconServerDetails` |
| 46 | `svc_VoiceInit` | | 72 | `svc_UserMessage` |
| 47 | `svc_VoiceData` | | 74 | `svc_Broadcast_Command` |
| 48 | `svc_Print` | | 75 | `svc_HltvFixupOperatorStatus` |
| 49 | `svc_Sounds` | | 76 | `svc_UserCmds` |
| 50 | `svc_SetView` | | 77 | `svc_NextMsgPredicted` |
| 51 | `svc_ClearAllStringTables` | | 78 | `svc_EncryptedData` |
| 52 | `svc_CmdKeyValues` | | | |
| 53 | `svc_BSPDecal` | | | |
| 54 | `svc_SplitScreen` | | | |
| **55** | **`svc_PacketEntities`** | | | |
| 56 | `svc_Prefetch` | | | |
| 57 | `svc_Menu` | | | |
| 58 | `svc_GetCvarValue` | | | |
| 59 | `svc_StopSound` | | | |

**`Bidirectional_Messages`** (`0x224015`): 16 `bi_RebroadcastGameEvent`,
17 `bi_RebroadcastSource`, 18 `bi_GameEvent_DEPRECATED`, 19 `bi_PredictionEvent`.

The gaps (2, 10, 14, 24, 26, 29, 32, 64–69, 73) are retired IDs; the enum
retains them as holes. `SVC_Messages_LowFrequency` (`0x223FEC`) and
`svc_dummy` (`0x224009`) are marker strings, not enum members.

### 3.2 Why a string xref sweep finds nothing

This is the methodological trap that produced the wrong conclusion in
`server.md` §Unknowns item 5. All of `svc_PacketEntities`, `clc_BaselineAck`,
`net_Tick`, `SVC_Messages`, `CLC_Messages` and `NET_Messages` appear **exactly
once** in the image, as bytes *inside* a serialized `FileDescriptorProto`:

```
0x223980: ... 2a cb 02 0a 0c 43 4c 43 5f 4d 65 73 73 61 67 65 73 ...
                ^^ field-5 tag (enum_type)  ^^ len  ^^ "CLC_Messages"
```

There is **no** pointer to them and **no** `.text` reference — verified here by
a full rip-relative sweep (`refs_index()`) *and* a raw 8-byte pointer scan over
`.rdata`/`.data`. The message catalogue is looked up through the **protobuf
descriptor pool** at runtime, not through a string table. That is why
`server.md`'s observation ("zero `.text` references") was correct but its
conclusion ("the encoder is not in this module") was wrong: the same is true
*inside* `networksystem.dll`, where the encoder demonstrably lives.

### 3.3 The message schemas

Parsed from the two descriptor blobs (`netmessages.proto` at `0x221210`,
`networkbasetypes.proto` at `0x22AE70`). The ones that matter:

**`CSVCMsg_PacketEntities`** — the snapshot message (field numbers are exact):

| # | field | type | meaning |
|---|---|---|---|
| 1 | `max_entries` | int32 | entity slot count |
| 2 | `updated_entries` | int32 | entities written this frame |
| 3 | `legacy_is_delta` | bool | old-style delta flag |
| 4 | `update_baseline` | bool | client must rebase |
| 5 | `baseline` | int32 | baseline number |
| 6 | `delta_from` | int32 | **tick the delta is computed against** |
| 7 | `entity_data` | bytes | legacy bit-packed entity block |
| 8 | `pending_full_frame` | bool | full-frame pending |
| 9 | `active_spawngroup_handle` | uint32 | |
| 10 | `max_spawngroup_creationsequence` | uint32 | |
| 11 | `last_cmd_number_executed` | uint32 | |
| 12 | `server_tick` | uint32 | |
| 13 | `serialized_entities` | bytes | **flattened-serializer payload** |
| 15 | `alternate_baselines` | msg[] | `{entity_index, baseline_index}` |
| 16 | `has_pvs_vis_bits_deprecated` | uint32 | |
| 17 | `last_cmd_number_recv_delta` | sint32 | |
| 19 | `non_transmitted_entities` | msg | `{header_count, data}` |
| 20 | `cq_starved_command_ticks` | uint32 | |
| 21 | `cq_discarded_command_ticks` | uint32 | |
| 22 | `cmd_recv_status` | sint32 | |
| 23 | `outofpvs_entity_updates` | msg | `{count, data}` |
| 999 | `dev_padding` | bytes | |

Field 7 `entity_data` and field 13 `serialized_entities` are the two coexisting
encodings: the legacy Source 1-style block and the Source 2 flattened-serializer
block. CS2 uses **13**.

**`CSVCMsg_FlattenedSerializer`** — the schema handshake sent once per class:

| # | field | type |
|---|---|---|
| 1 | `serializers` | `ProtoFlattenedSerializer_t[]` |
| 2 | `symbols` | string[] |
| 3 | `fields` | `ProtoFlattenedSerializerField_t[]` |
| 4 | `coord_size_params` | `ProtoCoordSizeParams_t` |

`ProtoFlattenedSerializer_t` = `{serializer_name_sym, serializer_version,
fields_index[]}`. `ProtoFlattenedSerializerField_t` = `{var_type_sym,
var_name_sym, bit_count, low_value, high_value, encode_flags,
field_serializer_name_sym, field_serializer_version, send_node_sym,
var_encoder_sym, polymorphic_types[], var_serializer_sym, var_enum_info}`.
`ProtoCoordSizeParams_t` carries `coord_integer_bits`,
`coord_fractional_bits`, `coord_integer_bits_mp`,
`coord_fractional_bits_mp`, `normal_fractional_bits`, `angle_bits`.

This is the whole point of the design: the **server never ships field names on
the wire**. It ships an integer-symbol table once, then refers to fields by
`fields_index` forever after.

**`CCLCMsg_BaselineAck`** — client acknowledges a baseline:
`{baseline_tick int32 = 1, baseline_nr int32 = 2}`.

**`CNETMsg_Tick`** — `{tick, host_computationtime,
host_computationtime_std_deviation, legacy_host_loss, host_unfiltered_frametime,
hltv_replay_flags, expected_long_tick, expected_long_tick_reason,
host_frame_dropped_pct_x10, host_frame_irregular_arrival_pct_x10}`.

**`CNETMsg_SignonState`** — `{signon_state SignonState_t, spawn_count,
num_server_players, players_networkids, map_name, addons}`.

`SignonState_t`: `NONE 0, CHALLENGE 1, CONNECTED 2, NEW 3, PRESPAWN 4, SPAWN 5,
FULL 6, CHANGELEVEL 7`.

### 3.4 Framing

A netchannel packet is built by `CNetChan::Transmit` (`0xBE6E0`, 3,732 bytes)
and parsed by `CNetChan::ParseMessages` (`0xC00B0`, 3,559 bytes). The debug
spew strings give the header fields exactly:

```
0x237B38  UDP <- %s: sz=%5i seq=%5i ack=%5i rel=%1i tm=%8.3f
0x237240  UDP -> %s: sz=%5i seq=%5i ack=%5i rel=%1i tm=%8.3f
```

so the header is `{seq, ack, rel}` plus a timestamp. Above that sit the
SteamNetworkingSockets "SNP" frame layers:

```
0x2379D0  %8.3f: %s: ParseMessagesSNP RELIABLE%s %d bytes
0x237B98  %8.3f: %s: ParseMessagesSNP UNRELIABLE%s Seq=%d %d bytes
```

Reliable and unreliable payloads are separately sequence-numbered and
separately framed (`%s` is `(compressed)` when `net_use_packet_compression`
fired — string at `0x2379C0`). Each frame carries its own uncompressed size,
checked at `0xC2FEB` (`Unreasonable unreliable nUncompressedSize (%d).`) and
`0xC34C3` (reliable equivalent).

Three logical buffers are named at `0x236E10`/`0x236E30`/`0x236F30`:
`CNetChan::BUF_UNRELIABLE`, `CNetChan::BUF_RELIABLE`, `CNetChan::BUF_VOICE`.
Buffer management is `0xBBA50` (2,077 bytes); `CNetChan::SendData` is `0xC3B20`.

### 3.5 Dispatch

`CNetChan::ParseMessages` (`0xC00B0`) reads the message type with the helper at
`0xE28B0` (272 bytes), called once from `0xC0272`. The encoding is a
**nibble-prefixed varint**, not a plain 6-bit field:

```
0xe28b0  ... r9d = bit position, edx = bit count
0xe28e0  cmp eax, 6                  ; at least 6 bits available?
0xe2920  (6-iteration bit loop)      ; read 6 bits into edi
0xe2987  and edi, 0x3f
0xe298a  test dil, 0x30              ; bits 4..5 = width class
0xe2990  call 0x1bf5c0               ; escape -> ReadUBitVar-style extension
```

The escape target `0x1BF5C0` computes the extension width from the same two
bits (`0x1BF5CC`–`0x1BF5EF`): `r8d = (v >> 4) & 3`, then
`extra = (2 - r8d) < 0 ? 16 : 0` added to `r8d * 4`. Working that out:

| bits 4..5 | extra bits | total width | value range |
|---|---|---|---|
| 0 | 0 | 6 | 0–15 |
| 1 | 4 | 10 | 0–255 |
| 2 | 8 | 14 | 0–4095 |
| 3 | 28 | 34 | 0–2³²−1 |

The value is reassembled at `0x1BF712`–`0x1BF719` as
`and r15d,0xF` / `shl eax,4` / `or eax,r15d`, i.e. `(extension << 4) | (first6
& 0xF)`. So **`net_*` message types 0–15 cost 6 bits; `clc_*` (20–37) and
`svc_*` (40–78) cost 10 bits.** That the low range is reserved for
`NET_Messages` is visible directly in the enum in §3.1, and it is why per-tick
control traffic is cheaper than per-tick entity traffic.

After the type is read, `0xC00B0` looks up the handler and special-cases two:

```
0xc02fc  mov ecx, [rax + 0x18]     ; message type id
0xc02ff  cmp ecx, 4
0xc0302  jne 0xc0309
0xc0304  mov edi, [rdi + 0x50]     ; net_Tick -> tick field
0xc0309  cmp ecx, 0x37             ; 0x37 = 55 = svc_PacketEntities
0xc030e  mov edi, [rdi + 0xC0]     ; -> entity/command bookkeeping
```

The actual handler call is a virtual dispatch at `0xC0409`:

```
0xc0402  mov rcx, [rsi + 8]
0xc0406  mov rax, [rcx]
0xc0409  call qword ptr [rax + 0x40]   ; binding->HandleMessage()
```

`[rsi+8]` is the per-message `IProtobufBinding` instance; slot `+0x40` is its
deserialise-and-dispatch entry. `CNetworkMessages::ConfirmAllMessageHandlersInstalled`
(`0xE3190`) validates that every registered message has a handler before the
channel is allowed to run — failure is
`"Error installing message handlers into a net channel: missing handlers in
channel %s!"` (`0x239600`).

`CNetChan::ProcessMessages` (`0xC10B0`, 3,123 bytes) is the pump around it and
enforces a CPU budget:

* `0x237550` `"[%s] DISCONNECTING. ProcessMessages has exhausted its CPU time budget."`
* `0x237650` warning-budget variant
* `0x2376E0` `"Too many incoming messages on channel (%s) %d remain queued, limit per-frame is %d."`
* `0x237890` `"Too many queued messages on channel (%s) %d queued, limit is %d."`

---

## 4. Delta compression and snapshot encoding

This is the core of the module. Everything in this section is implemented
here, and **only** here — verified in §4.0.

### 4.0 Correcting the `server.dll` claim

`server.md` §4.2/§Unknowns-5 states that the delta encoder is not in
`server.dll` and points at `networksystem.dll`. That is **correct**, and it can
now be stated much more strongly. Byte-frequency of the identifying strings:

| string | `server.dll` | `networksystem.dll` |
|---|---|---|
| `CFlattenedSerializer::Encode` | **0** | 7 |
| `CFlattenedSerializer::MergeDeltas` | **0** | 5 |
| `CDeltaCalculator` | **0** | 5 |
| `BuildMergedSerializedEntity` | **0** | 4 |
| `CNetChan::ProcessMessages` | **0** | 1 |

`server.dll` contains `CNetworkSerializerClassInfo` / `CNetworkSerializerFieldInfo`
(its binder layer: `CNetworkSerializerClassInfo::Get( %s ) failed!` at
`server.dll` RVA `0x177B3D8`) and the protobuf *type* strings, but **not one
byte** of the encoder. The split is:

* `server.dll` — field metadata + per-class binders + `CNetworkTransmitComponent`;
  it hands networksystem a `CSerializedEntity` buffer.
* `networksystem.dll` — `CFlattenedSerializer` (per class), `CDeltaCalculator`
  (per field), `CFlattenedSerializers` (the merge/snapshot builder), `CNetChan`
  (the transport).

`server.md`'s other claim — that `svc_PacketEntities` has zero `.text`
references — is *also* true inside `networksystem.dll` (§3.2), because the name
lives in a protobuf descriptor. The absence of an xref is therefore not
evidence of absence.

### 4.1 The metadata model

Four classes, all RTTI-confirmed:

| class | vtable | slots | role |
|---|---|---|---|
| `CDeltaCalculator` | `0x233550` | 1 | per-field diff of one field between two states |
| `CFlattenedSerializer` | (per-class, not a single vtable) | — | one class's field layout + encode/decode |
| `CFlattenedSerializers` | `0x233A18` | 45 | the registry and the snapshot builder |
| `CSerializedEntities` | `0x23E1F8` | 23 | per-entity state store and baseline compare |

`CDeltaCalculator`'s single vtable slot is `0x63100` (560 bytes), which is the
`ErrorMsg` reporter — so the class is used through non-virtual methods and the
vtable exists only for the error interface. Its constructor is
`0x5EFD0` (621 bytes), identified by the two format strings it installs:

```
0x230D88  CDeltaCalculator::FieldCalcDelta fromBits
0x230E10  CDeltaCalculator::FieldCalcDelta toBits
```

The ctor zeroes a ~0x990-byte object and stores the "from" and "to"
`BitBuf`/field-descriptor pairs at `+0x10` and `+0x18` (`0x5F1EC`–`0x5F203`),
then computes bit counts as `(bit_count + 7) >> 3` (`0x5F18A`). That tells us
the calculator works on **two byte buffers plus per-field bit ranges**, not on
live C++ objects.

### 4.2 The per-field delta: `CalcDelta`

`CFlattenedSerializer::CalcDelta` at `0x70B00` (798 bytes) is the entry. It:

1. rejects `from == to` and mismatched serializer/version
   (`cmp r14d,[r9+0x30]` / `cmp eax,[r9+0x34]` at `0x70BB1`/`0x70BBB`);
2. `memcmp`s the two field buffers (`0x70BD1` → `0x1FE580`);
3. compares the field-path arrays element-wise (`0x70BE0`–`0x70BF8`);
4. constructs a `CDeltaCalculator` (`0x70C6C` → `0x5EFD0`) and calls the
   per-field worker at `0x63330` (1,765 bytes).

If the two states are byte-identical the whole class is skipped — this is the
`net_skip_redundant_change_callbacks` / `SkipRedundantChangeCallbacks` fast path
(`0x2341B8`, `0x234190`).

### 4.3 `CFlattenedSerializer` — the per-class codec

Per-class functions, all identified by their own error strings:

| RVA | size | function |
|---|---|---|
| `0x66370` | 1,407 | `BuildHierarchy_R` — builds the field tree, assigns depth |
| `0x68AB0` | 934 | `GatherSendProxyResults_R` |
| `0x69680` | 1,178 | `GatherBranchChanges_R` |
| `0x69B20` | **7,239** | `EncodeField` |
| `0x6BBE0` | 1,624 | `Encode` |
| `0x6DE20` | **6,694** | `Decode` |
| `0x72920` | 3,877 | `BuildDeltaProperties` |
| `0x73A80` | 4,000 | `WriteFieldList` |
| `0x74AC0` | **8,864** | `MergeDeltas` |
| `0x7B7F0` | 905 | `IsEqualSerializer` |
| `0x7F340` | 3,349 | `ApplyOverrides_R` |
| `0x80470` | 4,558 | `BuildOverrideField` |
| `0x83500` | 5,055 | `ValidateSerializedEntity` |
| `0x848C0` | 2,560 | `DumpSerializedEntityToConsole` |
| `0x85410` | 3,869 | `RemoveArrayElementsOutsideOfArrayMetadataBounds` |
| `0x86E10` | 3,060 | `MaybeWriteFlattenedSerializers_R` |

`EncodeField` (`0x69B20`) is the bit writer. Its prologue indexes an array of
**46-byte records** by `[serializer+0xDC]`:

```
0x69b67  movsxd r9, dword ptr [r11 + 0xDC]   ; field index
0x69b71  mov    rax, qword ptr [r11 + 8]
0x69b75  imul   rdx, r9, 0x2E                 ; 46-byte stride
0x69b79  mov    rax, qword ptr [rax + 0x30]   ; record array base
0x69b7d  add    rax, rdx
0x69b8b  movzx  ecx, byte ptr [rax + 0x2C]     ; encoder-kind byte
```

It then dispatches on `[record+0x2C]` (the encoder kind) and writes through
`g_BitBuf_BitWriteMasks`. The 46-byte record is consistent with a packed
`FlattenedSerializerField_t`, but the field-by-field layout of that record is
**not** fully mapped here (see §9).

`Encode` (`0x6BBE0`) is the frame around it: it sizes the destination, calls
`EncodeField` per changed field, and emits the two failure modes

```
0x231670  CFlattenedSerializer::Encode overflow failure for entity %d max size is %d bytes
0x2316F0  CFlattenedSerializer::Encode failure for entity %d
```

`Decode` (`0x6DE20`) mirrors it, with bounds checking:
`"CFlattenedSerializer::[ent %d] Decode path %s array index %d out of range %d
for field %s::%s [%d] %s"` (`0x231920`).

`WriteFieldList` (`0x73A80`) writes the field-path list for one entity — the
sequence of `CFieldPath`s that the delta actually touches.

### 4.4 Field paths and the Huffman encoder

A `CFieldPath` is the compact identity of one field within a nested struct
(`foo.bar[3].baz`). Paths are the unit of delta encoding: the wire says
"path 17 changed, here are N bits", never "field name X changed".

Evidence:

* RTTI declares a dedicated Huffman coder — `CFieldPathHuffmanEncoder` with
  `INode`/`InternalNode`/`LeafNode` (`0x294EB8`, `0x294EF0`, `0x294F30`,
  vtables `0x214490`, `0x2144A8`, `0x2144C0`);
* `CFieldPath::AddToTail` is `0x1D8EF0` (352 bytes) and `CFieldPath` path
  storage is `CUtlLeanVectorFixedGrowableBase<CFieldPath::Path_t,6,...>`
  (vtable `0x232F10`) — a 6-element inline path, heap-growing beyond;
* the depth limit is enforced with
  `"Path_SetCount failed, depth already == DEFAULT_MAX_PATH_DEPTH(%d)"`
  (`0x22FD90`);
* `fieldpathpacker.cpp` is a `__FILE__` literal (`0x2144D0`) referenced from
  `0x1D8EF0` and `0x1D91C0`;
* `FieldPathEncodeFinish` (`0x214470`) names the encode-termination step.

So the encoder is: **collect changed `CFieldPath`s → Huffman-code the path
indices → write each field's bits**. The Huffman table is rebuilt per
serializer from the observed change distribution, which is why
`BuildDeltaProperties` (`0x72920`) exists and why it logs
`"CFlattenedSerializer::BuildDeltaProperties using %d bytes for encoding
%d/%s"` (`0x231B00`).

`CDeltaFieldPathTracer` (`0x233C38`, slot `0xA3530`) and the
`net_why_field_excluded` / `net_permutation_info` / `net_spewserializer`
ConVars are the diagnostics for this layer.

### 4.5 The snapshot builder: `BuildMergedSerializedEntity`

The single most important function for the "how does a snapshot get built"
question is vtable slot **12** of `CFlattenedSerializers`:

**`0xA6560`, 8,825 bytes — `CFlattenedSerializers::BuildMergedSerializedEntity`.**

Confirmed by four of its own format strings:

```
0x2346C0  BuildMergedSerializedEntity:  delta header with corrupt array count [ ent %d ]:  entry %d/%d == %u!
0x234730  BuildMergedSerializedEntity:  ignoring %s, was in previous state only, now outside of valid range for root field %s [array count %d, base index %d]
0x234810  CFlattenedSerializers::BuildMergedSerializedEntity fieldDataBuf
0x2348F0  BuildMergedSerializedEntity:  problem writing %s:  %d bits [%d to %d] is < 1 bit!
```

plus the helper `CMergedEntityOffsetBuilder::AddToTail` (`0x2344F0`) and its
assertion `"Expecting at least one bit in offset"` (`0x2345D0`) and
`"delta >= 1u"` (`0x2345B8`).

What it does, reconstructed from the messages and the control flow:

1. For each entity it has a **previous** state and a **next** state.
2. It walks both field-path sets. A field present in both becomes a delta;
   a field present only in the previous state and now out of range is dropped
   (the `"ignoring %s, was in previous state only..."` path).
3. Array counts are re-validated against the baseline's array metadata; a
   mismatch is the `"corrupt array count"` fatal.
4. It appends `CMergedEntityOffsetBuilder` offsets — the (start bit, length)
   pairs that let the decoder skip unchanged regions.
5. It writes into `fieldDataBuf` and refuses any field that would occupy
   `< 1 bit`, which is the guard against pathological zero-width encodings
   (the four `"0 bit issue, spot N"` strings at `0x234868`, `0x234850`,
   `0x234948`, `0x234898`).

The result is the `serialized_entities` blob (field 13) of
`CSVCMsg_PacketEntities`.

`MergeDeltas` (`0x74AC0`, 8,864 bytes) is the sibling used when two partial
deltas must be combined — e.g. a field changed, then changed again before the
tick was sent. It reports the merge state per field as one of the literals
`previous only` (`0x231CC8`), `next state only` (`0x231D40`), `both states`
(`0x231D08`), `writing (in %s)` (`0x231D30`).

### 4.6 Baseline handling

Baselines are how the client can decode a delta without having received every
intermediate tick.

* The client acks a baseline with `CCLCMsg_BaselineAck {baseline_tick,
  baseline_nr}` (id 23).
* The server tracks per-entity alternate baselines via
  `CSVCMsg_PacketEntities.alternate_baselines[] = {entity_index,
  baseline_index}` (field 15) — so different entities can be delta'd against
  different baselines in the same packet.
* `CSerializedEntities::CompareSerializedEntities` (`0x109DC0`, 6,074 bytes,
  vtable `0x23E1F8` slot 10) is the baseline differ. Its strings pin the
  semantics:
  `"CompareSerializedEntities from field %s '%s' not present in to"` and the
  mirror, plus
  `"CompareSerializedEntities field %d path's differ from %s '%s' to %s '%s'"`.
  It also validates that both sides use the same serializer:
  `"from serializer is '%s' and to serializer is '%s', comparison doesn't make
  sense!"`.
* `update_baseline` (field 4) and `delta_from` (field 6) on the wire tell the
  client which tick to diff against.

The entity state itself is stored in `CSerializedEntity` objects allocated from
a pool controlled by `net_serializedentitymemory` /
`NetworkSystem/UseSerializedEntityPool` (`0x23DA30`), with the accounting
command `net_serializedentitymetadatainfo` printing
`"Average Memory Usage Per Entity   :  %8.3f bytes"` (`0x23DD80`).

### 4.7 Field-change callbacks

Separate from the wire delta is the *game-side* change notification. The
`CNetworkFieldChangedEventQueue` (vtable `0x2339A8`, 13 slots) queues
`MNetworkChangeCallback` / `MNetworkChangeTag` invocations so that a field
written by the server's simulation also fires the game's `NetworkVar`
callbacks.

| RVA | size | function |
|---|---|---|
| `0xB0EE0` | 2,105 | `QueueChange` |
| `0xB1720` | 825 | `QueueChange` (replay-compat variant) |
| `0xB1A60` | 1,560 | queue dispatch |
| `0xB3490` | 58 | slot 0 |
| `0xB0A10` | 1,218 | `QueueReplayCompatFieldChange` |

`QueueChange` fails with
`"CNetworkFieldChangedEventQueue::QueueChange:  ran out of scratch data space!!!"`
(`0x234ED0`) and spews per-change traces under `net_spewcounts`.

`CNetworkMessages::InitNetworkChangeTag` (`0xEC420`, 6,239 bytes) installs the
tag machinery and hard-fails if `CEntitySystem::Init` did not provide the
callback:
`"CNetworkMessages::InitNetworkChangeTag - missing m_NetworkChangeTagCallback,
should have been installed by CEntitySystem::Init call to g_pNetworkMessages"`
(`0x2391B0`).

### 4.8 Encoding statistics

`CNetworkEncodingStats` (vtable `0x22FD20`, 6 slots) collects the per-field
cost. Exposed as the `encoding_stats` ConVar and the `vcon_NetworkEncodingStats_t`
console type (`0x22FD70`). Field names visible in the vcon dump include
`reliable_bits`, `unreliable_bits`, `incoming_sequence`, `outgoing_sequence`,
`avg_packet_in`, `avg_packet_out`, `avg_packet_loss`, `latency_seconds`,
`prediction_errors`, `client_update_rate`, `server_framerate`,
`unfiltered_server_framerate`, `server_framerate_stddev`,
`incoming_data_bytespersecond`, `outgoing_data_bytespersecond`.

---

## 5. Steam networking

### 5.1 Initialisation

`CNetworkSystem::InitSteamNetworking` (`0xF51E0`, 2,205 bytes) is the entry,
called from the AppSystem `Connect` at `0xF61C0`. Its strings tell the whole
story:

```
0x23B988  CNetworkSystem::Init() failed - no SteamNetworking()
0x23BA10  Got ISteamNetworkingSockets user interfaces from steam client
0x23BA50  No steam client; SDR features will be unavailable
0x23BB90  Got ISteamNetworkingSockets user interfaces from standalone lib
0x23BB10  SteamDatagramClient_InitSteam failed.  %s
0x23BB40  SteamDatagramClient_Init failed.  %s
0x23B9C0  Steam supporting smaller max routable packet than engine expecting (%d vs %d)
0x23B580  Allowing IP connections without auth
0x23BD20  Using Valve ICE implementation
```

The logic:

1. If a Steam client is present, take `SteamNetworkingSockets_LibV12` /
   `SteamNetworkingUtils_LibV4` from it and initialise the SDR client with
   `SteamDatagramClient_InitSteam_InternalV1`.
2. Otherwise load `steamnetworkingsockets.dll` standalone and use
   `SteamDatagramClient_Init`.
3. Store the interfaces in `g_pSteamNetworkingSockets` (`0x23BB68`) and
   `g_pSteamNetworkingUtils` (`0x23BC20`).
4. Query the max routable packet size and warn if it is below the engine's
   expectation (`0xF53F3`).

`CNetworkSystem::InitGameServer` (`0xF5A80`, 1,452 bytes) is the dedicated-server
mirror, storing `g_pSteamGameServerNetworkingSockets` (`0x23BCD0`) and calling
`SteamDatagramServer_Init`. It retries on failure:

```
0x23BE80  Failed to start listening for SDR on port %d.  Waiting and will retry
0x23BEC8  Socket '%s' listening for SDR on port %d virtual port %d
0x23BE20  CreateHostedDedicatedServerListenSocket for socket '%s' failed /+/ port %u vport %d
```

`CNetworkSystem::Shutdown` (`0xF6340`, 885 bytes) unwinds it and reports
`"Leaked channel %s remote %s"` (`0x23C080`) for channels that outlived the
socket.

### 5.2 P2P vs dedicated

Three distinct transports, selected by socket kind:

| mode | selection evidence |
|---|---|
| loopback | `"loopback:%d"` (`0x2366A0`) formatted in `CNetChan::Setup` (`0xBC6FC`) |
| direct UDP | `sv_listen_directudp` (`0x23B418`): *"Server will listen for direct UDP connections on the configured port. This can be turned off to only listen for P2P/SDR"* |
| SDR / P2P | `net_p2p_listen_dedicated` (`0x23B0F0`): *"Should dedicated server listen for new-style P2P?"* |

The socket-kind enum is read at `0xBC6CF` as `[rbx+0x1C]` where
`rbx = this+0x8E94` (set at `0xBC637`), i.e. it is `[this+0x8EB0]` — the
`netadrtype_t` of the remote address. Values 0–4 select the format: 0 and 4
fall through to a plain `"%s:%d"`, 1 uses `loopback:%d`, and 2/3 use the
`netadr_t::ToString` path (`0x111060`).

P2P connection establishment is `NetworkSystem/CreateListenSocketP2P`
(`0x23C358`) and `EstablishNewSteamNetConnection ConnectP2P(%s) failed`
(`0x23C4D8`). A shared/cached connection path exists:
`EstablishCacheableSharedNetConnection(%s) failed` (`0x23C3D8`) and
`"Established cacheable shared Steam Net Connection to '%s'"` (`0x23C410`),
with `CacheableConnectionExpired` (`0x23C1B8`).

### 5.3 The receive path

`CNetworkSystem::PollSocket` (`0xF7E00`, 1,989 bytes) pumps the poll group:

```
0x23C1F0  %8.3f: PollSocket(%d)
0x23C208  UDP <- %s: sz=%i OOB (%d)
0x23C230  Netchan [%s] already associated with hconn #%u, but now we are getting messages on new hconn #%u using the same 'from' address
0x23B5B0  Can't match up steam connection user data %lld to netchan...
```

It calls `CNetworkSystem::GetPacket` (`0xF7A60`, 660 bytes), which drains
`SteamNetworkingSockets()->ReceiveMessagesOnPollGroup` and maps the Steam
connection handle back to a `CNetChan`:

```
0x23C0D8  CNetworkSystem::GetPacket
0x23C100  Got message on poll group for socket %s, but cannot find connection in table?
0x23C1D8  inpacket.message
```

The per-frame UDP parse is `0xC2230` (4,881 bytes), which is where the
reliability bookkeeping lives (§6).

### 5.4 `net_option` and the SteamNetworkingUtils options

`net_option` (`0x23CC78`) is a thin command over
`ISteamNetworkingUtils::SetConfigValue`. Its strings:

```
0x23CDC0  Get or set SteamNetworkingSockets options such as fake packet lag and loss
0x23CE10  net_option %s = %s
0x23CED8  SteamNetworkingSockets config option not found
0x23CF70  SteamNetworkingSockets not yet initialized.  Queuing command '%s'
0x23CFB8  Not allowed to change net_option '%s'
0x23CFE0  Failed to set SteamNetworkingSockets option '%s'
0x23D0B8  An old command that has been renamed to 'net_option'
0x23D100  The 'sdr' console command has been renamed to 'net_option'.  Please update your scripts
```

`net_fakelag` (`0x23D018`), `net_fakeloss` (`0x23D380`), `net_fakejitter`
(`0x23D458`) and `net_fakeclear` (`0x23D7E0`) are convenience wrappers that set
the `FakePacketLag_Send/Recv`, `FakePacketLoss_Send/Recv` and jitter options
and echo them back:

```
0x23D200  net_fakeloss = %g%%  (net_option FakePacketLoss_Send = %g%%, net_option FakePacketLoss_Recv = %g%%)
0x23D2C0  net_fakelag = %dms  (net_option FakePacketLag_Send = %dms, net_option FakePacketLag_Recv = %dms)
```

`net_fakejitter` takes `[send|recv] AVG [PCT] [MAX]` or a named `PROFILE` from
gameinfo (`0x23D477`, `0x23D4A2`, `"Cannot find jitter profile '%s' from
gameinfo"` at `0x23BAA8`).

`net_print_sdr_ping_times` (`0x23D8D8`) queries the SDR POP list and prints
`"Measured RTT to %d SDR points of presence."` (`0x23D850`) plus
`"SDR relay network status: %s (%d %d %d)"` (`0x23D918`).

---

## 6. Channel, lanes, reliability, ordering, fragmentation

### 6.1 `CNetChan`

`CNetChan` (vtable `0x2358A0`, 88 slots) implements `INetChannel` (vtable
`0x235508`, also 88 slots — the first 88 entries are the interface, the rest
`CNetChan`-specific). The object is large: `CNetChan::Setup` writes at
`[this+0x8E90]` and `[this+0x8FA0]`, so the instance is **> 36 KB**.

Layout landmarks proven by `CNetChan::Setup` (`0xBC610`, 1,812 bytes) and
`CNetChan::ParseMessages` (`0xC00B0`):

| offset | contents | evidence |
|---|---|---|
| `+0x6258` | address struct passed to `0xCAB30` (transmit) | `0xBE730` |
| `+0x8DAC` | incoming sequence number | `0xC03AD` |
| `+0x8DC8` | message-category bitmask | `0xC03C9` |
| `+0x8E48` | pending reliable bit count | `0xBE73C` |
| `+0x8E90` | channel index | `0xBC631` |
| `+0x8E94` | remote address (`netadr_t`, 0x20 bytes, copied at `0xBC63E`) | `0xBC637` |
| `+0x8EB0` | address type (`netadrtype_t`); drives the `loopback:` vs `%s:%d` name format at `0xBC6CF` | `0xBC6CF` |
| `+0x8EC0` | channel name buffer | `0xBC6AA` |
| `+0x8EC8` | socket/connection handle | `0xBC674` |
| `+0x8ED0` / `+0x8EE0` | timeout / rate doubles | `0xBC80C`, `0xBC814` |
| `+0x8FA0` | socket name | `0xBC648` |
| `+0x9000` | refcount block (atomic cmpxchg at `0xC3B5F`) | `0xC3B38` |

The outgoing sequence number is not written in `Setup`; it is maintained in the
transmit path, and `CNetChan::SendData` reads `[this+0x8E94+0x1C]` for the
channel state before touching `[this+0x9000]` (`0xC3B7E`–`0xC3BB6`).

### 6.2 Lanes / message categories

Source 2 replaces the Source 1 "subchannel" concept with **network categories**.
`INetworkSystem::RegisterNetworkCategory` (`0xDEDC0`, 280 bytes) enforces:

```
0x238700  INetworkSystem::RegisterNetworkCategory: all categories must have ids between 0-31!
0x238690  INetworkSystem::RegisterNetworkCategory: Attempted to register category %u twice (debug name: %s and %s)
```

The implementation indexes a 16-byte-stride array at `[this+0xA0]`
(`shl rbx,4` at `0xDEE2D`), with a `cmp edi,0x20` bound check at `0xDEDD8`.
So there are **at most 32 categories**, and the channel keeps them as a bitmask
at `+0x8DC8`.

Sending on a category the channel does not carry is the error
`"CNetChan::SendNetMessage: Trying to send message %s, which is an invalid
category for this channel!"` (`0x237C50`), raised from
`CNetChan::SendNetMessage` (`0xC3780`, 882 bytes). A full buffer gives
`"...Unable to send message %s, buffer is full!"` (`0x237CC0`), and a
serialisation failure gives `"...SerializeAbstract for message %s failed!"`
(`0x237BE0`).

### 6.3 Reliability and ordering

Two independent streams per channel — reliable and unreliable — each with its
own sequence space. The parse loop at `0xC2230` implements the standard
sliding-window logic and names every failure:

```
0x237A08  %s:Inbound net frame %d duplicated
0x237A30  %s:Inbound net frame %d out of order (latest received is %d)
0x237AE0  %s:Inbound net frame %d dropped
0x237A78  %s:Inbound net frames %d..%d dropped (%d frames)
0x237AB0  %s:Outbound net frame %d dropped
0x237B70  %s:Outbound net frame %d out of order
0x2379A0  Unreliable header too small
```

`%s` is the channel name from `CNetChan::Setup`. The same function computes
frame-loss statistics for `net_connections_stats`:
`"[%s] high frame misdelivery %.1f%%, %d/%d of %d frames dropped/reordered,
%.0fms ping, %.0fms peak jitter"` (`0x2370C0`).

`CNetChan::UpdateMessageStats` (`0xC6260`, 370 bytes) accumulates bit counts
and guards overflow:
`"CNetChan::UpdateMessageStats, bit counter about to roll over with addition of
%d bits, resetting to zero"` (`0x237D10`).

### 6.4 Fragmentation

Large messages are split by the **`svc_FullFrameSplit`** message
(`CSVCMsg_FullFrameSplit {tick, section, total, data}`, id 70) — not by a
transport-level fragmenter. The transport's own limit is expressed by
`net_limit_sv_recv_max_message_size_kb` and
`net_limit_sv_recv_segments_per_packet`, enforced server-side.

`CNetChan::SendData` (`0xC3B20`, 548 bytes) rejects oversize payloads with
`"ERROR! SendData %s data too big (%i)"` (`0x237C28`), where `%s` is
`"reliable"` or `"unreliable"` (`0x2366C0`/`0x2366D0`).

### 6.5 Compression

`net_use_packet_compression` (`0x2368C0`, help *"Compress network traffic"*)
gates LZ4. The compressed flag appears as the `(compressed)` literal in the
frame spew (`0x2379C0`). Decompression is centralised in
`CNetworkSystem::BufferToBufferDecompress` (`0xFB100`, 247 bytes), which
validates the destination size before inflating:

```
0x23C810  CNetworkSystem::BufferToBufferDecompress with improperly sized dest buffer (%u in, %llu needed)
0x23C980  CNetworkSystem::BufferToBufferDecompress with improperly sized dest buffer (%u in, %u needed)
```

The `%llu`/`%u` pair is the 32/64-bit size_t split. The LZ4 block framing is a
varint length prefix — the reader at `0x1C4680` is a 5-byte-capped varint
decoder (`cmp ecx,0x10` at `0x1C470F`), and the writer at `0x1C4600` emits the
matching `bsr`-based encoding.

`net_compresspackets_minsize` (`0x236CC0`, *"Don't bother compressing packets
below this size."*) is the threshold.

---

## 7. Rate limiting, bandwidth, and the `net_*` ConVars

### 7.1 CPU-budget rate limiting

Source 2's client-abuse protection is **CPU-time**, not byte-rate. Four ConVars
form a token bucket:

| ConVar | help |
|---|---|
| `sv_net_client_message_process_time_ms_warn_burst` | Warn if processing messages from a client consumes more than N ms of CPU time in a burst (token bucket capacity) |
| `sv_net_client_message_process_time_ms_warn_rate` | … per second, sustained (token bucket fill rate) |
| `sv_net_client_message_process_time_ms_drop_burst` | Drop a client if … in a burst |
| `sv_net_client_message_process_time_ms_drop_rate` | Drop a client if … per second, sustained |

All four are registered by this module (stubs at `0x2FD0` for `warn_burst` and
`0x31B0` for `drop_rate`, siblings at `0x3070`/`0x3110`). Enforcement is in
`CNetChan::ProcessMessages` (`0xC10B0`) — see the disconnect strings in §3.5.
`engine_frametime_warnings_enable` gates the warning path (`0xC1CB3`).

### 7.2 Queue and buffer limits

| ConVar | help |
|---|---|
| `net_max_message_process_count` | Maximum number of messages to process from a client in a single frame (0 == no limit). |
| `net_max_message_queue_size` | Maximum number of messages to allow waiting in queue after processing; exceeding this discards… |
| `net_limit_sv_recv_max_message_size_kb` | Server will reject message larger than N kb |
| `net_limit_sv_recv_segments_per_packet` | Server will reject packets with more than N segments |
| `net_limit_sv_recvbuffer_kb` | Server will not buffer more than N kb from connected clients |
| `net_limit_sv_recvbuffer_msg` | Server will not buffer more than N messages from connected clients |

### 7.3 Bandwidth estimation

There is **no** `rate` ConVar and no explicit bandwidth estimator in this
module. Bandwidth accounting is observational only — `CNetworkEncodingStats`
(§4.8) and `CMsgServerNetworkStats` (proto fields `avg_packets_in/out`,
`avg_loss_in/out`, `avg_data_in/out`, `total_data_in/out`,
`avg_engine_latency_out`, `avg_ping_ms`) are counters, and congestion control
is delegated to SteamNetworkingSockets, which owns the actual send rate.

The only latency/loss *policy* knobs here are the `net_option`
`FakePacketLag_*` / `FakePacketLoss_*` simulation options (§5.4) and the QoS
reporting threshold `net_qospacketloss_percentage_threshold` (*"Spew a warning
if packet loss percentage is above this threshold"*), plus
`net_qosinterval_spew`.

### 7.4 Diagnostic ConVars and ConCommands

Every entry below is registered by this module (§7.5) — the help string was
read from the stub's own `lea`, not from string proximity.

| name | help |
|---|---|
| `net_showmsg` | Show incoming message: `<0/1/2/name>` where 1 == all and 2 == all except net_NOP (the real help text uses vertical bars) |
| `net_showreliable` | Like net_showmsg, but only spew reliable messages |
| `net_showudp` | Dump UDP packets summary to console |
| `net_showudp_remoteonly` | Dump non-loopback udp only |
| `net_showoob` | Show connectionless UDP traffic. |
| `net_showdrop` | Show dropped packets in console |
| `net_showpeaks` | Show messages for large packets only: `<size>` |
| `net_restrict_showmsg_socket` | If set, only net_showmsg spew for data inbound on this socket name e.g. client, server, etc. |
| `net_detailed_canpacket_log` | (gates the `!CanPacket()` traces) |
| `net_filelogging` | Log packets to files |
| `net_log_processing` | Log network processing |
| `net_channels` | Shows net channel info |
| `net_connections_stats` | Print detailed network statistics for each network connection |
| `net_status` | Shows current network status |
| `net_validatemessages` | Activates/deactivates net message validation |
| `net_messageinfo` | Display info about a message (by classname or id) |
| `net_listallmessages` | List all registered net messages |
| `net_message_size_enforce` | Check declared engine message size limit, and either warn or reject. Note that this is ignored in -tools mode |
| `net_option` | Get or set SteamNetworkingSockets options such as fake packet lag and loss |
| `net_public_adr` | For servers behind NAT/DHCP meant to be exposed to the public internet, this is the public facing ip address… |
| `net_p2p_listen_dedicated` | Should dedicated server listen for new-style P2P? |
| `sv_listen_directudp` | Server will listen for direct UDP connections on the configured port. This can be turned off to only listen for P2P/SDR |
| `hostip` | Host game server ip |

Serializer/delta diagnostics (all confirmed registered here):

| name | help |
|---|---|
| `net_permutation_info` | show permutation information for serializer |
| `net_spewcounts` | Spew serializer counts, client only by default, specify server to spew server counts |
| `net_spewserializer` | Spew serializer info |
| `net_culloptimization` | Enable optimization of slow path that makes HLTV CPU consumption high in AnimGraph-using mods… |
| `net_why_field_excluded` | `<classname> <fieldname>`: spew why field was excluded from networking for classname. |
| `net_skip_redundant_change_callbacks` | (toggle) |
| `net_captureculldata` | Captures low-level data to replay path culling algorithm behavior in controlled unit test environment |
| `net_max_polymorphic_spew` | Max polymorphic variants to spew when spewing a flattened serializer. |
| `net_serializedentitymetadatainfo` | Spew CSerializedEntity metadata information |
| `net_serializedentitymemory` | Spew CSerializedEntity memory |
| `net_fs_showindirections` | (toggle) |

Simulated-condition commands: `net_fakelag`, `net_fakeloss`, `net_fakejitter`,
`net_fakeclear`, `net_fakestatus`, `net_print_sdr_ping_times` (§5.4).

`net_qospacketloss_percentage_threshold` and `net_qosinterval_spew` are
registered here too (their help strings sit in the same stub cluster at
`0x236780`/`0x236708`), but the recovery above did not pair them with a
distinct help literal — see §9.

### 7.5 Registration mechanics

ConVars and ConCommands are registered by **58** small stub functions, each of
which reaches a registrar through one of four paths:

| registrar | RVA | role | call sites |
|---|---|---|---|
| ConVar ctor | `0x1C0D00` | zeroes the object, stores default, resolves `VEngineCvar007` | 31 |
| `ConVar_Register` | `0x1C1430` | the actual registration; error string `RegisterConVar: Unknown error registering convar "%s"!` (`0x213C00`) | 32 |
| `ConCommand` registrar | `0x1C2160` | commands such as `net_channels`, `net_status`, `net_option`; error string `RegisterConCommand: Unknown error registering con command "%s"!` (`0x213D00`) | 23 |
| 5-arg ConVar helper | `0xC7230` | wraps the ctor + register with a float default and a flags mask | 5 |

Of the 146 `.CRT$XCU` entries, **55** are ConVar/ConCommand registration stubs;
the other 3 registration stubs are reached from module init instead. The
remaining ~87 array entries are unrelated static construction (see §2.2).

A representative ConVar stub, `0x2F20` (163 bytes), registers
`net_use_packet_compression`:

```
0x2f20  sub  rsp, 0xB8
0x2f2c  lea  rcx, [rip + 0x2A0F2D]    ; -> 0x2A3E60  ConVar object (BSS)
0x2f47  mov  edx, 0xFFFFFFFF          ; default = -1
0x2f7a  call 0x1C0D00                 ; ConVar ctor
0x2f89  lea  r9,  [rip + 0x233910]    ; -> 0x2368A0  "Compress network traffic"
0x2f9d  lea  rdx, [rip + 0x23391C]    ; -> 0x2368C0  "net_use_packet_compression"
0x2fa4  lea  rcx, [rip + 0x2A0EB5]    ; -> 0x2A3E60  same ConVar object
0x2fab  call 0x1C1430                 ; ConVar_Register
0x2fbe  jmp  0x1DCB64                 ; tier0 atexit hook
```

A representative ConCommand stub, `0x46C0`, registers `net_channels` through
`0x1C2160` with a callback at `0xF9150`.

This is why the generic `cvars.py` scanner (which expects a
`{name*, default*, help*}` pointer triple laid out contiguously) returns zero
results here: the literals are consumed by `lea` into a stack frame, and the
name is passed in `rdx`, not stored in a pointer table.

The 54 names recovered this way are the ones the module itself owns. The
`sv_net_client_message_process_time_ms_*` family and
`engine_frametime_warnings_enable` are **read** here (`0xC10B0`, `0xC00B0`)
but registered elsewhere.

---

## 8. Twenty-five most significant functions

| # | RVA | size | function | why it matters |
|---|---|---|---|---|
| 1 | `0xA6560` | 8,825 | `CFlattenedSerializers::BuildMergedSerializedEntity` | **The snapshot builder.** Merges previous/next entity state into the `serialized_entities` blob. |
| 2 | `0x74AC0` | 8,864 | `CFlattenedSerializer::MergeDeltas` | Combines partial deltas; classifies each field as previous/next/both. |
| 3 | `0x69B20` | 7,239 | `CFlattenedSerializer::EncodeField` | The bit-level field writer; drives `g_BitBuf_BitWriteMasks`. |
| 4 | `0x6DE20` | 6,694 | `CFlattenedSerializer::Decode` | The bit-level field reader with array bounds checks. |
| 5 | `0xEC420` | 6,239 | `CNetworkMessages::InitNetworkChangeTag` | Installs `MNetworkChangeTag`/`MNetworkChangeCallback` dispatch. |
| 6 | `0xC4210` | 6,118 | `CNetChan` vtable[33] | Largest `CNetChan` method; frame assembly/send driver. |
| 7 | `0x109DC0` | 6,074 | `CSerializedEntities::CompareSerializedEntities` | **The baseline differ** — produces the field-change set. |
| 8 | `0x83500` | 5,055 | `CFlattenedSerializer::ValidateSerializedEntity` | Validates a delta against array metadata before send. |
| 9 | `0xC2230` | 4,881 | netchan inbound frame parse | Reliability/ordering/duplicate/drop logic for both streams. |
| 10 | `0x80470` | 4,558 | `CFlattenedSerializer::BuildOverrideField` | Builds replacement fields for overrides. |
| 11 | `0x73A80` | 4,000 | `CFlattenedSerializer::WriteFieldList` | Emits the changed `CFieldPath` list. |
| 12 | `0x72920` | 3,877 | `CFlattenedSerializer::BuildDeltaProperties` | Builds the per-serializer Huffman delta tables. |
| 13 | `0x85410` | 3,869 | `CFlattenedSerializer::RemoveArrayElementsOutsideOfArrayMetadataBounds` | Array shrink handling. |
| 14 | `0xBE6E0` | 3,732 | `CNetChan::Transmit` | Packet assembly and `SendMessage` to SNP. |
| 15 | `0xC00B0` | 3,559 | `CNetChan::ParseMessages` | Message-type read + handler dispatch. |
| 16 | `0x7F340` | 3,349 | `CFlattenedSerializer::ApplyOverrides_R` | Applies field overrides recursively. |
| 17 | `0xC10B0` | 3,123 | `CNetChan::ProcessMessages` | The pump; CPU-budget disconnect enforcement. |
| 18 | `0x86E10` | 3,060 | `CFlattenedSerializer::MaybeWriteFlattenedSerializers_R` | Emits `svc_FlattenedSerializer` once per class. |
| 19 | `0x848C0` | 2,560 | `CFlattenedSerializer::DumpSerializedEntityToConsole` | `net_spewserializer` backend. |
| 20 | `0xEE4A0` | 2,480 | `CNetworkSerializer::AssignSharedChangeCallbackIndex` | Allocates shared change-callback bit slots. |
| 21 | `0xAED30` | 2,361 | `CEntitySystem::BuildEntityNetworking` | Builds the per-class network serializers at level load. |
| 22 | `0xF51E0` | 2,205 | `CNetworkSystem::InitSteamNetworking` | Binds SteamNetworkingSockets / SDR. |
| 23 | `0xB0EE0` | 2,105 | `CNetworkFieldChangedEventQueue::QueueChange` | Game-side `NetworkVar` callback queueing. |
| 24 | `0xBBA50` | 2,077 | `CNetChan` buffer management | `BUF_UNRELIABLE`/`BUF_RELIABLE`/`BUF_VOICE` allocation. |
| 25 | `0xF7E00` | 1,989 | `CNetworkSystem::PollSocket` | Inbound poll-group pump; connection→netchan mapping. |

Honourable mentions that a reader will want: `0xEB600` (1,931) `CNetworkSerializer::DetermineFieldSerializerGroup`,
`0xBC610` (1,812) `CNetChan::Setup`, `0x6BBE0` (1,624) `CFlattenedSerializer::Encode`,
`0xDF2A0` (868) `CNetworkMessages::FindOrCreateNetMessage`,
`0x5EFD0` (621) `CDeltaCalculator` ctor, `0x70B00` (798) `CFlattenedSerializer::CalcDelta`,
and `0x1C27E0` (94, no `.pdata`) `CreateInterface`.

---

## 9. Unknowns

These are the things this reversal does **not** establish, with the specific
evidence that would settle each.

1. **The exact bit layout of `CFieldPath` on the wire.** `CFieldPath::AddToTail`
   (`0x1D8EF0`) and the Huffman coder (`INode`/`InternalNode`/`LeafNode`,
   vtables `0x214490`/`0x2144A8`/`0x2144C0`) are located, and the depth limit is
   known (`DEFAULT_MAX_PATH_DEPTH`), but the per-path encoding — how the path
   index, array index and sub-field index are packed into bits — is not
   decoded. Settling it needs a dynamic trace of `EncodeField` (`0x69B20`) with
   a known entity, or a match against the public `CS2` demo parser's
   `serialized_entities` implementation.

2. **The Huffman table construction.** `BuildDeltaProperties` (`0x72920`)
   clearly builds a table from observed change frequencies, but the tie-break
   and rebuild policy (per tick? per N ticks? on class change?) are not
   determined. The string `"CFlattenedSerializer::BuildDeltaProperties using %d
   bytes for encoding %d/%s"` (`0x231B00`) implies per-serializer sizing but not
   the schedule.

3. **`CDeltaCalculator`'s field-op dispatch.** The ctor (`0x5EFD0`) stores a
   function pointer at `[this+0x00]` from `lea rax,[rip+0x1D454F]` (`0x5EFFA`),
   which resolves to `.rdata` — this is the per-field-type delta operation
   table, and its entries are not enumerated here. `CalcDelta`'s per-field
   worker is `0x63330` (1,765 bytes); it references the `" poly %s [%u]"` and
   `DEFAULT_MAX_PATH_DEPTH` literals, confirming it walks polymorphic field
   paths, but its op-code dispatch is not decoded. The 46-byte record stride
   (`0x69B75`) and its `+0x2C` encoder-kind byte are proven; the rest of the
   record is not.

4. **The `0x8DC8` category bitmask semantics.** The 32-category limit is proven
   (`0xDEDD8`), and the bitmask offset is proven (`0xC03C9`), but which category
   ID maps to which logical lane (voice, entities, user commands, …) is not
   recovered — the registration names are passed as runtime `debug name`
   strings, not literals, so they are not in `.rdata`.

5. **`CNetChan` vtable slot names.** 88 slots are recovered but only a handful
   are attributable (`Transmit`, `ProcessMessages`, `SendNetMessage`, `Setup`,
   `UpdateMessageStats`, `Buffer`). The remainder are reached only through the
   `INetChannel` interface, whose methods have no in-image name strings. The
   86-slot block at `0x1DD9DC` shared by `INetChannel` is a `purecall` stub,
   confirming those slots are unimplemented in the base interface.

6. **Whether `entity_data` (field 7) is ever populated.** The legacy
   bit-packed block coexists with `serialized_entities` (field 13) in the
   schema. `legacy_is_delta` (field 3) and the `%#GameUI_Disconnect_BadClientDeltaTick`
   string (`0x227D78`) suggest the legacy path exists for compatibility, but no
   writer was located in this module. It may be written by `engine2.dll`.

7. **The exact SNP framing header.** `ParseMessagesSNP` (`0xC2230`) reads a
   header whose fields are `{seq, ack, rel, tm, uncompressed_size, compressed}`
   per the spew strings, but the bit widths are not decoded. The header layout
   is owned by `steamnetworkingsockets.dll` (`SteamNetworkingSockets012`), which
   is outside this module.

8. **`net_option` string→option-ID mapping.** The command forwards a name to
   `ISteamNetworkingUtils::SetConfigValue`, and the option enum lives in
   `steamnetworkingsockets.dll`. The mapping table is therefore not in this
   image.

9. **The `0x2A3F30` `CNetworkMessages` singleton.** Its ctor (`0xDDC30`) writes
   the vtable at `[rip+0x1C62D0]`, but the object is in BSS and its full field
   layout is only inferable from the methods that touch it (`+0xA0` category
   array, `+0xB0`/`+0x168` message dictionaries, `+0x510` a lock). A precise
   layout would need the PDB.

10. **The exact partition of the 146 `.CRT$XCU` entries.** 4 are the interface
    registrars (§2.2) and 55 are ConVar/ConCommand stubs (§7.5); the remaining
    ~87 are module-level static construction (logging channels, allocators,
    container inits). The partition was established by size signature and call
    target, not enumerated entry by entry. The 115-entry factory table is a
    separate mechanism driven from `0x1BDB90`, not from this array.
