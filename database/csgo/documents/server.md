# `server.dll` — Counter-Strike 2 authoritative game module

Reverse-engineering notes. Every claim below is tied to an RVA in
`csgo/bin/win64/server.dll`, with `ImageBase = 0x180000000`. RVAs match the
`.asm` dumps in `docs/server/` and the helper tooling in
`scripts/server/` (committed).

Where a symbol is not proven by an RTTI type descriptor, a `__FILE__` literal, a
`LoggingSystem` format string, or a vtable layout, the name is marked
**inferred** together with the evidence that produced it. Nothing here is
guessed silently.

Companion artefacts produced while writing this document (all in
`scripts/server/` (committed)):

| file | contents |
|---|---|
| `srv.py` | PE/capstone helper: `funcs()`, `mfuncs()`, `refs_index()`, `text()`, `strings()` |
| `ad2.py` | annotated disassembler over *merged* function boundaries |
| `srv_rtti2.py` (already run; output in `index/vtables/server.json`) | relaxed MSVC RTTI walk → `srvcache/methods2.json` (3,990 classes / 4,897 vtables) |
| `cvars.py` | ConVar/ConCommand operand recovery → `index/cvars/server.json` (1,545 unique) |
| `stubs.py`, `size.py`, `scanrefs.py` | interface-stub scanner, leaf-function sizer, linear xref sweep |

---

## 0. A note on function boundaries in this image

`server.dll`'s `.pdata` holds **108,977** `RUNTIME_FUNCTION` records, which is
the number quoted in the task brief. That is *not* the function count. MSVC
emits one record per hot/cold *chunk*, and only the first chunk of a function
starts on a 16-byte boundary:

* 108,977 records total,
* 63,969 of them begin at a 16-byte-aligned RVA,
* 52,571 records are exactly contiguous with their predecessor
  (`prev.begin + prev.size == next.begin`).

Collapsing contiguous non-aligned chunks onto their aligned head yields
**63,970** functions, median size 191 bytes. All sizes quoted in this document
use that merged map (`Mod.mfuncs()` in `srv.py`). Quoting a raw `.pdata` size for
a hot function understates it by up to 20×: `CSource2Server::GameFrame` is
recorded as a 132-byte `.pdata` entry but is really **1,505 bytes**
(`0xDD8A60`–`0xDD9040`).

The same caveat applies to RTTI vtable walks: many virtual thunks are leaf
functions with **no** `.pdata` entry at all. A strict walk truncates
`CCSGameRules`'s vtable at slot 1; the relaxed walk (accept any pointer into
`.text`) recovers **130 slots**.

---

## 1. Identity

### 1.1 Hashes and headers

| property | value |
|---|---|
| path | `csgo/bin/win64/server.dll` |
| size | 34,672,792 bytes |
| SHA-256 | `70c66e850b2ce72c8c7ca026de6989ef4de7f12dad64ec503645fbd2a7f06d9f` |
| machine | `0x8664` (x86-64) |
| subsystem | 2 (`IMAGE_SUBSYSTEM_WINDOWS_GUI`) |
| image base | `0x180000000` |
| `SizeOfImage` | `0x257C000` = 39,305,216 bytes |
| PE timestamp | `1793836289` → **2026-11-04 23:51:29 UTC** |
| checksum | `0x211CA1B`, present and valid |
| DLL characteristics | `0x160` — `HIGH_ENTROPY_VA`, `DYNAMIC_BASE`, `NX_COMPAT`; **no** `GUARD_CF` |
| Authenticode | **not signed** |
| entry point RVA | `0x16B5F9C` |
| TLS callbacks | `0x16B58DC`, `0x16B62E8` |

`ASLR` on, `CFG` off — identical posture to `client.dll`. `client.dll`'s
timestamp is `1793836250` (39 s earlier) and its checksum `0x0256CDA1`; the two
modules come from the same build job.

The entry point at `0x16B5F9C` is the standard `_DllMainCRTStartup` shape:
`if (fdwReason == 1) call 0x16B6594;` (the C initialiser) then
`jmp 0x16B5E74` (the C++ dynamic initialiser walker). The two TLS callbacks
install per-thread state: `0x16B58DC` gates on `fdwReason == 2` and writes a
byte at `gs:[0x58]`-indexed TLS slot + `0x23C`; `0x16B62E8` handles reasons 0
and 3 and touches TLS slot + `0x240`.

### 1.2 PDB path

```
C:\buildworker\csgo_rel_win64\build\_build_\game\server\_vpc_server_csgo\unity\win64\_msvc_\Retail\server.pdb
```

The string is present in `.rdata` and also appears in the module inventory
(`index/inv/server.json`, `pdb` field). The build root
`C:\buildworker\csgo_rel_win64\build\src\...` is embedded in **150** distinct
`__FILE__` literals, 103 of them under `src\game\` and 28 specifically under
`src\game\server\`. Those literals are the source of every subsystem
attribution below that is not derived from RTTI.

The `unity` directory in the PDB path is confirmed by the image: `.text` is
24.5 MB in one contiguous blob and statically links tier0, tier1, tier2, v8,
the Source 2 entity2 layer, Recast/Detour navmesh, the `econ_csgo_legacy` item
schema, Pulse and the protobuf runtime. The import table has exactly 7 DLLs:

| DLL | imports |
|---|---|
| `tier0.dll` | 524 |
| `KERNEL32.dll` | 119 |
| `v8.dll` | 101 |
| `steam_api64.dll` | 11 |
| `WS2_32.dll` | 6 |
| `USER32.dll` | 3 |
| `ADVAPI32.dll` | 3 |

There is **no** import of `engine2.dll`, `networksystem.dll`, `host.dll` or
`client.dll`: the server reaches all of those through `CreateInterface` at
runtime, exactly as `client.dll` does.

### 1.3 Sections

| name | RVA | vsize | raw size | entropy |
|---|---|---|---|---|
| `.text` | `0x1000` | `0x1768D20` (24,547,616) | `0x1768E00` | 6.59 |
| `.rdata` | `0x176A000` | `0x632466` (6,497,382) | `0x632600` | 5.46 |
| `.data` | `0x1D9D000` | `0x613994` (6,371,732) | `0x1A8C00` | 4.43 |
| `.pdata` | `0x23B1000` | `0x13F44C` (1,307,724) | `0x13F600` | 6.89 |
| `.reloc` | `0x24F1000` | `0x8A828` (567,336) | `0x8AA00` | 5.46 |

`.data` has a 6.37 MB virtual size against a 1.74 MB raw size — 4.6 MB of BSS.
Every interface cache slot and every "g_p…" singleton lives in that BSS tail;
this is why so many globals in the listings below are `[.data]` with no raw
backing (e.g. `0x23ABEC0`, the interface list head).

`.text` is 24.5 MB, ~62 % of the image — smaller than the client's 26.7 MB
because the renderer, Panorama UI and the asset system are absent, but larger
than a bare server would be because the whole entity2/network-serializer stack
and the CS gameplay layer are compiled in.

### 1.4 Exports

Six, in the export directory:

| RVA | name | size |
|---|---|---|
| `0x0FF2180` | `BinaryProperties_GetValue` | 141 (leaf, no `.pdata`) |
| `0x16A10D0` | `CreateInterface` | 94 (leaf, no `.pdata`) |
| `0x0FF2900` | `ExtractModuleMetadata` | 428 |
| `0x16ADE30` | `GetResourceManifestCount` | 7 (leaf) |
| `0x16ADE40` | `GetResourceManifests` | 154 |
| `0x16AFF00` | `InstallSchemaBindings` | 75 |

The set is **identical in name and order** to `client.dll`'s six exports. The
implementations differ.

**`BinaryProperties_GetValue`** (`0xFF2180`). Same 8-way jump-table shape as the
client's, and the same table layout: `cmp ecx,7; ja fail; movsxd rax,ecx;
lea r8,[rip-0xFF2193]; mov ecx,[r8+rax*4+0xFF2210]; add rcx,r8; jmp rcx`.
The table at `0xFF2210` holds the eight case RVAs
`{0xFF21A0, 0xFF21CE, 0xFF21E2, 0xFF21B7, 0xFF21CE, 0xFF21E2, 0xFF21F6, 0xFF220A}`:

| `ecx` | case RVA | writes to `[rdx]` / `[rdx+8]` |
|---|---|---|
| 0 | `0xFF21A0` | `{"Release", 0}` — string at `0x179B940` |
| 1 | `0xFF21CE` | `{0, 1}` |
| 2 | `0xFF21E2` | `{1, 1}` |
| 3 | `0xFF21B7` | `{"server", 0}` — string at `0x1806458` |
| 4 | `0xFF21CE` | `{0, 1}` |
| 5 | `0xFF21E2` | `{1, 1}` |
| 6 | `0xFF21F6` | `{2, 1}` |
| 7 | `0xFF220A` | returns 0 |

The only difference from the client is case 3: `"client"` becomes `"server"`.
Case 0 (`"Release"`) is byte-identical, as is the `{ptr,kind}` struct layout
(kind 0 = string, 1 = integer).

**`ExtractModuleMetadata`** (`0xFF2900`, 428 bytes). Reads TLS slot index from
`0x23ACE90`, indexes the thread block at `+0x238`, and compares three dwords at
`0x22219B8` / `0x22219BC` / `0x22219C4` against the thread's tick. If none is
smaller it returns the address of the static metadata struct at `0x22219A8`
(`lea rax,[rip+0x122F044]` at `0xFF295D`), guarded by the flag at `0x22219C0`.
Otherwise it runs a per-thread one-shot init (`0x168D660` with `r8b=8`,
`dl=1`), calls the thunk at `0x175CB00`, and re-checks. Structurally identical
to the client's `0x0C33940`.

**`GetResourceManifestCount`** (`0x16ADE30`, 7 bytes):
`mov eax, [rip+0xCFE44A]; ret` — reads the dword at **`0x23AC280`**. Plain
global getter.

**`GetResourceManifests`** (`0x16ADE40`, 154 bytes). Walks the singly-linked
list rooted at **`0x23AC278`**; each node is `{next, cached_ptr, factory_fn}`.
For each node from index `ecx` (skipping `ecx` entries), if `node+8` is null it
calls `node+0x10()` and memoises the result in `node+8`. Copies pointers into
`r15[rbx*8]` up to `r14` entries and returns the count. This is the exact
structure the client has at `0x27A2F20`, relocated to `0x23AC278`.

The *producer* of that list is at `0x16ADCA0`, the registrar:

```asm
16adca0  mov rax, [rip+0xCFE5D1]     ; old head (0x23AC278)
16adca7  inc dword [rip+0xCFE5D3]    ; 0x23AC280  -- the count
16adcad  mov [rcx], rax              ; node->next = old head
16adcb0  mov rax, rcx
16adcb3  mov [rip+0xCFE5BE], rcx     ; head = node
16adcba  mov [rcx+8], rdx            ; node->cached = 0
16adcbe  mov qword [rcx+0x10], 0     ; node->factory = 0
```

Note the count at `0x23AC280` is incremented **at registration**, not at
enumeration, so `GetResourceManifestCount` reports registered manifests, not
resolved ones.

The "resource_manifests" string at `0x1ACC530` and the KV3 keys
`source_file`, `source_line`, `group` at `0x1ACB9F8`, `0x1ACBA20`, `0x192C4A0`
are consumed by the writer at `0x16ADA40` (2,030 bytes), which serialises a
manifest back out as KV3.

**`InstallSchemaBindings`** (`0x16AFF00`, 75 bytes). The client's version is
identical in shape:

```asm
16aff00  push rbx / sub rsp,0x20
16aff06  mov  rbx, rdx
16aff09  mov  rdx, rcx
16aff0c  lea  rcx, [rip+0x2E05C5]    ; 0x19904D8 "SchemaSystem_001"
16aff13  call 0x16C46F0              ; 262-byte "get interface by name"
16aff18  test eax, eax
16aff1a  je   16aff24                ; 0 == success
16aff1c  xor  al, al ; ret           ; non-zero == failure
16aff24  cmp  byte [rip+0xCFC765], 0 ; 0x23AC690  already-installed flag
16aff2b  jne  16aff43
16aff2d  mov  rcx, rbx
16aff30  mov  [rip+0xCFB4F9], rbx    ; 0x23AB430  cache the schema system
16aff37  call 0x16AFD80              ; 381-byte binding installer
16aff3c  mov  byte [rip+0xCFC74D], 1 ; 0x23AC690
16aff43  mov  al, 1 ; ret
```

`0x16C46F0` takes the interface name in `rcx` and the module/param in `rdx`;
its return convention is inverted relative to `CreateInterface`'s
(`0` = found). `0x23AB430` is the schema-system slot, and it is also the
`SchemaSystem_001` cache slot in the interface table (§2.3 row 10), so the two
paths agree.

---

## 2. `CreateInterface` and the interface table

### 2.1 `CreateInterface` — the dispatcher

`CreateInterface` at **`0x16A10D0`** is a **94-byte leaf function with no
`.pdata` entry** — the same omission as in `client.dll`, and for the same
reason (it is an export-only thunk). Complete body:

```asm
16a10d0  mov  r9,  [rip+0xD0ADE9]     ; r9 = g_pInterfaceList  (0x23ABEC0)
16a10d7  mov  r10, rdx                ; r10 = pReturnCode
16a10da  mov  r11, rcx                ; r11 = pName
16a10dd  test r9, r9
16a10e0  je   16a1110                 ; empty list -> not found
16a10e2  mov  rax, [r9+8]             ; rax = node->pszName
16a10e6  mov  r8, r11
16a10e9  sub  r8, rax                 ; r8 = pName - node->pszName
16a10ec  nop  dword ptr [rax]
16a10f0  movzx edx, byte ptr [rax]         ; inline byte-wise strcmp
16a10f3  movzx ecx, byte ptr [rax+r8]
16a10f8  sub  edx, ecx
16a10fa  jne  16a1103
16a10fc  inc  rax
16a10ff  test ecx, ecx
16a1101  jne  16a10f0
16a1103  test edx, edx
16a1105  je   16a111f                 ; match
16a1107  mov  r9, [r9+0x10]           ; r9 = node->next
16a110b  test r9, r9
16a110e  jne  16a10e2
16a1110  test r10, r10
16a1113  je   16a111c
16a1115  mov  dword ptr [r10], 1      ; IFACE_FAILED
16a111c  xor  eax, eax
16a111e  ret
16a111f  test r10, r10
16a1122  je   16a112b
16a1124  mov  dword ptr [r10], 0      ; IFACE_OK
16a112b  jmp  qword ptr [r9]          ; tail-call node->factory
```

The registered node is the same 24-byte record as on the client:

```
+0x00  void* (*factory)(void)     ; interface factory thunk
+0x08  const char* pszName        ; "Source2Server001"
+0x10  Node* pNext                ; singly linked, head-inserted
```

with the list head at **`0x23ABEC0`**. Lookup is a linear walk with an inline
byte-wise `strcmp`; **case sensitive**; `pReturnCode` may be null. There is no
hash, no binary search, no duplicate rejection.

The registrar at **`0x16A10B0`** is a 29-byte leaf, the exact analogue of the
client's `0x19D0FD0`:

```asm
16a10b0  mov [rcx+8], r8        ; node->pszName
16a10b4  mov [rcx], rdx         ; node->factory
16a10b7  mov rax, [0x23ABEC0]   ; old head
16a10be  mov [rcx+0x10], rax    ; node->next = old head
16a10c2  mov rax, rcx
16a10c5  mov [0x23ABEC0], rcx   ; head = node
16a10cc  ret
```

Registration order is therefore reverse of list order.

### 2.2 The registration thunk pattern

Every self-registered interface is a 4-instruction stub:

```asm
0eea60  lea r8,  [rip+0x18A1A99]   ; "ServerToolsInfo_001"
0eea67  lea rdx, [rip+0xD07652]    ; factory thunk -> 0x0DF60C0
0eea6e  lea rcx, [rip+0x20CAF93]   ; static node   -> 0x21B9A08
0eea75  jmp 0x16A10B0              ; register
0eea7a  int3
```

Because these stubs are **not** in `.pdata`, the way to enumerate them is a
byte scan of `.text` for `E9 rel32` (and `E8 rel32`) whose target is
`0x16A10B0`. That finds **exactly 10** stubs in this module:

| stub RVA | interface name | name string RVA | factory thunk | factory target | node RVA |
|---|---|---|---|---|---|
| `0x04C940` | `Source2GameDirector001` | `0x178B570` | `0x1DA5C0` | `0x1F9D5D0` | `0x1F9DAC8` |
| `0x05E720` | `customnavsystem001` | `0x17C6A98` | `0x3A3900` | `0x1DAA558` | `0x1FAE940` |
| `0x071F40` | `EntitySubclassUtilsV001` | `0x17FC540` | `0x55E580` | `0x1DBCC60` | `0x1F818…` |
| `0x0979B0` | `Source2ServerConfig001` | `0x18B86C8` | `0x96D1A0` | `0x2118EA8` | `0x2081…` |
| `0x0A8FD0` | `EmptyWorldService001_Server` | `0x18CDA20` | `0x9888B0` | `0x1E0D0E0` | `0x2077…` |
| `0x0EEA60` | `ServerToolsInfo_001` | `0x1990500` | `0xDF60C0` | `0x1E33C38` | `0x21B9A08` |
| `0x0EEA80` | `Source2GameClients001` | `0x1992010` | `0xDF60D0` | `0x1E33160` | `0x21B99E0` |
| `0x0EEAA0` | `Source2GameEntities001` | `0x1990F18` | `0xDF60E0` | `0x1E333E0` | `0x21B99A8` |
| `0x0EEAC0` | `Source2Server001` | `0x1990B00` | `0xDF60F0` | `0x1E33220` | `0x21B9970` |
| `0x124490` | `NavGameTest001` | `0x1A1BAB0` | `0x11114B0` | `0x1E54D38` | `0x2102…` |

All ten factory thunks are the same 8-byte "return the singleton slot" shape:

```asm
df60f0  lea rax, [rip+0x103D129]   ; -> 0x1E33220
df60f7  ret
```

`0x1E33220` is in `.data` and its first qword is `0x1990F38` — the
`CSource2Server` vtable. So, exactly as on the client, the factory returns a
pointer *slot* whose contents are the actual object; before
`CSource2Server::Connect` runs the slot holds zero.

Two of the ten names are non-standard spellings that are literal in the binary:
`customnavsystem001` (all lowercase) and `EntitySubclassUtilsV001`. The rest
follow the `<Module><Version>` convention.

**`Source2Server001` is the primary interface of this module**, and it is the
one the engine calls. The evidence is in `CSource2Server::Connect`
(`0xDD7D90`): after connecting ~20 tier libraries it calls
`0x23AB480` (`g_pMatchFramework`) → vtable `+0x60` → vtable `+0x00` with
`rdx = "Source2Server001"` and `r8 = this` (`0xDD8126`–`0xDD8133`). That is the
framework handing this module's own server object back to the host.

### 2.3 The interface *catalogue*

`CreateInterface` only knows the ten self-registered names above. The
**115-entry table** at **`0x1AC9F60`** is a different thing: the engine's
interface catalogue, a flat array of 16-byte rows
`{const char* name; void** cache_slot}`, where `cache_slot` points into the
`.data` BSS range `0x23AB360`–`0x23AB708` and receives the resolved pointer.

The table's structure is confirmed by the consumer at `0x16872A0`
(364 bytes), which loops `i < 0x73` (= 115) rows and, for each, checks
`*cache_slot == 0` then calls `factory_table[i]()`:

```asm
16872a5  lea  r13, [rip+0x442CB4]    ; 0x1AC9F60   table base
16872c5  mov  rdi, [rbx+8]           ; row->cache_slot
16872c9  cmp  qword ptr [rdi], 0
16872cd  jne  1687304                ; already resolved
16872cf  mov  rcx, [rbx]             ; row->name
16872d2  xor  edx, edx
16872d4  call qword ptr [r15+rbp*8]  ; factory for module rbp
16872d8  mov  [rdi], rax             ; store into cache slot
...
168730a  cmp  esi, 0x73              ; 115
168730d  jb   16872c5
```

and by `0x1687450` (235 bytes), the name-keyed variant, which does the same
inline `strcmp` walk against `row->name` and then stores the factory result in
`row->cache_slot`.

`0x1AC9F60` → `0x1ACA680`, 115 rows. The complete table, in order:

```
  0 VApplication001                          0x1ACA690   0x23AB360
  1 VEngineCvar007                           0x1ACA6A0   0x23AB368
  2 VStringTokenSystem001                    0x1ACA6B0   0x23AB370
  3 TestScriptMgr001                         0x1ACA6C8   0x23AB3B8
  4 VProcessUtils002                         0x1ACA6E0   0x23AB378
  5 VFileSystem017                           0x1993B38   0x23AB408
  6 VAsyncFileSystem2_001                    0x1ACA6F8   0x23AB410
  7 ResourceSystem013                        0x1ACA710   0x23AB440
  8 ResourceManifestRegistry001              0x1ACA728   0x23AB450
  9 ResourceHandleUtils001                   0x1ACA748   0x23AB448
 10 SchemaSystem_001                         0x19904D8   0x23AB430
 11 ResourceCompilerSystem001                0x1ACA760   0x23AB438
 12 VMaterialSystem2_001                     0x1ACA780   0x23AB458
 13 PostProcessingSystem_001                 0x1ACA798   0x23AB460
 14 InputSystemVersion001                    0x1ACA7B8   0x23AB468
 15 InputStackSystemVersion001               0x1ACA7D0   0x23AB470
 16 RenderDeviceMgr001                       0x1ACA7F0   0x23AB400
 17 RenderUtils_001                          0x1ACA808   0x23AB4E8
 18 SoundSystem001                           0x19936A8   0x23AB4F0
 19 SoundOpSystemEdit001                     0x1ACA818   0x23AB4F8
 20 SoundOpSystem001                         0x19936C8   0x23AB500
 21 SteamAudio001                            0x1ACA830   0x23AB508
 22 VP4003                                   0x1ACA840   0x23AB478
 23 Localize_001                             0x1ACA848   0x23AB3C8
 24 VMediaFoundation001                      0x1ACA858   0x23AB548
 25 VAvi001                                  0x1ACA870   0x23AB550
 26 VWebm001                                 0x1ACA878   0x23AB540
 27 VBik001                                  0x1ACA888   0x23AB558
 28 MeshSystem001                            0x1ACA890   0x23AB510
 29 MeshUtils001                             0x1ACA8A0   0x23AB518
 30 RenderDevice003                          0x1ACA8B0   0x23AB4D0
 31 VRenderDeviceSetupV001                   0x1ACA8C0   0x23AB4D8
 32 RenderHardwareConfig002                  0x1ACA8D8   0x23AB4E0
 33 SceneSystem_002                          0x1ACA8F0   0x23AB520
 34 IPulseSystem_001                         0x1ACA900   0x23AB528
 35 SceneUtils_001                           0x1ACA918   0x23AB530
 36 WorldRendererMgr001                      0x1ACA928   0x23AB560
 37 AssetSystem001                           0x1ACA940   0x23AB418
 38 AssetSystemTest001                       0x1ACA950   0x23AB420
 39 ParticleSystemMgr003                     0x1993720   0x23AB590
 40 VScriptManager010                        0x1993CE0   0x23AB538
 41 PropertyEditorSystem_001                 0x1ACA968   0x23AB428
 42 MATCHFRAMEWORK_001                       0x1993770   0x23AB480
 43 Source2V8System001                       0x19937A8   0x23AB490
 44 PanoramaUIEngine001                      0x1ACA988   0x23AB498
 45 PanoramaUIClient001                      0x1ACA9A0   0x23AB4A0
 46 PanoramaTextServices001                  0x1ACA9B8   0x23AB4A8
 47 ToolFramework2_002                       0x1ACA9D0   0x23AB598
 48 PhysicsBuilderMgr001                     0x1ACA9E8   0x23AB5B0
 49 VisBuilder_001                           0x1ACAA00   0x23AB5A8
 50 BakedLODBuilderMgr001                    0x1ACAA10   0x23AB5B8
 51 HelpSystem_001                           0x1ACAA28   0x23AB380
 52 ToolSceneNodeFactory_001                 0x1ACAA38   0x23AB388
 53 EconItemToolModel_001                    0x1ACAA58   0x23AB390
 54 SchemaTestExternal_Two_001               0x1ACAA70   0x23AB398
 55 SchemaTestExternal_One_001               0x1ACAA90   0x23AB3A0
 56 AnimationSystem_001                      0x1ACAAB0   0x23AB3A8
 57 AnimationSystemUtils_001                 0x1ACAAC8   0x23AB3B0
 58 HammerMapLoader001                       0x1ACAAE8   0x23AB5A0
 59 MaterialUtils_001                        0x1ACAB00   0x23AB3D0
 60 FontManager_001                          0x1ACAB18   0x23AB3D8
 61 TextLayout_001                           0x1ACAB28   0x23AB3E0
 62 AssetPreviewSystem_001                   0x1ACAB38   0x23AB3F0
 63 AssetBrowserSystem_001                   0x1ACAB50   0x23AB3F8
 64 AssetRenameSystem_001                    0x1ACAB68   0x23AB3E8
 65 VConComm001                              0x1ACAB80   0x23AB488
 66 MODEL_PROCESSING_SERVICES_INTERFACE_001  0x1ACAB90   0x23AB3C0
 67 NetworkSystemVersion001                  0x1993748   0x23AB568
 68 NetworkMessagesVersion001                0x1ACABB8   0x23AB570
 69 FlattenedSerializersVersion001           0x1ACABD8   0x23AB578
 70 SerializedEntitiesVersion001             0x1ACABF8   0x23AB580
 71 DemoUpconverterVersion001                0x1ACAC18   0x23AB588
 72 Source2Client002                         0x1ACAC38   0x23AB5E8
 73 Source2ClientUI001                       0x1ACAC50   0x23AB5F0
 74 Source2ClientPrediction001               0x1ACAC68   0x23AB648
 75 Source2Server001                         0x1990B00   0x23AB600
 76 Source2Host001                           0x1ACAC88   0x23AB618
 77 Source2ModTools001                       0x1ACAC98   0x23AB620
 78 Source2GameClients001                    0x1992010   0x23AB608
 79 Source2GameEntities001                   0x1990F18   0x23AB610
 80 EngineServiceMgr001                      0x1ACACB0   0x23AB650
 81 HostStateMgr001                          0x1ACACC8   0x23AB658
 82 NetworkService_001                       0x1ACACD8   0x23AB660
 83 NetworkClientService_001                 0x1ACACF0   0x23AB668
 84 NetworkP2PService_001                    0x1ACAD10   0x23AB670
 85 NetworkServerService_001                 0x1ACAD28   0x23AB678
 86 ToolService_001                          0x1ACAD48   0x23AB680
 87 RenderService_001                        0x1ACAD58   0x23AB698
 88 StatsService_001                         0x1ACAD70   0x23AB6A0
 89 VProfService_001                         0x1ACAD88   0x23AB6A8
 90 InputService_001                         0x1ACADA0   0x23AB6B0
 91 MapListService_001                       0x1ACADB8   0x23AB6B8
 92 GameUIService_001                        0x1ACADD0   0x23AB6C0
 93 SoundService_001                         0x1ACADE8   0x23AB6C8
 94 BenchmarkService001                      0x1ACAE00   0x23AB6D0
 95 KeyValueCache001                         0x1ACAE18   0x23AB6D8
 96 ClientServerSharedHandleSystem001        0x19938F8   0x23AB6E0
 97 GameResourceServiceClientV001            0x1ACAE30   0x23AB6F8
 98 GameResourceServiceServerV001            0x1ACAE50   0x23AB700
 99 Source2EngineToClient001                 0x1ACAE70   0x23AB628
100 Source2EngineToServer001                 0x19938A8   0x23AB630
101 Source2EngineToServerStringTable001      0x19938D0   0x23AB638
102 Source2EngineToClientStringTable001      0x1ACAE90   0x23AB640
103 VPhysics2_Interface_001                  0x1993860   0x23AB5C0
104 ModelDocUtils001                        0x1ACAEB8   0x23AB4B8
105 SmartPropsSystem_001                     0x1ACAED0   0x23AB4C0
106 AnimGraphEditorUtils001                  0x1ACAEE8   0x23AB4C8
107 EXPORTSYSTEM_INTERFACE_VERSION_001       0x1ACAF00   0x23AB5C8
108 ServerToolsInfo_001                      0x1990500   0x23AB688
109 ClientToolsInfo_001                      0x1ACAF28   0x23AB690
110 Vrad3_001                                0x1ACAF40   0x23AB5E0
111 NavSystem001                             0x1993888   0x23AB5D0
112 NavGameTest001                           0x1A1BAB0   0x23AB5D8
113 LocalServerClientAccess001               0x1ACAF50   0x23AB6E8
114 ClientLocalServerAccess001               0x1ACAF70   0x23AB6F0
```

**115 names — the authoritative count of interfaces this module advertises.**
The table is byte-for-byte the same list as `client.dll`'s 115-entry table; the
only difference is the cache-slot range (`0x23AB360`–`0x23AB708` here versus
`0x27A2000`–`0x27A2400` there). That makes sense: both are the shared engine
catalogue emitted into every game module.

Cross-check against `index/ifaces/server.txt` (108 lines): that file is a
*string scan*, not a table dump. Its extra names are Steam interfaces
(`SteamClient023`, `SteamGameServer014`, …) resolved through
`SteamInternal_FindOrCreate*Interface`, crypto constants (`CAMELLIA128/192/256`),
and econ item-schema class names (`CWeaponM249`, `CWeaponSG556`, …). The table
has 45 names *not* in that file (`SchemaSystem_001`, `MATCHFRAMEWORK_001`,
`RenderDevice003`, the whole `*Service_001` family, …). Neither list is a
superset of the other; the table is authoritative.

### 2.4 The interface *consumer* side

`CSource2Server::Connect` at **`0xDD7D90`** (1,148 bytes) is the counterpart to
the client's `CSource2Client::Connect`. It resolves ~20 interfaces and stores
each into its own BSS slot, aborting with a `LoggingSystem_Log` on any failure:

| call RVA | interface | destination |
|---|---|---|
| `0xDD7E41` | `Source2EngineToServer001` | `0x21BA010` |
| `0xDD7EDE` | `Source2EngineToServerStringTable001` | `0x21B9730` |
| `0xDD7F1A` | `GameModelInfo001` | `0x21BA1A8` |
| `0xDD7F56` | `SaveRestoreDataVersion001` | `0x218BD10` |
| `0xDD7F92` | `VFileSystem017` | `0x21BA1A0` |
| `0xDD7FCE` | `SoundOpSystem001` | `0x21B9738` |
| `0xDD800A` | `SceneFileCache002` | `0x21B9740` |
| `0xDD8046` | `INETSUPPORT_001` | `0x21BA1B0` |
| `0xDD8082` | `GameConfigServerV001` | `0x218BFF8` |
| `0xDD80DE` | `VScriptManager010` (only if the preceding query returns null) | `0x23AB538` |
| `0xDD813D` | `GameTypes001` | `0x2125888` |
| `0xDD81AC` | `GameEventSystemServerV001` (only if slot empty) | `0x21B9498` |

Between them it also fetches `CommandLine()` (import at `0x176B450`),
`g_pMatchFramework` (`0x23AB480`) and `g_pSource2Engine` (`0x23AB630`), and
logs a `COM_TimestampedLog` marker (`0x176A608`) at each phase:
`"ConnectTier1/2/3Libraries - Start"` (`0x1993920`), `"- Finish"`
(`0x1993948`), `"Factories - Start"` (`0x1993A20`), `"Factories - Finish"`
(`0x1993D98`).

`0xDD81E4` calls `[g_pSource2Engine vtable + 0x270]` and stores the result in
`0x21BA008`; `0xDD81D5` calls `0x1376170` with `rdx = "server"` (`0x1806458`) —
the same `"server"` literal `BinaryProperties_GetValue` returns for selector 3.

---

## 3. Authoritative simulation

### 3.1 The frame-advance entry point

The function that advances one server frame is
**`CSource2Server::GameFrame` at `0xDD8A60`** — **1,505 bytes** across
`.pdata` chunks `[0xDD8A60,0xDD8AE4)`, `[0xDD8AE4,0xDD8AEE)`,
`[0xDD8AEE,0xDD8AF6)`, `[0xDD8AF6,0xDD8D77)`, `[0xDD8D77,0xDD8F95)`,
`[0xDD8F95,0xDD9026)`. It is vtable slot **19** of `CSource2Server`
(`0x1990F38 + 19*8 = 0x1990FD0`), and the only reference to its address is
that vtable entry.

Signature (from the prologue and the string arguments): `GameFrame(this,
float frametime, bool simulating, bool first_tick)` — `rcx=this`, `xmm1`/
stack for the time, `r8b` and `r9b` booleans captured at `0xDD8AA3` and
`0xDD8AC3`.

It is bracketed by a `VProfScopeHelper` at `0x176B128` with the literal
`"CSource2Server::GameFrame"` (`0x1994008`), file
`...\src\game\server\gameinterface.cpp` (`0x1993FC0`), line `0x411`
(`mov qword ptr [rbp-0x51], 0x411`). The nested `"GameFrame"`
(`0x1993FB0`) string is the scope-name component.

Structure:

```asm
dd8a60  ...                                ; VProf scope open
dd8ace  call [0x176B128]                   ; EnterScopeInternal
dd8ad7  call 0xC59850                      ; byte getter, global 0x1F3???
dd8ade  je   0xDD9026                      ; early out -> scope close only
dd8b1e  call 0xC5E530                      ; perf-timing sample (see below)
dd8b23  call 0x199580                      ; thread-tick / frame-counter update
dd8b28  mov  rax, [0x21B9968]
dd8b2f  cmp  byte [rax+0x58], 0
dd8b33  je   0xDD8BE6                      ; skip timing accumulation
   ...   accumulate min/max/avg frametime into 0x21B9750 / 0x21B9758 / 0x21B9768
dd8be6  xorps xmm6,xmm6
dd8be9  test r15b, r15b                    ; the "simulating" argument
dd8bec  je   0xDD8CD9
   ...   autosave / autosavedangerous handling, 0x21BA1C0 -> vtable +0x288
dd8cd9  mov  rcx, [0x21BA010]              ; g_pSource2EngineToServer
dd8ce0  mov  rax, [rcx]
dd8ce3  call [rax+0x1B8]                   ; engine -> server "get tick" query
dd8ce9  mov  rsi, [0x1E328D0]              ; g_pGlobals (shared Globals struct)
dd8cf0  mov  [0x1E4E5E0], al               ; global "in frame" flag
dd8cf6  ...   read/restore globals fields at +0x30/+0x34/+0x50/+0x58/+0x44
dd8d55  call 0xBECCD0                      ; physics/entity system frame step
dd8d5a  mov  rax, [0x21B9868]
dd8d71  cmp  byte [rax+0x58], 0
dd8d75  je   0xDD8D87
dd8d77  mov  rcx, [0x21B9498]              ; g_pGameEventSystemServer
dd8d81  call [rax+0x90]                    ; flush queued game events
dd8d87  ...   VProf scope for "net" work
dd8e3d  call 0x53BAA0                      ; profiled block
dd8e42  cmp  byte [0x21170E5], 0
dd8e4b  ...   propagate a bool into globals
dd8e60  mov  rcx, [0x234ACE8]              ; some subsystem, vtable +0x50
dd8e72  mov  rcx, [0x2226670]              ; another, vtable +0x08
dd8e84  ...   zero 0x21B9750 / 0x21B9758 / 0x21B9768 / 0x21B9760 / 0x21B9770
dd8eb1  call 0xF99720                      ; UpdateQueryCache  (querycache.cpp)
dd8eb6  mov  rcx, [0x1DBD3C0]
dd8ec1  call [rax]                         ; dispatch
dd8ec6  mov  rcx, [0x2331B00]
dd8ecd  call 0x138E480                     ; entity I/O dispatch ("unhandled input: ...")
dd8ee0  ...   second VProf scope
dd8f84  call 0xFC2F90                      ; "is dedicated" predicate (cmp [0x221EB50],0)
dd8f8f  test al, al
dd8f95  call 0xFC2F10                      ; only when dedicated
dd8f9a  mov  rcx, [0x218B950]              ; g_pGameRules-ish slot
dd8fa1  call 0xBECCD0
dd8fa6  call 0xD17DD0                      ; CBasePlayerPawn::UpdateAllClientData
dd8fab  mov  rcx, [0x21BA1C0]
dd8fb7  call [rax+0x198]                   ; client-update notification
dd8fc0  lea  rcx, [0x21B98B0]
dd8fc7  call 0xFC94C0
dd8fcc  mov  rcx, [0x2331B00]
dd8fd5  call 0x1382FB0                     ; entity-system frame step (see §3.2)
dd8fda  mov  rcx, [0x21B9498]
dd8fe4  call [rax+0x90]                    ; flush game events again
dd8fea  ...   restore globals fields
dd9026  call rbx                           ; VProf scope close
dd9028  ...   epilogue
```

The two calls that do the actual world advance are **`0xBECCD0`** (46 bytes,
`mov rcx,[0x1FF5690]; test; je; call 0x5A5C40; jmp 0x13829C0`) — it forwards to
the entity-system tick — and **`0x1382FB0`** (414 bytes), which is the
`CEntitySystem` frame driver described next.

`0xC5E530` (160 bytes) samples the frame time:
`[0x23AB3A8] vtable +0xC8` (a `-1` sentinel check), then
`[0x176B250]` (a `Plat_FloatTime`-style import) and
`[0x176AA80]` (a 64-bit counter, likely `GetTimeMicroseconds`-equivalent),
converting to float and pushing into the stats sink at `0x23AB488`
(`VProfService_001` cache slot) via `vtable +0x80` with tag `0x414E5446`
(`'F','T','N','A'` little-endian = `"FTNA"`).

`0x199580` (365 bytes) is the per-thread tick bookkeeping: it reads
`gs:[0x58]`, indexes with the TLS slot at `0x23ACE90`, adds `0x238`, and
compares the thread tick against two globals at `0x1F53088` and `0x1F530A0`,
propagating two booleans into `0x1D9ED74` and `0x1F49CE4`. This is the
`ThreadInMainThread` / `g_nTimeStamp` pattern used throughout Source 2.

### 3.2 The entity-system frame: `0x1382FB0`

`0x1382FB0` (414 bytes) is the function `GameFrame` calls at `0xDD8FD5` to step
the entity world. Its shape:

```asm
1382fb0  ...                       ; prologue
1382fd4  call 0x13829C0            ; BeginFrame
1382fe3  inc  dword [rbx+0xC48]    ; nesting depth
1382fee  ...   stack-alloc a 0x32-entry scratch array
1383020  loop:
1383028    call 0x13858C0          ; ProcessQueuedSpawnGroupOps
138302d    cmp  dword [rbx+0xC68], 0
1383034    jg   1383020            ; repeat while work remains
1383036  movzx edi, byte [rbx+0xC67]   ; save "in frame" flag
138303d  mov  byte [rbx+0xC67], 1
1383044  cmp  byte [rbx+0xC62], 0
138304b  je   1383065
138304d  cmp  dword [rbx+0xC48], 1
1383054  jg   1383065
1383056  call 0x1383150          ; first-level path
138305e  jmp  1383072
1383065  call 0x13823E0          ; nested / second path
1383072  dec  dword [rbx+0xC48]
1383078  mov  byte [rbx+0xC67], dil   ; restore
138307f  cmp  dword [rbx+0xC48], 0
1383086  jg   13830B0
1383088  cmp  byte [rbx+0xC60], 0
138308f  je   13830A8
1383091  call 0x13829C0          ; EndFrame
13830a0  mov  word [rbx+0xC60], 0
13830a8  call 0x13834B0          ; FlushDeferredWork
13830b0  ...                      ; epilogue
```

`0x13829C0` (1,519 bytes) is the begin/end frame pair — it early-outs on a
re-entrancy guard at `[rcx+0xC4C]`, sets `[rcx+0xC60]`/`[rcx+0xC61]`, and, when
`dl != 0`, calls `0x1382860` (341 bytes) to reset per-frame state. `0x1383150`
(860 bytes) and `0x13823E0` (758 bytes) are the two think-dispatch paths;
`0x13834B0` (875 bytes) flushes deferred component work.

`0x13858C0` (1,497 bytes) is **`ProcessQueuedSpawnGroupOps`** (inferred): it
iterates a 0x32-entry array at `[rcx+0xC70]`, resolves each entry's
`targetname` (`"targetname"` at `0x17CD398`, used at `0x1385964`) through the
entity handle table at `0x1F47078`, and executes the queued spawn-group
operation.

### 3.3 `CSource2Server`'s vtable

`CSource2Server` (RTTI at `0x1B85928`, vtable **`0x1990F38`**, 103 slots, plus
a 1-slot secondary at `0x1991278`). Slot map (index → RVA → what the body does):

| slot | RVA | size | identification |
|---|---|---|---|
| 0 | `0xDD7D90` | 1,148 | `Connect` — `"ConnectTier1/2/3Libraries - Start/Finish"`, `"CSource2Server::Connect - ..."` ×10 |
| 1 | `0xDD8210` | 61 | disconnect / teardown |
| 3 | `0xDD8270` | 14 | trivial predicate |
| 4 | `0xDD8500` | 196 | |
| 5 | `0xDD8620` | 114 | `"CSharedEdictChangeInfo high water mark %u"` |
| 8 | `0xDD7D30` | 90 | |
| 13 | `0xDD86E0` | 120 | `"Forcing S1 g_pNetworkStringTable to use version from engine.dll"` (`0x1994050`, at `0xDD870F`) |
| 14 | `0xDD8760` | 241 | `"CSource2Server::WriteSignonMessages: Failed to serialize Source1LegacyGameEventList_t"` |
| 15 | `0xDD8860` | 222 | |
| 18 | `0x1ACE00` | 2,256 | `ApplyGameSettings` — `"CSource2Server::ApplyGameSettings game settings payload received:"` |
| **19** | **`0xDD8A60`** | **1,505** | **`GameFrame`** |
| 24 | `0x1B0E30` | 153 | `"g:cs2,gt:%u,gm:%u,sk:%u,%s"` |
| 27 | `0xDD9120` | 64 | |
| 30 | `0xDD91A0` | 51 | |
| 39 | `0xDD9280` | 418 | |
| 41 | `0xDD9440` | 59 | `"CSource2Server::GameServerSteamAPIActivated()"` |
| 42 | `0xDD9480` | 68 | `"CSource2Server::GameServerSteamAPIDeactivated()"` |
| 43 | `0xDD94D0` | 81 | `"hostname_changed"` event |
| 45 | `0xDD95D0` | 52 | |
| 47 | `0xDD96F0` | 67 | `"server_cvar"` event |
| 48 | `0xDD98D0` | 50 | |
| 49 | `0xDD9C80` | 430 | `"startup_ServerModuleInit"`, `"startup_GameRulesCreated"`, `"startup_SteamLoggedOn"`, `"startup_RequestedGcSession"`, `"startup_ReceivedGcSession"`, `"startup_ReservedForGame"` |
| 52 | `0xDD8980` | 187 | `"OpenSaveFileAndExtractLevels() failed for save file: %s"` (`0x19940D0`), `"CSource2Server::GetLevelsFromSaveFile"` (`0x1994098`) |
| 54 | `0xDD9050` | 76 | |
| 55/56 | `0xDD97F0`/`0xDD9860` | 106/106 | |
| 57 | `0xDD9B60` | 89 | `"SV:  can't save, no IEntity2SaveRestore"` |
| 63/64 | `0xDD9FB0`/`0xDDA030` | 115/115 | |
| 65–68,70 | `0xDDA0B0`…`0xDDA0F0` | 30 each | one-liners |
| 69 | `0x1B5C10` | 56 | `"sv_maxuptimelimit has reached ..."` |
| 71 | `0xDDA150` | 45 | |
| 75 | `0xDDA180` | 59 | |
| 77 | `0xDDA1D0` | 114 | |
| 80 | `0xDDA260` | 331 | |
| 81/82 | `0xDDA3B0`/`0xDDA3E0` | 47/38 | |
| 83 | `0xDDA410` | 1,089 | `"ehandle"`, `"%d (s/n %d)"`, `"[-1] -> empty"` — entity-handle debug printer |
| 88 | `0x1B4C60` | 42 | |
| 89 | `0x1AD7A0` | 40 | |
| 91 | `0x1AEE00` | 1,253 | edict/networkable-slot validation |
| 92 | `0x1B3680` | 30 | |
| 98 | `0xDDA900` | 59 | |
| 101 | `0xDDA960` | 207 | |

The 103-slot vtable is the module's primary `ISource2Server`-family surface.
Slot 19 (`GameFrame`) is the only slot that the engine's frame pump needs.

### 3.4 `CGameRulesGameSystem` and the rules install

`CGameRulesGameSystem` (RTTI `0x1B858A8`, vtable **`0x1991490`**, 65 slots) is
the game-system wrapper that owns the rules object. Its relevant slots:

| slot | RVA | behaviour |
|---|---|---|
| 3 | `0xDDAF00` | `"%s:  CGameRulesGameSystem::GameInit installed game rules"` |
| 4 | `0xDDAF80` | `"%s:  CGameRulesGameSystem::GameShutdown uninstalled game rules"` |
| 7 | `0xDDB050` | forwards to `[g_pGameRules vtable +0x80]` |
| 12 | `0xDDB180` | 56 bytes |
| 31/32 | `0xDDB220`/`0xDDB240` | forwarders: `[g_pGameRules vtable +0x90]` and `+0x190` |
| 34 | `0xDDB260` | forwarder: `[g_pGameRules vtable +0x98]` |
| 60 | `0xDDAEE0` | forwarder: `[g_pGameRules vtable +0x38]` |
| 62 | `0xDDAED0` | forwarder: `[g_pGameRules vtable +0x40]` |
| 64 | `0xDDAEC0` | empty `ret 0` |

`0xDDAF00` also calls `0x93D150` on `[rdx]` and then
`[0x21BA1C0 vtable +0xA8]` — the `CCSGameRules` install path.

### 3.5 `CCSGameRules`

`CCSGameRules` (RTTI `0x1B64068`, vtable **`0x18C5450`**, **130 slots**; plus a
4-slot secondary at `0x18C5868`). The 130 slots are the `IGameRules` surface.

Key slots:

| slot | RVA | size | identification |
|---|---|---|---|
| 0 | `0x95EFB0` | 33 | schema-binder stub (`lea rdx, <schema>; call 0x165BFC0`) |
| 1 | `0x91A5B0` | 8 | `mov rax,[0x211AED0]; ret` — getter |
| 16 | `0x911CE0` | 47 | |
| **18** | **`0x923BC0`** | **117** | **`FrameUpdatePreEntityThink`** |
| 20 | `0x90BD00` | 78 | |
| 25 | `0xDE7CD0` | 245 | |
| 29 | `0x93B180` | 500 | `"csgo_team1"`, `"csgo_team2"`, `"csgo_grenadeclip"`, `"csgo_droneclip"`, `"csgo_moveable"`, `"csgo_opaque"` |
| 30 | `0x93B380` | 130 | |
| 39 | `0x918980` | 149 | `"CrosshairCode"` |
| 46 | `0xE7E7D0` | 127 | `"sv_gravity"` |
| 50 | `0x9669F0` | 7,173 | **`Think`** |
| 58 | `0x918A30` | 104 | `"client_connected"` |
| 61 | `0x922C10` | 288 | |
| 65 | `0x93E710` | 145 | |
| 66 | `0x918730` | 582 | `"changeteam"`, `"single_player_pause"`, `"end_single_player_pause"`, `"nextmap"` |
| 84 | `0x91BA50` | 5,352 | `"classname"`, `"cs_player_manager"`, `"...entityspawner.h"`, `"Spawn"` |
| 101 | `0xDE95C0` | 147 | `"SOURCE2 SAVE COMMENT"` |
| 102 | `0x92A610` | 3,330 | `"game_vars"`, `"gc_status"`, `"sv_shutdown_requested"` |
| 103 | `0xDF25D0` | 266 | `"CGameRules - paused on tick %d"`, `"CGameRules - unpaused on tick %d, pause duration was %d ticks"` |
| 110/112 | `0xDE69A0`/`0xDE6A50` | 175/189 | `"Game is paused but no pause start tick?"` |
| 121 | `0x931770` | 162 | `"sv_mmqueue_reservation"` |
| 129 | `0x92CDF0` | 3,426 | `"Going to intermission..."` |

**`CCSGameRules::FrameUpdatePreEntityThink`** (`0x923BC0`, 117 bytes) is a pure
VProf wrapper:

```asm
923bc0  ...                                  ; prologue, save rdx into rdi
923bca  lea rax, [0x18C8B70]                 ; "...\src\game\shared\cstrike15\cs_gamerules.cpp"
923bd1  mov qword [rsp+0x28], 0x139B         ; line 5019
923be9  lea rax, [0x180CA78]                 ; "FrameUpdatePreEntityThink"
923bf8  lea rdx, [0x1E0B510]                 ; VProf budget group
923c05  lea rcx, [0x18C8D98]                 ; "CCSGameRules::FrameUpdatePreEntityThink"
923c17  call [0x176B128]                     ; EnterScopeInternal
923c1d  mov rcx, rdi
923c23  call 0x233F10                        ; <the real work>
923c28  call rbx                             ; LeaveScope
923c34  ret
```

So the pre-think body lives at **`0x233F10`**, and that body is **11 bytes**:

```asm
233f10  mov  dword ptr [rip+0x1D6AE52], 0   ; 0x1F9ED6C = 0
233f1a  ret
```

That is the whole of `CCSGameRules::FrameUpdatePreEntityThink`'s payload: it
clears a single global dword at **`0x1F9ED6C`**. That global is read at
`0x2086B2` / `0x2086C7` and `0x237BE2` / `0x237BF7` and written here only — a
per-frame "pending" latch. The pre-entity-think hook is therefore a one-line
state clear, not a subsystem driver; all the rules work happens in `Think`
(slot 50). This corrects an inference made earlier in the analysis.

**`CCSGameRules::Think`** (`0x9669F0`, **7,173 bytes**) is the round/phase state
machine. It is called only through vtable slot 50. Its structure:

* VProf open with `"CCSGameRules::Think"` (`0x18C9CA0`), file
  `...\cs_gamerules.cpp` (`0x18C8B70`), line `0x2909` (`0x966A0A`).
* `0x966A58` → `0x13DC1F0` (198 B), `0x966A5D` → `0xC597C0` (81 B), then a
  `test al,al; jne 0x9685E4` guard.
* `0x966A9F` calls `[0x21BA010 vtable +0xD0]` — an engine→server query. On null
  it calls `[+0xC0]` and records a 32-bit value into the ring buffer at
  `[r15+0x5438]` with a wrap at `0x1000` (`0x966AC7`–`0x966AEA`); a second ring
  at `[r15+0x9440]` (also wrap `0x1000`, `0x966AFC`–`0x966B1F`); a third at
  `[r15+0xD448]` (`0x966B3B`).
* Phase transition detection at `0x9683D2`: `mov eax,[r15+0x11C]` (the old
  `m_gamePhase`), store `[r15+0x13A8]`, then a chain of comparisons that fire
  `IGameEventManager2::CreateEvent` + `FireEventToClient` (vtable `+0xC8` on the
  manager at `[0x21BA1C0]`) with these event names, in this order:

  | compare | event string |
  |---|---|
  | `eax == 5` | `"MatchEnded"` (`0x18CB7A0`) |
  | `[rsp+0x58][0] != 0` | `"WarmupPeriod"` (`0x18CB7B0`) |
  | `[r15+0xD8] != 0` | `"FreezePeriod"` (`0x18CB7C0`) |
  | `[r15+0xA44] != 0` | `"RoundOver"` (`0x18CB7D0`) |
  | `eax == 4` | `"HalfTime"` (`0x18CB7E0`) |

  (Offsets `+0x11C` = `m_gamePhase`, `+0xD8` = `m_bFreezePeriod`,
  `+0xA44` = `m_bRoundOver`-ish, `+0x13A8` = last-seen phase — the first three
  are confirmed by the `CCSGameRules` network-field binder at `0x933450`,
  which references `m_gamePhase` (`0x935765`), `m_bFreezePeriod` (`0x9334C2`),
  `m_bWarmupPeriod` (`0x933705`), `m_bBombPlanted` (`0x936DE9`), etc.)
* `0x966DF2`–`0x968900` emit the round-flow notices:
  `"#SFUI_Notice_Player_Balanced"`, `"#SFUI_Notice_Teams_Balanced"`,
  `"#SFUI_Notice_Auto_Team_Balance_Next_Round"`, `"cs_win_panel_match"`,
  `"endmatch_cmm_start_reveal_items"`, `"WonRound"`, `"announce_phase_end"`,
  `"buytime_ended"`, `"radio.locknload"`, `"round_time_warning"`,
  `"World triggered \"Restart_Round_(%i_%s)\""`, `"Team \"CT\" scored \"%i\"
  with \"%i\" players"`, `"#SFUI_Notice_Game_will_restart_in"`,
  `"#SFUI_Notice_All_Players_Connected"`.

The `0x933450` function (25,686 bytes) is the `CCSGameRules` **network-field
binder**: it walks 117 `NetworkVar` descriptors in declaration order
(`m_bFreezePeriod`, `m_bWarmupPeriod`, `m_fWarmupPeriodEnd`, … `m_iRoundWinStatus`),
calling `CNetworkSerializerClassInfo::Get` and the field-registration helpers.
It is the server-side analogue of `client.md` §6.2's `0x7625AC`.

---

## 4. Network serialization

### 4.1 The serializer

The entity2 network serializer is compiled into this module. Its identifying
strings all come from `...\src\entity2\entity2_networking.cpp` (`0x1A5C780`):

| RVA | string |
|---|---|
| `0x177C1D8` | `CNetworkSerializerClassInfo::Get( %s ) failed!` |
| `0x1A5B520` | `CNetworkSerializerFieldInfo::InitCodeGenTypes:  unable to find class %s for field %s %s::%s` |
| `0x1A5C7C8` | `CNetworkSerializerBindingBuildFilter::GetFieldPriority` |
| `0x1A5C6E8` | `CNetworkSerializerBindingBuildFilter` vtable |
| `0x1A5C6B8` | `INetworkSerializerBindingBuildFilter` vtable |

`CNetworkSerializerBindingBuildFilter::GetFieldPriority` is at **`0x13AC0A0`**
(199 bytes); it asserts
`nPriority != NETWORK_FIELD_CHANGE_DEFAULT_PRIORITY` and
`"Component %s illegally specified INT_MIN as its priority!"`
(`0x13AC154`), both from `entity2_networking.cpp` (`0x13AC115`).

`CNetworkSerializerClassInfo::Get` is called from **178** distinct sites — every
generated `NetworkVar` binder in the image. The class-info dictionary is
`CUtlDict<class CNetworkSerializerClassInfo*, class CDefFastCaselessStringLess>`
(RTTI, its `Insert` at `0x1A5B6C0`). Class-info lookup is **caseless**; the
`CreateInterface` lookup above is case **sensitive**. That is a real,
observable asymmetry between the two registries.

`CNetworkTransmitComponent` (RTTI `0x1B20BB8`, vtable **`0x1781F40`**, 6 slots)
is the per-entity transmit state:

| slot | RVA | behaviour |
|---|---|---|
| 0 | `0x186B40` | `FireEvent( m_bPendingStateChange == true )` — the full-change marker |
| 1 | `0x1A3CC0` | 33 bytes |
| 2 | `0x195BC0` | 56 bytes |
| 3 | `0x18F9F0` | 0 (leaf) |
| 4 | `0x195790` | 0 (leaf) — a *second* `CNetworkTransmitComponent`-named binder |
| 5 | `0x17E010` | 221 bytes |

`0x186B40` is the delta-compression reset point:

```asm
186b40  cmp  byte [rcx+0x185], 0        ; m_bPendingStateChange
186b4d  je   186c2d                     ; nothing pending
186b56  cmp  byte [0x1F49CE6], 0        ; developer/diagnostic channel
186b5d  je   186c16
186b63  mov  eax, [rcx+0x180]           ; m_nChangeFlags
186b69  test al, 2
186b6b  jne  186c16
   ...    log "CNetworkTransmitComponent::FireEvent( m_bPendingStateChange == true )"
   ...    log "%s:  %d %s being marked full change"
186c16  lock or dword [rcx+0x180], 3    ; set FULL_CHANGE bits
186c1e  xor  eax, eax
186c20  mov  word [rcx+0x19E], ax       ; clear delta counters
186c27  mov  byte [rcx+0x185], al       ; clear pending flag
186c2d  ret
```

So `[this+0x180]` is a bitfield of change flags (bits 0/1 = "full change"
requested), `[this+0x185]` is the pending flag, and `[this+0x19E]` is a pair of
16-bit delta counters that reset on a full change. This is the mechanism behind
`m_bPendingStateChange`, `m_bFullChange`, and the per-entity baseline diff.

### 4.2 The snapshot / packet-entities message set

The wire messages are the protobuf `CSVCMsg_*` family, defined by string
literals in this image:

| RVA | string |
|---|---|
| `0x1890311` | `CSVCMsg_PacketEntities` |
| `0x1890372` | `update_baseline` |
| `0x189038B` | `baseline` |
| `0x18904A5` | `alternate_baselines` |
| `0x18904BE` | `2,.CSVCMsg_PacketEntities.alternate_baseline_t` |
| `0x1890550` | `22.CSVCMsg_PacketEntities.non_transmitted_entities_t` |
| `0x18905EB` | `21.CSVCMsg_PacketEntities.outofpvs_entity_updates_t` |
| `0x1890666` | `baseline_index` |
| `0x18903C6` | `pending_full_frame` |
| `0x188FAAD` | `CSVCMsg_ClassInfo` |
| `0x1890A5A` | `CSVCMsg_FullFrameSplit` |
| `0x1889068` | `CSVCMsg_FlattenedSerializer` |
| `0x188F906` | `CSVCMsg_ServerInfo` |
| `0x188A297` | `CSVCMsg_GameSessionConfiguration` |
| `0x188FAEB` | `.CSVCMsg_ClassInfo.class_t` |
| `0x1891D4B`, `0x1882130` | `svc_PacketEntities` |
| `0x1891E01`, `0x18821E0` | `svc_FullFrameSplit` |
| `0x1891C3F`, `0x1882028` | `svc_ClassInfo` |
| `0x18819D0` | `clc_BaselineAck` |
| `0x188F597` | `CCLCMsg_BaselineAck` |
| `0x1891AF5` | `clc_BaselineAck` |
| `0x1882258`, `0x1891E85` | `svc_UserCmds` |
| `0x19CD290` | `Delta encode svc_UserCmds message` |

The field-name strings are **protobuf reflection metadata**, not code paths:
they are referenced only from the generated `CProtobufBinding<>` descriptors
(e.g. `.?AVCSVCMsg_PacketEntities@@` at `0x1EDE228`,
`.?AVCSVCMsg_PacketEntities_alternate_baseline_t@@` at `0x1EDD5D0`). A
rip-relative scan finds **zero** `.text` references to
`CSVCMsg_PacketEntities`, `svc_PacketEntities`, or `CSVCMsg_FullFrameSplit`.
The *serializer itself* is not in this module — it lives in
`networksystem.dll`/`engine2.dll`, and the server reaches it through
`NetworkSystemVersion001` (`0x23AB568`) and `NetworkMessagesVersion001`
(`0x23AB570`).

What *is* in this module is the server-side writer of the two user-command
paths and the class-info registration:

* `0x108BB0` (152 bytes) registers ConVar
  `sv_cq_delta_encode_svc_usercmds` (`0x19CD2B8`, help
  `"Delta encode svc_UserCmds message"` at `0x19CD290`, flags `0x82000`).
* `0x108E70` registers `sv_cq_validate_encoded_svc_usercmds`
  (`0x19CD340`).
* `0x105DE0` registers `cq_fake_starve`
  (`0x19CD280`, help
  `"if set, starve this many commands by discarding during process usercmds."`
  at `0x19CD230`).
* `0x108F20` registers `sv_lagcompensationforcerestore`
  (`0x19CB240`).

Those four are the only places in `.text` where the usercmd-delta machinery is
exposed; the encode/decode bodies are behind the `NetworkSystemVersion001`
vtable.

### 4.3 The snapshot writer in `CSource2Server`

The only `CSource2Server` slot that touches serialization directly is slot 14,
`0xDD8760` (241 bytes):

> `"CSource2Server::WriteSignonMessages: Failed to serialize Source1LegacyGameEventList_t"` (`0x1993EF0`)

That is the signon path: the server serializes the legacy game-event list into
the signon blob and logs this on failure. The corresponding success path is in
slot 13, `0xDD86E0` (120 bytes):

> `"Forcing S1 g_pNetworkStringTable to use version from engine.dll"` (`0x1994050`, used at `0xDD870F`)

which reconciles the Source-1 style network string table with the engine's copy
— the same compatibility shim the client has.

The **transient snapshot cache** is `CServerTransientSnapshotCache` (RTTI
`0x1B772F0`, vtable **`0x1942CD8`**, 65 slots). Its only non-trivial slots:

| slot | RVA | behaviour |
|---|---|---|
| 4 | `0xBCA8A0` | 30 B — release every cached handle (`lock dec [obj+0x20]`, call release vtable `+0x10`) |
| 35 | `0xBCA950` | 35 B — evict entries older than `g_pGlobals->tickcount` (`0x1E328D0+0x44`) |
| 60 | `0xBCA880` | 0 |
| 62 | `0xBCA870` | 0 |
| 63 | `0xBCBC80` | 64 B — destructor |
| 64 | `0xBCA860` | 0 |

The cache is a `CUtlVector`-like array of 16-byte `{handle, tick}` entries at
`[this+0x20]` with count at `[this+0x18]`; `0xBCA950` walks from the tail and
drops entries whose tick is older than the current globals tick, shifting the
rest down. This is the server's "keep the last N snapshots for rewind" store,
not the wire encoder.

### 4.4 `CSource2GameEntities001`

The `Source2GameEntities001` interface (registered at `0x0EEAA0`, factory
`0xDF60E0` → slot `0x1E333E0`) is the game-entity service the engine binds to.
Its vtable is at `0x1E333E0`; the object's methods are the entity-spawn /
entity-lookup surface used by `CGameEntitySystem`. The corresponding
`Source2GameClients001` (factory `0xDF60D0` → `0x1E33160`) is the per-client
service. Both are 1-slot secondary vtables in the RTTI sense; the real work is
in the `CGameEntitySystem` vtable below.

`CGameEntitySystem` (RTTI `0x1B78F90`, vtable **`0x1945ED0`**, 24 slots):

| slot | RVA | size | identification |
|---|---|---|---|
| 0 | `0xBEBF80` | 114 | |
| 1 | `0xBEC000` | 340 | `"GameSessionManifest.vrgrp"` |
| 2 | `0xBEBAC0` | 1,202 | `"kv 0x%p AddRef refcount == %d"` — the KV handle refcount |
| 3 | `0xBEB9B0` | 122 | |
| 4 | `0xBEBA30` | 135 | |
| 5 | `0xBEC160` | 114 | |
| 6 | `0xC0BA20` | 124 | |
| 7 | `0x137C610` | 87 | `"kv 0x%p AddRef refcount == %d"` |
| 8 | `0x138AE90` | 122 | `"kv 0x%p Release refcount == %d"` |
| 9 | `0xC10990` | 30 | |
| 10 | `0xBE3350` | 216 | |
| 11 | `0xC02860` | 29 | |
| 13 | `0xBFDEA0` | 554 | `"player"`, `"pvsplayer"`, `"picker"`, `"parent"`, `"owner"` — the PVS/ownership filter |
| 14 | `0xC12880` | 98 | |
| 15 | `0xC122F0` | 94 | |
| 16 | `0xC12A90` | 101 | |
| 18 | `0xC2AC10` | 94 | |
| 19 | `0xC2AC70` | 125 | |
| 20 | `0xBE3EA0` | 47 | |
| 21 | `0xC14E40` | 63 | |
| 22 | `0xC12C40` | 114 | |
| 23 | `0xC34000` | 47 | |

Slot 13's `"pvsplayer"` / `"picker"` strings make it the **PVS filter** — the
function that decides which entities are transmitted to which client. It is the
server-side counterpart of the client's `C_BaseEntity` PVS handling.

---

## 5. Game rules and modes

### 5.1 The hierarchy

`CCSGameModeRules` is a separate, smaller class from `CCSGameRules`. The RTTI
descriptors are:

| class | type descriptor | vtable | slots |
|---|---|---|---|
| `CCSGameModeRules` | `0x18B9C98` | **`0x18C5AA0`** | 11 |
| `CCSGameModeRules_Noop` | `0x18BA970` | **`0x18C5B00`** | 11 |
| `CCSGameModeRules_ArmsRace` | `0x18BE868` | **`0x18C5B60`** | 11 |
| `CCSGameModeRules_Deathmatch` | `0x18BEC60` | **`0x18C5D28`** | 11 |

There are exactly **four** subclasses; `ArmsRace`, `Deathmatch` and `Noop` are
the only concrete modes. (No `_Casual`, `_Competitive`, `_Wingman`, `_Retake`
subclass exists in this build — those are expressed through `CCSGameRules`
fields and `CCSGameModeRules_Noop` plus ConVars.)

The mode-rule objects are **constructed** at `0x905580` (ArmsRace, 219 B) and
`0x905660` (Deathmatch, 456 B). Each writes the *base* vtable first
(`0x18C5AA0` at `0x905595` / `0x90567E`), initialises the fields, then
overwrites `[rcx]` with the subclass vtable (`0x18C5B60` at `0x9055D5`,
`0x18C5D28` at `0x9056CC`). Neither constructor calls the base's slot-2 body;
they are self-contained. They are reached only from factory code
(`0x8D98A6` / `0x8D98D4` jump to the ArmsRace ctor; `0x944617` / `0x944687`
jump to both), never from a vtable.

The vtable slot 2 body `0x90BB40` (157 B) is the **scalar deleting destructor**,
not a constructor. It is stored at `0x18C5AB0` (= vtable + 2×8), and it:

```asm
90bb4f  lea  rax, [0x18C5AA0]     ; restore the base vtable
90bb58  mov  [rcx], rax
90bb63  mov  dword [rcx+0x10], 0
90bb66  test dword [rcx+0x24], 0xC0000000
90bb6b  jne  90bbb7               ; static allocation -> no free
90bb6d  mov  rdx, [rcx+0x18]      ; vector data
90bb83  call [g_pMemAlloc vtable+0x18]   ; free()
90bb86  mov  qword [rcx+0x18], 0
90bb8d  mov  dword [rcx+0x20], 0  ; count = 0
90bb90  ...                       ; a second identical free/reset
90bbb7  test dil, 1               ; the MSVC "delete this?" flag
90bbbb  je   90bbca
90bbbd  mov  edx, 0x30            ; object size
90bbc5  call 0xFF2490             ; operator delete
90bbca  ret
```

The `0x30` passed to `operator delete` is the base object size, confirming the
base class is 48 bytes. The `0xC0000000` mask on `[+0x24]` is the
"static/allocated-in-place" flag pair the rest of the engine uses for
`CUtlVector`.

The per-class helper functions in the schema-descriptor rows are
`0x8D9490` (Noop, referenced from `0x1E06D98`), `0x8D9620` (ArmsRace, from
`0x1E06E18`) and `0x8D97B0` (Deathmatch, from `0x1E06ED0`). Each dispatches on a
small selector (`sub ecx,2; je …; sub ecx,1; je …`), i.e. they are the
per-class field-list accessors used by the serializer.

### 5.2 `CCSGameModeRules` — the base class, reversed

Vtable `0x18C5AA0`, 11 slots. Full map with real sizes (leaf-aware):

| slot | RVA | size | body |
|---|---|---|---|
| 0 | `0x95EEF0` | 33 | schema-binder stub: `lea rdx,[0x1E06D30]; call 0x165BFC0; ret` |
| 1 | `0x91A570` | 8 | `mov rax,[0x211A730]; ret` |
| 2 | `0x90BB40` | 157 | **scalar deleting destructor** — restores the base vtable, frees the vector at `+0x18`, `operator delete` with size `0x30` |
| 3 | `0x93D4F0` | 3 | `mov al,1; ret` |
| 4 | `0x94EA60` | 1 | `ret 0` |
| 5 | `0x94DF10` | 1 | `ret 0` |
| 6 | `0x94DE20` | 1 | `ret 0` |
| 7 | `0x94DE30` | 1 | `ret 0` |
| 8 | `0x94D9B0` | 1 | `ret 0` |
| 9 | `0x94DDE0` | 1 | `ret 0` |
| 10 | `0x921C20` | 1 | `ret 0` |

So the **base class is a pure interface with empty defaults**. Slot 0 is the
network-schema binder for the class `CCSGameModeRules` (the schema descriptor at
`0x1E06D30` holds `{0, &".?AVCCSGameModeRules@@"}`). Slot 2 is the only
non-trivial base slot: the destructor, not a constructor.

The base object layout, from the destructor and from the two subclass
constructors, is:

```
+0x00  vtable
+0x08  void*   base sub-object pointer (written by 0x9055B1 / 0x9056C1)
+0x10  int32   some mode id (0)
+0x18  void*   vector data
+0x20  int32   vector count
+0x24  int32   vector capacity | 0xC0000000 static bits
+0x28  int32   (0xFFFFFFFF init at 0x9055E7)
+0x2C  bool    (0x9055EE)
```

and the destructor's `operator delete(rcx, 0x30)` confirms a 48-byte base.

### 5.3 `CCSGameModeRules_ArmsRace` — the subclass

Vtable `0x18C5B60`, 11 slots. Differences from the base:

| slot | base | ArmsRace | body |
|---|---|---|---|
| 0 | `0x95EEF0` | **`0x95EF20`** | schema binder → descriptor `0x1E06E60` |
| 1 | `0x91A570` | **`0x91A580`** | `mov rax,[0x211A750]; ret` |
| 2 | `0x90BB40` | **`0x90BBE0`** | scalar deleting destructor (52 B) — calls `0x908CD0` then `operator delete` |
| 3 | `0x93D4F0` | **`0x93D4F0`** | inherited `mov al,1; ret` |
| 4 | `0x94EA60` | **`0x94EA70`** | 184 B — the mode's per-frame update |
| 5 | `0x94DF10` | **`0x94DF20`** | **868 B — `GMR_ResetRound`** |
| 6 | `0x94DE20` | `0x94DE20` | inherited |
| 7 | `0x94DE30` | **`0x94DE40`** | 34 B — resets the fields at `+0x4C`..`+0x64` |
| 8 | `0x94D9B0` | **`0x94D9C0`** | 450 B — the "start round" hook |
| 9 | `0x94DDE0` | **`0x94DDF0`** | 28 B — `jmp 0x92C0F0` |
| 10 | `0x921C20` | **`0x921C30`** | 77 B |

The constructor `0x905580` writes the full object layout:

```asm
905595  lea rax, [0x18C5AA0]        ; base vtable first
90559c  mov [rcx], rax
9055ad  mov qword [rcx+8], 0
9055b5  ...                         ; TLS/thread guard (0x23C)
9055d5  lea rax, [0x18C5B60]        ; THEN the ArmsRace vtable
9055dc  mov qword [rbx+0x18], 0     ; vector data
9055e0  mov qword [rbx+0x20], 0     ; count
9055e4  mov dword [rbx+0x10], 0
9055e7  mov dword [rbx+0x28], -1
9055ee  mov byte  [rbx+0x2c], 0
9055f2  mov qword [rbx], rax        ; install subclass vtable
9055f7  mov qword [rbx+0x38], 0
9055fb  mov qword [rbx+0x40], 0
9055ff  mov dword [rbx+0x30], 0
905602  mov word  [rbx+0x48], 1
905608  mov dword [rbx+0x4c], -1
90560f  mov dword [rbx+0x50], 0
905612  mov dword [rbx+0x54], -1
905619  mov dword [rbx+0x58], 0
90561c  mov qword [rbx+0x5c], 0
905620  mov dword [rbx+0x64], -1
905627  mov qword [rbx+0x68], 0
90562b  mov qword [rbx+0x70], 0
90562f  mov dword [rbx+0x80], 0x20
905639  mov byte  [rbx+0x84], 0
90563f  mov qword [rbx+0x78], 0
905643  call  0x956090              ; CUtlVector/string-pool init
```

So `ArmsRace` adds, past the base's `+0x2C`:

```
+0x30  float   (0 at 0x9055FF)
+0x38  void*   vector data
+0x40  void*   vector data 2
+0x48  uint16  = 1
+0x4C  int32   = -1
+0x50  int32   = 0
+0x54  int32   = -1
+0x58  int32   = 0
+0x5C  void*   = 0
+0x64  int32   = -1
+0x68  void*   = 0
+0x70  void*   = 0
+0x78  void*   = 0
+0x80  int32   = 0x20   (capacity)
+0x84  bool    = 0
```

`0x94DF20` (**`GMR_ResetRound`**, 868 B) is the round reset. It:

1. calls `0x956090` (the vector/string-pool reset),
2. sets `[this+0x64] = -1`,
3. walks the entity list at `0x1E328D0` (globals) looking for a live player via
   `0xCBC9A0(entity_index)`, then, for each, checks
   `[ent+0x388] & 0x100` (a "connected/active" bit) and calls
   `[0x21BA010 vtable +0x308]` (engine→server "respawn/notify") with
   `r9d = 0x27`,
4. clears `[0x21BA1C0+0xDC4]` and calls `0x9244B0` (866 B, the round-state
   reset) on `g_pCCSGameRules`,
5. logs `"GMR_ResetRound"` (`0x18CBDA0`) on the diagnostic channel.

`0x94D9C0` (450 B) is the "start round" hook: it reads
`[player+0x388] >> 8 & 1` (the same connected bit), and calls `0xA71500` (368 B)
or the engine respawn path depending on it.

`0x921C30` (77 B) is the `ArmsRace` slot-10 override, reading
`[0x1F?]` globals; `0x921C20` (base, 1 byte) is a no-op.

### 5.4 `CCSGameModeRules_Deathmatch` — contrast

Vtable `0x18C5D28`, 11 slots:

| slot | RVA | size | note |
|---|---|---|---|
| 0 | `0x95EF50` | 33 | schema binder → descriptor `0x1E06F68` |
| 1 | `0x91A590` | 8 | `mov rax,[0x211AC10]; ret` |
| 2 | `0x90BC20` | 52 | scalar deleting destructor (calls `0x908E40`) |
| 3 | `0x93D4F0` | 3 | inherited |
| 4 | `0x94F530` | **2,757** | per-frame DM bonus/weapon logic |
| 5 | `0x94E290` | **852** | **`GMR_ResetRound`** |
| 6 | `0x94DE20` | 1 | inherited |
| 7 | `0x94DE70` | 98 | |
| 8 | `0x94DB90` | 62 | |
| 9 | `0x94DDE0` | 1 | inherited |
| 10 | `0x922080` | **2,265** | kill-award / scoring |

`Deathmatch`'s schema descriptor at `0x1E06EF0`–`0x1E06F60` declares three
network fields:

| field | type | offset |
|---|---|---|
| `m_flDMBonusStartTime` (`0x18BF088`) | float | 0x30 |
| `m_flDMBonusTimeLength` (`0x18BF0B0`) | float | 0x34 |
| `m_sDMBonusWeapon` (`0x18BF0C8`) | string | 0x38 |

which are exactly the `NetworkVar` types the RTTI file lists as
`?$CNetworkVarBase@MVNetworkVar_m_flDMBonusTimeLength@CCSGameModeRules_Deathmatch`
(`rtti/server.txt`). The base class declares only `__m_pChainEntity`
(`0x1781340`) at `0x1E06D10`.

`0x94E290` (`GMR_ResetRound` for DM) logs the same `"GMR_ResetRound"` string and
performs the DM variant of the respawn sweep. `0x922080` (2,265 B) contains the
scoring strings `"weapon_healthshot"` (`0x9225E8`),
`"#Player_Point_Award_Assist_Enemy_Plural"` (`0x922837`),
`"#Player_Point_Award_Assist_Enemy"` (`0x92283E`), `"chicken"` (`0x92288B`),
`"unknown"` (`0x9228CE`), `"#Player_Point_Award_Killed_Enemy"` (`0x9228F5`),
`"#Player_Point_Award_Killed_Enemy_NoWeapon"` (`0x922913`) — the kill-award
table.

### 5.5 `CCSGameModeRules_Noop`

Vtable `0x18C5B00`, 11 slots, and it is **byte-identical to the base** in every
slot except slot 2 (destructor `0x90BC60`, 157 B — same code as the base's
`0x90BB40` but installing `0x18C5B00`), slot 0 (binder `0x95EF80` → descriptor
`0x1E06DA0`) and slot 1 (`0x91A5A0`). Its slot 3 is `0x93D500` (`xor al,al;
ret`) — the only behavioural difference from the base's `mov al,1; ret`. That
single-bit difference is how "no game mode" reports itself as inactive.

---

## 6. Movement and prediction parity

### 6.1 The class

`CPlayer_MovementServices` (RTTI `0x1B7BD40`, vtable **`0x1953190`**, 51 slots)
and `CPlayer_MovementServices_Humanoid` (vtable **`0x1953610`**) are the
server-side movement services. `CCSPlayer_MovementServices` is a separate,
larger class (RTTI `0x1B716B8`, vtable **`0x1923F70`**, 59 slots) that adds the
CS-specific duck/stamina/jump state.

The three named functions, and the only call sites that reach them, are:

| function | RVA | size | slot | callers |
|---|---|---|---|---|
| `CPlayer_MovementServices::UpdateInputState` | **`0xC7FCC0`** | 744 | 23 | `0xA51010`, `0xAE91D0` |
| `CPlayer_MovementServices::SetupMove` | **`0xC7E8D0`** | 690 | 34 | `0xA500C0`, `0xAE2344` |
| `CPlayer_MovementServices::DoMovement::Subtick` | **`0xC6F2A0`** | 1,175 | (not virtual — internal) | — |

All three are VProf-wrapped with `...\src\game\shared\player_movementservices.cpp`
(`0x19533E0`) and the literal function names at `0x1953430`, `0x1953500`,
`0x1953540`.

### 6.2 `UpdateInputState` — `0xC7FCC0`

```asm
c7fcc0  ...                          ; VProf open, "CPlayer_MovementServices::UpdateInputState"
c7fd3a  cmp  qword [rdi+0x38], 0     ; m_pPawn?
c7fd43  call 0xC856B0                ; lazy-init the back-pointer
c7fd48  mov  rcx, [rdi+0x38]
c7fd4c  lea  r8,  [rsp+0xB8]
c7fd54  mov  rdx, r13                ; the CUserCmd*
c7fd57  call 0xD3EFD0                ; extract button bits from the cmd
c7fd5c  mov  rcx, [rsp+0xB8]
c7fd64  or   qword [rdi+0x78], rcx   ; m_nButtons |= cmd->buttons
c7fd68  not  rcx
c7fd6b  and  qword [rdi+0x70], rcx   ; m_nOldButtons &= ~cmd->buttons
c7fd6f  ...
c7fd7e  call 0xC86930                ; get the pawn
c7fd88  ...                          ; if pawn && !dead -> [pawn+0x4B0]
c7fdbb  mov  r9, [rdi+0x190]
```

`[this+0x70]` = previous buttons, `[this+0x78]` = current buttons. The
`0xD3EFD0` call is the `CUserCmd` → button-bit extractor, the same one the
client uses.

### 6.3 `SetupMove` — `0xC7E8D0`

```asm
c7e8d0  ...                          ; VProf open
c7e943  cmp  qword [rsi+0x38], 0
c7e94c  call 0xC856B0                ; lazy pawn back-pointer
c7e951  mov  r14, [rsi+0x38]
c7e95a  ...                          ; build an EntityHandle from [r14+0x10]
c7e994  mov  [rbp+4], r8d            ; out->entity = handle
c7e998  lea  rdi, [0x1DF3150]        ; default MoveData
c7e99f  mov  rax, [r13+0x40]
c7e9a3  lea  rcx, [0x1DFB448]
c7e9aa  test rax, rax
c7e9ad  cmovne rdi, rax              ; override with cmd-supplied move data
c7e9b1  mov  rax, [rdi+0x40]
c7e9b8  cmovne rcx, rax
c7e9bc  movss xmm3, [rcx+0x20]       ; view angles / velocity basis
c7e9c1  movss xmm2, [rcx+0x1C]
c7e9c6  movss xmm1, [rcx+0x18]
c7e9cb  lea  rcx, [rsp+0x20]
c7e9d0  call 0x1AB860                ; AngleVectors / basis construction
c7e9d5  mov  r8d, [rdi+0x7C]
c7e9d9  lea  r9, [rsp+0xB0]
```

`SetupMove(this, CUserCmd*, CMoveData*)` is the classic Source signature, and
the body is the classic body: resolve the pawn, build the entity handle, pick
the move-data basis, call the angle→vector helper at `0x1AB860`, then fill the
`CMoveData` fields. `0x1DF3150` and `0x1DFB448` are the two static default
`CMoveData`/basis objects.

### 6.4 `DoMovement::Subtick` — `0xC6F2A0`

This is the CS2 sub-tick movement integrator. It is the function that consumes
`CSubtickMoveStep` records (RTTI `0x1ED7160`, proto name at `0x184357F`) and the
`subtick_*` field names at `0x19224A0`–`0x1922760`
(`subtick_duration_fraction`, `subtick_end_fraction`, `subtick_start_fraction`,
`subtick_duration`, `end_subtick_fraction`, `start_subtick_fraction`).

```asm
c6f2a0  ...                          ; prologue, save xmm6..xmm15
c6f2e6  mov  rax, [rcx]
c6f2e9  call [rax+0x128]             ; virtual: "is this move sub-ticked?"
c6f2ef  mov  r14d, [rdi+0x28]        ; step count
c6f2f3  xor  r15d, r15d
c6f2f6  movzx r13d, al
c6f2fa  movsd xmm7, [rdi+0x14]       ; start fraction (double)
c6f303  movsd xmm10, [rdi+0x20]      ; end fraction
c6f30c  mov  ebx, [rdi+0x1C]
c6f348  cmp  dword [rdi+0x60], 0     ; any steps?
c6f34c  jle  0xC6F6C5
c6f358  lea  rax, [0x19533E0]        ; "...\player_movementservices.cpp"
c6f367  lea  rcx, [0x1953530]        ; "DoMovement"
c6f3dc  lea  rcx, [0x1953540]        ; "CPlayer_MovementServices::DoMovement::Subtick"
c6f3ff  call [0x176B128]             ; VProf enter
c6f405  mov  rbp, [rdi+0x68]         ; step array
c6f40c  mov  rcx, rdi
c6f412  movss xmm2, [rsi+rbp]        ; step[i].time
c6f417  call 0xC610B0                ; apply one step at time
c6f41c  ucomiss xmm6, [rsi+rbp]
c6f422  je   0xC6F5A4                ; zero-length step -> skip
c6f428  ...                          ; write back [rdi+0x20]/[rdi+0x28]/[rdi+0x2C]/[rdi+0x30]/[rdi+0x34]
c6f451  mov  eax, [rsi+rbp+0x18]
c6f455  mov  [rdi+0x14], eax         ; view angles
c6f458  mov  eax, [rsi+rbp+0x1C]
c6f45c  mov  [rdi+0x18], eax
c6f45f  ...                          ; stamina / duck accumulation from [rdi+0xD4]/[rdi+0xD8]/[rdi+0xDC]/[rdi+0xE0]
```

The loop at `0xC6F3C0`–`0xC6F5A4` runs once per sub-tick step, each call to
`0xC610B0` advancing the simulation by `step[i].time` and updating
`[rdi+0x14]`/`[rdi+0x18]` (view angles) and the stamina accumulator
`[rdi+0xDC]`–`[rdi+0xE0]`. This is the authoritative counterpart of the
client's prediction step: identical code shape, same `CMoveData` offsets.

`sv_subtick_movement_view_angles` (`0x1922F70`) gates whether sub-tick view
angles participate, with the help string
`"Whether or not subtick view angles are taken into account during movement."`
at `0x1922F20`.

### 6.5 `CCSPlayer_MovementServices` extras

`CCSPlayer_MovementServices` (vtable `0x1923F70`, 59 slots) adds the CS-specific
state. The named bodies:

| slot | RVA | size | identification |
|---|---|---|---|
| 8 | `0xAE2020` | 339 | |
| 9 | `0xC6C880` | 202 | |
| 11 | `0xC7FFB0` | 71 | |
| 13 | `0xC7BE80` | 417 | |
| 15 | `0xC7B8C0` | 339 | |
| 23 | `0xAE91C0` | 93 | |
| 25 | `0xC7CB80` | 254 | `"frozen"` |
| 27 | `0xC6DFC0` | 2,544 | the main per-command move |
| 33 | `0xAC6FC0` | 265 | |
| 35 | `0xAE26B0` | 255 | |
| 36 | `0xAE2C50` | 145 | |
| 38 | `0xAC4B20` | 222 | |
| 39 | `0xAC4C00` | 282 | |
| 42 | `0xC7F1E0` | 265 | |
| 43 | `0xAC46E0` | 245 | |
| 44 | `0xC7F120` | 186 | `"sv_cheats"` |
| 45 | `0xABCD00` | 522 | |
| 47 | `0xC70E10` | 1,351 | |
| 48 | `0xAB79E0` | 685 | |
| 49 | `0xC6FDE0` | 341 | |
| 51 | `0xC7F8B0` | 250 | |
| 53 | `0xAE9A50` | 144 | |
| 56 | `0xAE2230` | 220 | |
| 58 | `0xADC080` | 114 | `"player_footstep"` |

`0xACD6F0` (12,169 B) is the `CCSPlayer_MovementServices` **network-field
binder** (the analogue of `client.md` §6.14's `0x8C6910`). It declares the CS
movement network vars in declaration order:
`m_bUsingGroundTopologyOffset`, `m_flUsingGroundTopologyOffsetTransitionSmoothing`,
`m_nLadderSurfacePropIndex`, `m_bDucked`, `m_flDuckAmount`, `m_flDuckSpeed`,
`m_bDuckOverride`, `m_bDesiresDuck`, `m_bDucking`, `m_flDuckRootOffset`,
`m_flDuckViewOffset`, `m_flLastDuckTime`, `m_flBombPlantViewOffset`,
`m_nGameCodeHasMovedPlayerAfterCommand`, `m_fStashGrenadeParameterWhen`,
`m_bUseFrictionStashedSpeed`, `m_flUseFrictionStashedSpeedUntilFrac`,
`m_flFrictionStashedSpeed`, `m_flStamina`, `m_LegacyJump`, `m_ModernJump`,
`m_nLastJumpTick`, `m_flLastJumpFrac`, `m_flLastJumpVelocityZ`,
`m_bJumpApexPending`, `m_bHasEverProcessedCommand`. Those names, together with
`CCSPlayerLegacyJump` (`0xACF932`) and `CCSPlayerModernJump` (`0xACFA18`),
confirm the class is the CS movement state, not the generic engine one.

### 6.6 The pre-move hooks

`PreWalkMove` (`0x1924EB0`) and `PreSource1AirMove` (`0x1924EC0`) are the two
named hooks the CS movement inserts before the generic walk/air integrators:

| function | RVA | size | referenced from |
|---|---|---|---|
| `PreWalkMove` | `0xAEAA70` | 1,328 | `0xAEAC83` (inside itself, the VProf name) |
| `PreSource1AirMove` | `0xAE34A0` | 64 | `0xAE34B8` |

`0xAEAA70` is a full movement integrator (speed clamp, `sqrtss` on the velocity
magnitude, the `0xAE0230`/`0xAD77F0` helpers, duck-state blending at
`[rsi+0x690]`/`[rsi+0x694]`). `0xAE34A0` is a 64-byte trampoline.

The ConVars that parameterise this code are all present in `index/cvars/server.json`:
`sv_accelerate` (`0x19B7BE8`), `sv_friction` (`0x19B7CB8`), `sv_maxspeed`
(`0x19B7BD8`), `sv_airaccelerate` (`0x19B7BF8`), `sv_accelerate_use_weapon_speed`
(`0x19228A8`), `sv_accelerate_debug_speed` (`0x19228C8`), `sv_staminajumpcost`
(`0x19225D8`), `sv_staminalandcost` (`0x1922628`), `sv_staminarecoveryrate`
(`0x1922818`), `sv_staminamax` (`0x1922848`).

### 6.7 The prediction *driver*

`CBasePlayerController::SimulateUserCommands` (vtable slot 271 of
`CBasePlayerController`, RTTI vtable `0x192F760`) is at **`0xB67390`** (40-byte
`.pdata` chunk, real body 541 bytes at `0xB67390`–`0xB675A4`). It is the
server's per-controller command pump:

```asm
b67390  ...                          ; VProf open, "...\baseplayercontroller.cpp"
b67399  mov  rax, [rcx]
b6739f  call [rax+0x820]             ; IsConnected/IsActive predicate
b673a7  je   0xB675A4                ; not active -> done
b673ad  mov  rcx, [0x218BFF8]        ; g_pGameConfiguration
b673b4  add  rcx, 8
b673c0  call [rax+0xB8]              ; config query
b673c9  test al, al
b673cb  je   0xB673DA
b673cd  mov  eax, [rdi+0x388]
b673d3  shr  eax, 8
b673d6  test al, 1
b673d8  je   0xB673E4
b673da  mov  dword [rdi+0x368], -1   ; clear the simulated tick
b673e4  ...                          ; resolve the pawn entity handle
b6743d  call [rax+0xB08]             ; notify the pawn
b67455  cmp  [rdi+0x368], ecx        ; already simulated this tick?
b6745b  je   0xB6759C                ; yes -> done
b67469  ...                          ; VProf open, "SimulateUserCommands"
b674ab  mov  [rdi+0x368], ecx        ; mark tick
b674ec  call [0x176A2B0]             ; GetCurrentThreadId
b674f2  ...                          ; save/restore globals timing fields
b67535  call [rax+8]                 ; (pre-command hook)
b67538  mov  rax, [rdi]
b6753e  call [rax+0x878]             ; <the real simulate>
b6754d  call [rax+8]                 ; (post-command hook)
b6756f  call rbx                     ; VProf leave
```

`CBasePlayerController::OnSimulateUserCommands` is at **`0xB66860`** (541-byte
`.pdata` chunk, 1,899 bytes real). It is the function that:
* VProf-opens with `"CBasePlayerController::OnSimulateUserCommands"`
  (`0x19335C8`), file `...\baseplayercontroller.cpp` (`0x19332D0`),
* at `0xB669D1` VProf-opens `"RunCommand"` (`0x19335F8`),
* at `0xB66A5B` calls `[cmd vtable +0x30]` (the command's `GetType`/`Clone`),
* at `0xB66B60` stores the `CUserCmd*` into `[r14+0x708]`,
* at `0xB66B6A` calls `[this vtable +0x828]` (the "process one command" hook),
* at `0xB66B90`–`0xB66BCA` walks a 24-byte-stride array at `[r14+0x7A8]` of
  `{int32 tick, uint32 flags, void* fn}` and invokes `fn` for each entry whose
  `tick <= current` and whose `flags & 8` is clear, then sets `flags |= 8`.

That array is the **per-command callback queue** — the server-side analogue of
the client's prediction event list.

`RunThinks` (`0x19332C0`) and `"controller->PhysicsRunThink()"` (`0x1933320`)
are the two strings referenced by `0xB66D94` and `0xB66DAD` inside
`0xB66860`; and again at `0xB71079` / `0xB71092` inside `0xB70F00` (the
`CCSPlayerPawn`/`CBasePlayerController` think runner). `0xB70F00` is the
function that walks `[rdi+0x708]` (the current `CUserCmd`) and calls
`0x2B74C0` (935 B) and `0x16A0D90` (192 B) per think.

---

## 7. Weapon firing and damage

### 7.1 The canonical fire path

The canonical server-side fire path is:

```
CBasePlayerWeapon/CCSWeaponBase  (virtual "primary attack")
   -> 0x9F8A70  CSBaseGunFire
        -> 0x2A4F50  FX_FireBullets
             -> 0x99A410  FireBullets (the bullet-loop)
```

**`0x9F8A70`** (1,824 bytes) is `CSBaseGunFire` (inferred name; the evidence is
the format string at `0x9F8D2D`:
`"%s: CSBaseGunFire player %s using %s attack time %.4f [ #%d : %.3f ]"` and the
two sibling strings `"interpolated"` (`0x9F8CFC`), `"last history"`
(`0x9F8D03`), `"no history - using calculated time %.4f"` (`0x9F8D8C`),
`"ang %.4f %.4f %.4f, pos %.4f %.4f %.4f"` (`0x9F8DE5`)). Its prologue:

```asm
9f8a70  ...                          ; save r9d (the attack mode)
9f8aa0  call 0xB54F20                ; get the owning pawn from `this`
9f8aab  je   0x9F8B81                ; no pawn -> out
9f8ab7  call [vtable+0xAC0]          ; "can fire?" (ammo/clip)
9f8ac3  test eax, eax
9f8ac5  jne  0x9F8B9B                ; cannot fire -> the dry-fire branch
9f8acb  cmp  byte [rsi+0xF50], 0     ; some weapon flag
9f8ad1  je   0x9F8B81
9f8ada  call 0xA1E400                ; compute inaccuracy/spread
9f8ae5  call [vtable+0xD28]          ; "is this a gun?" predicate
9f8aef  call [vtable+0xBB0]          ; get the current spread
9f8b11  call 0xB763D0                ; apply the spread
9f8b1c  call [vtable+0xD28]
9f8b34  mov  edx, 0x66               ; mode 0x66 = "primary"
9f8b39  call 0x9F7840                ; <the actual fire dispatch>
9f8b46  call [vtable+0xD38]          ; post-fire (recoil/anim)
9f8b4e  mov  edx, 0x32               ; mode 0x32 = "secondary"
9f8b53  call 0x9F7840
```

So `0x9F7840` (951 B) is the **mode dispatcher** — it takes the mode in `edx`
and performs the per-mode fire. `0x66`/`0x32` are the primary/secondary mode
IDs.

**`0x2A4F50`** (2,659 bytes) is **`FX_FireBullets`** — the function whose
identity is pinned by four strings:

* `0x17AAAE0` `"FireBullets @ %10f [ %s ]: inaccuracy=%f  spread=%f  max dispersion=%f  mode=%2i  vel=%10f  seed=%3i  %s"` (used at `0x2A52F0`)
* `0x17AAB90` `"FX_FireBullets: GetItemDefinition failed"` (at `0x2A511F`)
* `0x17AABC0` `"FX_FireBullets: GetWeaponEconDataFromItem failed for weapon %s"` (at `0x2A5147`)
* `0x17AAC00` `"FX_FireBullets: GetCSWeaponDataFromItem failed for weapon %s"` (at `0x2A51B9`)

Body:

```asm
2a4f50  ...                          ; prologue; rcx=player index, rdx=weapon
2a4f8e  test r8, r8                  ; r8 = the weapon entity
2a4f9c  call 0x1029810               ; resolve weapon from index if needed
2a4fb0  cmp  byte [rax+0x68], 0
2a4fcb  call 0xC10AA0                ; g_pGameRules->GetPlayerByIndex?
2a4fdc  call [vtable+0x558]          ; "is alive"?
2a4ff6  call [vtable+0xCA8]          ; "can shoot"?
2a5035  call 0xC629E0                ; get the shoot position/angles
2a5069  call [vtable+0x5F0]          ; econ item view
2a5086  call 0xAC5DE0                ; item def index -> CSWeaponData
2a5095  call 0x29F040                ; (debug) weapon-data dump
2a5112  call 0x1067FF0               ; GetItemDefinition
2a5131  call 0x9C03D0                ; GetWeaponEconDataFromItem
2a51A0  call 0x9BE8C0                ; GetCSWeaponDataFromItem
2a5211  call 0x3D95F0                ; movetype
2a5293  call 0x3D6FB0                ; GetAbsOrigin-ish
2a529B  call 0x1CD370                ; inaccuracy
2a52F0  ...                          ; the debug log
2a53C1  call 0x99A410                ; FireBullets  <-- the bullet loop
2a53C9  call 0x22C170                ; post-fire bookkeeping
2a53F5  ...                          ; [r14+0x820]/[+0x82C]/[+0x830]/[+0x834] = spread state
2a5403  call 0x24D4E0
2a541F  call 0xB069D0                ; increment the player's shot counter
2a5429  inc  dword [rax+0x44]        ; m_totalShotsOnServer-ish
2a5498  ...                          ; dispatch the CMsgTEFireBullets
```

`0x99A410` (**`FireBullets`**, 1,076 bytes) is the bullet loop. Its prologue:

```asm
99a410  ...                          ; rcx = player index, rdx = weapon,
                                     ; r8 = weapon entity, r9 = the shot params
99a426  test rdx, rdx
99a433  call 0x1029810               ; resolve the weapon entity
99a444  cmp  byte [rbp+0x68], 0
99a470  call 0xC83DD0                ; build a CGameTrace
99a486  call 0xC84870                ; (trace setup, 400 B)
99a490  call 0xC8C8D0                ; (trace init, 559 B)
99a4a3  ...                          ; encode the player index into [0x2125884]
99a4ba  or   dword [0x2125828], 0x40000
99a4c7  mov  [0x2125884], eax
99a514  call [vtable+0xAC0]          ; per-weapon "should trace"
99a51d  ...                          ; loop over pellets (shotgun) or 1 (rifle)
```

`0x2125828` and `0x2125884` are the **global "current bullet trace context"**
used by the damage path.

### 7.2 The damage path

Damage is applied through `CBaseEntity::TakeDamage`, whose signature is pinned by
the script binding at `0x24DB10` (2,884 bytes, `CFuncMover`-adjacent script
`Entity.TakeDamage`): it logs `"Calling %s.%s"` with `%s = "Entity"`,
`%s = "TakeDamage"` (`0x179A750`), and validates the `this` pointer, then
forwards. The actual entity-side entry is `0x20A7D0` (1,671 B), referenced from
`0x20ACF9`.

`CTakeDamageInfo` (RTTI `0x1EC4D80`) is the info struct; its constructors are at
`0x502880` (688 B) and `0x5032D0` (272 B), and `0x50A850` (8,672 B) is the
`TakeDamageInfo` **network-field binder** (`0x17FB6A0`). `CTakeDamageResult`
(RTTI `0x1EC4DA8`-adjacent, constructor `0xF9A300`) is the result struct.

The debug assertion strings for the damage path:

| RVA | string |
|---|---|
| `0x17CCAD0` | `CBaseEntity::TakeDamageOld: damagetype %d with info.GetDamageForce() == Vector::vZero` |
| `0x17CCB30` | `CBaseEntity::TakeDamageOld: damagetype %d with info.GetDamagePosition() == VectorWS::vZero` |
| `0x1812010` | `CreateDamageInfo` (script helper) |
| `0x1812078` | `DestroyDamageInfo` |
| `0x181B450` | `"Apply damage to this entity. Use CreateDamageInfo() to create a damageinfo object."` |
| `0x181B4A8` | `Script_TakeDamage` |

The `CFireBulletTakeDamageListener` (RTTI `0x1F029E8`, vtable **`0x17AAB58`**,
2 slots) is the bridge from a bullet hit to the damage system:

| slot | RVA | body |
|---|---|---|
| 0 | `0x2AF760` | 45 B — `OnTakeDamage`: calls `0xAD2840` (314 B, the "is this the right victim" test), then sets `[this+0x10] = 1`, then dispatches on `[info+0x4C] & (1<<0x13)` (the damage-type bit) to `0x2AC490` (448 B) or `0x2A5FC0` (346 B), then `0x2AFC60` (426 B) |
| 1 | `0x2AF830` | 0 (leaf) |

`0x2AFC60` is the actual damage application: it re-resolves the attacker entity
handle (`[rcx+0xC98]` → `0x1F47078` handle table), calls
`[0x21BA1C0 vtable +0x288]` (`g_pCCSGameRules->IsDamageAllowed`), then
`0xCF7020` (the distance/falloff check), then dispatches
`"autosavedangerousissafe"` (`0x1994028`) on the match framework at `0x21BA010`.

`CCSPlayer_BulletServices` (RTTI `0x1EBE268`, vtable **`0x1920300`**, 23 slots)
is the per-player hit accounting service. Its network var
`m_totalHitsOnServer` (`0x191E488`) is the hit counter. Slots:

| slot | RVA | size |
|---|---|---|
| 0 | `0xA9AD30` | 33 |
| 2 | `0xC893F0` | 62 |
| 3 | `0xC886A0` | 54 |
| 6 | `0xA6DA40` | 92 |
| 8 | `0xA9B790` | 0 |
| 20 | `0xC85B10` | 72 |
| 22 | `0xA99130` | 19 |

`0xA6DA40` is the destructor-ish body (calls `0xA6D080` (298 B) then frees);
`0xA99130` forwards to `0xC86D00` (the base component init).

### 7.3 The weapon network-field binder

`0xA078D0` (13,133 bytes) is the `CCSWeaponBase`-family network-field binder
(the analogue of `client.md` §6.1's `0x813CE0`). It declares
`m_iWeaponGameplayAnimState` (`0xA078D0`+), `WeaponGameplayAnimState`,
`m_flWeaponGameplayAnimStateTimestamp`, and the rest of the weapon state.

`CCSWeaponBase` RTTI vtable is `0x18EC818`, **437 slots**; `CCSWeaponBaseGun`
is `0x18ED608`/`0x18ED620`/`0x18ED650`; `CCSWeaponBaseShotgun` is at
`0x18EAC30`. The per-weapon classes (`CWeaponP250` `0x18EA0C0`,
`CWeaponNegev` `0x18EA0B0`, `CWeaponMP9` `0x18EA080`, `CWeaponP90`
`0x18EA3A8`, `CWeaponSCAR20` `0x18EAC10`, `CWeaponSG556` `0x18EAC20`,
`CWeaponSSG08` `0x18EAC48`, `CWeaponNOVA` `0x18EAC58`, `CWeaponTec9`
`0x18EAC68`, `CWeaponSawedoff` `0x18EAC78`, `CWeaponUMP45` `0x18EAC88`,
`CWeaponXM1014` `0x18EAC98`) are all RTTI descriptors only; the per-weapon
data is loaded from the `CCSWeaponBaseVData`/`CCSWeaponBaseVData` schema
(`CCSWeaponBaseVData` at `0x18E4AA0`, `CBasePlayerWeaponVData` at `0x18E4A10`).

`CCSWeaponBase::GetEconWpnData` (`0x18F0730`) is the econ-data accessor.
`CCSWeaponBase_API::SetAmmoAmount` (`0x18EBDA0`), `SetReserveAmmoAmount`
(`0x18EBDC8`), `ToggleCanBePickedUp` (`0x18EBD78`) are the script API.

The weapon's **attack timing** is computed by
`GetWeaponAttackTime` (inferred name) at **`0xA02C60`** (4,432 bytes), pinned by
five strings:

| RVA | string |
|---|---|
| `0x18F09D8` | `sv: GetWeaponAttackTime - null cmd` |
| `0x18F0A00` | `sv: GetWeaponAttackTime - null player controller` |
| `0x18F0A38` | `sv: GetWeaponAttackTime - null player` |
| `0x18F0AE0` | `sv: GetWeaponAttackTime player %s cmd %d attack [ #%d : %.3f ] sv tick [ #%d : %.3f ]` |
| `0x18F0B60` | `sv: Firing first shot, sv tick [ #%d : %.3f ], but no attack information present in command %d with %d history entries` |

and its sibling `0xA02700` (619 bytes) which asserts:

> `sv: ERROR: Player %s calculated shoot time [ #%d + %.3f ] does not match time from cmd [ #%d + %.3f ]` (`0x18F0910`)

> `sv: ERROR: Shoot pos for player %s does not match, diff = %.3f. Using server position.` (`0x18F0980`)

`0xA02C60` reads the attack history from
`[pawn+0x708]` (`CUserCmd*`) → `[cmd+0x4C]`/`[cmd+0x50]` (the two attack-history
indices) → `[history+0x38]` → `[entry+0x68]` (tick) and `[entry+0x6C]`
(fraction), then calls `0x9209F0` (66 B) and `0x9F2EF0` (23 B) to combine them
into a `GameTick_t` + fraction. That is the **server-side authoritative attack
time**, and it is the value lag compensation rewinds to.

---

## 8. Hit registration and lag compensation

### 8.1 `CLagCompensationManager`

`CLagCompensationManager` has two vtables:
`0x19CF610` (RTTI `0x1B8C5E8`, 65 slots — the game-system interface) and
`0x19CF820` (RTTI `0x1B8C6A0`, 11 slots — the concrete manager). The 11-slot
vtable is where the lag-comp logic lives:

| slot | RVA | size | body |
|---|---|---|---|
| 0 | `0xEDEBE0` | **7,136** | **`StartLagCompensation`** |
| 1 | `0xEE0B50` | 45 | |
| 2 | `0xEE08D0` | 30 | |
| 3 | `0xEE0800` | 199 | |
| 4 | `0xEC7020` | 114 | `"FinishLagCompensation"` (`0x19CF8D0`), file `...\player_lagcompensation.cpp` (`0x19CF890`) |
| 5 | `0xECB710` | 45 | |
| 6 | `0xECB6E0` | 38 | |
| 7 | `0xEBF0B0` | 105 | |
| 8 | `0xEDA960` | 293 | |
| 9 | `0xED21B0` | 0 | |
| 10 | `0xEC8610` | 53 | |

Slot 32 of the 65-slot vtable is `0xEC7250` (3,840 bytes) — the
**`FrameUpdatePostEntityThink`** hook:

```asm
ec7250  ...                          ; prologue
ec7261  mov  rax, [0x1E328D0]        ; g_pGlobals
ec726b  cmp  dword [rax+0x10], 1     ; maxClients <= 1 -> no lag comp needed
ec726f  jle  0xEC813C
ec7275  mov  rax, [0x21E1A90]        ; g_pCVar-ish
ec727c  cmp  byte [rax+0x58], 0
ec7280  je   0xEC813C
ec728a  lea  rax, [0x19CF890]        ; "...\player_lagcompensation.cpp"
ec72a8  lea  rcx, [0x19CF978]        ; "CLagCompensationManager::FrameUpdatePostEntityThink"
ec72b3  lea  rax, [0x1808ED0]        ; "FrameUpdatePostEntityThink"
ec72e6  call [0x176B128]             ; VProf enter
ec72f1  ...                          ; build a CUtlVector of players to rewind
```

So the manager's frame hook runs **after** entity think, and only when
`maxClients > 1` and the relevant subsystem is enabled.

### 8.2 `StartLagCompensation` — `0xEDEBE0`

The 7,136-byte body is the whole rewind. Its strings, in order of appearance,
are the algorithm's skeleton:

| RVA | offset in body | string |
|---|---|---|
| `0x19CF890` | `0xEDECEB` | `...\src\game\server\player_lagcompensation.cpp` |
| `0x19CF8D0` | `0xEDED04` | `StartLagCompensation` |
| `0x19CFA28` | `0xEDEE52` | `sv: Running lag compensation for player %s cmd %d tick %d` |
| `0x19CFB80` | `0xEDEED4` | `Lag comp cmd had no attack history information, using target time.` |
| `0x19CFD80` | `0xEDEF28` | `sv: StartLagCompensation clamped invalid attack history index to -1. Was %d, cmd history size %d.` |
| `0x19CFE80` | `0xEDF1AB` | `sv: Lag comp - full interp info doesn't match target time, using target time instead.` |
| `0x19CFE30` | `0xEDF303` | `sv: Lag comp - clamping to sv_max_unlag (%.3f), using target time.` |
| `0x19CFDE8` | `0xEDF3D9` | `sv: Lag comp - full interp info not valid, using target time.` |
| `0x19CF8F0` | `0xEDF77F` | `single interp backtrack` |
| `0x19CF910` | `0xEDF89A` | `sv_interp0 backtrack` |
| `0x19CF930` | `0xEDF9AD` | `sv_interp1 backtrack` |
| `0x19CF950` | `0xEDFA3E` | `cl_interp backtrack` |
| `0x19CF970` | `0xEDFB38` | `target time backtrack` |
| `0x19CFF50` | `0xEDFEEE` | `sv: Lag comp - Server world-space interpolated head pos for player %s at time does not match` |
| `0x19CFFD0` | `0xEDFF5A` | `Head pos cl: %.4f, %.4f, %.4f - abs pos cl: %.4f, %.4f, %.4f - abs ang cl: %.4f, %.4f, %.4f` |
| `0x19D0060` | `0xEE0009` | `Head pos sv: %.4f, %.4f, %.4f - abs pos sv: %.4f, %.4f, %.4f - abs ang sv: %.4f, %.4f, %.4f` |
| `0x19D0108` | `0xEE010F` | `Head pos diff: %.4f - abs pos diff: %.4f - abs ang diff: %.4f %.4f %.4f` |

The five "backtrack" strings are the **five rewind strategies** the manager
chooses between, in priority order:

1. `single interp backtrack` — one interpolation sample
2. `sv_interp0 backtrack` — server interp ratio 0
3. `sv_interp1 backtrack` — server interp ratio 1
4. `cl_interp backtrack` — the client's reported interp
5. `target time backtrack` — the raw target time (fallback)

The rewind itself reconstructs the *head position* of each target pawn at the
rewound time. The three "Head pos …" strings are the validation of that
reconstruction: it computes the head position three ways (client, server,
world-space interpolated) and logs a diff. The `sv_csgo_shoot_lagcompensation_max_error`
(`0x18EBB00`) and `sv_csgo_shoot_assert_lagcompensation_error` (`0x18EBA78`)
ConVars at `0xC1490` gate whether the diff is fatal.

`StartLagCompensation` takes `(this, CUserCmd*, player)` — `rdx` is the cmd
(`test rdx, rdx; je 0xEE07F9` at `0xEDEBE0`) and `r8` is the player. The
`"StartLagCompensation with NULL CUserCmd!!!"` string at `0x19CF9E0` is
referenced from `0xEE0B34` — a 19-byte function at `0xEE0B2F` that is a
standalone assert, not part of the 7,136-byte body.

### 8.3 `RecordDataIntoTrack` — `0xED95E0`

`CLagCompensationManager::RecordDataIntoTrack` (`0x19D01D8`) is at **`0xED95E0`**
(928 bytes). It is called from `0xEC80BA` (inside `FrameUpdatePostEntityThink`)
and is the function that *fills* the rewind history. Its job: for each player,
record `{tick, origin, angles, head position}` into a ring buffer so that
`StartLagCompensation` can later look it up.

The ConVars that bound it:

| RVA | name | default/help |
|---|---|---|
| `0x192BC08` | `sv_maxunlag` | `"Maximum lag compensation in seconds"` (`0x192BBE0`) |
| `0x192BD30` | `sv_maxunlag_player` | `"If >0, maximumum lag compensation used for other human pawns. Applied after sv_maxunlag!"` (`0x192BCD0`) |
| `0x192BE40` | `sv_lagcomp_filterbyviewangle` | |
| `0x19CB020` | `sv_unlag` | |
| `0x19CB2C0` | `sv_unlag_fixstuck` | |
| `0x19CB430` | `sv_unlag_debug` | |
| `0x19CB240` | `sv_lagcompensationforcerestore` | |

`sv_maxunlag` is registered at `0xCF8C0` (179 bytes), which shows the exact
ConVar-registration shape used by every `sv_*` in this module:

```asm
0cf8c0  ...                          ; zero a 0x58-byte ConVarDescriptor on stack
0cf90f  mov  eax, 7
0cf914  mov  word [r11-0x28], ax     ; type = 7 (float)
0cf919  call 0x1CDF90                ; default-value helper
0cf91e  movss xmm1, [0x1780580]      ; default = 1.0f (shared constant)
0cf92e  movss xmm2, [0x1780580]
0cf936  lea  rdx, [0x192BC08]        ; "sv_maxunlag"
0cf942  lea  rcx, [0x217B4F8]        ; the ConVar object (BSS)
0cf949  lea  rax, [0x192BBE0]        ; help text
0cf950  mov  r9d, 0x82000            ; FCVAR_* flags
0cf95b  call 0x17BA50                ; register
0cf960  lea  rcx, [0x1739550]        ; static destructor
0cf967  jmp  0x16B5788               ; atexit
```

### 8.4 `CHitboxSystem` — the trace

`CHitboxSystem` (RTTI `0x1F150F8`; `CCSHitboxSystem` RTTI `0x1F15220`) has no
RTTI vtable found by the relaxed walk — its methods are non-virtual or the
vtable is in a module that was stripped. The trace entry point is nevertheless
identified:

**`0x1A82B0`** (2,030 bytes) — `CHitboxSystem::TraceShapeAgainstHitboxesDefault`,
pinned by three strings:

* `0x1782F18` `"CHitboxSystem::TraceShapeAgainstHitboxesDefault"` (VProf name)
* `0x1782F48` `"TraceShapeAgainstHitboxesDefault - GetHitBoxListAndTransforms"` (nested VProf)
* `0x1782EA0` `"TraceShapeAgainstHitboxesDefault"` (nested VProf name)
* file `...\src\game\shared\hitboxcomponent.cpp` (`0x1782ED0`)

Body:

```asm
1a82b0  ...                          ; prologue
1a8331  call [vtable+0x1B8]          ; get the hitbox component
1a8358  call [vtable+0x60]           ; get the hitbox set
1a842b  call 0xCACD40                ; build the hitbox transform list (563 B)
...
```

The trace goes through `CGamePhysicsQueryInterface` (strings
`"CGamePhysicsQueryInterface::TraceShape"` `0x1949998`,
`"Physics/TraceShape (Server)"` `0x19499C0`,
`"TraceShapeToEntity"` `0x19499F8`, `"TraceShapeWithSortedResults"` `0x1949BF8`)
whose `TraceShape` body is **`0xC2F3C0`** (1,294 bytes).

`CHitboxSystem::TraceShapeAgainstHitboxesDefault` is called from the physics
query path; the per-weapon variant at `0xA37960` (256 bytes) is the function that
emits `"%s: TraceShapeAgainstHitboxes"` (`0x191C8A8`, used at `0xA379BE`). I
could not find a direct `call` to `0xA37960` in `.text` — it is reached through
a function pointer (its address appears in a vtable or callback table), so its
caller is not statically determined.

### 8.5 The rewind → trace → damage flow

Putting it together, the hit-registration flow is:

1. Client sends `CUserCmd` (with `subtick_moves` and attack history) — the
   server receives it in `Source2EngineToServer001` (`0x21BA010`).
2. `CBasePlayerController::OnSimulateUserCommands` (`0xB66860`) runs per
   command; it stores the cmd at `[this+0x708]` and calls
   `[vtable+0x828]`.
3. `CBasePlayerController::SimulateUserCommands` (`0xB67390`) marks the tick
   at `[this+0x368]` and calls `[vtable+0x878]`.
4. The weapon's primary attack reaches `CSBaseGunFire` (`0x9F8A70`) →
   `0x9F7840` → `FX_FireBullets` (`0x2A4F50`) → `FireBullets` (`0x99A410`).
5. `GetWeaponAttackTime` (`0xA02C60`) computes the authoritative attack time
   from the cmd's attack history.
6. `CLagCompensationManager::StartLagCompensation` (`0xEDEBE0`) rewinds every
   other player's recorded position to that time, using the five backtrack
   strategies.
7. `CHitboxSystem::TraceShapeAgainstHitboxesDefault` (`0x1A82B0`) traces the
   bullet against the rewound hitboxes.
8. On a hit, `CFireBulletTakeDamageListener::OnTakeDamage` (`0x2AF760`)
   dispatches to `0x2AFC60`, which applies the damage through
   `CBaseEntity::TakeDamage` (`0x20A7D0`).
9. `CLagCompensationManager::FinishLagCompensation` (`0xEC7020`) restores the
   un-rewound positions.

---

## 9. The 25 most significant functions

Sizes are merged (leaf-aware where noted). "Vtable" is the class the function is
a virtual of; "slot" is the index.

| # | RVA | size | name | purpose |
|---|---|---|---|---|
| 1 | `0x16A10D0` | 94 | `CreateInterface` (export) | interface lookup + factory tail-call; linear strcmp over `0x23ABEC0` |
| 2 | `0x16A10B0` | 29 | `CreateInterface` registrar (inferred) | head-insert a `{factory,name,next}` node |
| 3 | `0xDD7D90` | 1,148 | `CSource2Server::Connect` | resolves 20 interfaces, connects tier libraries, hands `Source2Server001` to the framework |
| 4 | **`0xDD8A60`** | **1,505** | **`CSource2Server::GameFrame`** | **the per-frame server advance (vtable slot 19)** |
| 5 | `0x1ACE00` | 2,256 | `CSource2Server::ApplyGameSettings` | parses the `game/map`,`game/type`,`game/mode` KV payload |
| 6 | `0x16B5F9C` | 1,815 | `_DllMainCRTStartup` (inferred) | entry point; runs C then C++ initialisers |
| 7 | `0x16872A0` | 364 | interface-catalogue resolver (inferred) | walks the 115-row table at `0x1AC9F60` |
| 8 | `0x16ADE40` | 154 | `GetResourceManifests` (export) | enumerates the manifest list at `0x23AC278` |
| 9 | `0x16AFF00` | 75 | `InstallSchemaBindings` (export) | installs the network-schema bindings |
| 10 | `0x9058C0` | 9,365 | `CCSGameRules` constructor (inferred) | builds the 0x11450-byte rules object; installs vtables `0x18C5450`/`0x18C5868`; calls `0xE66A70`; logs `"[STARTUP] {%.3f} created game rules"` |
| 11 | `0x9669F0` | 7,173 | **`CCSGameRules::Think`** | the round/phase state machine; fires `MatchEnded`/`WarmupPeriod`/`FreezePeriod`/`RoundOver`/`HalfTime` |
| 12 | `0x923BC0` | 117 | `CCSGameRules::FrameUpdatePreEntityThink` | VProf trampoline to `0x233F10`, which is an 11-byte clear of `0x1F9ED6C` |
| 13 | `0x933450` | 25,686 | `CCSGameRules` network-field binder (inferred) | 117 `NetworkVar` descriptors |
| 14 | `0x957E50` | 12,117 | `CCSGameRules` round-restart (inferred) | `"RestartRound"`, `"NumAliveTerrorist( rnd %d ) = %d"` |
| 15 | `0x1382FB0` | 414 | `CEntitySystem` frame driver (inferred) | begin/think/end + deferred-work flush |
| 16 | `0x13829C0` | 1,519 | `CEntitySystem` begin/end frame (inferred) | re-entrancy guard, per-frame reset |
| 17 | `0x13858C0` | 1,497 | queued spawn-group op processor (inferred) | resolves `targetname` handles and executes spawn-group work |
| 18 | `0x186B40` | 243 | `CNetworkTransmitComponent::FireEvent` | the delta-compression full-change marker |
| 19 | `0xB66860` | 1,899 | `CBasePlayerController::OnSimulateUserCommands` | per-command dispatch, `RunCommand` VProf, the 24-byte callback queue |
| 20 | `0xB67390` | 541 | `CBasePlayerController::SimulateUserCommands` | the per-tick command pump (vtable slot 271) |
| 21 | `0xC7E8D0` | 690 | `CPlayer_MovementServices::SetupMove` | builds `CMoveData` from the cmd (slot 34) |
| 22 | `0xC7FCC0` | 744 | `CPlayer_MovementServices::UpdateInputState` | `m_nButtons`/`m_nOldButtons` update (slot 23) |
| 23 | `0xC6F2A0` | 1,175 | `CPlayer_MovementServices::DoMovement::Subtick` | the sub-tick movement integrator |
| 24 | `0xEDEBE0` | **7,136** | **`CLagCompensationManager::StartLagCompensation`** | the rewind; five backtrack strategies; head-position validation |
| 25 | `0x2A4F50` | 2,659 | **`FX_FireBullets`** | the canonical fire path; econ-data resolution; calls `FireBullets` at `0x99A410` |

Honourable mentions that would be #26–#32: `0xED95E0` (928) `RecordDataIntoTrack`;
`0x99A410` (1,076) `FireBullets`; `0x9F8A70` (1,824) `CSBaseGunFire`;
`0x1A82B0` (2,030) `CHitboxSystem::TraceShapeAgainstHitboxesDefault`;
`0xEC7250` (3,840) `CLagCompensationManager::FrameUpdatePostEntityThink`;
`0xA02C60` (4,432) `GetWeaponAttackTime`; `0xA078D0` (13,133) `CCSWeaponBase`
network-field binder.

---

## 10. Unknowns

These are things the offline static analysis could **not** determine. Each names
what would resolve it.

1. **The interface *count* semantics.** `GetResourceManifestCount` returns
   `[0x23AC280]`, which the registrar at `0x16ADCA0` increments on registration.
   I could not find a decrement, so the counter is monotonic and may exceed the
   number of *live* nodes if anything ever unregisters. Whether
   `resource_manifest` nodes are ever removed is unknown; a runtime watchpoint on
   `0x23AC280` during a map cycle would settle it.

2. **The `0x1383150` / `0x13823E0` split.** `0x1382FB0` chooses between these
   two think paths based on `[rbx+0xC62]` and the nesting depth at
   `[rbx+0xC48]`. Which is "pre-entity think" and which is "post-entity think"
   is not determinable from the code alone — both call the same downstream
   dispatcher. Resolving it needs a dynamic trace of `CCSGameRules::Think`
   relative to `CNetworkTransmitComponent::FireEvent`.

3. **`CCSGameModeRules` slot semantics.** The base class is 8 empty `ret 0`
   slots plus a destructor, a schema binder and a "returns 1" predicate. There
   are no `__FILE__` literals and no log strings in any of the 44 slot bodies,
   so the *meaning* of each virtual (ResetRound? StartRound? GetRespawnTime?) is
   inferred only from which subclass overrides it. `ArmsRace` overrides
   4,5,7,8,9,10 and `Deathmatch` overrides 4,5,7,8,10; the shared slot 5 is
   proven `GMR_ResetRound` by the log string, but slots 4, 7, 8, 10 have no name
   evidence. A `--vprof`-instrumented run with the VProf names visible would name
   them.

4. **The mode-selection function.** `0x908CD0` and `0x908E40` are *member-clear
   helpers*, not mode pickers: they zero the `CUtlVector`-shaped fields at
   `+0x68`/`+0x6C`/`+0x70`/`+0x78` (ArmsRace) and additionally
   `+0x4C`/`+0x50`/`+0x58`/`+0x5C` (Deathmatch), and are called only from the
   two destructors at `0x90BBEF` / `0x90BC2F`. I initially read them as
   selection sites and that was wrong. Where the engine decides between
   `Noop`, `ArmsRace` and `Deathmatch` is therefore still unknown. The
   constructors are reached only through function pointers (`0x8D98A6`,
   `0x8D98D4`, `0x944617` for ArmsRace; `0x8D9E33`, `0x8D9E5F`, `0x944687` for
   Deathmatch) that the static scan did not resolve to a caller. A breakpoint on
   `0x905580` / `0x905660` during a mode change would identify the caller.

4. **The `0x9F7840` mode dispatcher.** `CSBaseGunFire` calls it with `edx = 0x66`
   and `edx = 0x32`. I could not determine the full mode enumeration — only that
   two values exist. The `CBasePlayerWeapon`/`CCSWeaponBaseGun` vtable slots that
   would expose the enum (`+0xD28`, `+0xD38`, `+0xBB0`, `+0xAC0`) are all in the
   weapon class hierarchy, and the corresponding functions are not in the
   `.pdata` map with usable names.

5. **The delta-compression encoder itself.** §4.2 shows that `CSVCMsg_*` and
   `svc_PacketEntities` strings have **zero** `.text` references. The actual
   bit-level delta encoder is in `networksystem.dll` / `engine2.dll`, reached
   through `NetworkSystemVersion001`. This module contributes the *field
   metadata* (`CNetworkSerializerClassInfo`, the per-class binders) and the
   *transmit state* (`CNetworkTransmitComponent`), but not the wire format. A
   full snapshot-format reversal needs those two DLLs, which are outside the
   scope of this task.

6. **`CCSGameRules`'s `+0x11C` / `+0xD8` / `+0xA44` field names.** These are the
   three fields the phase-transition switch reads. `+0x11C` is almost certainly
   `m_gamePhase` and `+0xD8` `m_bFreezePeriod` (both confirmed by their
   `NetworkVar` names in the binder at `0x933450`), but the *offsets* in the
   binder are the network-serialised offsets, not necessarily the C++ object
   offsets. `+0xA44` is unnamed. Confirming the mapping needs either a debug
   build or a runtime memory diff across a phase transition.

7. **The `+0x388` bitfield.** Three separate functions (`0x94DFA8`,
   `0xB673CD`, `0x94D9CF`) test `([entity+0x388] >> 8) & 1`, and `0x2A523A`
   tests bits 0 and 1 of the same dword with the string prefixes `"GROUND "` and
   `"DUCKING "`. So `+0x388` is a packed flags dword, but the full bit layout is
   not recoverable from these three uses. A `flags` enum in the schema
   (`FL_ONGROUND`, `FL_DUCKING`, …) would name the rest.

8. **`0x233F10`.** The body of `CCSGameRules::FrameUpdatePreEntityThink` is a
   single `call 0x233F10`, and `0x233F10` is exactly 11 bytes
   (`mov dword [0x1F9ED6C], 0; ret`). What that latch *gates* is not
   determined: `0x1F9ED6C` is read at `0x2086B2`, `0x2086C7`, `0x237BE2`,
   `0x237BF7`, but none of those four read sites has an identifying string. The
   pre-think hook is thus proven to be a one-dword clear; its *consumer* is not
   identified.

9. **Whether `CCSPlayer_MovementServices`'s slot 27 (`0xC6DFC0`, 2,544 B) is the
   real `ProcessMovement`.** It is the largest movement body and is called from
   the `CBasePlayerPawn` think path, but it has no `__FILE__` literal and no log
   string. Its shape (thread-local accessor at `0x6F1AC0`, `0x23C` TLS guard) is
   the same as the CS movement services' other methods. The name is inferred
   from position and size only.

10. **The exact `CCSGameRules` phase enumeration.** The switch at `0x9683E0`
    compares `eax` against `5` and `4` and reads `+0x11C`, but only five phase
    names appear as strings (`MatchEnded`, `WarmupPeriod`, `FreezePeriod`,
    `RoundOver`, `HalfTime`). The enum almost certainly has more members
    (`GameCommencing`, `TeamWin`, `Overtime`, …) whose events are fired
    elsewhere. The full enum would need the `cs_gamerules.h` header, which is
    not embedded.

11. **The `CHitboxSystem` vtable.** No RTTI vtable was recovered for
    `CHitboxSystem` or `CCSHitboxSystem` despite both type descriptors existing
    (`0x1F150F8`, `0x1F15220`). Either the vtables are constructed at runtime
    (unlikely for MSVC) or they are in a section the relaxed walk did not reach.
    The method at `0x1A82B0` is identified by string, not by vtable slot, so its
    index within the interface is unknown.

12. **`0x1AEE00` (1,253 B, `CSource2Server` slot 91).** It reads
    `[rdx+4] & 0xF00000`, compares against `0xB00000` and `0x100000`, and
    extracts a `>> 0x18` value compared against 1 and 5. That is edict/networkable
    slot validation, but the exact field layout is not determined.

13. **The 4,897-vtable RTTI walk's completeness.** The relaxed walk recovers
    3,990 classes and 4,897 vtables from 5,524 type-descriptor lines. The 1,534
    unrecovered descriptors are mostly template instantiations
    (`?$CNetworkVarBase@…`, `?$CNetworkArrayBase@…`) whose `COL` pointers are
    never emitted because the template is header-only. This is expected, but it
    means the slot counts for the CS classes (e.g. `CCSPlayerPawn` = 413) may
    still be truncated at the first non-`.text` slot. A `.pdata`-only walk would
    be strictly smaller; a walk that follows `jmp` thunks would be strictly
    larger.

14. **`sv_maxunlag_player`'s semantics.** Its help text
    (`"If >0, maximumum lag compensation used for other human pawns. Applied
    after sv_maxunlag!"`, with the typo `maximumum`) is clear, but I could not
    find the branch in `0xEDEBE0` that reads it. It is registered at `0xCF980`
    but its value is consumed somewhere in the 7,136-byte body that the
    annotated listing does not reach (the body is large enough that a manual
    read of all 7,136 bytes was not done).

15. **`CCSGameRulesProxy`.** RTTI has `CCSGameRulesProxy` (`rtti/server.txt`)
    but I did not locate its vtable or its `GetGameRules` body. It is the entity
    that exposes `CCSGameRules` to the network layer; its absence from this
    document is an omission, not evidence that it is missing from the binary.

---

## Appendix A: verified counts

| quantity | value | source |
|---|---|---|
| file size | 34,672,792 | PE header |
| SHA-256 | `70c66e85…f06d9f` | `index/inv/server.json` |
| PE timestamp | 1793836289 (2026-11-04 23:51:29 UTC) | PE header |
| sections | 5 | PE header |
| exports | 6 | export directory |
| imports (DLLs) | 7 | import directory |
| imports (symbols) | 767 | sum of the 7 tables |
| `.pdata` records | 108,977 | exception directory |
| real functions (merged) | 63,970 | 16-byte-alignment merge |
| RTTI type descriptors | 5,524 | `index/rtti/server.txt` |
| RTTI classes recovered | 3,990 | relaxed walk |
| RTTI vtables recovered | 4,897 | relaxed walk |
| vtable slots with `.pdata` size | 85,587 | `methods2.json` |
| self-registered interfaces | 10 | `jmp 0x16A10B0` scan |
| catalogue interfaces | 115 | table at `0x1AC9F60` |
| ConVars/ConCommands registered | 1,545 unique (1,555 sites) | `index/cvars/server.json` |
| `sv_*` ConVars | 345 | `index/cvars/server.json` |
| `mp_*` ConVars | 233 | `index/cvars/server.json` |
| distinct `__FILE__` literals | 150 | string scan |
| `src\game\server\*` files | 28 | string scan |
| `CCSGameModeRules` subclasses | 4 | RTTI |
| `CSource2Server` vtable slots | 103 (+1) | RTTI |
| `CCSGameRules` vtable slots | 130 (+4) | RTTI |
| `CCSWeaponBase` vtable slots | 437 | RTTI |
| `CCSPlayerPawn` vtable slots | 413 | RTTI |
| `CLagCompensationManager` slots | 65 (+11) | RTTI |

## Appendix B: reproducing the analysis

```bash
cd database/csgo/scripts/server

# 1. parsed PE + cached strings + linear xref index (writes srvcache/)
python3 srv.py
python3 scanrefs.py

# 2. relaxed RTTI (writes srvcache/methods2.json)
python3 srv_rtti2.py

# 3. ConVar census (writes cvars.json)
python3 cvars_server.py

# 4. annotated listing of any function (merged boundaries)
python3 ad2.py 0xdd8a60          # whole function
python3 ad2.py 0xdd8a60 0x200    # first 0x200 bytes

# 5. interface-stub enumeration
python3 stubs.py
```

The `.asm` dumps in `docs/server/` cover the 300 largest `.pdata` chunks; they
are useful for a first look but use the **raw** chunk boundaries, so a function
appears as several files (`1001ae0.asm` is one chunk of a larger body).
`ad2.py` is authoritative for boundaries.
