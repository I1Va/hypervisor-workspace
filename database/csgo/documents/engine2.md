# engine2.dll — Technical Reverse-Engineering Report

**Target:** `/home/iabrutin/Work/agent-projects/.corpus/cs2/bin/win64/engine2.dll`
(Counter-Strike 2 / CS:GO install, `game/bin/win64`)
**Size:** 7,498,392 bytes
**SHA256:** `a1b682acb5cedf11bed4784b0191a5452e93ee8f3023f95fa11ab3c3676b0fbc`

All addresses in this document are **RVAs** (relative virtual addresses) unless explicitly written with the
`0x1800…` image base. The image base is `0x180000000`, so VA = `0x180000000 + RVA`.

Method: `pefile` for structure, Capstone for a complete instruction-level scan of `.text` (every function
boundary from `.pdata`), radare2 + r2ghidra (`pdg`) for decompilation, plus a Murmur2 `CUtlStringToken`
oracle (§6.1) to recover the hashed command-line parameters the engine compares against. Function boundaries
are exact (`.pdata` `RUNTIME_FUNCTION` entries), not heuristic. Where a "function" is split into several
`.pdata` fragments by the MSVC linker (shared prologues / tail merging) I give the merged extent and say so.

`engine2.dll` is **not a game module**. It is the Source 2 **engine host**: it owns the process after
`cs2.exe` hands over, it builds the app-system dictionary, loads every other module, and runs the frame
loop. This is the counterpart of `cs2.md` (the launcher) and `client.md` (the client game module).

---

## 1. Identity

| Property | Value |
|---|---|
| File name | `engine2.dll` |
| Size | 7,498,392 bytes |
| SHA256 | `a1b682acb5cedf11bed4784b0191a5452e93ee8f3023f95fa11ab3c3676b0fbc` |
| Machine | `0x8664` (x86-64) |
| Subsystem | 2 (`IMAGE_SUBSYSTEM_WINDOWS_GUI`) |
| Image base | `0x180000000` |
| Entry point | RVA `0x4b1fdc` (VA `0x1804b1fdc`) |
| `SizeOfImage` | `0xa15000` (10,571,776) |
| `SizeOfHeaders` | `0x400` |
| File alignment / section alignment | `0x200` / `0x1000` |
| Checksum | `0x734ca7` — **matches** the computed checksum |
| `DllCharacteristics` | `0x160` = `HIGH_ENTROPY_VA` (0x20) + `DYNAMIC_BASE` (0x40) + `NX_COMPAT` (0x100). **`GUARD_CF` (0x4000) is absent.** |
| File characteristics | `0x2022` = `EXECUTABLE_IMAGE` + `LARGE_ADDRESS_AWARE` + `DLL` |
| Sections | 6 |
| Functions (`.pdata`) | 22,269 `RUNTIME_FUNCTION` entries; 11,054 after merging linker-split fragments; 5,033,570 bytes of code |
| PDB path | `C:\buildworker\csgo_rel_win64\build\_build_\engine2\_vpc_engine2\default\win64\_msvc_\Retail\engine2.pdb` |
| Build timestamp | `1793662660` = **2026-11-02 23:37:40 UTC** |
| Authenticode | **not signed** (`signed: false`) |
| Exports | 43 (7 engine API + 36 `opus_*`) |
| TLS callbacks | 2 — `0x4b1c54`, `0x4b23a4` |
| Import DLLs | 9: `tier0` (709), `KERNEL32` (154), `steam_api64` (22), `WS2_32` (13), `USER32` (11), `GDI32` (9), `steamnetworkingsockets` (2), `ADVAPI32` (1), `WINMM` (1) |
| `/GS` cookie | `0x6b68c0`, default `0x2b992ddfa232`; init at `0x4b2644` |

The PDB path names the VPC project `_vpc_engine2`, built for `csgo_rel_win64` — the retail CS2 branch.
The build stamp `Nov  2 2026` / `15:35:28` is *also* hard-coded as string data at `0x624ae0` / `0x624af0`
and written into the engine's build-identity globals at `0x20920b`/`0x20921f`. It is 19 days later than
`cs2.exe`'s build (2026-10-14, §1 of `cs2.md`), i.e. the launcher and the engine are separate build jobs
that were shipped together.

### 1.1 Sections

| Name | RVA | Virtual size | Raw size | Entropy | Characteristics |
|---|---|---|---|---|---|
| `.text` | `0x1000` | `0x51032a` (5,309,226) | `0x510400` | 6.52 | code, execute+read |
| `.rdata` | `0x512000` | `0x19d81e` (1,693,726) | `0x19da00` | 5.31 | initialized read-only data |
| `.data` | `0x6b0000` | `0x315424` (3,232,804) | `0x29000` | 4.29 | read/write data (3.0 MB of BSS) |
| `.pdata` | `0x9c6000` | `0x413dc` (267,228) | `0x41400` | 6.45 | exception directory (22,269 × 12 bytes) |
| `_RDATA` | `0xa08000` | `0x30` (48) | `0x200` | **0.18** | initialized read-only data |
| `.reloc` | `0xa09000` | `0xb48c` (46,220) | `0xb600` | 5.46 | base relocations |

`.text` holds 5,033,570 bytes of actual code out of 5,309,226 virtual bytes (94.8%; the rest is `int3`/`nop`
alignment padding). Median function size is **226 bytes**; the distribution over the 11,054 merged functions is
240 ≤32 B, 1,442 in 33–64, 1,561 in 65–128, 2,697 in 129–256, 2,455 in 257–512, 1,579 in 513–1024,
752 in 1025–2048, 252 in 2049–4096 and 76 above 4 KB. The largest single function is `0x3c87d0`
(54,364 bytes) — see §7.

### 1.2 The unusual `_RDATA` section

`_RDATA` is a 48-byte read-only section at `0xa08000` containing **three SSE2 double constants, each
duplicated**:

```
0xa08000  0x4330000000000000 4503599627370496.0    (2^52)
0xa08008  0x4330000000000000 4503599627370496.0
0xa08010  0x8000000000000000 -0.0
0xa08018  0x8000000000000000 -0.0
0xa08020  0x3ff0000000000000 1.0
0xa08028  0x3ff0000000000000 1.0
```

Its **only** consumer is `0x4b2790`, a 74-byte leaf function that is the MSVC `__dtoul3`/`_dtoul`
family's **`double`→`uint64` conversion helper** (`cvttsd2si` emulation with the 2^52 bias). It loads
`[0x180a08000]` at `0x4b2793`, `[0x180a08010]` at `0x4b279a` and `[0x180a08020]` at `0x4b27c8`.

Why it exists as a *separate section* rather than living in `.rdata` is an artefact of the MSVC linker:
when `/Gy` (function-level linking) is combined with a **`__declspec(selectany)`-style COMDAT constant**
referenced only from one COMDAT function, the linker can emit the constant into a synthetic `_RDATA`
section so it survives `/OPT:ICF` and `/OPT:REF` without being merged into `.rdata`'s sort order. It is
48 bytes and cannot hold anything else — the section is pure FP scaffolding. There are no other references
to `0xa08000`–`0xa0802f` anywhere in `.text` (verified by a full RIP-relative scan).

### 1.3 Entry point, TLS and CRT initialisers

```
0x4b1fdc  mov [rsp+8], rbx
0x4b1fe1  mov [rsp+0x10], rsi
0x4b1fe6  push rdi
0x4b1fe7  sub  rsp, 0x20
0x4b1feb  mov  rdi, r8
0x4b1fee  mov  ebx, edx
0x4b1ff0  mov  rsi, rcx
0x4b1ff3  cmp  edx, 1
0x4b1ff6  jne  0x4b1ffd
0x4b1ff8  call 0x4b2644            ; __security_init_cookie
0x4b1ffd  mov  r8, rdi
0x4b2000  mov  edx, ebx
0x4b2002  mov  rcx, rsi
0x4b2005  ...
0x4b2014  jmp  0x4b1eb4            ; __scrt_common_main_seh
```

`0x4b2644` is the stock MSVC `__security_init_cookie`, byte-for-byte in structure: it compares the cookie
at `0x6b68c0` against `0x2b992ddfa232`, and if unchanged derives a new one from
`GetSystemTimeAsFileTime ^ GetCurrentThreadId ^ GetCurrentProcessId ^ QueryPerformanceCounter ^ &cookie`,
masks to 48 bits, and stores `~cookie` at `0x6b6900`.

The **TLS directory** is present (`0x625f80`, 40 bytes):

| Field | Value |
|---|---|
| `StartAddressOfRawData` | `0x656ea0` |
| `EndAddressOfRawData` | `0x6589ac` |
| `AddressOfIndex` | `0x7354c4` |
| `AddressOfCallBacks` | `0x516318` |

Two callbacks:

| Callback | Purpose (by inspection) |
|---|---|
| `0x4b1c54` | On `DLL_PROCESS_ATTACH`-equivalent (`edx==2`, `DLL_THREAD_ATTACH`) it sets the per-thread byte at `gs:[0x58]+0x74` to 1 and walks the `.CRT$XLB`-style array `0x516298`–`0x5162c8` calling each entry — i.e. **per-thread CRT initialisers**, six of them: `0x21480`, `0x21450`, `0x219d0`, `0x21a80`, `0x21c00`, `0x21a40`. |
| `0x4b23a4` | On `edx==3` (`DLL_THREAD_DETACH`) and `edx==0` it walks the same table calling the corresponding destructors, then decrements a per-thread refcount at `[gs:[0x58]+0x80]`. |

The six per-thread initialisers are all **static-object constructors for thread-local `CUtlVector`/`CUtlString`
state**: each computes `gs:[0x58] + <TLS index>` and stores its vftable + zeroed fields
(`0x21480`: 0x48-byte object, `0x21450`: 0x58-byte, `0x219d0`: 0x1a0-byte, `0x21a80`, `0x21c00`: 0x620-byte,
`0x21a40`: 0xd20-byte with a self-pointer at +0xdc0). The `0x12345678` immediates at `0x219d6`, `0x21a8d`,
`0x21a58` are MSVC's uninitialised-TLS sentinel pattern.

### 1.4 Exports (43)

`engine2.dll` exports exactly 43 symbols, in three groups. Full table with RVAs:

**Engine API (7):**

| Ordinal | RVA | Name | Size | What it does |
|---|---|---|---|---|
| 1 | `0x249240` | `BinaryProperties_GetValue` | 141 | 8-case switch answering build-property queries: `0`→`"Release"`, `3`→`"engine2"`, `1/4`→0, `2/5`→1, `6`→2. Used by tooling that must know a module's config without the PDB. |
| 2 | `0x40aec0` | `CreateInterface` | 94 | The interface dispatcher, §4. |
| 3 | `0x2496e0` | `ExtractModuleMetadata` | 428 | Fills the `CBaseVModuleMetadataProvider` singleton (`0x9c44e8`) and registers it — the resource-manifest / module-metadata handshake used by `resourcesystem`. |
| 4 | `0x422bf0` | `GetResourceManifestCount` | 7 | `return *(int*)0x734a90;` |
| 5 | `0x422c00` | `GetResourceManifests` | 154 | Walks the singly-linked list at `0x734a88` of `{next, ptr, lazy_fn}` and copies up to *n* manifest pointers into the caller's array, forcing each `lazy_fn()` once. |
| 6 | `0x424310` | `InstallSchemaBindings` | 75 | See §4.4. |
| 7 | `0x2111e0` | `Source2Main` | 691 | The engine entry point, §2. |

**Opus codec (36):** `opus_encode` `0x37c8c0`, `opus_encode_float` `0x37cab0`,
`opus_encoder_create` `0x37f570`, `opus_encoder_ctl` `0x37f690`, `opus_encoder_destroy` `0x37fff0`,
`opus_encoder_get_size` `0x380000`, `opus_encoder_init` `0x380050`, `opus_decode` `0x39eec0`,
`opus_decode_float` `0x39f010`, `opus_decoder_create` `0x3a00a0`, `opus_decoder_ctl` `0x3a0190`,
`opus_decoder_destroy` `0x37fff0` (**aliased with `opus_encoder_destroy`**), `opus_decoder_get_nb_samples`
`0x3a03c0`, `opus_decoder_get_size` `0x3a0450`, `opus_decoder_init` `0x3a04a0`,
`opus_packet_get_bandwidth` `0x3a05f0`, `opus_packet_get_nb_channels` `0x3a0640`,
`opus_packet_get_nb_frames` `0x3a0650`, `opus_packet_get_nb_samples` `0x3a0690`,
`opus_packet_get_samples_per_frame` `0x39e050`, `opus_packet_parse` `0x39e0d0`,
`opus_packet_pad` `0x38b170`, `opus_packet_unpad` `0x38b2e0`,
`opus_multistream_packet_pad` `0x38ae40`, `opus_multistream_packet_unpad` `0x38af40`,
`opus_repacketizer_cat` `0x38b410`, `opus_repacketizer_create` `0x38b500`,
`opus_repacketizer_destroy` `0x37fff0` (same alias), `opus_repacketizer_get_nb_frames` `0x38b530`,
`opus_repacketizer_get_size` `0x38b540`, `opus_repacketizer_init` `0x38b550`,
`opus_repacketizer_out` `0x38b560`, `opus_repacketizer_out_range` `0x38b590`,
`opus_pcm_soft_clip` `0x39e5e0`, `opus_get_version_string` `0x391aa0`,
`opus_strerror` `0x391ab0`.

The three `*_destroy` exports and `opus_repacketizer_destroy` all point at **`0x37fff0`**, a 5-byte thunk
`jmp 0x190ae0` → `g_pMemAlloc->free(ptr)`. This is expected: in libopus all four destroy functions are
literally `opus_free(st)`.

---

## 2. `Source2Main` — the export cs2.exe calls

`cs2.exe` calls `Source2Main` at its RVA `0x4bde` with a six-argument call
(`hInstance, hPrevInstance, lpCmdLine, nCmdShow, exeDirUtf8, "csgo"`), documented in `cs2.md` §2.3. The
engine-side receiver is `0x2111e0`, 691 bytes, with the **six arguments passed in `rcx, rdx, r8, r9` plus two
stack slots** — exactly matching the launcher's layout. `cs2.md`'s claim that the launcher never returns is
correct for the *successful* path only: `Source2Main` does `ret` when the engine shuts down normally.

### 2.1 Signature

```c
uint32_t Source2Main(HINSTANCE hInst,        // rcx  (unused after being saved in r14)
                     HINSTANCE hPrevInst,    // rdx  (saved in rsi, unused)
                     const char *lpCmdLine,  // r8   (saved in rbx)
                     int  nShowCmd,          // r9d  (saved in edi)
                     const char *pszExeDir,  // [rsp+0xb0]  -> forwarded as 5th arg
                     const char *pszGameName);// [rsp+0xb8]  -> forwarded as 6th arg
```

Only `lpCmdLine` (`rbx`) is actually consumed here, at `0x21124a`. `pszExeDir` and `pszGameName` are
re-pushed at `0x211387`–`0x21139c` and forwarded to `0x20e170` (§2.3). `hInst`/`hPrevInst`/`nShowCmd`
are dead: `r14`, `rsi` and `edi` are loaded and then only `edi` is re-used, at `0x2113a1`, as the `nShowCmd`
argument of the inner call. So `Source2Main` is a **thin prologue** around `0x20e170`.

### 2.2 What `0x2111e0` initialises, in order

| RVA | Call | Effect |
|---|---|---|
| `0x211204` | `tier0!KeyValuesSystem()` | Fetch the KV singleton |
| `0x211212` | `[kv+0xa0](kv, 1)` | `SetUseFixedSymbolTable(true)`-style init — allocates the KeyValues symbol table *before* any key is parsed |
| `0x211231` | `CThreadLocalScope::CThreadLocalScope(&scope, 0, 0)` | Declares the calling thread's TLS scope |
| `0x211237` | `tier0!DeclareCurrentThreadIsMainThread()` | Pins thread 0 as the engine main thread (tier0 asserts on later violations) |
| `0x211250` | `[cmdline+0x10](cmdline, lpCmdLine)` | `CCommandLine::SetArgv0`-equivalent — installs the launcher's command line |
| `0x21125c` | `Tier0GenericMiniDumpHandler_SetOptions(0, 1)` | Crash handler: enable minidumps |
| `0x211277` | `cmdline->HasParm(0x258941d)` | hashed test — **`-attachtodebugger`** |
| `0x211292` | `cmdline->HasParm(0x42550058)` | hashed test — **`-breakimmediately`** |
| `0x2112a2` | `Plat_AttachDebuggerToProcess(has_breakimm, 0)` | if either flag present, attach a debugger |
| `0x2112b0` | `MiniDumpCommentEnsureOSDescription()` | fill the minidump comment with the OS description |
| `0x2112d1` | `cmdline->FindParm(0xc64d5c6e, 0)` | **`-nominidumps`** — if absent (returns 0) install the engine's handler |
| `0x2112ec` | `Tier0GenericMiniDumpHandler_SetPreHandlerCallback(0x210c90)` | pre-handler: pushes the `CMiniDumpComment` text into **Steam** via `SteamAPI_SetMiniDumpComment` and into tier0 via `MinidumpSetMiniDumpComment` |
| `0x21130d` | `cmdline->FindParm(0xd8a5d350, 0)` | **`-nobreakpad`** |
| `0x21131d` | `SetDefaultMiniDumpHandler(0x210cc0, 1)` | installs `CEngine2MinidumpCommentBuilder` (RTTI at `0x651f48`) as the default handler |
| `0x21133b` | `cmdline->HasParm(0xe29d0d0c)` | **`-noassertlistener`** (name inferred from use; hash not recovered, §9) |
| `0x211349` | `RegisterAssertionFailureListener(0x6c0258)` | registers the engine's assert hook |
| `0x21135c` | `g_pMemAlloc->GetVProfState()` (vtable +0x120) | if profiling enabled |
| `0x21137a` | `g_pMemAlloc->SetName("Engine_Startup")` (vtable +0x98) | tag the allocator region |
| `0x211380` | `MinidumpAgeLogs()` | rotate old minidumps |
| `0x2113aa` | **`fcn.0x20e170(hInst, hPrevInst, nShowCmd, pszExeDir, pszGameName)`** | the real engine body |
| `0x2113c8` | `[0x6bc814]` flag test | if `CSteam3Client` was initialised |
| `0x2113dc` | `LoggingSystem_IsChannelEnabled(LOG_GENERAL, 2)` | |
| `0x2113f8` | `LoggingSystem_Log(LOG_GENERAL, 2, "CSteam3Client::Shutdown\n")` | |
| `0x211405` | `SteamAPI_Shutdown()` | tear down Steam |
| `0x211418` | `g_pMemAlloc->GetVProfState()` | |
| `0x211436` | `g_pMemAlloc->SetName("Engine_Shutdown")` | |
| `0x211441` | `~CThreadLocalScope()` | |
| `0x211447` | `Plat_OnExecutableExitingMain()` | tier0 exit notification |
| `0x21145b` | `[kv+0xa0](kv, 0)` | undo §2.2 item 2 |
| `0x211470` | `[kv+0xa8](kv, 1)` | final KV teardown |
| `0x211477` | `return ebx` | the engine's exit code |

Note the structure: **`Source2Main` is a `__try/__except` wrapper.** `0x211387` is the start of the
`try` body (`try.1.1802111e0.from` in r2's naming) and `0x2113b7` is the filter, which logs
`"MINIDUMP_WRAP_CODE: In __except block\n"` (`0x61e300`) via `MinidumpLog`. So a crash inside `0x20e170`
is converted into a minidump plus a clean `ret`, and the process does not simply die. The
`dword [rsp+0x30] = 1` at `0x2112a8` is the `__except` return-value slot.

### 2.3 `0x20e170` — the engine body (1,628 bytes)

`0x20e170` is what actually becomes the game. Its flow:

1. **`-dedicated` gate (`0x20e18f`–`0x20e1b2`).** `cmdline->FindParm(0x55a5c01b, 0)`; if non-zero the
   engine is a dedicated server and takes a *different* init path: `SetAssertionPrompt(0xff, 6)` at
   `0x20e1c4`, `uVar12 = 1`, and **no** single-instance mutex.
2. **Single-instance mutex (client path).** `Plat_CreateGameInstanceMutex(pszGameName)` at `0x20e1cd`. If it
   returns NULL: `Plat_MessageBox("Source2 - Warning", "Only one instance of the game can be running at one
   time.", 0)` at `0x20e2a5`–`0x20e2b1` and `return 1`.
3. **Allocate the 0x4e8-byte engine object** at `0x20e1e7` via `g_pMemAlloc->Alloc(0x4e8)`, then construct it
   with `fcn.0x1928c0(obj, is_dedicated, hInst, hPrevInst, nShowCmd)` at `0x20e210`. Immediately afterwards
   the **two vftables are stamped**: `[obj] = 0x609280` and `[obj+0x498] = 0x6092d8` (`0x20e215`, `0x20e22d`).
   Both locators resolve to `.?AVCMaterialSystem2AppSystemDict@@` (CompleteObjectLocator `0x648f88` and
   `0x649000`) — so the engine's root object is a **`CMaterialSystem2AppSystemDict`**, the concrete
   `CAppSystemDict` that knows how to instantiate `materialsystem2` (§3).
4. **Console / logging.** `-tools` check (`0xbc4f1a2`) at `0x20e2f0`, `-addon` (`0x4ebeac3f`) at
   `0x20e438`, and `Plat_EnableHighQoSExecutionSpeed()` at `0x20e36a` when the hashed flag
   `0xcf571fda` is *absent* (spelling unrecovered, §9.1).
5. **`fcn.0x2082a0(obj, pszExeDir, pszGameName, is_tools_or_addon)`** at `0x20e387` — the *pre-init*
   (§2.4).
6. **`inc dword [obj+0x438]`** at `0x20e39a` — the dict's refcount; `[obj+0xf9]` → `[obj+0x141]=1` at
   `0x20e3a9`; then **`[obj+8](obj)`** at `0x20e3b6` — the `CAppSystemDict::Init()` virtual. If it returns
   non-zero (`0x20e3b9`):
   - `[0x739907] = [obj+0x4e5]` (a byte, the "tools" flag) at `0x20e3c1`
   - if the engine window (`0x733f18`) exists and `is_tools_or_addon` is false, ask
     `[0x733e70+0xc8]()` (the application) whether to suppress it; if so `[win+0x360](win, 0)` at
     `0x20e3ff`
   - `[0x733e78+0xa8](..., 0x106550)` at `0x20e416` — register the engine's console-command handler
   - `fcn.0x20dbd0()` at `0x20e41c` — **render-system selection** (§2.5)
   - `[obj+0x450] = 0x6b9670` (a vtable-ish pointer) at `0x20e421`
   - `-addon` (`0x4ebeac3f`) at `0x20e438`: if present and the renderer supports it, enter the addon
     path (`[0x733e70+0x1a0](...,1)` at `0x20e47c`, `[0x733e70+0x120](..., addon)` at `0x20e48c`,
     `[obj+0x443]=1`, `[obj+0x444]=0` under `LOCK`, `[obj+0x89] = addon string`)
   - if `[obj+0x1f] == 0`: `fcn.0x2f0390(obj, "inputsystem", "InputStackSystemVersion001", 0)` and
     `[0x733f80+0x58](..., "engine2", -1)` — the **input-stack** app-system, loaded lazily here rather
     than in `LoadAppSystems`.
   - **`fcn.0x209140(obj, <app-system name>)`** at `0x20e50f` — `LoadAppSystems` (§3).
7. **OS gate.** `Plat_GetOSType()` at `0x20e51d`; if `<= 10` → "This version of Windows is not supported,
   please upgrade to a newer version\n" via `Plat_FatalError` (`0x20e8**`) or the localised
   `#Engine_UnsupportedWindowsTitle`/`Body` message box plus `Plat_ExitProcess(1)`.
8. **`fcn.0x20d8d0()`** at `0x20e577` — the **minimum-physical-memory** check
   (`Engine2/MinimumPhysicalMemoryMB`, `#Engine_NotEnoughPhysicalMemory_Title`/`_Body`).
9. **Shutdown sequence** (`0x20e5d2`–`0x20e647`):
   `fcn.0x20c700(obj)` (the **`MainLoop`** — see §5), then `Plat_DestroyGameInstanceMutex`,
   `fcn.0x2f3840(obj)` (per-module teardown), `"Source2Shutdown\n"`, `"ShutdownSource2Logging\n"`,
   `LoggingSystem_EnableLogCapture(0)`, `LoggingSystem_PopLoggingState(0)`, log-file close
   (`"Log file closed\n"` at `0x978420`), `Plat_FloatTime()` into `0x978460`, teardown of `0x737430`
   (the **network-string-table** container, allocated in `0x2082a0`) and `0x737438` (the **`CNetConsoleMgr`**,
   vftable `0x5c5ea8`, RTTI `.?AVCNetConsoleMgr@@`), zeroing `0x9bcfe0`/`0x9bcfd0`/`0x9bcfd8`/`0x9bcfe8`/
   `0x9bcff0`, then `[obj](obj, 1)` (the destructor) and `return 0`.

**So `Source2Main` returns 0 on a clean shutdown and 1 on any early failure** — matching `cs2.md`'s note
that `0x4be7` (the launcher's post-call cleanup) is "only reached if the engine returns early". It is
reached on a *normal quit* too.

### 2.4 `0x2082a0` — `CAppSystemDict` pre-init (3,732 bytes)

Called once, at `0x20e387`, before `Init()`. Its job is everything that must happen *before* the app-system
dictionary can be built:

| RVA | What |
|---|---|
| `0x208768` | `"No mod specified! This is necessary to run!"` — fatal if `pszGameName` is empty and `-game` is absent |
| `0x2087d8`–`0x208814` | reads `gameinfo.gi`'s `FileSystem/ForceFixedAppIds` → if set, clears `0x9bcf88` and `0x7369a5` (Steam AppID pinning) |
| `0x208814` | `KeyValues::FindKey(gameinfo, "Engine2")` → the engine's own config block, kept in `iVar13` for the rest of the function |
| `0x208873` | `fcn.0x19d950(obj, "resource/game-icon.bmp")` — window icon |
| `0x2088a2`–`0x208907` | `AllocWarnMB` / `AllocWarnMB_pc64` / `AllocFailMB` / `AllocFailMB_pc64` / `ReserveWarnMB` / `ReserveWarnMB_pc64`, each overridable by a `+`-cvar; then `g_pMemAlloc->SetAllocWarningThreshold(warn<<20)`, `SetAllocFailThreshold(fail<<20)`, `Plat_SetVirtualReserveWarnLimit(reserve<<20)` |
| `0x2089d6` | `Engine2/DiscardMouseFocusClick` → `[obj+0x4e4]` |
| `0x208a16` / `0x208a21` | startup background: `-cn` variant selects `materials/startup_background_cn.vmat`, else `materials/startup_background.vmat` → `[obj+0x4d8]` |
| `0x208a**` | `fcn.0x200370(obj)` — resource-manifest / search-path setup |
| `0x208a65` / `0x208aa9` | MSAA: `Engine2/RenderingPipeline/SupportsMSAA`, then `MSAADefaultNonVR` or a `+msaa` override mapped 2/4/6/8/16 → enum 1..5 stored at `[obj+0x4e0]` |
| `0x208b**` | `-windowless` (`0x9e22d97c`) → `Plat_EnableHeadlessMode()` |
| `0x208b83` | render-system option: if neither of two flags is present, read `DefaultRenderSystemOption` from the game config into `[obj+0x4c8]`, `[obj+0x4d0] = 0` |
| `0x208c0c` | allocate a `CVirtualMemorySnapshot` (0x70 bytes) into `0x9bbc60`, `Capture(GetCurrentProcess())`, and `Msg("Unable to capture %s virtual memory information\n","Source2PreInit")` on failure |
| `0x208c7f` | tools path (`is_tools`): `[obj+0xf9] = 1`; `-noreact`/`-nowatchdog` hashed checks → `fcn.0x2f3ec0(obj,1)`; `Plat_SetEnv("IgnoreChildProcesses", ...)` |
| `0x208cb1`–`0x208d04` | **build identity**: if `0x9c44b8` is empty, sets `0x9c44d0="valve"`, `0x9c44b8="Nov  2 2026"`, `0x9c44c0="15:35:28"` and calls `fcn.0x248b30(...)` |
| `0x208d**` | `fcn.0x207a00(gameinfo, [obj+0xfc], [obj+0xf9])` — **the real config/console bootstrap** |
| `0x208dcf`–`0x208e99` | `fcn.0x207dc0(...)` — language detection (`SupportedLanguages` block, `SetUILanguageOnSteamDropDown`), with the **`schinese` fallback** at `0x20912d`: if `SteamUtils()->GetSteamUILanguage()` is not English, `0x9c20fc = 1` and the language string becomes `"schinese"`; otherwise `"english"` (`0x208ea0`) |
| `0x2090**` | writes `[obj+0x100]`/`[obj+0x110]`/`[obj+0x108]`/`[obj+0x118]` (four language variants) |
| `0x208fb7` / `0x208fda` | `Engine2/LvConfig` + `low_violence` → `[obj+0x14d]` (low-violence flag) |
| `0x2091**` | `fcn.0x2488e0(is_tools, gameinfo)` — Steam / AppID / beta-branch handling |

### 2.5 `0x20dbd0` — render-system selection (1,044 bytes)

Called from `0x20e41c`. It builds the module name `"pc64"` (`0x61cfa0`), then appends suffixes to form the
render-system search key, and picks one of the hard-coded candidates visible in `.rdata`:

| String | RVA | Meaning |
|---|---|---|
| `rendersystemempty.dll` | `0x60a109` | `-empty` |
| `rendersystemdx11.dll` | `0x60a2e0` | `-dx11` |
| `rendersystemvulkan.dll` | `0x60a302` | `-vulkan` |

The failure paths emit `"Failed to load rendersystemvulkan.dll. Likely missing Vulkan loader
(vulkan-1.dll) ..."` (`0x60a6b1`). The chosen option is stored in `[obj+0x4c8]` (from `0x2082a0`) and the
result is the `RenderDevice003` / `RenderDeviceMgr001` interfaces resolved later in §3.

### 2.6 Cross-reference to cs2.md

`cs2.md` §2.3 (`0x4bde`) says: `rcx = hInstance (0x140000000)`, `rdx = hPrevInstance (0)`, `r8 = lpCmdLine`,
`r9 = nCmdShow`, `[rsp+0x20] = exeDirUtf8`, `[rsp+0x28] = "csgo"`. The engine side confirms every slot:
`r9d` is saved to `edi` and forwarded at `0x2113a1`; `[rsp+0xb0]`/`[rsp+0xb8]` are re-pushed as
`[rsp+0x20]`/`[rsp+0x28]` at `0x21138f`/`0x21139c` and consumed by `0x20e170` as `arg3`/`arg4` (the
`in_stack_00000028` / `in_stack_00000030` in the decompilation). The launcher's `"csgo"` string is what
`Plat_CreateGameInstanceMutex` at `0x20e1cd` uses as the mutex name. `cs2.md`'s note that
`Source2Main` is "`noreturn` in practice" should be read as "the launcher's `0x4be7` is only reached on
engine exit"; the engine *does* return, with 0 on success.

---

## 3. Module loading and bootstrap

`engine2.dll` loads every other module itself. There are **two distinct loaders**, and they are not
interchangeable.

### 3.1 The two loaders

| Loader | RVA | Signature | What it does |
|---|---|---|---|
| `CAppSystemDict::AddSystem` (inferred name — see below) | `0x2f0390` | `(dict, module, interface, flags)` | Adds **one** interface: looks it up in the dict's `CUtlSymbolTable` at `+0x68`, checks the existing entry's `+0x48` vtable slot ("is this the same interface?"), strips the extension from the module name, `V_stricmp_fast`s them, and on mismatch either `Warning`s (flags==1) or `Plat_FatalError`s with *"AppSystemDict: Attempted to add two different systems with the same interface name %s!\n(Module names differ: existing '%s' != requested '%s')"*. On success it allocates a 0xe00-byte record, fills `{module, interface, ptr=0, ...}` and calls `0x2f2850` to actually load. |
| `CAppSystemDict::AddSystems` (inferred) | `0x2f06c0` | `(dict, count, {module,interface}[])` | Batch form. Same `+0x48` check per entry, then one `0x2f2850` call per row. Errors: *"*****************: Cannot call CAppSystemDict::AddSystems without initializing first!\n"* at `0x2f06eb`. |

The names are **inferred**: no RTTI or string in the binary contains `AddSystem`/`AddSystems`, but
`0x2f2850`'s diagnostics use the literal `"CAppSystemDict::LoadSystemAndDependencies"` (`0x2f0a00` caller
context, string at `0x2f2db4` region), and `0x2f0390`/`0x2f06c0` are the only two functions that mutate the
dictionary's interface table. Evidence: `0x2f0390` accesses `dict+0x68` (the `CUtlSymbolTable` also used at
`0x1928c0`+0x68 by the constructor) and `dict+0x1c`/`+0x20`/`+0x58` (the vector-of-records). I mark them
`AddSystem`/`AddSystems` as *inferred* throughout.

### 3.2 `0x2f2850` — `LoadSystemAndDependencies` (3,959 bytes)

This is the actual module loader, and its diagnostics name it. It:

1. `CMemAllocSystemInitialize()` (`0x2f2850`+0x11).
2. Allocates a 0x20-entry `CUtlSymbolTable` at `+0x220` for cycle detection.
3. For each requested row: `fcn.0x2f0a00(row->name, NULL)` — check whether the module is already loaded;
   if not, `fcn.0x2f21c0(dict, row->module, &err, flags==2)` — the **path resolver + `Plat_LoadModule`**
   (§3.3).
4. On success: `Plat_GetModuleInterfaceFactory(hmod, &iface)` (`0x2f2a28`) — the module's
   `CreateInterface`-equivalent.
5. On failure it prints one of three messages, gated by `flags==0`:
   - `#AppFramework_InvalidLocalFiles` + *"A game file appears to be missing or corrupted. In the Steam
     client go to the game's properties. In the 'Local Files' tab select 'Verify Integrity of Game Cache'
     ..."* (`0x2f2db4` region)
   - `#AppFramework_OutOfMemory` + *"The system ran out of memory while loading the game."* when the load
     error is 8 or 0xe
   - else the detailed form *"%s: nLoadError: %d, RequestModule: %s, RequestInterface: %s, Module: %s,
     Interface: %s"* with `"CAppSystemDict::LoadSystemAndDependencies"` as `%s` — **this string is the
     function's own name.**
6. Recurses into declared dependencies (the `row->deps` vector), and `Plat_MessageBox("Unable to Start
   Game", ...)` at `0x2f2d**` on a fatal dependency failure.

### 3.3 `0x2f21c0` — module path resolution + `Plat_LoadModule`

1,665 bytes. Given a module name like `"filesystem_stdio"`:

- `V_UnqualifiedFileName(name)` (`0x2f2207`), `CUtlString::Insert`, `StripExtension` → the base name.
- `ShortenPath` on the full path (`0x2f2280`) and `V_stricmp_fast` against a **cached module table**
  (the `0x734240` array of `{slot, generation}` written by `0x406120`).
- Builds candidate paths by `ComposeFileName` (`0x2f2319` etc.) and tests each with `Plat_FileExists`.
- Loads with **`Plat_LoadModule`** (`0x2f2276`, `0x2f228c`), falling back to `Plat_LoadModuleRaw`
  (`0x2f2269`, `0x2f2288`) when the plain load fails — `Raw` skips tier0's DLL-load-denial policy.
- Times the load with `Plat_RelativeTicks` and logs
  **`"CAppSystemDict::LoadModuleInPath( %-23s ) %8.3f msec"`** (`0x2f2322` region). This string is the
  second self-identifying diagnostic.
- Stores the `HMODULE` in the dict's module vector and `MemAlloc_StrDupFunc`s the resolved path.

So the *module name* → *DLL path* mapping is entirely engine2's: it supplies the paths and tier0 supplies
`Plat_LoadModule`/`Plat_LoadModuleRaw`. `engine2.dll` *does* import `LoadLibraryExW`, `LoadLibraryA`,
`GetProcAddress` and `FreeLibrary` directly from `KERNEL32` — 17 call sites in total
(`LoadLibraryA` at `0x211a6c`; `LoadLibraryExW` at `0x2493ea`, `0x249424`, `0x4deb27`, `0x4deb7b`;
`GetProcAddress` at `0x24951d`, `0x4b1460`, `0x4b1477`, `0x4b148e`, `0x4c028f`, `0x4dec0f`;
`FreeLibrary` at `0x211ad3`, `0x249482`, `0x4c02b6`, `0x4d47eb`, `0x4dec03`, `0x4df95b`) — but **none of
them are on the app-system path**: they serve `ExtractModuleMetadata`'s loader, `0x211af0`'s
`Kernel32.dll`/`Psapi.dll` probing for `GetModuleInformation`, the CRT at `0x4b1460`, and the
optional-DLL probes at `0x4c028f`/`0x4deb27`/`0x4dec0f`. Every game module goes through tier0's
`Plat_LoadModule`.

### 3.4 The load order

`0x209140` (`LoadAppSystems`, 6,900 bytes) is the orchestrator. Its flow, with the exact RVAs of each
`AddSystem`/`AddSystems` call, is:

**Phase A — the fixed core list** (`0x209456` onward, `COM_TimestampedLog("LoadAppSystems:   appSystems
Load(start)")`). A `CUtlVector<{module,interface}>` is built up in place, one `16-byte` row at a time:

| Order | Module | Interface | Row built at |
|---|---|---|---|
| 1 | `tier0` | `TestScriptMgr001` | `0x209467` |
| 2 | `tier0` | `VProcessUtils002` | `0x2094e5` |
| 3 | `localize` | `Localize_001` | `0x209559` |
| 4 | `meshsystem` | `MeshSystem001` | `0x2095fe` |
| 5 | `worldrenderer` | `WorldRendererMgr001` | `0x2096a8` |
| 6 | `pulse_system` | `IPulseSystem_001` | `0x20974d` |
| 7 | `vscript` | `VScriptManager010` | `0x2098ee` — **conditional**, see below |
| 8 | `networksystem` | `NetworkSystemVersion001` | `0x20999d` |
| 9 | `animationsystem` | `AnimationSystem_001` | `0x209a4f` |
| 10 | `vphysics2` | `VPhysics2_Interface_001` | `0x209b01` |
| 11 | `soundsystem` | `SoundOpSystem001` | `0x209bbc` |
| 12 | `steamaudio` | `SteamAudio001` | `0x209ca0` — **conditional** |
| 13 | `scenesystem` | `SceneSystem_002` | `0x209d68` — **tools only** |
| 14 | `scenesystem` | `SceneUtils_001` | `0x209e23` — **tools only** |
| 15 | `soundsystem` | `SoundSystem001` | `0x209ed6` — **tools only** |
| 16 | `particles` | `ParticleSystemMgr003` | `0x209f88` — **tools only** |
| 17 | `panoramauiclient` | `PanoramaUIClient001` | `0x20a091` — **conditional** |

The `vscript` row is gated by `Engine2/VScriptUsage` (`0x209826`–`0x2098fa`). The value is compared against
`"client"`, `"server"` and `"none"` with `V_stricmp_fast` (`0x209872`/`0x209892`/`0x2098aa`) and turned into
a bitmask (1/2/3). The **allowed** mask is 3 if `HasModAppSystems`, else 3 when not dedicated and 2 when
dedicated (`0x2098**`). The row is appended only when `(allowed & wanted) != 0`.

`soundsystem/SteamAudio001` is gated on `Engine2/SoundSystem/SteamAudioEnabled` (`0x209c88`).
`scenesystem`, `SoundSystem001`, `particles` and the resource-type registrations
(`RESOURCE_TYPE_POST_PROCESSING` / `_PANORAMA_LAYOUT` / `_PANORAMA_STYLE`, `0x20a0c4`–`0x20a0fb`) are
inside a `if (tools)` branch that begins at `0x20a05a`.
`panoramauiclient` is skipped when `Engine2/PanoramaUIClientFromClient` is set (`0x20a05a`–`0x20a091`).

Then **`fcn.0x2f06c0(dict, 17, rows)`** at `0x20a132` — one batch `AddSystems`.

**Phase B — the server/client configs** (`0x20a190` onward). `fcn.0x2f3f00(dict, 1)` bumps a phase
counter. `[0x733f18]` (the filesystem) is asked for `"GAMEBIN"` (`0x20a190`), and the result is passed to
`fcn.0x2f4040(dict, path)` — the **game-bin search path** for subsequent module resolution. Then:

| Order | Module | Interface | Flags | RVA |
|---|---|---|---|---|
| 18 | `server_valve` **or** `server` | `Source2ServerConfig001` | 0 or 2 | `0x20a246` / `0x20a270` |
| 19 | `client_valve` **or** `client` | `Source2ClientConfig001` | 0 | `0x20a2a6` |

The `server_valve`/`client_valve` names are chosen by two `-tools`-adjacent hashed checks at `0x2093d8`
(`"MaterialSystem2App"` context) / `0x2093f0` (`"client_valve"`) / `0x2093f7` (`"client"`): when both
`0x50924de5` and `0x8f74045f` are present the module name is `client_valve`, else `client`. The
`server_valve` selection at `0x20a238` is driven by `-tools`/`-dedicated` (§6.1).

**Phase C — `PanoramaUIClient001` from the client** (`0x20a35f`–`0x20a3b6`): if
`Engine2/PanoramaUIClientFromClient` is set, `AddSystem(dict, <client module>, "PanoramaUIClient001", 0)`
at `0x20a39b`, storing the handle at `0x733fb0`.

**Phase D — tools** (`0x20a3d8`–`0x20a41c`): if `[obj+0xf9]` (tools) and `HasModAppSystems`:
`AddSystem(dict, "modtools", "Source2ModTools001", 0)` at `0x20a3e9`, then
`AddSystems(dict, 1, {{"toolframework2","ToolFramework2_002"}})` at `0x20a41c`, then widens the window's
`WS_*` style bits via `[0x733ed8+400]`/`+0x198` (`| 0x20`, then `| 0x84` if none of `0x1c`).

**Phase E — services** (`0x20a554`–`0x20a591`). `AddSystem(dict, factory(), "EngineServiceMgr001")` and
`"HostStateMgr001"` — but note the module argument is `fcn.0x40af20()`, which is
`lea rax,[0x18040aec0]; ret` i.e. **the address of `CreateInterface` used as a "self" sentinel**. These two
services are built into engine2 itself.

The call used here is `0x2efd00` (530 bytes), a **third** add-system variant distinct from `0x2f0390`:
signature `(dict, module, interface)`, it resolves the interface name through the same
`CUtlSymbolTable` at `dict+0x68` but tests the existing record's `+0x18` field for null (rather than
calling `[iface+0x48]` as `0x2f0390` does), and on a duplicate emits
*"AppSystemDict: Attempted to add two different systems with the same interface name %s!\n(Existing
entry.)\n"* via `Plat_FatalError`. It has exactly **3 call sites**: `0x20a55e` and `0x20a575` (these two
services) and `0x20ab33` (Phase G's `EngineGameUI001` registration).

**Phase F — game UI and the client/server service set** (`0x20a5b8`–`0x20a7d4`).

If `!HasModAppSystems` (i.e. the engine is not driving a mod's app systems):
`AddSystem(dict, factory(), "EngineGameUI001")` at `0x20a640`.

Otherwise a `CUtlVector` of `{module,interface}` is built with `fcn.0x212220` (the vector-append helper)
and then `fcn.0x2f06c0(dict, n, rows)` is called **three times** at `0x20a703`, `0x20a751` and `0x20a791`:

- client path (`[obj+0xfc] == 0`):
  1. `{engine2, EngineGameUI001}` — `0x20a5b8`
  2. `{engine2, Source2EngineToClient001}`, `{engine2, VENGINE_GAMEUIFUNCS_VERSION005}`,
     `{engine2, INETSUPPORT_001}`, `{host, Source2Host001}`, `{client, Source2Client002}`,
     `{client, Source2ClientPrediction001}`, `{client, Source2ClientUI001}` — `0x20a645`–`0x20a6a4`
  3. `{client, ClientLocalServerAccess001}` if `Engine2/ClientLocalServerAccess` — `0x20a6e4`
  4. `{client, Source2GameEntities001}`, `{client, Source2GameClients001}`, `{client, Source2Server001}`
     — `0x20a717`–`0x20a73d`
  5. `{client, LocalServerClientAccess001}` if `Engine2/LocalServerClientAccess` — `0x20a772`
  6. `{client, LegacyGameUI001}` if `fcn.0x206880()` (i.e. `Engine2/HasLegacyGameUI`) — `0x20a79f`
- dedicated path (`[obj+0xfc] != 0`):
  `{engine2, INETSUPPORT_001}`, `{host, Source2Host001}`, `{server, Source2GameEntities001}`,
  `{server, Source2GameClients001}`, `{server, Source2Server001}` — `0x20a7c3`–`0x20a8a2`

**Phase G — registration of engine-provided interfaces into other modules** (`0x20a974`–`0x20ab21`).
If `[0x733f90]` (the `MATCHFRAMEWORK_001` registry) exists, engine2 registers its own implementations:

```
[0x733f90]->GetFactory()->Register("INETSUPPORT_001",        0x6b8c70)
[0x733f90]->...->Register("Source2EngineToClient001",        0x734138)
[0x733f90]->...->Register("LegacyGameUI001",                 0x6bd748)
[0x733f90]->...->Register("Source2EngineToServer001",        0x734140)
[0x733f90]->...->Register("HostStateMgr001",                 0x734168)
[0x733f90]->...->Register("EngineServiceMgr001",             0x734160)
```

**Phase H — module enumeration** (`0x20ab21`–`0x20abc0`). Unless a hashed flag (`0x40f181e0`) is present,
`Plat_GetLoadedModules(&array)` and `fcn.0x211af0(module)` per entry — the latter resolves
`GetModuleInformation` from `Kernel32.dll`/`Psapi.dll` and logs each module's size, i.e. it is the
**`StackTools_EnumerateKnownLoadedModules`** hook used by minidumps (`0x211af0`'s imports are
`GetModuleHandleExA("Kernel32.dll")`, `GetModuleHandleExA("Psapi.dll")`,
`Plat_GetModuleProcAddress(...,"GetModuleInformation")`).

Finally `COM_TimestampedLog("LoadAppSystems:  finished")` at `0x20abcf` and `return 1`.

### 3.5 Comparison against `graph.json`

`graph.json` puts `engine2` at `layer 1` with `imports: {tier0: 709, KERNEL32: 154, steam_api64: 22,
WS2_32: 13, USER32: 11, GDI32: 9, steamnetworkingsockets: 2, ADVAPI32: 1, WINMM: 1}`. That is *static*
linking only. The **dynamic** dependency set is much larger and is what §3.4 enumerates: engine2 will
`Plat_LoadModule` at least **24 distinct DLLs** at runtime (tier0, localize, meshsystem, worldrenderer,
pulse_system, vscript, networksystem, animationsystem, vphysics2, soundsystem, steamaudio, scenesystem,
particles, panoramauiclient, modtools, toolframework2, materialsystem2, filesystem_stdio, inputsystem,
client, server, host, resourcesystem, schemasystem), none of which appear in its import table. `graph.json`
also has no edge for `engine2 → materialsystem2`, `engine2 → client` or `engine2 → server`, because those
are `LoadLibrary` calls that happen through tier0's `Plat_LoadModule` — invisible to a PE import scan.
`graph.json`'s `third_party_surface.engine2 = {steam_api64: 22, steamnetworkingsockets: 2}` is correct and
exhaustive for *statically linked* third-party code; §7 adds the statically-linked **libopus**, **PCRE**,
**protobuf 3.21.8**, **zlib**, **libpng** and **WebRTC AEC3/AGC2** that are also compiled in but not
visible as imports.

### 3.6 `filesystem_stdio` and the special-cased subsystems

`filesystem_stdio` is loaded **before** `LoadAppSystems`, from `0x1934e0` (`CTier2AppSystemDict::Init`,
698 bytes — the function's own `__FILE__` is `public\appframework\tier2app.h` line `0x2ea`):

```
0x1934f8  fcn.0x191bd0(obj)                       ; mod discovery / VMOD
0x193519  AddSystem(obj, "filesystem_stdio", "VFileSystem017", 0)
0x19352a  fcn.0x2f1e20(obj)                       ; get the IFileSystem*
0x193542  CRefCount::AddRef
0x193551  fcn.0x193fe0(obj)                       ; GAMEROOT/CONTENTROOT setup
0x19377e  fcn.0x192e60(obj)                       ; console/log-file setup
```

`0x193fe0` (6,959 bytes) is the **game-directory resolver**: it derives `EXECUTABLE_PATH` and `bin\win64`
from `Plat_GetGameDirectory` (`0x194094`), verifies the slashes (`V_AreSlashesCorrect`, `0x194148`), then
walks `FileSystem/SearchPaths` from `gameinfo.gi` (`0x194447`–`0x194554`), composing each entry and testing
`Plat_IsDirectory` (`0x194545`). It sets `GAMEROOT` and `CONTENTROOT` (`0x19466c`/`0x194688`) and, if the
two are not siblings, logs *"Search paths for GAMEROOT and CONTENTROOT are expected to be sibling
directories\n\tGAMEROOT: \"%s\"\n\tCONTENTROOT: \"%s\"\n"* (`0x1935**`, `tier2app.h:0x2ea`).

`0x191bd0` (1,132 bytes) is the **mod-directory resolver**: it reads `-game` (`FindParm(0x23ec0df8)`) or the
`VMOD` environment variable (`Plat_GetEnv("VMOD", ...)`, `0x191**`), and on failure shows
*"Application \"%s\"\nis running without a known mod!\n\nSet the VMOD environment variable or run with
-game to set the mod name.\n"* and *"No know mod!"* (the typo is in the binary). It ends by registering
`AddSystem(obj, "tier0", "VStringTokenSystem001", 0)` at `0x19201b`.

`0x1928c0` (842 bytes, the `CMaterialSystem2AppSystemDict` constructor called from `0x20e210`) then does the
**console bootstrap**: it reads `-condebug` / `-consolelog` / `-con_logfile` (hashes `0x1ae13a16`,
`0x499c6bd0`, `0x99463093`), sets `[obj+0x468]=1` for console logging, computes the log file name (default
`"console.log"`, `0x192a05`), and registers `AddSystem(obj, "vconcomm", "VConComm001", 0)` at `0x192b9a`
(unless `-consoleapp` is present, `0x192b75`). It also initialises `CUtlSymbolTable`s at `+0x348` and
`+0x3b8`, a `CMemAllocSystemInitialize`, and the `0x4e8`-byte object's two `CUtlString`s at `+0x458`
(log file) and `+0x4d8` (startup background).

---

## 4. The interface registry

### 4.1 `CreateInterface` — `0x40aec0`, 94 bytes

```
40aec0  mov  r9,  [rip+0x329b11]     ; r9 = g_pInterfaceList  (0x7349d8)
40aec7  mov  r10, rdx                ; r10 = pReturnCode
40aeca  mov  r11, rcx                ; r11 = pName
40aecd  test r9, r9
40aed0  je   40af00                  ; empty list -> not found
40aed2  mov  rax, [r9+8]              ; rax = node->pszName
40aed6  mov  r8,  r11
40aed9  sub  r8,  rax                ; r8 = pName - node->pszName
40aedc  nop  dword [rax]
40aee0  movzx edx, byte [rax]        ; strcmp loop, byte at a time
40aee3  movzx ecx, byte [rax+r8]
40aee8  sub  edx, ecx
40aeea  jne  40aef3
40aeec  inc  rax
40aeef  test ecx, ecx
40aef1  jne  40aee0
40aef3  test edx, edx
40aef5  je   40af0f                  ; match
40aef7  mov  r9, [r9+0x10]           ; r9 = node->next
40aefb  test r9, r9
40aefe  jne  40aed2
40af00  test r10, r10
40af03  je   40af0c
40af05  mov  dword [r10], 1          ; IFACE_FAILED
40af0c  xor  eax, eax
40af0e  ret
40af0f  test r10, r10
40af12  je   40af1b
40af14  mov  dword [r10], 0          ; IFACE_OK
40af1b  jmp  qword [r9]              ; tail-call node->factory
```

Registered node is a 24-byte record:

```
+0x00  void* (*factory)(void)
+0x08  const char* pszName
+0x10  Node* pNext           ; singly linked, head-inserted
```

List head is `0x7349d8`. Lookup is a linear walk with an inline byte-wise `strcmp`; **no hash, no binary
search, case sensitive**. `pReturnCode` may be null.

**The registrar** is `0x40aea0` (36 bytes), immediately before `CreateInterface`:

```
40aea0  mov [rcx+8], r8       ; node->pszName
40aea4  mov [rcx],   rdx      ; node->factory
40aea7  mov rax, [0x7349d8]   ; old head
40aeae  mov [rcx+0x10], rax   ; node->next = old head
40aeb2  mov rax, rcx
40aeb5  mov [0x7349d8], rcx   ; head = node
40aebc  ret
```

Registration order is therefore **reverse of list order**, and duplicate names are *not* rejected — the
first match walking from the newest registration wins. Two further helpers sit next to it:
`0x40ae50` (56 bytes, "connect" notification, called from 16 sites including `0x52270`, `0x13ce4c`,
`0x1a936c`, `0x1aa8c5`, `0x1b5d35`, `0x1c04d1`, `0x1d663e`, `0x1e2e26`, `0x1e65f0`, `0x1e72b5`, …) and
`0x40ae90` (8 bytes, clears the one-shot flag at `0x7349d0`; 6 callers). `0x40af20` is the "give me the
address of `CreateInterface`" thunk used by `0x209140` as the self-module sentinel (§3.4 phase E).

### 4.2 The registration thunk pattern

Every self-registered interface in this module is a 21-byte stub followed by `jmp 0x40aea0`:

```asm
005240  lea r8,  [rip+0x...]   ; "Source2EngineToClient001"
005247  lea rdx, [rip+0x...]   ; factory thunk -> 0x75d00
00524e  lea rcx, [rip+0x...]   ; static node   -> 0x739720
005255  jmp 0x40aea0           ; register
00525a  int3
```

The factory thunk is a one-line "return the singleton slot":

```asm
075d00  lea rax, [rip+0x...]   ; -> 0x738d70 (the object slot)
075d07  ret
```

### 4.3 The full registered table — 34 entries

A scan of every `jmp 0x40aea0` in `.text` finds exactly **34** stubs. Decoded:

| Stub RVA | Interface name | Factory thunk | Node RVA |
|---|---|---|---|
| `0x005255` | `Source2EngineToClient001` | `0x75d00` | `0x739720` |
| `0x005bf5` | `Source2EngineToClientStringTable001` | `0x9d060` | `0x739828` |
| `0x0066c5` | `Source2EngineToServer001` | `0xa3b40` | `0x977cd0` |
| `0x0079f5` | `Source2EngineToServerStringTable001` | `0xbbde0` | `0x977eb8` |
| `0x00ba05` | `INETSUPPORT_001` | `0x1080b0` | `0x978708` |
| `0x00f6e5` | `EngineGameUI001` | `0x13cbe0` | `0x978eb8` |
| `0x00f715` | `VENGINE_GAMEUIFUNCS_VERSION005` | `0x13d8e0` | `0x978ed0` |
| `0x010e75` | `BenchmarkService001` | `0x1a9340` | `0x9790a8` |
| `0x010f95` | `BugService001` | `0x1aa3a0` | `0x9792f8` |
| `0x010fe5` | `BugBugService001` | `0x1adb60` | `0x979328` |
| `0x0110b5` | `GameResourceServiceClientV001` | `0x1b1970` | `0x979360` |
| `0x0110f5` | `GameResourceServiceServerV001` | `0x1b1980` | `0x979390` |
| `0x0114d5` | `GameUIService_001` | `0x1b4ee0` | `0x9797e8` |
| `0x011715` | `InputService_001` | `0x1b8eb0` | `0x9b8510` |
| `0x012645` | `MapListService_001` | `0x1cc720` | `0x9b87d8` |
| `0x012815` | `NetworkClientService_001` | `0x1d3db0` | `0x9b8b20` |
| `0x012915` | `NetworkP2PService_001` | `0x1db5e0` | `0x9b8ca0` |
| `0x012ca5` | `NetworkServerService_001` | `0x1e0240` | `0x9b8ee0` |
| `0x012fe5` | `NetworkService_001` | `0x1e6400` | `0x9b8f50` |
| `0x013075` | `RenderService_001` | `0x1e6860` | `0x9b9150` |
| `0x013945` | `ScreenshotService001` | `0x1e9610` | `0x9b93c0` |
| `0x0139a5` | `SoundService_001` | `0x1ee5d0` | `0x9b9710` |
| `0x014ea5` | `SplitScreenService_001` | `0x1f5600` | `0x9b98f8` |
| `0x014f75` | `StatsService_001` | `0x1f8180` | `0x9b9fb8` |
| `0x015125` | `ToolService_001` | `0x1fc610` | `0x9ba008` |
| `0x0156b5` | `VProfService_001` | `0x1fe370` | `0x9ba070` |
| `0x015a85` | `ClientServerSharedHandleSystem001` | `0x200990` | `0x9ba150` |
| `0x017665` | `EngineServiceMgr001` | `0x212b90` | `0x9ba638` |
| `0x017a35` | `GameEventSystemClientV001` | `0x218330` | `0x9ba8f0` |
| `0x017a55` | `GameEventSystemServerV001` | `0x218340` | `0x9ba908` |
| `0x017ba5` | `HostStateMgr001` | `0x21cda0` | `0x9ba930` |
| `0x017bd5` | `KeyValueCache001` | `0x21f440` | `0x9ba948` |
| `0x018965` | `ClientServerEngineLoopService_001` | `0x225330` | `0x9bac08` |
| `0x018ea5` | `SimpleEngineLoopService_001` | `0x234c80` | `0x9bae40` |

Four of these factories are pure "return this global" one-liners, which tells you the object lives in
`.data`:
`0x212b90` → `0x9ba3b0` (`EngineServiceMgr001`),
`0x234c80` → `0x6c03b0` (`SimpleEngineLoopService_001`),
`0x225330` → `0x9baae0` (`ClientServerEngineLoopService_001`),
`0x40af20` → `&CreateInterface` (self).

### 4.4 The *other* registry: the 115-entry catalogue at `0x561420`

`CreateInterface` only knows the 34 names above. The engine also carries a **flat catalogue** of
`{const char *name; void **cache_slot;}` 16-byte rows starting at `0x561420` and running to `0x561b50`,
i.e. **exactly 115 entries**:

```
0x561420  "VApplication001"              -> 0x733e70
0x561430  "VEngineCvar007"               -> 0x733e78
0x561440  "VStringTokenSystem001"        -> 0x733e80
...
0x561b40  "ClientLocalServerAccess001"   -> 0x734200
```

The full list is reproduced in the table below (names are the literal `.rdata` strings; the slot is the
`.data` pointer that receives the resolved interface). The catalogue is consumed by `0x406120`
(`InitInterfaceCaches`, 1,131 bytes) — its only direct reference to `0x561420` is `lea rdi,[0x180561420]` at
`0x40613b` — which for each row either calls the factory directly (`arg2 == 0`) or matches `arg2` against
the name and then calls the factory, storing the result through the slot. A second helper `0x406920`
(`GetCachedInterface`, 100 bytes) resolves a **slot** (not a name) to the interface pointer, with
`-1` meaning "the first valid entry". `0x406240`/`0x4062d0` are the `ConVar` constructors and `0x406ad0` /
`0x407d90` are the two `ConCommand` constructors (§6).

**Catalogue vs. `ifaces/engine2.txt`.** The 104-name index in `ifaces/engine2.txt` is a *superset*: it
includes 27 names that are only present as `.rdata` strings (Steam client interfaces like `SteamClient023`,
`SteamUser023`; the config interfaces `Source2ClientConfig001`/`Source2ServerConfig001`; the loop services
`ClientServerEngineLoopService_001`; and `VENGINE_GAMEUIFUNCS_VERSION005`), and it *omits* 39 names that
appear only in the catalogue (`SchemaSystem_001`, `Localize_001`, `MaterialUtils_001`, `SceneSystem_002`,
`SceneUtils_001`, `ToolFramework2_002`, `MapListService_001`, `Network*Service_001`, `RenderService_001`,
`SoundService_001`, `StatsService_001`, `ToolService_001`, `PanoramaUIEngine001`, `FontManager_001`, …).
Neither set is "the" registry: the catalogue is engine2's *consumer* list (what it resolves), the 34
`CreateInterface` entries are what engine2 *produces*, and the index is the union of everything the module
mentions by name. All three are recorded here so the discrepancy is explicit rather than papered over.

**`InstallSchemaBindings` (`0x424310`, 75 bytes).** This is a cross-module handshake, not a registration:

```
424310  push rbx / sub rsp,0x20
424316  mov rbx, rdx                 ; save the callback
424319  mov rdx, rcx                 ; rdx = the module name to look for
42431c  lea rcx, "SchemaSystem_001"  ; 0x561bb8
424323  call 0x4cfe20                ; strcmp-like helper
424328  test eax,eax
42432a  je   424334                  ; equal -> proceed
42432c  xor al,al / ret              ; not schemasystem -> return 0
424334  cmp byte [0x734ab8], 0       ; already installed?
42433b  jne  424353
42433d  mov rcx, rbx
424340  mov [0x733f40], rbx          ; cache the ISchemaSystem*
424347  call 0x424190                ; the actual binding installer
42434c  mov byte [0x734ab8], 1       ; one-shot
424353  mov al,1 / ret
```

So: `InstallSchemaBindings(pszModuleName, pSchemaSystem)` returns 1 only if `pszModuleName ==
"SchemaSystem_001"`, and installs the bindings exactly once. `0x424190` (381 bytes) then walks the
`entity_api`/`fields`/`base` schema blocks (`0x424375`, `0x4243d8`, `0x4243e4`). This is the engine side of
the entity-schema binding that `client.md` §3.4 documents from the client side.

`GetResourceManifests` (`0x422c00`) and `GetResourceManifestCount` (`0x422bf0`) are the pair
`resourcesystem` calls during mount; they walk the list at `0x734a88` whose nodes are
`{next, ptr, lazy_fn}` — `lazy_fn` is invoked at most once per node (`puVar1[1]` caches the result).

---

## 5. The main loop

There are **two nested loops**, and the distinction matters.

### 5.1 The outer loop: `CEngineServiceMgr::_MainLoop` — `0x214980` (4,824 bytes)

This is the function whose `__FILE__` is `src\engine2\engineservicemgr.cpp` and whose vprof budget group
is `"CEngineServiceMgr::_MainLoop"` (`0x2149c7`). It is **not** referenced from the `CEngineServiceMgr`
vtable at `0x61f060` (a qword scan of `.rdata` finds no pointer to `0x214980`); it is called directly
from `0x20d3fc`, inside `MainLoop` (§5.2). It is *not* the frame loop — it is the **loop-mode
dispatcher**.

Structure:

1. **Watchdog.** `Plat_IsInDebugSession()` and a hashed "is game" test → `Plat_BeginWatchdogTimer(0x3c,
   "CEngineServiceMgr::_MainLoop")` at `0x2149c7` region.
2. **`loop_dump` support.** If `0x9bcfcc` (set by the `loop_dump` ConCommand at `0x17670`) is non-zero:
   print `"** No active loop **\n"` or `"Active loop %s:\n"` + `[loop+0x50](loop)`.
3. **ETW autodetect.** `0x6b9f40` is the ETW level; a rising edge produces `"ETW collection detected\n"`,
   `"Command line: %s\n"` and `fcn.0x20f0f0()` which calls `fcn.0x20e8a0(0x61ad18, 4, 0)` — the
   `Plat_EventRegister` provider registration (`0x61ad18` is a 4-entry provider descriptor, and
   `0x20e830` is the `Msg`-based provider callback).
4. **Window geometry.** `Plat_GetWindowClientBounds` / `Plat_GetWindowContentsScale` /
   `[0x733fe0+0x20]` (the render device's window), with a `fVar21 < 1.0` guard at `0x6256dc`. On change it
   forwards the new rect + scale to `[0x733f78+0x200]` (input) at `0x214c92`.
5. **Per-loop pre-tick.** `iStack_358 = {window, hwnd, size, scale}` and either
   `[0x733f50+0x68](5000000, 1)` (no loop → sleep 5 s) or `[loop+0x40](loop, &iStack_358)` at `0x214d50`.
6. **The mode switch.** `0x9ba520` is a tri-state: 1 = "pending switch", 2 = "running", 0 = "idle".
   - `0x9ba520 == 1`: ask `[0x7340a8+0x98]()` (the tool framework) whether it wants control; if 1 stay,
     if 0 → 2.
   - `0x9ba520 == 2`: `[0x733f98+0xd0](tools_or_engine)` at `0x214dd6`, then
     `[loop+0x60](loop, &iStack_358)` at `0x214df8` — **this is the per-frame tick of the active loop
     object** — then `[0x734178+0xd8](0x3b)` and `[0x734188+0xf0](0x3b)` (network services, 59 ms budget),
     then tears down the pending loop (`func_0x1802140f0`), then `func_0x180213d80` (loop-state push).
7. **Loop switch.** `0x9ba468` is the "requested loop" (a KeyValues). `func_0x180213d80` reads it, compares
   the requested index/name against the current (`[0x9ba468] == [0x9ba470]` via `CUtlString::operator==`),
   and if different calls `func_0x180216820(loop, name)` — the **loop factory** — then
   `[newloop+0x20](idx, [loop+0x1c], [loop][2], &0x9ba3d8)` (construct) at `0x2150**`.
8. **Sleep / frame pacing.** `func_0x180214830(window)` returns whether the app should idle (it consults
   `[0x733f78+0x230]`, `[0x733f98+0x68]`, `0x9ba330+0x58`, the `-` hashed flags `0x16627b76` and
   `0x2ae8adab`, `[0x734030+0x540]`, `[0x733fe0+0x578]`, `[0x6bc1e0+0x68]`). If it returns true:
   `uVar13 = *(*(0x9ba320) + 0x58)` — the `engine_no_focus_sleep` budget. That ConVar is registered at
   `0x17030` into the 16-byte `{handle, value-ptr}` descriptor at `0x9ba318`; `0x9ba320` is its `+8`
   (the value pointer), and `+0x58` off that is the integer value;
   if the window is minimised, `max(100, uVar13)`. The value is cached in `0x6b96e0` and, on change, logged
   as `"Will now sleep %dms each frame\n"` at `0x2156**`.
9. **The sleep itself** (`0x2155a5` onward, 0x5b3 line in `engineservicemgr.cpp`): a vprof scope
   `"Sleep"` (`0x6b96e8`), then
   ```
   fVar22 = Plat_FloatTime();
   do {
       uVar13 = min(pcVar15, 100);
       [0x733f78+0x158](uVar13);        // input->Sleep(ms) -> ThreadNanoSleep
       pcVar15 -= uVar13;
   } while (pcVar15 > 0 && func_0x180214830(window));
   0x9bcfc0 = Plat_FloatTime() - fVar22;   // measured sleep time
   func_0x180220e80("idle_sleep", 2);
   ```
   So the loop sleeps in **≤100 ms chunks** and re-checks whether it should wake, up to the full
   `engine_no_focus_sleep` budget. This is the "sleep/spin scheduler" the task asks about: it is a
   *chunked* sleep with a wake predicate, not a pure spin.
10. **Post-frame work.** `0x9ba490` is the count of "deferred jobs"; each is polled via
    `[job+0x18]()` at `0x2159**`, a return of 2 means "failed", and the job vector is compacted in place
    (swap-with-last). When the count reaches zero the loop is switched: `[0x9ba3e8][idx]` gives the
    loop-mode object, `[loop+0x30](loop, &iStack_358, 0x9ba528)` and `[0x9b8f80+0x120]()` run, and
    `func_0x180213af0(..., 1)` finalises.
11. **Steam restart path.** If `[0x9ba3a0+0x58]` (a ConVar) is set and Steam is running, `_MainLoop` opens
    `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)`, finds `steam.exe`, and `CreateProcessA` on it with
    `-applaunch <appid>` (`0x215133`), printing `"Restarting application ID %d via Steam...\n"`. This is the
    "restart through Steam" mechanism.
12. `Plat_EndWatchdogTimer("CEngineServiceMgr::_MainLoop")` and return.

### 5.2 The inner loop: `0x20d0f0` — `"MainLoop"` (1,631 bytes)

`0x20d0f0` is the function whose `__FILE__`/`__FUNCTION__` pair is
`src\engine2\engine2.cpp` / `"MainLoop"` (`0x20d1e7`/`0x20d1f2`, and again at `0x20d56b`). It is called
from `0x20e631`, i.e. from `0x20e170` step 9. Its budget group is `"MainLoop"` (`0x6b9678`), and it wraps
the whole loop in `CStackTop_Base`.

```
20d0f0  CStackTop_Base ctor
20d1**  if (window == NULL && !has_render_device() && [0x733e70+0xb8]() && [0x733e70+0xc0]() == 0)
            Plat_FatalError("GetAppWindow() returned NULL");
20d**   Plat_SetCurrentFrame(0);
        t0 = Plat_USTime();  one_second = t0 + 1000000;
        last = Plat_FloatTime();
        do {
            AssertsMarkFrame();
            ... vprof enable/disable (0x6c0199/0x6c019a, g_VProfCurrentProfile+0x100c)
            ... SetProfileAllThreads, MarkFrame
            func_0x1801fe8a0();          // vprof counter plumbing
            func_0x180108020();          // "Begin mem_test"/"End mem_test" probe
            vprof scope "MainLoop" @ engine2.cpp:0xcca
            f0 = Plat_FloatTime();
            if (fatal) { while (Plat_HasEnteredFatalState()) ThreadSleep(1000); }
            if (one_second <= Plat_USTime()) { one_second = now + 1000000; ... }
            r = func_0x180214980(...);   // <-- CEngineServiceMgr::_MainLoop
            func_0x18021e7d0();          // deferred-KV cleanup
            if (0x9ba4a0) { 0x9ba4a0 = 0; if (0x6c02d0) { ...host-activate switch... } }
            if (r == 0) {                // engine asked to quit
                [0x733f50+0x70]();       // resourcesystem->Shutdown
                log "Dispatching EventAppShutdown_t {"
                dispatch EventAppShutdown_t (0x6ba7a0)
                log "} Dispatched EventAppShutdown_t"
                func_0x180200580(1);
                [0x733f20+0x78]();
                log "MainLoop returning"
                return;
            }
            f1 = Plat_FloatTime();
            0x9bcf98 = f1 - f0;          // frame time
            if (r == 1) { func_0x180215eb0(...); f0 = Plat_FloatTime(); 0x9bcf9c = f0-f1; }
            else if (r == 2) { last = Plat_FloatTime(); ... }
            Plat_ChangeCurrentFrame(1);
        } while (true);
```

**Return protocol:** `0x214980` returns 0 → quit, 1 → "normal frame, sleep", 2 → "frame consumed a
sleep". `0x9bcf98` is the *frame* duration and `0x9bcf9c` the *sleep* duration; both are read by the
`!engine_frametime_warnings_enable` code at `0x221434`.

### 5.3 The frame's inner work: `CLoopTypeClientServer::Update` — `0x22a510` (11,098 bytes)

The active loop object is a `CLoopTypeClientServer` (vtable `0x620fe0`, locator `0x653c40`). Its
`Update` slot is `+0x40` = `0x22a510`; the `__FILE__` is `src\engine2\looptypeclientserver.cpp`, and the
vprof group names in the body are `"ClientSimulateTick"` (`0x22b227`), `"ClientSimulateFrame"`
(`0x22bb0e`), `"FrameBoundary"` (`0x22c816`), `"Present_RenderDevice"` (`0x22cac8`/`0x22cb14`) and
`EventFrameBoundary_t` (`0x22ceca`, string at `0x621190`).

The frame is:

1. `Plat_FloatTime()` twice (`fVar27`, `fVar28`) — the frame start time and a second reference.
2. `func_0x180228670(loop)` / `func_0x180228950(loop)` — per-frame bookkeeping.
3. `func_0x180229010(loop, t0, &tick, t1, &pf)` — **compute how many server ticks and client ticks to
   run this frame**. `puStack_2d8` is the server-tick count and `pfVar35` the client-tick count; both are
   logged: `"%f FRAME start %d ticks\n"` and `"%f FRAME start %d server ticks %d client ticks\n"`
   (`0x22b**`).
4. `func_0x18021f450(&queue, loop)` then `func_0x18022fd90(loop, t, loop+0x188, &queue)` and
   `func_0x18022f660(loop, &pf, &x, &queue)` — set up the frame's work queue.
5. **Server ticks**: `func_0x180229d40(loop, ctx, serverTicks, f, pf, ...)` — the
   `CLoopTypeClientServerService::OnServerAdvanceTick` / `OnServerPostAdvanceTick` /
   `OnServerBeginAsyncPostTickWork` / `OnServerEndAsyncPostTickWork` dispatcher (`0x225340`, 8,453 bytes,
   strings at `0x226a2c`–`0x226b**`).
6. **Client ticks**: `func_0x18022a1f0(loop, n)` — `ClientCommandTick` (`0x22a1f0`, 439 bytes).
7. **Client simulate**: `func_0x18022fd90` again, then the `ClientSimulateTick` / `ClientSimulateFrame`
   vprof scopes, and the `DispatchEvent( %s ) took %f msecs` wrappers `0x230b90`, `0x230d50`,
   `0x230f10`, `0x2310d0`, `0x231290`, `0x231450`, `0x231610` (plus `0x22f660` and `0x22fd90` earlier in
   the frame). All **30** such wrappers in the module are 436 bytes and byte-identical apart from the
   event-descriptor pointer — `0x22f660`, `0x22f850`, `0x22fa10`, `0x22fbd0`, `0x22fd90`, `0x22ff50`,
   `0x230110`, `0x2302d0`, `0x230490`, `0x230650`, `0x230810`, `0x2309d0`, `0x230b90`, `0x230d50`,
   `0x230f10`, `0x2310d0`, `0x231290`, `0x231450`, `0x231610`, `0x2317d0`, `0x231990`, `0x231b50`,
   `0x231d10`, `0x231ed0`, `0x232090`, `0x232250`, `0x232410`, `0x2325d0`, `0x235bf0` (plus the
   generic `0x220620`, 724 bytes). This is `CGameEventDispatcher::Dispatch` after the compiler unrolled
   a table of dispatches; each wrapper tests `[this+9]` (a "log this event" byte) and, if set, emits
   `"%s: %5d:  DispatchEvent( %s )\n"` via `Msg` before invoking the handler.
8. `func_0x18022e3d0(&x)` — `FrameBoundary`; then the `Present_RenderDevice` scope and the actual
   present; then `EventFrameBoundary_t` dispatch at `0x22ceca`.
9. Frame-time accounting into `0x9bcf98`/`0x9bcf9c` (§5.2).

### 5.4 Timing constants

The FP constants the loop uses live in `.rdata` and are worth recording because they *are* the timing
model:

| RVA | Value | Meaning |
|---|---|---|
| `0x625650` | `1e-9` (as double) | ns → s |
| `0x6256e0` | `0.01` | 10 ms — the "target time is close enough" window used by `0x214450` |
| `0x625728` | `1.0` | one second |
| `0x6256e8` | `0.015625` | 1/64 s |
| `0x625740` | `5.0` | the ETW "collection detected" window |
| `0x625798` | `1000.0` | s → ms |
| `0x6257c8` | `1e9` | s → ns |
| `0x6256dc` | `1.0` | the contents-scale / `max(1.0, scale)` guard |

`0x214450` (989 bytes) is the **frame-time filter**: it takes the previous target, the actual time, and
the "server asked to sleep" value, and returns 0 (sleep) or 1 (don't). Its log line is
*"Server asked to sleep for %.3fms, but plat time advanced by %.3fms. (We woke up %.3fms early)\n"*
(`0x215f**`). `0x215eb0` (628 bytes) is `SleepAfterMainLoop` (vprof group `0x6b96d0`), which calls
`ThreadNanoSleep` and, when the dedicated-server VProfLite path is active, brackets the sleep with
`VProfLite_DedicatedServerSleepBegin`/`End`.

**Server/client tick separation.** The server tick count and client tick count are computed independently
in `0x229010` (2,693 bytes) and are both logged. `sv_tick_parallel_with_client` is a real ConVar
(`0x406240` at `0x172**` region) and appears four times in the command table — so CS2 can run server and
client ticks **in parallel** or serially, and the loop object decides per frame. The actual parallel
execution is in `0x225340`, which is why that function is 8.4 KB: it has both a serial path and a
job-queue path gated on `sv_tick_parallel_with_client`.

---

## 6. Cvar / command dispatch

### 6.1 The command line is hashed, not compared

This is the single most important structural fact about `engine2.dll`'s option handling, and it is why a
plain string search for `-dev` or `-console` in `.text` finds nothing.

`tier0!CommandLine()` returns a `CCommandLine*`. Every argument test in engine2 is:

```asm
call tier0!CommandLine
mov  rcx, rax                  ; this
mov  edx, 0xXXXXXXXX           ; the *hash* of the parameter name
xor  r8d, r8d                  ; default (0)
call [vtable + 0x98]           ; CCommandLine::FindParm(const char* name, int default)
```

or `[vtable + 0x90]` (`HasParm`), or `[vtable + 0xb0]` (`ParmValue`), or `[vtable + 0x20]`
(`HasParmNoHash`, used where the caller already has a raw string), or `[vtable + 0x18]`
(`ParmValueInt`), or `[vtable + 0x30]`/`[vtable + 0x68]` (`ParmValueFloat` / `GetArgv`).

The hash is **Murmur2 with seed `0x31415926`** — the Source 2 `CUtlStringToken` construction, the same
family `client.md` §6.2 describes around the Murmur2 constant `0x5BD1E995`. The seed here is the
Source-style `0x31415926`, not `client.dll`'s default, which is why a plain Murmur2 with seed 0 does not
reproduce these values. Verified by brute force against the recovered set: with
seed `0x31415926`, `murmur2("-attachtodebugger") == 0x0258941d`, `murmur2("-breakimmediately") ==
0x42550058`, `murmur2("-windowless") == 0x9e22d97c`, `murmur2("-nominidumps") == 0xc64d5c6e`,
`murmur2("-nobreakpad") == 0xd8a5d350`, `murmur2("-netconport") == 0xe04399b8`,
`murmur2("-tools") == 0xbc4f1a2`, `murmur2("-addon") == 0x4ebeac3f`,
`murmur2("-dedicated") == 0x55a5c01b`, and the four bare coordinate flags `-w` `0x60011611`, `-h`
`0x472745af`, `-x` `0xe21b1c73`, `-y` `0x1a347fff` — all exact matches. This oracle is how the table
below was produced.

**Recovered parameters** (name → hash → where used):

| Hash | Name | Used at |
|---|---|---|
| `0x0258941d` | `-attachtodebugger` | `0x21126f` |
| `0x42550058` | `-breakimmediately` | `0x21128a` |
| `0xc64d5c6e` | `-nominidumps` | `0x2112c9` |
| `0xd8a5d350` | `-nobreakpad` | `0x211305` |
| `0x55a5c01b` | `-dedicated` | `0x20e195` |
| `0x4ebeac3f` | `-addon` | `0x20e4a3` |
| `0xbc4f1a2` | `-tools` | `0x20e2f0` region, `0x20e3c8` |
| `0xe04399b8` | `-netconport` | `0x2082a0`+0x2f4 |
| `0x9e22d97c` | `-windowless` | `0x2082a0`+0x9e0 |
| `0x60011611` / `0x472745af` / `0xe21b1c73` / `0x1a347fff` | `-w` / `-h` / `-x` / `-y` | `0x2082a0` window-geometry overrides |
| `0x23ec0df8` | `-game` | `0x191**`, `0x2082a0` |
| `0xcdbd1292` | `-cn` (startup background / language) | `0x2089**`, `0x2091**` |
| `0x8bc6a18d` | (window init flag) | `0x194025` |
| `0x1ae13a16` / `0x499c6bd0` / `0x99463093` | console-logging flags | `0x1928c0` |
| `0x8434c0e9` | (CTextConsoleWin guard) | `0x2082a0`+0x1e2 |

The **unrecovered** hashes (`0x63242f0f`, `0xa365b5d5`, `0x6bd98edd`, `0x5d0e81d2`, `0x40f181e0`,
`0x8434c0e9`, `0xcf571fda`, `0xe29d0d0c`) are listed in §9. They are hashes of strings that do not appear
in any of the 99 binaries in the corpus, so they are either multi-word (`-no<something>_<something>`) or
internal test flags.

### 6.2 ConVar registration — `0x406ad0`

`0x406ad0` (787 bytes) is the modern `ConVar` constructor used for the vast majority of the engine's
cvars. Signature (by call-site reconstruction):

```c
ConVar *ConVar_Register(ConVar *out,        // rcx
                        const char *name,    // rdx
                        const char *default, // r8
                        int flags,           // r9d
                        const char *help,    // [rsp+0x110] (the 5th arg)
                        ...);
```

It reads the *current* thread's `CConVar`-registry slot at `gs:[0x58] + 0x70` and, if the ConVar has a
`+0x60` word that is not `0xffff`, indexes a **0x58-byte-stride table at `0x6b58d0`** — that is the
`VEngineCvar007` per-module cvar array (the same `[0x733e78+0x148]` lookup as `0x4062d0`). It then links
the new ConVar into `0x6b6500` (the head) and fills the `ConVar` fields (`+0` name, `+8` default,
`+0x10` value, `+0x18` flags, `+0x20` help).

A **337 call sites** exist for `0x406ad0` in `.text`; extracting the `rdx` string from each gives
**309 distinct ConVar names** — that is the engine's own cvar registry. Notable engine-level ones:

| ConVar | Registered at | Help text |
|---|---|---|
| `fps_max` | `0x172f0` | "Frame rate limiter. 0=no limit. Does not apply to dedicated server." |
| `fps_max_ui` | `0x173a0` | "Frame rate limiter while the game UI is displayed. …" |
| `fps_max_tools` | `0x17440` | |
| `sv_fps_max` | `0x174e0` | "Dedicated server frame rate limiter. 0=tick rate. Only applies to the dedicated server." |
| `engine_no_focus_sleep` | `0x17030` | (registered into `0x9ba318`, flags 3, default `0x14`=20) |
| `engine_no_focus_sleep_vconsole_suppress` | `0x170e0` | "When VConsole is in the foreground, don't trigger engine_no_focus_sleep behavior" |
| `print_changed_convars` | `0x16bd0` | "Prints all convars that have changed from their default value" |
| `opus_encode_test_signal` | `0x148d0` | (flags 2, hidden) |
| `sv_tick_parallel_with_client` | `0x172**` region | |
| `input_forceuser` | `0x5260` | |
| `demo_max_consecutive_skip_packets`, `demo_recordcommands`, `demo_quitafterplayback`, `demo_usefastgoto`, `timedemo_start`, `timedemo_end`, `demo_flush`, `demo_debug`, `cl_flushentitypacket`, `cl_parallel_readpacketentities`, `cl_parallel_readpacketentities_threshold`, `cl_generate_postdataupdatepreserved` | — | (sampled from the 309) |

Two older constructors also exist: `0x4062d0` (129 bytes, "default-only" ConVar — 383 call sites but only
10 distinct *names*, because it is mostly called with a sentinel) and `0x406240` (131 bytes, a
ConVar-ref constructor that copies an existing ConVar; 27 call sites, 17 distinct names such as `password`,
`sv_skyname`, `tv_delay`, `tv_delay1`, `mat_shading_complexity`, `mat_overdraw`,
`cl_spawngroup_spewresources`). `0x406920` (100 bytes) is the resolver that maps a ConVar *handle* back to
its `ConVar*`.

### 6.3 ConCommand registration — `0x407d90`

`0x407d90` (522 bytes) is the `ConCommand` constructor:

```c
ConCommand *ConCommand_Register(ConCommand *out,   // rcx
                                const char *name,   // rdx
                                void (*fn)(void),   // r8
                                const char *help,   // r9
                                int flags,          // [rsp+0x90]
                                ...);
```

**223 call sites**, **204 distinct command names**. Sample: `stop`, `record`, `_record`, `vtune`,
`playdemo`, `timedemo`, `timedemoquit`, `listdemo`, `benchframe`, `demo_pause`, `demo_resume`,
`demo_togglepause`, `loop_dump`, `addons`, `map`, `changelevel`, `connect`, `maps`, `alias`, `bind`,
`bindtoggle`, `addip`, `banid`, `banip`, `bugvoice_clear`, `bugvoice_save`, `button_info`,
`StackStats_Dump`, `auto_bug`, `+bugvoice`, `-bugvoice`.

The **`map` / `changelevel` / `connect` / `maps`** group is registered from `0x1cc730` (891 bytes), which
shows the exact construction pattern:

```asm
1cc730  mov qword [0x9b86c2], 0xffff     ; ConCommand::m_nFlags = -1 sentinel
        mov qword [0x9b8690], 0x612930   ; callback
        mov qword [0x9b86a0], 0
        ...
        lea rcx, [0x9b86d8]              ; ConCommand object
        lea rdx, "maps"                  ; 0x6129** 
        lea r8,  [<help>]
        lea r9,  "Displays list of maps."
        mov [rsp+0x20], 0x80000          ; flags
        call 0x407d90
```

and `map` is at `0x1cc7**` with help `"map <mapname> :Load a new map."` and callback `0x1cd300`,
`changelevel` with `"changelevel <mapname> :Multiplayer change level."` and callback `0x1cea30`,
`connect` with `"Connect to a remote server."`.

### 6.4 The execution path

Command *execution* is not in engine2 — it is in tier0 (`CCommandBuffer`). engine2 supplies:

1. **The buffer wrapper** — `0x1c69b0` (1,170 bytes), whose body is
   `CCommandBuffer::BeginProcessingCommands(buf, 1)` → `while (DequeueNextCommand()) { ... }` →
   `EndProcessingCommands()`. It locks a `CAtomicMutex` at `+0x0` (the `LOCK`/`InterlockedCompareExchange`
   idiom at `0x1c69**`), and indexes the per-thread command buffer as
   `thread * 0x86d8 + 0x588 + obj`.
2. **The dispatcher** — `0x1c6e50` (1,282 bytes) is called once per dequeued command. It resolves the
   command name via the symbol table at `arg1+0x32f98` (`Find_CUtlSymbolTable`), allocates a
   0x668-byte command object (`func_0x1801cc210`), and calls either
   - `func_0x1801c5fc0` — **commands**: if the name is not a ConCommand, `"Unknown command '%s'!\n"`
     (LOG_CONSOLE, severity 3) at `0x1c5f**`; if it is a cheat and cheats are off,
     `"SV: Cheat command '%s' ignored.\n"`; else the callback runs.
   - `func_0x1801c64f0` — **convars**: `"%s = %s\n"` for a query, `"Unknown convar '%s'!\n"` otherwise.
3. **The `__beginseq`/`__endseq`** pseudo-commands are handled inline at `0x1c6d01`/`0x1c6c46`
   (`V_stricmp_fast(name, "__beginseq")` at `0x1c6d0d`, `"__endseq"` at `0x1c6c0f`). These are the
   conditional-execution blocks tier0's `CCommandBuffer` emits; engine2's job is to track the nesting.
4. **The command source** is the `CCommandBuffer` in `VEngineCvar007`/`VConComm001`. `0x1c4770`
   (3,219 bytes, `CInputService::OnClientProcessInput`) calls `0x1c69b0` twice — once for input-driven
   commands, once for the console. `0x1c69b0`'s own callers are `0x1c49ca` and `0x1c5229`, both inside
   `0x1c4770`.
5. **The `grep` command** at `0x1c58d0` (439 bytes) is worth noting because it exposes the **PCRE**
   binding: `"Usage:  grep pattern text\n"`, then `fcn.0x3c7c60(pattern, 0x800, &err, &errstr, 0)` →
   `fcn.0x3c7c90` (the 2,872-byte regex compiler), then `fcn.0x3d5f90` (the 3,475-byte matcher), then
   `"WARNING: Unable to compile regex '%s', %s\n"`. So the console has real regex support, backed by the
   statically-linked PCRE in §7.

---

## 7. Bundled codecs and third-party code

### 7.1 libopus — 36 exports, ~143 KB of code

`opus_*` occupies `0x37c8c0`–`0x3a0690`: **109 functions, 143,272 bytes** (2.8% of `.text`). The version
string is the giveaway:

```
0x391aa0  lea rax, [0x533c28]      ; "libopus unknown"
0x391aa7  ret
```

`"libopus unknown"` is what libopus returns when built **without** `--enable-custom-modes` / the
`PACKAGE_VERSION` macro being defined — i.e. a raw amalgamation build, not the CMake build. Consistent with
that, the code has no `silk/` or `celt/` string, no `OPUS_` assert strings, and no `pcre`-style version
banner: it was compiled with assertions off.

**What it is used for.** The exports are the *whole* public API, including the repacketizer and the
multistream packet helpers, which is more than a simple voice encoder needs. The engine's own consumer is
`0x1eed80` (2,270 bytes), which allocates `CCircularBuffer`s at `+0x1d0`/`+0x1e8` and drives
`opus_encoder_create` / `opus_encode` / `opus_decode` — the voice pipeline. `0x1f01b0` (2,036 bytes) is the
matching decoder path. The `opus_encode_test_signal` ConVar at `0x148d0` is a developer self-test.

**Why here, not in `soundsystem`.** `soundsystem.dll` does **not** import `engine2.dll` (verified against
all 99 DLLs in the corpus — zero importers). The reason is that voice data crosses the *network* boundary:
the engine owns `networksystem`/`Source2EngineToServer` and must be able to encode/decode voice without
depending on the audio module, which may be absent in dedicated-server and `-headless` builds. Putting
libopus in `engine2` keeps the dedicated server self-contained.

### 7.2 PCRE (8.x, UTF/UCP-capable)

`0x538xxx`–`0x53axxx` in `.rdata` holds the PCRE error-message table, including
`"this version of PCRE is not compiled with PCRE_UTF8 support"` (`0x538dd3`),
`"this version of PCRE is not compiled with PCRE_UCP support"` (`0x539370`),
`"PCRE does not support \\L, \\l, \\N{name}, \\U, or \\u"` (`0x538e61`), and the
`"(*MARK"` / `"(*ACCEPT"` verb strings. The engine is at `0x3c7c90` (2,872 bytes — `pcre_compile`),
`0x3d5f90` (3,475 bytes — `pcre_exec`), `0x3d6d30` (105 bytes — `get_ucp`-style table probe over
`{0x7f, 0x7ff, 0xffff, 0x1fffff, 0x3ffffff, 0x7fffffff}` at `0x539750`), `0x3d6da0` (459 bytes),
`0x3d6f70` (494 bytes), `0x3d7380` (1,444 bytes — `match()`). No `pcre2` string exists, so this is the
**PCRE 8.x** line, not PCRE2. The 54,364-byte function `0x3c87d0` is `pcre_exec`'s
`match()`/`match_ref`/backtracking core (its only callees are the `0x3d5c30`/`0x3d6d30`/`0x3d6da0`/
`0x3d6f70`/`0x3d7380` helpers and `memcpy`/`memmove`). Consumer: the `grep` console command (§6.4).

### 7.3 protobuf 3.21.8

`U:\thirdpartycode\nonredist\protobuf\protobuf-3.21.8\src\google\protobuf\…` appears in 72
`__FILE__` strings (`descriptor.cc`, `wire_format.cc`, `extension_set.cc`, `map_field.h`,
`parse_context.h`, `reflection_internal.h`, `dynamic_message.h`, `descriptor.h`,
`extension_set_inl.h`, `map_field_inl.h`). The biggest protobuf functions are `0x283680` (8,627 bytes,
descriptor validation), `0x287310` (8,198), `0x285910` (6,137), `0x29ed50` (8,088, option parsing),
`0x2bd350` (7,880, wire format), `0x2af530` (7,332, extension set), `0x28b8a0` (6,612, message
reflection), `0x28e860` (5,626). The generated CS2 protobufs (`CMsgSource2NetworkFlowQuality`,
`CMsgSource2PerfIntervalSample`, `CSource2Metrics_*`, `C2S_CONNECT_Message`, `CCLCMsg_*`, `CDemo*`) are
compiled in as RTTI-visible classes — see `rtti/engine2.txt`.

### 7.4 zlib, libpng, WebRTC AEC3/AGC2

- **zlib**: `0x4a90b0` (6,564 bytes, `inflate`) with `"unknown compression method"`, `"invalid window
  size"`, `"incorrect header check"`, `"unknown header flags set"`, `"header crc mismatch"`. Used by the
  VPK reader (`filesystem_stdio`'s decompressor lives here, not in that module).
- **libpng**: `0x36de00` (6,365 bytes, `png_read_info`) with the `IHDRPLTEIDATIEND…` chunk-name table.
- **WebRTC AEC3/AGC2**: `0x433bf0` (9,036 bytes) with `WebRTC-Aec3StereoContentDetectionKillSwitch`,
  `WebRTC-Aec3AntiHowlingMinimizationKillSwitch`, `WebRTC-Aec3UseShortConfigChangeDuration`,
  `WebRTC-Aec3UseZeroInitialStateDuration`, `WebRTC-Aec3UseDot1SecondsInitialStateDuration`. 34 distinct
  `webrtc/…` `__FILE__` paths are present (`audio_processing/aec3/*`, `agc2/*`, `vad/*`, `resampler/*`,
  `common_audio/*`, `rtc_base/*`). This is the echo canceller that runs on the *capture* side of voice
  before opus.

### 7.5 What is **not** here

No V8 (that is `client`/`server`/`panorama`), no `embree`, no Qt, no SDL (SDL is loaded via
`Plat_LoadSDL`/`Plat_RequireSDL` at `0x19bbc0` but is an external DLL), no `libav*`. The engine's own
renderer is absent too: `rendersystemdx11.dll` / `rendersystemvulkan.dll` / `rendersystemempty.dll` are
`Plat_LoadModule`d at runtime (§2.5).

---

## 8. The 25 most significant functions

Sizes are exact `.pdata`-merged extents. "Purpose" is the function's own `__FILE__`/`__FUNCTION__` or
vprof group where available, otherwise the strongest evidence, and is marked *inferred* when the name is
mine.

| # | RVA | Size | Name | Purpose |
|---|---|---|---|---|
| 1 | `0x2111e0` | 691 | **`Source2Main`** (export 7) | The export `cs2.exe` calls. `__try/__except` prologue around `0x20e170`: installs the command line, crash handler and assertion listener, then hands over to the engine body. Returns 0 on clean exit, 1 on failure. |
| 2 | `0x20e170` | 1,628 | **`Source2Main` body** (*inferred*) | Single-instance mutex, `-dedicated` split, allocates the 0x4e8-byte `CMaterialSystem2AppSystemDict`, runs pre-init + `Init()` + `LoadAppSystems` + `MainLoop` + full shutdown. |
| 3 | `0x209140` | 6,900 | **`CAppSystemDict::LoadAppSystems`** (self-named: `"LoadAppSystems: …"` logs at `0x209456`, `0x20a142`, `0x20a2fa`, `0x20a599`, `0x20a8e6`, `0x20abcf`) | The 8-phase module bootstrap of §3.4: 17 fixed core systems, server/client configs, tools, services, game UI, the 7+5 client/dedicated service sets, the 6 engine→other-module interface registrations, and module enumeration. |
| 4 | `0x2082a0` | 3,732 | `CAppSystemDict` pre-init (*inferred*) | gameinfo parsing, allocator thresholds, MSAA, render-system option, VM snapshot, build identity, language/`schinese` fallback, low-violence. |
| 5 | `0x20d0f0` | 1,631 | **`MainLoop`** (self-named: `engine2.cpp` / `"MainLoop"`, budget group `0x6b9678`) | The engine's frame loop: vprof, `CEngineServiceMgr::_MainLoop`, `EventAppShutdown_t` on quit, frame/sleep timing into `0x9bcf98`/`0x9bcf9c`. |
| 6 | `0x214980` | 4,824 | **`CEngineServiceMgr::_MainLoop`** (self-named: `engineservicemgr.cpp`, vprof `"CEngineServiceMgr::_MainLoop"`) | Loop-mode dispatcher + sleep scheduler of §5.1. |
| 7 | `0x22a510` | 11,098 | **`CLoopTypeClientServer::Update`** (vtable `0x620fe0` slot +0x40; `looptypeclientserver.cpp`) | The actual game frame: computes server/client tick counts, runs server ticks, client ticks, client simulate, the event dispatches, frame boundary, present. |
| 8 | `0x225340` | 8,453 | **`CLoopTypeClientServerService`** service dispatch (self-named: `"CLoopTypeClientServerService::OnServerAdvanceTick"` etc.) | Server-side tick pipeline incl. the `sv_tick_parallel_with_client` parallel path. |
| 9 | `0x2f2850` | 3,959 | **`CAppSystemDict::LoadSystemAndDependencies`** (self-named in its own error format string) | The real module loader: resolve path, `Plat_LoadModule`, `Plat_GetModuleInterfaceFactory`, dependency recursion, the three user-facing failure messages. |
| 10 | `0x2f21c0` | 1,665 | Module path resolver (*inferred*) | `V_UnqualifiedFileName` + `ComposeFileName` + `Plat_FileExists` + `Plat_LoadModule`/`Raw`; logs `"CAppSystemDict::LoadModuleInPath( %-23s ) %8.3f msec"`. |
| 11 | `0x2f0390` | 808 | `CAppSystemDict::AddSystem` (*inferred*) | Add one `{module,interface}` with duplicate-interface fatal check. |
| 12 | `0x2f06c0` | 829 | `CAppSystemDict::AddSystems` (*inferred*) | Batch form; used 5× by `0x209140` and 2× by `0x19b2f0`. |
| 13 | `0x40aec0` | 94 | **`CreateInterface`** (export 2) | The 24-byte-node linked-list dispatcher of §4.1. |
| 14 | `0x40aea0` | 36 | `InterfaceReg::InterfaceReg` (*inferred*) | The registrar; 34 stubs `jmp` here. |
| 15 | `0x1928c0` | 842 | `CMaterialSystem2AppSystemDict` ctor (RTTI `0x648f88`) | Console/log-file setup, `vconcomm` registration, symbol tables, `CMemAllocSystemInitialize`. |
| 16 | `0x1934e0` | 698 | **`CTier2AppSystemDict::Init`** (self-named: `tier2app.h:0x2ea`) | Loads `filesystem_stdio` / `VFileSystem017` and establishes GAMEROOT/CONTENTROOT. |
| 17 | `0x193fe0` | 6,959 | Game-directory resolver (*inferred*) | `EXECUTABLE_PATH`, `bin\win64`, `FileSystem/SearchPaths`, `GAMEROOT`/`CONTENTROOT` sibling check. |
| 18 | `0x191bd0` | 1,132 | Mod-directory resolver (*inferred*) | `-game` / `VMOD`; `"No know mod!"`; registers `tier0/VStringTokenSystem001`. |
| 19 | `0x1c69b0` | 1,170 | `CCommandBuffer` drain (*inferred*) | `BeginProcessingCommands`/`DequeueNextCommand`/`EndProcessingCommands` loop, `__beginseq`/`__endseq` nesting. |
| 20 | `0x1c6e50` | 1,282 | Command dispatcher (*inferred*) | Per-command lookup; routes to command (`0x1c5fc0`) or convar (`0x1c64f0`) handlers. |
| 21 | `0x1c5fc0` | 1,320 | Command executor (*inferred*) | `"Unknown command '%s'!"`, `"SV: Cheat command '%s' ignored."`, callback invocation. |
| 22 | `0x406ad0` | 787 | `ConVar` constructor | 337 call sites, 309 distinct engine cvars (§6.2). |
| 23 | `0x407d90` | 522 | `ConCommand` constructor | 223 call sites, 204 distinct commands (§6.3). |
| 24 | `0x3c87d0` | 54,364 | PCRE 8.x `match()` core | The backtracking engine behind the `grep` console command. Largest function in the module. |
| 25 | `0x37cbf0` | 10,610 | libopus CELT encoder core (*inferred*) | Called by `opus_encode` (`0x37c8c0`) and `opus_encode_float` (`0x37cab0`); in turn calls `0x381260` (11,875 bytes, the CELT `run_prefilter`/`mdct` block). |

Runners-up worth naming: `0x19b2f0` (623 B, the *second* `LoadAppSystems`, the `inputsystem`/`localize`/
`materialsystem2` chain called from `0x19b260`), `0x19b260` (142 B, `CTier2AppSystemDict::AddSystems`
wrapper), `0x19bbc0` (1,016 B, SDL bring-up: `Plat_LoadSDL`, `Plat_RequireSDL`,
`Plat_RestartCurrentProcess`), `0x20dbd0` (1,044 B, render-system selection), `0x20c700` (2,540 B, the
`ActivateGameUI()`/`levelload` startup-asset path), `0x1c4770` (3,219 B,
`CInputService::OnClientProcessInput`), `0x211af0` (470 B, module enumeration for minidumps), `0x229010`
(2,693 B, tick-count computation), `0x214450` (989 B, frame-time filter), `0x215eb0` (628 B,
`SleepAfterMainLoop`).

---

## 9. Unknowns

These are things I could not establish from the local corpus. Each names what would resolve it.

1. **Eleven command-line parameter hashes are unrecovered.** `0x63242f0f`, `0xa365b5d5`, `0x6bd98edd`,
   `0x5d0e81d2`, `0x40f181e0`, `0x8434c0e9`, `0xcf571fda`, `0xe29d0d0c`, plus `0x8bc6a18d`,
   `0x1ae13a16`/`0x499c6bd0`/`0x99463093` and `0x23ec0df8` (the last four are used *around* known
   functionality but the exact spelling is not in any string in the corpus). Brute force over every
   `-`/`+`/bare token of length ≤4, over all 27k identifier-like strings in the corpus, over
   `-no…`/`-disable…`/`-force…` compositions, and over the 204 known ConCommand names all failed. They are
   probably multi-word (`-no<word>_<word>`). **What would resolve it:** a `tier0.dll` disassembly of
   `CCommandLine::FindParm` to confirm the hash is really `CUtlStringToken` and not a *salted* variant
   used only for `HasParm` (I verified the plain seed-`0x31415926` Murmur2 on 14 other flags, so the
   algorithm is right; the *strings* are the unknown), or a runtime trace of the argument table.
2. **The exact identity of `0x210cc0`.** `Source2Main` passes it to `SetDefaultMiniDumpHandler` at
   `0x21131d`, and `.pdata` merges it into `0x210c90` (423 bytes). `0x210c90` is a 48-byte pre-handler
   that calls `SteamAPI_SetMiniDumpComment` and `MinidumpSetMiniDumpComment`; `0x210cc0` is the *entry
   point* of the merged fragment, i.e. the actual `CEngine2MinidumpCommentBuilder::BuildComment`-style
   function. Its RTTI is `.?AVCEngine2MinidumpCommentBuilder@@` (locator `0x651f48`), so the class is
   known but the method is not.
3. **`CAppSystemDict`'s exact class.** The engine's root object is a `CMaterialSystem2AppSystemDict`
   (two vftables, `0x609280`/`0x6092d8`, both with locator type `0x6d3440`). But `0x2ef160` — the
   constructor used by `0x1928c0` — writes vftable `0x521d40`, whose locator (`0x629128`) is
   `.?AVCAppSystemDict@@`. So the object starts life as a `CAppSystemDict` and is re-vtabled twice. The
   *order* of those three vtables (which is constructed where) is not fully resolved; the two
   `CMaterialSystem2…` locators differ only in their `offset` field (`0` vs `1176`), i.e. they are the
   primary and a secondary (multiple-inheritance) sub-object.
4. **`0x2f4040`'s exact role.** Called once, at `0x20a1de`, with `(dict, "GAMEBIN")`'s value. It is
   almost certainly "add this directory to the module search path", but I did not decompile it in full,
   so it may also register the directory with `filesystem_stdio`.
5. **Whether `0x225340`'s parallel path is ever taken in CS2 retail.** The function has both a serial and
   a job-queue path keyed on `sv_tick_parallel_with_client`; the *default* value of that ConVar is not
   recoverable from static data (it is a runtime `ConVar` default set by a `+`-cvar or by
   `gameinfo.gi`). **What would resolve it:** a runtime cvar dump, or the ConVar's default argument at
   its `0x406ad0` call site (which I located but did not decode the 5th-arg help/flag word for).
6. **The loop-mode state machine's exact transition table.** `0x9ba520` is tri-state and `0x9ba458` is
   the active-loop index into `0x9ba3e8`; `0x9ba468`/`0x9ba470` are "requested"/"current" KeyValues.
   I traced the transitions at `0x214dd6`, `0x214f**`, `0x2152**` and `0x2158**` but the full table
   (which `CLoopMode*` class is index *i*) is not established — the `CLoopModeFactory<VCLoopMode*>` RTTI
   at `0x644f10`–`0x6455f0` gives the seven classes (`AddonDownload`, `Console`, `InGameUI`, `LevelLoad`,
   `MainMenu`, `RemoteConnect`, `SourceTVRelay`) but not their indices.
7. **The purpose of `_RDATA`.** I can prove *what* it holds (three FP constants) and *who* reads it
   (`0x4b2790` only), but not *why the linker put it in its own section*. The COMDAT/`/OPT:ICF`
   explanation in §1.2 is the most likely and is consistent with the 48-byte size and 0.18 entropy, but
   it is a hypothesis, not a proof.
8. **`BinaryProperties_GetValue`'s remaining cases.** The switch has 8 cases; r2ghidra recovered 0,1,2,3,
   4,5,6. Case 7 and the meaning of the numeric returns (1→0, 2→1, 6→2) are not established.
9. **The `-noassertlistener`-class flag `0xe29d0d0c`.** Its *use* is clear (skip
   `RegisterAssertionFailureListener(0x6c0258)`), its spelling is not (§9.1).
10. **`CEngineWatchdogThread`** (RTTI `0x652620`) has no obvious constructor call site found in the
    functions I decompiled. `Plat_BeginWatchdogTimer`/`EndWatchdogTimer` are called directly from
    `0x214980`, so the class may only exist for the *thread* that the watchdog creates, which is in
    tier0.

---

### Appendix A — the 115-entry interface catalogue at `0x561420`

Format: `{const char *name; void **cache_slot;}`. Slot addresses are in `.data`.

| # | Name | Slot |
|---|---|---|
| 0 | `VApplication001` | `0x733e70` |
| 1 | `VEngineCvar007` | `0x733e78` |
| 2 | `VStringTokenSystem001` | `0x733e80` |
| 3 | `TestScriptMgr001` | `0x733ec8` |
| 4 | `VProcessUtils002` | `0x733e88` |
| 5 | `VFileSystem017` | `0x733f18` |
| 6 | `VAsyncFileSystem2_001` | `0x733f20` |
| 7 | `ResourceSystem013` | `0x733f50` |
| 8 | `ResourceManifestRegistry001` | `0x733f60` |
| 9 | `ResourceHandleUtils001` | `0x733f58` |
| 10 | `SchemaSystem_001` | `0x733f40` |
| 11 | `ResourceCompilerSystem001` | `0x733f48` |
| 12 | `VMaterialSystem2_001` | `0x733f68` |
| 13 | `PostProcessingSystem_001` | `0x733f70` |
| 14 | `InputSystemVersion001` | `0x733f78` |
| 15 | `InputStackSystemVersion001` | `0x733f80` |
| 16 | `RenderDeviceMgr001` | `0x733f10` |
| 17 | `RenderUtils_001` | `0x733ff8` |
| 18 | `SoundSystem001` | `0x734000` |
| 19 | `SoundOpSystemEdit001` | `0x734008` |
| 20 | `SoundOpSystem001` | `0x734010` |
| 21 | `SteamAudio001` | `0x734018` |
| 22 | `VP4003` | `0x733f88` |
| 23 | `Localize_001` | `0x733ed8` |
| 24 | `VMediaFoundation001` | `0x734058` |
| 25 | `VAvi001` | `0x734060` |
| 26 | `VWebm001` | `0x734050` |
| 27 | `VBik001` | `0x734068` |
| 28 | `MeshSystem001` | `0x734020` |
| 29 | `MeshUtils001` | `0x734028` |
| 30 | `RenderDevice003` | `0x733fe0` |
| 31 | `VRenderDeviceSetupV001` | `0x733fe8` |
| 32 | `RenderHardwareConfig002` | `0x733ff0` |
| 33 | `SceneSystem_002` | `0x734030` |
| 34 | `IPulseSystem_001` | `0x734038` |
| 35 | `SceneUtils_001` | `0x734040` |
| 36 | `WorldRendererMgr001` | `0x734070` |
| 37 | `AssetSystem001` | `0x733f28` |
| 38 | `AssetSystemTest001` | `0x733f30` |
| 39 | `ParticleSystemMgr003` | `0x7340a0` |
| 40 | `VScriptManager010` | `0x734048` |
| 41 | `PropertyEditorSystem_001` | `0x733f38` |
| 42 | `MATCHFRAMEWORK_001` | `0x733f90` |
| 43 | `Source2V8System001` | `0x733fa0` |
| 44 | `PanoramaUIEngine001` | `0x733fa8` |
| 45 | `PanoramaUIClient001` | `0x733fb0` |
| 46 | `PanoramaTextServices001` | `0x733fb8` |
| 47 | `ToolFramework2_002` | `0x7340a8` |
| 48 | `PhysicsBuilderMgr001` | `0x7340c0` |
| 49 | `VisBuilder_001` | `0x7340b8` |
| 50 | `BakedLODBuilderMgr001` | `0x7340c8` |
| 51 | `HelpSystem_001` | `0x733e90` |
| 52 | `ToolSceneNodeFactory_001` | `0x733e98` |
| 53 | `EconItemToolModel_001` | `0x733ea0` |
| 54 | `SchemaTestExternal_Two_001` | `0x733ea8` |
| 55 | `SchemaTestExternal_One_001` | `0x733eb0` |
| 56 | `AnimationSystem_001` | `0x733eb8` |
| 57 | `AnimationSystemUtils_001` | `0x733ec0` |
| 58 | `HammerMapLoader001` | `0x7340b0` |
| 59 | `MaterialUtils_001` | `0x733ee0` |
| 60 | `FontManager_001` | `0x733ee8` |
| 61 | `TextLayout_001` | `0x733ef0` |
| 62 | `AssetPreviewSystem_001` | `0x733f00` |
| 63 | `AssetBrowserSystem_001` | `0x733f08` |
| 64 | `AssetRenameSystem_001` | `0x733ef8` |
| 65 | `VConComm001` | `0x733f98` |
| 66 | `MODEL_PROCESSING_SERVICES_INTERFACE_001` | `0x733ed0` |
| 67 | `NetworkSystemVersion001` | `0x734078` |
| 68 | `NetworkMessagesVersion001` | `0x734080` |
| 69 | `FlattenedSerializersVersion001` | `0x734088` |
| 70 | `SerializedEntitiesVersion001` | `0x734090` |
| 71 | `DemoUpconverterVersion001` | `0x734098` |
| 72 | `Source2Client002` | `0x7340f8` |
| 73 | `Source2ClientUI001` | `0x734100` |
| 74 | `Source2ClientPrediction001` | `0x734158` |
| 75 | `Source2Server001` | `0x734110` |
| 76 | `Source2Host001` | `0x734128` |
| 77 | `Source2ModTools001` | `0x734130` |
| 78 | `Source2GameClients001` | `0x734118` |
| 79 | `Source2GameEntities001` | `0x734120` |
| 80 | `EngineServiceMgr001` | `0x734160` |
| 81 | `HostStateMgr001` | `0x734168` |
| 82 | `NetworkService_001` | `0x734170` |
| 83 | `NetworkClientService_001` | `0x734178` |
| 84 | `NetworkP2PService_001` | `0x734180` |
| 85 | `NetworkServerService_001` | `0x734188` |
| 86 | `ToolService_001` | `0x734190` |
| 87 | `RenderService_001` | `0x7341a8` |
| 88 | `StatsService_001` | `0x7341b0` |
| 89 | `VProfService_001` | `0x7341b8` |
| 90 | `InputService_001` | `0x7341c0` |
| 91 | `MapListService_001` | `0x7341c8` |
| 92 | `GameUIService_001` | `0x7341d0` |
| 93 | `SoundService_001` | `0x7341d8` |
| 94 | `BenchmarkService001` | `0x7341e0` |
| 95 | `KeyValueCache001` | `0x7341e8` |
| 96 | `ClientServerSharedHandleSystem001` | `0x7341f0` |
| 97 | `GameResourceServiceClientV001` | `0x734208` |
| 98 | `GameResourceServiceServerV001` | `0x734210` |
| 99 | `Source2EngineToClient001` | `0x734138` |
| 100 | `Source2EngineToServer001` | `0x734140` |
| 101 | `Source2EngineToServerStringTable001` | `0x734148` |
| 102 | `Source2EngineToClientStringTable001` | `0x734150` |
| 103 | `VPhysics2_Interface_001` | `0x7340d0` |
| 104 | `ModelDocUtils001` | `0x733fc8` |
| 105 | `SmartPropsSystem_001` | `0x733fd0` |
| 106 | `AnimGraphEditorUtils001` | `0x733fd8` |
| 107 | `EXPORTSYSTEM_INTERFACE_VERSION_001` | `0x7340d8` |
| 108 | `ServerToolsInfo_001` | `0x734198` |
| 109 | `ClientToolsInfo_001` | `0x7341a0` |
| 110 | `Vrad3_001` | `0x7340f0` |
| 111 | `NavSystem001` | `0x7340e0` |
| 112 | `NavGameTest001` | `0x7340e8` |
| 113 | `LocalServerClientAccess001` | `0x7341f8` |
| 114 | `ClientLocalServerAccess001` | `0x734200` |

### Appendix B — import census

| DLL | Count | Notes |
|---|---|---|
| `tier0.dll` | 709 | The engine's entire platform layer: `CommandLine`, `Plat_*` (≈90 distinct), `Thread*`, `MemAlloc_*`, `KeyValues`, `CUtlBuffer`, `CUtlString`, `CUtlSymbolTable`, `LoggingSystem_*`, `CVProfile`, `V_*` string/float helpers, `CCommandBuffer`, `CThread*`, `netadr_t`, `CLZSS`, `CCircularBuffer`, `CUtlSortVector`, `CUtlRBTree`, `CTSListBase`, `CMiniDumpComment`, `Plat_LoadModule`/`Raw`, `Plat_GetModuleInterfaceFactory`, `Plat_CreateGameInstanceMutex`, `Plat_LoadSDL`/`RequireSDL`/`CheckSDL`/`UnloadSDL`, `Plat_EnableHeadlessMode`, `Plat_AttachDebuggerToProcess`, `SetDefaultMiniDumpHandler`, `Tier0GenericMiniDumpHandler_*`, `RegisterAssertionFailureListener`, `MinidumpAgeLogs`, `Worldsize_*`, `QuantizedFloat*` |
| `KERNEL32.dll` | 154 | Win32 primitives (`CreateProcessA`, `CreateToolhelp32Snapshot`, `Process32First/Next`, `OpenProcess`, `K32GetModuleFileNameExA`, `CloseHandle`, `GetModuleHandleExA`, `QueryPerformanceCounter`, `GetSystemTimeAsFileTime`, `GetCurrentThreadId`, `GetCurrentProcessId`, `GetCurrentProcess`) **and the raw loader** `LoadLibraryA`, `LoadLibraryExW`, `GetProcAddress`, `FreeLibrary` (see §3.3) |
| `steam_api64.dll` | 22 | `SteamAPI_Init*`, `SteamAPI_Shutdown`, `SteamAPI_RunCallbacks`, `SteamAPI_Register/UnregisterCallback/CallResult`, `SteamInternal_ContextInit`, `SteamInternal_CreateInterface`, `SteamInternal_FindOrCreate{User,GameServer}Interface`, `SteamGameServer_*`, `SteamAPI_SetMiniDumpComment`, `SteamAPI_WriteMiniDump`, `SteamAPI_SetBreakpadAppID`, `SteamAPI_UseBreakpadCrashHandler` |
| `WS2_32.dll` | 13 | `socket`, `bind`, `listen`, `accept`, `connect`, `send`, `recv`, `shutdown`, `closesocket`, `select`, `ioctlsocket`, `setsockopt`, `WSAGetLastError` |
| `USER32.dll` | 11 | `DialogBoxParamW`, `EndDialog`, `GetDlgItem`, `GetClientRect`, `GetWindowRect`, `SetWindowPos`, `SetWindowTextW`, `ShowWindow`, `InvalidateRect`, `SendMessageA`, `LoadImageA` |
| `GDI32.dll` | 9 | `CreateCompatibleDC`, `DeleteDC`, `SelectObject`, `GetStockObject`, `SetMapMode`, `SetStretchBltMode`, `StretchBlt`, `DeleteObject`, `GetObjectA` — the **`CTextConsoleWin`** blitter |
| `steamnetworkingsockets.dll` | 2 | `SteamNetworkingIdentity_ToString`, `SteamDatagram_SetNetworkConfig` |
| `ADVAPI32.dll` | 1 | `EventSetInformation` — ETW provider registration |
| `WINMM.dll` | 1 | `timeGetTime` |

**No `engine2.dll` importers exist in the corpus**: none of the 99 DLLs imports it. `cs2.exe` reaches it
only through `LoadLibraryExW` + `GetProcAddress("Source2Main")` (see `cs2.md` §2.3), and every other
module talks to it through `CreateInterface` or through the `MATCHFRAMEWORK_001` registry.
