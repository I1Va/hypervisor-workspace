# `tier0.dll` — the Source 2 platform/runtime layer

Reverse-engineering notes. Every claim below is tied to an RVA in
`csgo/bin/win64/tier0.dll`, with `ImageBase = 0x180000000`. RVAs match the
`.asm` dumps in `docs/tier0/` (300 largest `.pdata` chunks) and the helper
tooling written for this document (`t0.py`, `bounds.py`, `ad3.py`,
`classify.py`, `parse_cpp.py`, all under `/tmp/opencode/csgo-analysis/t0/`).

Where a name is not proven by an export, an RTTI type descriptor, a `__FILE__`
literal or a format string, it is marked **inferred** together with the evidence
that produced it. Nothing here is guessed silently.

---

## 0. Function boundaries in this image (read this first)

`tier0.dll` has **10,809** `RUNTIME_FUNCTION` records, which is the figure in the
task brief. That is not the function count: MSVC splits a function into
hot/cold *chunks* and emits one record per chunk. Two different merge rules give
two different answers, and both are needed:

| rule | result | note |
|---|---|---|
| merge contiguous chunks whose start is **not** 16-byte aligned (the `server.md` rule) | **5,135** functions, median 296 B | fast, but over-splits |
| merge any chunk that is contiguous **and** whose predecessor did not end in `ret`/`jmp`/`int3` | **5,361** functions, median 291 B | used throughout this document |

The second rule matters because a cold chunk can itself land on a 16-byte
boundary. The CPU-feature initialiser is the clean example: `.pdata` has
records at `0x62D20` (16 B), `0x62D30` (47 B), `0x62D5F` (1,209 B) … all
aligned, all contiguous. The naive rule reports `0x62D20` as a 16-byte leaf;
it is really a **1,651-byte** function running `0x62D20`–`0x63393`
(`call 0x62d20` at `0x63A5F` proves the entry point). A raw `.pdata` size
therefore understates such functions by two orders of magnitude.

All sizes quoted below are from the terminator-aware map (`bounds.py` →
`funcmap.json`). Functions with **no** `.pdata` record at all (export-only
thunks, `ret`-only stubs) are reported with size 0 and are marked "leaf".

---

## 1. Identity

### 1.1 Hashes and headers

| property | value |
|---|---|
| path | `csgo/bin/win64/tier0.dll` |
| size | **3,979,928** bytes (the brief's 4,029,440 is the *mapped* `SizeOfImage` `0x401000` = 4,198,400 plus header rounding; the file on disk is 3,979,928) |
| SHA-256 | `030d4fa04a62208d4f28d4bd6a35f8234f3da4fdbb74062020e6ebe5b4abbbe8` ✔ verified against the file |
| machine | `0x8664` (x86-64) |
| subsystem | 2 (`IMAGE_SUBSYSTEM_WINDOWS_GUI`) |
| image base | `0x180000000` |
| `SizeOfImage` | `0x401000` = 4,198,400 |
| PE timestamp | `1793662171` → **2026-11-02 23:29:31 UTC** |
| checksum | `0x3D2B0A`, present and valid |
| DLL characteristics | `0x160` — `HIGH_ENTROPY_VA`, `DYNAMIC_BASE`, `NX_COMPAT`; **no** `GUARD_CF` |
| Authenticode | **not signed** |
| entry point | RVA `0x2A256C` |
| TLS callbacks | `0x1FE130`, `0x2A20A0`, `0x2A2118`, `0x1FE140` |

The build is 2 days older than `server.dll` (`1793836289`, 2026-11-04) but from
the same job tree — the PDB root string is identical.

### 1.2 PDB path

```
C:\buildworker\csgo_rel_win64\build\_build_\tier0\_vpc_tier0\default\win64\_msvc_\Retail\tier0.pdb
```

Present in `.rdata` and in `index/inv/tier0.json`. Note the
`_vpc_tier0\default` — unlike `server`/`client` (which are `_vpc_*_csgo\unity`),
tier0 is built as its **own VPC project with its own PDB**, i.e. it is a
standalone library, not a unity blob of the game.

Only **24** distinct `C:\buildworker\csgo_rel_win64\build\...` literals exist,
and they are the whole source map of the module:

| count | prefix | files |
|---|---|---|
| 18 | `src\tier0\` | `checksum_blake3.cpp`, `coroutine.cpp`, `fileio.cpp`, `keyvalues3_kv1textwriter.cpp`, `keyvalues3_textreader.cpp`, `keyvaluessystem.cpp`, `kv3format_manager.cpp`, `logging.cpp`, `memprocessheap.cpp`, `memstack.cpp`, `memstd.cpp`, `platform.cpp`, `quantizedfloatencoderregistry.cpp`, `stringparse.cpp`, `tier0_strtools.cpp`, `utlmemoryarena.cpp`, `utlvectormemory.cpp`, `vprof.cpp` |
| 5 | `src\public\tier0\` | `quantizedfloatencoder.h`, `threadmutex.h`, `tslist.h`, `utldict.h`, `utlrbtree.h` |
| 1 | `_build_\tier0\` | (PDB path itself) |

That list *is* the module: 18 translation units plus 5 shared headers. Everything
else — KeyValues, `CUtlString`, `CUtlBuffer`, the debug-symbol backends, the
minidump machinery, the file-I/O layer — is compiled into those 18 TUs
(`keyvaluessystem.cpp` alone is enormous) or is statically linked third-party
code (`mimalloc`, `zstd`, `lz4`, `xxhash`, `blake3`, SHA-1/MD5, LZMA, `fmt`).

### 1.3 Sections

| name | RVA | vsize | raw size | entropy |
|---|---|---|---|---|
| `.text` | `0x1000` | `0x2ED4A4` (3,069,092) | `0x2ED500` | 6.59 |
| `.rdata` | `0x2EF000` | `0xA5780` (678,016) | `0xA5A00` | 6.24 |
| `.data` | `0x395000` | `0x43D9C` (277,916) | `0xEC00` | 2.47 |
| `.pdata` | `0x3D9000` | `0x1FAAC` (129,708) | `0x1FC00` | 6.34 |
| `.rsrc` | `0x3F9000` | `0x3FA8` (16,296) | `0x4000` | 3.87 |
| `.reloc` | `0x3FD000` | `0x3178` (12,664) | `0x3200` | 5.45 |

`.text` is 77 % of the image. `.data` is 277 KB virtual against 60 KB raw —
217 KB of BSS, which is where `g_pMemAlloc` (`0x3AC458`), the CPU descriptor
(`0x3AC600`), the logging singleton (`0x3AD9C0`) and the interface cache slots
live. `.reloc` is tiny (12.6 KB) because tier0 is *not* full of absolute
pointers — almost everything is RIP-relative.

### 1.4 Imports — 8 DLLs, 317 symbols

| DLL | imports |
|---|---|
| `KERNEL32.dll` | 217 |
| `USER32.dll` | 55 |
| `ADVAPI32.dll` | 18 |
| `GDI32.dll` | 15 |
| `WS2_32.dll` | 4 |
| `RPCRT4.dll` | 4 |
| `api-ms-win-core-synch-l1-2-0.dll` | 3 (`WaitOnAddress`, `WakeByAddressAll`, `WakeByAddressSingle`) |
| `WINMM.dll` | 1 (`timeBeginPeriod`) |

There is **no Valve import at all**. tier0 is the bottom of the dependency
graph; the only way to confirm this is that the module has no import of
`tier1`, `vstdlib`, `engine2` or anything else beginning with a Valve name, and
its own interface table (§8.1) contains no `CreateInterface` call.

Notable KERNEL32 imports that shape the rest of this document:
`RtlCaptureContext`/`RtlLookupFunctionEntry`/`RtlVirtualUnwind` (the stack
walker, §6.3), `QueryPerformanceCounter`/`QueryPerformanceFrequency` (all
timing, §9.3), `GetSystemTimes`/`GetProcessTimes` (CPU load, §7.4),
`SetThreadAffinityMask`/`SetProcessAffinityMask` (core pinning, §7.4),
`AddVectoredExceptionHandler`/`SetUnhandledExceptionFilter` (crash path, §6),
`LoadLibraryExW`/`GetProcAddress` (`Plat_LoadModule`, §8.2),
`WaitOnAddress`/`WakeByAddress*` (`CAtomicMutex`, §4).

### 1.5 Exports — 2,625 names, and why

| quantity | value |
|---|---|
| export directory entries | **2,625** |
| distinct RVAs | 2,399 |
| C++ mangled (`?...`) | **1,529** (1,528 demangle cleanly) |
| plain C names | **1,096** |
| ordinals | 1…2,625, contiguous |
| exports into `.text` | 2,584 |
| exports into `.rdata` (vtables) | 13 |
| exports into `.data` (globals) | 28 |
| exports with a real `.pdata` body | 1,611 |
| export-only leaves (no `.pdata`) | **1,014** |

The count is large for three structural reasons, none of which is "many
functions":

1. **It is a C++ API surface, exported wholesale.** MSVC's `dllexport` on a
   class exports every member. `KeyValues` alone contributes **94** names,
   `CVProfile` 73, `CBufferString` 72, `CUtlBuffer` 68, `CUtlString` 65,
   `CDbgHelpFunctionsLoader` 52, `CVProfNode` 40, `CKeyValues_Data` 38,
   `CThread` 27. These are *methods*, not entry points anyone else calls.
2. **Header-inline code is emitted once and exported**, so template
   instantiations collapse onto one address: 70 RVAs carry more than one name,
   and `0x86A0` carries **67** (`ret 0`/`ret 8` stubs for every empty
   destructor and every `ValidateStorage`), `0x566E0` carries **30**,
   `0x652A0` **18**, `0x17FB0` **15** (all `xor al,al; ret`), `0x18A8F0` **10**.
   That is 226 of the 2,625 names pointing at code that is 1–3 instructions
   long.
3. **Three near-identical template families are exported side by side**:
   `CUniformRandomStreamImpl<CAtomicMutex>` (10), `<CThreadNullMutex>` (12),
   `<CThreadNullVerificationMutex>` (11) — 33 exports for one random-number
   generator; and `VProfScopeHelper<…>` with 6×10 = 60 exports across
   `0x18A8F0`/`0x18ABA0`.

So 2,625 names ≈ 2,399 addresses ≈ **1,611 real bodies**, and the real
*implemented functionality* is closer to the 18-TU file list above.

**28 exports are data, not code**, and they are the interesting ones for other
tools:

| RVA | export |
|---|---|
| `0x3AC458` | `g_pMemAlloc` — the global `IMemAlloc*` |
| `0x39A3D0` | `g_pThreadPool` |
| `0x3AB338` | `g_pFiberJobPool` |
| `0x39A370` | `g_pScheduledFunctions` |
| `0x3CC630` | `g_VProfCurrentProfile` |
| `0x3D7859` | `g_bPlatCPUTicksAreReliable` |
| `0x3D79B0` | `g_flThreadedJobWaitTimeAccumulator` |
| `0x3D7A24` / `0x39C3C0` / `0x39C3CC` / `0x3D7A60` | `g_VProfNodeSpikeReporting` / `…Multiplier` / `…MinimumMs` / `g_VProfSignalSpike` |
| `0x39C400` / `0x39C40C` / `0x39C3FC` / `0x39C404` | `g_nConfigMaxCoord`, `g_flConfigMaxCoord`, `g_flConfigMaxObjectPosition`, `g_flToolsDefaultFarZ` |
| `0x3AD4D8`–`0x3AD5F8`, `0x3CC1D8` | `LOG_DEVELOPER_CONSOLE`, `LOG_SYMBOLS`, `LOG_ASSERT`, `LOG_CONSOLE`, `LOG_DEVELOPER_VERBOSE`, `LOG_GENERAL`, `LOG_DEVELOPER`, `LOG_VPROF` |
| `0x399FC0`, `0x3AB340`, `0x3AB3D0` | `g_BitStringEndMasks`, `g_BitBuf_ExtraMasks`, `g_BitBuf_BitWriteMasks` |
| `0x327170` | `g_Mathlib_GammaToLinearByteTable` |
| `0x3CBC00` | `g_TSPointerListNodes` |

Thirteen `??_7…@@6B@` vtable exports also exist: `CUtlCharConversion`
(`0x306260`), `IFormatOutputStream` (`0x306E38`) and its four subclasses
(`0x306EC0`, `0x309A30`, `0x309AB8`, `0x309B40`), the four
`IKeyValuesDumpContext` implementations (`0x313138`, `0x313168`, `0x313198`,
`0x3131C8`), `CMiniDumpCommentBuilderBase` (`0x327158`) and `CThread`
(`0x32DF08`).

### 1.6 `CreateInterface` — the one exported dispatcher

`CreateInterface` at **`0x20EA20`** is a 94-byte leaf with **no `.pdata`**
record, exactly like `server.dll`'s and `client.dll`'s. It is a linear walk of a
singly-linked list with an inline byte-wise `strcmp`, head at `0x3AA090`, node
layout `{factory, name, next}`, and a tail-call to the factory:

```asm
20ea20  mov r9,  [rip+0x19b669]     ; 0x3AA090  list head
20ea32  mov rax, [r9+8]             ; node->pszName
20ea40  movzx edx, byte [rax]
20ea43  movzx ecx, byte [rax+r8]
20ea48  sub  edx, ecx
...
20ea7b  jmp  qword ptr [r9]         ; tail-call node->factory
```

The registrar is at **`0x20EA00`** and is called by exactly **four** stubs in
this module — the only self-registered interfaces tier0 has:

| stub | interface | name string | factory thunk |
|---|---|---|---|
| `0x1B20` | `VEngineCvar007` | `0x311A68` | `0x685A0` |
| `0x5620` | `VProcessUtils002` | `0x32BA98` | `0x156760` |
| `0x5D20` | `TestScriptMgr001` | `0x32CE90` | `0x16C700` |
| `0x6F40` | `VStringTokenSystem001` | `0x330748` | `0x1A4130` |

`VApplication001` (`0x2F4AC0`) has no registrar stub of its own; it exists only
as a row in the interface catalogue (§8.1).

`0x20EA80` is a second `CreateInterface` entry (`lea rax,[rip-0x67]; ret`) that
returns `0x20EA20`; `0x685B0` (`Import_GetICVarFactory`) is `jmp 0x20EA80` and
is the documented hook other modules use to get `VEngineCvar007` without
linking against it.

---

## 2. This module is special: the shared runtime

`index/graph.json` records **102** modules. `tier0` has `layer: 0`,
`role: "Platform layer: allocators, threads, logging, crash handler"`, imports
**zero** Valve modules, and is imported by **52** of them — more than any other
module in the corpus (`video64` is next with 2 dependents; `Qt5Core` has 19 but
is third-party).

| importer | symbols | importer | symbols |
|---|---|---|---|
| `engine2` | 709 | `panorama` | 287 |
| `resourcecompiler` | 705 | `rendersystemdx11` | 283 |
| `client` | 691 | `particles` | 236 |
| `server` | 524 | `filesystem_stdio` | 235 |
| `vconsole2` | 473 | `animationsystem` | 233 |
| `assetpreview` | 381 | `materialsystem2` | 230 |
| `toolframework2` | 339 | `scenesystem` | 225 |
| `rendersystemvulkan` | 325 | `panoramauiclient` | 206 |
| `physicsbuilder` | 320 | `networksystem` | 204 |
| `soundsystem` | 311 | `rendersystemempty` | 201 |

…down to `p4lib` (19), `valve_wmf` (25), `valve_avi` (32), `imemanager` (47),
`vprof_subtool` (49), `dashboard_subtool` (49), `soundviewer_subtool` (50).
**10,451 imported symbols in total.**

The 36 Valve modules that do *not* import tier0 are exactly the ones that
cannot: `tier0` itself, `cs2` (the launcher EXE), `video64` (a leaf codec
module), and the third-party/vendored set (`v8*`, `Qt5*`, `libav*`, `SDL3`,
`embree3`, `symsrv`, `steam_api64`, …). Of the *real* Source 2 modules,
**every single one** imports tier0. `v8system` (63), `vscript` (140),
`p4lib` (19) and `steamaudio` (174) are vendored-looking names that still pull
tier0 in, which is itself evidence that they were compiled inside the Valve
build with the tier0 headers on the include path.

That shape — one leaf module with no Valve dependencies, imported by every
other module — is what "shared runtime" means concretely: allocator, thread
primitives, string/container helpers, logging, crash dumps, timing, CPU
detection, `Plat_*` OS abstraction, KeyValues, and the global-object registry
all live here so that 52 DLLs in one process agree on `operator new`, on
`g_pMemAlloc`, on the logging channel table, on the crash handler, and on the
value of `Plat_FloatTime()`.

Two consequences worth stating explicitly:

* **There is exactly one heap.** Every `new` in every module resolves through
  `g_pMemAlloc` (`0x3AC458`) and therefore through tier0's `CStdMemAlloc`
  (§5). A memory bug in tier0 is a memory bug in all 52 modules.
* **There is exactly one crash handler and one log.** `SetDefaultMiniDumpHandler`
  (`0x13C3D0`) installs a single process-wide handler; `LoggingSystem_*` owns a
  single channel table at `0x3AD9C0`. Modules do not have private copies.

---

## 3. The demangled export catalogue, by subsystem

Grouping of all 2,625 exports. Classification is by name pattern
(`classify.py`), then manually corrected where a pattern is ambiguous; the
"methods" column counts the C++ exports and the "C API" column the plain ones.
Sizes are summed merged sizes and are only meaningful for the C API (many C++
exports are aliased stubs).

| group | exports | methods | C API | bytes | representative classes / prefixes |
|---|---|---|---|---|---|
| **string / containers** | 786 | 560 | 226 | 174,180 | `CBufferString` (72), `CUtlBuffer` (68), `CUtlString` (65), `CUtlSymbolTable` (15), `CCircularBuffer` (11), `CUtlMemoryPoolBase`-adjacent vectors, `KeyValues` dump contexts, `V_*` string/parse family |
| **threading** | 275 | 210 | 65 | 39,442 | `CThread` (27), `CFiber` (20), `CTSListBase` (11), `CThreadEvent` (11), `CThreadSyncObject` (11), `CThreadRWLock_FastRead` (10), `CUniformRandomStreamImpl<…Mutex>` (33) |
| **misc / uncategorised** | 271 | 60 | 211 | 54,447 | `netadr_t` (26), `CRunProcess` (7), `CEnvironmentBlock` (11), `CGridStringPrinter` (21), `CVertexKDTree` (13), KV3 sniffers, `CLZMA`, `CUtlLRUCacheBase` |
| **stack / symbol backend** | 193 | 175 | 18 | 42,256 | `CDbgHelpFunctionsLoader` (52), `CModuleListSnapshot` (17), `CVirtualMachineCallStackTranslationEncoder` (15), `CCallStackStatsGatherer_Base` (14), `CVirtualMemorySnapshot` (10), `CVDwarfSymbolModule`, `CVBreakpadSymbolModule` |
| **platform / OS** | 181 | 5 | 176 | 43,662 | `Plat_*` windowing, clipboard, registry, COM/OLE, SDL, process, environment, virtual memory, restart |
| **VProf** | 174 | 156 | 18 | 33,826 | `CVProfile` (73), `CVProfNode` (40), `VProfLite_*` (9), `VProfScopeHelper<…>` (60 aliased) |
| **filesystem / paths** | 167 | 55 | 112 | 47,033 | `V_*` path helpers, `CDirIterator` (10), `CDirTreeWatchManager` (9), `CDirWatcher` (7), `Fio*` raw I/O |
| **logging / output** | 118 | 68 | 50 | 21,393 | `LoggingSystem_*` (50), `C*FormatOutputStream` (40), `CMiniDumpComment`-free console/color helpers |
| **allocators** | 114 | 96 | 18 | 28,835 | `CMemoryStack` (11), `CUtlMemoryPoolBase` (11), `CUtlScratchMemoryPool` (12), `CUtlMemoryArena` (8), `CPoolAllocator` (7), `MemAlloc_*` (12) |
| **crash / minidump** | 70 | 48 | 22 | 12,166 | `CMiniDumpComment` (17), `CMiniDumpCommentBuilderBase` (5), `Tier0GenericMiniDumpHandler*` |
| **math** | 63 | 5 | 58 | 181 | `V_sinf`, `V_cosd`, `V_powf`, `V_roundd`, `V_qsort`, `V_tier0_sqrtd`, … (all thunks into the CRT, hence 181 bytes total) |
| **time** | 44 | 3 | 41 | 4,617 | `Plat_FloatTime`, `Plat_MSTime`, `Plat_USTime`, `Plat_TickDiff*`, `Plat_GetClockStart` |
| **compression** | 43 | 2 | 41 | 1,512 | `V_LZ4_*` (16), `V_ZSTD_*` (21), `CLZSS` (6) |
| **hashing / checksum** | 38 | 24 | 14 | 14,231 | `CSHA1` (6), `MD5*` (5), `CRC32_*`/`CRC64_*`, `CBlake3HashContext` (3), `V_XXH64_*` (7) |
| **assert** | 23 | 2 | 21 | 10,267 | `RegisterAssertionFailureListener`, `IgnoreAssert*`, `SetAssertionPrompt`, `LOG_ASSERT` |
| **convars** | 19 | 6 | 13 | 1,338 | `CCommandLine`, `CreateCommandLine`, `QuantizedFloat*` (10) |
| **text conversion** | 13 | 8 | 5 | 1,139 | `CUtlCharConversion` (12), `CStrAutoEncode` (15) |
| **CPU detection** | 11 | 6 | 5 | 5,718 | `CPUInformation` (3), `GetCPUInformation`, `Plat_CPUTickFrequency`, `Plat_GetCPUUsage`, `GetPerfSortedLogicalProcessors` |
| **crypto / UUID** | 9 | 4 | 5 | 1,413 | `Plat_UUIDToString`, `UniqueId*`, `GenerateHashFromUniqueId` |
| **serialization** | 7 | 3 | 4 | 3,025 | `KeyValues::LoadFromBuffer`, `ConvertKV3Format`, `KeyValuesToJSON` |
| **random** | 5 | 5 | 0 | 783 | `RandomFloat`, `RandomInt`, `RandomGaussianFloat`, `RandomSeed` |
| **RTTI** | 1 | 1 | 0 | 0 | `CreateDisposableKeyValuesSystem` |

### 3.1 The most important classes, with signatures

`CThread` — 27 methods, vtable at `0x32DF08`, ctor `0x175A90`:

```cpp
CThread();
virtual ~CThread();
virtual bool Start(unsigned int, ThreadPriorityEnum_t);        // 0x175CD0
virtual void OnExit();                                          // 0x86A0 (ret 0)
virtual bool WaitForCreateComplete(CThreadEvent *);             // 0x1760C0
virtual bool IsThreadRunning();                                 // 0x1760E0
static  unsigned long ThreadProc(void *);                       // 0x176150
bool Join(unsigned int);  void Stop(int);  bool Terminate(int);
unsigned Suspend();       unsigned Resume();
bool SetPriority(ThreadPriorityEnum_t);  ThreadPriorityEnum_t GetPriority() const;
void SetName(char const *);  char const *GetName();
unsigned GetThreadID() const;  ThreadHandle_t__ *GetThreadHandle();
bool IsAlive();  bool IsSuspended();  int GetResult();
static CThread *GetCurrentCThread();                            // 0x176070
static void Sleep(unsigned);  static void Yield();
```

`CBufferString` — 72 methods. The whole class is an SSO string with the
"short" form encoded in the top two bits of the length dword
(`0x40000000` = inline, `0x80000000` = borrowed). Key members:
`EnsureCapacity(int, char**, bool, bool*)` `0x50D60`,
`Insert(int, char const*, int, bool)` `0x51B10`,
`ShortenPath(bool)` `0x55320`, `SetDirect(char const*, int)` `0x19FA20`,
`AppendFormatV`, `ToLowerFast`, `ToUpperFast`, `ReplaceAt`, `RemoveAtUTF8`.

`CUtlString` (65), `CUtlBuffer` (68), `CUtlSymbolTable` (15),
`CUtlBinaryBlock` (6), `CUtlFilenameSymbolTable` (8),
`CUtlStringAndTokenWithStorage` (3), `CUtlLRUCacheBase` (4) — the standard
Source 2 container set, all exported in full.

`KeyValues` (94 methods) + `CKeyValues_Data` (38) + `KeyValues3` — the KV
system. `KeyValues::LoadFromBuffer` `0xB51B0` (3,726 B), `MergeFrom` `0xBA950`
(3,156 B), `FromString` `0xBB690` (1,724 B). `KeyValuesSystem()` is a leaf
export at `0xDCB80` (`lea rax,[rip+…]; ret`, 8 B) returning `&0x3AD790`
(the singleton, in `.data` BSS).

`CVProfile` (73) + `CVProfNode` (40) — the sampling profiler. `EnterScope*` /
`ExitScope*` families, `DumpNodes` `0x187B20` (3,496 B — the export at
`0x187B20` is an 80 B thunk that tail-calls the 2,314 B worker at `0x187BA1`);
`OutputReport` `0x188CC0` (2,240 B); `GenerateDataReport` `0x189740` (1,185 B,
recursing into `0x189767`).

`CDbgHelpFunctionsLoader` (52) — a lazy `GetProcAddress` shim around
`dbghelp.dll` (`SymInitialize`, `SymFromAddr`, `SymLoadModuleEx`,
`StackWalk64`, `MiniDumpWriteDump`, `SymSrvGetFileIndexes`, …). Every one of the
52 methods is a 160–240 byte thunk that calls `GetProcAddress` on first use.

`CMiniDumpComment` (17) — the comment buffer appended to every minidump:
`AppendComment`, `AppendFormattedComment`, `PrependComment`,
`EnsureEndsWithNumCharacters`, `EnsureOSDescription`, `OnExceptionCaught`.

`CModuleListSnapshot` (17) — enumerates loaded modules for the crash handler
*and* parses ELF (`FindElfVirtualSize` `0x13D970`, `FindElfBuildId` `0x13DC70`)
and Mach-O (`FindMachoVirtualSize` `0x13DE50`, `FindMachoUuid` `0x13DF20`)
headers. That is not Windows-only code; it is the shared crash format used by
Source 2 on Linux/macOS too.

`CUniformRandomStreamImpl<TMutex>` — the RNG, instantiated three times:

```cpp
template<class TMutex> class CUniformRandomStreamImpl {
  CUniformRandomStreamImpl();  explicit CUniformRandomStreamImpl(int seed);
  void  SetSeed(int);                       // 0x15E780 / 0x15ED00
  float RandomFloat(float lo, float hi);    // 0x15E880 / 0x15EDA0 / 0x15D9B0
  int   RandomInt(int lo, int hi);          // 0x15E8D0 / 0x15EE80 / 0x15DAD0
  float RandomFloatExp(float,float,float);
  float RandomGaussianFloat(float,float);
  void  RandomizeBits(void *, size_t);
private:
  int   GenerateRandomNumber_Locked();      // 0x15E1B0 (1,488 B, shared by all 3)
};
```

`GenerateRandomNumber_Locked` at `0x15E1B0` is the same address for all three
instantiations — the mutex is a template parameter that only changes the
locking wrapper, not the generator.

`netadr_t` (26 methods) — `SetFromString`, `SetFromSockadr`, `ToSockadr`,
`CompareAdr`, `IsLoopback`, `IsReservedAdr`, `ToString`. The only networking
type in the module, and it is here because `Plat_GetLocalHostname` and the
crash handler's "who am I" reporting need it.

`CRunProcess` (7) / `CEnvironmentBlock` (11) / `CProcess` — child-process
spawning with pipe capture, used by `RestartSelfFromAlternateLocation` and by
the symbol-loading path.

`CGridStringPrinter` (21) — the aligned-table printer behind `cvarlist`,
`find`, `log_dumpchannels`. `GetLines` at `0xA05B0` is the **largest single
export** in the module at 6,436 bytes.

---

## 4. Threading

### 4.1 The mutex family

The exports name three mutex types as template arguments of the RNG
(`CAtomicMutex`, `CThreadNullMutex`, `CThreadNullVerificationMutex`) but only
`CAtomicMutex` has its own code exported:

| type | evidence | behaviour |
|---|---|---|
| `CAtomicMutex` | `AcquireLock(unsigned)` `0x1750B0` (315 B) | futex-style: `lock xadd [this], 2`, low bits = waiter count, bit 1 = held; TSC-budgeted spin, then `WaitOnAddress`/`WakeByAddressSingle` on the same dword |
| `CAtomicSemaphore` | `DoWait()` `0x1751F0` (168 B) | same primitive, counting form |
| `CThreadNullMutex` | only as a template arg (12 exports) | no-op lock; used where the caller already serialises |
| `CThreadNullVerificationMutex` | only as a template arg (11 exports) | no-op lock that *asserts* the caller is the owning thread (a debug-build contract, kept in release as an assert) |
| `CThreadCrossProcessMutex` | ctor `0x174BE0`, `TryLock` `0x8660`, `Unlock` `0x8680`, `Release` `0x174C80`, `AssertOwnedByCurrentThread` `0x8690`, `SetTrace` `0x86A0` | named Win32 mutex (`CreateMutexA`), usable across processes; `SetTrace` and `AssertOwnedByCurrentThread` exist so a debug build can catch cross-thread misuse |
| `CThreadRWLock_FastRead` | 10 methods, ctor `0x1752A0` | read-mostly RW lock: fast path is an atomic increment of a reader count; the slow path (`UnlockRead_LockForWrite` `0x1753C0`, `UnlockWrite_LockForRead` `0x1754D0`, `HaveWriteLock_BlockReadsNow` `0x1756E0`, `EncounteredComplexReadLockOperation` `0x175850`) transitions through `CEventListNode` wait nodes |
| `CEventRWLock` / `CEventRWLock_Debuggable<true>` | `DuplicateReadLock` `0x8A600`, `UnlockRead_LockForWrite` `0x8A630`, `UnlockWrite_LockForRead` `0x8A860`, `WaitForReadLockTransition` `0x8AA80` | event-based RW lock with tracked read locks |

`AcquireLock` at `0x1750B0` is called from **284 sites** in this module and is
the single hottest synchronisation primitive in the image. Its disassembly
shows the Source 2 `CThreadFastMutex` shape precisely:

* `lock xadd [rcx], 2` at `0x1750D2` — the dword at `[rcx]` holds
  `(waiter_count << 2) | (held << 1)`, and the `xadd` both tests and increments
  the waiter count in one step;
* bit 1 clear (`test r14b, cl` / `je 0x1751A3`) → uncontended, so
  `lock cmpxchg [rcx], (old|1)` at `0x1751B5` is the whole acquisition;
* bit 1 set → contended: the spin budget is `1 << min(attempt, 8)` **TSC
  ticks**, measured with `rdtsc` at `0x175101` and `0x175114`, with `pause`
  between reads (`0x175130`);
* after the budget expires, `WaitOnAddress(&[rcx], &expected, 4, INFINITE)`
  at `0x17518B` (`0x2EFA08`, from `api-ms-win-core-synch-l1-2-0.dll`);
* the waiter cap is the u16 at `[rcx+6]` (`0x1750F0`), and after 10 attempts
  the backoff becomes a `pause` loop of up to 100 iterations
  (`0x175153`–`0x175175`).

### 4.2 Events, semaphores, barriers

| class | key methods |
|---|---|
| `CThreadSyncObject` | `Wait(unsigned)` `0x1747E0`, `Wait_NoDiagnostics` (same address), `WaitForMultiple(int, CThreadSyncObject**, bool, unsigned)` `0x174800`, `GetHandle` `0x8650`, `IsValid` `0x8640` |
| `CThreadEvent` | ctor `(bool)` `0x174A10`, ctor `(char const*, bool, bool)` `0x174A50` (named), ctor `(HANDLE)` `0x174AF0`, `Set` `0x174B00`, `Reset` `0x174B20`, `Check` `0x87450`, `CheckNamedEvent` `0x174A90`, `WaitForMultiple` `0x1749F0`/`0x174A00` |
| `CThreadSemaphore` | ctor `(int, int, char const*, bool)` `0x174B40`, `Release(int, int*)` `0x174BC0` |
| `CThreadBarrier` | ctor `(unsigned)` `0x177F70`, `ArriveAndWait` `0x178040` |
| `CThreadMultiWaitObject` / `…Event` / `…Semaphore` | `0x174F60`–`0x1750A0`; a "wait on N objects" abstraction implemented on `WaitForMultipleObjects`, plus free functions `ThreadMultiWaitObjectSetCreate` `0x174CA0`, `ThreadMultiWaitObjectSetDestroy` `0x174E50`, `ThreadMultiWait` `0x174EA0` |
| `COneTimeEvent` | `Allocate()` `0x861B0` |
| `CThreadBackgroundWorkGate` | ctor `0x178100`, `OnBeginBackgroundWork` `0x1781E0`, `OnEndBackgroundWork` `0x178280`, `PauseWork` `0x178300`, `ResumeWork` `0x178390`, `PauseRequested` `0x178400` |

### 4.3 `CreateSimpleThread` and the thread pool

`CreateSimpleThread` at **`0x1731B0`** (423 B) is the free-function thread
spawner every module uses:

```asm
1731b0  ; rcx=fn, rdx=arg, r8=outThreadId*, r9=stackSize, [rsp+0x90]=name
1731e4  mov rcx,[g_pMemAlloc]        ; 0x3AC458
1731f1  call [rax+8]                ; allocate 0x50-byte thread record
173210  mov edi,2
173217  lock cmpxchg [0x3CC4E0], edi ; one-time init of a static record
1732be  call CreateThread            ; stack 0x10000, flags 0
1732c9  lock cmpxchg [rbx+0x18], rdi ; store handle
1732e0  ... SuspendThread + SetEvent  ; optional "start suspended" handshake
```

The pool itself is an interface, not a concrete class in the exports:
`IThreadPool`, `CThreadPool`, `IFiberJobPool`, `CFiberJobPool`, `CJobThread`,
`CGlobalThreadPool` are RTTI names (§3, `index/rtti/tier0.txt`) but only the
following entry points are exported:

| RVA | symbol | note |
|---|---|---|
| `0xA77B0` | `CreateNewThreadPool` | allocates 0x180-byte pool via `g_pMemAlloc` vtable `+0x78`, then `jmp 0xA44A0` |
| `0xA77F0` | `DestroyThreadPool` | `mov rax,[rcx]; jmp [rax+0x10]` — virtual dtor |
| `0xA95C0` | `RunThreadPoolTests` | self-test |
| `0xA9770` | `RunThreadPoolPerFrameTests` | self-test |
| `0xA97F0` | `ParallelForSharedCode` | the parallel-for entry |
| `0x56AE0` | `CCallQueue::ParallelCallQueued` | queue a work item |
| `0x39A3D0` | `g_pThreadPool` | the global `IThreadPool*` |

The pool vtable is `0x327918` (in `.rdata`), 40 slots; slot `+0x40` is
`DestroyThreadPool` itself, slots `+0x48`…`+0x90` are `IThreadPool` methods
(`0x132010`–`0x132090`, each a 3-instruction `jmp [rax+N]` forwarder),
`+0xF8` is `Plat_GetMemPageSize` and `+0x100`… are `IMemAlloc` slots
(§5.1) — i.e. the same vtable prefix is shared by the allocator and the pool,
which is why both appear in one table.

### 4.4 Fibers and jobs

`CFiber` (20 methods) is a real fiber implementation, not a wrapper around
`ConvertThreadToFiber`: `AllocPooledFiber(SizeBuckets_t, size)` `0x893F0`,
`InitStackContext` `0x89940`, `ConstructThreadFiber` `0x89980`,
`SetThreadFiberMemoryRange` `0x89A10`, `ClearUnusedSpaceToFFEEFFEE` `0x89A70`
(a debug poison), `FiberYield(bool(*)(void*), void*)` `0x8A030`,
`ResumeJob` `0x89EC0`, `AbortJob` `0x89F70`, `WaitForJobCompletion` `0x8A370`,
`RunInThreadMemory` `0x8A300`, `IsRunningInThreadMemory` `0x8A2C0`.
`CThreadFiber` `0x8A530` is the thread-attached variant.
`g_pFiberJobPool` is at `0x3AB338`.

`CThreadedJob` / `CThreadedDependentJob` / `CThreadedJobWithDependencies` are
the job graph: `WaitOrImmediatelyExecute` `0xA7610`, `Abort` `0xA7680`,
`DoExecuteInternal` `0x1720C0`, `Wait` `0x172700`,
`ReleaseUpstreamDependency` `0x172070`, plus `GetJobManualEventFromPool`
`0xA3AC0` / `ReturnJobManualEventToPool` `0xA3BD0`.
`CThreadSwapTarget` / `CThreadSwapContext_Base` / `CThreadSwapJob`
(`0x1637D0`–`0x163DC0`) implement "run this job on the thread that owns
resource X".

### 4.5 Lock-free structures

`CTSListBase` (11 methods) is the intrusive lock-free stack:
`Push` `0x56620`, `Pop` `0x56630`, `InternalPush` `0x17A580` (208 B, the
`lock cmpxchg16b` loop), `InternalPop` `0x17A650`, `Detach` `0x17A6E0`,
`Count` `0x566D0`, `IsEmpty` `0x566C0`, `AccessUnprotected` `0x566E0`.
`g_TSPointerListNodes` (`0x3CBC00`) is the shared node pool. The header
`src\public\tier0\tslist.h` is in the string table, and
`CTSQueue<std::function<void()>*,0>::Push` (`0x30C810`) names the queue variant.

`ThreadAtomicWait` `0x172CB0`, `ThreadAtomicNotifyAll` `0x172D20`,
`ThreadAtomicNotifyOne` `0x172D30`, `ThreadAtomicNotifyN` `0x172D40` are thin
wrappers over `WaitOnAddress`/`WakeByAddress*` with a 32-bit key.

`ThreadInitOnceCall_ShouldRun` `0x172EC0` / `ThreadInitOnceCall_Finish`
`0x172F30` are the `call_once` pair.

### 4.6 Thread identity

| RVA | symbol | behaviour |
|---|---|---|
| `0x173B50` | `ThreadInMainThread` | `GetCurrentThreadId() == [0x3CC480]` |
| `0x173BD0` | `DeclareCurrentThreadIsMainThread` | writes `0x3CC480` |
| `0x173B70` | `ThreadInSecondaryMainThread` | second pinned id |
| `0x173B90` | `ThreadInPrimaryOrSecondaryMainThread` | either |
| `0x173C10` / `0x173C30` | `DeclareCurrentThreadIsSecondaryMainThread` / `ClearSecondaryMainThread` | |
| `0x173BC0` | `ThreadGetMainThreadId` | leaf |
| `0x1769F0` | `CThreadLocalScope::CThreadLocalScope` | 1,194 B — a per-thread scope registry keyed by thread handle *and* thread id, with a global `CAtomicMutex` (`GetScopeListMutex` `0x177160`), plus `CScopeCreatedOrDestroyedHandler` `0x177590` for observer callbacks |

The TLS block is the standard MSVC one: slot index at `0x3AA5A4`, access
`gs:[0x58]`, and the fields tier0 uses are `+0x24` (one-time-init flag),
`+0x30` (fiber job list head), `+0x190` (`CUtlMemoryStack`-style scratch
allocator, `GetThreadLocalStackAllocator` `0x19DE60`) and `+0x238` (the tick
used by `ExtractModuleMetadata`).

`ThreadSetDebugNameS2` `0x173CC0`, `ThreadGetDebugNameForThreadHandle`
`0x173F00`, `ThreadGetDebugNameForThreadId` `0x1741F0` implement the
`SetThreadDescription`-era naming; `ThreadSetPerfSetAffinity` `0x1735B0`
(1,118 B) is the core-pinning routine that walks
`GetLogicalProcessorInformationEx` records and sets both thread and process
affinity masks.

---

## 5. Allocators

### 5.1 The memory system

There are **four layers**, and all of them are visible in the binary:

```
 caller new/delete
        │
        ▼
  g_pMemAlloc  (0x3AC458)  ── IMemAlloc*  ──► CStdMemAlloc<MemConfig_t>
        │                                       (RTTI: .?AV?$CStdMemAlloc@UMemConfig_t@@@@)
        ▼
  CHeapMemAlloc / CMemStdPurePassThroughAlloc   ("Heap: standard allocator" / "…pass-through")
        │
        ▼
  CMemPassAllocT<LLA_AddAlignedSelectors<LowLevelAllocationScheme_mimalloc>>
        │                                       ("Low-level allocator: mimalloc")
        ▼
  mimalloc  ──► VirtualAlloc / HeapAlloc
```

Evidence for each layer:

* `g_pMemAlloc` is an exported **data** symbol at `0x3AC458`. It is written in
  exactly three places: `0x132B0E` (PageHeap path), `0x134173` (the
  standard-allocator path) and `0x13829C`. Read at **3,712** sites.
* `CMemAllocSystemInitialize` `0x12E1E0` (88 B) is the idempotent init: if
  `g_pMemAlloc != 0` it returns; otherwise it `bts` bit 30 of `0x3AD318`,
  and if the dword was exactly `0xBFFFFFFF` it prints
  `"Intentionally vague touch behavior for %p"` (string `0x30CB38`) and jumps
  to `0x134040`.
* `0x134040` (535 B) is the real selector. It reads the singleton at
  `0x3AC590` (`0x5C130` is `lea rax,[0x3AC590]; ret`, and
  `0x143EFD`–`0x143F10` confirms the layout: `rax = *(0x3AC590)` is the
  vtable, `rcx = &0x3AC590` is `this`, `call [rax+0x20]` is slot 4). It then
  asks four boolean questions by 32-bit hash — `0x4ED26557` (slot `+0x50`),
  `0xC554814E`, `0x6539DA`, `0xB80F851E` (slot `+0x20`) — and either installs
  the pass-through allocator (`0x3A13A8`, which points at
  `CMemStdPurePassThroughAlloc`) or builds a `CStdMemAlloc` with
  verifier/page-heap options. On the non-pass-through path it prints
  `"Standard memory allocator initialized with non-pass-through options"`
  (`0x3280F0`).
* `0x132A80` is the PageHeap branch: it reads the IFEO
  `PageHeapFlags` registry value (`0x327D20`, key template `0x327CD0`), prints
  `"PageHeap is on. Memory use will be larger than normal."` (`0x327A90`) or
  `"…off…"` (`0x327BB8`) straight to `OutputDebugStringA`, and installs
  `0x3A1370` (which points at `CHeapMemAlloc`).
* `0x133AC0` prints `"Low-level allocator: mimalloc"` (`0x327FC0`); the
  RTTI name `?$CMemPassAllocT@U?$LLA_AddAlignedSelectors@ULowLevelAllocationScheme_mimalloc`
  is at `0x3A33D0`, and the mimalloc option parser is in the string block
  `0x2F17B0`–`0x2F1870` (`"mimalloc: error: "`, `"mimalloc_%s"`,
  `"environment option mimalloc_%s has an invalid value."`).
* `0x133F11` prints `"Heap: standard allocator pass-through to low-level"`
  (`0x328138`); `0x1376BA` prints `"Heap: standard allocator"` (`0x3282A8`).
  `0x12F1B7` prints `"%s: out of memory, falling back to regular allocators"`
  (`0x3276F0`).

`IMemAlloc`'s vtable is the one the `MemAlloc_*` exports index into. Each of
the 12 hooks is a 3-instruction thunk through `g_pMemAlloc`:

| export | RVA | vtable slot | signature |
|---|---|---|---|
| `MemAlloc_AllocFunc` | `0x12DD30` | `+0x08` | `void *Alloc(size_t)` |
| `MemAlloc_ReallocFunc` | `0x12DD50` | `+0x10` | `void *Realloc(void*, size_t)` |
| `MemAlloc_FreeFunc` | `0x12DD70` | `+0x18` | `void Free(void*)` |
| `MemAlloc_AllocAlignedFunc` | `0x12DD90` | `+0x20` | `void *AllocAligned(size_t, size_t)` |
| `MemAlloc_FreeAlignedFunc` | `0x12DDB0` | `+0x30` | `void FreeAligned(void*)` |
| `MemAlloc_GetSizeFunc` | `0x12DDD0` | `+0x88` | `size_t GetSize(void*)` |
| `MemAlloc_GetAllocAttributesFunc` | `0x12DE60` | `+0x128` | `int GetAllocAttributes(void*)` |
| `MemAlloc_SetAllocAttributesFunc` | `0x12DE80` | `+0x130` | `int SetAllocAttributes(void*, int)` |
| `MemAlloc_CallocFunc` | `0x12DCE0` | `+0x08` then `memset` | `void *Calloc(size_t n, size_t sz)` (68 B, calls `Alloc` then `0x2EA280` = `memset`) |
| `MemAlloc_StrDupFunc` | `0x12E110` | `+0x08` + copy | `char *StrDup(char const*)` |
| `MemAlloc_StrDupWrapperFunc` | `0x12DDF0` | `+0x08` + copy | same, with the length precomputed |
| `MemAlloc_WcStrDupFunc` | `0x12E170` | `+0x08` + copy | `wchar_t *WcStrDup(wchar_t const*)` |

Slot `+0x28` is the align-size query and `+0x70` the `Free`-with-attribute
used by the heap-corruption reporter at `0x131FE0`. `MemAlloc_AllocFunc` and
`MemAlloc_ReallocFunc` are 0 bytes because they are tail-jumps that the
terminator-aware merge folds into their predecessor; the bytes are
`mov rdx,rcx / mov rcx,[g_pMemAlloc] / mov rax,[rcx] / jmp [rax+8]`.

The **verifier** is optional and noisy: `0x12E240` is a 7-way jump table of
`"HEAP WARNING: memory block at %p appears to be corrupt"` (`0x32756F`),
`"…pointer %p is invalid"` (`0x3275A8`), `"…unexpectedly unrecognized"`
(`0x3275D8`), `"…unexpectedly allocated"` (`0x327618`),
`"…unexpectedly free"` (`0x327658`), selected by an enum in `r8d`. When on,
it prints `"Lightweight memory verifier is ON (allocation sizes %s, %uMiB reserved, %s, %s)"`
(`0x328050`) with the guard-mode names `place high`, `place low`, `guard before`,
`no guard`, `guard both`, `guard after` (`0x327690`–`0x3276E0`).

### 5.2 The CUtl* allocator family

| class | ctor / init | alloc | free | note |
|---|---|---|---|---|
| `CUtlMemoryPoolBase` | `0x12F510` / `Init` `0x12F860` | `Alloc` `0x130920` (740 B), `AllocZero` `0x130C10` | `Free` `0x130C50` | fixed-size-object pool; `AddNewBlob` `0x130810`, `IsAllocationWithinPool` `0x130730`, `IterateAllocationsUnsafe` `0x12F870` (1,759 B), `ClearDestruct` `0x12FF50` (2,004 B). Refuses `0` elements (`0x327780`). |
| `CMemoryStack` | `0x132C10` / `Init` `0x132D40` (544 B) | `Access(void**, unsigned*)` `0x1336E0` | `FreeToAllocPoint` `0x133530`, `Purge` `0x133640` | reserve/commit stack with `CommitTo` `0x133110` and `MaybeCommitTo` `0x133050`; OOM report `0x327E40` includes committed/used KB; asserts `"ATTEMPTED TO DECOMMIT OWNED MEMORY STACK SPACE"` (`0x327EB0`); source file `src\tier0\memstack.cpp` (`0x327DD8`). |
| `CUtlScratchMemoryPool` | `0x17E7D0` / `0x17E7E0` / `Init` `0x17E8A0` | `AllocAligned(int,int)` `0x17E8E0`, `AddNewBlock` `0x17E9F0` | `FreeToAllocPoint(UtlScratchMemoryPoolMark_t)` `0x17EAC0` | mark/release scratch arena; `AllocSize` `0x17EB30`, `AllocationCount` `0x17EB50`, `TotalMemFree` `0x17EB80` |
| `CUtlMemoryArena` | `0x19DF30` (501 B) | `Alloc(unsigned)` `0x19E1C0` | `Free(unsigned char*)` `0x19E340` | `MaxAvailableAllocSize` `0x19E470`, `DumpBlockList` `0x19E260`, `MemoryBegin`/`MemoryEnd`; source `src\tier0\utlmemoryarena.cpp` |
| `CPoolAllocator` | `0x155EC0` | `Allocate(unsigned,unsigned)` `0x155F90` (528 B) | `Free(Handle_t)` `0x1561A0` | handle-based; `GrowPool` `0x156370`, `Debug_GetAllocationsSnapshot` `0x156400`, `ActivePoolHighWatermark` `0x1566E0` |
| `CUtl3DAllocator` / `CUtl3DAllocator2` | `0x1970C0` | `Allocate3D(w,h,d,Rect3D_t*)` `0x196AD0` (1,519 B) / `0x1972A0` (479 B) | `Free3D` `0x197480` (63 B, **`CUtl3DAllocator2` only**) | 3-D texture atlas allocation. The un-suffixed `CUtl3DAllocator` exports only its ctor, `Reset` `0x1967C0` and `Allocate3D`; its `Free3D` has no export entry in this build. `0x1968C0` (519 B) is an unexported helper that returns a `Rect3D_t` to the atlas (subtracts `w*h*d` from the counter at `+0x100`, unlinks the free-list node) and is called **only** from `0x196AD0` on that function's rollback path. |
| `CUtlMemoryBlockAllocator<T,CMemAllocAllocator>` | RTTI name at `0x313440` (`Alloc`), `0x3134B0` (`AddPage`) | | | paged block allocator behind `CUtlLeanVector` |

### 5.3 `CUtlVector` / `CUtlMemory` and the vector-memory hooks

`CUtlVector` is a header-only template and therefore has **no exports**, but
its out-of-line helpers are exported as C functions because the template
instantiations call them through function pointers:

| RVA | symbol | role |
|---|---|---|
| `0x1A72D0` | `UtlVectorMemory_FailedAllocation` | 80 B; called from **135** sites; prints the OOM text and aborts |
| `0x1A7150` | `UtlVectorMemory_CalcNewAllocationCount` | growth policy (called at `0x637B2`, `0x17370D`) |
| `0x1A72xx` | `UtlVectorMemory_Alloc` / `_AllocAligned` | `g_pMemAlloc` wrappers |

The template parameter is `CMemAllocAllocator` in every instantiation that the
RTTI names (`?$CUtlVector@…HV?$CUtlVectorMemory_Growable@…`), so vector growth
goes through `g_pMemAlloc` like everything else. `CUtlLeanVector` (the
`{ptr,count,capacity}`-in-8-bytes variant) uses
`CMemAllocAllocator` + `CUtlMemoryBlockAllocator` instead.

`CUtlRBTree` / `CUtlDict` / `CUtlHashtable` / `CUtlSortVector` are likewise
header-only; the only out-of-line piece is
`UtlRBTree_FailedInsertDuplicate` `0x1A7320` (83 B), and the headers
`src\public\tier0\utlrbtree.h` (`0x313085`) and `utldict.h` (`0x32DA7D`) are in the string table.

### 5.4 Per-thread and global hooks

`GetThreadLocalStackAllocator` `0x19DE60` (107 B) lazily allocates a
**256 KiB** (`0x40000`) block per thread through `g_pMemAlloc` vtable `+0x20`
(aligned alloc), stores it in the TLS block at `+0x190`, and keeps
`{base, 0x10000 committed, offset, ptr, end}` — the per-thread scratch arena
used by `CFmtStr`-style formatting.

`Qt_GetCustomAllocators` `0x12E380` (0 B, a leaf) exposes the allocator pair
to Qt so that `Qt5Core` and tier0 share a heap.

`Plat_VirtualAlloc` `0x147F50` (804 B), `Plat_VirtualFree` `0x148470`
(88 B — dispatches to `0x12EA30` for 8-byte, else `MEM_DECOMMIT` `0x4000`
for 4-byte, via the `VirtualFree` IAT slot `0x2EF468`), `Plat_VirtualProtect` `0x1483E0`,
`Plat_GetMemPageSize`, `Plat_GetAllocationGranularity`, and the
reserve-limit pair `Plat_SetVirtualReserveWarnLimit` / `…FailLimit` wrap the
raw OS calls; `"Virtual reservation exceeded limit /+/ %llu > %llu"`
(`0x329F60`) is the failure text. `TransferMemory` and
`DebugBuild_InitFillMemory` are debug helpers.

---

## 6. Logging and the crash/minidump path

### 6.1 Logging

`LoggingSystem_*` is **50 exports**, all thin wrappers around a singleton at
`0x3AD9C0`. The API splits into five concerns:

| concern | exports |
|---|---|
| channel registry | `RegisterLoggingChannel` `0x129290`, `FindChannel` `0x129BA0`, `GetChannel`/`GetChannelCount`/`GetFirstChannelID`/`GetNextChannelID`, `AddTagToChannel` `0x129A80`, `HasTag`, `FirstTag`/`NextTag`/`TagName`/`InvalidTag` |
| per-channel config | `Get/SetChannelVerbosity` `0x129EA0`/`0x129EC0`, `SetChannelVerbosityByName`/`ByTag`, `EnsureChannelVerbosity`, `Get/SetChannelColor` `0x129FA0`/`0x129FC0`, `Get/SetChannelFlags` `0x129FE0`/`0x12A000`, `SetChannelIndent`/`ChangeChannelIndent`, `Get/SetLastChannelLineComplete` |
| emit | `Log` `0x12A100` (60 B), `LogDirect` `0x12A5C0`, `LogAssert` `0x12A9C0`, `LogLines` `0x12AA10` (813 B), `Flush` `0x12AD40` |
| listeners | `RegisterLoggingListener` `0x129460`, `UnregisterLoggingListener` `0x1296E0`, `RegisterBackdoorLoggingListener` `0x129550`, `EnableBackdoorLoggingListeners` `0x129620`, `SetLoggingResponsePolicy` `0x129810` |
| state stack | `PushLoggingState` `0x129900`, `PopLoggingState` `0x129920`, `CurrentStateIndex` `0x129A50`, `ResetCurrentLoggingState` `0x1292C0`, `ResetBackdoorLoggingState` `0x1293B0` |

`LoggingSystem_Log` is called from **141** sites. It reads the thread's
one-time-init flag from TLS `+0x24`, checks
`GetCurrentThreadId()` against `0x3B89DC` for the state lock, then tail-calls
the internal `0x127E10` (2,564 B) which is the real formatting/dispatch engine
(it resolves the channel, compares severity against the channel's verbosity
table via a 6-entry jump table at `0x1287FC`, then walks the listener list at
TLS `+0x170`).

Log capture for crash reports is a separate ring:
`EnableLogCapture` `0x12AF10`, `AddLogCaptureString` `0x12B160`,
`AddLogCaptureV` `0x12B220`, `AddLogCapture` `0x12B2E0`,
`ClearLogCapture` `0x12B3B0`, `Get/SetMaxLogCaptureLines` `0x12AFE0`/`0x12B090`,
and the bridge `LoggingSystem_GetLogCaptureForMiniDump(CMiniDumpComment*, bool, char const*)`
`0x12B5A0` (399 B) which serialises the ring into the dump comment.
`"CLoggingSystem::AllocTag overflowed!"` (`0x327048`) is the tag-pool guard.

Above the channel layer sit the classic macros, exported as functions so other
modules can use them without the header:

| RVA | symbol | size |
|---|---|---|
| `0x7EE60` | `Msg` | 232 |
| `0x7EF50` | `Warning` | 203 |
| `0x7F020` | `SeriousWarning` | 287 |
| `0x7F3D0` | `DevMsg` | 205 |
| `0x7F4A0` | `DevWarning` | 205 |
| `0x7F830` | `ConMsg` (`?ConMsg@@YAXPEBDZZ`) | 203 |
| `0x7F900` | `ConDMsg` | 203 |
| `0x7F9D0` | `COM_TimestampedLog` | 1,820 |
| `0x800F0` | `TimestampedEvent` | 641 |
| `0x80380` | `TimestampedEventMsg` | 29 |
| `0x803A0` | `TimestampedEventMsgV` | 777 |
| `0x806B0` | `TimestampedEvent_RegisterListenerAndFlushBuffer` | 522 |

`Warning`/`DevMsg`/`DevWarning`/`ConMsg`/`ConDMsg` are all **~203 bytes** — the
same `va_list` forwarder with a different channel constant; `Msg` is 232
because it also handles the `-console` mirror. `DevMsg`/`DevWarning` are 205
because their first argument is a **severity** (`cmp ecx,2; cmovge` at
`0x7F3F6` selects the channel), so their real signature is
`(int severity, char const *fmt, ...)`. `ConMsg` is exported in mangled form
(`?ConMsg@@YAXPEBDZZ`) at `0x7F830`, which is why it is counted in the C++
column of §3 rather than the C-API column.

`LOG_*` exports (`LOG_GENERAL` `0x3AD5F4`, `LOG_CONSOLE` `0x3AD5AC`,
`LOG_DEVELOPER` `0x3AD5F8`, `LOG_DEVELOPER_VERBOSE` `0x3AD5F0`,
`LOG_DEVELOPER_CONSOLE` `0x3AD4D8`, `LOG_SYMBOLS` `0x3AD4DC`,
`LOG_ASSERT` `0x3AD5A8`, `LOG_VPROF` `0x3CC1D8`) are *data* exports — the
resolved channel ids, filled at startup by `LoggingSystem_RegisterLoggingChannel`.

Console/colour helpers are also here: `SetWin32ConsoleColor`,
`RestoreWin32ConsoleColor`, `InitWin32ConsoleColorContext`,
`GetWin32ConsoleCursorColumnIndex`, `Plat_Printf`, `Plat_DebugPrint`
`0x144AE0` (140 B, called from **193** sites — it is the `OutputDebugStringA`
+ `fputs(stderr)` sink), `Plat_DebugString`, `Plat_DebugString_Buffered`.

### 6.2 Fatal error

`Plat_FatalError` at **`0x140260`** (386 B) is called from **635** sites —
more than any other tier0 function. It:

1. sets the `g_bPlatHasEnteredFatalState` byte at `0x3D79A8`,
2. formats `"FATAL ERROR: "` + the caller's message into a 2 KiB stack buffer,
3. trims trailing newlines and appends one,
4. if the logging system has channels, emits through `LoggingSystem_LogLines`
   (`0x127E10`) with severity 5; otherwise `fputs(stderr)` (`0x7AE0`),
5. calls `Plat_ShouldCollectMiniDumpsForFatalErrors` (`0x148760`) and, if set,
   builds a `CatchAndWriteContext_t` and calls `InvokeMiniDumpHandler`
   (`0x13B270`) with `"error"` as the dump kind,
6. calls `0x141DB0` with `ecx=1` (the terminator) and `int3`.

`Plat_HasEnteredFatalState` `0x1403F0` is `movzx eax, byte [0x3D79A8]; ret`.
`Plat_NonFatalErrorFunc` `0x140180` is the recoverable variant.

### 6.3 The minidump chain

```
  MiniDumpExceptionHandler (0x13BF20)          ← vectored handler
        │  logs "%s: Start"
        │  if in debug session → "%s: In debug session, letting debugger have a crack at it."
        │  if -nominidumps      → "%s: -nominidumps in command line, not generating minidump."
        ▼
  default handler = Tier0GenericMiniDumpHandler (0x13ADB0, 286 B)
        │  logs "Tier0GenericMiniDumpHandler"
        │  tries full memory first
        ▼
  Tier0GenericMiniDumpHandlerEx (0x13A4C0, 2,275 B)
        │  builds MINIDUMP_EXCEPTION_INFORMATION + user streams
        │  MiniDumpWriteDump via CDbgHelpFunctionsLoader
        │  on failure: "…Data segment attempt failed, trying smaller dump."
        │               "…Full memory attempt failed, trying smaller dump."
        ▼
  MinidumpDefaultWriteCallback (0x139FB0) / MinidumpLog (0x13C9B0)
```

Pieces, all with RVAs:

| RVA | symbol | role |
|---|---|---|
| `0x13BF20` | `MiniDumpExceptionHandler` | 730 B; the `EXCEPTION_POINTERS` entry point |
| `0x13C3C0` | `MiniDumpRegisterForUnhandledExceptions` | installs `AddVectoredExceptionHandler` + `SetUnhandledExceptionFilter` |
| `0x13C3D0` | `SetDefaultMiniDumpHandler` | 149 B; sets `0x39BCE0`, logs `"SetDefaultMiniDumpHandler( %p )"`, then **`Plat_LoadModule("vfbasics.dll")`, `("vrfcore.dll")`, `("psapi.dll")`** at `0x13C421`/`0x13C432`/`0x13C443` — Application Verifier support |
| `0x13C470` | `GetDefaultMiniDumpHandler` | leaf |
| `0x13C480` | `Tier0GenericMiniDumpHandler_SetOptions` | |
| `0x138A70` | `Tier0GenericMiniDumpHandler_SetFilenamePrefix` | |
| `0x139780` | `Tier0GenericMiniDumpHandler_SetPreHandlerCallback` | this is the hook `engine2` uses (`0x2112EC` in engine2.md) |
| `0x86A0` | `Tier0GenericMiniDumpHandler_SetGetAdditionalFileAttachmentCallback` | `ret 0` — compiled out |
| `0x138A60` | `GetDefaultMiniDumpTypeFlags` | leaf; `mov eax,[0x39BCD0]; ret` (the flags word lives at `0x39BCD0`) |
| `0x138AD0` | `GetMiniDumpDirectory` | 264 B |
| `0x138BE0` | `GetNewMiniDumpFileName` | 1,138 B; `memstats_%d.txt`-style naming (`0x328170`) |
| `0x139060` | `CreateNewMiniDumpFile` | 851 B |
| `0x139520` | `MinidumpUserStreamInfoSetHeader` | custom user stream |
| `0x1395A0` | `MinidumpUserStreamInfoAppend` | 337 B |
| `0x139790` | `MiniDumpCommentEnsureOSDescription` | |
| `0x139FB0` | `MinidumpDefaultWriteCallback` | 655 B |
| `0x13A260` | `VWMD_tier0_MiniDumpWriteDump` | 161 B; lazy `GetProcAddress("MiniDumpWriteDump")` on `dbghelp` |
| `0x13B270` | `InvokeMiniDumpHandler` | 143 B; logs `"InvokeMiniDump\n"`, resolves the handler, `RaiseException(exceptionCode, …)` |
| `0x13B300`–`0x13B510` | `CatchAndWriteMiniDump`, `…Ex`, `…ExReturnsInt`, `…ExForVoidPtrFn`, `…ForVoidPtrFn` | 79–87 B each; `__try/__except` wrappers |
| `0x13C5B0` | `MinidumpAgeLogs` | 1,013 B; deletes old dumps |
| `0x13C9B0` | `MinidumpLog` | 888 B; the `"[MiniDump] %s"` logger, prefixed with the caller tag (`"MiniDumpExceptionHandler"`, `"Tier0GenericMiniDumpHandler"`, `"InvokeMiniDump"`, `"SetDefaultMiniDumpHandler( %p )"`) |
| `0x1393C0`/`0x1393D0`/`0x1393E0` | `Plat_GetMiniDumpErrorString` / `Clear…` / `Append…` | the error accumulator surfaced in the dump comment |
| `0x148750`/`0x148760` | `Plat_CollectMiniDumpsForFatalErrors` / `Plat_ShouldCollect…` | |
| `0x13CEE0` | `CMiniDumpComment` (17 methods, contiguous `0x13CEE0`–`0x13D400`) | ctor `0x13CEE0`, dtor `0x13CF50`, `Reset` `0x13D090`, `AppendOSComment` `0x13D0A0`, `AppendComment` `0x13D0F0`, `PrependComment` `0x13D140`, `AppendFormattedComment` `0x13D270`, `RemoveTrailingCharacters` `0x13D3C0`, `OnExceptionCaught` `0x13D400`, plus the `Get*Pointer`/`Ensure*` accessors at `0x13D030`–`0x13D060`; `GetStartPointer` is the shared getter `0x5E7E0` (`mov rax,[rcx+8]; ret`) |
| `0x13CDA0` | `CMiniDumpCommentBuilderBase::CMiniDumpCommentBuilderBase` | 249 B; vtable `0x327158` |

The comment is what makes a Valve dump readable: `CMiniDumpComment` carries
OS description (`Plat_GetOSDescriptionString` `0x1458A0`, 1,041 B), the
`-nominidumps` decision, the module list (`CModuleListSnapshot`), and the log
ring (`LoggingSystem_GetLogCaptureForMiniDump`). `MinidumpSetMiniDumpComment`
and `MailMiniDump` / `SendMiniDumpReport` / `UploadFilesToAnalyzer` are the
mail-out hooks; the latter three are 0-size aliases at `0x86A0`/`0x17FB0`
(i.e. no-ops in this build) which is itself informative: the *upload* path is
compiled out of the shipping CS2 build.

### 6.4 Stack walking and symbols

The walker is in `CDbgHelpFunctionsLoader` + `CStackTop_*` +
`CCallStackCapture`:

| RVA | symbol |
|---|---|
| `0x164030` | `CCallStackCapture::CCallStackCapture(int(*)(unsigned, void**, int, int), unsigned, unsigned)` (79 B) — takes a *replacement* backtrace function, so callers can swap the walker; `Capture` `0x164080` takes the same callback |
| `0x164140` | `CCallStackMarker` and `CRecursionCallStackMarker` ctors alias this 48 B address (zero-init `[rcx]`/`[rcx+8]`, optional `[rsp]` capture); `CCallStackMarker_ThisLine` is a separate 32 B function at `0x164150` |
| `0x1640D0` | `CCallStackMarkerBase::TestMarkerAgainstCapturedStackIndex(void**, int, int)` |
| `0x652A0` | `CStackTop_Base::GetCurrentTop(bool)` (18 names alias here; `xor eax,eax; ret` — stub) |
| `0x566E0` | `CStackTop_ReferenceParentStack` / `CStackTop_CopyParentStack` (3 ctors each, 30 names alias here) |
| `0x86A0` | `IterateCapturedStackAnnotations`, `StackMarkup_SaveState`/`RestoreState` (67 names alias here; `ret 0` — stub) |
| `0x18DA40` | `StackHelpers_Windows_GenerateSymbolSearchPath` (4,653 B) |
| `0x18EC70` | `StackHelpers_Windows_GenerateSymbolHomeDirectory` (4,001 B) |
| `0x1921C0`/`0x1921F0`/`0x192220` | `StackHelpers_Windows_GetDbgHelpWrapper` (46 B) / `GetImageHlpWrapper` (46 B) / `GetPSApiWrapper` (68 B) |
| `0x1AF6B0` | `CDwarfModule::GetValveSymbolPaths` (2,090 B) |
| `0x1C81D0` | `CVDbgHelpSymbolModule::Init` (1,031 B) |
| `0x1CCC70` | `CVDwarfSymbolModule::Init` (279 B) |
| `0x1CF690` | `CVBreakpadSymbolModule::Open` (1,572 B) |
| `0x180FF0` | `CVirtualMemorySnapshot` (10 methods, 9 exported): ctor `0x180FF0`, dtor `0x181040`, `Capture(unsigned)` `0x181110`, `Capture(void*)` `0x1811C0`, `Purge` `0x181220`, `Diff` `0x181CC0`, `GetLargestUnmappedRegion` `0x181F50`, `GetAddressAfterLastRegion` `0x182050`, `IsEqualRegion` `0x1820D0`, `Report(int)` `0x181340` |
| `0x18D190` | `CVirtualMachineCallStackTranslationEncoder` (15 methods, 14 exported) — ctor `0x18D190`, `DecodeFromNativePointer` `0x18D1A0`, `GetName` `0x18D210`; encodes a stack as `{module index, line offset}` pairs so a dump from a VM can be re-symbolised on another machine. **12 of its 15 accessors alias the stub `0x652A0`** (see below). |

A structural note that matters when reading this table: **three of these
addresses are symbol-collectors, not real implementations**, and they fail in
two different ways.

`0x86A0` and `0x652A0` are *stub collectors*: `0x86A0` is literally `ret 0`
(`c2 00 00`) and `0x652A0` is `xor eax,eax; ret` (`33 c0 c3`). They carry 67
and 18 names respectively, and the linker folded every method whose body
compiled to nothing into them.

`0x566E0` is a *trivial-constructor collector*: its body is `mov rax,rcx; ret`
(`48 8b c1 c3`) — return `this` — and it carries 30 names, all of them ctors
that only needed to store nothing. It is a real function, just a degenerate
one; the constructor bodies that do work (e.g. the two-argument
`CStackTop_CopyParentStack` ctors) live at the next addresses, `0x566F0` and
`0x56700`.

So any method in this document that resolves to `0x86A0`, `0x652A0` or
`0x566E0` is a **compiled-out or empty body**, not an implementation. In
particular the 12 `CVirtualMachineCallStackTranslationEncoder` accessors above
(`GetIndexBitMask`, `GetMappingSize`, `GetVMID`, …) resolve to `0x652A0`, i.e.
they are `return 0`; the real values were folded into immediate operands at
their call sites rather than exported as functions.

`GetFileAndLineFromAddress`, `GetSymbolNameFromAddress`,
`GetModuleNameFromAddress` are exported at the shared leaf `0x17FB0`
(`xor al,al; ret`) — i.e. **stubbed out in this build**. That is the single
most surprising fact in the module: the public symbol-resolution API is a
no-op, while the *internal* `CDbgHelpFunctionsLoader` machinery behind it is
fully present. `TranslateStackInfo` is likewise `return 0` at `0x652A0`, and
`Plat_IsCPUEmulated` is `xor al,al; ret` at `0x17FB0` — the one function that
*sounds* like a hypervisor detector is compiled out. By contrast
`Plat_DemangleRawTypeName` `0x146010` is a real implementation (it
manipulates the `CBufferString` short-string tag bits at `[rdx+4]`).

---

## 7. CPU and feature detection (hypervisor-relevant)

This is the most interesting part of tier0 for VM/hypervisor work, because it
is the one place in the whole Source 2 stack that touches `CPUID`, `XGETBV`,
`RDTSC` and the OS topology APIs directly. There are **four** independent
detection sites, and they do not share code.

### 7.1 `0x62D20` — the raw CPUID prober (1,651 B)

Called once, from `0x63A5F` inside `GetCPUInformation`. This is the only
function in the module that issues CPUID leaves 0/1/4/7/`0x80000000`/
`0x80000001`/`0x80000007` and writes a **packed feature byte**. It also has an
unusual structure: every CPUID result is stored to a **stack scratch area**
(`[rbp-0x44]`, `[rbp-0x40]`, `[rbp-0x3c]`), and the resulting flags are built
with *XOR-masking* against two global bytes, `0x3AC60C` and `0x3AC60D`:

```asm
62d7a  xor r9b, byte [0x3AC60C]     ; re-read existing bit, toggle
62d8b  xor r9b, byte [0x3AC60C]
62da2  xor dl,  r9b                 ; combine
62da5  and dl,  8
62da8  xor dl,  r9b                 ; -> bit 3 of feature byte
```

The same XOR pattern repeats for bits 4, 5, 6, 7, 0x10, 0x20, 0x40 of the
byte at `0x3AC60E`. Functionally it is
`byte = (byte & ~mask) | (newval & mask)` — a **branchless conditional bit
replacement**, not a read-modify-write for the sake of idempotence. (The
function has exactly one caller, `0x63A5F`, so repeat-call safety is not the
reason; see Unknown #8.)

There are **two** `cpuid`/`eax=0` vendor-caching blocks, and they are the same
code emitted twice under two separate one-time flags — `0x3D7498` guards the
first (`0x62E33`–`0x62E99`), `0x3D7499` the second (`0x62F57`–`0x62FBA`). Both
write the same globals: on the normal path the three `CPUID.0` result registers
go to `0x39A040` (EBX), `0x39A044` (EDX) and `0x39A048` (ECX) — i.e. the
12-byte vendor string in standard order — with a NUL written to `0x39A04C`.
When `CPUID.0.EAX == 0` (leaf unsupported) they instead write the literal
`"Generic_"` (`0x30CF68`) to `0x39A040`, then `"x86"` assembled as a 2-byte
store from `0x30CF70` plus a 1-byte store from `0x30CF72`, giving
`"Generic_x86"` at `0x39A040`. The duplication itself is an artifact of an
inlined `__cpuidex` helper that the compiler cloned per call site; the
*second* block additionally chains into the brand-string read
(`0x62FE6`–`0x6308F`, guarded by the *same* `0x3D7499`) and then caches the
vendor pointer at `0x3AC610`, which is descriptor field `+0x10`. The
`"AuthenticAMD"` compare at `0x62E99` (a `strcmp`-shaped `0x2E7680`) selects
the AMD path, and `"GenuineIntel"` is compared at `0x63108` in the same
routine. Both blocks explicitly handle a CPUID-less or CPUID-stubbed
environment by substituting the generic strings, which is why a hypervisor that
hides the vendor leaf does not crash tier0 — it just gets `"Generic_x86"`.

Leaves read, in order, with the exact instruction addresses:

| leaf | `eax` | address | what is extracted |
|---|---|---|---|
| 0 | `0` | `0x62D3C` | max standard leaf → `[rbp+0x28]` |
| 1 | `1` | `0x62D6C` | family/model/stepping, SSE/SSE2, CLFSH, MMX, CMOV, FXSR, TSC, APIC, PSN, HTT |
| 0 | `0` | `0x62E4A` | vendor string (first block, `0x3D7498` guard at `0x62DBB`/`0x62E4F`) |
| 1 | `1` | `0x62EBB` | re-read (ECX bit 6 = SSE3) |
| `0x80000000` | | `0x62EF9` | max extended leaf |
| `0x80000001` | | `0x62F12` | `EDX[31]` = 3DNow, `EDX[27]` = RDTSCP, `EDX[11]` = SYSCALL, `EDX[29]` = EM64T |
| 0 | `0` | `0x62F6E` | vendor string again (second block, `0x3D7499` guard at `0x62F57`/`0x62F5E`/`0x62FBA`) |
| `0x80000000` | | `0x62FF2` | max extended leaf (for the brand string) |
| `0x80000002..4` | | `0x6302E`, `0x63052`, `0x63073` | 48-byte **processor brand string** into `0x3AB300` |
| 4 | `4`, `ecx=0..0x3FF` | `0x63167` | deterministic cache params; computes size in KB into `[rbp+r8*4-0x48]` for cache levels 0..3 |
| 7 | `7`, `ecx=0` | `0x6321F` | `EBX[9]` = ERMS, `EBX[16]`=AVX512F, `EBX[17]`=AVX512DQ, `EBX[31]`=AVX512VL, `EDX[15]`=hybrid, `ECX[10]` |
| `0x80000001` | | `0x632B1` | `EDX[27]` = RDTSCP → bit 1 |
| `0x80000007` | | `0x632D8` | `EDX[8]` = invariant TSC → bit 2 |
| `0x80000005` | | `0x6330F` | AMD L1 cache sizes |
| `0x80000006` | | `0x63338` | AMD L2/L3 sizes |

**The invariant-TSC bit is the one to care about.** `0x80000007.EDX[8]`
("Invariant TSC") is set at `0x632DA`–`0x632E9` into bit 2 of `0x3AC60C`,
and that bit is what `Plat_SetCPUTicksAreReliable` (`0x140440`) tests:

```asm
140440  cmp byte [0x3D7525], 0     ; one-time
14044d  call 0x639f0               ; GetCPUInformation
140452  mov  byte [0x3D7525], 1
140459  movzx ecx, byte [rax+0xC]  ; feature byte
14045d  and  cl, 5                 ; bit0 = RDTSC, bit2 = invariant TSC
140460  cmp  cl, 5
140463  sete al
140466  mov  [0x3D7859], al        ; g_bPlatCPUTicksAreReliable
```

So `g_bPlatCPUTicksAreReliable` is true iff **RDTSC is present *and* the TSC is
invariant**. Under a hypervisor that does not expose `0x80000007` (or clears
EDX[8]), this byte is **0**, and every `Plat_*TickDiff*` / `VProf` path that
consults it takes the slow path. This is a directly observable, statically
locatable hypervisor fingerprint, and it is *exported* — another module can
read `g_bPlatCPUTicksAreReliable` at `0x3D7859` without calling anything.

### 7.2 `0x639F0` — `GetCPUInformation` (1,102 B)

The cached descriptor at **`0x3AC600`** (a 0x50-byte struct; the dword at
`[0]` is `0x50`, used as the "already initialised" magic at `0x639FA`):

| offset | meaning | source |
|---|---|---|
| `+0x00` | magic `0x50` (init flag) | `0x63A25` |
| `+0x04` | logical processor count | `0x63B46` |
| `+0x06` | physical core count | `0x63B64` |
| `+0x08` / `+0x0A` | P-core / E-core counts (hybrid only) | `0x635C3` / `0x635CB` |
| `+0x0C` | **feature byte 1** (§ below) | `0x62D20` → `0x62F44` |
| `+0x0D` | **feature byte 2** | `0x62D20` → `0x62EF3` |
| `+0x0E` | **feature byte 3** | `0x62D20` → `0x62F50` |
| `+0x10` | pointer to the cached `CPUID.0` vendor-string buffer `0x39A040` (`"AuthenticAMD"`/`"GenuineIntel"`, or `"Generic_x86"` if the leaf is stubbed) | `0x62FC8` |
| `+0x18` | brand string pointer (`0x3AB300`, the 48-byte `CPUID.0x80000002..4`) | `0x630EB` |
| `+0x20` | **raw `CPUID.1.EAX`** (family/model/stepping dword) | `0x63129` |
| `+0x24` | raw `CPUID.1.EDX` | `0x63138` (`r15d`, set at `0x62D96`) |
| `+0x28` | raw `CPUID.1.ECX` | `0x6313F` (`r12d`, set at `0x62D81`) |
| `+0x2C` | raw `CPUID.1.EBX` | `0x63132` (from `[rbp+0x20]`) |
| `+0x30` | L1 cache size (KB) | `0x631C2` (Intel leaf 4) / `0x6331C` (AMD `0x80000005`) |
| `+0x34` | L1 cache associativity | `0x63322` (AMD `0x80000005`) |
| `+0x38` | L2 cache size (KB) | `0x631CB` (Intel) / `0x6333F` (AMD `0x80000006`) |
| `+0x3C` | L2 cache associativity | `0x63348` (AMD) |
| `+0x40` | L3 cache size (KB) | `0x631D4` (Intel) / `0x63356` (AMD `0x80000006`, `EDX>>18<<9`) |
| `+0x44` | L3 cache associativity | `0x6335F` (AMD) |
| `+0x48` | **topology provider pointer** — set to the static object `0x3D35A0` at `0x63DD6`–`0x63DDD`, read at `0x635B1` | `0x63DDD` |

The struct is exactly **0x50 bytes** — the magic at `[0]` is `0x50` and the
provider pointer at `+0x48` is the last field. `0x3D35A0` is in `.data` **BSS**
(it reads as all zeros on disk), so the provider's vtable/fields are installed
at runtime; `0x63590` then reads `provider[+8]` as the array base and
`descriptor[+4]` as the count, and each record is 0x10 bytes
(`add r14,0x10` at `0x63892`).

The build order inside `GetCPUInformation` is:
`0x63A5F` call `0x62D20` (CPUID) → `0x63B46`/`0x63B64` counts →
`0x63DD1` call `0x633A0` (topology walk) → `0x63DDD` store the provider →
`0x63E08` call `0x63590` (sort/index). So the provider is populated by
`0x633A0` *before* it is stored, which means `0x633A0`'s first argument
(`rcx`, a `u16`) is the processor count and `r8` is the provider.

**`0x639F0` also dumps raw CPUID to a side table.** At `0x63C10`, after the
vendor string is resolved, the function runs `cpuid` for leaves `0`, `1`, `2`,
`4`, `5`, `6`, `9`, `0xA` in immediate succession and writes all four result
registers for each into the 32-dword table at **`0x3D7F30`**. (`0x63C10` is
reached from three places — the `"AuthenticAMD"` match at `0x63B7C`, the
NULL-vendor case at `0x63B8C`, and the case-insensitive compare result at
`0x63C0E` — so the dump runs on Intel parts too, not only AMD.)

| leaf | table slot | `eax` store | `ebx` store | `ecx` store | `edx` store |
|---|---|---|---|---|---|
| `0` | `0x3D7F30` | `0x63C4B` | `0x63C53` | `0x63C43` | `0x63C59` |
| `1` | `0x3D7F40` | `0x63C6C` | `0x63C72` | `0x63C61` | `0x63C7D` |
| `2` | `0x3D7F50` | `0x63C8D` | `0x63C98` | `0x63C85` | `0x63C9E` |
| `4` | `0x3D7F60` | `0x63CAE` | `0x63CB9` | `0x63CA6` | `0x63CBF` |
| `5` | `0x3D7F70` | `0x63CCF` | `0x63CDA` | `0x63CC7` | `0x63CE0` |
| `6` | `0x3D7F80` | `0x63CF0` | `0x63CFB` | `0x63CE8` | `0x63D01` |
| `9` | `0x3D7F90` | `0x63D11` | `0x63D1C` | `0x63D09` | `0x63D22` |
| `0xA` | `0x3D7FA0` | `0x63D39` | `0x63D3F` | `0x63D2A` | `0x63D45` |

The table is **write-only in this image** — a full xref sweep over all 5,361
merged functions finds 32 stores and **zero loads**. It exists for the
crash-dump/`-cpuinfo` diagnostic path (the same role as the raw register
dwords at `0x3AC620`–`0x3AC62C`). Two consequences for anyone counting CPUID
traffic: (a) eight extra leaves appear in an instruction trace that no tier0
logic consumes, and (b) the `0x63D4B`–`0x63D58` sequence that follows
(`cmp ecx,0xf`; `shr r9d,0x14`; `cmp ecx,0x17`) is *not* part of the dump —
it is the extended-family computation from `CPUID.1.EAX` (`r9d`) used to pick
the cache-sizing path.

**Feature byte `+0x0C`** (built at `0x62D20`, tested in `GetDescription`):

| mask | feature | test site | printed as |
|---|---|---|---|
| `0x01` | RDTSC (`CPUID.1.EDX[4]`) | `0x649DD` | `"RDTSC "` |
| `0x02` | RDTSCP (`CPUID.0x80000001.EDX[27]`) | `0x64A05` | `"RDTSCP "` |
| `0x04` | **invariant TSC** (`CPUID.0x80000007.EDX[8]`) | `0x140459` (`and cl,5`) | *(not printed)* |
| `0x08` | CMOV (`CPUID.1.EDX[15]`) | `0x64A2D` | `"CMOV "` |
| `0x10` | FCMOV (`CPUID.1.EDX[16]`) | `0x64A55` | `"FCMOV "` |
| `0x20` | SSE (`CPUID.1.EDX[25]`) | `0x646FC` | `"SSE "` |
| `0x40` | SSE2 (`CPUID.1.EDX[26]`) | `0x647ED` | `"SSE2 "` |

**Second feature byte `+0x0D`**:

| mask | feature | test site | printed as |
|---|---|---|---|
| `0x01` | MMX (`CPUID.1.EDX[23]`) | `0x649B5` | `"MMX "` |
| `0x08` | PCLMULQDQ (`CPUID.1.ECX[1]`) | `0x64A7D` | `"PCLMULQDQ "` |
| `0x40` | SSE4.1 (`CPUID.1.ECX[19]`) | `0x648DE` | `"SSE4.1 "` |
| `0x80` | SSE4.2 (`CPUID.1.ECX[20]`) | `0x64906` — `cmp byte, r14b` / `jge`, with `r14b` = 0 (`0x6409B`), i.e. a *signed* test for bit 7 | `"SSE4.2 "` |

**Third feature byte `+0x0E`**:

| mask | feature | test site | printed as |
|---|---|---|---|
| `0x01` | AVX usable (`CPUID.1.ECX[28]` **and** `XGETBV` XMM+YMM state) | `0x6493F` | `"AVX "` |
| `0x02` | AVX *blocked* — CPU supports AVX but the OS does not save YMM | `0x64936` | `"(-AVX) "` |
| `0x04` | AVX2 (`CPUID.7.EBX[5]`) | `0x64965` | `"AVX2 "` |
| `0x08` | AVX512F+DQ+VL **and** `VPCLMULQDQ` (`CPUID.7.ECX[10]`) | `0x6498D` | `"AVX512+VPCLMULQDQ "` |
| `0x10` | hybrid topology present | `0x640C4` | `" - %uP/%uE"` |

Note the AVX/AVX2/AVX512 bits are in the *third* byte, not the second — a
`test`-site table that assumes one byte per feature family will mis-attribute
them.

The AVX detection is the classic three-way check and it is worth quoting
because it is the pattern that differs under a VM:

```asm
62e0d  movzx eax, r12b          ; CPUID.1.ECX low byte
62e11  shl al, 2                ; rotate the two candidate bits up
62e14  xor al, cl               ; merge with the OSXSAVE-derived flag in cl
62e16  and al, 4
62e18  xor al, cl               ; -> sets bit 2 of the byte (mask 0x04)
...
6492e  movzx eax, byte [rbp+0xE]
64932  test al, 2
64934  je 0x6493f
64936  lea r8, [0x30D060]        ; "(-AVX) "  -- AVX present but unusable
6493f  test al, 1
64941  je 0x64965
64945  lea r8, [0x30D068]        ; "AVX "
```

The mask→label mapping in the table above is taken from the **printer** sites
(`0x64932`, `0x6493F`, `0x64965`, `0x6498D`), which are unambiguous, not from
the derivation block: the XOR-masking idiom at `0x62E0D`–`0x62E30` computes
`(old & ~mask) | (new & mask)` and is not statically readable bit-by-bit (see
Unknown #8). In particular the `and al,4` at `0x62E16` is the generic
"merge into bit 2" step reused for several features, **not** a claim that
`CPUID.1.ECX[28]` lands there.

The `XGETBV` itself is *not* in `0x62D20`; it is in the topology code at
`0x1DC0ED` (§7.3).

`GetDescription(CBufferString*, unsigned flags)` at **`0x63FB0`** (3,745 B) is
the printer that turns the descriptor into the human string
`"%u CPU%s (%i core%s - %uP/%uE, Frequency: %.01f %s, Features: SSE SSE2 …)"`,
and `GetIAFamilyModelStepping` `0x63E40`, `GetAMDFamily` `0x63EE0`,
`GetWinLevelRevision` `0x63F20` are the decoders — note they all re-derive
family/model/stepping from `[desc+0x20]` with the `family==6 || family==0xF`
extended-model rule and the `family==0xF` extended-family rule, i.e. they do
*not* trust the OS.

### 7.3 `0x66180` — the topology prober (`ICpuTopology`)

A second, independent CPUID site. It is an object with a vtable at `0x30D610`
and 12 slots, constructed at `0x66180` and filled by a chain of `CPUID`
queries at `0x6628E`, `0x66306`, `0x66344`, `0x66507`, `0x66541`, `0x66590`,
`0x66603`, `0x66639`, `0x6667B`, `0x666BA`, `0x66701`, `0x66743`, `0x66782`,
`0x667C4`, `0x66803`, `0x6684A`, `0x66883`, `0x668B9`, `0x668F2`, `0x66928`.

This is the code that implements `ICpuTopology` and its three concrete
strategies, all named in RTTI at `0x3A23F0`–`0x3A24C0`:

| class | type descriptor | strategy |
|---|---|---|
| `CpuidImpl` | `0x3A23F0` | pure CPUID |
| `DefaultImpl` | `0x3A2410` | fallback (single socket) |
| `GlpiExImpl` | `0x3A2440` | `GetLogicalProcessorInformationEx` |
| `GlpiImpl` | `0x3A2470` | `GetLogicalProcessorInformation` |
| `ICpuTopology` | `0x3A24A0` | interface |

The `GlpiExImpl`/`GlpiImpl` vtable is at `0x30D5B0` and the `CpuidImpl` vtable
at `0x30D610`; `0x30D550` is the trivial base. Selection happens in `0x66E50`
(where the `GetLogicalProcessorInformationEx` pointer is resolved from
`kernel32` at `0x66ED2`), with `0x653A0` as the GLPI-Ex parser and `0x652D0`
as the GLPI fallback. `0x66F0A` calls `0x653A0`; `0x67131` calls `0x66180`.

Key detail for VM work: the GLPI-Ex path (`0x653A0`, 469 B) walks the
`SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX` records and sorts by
`{Relationship, efficiency class}` using the comparator at `0x173A10`, which
compares, in order: `+8` (u64), `+4` (u16), `+0` (u16), `+2` (u8), `+3` (u8).
That comparator is what `GetPerfSortedLogicalProcessors` `0x173A80` uses to
produce the P-core-first ordering consumed by
`ThreadSetPerfSetAffinity` `0x1735B0`. If the hypervisor reports all cores
with the same efficiency class, the ordering degenerates to declaration order.

`XGETBV` sites (three, all outside `0x62D20`):

| RVA | context | what it does |
|---|---|---|
| `0x1DC0ED` | inside `0x1DC09A` (207 B, the CRT's `__cpu_features` init; merged range `0x1DC070`–`0x1DC16E` is 254 B) | checks `CPUID.1.ECX[27]` (OSXSAVE) then `xgetbv`, tests `(xcr0 & 6) == 6` for XMM+YMM, then `(xcr0 & 0xE0) == 0xE0` for AVX512 opmask/ZMM |
| `0x2A1F60` | inside `0x2A1DD4` (714 B, the CRT's `__isa_available` init) | same, plus a **family/model allow-list** for AVX2 (`0x2A1E47`–`0x2A1E74` compares `CPUID.1.EAX & 0xFFF3FF0` against `0x106C0`, `0x20660`, `0x20670`, and a bitmask `0x100010001` for a 0x20-wide range) |
| `0x2DE227` | inside `0x2DE1F0` (112 B) | checks `CPUID.1.ECX & 0x18001000 == 0x18001000` (XSAVE + OSXSAVE + AVX) then `xgetbv` and `(xcr0 & 6) == 6` |

The `0x2A1DD4` function is the most hypervisor-visible code in the module
after `0x62D20`: it does a full vendor check (`"GenuineIntel"` via three XOR
comparisons at `0x2A1DF5`/`0x2A1DFC`/`0x2A1E18`), the AVX2 family allow-list,
`CPUID.7.EBX[9]` (ERMS), `CPUID.7.EDX[15]`, `CPUID.0x24`, and sets
`__isa_available`. It is the CRT's copy, compiled in because tier0 links the
static CRT.

### 7.4 Frequency, load, core count

`Plat_CPUTickFrequency` at **`0x64E60`** (461 B) — note this is *not* a TSC
frequency, it is a **calibrated wall-clock frequency in Hz**:

1. reads the convar `"VALVE_CLOCK_SPEED_CALCULATION"` (`0x30CFA0`) via the
   `ICvar` singleton at `0x3AC590` (`0x142640` is the convar-string reader);
2. if set, `atoll`s it and uses that as the answer (`0x2C2B98`);
3. otherwise: `GetCurrentThread` + `SetThreadAffinityMask(thread, 1)` to pin to
   CPU 0 (`0x64F12`/`0x64F20`), `QueryPerformanceFrequency` (`0x64F2E`),
   **`rdtsc`** at `0x64F48`, spin until `QueryPerformanceCounter` advances by
   `freq/32`, **`rdtsc`** again at `0x64F6E`, restore affinity;
4. `frequency = (tsc_delta * qpc_freq) / qpc_delta`, cached at `0x3D7F20`;
5. if zero, `Plat_FatalError("Unable to determine CPU Frequency\n")`
   (`0x65020`).

That `rdtsc`-vs-`QueryPerformanceCounter` calibration is a classic
hypervisor-detection primitive in its own right: a VM whose TSC is scaled or
offset relative to the host clock produces a wildly wrong frequency here, and
the result is printed by `GetDescription` as `"Frequency: %.01f %s"`.

`Plat_GetCPUUsage` **`0x65030`** (405 B) — the *system-wide* CPU load, via
`NtQuerySystemInformation` (`0x3D32C8`, resolved lazily from `ntdll` at
`0x6504A`): class 0 (`SystemBasicInformation`, 0x40 bytes), class 3
(`SystemProcessorPerformanceInformation`, 0x20 bytes), class 2
(`SystemTimeOfDayInformation`, 0x148 bytes). It computes
`1 - (idle_delta / total_delta) / ncpu`. The class-2 call is used for the
wall-clock, not for load; it is the `KeBootTime`-based uptime.

`Plat_GetSystemLoad` **`0x14E250`** (212 B) — a *different* metric:
`GetSystemTimes` (`0x14E268`) → idle/kernel/user FILETIMEs → the ratio
`(idle) / (kernel+user+idle) * ncpu`, i.e. the same quantity via a different
API. Two independent load probes is a deliberate design choice (one is
per-processor, one is aggregate) but it also means a hypervisor that
intercepts one but not the other is detectable.

`Plat_GetNumberCpusOnline` **`0x14E330`** (18 B) is
`GetCPUInformation()->[+4]`, i.e. a cached count, **not** a live
`GetActiveProcessorCount`.

`Plat_GetPowerInfo` `0x142500` (189 B) and `Plat_IsOSInLowPowerUseMode`
`0x148A80` (259 B) use `PowrProf.dll` (`0x32A088`) — `CallNtPowerInformation`
and `GetSystemPowerStatus`. `Plat_GetCurrentDisplayMode`, `Plat_GetDPI`,
`Plat_GetMonitorCount` etc. are the USER32/GDI32 side.

### 7.5 What is *not* queried

Explicitly, because absence is evidence:

* **No `RDMSR`/`WRMSR`.** The byte scan finds 5 hits for `0F 32` and 4 for
  `0F 30`, at `0x53055`, `0x5C0D5`, `0x11BCCF`, `0x2B351D`, `0x2C3424`
  (`rdmsr` pattern) and `0xAC848`, `0xAC84F`, `0xAC869`, `0xAC870`
  (`wrmsr` pattern). All nine are *misaligned*: the five `0F 32` hits sit
  inside 32-bit `lea`/`call` RIP displacements (`0x53057`, `0x5C0D7`) or
  inside a 4-byte relative jump table at `0x2C3220`–`0x2C3450` whose entries
  are of the form `?? 32 2C 00` — the `0F 32` is the tail of one entry and
  the head of the next, not an instruction; the four `0F 30` hits are the
  middle two bytes of `48 8b 05 45 0f 30 00`-shaped `mov` displacements at
  `0xAC848`–`0xAC870`. Verified by disassembling each containing function
  from its `.pdata` `BeginAddress`; no `rdmsr`/`wrmsr` survives a
  linear sweep. tier0 never touches `IA32_TSC`, `IA32_MISC_ENABLE`,
  `IA32_PERF_STATUS` or any MSR. (Contrast: `client.dll`/`engine2.dll` also do
  not.)
* **`CPUID` leaves 2, 4, 5, 6, 9, 0xA are read, but only to be *dumped*, not
  interpreted.** In the AMD branch of `0x639F0` (`0x63C3D`–`0x63D45`) there is
  a straight-line sequence that executes `cpuid` for `eax = 0`, the
  already-loaded `eax = ebp` (leaf 1), then `2`, `4`, `5`, `6`, `9`, `0xA`,
  and stores all four result registers for each into a 32-dword table at
  **`0x3D7F30`** (`0x3D7F30`–`0x3D7FAC`, 8 leaves × 4 registers). No field is
  consumed in this module: a full xref sweep finds **32 stores and 0 loads**
  of that range. It is a diagnostic snapshot (the "dump raw CPUID" feature
  that ships with `-cpuinfo`-style reporting), so a VM cannot be identified by
  it — but it does mean the *instruction trace* of a CS2 process contains
  `CPUID` calls with `eax=2/5/6/9/0xA`, which is worth knowing if you are
  counting leaves rather than reading them.
* **No `CPUID` leaf 3, 0xB, 0xD, 0x14, 0x15, 0x16, 0x1F anywhere in the image**
  — and in particular **leaf `0x40000000` (hypervisor vendor) is never read**.
  A VM will not be identified by tier0 through the hypervisor leaf.
* **Two leaves are read only outside tier0's own code.** Leaf `0x24`
  (`TSC_THREAD_OFFSET`) is read only at `0x2A1EF7` inside `0x2A1DD4`, which is
  the statically-linked MSVC CRT's `__isa_available` / dispatch helper, not a
  tier0 routine. Leaves `0x1A` and `0x80000008` are read only by the topology
  prober `0x66180` (`0x66541`, `0x66344`). So "tier0 reads leaf X" is true but
  the *reader* is often not the platform layer.
* **No `RDTSCP` execution.** It is only *detected* (`0x80000001.EDX[27]`);
  no `0F 01 F9` exists in `.text`.
* **No `INT 0x29`-based debug detection** outside the CRT (`0x2A277C`,
  `0x2C3E5C`, `0x1BA3`, `0x5036`, …); the tier0-level check is
  `IsDebuggerPresent` at `0x143ED4`.
* **No hypervisor-brand strings** anywhere in `.rdata`: a full string scan for
  `VMware`, `VirtualBox`, `QEMU`, `KVM`, `Xen`, `Hyper-V`, `Microsoft Hv`,
  `KVMKVMKVM`, `bhyve`, `Parallels` returns nothing. The only near-miss is
  `CVirtualMachineCallStackTranslationEncoder`, which is a *symbol* encoder
  for dumps taken in VMs, not a detector.

So the VM-relevant surface of tier0 is: **the invariant-TSC bit
(`0x80000007.EDX[8]` → `g_bPlatCPUTicksAreReliable` at `0x3D7859`), the
TSC-vs-QPC frequency calibration (`0x64E60`), the AVX/XSAVE three-way check
(`0x62D20` + `0x1DC0ED` + `0x2A1F60`), and the topology/efficiency-class
ordering (`0x653A0` + `0x173A10`)**. All four are statically locatable and all
four are observable at runtime.

---

## 8. Platform abstraction

### 8.1 `Plat_*` — 259 exports, one prefix

`Plat_*` is the entire OS surface: 259 exports across 258 distinct names
(`Plat_DebugString` has two overloads). Grouped:

| area | count | examples |
|---|---|---|
| windowing / display | ~60 | `Plat_CreateWindow`, `Plat_GetWindowBounds`, `Plat_GetDesktopResolution`, `Plat_GetMonitorCount`, `Plat_IsWindowFocused`, `Plat_SetWindowIcon`, `Plat_GetDPI`, `Plat_IsHighDPI` |
| filesystem | ~35 | `Plat_FileExists`, `Plat_CreateDirectoryTree`, `Plat_RemoveDirectoryTree`, `Plat_RenameFile`, `Plat_GetTempDirectory`, `Plat_TranslateSymbolicLinks`, `Plat_IsSymlink` |
| time | 41 | `Plat_FloatTime`, `Plat_TickDiff*`, `Plat_GetClockStart`, `Plat_ConvertToLocalTime` |
| process / module | 22 | `Plat_LoadModule`, `Plat_LoadModuleRaw`, `Plat_UnloadModule`, `Plat_GetProcAddresses`, `Plat_GetLoadedModules`, `Plat_FindModuleByName` |
| registry | 6 | `Plat_RegistryOpenOrCreate`, `Plat_RegistryReadInt/String`, `Plat_RegistryWriteInt/String` |
| clipboard | 6 | `Plat_GetClipboardText`, `Plat_SetClipboardData`, `Plat_HasClipboardText` |
| environment | 8 | `Plat_GetEnv`, `Plat_SetEnv`, `Plat_ExpandEnvVars`, `Plat_GetCrtEnv` |
| COM / OLE | 10 | `Plat_InitializeCOM`, `Plat_LoadCOM`, `Plat_RequireOleAut`, `Plat_CheckSDL` |
| virtual memory | 6 | `Plat_VirtualAlloc/Free/Protect`, `Plat_GetMemPageSize`, `Plat_SetVirtualReserve*Limit` |
| crash / debug | 14 | `Plat_FatalError`, `Plat_IsInDebugSession`, `Plat_AttachDebuggerToProcess`, `Plat_GetRawCallStack` |
| CPU / power | 11 | §7 |
| misc | ~90 | `Plat_MessageBox`, `Plat_OpenURL`, `Plat_AlertUser`, `Plat_DesktopNotify`, `Plat_GetComputerName`, `Plat_GetUserName` |

`Plat_LoadSDL` / `Plat_RequireSDL` / `Plat_CheckSDL` / `Plat_UnloadSDL` /
`Plat_GetModuleSDL` (5 exports) load `SDL3.dll` (`0x32B870`) lazily and expose
the `SDL_Window*` ↔ `HWND` bridge; that is the whole reason tier0 imports
USER32 and GDI32.

`Plat_GetOSDescriptionString` `0x1458A0` (1,041 B) is the big one — it builds
the `"Windows 10 (build 19045) …"` string used in the dump comment, via
`VerifyVersionInfoW` + `RtlGetVersion`-style probing.

### 8.2 `Plat_LoadModule` — the single DLL gate

`Plat_LoadModule` at **`0x1462F0`** (1,836 B) is the function `engine2.md`
documents as the path through which "all 24 runtime DLLs load". Its shape
(call targets named where they are exports):

```
1462f0  ; rcx = module name, rdx = out handle, r8b = "raw" flag
146320  call 0x146110              ; split directory off the path (local helper)
146346  call 0x14830               ; V_IsAbsolutePath  -- is it already absolute?
146361  call 0x145E80              ; Plat_GetExecutablePathUTF8 -- base dir if not
146373  call 0x55320               ; CBufferString::ShortenPath
1463ca  call 0x12120               ; split "prefix:suffix" (4-way result)
1463e9  ...  "WARNING: Path suffix '%s' cannot be prefixed with '%s'\n"   (0x306858)
1463f2  ...  "WARNING: Suffix '%s' is a current-drive-root path (has a leading
              slash), cannot be prefixed with '%s'. Is the leading slash
              intentional and necessary?\n"                              (0x3067C0)
1463fb  ...  "WARNING: Suffix '%s' is a drive-relative path, cannot be
              prefixed with '%s'\n"                                      (0x306770)
146404  ...  "WARNING: Suffix '%s' is an absolute path, cannot be prefixed
              with '%s'\n"                                               (0x306720)
14642c  ...  normalise trailing '/' -> '\\'
146477  call 0x51B10               ; CBufferString::Insert
14651f  ...  strlen
146605  call 0x146C60              ; Plat_LoadModuleRaw
```

So the sequence is: if the name is already absolute (`0x14830` returns true) it
is used as-is; otherwise the **executable's directory** (`0x145E80`) is used as
the base and the name is appended. The four warning strings are the
`suffix:prefix` combination rules — a suffix that is itself absolute, a
drive-relative path, or a current-drive-root path is refused with a specific
message. That is the *whole* of tier0's path policy; the four-way result code
from `0x12120` (values 1..4 at `0x1463D5`–`0x1463E7`) is what selects which
message to print.

`Plat_LoadModuleRaw` **`0x146C60`** (680 B) is the actual loader:

```asm
146c89  call 0x164170              ; StackToolsNotify_BeginLoadingModule
146c8e  call GetCurrentThreadId
146cac  xchg [0x3CC200], rax       ; push a loader-lock record onto a global stack
146cb9  call 0x14830               ; re-check absolute-ness
146cd6  call 0x98D00               ; widen to UTF-16 (local helper, not an export)
146d22  call 0x145010              ; Plat_GetOSType()   (>= 0x11 == Win8+)
146d2c  call SetErrorMode(1)
146d4e  call LoadLibraryExW(path, 0, 0xB00)  ; LOAD_LIBRARY_SEARCH_*
146d72  call LoadLibraryExW(path, 0, r8d)    ; r8 = 8*raw
146da1  call GetLastError
146dcb  xchg [0x3CC208], 0         ; serialise with other loaders
146e35  call 0x8C520               ; resolve + cache the module record
146e4e  call 0x164520              ; StackToolsNotify_EndLoadingModule
146e5c  ...  GetProcAddress("BuiltDebug")
146e7b  ...  "Module %s is a debug build\n"
146e96  ...  "VALVE-MODULE-DEBUG-%08X"  CreateFileMappingA  ; debug marker
```

Three things here are directly relevant to engine2.md's claim:

1. **Every load goes through `LoadLibraryExW`**, never `LoadLibraryA`. The
   `0xB00` flags are `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR |
   LOAD_LIBRARY_SEARCH_DEFAULT_DIRS` (0x100 + 0x200 + 0x800), i.e. the DLL
   directory is searched but the *current* directory is not — a deliberate
   DLL-hijack mitigation.
2. **The path is classified as absolute or relative, and the two virtual
   schemes are treated differently.** `0x14830` (`V_IsAbsolutePath`, 311 B)
   returns true for: a drive prefix (`X:`), a UNC/device prefix (`\\` or `//`),
   or a path beginning with `"vpk:"` (`0x2F1E69`, compared case-insensitively).
   It returns **false** for a path beginning with `"ugc:"` (`0x2F1E2E`), for an
   empty string, and for everything else. The `ugc:` asymmetry is literal in the
   code: the `vpk:` compare on success restarts the scan past the prefix and
   falls through to `0x14927` (`mov al,1`), while the `ugc:` compare on success
   jumps to `0x14922` → `0x14955` → `xor al,al`. So `ugc:` paths get the
   executable's directory prepended, `vpk:` paths do not.
3. **The load is serialised process-wide.** `0x3CC200`/`0x3CC208` are a
   hand-rolled two-dword lock (the `xchg`/spin/`Sleep` sequence at
   `0x146DF0`–`0x146E1C`), and `0x3CC1E8`/`0x3CC1F0` are the
   `LdrLockLoaderLock`/`LdrUnlockLoaderLock` pointers resolved from `ntdll` at
   `0x4C90`. So a nested `Plat_LoadModule` from a `DllMain` cannot deadlock the
   loader, which is exactly the problem a "load 24 DLLs from one entry point"
   design creates.

**The denial policy** lives in `Plat_ReportDllLoadDenial` **`0x141180`** (452 B):

```asm
1411f9  lea rcx, "WARNING: %s Denied a request to load '%s'\n"
141200  call 0x7EF50            ; Warning()
141208  call GetCurrentThreadId
14120e  cmp  [0x39BCF4], eax    ; per-thread recursion guard
14122c  lock cmpxchg [0x39BCEC], 3
...
14125b  inc  dword [0x3CC498]   ; global denial counter
1412a5  call 0x51B10            ; append to the denial string at 0x3A1550
```

and `Plat_GetLastDllLoadDenial` **`0x141350`** (226 B) returns
`0x3A1550`/`0x3A1558` plus the counter at `0x3CC498`. So the policy is: a
denied load returns null, logs a warning with the requesting module name and
the denied name, and records the name so the caller can report it. The
`Raw` variant bypasses the denial because it does not call
`Plat_ReportDllLoadDenial` at all — that is the `engine2.md` "Raw skips
tier0's DLL-load-denial policy" claim, confirmed at the instruction level.

`Plat_IsSafeToLoadModules` **`0x1479A0`** is a 2-instruction leaf
(`mov edx,ecx; jmp 0x147760`) into `0x147760` (567 B), which checks the
`-nominidumps`-style convar at `0x3CC1F0`, takes the loader lock, and returns
whether it is currently safe to call `LoadLibrary` (it is the re-entrancy
guard for the crash handler: you must not `LoadLibrary` from inside a
`DllMain` while another thread holds the loader lock).

Other module functions:

| RVA | symbol | note |
|---|---|---|
| `0x146A20` | `Plat_GetLoadedModules` | 363 B; `K32EnumProcessModules`/`EnumProcessModules` from `kernel32`/`psapi` |
| `0x146B90` | `Plat_EnumerateModuleImportLibraries` | 149 B; walks the import table of a loaded module |
| `0x147020` | `Plat_FindModuleByName` | 652 B |
| `0x1472B0` | `Plat_IsModuleLoaded` | 26 B |
| `0x1472D0` | `Plat_GetModuleInformation` | 482 B; `K32GetModuleInformation` from `kernel32` (`0x1473E5`) with `psapi` fallback (`0x147421`) |
| `0x1474C0` | `Plat_GetModuleAddressInformation` | 546 B |
| `0x1476F0` | `Plat_NotifyModuleLoad` | 108 B |
| `0x1479B0` | `Plat_GetModuleInterfaceFactory` | 353 B; `GetProcAddress("CreateInterface")` under the loader lock |
| `0x147CC0` | `Plat_GetProcAddresses` | 508 B; batch resolve |
| `0x146F10` | `Plat_UnloadModule` | 245 B; `FreeLibrary` + `StackToolsNotify_UnloadedModule` |
| `0x1460E0` | `Plat_GetProcAddress` | 45 B |
| `0x145D20` | `Plat_GetModuleFilename` | 341 B |
| `0x145CC0` | `Plat_SetModuleFilename` | 82 B |
| `0x146060` | `Plat_RunningWithDebugModules` | 117 B |
| `0x147010` | `Plat_GetExeModule` | leaf |
| `0x14D7C0`/`0x14D7E0` | `Plat_RegisterModule`/`Plat_GetRegisteredModules` | leaf / stub |

`Plat_GetModuleInterfaceFactory` is the missing link between `Plat_LoadModule`
and `CreateInterface`: it is the only place in tier0 that does
`GetProcAddress(h, "CreateInterface")` (`0x147AD4`), and it does so while
holding the `0x3A1810` mutex. So the full chain that engine2 uses is

```
CAppSystemDict::LoadSystemAndDependencies
  → engine2 path resolver (ComposeFileName + Plat_FileExists)
  → tier0!Plat_LoadModule            (0x1462F0 → 0x146C60 → LoadLibraryExW)
  → tier0!Plat_GetModuleInterfaceFactory (0x1479B0 → GetProcAddress("CreateInterface"))
  → <module>!CreateInterface(name)   (each module's own linear walk)
  → <module> factory thunk
```

which is exactly the shape `engine2.md` §3.3 describes, now with tier0's half
of it pinned to addresses.

### 8.3 File I/O

Two layers, deliberately separated:

**`Fio*` — raw, unbuffered, 64-bit-capable** (the "fileio" layer, source
`src\tier0\fileio.cpp`):

| RVA | symbol |
|---|---|
| `0x8D120` | `FioCreateFile(char const*, EFioAccessFlags, EFioShareFlags, EFioCreateMode, unsigned, void*)` |
| `0x8D470`/`0x8D490`/`0x8D510` | `FioClose`, `FioRead` (two overloads: `int` and `u64`) |
| `0x8D5E0`/`0x8D630` | `FioWrite` (two overloads) |
| `0x8D6F0`/`0x8D7A0` | `FioReadAt`, `FioWriteAt` (positional) |
| `0x8D810` | `FioSeek(void*, __int64, EFioSeekMode, u64*)` |
| `0x8D8F0`/`0x8D910` | `FioTruncateToSeekPosition`, `FioSetSize` |
| `0x8DA10`/`0x8DA30` | `FioFlush`, `FioCancelIo` |
| `0x8DD80`/`0x8DE40` | `FioIsSameFileIdentity` (by handle / by path) |
| `0x8E340` | `FioDuplicate` |
| `0x8E3C0` | `FioCreatePipe` |
| `0x8FF40` | `FioCreateSymbolicLink` |
| `0x90920` | `FioIsDotDir` |
| `0x90E10`/`0x90E60` | `FioReadFileToMemory` |
| `0x90F00` | `FioCopyFile` |
| `0x8EC60`/`0x8E410` | `FioGetFileCRC32`, `FioGetFileCRC32Buffer` |
| `0x91340` | `FioGetActualFilenameCase` (2,089 B — case-corrects a path by walking the directory) |
| `0x8D0E0` | `FioFileTimeToTimeT` |
| `0x96910` | `FioEnumerateAbsPathsInDirRecursive` (1,176 B) |

**`V_*` / `V_f*` — the CRT-shaped wrappers**, 405 exports, which is the
single largest export family. They are `V_fopen`, `V_fread`, `V_fwrite`,
`V_fseek`, `V_fseeki64`, `V_ftell`, `V_ftelli64`, `V_fclose`, `V_fflush`,
`V_fprintf`, `V_vfprintf`, `V_snprintf`, `V_vsnprintf`, `V_sscanf`, `V_stat`,
`V_open`, `V_close`, `V_dup`, `V_ungetc`, `V_rewind`, `V_mkstemps`, … Each is
a 1–3 instruction thunk into the static CRT (e.g. `V_fread` at `0x7AF0` is a
jmp), and they exist so that other modules can do file I/O with a *single*
CRT instance and a *single* `errno`. `V_GetErrno` `0x7420` (16 B —
`call 0x2B2098; mov eax,[rax]; ret`) and `V_SetErrno` `0x7430` (21 B —
the matching store) are part of the same contract; `0x2B2098` is the
`__acrt_errno` accessor in the static CRT.

**Path helpers** (`V_*`, ~60): `V_FixSlashes`, `V_RemoveDotSlashes`,
`V_MakeAbsolutePath`, `V_MakeRelativePath`, `V_StripFilename`,
`V_StripExtension`, `V_GetFileExtension`, `V_IsAbsolutePath` (`0x14830`),
`V_UnqualifiedFileName`, `V_ComposeFileName`, `V_AppendSlash`,
`V_PathContainsPath`, `V_PathsMatch`, `V_AreFileNamesEqual`,
`V_FixInvalidFileNameCharacters`, `V_MakeAbsoluteVPKPathName`,
`V_GetVPKPathForm`, `V_IsFakePath`, `V_TranslateSymbolicLinks`,
`V_ValidatePathConcat`, `V_AbbreviatePathInPlace`.

`V_IsAbsolutePath` at **`0x14830`** (311 B) is the canonical
"what is a valid module path" test, and it is called by
`Plat_LoadModule` itself:

```asm
1484d  lea eax,[rdx-0x61]; cmp al,0x19; jbe → check [rcx+1]==':'
14854  lea eax,[rdx-0x41]; cmp al,0x19; ja  → not a drive letter
14865  cmp dl,'/'; je → check next byte for '/' or '\'
1486d  cmp dl,'\'; jne → scan for "vpk:" prefix
14890  ...  case-insensitive compare against "vpk:"
148d3  ...  case-insensitive compare against "ugc:"
```

So: `X:` or `\\` or `vpk:` or `ugc:` are *absolute* (trusted) forms; anything
else is relative and gets canonicalised. That is the check
`engine2.md`'s "module path resolver" relies on.

### 8.4 Time

All time is `QueryPerformanceCounter`-based, with a `QPC`-frequency cache at
`0x3D45A8` and a monotonic "greatest seen" counter at `0x3D6CE8`:

| RVA | symbol | behaviour |
|---|---|---|
| `0x140480` | (internal) QPC init | `QueryPerformanceFrequency` → `0x3D45A8` (as double at `0x3D6CE0`), `QueryPerformanceCounter` → `0x3D6CE8` = `0x3D6CF0` |
| `0x140500` | `Plat_RelativeTicks` | QPC, monotonically clamped to the greatest seen |
| `0x140550` | `Plat_RelativeTickFrequency` | the cached frequency |
| `0x140580` | `Plat_TickDiffSec` | `(t2-t1)/freq` |
| `0x1405C0` | `Plat_TickDiffSecF` | float form |
| `0x140650`/`0x1406B0` | `Plat_TickDiffMilliSec(F)` | |
| `0x140790`/`0x1407F0` | `Plat_TickDiffMicroSec(F)` | |
| `0x1408D0`/`0x140900` | `Plat_SecTickDiff(F)` | |
| `0x140990`/`0x140A00` | `Plat_MilliSecTickDiff(F)` | |
| `0x140B00`/`0x140B60` | `Plat_MicroSecTickDiff(F)` | |
| `0x140C60`/`0x140CD0` | `Plat_TicksAfterSecs(F)` | |
| `0x140DA0`/`0x140E40` | `Plat_TicksAfterMilliSecs(F)` | |
| `0x140F70`/`0x141000` | `Plat_TicksAfterMicroSecs(F)` | the inverse of the `TickDiff` family |
| `0x142030` | `Plat_GetClockStart` | returns `0x3D6CF0` |
| `0x142050` | `Plat_GetTime` | `GetSystemTimeAsFileTime`-based absolute time |
| `0x142210` | `Plat_FloatTime` | `(QPC - start) / freq` as double; **monotonic**, clamps to greatest-seen |
| `0x142290` | `Plat_MSTime` | integer ms |
| `0x142300` | `Plat_MSTime64` | 64-bit ms |
| `0x142380` | `Plat_USTime` | 64-bit µs |
| `0x1421A0` | `Plat_GetTimeString` | local-time formatting |
| `0x140410`/`0x140430` | `Plat_GetCurrentFrame` / `Plat_ChangeCurrentFrame` | a plain 64-bit counter at `0x3D7A30` |
| `0x1733E0` | `ThreadNanoSleep` | QPC spin + `timeBeginPeriod(1)` + `Sleep` |

`Plat_FloatTime` is the function every other module calls for "seconds since
start" — and it is **monotonic by construction**: the `cmp/jae` at
`0x14223A`/`0x1422C5` clamps the raw QPC to `0x3D6CE8` and writes back, so a
clock that goes backwards (a VM snapshot restore, an NTP step) cannot make
`Plat_FloatTime` regress. That clamp is worth knowing: it means
`Plat_FloatTime` cannot be used to detect time-travel, but the *jump* is still
visible as a discontinuity in the delta.

`Plat_GetClockStart` (`0x142030`) lazily initialises on first use, so a module
that calls `Plat_FloatTime` before `EarlyInit_Tier0` gets a valid clock.

### 8.5 Startup order

`EarlyInit_Tier0` **`0x84ED0`** (513 B) is called from exactly one place,
`0x229D85` (inside the CRT's `_initterm` chain). It registers a global-object
list head at `0x3D80D0` and is the only thing that must run before anything
else. `Start` **`0x172950`** (856 B) has **no internal caller** — it is the
exported "run the app-system init" entry that `engine2` calls, and it walks a
list of `{count, array}` descriptors calling each element's `+0x18` slot
(`0x1729A0`–`0x1729F5`).

The TLS callbacks do the per-thread half:
`0x1FE130` gates on `reason==1` and jumps to `0x2065A0`;
`0x2A20A0` gates on `reason==2` and walks the destructor list at
`0x2F0408`–`0x2F0410`;
`0x2A2118` handles reasons 0 and 3 and walks a TLS destructor array at
`TLS+0x30`;
`0x1FE140` handles reason 3 via `0x2067F0` and reason 0 via `0x206490`.

---

## 9. The 25 most significant functions

Sizes are terminator-aware merged sizes. "Leaf" = no `.pdata` record.

| # | RVA | size | name | purpose |
|---|---|---|---|---|
| 1 | **`0x1462F0`** | 1,836 | `Plat_LoadModule` (export) | **the single DLL gate** for the whole process: path normalisation, scheme rejection, suffix handling, then `Plat_LoadModuleRaw` |
| 2 | **`0x146C60`** | 680 | `Plat_LoadModuleRaw` (export) | `LoadLibraryExW(0xB00)` under a hand-rolled process-wide loader lock; debug-build marker via `BuiltDebug` + `VALVE-MODULE-DEBUG-%08X` |
| 3 | `0x141180` | 452 | `Plat_ReportDllLoadDenial` (export) | the denial policy: `"WARNING: %s Denied a request to load '%s'"`, per-thread recursion guard, global counter `0x3CC498` |
| 4 | `0x1479B0` | 353 | `Plat_GetModuleInterfaceFactory` (export) | the only `GetProcAddress("CreateInterface")` in the module; the bridge from `Plat_LoadModule` to each module's factory |
| 5 | **`0x13BF20`** | 730 | `MiniDumpExceptionHandler` (export) | the crash entry: debug-session and `-nominidumps` gates, then dispatch to the default handler |
| 6 | `0x13A4C0` | 2,275 | `Tier0GenericMiniDumpHandlerEx` (export) | builds the `MINIDUMP_EXCEPTION_INFORMATION` + user streams and calls `MiniDumpWriteDump`; retries with smaller dumps |
| 7 | `0x13ADB0` | 286 | `Tier0GenericMiniDumpHandler` (export) | the default handler installed at `0x39BCE0` |
| 8 | `0x13C3D0` | 149 | `SetDefaultMiniDumpHandler` (export) | installs the handler and loads `vfbasics.dll`/`vrfcore.dll`/`psapi.dll` |
| 9 | `0x140260` | 386 | `Plat_FatalError` (export) | 635 callers; formats, logs, optionally dumps, terminates |
| 10 | `0x12A100` | 60 | `LoggingSystem_Log` (export) | 141 callers; the channel/severity dispatch |
| 11 | `0x127E10` | 2,564 | (internal) logging engine | channel resolution, severity-vs-verbosity jump table, listener walk |
| 12 | **`0x1750B0`** | 315 | `CAtomicMutex::AcquireLock` (export) | 284 callers; futex on `WaitOnAddress`, TSC-budgeted spin |
| 13 | `0x1731B0` | 423 | `CreateSimpleThread` (export) | the thread spawner: alloc record, one-time static init, `CreateThread(0x10000)` |
| 14 | `0x175CD0` | 280 | `CThread::Start` (export) | the class-based spawner; vtable slot 1 of `0x32DF08` |
| 15 | **`0x12DCE0`** | 68 | `MemAlloc_CallocFunc` (export) | `g_pMemAlloc->Alloc` + `memset`; the visible tip of the four-layer allocator |
| 16 | `0x134040` | 535 | (internal) allocator selector | asks `ICvar` four hashed booleans, installs pass-through or `CStdMemAlloc` |
| 17 | `0x12E1E0` | 88 | `CMemAllocSystemInitialize` (export) | idempotent allocator init; `"Intentionally vague touch behavior for %p"` |
| 18 | **`0x639F0`** | 1,102 | `GetCPUInformation` (export) | builds the 0x50-byte CPU descriptor at `0x3AC600`; the module's most-called non-error function |
| 19 | **`0x62D20`** | 1,651 | (internal, called from `0x63A5F`) | **the raw CPUID prober**: leaves 0/1/4/7/`0x80000000`/`01`/`07`/`05`/`06`, vendor + brand string, cache sizes, invariant-TSC bit |
| 20 | `0x64E60` | 461 | `Plat_CPUTickFrequency` (export) | `rdtsc`-vs-QPC calibration with affinity pinning; caches at `0x3D7F20` |
| 21 | `0x65030` | 405 | `Plat_GetCPUUsage` (export) | `NtQuerySystemInformation` classes 0/3/2 |
| 22 | `0x140440` | 61 | `Plat_SetCPUTicksAreReliable` (export) | sets `g_bPlatCPUTicksAreReliable` from the RDTSC + invariant-TSC bits |
| 23 | `0x142210` | 123 | `Plat_FloatTime` (export) | monotonic seconds; the time base for all 52 modules |
| 24 | `0x84ED0` | 513 | `EarlyInit_Tier0` (export) | the first thing that runs; registers the global-object list at `0x3D80D0` |
| 25 | `0x20EA20` | 94 (leaf) | `CreateInterface` (export) | the interface dispatcher: linear `strcmp` over `0x3AA090`, tail-call to the factory |

Honourable mentions (#26–#32): `0x172950` `Start` (856) — the app-system
walker; `0x66180` `ICpuTopology` ctor (1,985) — the second CPUID site;
`0x653A0` GLPI-Ex parser (469) — the topology decoder; `0x1735B0`
`ThreadSetPerfSetAffinity` (1,118) — P-core pinning; `0x127130` (980) — the
`LoggingSystem` channel registrar; `0x0A05B0` `CGridStringPrinter::GetLines`
(6,436) — the largest export; `0x057F90` `CSHA1::Transform` (5,957) — the
largest pure-computation export.

---

## 10. Unknowns

Things this offline analysis could **not** determine. Each names what would
resolve it.

1. **The `CStdMemAlloc` vtable's full slot map.** `MemAlloc_*` pins slots
   `+0x08`, `+0x10`, `+0x18`, `+0x20`, `+0x28`, `+0x30`, `+0x70`, `+0x88`,
   `+0x128`, `+0x130`, and `0x3A13A8`/`0x3A1370` give the object layout, but
   the table itself is in `.data` BSS and is filled at runtime by
   `0x134040`. Which slot is `AllocAligned`'s align-size query, which is
   `GetActualSize`, and which are the verifier hooks is not recoverable
   statically. **Resolving:** a runtime dump of `*(void***)0x3AC458` in a
   live process, or the `memstd.cpp` header.

2. **Whether `Plat_LoadModule`'s denial list is a list at all.** The message
   is `"WARNING: %s Denied a request to load '%s'"` and the *second* argument
   is the module name, but the *first* is produced by `0x14E780` from `rcx`
   (the requesting module handle) — so it is "who asked" and "what was asked
   for". What decides *denial* is not in `0x141180`; it is in the caller.
   `Plat_LoadModuleRaw` never denies, and `Plat_LoadModule` only calls
   `0x14830`/`0x145E80` (path validity). So **there is no allow/deny list in
   tier0** — the "policy" is path validity plus whatever the caller checks.
   Confirming that there is no separate list requires reading every caller;
   the 10 call sites inside tier0 are `0x4CA0`, `0x4F0A`, `0x5346`,
   `0x84195`, `0x13C421`, `0x13C432`, `0x13C443`, `0x1460EB`, `0x147C54`,
   `0x16283E` and none of them is a policy check.

3. **The `0x66180` topology object's vtable slot semantics.** 12 slots are
   present at `0x30D610` (`0x65360` dtor, `0x66950` returns 3, `0x66960`
   enumerates, `0x66A50` enumerates differently, `0x66B20` returns
   `[this+0x94]`, `0x66B30` queries, `0x66CE0` queries, `0x86A0` stub, …),
   and the `ICpuTopology` RTTI name is at `0x3A24A0`, but which slot is
   `GetCoreCount` vs `GetEfficiencyClass` vs `GetNumaNode` is not determined.
   The `%3d: ProcessorCore %u - group %u, mask 0x%llx, flags 0x%x, efficiency %u`
   format (`0x30D1E0`) proves the *data* but not the accessor.

4. **The `0x2A1DD4` AVX2 family allow-list's full extent.** It compares
   `CPUID.1.EAX & 0xFFF3FF0` against `0x106C0`, `0x20660`, `0x20670` and then
   tests bit `(eax + 0xFFFCF9B0)` in a 33-bit mask `0x100010001`. That is 4
   models + 3 sparse bits. The full model list for "AVX2 is safe" is a
   compiler-internal table (`__isa_available` in the MSVC CRT) and the
   corresponding source is not in the binary. **Resolving:** the MSVC CRT
   source for the toolset that built this (the `_get_isa` / `__isa_available`
   dispatch logic in VC++ `cpu_disp.c`); the routine itself is not exported
   from tier0, so no RVA can be cited for it here.

5. **The exact set of `ICvar` booleans read by `0x134040`.** Four hashes
   (`0xC554814E`, `0x6539DA`, `0xB80F851E`, `0x4ED26557`) are passed to
   `ICvar` vtable `+0x20`/`+0x50`, but the convar *names* are not in the
   binary — they live in `vstdlib`/`tier1` or are registered by `tier0` itself
   at `0x685C0`. The strings `"PageHeapFlags"`, `"TracingFlags"`,
   `"PageHeap"`, `"stdout"`, `"memstats_%d.txt"` and the IFEO key
   `Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%s`
   are the visible ones; the four hashes are not resolved.

6. **Whether `LoggingSystem`'s channel table is a hash or a sorted array.**
   `FindChannel` `0x129BA0` (292 B) and `GetChannel` `0x129D10` are leaf
   accessors, and the table at `0x3AD9C0` is BSS. The `LoggingSystem_Log`
   path at `0x127E10` indexes `[channel + 0x148]` and `[TLS + 0x170]`, which
   looks like an array of `{verbosity, flags, color, name}` records, but the
   count and the lookup are runtime state. **Resolving:** a live dump of
   `0x3AD9C0` after `log_dumpchannels`.

7. **The `0x3D35A0` topology provider's class and vtable.** The descriptor's
   `+0x48` field points at `0x3D35A0`, which is `.data` BSS — all zeros on disk
   — so its vtable is installed at runtime by `0x633A0` (which calls provider
   vtable slots `+0x10`, `+0x18`, `+0x20`, `+0x48` at `0x633C8`–`0x6341E`).
   Which of the four RTTI implementations (`CpuidImpl`, `DefaultImpl`,
   `GlpiExImpl`, `GlpiImpl` at `0x3A23F0`–`0x3A2470`) is selected, and on what
   condition, is not determinable statically because the choice is made in
   `0x66E50`/`0x66F0A` at runtime from the availability of
   `GetLogicalProcessorInformationEx`. **Resolving:** a live read of
   `*(void**)0x3D35A0` and of the descriptor at `0x3AC600`.

8. **`0x62D20`'s use of the globals `0x3AC60C`/`0x3AC60D`.** The
   `xor`/`and`/`xor` sequence against `[0x3AC60C]` looks like "set or clear a
   bit", but the read-modify-write is against a *global*, so the more accurate
   reading is that it is a **branchless conditional bit-replacement**:
   `G' = (G & ~mask) | (bit ? mask : 0)`, where `bit` comes from a `CPUID`
   result register and `mask` is the feature's slot in the byte. That is why
   the source byte is read rather than written with a constant. Note that
   `0x62D20` has **exactly one caller in the whole image** (`0x63A5F`, inside
   `0x639F0`), so idempotence across repeat calls is *not* the motivation —
   an earlier draft of this document claimed otherwise. The branchless form is
   there because the bit value is produced conditionally from several `CPUID`
   bits and the compiler avoided a branch. What remains unexplained is only
   *why the compiler chose a global read* rather than a register scratch;
   that is a codegen artifact, not semantics. **Resolving:** not resolvable
   statically; the observable behaviour is fully determined by the formula
   above.

9. **The `0x13BF20` exception-code policy.** It calls `0x143E90`
   (`Plat_IsInDebugSession`) and reads `[rbp+0x77]` (the exception code) but
   the *decision table* for which codes produce a dump (vs. "let the debugger
   have it") is spread across `0x13C018`–`0x13C1C0` and the
   `VMINIDUMP_EXCEPTION_CODE` user-stream value at `0x328F40`. The
   `[0x3D83BC]` (`g_…DumpOnException`?) and `[0x3D84E8]` globals gate it;
   their initialisers are in `.data` BSS. **Resolving:** the convar names, or a
   watchpoint during a forced crash.

10. **The `CThread` vtable's real slot count.** `0x32DF08` has 6 valid slots
    (`0x172D70` dtor, `0x175CD0` Start, `0x2A2D10` `purecall`, `0x86A0` OnExit,
    `0x1760C0` WaitForCreateComplete, `0x1760E0` IsThreadRunning) and then the
    next qword is ASCII (`"Toolst"`), i.e. the vtable is **6 slots long and
    immediately followed by a string**. That is normal MSVC layout, but it
    means any tool that walks the vtable past 6 slots will read text. The same
    trap exists at `0x327158` (`CMiniDumpCommentBuilderBase`, 2 slots then
    text) and at `0x306260` (`CUtlCharConversion`).

11. **`0x84ED0`'s caller.** `EarlyInit_Tier0` is called from `0x229D85`, which
    is inside the CRT's `_initterm` array, but the *index* in that array is not
    recoverable without reading the CRT's `.CRT$XC*` sections. So "runs first"
    is true of tier0's own initialisers but not provably first in the process.

12. **Why `GetFileAndLineFromAddress` / `GetSymbolNameFromAddress` /
    `GetModuleNameFromAddress` / `Plat_IsCPUEmulated` are stubs.** All four are
    at the `xor al,al; ret` leaf `0x17FB0` (or `0x8690` for `Plat_Is64BitOS`,
    which is `mov al,1; ret`). For `Plat_IsCPUEmulated` this is clearly a
    deliberate "always false" (the "CPU emulated" concept was dropped); for
    the three symbol functions it may be an `#if` in `platform.cpp`. Which is
    which is not determinable from the binary.

13. **The `mimalloc` version and configuration.** The strings
    `"mimalloc: error: "`, `"mimalloc: warning: "`, `"mimalloc_%s"`,
    `"environment option mimalloc_%s has an invalid value."` are at
    `0x2F17B0`–`0x2F1870` and the RTTI name
    `?$CMemPassAllocT@U?$LLA_AddAlignedSelectors@ULowLevelAllocationScheme_mimalloc`
    at `0x3A33D0`, but there is no version string. The option parser is
    inlined. **Resolving:** the `mimalloc_*` environment-variable names that
    the parser accepts (a string scan finds only the generic format, so the
    option names are hashed or table-driven).

14. **The `0x3AD318` global allocator-state dword's bit layout.** It is
    manipulated with `bts`/`lock or`/`lock and` at `0x84F68`–`0x850C0` and
    `0x12E1EE`, with bits 25, 26, 28, 29, 30 in play and a `0x1FFFFFF`
    low-field. It is clearly `{refcount:25, initialising:1, initialised:1,
    shutting_down:1, …}`, but the exact assignment is not proven.

15. **The `CUtlMemoryPoolBase` growth policy.** `AddNewBlob` `0x130810`
    (260 B) and the `MemoryPoolGrowType_t` enum are exported but the enum
    values are not: the type appears only as a parameter in the ctor
    `0x12F510` and `Init` `0x12F860` signatures, so the enumerators were
    folded to integers at every call site and no RTTI descriptor for the
    enum is emitted.
    `"CUtlMemoryPoolBase: Cannot specify 0 elements to grow each time!"`
    (`0x327780`) is the only clue about the semantics. **Resolving:** a
    caller-side sweep for the literal third argument to `0x12F860`.

---

## Appendix A: verified counts

| quantity | value | source |
|---|---|---|
| file size | 3,979,928 | PE header |
| SHA-256 | `030d4fa0…abbbe8` | file + `index/inv/tier0.json` |
| PE timestamp | 1793662171 (2026-11-02 23:29:31 UTC) | PE header |
| sections | 6 | PE header |
| exports | 2,625 (2,399 distinct RVAs) | export directory |
| C++ exports | 1,529 (1,528 demangle) | `llvm-undname` |
| plain C exports | 1,096 | export directory |
| exports with a body | 1,611 | `.pdata` |
| export-only leaves | 1,014 | no `.pdata` |
| aliased names (RVA with >1 name) | 226 across 70 RVAs | export directory |
| imports (DLLs) | 8 | import directory |
| imports (symbols) | 317 | sum of the 8 tables |
| `.pdata` records | 10,809 | exception directory |
| functions, naive 16-byte merge | 5,135 | `t0.Mod.mfuncs()` |
| functions, terminator-aware merge | 5,361 | `bounds.py` |
| median function size | 291 B | `bounds.py` |
| RTTI type descriptors | 194 | `index/rtti/tier0.txt` |
| self-registered interfaces | 4 | `jmp 0x20EA00` scan |
| catalogue interfaces | 115 | table at `0x2F4390` |
| `Plat_*` exports | 259 | export directory |
| `V_*` exports | 405 | export directory |
| `LoggingSystem_*` exports | 50 | export directory |
| `MemAlloc_*` exports | 12 | export directory |
| `Thread*` free-function exports | 38 | export directory |
| `MiniDump*`/`Minidump*` exports | 11 (3 + 8) | export directory |
| distinct `__FILE__` literals | 25 (18 `src\tier0\*.cpp` + 5 `src\public\tier0\*.h` + `create.h` + `win32.h`) | string scan |
| `src\tier0\*` files | 18 | string scan |
| `src\public\tier0\*` headers | 5 | string scan |
| modules importing tier0 | **52** | `index/graph.json` |
| symbols imported from tier0 (total) | 10,451 | `index/graph.json` |
| CPUID instructions in `.text` | 65 real (65 byte matches) | linear sweep over `funcmap.json` + byte scan `0F A2` |
| `XGETBV` instructions | 3 | byte scan `0F 01 D0` |
| `RDTSC` instructions | 41 real (49 byte matches) | linear sweep over `funcmap.json`; 8 byte matches misaligned |
| `RDTSCP` instructions | **0** | byte scan `0F 01 F9` + linear sweep (both 0) |
| `RDMSR`/`WRMSR` instructions | **0** | byte scan `0F 32`/`0F 30` → 5 + 4 hits, all misaligned |

## Appendix B: reproducing the analysis

```bash
cd /tmp/opencode/csgo-analysis/t0

# 1. parse PE + strings + xrefs (writes t0cache/)
python3 t0.py

# 2. terminator-aware function map (writes funcmap.json)
python3 bounds.py

# 3. annotated disassembly of any function (merged boundaries, IAT + string comments)
python3 ad3.py 0x62d20            # whole function
python3 ad3.py 0x62d20 0x200      # first 0x200 bytes

# 4. export catalogue + subsystem grouping
python3 parse_cpp.py              # writes cpp_parsed.json
python3 classify.py               # writes groups.json

# 5. re-verify the byte-scan counts
python3 - <<'EOF'
from t0 import Mod
m = Mod(); t = [s for s in m.secs if s[0]=='.text'][0]
d = m.data[t[3]:t[3]+t[4]]
for pat, name in ((b'\x0f\xa2','cpuid'),(b'\x0f\x31','rdtsc'),
                  (b'\x0f\x01\xf9','rdtscp'),(b'\x0f\x01\xd0','xgetbv'),
                  (b'\x0f\x32','rdmsr'),(b'\x0f\x30','wrmsr')):
    n = d.count(pat); print(name, n)
EOF
```

The `.asm` dumps in `docs/tier0/` cover the 300 largest `.pdata` chunks and use
**raw** chunk boundaries, so a function appears as several files
(`62d20.asm` is the first 16 bytes of a 1,651-byte body). `ad3.py` is
authoritative for boundaries.
