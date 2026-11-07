# cs2.exe — Technical Reverse-Engineering Report

**Target:** `/tmp/opencode/csgo/bin/win64/cs2.exe` (Counter-Strike 2 / CS:GO install, `game/bin/win64`)
**Size:** 2,967,704 bytes
**SHA256:** `8614097aaa2761b0a7157c0045861713e769fb1e8235f50fc68f411294dd60cf`

All addresses in this document are **RVAs** (relative virtual addresses) unless explicitly written with the
`0x1400…` image base. The image base is `0x140000000`, so VA = `0x140000000 + RVA`.

Method: `pefile` for structure, Capstone for a complete instruction-level scan of `.text` (every function
boundary from `.pdata`), radare2 + r2ghidra (`pdg`) for decompilation, plus independent cryptographic
verification of the embedded signature material with Python/OpenSSL. Function boundaries are exact
(`.pdata` `RUNTIME_FUNCTION` entries), not heuristic. Where a "function" is split into several `.pdata`
fragments by the MSVC linker (shared prologues / tail merging) I give the merged extent and say so.

---

## 1. Identity

| Property | Value |
|---|---|
| File name | `cs2.exe` |
| Size | 2,967,704 bytes |
| SHA256 | `8614097aaa2761b0a7157c0045861713e769fb1e8235f50fc68f411294dd60cf` |
| Machine | `0x8664` (x86-64) |
| Subsystem | 2 (`IMAGE_SUBSYSTEM_WINDOWS_GUI`) |
| Subsystem version | 10.0 |
| OS version | 10.0 |
| Linker version | 14.40 (MSVC 2022 toolset) |
| Image base | `0x140000000` |
| Entry point | RVA `0xea60` (VA `0x14000ea60`) |
| `SizeOfImage` | `0x432000` (4,399,104) |
| `SizeOfHeaders` | `0x400` |
| File alignment / section alignment | `0x200` / `0x1000` |
| Checksum | `0x2e2e1a` — **matches** the computed checksum |
| `DllCharacteristics` | `0x8160` = `HIGH_ENTROPY_VA` (0x20) + `DYNAMIC_BASE` (0x40) + `NX_COMPAT` (0x100) + `TERMINAL_SERVER_AWARE` (0x8000). **`GUARD_CF` (0x4000) is absent.** |
| File characteristics | `0x22` = `EXECUTABLE_IMAGE` + `LARGE_ADDRESS_AWARE` |
| NumberOfRvaAndSizes | 16 (all 16 slots present; 9 are non-empty: export, import, resource, exception, security, basereloc, debug, load-config, IAT) |
| Sections | 6 |
| Functions (`.pdata`) | 713 `RUNTIME_FUNCTION` entries; 601 after merging linker-split fragments; 157,639 bytes of code |
| PDB path | `C:\buildworker\csgo_rel_win64\build\_build_\source2launcher\_vpc_source2launcher_csgo\default\win64\_msvc_\Retail\cs2.pdb` |
| PDB GUID / age | `91F6EA07-…` / age 4 (CodeView record at RVA `0x39a18`, 146 bytes) |
| Build timestamp | `1792003052` = **2026-10-14 18:37:32 UTC** |
| Authenticode signing time | **2026-10-14 18:37:43 UTC** (11 s after link, consistent with an automated build) |
| Embedded signature | present, `IMAGE_DIRECTORY_ENTRY_SECURITY` at file offset `0x2d1c00`, size `11416`, ends exactly at EOF (no overlay) |

The PDB path is the single most important identity fact: `source2launcher\_vpc_source2launcher_csgo`
is the **VPC project name of the Source 2 launcher** (`source2launcher.vpc`), built for the `csgo`
branch. This is the shim executable that Steam launches; it is *not* the game.

### 1.1 Sections

| Name | RVA | Virtual size | Raw size | Entropy | Characteristics |
|---|---|---|---|---|---|
| `.text` | `0x1000` | `0x295b5` (169,397) | `0x29600` (169,472) | 6.55 | code, execute+read |
| `.rdata` | `0x2b000` | `0x11f22` (73,506) | `0x12000` (73,728) | 5.98 | initialized read-only data |
| `.data` | `0x3d000` | `0x1dcea0` (1,953,440) | `0x80000` (524,288) | **0.03** | read/write data |
| `.pdata` | `0x21a000` | `0x216c` (8,556) | `0x2200` (8,704) | 5.39 | exception directory (713 × 12 bytes) |
| `.rsrc` | `0x21d000` | `0x213650` (2,176,592) | `0x213800` (2,177,024) | 6.10 | resources |
| `.reloc` | `0x431000` | `0x6c8` (1,736) | `0x800` (2,048) | 5.07 | base relocations: 10 blocks, 828 fixups |

`.text` holds 157,639 bytes of actual code out of 169,397 virtual bytes (the rest is `int3`/`nop`
alignment padding). Median function size is 127 bytes; the distribution is 70 functions ≤32 bytes,
105 in 33–64, 127 in 65–128, 129 in 129–256, 94 in 257–512, 50 in 513–1024, 23 in 1025–2048 and only
3 above 2 KB. This is a small, tightly written C++ program — as expected for a launcher.

### 1.2 Entry point

```
0xea60  sub  rsp, 0x28
0xea64  call 0xed98            ; __security_init_cookie
0xea69  add  rsp, 0x28
0xea6d  jmp  0xe8ec            ; __scrt_common_main_seh  (no return)
```

`0xed98` is the standard MSVC `__security_init_cookie`: it compares `__security_cookie`
(`0x1400bc380`) with the default `0x2b992ddfa232`, and if unchanged derives a new cookie from
`GetSystemTimeAsFileTime ^ GetCurrentThreadId ^ GetCurrentProcessId ^ QueryPerformanceCounter`
and stores `~cookie` at `0x1400bc3c0`. This is stock CRT code, byte-for-byte in structure.

### 1.3 TLS and CRT initialisers

There is **no TLS directory** (`IMAGE_DIRECTORY_ENTRY_TLS` = 0), therefore **no TLS callbacks** — the
usual `.CRT$XLB` callback chain has been optimised away (the launcher does not use `__declspec(thread)`).

Static initialisation runs through the merged `.CRT$XC*` table in `.rdata` at RVA `0x2b3b8`:

```
0x2b3b8: 0000000000000000            ; __xc_a  (CRT$XCA)
0x2b3c0: 0x14000e8d0
0x2b3c8: 0x140001010   -> 0x140111cc0
0x2b3d0: 0x140001020   -> 0x1400bcf40
0x2b3d8: 0x140001030   -> 0x1401bb7c0
0x2b3e0: 0x140001000   -> 0x140166a40
0x2b3e8: 0x1400010a0
0x2b3f0: 0x140001060
0x2b3f8: 0x140001110
0x2b400: 0x140001120
0x2b408: 0x1400010d0
0x2b410: 0x140001040
0x2b418: 0000000000000000            ; __xc_z  (CRT$XCZ)
0x2b420: 0000000000000000            ; __xi_a
0x2b428: 0x14000e808 …              ; __xi_* / __xt_* (C init + atexit)
```

The four initialisers `0x1000`, `0x1010`, `0x1020`, `0x1030` are three instructions each:

```
0x1000  lea rcx, [rip+0x165a39]   ; -> 0x140166a40
0x1007  jmp 0x140009d60           ; database constructor
```

i.e. they construct **four global trusted-launch database objects** at `0x140166a40`, `0x140111cc0`,
`0x1400bcf40`, `0x1401bb7c0`. `0x1040` creates the loader mutex (`CreateMutexA` → `0x140218b90`),
`0x1060` constructs a 0x78-byte object with vftable `0x14002a3f0` → `0x140218b48`, `0x10a0`
initialises the critical section `0x140218b68` and constructs vftable `0x14002a460`, `0x10d0`
constructs a 0x28-byte object with vftable `0x14002a470`, and `0x1110`/`0x1120` register `atexit`
destructors (`0x14000ece0`) for the vftables at `0x14002a4e0` / `0x14002a550`.

---

## 2. Purpose and startup sequence

### 2.1 What this binary is

`cs2.exe` is the **Source 2 launcher** for the CS:GO/CS2 tree. It is a ~170 KB GUI executable whose only
job is to:

1. validate that it is running from a trustworthy installation,
2. decide a **launch trust state** from the command line,
3. load `tier0.dll` (the platform layer) by absolute path,
4. resolve `engine2.dll` and its `Source2Main` entry point,
5. call `Source2Main(hInstance, 0, lpCmdLine, nCmdShow, exeDir, "csgo")` — after which the launcher
   process *becomes* the game (the engine runs in the same process; there is no second `CreateProcess`).

The name `cs2.exe` is misleading: the module description in the PDB is `source2launcher`. The real game
code lives in `engine2.dll`, `client.dll`, `server.dll`, `host.dll`, `materialsystem2.dll`, etc., all
present in the same directory. `cs2.exe` imports only `KERNEL32.dll` and `USER32.dll` — it cannot render,
play audio, or open a socket.

### 2.2 Startup sequence, stage by stage

```
[PE loader]
  └─ entry 0xea60
      ├─ 0xed98  __security_init_cookie
      └─ 0xe8ec  __scrt_common_main_seh            (369 bytes, 0xe8ec–0xea5d)
           ├─ 0xeaf4(1)   __scrt_initialize_crt      -> 0xf1a0 (CPU/XCR0 feature setup),
           │                                            0x109d8 (UCRT init), 0x1b9f0 (C init table)
           ├─ 0xeab8      __scrt_acquire_startup_lock (gs:[0x30]+8, lock cmpxchg 0x140218c88)
           ├─ 0xec54      __scrt_release_startup_lock
           ├─ 0xee9c/0xeea4  &__argv / &__environ
           ├─ 0xebbc      (startup-state dispatch, also runs _initterm)
           ├─ 0xeffc      __scrt_get_show_window_mode -> GetStartupInfoW().wShowWindow
           ├─ 0x1ae90     __p___argv  (command-line tokeniser)
           ├─ 0x4650      *** WinMain ***
           │     0x4650/0x46b9 = WinMain prologue fragment (1470 bytes merged to 0x4c0e)
           ├─ 0xf040      __scrt_is_nonwritable_in_current_image
           ├─ 0x1b244 / 0x1b234   _exit / _cexit paths
           └─ 0xec78      __scrt_common_main cleanup (calls 0x1ba04 + 0x10a00)
```

`WinMain` is called as `fcn.140004650(0x140000000 /*hInstance*/, 0 /*hPrevInstance*/, argv, showCmd)`
at `0xe9e6`–`0xe9ed` — the classic WinMain signature.

### 2.3 WinMain — `0x4650` … `0x4c0e` (1470 bytes, 4 `.pdata` fragments)

WinMain is *one* function split by the linker into fragments at `0x4650`, `0x46b9`, `0x46c8` and `0x49f0`.
Its control flow, in order:

**Phase 1 — locate itself and the Steam environment (`0x4650`–`0x46c8`)**

```
GetModuleFileNameW(hInstance, buf, 260)          ; 0x4698
  → failure (0 or ≥258) returns -5 (0xfffffffb) at 0x4c2a
strip the filename at the last '\'                ; 0x46dd -> 0x14000f668 (strrchrW)
```

**Phase 2 — derive the user-data directory (`0x46c8`–`0x49f0`, 808 bytes)**

```
GetEnvironmentVariableW(L"SteamPath", …)                       ; 0x4717
  if empty: scan argv for "-steampath " (with trailing space)   ; 0x4725, fcn.14000f480
            take the rest of that token, MultiByteToWideChar(CP_UTF8) at 0x47a6
GetEnvironmentVariableW(L"SteamUserDataFolder", …)             ; 0x47dc
  if empty and SteamAppId set and Steamid set:                  ; 0x480c / 0x4844
      wsprintfW(L"%u", strtoul(Steamid))                        ; 0x487d
      dir = SteamPath + "\\userdata\\" + <steamid64> + "\\" + SteamAppId + "\\local"   ; 0x4896–0x4908
```

So the launcher understands `SteamPath`, `SteamUserDataFolder`, `SteamAppId` and `Steamid` from the
environment, and the `-steampath <path>` switch as an override.

**Phase 3 — command-line trust state (`0x490d`–0x49e4)**

```
desired = 3                                    ; default
if argv contains "-insecure"                    desired = 0   (0x492b)
else if argv contains "-trusted"                desired = 3   (kept)
else if argv contains "-allow_third_party_software" desired = 2 (0x4956)
if argv contains "-tools"                       desired = 2   (0x4980)
```

`desired` is then passed to `fcn.140004fe0(buf, desired, 0, flags)` (`0x49df`), which performs the whole
trusted-launch database load and returns the *actual* state. If `actual != desired` the launcher prints
`"Launch state does not match desired\n"` via `OutputDebugStringA` (`0x49f7`) and continues.

**Phase 4 — load tier0 and enter the engine (`0x49f0`–0x4c0e)**

```
fcn.1400057f0(state)              ; 0x4a11  release hook trampolines / finalise
fcn.140003c10(cpuInfo, desired)   ; 0x4a31  CPUID feature detection
if (cpuInfo.SSE4_2 == 0)          ; 0x4a36..0x4a3f  (bit 7 of byte at stack+0x73)
     LauncherError("A CPU that supports the %s processor feature is required.", "SSE4.2")
fcn.140004220()                   ; 0x4a45  load tier0.dll (call #1, result discarded)
if (!fcn.140004220())             ; 0x4a4a  load tier0.dll (call #2, result tested at 0x4a4f)
     return 1
pLoadModule        = [0x140219e70]   ; tier0!Plat_LoadModule
```

Both calls are real (`e8 d6 f7 ff ff` at `0x4a45`, `e8 d1 f7 ff ff` at `0x4a4a`), and `0x4220` is
idempotent — it short-circuits on `if ([0x140219e58] != 0)` at `0x422d` (`48 83 3d 23 5c 21 00 00 /
0f 85 4c 02 00 00`). So the second call is a no-op returning 1, and the visible effect is a single
`tier0.dll` load. The duplication is a source-level artefact, not a bug in the analysis; I record it
rather than silently "fixing" the call graph.

```
pLoadModule        = [0x140219e70]   ; tier0!Plat_LoadModule
h = pLoadModule("engine2", 0, 0)     ; 0x4a6d
if (!h) h = pFindModule("engine2", &err, 0)   ; 0x4a92  tier0!Plat_FindModuleByName
if (!h) LauncherError("Unable to load module \"%s\"", "engine2")
pMain = pGetProcAddress(h, "Source2Main")     ; 0x4acc  tier0!Plat_GetModuleProcAddress
if (!pMain) return 1
GetModuleFileNameW(NULL, …); strip filename; WideCharToMultiByte(CP_UTF8)   ; 0x4ae9–0x4ba2
pMain(hInstance, hPrevInstance, lpCmdLine, nCmdShow, exeDirUtf8, "csgo")    ; 0x4bde
fcn.1400057f0(state)                                                       ; 0x4be7
return 0
```

The call at `0x4bde` is:

```
rcx = hInstance (0x140000000)     rdx = hPrevInstance (0)
r8  = lpCmdLine                   r9  = nCmdShow
[rsp+0x20] = exeDirUtf8           [rsp+0x28] = "csgo"
call Source2Main
```

That is a six-argument call: `Source2Main(HINSTANCE, HINSTANCE, char*, int, const char* gameDir,
const char* gameName)`. `engine2.dll` exports exactly one such symbol, `Source2Main` at `0x2111e0`
(verified against `engine2.dll`'s export table).

**Consequence:** the launcher never returns. `Source2Main` is `noreturn` in practice — it hands the
process to the engine's own main loop, and `0x4be7` is only reached if the engine returns early.

### 2.4 How `tier0.dll` is located and loaded — `0x4220` (634 bytes)

This is the only place the launcher performs a *dynamic* module load, and it deliberately avoids the
normal search path:

```
fcn.14001bd8c(L"Source2Launcher=1")   ; 0x4242  set env var (marks the process as a launcher)
GetModuleFileNameW(NULL, exePath, 260) ; 0x4257
strip filename                          ; 0x429b..0x42ed
wsprintfW(path, L"%s\\%s.dll", exeDir, L"tier0")   ; 0x4347  fcn.140003b00
LoadLibraryExW(path, NULL, 8 /*LOAD_WITH_ALTERED_SEARCH_PATH*/)  ; 0x4364
if (!hmod):
    GetLastError(); LauncherError("Failed to load the %s DLL.\n\nPath: \"%ls\"", "tier0", path)  ; 0x439d
hGetProc = GetProcAddress(hmod, "Plat_GetModuleProcAddress")   ; 0x43b8
if (!hGetProc) -> "Failed to load tier0"
pLoadModule   = hGetProc(hmod, "Plat_LoadModule")             ; 0x43df  -> 0x140219e70
pFindModule   = hGetProc(hmod, "Plat_FindModuleByName")       ; 0x43fd  -> 0x140219e48
pLogDirect    = hGetProc(hmod, "LoggingSystem_LogDirect")     ; 0x441b  -> 0x140219e68
pReportDenial = hGetProc(hmod, "Plat_ReportDllLoadDenial")    ; 0x4432  -> 0x140219e50
verify all four non-NULL, else "Failed to load tier0"
```

The four resolved pointers are stored in `.data` globals and used later:

| Global | Export | Used at |
|---|---|---|
| `0x140219e58` | `HMODULE` of tier0 | — |
| `0x140219e68` | `Plat_GetModuleProcAddress` | `0x4acc`, `0x4a6d` indirect |
| `0x140219e48` | `Plat_FindModuleByName` | `0x4a92` |
| `0x140219e70` | `Plat_LoadModule` | `0x4a6d` |
| `0x140219e50` | `Plat_ReportDllLoadDenial` | `0x44d0` (`fcn.1400044d0`), `0x5b71` |

`0x44d0` is a two-instruction wrapper: `mov rax,[0x140219e50]; test; jmp rax` — a lazily bound import
thunk for `Plat_ReportDllLoadDenial`.

All five names were confirmed present in `tier0.dll`'s export table (`Plat_LoadModule` 0x1462f0,
`Plat_FindModuleByName` 0x147020, `Plat_GetModuleProcAddress` 0x146c50, `Plat_ReportDllLoadDenial`
0x141180, `LoggingSystem_LogDirect` 0x12a5c0).

### 2.5 Error reporting — `0x44e0` (359 bytes)

Every failure path funnels through `fcn.1400044e0(errCode, fmt, arg, ctx)`:

```
fcn.140003af0()                                   ; TLS/errno block
FormatMessageA(0x1300, NULL, *errCode, 0x400, &msg, 0, NULL)     ; 0x44f0-ish
wsprintfA(buf, "Error: (0x%8.8x) %s", code, msgOrFallback)       ; 0x3bb0 with fmt 0x140039088
wsprintfA(buf2, "%s\n\n%s", formatted, "Launcher Error: %s")     ; 0x3bb0 with fmt 0x14003909c
MessageBoxA(NULL, text, "Launcher Error", 0)                     ; 0x45…? (import 0x14002b368)
LocalFree(msg)
```

The two format strings are at RVA `0x39088` (`"Error: (0x%8.8x) %s"`) and `0x3909c` (`"%s\n\n%s"`), with
the literal `"Launcher Error"` at `0x38f28` and `"[Failed To Resolve Error Code.]"` at `0x39068`.
`0x44a0` is a small helper used by the manifest checksum path:

```
0x44a0  push rbx; sub rsp,0x20
0x44ac  mov r8d, [rcx]      ; seed
0x44b2  not r8d             ; ~seed
0x44b8  mov rcx, rdx        ; buf
0x44bb  call 0x3650         ; crc32(buf, len, ~seed)
0x44c0  not eax             ; ~result
0x44c2  mov [rbx], eax      ; store back
```

i.e. `*seed = ~crc32(buf, len, ~*seed)` — the standard "CRC32 as a running hash" idiom.

---

## 3. Function catalogue

Names are descriptive and mine; every one is backed by the evidence column. Sizes are merged
`.pdata` extents where the linker split a function. "Frag" marks a `.pdata` fragment that is *not* a
standalone function.

### 3.1 CRT / runtime support (stock MSVC 14.40 code)

| RVA | Size | Name | Evidence |
|---|---|---|---|
| `0xea60` | 18 | `entry` | `__security_init_cookie` + `jmp __scrt_common_main_seh` |
| `0xed98` | 172 | `__security_init_cookie` | default cookie `0x2b992ddfa232`, `QueryPerformanceCounter`, `~cookie`→`0x1400bc3c0` |
| `0xe8ec` | 369 | `__scrt_common_main_seh` | startup-state machine, `_initterm`, calls WinMain |
| `0xeaf4` | 58 | `__scrt_initialize_crt` | → `0xf1a0`, `0x109d8`, `0x1b9f0` |
| `0xeab8` | 57 | `__scrt_acquire_startup_lock` | `gs:[0x30]+8`, `lock cmpxchg [0x140218c88]` |
| `0xec54` | 36 | `__scrt_release_startup_lock` | stores 0 |
| `0xec78` | 41 | `__scrt_common_main` cleanup | `0x1ba04` + `0x10a00` |
| `0xeeb4` | 328 | `_invoke_watson` / `__scrt_fastfail` | `IsProcessorFeaturePresent(0x17)`, `int 0x29`, `RtlCaptureContext`, `EXCEPTION_RECORD{0x40000015}`, `UnhandledExceptionFilter`, `int 3` |
| `0xeffc` | 58 | `__scrt_get_show_window_mode` | `GetStartupInfoW`, `wShowWindow` (default 10) |
| `0xf040` | 81 | `__scrt_is_nonwritable_in_current_image` | `GetModuleHandleW(0)`, `MZ`/`PE\0\0`, magic `0x20b`, `DllCharacteristics & 0x0100` |
| `0xf1a0` | 714 | `__scrt_initialize_cpu_features` / `__isa_available_init` | CPUID vendor check, XCR0 `xinuse`, sets `0x1400bc328/330/334/338/340` |
| `0xeb30` | 139 | `__scrt_is_ucrt_dll_in_use`-family helper | refs `0x140218c91/98/a8/b0/c0` |
| `0xf480` | 488 | `strstr` (SSE4.2 `pcmpistri` path) | `pcmpistri(…,0xc)`/`0x41`, `*0x1400bc330` dispatch |
| `0xf668` | ~200 | `wcsrchr` (reverse wide-char search) | walks to the NUL then back (`sub r8,2` / `cmp [r8], r9w` / `jne`), SSE2 `pcmpistri` fast path; used at `0x46dd`, `0x429b`, `0x87b5` to find the last `\` |
| `0x1053c` | ~120 | `wcschr` (forward wide-char search) | `pshuflw`/`pcmpeqw`/`pmovmskb` SSE2 scan, scalar tail at `0x10585`; used at `0x87d2` to find `.` |
| `0x29290` | 1645 | `memcpy` (16-case jump table) | switch at `0x393f0`, `ret` for len 0 |
| `0x29930` | 904 | `memset` (16-case jump table) | `imul r11, rdx` broadcast, table `0x394a0` |
| `0x29cd0` | 93 | `memcmp` | byte/qword compare, returns −1/0/1 |
| `0x29e07` | 168 | SEH funclet (`__C_specific_handler` body) | reads `EXCEPTION_POINTERS`, `0xc0000005` test |
| `0x29eaf` | 182 | second SEH funclet | same shape |
| `0x2a3f0`, `0x2a470` | 99 each | `std::mutex` lock/unlock helpers | tree walk on `0x140218b48`, `EnterCriticalSection` via `0x14002b110` |
| `0x2a4e0`, `0x2a550` | 101 each | `operator delete`-style destructors | `0x140219…` free list |
| `0x28ca8` | 211 | `__report_gsfailure` | `__security_cookie` `0x1400bc3c0`, `TerminateProcess(…, 0xC0000409)` |
| `0x1c074` | 86 | `_invalid_parameter_noinfo_noreturn` | `0x22104`, `int 0x29`, `0x40000015` |
| `0x1a27c` | 70 | `_invoke_watson` variant | `int 0x29`, `0xC0000417` (`STATUS_INVALID_CRUNTIME_PARAMETER`) |
| `0xf7d8` | — | `_CxxThrowException` | `RaiseException(0xe06d7363, 1, 4, …)` |
| `0x1f5b8` | 845 | `_findfirst64i32`/`_findnext64i32`/`_findclose` | `FindFirstFileExW`, `FindNextFileW`, `FindClose` |
| `0x2284c` | 1162 | `_write` (console/file) | `GetConsoleOutputCP`, `WriteFile` |
| `0x23190` | 784 | `_isatty`/`_write` console path | `GetConsoleMode`, `WriteFile` |
| `0x1c344` | 447 | `__acrt_get_proc_address` / delay-load resolver | `LoadLibraryExW` + `GetProcAddress`, `api-ms-`/`ext-ms-` strings |
| `0x1c290`, `0x1c308` | 117/60 | `_malloc_base`/`_free_base` | `HeapAlloc`/`HeapFree` on `0x140219860` |
| `0x1c270` | — | `_errno` | — |
| `0x1a22c` | — | `_invalid_parameter` | — |
| `0x13f6c`, `0x141e8`, `0x14378` | 287 (`0x14378`) | `__acrt_initialize` / locale + heap init | `0x1400bc4f0`, `InitializeCriticalSectionAndSpinCount` |
| `0xef00`-region (`0xeb30`…`0xf198`) | — | C++ EH support (`__CxxFrameHandler4`, `__FrameUnwindToState`) | `RtlUnwindEx` at `0xff24`, `RtlPcToFileHeader` |
| `0x1aa0`-region statics | — | `std::_Tree` (red-black tree) insert/erase/rebalance | `0x6f10` (440), `0x70c8` (795), `0x7410`, `0x7690` |

### 3.2 Crypto primitives (used by the trust checks)

| RVA | Size | Name | Evidence |
|---|---|---|---|
| `0x1130` | 2020 | `MD5_Transform` | K[0] `0xd76aa478` (`lea ecx,[rdx-0x28955b88]`), `ror 0x19`/`ror 0x14` |
| `0x1920` | 335 | `MD5` one-shot | IV `67452301 efcdab89 98badcfe 10325476`, calls `0x1130` |
| `0x1a70` | 48 | `SHA1_Init` | 5 words `67452301 efcdab89 98badcfe 10325476 c3d2e1f0`, count/buf at `+0x14`/`+0x1c` |
| `0x1aa0` | **5957** | `SHA1_Transform` | K `0x5a827999`/`0x6ed9eba1`/`0x8f1bbcdc`/`0xca62c1d6`; `bswap` on the block; 80 rounds unrolled |
| `0x31f0` | 181 | `SHA1_Update` | 64-bit bit-count at `+0x14`/`+0x18`, 64-byte block buffer at `+0x1c` |
| `0x32e0` | 874 | `SHA1_Final` | `0x80` pad, 8-byte big-endian length, calls `0x1aa0` |
| `0x3650` | 1184 | `CRC32` slicing-by-16 | 16 × 256-dword tables at `0x34ea0`…`0x38ea0`; verified `0x34ea0` = reflected poly `0xEDB88320` |
| `0x44a0` | 42 | `crc32(seed, buf, len)` | `~crc32_impl(buf, len, ~seed)` |
| `0xab10` | 42 | `manifest_checksum` | `crc32(0xffffffff, obj, 0x54d80)` then `~` |
| `0xcd20` | 519 | DER/BER TLV parser | `cmp byte [rcx], 0x30`, length forms, `0x03` BIT STRING, `0x06` OID |
| `0xd240` | 3191 | signature blob parser | calls `0xcd20`, extracts modulus/exponent/hash |
| `0xd35d` | 2599 | big-integer modular exponentiation (RSA verify core) | `0xe0f0` bignum helpers, `0xe230` alloc, `0xc4d0`/`0xc6e0` limb ops |
| `0xdec0` | 551 | `verify_sha1_signature` | builds SHA-1 state, hashes, `memcmp` 20 bytes |
| `0xbdf0` | 1613 | manifest record formatter (`;SHA1:`/`;MD5:`/`;CRC:`/`;ERR:`/`;CERT:`/`;ISS:`/`;VFL:`/`;VFR:`) | string refs `0x2c13c`…`0x2c17c`; emits `"Microsoft Windows"`/`"Microsoft Corporation"` |

**Independent verification of the crypto (done outside the binary):** the 512-byte `DIGEST:` blob at the
end of `csgo.signatures` verifies as **RSA PKCS#1 v1.5 / SHA-1** against the 4096-bit key embedded at
RVA `0x2bc90` with public exponent **17**:

```
recovered block prefix : 00 01 ff ff ff …            (valid v1.5 padding)
DigestInfo             : 30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14 <20 bytes>
embedded SHA-1         : 9d025306028c5bab5d0f69160729ecb9c6b3073b
SHA-1 of the 9314-byte  : 9d025306028c5bab5d0f69160729ecb9c6b3073b   ← match
manifest text before "DIGEST:"
```

The same key verifies `foreign.signatures` (SHA-1 `66b99fcf…`) and `system.signatures`
(SHA-1 `d70b9af6…`). A **second** 4096-bit key with e=17 sits at RVA `0x2bec0` and does *not* verify
those three files — it is the Steam-side key, selected when `*(db+0x2ac) == 2` (`0xb1d5` vs `0xb1e2`).
`fcn.14000bd30(db, path, 1|2)` (`0xbd30`, 22 bytes: `wcscpy(db+0x24, path); db->0x2ac = arg3`) is what
sets that selector; the call sites in `0x5005` pass **1** for `csgo`, `foreign` and `system` and **2**
for `steam`.

Also worth recording: the `CRC:` field in the `.signatures` files is CRC32 rendered with byte order
reversed relative to the usual `%08X` (`34/34` sampled entries match that way, `0/34` the plain way).
This is a property of the *data files*, not of `cs2.exe`.

### 3.3 Trusted-launch subsystem (the real content of this binary)

| RVA | Size | Name | Purpose / evidence |
|---|---|---|---|
| `0x4fe0` | 1985 (frags `0x4fe0`,`0x5005`,`0x55d4`) | `TL_LoadAndInit` | **Main trusted-launch driver.** Registers four manifests, parses `trustedlaunch.cfg`, computes the actual state, installs the three hooks. See §3.4 |
| `0x9d60` | 138 | `TL_DatabaseCtor` | Zeroes `+0x4f8d0` for `0x4e20` bytes, `InitializeCriticalSection(+0x546f0)`, sets `+0x4=1`, `+0x54d78 = -1`. Called by the four CRT initialisers and by `0x4f50/0x4f70/0x4f80/0x57b0/0x5920/0x5b00` |
| `0x8dc0` | 86 | `TL_AddManifest` | `if (db->count < 4) { db->obj[count++] = ptr; fcn.14000bd70(ptr, db+0x7f048); fcn.14000bd80(ptr, db+0x7f178); }` — **max 4 manifests** |
| `0xbd30` | 22 | `TL_SetManifestName` | `wcscpy(obj+0x24, name); obj->0x2ac = kind` |
| `0xbd00` / `0xbd10` / `0xbd20` / `0xbcd0` / `0xbce0` / `0xbcf0` / `0xbd60` | 2–6 each | manifest flag setters | write one byte/dword at fixed offsets (`+0`, `+4`, `+5`, `+6`, `+8`) |
| `0xbd70` / `0xbd80` | 8 each | `TL_SetArena` / `TL_SetThreadTable` | `mov [rcx+0x54718], rdx` / `mov [rcx+0x54d70], rdx` |
| `0xbd90` | 85 | `TL_VerifyAllRecords` | loops `count` records × 0x140, calls `0x8170` (Authenticode verify) per record |
| `0x7ea5` | 672 | `TL_LoadWintrust` | `LoadLibraryA("wintrust.dll")` + `crypt32.dll`, resolves 21 APIs (`WinVerifyTrust`, `CryptCATAdmin*`, `CryptCATCatalogInfoFromContext`, `CertGetNameStringW`, …). All pointers cached in `.data` `0x140218bd0`–`0x140218c70` |
| `0x7e90` | 21 | `TL_EnsureWintrust` | `if (!0x140218c78) return 0x7ea5();` |
| `0x8170` | 48 + 1509 | `TL_VerifyAuthenticode` | `WinVerifyTrust` wrapper; `0xaac56b` = `WINTRUST_ACTION_GENERIC_VERIFY_V2` GUID first dword, `0x11d0cd44`, `0xc000c28c`, `0xee95c24f` complete the GUID; `0x58` = `WTD_UI_NONE|WTD_REVOKE_WHOLECHAIN|WTD_CACHE_ONLY_URL_RETRIEVAL` style `dwUIChoice` struct; returns 1 only on `ERROR_SUCCESS` |
| `0x7950` | 755 | `TL_HashFile` | maps the file (`0x8a60` → `CreateFileW`), `GetFileInformationByHandle`, `SHA1`+`MD5`+`CRC32`, PE header validation (`MZ`, `PE\0\0`, `0x20b`, `SizeOfOptionalHeader`, section count, `CheckSum`), `0x5a4d`/`0x4550` checks at `0x7be9`–`0x7c43` |
| `0x81a0` | 1509 | `TL_ComputeFileSignatures` | `CreateFileMappingW` + `MapViewOfFile`, per-record SHA-1/MD5/CRC |
| `0x8a60` | 331 | `TL_OpenFileForHash` | `CreateFileW(GENERIC_READ, FILE_SHARE_READ)` with `\\?\` long-path fallback when `GetLastError()==0x7b` (`ERROR_BAD_PATHNAME`) |
| `0x8e20`/`0x8e7c`/`0x9314` | 1424 | `TL_VerifyFile` | **The gate.** See §3.5 |
| `0x9df0` | 441 | `TL_AddRecord` | inserts a 0x140-byte record (capacity 500, `cmp … 500`), under critical section `+0x546f0` |
| `0x9fb0` | 171 | `TL_FindRecordByName` | 0x140 stride walk, `memcmp` on the name, copies hash fields out |
| `0xa0a0` | 221 | `TL_FindRecordByPath` | compares filename + directory prefix + length |
| `0xa240` | 134 | `TL_ResolveByHash` | walks a hash tree (`0x7c50`) |
| `0xa3e0` | — | `TL_IsSignedRecord` | reads `+0x124` and a per-record flag |
| `0xa350` | 190 | `TL_IsKnownPublisher` | compares SHA-1/issuer triples against the allow-list at `+0x4f8d0` (200-byte records, count `+0x4f8cc`) |
| `0xa410` | — | `TL_CountPending` | counts records needing a trust check (`+0x54720` clear, `+0x6` set, `+0xf3` clear) |
| `0xa460` | 1029 | `TL_ReportLoop` | formats and emits all failing records |
| `0xab40` | 278 | `TL_CountReportable` | per-record predicate used by `CountItemsToReport` |
| `0xac60` | 544 | `TL_ReapCheckerThread` | `GetThreadId`, `GetExitCodeThread` (`0x103` = `STILL_ACTIVE`), folds thread results into counters `+0x14`/`+0x18`/`+0x20` |
| `0xae80` / `0xaf90` | 262 / 207 | `TL_LoadManifest` | `0xb060` + auto-load of `<name>.signature` sidecars |
| `0xb060` | 504 (frags `0xb060`,`0xb0c8`,`0xb0e9`) | `TL_ParseManifestFile` | `CreateFileW(GENERIC_READ)` → `CreateFileMappingA` → `MapViewOfFile` → `0xb290` parser; on failure optionally `0xe3d0` (RSA verify of the digest) |
| `0xb290` | 1969 | `TL_ManifestParser` | line parser: `...\` prefix, `~SHA1:`, `;CRC:`, `#` comments, `~` terminator; capacity 500 records |
| `0xba50` | 405 | `TL_StartCheckerThread` | `CreateThread`, copies up to 5 records into `+0x151cc` |
| `0xbbf0` | — | `TL_SetBaseDir` | appends `\` if missing (`+0x273b0`, `+0x275bc`) |
| `0xbd90`-adjacent `0x8170` | — | see above | — |
| `0x9470` | 54 | `TL_IsStateReady` | `+0x24==1 && +0x28==1 && (+0x2c-1)<2 && (+0x30-1)<2 && +0x44==9` |
| `0x94e0` | 144 | `TL_ReapThreadTable` | `OpenThread(0x40,0,id)`, `GetExitCodeThread`, `CloseHandle`, marks done |
| `0x9570` | 94 | `TL_StoreManifestChecksums` | `for i: db->crc[i] = 0xab10(obj[i])` → `db+0x04…+0x10` |
| `0x9700` | 334 | `TL_CountCheckedFiles` | sums `obj->0x14` for all manifests; also drives `0xba50`/`0xa410` |
| `0x9860` | 127 | `TL_CountLoadedFiles` | sums `obj->0x20` for all manifests |
| `0x9c70` | 133 | `TL_BuildReport` | `for each manifest: 0xbdf0(report_buf, …)`; then `0x98e0(db, out, 0xf0)` header |
| `0x98e0` | 910 | `TL_WriteReportHeader` | emits `"GXS:"`, `";TFL:"`, `";TFC:"`, `";TAS:"`, `";FAS:"`, `";PVC:"`, `";DTR:"`, `";DTF:"`, `";SWD:"` with `%s`/`%02X` |
| `0x9d00` | 93 | `snprintf` helper | `0x19000` (vsnprintf) |
| `0x5b00` | 193 | **`NtOpenFile` detour** | see §3.6 |
| `0x5920` | 410 (frags `0x5920`,`0x59c0`) | **`LoadLibraryExW` detour** | see §3.6 |
| `0x5bd0` | 8 | **`PeekMessageW` thunk** | `mov r10,[0x1400bcf30]; jmp r10` |
| `0x58b0` | 104 | **VEH handler** | `0xC0000096` (`int3`) / `0xC0000005` (AV) → `0x4c90` |
| `0x4c90` | 700 (frags `0x4c90`,`0x4da3`,`0x4ef5`) | `TL_NeutraliseCode` | see §3.6 |
| `0x6480` | 166 | `TL_InstallHook` | `0x6530` + bookkeeping in the hook map, `WaitForSingleObject(0x140218b90,1000)` |
| `0x6530` | 1717 | `TL_HookFunction` | prologue disassembly (`0xc440`), trampoline build (`0x6c00`), `VirtualProtect` + `WriteProcessMemory` of a 5-byte `E9`, `FlushInstructionCache`; records `{addr, trampoline, len}` in the RB-tree at `0x140218b48` |
| `0x6c00` | 784 (frags `0x6c00`,`0x6c7b`) | `TL_UnhookFunction` | restores the original prologue bytes |
| `0x6024` | 772 | `TL_AllocTrampolineNear` | `VirtualQuery` scan then `VirtualAllocEx(GetCurrentProcess(), …)` `MEM_RESERVE|MEM_COMMIT` `PAGE_EXECUTE_READWRITE` within ±2 GB, carves 0x40-byte slots |
| `0x5be0` | 428 | `TL_VectorGrow` | `std::vector` growth (`0x1fffffffffffffff` limit, `sar 3`) |
| `0x5fb0` | 116 | `TL_FreeTrampoline` | walks the map, `VirtualQuery`, frees pages |
| `0x6330` | 158 | `TL_ComputeRelocDelta` | — |
| `0x63d0` | 166 | `TL_ResolveTarget` | `memcpy` of the prologue |
| `0x6f10` | 440 | `std::_Tree::erase` | RB-tree rebalance |
| `0x70c8` | 795 | `std::_Tree::insert` | RB-tree rebalance |
| `0x4c90`-adjacent `0x4ef5` | 87 (frag) | tail of `TL_NeutraliseCode` | writes `48 31 C0 C3` (`xor eax,eax; ret`) |
| `0x4f50` | 32 | export body `CountFilesCompletedTrustCheck` | `0x9700(db); 0x9860(db)` |
| `0x4f70` | 12 | export body `CountFilesNeedTrustCheck` | `jmp 0x9700` |
| `0x4f80` | 70 | export body `CountItemsToReport` | `0x9470` gate, `0x9700`, `0x94e0`, Σ`0xab40` |
| `0x4fd0` | 7 (no `.pdata`) | export body `GetTotalFilesLoaded` | `mov eax,[0x14003d078]; ret` |
| `0x57b0` | 54 | export body `BSecureAllowed` | `0x9c70` into caller buffer, then `0x9470` |

### 3.4 `TL_LoadAndInit` — `0x4fe0` … `0x57a1` (the heart of the launcher)

Signature (recovered): `int TL_LoadAndInit(wchar_t *userDataDir /*260 wchars*/, int desiredState,
void *unused, void (*progress)(int, int))`.

```
db = 0x14003d000                              ; the primary database (a global, not the argument)
db->pathbuf   = userDataDir
db->pathbuf2  = userDataDir + 0x104
db->pathlen   = 0x104
db->pathlen2  = 0x208
0x9630(db)                                    ; no-op in this build (single `ret`)
0x8dc0(db, 0x140111cc0, 0)                    ; register manifest A  (csgo)
0x8dc0(db, 0x1400bcf40, 0)                    ; register manifest B  (steam)
0x8dc0(db, 0x1401bb7c0, 0)                    ; register manifest C  (system)
0x8dc0(db, 0x140166a40, 1)                    ; register manifest D  (foreign) + mark primary
0xbd30(0x140111cc0, userDataDir + "foreign.signatures", 1)
0x7e90()                                      ; load wintrust/crypt32
0xbd00(0x140111cc0); 0xbbf0(0x140111cc0, userDataDir)
0xbd20(0x1401bb7c0)                           ; flag = 2
0xbd30(0x1401bb7c0, userDataDir + "system.signatures", 1)
0xbbf0(0x1401bb7c0, GetWindowsDirectoryW())   ; system manifests also search Windows dir
0xbbf0(0x1401bb7c0, GetSystemDirectoryW())    ;   and System32
0xbd10(0x1400bcf40)                           ; flag = 1
0xbbf0(0x1400bcf40, userDataDir)
0xbd30(0x1400bcf40, userDataDir + "\\steam.signatures", 2)   ; Steam key
0xbcf0(0x140166a40)                           ; flag = 3, +6 = 1
if (userDataDir) {
    0xbd30/0xbbf0 … "\\cfg\\trustedlaunch.cfg"
    if (desiredState == 2 || desiredState == 3) {
        h = CreateFileW(cfg, GENERIC_READ, FILE_SHARE_READ, …, OPEN_EXISTING)
        if (h != INVALID_HANDLE_VALUE) {
            GetFileSizeEx; CreateFileMappingA(…,PAGE_READONLY); MapViewOfFile
            for each line: if (line[0] is a digit) 0x19df4(line)   ; strtoul
            UnmapViewOfFile; CloseHandle
        } else {
            h = CreateFileW(cfg, GENERIC_WRITE, …, OPEN_ALWAYS)
        }
        if (h != INVALID) {
            SetFilePointer(h, 0, 0, FILE_END)
            wsprintfA(line, "%d,%d,%d,0x%x,0x%x\n", desired, desired, GetCurrentProcessId(),
                      GetSystemTimeAsFileTime hi/lo)
            WriteFile(h, line, …)
            *(0x1400bc170) = h            ; db->reportHandle = h
        }
    }
}
actual = 0
if (desired != 0 || arg3 != 0) {
    actual = 0x9640(db) ? desired : 0     ; 0x9640 = "all four manifests parsed OK"
    switch (actual) {
      case 1: 0xbce0(A); 0xbce0(B); 0xbce0(D); break;   ; mark "Valve-signed"
      default: 0xbd60(D); if (actual == 3) 0xbcd0(D);   ; mark "allow third party"
    }
}
0x9570(db)                     ; per-manifest CRC32 into db+4..db+0x10
0x96f0(db, actual, desired)    ; db->0x3c = actual, db->0x40 = desired
if (!actual) { db->0x44 = 1; *status = 1; return 0; }
  0x44 = 2 … 9 as each hook stage succeeds:
      GetModuleHandleA("ntdll.dll")            else 0x44 = 2
      GetProcAddress "NtOpenFile"               else 0x44 = 3
      p = 0x6480(NtOpenFile, 0x5b00, 0)         else 0x44 = 3
      GetModuleHandleA("kernelbase.dll")        else 0x44 = 4
      GetProcAddress "LoadLibraryExW"           else 0x44 = 5
      p = 0x6480(LoadLibraryExW, 0x5920, 0)     else 0x44 = 5
      GetModuleHandleA("user32.dll")            else 0x44 = 6
      GetProcAddress "PeekMessageW"             else 0x44 = 7
      p = 0x6480(PeekMessageW, 0x5bd0, 0)       else 0x44 = 7
      AddVectoredExceptionHandler(1, 0x58b0)    else 0x44 = 8
      db->0x44 = 9
db->0x2fc = progressCallback
return actual
```

`0x9640` (`TL_AreAllManifestsLoaded`) is decisive: it calls `0xae80(obj[0], db+0x7f028, 0)` (load the
primary manifest), then `0xaf90` on the other three, stores the four results in `db+0x24/0x28/0x2c/0x30`,
and returns true only when `+0x24==1 && +0x28==1 && (+0x2c-1)<2 && (+0x30-1)<2`. This is exactly the
predicate `0x9470` re-checks (plus `+0x44==9`).

### 3.5 `TL_VerifyFile` — `0x8e20` / `0x8e7c` / `0x9314` (the enforcement gate)

```
TL_VerifyFile(db, path, mode, ctx):            ; mode 0 = check, 1 = report-only
  if (db->manifestCount == 0 || db->manifestCount < db->primaryIndex) return true
  build a path struct (0x8790) and find the manifest whose prefix matches (0xa1c0)
  rec = 0
  for each manifest obj:
      if (0xa0a0(obj, pathStruct, &index, 0)) { rec = obj; break }
  if (!rec) return true
  ...
  verdict:
    if 0x9fb0(rec, path) fails:
        if 0x7950(path, 0) fails and 0xa070(rec) fails → "File verification failure."
        else                                          → "… Could not calculate signature."
    else if index < 0:                                ; file not listed in the manifest
        if 0xa190(rec) && 0xa060(rec) → "… Unknown file not found in manifest. "
        else if 0xa080(rec)           → "… Unknown foreign dll. "
        else if 0xa090(rec)           → "… Unknown Unsigned File. "
    else:
        if 0xa240(rec, path, index, &newIndex) fails:
            0xa3e0(rec, path, newIndex)
            if 0xa070(rec) → "… File signature does not match manifest."
        else if 0xa1a0(rec, path, index) fails → "… File in wrong directory."
  if verdict != OK:
      db->failCount++                                ; db+0x7c
  if 0x9df0(rec, pathStruct, db+0x7f028) succeeds:    ; record the attempt
      db->checkedCount++                              ; db+0x78
      if verdict != OK:
          build "~<utf8 path>\n" at db+0x7f068
          WideCharToMultiByte(CP_UTF8, path)
          if (db->reportBuffer && len <= db->reportBufferSize) memcpy(…)
          if (db->reportHandle != -1) {
              n = 0x98e0(db, header, 0xf0)
              WriteFile(db->reportHandle, db+0x7f068, len, …)
              WriteFile(db->reportHandle, header, n, …)
          }
      recompute the per-manifest CRCs (0xab10) into db+0x14…
  return (verdict == OK)
```

All seven failure strings are at `0x2b8e8`, `0x2b920`, `0x2b9a0`, `0x2ba10`, `0x2baa0`, `0x2bb20`,
`0x2bb90`, and are written to the trusted-launch report file (`<userdata>\cfg\trustedlaunch.cfg`-adjacent
log) with a `~` prefix, plus optionally shown in a `MessageBoxW` at `0x937d` when `db+0x7f2fc != 0`.

### 3.6 The three user-mode hooks and the VEH

`0x6480` → `0x6530` installs a **5-byte `E9 rel32` inline hook** on three OS functions. The mechanism
is standard "Detours-style":

1. `0xc440` is a length-disassembler that measures the prologue bytes to relocate.
2. `0x6024` reserves executable memory within ±2 GB of the target (`VirtualQuery` scan + `VirtualAllocEx`
   on `GetCurrentProcess()`, `PAGE_EXECUTE_READWRITE`), so a rel32 jump can reach it.
3. `0x6c00` builds the trampoline: original prologue + `jmp` back to `target+len`.
4. `0x6530` then `VirtualProtect(target, len, PAGE_EXECUTE_READWRITE)`, `WriteProcessMemory(target, {E9
   rel32}, 5)`, `FlushInstructionCache`, and records `{target, trampoline, len}` in the RB-tree rooted
   at `0x140218b48` under the mutex `0x140218b90` and critical section `0x140218b68`.
5. `0x6c00` (second fragment) reverses this: restores the saved prologue bytes and frees the trampoline.

The three detours:

**`NtOpenFile` → `0x5b00`** (193 bytes)

```
rcx = PHANDLE FileHandle, rdx = ACCESS_MASK DesiredAccess,
r8  = POBJECT_ATTRIBUTES, r9 = PIO_STATUS_BLOCK
if (r8->ObjectName->Buffer != NULL && (DesiredAccess & 0x21) == 0x21) {   ; FILE_READ_DATA|FILE_EXECUTE
    if (!TL_VerifyFile(db, ObjectName->Buffer, 0, NULL)) {
        Plat_ReportDllLoadDenial(NULL, ObjectName->Buffer, 0);            ; 0x44d0
        return 0xC0000034;                                                ; STATUS_OBJECT_NAME_NOT_FOUND
    }
}
return real_NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock)
```

This is the load-blocking primitive: an unsigned or modified DLL opened for read+execute is reported
and then reported as *not existing*.

**`LoadLibraryExW` → `0x5920`** (410 bytes)

```
0x14003d0b4 = GetCurrentThreadId()
if (lpLibFileName && db->pathbuf && db->pathlen) {
    copy at most db->pathlen bytes of lpLibFileName into db->pathbuf (NUL-terminated)
}
if (0x93c0(db, lpLibFileName, &idx)) {                     ; is this module already tracked?
    if (idx >= 0 && db->tableCount < 0x40) {               ; 64 slots, 0x218 bytes each at 0x140210540
        copy 0x104-byte name; store VirtualAlloc'd copy; store length
    }
}
return real_LoadLibraryExW(lpLibFileName, hFile, dwFlags)
```

The table at `0x140210540` (count `0x140218b40`, max 64, stride `0x218`) is the "modules loaded during
this launcher's lifetime" list that `0x4c90` later consults.

**`PeekMessageW` → `0x5bd0`** (8 bytes): `mov r10,[0x1400bcf30]; jmp r10` — a plain pass-through thunk.
Its only purpose is to be a *hookable* copy so that the trampoline machinery has a third, harmless
target (and so that the message pump the engine uses goes through a function the launcher controls).

**VEH `0x58b0`** (104 bytes)

```
if (ExceptionRecord->ExceptionCode == 0xC0000096 /*STATUS_PRIVILEGED_INSTRUCTION*/) {
    if (0x4c90(0x140210540, ExceptionRecord->ExceptionInformation[0] /*RIP*/, 1)) return -1; /*continue*/
}
if (ExceptionRecord->ExceptionCode == 0xC0000005 /*ACCESS_VIOLATION*/
    && NumberParameters >= 2 && ExceptionInformation[1]) {
    return 0x4c90(0x140210540, ExceptionInformation[1] /*faulting address*/, 0) ? 0 : -1;
}
return 0; /*EXCEPTION_CONTINUE_SEARCH*/
```

`0x4c90` then rewrites the faulting code: it locates the containing 0x218-byte table entry
(`0x4d61`–`0x4d64` bounds check, `0x4d66`–`0x4d95` `VirtualQuery` to confirm the page is not
`MEM_FREE`), allocates it if needed, fills the region with `0x90` (`NOP`) via
`memset(ptr, 0x90, len)` at `0x4ece`–`0x4ed3`, and then overwrites the first bytes with the stub.
The stub bytes are assembled at `0x4ef5`:

```
0x4ef5  c6 03 90        mov byte [rbx], 0x90        ; only if the "single byte" flag is set
0x4ef8  48 ff c3        inc rbx
0x4efb  mov ax, [rsp+0xd8]   ; = 0x3148  (set at 0x4d17)
0x4f08  66 89 03        mov [rbx], ax               ; -> 48 31
0x4f15  66 c7 43 02 c0 c3   mov word [rbx+2], 0xc3c0 ; -> c0 c3
```

so the written sequence is `48 31 C0 C3` (`xor eax,eax; ret`), optionally preceded by a single `0x90`
padding byte. Then `VirtualProtect(…, PAGE_EXECUTE_READ)` at `0x4f26`. Net effect: **if anyone patches
or breaks a hooked function, that function is silently turned into a stub that returns 0** — an
anti-tamper response, not an anti-debug one. (The one `0xfa` byte written at `0x4e13` is a scratch
value on the stack, not part of the fill; the actual fill is `0x90`.)

### 3.7 Top-20 functions decompiled (summaries)

Ranked by interest, not size. All decompiled with `r2 -A -c "s <rva>; pdg"`.

1. **`0x4650` WinMain** (1470 merged) — described in §2.3. Recovered signature
   `int WinMain(HINSTANCE, HINSTANCE, LPSTR, int)`; four `.pdata` fragments; returns −5
   (`0xfffffffb`) when `GetModuleFileNameW` fails, 1 on any load failure, 0 after `Source2Main` returns.
2. **`0x4fe0` `TL_LoadAndInit`** (1985 merged) — §3.4. This is the single largest piece of *launcher*
   logic and the only place the trusted-launch state machine is driven.
3. **`0x5005`** is a fragment of the above, not a separate function; it contains the
   `foreign`/`system`/`steam`/`csgo` registration, the `trustedlaunch.cfg` read/append, the hook
   installation ladder and the state code assignment.
4. **`0x8e7c` `TL_VerifyFile`** (1424 merged) — §3.5.
5. **`0xb290` `TL_ManifestParser`** (1969) — parses the `.signatures` text format. Skips lines not
   starting with `...\` (`cmp dword [rbx], 0x5c2e2e2e` at `0xb2ee`), stops at `\n`/`\r`/`~`/`#`
   (`0xb35b`–`0xb36c`), stores up to 500 records, marks a `#` line as a comment at `+0x12a`, and handles
   the `;`-separated tags. Note the `~` separator between path and hash list.
6. **`0xbdf0` `TL_FormatRecord`** (1613) — the report writer. Emits, in order:
   `"<path>"`, `",SHA1:"` + 20 hex bytes, `",MD5:"` + 16 hex bytes, `",CRC:"` + 4 hex bytes,
   then four single-character status columns (`X`/`E`, `M`/`C`/`N`, `R`/`W`, `K`/`U`/`I`/`S`, `A`/`D`/`P`,
   `V`/`T`/`Y`/`F`), then `",CERT:"`, `",ISS:"`, `",VFL:"`, `",VFR:"`, `",ERR:"`.
   The `"Microsoft Windows"` / `"Microsoft Corporation"` strings at `0x2c0e8`/`0x2c110` are compared
   against certificate subject/issuer names to classify OS-signed binaries.
7. **`0x6530` `TL_HookFunction`** (1717) — §3.6 step 4. Contains the `VirtualProtect`/
   `WriteProcessMemory`/`FlushInstructionCache` triad and the RB-tree insert of the hook record.
8. **`0x6c7b` `TL_UnhookFunction`** (660) — §3.6 step 5; note the sanity check that the first byte is
   still `E9` (`*arg1_00 == -0x17`) and that the jump target still equals the trampoline before
   restoring.
9. **`0x81a0` `TL_ComputeFileSignatures`** (1509) — maps a file, computes SHA-1/MD5/CRC and fills the
   0x140-byte record; uses `GetFileInformationByHandle` for the volume serial + file index (so a file
   moved between volumes is distinguishable).
10. **`0x7950` `TL_HashFile`** (755) — the PE-aware hasher: `MZ`, `PE\0\0`, `0x20b`, `NumberOfSections`,
    `SizeOfOptionalHeader`, `CheckSum`, and a magic check `(uVar13>>0x20 - 0x100) & 0xfeff` that
    accepts only `0x8664` (AMD64) and `0x14c` (I386) machines.
11. **`0x9df0` `TL_AddRecord`** (441) — de-duplicates by name+hash then appends a 0x140-byte record;
    the capacity check `if (*(arg1+0x10) < 500)` is the only hard limit in the parser.
12. **`0xac60` `TL_ReapCheckerThread`** (544) — the asynchronous trust-check completer. Reads
    `GetExitCodeThread` on `db+0x54d78`; if the worker is still active (`0x103`) it returns 1; otherwise
    it folds every record of every manifest, updating `+0x14` (checked), `+0x18` (trusted) and
    `+0x20` (loaded) counters and copying the hash fields into the live records.
13. **`0xba50` `TL_StartCheckerThread`** (405) — `CreateThread` of the per-file verifier; keeps at most
    five pending records in `db+0x151cc`.
14. **`0x6024` `TL_AllocTrampolineNear`** (772) — the ±2 GB allocation dance; the `VirtualQuery` loop
    at `0x6024`–`0x6328` walks memory in `dwPageSize` steps looking for `MEM_FREE` (`0x10000`) pages
    large enough, then `VirtualAllocEx` with `MEM_RESERVE|MEM_COMMIT` (`0x3000`) and
    `PAGE_EXECUTE_READWRITE` (`0x40`).
15. **`0x4c90` `TL_NeutraliseCode`** (700) — §3.6, the VEH's enforcement arm.
16. **`0xd240` + `0xd35d` RSA verification** (3191 + 2599) — DER parse → bignum modexp → PKCS#1 v1.5
    unpad → SHA-1 compare. Verified empirically against the real `.signatures` files (§3.2).
17. **`0x1aa0` `SHA1_Transform`** (5957) — the single largest function in the image; fully unrolled
    80-round SHA-1. `0x1130` (2020) is the MD5 equivalent.
18. **`0x3650` `CRC32` slicing-by-16** (1184) — 16 tables × 256 dwords at `0x34ea0`–`0x38ea0`; the
    table at `0x34ea0` is the standard reflected `0xEDB88320` table (verified programmatically).
19. **`0x3c10` `CPUID feature detection`** (1540) — builds the `_ISA_Available`-style bitmask, reads
    vendor ID (`"AuthenticAMD"`/`"GenuineIntel"`/`"Generic_x86"`/`"Unknown"` at `0x38eb8`–`0x38ed0`),
    SSE4.2 (`+3` bit 3), AVX (`+0xd` bit 5/6), `xgetbv` for XMM/YMM state, and writes the brand string
    to `0x1400bcdf0`.
20. **`0xeeb4` `_invoke_watson`** (328) — the CRT abort path. Worth calling out because a naive
    reading of its `IsDebuggerPresent` import looks like an anti-debug check; it is not. The sequence
    `IsDebuggerPresent` → `SetUnhandledExceptionFilter(0)` → `UnhandledExceptionFilter` →
    conditional `int 3` is the stock MSVC "don't break into a debugger, just die" behaviour.

### 3.8 Other identified functions worth naming

* `0x8dc0` `TL_AddManifest` — the 4-manifest cap.
* `0x9c70` `TL_BuildReport` / `0x98e0` `TL_WriteReportHeader` — the report format (`GXS:` etc.).
* `0x9470` `TL_IsStateReady` — the `+0x44 == 9` gate that all four "Count…" exports and
  `BSecureAllowed` depend on.
* `0x9700` / `0x9860` / `0xab40` / `0xa410` — the four different "how many files" counters.
* `0x94e0` / `0xac60` — thread reapers.
* `0x9570` — per-manifest CRC32 cache in `db+4..db+0x10`.
* `0x4c0e` / `0x4c23` / `0x4c2a` — the three WinMain exits (`"A CPU that supports…"`,
  `return 1`, `return -5`).
* `0x7cc0` / `0x7d21` / `0x7e20` — three copies of the same `CryptCATAdmin*` catalogue-lookup helper
  (the linker emitted the body three times because the C++ inline function was instantiated in three
  TUs and not folded; all three call `0x7cc0`'s logic).
* `0x9d60` `TL_DatabaseCtor` — §1.3.
* `0x55d4` (fragment of `0x4fe0`) — the hook-installation ladder with the `0x44 = 2…9` status codes.

---

## 4. Imports

Two DLLs, 110 functions.

### 4.1 `KERNEL32.dll` — 106 functions

Grouped by what they reveal:

| Group | Functions | What it tells us |
|---|---|---|
| **Dynamic loading** | `LoadLibraryA`, `LoadLibraryExW`, `GetProcAddress`, `GetModuleHandleA`, `GetModuleHandleW`, `GetModuleHandleExW`, `FreeLibrary` | The launcher's entire module strategy is `LoadLibraryExW` with an absolute path + `GetProcAddress`. `LoadLibraryA` is used *only* for `wintrust.dll`/`crypt32.dll` (`0x7ea5`). No import of `engine2.dll`, `client.dll`, … — by design, so the launcher starts without the game. |
| **File I/O** | `CreateFileW`, `GetFileSizeEx`, `SetFilePointer`, `SetFilePointerEx`, `WriteFile`, `FlushFileBuffers`, `CreateFileMappingA/W`, `MapViewOfFile`, `UnmapViewOfFile`, `GetFileInformationByHandle`, `FindFirstFileExW`, `FindNextFileW`, `FindClose`, `GetFileType`, `GetStdHandle`, `SetStdHandle` | Reads and memory-maps the `.signatures` files and every DLL it hashes; writes the trusted-launch report. `FindFirstFileExW` is CRT directory iteration. |
| **Environment / command line** | `GetEnvironmentVariableA/W`, `SetEnvironmentVariableW`, `GetCommandLineA/W`, `GetEnvironmentStringsW`, `FreeEnvironmentStringsW` | Steam's `SteamPath`/`SteamAppId`/`Steamid`/`SteamUserDataFolder` protocol, and the `Source2Launcher=1` marker. |
| **Process/thread** | `CreateThread`, `OpenThread`, `GetExitCodeThread`, `GetThreadId`, `GetCurrentThreadId`, `GetCurrentProcessId`, `GetCurrentProcess`, `TerminateProcess`, `ExitProcess`, `CreateMutexA`, `ReleaseMutex`, `WaitForSingleObject` | The asynchronous trust-check worker (`0xba50`) and the hook-map mutex. `OpenThread` exists only to reap workers that already exited (`0x94e0`). |
| **Memory** | `VirtualAlloc`, `VirtualAllocEx`, `VirtualProtect`, `VirtualQuery`, `WriteProcessMemory`, `HeapAlloc`, `HeapFree`, `HeapReAlloc`, `HeapSize`, `GetProcessHeap` | `VirtualAllocEx` + `WriteProcessMemory` are here for the *self*-patching hooks (target = `GetCurrentProcess()`), not for process injection. |
| **Exception / unwind** | `AddVectoredExceptionHandler`, `UnhandledExceptionFilter`, `SetUnhandledExceptionFilter`, `RaiseException`, `RtlCaptureContext`, `RtlLookupFunctionEntry`, `RtlVirtualUnwind`, `RtlUnwindEx`, `RtlPcToFileHeader`, `EncodePointer` | VEH for the anti-tamper stub (`0x58b0`); the rest is stock MSVC C++ EH and `_invoke_watson`. |
| **Sync primitives** | `InitializeCriticalSection`, `InitializeCriticalSectionAndSpinCount`, `EnterCriticalSection`, `LeaveCriticalSection`, `DeleteCriticalSection`, `InitializeSListHead` | Guarding the record array (`db+0x546f0`) and the hook map (`0x140218b68`). |
| **Locale / console (CRT)** | `MultiByteToWideChar`, `WideCharToMultiByte`, `CompareStringW`, `LCMapStringW`, `GetStringTypeW`, `IsValidCodePage`, `GetACP`, `GetOEMCP`, `GetCPInfo`, `WriteConsoleW`, `GetConsoleMode`, `GetConsoleOutputCP`, `OutputDebugStringA`, `FormatMessageA` | All UTF-8↔UTF-16 conversion (the manifests are UTF-8, Win32 is UTF-16) plus UCRT initialisation. |
| **TLS/FLS (CRT)** | `TlsAlloc/GetValue/SetValue/Free`, `FlsAlloc/GetValue/SetValue/Free` | UCRT per-thread data. |
| **Diagnostics** | `GetLastError`, `SetLastError`, `IsDebuggerPresent`, `IsProcessorFeaturePresent`, `GetSystemInfo`, `GetSystemTimeAsFileTime`, `QueryPerformanceCounter`, `GetStartupInfoW`, `GetModuleFileNameW`, `GetSystemDirectoryW`, `GetWindowsDirectoryW` | `IsProcessorFeaturePresent` is used for `PF_XSAVE_ENABLED` (0x17) and the SSE/AVX dispatch. `GetSystemDirectoryW`/`GetWindowsDirectoryW` are used to extend the `system.signatures` search path (`0x5005`). |

### 4.2 `USER32.dll` — 4 functions

`MessageBoxA`, `MessageBoxW`, `wsprintfA`, `wsprintfW`.

That is *all* of USER32. The launcher has **no window, no message loop, no dialog API, no
`LoadImage`/`LoadBitmap`** — it never displays the 2 MB bitmap resource it carries. Every USER32 call is
either a fatal-error box (`0x44e0`, `0x937d`) or string formatting (`0x46c8`, `0x5005`, `0xaec4`,
`0xafc7`).

### 4.3 What the import set implies

* **No networking** (`ws2_32`), **no registry** (`advapi32`), **no COM/OLE**, **no DirectX/Vulkan**, **no
  audio**. The launcher cannot phone home, cannot read `HKLM\Software\Valve`, and cannot render. All of
  that is deferred to `engine2.dll` and friends.
* **No `CreateProcess`/`ShellExecute`.** The launcher does not spawn the game — it *becomes* the game by
  calling `Source2Main` in-process. This is why the process name in Task Manager stays `cs2.exe`.
* **No `dbghelp`, no `NtQueryInformationProcess`, no `CheckRemoteDebuggerPresent`.** There is no
  anti-debug capability beyond the CRT's stock `IsDebuggerPresent`.
* **No `advapi32`** means the catalogue-based signature verification must go through
  `wintrust.dll`/`crypt32.dll` loaded at runtime — which is exactly what `0x7ea5` does. That is a
  deliberate choice: a static import of `WinVerifyTrust` would show up in the import table and make the
  binary look like an installer; loading it lazily keeps the import table to two DLLs.
* **`VirtualAllocEx` + `WriteProcessMemory` + `FlushInstructionCache` + `VirtualProtect`** in a binary
  with no `CreateProcess` can only mean self-modification — confirmed by §3.6.
* **`GetSystemDirectoryW` + `GetWindowsDirectoryW` + `CryptCATAdmin*`** identify the "system signature"
  database: the launcher verifies that OS DLLs loaded into the game process are the ones Microsoft
  shipped.

---

## 5. Exports

The export directory (`0x3c230`, DLL name `cs2.exe`) has **7** entries. Five are code, two are data.

| Ordinal | RVA | Name | Kind |
|---|---|---|---|
| 1 | `0xbcde8` | `AmdPowerXpressRequestHighPerformance` | data (DWORD = 1) |
| 2 | `0x4c80` | `BSecureAllowed` | code thunk → `0x57b0` |
| 3 | `0x4c60` | `CountFilesCompletedTrustCheck` | code thunk → `0x4f50` |
| 4 | `0x4c50` | `CountFilesNeedTrustCheck` | code thunk → `0x4f70` |
| 5 | `0x4c70` | `CountItemsToReport` | code thunk → `0x4f80` |
| 6 | `0x4c40` | `GetTotalFilesLoaded` | code thunk → `0x4fd0` |
| 7 | `0xbcde4` | `NvOptimusEnablement` | data (DWORD = 1) |

### 5.1 `NvOptimusEnablement` (`0xbcde4` = 1) and `AmdPowerXpressRequestHighPerformance` (`0xbcde8` = 1)

These are **not code**. They are the two well-known *driver hint* exports that NVIDIA Optimus and AMD
PowerXpress look up in the main executable of a process:

* `NvOptimusEnablement = 1` → "render on the discrete NVIDIA GPU".
* `AmdPowerXpressRequestHighPerformance = 1` → "request the high-performance AMD GPU".

Their presence in a launcher is deliberate: because the launcher becomes the game process, the
driver's per-process GPU selection is decided from *this* image's export table. Exporting the two
DWORDs here guarantees that the game gets the discrete GPU even though the actual D3D/Vulkan device is
created in `rendersystemdx11.dll` / `rendersystemvulkan.dll`.

Both values are exactly `1` (`75 98 00 00 | 01 00 00 00 | 01 00 00 00` at `0xbcde0`), which is the
documented "enable" value. They are the only writable exports; nothing in `.text` references them.

### 5.2 `GetTotalFilesLoaded` (`0x4c40` → `0x4fd0`)

```
0x4c40  jmp 0x4fd0
0x4fd0  mov eax, [0x14003d078]
0x4fd6  ret
```

A 7-byte leaf function (no `.pdata` entry, because it has no stack frame). It returns a DWORD at
`0x14003d078`, i.e. `db+0x78`. That field is incremented in `0x8e7c` (`*(arg1+0x78)++` after a successful
`0x9df0`), so it is the **number of files recorded into the trusted-launch database**. However,
**nothing in the image writes `0x14003d078` except `0x8e7c`**, and `0x8e7c` is only reachable through
the `NtOpenFile` detour — so in a launcher run that never loads a game DLL the export returns `0`. It is
also the only counter that is *not* re-derived from the manifests, which is why it can disagree with
`CountFilesCompletedTrustCheck`.

### 5.3 `CountFilesNeedTrustCheck` (`0x4c50` → `0x4f70` → `0x9700`)

```
0x4c50  jmp 0x4f70
0x4f70  lea rcx, [rip+0x38089]      ; rcx = 0x14003d000
0x4f77  jmp 0x9700
```

`0x9700` (`TL_CountCheckedFiles`, 334 bytes) walks the registered manifests:

```
if (!db->manifest[3] || !db->manifest[1]) return 0     ; +0xd8 / +0xd0 must be non-NULL
for (i = db->count-1; i >= 0; i--) {
    rec = db->obj[i]
    if (!already_seen) { already_seen = 0xac60(rec, &flag); }   ; thread/exit-code reap
    total += rec->0x14                                          ; per-manifest counter
    if (flag) db->crc[i] = 0xab10(rec)                          ; refresh checksum
}
if (rec->0x18 < 4) { 0xba50(...); if (ok) 0xba50(...); ... }     ; kick the checker thread
for (i = count-1; i >= 0 && total < 4; i--) total += 0xa410(db->obj[i], 1)
return total
```

Semantics: **the number of files for which a trust check has been started** (sum of the per-manifest
`+0x14` counters, which `0xac60` increments once per matched record), plus a fallback pass over
`0xa410` (pending records) when fewer than 4 were seen. It also has the side effect of reaping the
checker thread and refreshing each manifest's CRC32.

### 5.4 `CountFilesCompletedTrustCheck` (`0x4c60` → `0x4f50`)

```
0x4c60  jmp 0x4f50
0x4f50  sub rsp,0x28; lea rcx,[0x14003d000]; call 0x9700      ; refresh + reap
0x4f60  lea rcx,[0x14003d000]; add rsp,0x28
0x4f6b  jmp 0x9860
```

`0x9860` (`TL_CountLoadedFiles`, 127 bytes) is a simple sum of each manifest's `+0x20` field:

```
sum = 0; for (i = 0; i < db->count; i++) sum += db->obj[i]->0x20; return sum
```

`+0x20` is incremented once per record in `0xac60`, so this is the **total number of files that have
been fully recorded in the database** (i.e. hashed and matched to a manifest entry). Because it first
runs `0x9700`, the answer is fresh at the moment of the call.

### 5.5 `CountItemsToReport` (`0x4c70` → `0x4f80`)

```
0x4f80  if (!0x9470(db)) return 1;         ; not initialised → sentinel 1
0x4f9e  0x9700(db);                        ; refresh counters + CRC
0x4faa  0x94e0(0x1400bc178);               ; reap the thread table
0x4fb6  sum = 0; for (i = 0; i < db->count; i++) sum += 0xab40(db->obj[i]);
0x4fc1  return sum;
```

`0xab40` (`TL_CountReportable`, 278 bytes) is the per-manifest predicate that mirrors the record
classification used by `0xbdf0`: for each 0x140-byte record it returns 1 when the record is "unsigned or
mismatched" (the `0x80092003` = `CRYPT_E_NO_MATCH` special case at `0xaba2` is checked explicitly, and
`0x2c0e8`/`0x2c110` = `"Microsoft Windows"`/`"Microsoft Corporation"` are matched to whitelist OS
binaries). So this export answers **"how many files would appear in the trusted-launch report"** —
and returns the sentinel `1` if the trusted-launch machinery never initialised.

### 5.6 `BSecureAllowed` (`0x4c80` → `0x57b0`)

```
0x57b0  if (n > 0 && buf != NULL) { *buf = 0; 0x9c70(db, buf, n, flag); }
0x57d6  return 0x9470(db);            ; → AL
```

`0x9c70` (`TL_BuildReport`, 133 bytes) builds the text report into the caller's buffer:
`arg3 -= 0x50`, then for each manifest `0xbdf0(obj, buf, len, &len)`, then `0x98e0(db, buf, len)`
appends the `GXS:`/`;TFL:`/`;TFC:`/`;TAS:`/`;FAS:`/`;PVC:`/`;DTR:`/`;DTF:`/`;SWD:` trailer. The `0x50`
reservation is the space needed for that trailer.

The **return value** is the security verdict: `0x9470` returns 1 only when all four manifests loaded
(`+0x24==1 && +0x28==1`), the two optional states are in range (`+0x2c`, `+0x30` ∈ {1,2}) and the
init ladder reached stage 9 (`+0x44 == 9`, i.e. the VEH is installed). So:

> `BSecureAllowed(buf, n, flag)` = "is the trusted-launch subsystem fully operational? If you gave me a
> buffer, here is the human-readable report."

This is the export a game DLL or an anti-cheat module would call to find out whether it may trust the
process. Note that it returns **false** when the user launched with `-insecure`, because `0x9640` fails
to validate the manifests in that state (`desired == 0` short-circuits `actual = 0`, so `+0x44 = 1`).

---

## 6. The `.data` anomaly: 1.95 MB virtual vs 512 KB raw

```
.data  RVA 0x3d000   VirtualSize 0x1dcea0 (1,953,440)   SizeOfRawData 0x80000 (524,288)   entropy 0.03
```

Virtual size is **3.7×** the raw size, and the file-backed portion is almost entirely zeros. A byte
scan of the 524,288 raw bytes finds only **845 non-zero bytes**, in exactly two clusters:

| RVA range | Bytes | Content |
|---|---|---|
| `0x3d000`–`0x3d003` | 4 | `17 53 23 16` = `0x16235317` |
| `0x3d0b8`–`0x3d0bb` | 4 | `a5 59 1e 3c` = `0x3c1e59a5` |
| `0xbc028`–`0xbc05c` | 53 | pointer table: `0x14003d0e8` ×2, `0x14007c888`, `0`, `0x14007c888` ×2, `0x1400bc028` (self-pointer) |
| `0xbc170`–`0xbc177` | 8 | `0xffffffffffffffff` (= `db+0x7f170`, the report file handle, initialised to `INVALID_HANDLE_VALUE`) |
| `0xbc300`–`0xbc343` | 68 | `CryptCATAdminAcquireContext2` state (hash algorithm handle etc.) |
| `0xbc380`–`0xbc385` | 6 | `__security_cookie` = `0x2b992ddfa232` (default, replaced at startup) |
| `0xbc3c0`–`0xbc3d3` | 20 | `__security_cookie_complement` and GS handler pointers |
| `0xbc4f0`–`0xbc504`, `0xbc538`–`0xbc57c`, … | ~200 | UCRT locale/heap/`_onexit` tables, `std::_Tree` sentinels |
| `0xbc6b8`–`0xbc6c8`, `0xbc72a`–`0xbc763`, `0xbc82a`–`0xbc863`, `0xbc942`–`0xbc97b`, `0xbca51`–`0xbca8a` | 5 × 58 | case-mapping tables for the locale (`_tolower`/`_toupper` 256-byte tables, 26 lower + 26 upper entries) |
| `0xbcb10`–`0xbcb58`, `0xbcb70`–`0xbcb88`, `0xbcba0`–`0xbcbbe`, `0xbcbd0`–`0xbcbee`, `0xbcc00`–`0xbccb3` | ~400 | more UCRT tables (codepage, `_pctype`, `_wctype`) |
| `0xbcd80`–`0xbcf16` | 407 | RTTI type descriptors (`unknown`, `.?AVexception@std@@`, `.?AVbad_alloc@std@@`, …, `.?AVtype_info@@`), `std::_Tree` node pools |

So the *initialised* portion of `.data` is only the last ~4 KB of the raw region plus the first 0xC0
bytes. Everything between `0x3d004` and `0xbc027` is file-backed zeros, and **everything from
`0xbd000` to `0x219ea0` (1,428,128 bytes) is not in the file at all** — it is `MEM_COMMIT`ed by the
loader as zero pages.

### 6.1 What lives in the zero-filled region

The `.data` region is, in effect, five large **global objects** plus their scratch buffers. Their bases
are fixed by the CRT static initialisers (§1.3) and by `TL_LoadAndInit`:

| Base RVA | Size | Object |
|---|---|---|
| `0x3d000` | `0x7ff40` (to `0xbcf40`) | **Primary trusted-launch database** (`db`) — the one all exports use. Contains the 0x54d80 common layout **plus** the 0x7f028 bump arena and 0x7f068 report buffer |
| `0xbcf40` | `0x54d80` | Manifest object **B** (`steam.signatures`, kind 2) |
| `0x111cc0` | `0x54d80` | Manifest object **A** (`csgo.signatures`, kind 1) |
| `0x166a40` | `0x54d80` | Manifest object **D** (`foreign.signatures`, kind 1) |
| `0x1bb7c0` | `0x54d80` | Manifest object **C** (`system.signatures`, kind 1) |
| `0x210540` | `0x8600` | 64-slot "modules loaded by the launcher" table used by the hooks (64 × 0x218 = 0x8600 exactly) |

The four secondary manifest objects are exactly `0x54d80` apart
(`0xbcf40 + 0x54d80 = 0x111cc0`, `0x111cc0 + 0x54d80 = 0x166a40`, `0x166a40 + 0x54d80 = 0x1bb7c0`,
`0x1bb7c0 + 0x54d80 = 0x210540`), which matches the size passed to the checksum routine (`0xab10` CRCs
`0x54d80` bytes per object) and the `InitializeCriticalSection` offset inside the constructor
(`+0x546f0`). The primary instance is 0x7ff40 long — the same 0x54d80 common prefix, then 0x2aa80 of
extra per-primary state (arena, report buffer, report handle, module table pointer). Its internal layout,
recovered from `0x9d60`, `0x8dc0`, `0x9df0`, `0xa350`, `0xac60` and `0x8e7c`:

```
+0x000  DWORD  magic 0x16235317                 (only in the primary instance)
+0x004  DWORD  crc[0..3]        (0x9570: per-manifest CRC32)
+0x014  DWORD  checkedCount[0..3]  (0xac60: +1 per matched record)
+0x020  DWORD  loadedCount[0..3]   (0xac60: +1 per matched record)
+0x024  DWORD  manifestOk[0..3]    (0x9640: result of 0xae80/0xaf90)
+0x034  DWORD  manifestCount       (0x8dc0: max 4)
+0x038  DWORD  primaryIndex        (0x8dc0: index of the manifest registered with flag 1)
+0x03C  DWORD  actualState         (0x96f0)
+0x040  DWORD  desiredState        (0x96f0)
+0x044  DWORD  initStatus          (1 = no manifests, 2..9 = ladder stage, 9 = ready)
+0x078  DWORD  recordedFiles       (0x8e7c; read by GetTotalFilesLoaded)
+0x07C  DWORD  failedFiles         (0x8e7c)
+0x0B8  DWORD  magic2 0x3c1e59a5
+0x0C0  void*  obj[4]              (0x8dc0: the four manifest objects)
+0x0D0  void*  checkerA, +0x0D8 checkerB   (0x9700 gate)
+0x2B0  0x140-byte record[500]     (0x9df0; capacity 500)
+0x273B0 wchar_t baseDir[260]      (0xbbf0)
+0x275B8 DWORD   baseDirLen
+0x275BC wchar_t baseDir2[260]
+0x277C4 DWORD   baseDir2Len
+0x4F8C8 DWORD   publisherCount
+0x4F8CC DWORD   publisherCapacity
+0x4F8D0 200-byte publisher[100]   (0xa350; zeroed by 0x9d60 for 0x4e20 bytes)
+0x546F0 CRITICAL_SECTION recordLock
+0x54718 void*   arena
+0x54720 BYTE    "all done" flag
+0x54728 DWORD   pendingCount
+0x54D70 void*   threadTable       (0xbd80; 0x1400bc178 for the primary)
+0x54D78 HANDLE  checkerThread     (initialised to -1)
+0x54D80 --- end of the common layout
```

The primary instance additionally carries the report scratch area and its bump allocator beyond the
common layout:

```
+0x7F028 arena/bump allocator     (0xbc028; 0x9df0 → 0x88a0 → 0x96d0)
+0x7F068 char reportLine[0x100]   (0x8e7c)
+0x7F16C DWORD reportLineLen
+0x7F170 HANDLE reportFile        (initialised to -1 at 0xbc170)
+0x7F2FC DWORD showMessageBoxOnFailure
```

That is why `db+0x7f170` lands exactly on the initialised `0xffffffffffffffff` at `0xbc170` — the file
confirms the field's initial value, and `0x8e7c`'s `if (*(arg1 + 0x7f170) != -1)` confirms its meaning.

### 6.2 Why the linker produced this shape

The launcher is a single-threaded, small-footprint program with four *fixed-size, statically allocated*
databases of 340,864 bytes each (`0x54d80`) — one per signature manifest — plus 20 KB of publisher
allow-list and 160 KB of record array, and one larger primary instance of 524,096 bytes (`0x7ff40`).
None of it can be `const` (it is filled at runtime), and none of it is initialised to anything other
than zero, so the linker emits it as uninitialised data: raw size covers only the initialised tail, and
`VirtualSize` covers the whole BSS. The 0.03 entropy of the section is the giveaway — a normal `.data`
with vtables and strings would be 4–6.

Two practical consequences:

1. **`SizeOfImage` is dominated by BSS.** 4.39 MB of virtual image for a 170 KB code section.
2. **The file is dominated by the bitmap.** `2,076,042` of the `2,967,704` bytes (70 %) is the
   `RT_BITMAP` resource 1002 — a 922 × 750, 24 bpp image. It is the launcher's splash/background
   artwork and, as noted, **no code in the binary ever loads it** (no `LoadImage`, no `LoadBitmap`,
   no `FindResource` import). It is almost certainly kept for the `-retail`-style branded error dialog
   that the *engine* can show after the launcher hands over.

### 6.3 Resource inventory (context for the size)

| Type | ID | Lang | Size | Content |
|---|---|---|---|---|
| `RT_BITMAP` (2) | 1002 | 1033 | 2,076,042 | `BITMAPINFOHEADER` 40 bytes, 922×750, 24 bpp, `BI_RGB` |
| `RT_DIALOG` (5) | 103 | 1033 | 160 | DLGTEMPLATE, `MS Shell Dlg` 8pt, 310×230, 3 items (a message-box-shaped template) |
| `RT_ICON` (3) | 1–8 | 1033 | 1,384–67,624 | 8 icon images (16×16 … 128×128, 8/32 bpp) |
| `RT_GROUP_ICON` (14) | 101 | 1033 | 118 | icon group |
| `RT_MANIFEST` (24) | 1 | 1033 | 1,281 | `asInvoker`, `PerMonitorV2`, `SegmentHeap`, Win10/11 GUID |
| `AFX_DIALOG_LAYOUT` | 103 | 1033 | 2 | MFC dialog layout stub |
| **`RT_VERSION` (16)** | — | — | — | **absent** |

The absence of a version resource is notable: `cs2.exe` has no `FileVersion`, `ProductName` or
`CompanyName`. This is consistent with a build-system-generated shim rather than a shippable product.

The manifest (`0x430148`) requests `asInvoker` (no UAC elevation), `PerMonitorV2` DPI awareness and
`SegmentHeap`, and declares support for the Windows 10/11 GUID
`{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}`.

---

## 7. Integrity, signature and anti-tamper checks

There is **no anti-debug code**. What exists is an elaborate *integrity* subsystem, and it is the reason
this binary is 170 KB of code.

### 7.1 Authenticode on itself

* The image carries a real Authenticode signature (`SECURITY` directory, 11,416 bytes, no overlay).
* The PKCS#7 blob contains six certificates: DigiCert Assured ID Root CA → DigiCert Trusted Root G4 →
  DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1 → **`C=US, ST=Washington, L=Bellevue,
  O=Valve Corp., CN=Valve Corp.`** (valid 2024-10-12 → 2027-10-08), plus the DigiCert timestamp chain
  and a 2026 timestamp responder.
* The `SpcIndirectData` digest is **SHA-256** and it **matches the file**: recomputing the
  Authenticode hash (zero `CheckSum`, zero the `SECURITY` directory entry, hash everything before the
  certificate table) gives
  `B316E274835D8F619C8C80147BBDBECD60AE564C72D650CA34F3EC7E0E6541CA`, identical to the value embedded in
  the signature. The signature is therefore intact, not just present.
* The signing time (`2026-10-14 18:37:43Z`) is 11 seconds after the PE `TimeDateStamp`
  (`2026-10-14 18:37:32Z`) — an automated build+sign step.

Note that `pefile`'s `signed` heuristic reports `False`; that is a pefile limitation, not evidence of an
unsigned binary. The directory and the PKCS#7 both parse, and the digest verifies.

### 7.2 The `.signatures` manifest chain (the real integrity system)

`cs2.exe` ships with four text manifests and a 4096-bit RSA key embedded in `.rdata`:

| File | Entries | Verified with | Result |
|---|---|---|---|
| `csgo.signatures` | 111 files + `DIGEST:` | key @ `0x2bc90` (e=17) | SHA-1 `9d025306…` ✓ |
| `foreign.signatures` | 12 files + `DIGEST:` | key @ `0x2bc90` | SHA-1 `66b99fcf…` ✓ |
| `system.signatures` | 4 `AUTH:` lines + `DIGEST:` | key @ `0x2bc90` | SHA-1 `d70b9af6…` ✓ |
| `steam.signatures` | *(absent from this install)* | key @ `0x2bec0` | n/a |

The chain, as implemented:

1. `0xb060` maps the file, `0xb290` parses the lines into 0x140-byte records.
2. The trailing `DIGEST:` line is base64-free hex; `0xe3d0` → `0xdec0` → `0xd240` → `0xd35d`
   performs **RSA PKCS#1 v1.5 verification with SHA-1** over the file text preceding `DIGEST:`.
3. `0xb1d5`/`0xb1e2` select the key by `obj->0x2ac`: `1` → `0x2bc90` (Valve), `2` → `0x2bec0` (Steam).
4. Only if that succeeds does `0x9640` consider the manifest "loaded", which is what gates
   `+0x44 = 9` and therefore `BSecureAllowed`.

I confirmed step 2 independently: the recovered PKCS#1 block is `00 01 ff ff …` with
`DigestInfo = 30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14 || SHA1`, and the embedded SHA-1 equals
`SHA-1(text before "DIGEST:")`. The exponent is **17** (not 65537) — unusual, and a useful fingerprint
for identifying this key family.

Each manifest entry also carries a `CRC:` (CRC32) and, for `foreign`/`system`, `SIGN:`/`ISS:` SHA-1
pairs. `0xa350` compares a file's SHA-1/issuer triple against the 100-entry, 200-byte allow-list at
`db+0x4f8d0`; `0x8170` calls `WinVerifyTrust` for the actual Authenticode check; `0x7950`/`0x81a0`
compute SHA-1 + MD5 + CRC32 for the record.

### 7.3 Runtime enforcement

* **`NtOpenFile` detour (`0x5b00`)** — refuses read+execute opens of files that fail
  `TL_VerifyFile`, returning `STATUS_OBJECT_NAME_NOT_FOUND`. This is what stops an unsigned DLL from
  being mapped into the game process at all.
* **`LoadLibraryExW` detour (`0x5920`)** — records every module the launcher loads into the 64-slot
  table at `0x140210540`, so the VEH can later recognise and neutralise code in those ranges.
* **VEH (`0x58b0`) + `TL_NeutraliseCode` (`0x4c90`)** — if a tracked function takes an access violation
  or executes an `int3`, the handler fills the containing page with `0x90` (`NOP`), writes
  `48 31 C0 C3` (`xor eax,eax; ret`) over the fault address, and resumes. Practical effect: **you cannot
  patch the hooks; if you try, the function silently starts returning 0.**
* **Hook-integrity check on removal** — `0x6c00` verifies that the first byte is still `E9` and that the
  rel32 still points at the trampoline before restoring the original prologue; otherwise it leaves the
  patch in place.
* **`trustedlaunch.cfg` audit trail** — `0x5005` appends
  `"%d,%d,%d,0x%x,0x%x\n"` (desired state, desired state, `GetCurrentProcessId()`,
  `GetSystemTimeAsFileTime` hi/lo) to `<userdata>\cfg\trustedlaunch.cfg` on every launch with
  `-trusted`/`-allow_third_party_software`, and the failing-file report is appended to the same file
  via `db+0x7f170`.

### 7.4 What is *not* there

* No `IsDebuggerPresent`-based branching. The single import site (`0xeeb4`, `0x19f5c`) is the MSVC
  `_invoke_watson` path: "if a debugger is attached, don't `int3`; otherwise `int3`". That is *less*
  hostile than typical anti-debug code.
* No timing checks (`QueryPerformanceCounter` is used only to seed the cookie).
* No `NtQueryInformationProcess`, no `ThreadHideFromDebugger`, no PEB walks, no `int 0x2d`, no
  `cpuid`-hypervisor detection.
* No self-CRC. The image does not hash its own `.text`; only the Authenticode signature (verified by
  the OS loader, not by the program) protects it.
* No `GUARD_CF`. `DllCharacteristics` lacks `0x4000`, `GuardCFFunctionTable`/`Count` are 0, and
  `__guard_check_icall_fptr` (`0x14002b380`) points at `0x9630`, which is a bare `ret` — CFG is declared
  (`GuardFlags = 0x100`, `IMAGE_GUARD_CF_INSTRUMENTED`) but **not enforced**.
* No `TerminateProcess` on verification failure. Failures are reported, logged, and (for DLL loads)
  turned into `STATUS_OBJECT_NAME_NOT_FOUND`; the launcher itself keeps running.

---

## 8. Things I could not determine

Stated explicitly rather than guessed:

1. **The two 32-bit magic values** at `db+0x00` (`0x16235317`) and `db+0x0b8` (`0x3c1e59a5`). Nothing in
   `.text` reads them by absolute address; they are either written via pointer arithmetic I did not
   trace, or they are build-stamped identifiers. I could not establish their purpose.
2. **The exact semantics of `+0x14` vs `+0x20` vs `+0x18`** inside a manifest object. I know each is
   incremented once per matched record in `0xac60` (with `+0x18` gated on `record[?] == 0`), and I know
   which export reads which, but I could not determine what distinguishes a "+0x14" file from a
   "+0x20" file beyond "check started" vs "recorded".
3. **The `0x7f028` arena's real owner.** The offset is only meaningful for the primary database
   (`0x3d000 + 0x7f028 = 0xbc028`, which is where the initialised pointer block lives). For the four
   0x54d80-sized manifest objects the same offset would fall outside the object, so either they never
   use it or they allocate it dynamically. I did not find the code path that distinguishes the two.
4. **The `0x2b3b8` `.CRT$XC*` table's exact ordering contract** beyond "these are the static
   initialisers"; the four `TL_DatabaseCtor` calls are unambiguous, but I did not prove the relative
   order of `0x10a0`/`0x1060`/`0x10d0` matters.
5. **`0xd35d`'s exact bignum algorithm.** I verified the *result* (PKCS#1 v1.5 SHA-1 verifies) but did
   not fully reconstruct the limb representation used by `0xe0f0`/`0xe230`.
6. **The purpose of the 2 MB bitmap.** No code path in `cs2.exe` loads it. Whether the engine picks it
   up by resource ID after the handover, or it is dead weight from a shared VPC project, is not
   determinable from this binary alone.
7. **`0x7cc0` / `0x7d21` / `0x7e20`** are three byte-identical copies of the same catalogue-lookup
   function. I did not determine whether the duplication is an `inline`-in-three-TUs artefact or three
   genuinely different call sites that the linker failed to fold; the three bodies reference the same
   `.data` slots (`0x140218c38`–`0x140218c70`).

---

## 9. Summary of the architecture

```
cs2.exe (source2launcher)
│
├── CRT (stock MSVC 14.40) ................ 0xea60 entry, 0xe8ec scrt main, 0xed98 cookie
├── WinMain ............................... 0x4650–0x4c0e
│    ├── Steam env / -steampath ........... 0x46c8
│    ├── trust state from argv ............ -insecure / -trusted /
│    │                                      -allow_third_party_software / -tools
│    ├── trusted-launch init .............. 0x4fe0 (TL_LoadAndInit)
│    │    ├── 4 manifests ................. csgo / steam / foreign / system
│    │    ├── RSA-4096 PKCS#1 SHA-1 ....... 0x2bc90 (Valve), 0x2bec0 (Steam), e = 17
│    │    ├── Authenticode via wintrust ... 0x7ea5, 0x8170
│    │    └── 3 inline hooks + VEH ........ NtOpenFile, LoadLibraryExW, PeekMessageW
│    ├── SSE4.2 check ..................... 0x3c10
│    ├── load tier0.dll by absolute path .. 0x4220
│    └── Source2Main(…, "csgo") ........... engine2.dll!0x2111e0
│
├── crypto ................................ MD5 0x1130, SHA-1 0x1aa0, CRC32 0x3650, RSA 0xd35d
├── .data ................................. 1.95 MB BSS: 4 × 0x54d80 + 1 × 0x7ff40 databases + 0x8600 module table
└── .rsrc ................................. 2.08 MB bitmap (unused by this binary) + icons + manifest
```

The design intent is clear: **`cs2.exe` is the trust anchor of the CS2 process.** It runs first, proves
that the installation is intact (signed manifests + Authenticode on every DLL), then installs three
detours so that no unsigned code can be loaded after it, and finally transfers control to
`engine2.dll!Source2Main` *in the same process*. The two GPU exports exist so the driver selects the
discrete GPU for the process that is about to become the game. Everything else in the file — the 1.95 MB
of BSS, the MD5/SHA-1/CRC32/RSA implementations, the wintrust/crypt32 plumbing, the hook engine — exists
to support that one decision.
