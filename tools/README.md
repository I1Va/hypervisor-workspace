# Detection probes

Small C++ probes that report the *quantity* a detection measures, rather than the
boolean VMAware prints. They exist because "TRAP fires" does not say why, and a
probe that reports `DR6`, a trap offset, or a latency ratio turns a session of
guessing into one command.

They live here because they are manual diagnostics a human runs by hand. The
daemon does not read this directory (see `database/policies/repository.md`).

| Probe | Answers |
|---|---|
| `ish.cpp` | `INTERRUPT_SHADOW` trap offset (must be 18, not 19); `TIMER`'s two ratios — CPUID/LFENCE (limit 2.75) and `#DB`/`ZwRaiseException` (limit 2.5) |
| `dr2.cpp` | whether a `#DB` loses `DR6` in hardware or in the `CONTEXT` Windows builds, by taking three readings inside one handler |
| `exc.cpp` | per-exit cost: `cpuid`, `vmcall`, `rdtsc`, `lfence` against a cross-core software counter |
| `hvx.cpp` | every gate VMAware's `hyper_x()` evaluates, and the real `tbs.dll` TCG-log result |
| `trapdb.cpp` | the exact `DR6` for five `#DB` cases (`trap`, `trap_only`, `dr0_only`, `icebp`, `cpuid_tf`) |
| `tfprobe.cpp` | `TF` and `DR0` single-shot counters with `DR6` |
| `kd3.cpp` | `KernelDebuggerEnabled` via `NtQuerySystemInformation(35)` — do not trust `KUSER_SHARED_DATA` offsets on this build |
| `topo2.cpp` | topology as the CPU database expects it |
| `par.cpp` | parallel speedup, for confirming the APs really run |

## Building and running

The guest has VS2022 but no developer prompt in an SSH session, so `vcvars64.bat`
must be called explicitly:

```powershell
$vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
$vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
cmd /c "call `"$vs\VC\Auxiliary\Build\vcvars64.bat`" >nul && cl /nologo /std:c++17 /EHsc /O2 probe.cpp"
```

Copy the file to the guest first. `scp -O` and `sftp` do not work against this
guest, so the working pattern is a host HTTP server plus
`(New-Object Net.WebClient).DownloadFile(...)`, verifying md5 raw-to-raw.

## Reading the results

- `ish shadow` → `ip_off` must be **18**. `19` means the interrupt shadow
  survived one instruction past the emulated CPUID.
- `ish timer` → the CPUID/LFENCE ratio cannot be brought under 2.75: CPUID exiting
  is CPU-mandatory on this CPU. See `database/hv/cpuid-exiting-floor.md`.
- `dr2 tf` vs `dr2 dr0` → the discriminator. A TF `#DB` reports `DR6=0x0` in both
  the `CONTEXT` and a fresh `GetThreadContext` (hardware genuinely empty); a DR0
  `#DB` reports `0xFFFF0FF1` (hardware set B0). That split is what located the
  TRAP problem, and what proved `#DB` interception makes it worse.
