---
topic: hypervisor-architecture
kind: reference
updated: 2026-11-08
see: [hvlog, detection-status, silent-root-mode-livelock]
---

# Hypervisor architecture

`PulverizedDXE` is a UEFI DXE driver that loads during boot and virtualises the
machine from that point on. It is not a hosted hypervisor: there is no host OS,
the firmware itself runs under VMX once `VMLAUNCH` succeeds.

Source: `hypervisor/efi-superrepo/PulverizedPkg/Sources/`.

## Boot sequence

| Stage | What happens |
|---|---|
| `HostPrep.c` | Enables VMX, builds EPT identity map, allocates per-core state |
| `VmxHypervisor.c` | Per core: VMCS setup, control fields, `VMLAUNCH` |
| `Pulverized.c` | DXE entry, installs the hypercall interface, arms the heartbeat |
| `Hypervisor.c` | Handles `ExitBootServices`: drops boot services, switches logging |

Per-core initialisation runs on each logical processor: the VMCS is loaded, the
GDT is dumped for reference, control MSRs are programmed, then `VMLAUNCH`. If a
field cannot be enabled the effective value is printed — "not all requested VM
control fields are enabled" is normal, not an error. Setup explicitly initializes
all three unused VM-entry/exit MSR-list counts to zero and aborts on a failed
write; clearing or zeroing VMCS backing memory does not initialize its fields.

## Exit dispatch

`Vmx/VmxExitHandlers.c` is the hot path. Every VM exit lands in `VmExitHandler`,
which dispatches on the basic exit reason.

Two rules make this file dangerous to change:

1. **A handler that never returns wedges the CPU silently.** The guest stops,
   but nothing is printed unless the handler logs on entry, which is why
   `HvLogEnter` exists (see `hvlog.md`).
2. **Two handlers are known livelock sites.** `HandleMonitorTrapFlag` (MTF stays
   set → every VM entry raises an MTF exit) and `HandleEptViolation` (always
   "redo instruction" → the same instruction retries forever). Both are
   documented in `experience/silent-root-mode-livelock.md`.

Logging must never perturb timing on this path. Serial output from an exit
handler is busy-waiting inside the guest's execution window, which is what
VMAware's timing checks measure.

## EPT

`Vmx/Ept.c`. Hooks work by removing execute permission from a page and handling
the resulting violation, then re-arming after a monitor-trap-flag exit. Current
limitations: 4 KiB pages only (the 1 GiB huge-page rework is a known task), and
hooks are re-armed in `HandleMonitorTrapFlag`.

## Hypercalls

Guest → hypervisor calls use CPUID leaf `0x4000BABE` with a key in RCX. The
interface is declared in `Sources/Hypercall/Hypercall.h`.

| Call | Purpose |
|---|---|
| `HYPERCALL_READ_HVLOG` | Read the in-memory log ring (works after a hang) |
| `HYPERCALL_SET_TRACE` | Turn serial mirroring on/off at runtime |

The log ring exists because serial can die exactly when it is needed; see
`hvlog.md`.

## Timing

VMX uses the physical TSC with a fixed zero VMCS offset and no TSC scaling.
RDTSC/RDTSCP normally execute natively; IA32_TSC, IA32_TSC_ADJUST, IA32_TSC_AUX
and IA32_TSC_DEADLINE pass through the MSR bitmaps. Windows and the local APIC
therefore use the same continuously advancing hardware clock.

The former per-exit correction in `Vmx/TscOffset.c` was removed: subtracting
root-mode time independently on each CPU creates cumulative skew, and stopping
that correction leaves the skew in place. Its deadline shadow also cannot track
hardware clearing an expired deadline or subsequent offset changes. The legacy
SET_TSC_OFFSET hypercall now rejects enable requests; disable remains idempotent.
The packed GET query retains its ABI. A fresh boot is required to replace an
older image with accumulated offsets.

The fallback handlers distinguish RDTSC from RDTSCP, preserve unaffected
registers, return RDTSCP's low 32-bit TSC_AUX in ECX, and enforce CR4.TSD using
guest SS.DPL. `Tests/run_tsc_clock_tests.py` exercises these production functions
with VMCS/MSR stubs; it does not establish Windows runtime correctness.

VM exits still consume real time. In particular CPUID exits are mandatory;
a VMAware TIMER latency finding is not by itself proof of TSC corruption.
DTB validation must compare clock monotonicity, cross-CPU coherence, QPC rate and
timer behavior with and without the hypervisor, alongside unchanged VMAware checks.
`control/dtb/probes/clock_coherence.c` supplies a bounded read-only Windows probe
for per-CPU TSC/QPC rates under sleep and CPUID load plus sequential migration.
It restores thread affinity and makes its limits explicit: QPC can share TSC's
source, and migration latency can hide small clock skew. Build with MinGW and
`exit_latency.S`, deploy/run through `dbg_run`. It is not an independent wall-clock
or interrupt-delivery test; current observations belong in `status.md`.

`control/dtb/probes/timer_deadlines.c` adds bounded waitable-timer coverage: four
pinned observers arm fresh relative one-shot timers at ordinary priority, first
idle and then with four pinned CPUID workers. It reports completion, QPC arm/wake
lateness intervals, placement and error counts. It exercises kernel timer
expiration and thread resumption but cannot isolate ISR latency from scheduling,
identify a physical APIC interrupt or independently calibrate wall time. It
changes no system timer resolution; a matched native baseline is needed before
claiming a latency regression.
