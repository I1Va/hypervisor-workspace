---
topic: hypervisor-architecture
kind: reference
updated: 2026-11-04
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
control fields are enabled" is normal, not an error.

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

`Timing.c` and the TSC handling exist to keep guest timing plausible. `RDTSC`,
`RDTSCP` and the preemption timer are all detection surfaces: a hypervisor that
adds a constant offset to every timestamp is trivially detectable. Tightening
these timings is an open task.
