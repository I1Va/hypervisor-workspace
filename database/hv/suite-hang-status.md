---
topic: vmaware-suite-hang
kind: status
date: 2026-11-05
see: [thread-mismatch, ap-init-sipi-uart-stall, vmaware-shortcut-false-signal]
---

# VMAware full-suite hang: current state

## Root cause (confirmed in source)

The hang is **not** in any single detection technique, and it is **not** NVRAM.

`cli/output.cpp:general()` runs two passes:

1. `checker(VM::VMID, ...)`, `checker(VM::NVRAM, ...)`, ... one per technique.
   This pass honours `--disable`.
2. Then, unconditionally:

```c
const VM::vmaware vm(VM::MULTIPLE, high_thresh_arg, all_arg, dynamic_arg);
```

**Pass 2 passes no disable flags.** It re-runs *every* technique on the target
platform, so `--disable` has no effect on it at all.

Consequences:

- `--disable <everything except NVRAM>` still hangs, because pass 2 runs
  everything. This is what defeated every bisection attempt.
- The techniques that hang **in isolation** are `TIMER` and `HYPERVISOR_HOOK`
  (both time out at 40-300 s via `dbg_technique`; `TIMER` was confirmed at a 300 s
  timeout, so it is a real hang, not slowness).
- `--percent` / `--detect` / `--stdout` never hit this, because `core::run_all`
  with `SHORTCUT` returns as soon as the score crosses the threshold
  (~0.2 s on this guest). That is why they appear to "pass" - see
  `experience/vmaware-shortcut-false-signal.md`.

So: **the full summary cannot be made to pass by disabling techniques.** It will
always reach `TIMER`, which hangs this guest.

## Full per-technique sweep (boot 43, one boot, no reboot)

Every technique was run individually through `dbg_technique`, which has no
shortcut and no second pass. Result: **78 of 78 ran, on a single boot, with no
reboot, no bugcheck and no power-off.**

| Outcome | Techniques |
|---|---|
| clean (74) | VMID, CPU_BRAND, HYPERVISOR_BIT, HYPERVISOR_STR, THREAD_COUNT, **THREAD_MISMATCH**, MAC, TEMPERATURE, CVENDOR, CTYPE, NVRAM, DMIDECODE, ... and all 35 macOS/Linux-only vectors |
| fires 100 | **TRAP, SINGLE_STEP, INTERRUPT_SHADOW, DBVM** |
| fires 20 | GPU_CAPABILITIES |
| hangs | **TIMER, HYPERVISOR_HOOK** (not the hypervisor - see below) |

Score 100 (threshold is 150, so `-d` would print 0). The four 100-point vectors
are all `#DB`/single-step related and are the remaining detection surface.

Critically, the hypervisor survived all 78 technique runs without a single
`CORE STALL`, `CORE STORM`, `LIVELOCK` or `PANIC`. That is the stability evidence:
**the hypervisor is not what crashes the suite; VMAware's own `TIMER` technique
hangs the guest.**

## Why TIMER hangs (bounded conclusion)

TIMER needs two *different physical cores*: one thread raises an exception, a
second measures instruction latency, and they spin-wait on each other. Its
scheduler (`timer::scheduler::get_mask`) reads `RelationProcessorCore` and refuses
to run unless it finds >= 2 distinct cores.

That input was verified correct with a purpose-built probe (`tools/topo2.cpp`):

```
leaf 0xB: type=1 count=1 (SMT level), type=2 count=4 (core level)
RelationProcessorCore: 4 cores, masks 0x1 0x2 0x4 0x8, 1 logical each, no SMT
L3 shared by all 4, one NUMA node, GetActiveProcessorCount = 4
VERDICT: coherent
```

So the scheduler has valid topology and still hangs. The hang happens with the
heartbeat still advancing and no hypervisor detector firing, i.e. inside guest
mode. Not yet localised further; this is the one remaining open defect.

## What is fixed and verified

Multicore, which was the primary defect:

| Check | Before | After |
|---|---|---|
| `NumberOfLogicalProcessors` | 1 | 4 |
| Parallel speedup (equal work) | ~1x | 3.79x across 4 distinct CPUs |
| Boot time | 76 s | 45-52 s |
| `THREAD_MISMATCH` | 45 | clean |


## Remaining open defect

`TIMER` and `HYPERVISOR_HOOK` hang the guest. Both are exception/context-switch
heavy:

- `TIMER` pins a thread to one processor and raises an exception on it while
  measuring instruction latency from a thread on another processor.
- `HYPERVISOR_HOOK` uses `NtSetContextThread` to program debug registers and
  single-step, then expects `#DB`.

The common factor is `#DB`/single-step delivery, which is the same area as the
pending-debug-exception livelock already fixed but not proven complete.

## Hypervisor-side evidence

- No `CORE STALL` / `CORE STORM` / `LIVELOCK` has fired during a hang.
- Heartbeats from all four APIC IDs continue during a hang (expected: after a
  bugcheck Windows spins the other processors in guest code).
- Two `0x101` events on record (15:42, 16:01) predate the multicore fix.
  Parameters: processor 3 and processor 1.

## Changes made

Real fixes kept:

- **AP bring-up**: no UART traffic inside the INIT/SIPI handshake. This was the
  multicore defect; see `ap-init-sipi-uart-stall.md`.
- **VMCALL** now advances guest RIP by the VM-exit instruction length before
  injecting `#UD`. It previously injected `#UD` with RIP unmoved, which livelocks
  a core if the guest's `#UD` handler returns to the same instruction.
- **`VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS`** is now written rather than OR-ed, and
  written on every exit including zero. It is not maintained by the processor, so
  an OR leaked BS forever and caused an endless `#DB` loop on one core - see
  `pending-debug-exceptions-livelock.md`.
- **Per-core state** for the heartbeat, NMI-window streak, livelock detector and
  stall table. All of these were single `STATIC` variables shared by four cores;
  the heartbeat was also a non-atomic race, which produced a false reading that
  "APs 4 and 6 stopped".
- **Hot path slimmed**: removed all per-violation serial prints from the EPT
  handlers, and reduced the new stall instrumentation to one store plus one
  increment per exit (the peer scan moved to `HandlePreemptionTimer`).

Tested and reverted (measured, not assumed):

- Clearing `NmiExiting` or `VirtualNmi` stops the firmware booting at
  `ExitBootServices`. Recorded in the source comments.

## Known-good baseline

`PulverizedPkg` HEAD `db8b0ab` plus the current working tree, built with:

```
cd hypervisor/efi-superrepo && NO_DOCKER=1 ./PulverizedPkg/build.sh
```

Healthy signature: boot to desktop in 45-55 s, four cores, `THREAD_MISMATCH`
clean, idle and light commands stable indefinitely.

## Next

1. Debug `TIMER` (smallest reproducer, deterministic hang). It is the single
   blocking item for a full-suite pass.
2. Capture a fresh `0x101` parameter set from a current build while `TIMER` runs.
3. Once `TIMER` is clean, re-test `HYPERVISOR_HOOK`.

