---
topic: thread-mismatch-root-cause
kind: reference
date: 2026-11-05
see: [ap-init-sipi-uart-stall, vmaware-detection-status]
---

# THREAD_MISMATCH: how VMAware detects it, and how to fix it

## What the check does

`THREAD_MISMATCH` compares the thread count the **CPU model is supposed to
have** against the thread count the **OS actually reports**.

From `database/materials/VMAware/src/vmaware.hpp`:

```c
const u32 actual = memo::thread_count::fetch();   // std::thread::hardware_concurrency()
const bool model_expects_smt = matched->smt;

if (model_expects_smt && !is_smt_active()) { ... return false; }   // SMT disabled on purpose
if (actual != matched->threads) { return true; }                   // DETECTION
```

- `matched` comes from a CRC32-hashed CPU model database keyed on the brand
  string. This stand's CPU is `{ "i5-4460", 4, false }`: **4 threads, no SMT**.
- `memo::thread_count::fetch()` is `std::thread::hardware_concurrency()`, cached
  once. On Windows/MSVC that resolves to the number of logical processors the
  process can see.

So on an i5-4460 the check is a single comparison:

```
hardware_concurrency() != 4   ->  detection
```

There is no timing, no exception, no VMCS read. It is a **topology consistency
check**: the guest's CPU brand says 4 threads, so the guest had better have 4.

## Why a hypervisor trips it

A VMM can make the brand string and the processor count disagree:

1. **APs never start.** The firmware advertises N LAPICs in the ACPI MADT, but
   the APs never reach a running state, so the OS brings up fewer processors
   than the MADT describes. Windows silently degrades to the BSP. This is what
   happened here - see `ap-init-sipi-uart-stall.md`.
2. **MADT disagrees with reality.** Fudging the MADT to advertise fewer
   processors than CPUID/the brand implies is itself detectable, and is why the
   BIOS processor count must not be "fixed" as a workaround.
3. **CPUID topology leaves are inconsistent.** Leaf `0xB`/`0x1F` report logical
   processor counts per package/core; if they contradict `hardware_concurrency()`
   and the MADT, the guest sees an incoherent machine.
4. **Affinity / processor-group weirdness.** If the guest's threads are pinned
   to one processor group the count can come back lower than the machine has.

## The fix that worked

Make the APs actually run, and make every layer agree:

| Layer | Requirement |
|---|---|
| ACPI MADT | one enabled LAPIC entry per core (verified: 4, APIC IDs 0/2/4/6) |
| AP bring-up | INIT -> wait-for-SIPI -> SIPI must complete (this was the bug) |
| CPUID | brand string and topology leaves unmodified, consistent with 4 threads |
| Windows | `NumberOfLogicalProcessors = 4`, all four `CentralProcessor\N` keys |

Measured result after the AP fix: `THREAD_MISMATCH` went **45 -> clean (0)**, and
a parallel workload showed **3.79x** speedup on equal total work across distinct
CPUs - i.e. the guest is genuinely multicore, not merely reporting a count.

## The trap

The check is not about the hypervisor's existence at all. It is about the guest's
**coherent view of its own machine**. Any VMM that starts successfully will pass
it; only one that half-starts the system trips it. That makes it a useful
correctness signal during development and a poor detection vector once the
multicore path is correct.

## How to verify

```
wmic cpu get NumberOfLogicalProcessors,NumberOfCores /format:list
reg query "HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor"
```
and the hypervisor trace line, which prints the per-core INIT/SIPI counts:

```
[HV] first heartbeat apic 2 ... inits 1 sipis 1     <- released correctly
```

`inits > 0, sipis == 0` means reset-but-never-released.
