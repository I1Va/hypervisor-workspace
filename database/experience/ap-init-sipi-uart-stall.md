---
topic: ap-init-sipi-uart-stall
kind: experience
date: 2026-11-05
symptom_class: single-core-guest
---

## Symptom

Windows reports one processor although the platform has four:

- `wmic cpu get NumberOfLogicalProcessors` → `1`
- `[Environment]::ProcessorCount` → `1`
- only `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0` exists
- VMAware `THREAD_MISMATCH` scores 45 (1 thread where an i5-4460 has 4)

Meanwhile every layer below Windows insists the machine has four cores:

- the ACPI MADT the guest received lists 4 LAPICs, all `ENABLED` (verified by
  reading `GetSystemFirmwareTable('ACPI', "APIC")` from inside the guest)
- the hypervisor logs `Detected 4 cores` and `Successfully started
  virtualization on core #0..#3`
- heartbeats appear from APIC IDs 0, 2, 4 and 6

## Why it misleads

Every visible signal says "4 cores". The natural conclusion is that the ACPI
table is wrong, or that Windows is ignoring the APs, or that the hypervisor is
only virtualizing the BSP. All three are wrong. The processor count was never
the defect - the APs simply never finished starting, and Windows silently
degraded to one processor instead of failing.

The tell is not a wrong number anywhere, it is an *absence*: no SIPI VM exit
ever occurred.

## Cause

The INIT handler stalled inside the INIT-SIPI handshake.

AP bring-up is a timed protocol: the BSP sends INIT, waits roughly 10 ms, then
sends SIPI. The SDM rule quoted in `HandleStartupIpi` is what makes the timing
fatal:

> If a logical processor is not in the wait-for-SIPI activity state when a SIPI
> arrives, no VM exit occurs and the SIPI is discarded.

`HandleInitSignal` did three things before returning, all of them slow:

1. `HvLogDumpRamToUart()` as its very first action - up to 64 KiB over a
   115200-baud UART, about 5.7 s of busy-wait, after ExitBootServices.
2. two trace lines forced to COM1 with `HvLogSetSerial(TRUE)`, about 4 ms each.
3. another ring dump at the end of the handler.

The core does not actually reach wait-for-SIPI until the handler returns and VM
entry completes, so the SIPI arrived while the core was still executing
hypervisor code and was thrown away. Measured consequence: `INIT apic 2` on every
boot with `sipis 0`, APs 4 and 6 never even INITed, and a single-processor
Windows.

The stall also produced a second, separate symptom: `HvLogNoteGuestExecution`
cleared the hang-dump latch, so the dump re-armed. Long runs of exits without
guest progress are the *normal shape* of AP bring-up, so the machine dumped the
ring repeatedly in the middle of the handshake - which is why the serial log
shows a full HANG DUMP immediately before every INIT.

## How to tell them apart

Read the per-core counters the INIT/SIPI trace prints:

```
[HV] first heartbeat apic 2 ... inits 1 sipis 1
```

`inits > 0, sipis == 0` means the AP was reset and never released - the handler
stall above. `inits == 0` for an AP means it was never addressed at all.

The confirming observation is that `sipis` becomes nonzero the moment the UART
work is removed from the handler, with no other change.

## Fix

- `HandleInitSignal` and `HandleStartupIpi` write to the RAM ring only. No
  `HvLogSetSerial(TRUE)`, no ring dump, no COM1 access at all on the handshake
  path.
- The ring dump is latched to once per boot: `HvLogNoteGuestExecution` no longer
  clears the latch, so a dump cannot re-arm and stall bring-up repeatedly.
- The dump is capped at the newest 8 KiB (`HV_HANG_DUMP_BYTES`) instead of the
  whole 64 KiB ring, so no dump can cost seconds wherever it fires.

Result: boot time 76 s → 50 s, `NumberOfLogicalProcessors=4`, and a parallel
workload shows 3.79x speedup on equal total work across distinct CPUs.

## Residual risk

- Any future logging added to `HandleInitSignal` or `HandleStartupIpi` must stay
  RAM-only. A single `HvLogSetSerial(TRUE)` block there reintroduces this exactly.
- A guest that is slow for unrelated reasons can still miss the ~10 ms window;
  the symptom would be identical, and the `sipis` counter is the discriminator.
- The ACPI/MADT route was measured and exonerated. Do not "fix" the BIOS
  processor count for this symptom.
