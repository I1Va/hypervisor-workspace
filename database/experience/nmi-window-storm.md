---
topic: nmi-window-storm
kind: experience
date: 2026-11-04
symptom_class: exit-storm
---

## Symptom

Arming the serial trace from the guest produced 5 MB of:

```
[HV] exit 2 ...   (NMI-window)
```

...interleaved with reason 20 (`CPUID`) exits, at roughly one per instruction.
The guest RIP advanced between them, so the machine was running - at maybe 1% of
normal speed. It looked exactly like a hang.

## Why it is misleading

The guest was alive the whole time. Every check that only asks "did it respond"
says yes; the failure is in throughput and in the trace itself.

## Cause

The NMI-window handler injected an NMI on every window exit without checking
whether one was owed. An NMI-window exit occurs when an NMI could be delivered but
is being held; if the handler satisfies the condition by injecting one, the next
window exit fires immediately, and the guest makes almost no progress.

## How to tell them apart

Look at the exit-reason histogram in the log (`[HV] R<reason> #<count>`). A single
reason with a runaway count while the guest RIP barely moves is a storm, not a
hang. A genuine root-mode wedge shows the opposite: silence, not volume.

## Fix

`HandleNmiWindow` now:
- only injects when an NMI is actually owed (tracked per logical processor, keyed
  by APIC ID from CPUID, because MP services are gone after `ExitBootServices`),
- caps consecutive window exits with no guest progress.

Separately, serial bytes are rationed against guest progress, so an armed trace
can no longer starve the machine it is tracing.

## Residual risk

NMI exiting must stay enabled. Disabling it stops the machine booting (it sits in
firmware looping on XSETBV exits with the RIP never advancing). Do not "simplify"
the NMI controls without a probe that distinguishes a storm from a wedge.
