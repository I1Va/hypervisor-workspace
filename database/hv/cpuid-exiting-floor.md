---
topic: cpuid-exiting-floor
kind: reference
updated: 2026-11-07
see: [debug-exception-delivery, detection-vectors]
---

# CPUID VM-exit overhead: architecture versus measurement

## Architectural boundary

CPUID unconditionally exits in VMX non-root operation. There is no ordinary
primary execution control to let it execute natively. **Primary processor-based
control bit 1 is not a CPUID-exiting switch.** Earlier versions of this document
misread that reserved control and the capability masks. The low capability dword
specifies required-1 bits; the high dword specifies allowed-1 settings.

A CPUID executed in VMX **root** mode does not cause a nested VM exit. It still
has a real serialization/instruction cost. Removing redundant root CPUID calls
is valid optimization, not removal of the mandatory guest exit.

## Current detector boundary

VMAware's Windows TIMER uses a counter thread on another CPU, not simply RDTSC.
Its independent checks compare CPUID/reference latency (threshold 2.75) and
single-step/software-exception latency (threshold 2.5). A guest TSC offset cannot
hide elapsed time measured by a separately executing software counter.

Earlier measurements recorded CPUID/reference=6.00 and debug/software-exception
=0.93. Those values belong to those particular builds and probes. They do not
prove that every implementation must exceed 2.75 or that optimization is useless.

The current independently reproduced result is TIMER fires:45 on VMAware
`v2.8.2-56-gc8092c6`. It remains a failure until the unchanged check measures
otherwise. Advertising another hypervisor's identity to trigger an exclusion is
not a timing or debug-state correctness fix.

## TRAP is not an intrinsic CPUID limitation

The old explanation that TF and an execute breakpoint cannot coincide after a
CPUID exit was wrong. Execute breakpoints are fault-class conditions recognized
before their target executes; the boundary may carry both trap/fault causes.

The implementation omitted guest DR7/DEBUGCTL save+restore. VM exit reset the
physical register used by its breakpoint helper. Requesting/checking both debug
controls and reading saved DR7 from the VMCS fixed the measured collision:
Windows' exception CONTEXT.Dr6 became `0xffff4ff1`, exactly one exception arrived,
and VMAware TRAP changed from 100 to 0 on daemon boot_id 2. No branding was used.
See `debug-exception-delivery.md` for the probe and remaining limitations.

## Timing work

After the debug-control correction, the existing `tscprobe.exe` reported:

```
cpuid_delta min=1544 p25=1548 med=1552
nop_delta min=24 p25=28 med=28
lfence_delta min=32 p25=36 med=36
cpuid_x2000 min=3069332 med=3286637 per_cpuid=1643
```

These are TSC probe measurements, **not TIMER's software-counter ratio**.
TSC correction was disabled (`enabled=0`, no per-core accumulated offsets).

The subsequent APIC-ID stack-header experiment was **reverted** on 2026-11-08.
It reached virtualization on all processors but remained in firmware for over
20 minutes with advancing heartbeats. Windows eventually became reachable;
calling this a CPU wedge was not justified. Reverting the HOST_RSP/header and
assembly handoff restored a 53.7-second boot. The delay's cause is not proven.
A structure-size assertion alone is not a complete assembly ABI proof.

The C-only EPT change now passes the dispatcher's existing root-mode APIC-ID
result to `EptSyncOnExit`. It removes one redundant serializing CPUID without
changing HOST_RSP or the assembly/C entry interface. Pre-dispatch RIP is also
shared between trace consumers; the unused private exit counter is removed.
Exit statistics use cache-line-separated histogram shards; the default logger
omits its redundant global aggregate total (`HV_LOG_EXIT_TOTALS=1` restores it).
Essential heartbeat, panic and interesting-exit tracing remain enabled.

Intermittent firmware delay recurred without a stack header, so attributing it
solely to the header is unsupported. Confirmed EFIAPI/SysV callback and root
exception-argument mismatches were subsequently corrected. Repeated measured
boots are needed to establish their relationship to the symptom.

The old `tscprobe.cs` generated stubs do not preserve Win64's nonvolatile RBX
around CPUID. Its numbers above are historical observations, not a trustworthy
native baseline. Use `control/dtb/probes/exit_latency.c` plus `.S` for new
comparisons. It preserves the Win64 ABI, verifies affinity/AUX endpoints, prints
accepted/rejected counts and percentiles, and separately reports a cross-core
software counter. Its ratios are descriptive, not the exact TIMER algorithm.
On this Haswell system TIMER's reference is **eight consecutive LFENCEs**, not
one; the native diagnostic includes both references without altering either.

Do not replace APIC discovery with an ungated x2APIC MSR read: that register
faults when x2APIC mode is not enabled.

Further optimizations must preserve CPUID topology/per-core semantics, pending
events, EPT invalidation, and guest register state. Do not cache arbitrary CPUID
results globally or slow a reference instruction to manipulate a detector ratio.
