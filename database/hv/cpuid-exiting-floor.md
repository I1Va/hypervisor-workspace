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

A separate debug-enabled TIMER-only wrapper around the unchanged header now
exposes both ratios. It identifies the instruction-latency subcheck as firing,
while the exception-latency subcheck stays below its threshold. Build identities,
ratios and limits belong in `status.md`; the separately compiled wrapper does not
authenticate the installed checker or guarantee identical generated code.

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

The clock-correctness work removes per-exit TSC subtraction entirely. Ordinary
CPUID and timer exits now bypass the logger filters at the dispatch site (verbose
exit totals still count them). Known-field VMCS writes whose status was already
discarded use inline `VmxWrite`; checked writes retain `vmwrite`. Retirement uses
inline reads for instruction length and CS rights. The accompanying assembly
checks cover both read and write helpers, and native retirement tests retain the
same VMCS effects. Current measured comparisons and their limits are in
`status.md`; these changes do not establish a TIMER pass or a repeatable speedup.

The common dispatcher directly handles CPUID and calls a noinline non-CPUID
switch for other exits. `VmExitHandler` and `HandleCpuid` use GCC O2 function
optimization while the module remains size-optimized; this lets LTO inline
retirement into the measured CPUID path. A reversal boot A/B showed a repeatable
~1.4% median reduction, but TIMER still fires. The exact image measurements are
in `status.md`. Its shared prefix still synchronizes EPT, records statistics and
tracks repeated exits; hardware clears the entry-event valid bit on real exits.
Pending-debug handling runs once after either branch. Livelock records occupy separate 64-byte cache
lines and invalid APIC IDs do not alias CPU 0. Retirement omits the CS-rights read
only when the calculated next RIP fits in 32 bits, where truncation cannot change
it. These changes have native semantic tests; current measurements are in
`status.md` and do not establish a latency gain.

SDM Vol. 3C 30.3.4 supplies a narrow redundant-write opportunity: a genuine
CPUID exit saves pending-debug exceptions clear when its original MOV-SS
blocking bit is clear. If the final computed pending value is also zero and no
handler writes that field or switches VMCS in between, a zero VMWRITE is
redundant. The predicate must use the original interruptibility state returned
from retirement, before its MOV-SS bit is cleared. Nonzero pending values,
MOV-SS cases and all non-CPUID exits require their existing handling. This is
a sufficient condition, not a claim that every MOV-SS exit saves nonzero state.

A per-CPU leaf-0 cache was removed after a measured regression. CPUID leaf 0 is
not completely immutable: IA32_MISC_ENABLE[22] can limit its maximum basic leaf.
The tested cache's live MSR check preserved that behavior, but the combined path
was slower. Ordinary guest requests continue executing native root-mode CPUID.

The entry-event valid bit is also hardware-maintained: SDM Vol. 3C 30.2 clears
bit 31 of encoding 0x4016 on every real VM exit. It need not be zero-written at
every dispatcher entry; lower stale bits are ignored while valid is clear, and
InjectInterrupt replaces the entire field for a new injection. Explicit checked
zero initialization is needed before first launch. VM-entry failure leaves the
valid bit unchanged (29.8), so any future recovery path must deliberately handle
that attempted event; the current fatal path must preserve diagnostic state.

Further optimizations must preserve CPUID topology/per-core semantics, pending
events, EPT invalidation, and guest register state. Do not cache arbitrary CPUID
results globally or slow a reference instruction to manipulate a detector ratio.
