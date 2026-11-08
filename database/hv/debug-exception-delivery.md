---
topic: debug-exception-delivery
kind: reference
updated: 2026-11-07
see: [cpuid-exiting-floor, pending-debug-exceptions-livelock]
---

# Guest debug-state preservation and #DB delivery

## Current verified correction

VM exit resets physical DR7 to `0x400` and clears `IA32_DEBUGCTL` (Intel SDM
Vol. 3C, 30.5.1). Reading physical DR7 in root mode therefore does not reveal
the guest's breakpoint enables. The previous code requested neither debug-state
save nor load and its root-mode breakpoint helper read that reset register.

`Vmx/VmxHypervisor.c` now requests and checks the **effective** controls:

- VM exit `SaveDebugControls=1` saves guest DR7 and `IA32_DEBUGCTL`.
- VM entry `LoadDebugControls=1` restores both.
- VMCS setup initializes the guest fields from their pre-launch values.
- Guest INIT initializes guest DR7 to `0x400` and guest DEBUGCTL to zero.
- `BreakpointBitsForRip` reads `VMCS_GUEST_DR7`, not host physical DR7.

Both controls are needed. DR0–DR3 and DR6 have no equivalent VMCS save/load
fields. Do not assume that fact applies to DR7.

## Physical-stand validation

`control/dtb/probes/debug_events.c` sets debug state on a suspended worker owned
by the probe process, then captures Windows' exception context through a VEH.
It is not a privileged direct hardware DR6 measurement. Exactly one exception
and successful worker continuation are checked; each invocation is bounded.

On the corrected boot (daemon boot_id 2), the log printed `save=1 load=1` on
all four processors. Observations:

| Probe | Before correction | With save/load correction |
|---|---|---|
| TF + NOP | one #DB, CONTEXT.Dr6=0 | unchanged |
| TF + CPUID | one #DB, CONTEXT.Dr6=0 | unchanged |
| DR0 execution breakpoint | `0xffff0ff1` | `0xffff0ff1` |
| DR0 after CPUID, TF clear | not measured | one #DB at target, `0xffff0ff1` |
| TF + DR0 collision after CPUID | one #DB, CONTEXT.Dr6=0 | one #DB, `0xffff4ff1` (BS+B0) |

VMAware `v2.8.2-56-gc8092c6`, measured individually through `dbg_technique`:
**TRAP changed from fires:100 to clean; TIMER remains fires:45.** These results
do not establish that every vector or future configuration is undetectable.
No Hyper-V identity or detector modification was used for this correction.

## Architectural corrections to earlier explanations

Earlier versions of this reference and source comments made incorrect claims:

- Execute breakpoints are fault-class events recognized **before** their target
  instruction executes. A trap/fault collision at that boundary is not
  architecturally impossible. The live collision result above confirms it.
- The processor does save the pending-debug field on VM exit, usually as zero,
  with important exceptions including MTF and MOV-SS blocking (SDM 30.3.4).
- Native pending-debug delivery normally updates DR6 (29.7.3); explicit injected
  events do not update DR6/DR7/DEBUGCTL for the VMM (29.6.1.1).
- A Windows exception context or GetThreadContext result is not a direct read of
  hardware DR6. In particular, querying the running current thread's context
  does not provide a sound debug-register diagnostic.
- POPFQ cannot load RF. OR-ing RF into its stack operand is not proof RF became
  set. TF is a separate bit and can be loaded.

Historical failed interception attempts remain evidence of those implementations,
not proof that correct forwarding or preservation is impossible. Do not repeat
unbounded #DB interception experiments based on the old explanations.

## Remaining correctness work

`RecordPendingSingleStep` still reconstructs BS from TF on an overly broad set
of exits. This should eventually use explicit successful-instruction completion,
preserve hardware-saved deferred debug causes, and honor BTF. An asynchronous
exit alone does not prove an instruction retired. Do not change that state
machine while attributing a separate DR7-preservation or performance test.

The dormant intercepted-#DB handler also guesses causes from TF/address matches.
Before enabling it, use debug exit qualification, account for ICEBP's privileged
software-exception instruction length, and correctly normalize debug state.
No generic "unexplained #DB implies BS" rule is valid.

TRAP now passes without enabling that dormant handler. TF-only CONTEXT.Dr6=0 is
still observable and requires separate investigation, not a fabricated success.
