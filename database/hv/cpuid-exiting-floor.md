---
topic: cpuid-exiting-floor
kind: reference
updated: 2026-11-06
see: [detection-vectors, interruptibility, vmexit-cost]
---

# The CPUID exit floor

Two of the three remaining detections are the same fact seen from two sides:
**CPUID always VM-exits, and on this processor that cannot be changed.** This
document records the measurement that establishes it and what follows.

## The measurement

`IA32_VMX_PROCBASED_CTLS` (0x482) reports, for each primary processor-based
control bit, whether it may be 0 (low 32 bits) and whether it may be 1 (high 32
bits). Read on the DTB (i5-4460, Haswell):

```
PROCBASED cap=FFF9FFFE0401E172  eff=94006172  cpuid_exit_bit=1  must1=1
```

Bit 1 of the *high* dword is set, i.e. CPUID exiting is in the "must be 1" mask.
Intel VT-x **mandates** that CPUID causes a VM exit. There is no configuration
in which a guest executes CPUID natively while VMX is active.

That single fact decides two detections.

## What it costs

Measured with a cross-core software counter (the same technique VMAware's TIMER
uses, so the units are comparable). Two threads pinned to different cores, the
counter thread incrementing a volatile in a straight line:

| Operation | Ticks | Ratio to LFENCE | Note |
|---|---|---|---|
| LFENCE ×8 | 512 | 1.00 | baseline, no exit |
| CPUID | 3072 | **6.00** | limit is 2.75 |
| `#DB` (single-step) | 7168 | — | |
| `ZwRaiseException` | 7680 | — | ratio 0.93, limit 2.5 |

A VM exit plus entry costs on the order of 1500+ cycles; bare-metal CPUID costs
roughly 100-200. The ratio is therefore bounded below by the exit itself. **No
amount of handler optimisation reaches 2.75.** Removing our own instrumentation
(two RDTSCP pairs, ~140 cycles) was worth doing but changed nothing measurable,
which is the evidence that the floor dominates.

## TIMER: why it fires

`VM::timer()` has two independent sub-checks:

1. CPUID latency / LFENCE latency ≥ 2.75 → "Detected #VMEXIT latency".
2. `#DB` latency / `ZwRaiseException` latency ≥ 2.5 → "Detected #DB interception".

Measured here: (1) is 6.00 and fires; (2) is 0.93 and does not. That is consistent
with the exception bitmap being 0 — we are not in the `#DB` path, so sub-check 2
is satisfied while sub-check 1 is structurally impossible to satisfy.

## TRAP: why it fires

VMAware's `trap()` requires `DR6.BS` and `DR6.B0` in the *same* `#DB`:

```asm
or dword [rsp], 0x10100   ; TF and RF
popfq
cpuid                     ; offset 12 - TF makes this the trapping instruction
mov rbx, r8               ; offset 14 - also the DR0 target
```

On bare metal CPUID completes, the TF trap is taken at the next instruction
boundary, DR0 matches that same address, and the processor sets BS and B0
together. Under VMX the CPUID exits; the VMM queues BS in
`GUEST_PENDING_DEBUG_EXCEPTIONS` and the `#DB` is delivered at VM entry, before
any guest instruction at offset 14 has executed. The processor sets BS and not
B0, VMAware sees "status lost", and TRAP fires.

`SINGLE_STEP` is clean because it needs only BS, which is exactly what the pending
field provides. TRAP needs the collision, and the collision cannot happen because
the instruction the breakpoint is on never runs before the trap is delivered.

## What was tried and rejected

- **Synthesising B0 in the pending-debug path.** Gated on TF-set *and* DR0
  matching the resume RIP it did not hang, but it also did not change the
  observed DR6 — the guest-side value stayed 0x0. Ungated, an earlier attempt
  hung the guest: B0 re-armed a breakpoint on an instruction that had not run, so
  the guest took `#DB`, resumed at the same RIP, and fired again. A hang is worse
  than a detection.
- **Clearing CPUID exiting.** Impossible; see the capability MSR above.
- **Making the handler cheaper.** Measured, no effect on the ratio.

## The DR6 split, which is where TRAP actually lives

Measured on boot 10 with all five `trapdb` cases and `tfprobe`:

| Case | Delivery | DR6 observed by the guest |
|---|---|---|
| `tfcount` (TF, no CPUID) | TF | `0x0` |
| `cpuid_tf` (TF across a CPUID exit) | pending field | `0x0` |
| `icebp` | BS | `0x0` |
| `trap` (TF + DR0) | pending field | `0x0` |
| `dr0count` (DR0, no TF) | breakpoint | **`0xFFFF0FF1`** |

Every **TF-driven** `#DB` reports `DR6 = 0x0`; a **DR0-driven** `#DB` reports the
real value with B0 set. That is not consistent with "the pending field loses BS",
because `tfcount` sets no pending field at all and still reads 0.

A related defect found on the way: `BreakpointBitsForRip` read
`VMCS_GUEST_DR7`, but `SaveDebugControls`/`LoadDebugControls` are both 0, so the
field is stale (still `0x400` from setup) and the function always returned 0.
Fixed to read the physical `DR7`. That is a correctness fix and did not change
TRAP, which is further evidence the problem is delivery, not status synthesis.

So the next step is not another hypervisor bit: it is to establish whether
Windows' `CONTEXT` for a TF `#DB` on this guest reports `DR6` at all. The probe
for that is `drtest.exe`, which currently crashes with exit code 4 before
printing, so it needs fixing first.

## The one remaining lever

`hyper_x()` in VMAware decides whether the machine is a Hyper-V *host*. If it
returns `HYPERV_HOST`, `timer()` sets `check_nested` and **skips the CPUID
sub-check entirely**; `trap()` treats a missing B0 as acceptable; and
`interrupt_shadow()` returns false immediately.

Reaching `HYPERV_HOST` requires all of:

- `cpuid.0x40000001` EBX bit 0 set (root partition),
- `cpuid.0x40000000` vendor string exactly `Microsoft Hv`,
- a TCG measured-boot log readable through `tbs.dll` (`is_log_present`),
- on Windows 11 + admin only, the Hyper-V HAL check.

The last two are the obstacle: presenting the Hyper-V brand without a TPM log
makes VMAware take the `HYPERV_SPOOFED` branch, which adds
`brand_enum::NULL_BRAND` at **150 points** — far worse than the 45 and 100 it
would clear. So spoofing is only viable with a plausible TPM event log, which is
a separate project. Recorded here so the idea is not re-attempted blind.

## Consequences for the design

Because CPUID must exit, every CPUID in the guest pays the exit cost, and a
detector can measure it. The mitigations that remain are architectural rather
than local:

- **Minimise the number of exits the guest can cause per unit time.** Fewer
  intercepts means a lower chance a timing loop samples one.
- **Keep the handler minimal**, which is now done.
- **Consider TSC offsetting** (`UseTscOffsetting`) to compensate measured
  latency where a detector uses TSC. Not yet evaluated: it does not help a
  counter-based check like TIMER, and it introduces its own fingerprints.
- **Do not add intercepts without a measured detection to justify them.** Each
  one is visible to a timing check.
