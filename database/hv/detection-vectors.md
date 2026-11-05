---
topic: detection-vectors
kind: reference
updated: 2026-11-06
see: [cpuid-exiting-floor, vmexit-cost, hypercall-abi]
---

# Detection vectors and what each one requires

The inventory of what a detector can measure, ordered by how much the hypervisor
can influence it. This exists so that the interface work is aimed at the vectors
that will actually be used, rather than at whichever one was noticed last.

Status is against VMAware v2.8.2-56-gc8092c6 on the DTB, boot-verified.

## Currently firing

| Vector | Score | Mechanism | Structural? |
|---|---|---|---|
| `TIMER` | 45 | CPUID latency ÷ LFENCE latency ≥ 2.75; measured 6.00 | **Yes** — CPUID exiting is CPU-mandatory |
| `TRAP` | 100 | needs `DR6.BS` and `DR6.B0` in one `#DB`; the CPUID exit delivers the trap before the DR0 instruction runs | **Yes** — same cause |
| `GPU_CAPABILITIES` | 20 | virtual display adapter properties | No — cosmetic, needs a guest driver |

## Clean, and why they matter

| Vector | Mechanism | What would break it |
|---|---|---|
| `SINGLE_STEP` | `#DB` on a CPUID single-step | needs BS only, which the pending field provides |
| `DBVM` | `VMCALL`/`VMMCALL` backdoor probe | must inject `#UD` **and** advance RIP |
| `INTERRUPT_SHADOW` | `#DB` must arrive at the instruction after `MOV SS`, not later | fixed by retiring the shadow on emulated instructions |
| `THREAD_MISMATCH` | `NumberOfLogicalProcessors` vs the CPU database entry | any topology lie |
| `NVRAM` | firmware variable store contents | — |
| `HYPERVISOR_HOOK` | hooks on `ntdll` functions | must not hook user-mode APIs |

## Vectors that are not currently exercised, and their requirements

These are the ones the interface must be built for. Each is a *class* of
detection, not a single check.

### 1. MSR and timing

- `IA32_TSC` / `RDTSCP` behaviour. We do **not** intercept RDTSC (deliberate: it
  is the largest timing fingerprint and an exit-storm source). If TSC offsetting
  is ever enabled, every read must stay self-consistent, including across cores —
  a per-core offset is itself detectable.
- `IA32_APERF`/`MPERF`, `IA32_MPERF` ratio checks.
- `IA32_DEBUGCTL` (LBR). Requires save/load debug controls to be coherent.
- **Requirement:** a single place that owns MSR policy, with a table of
  "intercepted / emulated / passed through" and the reason for each.

### 2. Debug registers and exceptions

- `DR0-DR7` must behave exactly as on bare metal, including the fact that DR6's
  status bits are *sticky until software writes them*.
- Exception bitmap must stay 0 unless an interception is measured to be worth its
  timing cost. Every intercept is a fingerprint (see `cpuid-exiting-floor.md`).
- `#DB`, `#AC`, `#MC` interaction.
- **Requirement:** a documented rule for when an exception may be intercepted,
  and a probe that measures the resulting latency before it is enabled.

### 3. CPUID and feature masking

- Every leaf we modify is a fingerprint. Currently only leaf 1 ECX bit 5 (VMX) is
  cleared, and VMAware does not check it.
- Hypervisor leaves (`0x40000000+`) must not exist unless deliberately branded.
- **Requirement:** a declarative CPUID policy table (leaf, register, mask,
  reason) so a change is reviewable and its fingerprint is known.

### 4. Timing and scheduling

- IPI latency, timer interrupt period, `KeQueryPerformanceCounter` coherence.
- Cross-core TSC synchronisation.
- AP startup timing.
- **Requirement:** never hold the guest in root mode. The NMI-window and
  preemption-timer paths must stay bounded; there are already storm detectors,
  and they must remain the last line of defence rather than the mechanism.

### 5. Memory and EPT

- EPT hook latency, `INVEPT`/`INVVPID` behaviour, accessed/dirty bit handling.
- Guest physical address layout: holes, reserved regions, MMIO behaviour.
- Split pages and their observable cost.
- **Requirement:** for memory shadowing (the cheat-development goal) the hook
  path must be fast enough not to be measurable, and must preserve the guest's
  view of the page exactly.

### 6. Firmware and platform

- SMBIOS/DMI tables, ACPI tables (MADT, FADT), PCI configuration space.
- `NVRAM` variables.
- SMM behaviour.
- **Requirement:** these are data, not code. A platform table that can be
  regenerated and diffed is worth more than hand-edited bytes.

### 7. Instruction semantics

- `CPUID` leaves that differ from the physical CPU.
- Instructions that must fault but do not (or vice versa): `VMCALL`, `VMFUNC`,
  `INVPCID`, `XSETBV`.
- The 15-byte instruction-length limit and `#GP` behaviour.
- **Requirement:** the `#UD`/`#GP` injection path must advance RIP correctly and
  must never livelock. This is already the lesson from `VMCALL`.

## What this implies for the interface

Three conclusions that shape the refactor:

1. **Policy must be declarative.** Every interception is a trade between
   functionality and a measurable fingerprint. That trade has to be visible in
   one table per subsystem, with the measurement that justified it, or the code
   drifts into intercepting things nobody chose.

2. **Every handler needs a latency budget.** The CPUID result shows that a
   handler which looks trivial can still be the dominant cost. A handler that
   exceeds its budget should be a build-time or boot-time warning, not a
   surprise discovered through a detection.

3. **The guest must be able to ask what the hypervisor is doing.** The
   `READ_HVLOG` and `SET_TRACE` hypercalls already exist and work. Extending that
   to a structured statistics call is what makes "is this handler expensive?"
   answerable in one command instead of a probe build.

## Priority

The two structural detections cannot be fixed by code that stays inside the
current design. The work that is actually available:

1. `GPU_CAPABILITIES` (20) — a guest-side driver, no hypervisor change.
2. The interface work, so that vectors 1-7 above are testable before they are
   needed.
3. Re-evaluating Hyper-V branding only if a plausible TPM event log becomes
   available; without one it costs 150 points instead of saving 145.

**Note on the TPM option.** `bcdedit /enum firmware` shows a `{bootmgr}` entry on
the ESP alongside the PXE entries, so a bare-metal control run is reachable. That
run would say which of the remaining vectors are caused by the hypervisor and
which are properties of this guest — worth doing before spending effort on
mitigations for vectors that may not be ours.
