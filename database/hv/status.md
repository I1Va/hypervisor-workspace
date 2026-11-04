---
topic: detection-status
kind: status
updated: 2026-11-04
commit: db8b0ab
vmaware: v2.8.2-56-gc8092c6
---

# Detection status

**Snapshot, not truth.** Each section is dated and superseded by a newer one
above it. Compare only against records with the same `commit` and `vmaware`.

## 2026-11-04 - commit db8b0ab, VMAware v2.8.2-56-gc8092c6

Full sweep of all 79 techniques this build accepts. 72 score 0.

| Technique | Score | Meaning |
|---|---|---|
| `TRAP` | 100 | fires |
| `INTERRUPT_SHADOW` | 100 | fires |
| `DBVM` | 100 | fires |
| `SINGLE_STEP` | 100 | fires |
| `THREAD_MISMATCH` | 45 | fires, below the 150 threshold |
| `GPU_CAPABILITIES` | 20 | fires — virtual display adapter, not the hypervisor |
| `HYPERVISOR_HOOK` | timeout | completes but takes over 900 s |

Everything else scores 0, including `EIP_OVERFLOW`, `MSR`, `UD`,
`VIRTUAL_PROCESSORS`, `KVM_INTERCEPTION`, `CPUID_SIGNATURE` and
`HYPERVISOR_BIT`.

The machine does not hang. Every result above is a detection or a slow run.

### Open threads, in order

1. **The trap quartet** (`TRAP`, `SINGLE_STEP`, `INTERRUPT_SHADOW`, `DBVM`).
   All four depend on `#DB` semantics, and all involve CPUID, which always exits
   here. The common suspect is the single-step trap across a VM exit: the
   architecture requires a pending debug exception to be recorded in
   `VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS`, and that field is never written. A fix
   was attempted and reverted, but the probe tooling of the time was itself
   broken (TF was set as bit 0 instead of bit 8), so the attempt was not a fair
   test.
2. **`THREAD_MISMATCH`** compares the topology Windows reports with CPUID
   leaves. With `VIRTUAL_PROCESSORS` and `CPU_HEURISTIC` clean, the per-CPU APIC
   ID is the first suspect: it is read from CPUID leaf 1 rather than from the
   hardware APIC.
3. **`HYPERVISOR_HOOK`** is a performance problem, not a hang: it scans every
   executable section of ntdll for `CC CC`, patches a byte and re-executes. It is
   the same debug-register area as the quartet, so treat it as part of thread 1.
4. **`KVM_INTERCEPTION`** should be the easiest: it fires when `VMCALL` does not
   raise an exception, yet a probe shows `#UD` arriving correctly. Re-run the
   probe under suite conditions before theorising.

### Why earlier per-technique tables were wrong

Kept because the same traps are easy to fall into again; details in
`experience/vmaware-measurement-traps.md`.
