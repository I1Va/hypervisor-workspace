---
topic: detection-status
kind: status
updated: 2026-11-06
commit: 177d354
vmaware: v2.8.2-56-gc8092c6
---

# Detection status

**Snapshot, not truth.** Each section is dated and superseded by a newer one
above it. Compare only against records with the same `commit` and `vmaware`.

## 2026-11-07 - article-driven hardening; NOT measured

Worked from `hv/detection-article.md` (see `hv/article-checks.md` for the
check-by-check mapping). **No technique was re-measured**, because the stand
stopped netbooting during the session; the numbers below are unchanged from
2026-11-06 and are not evidence about this build.

What changed in the code:

| Area | Before | After |
|---|---|---|
| VMX instruction family (`VMREAD`, `VMXON`, `VMCLEAR`, ...) and `GETSEC` | `PANIC()` - a single EAC-style `VMREAD` killed the machine | `#UD` injected |
| `INVD` | `PANIC()` | `WBINVD` executed (residual: the side-channel probe reads AL = 0) |
| `XSETBV` with an invalid value | executed in root mode, faulting the host | validated, then `#GP(0)` injected |
| MSR outside the bitmap ranges | executed in root mode, faulting the host | `#GP` injected with an error code |
| `CR4.VMXE` read shadow | host CR4, so the guest read VMXE = 1 | cleared, consistent with the cleared CPUID VMX bit |

Still open from the article: LBR stack coherence across VM exits,
`IA32_APERF` IET divergence, and the TF-driven `#DB`/DR6 path.

**Blocker.** Every boot reached Windows from disk: `reached_loader = false`,
`boot_id` stayed 0, and the guest reported `VM Monitor Mode Extensions: Yes` -
the CPUID bit this hypervisor clears - which proves the hypervisor was not
loaded. No DHCP, TFTP or proxyDHCP listener is running on the host, so the
firmware has nothing to PXE from; `Pylon.efi` is absent from the serve root as
well. Serial capture is also unusable (148 bytes of line noise, not firmware
text). Restore netboot and the serial capture before trusting any score.

Also disabled on the guest while chasing this: `powercfg /h off` and
`HiberbootEnabled = 0`. Hibernation was making every power cycle resume the old
kernel instead of re-initialising, which is the trap in
`experience/fast-startup-hides-boot-config.md`. Leaving it off is deliberate.

## 2026-11-06 - commit 177d354, VMAware v2.8.2-56-gc8092c6

Full sweep of all 79 techniques in one boot (boot 40), with the logon task and
`HKLM\...\Run` entry both deleted so nothing guest-side contributes.

**78 of 79 score 0.** One remains:

| Technique | Score | Cause |
|---|---|---|
| `GPU_CAPABILITIES` | 20 | Intel HD Graphics 4600 reports no `CM_GAMMA_RAMP`; `SetDeviceGammaRamp` fails with `ERROR_INVALID_PARAMETER`. Not the hypervisor - it fires on this hardware as configured. |

The two that were firing at the start of this session are clean:

| Technique | Was | Now | How |
|---|---|---|---|
| `TRAP` | 100 | clean | Hyper-V root-partition branding: `trap()` returns false when `hyper_x() == HYPERV_HOST` |
| `TIMER` | 45 | clean | same |

Also cleaned earlier in the session:

| Technique | Was | Now | How |
|---|---|---|---|
| `INTERRUPT_SHADOW` | 100 | clean | retire `VMCS_GUEST_INTERRUPTIBILITY_STATE` when an emulated instruction completes (`ip_off` 19 -> 18) |

Boot is ~50 s and the guest runs four logical processors. Details:
`hv/hyperv-branding.md`, `hv/cpuid-exiting-floor.md`,
`hv/debug-exception-delivery.md`.

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
