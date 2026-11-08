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

## 2026-11-08 - synthetic graphics verified; firmware-delay blocker

`dbg_screenshot` now visually confirms the full synthetic warning banner,
two boxes, health bars and readable HP/distance labels; the bounded preview
returns zero. This is synthetic graphics, not verified game memory. Live offline
CS2 remains blocked on independently verified layouts/session fields.

The next stall-diagnostic-off image (mtime `1794089961.933886`) rebooted through
Windows but remains pre-ExitBootServices with advancing per-core timer samples.
BSP samples are around `0x9a9977de–0x9a997887`; APs report HLT activity at
`0x9e1e5`. Timer samples prove recurring VM entry/exit, not AP instruction progress.
No reset was issued while classified booting. Its latency has not been measured.
Daemon restart renumbered this same physical boot from boot_id 6 to 1.

Direct native CPUID emulation and a bounded one-shot firmware snapshot are now
built and locally validated but **not live measured**. Final candidate SHA-256:
`7d847d70994d96719be668aeace83bc0e7c43cd13e8e480c9bbb1d3e2d620971`,
mtime `1794090854.6469235`. The snapshot is limited to one pre-EBS BSP record,
with validated code32/stack16 reads and an unchanged ordinary-RAM allowlist.
Latest observation of the running older image: heartbeat 2432, still pre-EBS,
no SSH, no panic. The new candidate cannot be loaded without a subsequent boot;
no reset has been issued while this boot remains classified booting.

## 2026-11-08 - retirement snapshot reuse measured

Image SHA-256 `8e14a13145a56c7c6d938679ab04891681e9b19820876c42cc7baac2ba480b0e`
(mtime `1794089554.376869`, uncommitted worktree) software-rebooted in 88.0
seconds, daemon boot_id 5. CPUID retirement reuses the dispatcher's pre-handler
RIP snapshot through a common retirement core; other handlers retain a live-RIP
wrapper. Interrupt shadow and compatibility-mode wrapping remain intact.

Native CPUID(0) median **890 TSC ticks**; all 2000 samples accepted. The prior
inline-VMREAD-only build measured 917 (versus 920 before inlining), so no large
latency gain was established for inlining alone. **TRAP and EIP_OVERFLOW clean;
TIMER fires:45.** Clock-state query reports disabled correction and zero offsets
in the first eight APIC slots. No undetectability/full-sweep claim.

## 2026-11-08 - VMCS processor identity lookup measured

Image SHA-256 `f9a374ad6ac3b7907faa9bf54eec4108ac6eb91a6c5a4d2fb656391de9fb3d93`
(mtime `1794088701.4518332`, uncommitted worktree) booted by software restart in
87.2 seconds, daemon boot_id 3. The dispatcher now resolves its existing VPID to
an immutable hardware initial-APIC-ID cache, with checked VMREAD/bounds and a
CPUID fallback. Entry stack/assembly and guest CPUID output are unchanged.

Native diagnostic CPUID(0) median: **920 TSC ticks**, versus 1191 in the preceding
build and 1487 in the initial register-safe baseline. Software-counter median:
163 increments. All 2000 samples accepted for each tested instruction. The
8-LFENCE reference is now measured separately; these descriptive measurements
still do not reproduce TIMER's synchronization/filtering.

**TRAP clean (0), TIMER fires:45** on the unchanged VMAware revision. Collision
probe: exactly one exception, CONTEXT.Dr6=`0xffff4ff1`, normal continuation.
Clock-state snapshots before/after: correction disabled, zero offsets in the
first eight APIC slots. No claim of undetectability or full-sweep success.

## 2026-11-08 - software reboot and framebuffer runtime validation

A graceful `shutdown /r /t 0` reboot through the new software-boot path was
confirmed (84.7 seconds, daemon boot_id 1 to 2 after its restart). No hardware
reset or forced application termination was used. The tested uncommitted image
mtime was `1794087769.0597942`; the pinned VMAware revision remains unchanged.

The current build includes C-only APIC-ID reuse for EPT, shared pre-dispatch RIP,
removal of the unused private exit counter, sharded exit statistics, and optional
aggregate trace totals (disabled by default). Native CPUID(0) median measured
1191 TSC ticks versus the earlier register-safe baseline's 1487. These are not
TIMER's software-counter ratios. GET_TSC_OFFSET snapshots before/after reported
disabled correction and zero offsets in APIC slots 0–7. **TRAP remains clean;
TIMER still fires:45.** No complete sweep has been performed.

The image also corrects confirmed EFIAPI/SysV AP callback and root-exception
argument mismatches. Their relationship to intermittent firmware delay remains
unproven; a single successful boot cannot establish causality.

The framebuffer now passes live capability and exclusive self-tests (pixels,
rectangle bounds, mouse/buttons/keys/wheel/focus). Actual Windows visual output
and real bot-match data are not yet verified. See `overlay.md` for the boundary.

## 2026-11-08 - boot recovery and timing work, uncommitted worktree

The APIC-ID stack-header experiment was reverted. Its boot eventually reached
Windows after a prolonged firmware phase; advancing heartbeats were evidence
against a CPU wedge. Restoring the prior assembly/C entry ABI and HOST_RSP setup
restored a 53.7-second boot (boot_id 5). The reason for the delay is unresolved.

On boot_id 5, VMAware `v2.8.2-56-gc8092c6` still reports **TRAP clean (0)** and
**TIMER fires:45**. The independent collision probe still records exactly one
exception with CONTEXT.Dr6=`0xffff4ff1` and successful continuation. These results
belong to the uncommitted worktree; no new complete sweep establishes that every
other vector is clean.

Next performance candidate: reuse the dispatcher's APIC-ID result in the EPT
check entirely in C, without changing assembly or guest-visible CPUID output.
The native register-safe latency diagnostic will replace the older C# probe,
whose generated CPUID stubs fail to preserve RBX.

## 2026-11-07 - debug-state correction, uncommitted worktree

Network boot is restored: DTB HTTP requests fetched both EFI payloads and the
serial log records processor startup, BOOT-CAT, and ExitBootServices. Results
below are for the **uncommitted worktree**, not the historical commit in the
frontmatter. VMAware remains `v2.8.2-56-gc8092c6`; no complete sweep was performed.

| Technique | Before correction | Boot_id 2 | Change |
|---|---|---|---|
| `TRAP` | fires:100 | clean (0) | Save/restore guest DR7 and DEBUGCTL; read guest DR7 from VMCS |
| `TIMER` | fires:45 | fires:45 | Not fixed; counter-based latency remains |

Independent suspended-worker probe: TF+DR0 collision at the CPUID resume RIP
changed from CONTEXT.Dr6=0 to `0xffff4ff1` (BS+B0), exactly one exception, normal
continuation. A plain execution breakpoint survived CPUID. Effective debug
save/load controls were logged as 1/1 on all four processors. This is an
architectural preservation correction, not the historical Hyper-V branding
exclusion. See `debug-exception-delivery.md` and `cpuid-exiting-floor.md`.

A separate APIC-ID handoff optimization is being boot-tested; no improvement in
TIMER is claimed yet. The previous documentation's claims that TRAP was
intrinsically impossible and that root CPUID causes nested exits were incorrect.

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
