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

## 2026-11-08 - owned histogram rejected after boot 28 measurement

The separate dense-owner histogram candidate measured CPUID medians 786 and
774 ticks, versus 774 twice on production boot 27. It did not establish a
repeatable gain. Installed VMAware stayed TIMER fires:45, TRAP/EIP_OVERFLOW 0.
The candidate was removed, its exact patch preserved, and production rebuilt to
its original image hash. Ready boot 29 reproduced the 774-tick median and
TIMER fires:45. Details and source provenance limitations live in
`../experiments/2026-11-08-owned-exit-counters/record.md`.

A new linked-image test preserves the host-FS invariant independently: it scans
sized function ranges, checks stack-protector/TLS configuration, and rejects
unexpected segment memory/base instructions. It does not analyze dynamic WRMSR
operands or replace architectural review.

## 2026-11-08 - remaining VMCS read and counter-ownership audit

After boot 27's measured host-FS improvement, source review found no generally
safe removal among the remaining CPUID VMREADs: reason/RIP/length,
interruptibility and RFLAGS carry state not present in root GPRs, and the CS-rights
read is already conditional on possible 32-bit wrapping. This is a scoped audit,
not a proof that all future restructuring is impossible.

The public histogram API supports same-shard concurrent writers and must retain
atomic RMW. Initial APIC IDs are truncated to eight bits and setup does not prove
their uniqueness on arbitrary x2APIC systems. A separate dispatcher-only owned
store must therefore use the validated dense processor-context index and never
mix its load/store increments with generic atomic writers. The existing public
multiwriter tests remain required.

## 2026-11-08 - host FS CPU identity; boot 27

Boot_id 27 loaded uncommitted image SHA-256
`10053ecf17a984485438cf40d2d31c521212920a60fc3bd12584c751e7258527`
by graceful software restart. HOST_FS_BASE points at the owning context's immutable
initial APIC ID; the exit-only identity helper now uses a single DWORD `fs:0`
load instead of checked VPID VMREAD and context lookup. Setup checks context
ownership, allocation bounds within the low-512-GiB host mapping, FS selector/base
writes, bitmap-address installation, effective MSR-bitmap enablement and native
FS_BASE read/write pass-through. Guest FS capture, VPID translation controls and
entry-stack ABI are preserved. Native host-identity and assembly tests pass.

Two 2000-sample runs measured CPUID median **774 TSC ticks** with no rejects,
versus 786 twice on boot 26. The observed reduction is about 1.5%. The separate
TIMER wrapper measured 697/96 = 7.26042 twice; exception ratios about 0.74.
Installed VMAware `v2.8.2-56-gc8092c6`: **TIMER fires:45; TRAP/EIP_OVERFLOW
clean (0)**. The breakpoint-collision probe still delivered one exception at
offset 14 with CONTEXT.Dr6=`0xffff4ff1`. Four-CPU clock-coherence and 1024 migration
samples completed without backwards time or CPU/AUX mismatches.

The new guest FS probe (`control/dtb/probes/guest_fs.c` and `.S`, executable
SHA-256 `62f565245ae18b152a424322906f94f4f1a22df327a4419c83c8587b914d01fc`)
completed 1000 FS-change/CPUID/FS-restore round trips per CPU on all four CPUs,
on both baseline boot 26 and candidate boot 27, with zero observed or restored
base mismatches. FS is restored entirely in assembly before returning to C.
This covers user-mode FSGSBASE on this Windows configuration; it is not a proof of
all guest FS uses or future linked-library compatibility. Root FS is now reserved
for the identity contract and must remain free of TLS or unrelated base writes.

## 2026-11-08 - redundant entry-event clear removed; boot 26

Boot_id 26 loaded uncommitted image SHA-256
`1c6db6c0e88932b0960e518362c3312a9e39a3cb0549066f57ec827af9261320`.
Setup explicitly initializes event-info encoding 0x4016 to zero with checked
VMWRITE; the dispatcher no longer zero-writes it on every exit. SDM 27.8.3/30.2
clears its valid bit on every real exit. InjectInterrupt still replaces the
whole field when queuing a new event; late VM-entry failure retains attempted
event state for the existing fatal diagnostic path. Updated native setup,
injection/collision, retirement/debug, dispatcher and timestamp tests pass.

Two 2000-sample runs measured CPUID median **786 TSC ticks** with no rejects,
versus 802 twice on boot 25 and 835 on boot 24. The combined observed reduction
from those two redundant-write removals is about 5.9%. Exact TIMER instruction
ratios were 7.13131 and 6.9703, exception ratios about 0.75. Installed VMAware
`v2.8.2-56-gc8092c6`: **TIMER fires:45; TRAP/EIP_OVERFLOW clean (0)**.
Both bounded CPUID single-step/collision probes match baseline: one exception at
offset 14, collision CONTEXT.Dr6=`0xffff4ff1`. TIMER acceptance remains open;
neither removed write changes clocks, thresholds or reference instruction speed.
Clock-coherence checks on this boot also completed four CPUs/1024 migrations
without backwards TSC/QPC or endpoint mismatches; legacy correction stayed disabled
with zero covered offsets. The watchdog-hardened timer diagnostic (probe SHA-256
`fa0a1cb98be087a037148cab1f6b50a0eb3bb382b21516cec4edb22f30c9257f`)
completed all 320 waits with zero errors/timeouts. Loaded median lateness was
about 13.93 ms, maximum upper bound 45.90 ms; dbg_run elapsed 8.3 seconds. These
are scheduling-inclusive QPC-relative observations, not independent wall time.

## 2026-11-08 - waitable-timer deadline continuity under four-core CPUID load

On boot_id 25, the separate `control/dtb/probes/timer_deadlines.c` diagnostic
completed 320 relative one-shot waitable-timer waits: 40 per CPU in each of idle
and four-core CPUID-load phases. All four allowed group-0 CPUs were covered.
There were zero timeouts, backwards QPC observations, placement mismatches or API
errors; diagnostic_exit=0, dbg_run elapsed 7.8 s. Probe executable SHA-256:
`8044c1cb99c9243eddefa0fe01f5f98b935f32ea379460065dab454cfe9e24ac`.
The source compiled with MinGW O2 and strict warnings without warnings.

Idle lateness medians were about 11.8–12.1 ms beyond the requested 50 ms; loaded
medians about 13.94 ms. Largest idle/loaded lateness upper bounds were 42.89/61.85
ms. Loaded workers completed about 10.37–11.18 million CPUID calls per CPU. This
exercises fresh kernel timer expirations and thread resumption under load; it
cannot separate interrupt delivery from scheduling latency, independently
calibrate wall time, or establish equivalence without a matched native baseline.
The process uses ordinary priorities and does not change timer resolution.
A subsequent source review removed a synchronous stderr write from the watchdog
before termination, since a stalled output pipe could otherwise delay it. The
watchdog now requests immediate process termination without output or DLL-detach
callbacks; strict compilation still passes. This follow-up was not the binary
used for the completed run above.

## 2026-11-08 - hardware-proven CPUID pending-debug zero-write elision

Boot_id 25 loaded uncommitted image SHA-256
`943651c8e127a9fc20ab7de301faab2be638ac04bb376ce2a39f2938ee0669c0`
by graceful software restart. Retirement returns the original interruptibility
state through both ordinary CPUID and hypercall paths. The pending-debug tail
omits a zero VMWRITE only for CPUID whose original MOV-SS blocking was clear,
using SDM 30.3.4's hardware save guarantee. Every nonzero pending value, MOV-SS
case and non-CPUID exit keeps its existing write behavior. No software cache of
VMCS contents is used. Native tests cover 26112 pending-debug cases per O2/Os
configuration plus retirement, dispatcher and timestamp suites.

The immediate production baseline on restored boot_id 24 measured CPUID median
835 ticks, TIMER diagnostic 742/96 = 7.72917. The candidate measured 802 ticks
twice (2000 accepted samples per instruction per run); TIMER numerator was 711
in both runs, ratios 7.2551 and 7.11. This is an observed ~4% median reduction
on this comparison, not a claim of universal performance or a TIMER pass.

Installed VMAware `v2.8.2-56-gc8092c6`: **TIMER fires:45; TRAP/EIP_OVERFLOW
clean (0)**. The bounded debug probe matched baseline: TF-CPUID delivered exactly
one exception at offset 14 with CONTEXT.Dr6=0; breakpoint collision delivered
exactly one at offset 14 with CONTEXT.Dr6=`0xffff4ff1` (BS/B0). These CONTEXT
values are not direct hardware DR6 readings. The exact TIMER diagnostic exception
ratios stayed about 0.744. Timing acceptance remains open.

## 2026-11-08 - stripped CPUID diagnostic; production restored on boot 24

Boot_id 23 ran a temporary `HV_CPUID_FLOOR_BENCH` branch before normal dispatch.
It executed native CPUID, wrote the four output registers, and used the existing
RIP-retirement helper. It bypassed EPT synchronization, entry-event clearing,
pending-debug delivery, CPUID masking, hypercalls and diagnostics for that exit.
Consequently it was not a correct production hypervisor and its TIMER result
cannot count as acceptance. The native probe accepted 2000 samples, median
792 TSC ticks; the separate debug TIMER wrapper returned instruction ratio
669/96 = 6.96875 and exception ratio 3154/4230 = 0.745626. This is one observed
stripped-path result, not a proven hardware floor or proof that all further
optimization is impossible. Register saves and retirement still ran. The image
hash was not captured before rebuilding; this observation is inconclusive as a
fully reproducible experiment.

The branch and build define were removed. The rebuilt production image matched
SHA-256 `fa0b487b418b86d85ef525c508dd69b737211e408adc7750550c9285bd7f892d`.
A graceful software reboot returned the stand to production boot_id 24 and ready.
The initial 60-second boot wait ended with verdict booting; subsequent status
confirmed desktop without reset. No stripped diagnostic remains in source.

SDM Vol. 3C 30.3.4 also corrects an earlier source comment: hardware normally
saves pending-debug exceptions clear on VM exit. Exceptions include MOV-SS
blocking and certain asynchronous exit reasons. A software cache of that field
cannot assume it stayed unchanged through guest execution. The source comment
was corrected; default pending-debug behavior was preserved.

## 2026-11-08 - minimal-path and linked O3 experiments rejected

On boot_id 22, a benchmark-only CPUID fast path omitted histogram and livelock
bookkeeping but retained EPT sync, event clear, emulation/retirement and pending-
debug delivery. Two 2000-sample runs measured medians 872 and 860 ticks; TIMER
instruction ratios were 7.43434 and 7.625, with exception ratio about 0.738.
The first software-counter sample was zero-heavy; the second looked normal. The
results neither explain nor reduce the stable full-path latency, so the diagnostic
branch and build define were removed. Full production source was rebuilt.

A separate linked-LTO O3 experiment enlarged `VmExitHandler` from 1169 to 1666
bytes versus the O2 reference. It was rejected without booting, O2 was restored,
and the O2 image rebuilt. This confirms that isolated non-LTO parity did not
predict the linked binary.

## 2026-11-08 - minimal CPUID path benchmark rejected

A temporary build-only `HV_MINIMAL_CPUID_BENCH` branch bypassed CPUID exit
histogram and livelock bookkeeping, while retaining EPT sync, entry-event clear,
CPUID emulation/retirement and pending-debug delivery. This was diagnostic only;
the branch and build define were removed and the full image rebuilt without a DTB
boot. On boot_id 22 the benchmark image measured CPUID medians 872 and 860 ticks
(2000 accepted samples each), with exact TIMER instruction ratios 7.43434 and
7.625; exception ratio stayed about 0.738. Software-counter samples were
zero-heavy in the first run; the repeat was normal. These noisy/inconsistent
results do not identify a meaningful contribution from statistics/livelock work,
so no production bookkeeping was removed. The full production path is restored.

## 2026-11-08 - frame-pointer codegen check rejected

A follow-on static comparison added `omit-frame-pointer` to the two O2 hot
functions. In the linked DEBUG image, `VmExitHandler` grew from 1138 to 1169
bytes and acquired additional callee-saved register stores around the VPID and
exit-reason reads. This is a worse linked path, so the flag was removed without
booting it. The retained source is back to the prior O2-only policy and was
rebuilt. No hardware result is inferred from this codegen-only comparison.

## 2026-11-08 - focused O2 handler optimization A/B

GCC `optimize("O2")` attributes on `VmExitHandler` and `HandleCpuid` let LTO
inline CPUID retirement and remove its call/return. The linked CPUID path preserves
common EPT synchronization, event clearing, statistics, native CPUID and pending
single-step behavior. It does not remove VMCS operations or change clock semantics.
Native retirement and dispatcher suites pass after adjusting the assembly test to
allow either inlined or out-of-line retirement.

A reversal A/B was run through graceful software boots. With attributes, boot_id
19 measured two 2000-sample CPUID medians of 835 TSC ticks and TIMER diagnostic
ratios 7.51515 and 7.52525 (instruction); without, boot_id 20 measured 847 and
ratio 7.69697. Reapplying the attributes produced boot_id 21, median 835 and
instruction ratio 7.38614. No latency samples were rejected. The observed median
improvement is about 1.4%; exact VMAware instruction counts moved from about 762
without to 744–746 with the optimization. The exception ratio stayed near 0.74.

On boot_ids 19 and 21, installed VMAware `v2.8.2-56-gc8092c6` reports
**TIMER fires:45; TRAP/EIP_OVERFLOW clean (0)**. Retain the small measured gain,
but it does not solve TIMER: the instruction ratio remains far above threshold
2.75. This is not a basis for removing guest-visible semantics or manipulating
the checker/reference instruction. A larger architectural opportunity is still
needed to close the remaining gap.

## 2026-11-08 - explicit empty MSR lists; user-rebooted boot 18

The uncommitted served image SHA-256 is
`5e5a1bc2931618e6c7ad3d18fe62152a0dc650b3486201199f5101aa485e8998`.
It restores baseline host EFER loading and full livelock tracking, and explicitly
writes zero to VM-exit MSR-store/load and VM-entry MSR-load counts. Setup rejects
any failed write. Native production-block tests cover all three writes and each
failure path. This is correctness hardening: no evidence established nonzero
counts in earlier images or a performance gain from their initialization.

The user rebooted the stand; daemon boot_id 18 reached desktop after loader/EBS
marks. The current server image was built before the recorded loader phase; the
stand does not return a cryptographic identity of the loaded payload. Native
CPUID median was 847 TSC ticks with all 2000 samples accepted. Separate TIMER
diagnostic ratios were 7.69697 instruction and 0.741289 exception. Installed
VMAware `v2.8.2-56-gc8092c6`: **TIMER fires:45; TRAP/EIP_OVERFLOW clean (0)**.
Clock coherence completed four CPUs and 1024 migrations without observed backwards
TSC/QPC or endpoint mismatches; inferred rate stayed about 3.19815 GHz. Legacy
correction query remained disabled with zero offsets in covered slots. Independent
wall time and complete Windows behavior remain unverified.

## 2026-11-08 - TIMER subcheck isolated; host EFER and tracking experiments rejected

A separate TIMER-only wrapper compiled the unchanged vendored header with debug
output, MSVC 19.32.31329 x64, `/O2 /std:c++17 /EHsc /DVMAWARE_DEBUG=1 /DNDEBUG`.
Header SHA-256 is
`6f9c13bed07a05c96f2e00d23c056650e44bb6980ce674c059b9ee470e0c5110`;
executable SHA-256 is
`9747bd171363c3e394c8e4b970b774d29e833242da926171dadffa5c5d12c467`.
The old Windows SDK required a temporary overlay of two topology typedefs from
Microsoft win32metadata commit `c16762d41f1bd641ff8c4389ebf16ee50747129f`.
Original/overlay ABI assertions passed; installed SDK and VMAware header were
unchanged. The reproducible build script is `control/dtb/probes/build_vma_timer.ps1`.
This diagnostic is separate from the installed checker; compiler/debug output can
change its generated code and timing. It does not authenticate the installed
checker's source identity.

On boot_id 15 it reports **instruction ratio 758/96 = 7.89583**, over threshold
2.75, and **exception ratio 3096/4167 = 0.742981**, below threshold 2.5. This
isolates instruction/exit latency as the failing TIMER subcheck in this build.
No branding, threshold changes, or reference-instruction slowdowns are involved.

The host EFER-load experiment retained guest EFER/debug save/restore and relied
on SDM 30.5.1's host-address-size assignment of LME/LMA. Boot_id 16, uncommitted
image `d664c15c8e08fb112b861abfd985171e77049cd51bb2549470d9f418c75230b5`,
booted by graceful restart in 86.3 seconds. Serial confirmed effective host EFER
load disabled on all four initialized processors. CPUID medians were 844/900
TSC ticks; exact TIMER ratios were 7.56 instruction and 0.743964 exception.
TIMER remained 45, TRAP/EIP_OVERFLOW 0. **No repeatable gain; control change reverted.**

Excluding unconditionally retiring CPUID from heuristic livelock bookkeeping was
then measured with baseline host EFER loading restored. Boot_id 17, image
`13c00acfb072a7aac756c20ad4cb5a6ff8b17c9d2866d55ab961b132d7d330ba`,
restarted normally in 90.5 seconds. CPUID median was 878 ticks (2000 accepted);
exact TIMER ratios were 7.64646 instruction and 0.742754 exception. Installed
VMAware `v2.8.2-56-gc8092c6` again returned TIMER 45, TRAP/EIP_OVERFLOW 0.
**No gain; diagnostic exclusion reverted.** Clock-coherence completed four CPUs
and 1024 migrations without observed backwards TSC/QPC or CPU/AUX mismatches;
legacy correction query remained disabled with zero covered offsets. These
observations do not establish independent wall-time or Windows timing equivalence.

## 2026-11-08 - checked register-output VMREAD measured

Boot_id 15 loaded uncommitted image SHA-256
`583ec194a909d6fe2446f8e0d9f22b935a654aa73a14a1b9ce0cc8d53ab54ce3`
by graceful software restart in 87.0 seconds. The checked VPID identity read now
uses a register destination instead of a stack slot; all validation and native
CPUID fallback remain. Generated-code checks and synthetic CF/ZF/identity tests
pass. CPUID medians were 900 immediately after boot and 847 on repetition, each
with 2000 accepted samples. No repeatable gain is established. TIMER remains
fires:45 through dbg_technique on VMAware `v2.8.2-56-gc8092c6`; no new TRAP or
EIP_OVERFLOW result is claimed for this boot. The legacy clock snapshot reports
disabled correction and zero offsets in slots 0–7, with its usual limitations.

## 2026-11-08 - bounded CPUID cache rejected; dispatcher split measured

These measurements use uncommitted images and VMAware
`v2.8.2-56-gc8092c6`; the historical frontmatter commit does not identify them.
A per-APIC leaf-0 cache checked live IA32_MISC_ENABLE[22] to preserve CPUID-limit
semantics. On boot_id 11, image SHA-256
`9d1c47af65e62ad849f2dd0f63678c944eddc26e27074892212fa704d2e89494`,
CPUID median was 1152 TSC ticks in two runs versus the prior 847. The cache and
its integration were removed. The MSR read is a plausible source of overhead;
these measurements do not isolate the instruction's cost. Boot attempts 9–10
had unexplained power/loader activity and are inconclusive.

The retained per-CPU livelock records have a 64-byte aligned stride; out-of-range
APIC IDs skip tracking instead of aliasing CPU 0. Boot_id 12, image
`61116f161b5142d9fd03fed1e4dfa3c4f59c9a026b64eef3dc6e6124a257df3f`,
measured 844 ticks. Conditional CS-rights reading during retirement then measured
844 on boot_id 13, image
`343d88ec4115607414076b21f39734183bbb9a131bb07a78c5d79e6e0e1d2883`;
TIMER remained 45. The native tests establish read elision for next-RIP values
that fit in 32 bits, not a measured gain at the probe's instruction site.

Non-CPUID dispatch is now behind an explicit noinline boundary. The linked
VmExitHandler shrank from 5876 to 827 bytes. Boot_id 14 loaded image
`6486c8ff38e7df3d17a7ae57257ca6292e2bc98ffdb83e514ee55becc75e2b67`
by graceful software reboot in 87.7 seconds. Two 2000-sample runs measured CPUID
medians 847 and 850 ticks, with no rejected samples. **No latency improvement is
established by outlining. TIMER fires:45; TRAP and EIP_OVERFLOW are clean (0).**
All three were run individually through dbg_technique on boot_id 14.

The clock-coherence diagnostic on boot_id 14 completed four-CPU sleep/load phases
and 1024 migration samples without observed backwards TSC/QPC or CPU/AUX
mismatches. Inferred rate remained about 3.19815 GHz. The legacy clock snapshot
reported disabled correction and zero offsets in APIC slots 0–7. These checks
retain their unauthenticated-ABI and non-independent-clock limitations. Windows
timing equivalence and TIMER remain unresolved.

## 2026-11-08 - Windows clock comparison and VMCS wrapper trimming

Latest uncommitted image SHA-256
`ba155b217c1abf18d90b60adf793d0cdf05ba55a7cb91c76a1e305149fe24b79`
booted normally by graceful software restart on daemon boot_id 7. Hot CPUID and
timer exits skip redundant trace filters; optional totals retain accounting.
Retirement's two status-discarding VMREAD calls and four status-discarding VMWRITE
sites now use inline helpers. Event clearing, pending-debug writes and retirement
semantics are retained. Local native/UBSan and assembly checks pass.

A one-time firmware boot sequence selected the direct Windows Boot Manager.
Windows LastBootUpTime was `11/8/2026 10:09:45 AM`; the daemon retained boot_id 5
because this boot emitted no loader marks. The legacy hypercall returned zeros
without its usual key echo; CPUID median was 146 TSC ticks and TIMER was clean.
The one-time selection was consumed and normal firmware order was verified before
returning to hypervisor boots 6 and 7. These observations distinguish the baseline
from the preceding hypervisor boot; daemon boot_id alone does not.

The same read-only `control/dtb/probes/clock_coherence.c` diagnostic ran on both
boot paths: four CPUs, sleep and CPUID-load phases, 1024 sequential migration
samples. Neither path produced backwards TSC/QPC or AUX/affinity mismatches.
Inferred TSC rates were approximately 3.19815 GHz on both. QPC may derive from TSC;
this is not independent wall-time calibration, and affinity-switch latency can
hide small inter-core skew. The diagnostic changes no timers or hypervisor state.

On final boot_id 7, the native latency diagnostic accepted all 2000 samples per
instruction and measured CPUID median 900 TSC ticks. Earlier candidates measured
856 (boot 4), 916/890 (boot 5) and 908 (boot 6); no repeatable improvement is
established by those small changes. VMAware `v2.8.2-56-gc8092c6`: **TIMER fires:45;
TRAP and EIP_OVERFLOW clean (0)**. Legacy clock query remains disabled with zero
reported offsets in slots 0–7. Windows timing equivalence and TIMER remain open;
no observed large clock drift is reproduced by these probes.

## 2026-11-08 - native TSC policy; initial DTB checks completed

The current uncommitted candidate removes per-exit/per-CPU clock correction and
synthetic TSC_DEADLINE translation. Legacy enable requests fail without changing
clock state. The normally unused timestamp exit fallback now distinguishes
RDTSCP, returns TSC_AUX, honors CR4.TSD and has no RDTSC hypercall side effect.
See `architecture.md` for the clock policy and validation scope.

Firmware builds locally. Native tests cover timestamp semantics, production
hypercall/timestamp dispatch and clock-MSR bitmaps, plus retirement and
dispatcher/progress behavior. After moving the session into the workspace,
the configured DTB MCP became available. A graceful software boot reached ready
on daemon boot_id 4. Built image SHA-256:
`234ed5e7e6ff928b15430db46bbcfb94897d3c23cbdfa1692e93a9879e516c53`.

On boot_id 4, unchanged VMAware revision `v2.8.2-56-gc8092c6` reports
**TIMER fires:45; TRAP clean (0)**. The existing native exit-latency probe accepted
all 2000 samples per instruction with zero backwards/AUX/affinity rejections;
CPUID(0) median was 856 TSC ticks. Its software-counter phase completed. These
are not cross-CPU TSC synchronization or QPC rate measurements. Legacy clock
queries before/after report correction disabled and zero offsets in covered
APIC slots 0–7; their unauthenticated ABI and coverage limitations remain.

No bare-metal Windows A/B was performed. The reported Windows malfunction is not
yet causally attributed: previous live records already showed correction
disabled and zero offsets. No full-suite or undetectability claim.

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
