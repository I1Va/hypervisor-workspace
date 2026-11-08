---
topic: 2026-11-08-owned-exit-counters
kind: experiment
date: 2026-11-08
commit: f54511d
vmaware: v2.8.2-56-gc8092c6
boot_id: 28
technique: TIMER
result: inconclusive
phase_at_failure: desktop
verdict_source: dbg_technique
---

## What was run

The candidate was an uncommitted diff on PulverizedPkg `f54511d`; the complete
source/test diff is retained as `candidate.patch`. The `commit` field identifies
the base, not a committed candidate. Consequently this record is marked
inconclusive under the recording policy, although the tool's TIMER verdict is
unambiguous. Candidate EFI SHA-256:
`201b9f957c796c8bd24740c85d4164c10e929d0eabbfbd122437237025fac2e0`.

The candidate added separate dispatcher-owned histogram storage keyed by the
validated dense context index at host `fs:4`. Its normal increments used atomic
load/store; the public multiwriter API and fallback retained atomic RMW. Readers
combined both stores. The existing APIC-range gate was preserved.

Build: `NO_DOCKER=1 ./PulverizedPkg/build.sh`. Then
`dbg_boot(method="software", wait_for="ready", timeout=60, force=false)`.
On ready boot 28, two `dbg_run` invocations each executed
`%TEMP%\exit_latency.exe 2000` and
`%TEMP%\vma-timer-diag\vma_timer.exe`. The second also ran
`%TEMP%\guest_fs.exe` and `%TEMP%\debug_events.exe collision`.
Finally, `dbg_technique` ran TIMER, TRAP and EIP_OVERFLOW separately with
`timeout=30, include_output=true`.

## Result

Both latency runs accepted all 2000 CPUID samples with no AUX, affinity or
backwards-timestamp rejections. CPUID medians were 786 and 774 TSC ticks; minima
were 752 in both. The prior committed host-FS production image on boot 27 measured
774 twice. These are descriptive cross-boot observations, not a controlled
within-boot A/B or a proven hardware floor.

TIMER wrapper output:

```text
TIMER: Instruction > VMM -> 690 | nVMM -> 98 | Ratio -> 7.04082
TIMER: Exception > VMM -> 3105 | nVMM -> 4184 | Ratio -> 0.742113
TIMER: Instruction > VMM -> 688 | nVMM -> 96 | Ratio -> 7.16667
TIMER: Exception > VMM -> 3088 | nVMM -> 4178 | Ratio -> 0.73911
```

Installed checker, all on boot 28 and revision `v2.8.2-56-gc8092c6`:

```text
TIMER: rc=0 score=45 verdict=fires:45 output=45
TRAP: rc=0 score=0 verdict=clean output=0
EIP_OVERFLOW: rc=0 score=0 verdict=clean output=0
```

Both measurement calls returned `phase=desktop, verdict=ready, rc=0`.
Guest FS completed 1000 round trips on each of four CPUs with zero observed or
restoration mismatches. The collision probe returned:

```text
case=collision hits=1 exception=0x80000004 rip_offset=14 context_dr6=0xffff4ff1 BS=1 B0=1 eflags=0x206 worker_exit=0
```

Native tests passed: stats at Os/O2 with logging on/off and UBSan, original
same-shard multiwriter tests, duplicate-APIC owned writers, concurrent readers,
fallback, publication, core-stall, host identity, and FS/VMREAD assembly with LTO.
The final linked guard inspected 8909 instructions, one FS:0 load and one FS:4
load, with no TLS or unexpected segment-base operations.

## Interpretation

The candidate did not establish a repeatable latency improvement and did not
pass TIMER. The lower wrapper numerator alone does not justify its added owner
load, metadata checks, approximately 44 KiB of static storage and reader scans.
The candidate was rejected and its exact diff reversed. Counter correctness
checks passed, but they do not establish a performance benefit. The original
public atomic-RMW counter contract remains in production.

Restoration was verified on boot 29. The rebuilt EFI exactly matched production
SHA-256 `10053ecf17a984485438cf40d2d31c521212920a60fc3bd12584c751e7258527`.
The linked guard passed 8845 instructions, one FS:0 load and no FS:4 load.
All 2000 CPUID samples were accepted, median 774 ticks. The TIMER wrapper returned
700/99 = 7.07071 and exception ratio 3108/4200 = 0.74; installed TIMER returned
`rc=0, score=45, verdict=fires:45`, with boot 29 desktop/ready and the same checker
revision. Thus the restored image reproduced the earlier production median.

## Next

Retain the linked-image guard independently. Future candidates must preserve
native clock behavior and guest instruction semantics; this histogram change is
closed unless a new design establishes a measurable benefit.
