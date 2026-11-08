---
topic: 2026-11-08-vmx-entry-call-space
kind: experiment
date: 2026-11-08
commit: 3c981ee
vmaware: v2.8.2-56-gc8092c6
boot_id: 30
technique: TIMER
result: fires:45
phase_at_failure: desktop
verdict_source: dbg_technique
---

## What was run

Removed the balanced `sub rsp, 0x20` / `add rsp, 0x20` around the System V
`VmExitHandler` call in `VmxEntryPoint`. The host stack starts 16-byte aligned;
the GPR and XMM frames total 0xe0 bytes, so removing the 32-byte reservation
preserves call alignment and guest-state offsets. Existing SIMD saves remained.
The candidate commit also adds native entry-frame tests and function-size
metadata for linked instruction coverage.

Candidate EFI SHA-256:
`76f1f699a9c3a99ca4c4c7c97c18e33c1a9ffdf5dd675fd05638a47ea253becf`.
Built with `NO_DOCKER=1 ./PulverizedPkg/build.sh` after committing `3c981ee`.
Booted using `dbg_boot(method="software", wait_for="ready", timeout=60,
force=false)` to ready boot 30.

Two `dbg_run(timeout=35)` calls each ran `%TEMP%\exit_latency.exe 2000` and
`%TEMP%\vma-timer-diag\vma_timer.exe`. The first also ran
`%TEMP%\guest_fs.exe` and `%TEMP%\debug_events.exe collision`.
Then `dbg_technique` ran TIMER, TRAP and EIP_OVERFLOW separately with
`timeout=30, include_output=true`.

## Result

Both CPUID medians were **777 TSC ticks**, accepting all 2000 samples with no
AUX, affinity or backwards-timestamp rejections. Prior production boot 29
measured 774. This cross-boot comparison does not establish a causal 3-tick
regression, and it does not demonstrate a speedup.

TIMER wrapper output:

```text
TIMER: Instruction > VMM -> 701 | nVMM -> 101 | Ratio -> 6.94059
TIMER: Exception > VMM -> 3103 | nVMM -> 4182 | Ratio -> 0.741989
TIMER: Instruction > VMM -> 702 | nVMM -> 102 | Ratio -> 6.88235
TIMER: Exception > VMM -> 3108 | nVMM -> 4188 | Ratio -> 0.74212
```

Installed VMAware, boot 30, revision `v2.8.2-56-gc8092c6`:

```text
TIMER: rc=0 score=45 verdict=fires:45 output=45
TRAP: rc=0 score=0 verdict=clean output=0
EIP_OVERFLOW: rc=0 score=0 verdict=clean output=0
```

Both guest command calls returned `rc=0, phase=desktop, verdict=ready`.
Guest FS completed 1000 round trips on each of four CPUs with zero observed or
restoration mismatches. Exception collision output:

```text
case=collision hits=1 exception=0x80000004 rip_offset=14 context_dr6=0xffff4ff1 BS=1 B0=1 eflags=0x206 worker_exit=0
```

Native execution of the actual entry instructions, with only VMRESUME replaced
by a continuation jump, passed at O2 and Os with UBSan. It checks all 15 GPRs,
CPUID output writeback, XMM0–5 restoration, handler-entry alignment, production
header offsets, and stack canaries. No simulator or VMX instruction is executed
by that test.

## Interpretation

Removing the unnecessary ABI reservation did not demonstrate a latency gain or
pass TIMER. The runtime change was rejected in `d6fd841`. The native ABI test
was retained and supports both balanced layouts. Function-size metadata and a
linked-test assertion were also retained: the previous sized-function scan had
omitted `VmxEntryPoint`. The restored guard now checks 8894 instructions instead
of 8845, with one FS:0 load and no TLS or unexpected segment-base operations.

The restored EFI exactly matches the prior production SHA-256
`10053ecf17a984485438cf40d2d31c521212920a60fc3bd12584c751e7258527`.
It booted successfully as boot 31, desktop/ready, by software restart.
The restored native ABI test also passed O2/Os with UBSan. These measurements
rule out a demonstrated gain from this local change, not other optimizations or
an architectural latency floor.

## Next

Keep the native entry ABI and linked coverage guards. TIMER acceptance remains
open; further candidates must preserve native clocks and instruction semantics.
