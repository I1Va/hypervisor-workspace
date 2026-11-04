---
topic: vmaware-measurement-traps
kind: experience
updated: 2026-11-04
see: [detection-status, experiment-recording]
---

# Four ways a VMAware run lies to you

Each of these produced a confident, wrong verdict that was believed for days.
They are ordered by how expensive they were.

## 1. `-d` is thresholded at 150, so weak detections read as clean

`-d` returns a thresholded boolean: 1 only when the total score reaches 150. A
technique scoring 45 prints 0 and looks clean. `SYSTEM_FIRMWARE` at 45 was
reported "clean" this way.

Use `--percent`: it returns the accumulated score itself, so with one technique
enabled the value is that technique's own weight.

## 2. `--disable` aborts the entire run on an unknown name

`VCPU_SCHEDULING` and `EMULATION` are declared in `vmaware.hpp` but rejected by
the binary. Passing either in `--disable` makes VMAware exit immediately - which
is indistinguishable from a clean result: `seconds=0`, nothing detected.

The technique list is therefore parsed from `vmaware.hpp` and filtered against a
verified unsupported set, rather than hand-maintained.

## 3. The full summary never reaches a file over SSH

`PRINT_LINE` routes through the TUI, which writes into a console buffer. With no
console the output is discarded and the output file stays at 0 bytes - even with
`-o`, `--no-ansi` or `--json`.

Worse, `general()` ends in `console_pause()`, which blocks on stdin forever. So
a full-suite run appeared to produce nothing **and** left a `vmaware.exe`
spinning, which then degraded the guest and made the next run look like a hang.
Feed `< NUL` so `console_pause()` returns at EOF.

## 4. A leftover process makes the stand look hung

A `vmaware.exe` left spinning from an earlier run keeps the guest at roughly
100x normal command latency. Observed: 35 s per SSH command with two leftovers,
122 ms after killing them.

`dbg_technique` and `dbg_suite` kill leftovers first, because otherwise the next
measurement is contaminated by the previous one.

## The general lesson

Before believing any result, check that the tool was **capable** of reporting.
A run that produces no output and leaves a process behind looks exactly like a
hypervisor hang. See `stale-probe-processes.md`.
