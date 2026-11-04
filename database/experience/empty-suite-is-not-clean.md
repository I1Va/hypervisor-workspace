---
topic: empty-suite-is-not-clean
kind: experience
date: 2026-11-04
symptom_class: false-confidence
---

## Symptom

The full suite ran for 669 seconds, wrote a result file, and reported
`seconds=669.0`. It contained **zero** per-technique lines. The harness called
that `verdict: clean`.

## Why it is misleading

"Ran to completion with nothing detected" and "ran to completion without
recording anything" produce the same file, and the first is the goal of the whole
project. So the wrong reading is the one you *want* to be true, which is why it
survived as a believed result while the detection actually persisted.

## Cause

VMAware's `PRINT_LINE` routes through its TUI, which writes into a console
buffer. With no console - which is every SSH session - the summary lines are
discarded. `run_full_suite.ps1` still appends its own `=== seconds=` timing line,
so the file exists, is non-empty, and looks like a completed run.

## How to tell them apart

Count the per-technique lines before interpreting any verdict:

```
[ NOT DETECTED ] Checking <NAME>...
[   DETECTED   ] Checking <NAME>...
```

`checked == 0` means nothing was verified, regardless of how long it ran or what
the timing line says.

## Fix

`suite` now returns `verdict: inconclusive` with an explicit explanation when the
result file has no technique lines, instead of `clean`. The verdict values are
deliberately distinct so a caller cannot mistake one for the other.

Per-technique results come from `dbg_technique`, which uses `--percent` and
therefore reports the score itself rather than a thresholded boolean.

## Residual risk

The suite remains useful for "did anything change" only when it produces lines.
Until the TUI capture limitation is worked around, `dbg_technique` is the
authoritative source for a score, and `dbg_suite` is a smoke test.
