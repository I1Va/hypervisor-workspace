---
topic: vmaware-shortcut-false-signal
kind: experience
date: 2026-11-05
symptom_class: misleading-measurement
---

## Symptom

`vmaware.exe --percent` returns in about 0.2 s with `100`, while `vmaware.exe`
with no arguments, and `--all`, both hang the guest.

It is very tempting to conclude from that: "the techniques are fine, so the
problem is in the reporting/TUI path". That conclusion is wrong.

## Why it misleads

`--percent` looks like a cheap way to run the whole suite with output suppressed.
It is not. It calls `VM::percentage()`, which calls `core::run_all(flags,
SHORTCUT)` - and with `shortcut` set the loop returns as soon as the score
crosses the threshold:

```c
if (shortcut && (points >= threshold_points)) {
    return points;            /* remaining techniques never run */
}
```

This guest already scores far above the threshold, so the run terminates after
the first handful of techniques. Everything after that point is never executed,
which is exactly why it finishes in 0.2 s.

The same applies to `-d`/`--detect` (`VM::detect` shares the shortcut path).

## Cause

`--percent`, `--detect` and `--stdout` are **early-exit** modes. They are not a
silent full run. Zero information about any technique past the threshold can be
obtained from them.

## How to tell them apart

Watch the elapsed time. A genuine full pass over ~80 techniques on this stand
takes on the order of a second or more; 0.2 s means it bailed out early.

The definitive check is to time the same binary with a technique that is known to
be expensive (or to time out on its own) enabled and compare.

## Fix

Do not use `--percent`/`--detect` as a stand-in for a full run. For completeness
use no-argument mode (the "full summary") or `--all`, and accept the cost.

## Second trap in the same area

`--all` does **not** mean "the full summary". Per the tool's own help:

> `-a | --all` - run the result with ALL the techniques shown and enabled

On Windows the checker normally skips techniques that are not Windows-applicable
(`is_unsupported()` gates on `WINDOWS_START..WINDOWS_END`), but with `--all` the
skip is bypassed and the technique is executed anyway:

```c
if (is_unsupported(flag)) {
    unsupported_count++;
    if (arg_bitset.test(ALL) == false) { return; }
}
const bool result = VM::check(flag);      /* --all runs it regardless */
```

So `--all` executes Linux/MacOS-only vectors on Windows. A hang under `--all` may
be an out-of-platform vector being run where it was never meant to run, and says
nothing about the Windows detection surface.

## Residual risk

Any future bisection must build its `--disable` list from the binary's own
technique list (`case X: return "NAME"` in `vmaware.hpp`) rather than a
hand-written list, because a missing name silently means "technique stays
enabled". Note also that `VCPU_SCHEDULING` and `EMULATION` are rejected as
`--disable` arguments ("Unknown technique"), so they cannot be excluded that way.
