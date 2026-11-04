---
topic: silent-root-mode-livelock
kind: experience
date: 2026-11-04
symptom_class: total-silence
---

## Symptom

SSH stops answering. Serial is silent. The power LED is on. Nothing anywhere says
why. A reset is the only recovery.

## Why it is misleading

There is no output at all, so the natural conclusion is "the hypervisor crashed".
In fact the hypervisor is running perfectly - it is just looping in a handler and
never returning to the guest.

## Cause

Two independent handlers had no exit path:

1. **`HandleMonitorTrapFlag` was an empty stub.** MTF is set when an EPT hook
   fires. While it stays set, every VM entry raises an MTF exit immediately. The
   guest never executes, and because the preemption timer only counts guest
   execution, the heartbeats stop too - so the usual "is it alive" signal is
   gone as well.
2. **`HandleEptViolation` always returned "redo instruction".** With no matching
   hook, that retries the same instruction forever.

## How to tell them apart from a crash

A crash usually prints something, or at least the last exit reason stays in the
log. Silence plus a live machine plus a frozen heartbeat is the signature of a
root-mode livelock.

The discriminating evidence is `[HV] enter <reason> rip <rip>`, logged
immediately before dispatch: when a handler never returns, that is the last line
written, and it names the culprit. This is exactly why `HvLogEnter` exists.

## Fix

- `HandleMonitorTrapFlag` now clears MTF, then re-arms the hooks that
  `EptHandleHookedPage` removed.
- `HandleEptViolation` only redoes the instruction when a hook handled it;
  otherwise it logs address/qualification/RIP over serial and steps over.
- A livelock detector reports a long unbroken run of the same
  (exit reason, guest RIP) over serial, since that survives a hard wedge.

## Residual risk

Any new handler that can spin in root mode reintroduces this class of failure.
Two rules for every handler:

- it must always return to the guest, or log and step over;
- it should log on entry if it does real work, so a wedge names itself.

Never add an unbounded loop to the exit path to "wait for" something.
