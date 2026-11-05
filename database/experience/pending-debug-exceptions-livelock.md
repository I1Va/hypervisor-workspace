---
topic: pending-debug-exceptions-livelock
kind: experience
date: 2026-11-05
symptom_class: guest-bugcheck
---

## Symptom

Windows bugchecks with `CLOCK_WATCHDOG_TIMEOUT` (0x101) shortly after VMAware
starts, on a guest that boots and runs normally otherwise. Sometimes the machine
reboots instead of showing the bugcheck.

The hypervisor log shows no panic, no triple fault and no livelock; the serial
capture just ends. One earlier capture did contain a VM-entry failure
`0x80000021` (invalid guest state) followed by a `PANIC`.

## Why it misleads

`CLOCK_WATCHDOG_TIMEOUT` is a *secondary processor* failing to service its clock
interrupt, so the obvious reading is "a core is stuck in the hypervisor" or "the
APs are broken again". Both send you back to the INIT-SIPI path, which by then is
already correct.

The real defect is in the debug-exception bookkeeping, and it is invisible until
the guest sets `RFLAGS.TF` - which is exactly what VMAware's TRAP and
SINGLE_STEP stubs do. So the fault appears only when VMAware runs, and looks
like VMAware hanging the machine.

## Cause

`VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS` was OR-ed into and never cleared:

```c
if (Pending == 0) return;                        /* field left as-is */
vmwrite(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS,
        VmxRead(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS) | Pending);
```

The processor does not maintain this field: a VM exit does not save into it and
a VM entry does not clear it. The VMM owns it completely. So once BS was set for
one single-step it stayed set for the life of the VMCS.

A nonzero pending debug exceptions field raises `#DB` at *every* VM entry. The
core therefore delivered a debug exception before the first guest instruction,
the guest handler ran, and the next entry raised another - an endless `#DB` loop
at a single instruction boundary. That core never serviced its clock interrupt,
and Windows bugchecked the machine.

`ExitWillReExecute` returned early without clearing the field either, so the
faulting-exit path leaked it the same way.

## How to tell them apart

The discriminator is that this failure is *per core and tied to TF*, not to AP
bring-up:

- the INIT/SIPI counters are healthy (`inits 1 sipis 1`) and all four cores
  heartbeat
- the bugcheck appears only after a VMAware run, never on an idle desktop
- running the same technique repeatedly reproduces it

A genuine "core stuck in root mode" would freeze the heartbeat for that APIC ID.
Here the heartbeat keeps advancing right up to the bugcheck.

## Fix

Write the field instead of OR-ing it, on every exit, including when the value is
zero:

```c
vmwrite(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS, Pending);
```

This is self-correcting: delivering a debug exception clears `RFLAGS.TF`, so the
next exit reads TF clear and writes 0. The `ExitWillReExecute` case is handled by
masking the value rather than returning early, so a faulting exit also writes 0.

`DR6` is still only ever set here, never cleared: hardware leaves its status bits
set until software writes them, and clearing BS from the exit handler would race
a `#DB` the processor delivered natively (no exit is taken for those, so this
code never sees them).

Result: 15 consecutive technique runs across TRAP, SINGLE_STEP,
INTERRUPT_SHADOW, DBVM and THREAD_MISMATCH on one boot, plus a CPU load test, with
no bugcheck and no reboot.

## Residual risk

- Any future "pending" VMCS field must be written, not OR-ed. The processor
  maintains none of them across exits, so an OR is always a leak.
- If the guest is allowed to leave TF set and also blocks `#DB` delivery, the
  same livelock shape can recur through a different field (interruptibility
  state). The 0x101 bugcheck with a healthy heartbeat is the signature.
