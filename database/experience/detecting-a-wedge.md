---
topic: detecting-a-wedge
kind: experience
date: 2026-11-04
symptom_class: ambiguous-hang
---

## Symptom

The guest stops answering. SSH times out, or hangs, or the machine simply does
not respond. It is impossible to tell from the outside whether the guest is busy
or dead.

## Why it is hard

A TCP connect succeeds as long as the kernel is alive, even when every process is
starved. A failed SSH connection can mean a hung hypervisor, a loaded guest, or a
network problem. Every one of those has the same symptom and a different correct
response:

- busy → **wait** (resetting destroys the run)
- hung (root mode) → **reset** (waiting never helps)

Getting this wrong costs either a wasted machine boot or a discarded experiment.

## How to tell them apart

The hypervisor heartbeat.

```
[HV] heartbeat <N> guest rip <rip>
```

It is printed from the preemption-timer exit, and the timer counts **only guest
execution**, so:
- if it advances, the CPU is running guest code → the guest is slow, not hung;
- if it is frozen, no guest code has executed → the guest is wedged.

TCP being alive while the heartbeat is frozen is the signature of a **root-mode
wedge**: the network stack answers from an interrupt path while no scheduled
thread ever runs.

`dbg_status` reports both facts and the derived verdict. Read `verdict` and
`detail`, not just "ssh timed out".

## Fix

The old `probe.py` (a bare TCP connect to :22) was replaced with the `dtbd`
state machine, which combines the heartbeat with the network state and reports
`ready` / `booting` / `wedged` / `hung`.

## Residual risk

A frozen heartbeat plus a silent serial port is ambiguous on its own, because
Windows power-gates COM1. The heartbeat itself is only observable through the
serial log (or the RAM ring, which needs a working guest). So a machine that is
wedged *and* whose COM1 is gated will look like "hung" rather than "wedged" -
both lead to a reset, so the distinction costs little.
