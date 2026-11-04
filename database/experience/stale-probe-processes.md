---
topic: stale-probe-processes
kind: experience
date: 2026-11-04
symptom_class: slow-guest
---

## Symptom

Every command on the guest takes 8-35 s. `probe.py` says ALIVE. Nothing errors.
The stand looks "fine but slow", so the first instinct is that the network or the
hypervisor is at fault.

## Why it is misleading

It presents as a hypervisor performance problem. The hypervisor is innocent; the
guest is simply out of CPU because a previous run left a detection tool spinning.

## Cause

`vmaware.exe` does not always exit. `general()` ends in `console_pause()`, which
blocks on stdin forever, so a non-interactive run can hang after printing. Over a
few runs several copies accumulate. Each one burns a core scanning ntdll.

Measured on this stand: two leftover processes; a `hostname` command took 35 s
with them and 122 ms after `taskkill`.

## How to tell them apart

Run `tasklist /fi "imagename eq vmaware.exe"` on the guest. Any output above the
header means leftovers exist. This is worth doing before blaming the hypervisor
for slowness.

A second signal: SSH handshake slowness. A healthy guest completes one in
~100 ms; a starved one takes tens of seconds. The daemon reuses one master, so
after the first command a slow command is a real signal rather than handshake
overhead.

## Fix

Kill leftovers before every measurement. `dbg_technique` and `dbg_suite` do this
as their first step, and report the count in the `killed` field, so a contaminated
environment is visible in the result rather than silently inherited.

## Residual risk

Any other runaway process on the guest has the same effect. The measurement
itself is only protected against `vmaware.exe`, which is the one known to do it.
