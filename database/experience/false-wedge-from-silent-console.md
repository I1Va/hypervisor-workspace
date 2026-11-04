---
topic: false-wedge-from-silent-console
kind: experience
date: 2026-11-04
symptom_class: false-positive-wedge
---

## Symptom

The stand reported `wedged`: kernel reachable, SSH up, hypervisor heartbeat
frozen for 221 s. Every signal said the hypervisor had stopped executing, and
the correct response to that verdict is a reset.

The guest was fine. A command answered in 7.8 s while that verdict was showing.

## Why it is misleading

`wedged` is the most destructive verdict the harness can produce: it justifies
rebooting the machine and discarding a run. So a false positive is worse than no
verdict at all. The evidence looked strong - a counter that had not moved for
over three minutes - and the conclusion was still wrong.

## Cause

Windows power-gated COM1. The heartbeat is only observable through the serial
log, so gating the UART freezes the observable counter **without the guest
stopping**. The log being silent was read as "the tracer has nothing to say",
when it actually meant "the tracer cannot speak".

This is the same underlying fact as `com1-power-gating.md`, but the failure mode
is the opposite one: there, silence hid a healthy machine; here, silence was
taken as proof of a dead one.

## How to tell them apart

Ask what the network proves independently:

- TCP:22 accepting ⇒ sshd is listening ⇒ **userland is running**.
- A frozen counter ⇒ only "no guest execution *observed*", not "none happened".

So a frozen counter is evidence of a wedge **only while the console is still
producing bytes**. If the console is silent too, the heartbeat is unobservable,
and the honest verdict is what the network shows.

## Fix

`State.classify` now requires a fresh console (`serial.age < 5 s`) before
believing a frozen heartbeat. With a silent console and a reachable guest it
reports `ready` or `booting` and says the heartbeat cannot be read.

Separately, `dbg_boot` now starts the guest-side COM1 keepalive as part of
bringing the stand up. It used to be an undocumented manual step, which is
exactly why a fresh boot silently lost its trace.

## Residual risk

A machine that is genuinely wedged **and** whose console is gated will report
`ready` rather than `wedged`. A command will then time out, and the timeout path
has the same problem: it compares heartbeats, which are stale either way. In that
case the distinguishing observation is that commands never complete while TCP
stays open - so treat repeated timeouts with a silent console as a probable
wedge, and reset.
