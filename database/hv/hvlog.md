---
topic: hvlog
kind: reference
updated: 2026-11-04
see: [architecture, com1-power-gating, detecting-a-wedge]
---

# Hypervisor debug log

Reading this log correctly is the difference between a five-minute diagnosis and
a wasted session. There are three channels, and they fail in different ways.

## The three channels

| Channel | Survives a hang | Survives Windows' power management | Cost |
|---|---|---|---|
| COM1 serial (115200) | mostly | **no** | high - busy-wait in the exit path |
| RAM ring buffer (64 KiB) | yes | yes | cheap |
| `PANIC()` path | no | no | - |

The RAM ring is read by the guest through `HYPERCALL_READ_HVLOG`. That is the
only channel that works when serial has been power-gated, which is why it exists.

## The heartbeat

```
[HV] heartbeat <N> guest rip <rip>
```

Printed from the preemption-timer exit, once per 64 ticks. The timer only
**counts guest execution**, so:

- heartbeat advancing → the guest is running,
- heartbeat frozen with a fresh console → the guest may have stopped executing;
  a silent console makes the heartbeat unobservable.

`dtbd` combines this signal with console freshness when assessing a timeout.
If the console is silent or a counter is missing, it reports `unknown` rather
than inferring a wedge.

## Other markers

| Marker | Meaning |
|---|---|
| `[HV] runtime log online` | the DXE driver (re)initialised — count these to identify a netboot cycle |
| `VMLAUNCH` | per-core virtualisation start |
| `ExitBootServices was called` | firmware handed off; Windows takes over |
| `[HV] enter <reason> rip <rip>` | a handler was entered — if the log stops here, that handler is the wedge |
| `[HV] R<reason> #<count>` | throttled per-reason trace; the reason with a runaway count is the storm |

## Why silence proves nothing

Windows power-gates COM1 when idle: every register then reads `0xFF` and the log
stops, on every boot, at a fixed point. A silent console is therefore **not**
evidence of a hang. See `experience/com1-power-gating.md`.

Corollary rules:

- Never conclude "the hypervisor died" from silence alone. Check the heartbeat
  and the network first.
- Writing `0x07` to the UART FIFO control register mid-line truncates the line.
  Only `0x01` is safe.
- `HvLogSetSerial` must only flip a flag; programming the divisor belongs in
  `HvLogInit` and in the write-failure repair path.

## Cost, and why serial is rationed

A character write busy-waits on TXRDY. At 115200 baud a 45-character line is
~4 ms inside a VM-exit handler, and a 64 KiB dump is ~5.7 s. An earlier build
that dumped from the routine exit path stalled boot completely; an armed trace
produced 5 MB, which at that baud rate is about seven minutes of busy-waiting.

So: serial is on during boot, off after `ExitBootServices`, on for `PANIC`, and
on for one heartbeat line per 64 ticks. Bytes are rationed against guest
progress (`HvLogNoteGuestProgress`) to limit tracing overhead. Debug output can
still slow the guest significantly and affect timing-sensitive tests.

## Reading it through the harness

`dbg_log --grep ... --limit N` plus the returned `cursor`. Pass the cursor back
to read only what is new: boot transcripts run to megabytes and re-reading them
is the main way an agent wastes context.
