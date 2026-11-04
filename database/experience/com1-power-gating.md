---
topic: com1-power-gating
kind: experience
date: 2026-11-04
symptom_class: silent-serial
---

## Symptom

Boot logs fine, then output stops at a fixed point after Windows starts, on every
boot. The hypervisor appears to have died, but the machine keeps working and SSH
still answers.

## Why it is misleading

Silence is the one thing that looks identical for "the tracer stopped writing"
and "the whole machine stopped". Every instinct says the hypervisor crashed.

## Cause

Windows power-gates COM1 when it is idle. The UART goes to D3, the legacy I/O
range stops decoding, and **every register reads `0xFF`**:

```
LSR=0xff MCR=0xff LCR=0xff IER=0xff FCR=0xff DIV=65535
```

The port is not misprogrammed. It is powered down.

## How to tell them apart

Holding a handle open brings the device back to D0 and the log resumes within one
heartbeat. If opening the port restores output, the port was gated and nothing
was wrong with the hypervisor.

Also check the heartbeat in `dbg_status`: a guest that is executing normally with
a silent console is the signature of power gating, not of a crash.

## Fix

The guest-side keepalive holds the port open for the whole session, started
through WMI so it survives the SSH session ending. `PnPCapabilities=0x18` in the
device registry key is **not** enough on its own.

## Residual risk

A silent console still cannot prove a hang, and a wedged guest still cannot run
the reader that would restore it. So: silence plus a frozen heartbeat is
ambiguous, and both readings lead to a reset anyway.

Related traps that cost time:

- Writing `0x07` to the FIFO control register mid-line clears the transmit FIFO
  and truncates the line. Only `0x01` (enable, no clear) is safe.
- Reconfiguring the UART between characters corrupts the line it is printing.
- `HvLogSetSerial` must only flip a flag; programming the divisor belongs in
  `HvLogInit` and in the write-failure repair path.
