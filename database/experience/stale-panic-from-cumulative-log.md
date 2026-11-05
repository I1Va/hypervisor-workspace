---
topic: stale-panic-from-cumulative-log
kind: experience
date: 2026-11-05
symptom_class: false-panic
---

## Symptom

`dbg_boot` returns `verdict: panic` with a message naming a VM-exit failure, on
every boot, even after reverting the hypervisor to a commit that booted minutes
earlier. `dbg_status` keeps reporting the same panic while the serial heartbeat
advances normally. Power-cycling does not clear it. Boot reports show
`serial_bytes: 0` for the "panicking" boot, which is the giveaway: a machine that
panicked would have printed something.

## Why it misleads

The verdict looks like a hypervisor fault, and the detail even quotes a real
panic line, so the natural next step is to bisect the source. That wastes the
session: the message is from an *earlier* boot, and the current image is fine.
Because `dbg_boot` treats `panic` as terminal, it also refuses to boot again, so
the stand looks broken when it is healthy.

## Cause

`parse_serial` in `control/dtb/daemon.py` scanned the last 256 KiB of the serial
capture. That file is cumulative across every boot since the daemon started, so
"the tail" is not "this boot". A panic line stays inside the window until 256 KiB
of newer output pushes it out — which can be many boots later. The classifier
then reports `panic` for a machine that is booting normally.

## How to tell them apart

Two checks, either is conclusive:

- `dbg_status` reports `serial_bytes` unchanged (or 0) across the "panicking"
  boot. No new bytes means no new panic.
- Compare byte offsets in the capture. If the last `PANIC` offset is *lower*
  than the last boot marker (`[HV] runtime log online`), the panic is older than
  the current boot:

  ```
  grep -boa "PANIC" /tmp/opencode/dtb/serial.log | tail -1
  grep -boa "\[HV\] runtime log online" /tmp/opencode/dtb/serial.log | tail -1
  ```

A second, cheaper discriminator: put a unique string in the hypervisor banner
(`Sources/Pulverized.c`) and grep the capture for it. If it appears, the build
you served is the build that ran, and any panic in the window is not from it.

## Fix

`parse_serial` now scopes to the current boot: it finds the last
`[HV] runtime log online` marker and scans only from there, falling back to the
256 KiB tail when no marker exists. Panic, heartbeat, last-enter and the
EBS/loader flags all read from that scope.

## Residual risk

- A panic *within* the current boot is reported correctly, which is what the
  verdict is for.
- If a boot produces no `runtime log online` marker at all (very early death,
  before the banner), the fallback window applies and the old behaviour returns.
- The capture is never truncated, so it grows without bound; a daemon restart
  resets the boot counter but not the file. Truncating on restart would make the
  offsets above less useful, so it was left alone.
