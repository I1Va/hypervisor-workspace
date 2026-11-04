---
name: dtb-harness
description: Use for any work on the DTB test stand - booting it, running commands on the Windows guest, running VMAware, reading the hypervisor debug log, or deciding whether a hang is real. Covers the dbg_* tools and the rules that keep results trustworthy.
---

# DTB harness

The physical stand is controlled by one daemon through one small set of tools.
Use them. Do not open serial ports, do not call `ssh` directly, and do not run
the legacy `tools/*.py` scripts - they predate the daemon and most of them are
now wrong (see "Why the old scripts are not used" below).

## The tools

| Tool | Use it for |
|---|---|
| `dbg_status` | **First call for every question about the stand.** Power, network, ssh, boot phase, verdict, heartbeat age, build freshness, recent transitions. |
| `dbg_power` | `on` / `off` / `reset` / `cycle`. Prefer `reset`. |
| `dbg_boot` | Serve + reset + follow phases. Refuses a stale image. |
| `dbg_run` | One shell command on the guest. ~0.3 s, not 8-35 s. |
| `dbg_log` | Debug serial capture, with `grep` and an incremental `cursor`. |
| `dbg_technique` | One VMAware technique in isolation, with its score. |
| `dbg_suite` | The whole VMAware suite. |
| `dbg_firmware` | Ask the Arduino for its version. |

## The rule that matters most

**Never treat a timeout as a failure until you have read the verdict.**

Every timeout is already resolved for you using the hypervisor heartbeat, which
only advances while the guest executes:

| Verdict | Meaning | Response |
|---|---|---|
| `slow` | timed out, heartbeat advanced | retry with a longer timeout, or reduce logging/load |
| `wedged` | timed out, heartbeat frozen, kernel alive | nothing will improve by waiting; `dbg_power reset` |
| `hung` | no network and no console progress | check the LED, then `dbg_power cycle` |
| `ready` | ssh shell available | proceed |
| `booting` | coming up | **wait. Do not reset a booting machine.** |
| `panic` | hypervisor said why on the console | `dbg_log --grep PANIC` |

A silent serial log is **not** evidence of a hang: Windows power-gates COM1 when
idle. The heartbeat plus the network is the evidence.

## Order of operations

1. `dbg_status`. Act on the verdict; do not run anything else first.
2. If `booting`, wait. If `off`, `dbg_power on`. If `wedged`, `dbg_power reset`.
3. Build before testing. `dbg_boot` refuses a stale image on purpose.
4. After a change: `dbg_boot`, then `dbg_run`, then `dbg_technique` or `dbg_suite`.

## Why the old scripts are not used

`tools/` is legacy and mostly superseded. Two of them were outright broken:
`try_technique.py` read `database/VMAware/...` (the directory moved) and
`bisect_vmaware.py` shelled `tools/probe.py` relative to the working directory.
`probe.py` also cannot distinguish slow from wedged, which is the distinction
that decides whether to reset - so it is not just slower, it is wrong.

Anything you still need from that directory, ask the harness for instead.

## Recording results

A technique score or suite verdict is only meaningful with the build and the
VMAware revision next to it. Both tools return `boot_id` and `vmaware_rev` for
exactly this reason - quote them. See `database/policies/experiments.md`.
