---
topic: breaking-the-stall
kind: experience
date: 2026-11-06
symptom_class: no-progress
---

# What broke the stall

This is the lesson about *how the deadlock was broken*, not about any single
bug. It is written because the technical fixes are documented elsewhere
(`thread-mismatch.md`, `suite-hang-status.md`, `fast-startup-hides-boot-config.md`,
`debug-exception-delivery.md`) but the reason a long stall ended is not obvious
from any of them, and a future session will stall the same way.

## Symptom

Many sessions of work, a hypervisor that booted, and no measurable progress:

- VMAware reported five-to-six firing vectors for weeks.
- The full suite "hung", so every attempt ended in a reset rather than a
  measurement.
- Changes were made, tested, and reverted without any of them being shown to
  matter.
- Every individual experiment *looked* like it had been run. None of them
  *was* a measurement, because each one had a confound that was not visible
  from inside the experiment.

That last point is the stall. It was not a lack of effort or a lack of ideas.
It was that the feedback loop was broken: the experiments could not fail.

## Why it misleads

Three separate mechanisms made results meaningless, and each one is invisible
from the experiment that is affected by it:

1. **The guest was not rebooting.** A relay power cycle hibernated Windows and
   the next power-on resumed the saved kernel. Boot configuration changes were
   written, correctly, to disk and never read. Any experiment depending on the
   guest re-initialising was measuring the previous boot.
2. **A "clean" score could be a threshold artifact.** `--percent -d` exits early
   once the score crosses a threshold, so a 45-point detection printed `0`. A
   pass that took 0.2 s was not a pass; it was an early exit.
3. **A "hang" was usually not the hypervisor.** Leftover `vmaware.exe` processes,
   a second-pass bug in the summary that ignored `--disable`, and the session-0
   / session-1 split all produced symptoms that looked exactly like a hypervisor
   wedge.

## The four things that actually moved it

Each one is worth more than the bug it fixed, because each one restored
observability.

### 1. Stop guessing about state; read it

Every restart of the investigation began with `dbg_status`, and the decisive
turns all came from **a value read from the machine rather than inferred from
behaviour**:

- `NumberOfLogicalProcessors` — read as 1, which is the fact that proved the
  INIT-SIPI handshake was broken. The symptom had been "sometimes slow", which
  pointed at nothing.
- `NtQuerySystemInformation(SystemKernelDebuggerInformation)` — read
  `KernelDebuggerEnabled=1`, which proved the kernel debugger owned `#DB` and
  `DR0-3`. The symptom had been "the four debug vectors fire", which is
  consistent with at least five different causes.
- `powercfg /a` — listed `Hibernate` and `Fast Startup`, which is the fact that
  explained a whole class of reverted settings.
- A `C:\` marker file that survived a power cycle — which *disproved* "the image
  is a ramdisk" before that theory could cost another session.

The rule that comes out of it: **if the state can be read, never infer it.** A
whole class of dead ends here were theories about state that a single query
would have settled.

### 2. Make the instrument say why it failed

Two tool failures consumed the most time, and both were the same bug: an error
message that described the *symptom* of the tool rather than the *reason*.

- `dbg_screenshot` returned `Error executing tool dbg_screenshot` for a whole
  session. The actual reason was `the DTB is at the login screen (no
  explorer.exe)`. The command was also advertised in `dtbctl`'s own help but had
  no dispatch branch, so it fell through to "unknown command". Two real defects,
  both invisible, because the MCP layer discarded the exception text.
- A `dbg_technique` failure likewise surfaced as `Error executing tool
  dbg_technique` with no detail.

Both were fixed by making failure *explain itself* (`_fail()` in `mcp_dtb.py`,
plus the missing CLI branch). This is not cosmetic. An opaque error makes a
broken tool indistinguishable from a working tool that found nothing, and the
natural response — retry, or work around it — destroys the information.

**The rule: a tool that fails must say what it observed and what it wanted.**

### 3. Separate the instrument from the thing measured

The suite "hung" repeatedly. The breakthrough was not fixing the hang; it was
**running one technique per boot** (`dbg_technique NAME`) instead of the suite.
That converted an unattributable hang into a per-technique sweep with a named
culprit, and it produced the finding that 78 of 78 techniques ran in one boot
with no panic — so the "hang" was not one broken thing but a specific
interaction.

The same idea in another form: for the `#DB` work, a purpose-built probe
(`trapdb.cpp`) that runs five cases in isolation and prints the exact `DR6`
was worth more than any number of VMAware runs, because VMAware reports a
boolean and the probe reports a measurement.

**The rule: when a composite test is stuck, decompose it until each part can be
run alone, and build a probe that reports the quantity rather than the verdict.**

### 4. Take the user's observation literally

The user said: "when you power off pc after it was on, `restoring` blue screen
appears."

That single sentence explained a failure mode that had already survived several
sessions of work: Windows was hibernating, so every "real reboot" was a resume,
so every boot-configuration experiment was void. It was decisive because it
identified the *boot path*, not the setting.

The same happened with "do reboot from user mode; if pc hangs use arduino power
off" — which produced `os_power`, and with "disable multicore?" which was worth
answering with a measurement rather than an opinion.

**The rule: a user's description of a physical symptom outranks any theory
derived from logs, because it is an observation of the system the logs do not
cover.**

## What concretely followed

| Fix | Enabling observation |
|---|---|
| APC/INIT-SIPI: UART writes removed from the handshake | `NumberOfLogicalProcessors` read 1 |
| VMCALL advances guest RIP before injecting `#UD` | a single core livelocked on one RIP |
| `GUEST_PENDING_DEBUG_EXCEPTIONS` written, not OR-ed | endless `#DB` loop, `CLOCK_WATCHDOG_TIMEOUT` on an AP |
| Per-core heartbeat/NMI/stall state | false "APs stopped" reading, traced to a non-atomic shared `STATIC` |
| Kernel debugger disabled | `KernelDebuggerEnabled=1` from a supported API |
| `os_power` (restart from inside Windows) | "restoring" screen on power-on |
| `screenshot` dispatch branch + `_fail()` | an opaque tool error hid two real defects |

Net effect: `THREAD_MISMATCH` 45 → clean, `SINGLE_STEP` clean, `DBVM` clean,
`NVRAM` clean, the suite stopped hanging, boot 76 s → ~50 s, and the guest runs
four logical processors instead of one.

## Discriminating observations worth remembering

These are the cheap checks that separate a real hypervisor fault from an
instrument fault. Each cost a session to learn.

| Symptom | Check that settles it |
|---|---|
| "VMAware says clean" | did it take more than ~1 s? `--percent`/`-d`/`--stdout` early-exit at the threshold |
| "the machine is wedged" | `dbg_status` verdict, then `heartbeat_age`; `slow` means wait |
| "serial is silent" | is COM1 power-gated? a heartbeat is `[HV] heartbeat N apic M` |
| "settings revert" | marker file on `C:` **and** `powercfg /a` for Hibernate |
| "the hypervisor hangs" | was a leftover `vmaware.exe` running? was the kernel debugger on? |
| "the full suite produces nothing" | run one technique per boot |
| "the tool is broken" | does it explain *why*, or only *that* it failed? |

## Residual risk

- The stand is still fragile: a power-off during `hv_boot` needs off → on →
  `dbg_boot`. Do not read a failed boot as a code regression without checking
  that the image was fresh (`build.fresh`) and the boot actually incremented
  `boot_id`.
- Because `--percent` early-exits, a *fast* `clean` is never evidence. Only a
  full-threshold run or a per-technique score is.
- The hypervisor's own heartbeat can be stale while the guest is perfectly
  healthy (the counter repeats per core). A stale `heartbeat_age` is not proof
  of a wedge; the verdict is.
