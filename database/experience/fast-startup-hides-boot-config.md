---
topic: fast-startup-hides-boot-config
kind: experience
date: 2026-11-06
symptom_class: settings-revert
---

## Symptom

A change made with `bcdedit` on the DTB guest appears to succeed and then is
gone after the next power cycle:

```
bcdedit /debug {current} off
The operation completed successfully.
bcdedit /enum {current} | findstr /i debug
debug                   No              <- correct, immediately after

<power off, power on>

bcdedit /enum {current} | findstr /i debug
debug                   Yes             <- reverted
```

The disk is persistent - a marker file written to `C:\` survives the same power
cycle - so "the image is a ramdisk" is the wrong explanation.

## Why it misleads

`C:\` persisting makes it look as though the write was lost, or that something
rewrites the BCD at boot. Neither is true. The value really is on disk, in
`\EFI\Microsoft\Boot\BCD` on the EFI System Partition.

What is wrong is the *boot itself*: powering off does not shut Windows down.

## Cause

The guest has Fast Startup (`HiberbootEnabled`) and Hibernate available, so a
power-button press puts Windows into hibernation. The next power-on **resumes
the saved kernel** - visible as the "Restoring your previous version of Windows"
screen. A resumed kernel was initialised with the *old* boot configuration, so
the new value is never read, no matter how many times the machine is power
cycled.

The Arduino relay cannot distinguish "power off" from "hibernate": it presses the
same button either way.

## How to tell them apart

Two observations, both cheap:

1. `powercfg /a` lists `Hibernate` and `Fast Startup` as available.
2. The screen shows "Restoring your previous version of Windows" on power-on
   rather than a normal boot.

The decisive one: change a boot setting, then restart **from inside Windows**
(`shutdown /r /f /t 0`) instead of pressing the button. The setting then
persists. That isolates the boot path from the disk.

## Fix

Restart from inside the OS whenever the experiment depends on the guest really
re-initialising:

```
dtbctl os_power reboot      # or the dbg_os_power MCP tool
```

That is a genuine boot, so `bcdedit`, driver state and kernel debug settings all
take effect. Keep the Arduino relay for what it is actually good at: recovering a
machine that is hung or already off.

Measured result of getting this right: `NtQuerySystemInformation(
SystemKernelDebuggerInformation)` went from `KernelDebuggerEnabled = 1` to `0`,
and with the kernel debugger off, `SINGLE_STEP` and `DBVM` became clean and all
five `#DB` probe cases began delivering exceptions.

## Residual risk

- A relay power cycle is still required after a hang; do not read "the machine
  came back" as "the machine rebooted". Compare the boot id, which is why
  `os_power` reports `boot_before` and `boot_id` and says so when they match.
- `shutdown /s /f /t 0` can still leave the machine in a hybrid state; if a
  setting must be proven, verify with the API rather than the registry.
