# Debugging notes: Pulverized UEFI hypervisor on the DTB

Working notes for bringing up `hypervisor/efi-superrepo` on the DTB test machine
and passing VMAware. Kept because most of the failures here were *silent*: the
machine simply stopped responding, and the reason was only found by making the
hypervisor report on itself.

## The test loop

```sh
# host: serve the DXE image
cd hypervisor/efi-superrepo && ./serve.sh          # port 6767

# host: capture the debug UART (separate terminal / background)
python3 tools/capture_serial.py /tmp/opencode/serial.log

# reset the DTB, wait for SSH
python3 tools/reset_pc.py
python3 tools/probe.py                             # TCP:22 liveness

# after boot: keep COM1 powered so the log survives (see below)
tools/ensure_com1_keepalive.sh

# run one VMAware technique in isolation
python3 tools/try_technique.py HYPERVISOR_HOOK
```

Build: `cd hypervisor/efi-superrepo && NO_DOCKER=1 ./PulverizedPkg/build.sh`
(~10 s incremental). If the build fails with
`No rule to make target '/PulverizedPkg/Sources/...'`, the generated makefile
lost `$(WORKSPACE)`: `rm -rf Build/Pulverized` and rebuild.

`tools/reset_pc.py` queries the power LED and then either resets or powers on.
Do not add retries around it: each attempt presses the physical power button
again, and interrupting a run can leave the servo holding the button down.

## Why the serial log kept dying (solved)

Symptom: boot logs fine, then output stops at a fixed point after Windows
starts, on every boot, even with the COM1 driver disabled.

Cause: Windows power-gates COM1 when it is idle. The UART goes to D3 and the
legacy I/O range stops decoding, so **every register reads `0xFF`**:

```
LSR=0xff MCR=0xff LCR=0xff IER=0xff FCR=0xff DIV=65535
```

The port is not misprogrammed, it is powered down. Holding a handle open
brings it back to D0 and the log resumes within one heartbeat.

Fix: `tools/com1_keepalive.ps1` holds the port open for the whole session, and
`tools/ensure_com1_keepalive.sh` starts it (via WMI, so it survives the SSH
session ending). `PnPCapabilities=0x18` in the device's registry key is not
enough on its own.

Related traps that cost time:

* Writing `0x07` to the FIFO control register mid-line clears the transmit
  FIFO and truncates the line. Only `0x01` (enable, no clear) is safe.
* Reconfiguring the UART between characters (e.g. inside a
  set-serial-enabled helper) corrupts the line it is printing.
* `HvLogSetSerial` must only flip a flag. Programming the divisor belongs in
  `HvLogInit` and in the write-failure repair path.

## The RAM log (the channel that cannot be broken)

Serial is expensive and can be gone exactly when needed, so every log
character is also mirrored into a 64 KiB ring buffer in hypervisor memory and
read back by a guest tool through `HYPERCALL_READ_HVLOG`
(`0x2f8a41d0c7b13`, CPUID leaf `0x4000BABE`, key in RCX).

`tools/hvlog_reader.cs` is uploaded and compiled on the guest with
`Add-Type`; `tools/com1_launch.ps1`-style helpers exist because nested quoting
through SSH mangles the Cyrillic profile path. Prefer uploading a `.ps1` and
running `-File`.

Three things had to be right for the dump to be usable:

* Mirror in `HvLogPutc`, not `HvLogStr`. `HvLogHex`/`HvLogDec` write through
  `HvLogPutc`, so mirroring at the string layer produced lines reading
  `exit reason  rip 0x` with every number missing.
* Translate the destination page by page. A guest buffer is virtually
  contiguous but physically scattered; translating only the base address and
  copying linearly wrote past the first page into unrelated physical memory,
  so the dump was 1 KB of text followed by 59 KB of NULs.
* Keep the buffer at 64 KiB. A 1 MiB static buffer pushed the DXE image past
  what the chainloader accepts and broke boot with `0xc0000001`.

## Logging must not slow the guest

Timing-sensitive checks are meaningless if the tracer perturbs the machine.
Three costs were removed from the VM-exit path:

* `HvLogEnsureWritable` ran on every exit before deciding to print anything:
  three port reads per VM exit.
* Every character spun on TXRDY. At 115200 baud a 45-character line is about
  4 ms of busy-waiting inside the exit handler.
* The heartbeat called `HvLogDumpUart`, which can spin 2,000,000 LSR reads.

The hot path now only appends to RAM. Serial is on during boot, off after
`ExitBootServices`, and turned back on by `PANIC` and by one heartbeat line per
64 ticks (the only cheap proof of life a hard wedge leaves behind). A full
VMAware run went from lagging badly to `elapsed=0s`.

## Bugs found and fixed

### 32-bit RIP overflow (`d81bce4`)

`EIP_OVERFLOW` froze the machine every time:

```
Guest RIP             = 0000000100000000
Guest CS access rights = 000000000000C0FB   (L = 0, compatibility mode)
VM-exit reason (Full) = 80000021
```

`0x80000021` is a VM-entry failure due to invalid guest state, and it landed in
the unhandled-exit default, which `PANIC()`s.

`ResumeToNextInstruction` always computed RIP + instruction length as 64 bits.
The technique deliberately executes CPUID at `0xFFFFFFFE` with `CS = 0x23`,
expecting the instruction pointer to wrap to 0 as the hardware does. Adding the
length produced `0x100000000`, illegal while CS.L is clear.

Fix: honour the L bit and truncate the new RIP to 32 bits when the code segment
is not 64-bit. `EIP_OVERFLOW` now returns 0.

### Silent root-mode livelocks (`20ff891`)

Two paths could wedge every CPU with no output at all:

* `HandleMonitorTrapFlag` was an empty stub. MTF is set when an EPT hook fires;
  while it stays set, every VM entry raises an MTF exit immediately. The guest
  never executes, and since the preemption timer only counts guest execution the
  heartbeats stop as well. Now clears MTF, then re-arms the hooks that
  `EptHandleHookedPage` removed.
* `HandleEptViolation` always returned "redo instruction". With no matching hook
  that retries the same instruction forever. Now only redo when a hook handled
  it; otherwise log the address/qualification/RIP over serial and step over.

A livelock detector in `VmExitHandler` reports a long unbroken run of the same
(exit reason, guest RIP) over serial, since that is the only channel that
survives a hard wedge.

## Interpreting a hang

* **SSH dies, serial keeps printing heartbeats** - the guest is wedged, the CPU
  is still returning to the hypervisor. Look at the last guest RIP.
* **SSH dies, serial goes silent** - the CPU is stuck in root mode and is not
  reaching any exit that logs. Be careful: silence is also what you get if COM1
  is power-gated, so always run `ensure_com1_keepalive.sh` first.
* **SSH dies, no route to host, power LED on** - the kernel is not being
  scheduled at all: a hard root-mode wedge.
* **Power LED off** - the machine powered itself down (a BSOD can do this).

Heartbeats only advance when the guest executes, so a stopped heartbeat plus a
live machine means "never returned to guest", not "guest is slow".

## VMAware status

Measured on the DTB with the harness fixed (`tools/try_technique.py`, which runs
`--percent` with only one technique enabled, so the score is that technique's own
weight). All 79 techniques this build accepts were swept; 72 score 0.

| Technique | Score | Meaning |
|---|---|---|
| `TRAP` | 100 | fires |
| `INTERRUPT_SHADOW` | 100 | fires |
| `DBVM` | 100 | fires |
| `SINGLE_STEP` | 100 | fires |
| `THREAD_MISMATCH` | 45 | fires, below the 150 threshold |
| `GPU_CAPABILITIES` | 20 | fires (virtual display adapter, not the hypervisor) |
| `HYPERVISOR_HOOK` | timeout | completes but takes over 900 s |

Everything else - including `EIP_OVERFLOW`, `MSR`, `UD`, `VIRTUAL_PROCESSORS`,
`KVM_INTERCEPTION`, `CPUID_SIGNATURE` and `HYPERVISOR_BIT` - scores 0.

**The machine does not hang.** Every result above is a detection or a slow run,
never a crash, and the desktop stays usable throughout.

### Why earlier per-technique results in this document were wrong

Three separate faults in the harness, each of which produced a confident but
false verdict:

1. **`-d` cannot isolate a technique.** It returns a *thresholded* boolean: true
   only when the total score reaches 150. With a single technique enabled, one
   that fires weakly still reports 0. `THREAD_MISMATCH` scores 45 and was
   therefore reported "clean". `--percent` returns the score itself and is what
   this table uses.

2. **Two names in the technique list are not in this build.**
   `VCPU_SCHEDULING` and `EMULATION` are declared in `vmaware.hpp` but rejected
   by the binary, and `--disable` **aborts the whole run** on an unknown name.
   Any invocation containing them did nothing at all, in `seconds=0`. Both were
   confirmed by trying every name individually against the binary; the tool now
   filters them out.

3. **The full summary never reaches a file over SSH.** `PRINT_LINE` routes
   through the TUI, which writes into a console buffer; with no console the
   output is discarded and the file stays at 0 bytes, even with `-o`,
   `--no-ansi` or `--json`. `general()` also ends in `console_pause()`, which
   blocks on stdin forever. This is why full-suite runs appeared to produce
   nothing and left a `vmaware.exe` spinning: that leftover then degraded the
   guest until it was killed.

The lesson is in the last one: a run that produces no output and leaves a process
behind looks exactly like a hypervisor hang. Check that the tool is capable of
reporting before believing its silence.

### HYPERVISOR_HOOK is a performance problem, not a hang

It exceeds 900 s while every other technique finishes in about a second. The
hypervisor trace during the run shows heartbeats advancing normally, so the guest
is executing throughout. The technique scans every executable section of ntdll
for `CC CC`, patches a byte, and re-executes - so it is dominated by debug
register and single-step behaviour, which is the same area as `TRAP`,
`SINGLE_STEP` and `INTERRUPT_SHADOW`. Treating those four as one problem is the
obvious next step.

### The NMI-window storm (a real bug, found and fixed)

While chasing what looked like a hang, arming serial tracing from the guest
(`HYPERCALL_SET_TRACE`) produced 5 MB of an **NMI-window exit storm**:
`exit reason 0` (NMI) and `exit reason 8` (NMI-window) alternating, with the
guest RIP advancing between them. The guest was running the whole time, at
roughly one instruction per VM exit.

`HandleNmiWindow` injected an NMI on every window exit without checking whether
one was owed, and a window exit is taken at the start of every instruction the
guest can be interrupted at, so each fabricated NMI let the next window exit
fire immediately. Fixed by tracking NMIs per logical processor (APIC ID from
CPUID, since the MP services protocol is gone after `ExitBootServices`), only
injecting when one is actually pending, and capping consecutive window exits
with no guest progress.

Two lessons from the same episode:

* **The tracer can starve the guest.** Arming serial produced 5 MB, which at
  115200 baud is about seven minutes of busy-waiting inside exit handlers. The
  debugging aid had become the hang. Serial bytes are now rationed against guest
  progress, refilled only on the heartbeat boundary.
* **Never trust a debug aid that can itself stall.** A 64 KiB dump is ~5.7 s of
  busy-wait inside an exit; boot has exit storms, so an earlier version that
  dumped from the routine exit path stalled bring-up completely.

### A note on probes

`tools/vmprobe.cs` runs one primitive per process and reports the exact fault
offset, so a stub that hangs cannot take the whole run with it. It found two bugs
in itself worth remembering: TF is RFLAGS bit 8 (setting bit 0 silently leaves
single-step off), and a handler that resumes a faulted stub must clear TF and
leave the stack balanced, or it loops forever and looks like a hung probe.

### Changing the NMI controls breaks boot

Both tempting shortcuts stop the machine booting:

* `NmiExiting = FALSE` - the machine sits in firmware looping on XSETBV exits
  with the guest RIP never advancing.
* `VirtualNmi = FALSE` (with NMI exiting still on) - wedges immediately after
  `ExitBootServices`.

Keep the `NmiExiting = TRUE` / `VirtualNmi = TRUE` pairing and fix storms in the
pending logic. An early `NmiExiting = FALSE` test was also misread, because that
build carried an unrelated INIT-time log dump that broke boot on its own; do not
change two things at once when the only symptom is "it does not boot".

### An INIT is not a hang

`HandleInitSignal` parks the core in wait-for-SIPI. During boot that is routine
(the BSP sends INIT to every AP), so dumping the log there stalled bring-up
badly. After `ExitBootServices` an INIT means the platform is resetting, so the
dump is enabled only then, via `HvLogAllowInitDump`.

## Tooling

| File | Purpose |
|---|---|
| `tools/run_suite.py` | run the **whole** VMAware suite detached and list what is detected (use this, not the isolated runner) |
| `tools/run_full_suite.ps1` / `launch_full_suite.ps1` | guest side of the above |
| `tools/try_technique.py` | run one technique in isolation; detached, collects the guest's own verdict |
| `tools/run_technique.ps1` / `launch_technique.ps1` | guest side of the above |
| `tools/vmprobe.cs` | measure one trap primitive (`vmcall`, `icebp`, `tfcpuid`, ...) and report the exact fault offset |
| `tools/bisect_vmaware.py` | older per-technique bisect; its `TECHNIQUES` list is hand-maintained and unverified |
| `tools/probe.py` | TCP:22 liveness check |
| `tools/reset_pc.py` | query power LED, then reset or power on |
| `tools/capture_serial.py` | resilient serial capture; reopens on re-enumeration or idle |
| `tools/hvlog_reader.cs` | guest-side RAM log reader (hypercall) |
| `tools/hv_trace.cs` | guest-side switch for the hypervisor's serial trace |
| `tools/deploy_hv_trace.sh` | compile `hv_trace.cs` on the guest |
| `tools/ensure_com1_keepalive.sh` | start the COM1 keepalive after each boot |
| `tools/com1_keepalive.ps1` | hold COM1 open so it stays in D0 |
| `tools/com1_verify.ps1` | prove the port is held open |
| `tools/com1_status.ps1` | report device state and power settings |

Two lessons about these tools, both learned the hard way:

* A network liveness check cannot distinguish "slow" from "hung". Any tool that
  reports a freeze must be able to say whether the guest ever finished.
* A result file that is not checked for freshness will happily serve the previous
  run's answer. Always compare the file's timestamp with the run you just
  started.

## Blocked: both USB serial adapters dropped off the bus

The last session ended with the host losing both CH340 adapters at once:

```
usb 1-2: USB disconnect, device number 6
ch341-uart ttyUSB0: ch341-uart converter now disconnected from ttyUSB0
usb 1-1: USB disconnect, device number 8
ch341-uart ttyUSB1: ch341-uart converter now disconnected from ttyUSB1
```

They are gone from `lsusb` entirely (not just missing device nodes), a PCI bus
rescan did not bring them back, and the DTB is therefore unreachable: no serial,
no Arduino power control, no ping. That is a host-side USB problem, not a
hypervisor one, and it needs the cables or hubs physically re-seated.

Until that is fixed, the next steps are blocked. They are, in order:

1. Re-plug the adapters and confirm `/dev/ttyUSB0` (PC serial) and `/dev/ttyUSB1`
   (Arduino) both return, then power the DTB on with `tools/reset_pc.py`.
2. Re-run the full suite with `tools/run_suite.py` and confirm the detection list
   matches the screenshot. This validates the new harness before it is trusted.
3. Attack `THREAD_MISMATCH`: it compares the topology Windows reports with the
   CPUID leaves. With `VIRTUAL_PROCESSORS` and `CPU_HEURISTIC` clean, the APIC ID
   used for per-CPU state is the first suspect, since it is read from CPUID leaf
   1 rather than from the hardware APIC.
4. Attack the trap-based trio (`DBVM`, `SINGLE_STEP`, `INTERRUPT_SHADOW`). All
   three depend on `#DB` semantics, and all three involve CPUID, which always
   causes a VM exit here. The single-step trap across a VM exit is the common
   suspect: the architecture requires a pending debug exception to be recorded in
   `VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS`, and that field is never written. A fix
   was attempted and reverted because it did not change the verdicts, but the
   probe tooling at the time was broken (TF was being set as bit 0 instead of bit
   8), so the attempt was not a fair test. Re-do it with `tools/vmprobe.cs`.
5. `KVM_INTERCEPTION` should be the easiest of all: it fires when `VMCALL` does
   not raise an exception, yet the probe shows `#UD` arriving correctly. Re-run
   the probe under the same conditions as the suite before theorising.

## A hang can also be a power state

Twice the machine looked dead (power LED on, no serial, no ping) and a reset
pulse did not recover it, while the Arduino answered normally on its own port.
Pressing the power button once brought it back. When the reset header has no
effect, check that the machine is not sitting in a state that only a power
cycle clears before concluding the hypervisor wedged it.

