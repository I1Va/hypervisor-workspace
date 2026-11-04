---
topic: platform
kind: reference
updated: 2026-11-04
see: [hvlog, detecting-a-wedge, stale-probe-processes]
---

# The DTB test stand

Two machines: a **host PC** (this Linux box) and the **DTB**, the machine under
test running Windows with the hypervisor loaded underneath.

## Connections

| Link | Device | Purpose |
|---|---|---|
| Debug UART | `/dev/ttyUSB0`, 115200 8N1 | Hypervisor and firmware console output |
| Arduino | `/dev/ttyUSB1`, 9600 8N1 | Power button servo, reset relay, power LED sense |
| Network | `192.168.3.67:22` | SSH to the Windows guest |
| HTTP boot | host `0.0.0.0:6767` | Serves the build for network boot |

Host address on that network is `192.168.3.13`. The Arduino is driven entirely
from this host over `/dev/ttyUSB1`; there is no network path to it.

Both USB serial adapters are CH340s. They enumerate as `ttyUSB0`/`ttyUSB1` but
**the numbering is not guaranteed** — identify them by
`/dev/serial/by-id/usb-1a86_USB2.0-Ser_-if00-port0` (debug UART) and
`usb-1a86_USB_Serial-if00-port0` (Arduino) if a swap is suspected.

## Boot path

1. The guest's UEFI boots from the network.
2. It fetches `Pylon.efi` (a bootloader shim), which chains
   `ChainLoaderApp.efi`, which loads `PulverizedDXE.efi`.
3. `PulverizedDXE` sets up VMX on every core and continues booting Windows
   under it.

The hypervisor is therefore already active during the rest of the Windows boot.

## Power control

The Arduino drives:
- a **servo** that physically presses the power button (pin 3),
- a **relay** across the reset header (pin 2),
- a **sense input** on the motherboard power LED (pin 4).

The firmware speaks a line protocol at 9600 baud; see
The firmware source lives in `control/dtb/firmware/arduino.c` (the stand's
hardware layer, next to the daemon that drives it). `power_off` requires firmware
v2: ATX needs the button held ~6 s to latch off.

## Rules that come from the hardware

- **Opening the Arduino's serial port reboots the Arduino** (DTR assertion),
  costing ~2.5 s. The daemon opens it once and holds it.
- **`reset` may have no effect** if the machine is in a state that only a full
  power cycle clears. If the power LED is on and reset does nothing, `cycle`.
- **A BSOD can power the machine down.** An unexpected `power=OFF` after a test
  usually means the guest crashed hard, not that the relay fired.
- **Do not retry power commands blindly.** Every attempt presses real hardware;
  a retry loop can leave the servo holding the button down.

## What not to do

- Do not launch the QEMU simulator for testing. It does not reproduce the
  hardware and the goal is a physical-machine result.
- Do not open `/dev/ttyUSB0` while the daemon is running; you will steal bytes
  from the capture. Use `dbg_log`.
