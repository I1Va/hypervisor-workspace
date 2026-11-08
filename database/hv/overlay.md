---
topic: hypervisor-overlay
kind: reference
updated: 2026-11-07
see: [hypervisor-architecture]
---

# Hypervisor-rendered overlay foundation

## Ownership and presentation

The Intel CPUID hypercall path exposes a **software framebuffer in VMX root**.
Windows presents it using a normal, visible, topmost layered window. This is not
GPU/scanout interception, a hidden overlay, or a firmware GOP framebuffer that
continues working after Windows changes graphics modes. Exclusive fullscreen,
secure desktops, and other compositor-bypassing surfaces are not supported.
The bridge does not launch or read any game.

Sources:

- `hypervisor/efi-superrepo/PulverizedPkg/Sources/Overlay/Overlay.c`: CPU rendering,
  premultiplied BGRA pixels, input state, immediate-mode buttons.
- `OverlayAbi.h` in that directory: single shared, versioned wire ABI.
- `OverlayTransport.c`: request copying, paging validation, synchronization.
- `tools/hvoverlay/`: Windows presentation/input bridge and guest client
  (`usermode-gfx` submodule).
- `tools/usermode-cs2/`: CS2 user-mode prototypes (`cs2mem/` and `cs2overlay/`)
  in a separate submodule. Their extraction does not establish live-game validity.

The surface is global, with one trusted bridge/renderer consumer. It is not
per-process, multi-client, or an authenticated interface. The existing fixed
hypercall key is an ABI discriminator, not a security boundary. Existing general
memory-write hypercalls already confer broad privileges; this subsystem does
not make the VMM safe against hostile callers.

## Framebuffer contract

`HYPERCALL_OVERLAY` uses the existing CPUID calling convention, with a resident,
writable `HVOV_REQUEST` pointer in RSI, exact size in RDX, and zero in R8/R9.
RAX and the response `Status` contain an `HVOV_*` status. Check both; executing
CPUID on a system without this implementation must not look like success.

- Pixels are **premultiplied BGRA8**, integer `0xAARRGGBB`. RGB must not exceed
  alpha. Alpha zero is transparent.
- `RESIZE` explicitly creates/resets the surface, at most 1280 x 720. No runtime
  allocations. Its full-surface clear is setup work; do not resize per frame.
- `FILL`, `UPLOAD`, `READ`, and `BUTTON` process at most 1024 pixels per request.
  Rectangles are tightly packed, surface-local, and must be entirely in bounds.
  There is no implicit clipping, scaling, GPU drawing, or blending operation:
  upload overwrites pixels; Windows composites the resulting alpha surface.
- Reads/writes are synchronous and tile-granular. There is no whole-frame
  transaction/double buffering. A single-threaded bridge serializes drawing and
  readback; multi-producer tearing is not solved.
- A non-blocking try-lock protects renderer state and the static transport
  scratch buffer. Contention returns `BUSY`; no spin or serial output occurs.

The framebuffer adds about 3.52 MiB of static runtime-driver storage, independent
of the hypervisor's existing bump allocator. Larger surfaces must be designed
with memory and VM-exit latency budgets, not by removing the bounds checks.

## Input and buttons

The bridge forwards absolute local mouse coordinates, five mouse-button states,
vertical wheel deltas, focus, and a 256-bit Windows virtual-key state bitmap.
Input is collected using ordinary window messages, not USB/PS2 interception or
an OS-global keylogger. The OS draws the cursor.

`INPUT` accumulates mouse transitions/wheel deltas. `BUTTON` takes a stable
nonzero ID and a bounded rectangle, draws it, and returns hovered/held/clicked
flags. A left press inside captures the ID; release inside clicks. Another
button cannot steal capture. Release outside cancels. Focus loss clears keys,
buttons, and active capture without manufacturing a click.

Call buttons once per input frame **before** `POLL_INPUT`. Poll publishes up to
64 button rectangles for the following input frame and consumes pending raw
transitions/wheel; submit an initial button/poll frame before accepting input.
Do not add an independent consumer. Overlapping buttons resolve in submission
order. Each input call processes mouse edges against the published geometry at
that event's coordinates, preserving press/release order across render frames.
Multiple completed clicks on one ID before drawing coalesce to one clicked flag.
Focus loss discards pending clicks and capture. Raw input remains a state and
transition accumulator, not an ordered text/key event queue. There is no text/IME,
horizontal-wheel, gamepad, or touch support.

## Future ImGui integration

Use the guest client to upload CPU-rendered pixels in bounded tiles and use the
input snapshot as the platform-backend starting point. Dear ImGui itself and a
triangle/texture rasterizer are **not implemented**. Add ordered text/key events
and proper text-input handling before claiming a complete ImGui platform backend.
A GPU/native-scanout backend would be a separate, device-aware project.

## Transport assumptions and limits

Before virtualization, capture a bounded EFI memory-map snapshot of ordinary
RAM and the loaded VMM image range. If discovery fails or the map is too large,
only the overlay interface stays disabled. Runtime copies:

1. Accept only low canonical user addresses and an exact fixed request size.
2. Walk guest page tables and EPT read-only, without EPT splits or allocation.
3. Require present/user/writable mappings and ordinary RAM below the root map's
   512 GiB identity limit. Reject device MMIO and the loaded VMM image.
4. Resolve and validate all request spans before execution, then reuse the same
   host physical spans for copy-in and copy-back; never re-walk halfway through
   completion. The bridge locks and owns its pages until the call returns.

The snapshot excludes memory hot-added after initialization. Guest callers must
keep request pages resident, writable, and mapped for the synchronous call.
The copy is not fault-recovering and cannot make adversarial concurrent guest
page-table mutation, concurrent EPT reconfiguration, or privileged corruption of
the VMM safe. Four-level guest paging only; AMD's legacy hypercall path is not
wired to this interface.

## Verification boundary

The EFI driver builds locally. Native renderer unit tests exercise pixel formats,
readback, bounds, capture/click behavior, focus loss, and wheel overflow under
address/undefined-behavior sanitizers. Transport unit tests use explicit RAM page
tables; these are unit tests, not a VM or the prohibited simulator.

DTB runtime validation on 2026-11-08 now passes the read-only `--probe` and
exclusive `--selftest`: exact fill/upload/read pixels, packed rows, tile/bounds
checks, five mouse buttons, 256-key bitmap, wheel, focus loss, ordered button
capture/clicks, and input polling. The initialization failure was the fixed
256-range capacity applied before normalizing fragmented firmware RAM descriptors.
The snapshot now sorts and merges adjacent/overlapping ordinary RAM before
applying that limit, preserving gaps, MMIO rejection and image exclusion.

A same-user, limited InteractiveToken scheduled task also completed bounded
synthetic previews on desktop session 1: 213 presentation calls over 10 seconds
and 640 over 30 seconds, with exact changed-pixel verification and clean teardown.
The first screenshot attempts missed the preview or excluded layered windows;
a managed CaptureBlt flag attempt was rejected by .NET's enum validation. The
capture helper now uses GDI BitBlt with SRCCOPY|CAPTUREBLT and releases its DCs.
After readability improvements, a concurrent bounded preview screenshot described
by `dbg_screenshot` confirmed the full **TEST DATA - NOT A MATCH** banner,
**SYNTHETIC PREVIEW / ENEMIES 2**, two boxes, green health bars, and readable
`#7 HP:84 4M` / `#11 HP:76 6M` labels on desktop session 1. The preview task
returned zero. This establishes synthetic graphics only, not real player data.

Physical mouse interaction and real offline CS2 match data still require separate
runtime validation. The available corpus identifies module hashes but does not
verify the necessary entity layout, local-pawn/matrix roots, absolute-position
storage, or connected/local-server flags. No real bot-match success is established.
