# cs2mem — offline CS2 player-state reader over the hypervisor

Reads player positions, health and team out of a **local, offline CS2 bot match**
by reading the game's address space from the hypervisor, not from inside the game
process. Built for research on the hypervisor's memory-access path.

## Scope — read this first

This is for **offline bot matches on your own machine**, with CS2 launched
`-insecure` (VAC off). It is not for online play, and the code says so in the
places where that matters rather than relying on the reader to remember.

Two reasons the offline restriction is structural rather than advisory:

1. Reading another player's position and health during a live match is an
   information advantage against people who cannot consent to it. That is true
   regardless of what the tool is called.
2. Online CS2 means VAC, and the hypervisor architecture exists to be invisible
   to it. A tool that is invisible to VAC is not a mod.

If you want live-match data legitimately, the paths are demo parsing (complete,
per-tick, sanctioned) or a server plugin on your own server.

## What it does

```
cs2mem check      verify hypercalls work, print the current CR3
cs2mem modules    find cs2.exe, print PID, CR3, module bases
cs2mem probe R    hexdump client.dll+R through the hypervisor
cs2mem players    read live player state (needs cs2mem.ini)
cs2mem discover   scan for the entity system and offsets (not yet implemented)
```

## Why the hypervisor, and what it costs

The alternative is `ReadProcessMemory` from a helper process. That is simpler and
for offline work it is strictly better. The hypervisor path is worth building only
because it is the thing being studied: it reads guest memory from root mode via
`HYPERCALL_READ_VIRTUAL_MEMORY`, using the target's CR3.

Consequences that shaped the design:

- **The tool never opens the game with `VM_READ`.** It uses
  `PROCESS_QUERY_LIMITED_INFORMATION` only, for module enumeration. That is
  deliberate: with no read handle, a bug in the hypervisor path cannot silently
  fall back to a plain read and look like it works.
- **Every read is page-split and checked.** A wrong CR3 does not fail; it returns
  another process's memory, which looks like plausible garbage. `hvmem.c` splits
  reads on page boundaries and reports which page failed.
- **Offsets are data, not code.** They live in `cs2mem.ini`, pinned to a
  `client_sha256`. CS2 is schema-driven and moves these every patch; baked
  offsets are correct for one build and silently wrong for the next.

## Build

```sh
x86_64-w64-mingw32-gcc -O2 -Wall -Wextra -o cs2mem.exe \
    main.c hvmem.c target.c cs2cfg.c cs2ent.c
```

Static, no CRT dependency beyond what mingw supplies. Run as administrator on the
guest (needed for the module snapshot and for the hypercall's kernel walk).

## Prerequisites

1. **The hypervisor must expose `HYPERCALL_GET_PROCESS_CR3`.** The stock build
   only has `HYPERCALL_GET_CURRENT_CR3`, which returns *your* CR3 and is useless
   for reading the game. See `hypervisor_patch.md` — this is a ~60-line addition
   and the tool reports its absence explicitly rather than as "game not found".
2. **`cs2mem.ini` must exist and match the running `client.dll`.** Generate it
   with `discover` (not yet implemented — see below).
3. **CS2 launched `-insecure`.**

## The honest gap: offsets are not resolved

`database/csgo/documents/client.md` §10 records that `CGameEntitySystem`'s chunk
stride and the `CEntityIndex` → chunk mapping were **not** recovered from the
disassembly. I am not going to invent numbers for them.

So `cs2mem players` will refuse until `cs2mem.ini` exists, and `discover` is a
stub. What `discover` has to do:

1. Find the `dw_entity_system` global. It is a data-section pointer that becomes
   non-null when a map loads. Scan `client.dll`'s `.data` for a pointer whose
   target has a vtable pointing into `client.dll`'s `.rdata`, then validate by
   reading `off_highest_index` and checking it is a plausible entity count
   (1..65536).
2. Find `chunk_stride` by taking a known-live entity index, reading its health
   field at candidate strides, and accepting the stride where health lands in
   1..100 and origin is finite and non-zero for several entities at once. A wrong
   stride produces exactly zero valid entities; the right one produces 10.
3. Find the field offsets the same way: scan the first 0x2000 bytes of a validated
   pawn for a float triple that is finite, inside ±32768, and differs between two
   pawns (that is the origin); scan for a byte in 1..100 that drops when a bot is
   shot (that is health).

That is a measurement job, not a guess, and it needs the game running. It is the
next piece of work.

## Files

| File | Holds |
|---|---|
| `hvcalls.h` | the guest-side hypercall ABI, self-contained |
| `hvmem.c/.h` | page-split reads through `HYPERCALL_READ_VIRTUAL_MEMORY` |
| `target.c/.h` | find `cs2.exe`, its PID, CR3 and modules |
| `cs2cfg.c/.h` | the offset table as data, pinned to a build hash |
| `cs2ent.c/.h` | entity-system walk and player validation |
| `main.c` | CLI |
| `hypervisor_patch.md` | the hypervisor-side addition this needs |

## Verification status

- Compiles clean with `-Wall -Wextra`, no warnings.
- The hypercall register ABI was checked against the generated assembly: leaf
  `0x4000BABE` in EAX, key in RCX, call number in RDI, arguments from RSI.
- **Not run against a live game.** The DTB is offline and there is no local CS2
  install. Every claim about behaviour at runtime is untested.

## Ethics and limits, stated plainly

The offline guard is a policy check, not a security mechanism, and it is
documented as such in `cs2ent.c`. It stops the tool being pointed at a live match
by accident. It will not stop anyone determined, and pretending otherwise would be
dishonest. The real boundary is the one in the first section: this reads your own
offline session, and that is the only use it is built for.
