# Running cs2mem against a real CS2 install

The tool does not work end-to-end yet. This is the ordered path, with the two
blockers named up front so you don't spend a session on a false start.

## Blockers

| # | Blocker | Where | Effort |
|---|---|---|---|
| 1 | Hypervisor has no `HYPERCALL_GET_PROCESS_CR3` | `PulverizedPkg/Sources/Hypercall.c` | ~100 lines, incl. symbol resolution |
| 2 | Entity offsets unresolved (`chunk_stride`, field offsets) | `cs2mem.ini` does not exist | one measurement session with the game running |

Until both are done, `cs2mem players` refuses. `check` and `modules` work as soon
as blocker 1 is fixed — and that is the right order to test in.

## Prerequisites on the guest

- Windows 10/11 x64, administrator shell.
- CS2 installed (Steam appid 730).
- The hypervisor loaded and running. `cs2mem check` proves it.
- The game launched **`-insecure`** for a local bot match. The tool reads the
  game's command line and refuses otherwise.

```bat
:: from the CS2 install root
game\bin\win64\cs2.exe -insecure +map de_dust2 +bot_quota 10 +sv_cheats 1
```

`-insecure` disables VAC. That is the point: this reads an offline session.

## Step 1 — prove the hypercall path

```bat
cs2mem check
```

Expected:

```
OK: hypercalls work, current CR3 = 0x1ad000
```

If it prints `FAIL: hypercall path did not return a CR3`, either the hypervisor
is not running or the key in `hvcalls.h` does not match `Hypercall.h`. A wrong key
still executes CPUID and returns 0, which is why this is checked first and
reported as its own failure rather than as "game not found".

## Step 2 — add `HYPERCALL_GET_PROCESS_CR3`

Follow `hypervisor_patch.md`. It is not a drop-in: `FindKernelSymbol` and the
guest read helpers do not exist in the tree and must be written. The table at the
end of that file states exactly which pieces exist and which are new.

After patching, rebuild and reflash the hypervisor, then boot.

## Step 3 — validate the CR3 walk against a process you control

**Do not test against CS2 first.** A wrong `DirectoryTableBase` does not fail — it
returns a real-looking address, reads succeed, and every value comes from a
different process. The only way to catch that is to check against something whose
layout you already know.

```bat
:: with notepad.exe open
cs2mem modules
```

Wrong: `cs2mem` only looks for `cs2.exe`. Add the `--exe` flag:

```bat
cs2mem --exe notepad.exe modules
```

What to check:

1. The CR3 is page-aligned and non-zero.
2. The module list matches Process Explorer — same bases, same count.
3. `cs2mem probe <rva-of-.text-start> 64` on `notepad.exe` shows a plausible PE
   prologue, not zeros and not another process's code.

If module bases match but the probe shows garbage, the CR3 is from the wrong
process — the exact failure mode this step exists to catch.

## Step 4 — confirm the game's CR3 and modules

```bat
cs2mem modules
```

Expect `cs2.exe` with `client.dll`, `engine2.dll`, `server.dll`, `tier0.dll` in
the list. Note the `client.dll` base — every offset in `cs2mem.ini` is relative to
it.

```bat
cs2mem probe 1000 64
```

`client.dll+0x1000` is the start of `.text`. Expect real x64 code (`48 89 5c 24`,
`48 83 ec`, `e9`…), not zeros. This is the single most useful check in the whole
tool: it separates "hypervisor reads work" from "offsets are wrong", and those
two failures otherwise look identical downstream.

## Step 5 — generate the offsets

`discover` is a stub. Until it is written, fill `cs2mem.ini` by hand using the
procedure in `README.md`. In outline:

1. **`dw_entity_system`** — in `client.dll`'s `.data`, find a qword that becomes
   non-null after a map loads and whose target's first qword is a vtable pointing
   into `client.dll`'s `.rdata`. Confirm by reading `off_highest_index`: a
   plausible entity count is 1..65536.
2. **`chunk_stride`** — the hard one. Take an index you know is a live player,
   read the health field at candidate strides from 0x10 to 0x1000 in 8-byte steps,
   and accept the stride where health lands in 1..100 *and* origin is finite and
   non-zero *for a dozen entities at once*. A wrong stride yields zero valid
   entities; the right one yields the bot count.
3. **field offsets** — scan the first 0x2000 bytes of a validated pawn for a
   float triple that is finite, inside ±32768, and differs between two pawns
   (origin); a byte in 1..100 that drops when a bot is shot (health); a byte that
   is exactly 2 or 3 and differs across teams (team).

Write the result with the `client.dll` SHA256:

```bat
certutil -hashfile "C:\...\game\csgo\bin\win64\client.dll" SHA256
```

The tool refuses to run if the hash in `cs2mem.ini` does not match, because CS2
moves these offsets every patch and a stale table reads plausible garbage.

## Step 6 — read players

```bat
cs2mem players
cs2mem players --json
```

Expected output:

```
scanned 4096 slots, 10 players
index  team hp   alive  origin
9      T    100  1      (1234.5, -820.1, 64.0)
11     CT   87   1      (1190.2, -795.4, 64.0)
...
```

`scanned` is how many slots were examined; if it is large and the player count is
zero, the offsets are wrong (most likely `chunk_stride`). If `scanned` is zero,
the entity system pointer is wrong.

## What you should expect to go wrong

- **`scanned 0`** — `dw_entity_system` wrong, or no match loaded. Check the map
  is actually running, not the main menu.
- **`scanned > 1000`, `0 players`** — `chunk_stride` or a field offset is wrong.
  This is the expected first result; it means reads work and offsets don't.
- **A player with absurd coordinates** — validation should have caught it. If it
  does not, the origin offset points at something else and `origin_sane` needs
  tightening.
- **Reads fail on the first page** — the CR3 is stale. The game re-creates its
  address space on map change; re-run after each load.

## When it works

You get a table of positions, health and team, updated per invocation. That is the
extraction layer. What you do with it is the next piece: a JSON stream for a
visualiser, or per-tick logging for analysis.

For anything beyond an offline bot match, the sanctioned paths are demo parsing
(`.dem` files contain full per-tick player state) or a plugin on your own server.
Both give better data than a runtime read, and neither needs the hypervisor.
