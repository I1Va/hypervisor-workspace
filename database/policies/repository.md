---
topic: repository-layout
kind: reference
updated: 2026-11-04
see: [documentation, experiment-recording]
---

# Repository layout policy

The repository has two halves. The split is not stylistic - it is the boundary
between code that must stay deterministic and code the agent may rewrite.

| Directory | Access | Holds |
|---|---|---|
| `workspace/` | open: read and edit | instructions, knowledge base, hypervisor source, legacy scripts |
| `control/` | open: read and edit | stand daemon, Arduino firmware, session supervisor |

## Why the split exists

`control/` owns state that cannot be reconstructed from outside:

- an open Arduino serial handle - opening the port asserts DTR and reboots the
  board, so it is opened once and held,
- an SSH master socket - one handshake instead of one per command,
- which boot a serial log line belongs to.

The rule is about *hardware ownership*, not about reading. The agent may read and
edit `control/` - it may need to fix a tool that is not ready. What it must not do
is become a second hardware owner: no opening the serial ports, no direct SSH
connection, no second daemon. Those are the daemon's, and a competing opener
reboots the board or breaks the master.

Operate the stand through the DTB MCP interface:

- `dbg_describe` returns the daemon's current command contract.
- `dbg_status` returns the current stand state; call it before stand work.
- Use the other `dbg_*` tools to operate the stand.

If a tool is missing or wrong, fixing `control/` is in scope. After changing
daemon code, restart the daemon (`control/dtb/dtbctl restart`) - but never while a
long command is running, because that command's outcome is then unknown.

## Submodules

`hypervisor/efi-superrepo` and `database/materials/VMAware` are git submodules.
This is what makes an experiment record checkable: the superproject pins a
specific commit of each, so `commit` and `vmaware` in a record are meaningful.

Rules:

- **Never edit inside a submodule as part of a doc change.** A submodule bump is
  its own commit, and it changes the meaning of every later measurement.
- **A bump needs a reason**: either a fix to test, or a dependency update. Say
  which in the message.
- **Do not version large binaries.** Vendor PDFs live in `database/reference/`
  but are ignored; the registry names them, `.gitignore` excludes the bytes.

## Legacy `tools/`

`workspace/tools/` is what the harness replaced. The Python entry points are gone:
they were slow, and two of them were broken. The scripts still there are manual
diagnostics a human may run by hand.

The daemon does **not** read from this directory. The scripts it uploads live in
`control/dtb/guest_scripts/`, because they execute with the daemon's authority and
an agent-editable copy would let the workspace change what is measured. If a
helper is needed for regular operation, put it in `control/` and expose it as a
`dbg_*` tool - never in `workspace/tools/`.
