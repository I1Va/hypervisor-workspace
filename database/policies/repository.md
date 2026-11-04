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
| `control/` | **closed**: use its interface, never read it | stand daemon, Arduino firmware, session supervisor |

## Why the boundary is enforced

`control/` owns state that cannot be reconstructed from outside:

- an open Arduino serial handle - opening the port asserts DTR and reboots the
  board, so it is opened once and held,
- an SSH master socket - one handshake instead of one per command,
- which boot a serial log line belongs to.

If the agent could read that code it would be tempted to "just" open the port or
call ssh directly, and two owners of the hardware reboot the Arduino against each
other. So `read` on `control/**` is denied in `opencode.jsonc`, and the interface
is the only way in:

```sh
control/dtb/dtbctl describe    # the contract, served at runtime
control/dtb/dtbctl status      # current state
```

The contract is served rather than documented precisely so it cannot drift from
behaviour.

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

`workspace/tools/` is what the harness replaced. It is kept because the guest-side
PowerShell scripts are still used by the daemon, but the Python entry points are
gone: they were slow, and two of them were broken. Do not add new scripts there;
add a `control/dtb` command and expose it as a `dbg_*` tool.
