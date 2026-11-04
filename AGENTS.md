# AGENTS.md

You work on an invisible UEFI hypervisor tested on a physical stand (DTB). The
pass criterion is that VMAware does not detect it.

This file is a router. It holds only what must never be missed; everything else
lives in `database/` and is read on demand.

## Repository layout

The repository has two halves, and the boundary is enforced rather than agreed:

| Directory | Access | Contains |
|---|---|---|
| `workspace/` (this tree) | open - read and edit | instructions, knowledge base, hypervisor source, legacy scripts |
| `control/` | **closed** - use its tools, do not read it | stand daemon, Arduino firmware, session supervisor |

Agent restrictions are in `agent_restrictions.md`; they are loaded by OpenCode configuration and must be followed.

## The loop

```
edit hypervisor -> build -> dbg_boot -> dbg_run -> dbg_technique
```

Build: `cd hypervisor/efi-superrepo && NO_DOCKER=1 ./PulverizedPkg/build.sh`.
If it fails with `No rule to make target '/PulverizedPkg/Sources/...'`, the
generated makefile lost `$(WORKSPACE)`: `rm -rf Build/Pulverized` and rebuild.

## Where knowledge lives

Read `database/index.md` first; it is the registry. Then read at most the two or
three documents that match, not the whole tree.

| Need | Read |
|---|---|
| Stand details, wiring, addresses | `database/bench/platform.md` |
| How the hypervisor works | `database/hv/*.md` |
| Current detection status | `database/hv/status.md` |
| A past lesson that may explain today's symptom | `database/experience/*.md` |
| What was already measured | `database/experiments/*/record.md` |
| How to write any of the above | `database/policies/*.md` |

## Policies you must follow

- `database/policies/documentation.md` - where documentation goes and how it is
  superseded.
- `database/policies/experiments.md` - what makes a result a result.
- `database/policies/experience.md` - when to write a lesson down.
- `database/policies/repository.md` - the open/closed split and submodule rules.

