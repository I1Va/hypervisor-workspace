# AGENTS.md

You work on an invisible UEFI hypervisor tested on a physical stand (DTB). The
pass criterion is that VMAware does not detect it.

This file is a router. It holds only what must never be missed; everything else
lives in `database/` and is read on demand.

## Non-negotiables

1. **Never launch the simulator.** Testing happens on the DTB.
2. **The stand is controlled only through the `dbg_*` tools.** Do not open
   serial ports, do not call `ssh` directly, do not use `tools/*.py`. The daemon
   owns the hardware; a second owner reboots the Arduino or fights the SSH
   master.
3. **Never infer state you can read.** Call `dbg_status` first.
4. **A timeout is not a failure until the verdict says so.** `slow` means wait,
   `wedged` means reset. Resetting a `booting` machine destroys the run.
5. **Do not test a stale build.** `dbg_boot` refuses one; rebuilding is cheap
   (~10 s incremental).
6. **No secrets, credentials or absolute host paths in committed files.**

## The loop

```
edit hypervisor -> build -> dbg_boot -> dbg_run -> dbg_technique / dbg_suite
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

## Retrieval discipline

Before reading anything, ask: *which single document answers this?* Read the
registry, filter by the frontmatter fields, open the smallest match. If you find
yourself reading four documents to answer one question, the documentation is
wrong - fix it as part of the task.

Never re-read a document already cited in this session.
