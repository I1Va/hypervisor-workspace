---
topic: 2026-11-04-harness-refactor
kind: experiment
date: 2026-11-04
commit: db8b0ab
vmaware: v2.8.2-56-gc8092c6
boot_id: 0
technique: "suite"
result: inconclusive
phase_at_failure: desktop
verdict_source: manual
---

## What was run

Harness refactor only; no hypervisor change. Baseline measurements taken on the
live stand to justify each part of the new harness:

- `probe.py` TCP connect: 28 ms, reports ALIVE
- SSH command, fresh handshake: 8-35 s
- SSH command, multiplexed: 86-99 ms
- SSH command after killing 2 leftover `vmaware.exe`: 122 ms
- Arduino query with per-call port open: 2.6 s
- Arduino query with a persistent handle: 55 ms
- `try_technique.py CPUID_SIGNATURE`: crashed, `FileNotFoundError
  database/VMAware/src/vmaware.hpp`

## Result

No detection measurement was taken, so this record is `inconclusive` by its own
policy - and that is the correct classification. It documents a tooling baseline,
not a VMAware verdict.

Post-refactor measurements (same stand, same boot):

| Path | Before | After |
|---|---|---|
| `dbg_status` | n/a | 160 ms |
| `dbg_run hostname` | 8-35 s | 300 ms |
| Timeout disambiguation | impossible | verdict `slow` + heartbeat evidence |

## Interpretation

The 8-35 s per command was not the network: TCP connect was 28 ms throughout. It
was guest CPU starvation from leftover probe processes. The old harness could not
see this because its only liveness check was a TCP connect, which succeeds on a
guest that is too starved to complete an SSH handshake in under a minute.

The same ambiguity made "hung" and "slow" indistinguishable, and those require
opposite responses. Resolving a timeout against the hypervisor heartbeat is
therefore not an optimisation - it changes which action is correct.

## Next

1. Re-run `dbg_suite` on this boot to confirm the harness reproduces the known
   detection table (`hv/status.md`), then record it properly with this template.
2. Attack the trap quartet (`TRAP`, `SINGLE_STEP`, `INTERRUPT_SHADOW`, `DBVM`)
   starting with `VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS`, per `hv/status.md`.
