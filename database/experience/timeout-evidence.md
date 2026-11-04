---
topic: timeout-evidence
kind: experience
date: 2026-11-04
symptom_class: ambiguous-hang
---

# Timeout verdicts need observable evidence

This supersedes the unconditional frozen-heartbeat conclusions in
`detecting-a-wedge.md` and the reset advice in `false-wedge-from-silent-console.md`.
Those historical records remain evidence of earlier reasoning.

A counter that advances during a timed-out command shows guest execution. A
counter that does not advance can support a wedge diagnosis only if the counter
was observed before and after, is stale, and the console is still producing
fresh bytes. With no counter or a silent console, COM1 power gating or another
observation failure can hide guest progress. The correct verdict is `unknown`;
a timeout and silent serial alone do not justify resetting the machine.

The `dbg_run` and `dbg_suite` timeout paths use this same distinction. Inspect
status and other available evidence before choosing a recovery action.
