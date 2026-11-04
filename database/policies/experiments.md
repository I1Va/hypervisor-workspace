---
topic: experiment-recording
kind: reference
updated: 2026-11-04
see: [documentation, experience]
---

# Experiment recording policy

A result without a build hash and a checker revision is an anecdote. This file
defines when a measurement becomes a record, and what it must contain.

## When to record

Record when **any** of these is true:

- a detection verdict changes (clean → fires, or the reverse),
- a score moves, even if the verdict does not,
- a hang, panic or wedge was reproduced,
- a change was reverted because it made things worse.

Do not record routine greens: "technique ran, nothing changed"
belongs in the conversation, not the archive.

Records are written **only when asked** - the harness returns results, it does
not write history by itself. `dbg_technique` hands back
everything needed; turning that into a record is a deliberate act.

## Required frontmatter

```yaml
---
topic: 2026-11-04-ept-hook-mtf
kind: experiment
date: 2026-11-04
commit: db8b0ab            # PulverizedPkg HEAD that was actually served
vmaware: v2.8.2-56-gc8092c6 # from the tool's vmaware_rev field
boot_id: 7                  # which boot produced this, from the tool
technique: HYPERVISOR_HOOK
result: fires:100           # clean | fires:N | timeout | wedged | panic | inconclusive
phase_at_failure: desktop
verdict_source: dbg_technique
---
```

Every field above is either returned by a tool or trivially available. If one is
missing, the record is marked `inconclusive` rather than left blank.

## Body

Four sections, in this order, and nothing else:

```markdown
## What was run
The exact command and parameters.

## Result
The tool output, verbatim where it matters. Include the stand verdict, not just
the score, because "clean because the guest was wedged" is not clean.

## Interpretation
What this means for the detection vector. Keep it to the claim the data supports.

## Next
The next experiment, or "none" if the thread is closed.
```

## Evidence

Large evidence (serial capture, screenshot, result file) goes beside the record:

```
database/experiments/2026-11-04-ept-hook-mtf/
├── record.md
├── serial.log        # extract around the event, not the whole boot
└── result.txt
```

**Screenshots never go into the record.** Capture the screen with
`dbg_screenshot`, which sends the image to a vision model and returns text;
store that text. Opening an image in the main session can interrupt it, so the
image itself is discarded after description (see `agent_restrictions.md`).

Extract the relevant window from the serial log rather than committing a
megabyte of heartbeats. The tool's `cursor` makes this easy: note the cursor
before and after, and keep only that slice.

## Comparing records

Two records are comparable only when `commit` and `vmaware` match. When they do
not, the later record states what changed. This is the whole reason the fields
are mandatory: the existing score table in the old debugging document could not
answer "which build produced this?" and was therefore not evidence.

## Retention

Records are never deleted. A record proven wrong is superseded by a newer one
that says so, and the registry marks the old one `superseded`.
