---
topic: experience-accumulation
kind: reference
updated: 2026-11-04
see: [documentation, experiment-recording]
---

# Engineering experience policy

Some failures cost hours because the symptom was misleading, not because the
problem was hard. Those are the only ones worth writing down - and they are worth
a lot, because the next person (or the next session) will meet the same symptom.

## The trigger

Write a lesson when **the symptom pointed somewhere other than the cause.**

Examples from this project, which is why this policy exists:

| Symptom | Cause | What it cost |
|---|---|---|
| "The hypervisor hangs" | `HandleMonitorTrapFlag` was an empty stub; MTF stayed set forever | a session of resets |
| "The machine is dead, serial is silent" | Windows power-gated COM1 to D3 | several sessions, on every boot |
| "VMAware says clean" | `-d` is thresholded at 150, so a 45-point detection printed 0 | a false pass, believed for days |
| "The full suite produces nothing" | `PRINT_LINE` goes through the TUI, which has no console over SSH | a leftover spinning process that then degraded the guest |
| "The stand hangs, ssh takes 30 s" | two leftover `vmaware.exe` from earlier runs | the real cause of what looked like a hung machine |

A bug that was hard to *fix* but obvious to *find* is not this kind of lesson; it
belongs in the subsystem reference.

## The shape

One file per lesson, `database/experience/<slug>.md`:

```markdown
---
topic: com1-power-gating
kind: experience
date: 2026-11-04
symptom_class: silent-serial
---

## Symptom
What you see. Precise enough to match: "serial stops at a fixed point after
Windows starts, on every boot".

## Why it misleads
Why the obvious interpretation is wrong.

## Cause
The actual mechanism.

## How to tell them apart
The discriminating observation. This is the most valuable section: it is what
turns the next occurrence from a session into a minute.

## Fix
What was changed.

## Residual risk
What can still produce this symptom. "Silence is also what you get if COM1 is
power-gated" is exactly this section.
```

## Rules

- **Write it while the evidence is fresh.** A lesson written a week later
  contains the cause but not the discriminating observation, and the observation
  is the point.
- **Symptom first.** The file must open with what the next person will *see*.
  Retrieval is by symptom, not by cause - you cannot search for something you do
  not yet know.
- **One lesson per file.** Two lessons in one file means neither is findable.
- **Name the tool that discriminates**, if one exists (`dbg_status` verdict,
  `dbg_firmware`, a log marker). A lesson that says "check carefully" is not a
  lesson.
- **Keep it short.** If it exceeds a screen, part of it is reference material and
  belongs in L2.

## When a lesson stops being true

The cause is fixed and the symptom can no longer occur: mark the frontmatter
`status: historical` and say in one line what replaced it. Do not delete - the
next reader still needs to know why the code looks the way it does.
