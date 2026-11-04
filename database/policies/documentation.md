# Documentation policy

Documentation here is an index over knowledge, not an archive of conversations.
The rule this file enforces: **a fact lives in exactly one place, and that place
is chosen by what kind of fact it is.**

## The four levels

| Level | Location | Holds | Written by |
|---|---|---|---|
| L0 | `AGENTS.md` | routing and non-negotiables, under 150 lines | human, rarely |
| L1 | `database/index.md` | the registry: every document, one line each | whoever adds a document |
| L2 | `database/bench/`, `database/hv/` | durable reference: how the stand is wired, how a subsystem works | whoever changes that subsystem |
| L3 | `database/experience/`, `database/experiments/` | dated, append-only records: what happened, what was learned | whoever ran the experiment |

L0 is a router; if it grows past a screen it has started absorbing L2 and should
be cut back. L3 is append-only: an old record is evidence, so it is corrected by
a newer record rather than edited.

## Where a new fact goes

Ask in this order:

1. **Is it a rule that must never be missed?** → `AGENTS.md`. This is the most
   expensive place to put anything, because it is loaded every session.
2. **Is it true regardless of when it was learned?** → L2, in the subsystem
   document. How EPT hooks work belongs here; "EPT hooks were broken last
   Tuesday" does not.
3. **Is it a measurement?** → L3 `experiments/`. Always with its commit and
   `vmaware_rev`, or it is not a measurement.
4. **Is it a trap that cost time and would cost it again?** → L3 `experience/`.
   The test is: *would a competent engineer hit this again?* If yes, write it.
5. **Is it a status snapshot?** → `database/hv/status.md`, which is dated and
   superseded rather than deleted.

## Superseding, never deleting

When documentation becomes wrong:

- L2: edit it. Reference documentation describes the present.
- L3: do not edit. Add a newer record that says what changed and why the old one
  no longer applies.
- `status.md`: add a new dated section at the top. The previous one stays so that
  "it used to pass" remains answerable.

Deleting a document is allowed only when its content has moved and the registry
entry says where.

## Frontmatter

Every L2 and L3 document starts with frontmatter. It makes retrieval a filter
rather than a full read:

```yaml
---
topic: ept-hooks          # stable slug, used for cross-references
kind: reference           # reference | status | experience | experiment
updated: 2026-11-04
see: [vmexit, hvlog]      # related topic slugs
---
```

Experiment records add `commit`, `vmaware`, `technique`, `result`,
`phase_at_failure` (see `experiments.md`).

## The registry

`database/index.md` has one line per document:

```
| topic | kind | one-line description | path |
```

A document that is not in the registry does not exist as far as retrieval is
concerned, so adding a file and adding its line are one action.

## Anti-patterns

These are the failure modes that produced the current 17 KB
`hypervisor-debugging.md`, a file that mixed solved bugs, open leads and tool
documentation so that none of it could be found:

- **A diary.** Chronological notes. Nobody can search a narrative; split by
  subject.
- **Advice in tool docs.** If a tool has a rule, put it in the tool's
  description where it is read at the moment of use.
- **Duplicated instructions.** `init.md` and `tasks.md` said the same thing as
  `platform.md`, so they drifted apart. One source.
- **A doc describing a command line that has since moved.** The freshness check
  and the build path live in the tool that enforces them.
