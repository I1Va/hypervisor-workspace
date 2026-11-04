# Knowledge registry

Every document in `database/`. If a file is not listed here, retrieval will not
find it - so adding a file and adding its line is one action.

Read this file first, pick the smallest match, then read only that.

| topic | kind | description | path |
|---|---|---|---|
| platform | reference | Stand wiring, addresses, ports, credentials, wiring notes | `bench/platform.md` |
| hypervisor-architecture | reference | Pulverized DXE layout: host prep, VMCS, exit dispatch, EPT | `hv/architecture.md` |
| hvlog | reference | Debug log design: heartbeat, serial capture, hvlog reader, why silence is ambiguous | `hv/hvlog.md` |
| detection-status | status | Current VMAware verdicts and which vectors still fire (dated) | `hv/status.md` |
| 2026-11-04-harness-refactor | experiment | Tooling baseline; why per-command latency was 8-35 s and how timeouts are now resolved | `experiments/2026-11-04-harness-refactor/record.md` |
| com1-power-gating | experience | Serial stops after Windows starts; COM1 goes to D3 | `experience/com1-power-gating.md` |
| detecting-a-wedge | experience | Telling a slow guest from a wedged one, and why the old probe could not | `experience/detecting-a-wedge.md` |
| vmaware-measurement-traps | experience | `-d` vs `--percent`, unknown technique names, TUI output vanishing | `experience/vmaware-measurement-traps.md` |
| stale-probe-processes | experience | A leftover `vmaware.exe` makes the whole stand look hung | `experience/stale-probe-processes.md` |
| nmi-window-storm | experience | Fabricated NMIs caused an exit storm that looked like a hang | `experience/nmi-window-storm.md` |
| silent-root-mode-livelock | experience | MTF stuck set / EPT redo loop wedged every CPU with no output | `experience/silent-root-mode-livelock.md` |

## Policies

| topic | description | path |
|---|---|---|
| repository-layout | The two halves of the repo, the closed boundary, submodule rules | `policies/repository.md` |
| documentation | Four documentation levels, where a fact goes, superseding rules | `policies/documentation.md` |
| experiment-recording | What makes a measurement a record, required frontmatter | `policies/experiments.md` |
| experience-accumulation | When a misleading symptom becomes a written lesson | `policies/experience.md` |

## Archive

Superseded documents, kept as evidence rather than deleted. Not for retrieval -
use the live documents above.

| topic | description | path |
|---|---|---|
| hypervisor-debugging (superseded) | The original 17 KB working notes this knowledge base was split from. Kept because it holds reasoning the split did not preserve. | `archive/2026-11-04-hypervisor-debugging.md` |
| platform (superseded) | The original `platform.md`, including contradictory instructions later removed. | `archive/2026-11-04-platform-original.md` |

## Materials

| Item | Purpose | Path |
|---|---|---|
| VMAware | The detection tool under test, vendored and pinned | `materials/VMAware/` |
| Z97-WS manual | Motherboard reference for stand wiring | `reference/E12543b_Z97-WS_UM_V2_WEB.pdf` |
