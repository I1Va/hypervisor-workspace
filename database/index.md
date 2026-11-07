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
| false-wedge-from-silent-console | experience | A silent console froze the heartbeat and produced a false `wedged` verdict on a healthy guest | `experience/false-wedge-from-silent-console.md` |
| stale-boot-server | experience | A stale HTTP server held the boot port, served 404, and the machine sat in firmware | `experience/stale-boot-server.md` |
| empty-suite-is-not-clean | experience | A 669 s suite run that recorded nothing was reported as clean; the tool has since been removed | `experience/empty-suite-is-not-clean.md` |
| com1-power-gating | experience | Serial stops after Windows starts; COM1 goes to D3 | `experience/com1-power-gating.md` |
| detecting-a-wedge | experience | Historical diagnosis; its frozen-heartbeat conclusion is superseded by false-wedge-from-silent-console and timeout-evidence | `experience/detecting-a-wedge.md` |
| timeout-evidence | experience | Timeout verdicts require observable heartbeat evidence; supersedes unsafe reset advice in earlier records | `experience/timeout-evidence.md` |
| vmaware-measurement-traps | experience | `-d` vs `--percent`, unknown technique names, TUI output vanishing | `experience/vmaware-measurement-traps.md` |
| stale-probe-processes | experience | A leftover `vmaware.exe` makes the whole stand look hung | `experience/stale-probe-processes.md` |
| stale-panic-from-cumulative-log | experience | A panic from an earlier boot is reported as current; `dbg_boot` then refuses to boot a healthy machine | `experience/stale-panic-from-cumulative-log.md` |
| nmi-window-storm | experience | Fabricated NMIs caused an exit storm that looked like a hang | `experience/nmi-window-storm.md` |
| silent-root-mode-livelock | experience | MTF stuck set / EPT redo loop wedged every CPU with no output | `experience/silent-root-mode-livelock.md` |
| ap-init-sipi-uart-stall | experience | A stalled INIT handler discarded the SIPI; Windows came up on one processor while every signal said four | `experience/ap-init-sipi-uart-stall.md` |
| pending-debug-exceptions-livelock | experience | Pending-debug field OR-ed and never cleared; endless #DB starved a core into CLOCK_WATCHDOG_TIMEOUT | `experience/pending-debug-exceptions-livelock.md` |
| vmaware-shortcut-false-signal | experience | `--percent`/`--detect` early-exit at the score threshold, so they are not a silent full run; and `--all` bypasses the platform filter | `experience/vmaware-shortcut-false-signal.md` |
| thread-mismatch | reference | How THREAD_MISMATCH is computed (hardware_concurrency vs the CPU-model thread count) and what has to agree to pass it | `hv/thread-mismatch.md` |
| suite-hang-status | status | Why the VMAware full summary hangs: the second pass ignores `--disable`; per-technique sweep results; TIMER/HYPERVISOR_HOOK are the only hangs | `hv/suite-hang-status.md` |
| intel-sdm | reference | Intel SDM combined volumes 1-4 (PDF, 26 MB, not versioned; referenced for VMX/NMI/topology rules) | `specifications/intel-sdm-vol-1-2abcd-3abcd-4.pdf` |
| debug-exception-delivery | reference | What is measured about #DB delivery: TF is accepted, hardware raises the trap, DR6 is the VMM's job, re-injection fails VM entry; why TRAP/SINGLE_STEP/DBVM/INTERRUPT_SHADOW fire | `hv/debug-exception-delivery.md` |
| cpuid-exiting-floor | reference | CPUID exiting is CPU-mandatory (capability MSR must1=1), so TIMER's CPUID/LFENCE ratio of 6.00 (limit 2.75) is structural and TRAP can never see BS or B0 together; measurements and what was tried. The branding lever this analysis left open was subsequently implemented - see hyperv-branding | `hv/cpuid-exiting-floor.md` |
| detection-vectors | reference | Inventory of what a detector can measure, what each requires from the hypervisor, current status, and the three interface conclusions (declarative policy, per-handler latency budget, structured hypercall stats) | `hv/detection-vectors.md` |
| hyperv-branding | reference | How TRAP and TIMER were cleared by presenting a Hyper-V root partition: the measured gates, the three traps (root flag is in 0x40000003 not 0x40000001, the hypervisor bit must be set too, Hv#1 must be withheld or the loader stalls), and the 150-point risk | `hv/hyperv-branding.md` |
| fast-startup-hides-boot-config | experience | `bcdedit` succeeds but is gone after a power cycle: the relay hibernates and the next power-on resumes the old kernel. Restart from inside Windows instead | `experience/fast-startup-hides-boot-config.md` |
| breaking-the-stall | experience | Why many sessions produced no progress, and the four practices that restored the feedback loop: read state instead of inferring it, make tools explain failure, decompose composite tests, take physical observations literally | `experience/breaking-the-stall.md` |

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

## CS2 / CS:GO corpus

| topic | kind | description | path |
|---|---|---|---|
| csgo-corpus | reference | What the corpus is, layout, documented modules, method | `csgo/README.md` |
| csgo-resume | reference | State at hand-off, bootstrap, per-module procedure, traps | `csgo/RESUME.md` |
| csgo-cs2-launcher | reference | `cs2.exe`: Source 2 launcher and its install trust subsystem | `csgo/documents/cs2.md` |
| csgo-client | reference | `client.dll`: interfaces, entities, prediction, HUD, ConVars | `csgo/documents/client.md` |
| csgo-manifest | index | Every module: size, hash, PDB, function count, doc status | `csgo/index/manifest.json` |
