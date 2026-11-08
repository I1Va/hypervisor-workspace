---
topic: multicore-timing-research
kind: reference
updated: 2026-11-08
see: [hypervisor-architecture, cpuid-exiting-floor, detection-status, article-checks]
---

# Multicore hypervisor timing: capabilities and limits

Changing reported time can conceal a particular timestamp measurement. It does
not remove execution time, another CPU's completed work, device progress, or
external observations. A practical design must specify its observer model:
which clocks, privileges, concurrently executing processors and devices can the
guest observe? No reviewed source establishes a general way to make an arbitrary
native multicore Windows workload indistinguishable from its virtualized run.
This is an engineering conclusion under that broad observer model, not a theorem
that every restricted test must detect every VM.

This review uses the local Intel SDM 325462-092US (June 2026), Microsoft and Linux
specifications, QEMU documentation, original research and the pinned VMAware
source. Web search returned HTTP 403; sources were retrieved directly. Publication
abstracts support only the claims stated below, not unexamined implementation
claims. No firmware or stand settings were changed for this research.

## Distinguish the goals

| Goal | What success establishes | What it does not establish |
|---|---|---|
| Windows clock correctness | Monotonic cross-CPU time, stable conversion, coherent timer deadlines | Native instruction latency |
| Lower virtualization overhead | Less actual time spent exiting, handling and entering | Universal invisibility |
| Passing a timestamp probe | A particular observer sees a plausible result | Agreement with independent clocks or concurrent progress |
| Timing transparency | All allowed observations fit a specified native model | Achievable without defining the model and its exclusions |

A VM can have correct clocks and measurable overhead. CPU time consumed servicing
an exit is real elapsed time. The Hyper-V VP runtime specification even explicitly
includes hypervisor work performed on behalf of a guest [4].

## Why a second CPU changes the problem

Let CPU A execute an instruction that exits and CPU B continuously publish a
counter in shared memory. CPU A can read that counter before and after its
instruction. No RDTSC, QPC or device-clock read is required inside that interval.
An offset applied to CPU A's timestamps does not alter CPU B's published progress.
The counter is noisy and depends on scheduling, frequency and memory coherence;
it is independent of the modified timestamp interface, not independent of the
hypervisor's entire scheduling control.

Garfinkel et al. explicitly discuss this type of relative timing on logical
processors, plus DMA and external observations [7, section 2.3]. Later browser
work demonstrates implicit clocks without explicit clock queries [8]. Remote
concurrency research demonstrates timing information in response ordering [9].
Neither browser nor remote work is itself a universal VM detector.

The local VMAware TIMER source provides a concrete current example:

- `src/vmaware.hpp:7751`: a counter thread publishes increments on another CPU.
- `:7987`: the non-SERIALIZE path measures eight LFENCEs and CPUID using that
  counter. The Haswell stand uses this path.
- `:8044`: a lowest-dense-cluster estimator filters samples; results are not the
  diagnostic probe's simple medians.
- `:8139`: CPUID/reference ratio is evaluated; the same technique also evaluates
  debug-exception/software-exception latency. A score alone does not identify
  which branch fired.

The pinned host source describes the algorithm; it does not authenticate the
identity of the installed guest executable. Current run evidence remains in
`status.md`, not this reference.

## Available approaches

| Approach | Plausible use | Multicore limitations and costs |
|---|---|---|
| Fixed TSC offset | Choose an epoch; align counter domains | Fixed offsets cancel in elapsed-time differences; no latency removal |
| Per-exit, per-CPU offset correction | Alter a local timestamp interval | Different workloads accumulate different offsets; migration and deadlines become inconsistent; peer counters keep progressing |
| Hardware TSC scaling | Present a stable virtual frequency, including migration compatibility | Uniform scaling also scales reference intervals; ratios are unchanged; independent counters/devices remain |
| One coherent VM-wide virtual clock | Preserve clock consistency across vCPUs | Does not control software progress; publication must avoid backwards time and timer disagreement |
| Intercept timestamp reads | Implement richer virtual-time semantics | Adds exits on a frequent path, still leaves non-timestamp observers |
| Coordinated vCPU suspension / gang scheduling | Control concurrent progress in a constrained execution model | Peers do not stop retroactively; coordination adds latency, affects locks/IPIs/scheduling, and devices/external observers continue |
| Deterministic execution with virtualized I/O | Reproducible internal virtual time in a controlled environment | Major execution-model change, restricted parallelism and external-time divergence; not native real-time Windows behavior |
| Paravirtual clocks and scheduling information | Correct, efficient cooperative guest timekeeping | Explicit virtualization interface; not concealment and not deletion of instruction cost |
| Reduce exits and handler cost | Improve real application latency and throughput | Hardware-mandatory exits remain; gains depend on workload and available controls |
| Noise, coarsened clocks, artificial delays | Reduce measurement precision in a defined security model | Repeated/relative measurements and implicit clocks remain; artificial delay is additional overhead |

### Hardware TSC offset and scaling

Intel SDM Vol. 3C sections 27.6.5 and 28.3 define the guest transformation [1]:

```
guest_tsc = ((physical_tsc * multiplier) >> 48) + offset
```

Scaling is capability-dependent. With scaling disabled, only the offset is added.
RDTSCP also returns the low 32 bits of IA32_TSC_AUX. Native RDMSR of IA32_TSC is
covered by the documented transformation; not every timing facility is.

A fixed offset disappears from `end - start`. Uniform rate scaling changes both
measured instruction and reference intervals by the same factor, so it cannot
by itself correct their ratio. Frequency calibration can also reveal changes
relative to another clock. Modifying the rate only during selected operations
creates a time-dependent clock with a much broader consistency burden.

On hardware without the newer APIC-timer virtualization control, TSC offsetting
does not transform IA32_TSC_DEADLINE; it remains tied to the actual TSC. The June
2026 SDM also describes newer deadline-shadow/APIC-timer virtualization controls.
Those must not be assumed to exist on the i5-4460. Their existence does not make
peer software progress a TSC-derived quantity.

Invariant TSC means rate behavior, not an unconditional guarantee that all
sockets/cores have identical epochs. Distinguish rate, synchronization and
instruction-ordering guarantees [1, 2, 5].

### A shared clock is possible; it is not sufficient

A coherent virtual time domain is a normal hypervisor feature. It does not
inherently require forcing every vCPU to exit on every guest exit: trap-based
reads, versioned shared mappings and controlled epoch changes are different
ways to maintain a defined clock contract. Native per-VMCS offsets cannot,
however, be instantaneously republished on arbitrary running peers merely by
updating a C variable.

Even a perfectly coherent shared timestamp function does not erase observations
already made by other vCPUs. Backwards epoch changes are particularly problematic;
rate slewing avoids some discontinuities but still changes elapsed-time behavior.
Any changed virtual time must also have defined relationships with timers, power
states, suspend/resume, guest TSC writes and permitted device time sources.

### Coordinating every processor

Pausing peers can remove part of their progress during a coordinated interval.
It is not an instantaneous response to the beginning of an exit. Peers may execute
and publish state before notification reaches them, while synchronization itself
costs time. Multicore Windows code can observe lock-holder delays, IPI latency,
interrupt delivery and relative completion order. Assigned GPU/NIC/device work
and remote observers add clocks outside the vCPU schedule.

A design that controls execution, shared-memory interactions and I/O can establish
its own internal time semantics. That is a different objective from maintaining
native real-time behavior. QEMU's instruction-counted virtual clock illustrates
the scope: icount is not cycle-accurate and is incompatible with multi-threaded
TCG; replay also coordinates timers and external-input events [6]. No emulator
was launched for this review.

### Production clocks

Hyper-V's reference-time contract is partition-wide and monotonic across virtual
processors. Its reference TSC page uses scale, offset and a sequence number so a
guest can read a consistent mapping without an intercept. Synthetic timer signals
are guaranteed not to arrive early, but may be delayed [3]. This explicitly
addresses correct virtual time and scheduling delays.

KVM pvclock publishes a timestamp anchor, system-time anchor, conversion values
and a version. Its cross-CPU monotonicity flag is a specified capability, not an
assumption. Steal-time reporting separately communicates time a vCPU did not run;
it does not silently remove that interval from all clocks [2].

Microsoft recommends QPC over direct application TSC reads and describes the
reference-time enlightenment as a lower-overhead option [5]. Advertising an
interface requires implementing its documented contract. A detector exclusion
triggered by branding does not validate that contract or fix real overhead.

### Reducing real overhead

Intel SDM section 28.1.2 lists CPUID as an unconditional non-root VM exit [1].
There is no ordinary Intel VMX control to let guest CPUID execute natively. This
is a hardware rule, not a universal numerical bound on handler latency or on a
detector ratio. Handler improvements can still matter.

VPID permits retaining eligible translation-cache entries across VMX transitions.
Posted-interrupt processing can avoid selected interrupt exits when all required
controls and platform facilities are present. Neither feature makes all exits
free. Translation invalidation instructions act on the executing logical
processor, so shared mapping changes still require multicore coordination.
KVM's multicast IPI hypercall is a concrete example of amortizing transitions by
batching work with guest cooperation [12].

Useful targets include unnecessary intercepts, synchronous logging, redundant
VMCS operations, contended global state, translation invalidations and memory
locality. EPT/VPID and APIC virtualization reduce particular costs where supported;
interrupt acceleration does not remove a mandatory CPUID exit. Optimize the
measured dominant cost, preserve architectural state and measure unchanged
workloads. An optimization that has no reproducible gain should not be called a
successful timing fix.

AMD SVM has a different interception model, including a configurable CPUID
intercept, corroborated here by upstream Linux's SVM definitions [13]; AMD's
current official APM download was not retrieved. That makes some exits avoidable
when native CPUID semantics are acceptable; it is not a route to disabling
Intel's mandatory exit and does not remove virtualization effects from other
instructions or devices.

## How to read the project's 2020 article

The secret.club articles [10] document particular historical checks and discuss
counter rewriting and emulation. Their timestamp-probe discussion is useful for
understanding those probes. It does not establish global timer consistency,
multicore transparency or current anti-cheat behavior. The April article itself
also discusses APERF-based comparisons, so its scope is not that every observer
uses RDTSC.

Claims based on fixed cycle allowances, average per-instruction costs, or fixed
transition costs need hardware-specific validation. Native instruction latency
also depends on operand/leaf, cache state, contention, ordering, frequency and
microcode. Historical cost figures are not specifications.

## Implications for this project

Keep correctness and performance acceptance separate. Preserve the physical
clock mapping while diagnosing the reported Windows malfunction. Do not infer
an OS bug from TIMER alone or claim that correct QPC proves native performance.
Use a baseline with the same CPU topology, Windows build, probes and relevant
power configuration. Establish which TIMER submeasurement fires rather than
assuming it from the combined score.

Prioritize real exit-cost measurement, timer/interrupt delivery and application
reproduction. Assess richer clock interfaces only if required for a concrete
timekeeping feature, such as migration or cooperative guest timekeeping. The
reviewed sources do not justify reinstating per-CPU exit-time subtraction as a
Windows correctness fix. Full transparency and a restricted observer passing a
test remain distinct claims.

## Sources and verification

1. Intel, *64 and IA-32 Architectures Software Developer's Manual*, combined
   325462-092US, June 2026. Read local PDF: `specifications/intel-sdm-vol-1-2abcd-3abcd-4.pdf`.
   Relevant Vol. 3C sections 27.6.5, 28.1.2, 28.3; capability controls in 27.6.2.
   [Official distribution page](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html).
   The web page returned a regional notice; technical statements were checked in
   the local PDF, not inferred from the web response.
2. Linux KVM, [Timekeeping Virtualization](https://docs.kernel.org/virt/kvm/x86/timekeeping.html)
   and [KVM-specific MSRs](https://docs.kernel.org/virt/kvm/x86/msr.html).
   Read full relevant sections. The timekeeping narrative dates to 2010 and some
   hardware/Windows discussion is historical; current Intel/Microsoft contracts
   take priority over those old examples.
3. Microsoft, [Hyper-V TLFS: Timers](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/timers).
   Read reference-counter, reference-TSC page and synthetic-timer contracts.
4. Microsoft, [TLFS: Virtual Processor](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/vp-properties).
   Read VP runtime and guest spinlock behavior.
5. Microsoft, [Acquiring high-resolution time stamps](https://learn.microsoft.com/en-us/windows/win32/sysinfo/acquiring-high-resolution-time-stamps).
   Read virtualization, direct-TSC, hardware-clock and frequency guidance.
6. QEMU, [TCG Instruction Counting](https://www.qemu.org/docs/master/devel/tcg-icount.html)
   and [Execution Record/Replay](https://www.qemu.org/docs/master/devel/replay.html).
   Read design documentation; no execution or simulator testing.
7. Garfinkel, Adams, Warfield, Franklin, *Compatibility is Not Transparency:
   VMM Detection Myths and Realities*, HotOS XI, 2007.
   [Original full text](https://www.usenix.org/legacy/events/hotos07/tech/full_papers/garfinkel/garfinkel_html/index.html).
   Read full text; position paper, not a modern formal impossibility proof.
8. Kohlbrenner and Shacham, *Trusted Browsers for Uncertain Times*, USENIX Security,
   2016. [Official abstract](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/kohlbrenner).
   Verified abstract: implicit clocks and limits of degrading explicit clocks.
   Browser findings are supporting analogy, not a native VM evaluation.
9. Van Goethem, Popper, Joosen, Vanhoef, *Timeless Timing Attacks: Exploiting
   Concurrency to Leak Secrets over Remote Connections*, USENIX Security, 2020.
   [Official abstract](https://www.usenix.org/conference/usenixsecurity20/presentation/van-goethem).
   Verified abstract: response order reveals relative timing in evaluated
   protocols. Not a direct hypervisor detector or universal sensitivity claim.
10. secret.club, [How anti-cheats detect system emulation](https://secret.club/2020/04/13/how-anti-cheats-detect-system-emulation.html)
    and [BattlEye hypervisor detection](https://secret.club/2020/01/12/battleye-hypervisor-detection.html),
    2020. Read relevant technical sections as historical reverse-engineering,
    not current vendor specifications or proof of a complete timing design.
11. Local VMAware `v2.8.2-56-gc8092c6`, `materials/VMAware/src/vmaware.hpp`.
    Read TIMER implementation. Consult `status.md` for executable-identity and
    measurement limitations.
12. Linux KVM, [x86 hypercalls: KVM_HC_SEND_IPI](https://docs.kernel.org/virt/kvm/x86/hypercalls.html#kvm-hc-send-ipi).
    Documented multicast IPI batching, checked as production design evidence.
13. Linux v6.12, [SVM architecture definitions](https://github.com/torvalds/linux/blob/v6.12/arch/x86/include/asm/svm.h).
    `INTERCEPT_CPUID` confirms a selectable VMCB intercept. This verification
    uses upstream source, not a fetched AMD architecture manual.
