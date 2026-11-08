---
topic: kvm-timekeeping-implementation
kind: reference
updated: 2026-11-08
see: [multicore-timing-research, cpuid-exiting-floor, detection-status]
---

# KVM timekeeping: implementation findings

## Source provenance and scope

The exact requested repository was accessible through Git:
`https://git.kernel.org/pub/scm/virt/kvm/kvm.git`.
Its web and plain-file endpoints returned an Anubis challenge, but Git clone
succeeded. The inspected `master` revision was
`6628e7d4c6b25c8d18f1345e3a20d21829aae7e4` (Linux 7.4-rc1,
commit date 2026-11-01). These are source findings, not KVM runtime measurements
or evidence that VMAware passes on KVM. No stand operation was needed.

All source links below pin that revision through the upstream Linux mirror.
The kernel.org tree can also be queried with the same commit identifier.

## 1. Maintain clock rate and continuity, not erase every exit

The guest TSC mapping is conceptually
`guest_tsc = scale(host_tsc, ratio) + offset`.
`kvm_read_l1_tsc`, `kvm_compute_l1_tsc_offset` and the multiplier/offset writers
implement that mapping. Hardware support is capability-checked; scaling is not
assumed available on every Intel CPU. The VMX backend installs the mapping in
VMCS fields. Its ordinary execution controls clear RDTSC exiting; nested
virtualization can request a different interception policy.

Sources: [x86.c:1023–1090, 1154–1298](https://github.com/torvalds/linux/blob/6628e7d4c6b25c8d18f1345e3a20d21829aae7e4/arch/x86/kvm/x86.c#L1023-L1298),
[vmx.c:2064–2071](https://github.com/torvalds/linux/blob/6628e7d4c6b25c8d18f1345e3a20d21829aae7e4/arch/x86/kvm/vmx/vmx.c#L2064-L2071),
[vmx.c:4651–4692](https://github.com/torvalds/linux/blob/6628e7d4c6b25c8d18f1345e3a20d21829aae7e4/arch/x86/kvm/vmx/vmx.c#L4651-L4692).

Offset changes have explicit causes: guest TSC/TSC_ADJUST writes, userspace
initialization or restoration, unstable host clocks, and host suspend recovery.
`kvm_synchronize_tsc` serializes updates and tracks matching vCPU generations.
On reliable hosts it can reuse an identical offset across synchronized vCPUs.
Host migration/load handling detects backwards TSC and enables catch-up for
unstable clocks. Catch-up advances a lagging TSC toward elapsed reference time;
it is not subtraction of root-mode execution time after every CPUID.

Sources: [x86.c:1314–1439](https://github.com/torvalds/linux/blob/6628e7d4c6b25c8d18f1345e3a20d21829aae7e4/arch/x86/kvm/x86.c#L1314-L1439),
[x86.c:1842–1864](https://github.com/torvalds/linux/blob/6628e7d4c6b25c8d18f1345e3a20d21829aae7e4/arch/x86/kvm/x86.c#L1842-L1864),
[x86.c:2583–2620](https://github.com/torvalds/linux/blob/6628e7d4c6b25c8d18f1345e3a20d21829aae7e4/arch/x86/kvm/x86.c#L2583-L2620),
[msrs.c:1592–1649](https://github.com/torvalds/linux/blob/6628e7d4c6b25c8d18f1345e3a20d21829aae7e4/arch/x86/kvm/msrs.c#L1592-L1649).

## 2. Publish a consistent multicore clock

KVM explicitly documents how independently sampled TSC/time anchors can violate
cross-vCPU monotonicity even when hardware TSCs are synchronized. Its master
clock uses one shared reference snapshot, enabled only under qualifying host
clock and matched-vCPU conditions. Master-clock updates block guest entries
while the shared state changes and request vCPU clock refreshes afterward.

The pvclock ABI publishes TSC and system-time anchors plus multiplier/shift
values. Readers validate a version before and after the read; odd versions
mean an update is underway. `kvm_setup_guest_pvclock` follows this protocol even
while its own vCPU is paused, since another vCPU may read the page.

Sources: [x86.c:1520–1657](https://github.com/torvalds/linux/blob/6628e7d4c6b25c8d18f1345e3a20d21829aae7e4/arch/x86/kvm/x86.c#L1520-L1657),
[x86.c:1743–1788](https://github.com/torvalds/linux/blob/6628e7d4c6b25c8d18f1345e3a20d21829aae7e4/arch/x86/kvm/x86.c#L1743-L1788),
[KVM-specific MSR ABI](https://docs.kernel.org/virt/kvm/x86/msr.html).

## 3. Compensate timer delivery separately from clock readings

KVM can schedule an emulated LAPIC deadline early by `timer_advance_ns` to
compensate for delivery overhead. It measures early/late arrival, ignores tiny
fluctuations and large spikes, and adapts the advance. If processing is early,
it performs a bounded wait toward the actual guest deadline. Posted-interrupt
handling performs the wait before posting, because waiting after posting cannot
prevent early observation by a running guest.

The VMX hardware-timer path translates the guest deadline into host TSC units,
accounts for TSC scaling and advance, checks the preemption-timer range, and can
fall back to a software timer. This changes when the host services a deadline;
it does not conceal CPUID execution latency by changing guest timestamps.

Sources: [lapic.c:1958–2119](https://github.com/torvalds/linux/blob/6628e7d4c6b25c8d18f1345e3a20d21829aae7e4/arch/x86/kvm/lapic.c#L1958-L2119),
[vmx.c:8237–8304](https://github.com/torvalds/linux/blob/6628e7d4c6b25c8d18f1345e3a20d21829aae7e4/arch/x86/kvm/vmx/vmx.c#L8237-L8304).

## 4. Windows gets an explicit compatible clock interface

KVM implements Hyper-V reference time and a reference-TSC page for guests that
use the advertised interface. The page converts TSC into 100-nanosecond units
with scale/offset and a sequence protocol. KVM requires the stable pvclock flag
before constructing valid fast-page parameters. During update it sets sequence
zero, directing the guest to the reference-count MSR until publication finishes.
This is an implemented guest-visible ABI, not just a vendor string.

Source: [hyperv.c:1136–1258](https://github.com/torvalds/linux/blob/6628e7d4c6b25c8d18f1345e3a20d21829aae7e4/arch/x86/kvm/hyperv.c#L1136-L1258).
For feature dependencies and Windows usage, see
[QEMU Hyper-V enlightenments](https://www.qemu.org/docs/master/system/i386/hyperv.html).

KVM's reenlightenment support is not unlimited: its source explicitly expects
userspace to preserve guest TSC frequency/value across migration and prevent
unsupported migration when necessary. Do not describe it as arbitrary live
TSC-frequency correction.

## 5. A relevant real-overhead difference: virtual CPUID tables

`kvm_emulate_cpuid` calls `kvm_cpuid`, looks up a configured per-vCPU entry,
writes four output registers, and retires the instruction. It does not issue
native host CPUID for every ordinary guest request. Dynamic outputs are updated
from virtual state, including OSXSAVE, APIC enablement, OSPKE and XSAVE sizes;
some features have additional special handling.

Sources: [cpuid.c:291–326](https://github.com/torvalds/linux/blob/6628e7d4c6b25c8d18f1345e3a20d21829aae7e4/arch/x86/kvm/cpuid.c#L291-L326),
[cpuid.c:2110–2184](https://github.com/torvalds/linux/blob/6628e7d4c6b25c8d18f1345e3a20d21829aae7e4/arch/x86/kvm/cpuid.c#L2110-L2184).

This is not proof that a stale hardware snapshot is correct for this project.
KVM owns a virtual CPU model and relevant virtual state. A transparent
passthrough design still has to address native MSR changes, firmware/SMM,
topology and dynamic enumeration. The previously rejected cache with per-hit
RDMSR is not equivalent to KVM's model. A coherent virtual model is a distinct
candidate, but changing that guest contract requires explicit design and tests.

## Implications for this project

- Keep elapsed time and timer delivery as separate correctness problems.
- Do not restore per-exit TSC subtraction on the claim that KVM uses it; the
  inspected ordinary paths do not support that claim.
- A shared clock anchor/publication protocol matters if adding a PV clock.
  Windows requires an interface it actually consumes; KVM pvclock registration
  cannot simply be assumed for an unmodified Windows guest.
- Do not add early scheduling to a native physical LAPIC timer merely because
  KVM does it for emulated delivery. First establish a virtualization-induced
  deadline-service delay and who owns timer programming.
- For CPUID real-cost reduction, investigate a deliberate virtual CPU model,
  not another unchecked hardware cache. No performance result follows from this
  source inspection alone.
- KVM's own timekeeping documentation explicitly acknowledges timing leaks and
  says fully isolated virtual time may cease to track real time. Correct guest
  clocks do not establish native-equivalent execution latency or detector silence.

Source for the final limit:
[timekeeping.rst:635–645](https://github.com/torvalds/linux/blob/6628e7d4c6b25c8d18f1345e3a20d21829aae7e4/Documentation/virt/kvm/x86/timekeeping.rst#L635-L645).
The timekeeping overview is historical (2010); use the pinned implementation,
not its old hardware-availability statements, for current capability behavior.
