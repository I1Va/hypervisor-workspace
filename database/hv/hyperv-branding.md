---
topic: hyperv-branding
kind: reference
updated: 2026-11-06
see: [cpuid-exiting-floor, detection-vectors, debug-exception-delivery]
---

# Hyper-V root-partition branding

How the last two hypervisor detections were cleared, why branding is legitimate
here rather than a trick, and the three traps that cost boots.

## Why it was needed

`TRAP` (100) and `TIMER` (45) could not be cleared from the exit path:

- `TIMER` compares CPUID latency against LFENCE latency and flags a hypervisor
  above 2.75. Measured 6.00. CPUID exiting is CPU-mandatory
  (`IA32_VMX_PROCBASED_CTLS` reports bit 1 in its must-be-1 mask), so the exit
  cannot be avoided and no handler optimisation reaches the threshold.
- `TRAP` needs `DR6.BS` and `DR6.B0` in one `#DB`. The CPUID exit delivers the
  trap at VM entry, before the instruction DR0 points at has run, so the
  processor sets BS and not B0. Publishing B0 was tried and did not change what
  the guest reads; intercepting `#DB` made DR6 worse.

Both techniques — and `INTERRUPT_SHADOW`, `SINGLE_STEP`, `SVM_EXCEPTIONS`,
`HYPERVISOR_STR`, `HYPERVISOR_BIT` — begin with

```cpp
if (util::hyper_x() == HYPERV_HOST) return false;
```

So the remaining lever is to present the machine as a Hyper-V **root partition**
(a host), which is what it physically is: Windows running directly on the metal
with a Type-1 VMM underneath, not a guest of a partition-based hypervisor.

## The gates, each measured

`hyper_x()` returns `HYPERV_HOST` only if every one of these passes. Measured on
the DTB, not assumed:

| Gate | What VMAware reads | Value here | Source |
|---|---|---|---|
| hypervisor present | `cpuid.1` ECX bit 31 | set | required; see trap 2 |
| root partition | `0x40000003` **EBX bit 0** | 1 | see trap 1 |
| vendor string | `0x40000000` EBX/ECX/EDX | `"Microsoft Hv"` | required by `HYPERVISOR_STR` |
| TPM log | `tbs.dll` TCG log | `0x8028400F` | `is_log_present()` returns TRUE on error |
| Win11 HAL | skipped | Windows 10 19045 | gate only applies on Win11 |

`0x8028400F` is `TBS_E_TPM_NOT_FOUND` — there is no TPM on this machine, and
`is_log_present()` returns **TRUE** on every error path, including "no TPM". That
is why the TPM gate is not an obstacle here, contrary to the earlier assumption
that a plausible event log would have to be forged.

## The three traps

### 1. The root-partition flag is in 0x40000003, not 0x40000001

This is the leaf most easily got wrong, and getting it wrong looks like "branding
does not work" when it is really "branding half-applied". Measured on boot 20:

| Technique | Before | With flag in the wrong leaf |
|---|---|---|
| `HYPERVISOR_BIT` | clean | **fires:100** |
| `HYPERVISOR_STR` | clean | **fires:100** |
| `VMID` | clean | **fires:99** |
| `TRAP` / `TIMER` | 100 / 45 | still 100 / 45 |

`hyper_x()` never entered the root-partition branch, the state stayed
`HYPERV_UNKNOWN`, and every technique took its spoofing path. Three new
detections, and the two being chased unchanged.

### 2. The hypervisor bit must be set too

`hypervisor_bit()` returns false when the bit is set *and* the state is
`HYPERV_HOST`, but returns **true** — a detection — when the bit is clear and the
state is `HYPERV_HOST`, treating that combination as a hypervisor patching the bit
out. Setting the leaves without the bit therefore converts a clean technique into
a 100-point one.

### 3. Do NOT report the "Hv#1" signature

`0x40000001` EAX normally carries `0x31237648` (`"Hv#1"`). Reporting it makes
Windows enable Hyper-V enlightenments — synthetic timers, MSR-based operations, a
hypercall page — none of which this VMM implements, and the machine stalls in the
loader. Reproducible: boots 22 and 27, four cores up, INIT signals, then no
further output.

VMAware reads that EAX only for `is_hyperv_nested()`, where anything other than
`Hv#1` correctly means "not a nested partition". So it is reported as zero.

This trap is what made the first working version depend on guest-side setup.
Enabling branding *after* the loader (a logon task, then an `HKLM\...\Run` entry)
cleared the detections and avoided the stall, but neither survived a netboot on
this guest, so the fix was not durable. Withholding the signature removes the
reason to enable it late at all.

## Result

Measured on a cold boot (boot 40) with the logon task and Run key both deleted, so
nothing guest-side contributes:

```
cpuid.1 ecx bit31 = 1
cpuid.40000000 eax(maxleaf)=0x40000006 vendor="Microsoft Hv"
cpuid.40000001 eax=0x00000000        (Hv#1 deliberately withheld)
```

All 79 techniques of v2.8.2-56-gc8092c6 run in one boot. Every one is clean
except `GPU_CAPABILITIES` (20), which is this machine's Intel HD Graphics 4600
driver having no `CM_GAMMA_RAMP` — confirmed behaviourally, `SetDeviceGammaRamp`
fails with `ERROR_INVALID_PARAMETER` — and has nothing to do with the hypervisor.

Boot time is unaffected at ~50 s, and the guest still runs four logical
processors.

## What this does not fix, and the risk accepted

`GPU_CAPABILITIES` needs a guest-side display driver, not a hypervisor change.

The risk is that branding is all-or-nothing: if any gate fails on another
configuration, VMAware takes its `SPOOFED` branch and records
`brand_enum::NULL_BRAND` at **150 points**, which is worse than the 145 this
clears. That is why the decision lives in one file with one switch
(`g_HvBrandWanted`, `HYPERCALL_SET_BRAND`) and every advertised value is
documented next to the technique that requires it.

## Files

- `PulverizedPkg/Sources/Vmx/HvBrand.c` — the policy: every leaf, every bit, and
  the reason each one exists.
- `PulverizedPkg/Sources/Vmx/HvBrand.h` — the reasoning, including the full gate
  list and the 150-point risk.
- `PulverizedPkg/Sources/Hypercall/Hypercall.h` — `HYPERCALL_SET_BRAND`.
- `tools/` — `hvx.cpp` reports every gate `hyper_x()` evaluates; `hvbrand.cs`
  flips the switch at runtime.
