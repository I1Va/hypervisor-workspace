---
topic: article-checks
kind: reference
updated: 2026-11-07
see: [detection-vectors, debug-exception-delivery, cpuid-exiting-floor, hyperv-branding]
---

# The detection-article checks, and what this hypervisor does about each

Source: `hv/detection-article.md` (secret.club, "VMM detection"). This file maps
every check in that article to the code that answers it, so the article does not
have to be re-read and re-analysed each time. It records what was *changed* and
what is *knowingly still open*; it is not a claim that all of it passes.

Status was written before the stand could be re-measured (see the note at the
end). "Answered" below means "the code now does the architecturally correct
thing", not "VMAware was observed to score 0".

## The severe finding: probes that killed the machine

Every instruction in the article that exits unconditionally (Intel SDM Vol 3C
28.1.2: CPUID, GETSEC, INVD, XSETBV, and the whole VMX family) reached the exit
dispatcher. Only CPUID, VMCALL and XSETBV had handlers. **Every other one fell
through to `default:` and called `PANIC()`.**

That is worse than being detected. EasyAntiCheat performs a single `VMREAD` at
CPL 0 on driver load (the article documents this); an `INVD` side-channel probe
or a `VMXON` does the same thing. Any of them stopped the machine dead, with no
log and no recovery, and the probe did not even have to interpret a result.

| Instruction | Was | Now | Why that is the right answer |
|---|---|---|---|
| `VMREAD`, `VMWRITE`, `VMCLEAR`, `VMPTRLD`, `VMPTRST`, `VMLAUNCH`, `VMRESUME`, `VMXON`, `VMXOFF`, `INVEPT`, `INVVPID`, `GETSEC` | `PANIC()` | `#UD` injected | Real hardware without VMX enabled raises `#UD`. CPUID.1:ECX.VMX is cleared here, so `#UD` is the only answer consistent with what the guest was told. `#GP` instead of `#UD` is itself a signal - the article names that as indicative of presence. |
| `INVD` | `PANIC()` | `WBINVD` executed | See the residual below. |
| `XSETBV` | executed the guest's value in root mode | validated first, then `#GP(0)` injected on a bad value | A value the processor rejects faults in *root* mode, which is a `PANIC`. A ten-instruction user-mode probe could kill the machine. |

`#UD` is a fault, so RIP is **not** advanced for those cases - the guest's own
handler decides, which is what VMAware's probes check. VMCALL is the exception
and keeps its existing handler, which advances RIP first to avoid the livelock
that a fault-at-the-same-RIP produces.

## Check-by-check

| Article check | Answer | State |
|---|---|---|
| Garbage write to unimplemented MSR | `MsrIsCoveredByBitmaps`: an MSR outside `0000-1FFF` / `C0000000-C0001FFF` gets `#GP` injected, with an error code, RIP not advanced | Fixed. Previously the access was executed in root mode, which faults in root mode and panics. |
| Synthetic MSR probe (`rdmsr 0x40000000`) | same range test: `0x40000000` is outside both ranges, so `#GP` | Fixed by the same change. |
| `#DB` with `TF` (single-step boundary) | `RecordPendingSingleStep` + `debug-exception-delivery.md` | Known open. The DR6 the guest observes is `0x0` for TF-driven `#DB`; measured and documented, not guessed. |
| `XSETBV` fault in the host | `IsValidXcr0` + `#GP(0)` injection | Fixed. |
| LBR / `IA32_DEBUGCTL` | not intercepted; the VMCS save/load debug controls are not used | Not implemented. `wrmsr 0x1D9` passes through to hardware, which is what bare metal does, so the "does LBR read back" probe behaves natively. The *LBR-stack-across-VM-exit* variant is still a live vector: LBR is not saved/restored around exits. |
| LBR stack across VM exit | not handled | Open. Would need the VM-exit MSR-store/load areas. |
| CRn access exiting (VMware bug) | `HandleCrAccess` writes the read shadow exactly as the guest asked | Answered. |
| CR4 mask & VMX availability | read shadow now clears `CR4.VMXE` | Fixed. The shadow used to be the host's CR4, which has VMXE set while in VMX operation, so the guest could read VMXE = 1 while CPUID said VMX was absent. |
| CPUID leaf comparison (`0x40000000` vs an invalid leaf) | CPUID is passed through except leaf 1 | Answered structurally: no hypervisor leaves exist unless branded, and an invalid leaf returns the hardware's zeroed response. |
| `INVD`/`WBINVD` side channel | `WBINVD` executed | **Residual, see below.** |
| `RDTSC`/`CPUID`/`RDTSC` timing | TSC offsetting (other agent) | Out of scope for this work; owned by the TSC agent. |
| IET divergence (`IA32_APERF`) | not intercepted | Open, and unfixable by interception alone: the article's point is that APERF is hard to spoof. Not currently exercised by VMAware. |
| WoW64 descriptor table (SGDT/SIDT length) | descriptor-table exiting is **off** | Not applicable while the control is 0: the guest's SGDT/SIDT execute natively, so the 6-byte vs 10-byte length is the hardware's own. It becomes a bug the moment that control is turned on, so do not enable it without adding the long-mode length check. |
| EAC `VMREAD` | `#UD` | Fixed. |
| EAC `IA32_EFER` read (SCE bit) | not intercepted | Answered: the read passes through to hardware, which reports the real value. |

## Residuals, stated plainly

1. **`INVD` reads as a hypervisor.** The check writes a dirty line, `WBINVD`s,
   dirties it again and `INVD`s; bare metal discards the dirty line (AL = 1), a
   WBINVD-or-no-op emulation keeps it (AL = 0). A real `INVD` in root mode also
   discards *our* dirty lines - the EPT, the hook list, the VMCS region - which
   is not recoverable. Selective writeback is not expressible, so the choice is
   between a dead machine and one wrong byte. The wrong byte is accepted.

2. **`IA32_APERF` divergence** is not addressed. It is the article's strongest
   standard vector and needs no interception to run.

3. **LBR stack coherence across exits** is not addressed.

## Why nothing here is measured yet

The stand stopped netbooting during this work: every boot reaches Windows from
disk with `reached_loader = false`, `boot_id` stays 0, and the guest reports
`VM Monitor Mode Extensions: Yes` (the bit this hypervisor clears), which proves
the hypervisor is not loaded. No DHCP, TFTP or proxyDHCP listener is running on
the host, so the firmware has nothing to PXE from. Serial capture is also
unusable - 148 bytes of line noise rather than firmware text.

Until that is restored, the changes above are reviewable and build clean but are
**not** evidence that any VMAware technique changed score.
