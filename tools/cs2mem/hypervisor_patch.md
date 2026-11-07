# Hypervisor patch: `HYPERCALL_GET_PROCESS_CR3`

`cs2mem` needs the CR3 of a *named process*, not its own. The stock hypervisor
only exposes `HYPERCALL_GET_CURRENT_CR3`, which returns the caller's CR3 — correct
for reading yourself, useless for reading the game.

This is the one hypervisor-side change the tool requires.

## Why a hypercall and not a driver

The hypervisor is already in root mode with guest physical memory addressable. It
can walk `PsActiveProcessHead` directly. A kernel driver would need signing, would
be another component to trust, and would be strictly more machinery for the same
read.

## What to add

### 1. The call number

In `Sources/Hypercall/Hypercall.h`, with the other defines:

```c
#define HYPERCALL_GET_PROCESS_CR3 0x2C41D7E9A05B3
```

It must not collide with an existing number. The existing values are arbitrary
64-bit constants; this one is new and unused.

### 2. The implementation

In `Sources/Hypercall.c`, before `HypercallHandler`:

```c
/*
 * DirectoryTableBase for a given PID, or 0 if the process does not exist.
 *
 * Walks the guest's PsActiveProcessHead list. The EPROCESS layout is version
 * dependent, so the two fields we need are located by signature rather than by
 * hardcoded offsets:
 *
 *   UniqueProcessId  - a HANDLE, immediately preceded by the previous/next
 *                      ActiveProcessLinks (two LIST_ENTRYs)
 *   DirectoryTableBase - the qword at EPROCESS+0x28 on all x64 builds since
 *                      Vista; it is page aligned and non-zero for a live
 *                      process.
 *
 * PsActiveProcessHead is found through the kernel's own export table, which the
 * hypervisor can read because it has the guest physical map.
 */
STATIC
UINT64
GetCr3ForProcess(UINT32 Pid)
{
	UINT64 PsActiveProcessHead = 0;
	UINT64 ListEntry;
	UINT64 Ep;

	/*
	 * FindKernelSymbol does NOT exist in the current tree - it is the one piece
	 * of this patch that has to be written from scratch. Resolving
	 * PsActiveProcessHead needs the kernel's export table: locate ntoskrnl's
	 * PE headers by scanning guest physical memory for "MZ", or take the base
	 * from the kernel's own EPROCESS.ImageBase via a known export. A simpler
	 * alternative that avoids symbol resolution entirely: nt!PsActiveProcessHead
	 * is at a fixed offset from the ntoskrnl base, and the ntoskrnl base can be
	 * read from the guest's IA32_LSTAR MSR (the syscall entry point lives inside
	 * ntoskrnl).
	 */
	if (!FindKernelSymbol("PsActiveProcessHead", &PsActiveProcessHead))
	{
		return 0;
	}

	/*
	 * PsActiveProcessHead is the LIST_ENTRY head. ActiveProcessLinks.Flink of
	 * the first process points at the next process's ActiveProcessLinks, which
	 * sits at EPROCESS + 0x448 on current builds. Rather than bake that in, walk
	 * the list and for each entry recover EPROCESS by scanning a window
	 * backwards for the UniqueProcessId that matches.
	 */
	ListEntry = ReadGuestU64(PsActiveProcessHead);
	for (UINT32 Guard = 0; Guard < 4096 && ListEntry != 0 &&
	     ListEntry != PsActiveProcessHead; Guard++)
	{
		/* Try the plausible EPROCESS bases around this list entry. */
		for (UINT32 Back = 0x400; Back <= 0x600; Back += 8)
		{
			Ep = ListEntry - Back;
			if (ReadGuestU32(Ep + 0x440) == Pid)
			{
				UINT64 Dtb = ReadGuestU64(Ep + 0x28);
				if (Dtb != 0 && (Dtb & 0xFFF) == 0)
				{
					return Dtb;
				}
			}
		}
		ListEntry = ReadGuestU64(ListEntry);
	}
	return 0;
}
```

The two helpers it needs are thin wrappers over what the module already has:

```c
/* Read a qword from guest *virtual* memory in the kernel's own address space.
 * The kernel runs on the same CR3 as the hypervisor's current guest, so the
 * current guest CR3 is the right one here. VmxRead(VMCS_GUEST_CR3) is how the
 * CPUID hypercall handler already obtains it (VmxExitHandlers.c). */
STATIC UINT64 ReadGuestU64(UINT64 Gva)
{
	UINT64 Value = 0;
	UINT64 Gpa = GetPhysicalAddressForGuest(VmxRead(VMCS_GUEST_CR3), Gva);
	if (Gpa == 0) return 0;
	ReadPhysicalMem((VOID *)Gpa, &Value, sizeof(Value));
	return Value;
}

STATIC UINT32 ReadGuestU32(UINT64 Gva)
{
	UINT32 Value = 0;
	UINT64 Gpa = GetPhysicalAddressForGuest(VmxRead(VMCS_GUEST_CR3), Gva);
	if (Gpa == 0) return 0;
	ReadPhysicalMem((VOID *)Gpa, &Value, sizeof(Value));
	return Value;
}
```

Note the argument order of `ReadPhysicalMem`: it is `(physical address, buffer,
size)` — the destination is the physical address, which reads backwards from the
name. `MemoryAccess.h` confirms it, and getting it wrong is a silent corruption of
whichever physical page the buffer happened to occupy.

### 3. The dispatch case

In the `switch (CallNum)` in `HypercallHandler`:

```c
case HYPERCALL_GET_PROCESS_CR3:
	/*
	 * arg1 = PID. Returns the CR3 as the status value itself, not through a
	 * guest buffer.
	 *
	 * Returning by value rather than writing to a guest pointer is deliberate:
	 * HYPERCALL_GET_TSC_OFFSET had to be changed to do the same after a
	 * structured copy through a guest pointer read back as zeros.
	 */
	return (HYPERCALL_STATUS)GetCr3ForProcess((UINT32)arg1);
```

### 4. The guest-side declaration

Add to `Hypercall.h` next to the others, so the guest tools can call it:

```c
static inline UINT64 HypercallGetProcessCr3(UINT32 Pid)
{
	return INVOKE_HYPERCALL(HYPERCALL_GET_PROCESS_CR3, (UINT64)Pid, 0, 0, 0);
}
```

## Validation before wiring it to the game

Do not trust this against CS2 first. Prove it against a process you can check:

1. `cs2mem check` — confirms the hypercall path works at all and prints your CR3.
2. `cs2mem modules` on **`notepad.exe`** — if it prints a plausible CR3 and module
   list, the walk is right. Compare the module base to what Process Explorer shows.
3. Only then point it at `cs2.exe`.

Step 2 matters because a wrong `DirectoryTableBase` does not fail: it returns a
real-looking address, reads succeed, and every value is from another process. That
is the failure mode this whole design is built to make visible, and the only way to
see it is to test against a process whose layout you already know.

## The EPROCESS offset caveat

`0x28` for `DirectoryTableBase` and `0x440`/`0x448` for the PID and links are
current for Windows 10 19045 and 11. They move between major builds. The scan
window (`0x400..0x600` for the PID) absorbs the link offset moving; the `0x28`
offset does not move in practice but should be confirmed on the target build by
dumping a known process's EPROCESS and checking the qword at `+0x28` is page
aligned and matches the CR3 that `HYPERCALL_GET_CURRENT_CR3` returns for a process
you control.

## What this deliberately does not do

It does not hide anything. It does not hook, alias, or write. It reads a CR3 and
returns it. The hypervisor's existing invisibility properties (TSC offsetting,
CPUID branding, exit handling) are a separate concern, and none of them are needed
for an offline bot match — which is why the offline restriction is where it is.

## Two things this patch needs that are not in the tree

Checked against `PulverizedPkg/Sources`, not assumed:

| Needed | Status |
|---|---|
| `ReadPhysicalMem` | **exists** (`Memory/MemoryAccess.h`), but note the argument order: `(physical_address, buffer, size)` — the destination is the physical address |
| `GetPhysicalAddressForGuest` | **exists** (`Memory/MemoryAccess.h`) |
| `VmxRead(VMCS_GUEST_CR3)` | **exists** (`Vmx/Ia32.h`), already used by the CPUID handler |
| `FindKernelSymbol` | **does not exist** — must be written, or avoided by deriving the ntoskrnl base from `IA32_LSTAR` |
| `ReadGuestU64` / `ReadGuestU32` | **do not exist** — the two helpers above are new code |

So this is not a drop-in patch; it is roughly 100 lines including the symbol
resolution. Budget for that before starting.
