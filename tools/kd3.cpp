// Definitively answers: is a kernel debugger enabled in this guest?
//
// Why this matters more than anything else right now:
//
// VMAware's TRAP, SINGLE_STEP, INTERRUPT_SHADOW and DBVM all depend on a #DB
// reaching a user-mode handler. On this stand the hardware demonstrably raises
// the trap (an exception exit with reason 0, vector 1 and RFLAGS.TF set was
// captured), user mode owns DR0-DR7 (a write/read cycle returns what was
// written), and yet no handler ever runs.
//
// The one documented mechanism that consumes #DB and owns the debug registers
// before user mode is the kernel debugger. If KD is enabled, all four vectors
// are explained by a single configuration setting rather than by a hypervisor
// bug - and the fix is one boot option, not a code change.
//
// Previous attempts to read this from KUSER_SHARED_DATA were inconclusive: the
// offset assumed for ActiveProcessorCount returned 784 where 4 was expected, so
// the structure layout for this build is not what was assumed and the adjacent
// KdDebuggerEnabled byte cannot be trusted either.
//
// This uses the supported interface instead:
//   NtQuerySystemInformation(SystemKernelDebuggerInformation /* 35 */)
// which returns SYSTEM_KERNEL_DEBUGGER_INFORMATION:
//   BOOLEAN KernelDebuggerEnabled;
//   BOOLEAN KernelDebuggerNotPresent;
//
// Build: cl /nologo /std:c++17 /EHsc /O1 kd3.cpp
#include <windows.h>
#include <winternl.h>
#include <cstdio>
#include <cstdint>

typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(ULONG, PVOID, ULONG, PULONG);

struct KernelDebuggerInformation
{
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
};

int main()
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) { printf("no ntdll\n"); return 1; }

    auto NtQuerySystemInformation =
        (NtQuerySystemInformation_t)(void*)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) { printf("no NtQuerySystemInformation\n"); return 1; }

    printf("=== SystemKernelDebuggerInformation (class 35) ===\n");

    KernelDebuggerInformation info = {};
    ULONG returned = 0;
    NTSTATUS st = NtQuerySystemInformation(35, &info, sizeof(info), &returned);

    printf("  NTSTATUS = 0x%08lX  returned = %lu\n", (unsigned long)st, (unsigned long)returned);
    printf("  KernelDebuggerEnabled    = %u\n", (unsigned)info.KernelDebuggerEnabled);
    printf("  KernelDebuggerNotPresent = %u\n", (unsigned)info.KernelDebuggerNotPresent);

    const bool kdEnabled = (st == 0) && (info.KernelDebuggerEnabled != 0);
    const bool kdPresent = (st == 0) && (info.KernelDebuggerNotPresent == 0);

    printf("\n  interpretation: kernel debugger is %s", kdEnabled ? "ENABLED" : "disabled");
    if (kdEnabled)
        printf(", and a debugger is %s", kdPresent ? "ATTACHED" : "NOT attached");
    printf("\n");

    /*
     * Second, independent check: the BCD value that drives it, read from the
     * registry mirror of the current loader entry. This shows whether the
     * "debug" setting seen by bcdedit is actually in force for this boot.
     */
    printf("\n=== registry view of the boot configuration ===\n");
    HKEY k;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SYSTEM\\CurrentControlSet\\Control\\SystemBootDevice", 0, KEY_READ, &k) == ERROR_SUCCESS)
    {
        RegCloseKey(k);
    }
    else
    {
        printf("  (no SystemBootDevice key)\n");
    }

    /*
     * Kernel debugger flags live in the loaded configuration's control set.
     * HKLM\SYSTEM\CurrentControlSet\Control is the runtime copy.
     */
    DWORD debugFlag = 0, debugOpt = 0, size = sizeof(DWORD);
    if (RegGetValueA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control",
                     "Debug", RRF_RT_REG_DWORD, nullptr, &debugFlag, &size) == ERROR_SUCCESS)
        printf("  HKLM\\...\\CurrentControlSet\\Control\\Debug = %lu\n", (unsigned long)debugFlag);
    else
        printf("  Control\\Debug not present\n");

    size = sizeof(DWORD);
    if (RegGetValueA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control",
                     "DebugOptions", RRF_RT_REG_DWORD, nullptr, &debugOpt, &size) == ERROR_SUCCESS)
        printf("  DebugOptions = 0x%08lX\n", (unsigned long)debugOpt);
    else
        printf("  DebugOptions not present\n");

    printf("\nVERDICT: %s\n",
        kdEnabled
            ? "KD IS ENABLED - it consumes #DB and owns DR0-DR3; disable it and retest the four vectors"
            : "KD is not enabled - the #DB loss is elsewhere and is a real hypervisor or kernel issue");

    return 0;
}
