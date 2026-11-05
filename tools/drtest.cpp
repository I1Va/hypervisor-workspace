// Behavioural test: does this guest let user mode own DR0-DR3 and receive #DB?
//
// Why: KUSER_SHARED_DATA says KdDebuggerEnabled = 1 on this guest, which means a
// kernel debugger is initialised. An initialised KD is documented to own the
// debug registers and to consume #DB, which would explain, in one stroke, why
// VMAware's TRAP, SINGLE_STEP, INTERRUPT_SHADOW and DBVM all report a detection:
// their stubs all depend on a #DB reaching a user-mode handler.
//
// This test does not trust any struct offset. It measures behaviour:
//
//   dr_writeback  Write DR0/DR7, read them back. If the values we wrote survive,
//                 user mode owns the registers; if they are rewritten or zeroed,
//                 the kernel owns them.
//   tf_once       Set TF directly via NtSetContextThread (bypassing popfq, so the
//                 result cannot be blamed on instruction emulation), then
//                 execute one instruction. A #DB must arrive.
//
// Both are read-only observations of guest behaviour; neither changes the system.
//
// Build: cl /nologo /std:c++17 /EHsc /O1 drtest.cpp
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>

static volatile LONG     g_hits = 0;
static volatile uint64_t g_dr6  = 0;

static LONG CALLBACK Filter(EXCEPTION_POINTERS* ep)
{
    if (!ep || !ep->ExceptionRecord || !ep->ContextRecord)
        return EXCEPTION_CONTINUE_SEARCH;

    InterlockedIncrement(&g_hits);
    if (g_dr6 == 0) g_dr6 = ep->ContextRecord->Dr6;

    ep->ContextRecord->EFlags &= ~(DWORD)0x100;
    ep->ContextRecord->Dr7 = 0;
    ep->ContextRecord->Dr0 = 0;
    ep->ContextRecord->Dr6 = 0;
    return EXCEPTION_CONTINUE_EXECUTION;
}

int main()
{
    const HANDLE self = GetCurrentThread();

    printf("=== debug register ownership ===\n");

    CONTEXT c = {};
    c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(self, &c)) { printf("GetThreadContext failed %lu\n", GetLastError()); return 1; }

    /* A distinctive value that cannot be confused with a reset value. */
    const uint64_t wantDr0 = 0x00007FF6DEADB000ULL;
    const uint64_t wantDr7 = 0x0000000000000001ULL;

    c.Dr0 = wantDr0;
    c.Dr7 = wantDr7;
    c.Dr6 = 0;
    if (!SetThreadContext(self, &c)) { printf("SetThreadContext failed %lu\n", GetLastError()); return 1; }

    CONTEXT back = {};
    back.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(self, &back);

    printf("  wrote DR0=%016llX DR7=%016llX\n",
           (unsigned long long)wantDr0, (unsigned long long)wantDr7);
    printf("  read  DR0=%016llX DR7=%016llX\n",
           (unsigned long long)back.Dr0, (unsigned long long)back.Dr7);

    const bool dr0_kept = (back.Dr0 == wantDr0);
    const bool dr7_kept = ((back.Dr7 & 1) == 1);
    printf("  -> DR0 survived=%d  DR7.LocalEnable0 survived=%d\n", (int)dr0_kept, (int)dr7_kept);

    /* Clean up before the next test. */
    back.Dr0 = 0; back.Dr7 = 0; back.Dr6 = 0;
    SetThreadContext(self, &back);

    printf("\n=== TF via NtSetContextThread ===\n");

    /* Executable one-instruction stub: nop; nop; ret */
    unsigned char* mem = (unsigned char*)VirtualAlloc(nullptr, 0x1000,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) { printf("alloc failed\n"); return 1; }
    mem[0] = 0x90; mem[1] = 0x90; mem[2] = 0xC3;

    CONTEXT tc = {};
    tc.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(self, &tc)) { printf("GetThreadContext(ctrl) failed\n"); return 1; }

    const DWORD64 savedRip = tc.Rip;
    const DWORD   savedEflags = tc.EFlags;

    tc.Rip = (DWORD64)mem;
    tc.EFlags |= 0x100;             /* TF */
    tc.Dr7 = 0; tc.Dr0 = 0; tc.Dr6 = 0;
    if (!SetThreadContext(self, &tc)) { printf("SetThreadContext(TF) failed %lu\n", GetLastError()); return 1; }

    g_hits = 0; g_dr6 = 0;

    __try {
        /* Run the stub. If TF is honoured a #DB fires after the first nop. */
        ((void(*)(void))mem)();
    }
    __except (Filter(GetExceptionInformation())) { }

    printf("  hits=%ld dr6=%016llX -> %s\n",
           (long)g_hits, (unsigned long long)g_dr6,
           g_hits ? "#DB DELIVERED - user mode receives debug exceptions"
                  : "#DB NOT DELIVERED - debug exception consumed before user mode");

    /* Restore. */
    CONTEXT rc = {};
    rc.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(self, &rc)) {
        rc.Rip = savedRip;
        rc.EFlags = savedEflags;
        rc.Dr0 = 0; rc.Dr7 = 0; rc.Dr6 = 0;
        SetThreadContext(self, &rc);
    }

    printf("\nVERDICT: %s\n",
        (dr0_kept && dr7_kept && g_hits)
            ? "debug registers and #DB are available to user mode - KD is not consuming them"
            : "debug state is NOT fully available to user mode - consistent with an active kernel debugger");

    return 0;
}
