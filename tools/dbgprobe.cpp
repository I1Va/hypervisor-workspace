// Decides whether debug exceptions (#DB) reach user mode in this guest.
//
// Written in C++ with structured exception handling because that is exactly
// what VMAware uses. Earlier attempts used C# vectored handlers and proved
// unreliable: a collected delegate makes the handler silently never run, which
// is indistinguishable from "the exception was swallowed".
//
// Each case runs one tiny stub and reports:
//   - whether an exception was caught at all,
//   - its code,
//   - the instruction pointer where it was caught,
//   - the DR6 value the handler observed.
//
// DR6 is the discriminator. Windows' debug handler reads DR6 and discards a
// #DB whose status bits are clear, treating it as spurious. So "no exception"
// and "#DB with empty DR6" produce the same user-visible result but mean very
// different things.
//
// Cases:
//   icebp  - ICEBP (0xF1): #DB in trap class, must set DR6.BS, RIP advances 1
//   tfnop  - TF then two NOPs: pure single-step, no VM exit involved
//   tfcpuid- TF then CPUID: single-step across a VM exit (CPUID always exits)
//   dr0    - DR0 execute breakpoint with DR7 enable: must set DR6.B0
//   ud2    - control: #UD must be caught, proving SEH itself works
//
// Build (on the guest, x64 Native Tools prompt):
//   cl /nologo /std:c++17 /EHsc /O1 dbgprobe.cpp
#include <windows.h>
#include <cstdio>
#include <cstdint>

static volatile LONG g_hits = 0;
static volatile DWORD g_code = 0;
static volatile uintptr_t g_ip = 0;
static volatile uint64_t g_dr6 = 0;

// Set by each case before running its stub: where the handler should resume.
static volatile uint64_t g_resume = 0;

static LONG CALLBACK Filter(EXCEPTION_POINTERS* ep)
{
    if (!ep || !ep->ExceptionRecord || !ep->ContextRecord)
    {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    const DWORD code = ep->ExceptionRecord->ExceptionCode;

    // Only the faults these stubs are expected to raise.
    if (code != EXCEPTION_SINGLE_STEP && code != EXCEPTION_ILLEGAL_INSTRUCTION &&
        code != EXCEPTION_BREAKPOINT)
    {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    InterlockedIncrement(&g_hits);
    if (g_code == 0)
    {
        g_code = code;
        g_ip = (uintptr_t)ep->ExceptionRecord->ExceptionAddress;
        g_dr6 = ep->ContextRecord->Dr6;
    }

    // Resume after the faulting instruction so the stub cannot loop forever.
    // RIP is advanced by the caller-supplied amount via the stub's own layout:
    // every stub below ends in a RET that is safe to resume at.
    ep->ContextRecord->EFlags &= ~0x100u;   // clear TF
    ep->ContextRecord->Dr7 = 0;
    ep->ContextRecord->Dr6 = 0;
    ep->ContextRecord->Dr0 = 0;
    ep->ContextRecord->Rip = (DWORD64)g_resume;

    return EXCEPTION_CONTINUE_EXECUTION;
}

static const char* Name(DWORD code)
{
    switch (code)
    {
        case 0: return "none";
        case EXCEPTION_SINGLE_STEP: return "#DB";
        case EXCEPTION_ILLEGAL_INSTRUCTION: return "#UD";
        case EXCEPTION_BREAKPOINT: return "#BP";
        case EXCEPTION_ACCESS_VIOLATION: return "#PF";
        case EXCEPTION_PRIV_INSTRUCTION: return "#GP";
        default: return "other";
    }
}

static void* AllocExec(const unsigned char* code, size_t len, uint64_t* base)
{
    void* mem = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE,
                             PAGE_EXECUTE_READWRITE);
    if (!mem) return nullptr;
    memcpy(mem, code, len);
    *base = (uint64_t)mem;
    return mem;
}

static void RunCase(const char* which)
{
    g_hits = 0; g_code = 0; g_ip = 0; g_dr6 = 0;

    unsigned char code[64];
    size_t len = 0;
    uint64_t resumeOffset = 0;

    if (strcmp(which, "icebp") == 0)
    {
        // icebp; ret
        const unsigned char c[] = { 0xF1, 0xC3 };
        memcpy(code, c, sizeof(c)); len = sizeof(c);
        resumeOffset = 1;            // after the icebp byte
    }
    else if (strcmp(which, "tfnop") == 0)
    {
        // pushfq; pop rax; or eax,0x100; push rax; popfq; nop; nop; ret
        const unsigned char c[] = {
            0x9C, 0x58,
            0x0D, 0x00, 0x01, 0x00, 0x00,
            0x50, 0x9D,
            0x90, 0x90,
            0xC3
        };
        memcpy(code, c, sizeof(c)); len = sizeof(c);
        resumeOffset = 11;           // the ret
    }
    else if (strcmp(which, "tfcpuid") == 0)
    {
        // pushfq; pop rax; or eax,0x100; push rax; popfq; cpuid; nop; ret
        const unsigned char c[] = {
            0x9C, 0x58,
            0x0D, 0x00, 0x01, 0x00, 0x00,
            0x50, 0x9D,
            0x0F, 0xA2,
            0x90,
            0xC3
        };
        memcpy(code, c, sizeof(c)); len = sizeof(c);
        resumeOffset = 12;           // the ret
    }
    else if (strcmp(which, "dr0") == 0)
    {
        // nop; nop; nop; nop; ret   - breakpoint armed on the third nop
        const unsigned char c[] = { 0x90, 0x90, 0x90, 0x90, 0xC3 };
        memcpy(code, c, sizeof(c)); len = sizeof(c);
        resumeOffset = 4;            // the ret
    }
    else if (strcmp(which, "ud2") == 0)
    {
        // ud2; ret
        const unsigned char c[] = { 0x0F, 0x0B, 0xC3 };
        memcpy(code, c, sizeof(c)); len = sizeof(c);
        resumeOffset = 2;
    }
    else
    {
        printf("unknown case %s\n", which);
        return;
    }

    uint64_t base = 0;
    void* mem = AllocExec(code, len, &base);
    if (!mem) { printf("alloc failed\n"); return; }

    g_resume = base + resumeOffset;

    if (strcmp(which, "dr0") == 0)
    {
        // Arm an execute breakpoint on the third nop.
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(GetCurrentThread(), &ctx))
        {
            ctx.Dr0 = base + 2;
            ctx.Dr7 = 1;            // local enable 0, RW0=00 (execute), LEN0=00
            ctx.Dr6 = 0;
            SetThreadContext(GetCurrentThread(), &ctx);
        }
    }

    __try
    {
        ((void(*)())mem)();
    }
    __except (Filter(GetExceptionInformation()))
    {
    }

    if (strcmp(which, "dr0") == 0)
    {
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(GetCurrentThread(), &ctx))
        {
            ctx.Dr0 = 0; ctx.Dr7 = 0; ctx.Dr6 = 0;
            SetThreadContext(GetCurrentThread(), &ctx);
        }
    }

    printf("%-8s hits=%ld code=%-4s ip_off=%-4lld dr6=0x%llX BS=%d B0=%d\n",
           which, g_hits, Name(g_code),
           g_code ? (long long)(g_ip - base) : -1LL,
           (unsigned long long)g_dr6,
           (int)((g_dr6 >> 14) & 1),
           (int)(g_dr6 & 1));

    VirtualFree(mem, 0, MEM_RELEASE);
}

int main()
{
    printf("ProcessorCount=%lu\n", GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
    RunCase("ud2");
    RunCase("icebp");
    RunCase("tfnop");
    RunCase("tfcpuid");
    RunCase("dr0");
    return 0;
}
