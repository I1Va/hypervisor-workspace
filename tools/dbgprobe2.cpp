// Discriminates "TF never set" from "trap generated but swallowed".
//
// Measured so far with exception bitmap 0 (hypervisor does not intercept #DB):
//   ud2      -> #UD caught by SEH          (fault delivery works)
//   icebp    -> nothing
//   tfnop    -> nothing
//   tfcpuid  -> nothing
//   dr0      -> nothing
//
// Every #DB-class event is missing while a #UD works, and the hypervisor is not
// intercepting #DB, so either the trap is never generated or it is consumed
// inside Windows before reaching user mode.
//
// New cases:
//   tfread  - set TF, then immediately read RFLAGS back. If TF reads 1 the flag
//             was accepted and the trap simply never fired. If it reads 0 the
//             flag was silently discarded, which is a different bug entirely.
//   int3    - #BP is also a trap and goes through the same IDT path. If #BP
//             arrives but #DB does not, the fault is specific to debug
//             exceptions rather than to trap delivery in general.
//   into    - #OF, another trap-class exception, as a second control.
//   icebpn  - ICEBP followed by a distinctive byte so the resumed RIP is
//             observable even when no exception is reported.
//
// Build: cl /nologo /std:c++17 /EHsc /O1 dbgprobe2.cpp
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>

static volatile LONG g_hits = 0;
static volatile DWORD g_code = 0;
static volatile uintptr_t g_ip = 0;
static volatile uint64_t g_dr6 = 0;
static volatile uint64_t g_resume = 0;

static LONG CALLBACK Filter(EXCEPTION_POINTERS* ep)
{
    if (!ep || !ep->ExceptionRecord || !ep->ContextRecord)
    {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    const DWORD code = ep->ExceptionRecord->ExceptionCode;
    if (code != EXCEPTION_SINGLE_STEP && code != EXCEPTION_ILLEGAL_INSTRUCTION &&
        code != EXCEPTION_BREAKPOINT && code != EXCEPTION_INT_OVERFLOW)
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

    ep->ContextRecord->EFlags &= ~0x100u;
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
        case EXCEPTION_INT_OVERFLOW: return "#OF";
        case EXCEPTION_ACCESS_VIOLATION: return "#PF";
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

int main()
{
    printf("ProcessorCount=%lu\n", GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));

    struct Case { const char* name; unsigned char code[24]; size_t len; uint64_t resume; };
    static const Case cases[] = {
        // #BP: trap-class, same IDT path as #DB.
        { "int3",  { 0xCC, 0x90, 0xC3 }, 3, 1 },
        // #OF: another trap-class exception.
        { "into",  { 0x9C, 0x58, 0x0D, 0x00, 0x08, 0x00, 0x00, 0x50, 0x9D, 0xCE, 0xC3 }, 11, 10 },
        // TF then read RFLAGS back: answers "was TF accepted?".
        // pushfq; pop rax; or eax,0x100; push rax; popfq;
        // pushfq; pop rax; and eax,~0x100; push rax; popfq; ret
        { "tfread",{ 0x9C, 0x58, 0x0D, 0x00, 0x01, 0x00, 0x00, 0x50, 0x9D,
                     0x9C, 0x58,
                     0x25, 0xFF, 0xFE, 0xFF, 0xFF,
                     0x50, 0x9D, 0xC3 }, 19, 18 },
        // ICEBP then a nop then ret: lets the resumed RIP be observed.
        { "icebpn",{ 0xF1, 0x90, 0xC3 }, 3, 1 },
    };

    for (const Case& c : cases)
    {
        g_hits = 0; g_code = 0; g_ip = 0; g_dr6 = 0;

        uint64_t base = 0;
        void* mem = AllocExec(c.code, c.len, &base);
        if (!mem) { printf("%-8s alloc failed\n", c.name); continue; }

        g_resume = base + c.resume;

        uint64_t ret = 0;
        __try
        {
            // Every stub ends in RET; read the return value for tfread.
            ret = ((uint64_t(*)())mem)();
        }
        __except (Filter(GetExceptionInformation()))
        {
        }

        if (strcmp(c.name, "tfread") == 0)
        {
            // TF is bit 8 of the flags the stub read back while TF was set.
            printf("%-8s hits=%ld code=%-4s rflags=0x%llX TF_readback=%d\n",
                   c.name, g_hits, Name(g_code),
                   (unsigned long long)ret, (int)((ret >> 8) & 1));
        }
        else
        {
            printf("%-8s hits=%ld code=%-4s ip_off=%-3lld dr6=0x%llX BS=%d B0=%d\n",
                   c.name, g_hits, Name(g_code),
                   g_code ? (long long)(g_ip - base) : -1LL,
                   (unsigned long long)g_dr6,
                   (int)((g_dr6 >> 14) & 1), (int)(g_dr6 & 1));
        }

        VirtualFree(mem, 0, MEM_RELEASE);
    }

    return 0;
}
