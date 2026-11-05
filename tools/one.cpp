// One case per run, with output flushed before each stub executes.
//
// The batch version hung with no output at all, which hides which case did it.
// This version prints and flushes first, so a hang still leaves a record of
// what was about to run.
//
// Build: cl /nologo /std:c++17 /EHsc /O1 one.cpp
// Run:   one.exe <int3|icebp|tfread|into|tfnop>
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

    printf("  [filter] code=0x%08lX hits=%ld\n", (unsigned long)code, (long)g_hits);
    fflush(stdout);

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
        default: return "other";
    }
}

int main(int argc, char** argv)
{
    const char* which = (argc > 1) ? argv[1] : "int3";

    unsigned char code[32];
    size_t len = 0;
    uint64_t resume = 0;

    if (!strcmp(which, "int3"))
    {
        unsigned char c[] = { 0xCC, 0x90, 0xC3 };
        memcpy(code, c, sizeof(c)); len = sizeof(c); resume = 1;
    }
    else if (!strcmp(which, "icebp"))
    {
        unsigned char c[] = { 0xF1, 0x90, 0xC3 };
        memcpy(code, c, sizeof(c)); len = sizeof(c); resume = 1;
    }
    else if (!strcmp(which, "into"))
    {
        // pushfq; pop rax; or eax,0x800; push rax; popfq; into; ret
        unsigned char c[] = { 0x9C, 0x58, 0x0D, 0x00, 0x08, 0x00, 0x00,
                              0x50, 0x9D, 0xCE, 0xC3 };
        memcpy(code, c, sizeof(c)); len = sizeof(c); resume = 10;
    }
    else if (!strcmp(which, "tfread"))
    {
        unsigned char c[] = { 0x9C, 0x58, 0x0D, 0x00, 0x01, 0x00, 0x00, 0x50, 0x9D,
                              0x9C, 0x58,
                              0x25, 0xFF, 0xFE, 0xFF, 0xFF,
                              0x50, 0x9D, 0xC3 };
        memcpy(code, c, sizeof(c)); len = sizeof(c); resume = 18;
    }
    else if (!strcmp(which, "tfnop"))
    {
        unsigned char c[] = { 0x9C, 0x58, 0x0D, 0x00, 0x01, 0x00, 0x00,
                              0x50, 0x9D, 0x90, 0x90, 0xC3 };
        memcpy(code, c, sizeof(c)); len = sizeof(c); resume = 11;
    }
    else
    {
        printf("unknown case\n");
        return 2;
    }

    void* mem = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE,
                             PAGE_EXECUTE_READWRITE);
    if (!mem) { printf("alloc failed\n"); return 1; }
    memcpy(mem, code, len);

    uint64_t base = (uint64_t)mem;
    g_resume = base + resume;

    printf("case=%s base=0x%llX resume_off=%llu\n",
           which, (unsigned long long)base, (unsigned long long)resume);
    printf("about to execute\n");
    fflush(stdout);

    uint64_t ret = 0;
    __try
    {
        ret = ((uint64_t(*)())mem)();
    }
    __except (Filter(GetExceptionInformation()))
    {
    }

    printf("done hits=%ld code=%s ret=0x%llX\n",
           (long)g_hits, Name(g_code), (unsigned long long)ret);
    if (!strcmp(which, "tfread"))
    {
        printf("tfread TF_readback=%d (rflags=0x%llX)\n",
               (int)((ret >> 8) & 1), (unsigned long long)ret);
    }
    fflush(stdout);

    return 0;
}
