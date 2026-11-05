// Answers the one question that decides the whole #DB family:
// does RFLAGS.TF actually take effect inside this guest?
//
// Context: a probe replicating VMAware's TRAP/SINGLE_STEP/DBVM stubs found that
// *every* #DB class is swallowed - TF alone, DR0 alone, ICEBP, and TF across
// CPUID all produce no exception at all. That can mean two very different
// things:
//
//   (a) TF is honoured, a #DB is raised, but it never reaches user mode
//       (the hypervisor or the kernel drops it), or
//   (b) TF never takes effect at all, so no #DB is ever generated.
//
// They need different fixes, and the guest can tell them apart without any
// hypervisor change: set TF with popfq, then read RFLAGS back immediately
// WITHOUT clearing TF. Bit 8 is the answer.
//
//   tfread   set TF, read RFLAGS back, return it. No clearing, so the value is
//            the real post-popfq RFLAGS.
//   tfcount  set TF, then increment a global 100 times. If TF works the trap
//            fires at the first boundary and the counter stays ~0; if TF is
//            ignored the loop completes and the counter is 100.
//   dr0count same idea with an execute breakpoint on the 3rd instruction.
//
// Build: cl /nologo /std:c++17 /EHsc /O1 tfprobe.cpp
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>

static volatile LONG     g_hits = 0;
static volatile uint64_t g_dr6  = 0;
static volatile uint64_t g_resume = 0;
static volatile uint64_t g_counter = 0;

static LONG CALLBACK Filter(EXCEPTION_POINTERS* ep)
{
    if (!ep || !ep->ExceptionRecord || !ep->ContextRecord)
        return EXCEPTION_CONTINUE_SEARCH;

    const DWORD code = ep->ExceptionRecord->ExceptionCode;
    if (code != EXCEPTION_SINGLE_STEP && code != EXCEPTION_ILLEGAL_INSTRUCTION)
        return EXCEPTION_CONTINUE_SEARCH;

    InterlockedIncrement(&g_hits);
    if (g_dr6 == 0) g_dr6 = ep->ContextRecord->Dr6;

    ep->ContextRecord->EFlags &= ~(DWORD)0x100;
    ep->ContextRecord->Dr7 = 0;
    ep->ContextRecord->Dr0 = 0;
    ep->ContextRecord->Dr6 = 0;
    ep->ContextRecord->Rip = (DWORD64)g_resume;
    return EXCEPTION_CONTINUE_EXECUTION;
}

// mov rax, imm64 ; mov [rax], 0 ; pushfq ; or [rsp], 0x100 ; popfq ;
// pushfq ; pop rdx ; mov [rax+8], rdx ; ret
static void RunTfRead()
{
    g_hits = 0; g_dr6 = 0;

    unsigned char code[128];
    size_t n = 0;

    code[n++] = 0x48; code[n++] = 0xB8;            /* mov rax, imm64 */
    {
        uint64_t addr = (uint64_t)&g_counter;
        memcpy(code + n, &addr, 8); n += 8;
    }
    code[n++] = 0x48; code[n++] = 0xC7; code[n++] = 0x00;  /* mov qword [rax], 0 */
    code[n++] = 0; code[n++] = 0; code[n++] = 0; code[n++] = 0;

    /* pushfq; or dword [rsp], 0x100; popfq */
    code[n++] = 0x9C;
    code[n++] = 0x81; code[n++] = 0x0C; code[n++] = 0x24;
    code[n++] = 0x00; code[n++] = 0x01; code[n++] = 0x00; code[n++] = 0x00;
    code[n++] = 0x9D;

    /* pushfq; pop rdx  -> rdx = RFLAGS with TF still set */
    code[n++] = 0x9C;
    code[n++] = 0x5A;

    /* mov [rax+8], rdx */
    code[n++] = 0x48; code[n++] = 0x89; code[n++] = 0x50; code[n++] = 0x08;

    code[n++] = 0xC3;                              /* ret */

    void* mem = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) { printf("alloc failed\n"); return; }
    memcpy(mem, code, n);

    const uint64_t base = (uint64_t)mem;
    g_resume = base + n - 1;                       /* the ret */

    __try { ((void(*)())mem)(); }
    __except (Filter(GetExceptionInformation())) { }

    // g_counter low 8 bytes hold 0; the RFLAGS readback is at +8.
    // Read it back through a struct view of the same storage.
    uint64_t readback = 0;
    memcpy(&readback, (const void*)((const uint8_t*)&g_counter + 8), 8);

    printf("tfread   hits=%ld TF_readback=%d rflags=0x%llX  -> %s\n",
           (long)g_hits, (int)((readback >> 8) & 1),
           (unsigned long long)readback,
           ((readback >> 8) & 1)
               ? "TF IS SET - so a #DB should be raised"
               : "TF IS NOT SET - popfq silently discarded it");

    VirtualFree(mem, 0, MEM_RELEASE);
}

static void RunTfCount()
{
    g_hits = 0; g_dr6 = 0;
    g_counter = 0;

    unsigned char code[128];
    size_t n = 0;

    code[n++] = 0x48; code[n++] = 0xB8;
    {
        uint64_t addr = (uint64_t)&g_counter;
        memcpy(code + n, &addr, 8); n += 8;
    }
    code[n++] = 0x48; code[n++] = 0xC7; code[n++] = 0x00;
    code[n++] = 0; code[n++] = 0; code[n++] = 0; code[n++] = 0;

    /* pushfq; or dword [rsp], 0x100; popfq */
    code[n++] = 0x9C;
    code[n++] = 0x81; code[n++] = 0x0C; code[n++] = 0x24;
    code[n++] = 0x00; code[n++] = 0x01; code[n++] = 0x00; code[n++] = 0x00;
    code[n++] = 0x9D;

    /* mov rcx, 100 */
    code[n++] = 0x48; code[n++] = 0xC7; code[n++] = 0xC1;
    code[n++] = 100; code[n++] = 0; code[n++] = 0; code[n++] = 0;

    const size_t loop = n;
    /* inc qword [rax] */
    code[n++] = 0x48; code[n++] = 0xFF; code[n++] = 0x00;
    /* dec rcx */
    code[n++] = 0x48; code[n++] = 0xFF; code[n++] = 0xC9;
    /* jnz loop */
    code[n++] = 0x75;
    code[n++] = (unsigned char)((long)loop - (long)(n + 1));
    code[n++] = 0xC3;

    void* mem = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) { printf("alloc failed\n"); return; }
    memcpy(mem, code, n);

    const uint64_t base = (uint64_t)mem;
    g_resume = base + n - 1;

    __try { ((void(*)())mem)(); }
    __except (Filter(GetExceptionInformation())) { }

    printf("tfcount  hits=%ld counter=%llu dr6=0x%llX  -> %s\n",
           (long)g_hits, (unsigned long long)g_counter, (unsigned long long)g_dr6,
           (g_counter < 100)
               ? "trap fired - execution stopped early"
               : "loop completed - TF had NO effect");

    VirtualFree(mem, 0, MEM_RELEASE);
}

static void RunDr0Count()
{
    g_hits = 0; g_dr6 = 0;
    g_counter = 0;

    /* mov rax, imm64 ; mov [rax],0 ; inc [rax] x4 ; ret  -- breakpoint on 3rd inc */
    unsigned char code[64];
    size_t n = 0;
    code[n++] = 0x48; code[n++] = 0xB8;
    {
        uint64_t addr = (uint64_t)&g_counter;
        memcpy(code + n, &addr, 8); n += 8;
    }
    code[n++] = 0x48; code[n++] = 0xC7; code[n++] = 0x00;
    code[n++] = 0; code[n++] = 0; code[n++] = 0; code[n++] = 0;

    const size_t firstInc = n;
    for (int i = 0; i < 4; ++i) {
        code[n++] = 0x48; code[n++] = 0xFF; code[n++] = 0x00;   /* inc qword [rax] */
    }
    code[n++] = 0xC3;

    void* mem = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) { printf("alloc failed\n"); return; }
    memcpy(mem, code, n);

    const uint64_t base = (uint64_t)mem;
    g_resume = base + n - 1;

    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        ctx.Dr0 = base + firstInc + 3 * 3;   /* the 4th inc */
        ctx.Dr7 = 1;                          /* local enable 0, execute */
        ctx.Dr6 = 0;
        SetThreadContext(GetCurrentThread(), &ctx);
    }

    __try { ((void(*)())mem)(); }
    __except (Filter(GetExceptionInformation())) { }

    CONTEXT c2 = {};
    c2.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &c2)) {
        c2.Dr0 = 0; c2.Dr7 = 0; c2.Dr6 = 0;
        SetThreadContext(GetCurrentThread(), &c2);
    }

    printf("dr0count hits=%ld counter=%llu dr6=0x%llX  -> %s\n",
           (long)g_hits, (unsigned long long)g_counter, (unsigned long long)g_dr6,
           (g_hits > 0) ? "breakpoint fired" : "breakpoint did NOT fire");

    VirtualFree(mem, 0, MEM_RELEASE);
}

int main(int argc, char** argv)
{
    const char* w = (argc > 1) ? argv[1] : "tfread";
    printf("case=%s\n", w); fflush(stdout);

    if      (!strcmp(w, "tfread"))  RunTfRead();
    else if (!strcmp(w, "tfcount")) RunTfCount();
    else if (!strcmp(w, "dr0count"))RunDr0Count();
    else { printf("unknown\n"); return 2; }

    fflush(stdout);
    return 0;
}
