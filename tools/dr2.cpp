// Answers one question: for a TF-driven #DB, is DR6 lost in hardware or is it
// lost in the CONTEXT Windows hands to the user-mode handler?
//
// Why it matters: VMAware's TRAP and SINGLE_STEP read
// info->ContextRecord->Dr6 inside their SEH filter. Measured on this guest, every
// TF-driven #DB shows Dr6 = 0 there, while a DR0-driven #DB shows 0xFFFF0FF1. If
// a *fresh* GetThreadContext inside the same handler reports the bits, then the
// exception CONTEXT is the lossy path and the fix is different from anything in
// the VMCS.
//
// Three readings are taken inside the same handler:
//   1. the CONTEXT attached to the exception (what VMAware reads),
//   2. GetThreadContext on the current thread (a fresh kernel round-trip),
//   3. the raw value again after clearing nothing (stability check).
//
// Two cases, so the TF and breakpoint paths can be compared:
//   tf   - set TF via popfq, execute one instruction
//   dr0  - DR0 execute breakpoint, no TF
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>

static volatile LONG     g_hits   = 0;
static volatile uint64_t g_ctxDr6 = 0;
static volatile uint64_t g_fresh  = 0;
static volatile uint64_t g_again  = 0;
static volatile DWORD    g_code   = 0;

static LONG CALLBACK Filter(EXCEPTION_POINTERS* ep)
{
    if (!ep || !ep->ExceptionRecord || !ep->ContextRecord)
        return EXCEPTION_CONTINUE_SEARCH;

    InterlockedIncrement(&g_hits);
    if (g_hits == 1) {
        g_code   = ep->ExceptionRecord->ExceptionCode;
        g_ctxDr6 = ep->ContextRecord->Dr6;

        /* Fresh kernel round-trip, before touching anything. */
        CONTEXT c = {};
        c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(GetCurrentThread(), &c)) {
            g_fresh = c.Dr6;
        }

        /* Second read: is it stable, or was it consumed by the first read? */
        CONTEXT c2 = {};
        c2.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(GetCurrentThread(), &c2)) {
            g_again = c2.Dr6;
        }
    }

    ep->ContextRecord->EFlags &= ~(DWORD)0x100;
    ep->ContextRecord->Dr7 = 0;
    ep->ContextRecord->Dr0 = 0;
    ep->ContextRecord->Dr6 = 0;
    return EXCEPTION_CONTINUE_EXECUTION;
}

static void report(const char* name)
{
    printf("%-4s hits=%ld code=0x%08lX  ctx_dr6=0x%llX  fresh_dr6=0x%llX  again_dr6=0x%llX\n",
           name, (long)g_hits, (unsigned long)g_code,
           (unsigned long long)g_ctxDr6,
           (unsigned long long)g_fresh,
           (unsigned long long)g_again);
    if (g_hits == 0) {
        printf("     no exception\n");
        return;
    }
    const int ctxBS = (int)((g_ctxDr6 >> 14) & 1), ctxB0 = (int)(g_ctxDr6 & 1);
    const int frBS  = (int)((g_fresh  >> 14) & 1), frB0  = (int)((g_fresh  & 1));
    printf("     CONTEXT: BS=%d B0=%d   FRESH: BS=%d B0=%d   -> %s\n",
           ctxBS, ctxB0, frBS, frB0,
           (frBS | frB0) && !(ctxBS | ctxB0)
               ? "DR6 EXISTS but the exception CONTEXT loses it"
               : (!(frBS | frB0) && !(ctxBS | ctxB0))
                   ? "DR6 is genuinely empty in hardware"
                   : "both paths agree");
}

int main(int argc, char** argv)
{
    const char* which = (argc > 1) ? argv[1] : "tf";

    if (!strcmp(which, "dr0")) {
        /* A DR0 execute breakpoint on a known address, no TF involved. */
        unsigned char* mem = (unsigned char*)VirtualAlloc(nullptr, 0x1000,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!mem) { printf("alloc failed\n"); return 1; }
        mem[0] = 0x90; mem[1] = 0xC3;   /* nop; ret */

        CONTEXT c = {};
        c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        GetThreadContext(GetCurrentThread(), &c);
        c.Dr0 = (DWORD64)mem;
        c.Dr7 = 1;
        c.Dr6 = 0;
        SetThreadContext(GetCurrentThread(), &c);

        g_hits = 0; g_ctxDr6 = 0; g_fresh = 0; g_again = 0; g_code = 0;
        __try {
            ((void(*)(void))mem)();
        }
        __except (Filter(GetExceptionInformation())) { }

        c.Dr0 = 0; c.Dr7 = 0; c.Dr6 = 0;
        SetThreadContext(GetCurrentThread(), &c);
        report("dr0");
        VirtualFree(mem, 0, MEM_RELEASE);
        return 0;
    }

    /* TF set with popfq, then one instruction. No VMCS involvement at all. */
    g_hits = 0; g_ctxDr6 = 0; g_fresh = 0; g_again = 0; g_code = 0;
    __try {
        /*
         * A hand-assembled stub, because MSVC x64 has no inline assembler and
         * the eflags intrinsics are not available in every configuration.
         * pushfq / or dword [rsp], 0x100 / popfq / nop / ret
         */
        static const unsigned char tf_stub[] = {
            0x9C,                                      /* pushfq */
            0x81, 0x0C, 0x24, 0x00, 0x01, 0x00, 0x00,  /* or dword [rsp], 0x100 */
            0x9D,                                      /* popfq */
            0x90,                                      /* nop -> #DB here */
            0xC3                                       /* ret */
        };
        static void (*fn)() = nullptr;
        if (!fn) {
            unsigned char* p = (unsigned char*)VirtualAlloc(nullptr, 0x1000,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!p) { printf("alloc failed\n"); return 1; }
            memcpy(p, tf_stub, sizeof(tf_stub));
            fn = (void(*)())p;
        }
        fn();
    }
    __except (GetExceptionCode() == EXCEPTION_SINGLE_STEP
              ? (Filter(GetExceptionInformation()), EXCEPTION_CONTINUE_EXECUTION)
              : EXCEPTION_CONTINUE_SEARCH) {
    }
    report("tf");
    fflush(stdout);
    return 0;
}
