// Replicates VMAware's TRAP and SINGLE_STEP scenarios and reports the exact
// DR6 the guest handler observes.
//
// Why: VMAware's TRAP check (vmaware.hpp, trap()) sets DR0 to stub+14 and sets
// TF, then requires the #DB at that address to report DR6 == (BS | B0), i.e.
// bit 14 and bit 0 both set. Anything else is treated as "the hypervisor
// swallowed the trap". SINGLE_STEP requires a genuine #DB on CPUID.
//
// So the useful measurement is not "did an exception arrive" but "what exact
// DR6 did it carry". That distinguishes:
//   BS|B0  -> correct, VMAware clean
//   BS only / B0 only -> hypervisor rewrote one of the bits
//   neither -> exception delivered but status bits lost
//   no exception at all -> trap swallowed entirely
//
// The stub is byte-identical to VMAware's trampoline_stub:
//   49 89 D8                  mov r8, rbx
//   9C                        pushfq
//   81 04 24 00 01 01 00      or dword [rsp], 0x10100   (TF + RF)
//   9D                        popfq
//   0F A2                     cpuid
//   4C 89 C3                  mov rbx, r8      <-- offset 14, the DR0 target
//   C3                        ret
//
// Cases:
//   trap        DR0 = stub+14, TF set via the stub, one run. Expect BS|B0.
//   trap_only   TF set, no DR0. Expect BS only.
//   dr0_only    DR0 set, no TF. Expect B0 only.
//   icebp       ICEBP (0xF1). Expect BS.
//   cpuid_tf    TF then CPUID then harmless bytes. Expect BS, RIP past CPUID.
//
// Build: cl /nologo /std:c++17 /EHsc /O1 trapdb.cpp
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>

static volatile LONG  g_hits   = 0;
static volatile DWORD g_code   = 0;
static volatile uint64_t g_dr6 = 0;
static volatile uint64_t g_ip   = 0;
static volatile uint64_t g_expect = 0;
static volatile LONG  g_stop   = 0;

static LONG CALLBACK Filter(EXCEPTION_POINTERS* ep)
{
    if (!ep || !ep->ExceptionRecord || !ep->ContextRecord)
        return EXCEPTION_CONTINUE_SEARCH;

    const DWORD code = ep->ExceptionRecord->ExceptionCode;

    // Only the classes these stubs raise.
    if (code != EXCEPTION_SINGLE_STEP && code != EXCEPTION_ILLEGAL_INSTRUCTION &&
        code != EXCEPTION_BREAKPOINT)
        return EXCEPTION_CONTINUE_SEARCH;

    InterlockedIncrement(&g_hits);
    if (g_code == 0) {
        g_code = code;
        g_ip   = (uint64_t)ep->ExceptionRecord->ExceptionAddress;
        g_dr6  = ep->ContextRecord->Dr6;
    }

    // Restore a sane state and stop the stub, so a misbehaving hypervisor
    // cannot loop us forever. Resume at the stub's RET when we know it,
    // otherwise just clear the trap sources and let it retry.
    ep->ContextRecord->EFlags &= ~(DWORD)0x100;   // TF
    ep->ContextRecord->Dr7 = 0;
    ep->ContextRecord->Dr6 = 0;
    ep->ContextRecord->Dr0 = 0;
    if (g_expect)
        ep->ContextRecord->Rip = (DWORD64)g_expect;
    InterlockedExchange(&g_stop, 1);
    return EXCEPTION_CONTINUE_EXECUTION;
}

// Byte-identical to VMAWARE's trampoline_stub.
static const unsigned char trampoline_stub[] = {
    0x49, 0x89, 0xD8,
    0x9C,
    0x81, 0x04, 0x24, 0x00, 0x01, 0x01, 0x00,
    0x9D,
    0x0F, 0xA2,
    0x4C, 0x89, 0xC3,   /* offset 14 */
    0xC3
};

// TF set, CPUID, then NOPs then RET. Used for cpuid_tf.
static const unsigned char cpuid_tf_stub[] = {
    0x9C,                                          /* pushfq */
    0x81, 0x0C, 0x24, 0x00, 0x01, 0x00, 0x00,       /* or dword [rsp], 0x100 (TF) */
    0x9D,                                          /* popfq */
    0x0F, 0xA2,                                    /* cpuid */
    0x90, 0x90, 0x90, 0x90,                        /* nops */
    0xC3                                           /* ret */
};

static void* AllocExec(const unsigned char* code, size_t len, uint64_t* base)
{
    void* mem = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) return nullptr;
    memcpy(mem, code, len);
    *base = (uint64_t)mem;
    return mem;
}

static void Report(const char* name, uint64_t base)
{
    const bool bs = (g_dr6 >> 14) & 1;
    const bool b0 = g_dr6 & 1;
    const char* verdict =
        (g_hits == 0)        ? "NO EXCEPTION - trap swallowed" :
        (bs && b0)           ? "BS|B0 - correct (VMAware TRAP clean)" :
        (bs && !b0)          ? "BS only - breakpoint status bit lost" :
        (!bs && b0)          ? "B0 only - single-step status bit lost" :
                               "neither BS nor B0 - status lost";
    printf("%-9s hits=%ld code=0x%08lX ip_off=%-4lld dr6=0x%llX BS=%d B0=%d  %s\n",
           name, (long)g_hits, (unsigned long)g_code,
           g_code ? (long long)(g_ip - base) : -1LL,
           (unsigned long long)g_dr6, (int)bs, (int)b0, verdict);
}

static void RunCase(const char* which)
{
    g_hits = 0; g_code = 0; g_dr6 = 0; g_ip = 0; g_expect = 0; g_stop = 0;

    uint64_t base = 0;
    void* mem = nullptr;
    size_t len = 0;

    if (strcmp(which, "icebp") == 0) {
        static const unsigned char c[] = { 0xF1, 0x90, 0xC3 };
        mem = AllocExec(c, sizeof(c), &base); len = sizeof(c);
        g_expect = base + 2;                 /* the RET */
    } else if (strcmp(which, "cpuid_tf") == 0) {
        mem = AllocExec(cpuid_tf_stub, sizeof(cpuid_tf_stub), &base);
        len = sizeof(cpuid_tf_stub);
        g_expect = base + sizeof(cpuid_tf_stub) - 1;   /* the RET */
    } else {
        mem = AllocExec(trampoline_stub, sizeof(trampoline_stub), &base);
        len = sizeof(trampoline_stub);
        g_expect = base + sizeof(trampoline_stub) - 1; /* the RET */
    }

    if (!mem) { printf("%-9s alloc failed\n", which); return; }

    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (strcmp(which, "trap") == 0 || strcmp(which, "dr0_only") == 0) {
        if (GetThreadContext(GetCurrentThread(), &ctx)) {
            ctx.Dr0 = base + 14;   /* stub+14: mov rbx, r8 */
            ctx.Dr7 = 1;           /* local enable 0, execute */
            ctx.Dr6 = 0;
            SetThreadContext(GetCurrentThread(), &ctx);
        }
    }

    __try {
        ((void(*)())mem)();
    }
    __except (Filter(GetExceptionInformation())) {
    }

    if (strcmp(which, "trap") == 0 || strcmp(which, "dr0_only") == 0) {
        CONTEXT c2 = {};
        c2.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(GetCurrentThread(), &c2)) {
            c2.Dr0 = 0; c2.Dr7 = 0; c2.Dr6 = 0;
            SetThreadContext(GetCurrentThread(), &c2);
        }
    }

    Report(which, base);
    VirtualFree(mem, 0, MEM_RELEASE);
}

int main(int argc, char** argv)
{
    // One case per invocation: a swallowed trap must not be able to wedge the
    // whole probe, and the shell can time out a single case cleanly.
    const char* which = (argc > 1) ? argv[1] : "trap";
    printf("case=%s\n", which);
    fflush(stdout);

    if      (strcmp(which, "trap")      == 0) RunCase("trap");
    else if (strcmp(which, "trap_only") == 0) RunCase("trap_only");
    else if (strcmp(which, "dr0_only")  == 0) RunCase("dr0_only");
    else if (strcmp(which, "icebp")     == 0) RunCase("icebp");
    else if (strcmp(which, "cpuid_tf")  == 0) RunCase("cpuid_tf");
    else { printf("unknown case\n"); return 2; }

    fflush(stdout);
    return 0;
}
