// Replicates VMAware's INTERRUPT_SHADOW and TIMER measurements and reports the
// exact quantities, instead of the boolean VMAware prints.
//
// Build: cl /nologo /std:c++17 /EHsc /O2 ish.cpp
// Cases: `ish shadow`, `ish cpuid`, `ish timer`, or no argument for all.
//
// INTERRUPT_SHADOW: VMAware runs cpuid_blockstep_stub, which does
//   mov ss, ax        (starts an interrupt shadow at offset 14)
//   cpuid             (offset 16 - must NOT read the shadow)
//   pop rbx           (offset 18 - bare metal reports the #DB here)
// and declares a hypervisor if the trap IP is anything other than stub+18.
// So the useful measurement is the offset, not "did it fire".
//
// TIMER: two ratios.
//   (a) CPUID latency / LFENCE latency  must stay below 2.75
//   (b) #DB latency  / ZwRaiseException latency must stay below 2.5
// This probe measures both with RDTSC (fine for diagnosis; VMAware avoids TSC
// because it is the thing being detected).
//
// Build (guest, x64 Native Tools prompt):
//   cl /nologo /std:c++17 /EHsc /O2 ish.cpp advapi32.lib
#include <windows.h>
#include <intrin.h>
#include <cstdio>
#include <cstdint>
#include <cstring>

// ---------------------------------------------------------------- INT_SHADOW

// Byte-identical to VMAware's cpuid_blockstep_stub.
static const unsigned char cpuid_blockstep_stub[] = {
    0x53,                                      /* 0  push rbx */
    0x31, 0xC0,                                /* 1  xor eax, eax */
    0x8C, 0xD0,                                /* 3  mov ax, ss */
    0x9C,                                      /* 5  pushfq */
    0x81, 0x0C, 0x24, 0x00, 0x01, 0x00, 0x00,  /* 6  or dword [rsp], 0x100 */
    0x9D,                                      /* 13 popfq */
    0x8E, 0xD0,                                /* 14 mov ss, ax   <- shadow starts */
    0x0F, 0xA2,                                /* 16 cpuid        <- must not trap */
    0x5B,                                      /* 18 pop rbx      <- bare metal traps */
    0x90,                                      /* 19 nop */
    0x9C,                                      /* 20 pushfq */
    0x81, 0x24, 0x24, 0xFF, 0xFE, 0xFF, 0xFF,  /* 21 and dword [rsp], 0xFFFFFEFF */
    0x9D,                                      /* 28 popfq */
    0xC3                                       /* 29 ret */
};

static volatile LONG     g_hits = 0;
static volatile DWORD    g_code = 0;
static volatile uint64_t g_ip = 0;
static volatile uint64_t g_base = 0;
static volatile uint64_t g_dr6 = 0;
static volatile uint64_t g_rflags = 0;
static volatile uint64_t g_expect = 0;

static LONG CALLBACK Filter(EXCEPTION_POINTERS* ep)
{
    if (!ep || !ep->ExceptionRecord || !ep->ContextRecord)
        return EXCEPTION_CONTINUE_SEARCH;
    InterlockedIncrement(&g_hits);
    if (g_code == 0) {
        g_code = ep->ExceptionRecord->ExceptionCode;
        g_ip = (uint64_t)ep->ExceptionRecord->ExceptionAddress;
        g_dr6 = ep->ContextRecord->Dr6;
        g_rflags = ep->ContextRecord->EFlags;
    }
    ep->ContextRecord->EFlags &= ~(DWORD)0x100;
    ep->ContextRecord->Dr6 = 0;
    if (g_expect)
        ep->ContextRecord->Rip = (DWORD64)g_expect;
    return EXCEPTION_CONTINUE_EXECUTION;
}

static void RunInterruptShadow()
{
    g_hits = 0; g_code = 0; g_ip = 0; g_dr6 = 0; g_rflags = 0;

    void* mem = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE,
                             PAGE_EXECUTE_READWRITE);
    if (!mem) { printf("int_shadow alloc failed\n"); return; }
    memcpy(mem, cpuid_blockstep_stub, sizeof(cpuid_blockstep_stub));
    g_base = (uint64_t)mem;
    g_expect = g_base + sizeof(cpuid_blockstep_stub) - 1;  /* the RET */

    __try {
        ((void(*)())mem)();
    }
    __except (Filter(GetExceptionInformation())) {
    }

    const long long off = g_code ? (long long)(g_ip - g_base) : -1;
    printf("int_shadow hits=%ld code=0x%08lX ip_off=%lld expected=18 dr6=0x%llX rflags=0x%llX  %s\n",
           (long)g_hits, (unsigned long)g_code, off,
           (unsigned long long)g_dr6, (unsigned long long)g_rflags,
           (g_hits == 0)  ? "NO EXCEPTION" :
           (off == 18)    ? "correct (#DB at pop rbx) - bare metal behaviour" :
           (off == 16)    ? "TRAPPED AT CPUID - hypervisor leaked the shadow" :
                            "wrong offset - anomaly");
    VirtualFree(mem, 0, MEM_RELEASE);
}

// --------------------------------------------------------------------- TIMER

static uint64_t g_counter = 0;
static volatile LONG g_stop = 0;

static DWORD WINAPI CounterThread(LPVOID)
{
    uint64_t local = 0;
    while (!g_stop) {
        // Same shape as VMAware's TICK loop: straight-line increments to a
        // volatile so the store keeps the thread from being optimised away.
        for (int i = 0; i < 512; ++i) { local++; g_counter = local; }
    }
    return 0;
}

static uint64_t g_best_cpuid = ~0ull, g_best_lfence = ~0ull;
static uint64_t g_best_db = ~0ull, g_best_api = ~0ull;

static uint64_t MeasureCpuid()
{
    volatile uint64_t* p = &g_counter;
    uint64_t sync = *p;
    while (*p == sync) {}
    sync = *p; while (*p == sync) {}
    uint64_t pre = *p;
    int r[4]; __cpuid(r, 0);
    uint64_t post = *p;
    return (post > pre) ? post - pre : ~0ull;
}

static uint64_t MeasureLfence()
{
    volatile uint64_t* p = &g_counter;
    /*
     * Eight LFENCEs are faster than one tick of the counter thread, so a single
     * attempt usually observes no advance. VMAware treats that as an invalid
     * sample and retries; so does this, otherwise the minimum is the failure
     * value and the ratio is meaningless.
     */
    for (int attempt = 0; attempt < 200; ++attempt) {
        uint64_t sync = *p;
        while (*p == sync) {}
        sync = *p; while (*p == sync) {}
        uint64_t pre = *p;
        _mm_lfence(); _mm_lfence(); _mm_lfence(); _mm_lfence();
        _mm_lfence(); _mm_lfence(); _mm_lfence(); _mm_lfence();
        uint64_t post = *p;
        if (post > pre) return post - pre;
    }
    return ~0ull;
}

// Single-step (#DB) latency: TF then a nop, timed with the counter.
static uint64_t MeasureDb()
{
    volatile uint64_t* p = &g_counter;
    uint64_t sync = *p;
    while (*p == sync) {}
    sync = *p; while (*p == sync) {}
    uint64_t pre = *p;
    uint64_t post = 0;
    __try {
        unsigned __int64 fl = __readeflags();
        __writeeflags(fl | 0x100);
        __nop();
    }
    __except (GetExceptionCode() == EXCEPTION_SINGLE_STEP
              ? (GetExceptionInformation()->ContextRecord->EFlags &= ~0x100U,
                 EXCEPTION_CONTINUE_EXECUTION)
              : EXCEPTION_CONTINUE_SEARCH) {
    }
    post = *p;
    return (post > pre) ? post - pre : ~0ull;
}

// ZwRaiseException latency - the software half of the comparison.
static uint64_t MeasureApi()
{
    typedef LONG NTSTATUS;
    static bool resolved = false;
    static NTSTATUS(__stdcall* raise_exc)(PEXCEPTION_RECORD, PCONTEXT, BOOLEAN) = nullptr;
    if (!resolved) {
        HMODULE nt = GetModuleHandleA("ntdll.dll");
        if (nt) raise_exc = (NTSTATUS(__stdcall*)(PEXCEPTION_RECORD, PCONTEXT, BOOLEAN))
                            GetProcAddress(nt, "ZwRaiseException");
        resolved = true;
    }
    if (!raise_exc) return ~0ull;

    volatile uint64_t* p = &g_counter;
    uint64_t sync = *p;
    while (*p == sync) {}
    sync = *p; while (*p == sync) {}
    uint64_t pre = *p;
    CONTEXT ctx = {}; ctx.ContextFlags = CONTEXT_FULL;
    EXCEPTION_RECORD er = {}; er.ExceptionCode = EXCEPTION_SINGLE_STEP;
    __try {
        /*
         * Capture a real context first. Raising with a zeroed CONTEXT puts
         * RIP = 0 in the exception record, and the kernel then tries to
         * dispatch a #DB at address 0 - the process dies instead of measuring.
         */
        RtlCaptureContext(&ctx);
        ctx.ContextFlags = CONTEXT_FULL;
        raise_exc(&er, &ctx, 1);
    }
    __except (GetExceptionCode() == EXCEPTION_SINGLE_STEP
              ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
    }
    uint64_t post = *p;
    return (post > pre) ? post - pre : ~0ull;
}

static const char* cupid_verdict(double r)
{
    return r >= 2.75 ? "ABOVE LIMIT - #VMEXIT latency detected" : "below limit";
}

static void RunCpuid()
{
    int r[4];
    __cpuid(r, 0);
    printf("cpuid leaf0 max=%u vendor=%.4s%.4s%.4s\n", (unsigned)r[0],
           (char*)&r[1], (char*)&r[3], (char*)&r[2]);

    int r1[4];
    __cpuid(r1, 1);
    printf("cpuid leaf1 ecx=0x%08X  VMX(bit5)=%d %s\n", (unsigned)r1[2],
           (r1[2] >> 5) & 1,
           ((r1[2] >> 5) & 1) ? "VMX bit SET -> CPUID ran natively (not intercepted)"
                              : "VMX bit CLEARED -> our handler ran, CPUID IS intercepted");
    printf("cpuid leaf1 edx=0x%08X\n", (unsigned)r1[3]);
}

static void RunTimer()
{
    HANDLE t = CreateThread(nullptr, 0, CounterThread, nullptr, 0, nullptr);
    SetThreadPriority(t, THREAD_PRIORITY_HIGHEST);

    /* Distinct cores for the two threads, if there are at least two. */
    {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        if (si.dwNumberOfProcessors >= 2) {
            GROUP_AFFINITY ga = {};
            ga.Mask = 1;
            SetThreadGroupAffinity(t, &ga, nullptr);
            ga.Mask = 2;
            SetThreadGroupAffinity(GetCurrentThread(), &ga, nullptr);
        }
        printf("timer cores=%u\n", (unsigned)si.dwNumberOfProcessors);
    }
    Sleep(150);   /* let the counter thread get scheduled */

    for (int i = 0; i < 400; ++i) {
        uint64_t a = MeasureCpuid();  if (a < g_best_cpuid) g_best_cpuid = a;
        uint64_t b = MeasureLfence(); if (b < g_best_lfence) g_best_lfence = b;
        uint64_t c = MeasureDb();     if (c < g_best_db) g_best_db = c;
        uint64_t d = MeasureApi();    if (d < g_best_api) g_best_api = d;
    }
    g_stop = 1;
    WaitForSingleObject(t, 2000);
    CloseHandle(t);

    const double cpu_ratio = g_best_lfence ? (double)g_best_cpuid / (double)g_best_lfence : 0;
    const double exc_ratio = g_best_api ? (double)g_best_db / (double)g_best_api : 0;
    printf("timer cpuid=%llu lfence=%llu ratio=%.2f  (limit 2.75) %s\n",
           (unsigned long long)g_best_cpuid, (unsigned long long)g_best_lfence,
           cpu_ratio, cupid_verdict(cpu_ratio));
    printf("timer db=%llu api=%llu ratio=%.2f  (limit 2.5) %s\n",
           (unsigned long long)g_best_db, (unsigned long long)g_best_api,
           exc_ratio,
           (g_best_db == ~0ull || g_best_api == ~0ull) ? "NO MEASUREMENT" :
           (exc_ratio >= 2.5) ? "ABOVE LIMIT - #DB interception detected" : "below limit");
}

int main(int argc, char** argv)
{
    const char* what = (argc > 1) ? argv[1] : "all";
    if (!strcmp(what, "shadow") || !strcmp(what, "all")) RunInterruptShadow();
    if (!strcmp(what, "cpuid")  || !strcmp(what, "all")) RunCpuid();
    if (!strcmp(what, "timer")  || !strcmp(what, "all")) RunTimer();
    fflush(stdout);
    return 0;
}
