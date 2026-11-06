// Measures the cost of different VM-exit kinds against a cross-core software
// counter, the same way VMAware's TIMER does.
//
// Purpose: decide whether TIMER's 6.0 ratio can be reduced by making our exit
// handler cheaper, or whether it is the floor cost of a VM exit and no handler
// change can help.
//
// The comparison that answers it:
//   cpuid  - always exits on Intel VT-x (the control bit is CPU-mandatory),
//            our handler does the most work
//   vmcall - always exits, our handler is minimal (vmwrite + inject #UD)
// If vmcall is as slow as cpuid, the exit floor dominates and optimising the
// CPUID handler is pointless.
#include <windows.h>
#include <intrin.h>
#include <cstdio>
#include <cstdint>

static volatile uint64_t g_counter = 0;
static volatile LONG g_stop = 0;

static DWORD WINAPI CounterThread(LPVOID)
{
    uint64_t local = 0;
    while (!g_stop) {
        for (int i = 0; i < 512; ++i) { local++; g_counter = local; }
    }
    return 0;
}

static inline void sync_tick()
{
    volatile uint64_t* p = &g_counter;
    uint64_t s = *p;
    while (*p == s) {}
    s = *p;
    while (*p == s) {}
}

// Returns the best (lowest) observed latency for the supplied operation.
template <typename Fn>
static uint64_t measure(Fn fn, int attempts = 600)
{
    uint64_t best = ~0ull;
    for (int i = 0; i < attempts; ++i) {
        sync_tick();
        uint64_t pre = g_counter;
        fn();
        uint64_t post = g_counter;
        if (post > pre && (post - pre) < best) best = post - pre;
    }
    return best;
}

static void do_cpuid()
{
    int r[4];
    __cpuid(r, 0);
}

static void do_lfence()
{
    _mm_lfence(); _mm_lfence(); _mm_lfence(); _mm_lfence();
    _mm_lfence(); _mm_lfence(); _mm_lfence(); _mm_lfence();
}

static void do_vmcall()
{
    /*
     * MSVC x64 has no inline assembler, so the VMCALL is executed from an
     * allocated RWX stub. VMCALL; RET.
     */
    static void (*fn)() = nullptr;
    if (!fn) {
        unsigned char* p = (unsigned char*)VirtualAlloc(nullptr, 0x1000,
                              MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!p) return;
        p[0] = 0x0F; p[1] = 0x01; p[2] = 0xC1; p[3] = 0xC3;
        fn = (void(*)())p;
    }
    /* Our handler injects #UD, so this must be trapped. */
    __try {
        fn();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

static void do_rdtsc()
{
    unsigned __int64 t = __rdtsc();
    (void)t;
}

int main()
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);

    HANDLE t = CreateThread(nullptr, 0, CounterThread, nullptr, 0, nullptr);
    SetThreadPriority(t, THREAD_PRIORITY_HIGHEST);
    if (si.dwNumberOfProcessors >= 2) {
        GROUP_AFFINITY ga = {};
        ga.Mask = 1; SetThreadGroupAffinity(t, &ga, nullptr);
        ga.Mask = 2; SetThreadGroupAffinity(GetCurrentThread(), &ga, nullptr);
    }
    Sleep(200);

    const uint64_t lf  = measure(do_lfence);
    const uint64_t cp  = measure(do_cpuid);
    const uint64_t vc  = measure(do_vmcall);
    const uint64_t rd  = measure(do_rdtsc);

    g_stop = 1;
    WaitForSingleObject(t, 2000);
    CloseHandle(t);

    printf("cores=%u\n", (unsigned)si.dwNumberOfProcessors);
    printf("lfence=%llu  (baseline)\n", (unsigned long long)lf);
    printf("rdtsc =%llu  native (not intercepted)\n", (unsigned long long)rd);
    printf("cpuid =%llu  ratio=%.2f  (limit 2.75)\n", (unsigned long long)cp,
           lf ? (double)cp / (double)lf : 0.0);
    printf("vmcall=%llu  ratio=%.2f  (minimal handler, always exits)\n",
           (unsigned long long)vc, lf ? (double)vc / (double)lf : 0.0);
    printf("\ncpuid-vmcall=%lld ticks attributable to our CPUID handler\n",
           (long long)cp - (long long)vc);
    fflush(stdout);
    return 0;
}
