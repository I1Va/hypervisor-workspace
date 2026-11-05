// Proves the guest really has multiple processors, not just a processor count.
//
// Why this exists: Windows reporting NumberOfLogicalProcessors=4 is necessary
// but not sufficient. The count comes from firmware/ACPI data and can be right
// while only one core ever executes - which is exactly how the multicore bug
// presented before it was fixed (4 LAPICs advertised, 1 processor running).
//
// Method: run a fixed amount of CPU work on N threads and measure wall time.
// Real parallelism makes N threads finish in about the same time as one; a
// single-core system takes N times as long. The work is a dependent integer
// chain so it cannot be optimised away or vectorised.
//
// Also reports, per thread, which processor it actually ran on, via
// GetCurrentProcessorNumber.
//
// Build: cl /nologo /std:c++17 /EHsc /O2 par.cpp
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <vector>

static volatile uint64_t g_sink;

static void Work(uint64_t iterations)
{
    uint64_t x = GetCurrentThreadId() | 1;
    for (uint64_t i = 0; i < iterations; ++i)
    {
        // Dependent chain: each step needs the previous value.
        x = x * 6364136223846793005ULL + 1442695040888963407ULL;
        x ^= x >> 33;
    }
    g_sink = x;
}

struct ThreadArg
{
    uint64_t iterations;
    DWORD    ranOn;
};

static DWORD WINAPI ThreadProc(LPVOID param)
{
    ThreadArg* a = (ThreadArg*)param;
    // Record where we start; a real multicore run uses several distinct CPUs.
    a->ranOn = GetCurrentProcessorNumber();
    Work(a->iterations);
    return 0;
}

static double RunWithThreads(int n, uint64_t iterations, std::vector<DWORD>& cpus)
{
    std::vector<HANDLE>  handles(n);
    std::vector<ThreadArg> args(n);
    cpus.assign(n, 0xFFFFFFFF);

    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    for (int i = 0; i < n; ++i)
    {
        args[i].iterations = iterations;
        args[i].ranOn = 0xFFFFFFFF;
        handles[i] = CreateThread(nullptr, 0, ThreadProc, &args[i], 0, nullptr);
    }
    WaitForMultipleObjects((DWORD)n, handles.data(), TRUE, INFINITE);

    QueryPerformanceCounter(&end);

    for (int i = 0; i < n; ++i)
    {
        cpus[i] = args[i].ranOn;
        CloseHandle(handles[i]);
    }

    return (double)(end.QuadPart - start.QuadPart) / (double)freq.QuadPart;
}

int main()
{
    SYSTEM_INFO si = {};
    GetSystemInfo(&si);
    printf("GetSystemInfo.dwNumberOfProcessors = %lu\n", (unsigned long)si.dwNumberOfProcessors);
    printf("GetActiveProcessorCount(ALL)        = %lu\n",
           (unsigned long)GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));

    // Warm up so the first measurement is not dominated by page faults / JIT.
    std::vector<DWORD> cpus;
    RunWithThreads(1, 2000000, cpus);

    const uint64_t iters = 60000000;

    std::vector<DWORD> c1, c4;

    // Baseline: one thread doing ALL the work.
    double t1 = RunWithThreads(1, iters * 4, c1);

    // Same total work, split across four threads.
    double t4 = RunWithThreads(4, iters, c4);

    printf("\n1 thread  x %llu : %.3f s   ran on cpu %lu\n",
           (unsigned long long)(iters * 4), t1, (unsigned long)c1[0]);
    printf("4 threads x %llu : %.3f s   ran on cpus", (unsigned long long)iters, t4);
    for (DWORD c : c4) printf(" %lu", (unsigned long)c);
    printf("\n");

    // Same total work, so real parallelism finishes ~4x sooner.
    const double speedup = t1 / t4;
    printf("\nspeedup(4 threads vs 1, equal total work) = %.2fx\n", speedup);

    int distinct = 0;
    {
        bool seen[64] = {};
        for (DWORD c : c4)
        {
            if (c < 64 && !seen[c]) { seen[c] = true; ++distinct; }
        }
    }
    printf("distinct CPUs used by 4 threads = %d\n", distinct);

    printf("VERDICT: %s\n",
           (speedup > 2.0 && distinct >= 2)
               ? "genuinely multicore - four threads do the work in about a quarter of the time"
               : "NOT multicore - four threads take about as long as one");

    return 0;
}
