// Decides whether single-step trapping happens at all.
//
// Measured so far:
//   ud2      -> #UD caught                        (fault delivery works)
//   icebp    -> no exception, execution continues
//   tfnop    -> no exception, execution continues
//   into     -> #UD (correct: INTO is invalid in 64-bit mode, my error)
//   int3     -> hangs
//   tfread   -> broken: it cleared TF in the value it returned, so it could
//               not answer its own question
//
// The open question is whether TF is accepted by popfq and simply never traps,
// or whether it traps and something swallows the #DB. A memory counter answers
// it without relying on exception handling at all:
//
//   store 0 to [counter]; set TF; increment [counter] 100 times; read [counter]
//
// If single-step works, execution stops after the first increment, so the
// counter is 1 (and the handler, if any, sees it). If TF is ignored, the loop
// completes and the counter is 100.
//
// The counter is a static in this process, so its address is stable and the stub
// can reach it with an absolute move.
//
// Build: cl /nologo /std:c++17 /EHsc /O1 tfcount.cpp
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>

static volatile LONG g_hits = 0;
static volatile uint64_t g_resume = 0;
static volatile uint64_t g_counter = 0;

static LONG CALLBACK Filter(EXCEPTION_POINTERS* ep)
{
    if (!ep || !ep->ExceptionRecord || !ep->ContextRecord)
    {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    InterlockedIncrement(&g_hits);
    printf("  [filter] code=0x%08lX dr6=0x%llX\n",
           (unsigned long)ep->ExceptionRecord->ExceptionCode,
           (unsigned long long)ep->ContextRecord->Dr6);
    fflush(stdout);

    ep->ContextRecord->EFlags &= ~0x100u;
    ep->ContextRecord->Dr7 = 0;
    ep->ContextRecord->Dr0 = 0;
    ep->ContextRecord->Rip = (DWORD64)g_resume;
    return EXCEPTION_CONTINUE_EXECUTION;
}

int main(int argc, char** argv)
{
    bool setTf = !(argc > 1 && !strcmp(argv[1], "notf"));

    // Build the stub:
    //   mov rax, <counter>
    //   mov qword [rax], 0
    //   pushfq; pop rcx; or ecx,0x100; push rcx; popfq      (TF set, unless notf)
    //   mov rdx, 100
    // loop:
    //   inc qword [rax]
    //   dec rdx
    //   jnz loop
    //   ret
    unsigned char code[96];
    size_t n = 0;

    // mov rax, imm64
    code[n++] = 0x48; code[n++] = 0xB8;
    {
        uint64_t counterAddress = (uint64_t)&g_counter;
        memcpy(code + n, &counterAddress, 8);
        n += 8;
    }

    // mov qword ptr [rax], 0
    code[n++] = 0x48; code[n++] = 0xC7; code[n++] = 0x00;
    code[n++] = 0; code[n++] = 0; code[n++] = 0; code[n++] = 0;

    if (setTf)
    {
        // pushfq; pop rcx; or ecx,0x100; push rcx; popfq
        unsigned char tf[] = { 0x9C, 0x59, 0x81, 0xC9, 0x00, 0x01, 0x00, 0x00,
                               0x51, 0x9D };
        memcpy(code + n, tf, sizeof(tf)); n += sizeof(tf);
    }

    // mov rdx, 100
    code[n++] = 0x48; code[n++] = 0xC7; code[n++] = 0xC2;
    code[n++] = 100; code[n++] = 0; code[n++] = 0; code[n++] = 0;

    size_t loopStart = n;

    // inc qword ptr [rax]
    code[n++] = 0x48; code[n++] = 0xFF; code[n++] = 0x00;

    // dec rdx
    code[n++] = 0x48; code[n++] = 0xFF; code[n++] = 0xCA;

    // jnz loopStart  (rel8)
    code[n++] = 0x75;
    code[n++] = (unsigned char)((long)loopStart - (long)(n + 1));

    // ret
    code[n++] = 0xC3;

    void* mem = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE,
                             PAGE_EXECUTE_READWRITE);
    if (!mem) { printf("alloc failed\n"); return 1; }
    memcpy(mem, code, n);

    uint64_t base = (uint64_t)mem;
    g_resume = base + n - 1;   // the ret

    printf("mode=%s stub_len=%zu about to run\n", setTf ? "TF" : "noTF", n);
    fflush(stdout);

    __try
    {
        ((void(*)())mem)();
    }
    __except (Filter(GetExceptionInformation()))
    {
    }

    printf("result mode=%s counter=%llu traps=%ld\n",
           setTf ? "TF" : "noTF",
           (unsigned long long)g_counter, (long)g_hits);
    fflush(stdout);

    return 0;
}
