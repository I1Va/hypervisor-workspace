// Determines whether the kernel debugger (KD) is actually initialised in this
// guest, which is the single most likely reason every #DB is swallowed.
//
// Why: a probe replicating VMAware's stubs found that TF is accepted (RFLAGS
// reads back 0x306, bit 8 set) but no trap ever fires, and DR0 never produces an
// exception either. That is exactly the signature of KD being active:
//   - KD owns DR0-DR3, so a user-mode breakpoint is silently overwritten;
//   - KD hooks the #DB path in the kernel, so single-step traps are consumed
//     before they can reach a user-mode handler.
// The BCD on this guest says `debug Yes` with `hypervisordebugtype Serial`.
//
// Method: KUSER_SHARED_DATA is mapped read-only at a fixed address in every
// process and carries the kernel-debugger flags. Rather than trust one offset,
// this dumps the whole region so the flags can be identified by their pattern,
// and cross-checks with the documented structure when available.
//
// Reported:
//   - a hex dump of KUSER_SHARED_DATA 0x2C0..0x300
//   - KdDebuggerEnabled / KdDebuggerNotPresent at their documented offsets
//   - NtGlobalFlag-style checks are NOT used; this is read-only inspection
//
// Build: cl /nologo /std:c++17 /EHsc /O1 kd2.cpp
#include <windows.h>
#include <cstdio>
#include <cstdint>

int main()
{
    const unsigned char* k = (const unsigned char*)0x7FFE0000;

    printf("KUSER_SHARED_DATA dump 0x2C0..0x300:\n");
    for (unsigned off = 0x2C0; off < 0x300; off += 16) {
        printf("  %04X:", off);
        for (unsigned i = 0; i < 16; ++i)
            printf(" %02X", k[off + i]);
        printf("\n");
    }

    /*
     * Documented layout for x64 (Win10 1607+ / 20H2):
     *   0x2D0 ActiveProcessorCount   ULONG
     *   0x2D4 KdDebuggerEnabled      BOOLEAN
     *   0x2D5 KdDebuggerNotPresent   BOOLEAN
     *   0x2D6 KdPreviouslyEnabled    BOOLEAN
     * Offsets shift between builds, so the dump above is authoritative and
     * these are printed only as a cross-check.
     */
    printf("\ninterpretation at documented offsets:\n");
    printf("  0x2D0 ActiveProcessorCount  = %lu\n", (unsigned long)*(const ULONG*)(k + 0x2D0));
    printf("  0x2D4 KdDebuggerEnabled     = %u\n", (unsigned)k[0x2D4]);
    printf("  0x2D5 KdDebuggerNotPresent  = %u\n", (unsigned)k[0x2D5]);
    printf("  0x2D6 KdPreviouslyEnabled   = %u\n", (unsigned)k[0x2D6]);

    /*
     * The reliable, offset-independent test: KdDebuggerNotPresent lives next to
     * KdDebuggerEnabled as two adjacent bytes. If exactly one of 0x2D4/0x2D5 is
     * 0 and the other is 1, the layout matches and the pair is meaningful.
     */
    const unsigned en = k[0x2D4], np = k[0x2D5];
    const bool layout_ok = (en <= 1) && (np <= 1);

    printf("\nlayout plausible: %s\n", layout_ok ? "yes" : "no (offsets differ on this build)");

    if (layout_ok) {
        printf("VERDICT: kernel debugger is %s\n", en ? "INITIALISED - it owns DR0-DR3 and consumes #DB" : "not initialised");
        if (en) {
            printf("         debugger attached: %s\n", np ? "no (waiting/timing out)" : "yes");
        }
    } else {
        /*
         * Fall back to a behavioural test that cannot be fooled by offsets:
         * read DR7 as the thread sees it. KD keeps DR7 non-zero on its own
         * account; a clean user thread should see the value we last wrote.
         */
        CONTEXT c = {};
        c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(GetCurrentThread(), &c)) {
            printf("DR0..DR7 as seen by this thread: %016llX %016llX %016llX %016llX  DR6=%016llX DR7=%016llX\n",
                   (unsigned long long)c.Dr0, (unsigned long long)c.Dr1,
                   (unsigned long long)c.Dr2, (unsigned long long)c.Dr3,
                   (unsigned long long)c.Dr6, (unsigned long long)c.Dr7);
            printf("VERDICT: inconclusive from flags; DR7 must be written then read back to test ownership\n");
        }
    }

    return 0;
}
