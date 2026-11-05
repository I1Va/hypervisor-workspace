// Reads the kernel-debugger state flags from KUSER_SHARED_DATA.
//
// The BCD reports "debug Yes", but that only records an intent: whether KD is
// actually initialised is what matters, because an initialised KD owns the
// debug registers and consumes #DB before user mode ever sees it.
//
// KUSER_SHARED_DATA is mapped read-only at a fixed address in every process, so
// these fields can be read without a driver.
//   offset 0x2D4 : KdDebuggerEnabled          (1 = KD initialised)
//   offset 0x2D5 : KdDebuggerNotPresent       (1 = no debugger attached)
//
// Build: cl /nologo /EHsc /O1 kdstate.cpp
#include <windows.h>
#include <cstdio>
#include <cstdint>

int main()
{
    const unsigned char* kusd = (const unsigned char*)0x7FFE0000;

    const unsigned char enabled = kusd[0x2D4];
    const unsigned char notPresent = kusd[0x2D5];

    printf("KdDebuggerEnabled    = %u\n", (unsigned)enabled);
    printf("KdDebuggerNotPresent = %u\n", (unsigned)notPresent);
    printf("interpretation: %s\n",
           enabled ? "kernel debugger IS initialised" : "kernel debugger is NOT initialised");

    // SharedUserData also carries the processor count the kernel believes in.
    const ULONG procs = *(const ULONG*)(kusd + 0x0C0);
    printf("KUSER_SHARED_DATA.ActiveProcessorCount = %lu\n", (unsigned long)procs);

    return 0;
}
