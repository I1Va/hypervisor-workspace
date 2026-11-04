// Measures the specific CPU behaviours VMAware's trap-based checks rely on.
//
// The suite tells you *that* a check failed, not *why*. Each probe here
// exercises one primitive and prints the raw result, so the hypervisor's
// behaviour can be compared with real hardware.
//
// A vectored exception handler observes faults at instruction granularity,
// which is what makes this useful: the interesting question is not "did an
// exception happen" but "did it happen at the instruction it should have".
//
// Every probe is stack-balanced and self-contained. Only ONE probe runs per
// process: a faulting stub can leave the thread in a state that poisons the
// next one, and a probe that hangs would otherwise take the whole run with it.
//
// Build on the guest (no compiler on the DTB, but csc ships with .NET):
//   csc.exe /nologo /out:vmprobe.exe vmprobe.cs
//   vmprobe.exe vmcall
//   vmprobe.exe int3
//   vmprobe.exe icebp
//   vmprobe.exe tfcpuid
//   vmprobe.exe tfnop
using System;
using System.Runtime.InteropServices;

public static class VmProbe
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(IntPtr addr, UIntPtr size, uint type, uint protect);

    [DllImport("kernel32.dll")]
    static extern bool VirtualFree(IntPtr addr, UIntPtr size, uint type);

    [DllImport("kernel32.dll")]
    static extern IntPtr AddVectoredExceptionHandler(uint first, VectoredHandler handler);

    delegate int VectoredHandler(IntPtr exceptionPointers);

    const uint MEM_COMMIT = 0x1000, MEM_RESERVE = 0x2000;
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    const uint MEM_RELEASE = 0x8000;

    const int CONTINUE_EXECUTION = unchecked((int)0xFFFFFFFF);
    const int CONTINUE_SEARCH = 0;

    const int CONTEXT_EFLAGS = 0x44;
    const int CONTEXT_RIP = 0xF8;

    static ulong g_faultAddress;
    static uint g_faultCode;
    static ulong g_fixupRip;
    static bool g_fixupSet;

    static int Handler(IntPtr exceptionPointers)
    {
        IntPtr record = Marshal.ReadIntPtr(exceptionPointers, 0);
        IntPtr context = Marshal.ReadIntPtr(exceptionPointers, IntPtr.Size);

        g_faultCode = (uint)Marshal.ReadInt32(record, 0);
        g_faultAddress = (ulong)Marshal.ReadIntPtr(record, 16).ToInt64();

        if (g_fixupSet && context != IntPtr.Zero)
        {
            Marshal.WriteInt64(context, CONTEXT_RIP, (long)g_fixupRip);

            // Clear TF. Left set, the fixup instruction raises another #DB and
            // this handler loops forever, which is indistinguishable from a
            // hung probe.
            uint eflags = (uint)Marshal.ReadInt32(context, CONTEXT_EFLAGS);
            Marshal.WriteInt32(context, CONTEXT_EFLAGS, (int)(eflags & ~0x100u));

            g_fixupSet = false;
            return CONTINUE_EXECUTION;
        }

        return CONTINUE_SEARCH;
    }

    static string Describe(uint code)
    {
        switch (code)
        {
            case 0: return "none";
            case 0xC000001D: return "ILLEGAL_INSTRUCTION #UD";
            case 0x80000003: return "BREAKPOINT #BP";
            case 0x80000004: return "SINGLE_STEP #DB";
            case 0xC0000005: return "ACCESS_VIOLATION";
            case 0xC0000096: return "PRIVILEGED_INSTRUCTION #GP";
            default: return "0x" + code.ToString("X8");
        }
    }

    static int Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine("usage: vmprobe <vmcall|vmmcall|int3|icebp|tfcpuid|tfnop>");
            return 2;
        }

        string which = args[0].ToLowerInvariant();
        byte[] code;
        long expected;

        switch (which)
        {
            case "vmcall":   // VMCALL: #UD outside VMX root
                code = new byte[] { 0x0F, 0x01, 0xC1, 0xC3 };
                expected = 0;
                break;
            case "vmmcall":  // VMMCALL: AMD-only, #UD on Intel
                code = new byte[] { 0x0F, 0x01, 0xD9, 0xC3 };
                expected = 0;
                break;
            case "int3":     // control: #BP must arrive
                code = new byte[] { 0xCC, 0xC3 };
                expected = 0;
                break;
            case "icebp":    // #DB, and RIP must advance by exactly 1
                code = new byte[] { 0xF1, 0xC3 };
                expected = 1;
                break;
            case "tfcpuid":
                // TF is RFLAGS bit 8. Flags go through a register, never the
                // stack, so the stack stays balanced on the fault path.
                code = new byte[] {
                    0x53,                           // 0  push rbx
                    0x9C,                           // 1  pushfq
                    0x58,                           // 2  pop rax
                    0x0D, 0x00, 0x01, 0x00, 0x00,   // 3  or eax, 0x100
                    0x50,                           // 8  push rax
                    0x9D,                           // 9  popfq
                    0x0F, 0xA2,                     // 10 cpuid
                    0x5B,                           // 12 pop rbx   <- trap here
                    0xC3                            // 13 ret
                };
                expected = 12;
                break;
            case "tfnop":
                code = new byte[] {
                    0x9C,                           // 0  pushfq
                    0x58,                           // 1  pop rax
                    0x0D, 0x00, 0x01, 0x00, 0x00,   // 2  or eax, 0x100
                    0x50,                           // 7  push rax
                    0x9D,                           // 8  popfq
                    0x90,                           // 9  nop
                    0xC3                            // 10 ret      <- trap here
                };
                expected = 10;
                break;
            default:
                Console.WriteLine("unknown probe " + which);
                return 2;
        }

        IntPtr mem = VirtualAlloc(IntPtr.Zero, (UIntPtr)0x1000,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (mem == IntPtr.Zero)
        {
            Console.WriteLine("VirtualAlloc failed");
            return 1;
        }

        ulong baseAddr = (ulong)mem.ToInt64();
        Marshal.Copy(code, 0, mem, code.Length);

        g_faultAddress = 0;
        g_faultCode = 0;
        g_fixupRip = baseAddr + (ulong)code.Length - 1;
        g_fixupSet = true;

        IntPtr handler = AddVectoredExceptionHandler(1, Handler);
        try
        {
            var fn = (Action)Marshal.GetDelegateForFunctionPointer(mem, typeof(Action));
            fn();
        }
        catch (Exception e)
        {
            Console.WriteLine("managed exception: " + e.GetType().Name);
        }

        long where = g_faultAddress == 0 ? -1 : (long)(g_faultAddress - baseAddr);
        string match = g_faultCode == 0
            ? "NO FAULT"
            : (where == expected ? "at expected offset" : "offset mismatch");

        Console.WriteLine(string.Format("{0,-8} code={1,-24} offset={2,-4} expected={3,-4} {4}",
                                        which, Describe(g_faultCode), where, expected, match));
        return 0;
    }
}
