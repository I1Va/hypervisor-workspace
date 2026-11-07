// Turns the hypervisor's TSC-offsetting (root-mode time freeze) on or off from
// the guest.
//
// Why a runtime switch: the freeze trades the exit-latency signal for per-core
// offset drift, and only a measurement can say which matters on this guest.
// The same boot can be measured with the feature both off and on, which is the
// only way to attribute a change to it.
//
// Hypercall ABI: CPUID with EAX = 0x4000BABE and RCX = key. Arguments are in
// RDI (call number), RSI (arg1), RDX (arg2). Result comes back in RAX.
// Call 0x2b6e1d90a7c43 = SET_TSC_OFFSET, arg1 = 1 enable, 0 disable.
//
// Usage: hv_tsc.exe <0|1>
using System;
using System.Runtime.InteropServices;

public static class HvTsc
{
    const ulong Key = 0xBABEB8CEC88D3;
    const uint Leaf = 0x4000BABE;
    const ulong SetTscOffset = 0x2b6e1d90a7c43;

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(IntPtr addr, UIntPtr size, uint type, uint protect);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate ulong HypercallFn(ulong channel, ulong enabled);

    public static int Main(string[] args)
    {
        ulong enabled = (args.Length > 0 && args[0] != "0") ? 1UL : 0UL;
        Console.WriteLine("step: start enabled=" + enabled);

        // Entered with channel in RCX and enabled in RDX (Windows x64 ABI), exactly
        // like hv_trace: the hypercall wants arg1 in RSI and arg2 in RDX, so only
        // RCX moves. Kept two-argument because that shape is measured working on
        // this guest; a single-argument delegate faults here for reasons that are
        // not worth chasing.
        byte[] stub = new byte[] {
            0x48, 0x89, 0xCE,                                       // mov rsi, rcx   (enabled -> arg1)
            0x48, 0xB9, 0,0,0,0,0,0,0,0,                            // mov rcx, key
            0x48, 0xBF, 0,0,0,0,0,0,0,0,                            // mov rdi, call number
            0xB8, 0xBE, 0xBA, 0x00, 0x40,                           // mov eax, 0x4000BABE
            0x0F, 0xA2,                                             // cpuid
            0xC3                                                    // ret
        };
        // Layout: 0..2 mov rsi,rcx | 3..12 mov rcx,imm64 (imm at 5)
        //         13..22 mov rdi,imm64 (imm at 15) | 23..27 mov eax,imm32 | 28..29 cpuid | 30 ret
        BitConverter.GetBytes(Key).CopyTo(stub, 5);
        BitConverter.GetBytes(SetTscOffset).CopyTo(stub, 15);

        Console.WriteLine("step: stub built");

        IntPtr code = VirtualAlloc(IntPtr.Zero, (UIntPtr)stub.Length, 0x3000, 0x40);
        Console.WriteLine("step: alloc=" + code);
        if (code == IntPtr.Zero)
        {
            Console.WriteLine("VirtualAlloc failed");
            return 1;
        }
        Marshal.Copy(stub, 0, code, stub.Length);
        Console.WriteLine("step: copied");

        HypercallFn fn = (HypercallFn)Marshal.GetDelegateForFunctionPointer(code, typeof(HypercallFn));
        Console.WriteLine("step: calling");
        ulong status = fn(enabled, 0);
        Console.WriteLine("step: returned");

        Console.WriteLine("set_tsc_offset enabled=" + enabled + " status=" + status);
        return 0;
    }
}
