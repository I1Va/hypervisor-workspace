// Turns the hypervisor's serial (COM1) tracing on or off from the guest.
//
// Why this exists: serial output is disabled after ExitBootServices because a
// character write busy-waits inside the VM-exit handler and perturbs the timing
// that VMAware measures. But when a handler wedges the CPU in root mode the
// guest never runs again, so the RAM log cannot be read back and a silent port
// leaves no evidence at all. Arming serial tracing immediately before running a
// suspect technique makes the final exits visible on the wire.
//
// Hypercall ABI: CPUID with EAX = 0x4000BABE and RCX = key. Arguments are in
// RDI (call number), RSI (arg1), RDX (arg2). Result comes back in RAX.
// Call 0x3a71c0de4f1b2 = SET_TRACE, arg1 = channel (0 serial), arg2 = enable.
//
// Usage: hv_trace.exe <0|1>
using System;
using System.Runtime.InteropServices;

public static class HvTrace
{
    const ulong Key = 0xBABEB8CEC88D3;
    const uint Leaf = 0x4000BABE;
    const ulong SetTrace = 0x3a71c0de4f1b2;

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(IntPtr addr, UIntPtr size, uint type, uint protect);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate ulong HypercallFn(ulong channel, ulong enabled);

    public static int Main(string[] args)
    {
        ulong enabled = (args.Length > 0 && args[0] != "0") ? 1UL : 0UL;

        // Entered with channel in RCX and enabled in RDX (Windows x64 ABI).
        // The hypercall wants arg1 in RSI and arg2 in RDX, so only RCX moves.
        byte[] stub = new byte[] {
            0x48, 0x89, 0xCE,                                       // mov rsi, rcx   (channel -> arg1)
            0x48, 0xB9, 0,0,0,0,0,0,0,0,                            // mov rcx, key
            0x48, 0xBF, 0,0,0,0,0,0,0,0,                            // mov rdi, call number
            0xB8, 0xBE, 0xBA, 0x00, 0x40,                           // mov eax, 0x4000BABE
            0x0F, 0xA2,                                             // cpuid
            0xC3                                                    // ret
        };
        // Layout: 0..2 mov rsi,rcx | 3..12 mov rcx,imm64 (imm at 5)
        //         13..22 mov rdi,imm64 (imm at 15) | 23..27 mov eax,imm32 | 28..29 cpuid | 30 ret
        BitConverter.GetBytes(Key).CopyTo(stub, 5);
        BitConverter.GetBytes(SetTrace).CopyTo(stub, 15);

        IntPtr code = VirtualAlloc(IntPtr.Zero, (UIntPtr)stub.Length, 0x3000, 0x40);
        Marshal.Copy(stub, 0, code, stub.Length);

        HypercallFn fn = (HypercallFn)Marshal.GetDelegateForFunctionPointer(code, typeof(HypercallFn));
        ulong status = fn(0, enabled);

        Console.WriteLine("set_trace enabled=" + enabled + " status=" + status);
        return 0;
    }
}
