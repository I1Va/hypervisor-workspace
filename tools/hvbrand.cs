// Enables or disables the hypervisor's CPUID branding at runtime.
//
// Usage: hvbrand.exe 0|1
//   1 = advertise a Hyper-V root partition (hypervisor bit + Hyper-V leaves)
//   0 = stop advertising anything (the default)
//
// Only does the hypercall. Reading the resulting CPUID state is done by the
// existing hvx.exe probe, which already prints every leaf this affects - keeping
// one fragile hand-assembled CPUID stub in the tree instead of two.
//
// ABI: CPUID leaf 0x4000BABE, key in RCX, call number in RDI, arg1 in RSI.
// SET_BRAND = 0x2e7c4b91a8306
using System;
using System.Runtime.InteropServices;

public static class HvBrand
{
    const ulong Key = 0xBABEB8CEC88D3;
    const ulong SetBrand = 0x2e7c4b91a8306;

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(IntPtr addr, UIntPtr size, uint type, uint protect);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate ulong HypercallFn(ulong arg1, ulong arg2);

    static ulong Call(ulong arg1, ulong arg2)
    {
        byte[] stub = new byte[] {
            0x48, 0x89, 0xCE,                    // mov rsi, rcx
            0x48, 0xB9, 0,0,0,0,0,0,0,0,         // mov rcx, key   (imm at 5)
            0x48, 0xBF, 0,0,0,0,0,0,0,0,         // mov rdi, call  (imm at 15)
            0xB8, 0xBE, 0xBA, 0x00, 0x40,        // mov eax, leaf
            0x0F, 0xA2,                          // cpuid
            0xC3                                 // ret
        };
        BitConverter.GetBytes(Key).CopyTo(stub, 5);
        BitConverter.GetBytes(SetBrand).CopyTo(stub, 15);

        IntPtr code = VirtualAlloc(IntPtr.Zero, (UIntPtr)stub.Length, 0x3000, 0x40);
        Marshal.Copy(stub, 0, code, stub.Length);
        HypercallFn fn = (HypercallFn)Marshal.GetDelegateForFunctionPointer(code, typeof(HypercallFn));
        return fn(arg1, arg2);
    }

    public static int Main(string[] args)
    {
        ulong enable = (args.Length > 0 && args[0] != "0") ? 1UL : 0UL;
        long rc = (long)Call(enable, 0);
        Console.WriteLine("set_brand=" + enable + " rc=" + rc);
        return rc == 0 ? 0 : 1;
    }
}
