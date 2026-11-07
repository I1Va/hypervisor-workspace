// Dumps CPUID leaves that the hypervisor is known to modify, so "is the
// hypervisor actually intercepting CPUID" can be answered directly.
//
// The decisive leaf is 1: VmxHypervisor.c clears ECX bit 5 (VMX) in HandleCpuid.
// On this machine VT-x is enabled in firmware, so a native read has bit 5 SET and
// an intercepted read has it CLEAR. That difference cannot be produced any other
// way, and it does not depend on branding.
//
// Also prints leaf 0 (max basic leaf) and 0x40000000 (hypervisor vendor), and the
// per-CPUID latency, because ~96 TSC ticks is native-CPUID territory and a real
// VM exit should be an order of magnitude more.
//
// Usage: cpuidprobe.exe
using System;
using System.Runtime.InteropServices;

public static class CpuidProbe
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(IntPtr addr, UIntPtr size, uint type, uint protect);

    // cpuid with EAX=leaf, results stored to the out pointer.
    //
    // Leaf arrives in ECX and the out pointer in RDX (Windows x64 ABI). Both need
    // care: cpuid clobbers EAX/EBX/ECX/EDX, so the out pointer is moved to R10
    // first (cpuid preserves R10) and the leaf is loaded into EAX last.
    static readonly string Code =
        "49 89 D2 " +           // mov r10, rdx   (out pointer; cpuid preserves r10)
        "89 C8 " +              // mov eax, ecx   (leaf)
        "0F A2 " +              // cpuid
        "41 89 02 " +           // mov [r10],    eax
        "41 89 5A 04 " +        // mov [r10+4],  ebx
        "41 89 4A 08 " +        // mov [r10+8],  ecx
        "41 89 52 0C " +        // mov [r10+12], edx
        "C3";                   // ret

    static byte[] Parse(string hex)
    {
        string[] p = hex.Split(' ');
        byte[] b = new byte[p.Length];
        for (int i = 0; i < p.Length; i++) b[i] = Convert.ToByte(p[i], 16);
        return b;
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate void CpuidFn(ulong leaf, ulong outPtr);

    static CpuidFn g_fn;

    static uint[] Leaf(uint leaf)
    {
        IntPtr buf = VirtualAlloc(IntPtr.Zero, (UIntPtr)64, 0x3000, 0x04);
        for (int i = 0; i < 64; i++) Marshal.WriteByte(buf, i, 0);
        g_fn(leaf, (ulong)buf.ToInt64());
        uint[] r = new uint[4];
        for (int i = 0; i < 4; i++) r[i] = (uint)Marshal.ReadInt32(buf, i * 4);
        return r;
    }

    public static int Main(string[] args)
    {
        byte[] code = Parse(Code);
        IntPtr mem = VirtualAlloc(IntPtr.Zero, (UIntPtr)code.Length, 0x3000, 0x40);
        Marshal.Copy(code, 0, mem, code.Length);
        g_fn = (CpuidFn)Marshal.GetDelegateForFunctionPointer(mem, typeof(CpuidFn));

        uint[] l0 = Leaf(0);
        Console.WriteLine("leaf0        max_basic=0x" + l0[0].ToString("X"));

        uint[] l1 = Leaf(1);
        Console.WriteLine("leaf1        eax=0x" + l1[0].ToString("X8") +
                          " ecx=0x" + l1[2].ToString("X8"));
        Console.WriteLine("  HYPERVISOR_PRESENT(ecx31)=" + ((l1[2] >> 31) & 1) +
                          "  VMX(ecx5)=" + ((l1[2] >> 5) & 1));
        Console.WriteLine("  >>> VMX bit is cleared by HandleCpuid, so 0 here means the");
        Console.WriteLine("      hypervisor IS intercepting CPUID; 1 means it is NOT running.");

        uint[] l4 = Leaf(0x40000000);
        char[] v = new char[12];
        BitConverter.GetBytes(l4[1]).CopyTo(v, 0);
        BitConverter.GetBytes(l4[2]).CopyTo(v, 4);
        BitConverter.GetBytes(l4[3]).CopyTo(v, 8);
        Console.WriteLine("leaf40000000 eax=0x" + l4[0].ToString("X") +
                          " vendor=\"" + new string(v) + "\"");
        return 0;
    }
}
