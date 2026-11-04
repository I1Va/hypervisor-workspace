// Reads the hypervisor's RAM log through the CPUID-based hypercall.
//
// Hypercall ABI: CPUID with EAX = 0x4000BABE and RCX = key. Arguments are in
// RDI, RSI, RDX (SysV order) and the result comes back in RAX.
// Reading the log is call 0x2f8a41d0c7b13 with RDI = destination, RSI = capacity.
//
// Uploaded and compiled on the guest with Add-Type because the DTB has no C
// compiler. Deliberately written for the older C# version PowerShell ships.
using System;
using System.IO;
using System.Runtime.InteropServices;

public static class HvLogReader
{
    const ulong Key = 0xBABEB8CEC88D3;
    const uint Leaf = 0x4000BABE;
    const ulong ReadHvLog = 0x2f8a41d0c7b13;

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(IntPtr addr, UIntPtr size, uint type, uint protect);

    public static int Main(string[] args)
    {
        string outPath = (args.Length > 0) ? args[0] : "hvlog.txt";
        int capacity = (args.Length > 1) ? int.Parse(args[1]) : (1024 * 1024);

        byte[] buffer = new byte[capacity];
        GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        try
        {
            ulong dest = (ulong)handle.AddrOfPinnedObject().ToInt64();

            // Hypercall ABI: EAX = leaf, RCX = key, RDI = call number,
            // RSI = arg1 (destination), RDX = arg2 (capacity), result in RAX.
            //
            // The function is entered with dest in RCX and capacity in RDX
            // (Windows x64 calling convention: rcx, rdx), so move them into
            // the hypercall's registers first, then set key/call/leaf.
            byte[] stub = new byte[] {
                0x48, 0x89, 0xCE,                                           // mov rsi, rcx  (dest -> arg1)
                0x48, 0x89, 0xD0,                                           // mov rax, rdx  (capacity)
                0x48, 0x89, 0xC2,                                           // mov rdx, rax  (capacity -> arg2)
                0x48, 0xB9, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,     // mov rcx, key
                0x48, 0xBF, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,     // mov rdi, call number
                0xB8, 0xBE, 0xBA, 0x00, 0x40,                               // mov eax, 0x4000BABE
                0x0F, 0xA2,                                                 // cpuid
                0xC3                                                        // ret
            };
            // Byte layout (verified by count):
            //   0..2   mov rsi, rcx
            //   3..5   mov rax, rdx
            //   6..8   mov rdx, rax
            //   9..18  mov rcx, imm64   -> immediate at offset 11
            //  19..28  mov rdi, imm64   -> immediate at offset 21
            //  29..33  mov eax, imm32   -> immediate at offset 30
            //  34..35  cpuid
            //  36      ret
            BitConverter.GetBytes(Key).CopyTo(stub, 11);
            BitConverter.GetBytes(ReadHvLog).CopyTo(stub, 21);
            return Run(stub, buffer, capacity, dest, outPath);
        }
        finally
        {
            handle.Free();
        }
    }

    static int Run(byte[] stub, byte[] buffer, int capacity, ulong dest, string outPath)
    {
        IntPtr code = VirtualAlloc(IntPtr.Zero, (UIntPtr)stub.Length, 0x3000, 0x40);
        Marshal.Copy(stub, 0, code, stub.Length);

        HypercallFn fn = (HypercallFn)Marshal.GetDelegateForFunctionPointer(code, typeof(HypercallFn));
        ulong copied = fn(dest, (ulong)capacity);

        int length = (int)Math.Min((ulong)capacity, copied);
        byte[] result = new byte[length];
        Array.Copy(buffer, result, length);
        File.WriteAllBytes(outPath, result);
        Console.WriteLine("copied=" + copied + " written=" + length);
        return 0;
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate ulong HypercallFn(ulong dest, ulong capacity);
}
