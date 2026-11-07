// Reads back the TSC-offsetting state, packed into the hypercall's return value.
//
// The structured version (writing a struct to a guest buffer) came back all
// zeros including compile-time constants, so the answer is packed into RAX:
//
//   bit 0      enabled
//   bit 1      bit 3 of the live VMCS processor-based control
//   bits 15:8  low byte of that control dword
//   bits 23:16 number of cores with a non-zero offset
//
// Usage: hv_tscstate.exe
using System;
using System.Runtime.InteropServices;

public static class HvTscState
{
    const ulong Key = 0xBABEB8CEC88D3;
    const ulong GetTscOffset = 0x1c4f7a2e9b856;

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(IntPtr addr, UIntPtr size, uint type, uint protect);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate ulong StateFn(ulong unused, ulong unused2);

    public static int Main(string[] args)
    {
        // Two-argument shape is the one measured working on this guest; the
        // extra argument is ignored by the stub.
        byte[] stub = new byte[] {
            0x48, 0x89, 0xCE,                   // mov rsi, rcx
            0x48, 0xB9, 0,0,0,0,0,0,0,0,        // mov rcx, key
            0x48, 0xBF, 0,0,0,0,0,0,0,0,        // mov rdi, call number
            0xB8, 0xBE, 0xBA, 0x00, 0x40,       // mov eax, 0x4000BABE
            0x0F, 0xA2,                         // cpuid
            0xC3                                // ret
        };
        BitConverter.GetBytes(Key).CopyTo(stub, 5);
        BitConverter.GetBytes(GetTscOffset).CopyTo(stub, 15);

        IntPtr code = VirtualAlloc(IntPtr.Zero, (UIntPtr)stub.Length, 0x3000, 0x40);
        Marshal.Copy(stub, 0, code, stub.Length);

        StateFn fn = (StateFn)Marshal.GetDelegateForFunctionPointer(code, typeof(StateFn));
        ulong raw = fn(0, 0);

        Console.WriteLine("raw=0x" + raw.ToString("X"));
        Console.WriteLine("enabled=" + (raw & 1) +
                          " vmcs_control_bit3=" + ((raw >> 1) & 1) +
                          " control_low_byte=0x" + (((raw >> 8) & 0xFF)).ToString("X2") +
                          " cores_with_offset=" + ((raw >> 16) & 0xFF));
        return 0;
    }
}
