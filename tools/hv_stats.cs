// Reads the hypervisor's runtime counters (HYPERCALL_GET_STATS) and prints the
// exit-reason histogram.
//
// This exists because a timing measurement cannot distinguish "the exit is hidden
// by TSC offsetting" from "there is no exit to hide". The exit count settles it:
// if CPUID is not in the histogram, the CPUID handler is not running and no
// amount of offsetting will change what the guest measures.
//
// Usage: hv_stats.exe
using System;
using System.Runtime.InteropServices;

public static class HvStats
{
    const ulong Key = 0xBABEB8CEC88D3;
    const uint Leaf = 0x4000BABE;
    const ulong GetStats = 0x3d5b8a17c204f;

    [StructLayout(LayoutKind.Sequential)]
    public struct Stats
    {
        public uint Size;
        public uint Version;
        public ulong GuestProgress;
        public ulong TotalExits;
        public ulong ExitsSinceGuest;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 72)]
        public ulong[] ExitReason;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
        public ulong[] CoreExits;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
        public ulong[] CoreLastGuestTick;
        public ulong PendingDebugQueued;
        public ulong Dr6StatusPublished;
        public ulong Hypercalls;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(IntPtr addr, UIntPtr size, uint type, uint protect);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate ulong StatsFn(ulong dest, ulong size);

    static readonly string[] ReasonNames = BuildNames();

    static string[] BuildNames()
    {
        var n = new string[72];
        for (int i = 0; i < n.Length; i++) n[i] = "reason" + i;
        n[0] = "EXCEPTION_OR_NMI";
        n[10] = "CPUID";
        n[12] = "HLT";
        n[16] = "RDTSC";
        n[18] = "VMCALL";
        n[28] = "CR_ACCESS";
        n[31] = "MSR_READ";
        n[32] = "MSR_WRITE";
        n[48] = "EPT_VIOLATION";
        n[49] = "EPT_MISCONFIG";
        n[51] = "RDTSCP";
        n[52] = "PREEMPTION_TIMER";
        n[55] = "XSETBV";
        n[7] = "NMI_WINDOW";
        return n;
    }

    public static int Main(string[] args)
    {
        int size = Marshal.SizeOf(typeof(Stats));
        IntPtr buf = VirtualAlloc(IntPtr.Zero, (UIntPtr)size, 0x3000, 0x04);
        if (buf == IntPtr.Zero)
        {
            Console.WriteLine("VirtualAlloc failed");
            return 1;
        }
        // Zero it so unset fields are unambiguous.
        for (int i = 0; i < size; i++) Marshal.WriteByte(buf, i, 0);

        // Stub: rcx = dest, rdx = size (Windows x64 ABI).
        // Hypercall wants arg1 in RSI and arg2 in RDX, so dest moves rcx -> rsi.
        // Size is already in RDX, so it needs no move at all.
        byte[] stub = new byte[] {
            0x48, 0x89, 0xCE,                   // mov rsi, rcx   (dest -> arg1)
            0x48, 0xB9, 0,0,0,0,0,0,0,0,        // mov rcx, key
            0x48, 0xBF, 0,0,0,0,0,0,0,0,        // mov rdi, call number
            0xB8, 0xBE, 0xBA, 0x00, 0x40,       // mov eax, 0x4000BABE
            0x0F, 0xA2,                         // cpuid
            0xC3                                // ret
        };
        BitConverter.GetBytes(Key).CopyTo(stub, 5);
        BitConverter.GetBytes(GetStats).CopyTo(stub, 15);

        IntPtr code = VirtualAlloc(IntPtr.Zero, (UIntPtr)stub.Length, 0x3000, 0x40);
        Marshal.Copy(stub, 0, code, stub.Length);

        StatsFn fn = (StatsFn)Marshal.GetDelegateForFunctionPointer(code, typeof(StatsFn));
        ulong written = fn((ulong)buf.ToInt64(), (ulong)size);

        Stats s = (Stats)Marshal.PtrToStructure(buf, typeof(Stats));

        Console.WriteLine("returned=" + written + " size=" + s.Size + " version=" + s.Version);
        Console.WriteLine("total_exits=" + s.TotalExits + " guest_progress=" + s.GuestProgress +
                          " since_guest=" + s.ExitsSinceGuest + " hypercalls=" + s.Hypercalls);
        Console.WriteLine("pending_debug=" + s.PendingDebugQueued + " dr6_published=" + s.Dr6StatusPublished);

        for (int i = 0; i < 72; i++)
        {
            if (s.ExitReason != null && i < s.ExitReason.Length && s.ExitReason[i] != 0)
                Console.WriteLine("  [" + i.ToString().PadLeft(2) + "] " +
                                  ReasonNames[i].PadRight(20) + s.ExitReason[i]);
        }

        for (int i = 0; i < 64; i++)
        {
            if (s.CoreExits != null && i < s.CoreExits.Length && s.CoreExits[i] != 0)
                Console.WriteLine("  core apic " + i + " exits=" + s.CoreExits[i]);
        }

        return 0;
    }
}
