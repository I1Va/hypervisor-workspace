// Measures what the TSC offsetting is supposed to hide, directly.
//
//   delta = rdtsc; cpuid; rdtsc
//
// Without offsetting this includes the whole VM exit (exit, dispatch, handler,
// entry). With offsetting the guest's counter is frozen for that window and
// advanced by TSC_VISIBLE_COST, so the delta should collapse to a plausible
// constant.
//
// It also prints the cross-core TSC spread, because a per-core offset is itself
// a detection: if the offset accumulates at different rates on different cores,
// two threads pinned to different cores will disagree about the current TSC by
// more than bare metal ever would.
//
// Usage: tscprobe.exe [samples]
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

public static class TscProbe
{
    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentThread();

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetThreadAffinityMask(IntPtr hThread, UIntPtr dwThreadAffinityMask);

    [DllImport("kernel32.dll")]
    static extern int GetCurrentProcessorNumber();

    // rdtsc; cpuid(eax=0); rdtsc -> rax = (end - start)
    //
    // The start value goes in R8, NOT RBX: cpuid overwrites EAX/EBX/ECX/EDX, so
    // saving it in RBX (the first thing that looks free) destroys it and the
    // delta comes out as a random 40-bit number.
    const string Stub =
        "0F 31 " +                          // rdtsc            -> edx:eax
        "48 C1 E2 20 " +                    // shl rdx, 32
        "48 09 D0 " +                       // or  rax, rdx     -> rax = start
        "49 89 C0 " +                       // mov r8, rax      (r8 survives cpuid)
        "31 C0 " +                          // xor eax, eax
        "0F A2 " +                          // cpuid
        "0F 31 " +                          // rdtsc
        "48 C1 E2 20 " +                    // shl rdx, 32
        "48 09 D0 " +                       // or  rax, rdx     -> rax = end
        "4C 29 C0 " +                       // sub rax, r8      -> rax = end - start
        "C3";                               // ret

    // rdtsc; nop; rdtsc -> rax = (end - start). The control: no VM exit, so this
    // is the floor and must be much smaller than the cpuid delta if cpuid exits.
    const string NopStub =
        "0F 31 " +
        "48 C1 E2 20 " +
        "48 09 D0 " +
        "49 89 C0 " +
        "90 " +                             // nop
        "0F 31 " +
        "48 C1 E2 20 " +
        "48 09 D0 " +
        "4C 29 C0 " +
        "C3";

    // rdtsc; lfence; rdtsc -> the reference VMAware's TIMER divides by.
    const string LfenceStub =
        "0F 31 " +
        "48 C1 E2 20 " +
        "48 09 D0 " +
        "49 89 C0 " +
        "0F AE E8 " +                       // lfence
        "0F 31 " +
        "48 C1 E2 20 " +
        "48 09 D0 " +
        "4C 29 C0 " +
        "C3";

    // 2000 cpuid instructions in one stub, timed as a whole.
    //
    // This is the decisive test. A single cpuid delta cannot distinguish "the
    // exit is hidden by the offset" from "the exit is only ~100 ticks", because
    // both land near the same number. Amplifying separates them by orders of
    // magnitude:
    //
    //   offset working   -> 2000 * TSC_VISIBLE_COST  (~240k ticks)
    //   offset not working, real exit -> 2000 * exit cost (millions of ticks)
    //   no exit at all   -> 2000 * native cpuid (~200k ticks)
    //
    // The counter is in R9, NOT ECX: cpuid clobbers EAX/EBX/ECX/EDX, so using
    // ECX as the loop counter makes the loop depend on whatever cpuid returns
    // and it never terminates (measured: a 240 s hang, killed by hand).
    const string LoopStub =
        "0F 31 " +                          // rdtsc
        "48 C1 E2 20 " +                    // shl rdx, 32
        "48 09 D0 " +                       // or  rax, rdx
        "49 89 C0 " +                       // mov r8, rax        (start)
        "41 B9 D0 07 00 00 " +              // mov r9d, 2000      (counter, safe)
        "31 C0 " +                          // xor eax, eax
        "0F A2 " +                          // cpuid              (clobbers eax..edx)
        "41 FF C9 " +                       // dec r9d            (3 bytes)
        "75 F7 " +                          // jnz -9 (back to xor eax,eax)
        "0F 31 " +                          // rdtsc
        "48 C1 E2 20 " +                    // shl rdx, 32
        "48 09 D0 " +                       // or  rax, rdx       (end)
        "4C 29 C0 " +                       // sub rax, r8
        "C3";                               // ret

    static byte[] Parse(string hex)
    {
        string[] p = hex.Split(' ');
        byte[] b = new byte[p.Length];
        for (int i = 0; i < p.Length; i++) b[i] = Convert.ToByte(p[i], 16);
        return b;
    }

    delegate ulong DeltaFn();

    static ulong[] RunHex(int n, string hex)
    {
        byte[] code = Parse(hex);
        IntPtr mem = VirtualAlloc(IntPtr.Zero, (UIntPtr)code.Length, 0x3000, 0x40);
        Marshal.Copy(code, 0, mem, code.Length);
        DeltaFn fn = (DeltaFn)Marshal.GetDelegateForFunctionPointer(mem, typeof(DeltaFn));

        ulong[] s = new ulong[n];
        for (int i = 0; i < n; i++) s[i] = fn();
        Array.Sort(s);
        return s;
    }

    static ulong[] RunDelta(int n)
    {
        return RunHex(n, Stub);
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(IntPtr addr, UIntPtr size, uint type, uint protect);

    // Plain rdtsc, for the cross-core comparison.
    const string TscOnly =
        "0F 31 " +
        "48 C1 E2 20 " +
        "48 09 D0 " +
        "C3";

    static ulong ReadTsc()
    {
        byte[] code = Parse(TscOnly);
        IntPtr mem = VirtualAlloc(IntPtr.Zero, (UIntPtr)code.Length, 0x3000, 0x40);
        Marshal.Copy(code, 0, mem, code.Length);
        DeltaFn fn = (DeltaFn)Marshal.GetDelegateForFunctionPointer(mem, typeof(DeltaFn));
        return fn();
    }

    public static int Main(string[] args)
    {
        int n = (args.Length > 0) ? int.Parse(args[0]) : 200;

        Console.WriteLine("cpu=" + GetCurrentProcessorNumber() + " samples=" + n);

        ulong[] s = RunDelta(n);
        Console.WriteLine("cpuid_delta  min=" + s[0] + " p25=" + s[n / 4] + " med=" + s[n / 2] + " max=" + s[n - 1]);

        ulong[] nop = RunHex(n, NopStub);
        Console.WriteLine("nop_delta    min=" + nop[0] + " p25=" + nop[n / 4] + " med=" + nop[n / 2] + " max=" + nop[n - 1]);

        ulong[] lf = RunHex(n, LfenceStub);
        Console.WriteLine("lfence_delta min=" + lf[0] + " p25=" + lf[n / 4] + " med=" + lf[n / 2] + " max=" + lf[n - 1]);

        // The ratio VMAware's TIMER thresholds, computed the same way: cpuid
        // latency over lfence latency, both in TSC ticks.
        double ratio = lf[n / 2] != 0 ? (double)s[n / 2] / (double)lf[n / 2] : 0.0;
        Console.WriteLine("cpuid_lfence_ratio med=" + ratio.ToString("F2"));

        // 2000 cpuid calls, timed as a whole. Reported per-cpuid so it can be
        // compared directly against the single-cpuid delta above.
        ulong[] loop = RunHex(20, LoopStub);
        Console.WriteLine("cpuid_x2000  min=" + loop[0] + " med=" + loop[10] +
                          " per_cpuid=" + (loop[10] / 2000));

        // Cross-core: sample TSC on two different cores as close together as we
        // can and report the difference. On bare metal with a synchronised TSC
        // this is small and stable; a per-core offset makes it grow.
        ulong t0 = ReadTsc();
        int c0 = GetCurrentProcessorNumber();
        Thread.Sleep(50);
        ulong t1 = ReadTsc();
        int c1 = GetCurrentProcessorNumber();
        Console.WriteLine("tsc_wall_50ms=" + (t1 - t0) + " core0=" + c0 + " core1=" + c1);

        return 0;
    }
}
