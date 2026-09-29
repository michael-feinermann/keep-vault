using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text.Json;
using KalynaArchiver.Services;

internal static unsafe class QosChecks
{
    private static int checks;
    private static readonly ManualResetEventSlim blockedWorkerEntered = new(false);
    private static readonly ManualResetEventSlim releaseBlockedWorker = new(false);
    private static void Require(bool ok, string label) { if (!ok) throw new Exception(label); ++checks; }
    [DllImport("/usr/lib/libSystem.B.dylib")] private static extern nuint pthread_self();
    [DllImport("/usr/lib/libSystem.B.dylib")] private static extern int pthread_main_np();
    [DllImport("/usr/lib/libSystem.B.dylib")] private static extern int pthread_get_qos_class_np(nuint thread, out uint qos, out int priority);
    [DllImport("/usr/lib/libSystem.B.dylib")] private static extern int pthread_set_qos_class_self_np(uint qos, int priority);

    private static (uint Qos, int Priority) State()
    {
        Require(pthread_get_qos_class_np(pthread_self(), out uint qos, out int priority) == 0, "query");
        return (qos, priority);
    }
    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void Probe(nint context, nuint index)
    {
        int* values = (int*)context;
        int result = pthread_get_qos_class_np(pthread_self(), out uint qos, out int relative);
        values[index] = result == 0 && qos == 0x11 && relative == 0 ? 1 : -1;
    }
    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void BlockingProbe(nint context, nuint index)
    {
        blockedWorkerEntered.Set();
        releaseBlockedWorker.Wait();
        ((int*)context)[index] = 1;
    }
    private static Exception? scopeFailure;
    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void ScopeProbe(nint context, nuint index)
    {
        var original = State();
        try
        {
                foreach (uint qos in new uint[] { 0x15, 0x19, 0x21 })
                foreach (int priority in new[] { 0, -5 })
                {
                    var beforeSet = State();
                    int setStatus = pthread_set_qos_class_self_np(qos, priority);
                    Require(setStatus == 0, $"set test class {qos:X}/{priority}, previous={beforeSet}, status={setStatus}");
                    {
                        using var outer = MacCpuWorkerQos.EnterSynchronousScope();
                        Require(State() == (0x11u, 0), "utility inside");
                        { using var inner = MacCpuWorkerQos.EnterSynchronousScope(); Require(State() == (0x11u, 0), "nested utility"); }
                        Require(State() == (0x11u, 0), "outer after nested");
                    }
                    Require(State() == (qos, priority), "exact class and relative restore");
                    try { using var scope = MacCpuWorkerQos.EnterSynchronousScope(); throw new InvalidOperationException("synthetic"); }
                    catch (InvalidOperationException e) when (e.Message == "synthetic") { }
                    Require(State() == (qos, priority), "exception restore");
                }
                foreach (uint qos in new uint[] { 0x11, 0x09 })
                {
                    Require(pthread_set_qos_class_self_np(qos, -5) == 0, "set lower priority");
                    { using var scope = MacCpuWorkerQos.EnterSynchronousScope(); Require(State() == (qos, -5), "lower preserved"); }
                    Require(State() == (qos, -5), "lower preserved after");
                }
        }
        catch (Exception failure) { scopeFailure = failure; }
        finally
        {
            if (pthread_set_qos_class_self_np(original.Qos, original.Priority) != 0)
                scopeFailure = new Exception("scope probe failed to restore its GCD thread");
        }
    }

    internal static void Run()
    {
        Require(OperatingSystem.IsMacOS() && pthread_main_np() != 0, "macOS main thread");
        var mainState = State();
        { using var scope = MacCpuWorkerQos.EnterSynchronousScope(); Require(State() == mainState, "main unchanged inside"); }
        Require(State() == mainState, "main unchanged after");
        Exception? failure = null;
        var worker = new Thread(() =>
        {
            try
            {
                var runtimeState = State();
                int runtimeSetStatus = pthread_set_qos_class_self_np(0x15, 0);
                Require(runtimeState == (0u, 0) && runtimeSetStatus == 1, "observed PAL opts out of QoS with EPERM");
                { using var scope = MacCpuWorkerQos.EnterSynchronousScope(); Require(State() == runtimeState, "runtime QoS unchanged"); }
                Require(NativeCipherExecutor.DispatchForTests(1, &ScopeProbe, 0) == 0, "scope probe dispatch");
                if (scopeFailure is not null) throw scopeFailure;
                foreach (int count in new[] { 1, 3, 32, 128, 4096 })
                {
                    int[] values = new int[count];
                    var before = new (uint Qos, int Relative)[count];
                    var after = new (uint Qos, int Relative)[count];
                    NativeCipherExecutor.BeforeWorkerForTests = index =>
                    {
                        pthread_get_qos_class_np(pthread_self(), out uint q, out int p);
                        before[index] = (q, p);
                    };
                    NativeCipherExecutor.AfterWorkerForTests = index =>
                    {
                        pthread_get_qos_class_np(pthread_self(), out uint q, out int p);
                        after[index] = (q, p);
                    };
                    fixed (int* pointer = values) Require(NativeCipherExecutor.DispatchForTests((nuint)count, &Probe, (nint)pointer) == 0, "dispatch status");
                    Require(values.All(value => value == 1), "every real callback has utility");
                    Require(NativeCipherExecutor.OutstandingDispatchHandlesForTests == 0, "no retained GCHandles");
                    Require(before.SequenceEqual(after), "each pool and caller thread exactly restored before return");
                    NativeCipherExecutor.BeforeWorkerForTests = null;
                    NativeCipherExecutor.AfterWorkerForTests = null;
                    Require(State() == runtimeState, "caller restored after dispatch");
                }
                foreach (int failAfter in new[] { 0, 1, 2, 7 })
                {
                    int[] values = new int[16];
                    NativeCipherExecutor.RejectSubmissionAfterForTests = failAfter;
                    try { fixed (int* pointer = values) Require(NativeCipherExecutor.DispatchForTests(16, &Probe, (nint)pointer) == 3, "injected status"); }
                    finally { NativeCipherExecutor.RejectSubmissionAfterForTests = null; }
                    Require(values.Take(failAfter + 1).All(value => value == 1) && values.Skip(failAfter + 1).All(value => value == 0), "submitted callbacks joined with utility");
                    Require(State() == runtimeState, "caller restored after partial scheduling");
                }
                int[] failedValues = new int[16];
                NativeCipherExecutor.BeforeWorkerForTests = index => { if (index == 1) throw new Exception("synthetic worker failure"); };
                try { fixed (int* pointer = failedValues) Require(NativeCipherExecutor.DispatchForTests(16, &Probe, (nint)pointer) == 3, "worker failure status"); }
                finally { NativeCipherExecutor.BeforeWorkerForTests = null; }
                Require(failedValues.Where((value, index) => index != 1).All(value => value == 1) && failedValues[1] == 0, "worker failure joined all other callbacks");
                Require(NativeCipherExecutor.OutstandingDispatchHandlesForTests == 0, "no retained handles after failure");

            }
            catch (Exception ex) { failure = ex; }
        });
        worker.Start(); worker.Join();
        if (failure is not null) throw failure;
        int interruptedStatus = 99;
        int[] interruptedValues = new int[3];
        var interruptedCaller = new Thread(() =>
        {
            fixed (int* pointer = interruptedValues)
                interruptedStatus = NativeCipherExecutor.DispatchForTests(3, &BlockingProbe, (nint)pointer);
        });
        interruptedCaller.Start();
        try
        {
            Require(blockedWorkerEntered.Wait(TimeSpan.FromSeconds(10)), "blocking callback entered");
            interruptedCaller.Interrupt();
            Require(SpinWait.SpinUntil(() => Volatile.Read(ref NativeCipherExecutor.InterruptedWaitsForTests) == 1, TimeSpan.FromSeconds(10)), "interrupted wait observed");
            Require(interruptedCaller.IsAlive && Volatile.Read(ref interruptedStatus) == 99, "interruption did not release a live native context");
        }
        finally { releaseBlockedWorker.Set(); interruptedCaller.Join(); }
        Require(interruptedStatus == 3 && interruptedValues.All(value => value == 1), "all callbacks joined after interrupted wait");
        Require(NativeCipherExecutor.OutstandingDispatchHandlesForTests == 0, "all interruption handles released");
        blockedWorkerEntered.Reset(); releaseBlockedWorker.Reset();
        int failedWaitStatus = 99;
        int[] failedWaitValues = new int[3];
        NativeCipherExecutor.RejectNextWaitForTests = 1;
        var failedWaitCaller = new Thread(() =>
        {
            fixed (int* pointer = failedWaitValues)
                failedWaitStatus = NativeCipherExecutor.DispatchForTests(3, &BlockingProbe, (nint)pointer);
        });
        failedWaitCaller.Start();
        try
        {
            Require(blockedWorkerEntered.Wait(TimeSpan.FromSeconds(10)), "callback entered before injected wait failure");
            Require(SpinWait.SpinUntil(() => Volatile.Read(ref NativeCipherExecutor.FailedWaitsForTests) == 2, TimeSpan.FromSeconds(10)), "injected non-interruption wait failure observed");
            Require(failedWaitCaller.IsAlive && Volatile.Read(ref failedWaitStatus) == 99, "failed wait retained live native context");
        }
        finally { releaseBlockedWorker.Set(); failedWaitCaller.Join(); }
        Require(failedWaitStatus == 3 && failedWaitValues.All(value => value == 1), "all callbacks joined after injected wait failure");
        Require(NativeCipherExecutor.OutstandingDispatchHandlesForTests == 0, "all wait-failure handles released");
        Console.WriteLine(JsonSerializer.Serialize(new { status = "PASS", checks, scope = "actual managed QoS and executor sources; real native QoS queries; main/background/unspecified preservation, nested and exception restore, joined scheduling failures" }));
    }
}
