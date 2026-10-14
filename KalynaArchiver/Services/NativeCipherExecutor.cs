using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Diagnostics;

namespace KalynaArchiver.Services;

// The runtime's persistent worker pool is shared by every native module. The
// caller already owns all CPU permits; children must never acquire new permits.
internal static unsafe class NativeCipherExecutor
{
    private static readonly AsyncLocal<Measurements?> Observer = new();
    internal static IDisposable ObserveForTests(Measurements measurements)
    {
        ArgumentNullException.ThrowIfNull(measurements);
        var scope = new ObservationScope(Observer.Value);
        Observer.Value = measurements;
        return scope;
    }
    private sealed class ObservationScope(Measurements? previous) : IDisposable
    {
        private bool _disposed;
        public void Dispose()
        {
            if (_disposed) return;
            Observer.Value = previous;
            _disposed = true;
        }
    }
    // Aggregate public scheduling observations only. This seam has no callback,
    // data/key reference, queue mutation, permit or cancellation authority.
    internal sealed class Measurements
    {
        private readonly object _gate = new();
        private long _batches, _callbacks, _queueTicks, _callbackTicks, _joinTicks;
        private int _active, _peak, _minimumGrant = int.MaxValue, _maximumGrant;
        private int _unavailable;
        internal void Batch(int grant)
        {
            try { lock (_gate) { _batches = Add(_batches, 1); _minimumGrant = Math.Min(_minimumGrant, grant); _maximumGrant = Math.Max(_maximumGrant, grant); } }
            catch { Volatile.Write(ref _unavailable, 1); }
        }
        internal bool Start(long queued)
        {
            try { lock (_gate) { _queueTicks = Add(_queueTicks, Math.Max(0, Stopwatch.GetTimestamp() - queued)); _active++; _peak = Math.Max(_peak, _active); } return true; }
            catch { Volatile.Write(ref _unavailable, 1); return false; }
        }
        internal void Finish(long started)
        {
            try { lock (_gate) { _active--; _callbacks = Add(_callbacks, 1); _callbackTicks = Add(_callbackTicks, Math.Max(0, Stopwatch.GetTimestamp() - started)); } }
            catch { Volatile.Write(ref _unavailable, 1); }
        }
        internal void Joined(long started)
        {
            try { lock (_gate) _joinTicks = Add(_joinTicks, Math.Max(0, Stopwatch.GetTimestamp() - started)); }
            catch { Volatile.Write(ref _unavailable, 1); }
        }
        private static long Add(long a, long b) => b > long.MaxValue - a ? long.MaxValue : a + b;
        internal SchedulingSnapshot Snapshot()
        {
            lock (_gate) return new SchedulingSnapshot(_batches, _callbacks, _active, _peak,
                _batches == 0 ? 0 : _minimumGrant, _maximumGrant,
                (double)_queueTicks / Stopwatch.Frequency, (double)_callbackTicks / Stopwatch.Frequency,
                (double)_joinTicks / Stopwatch.Frequency, Volatile.Read(ref _unavailable) == 0,
                "Submission-to-callback includes handle allocation, submission and observer locking. Callback intervals overlap; their sums are not operation walltime or CPU time. Join includes useful callback work. No executor callbacks is possible for an inline single-worker native path.");
        }
    }
    internal sealed record SchedulingSnapshot(long batches, long completedCallbacks, int activeCallbacks,
        int peakActiveCallbacks, int minimumGrant, int maximumGrant, double submissionToCallbackSecondsSum,
        double callbackWallSecondsSum, double callerJoinWallSecondsSum, bool observationAvailable, string note);
#if KEEPVAULT_EXECUTOR_TESTING
    [ThreadStatic] internal static int? RejectSubmissionAfterForTests;
    [ThreadStatic] internal static nuint LastDispatchCountForTests;
    internal static Action<nuint>? BeforeWorkerForTests;
    internal static Action<nuint>? AfterWorkerForTests;
    internal static int OutstandingDispatchHandlesForTests;
    internal static int InterruptedWaitsForTests;
    internal static int RejectNextWaitForTests;
    internal static int FailedWaitsForTests;
    internal static int DispatchForTests(nuint count, delegate* unmanaged[Cdecl]<nint, nuint, void> worker, nint context)
        => ((delegate* unmanaged[Cdecl]<nuint, delegate* unmanaged[Cdecl]<nint, nuint, void>, nint, int>)&Execute)(count, worker, context);
#endif
    private static void InvokeWorker(nint callback, nint context, nuint identity)
    {
#if KEEPVAULT_EXECUTOR_TESTING
        BeforeWorkerForTests?.Invoke(identity);
#endif
        try
        {
            using var qos = MacCpuWorkerQos.EnterSynchronousScope();
            ((delegate* unmanaged[Cdecl]<nint, nuint, void>)callback)(context, identity);
        }
        finally
        {
#if KEEPVAULT_EXECUTOR_TESTING
            AfterWorkerForTests?.Invoke(identity);
#endif
        }
    }

    internal static void Install(nint library)
    {
        var register = (delegate* unmanaged[Cdecl]<delegate* unmanaged[Cdecl]<nuint, delegate* unmanaged[Cdecl]<nint, nuint, void>, nint, int>, int>)NativeLibrary.GetExport(library, "keepvault_v13_register_executor");
        if (register(&Execute) != 0) throw new CryptographicException("Native v13 executor registration failed.");
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
    private static int Execute(nuint count, delegate* unmanaged[Cdecl]<nint, nuint, void> worker, nint context)
    {
        if (count == 0 || count > (nuint)Array.MaxLength || worker == null) return 1;
#if KEEPVAULT_EXECUTOR_TESTING
        LastDispatchCountForTests = count;
#endif
        // The .NET PAL can permanently opt its threads out of pthread QoS.
        // On macOS submit synchronous native work to Apple's persistent
        // Utility queue instead. The existing grant bounds submitted jobs;
        // the invoking managed thread waits and does no additional CPU work.
        if (OperatingSystem.IsMacOS()) return ExecuteMac(count, (nint)worker, context);
        Task[]? jobs = null;
        int started = 0, status = 0;
        try
        {
            jobs = new Task[checked((int)count - 1)];
            nint callback = (nint)worker;
            for (int index = 1; index < (int)count; ++index)
            {
                nuint identity = (nuint)index;
#if KEEPVAULT_EXECUTOR_TESTING
                if (started == RejectSubmissionAfterForTests) throw new InvalidOperationException("Injected test scheduling failure.");
#endif
                jobs[started] = Task.Run(() => InvokeWorker(callback, context, identity));
                ++started;
            }
        }
        catch { status = 3; }
        try { InvokeWorker((nint)worker, context, 0); }
        catch { status = 3; }
        // No error, cancellation, or scheduling exception may return a native
        // stack-backed context to its caller while any queued reader is alive.
        for (int index = 0; index < started; ++index)
        {
            Task job = jobs![index];
            for (;;)
            {
                try { job.GetAwaiter().GetResult(); break; }
                catch
                {
                    status = 3;
                    if (job.IsCompleted) break;
                    Thread.Yield();
                }
            }
            jobs[index] = null!;
        }
        return status;
    }

    private sealed class MacBatch(nint callback, nint context, Measurements? measurements)
    {
        // The submission sentinel prevents completion while a fast first job
        // finishes before the remaining jobs have been enqueued.
        internal readonly TaskCompletionSource Completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _remaining = 1;
        internal readonly nint Callback = callback;
        internal readonly nint Context = context;
        internal readonly Measurements? Measurements = measurements;
        internal int Status;
        internal void AddWorker() => Interlocked.Increment(ref _remaining);
        internal void Signal()
        {
            if (Interlocked.Decrement(ref _remaining) == 0) Completion.TrySetResult();
        }
    }
    private sealed record MacJob(MacBatch Batch, nuint Identity, long Queued);

    private static int ExecuteMac(nuint count, nint callback, nint context)
    {
        try
        {
            nint queue = dispatch_get_global_queue(0x11, 0); // QOS_CLASS_UTILITY
            if (queue == 0) return 3;
            Measurements? measurements = Observer.Value;
            measurements?.Batch(checked((int)count));
            var batch = new MacBatch(callback, context, measurements);
            try
            {
                for (nuint index = 0; index < count; ++index)
                {
#if KEEPVAULT_EXECUTOR_TESTING
                    if (index > 0 && (int)index - 1 == RejectSubmissionAfterForTests)
                        throw new InvalidOperationException("Injected test scheduling failure.");
#endif
                    GCHandle handle = GCHandle.Alloc(new MacJob(batch, index,
                        measurements is null ? 0 : Stopwatch.GetTimestamp()));
                    bool counted = false;
                    try
                    {
                        batch.AddWorker();
                        counted = true;
#if KEEPVAULT_EXECUTOR_TESTING
                        Interlocked.Increment(ref OutstandingDispatchHandlesForTests);
#endif
                        dispatch_async_f(queue, GCHandle.ToIntPtr(handle), &MacWorker);
                        // Ownership transfers to the callback. dispatch_async_f
                        // has no fallible return after accepting this job.
                    }
                    catch
                    {
                        handle.Free();
                        if (counted)
                        {
#if KEEPVAULT_EXECUTOR_TESTING
                            Interlocked.Decrement(ref OutstandingDispatchHandlesForTests);
#endif
                            batch.Signal();
                        }
                        throw;
                    }
                }
            }
            catch { Interlocked.Exchange(ref batch.Status, 3); }
            finally { batch.Signal(); }
            // No cancellation or submission exception may release the native
            // stack-backed context while an accepted callback can still use it.
            long joinStarted = measurements is null ? 0 : Stopwatch.GetTimestamp();
            while (!batch.Completion.Task.IsCompleted)
            {
                try
                {
#if KEEPVAULT_EXECUTOR_TESTING
                    if (Interlocked.Exchange(ref RejectNextWaitForTests, 0) != 0)
                        throw new OutOfMemoryException("Injected wait failure.");
#endif
                    batch.Completion.Task.GetAwaiter().GetResult();
                }
                catch (Exception error)
                {
                    Interlocked.Exchange(ref batch.Status, 3);
#if KEEPVAULT_EXECUTOR_TESTING
                    if (error is ThreadInterruptedException) Interlocked.Increment(ref InterruptedWaitsForTests);
                    Interlocked.Increment(ref FailedWaitsForTests);
#else
                    _ = error;
#endif
                    Thread.Yield();
                }
            }
            measurements?.Joined(joinStarted);
            return batch.Status;
        }
        catch { return 3; }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
    private static void MacWorker(nint argument)
    {
        GCHandle handle = GCHandle.FromIntPtr(argument);
        MacJob job = (MacJob)handle.Target!;
        handle.Free();
#if KEEPVAULT_EXECUTOR_TESTING
        Interlocked.Decrement(ref OutstandingDispatchHandlesForTests);
#endif
        Measurements? measurements = job.Batch.Measurements;
        long started = measurements is null ? 0 : Stopwatch.GetTimestamp();
        bool observed = false;
        try
        {
            observed = measurements?.Start(job.Queued) == true;
            InvokeWorker(job.Batch.Callback, job.Batch.Context, job.Identity);
        }
        catch { Interlocked.Exchange(ref job.Batch.Status, 3); }
        finally
        {
            if (observed) measurements?.Finish(started);
            job.Batch.Signal();
        }
    }

    [DllImport("/usr/lib/libSystem.B.dylib")]
    private static extern nint dispatch_get_global_queue(nint identifier, nuint flags);
    [DllImport("/usr/lib/libSystem.B.dylib")]
    private static extern void dispatch_async_f(nint queue, nint context, delegate* unmanaged[Cdecl]<nint, void> work);
}
