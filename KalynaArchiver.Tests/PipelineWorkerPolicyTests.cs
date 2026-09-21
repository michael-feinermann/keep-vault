using System.Reflection;
using KalynaArchiver.Services;

// Managed scheduling tests only. No cipher, key derivation, file payload or native DLL is used.
internal static class PipelineWorkerPolicyTests
{
    public static async Task RunAsync()
    {
        await RunPolicyAsync();
        await RunNativeConcurrencyAsync();
        await RunOverrideScopesAsync();
    }

    public static Task RunPolicyAsync()
    {
        (int CpuCount, int ExpectedSlots)[] cases =
        [
            (int.MinValue, 1), (-1, 1), (0, 1), (1, 1), (2, 1), (4, 1), (8, 1),
            (16, 1), (32, 1), (63, 1), (64, 1), (65, 1), (96, 1), (127, 1),
            (128, 2), (129, 2), (191, 2), (192, 3), (255, 3), (256, 4),
            (512, 8), (1024, 16), (4095, 63), (4096, 64), (int.MaxValue, 64),
        ];
        // Two locked 16 MiB buffers per slot, small metadata allowance, and a 1/16 memory budget.
        const long bytesPerSlotBudget = 16L * (32L * 1024 * 1024 + 512);
        foreach ((int cpus, int expected) in cases)
        {
            int actual = KalynaContainerService.CalculatePipelineWorkerCount(cpus, long.MaxValue);
            Require(actual == expected, $"Windows CPU policy selected {actual} slots for {cpus} CPUs; expected {expected}.");
            long effectiveCpus = Math.Max(1, cpus);
            Require(actual * Math.Min(effectiveCpus, 64) <= effectiveCpus,
                "The Windows outer pipeline oversubscribed whole native teams.");
            int nativeTeams = KalynaContainerService.CalculateNativeTransformConcurrency(cpus);
            Require(nativeTeams is >= 1 and <= 64
                && nativeTeams * Math.Min(effectiveCpus, 64) <= 2L * effectiveCpus,
                "The independent global native-team bound overflowed or exceeded its CPU budget.");

            foreach (long memory in new[] { long.MinValue, -1L, 0L, 1L, 256L * 1024 * 1024 })
            {
                Require(KalynaContainerService.CalculatePipelineWorkerCount(cpus, memory) == 1,
                    "Unknown, invalid or small available memory must conservatively select one slot.");
            }
            for (int slots = 1; slots <= 64; slots++)
            {
                long boundary = bytesPerSlotBudget * slots;
                Require(KalynaContainerService.CalculatePipelineWorkerCount(cpus, boundary) == Math.Min(expected, slots),
                    "The memory budget did not admit exactly the affordable whole slots.");
                Require(KalynaContainerService.CalculatePipelineWorkerCount(cpus, boundary - 1) == Math.Min(expected, Math.Max(1, slots - 1)),
                    "The memory budget rounded up into an unaffordable slot.");
            }
        }
        return Task.CompletedTask;
    }

    public static async Task RunNativeConcurrencyAsync()
    {
        int limit = KalynaContainerService.CalculateNativeTransformConcurrency(Environment.ProcessorCount);
        using var release = new ManualResetEventSlim();
        using var cancellation = new CancellationTokenSource();
        var occupied = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int active = 0, started = 0, finished = 0, queuedStarted = 0;
        Task running = KalynaContainerService.RunBoundedChunkWorkersForTestsAsync(limit, _ =>
        {
            int current = Interlocked.Increment(ref active);
            Interlocked.Increment(ref started);
            try
            {
                Require(current <= limit, "Active native teams exceeded their global concurrency bound.");
                if (current == limit) occupied.TrySetResult();
                Require(release.Wait(TimeSpan.FromSeconds(15)), "Blocked test workers were not released.");
            }
            finally
            {
                Interlocked.Decrement(ref active);
                Interlocked.Increment(ref finished);
            }
        }, cancellation.Token);
        Task queued = Task.CompletedTask;
        bool cancellationObserved = false;
        try
        {
            await occupied.Task.WaitAsync(TimeSpan.FromSeconds(10));
            // A second operation must share the same bound, not obtain a new team budget.
            queued = KalynaContainerService.RunBoundedChunkWorkersForTestsAsync(3,
                _ => Interlocked.Increment(ref queuedStarted), cancellation.Token);
            await Task.Delay(100);
            Require(Volatile.Read(ref queuedStarted) == 0 && !queued.IsCompleted,
                "A separate container operation bypassed the occupied global native-team gate.");
            cancellation.Cancel();
            Require(!running.IsCompleted,
                "Cancellation returned before already-running callbacks relinquished their buffers.");
        }
        finally
        {
            cancellation.Cancel();
            release.Set();
            try { await Task.WhenAll(running, queued).WaitAsync(TimeSpan.FromSeconds(15)); }
            catch (Exception failure) when (cancellation.IsCancellationRequested && IsCancellationOnly(failure))
            {
                cancellationObserved = true;
            }
        }
        Require(cancellationObserved, "Queued native work did not observe cancellation.");
        Require(active == 0 && finished == started && started == limit && queuedStarted == 0,
            "Cancellation failed to join active work or allowed canceled queued work to execute.");

        // Reuse every permit together. A one-at-a-time probe would miss partial permit leaks.
        using var reuseRelease = new ManualResetEventSlim();
        using var reuseCancellation = new CancellationTokenSource();
        var allReused = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int reused = 0;
        Task reuse = KalynaContainerService.RunBoundedChunkWorkersForTestsAsync(limit, _ =>
        {
            if (Interlocked.Increment(ref reused) == limit) allReused.TrySetResult();
            Require(reuseRelease.Wait(TimeSpan.FromSeconds(15)), "Permit reuse workers were not released.");
        }, reuseCancellation.Token);
        try { await allReused.Task.WaitAsync(TimeSpan.FromSeconds(10)); }
        finally
        {
            reuseRelease.Set();
            reuseCancellation.Cancel();
            try { await reuse.WaitAsync(TimeSpan.FromSeconds(15)); }
            catch (Exception failure) when (reuseCancellation.IsCancellationRequested && IsCancellationOnly(failure)) { }
        }
        Require(reused == limit, "At least one native-team permit leaked after cancellation.");
    }

    public static async Task RunOverrideScopesAsync()
    {
        PropertyInfo effectiveProperty = typeof(KalynaContainerService).GetProperty(
            "PipelineWorkerCount", BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new InvalidOperationException("The effective pipeline-worker policy is unavailable.");
        int Effective() => (int)(effectiveProperty.GetValue(null)
            ?? throw new InvalidOperationException("The effective pipeline-worker policy returned null."));
        void RequireProduction() => Require(Effective() == KalynaContainerService.ProductionPipelineWorkerCount,
            "A test override escaped its scope into the production policy.");
        RequireProduction();
        foreach (int invalid in new[] { int.MinValue, -1, 0, 65, int.MaxValue })
        {
            bool rejected = false;
            try { using IDisposable unexpected = KalynaContainerService.UsePipelineWorkerCountForTests(invalid); }
            catch (ArgumentOutOfRangeException) { rejected = true; }
            Require(rejected, $"Invalid worker override {invalid} was accepted.");
            RequireProduction();
        }

        using (IDisposable outer = KalynaContainerService.UsePipelineWorkerCountForTests(8))
        {
            Require(Effective() == 8, "The outer test override was ignored.");
            IDisposable inner = KalynaContainerService.UsePipelineWorkerCountForTests(3);
            try { Require(Effective() == 3, "The nested test override was ignored."); }
            finally { inner.Dispose(); }
            inner.Dispose();
            Require(Effective() == 8, "Disposing a nested override twice lost the outer scope.");
            try
            {
                using IDisposable failed = KalynaContainerService.UsePipelineWorkerCountForTests(7);
                throw new ScopeFailure();
            }
            catch (ScopeFailure) { }
            Require(Effective() == 8, "An exception leaked the nested override.");

            var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var childRelease = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            Task child = Task.Run(async () =>
            {
                Require(Effective() == 8, "An asynchronous child did not inherit its parent scope.");
                using IDisposable childOverride = KalynaContainerService.UsePipelineWorkerCountForTests(5);
                entered.TrySetResult();
                await childRelease.Task.WaitAsync(TimeSpan.FromSeconds(15));
                Require(Effective() == 5, "The asynchronous child lost its own override after resuming.");
            });
            try
            {
                await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
                Require(Effective() == 8, "The child's test override changed the concurrent parent flow.");
            }
            finally
            {
                childRelease.TrySetResult();
                await child.WaitAsync(TimeSpan.FromSeconds(15));
            }
            Require(Effective() == 8, "Finishing a child changed the parent's override.");
        }
        RequireProduction();
    }

    private static bool IsCancellationOnly(Exception failure) =>
        failure is OperationCanceledException
        || failure is AggregateException aggregate
            && aggregate.Flatten().InnerExceptions.Count > 0
            && aggregate.Flatten().InnerExceptions.All(error => error is OperationCanceledException);

    private sealed class ScopeFailure : Exception { }

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
}
