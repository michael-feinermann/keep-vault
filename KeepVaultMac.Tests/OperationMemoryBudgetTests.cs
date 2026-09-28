using KalynaArchiver.Services;

internal static class OperationMemoryBudgetTests
{
    internal static IReadOnlyList<TestCase> Tests =>
    [
        new("resources.shared-memory-budget", "nested reuse, aggregate contention, cancellation and live entropy accounting", RunAsync, TestResource.ProcessGlobal, "Resources"),
        new("resources.shared-runtime-budget", "finite wall time, parent/child CPU time and byte-progress stall deadlines", RuntimeAsync, TestResource.Light, "Resources"),
    ];

    private static Task RuntimeAsync()
    {
        string path = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var policy = new ArchiveOperationPolicy(path, path, wallTimeBudget: TimeSpan.FromSeconds(10),
            cpuTimeBudget: TimeSpan.FromSeconds(5), noProgressTimeout: TimeSpan.FromSeconds(2));
        TimeSpan wall = TimeSpan.Zero, cpu = TimeSpan.Zero;
        using (var budget = new OperationExecutionBudget(policy, default, () => wall, () => cpu, enableTimer: false))
        {
            wall = TimeSpan.FromSeconds(1);
            budget.RecordProgress(1);
            wall = TimeSpan.FromSeconds(2.5);
            budget.CheckLimits();
            Require(!budget.Token.IsCancellationRequested, "Actual byte progress did not renew the stall interval.");
            budget.RecordProgress(0);
            wall = TimeSpan.FromSeconds(3);
            budget.CheckLimits();
            Require(budget.Token.IsCancellationRequested && budget.Failure is TimeoutException,
                "Zero-byte/status activity bypassed the exact stall deadline.");
            Expect<TimeoutException>(() => budget.RecordProgress(1));
        }
        wall = TimeSpan.Zero;
        using (var budget = new OperationExecutionBudget(policy, default, () => wall, () => cpu, enableTimer: false))
        {
            cpu = TimeSpan.FromSeconds(3);
            budget.RecordChildCpu(TimeSpan.FromSeconds(2));
            budget.CheckLimits();
            Require(budget.Token.IsCancellationRequested && budget.Failure!.Message.Contains("CPU-time", StringComparison.Ordinal),
                "Parent and child CPU consumption were not combined.");
        }
        cpu = TimeSpan.Zero;
        using (var budget = new OperationExecutionBudget(policy, default, () => wall, () => cpu, enableTimer: false))
        {
            for (int second = 1; second < 10; second++)
            {
                wall = TimeSpan.FromSeconds(second);
                budget.RecordProgress(1);
            }
            wall = TimeSpan.FromSeconds(10);
            Expect<TimeoutException>(() => budget.RecordProgress(1));
            budget.CheckLimits();
            Require(budget.Token.IsCancellationRequested && budget.Failure!.Message.Contains("wall-time", StringComparison.Ordinal),
                "Byte progress bypassed the absolute wall deadline.");
        }
        return Task.CompletedTask;
    }

    private static async Task RunAsync()
    {
        long initialWorking = OperationMemoryBudget.WorkingReservedBytesForTests;
        long initialEntropy = OperationMemoryBudget.EntropyReservedBytes;
        Require(initialWorking == 0 && initialEntropy == 0, "Memory-budget fixture requires no active operation or mouse collection.");
        Require(OperationExecutionBudget.ActiveOwnersForTests == 0, "A previous operation retained a runtime owner.");
        string path = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        long maximum = OperationMemoryBudget.HostMemoryCeilingBytes;
        var policy = new ArchiveOperationPolicy(path, path, memoryBudgetBytes: maximum, maxCpuWorkers: 1, maxQueuedChunks: 1);
        foreach (string phase in new[] { "runtime", "lease" })
        {
            OperationMemoryBudget.ConstructionHookForTests = current => { if (current == phase) throw new IOException("injected construction failure"); };
            try
            {
                try { using var unexpected = await OperationMemoryBudget.AcquireAsync(policy, default); throw new Exception("Construction fault was ignored."); }
                catch (IOException) { }
            }
            finally { OperationMemoryBudget.ConstructionHookForTests = null; }
            Require(OperationExecutionBudget.ActiveOwnersForTests == 0 && OperationMemoryBudget.WorkingReservedBytesForTests == 0,
                "Failed construction retained a timer, runtime owner or memory reservation.");
        }
        long native = ZpaqService.NativeResidentBudget(policy, reserveKdf: true);
        Require(native + checked((long)V13MasterKdf.MemoryMaxKiB * 1024) == policy.HeavyWorkerMemoryBudgetBytes,
            "The child and maximum KDF matrix do not share exactly one approved heavy-worker budget.");
        using (OperationMemoryBudget.Lease outer = await OperationMemoryBudget.AcquireAsync(policy, default))
        {
            long reserved = OperationMemoryBudget.WorkingReservedBytesForTests;
            using (outer.EnterScope())
            using (policy.EnterScope())
            using (OperationMemoryBudget.Lease nested = await OperationMemoryBudget.AcquireAsync(policy, default))
            {
                OperationMemoryBudget.ConstructionHookForTests = current => { if (current == "nested-lease") throw new IOException("injected nested construction failure"); };
                try
                {
                    try { using var unexpected = await OperationMemoryBudget.AcquireAsync(policy, default); throw new Exception("Nested construction fault was ignored."); }
                    catch (IOException) { }
                }
                finally { OperationMemoryBudget.ConstructionHookForTests = null; }
                Require(OperationExecutionBudget.ActiveOwnersForTests == 1 && OperationMemoryBudget.WorkingReservedBytesForTests == reserved,
                    "A failed nested owner changed the parent's reservation or deadline lifetime.");
                Require(OperationMemoryBudget.WorkingReservedBytesForTests == reserved, "Nested service reserved the same memory twice.");
                using (OperationMemoryBudget.HeavyLease child = await OperationMemoryBudget.AcquireHeavyAsync(
                    policy.HeavyWorkerMemoryBudgetBytes - 1, default))
                {
                    using (OperationMemoryBudget.HeavyLease matrix = await OperationMemoryBudget.AcquireHeavyAsync(1, default))
                        Require(child.Bytes + matrix.Bytes == policy.HeavyWorkerMemoryBudgetBytes,
                            "Overlapping child and matrix charges did not exactly fit their shared budget.");
                    using var heavyCancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
                    try
                    {
                        using var excess = await OperationMemoryBudget.AcquireHeavyAsync(2, heavyCancellation.Token);
                        throw new Exception("A matrix bypassed the active native worker's memory charge.");
                    }
                    catch (OperationCanceledException) { }
                }
                using OperationMemoryBudget.HeavyLease all = await OperationMemoryBudget.AcquireHeavyAsync(
                    policy.HeavyWorkerMemoryBudgetBytes, default);
            }
            using IDisposable entropy = OperationMemoryBudget.ReserveEntropy(policy.EntropyCaptureBudgetBytes, policy.EntropyCaptureBudgetBytes);
            Require(OperationMemoryBudget.WorkingReservedBytesForTests + OperationMemoryBudget.EntropyReservedBytes <= maximum,
                "Live entropy exceeded the shared host memory ceiling.");
            Expect<IOException>(() => OperationMemoryBudget.ReserveEntropy(1, long.MaxValue));
            using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
            Task contender;
            using (ExecutionContext.SuppressFlow())
                contender = Task.Run(async () => { using var other = await OperationMemoryBudget.AcquireAsync(policy, cancellation.Token); });
            try { await contender; throw new Exception("A competing operation bypassed the aggregate budget."); }
            catch (OperationCanceledException) { }
        }
        Require(OperationMemoryBudget.WorkingReservedBytesForTests == initialWorking
            && OperationMemoryBudget.EntropyReservedBytes == initialEntropy
            && OperationExecutionBudget.ActiveOwnersForTests == 0, "Memory/runtime reservations were not released.");
        Expect<ArgumentOutOfRangeException>(() => new ArchiveOperationPolicy(path, path, memoryBudgetBytes: checked(maximum + 1)));
        using (OperationMemoryBudget.Lease small = await OperationMemoryBudget.AcquireAsync(
            new ArchiveOperationPolicy(path, path, memoryBudgetBytes: maximum / 2), default))
        using (small.EnterScope())
        {
            try { using var invalid = await OperationMemoryBudget.AcquireAsync(policy, default); throw new Exception("Nested budget increased."); }
            catch (InvalidOperationException) { }
        }
    }
    private static void Require(bool condition, string message) { if (!condition) throw new Exception(message); }
    private static void Expect<T>(Action action) where T : Exception
    { try { action(); } catch (T) { return; } throw new Exception($"Expected {typeof(T).Name}."); }
}
