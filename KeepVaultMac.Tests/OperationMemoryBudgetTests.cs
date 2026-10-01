using KalynaArchiver.Services;

internal static class OperationMemoryBudgetTests
{
    internal static IReadOnlyList<TestCase> Tests =>
    [
        new("resources.shared-memory-budget", "nested reuse, aggregate contention, cancellation and live entropy accounting", RunAsync, TestResource.ProcessGlobal, "Resources"),
        new("resources.shared-runtime-budget", "unbounded wall/CPU/stall observations, manual cancellation and real failures", RuntimeAsync, TestResource.Light, "Resources"),
    ];

    private static Task RuntimeAsync()
    {
        string path = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var policy = new ArchiveOperationPolicy(path, path);
        TimeSpan wall = TimeSpan.Zero, cpu = TimeSpan.Zero;
        using var cancel = new CancellationTokenSource();
        using (var budget = new OperationExecutionBudget(policy, cancel.Token, () => wall, () => cpu))
        {
            foreach (TimeSpan elapsed in new[] { TimeSpan.FromHours(4), TimeSpan.FromHours(24), TimeSpan.FromDays(12) })
            {
                wall = elapsed;
                cpu = elapsed * 4;
                budget.RecordChildCpu(elapsed * 2);
                _ = budget.Observe();
                budget.RecordProgress(0);
                Require(!budget.Token.IsCancellationRequested && budget.Failure is null,
                    "Elapsed wall/CPU/stall observations gained cancellation authority.");
                budget.RecordProgress(1);
            }
            Require(budget.Observe().Cpu > TimeSpan.FromHours(32), "Child CPU observations were not retained.");
            cancel.Cancel();
            Require(budget.Token.IsCancellationRequested, "Manual cancellation was lost.");
        }
        using (var budget = new OperationExecutionBudget(policy, default, () => throw new IOException(), () => cpu))
        {
            budget.RecordProgress(1);
            Require(budget.Observe().Elapsed is null && !budget.Token.IsCancellationRequested,
                "A broken observer cancelled the operation.");
            var error = new IOException("test operation failure");
            budget.ReportFailure(error);
            Require(budget.Token.IsCancellationRequested && ReferenceEquals(budget.Failure, error),
                "A real failure did not retain its cause and cancel the operation.");
        }
        return Task.CompletedTask;
    }

    private static async Task RunAsync()
    {
        long initialWorking = OperationMemoryBudget.WorkingReservedBytesForTests;
        long initialEntropy = OperationMemoryBudget.EntropyReservedBytes;
        Require(initialWorking == 0 && initialEntropy == 0, "Memory fixture requires no active operation or records.");
        ResourceObservation observed = new(7, 16L << 30, 16L << 30, 64L << 20, 12L << 30, MemoryPressure.Normal, true);
        PlatformResourceObserver.ObservationForTests = () => observed;
        try
        {
            string path = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var policy = new ArchiveOperationPolicy(path, path, memoryBudgetBytes: 512L << 20, maxCpuWorkers: 1);
            foreach (string phase in new[] { "runtime", "lease" })
            {
                OperationMemoryBudget.ConstructionHookForTests = current => { if (current == phase) throw new IOException("injected construction failure"); };
                try { try { using var unexpected = await OperationMemoryBudget.AcquireAsync(policy, default); throw new Exception("Construction fault ignored."); } catch (IOException) { } }
                finally { OperationMemoryBudget.ConstructionHookForTests = null; }
                Require(OperationExecutionBudget.ActiveOwnersForTests == 0 && OperationMemoryBudget.WorkingReservedBytesForTests == 0,
                    "Failed construction retained ownership or a memory charge.");
            }
            using (policy.EnterScope())
            using (OperationMemoryBudget.Lease outer = await OperationMemoryBudget.AcquireAsync(policy, default))
            using (outer.EnterScope())
            {
                Require(OperationMemoryBudget.WorkingReservedBytesForTests == ResourcePlanner.OperationBaseBytes,
                    "The operation reserved its allowed maximum instead of its base.");
                object? context = OperationMemoryBudget.CurrentContextIdentity;
                using (OperationMemoryBudget.Lease nested = await OperationMemoryBudget.AcquireAsync(policy, default))
                using (nested.EnterScope())
                    Require(ReferenceEquals(context, OperationMemoryBudget.CurrentContextIdentity)
                        && OperationMemoryBudget.WorkingReservedBytesForTests == ResourcePlanner.OperationBaseBytes,
                        "A nested operation duplicated memory or changed the owner.");
                using (OperationMemoryBudget.HeavyLease matrix = await OperationMemoryBudget.AcquireHeavyAsync(400L << 20, default))
                {
                    Require(OperationMemoryBudget.WorkingReservedBytesForTests == ResourcePlanner.OperationBaseBytes + (400L << 20),
                        "The concrete matrix/model charge is missing.");
                    try { using var excess = await OperationMemoryBudget.AcquireWorkingAsync(120L << 20, default); throw new Exception("Overlap bypassed the operation ceiling."); }
                    catch (IOException) { }
                    using var cancel = new CancellationTokenSource();
                    cancel.Cancel();
                    try { using var cancelled = await OperationMemoryBudget.AcquireWorkingAsync(1, cancel.Token); throw new Exception("Cancelled admission acquired memory."); }
                    catch (OperationCanceledException) { }
                }
                Require(OperationMemoryBudget.WorkingReservedBytesForTests == ResourcePlanner.OperationBaseBytes,
                    "The completed phase retained its large reservation.");
                // An opaque native model has a proven peak admission, not an
                // allocator ACK for every live byte. Keep that lease pending
                // even after OS free memory falls, accepting conservative denial.
                long reserve = observed.PhysicalMemoryBytes / 32;
                observed = observed with { ReclaimableMemoryBytes = reserve + (180L << 20) };
                using (OperationMemoryBudget.HeavyLease opaque = await OperationMemoryBudget.AcquireWorkingAsync(100L << 20, default))
                {
                    observed = observed with { ReclaimableMemoryBytes = reserve + (80L << 20) };
                    try { using var denied = await OperationMemoryBudget.AcquireWorkingAsync(1, default); throw new Exception("Opaque native pending peak disappeared before free."); }
                    catch (IOException) { }
                    Require(!outer.Token.IsCancellationRequested,
                        "Conservative optional admission denial cancelled the operation.");
                }
                observed = observed with { ReclaimableMemoryBytes = 12L << 30 };
                using (OperationMemoryBudget.HeavyLease buffer = await OperationMemoryBudget.AcquireWorkingAsync(204, default))
                {
                    byte[] actual = new byte[204];
                    buffer.CommitAllocation();
                    Require(policy.Usage.LeasedMemoryBytes == ResourcePlanner.OperationBaseBytes + actual.Length,
                        "Actual index bytes were rounded to a maximum frame.");
                    System.Security.Cryptography.CryptographicOperations.ZeroMemory(actual);
                }
                using (IDisposable records = OperationMemoryBudget.ReserveEntropy(32L << 20, policy.EntropyCaptureBudgetBytes))
                    Require(OperationMemoryBudget.EntropyReservedBytes == 32L << 20, "Live records were not charged.");
                observed = observed with { ReclaimableMemoryBytes = 1L << 20, Pressure = MemoryPressure.Critical };
                try { using var denied = await OperationMemoryBudget.AcquireWorkingAsync(204, default); throw new Exception("OS pressure was ignored."); }
                catch (IOException) { }
                observed = observed with { ReclaimableMemoryBytes = 12L << 30, Pressure = MemoryPressure.Normal };
            }
            Require(OperationMemoryBudget.WorkingReservedBytesForTests == initialWorking
                && OperationMemoryBudget.EntropyReservedBytes == initialEntropy && policy.Usage.LeasedMemoryBytes == 0
                && OperationExecutionBudget.ActiveOwnersForTests == 0, "Phase/lifetime charges were not released.");
            using (policy.EnterScope())
            using (OperationMemoryBudget.HeavyLease standalone = OperationMemoryBudget.AcquireWorking(204))
                Require(OperationMemoryBudget.WorkingReservedBytesForTests == 204,
                    "The standalone pre-KDF index did not share the global actual-memory ledger.");
        }
        finally
        {
            PlatformResourceObserver.ObservationForTests = null;
            OperationMemoryBudget.ConstructionHookForTests = null;
        }
    }
    private static void Require(bool condition, string message) { if (!condition) throw new Exception(message); }
    private static void Expect<T>(Action action) where T : Exception
    { try { action(); } catch (T) { return; } throw new Exception($"Expected {typeof(T).Name}."); }
}
