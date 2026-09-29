using KalynaArchiver.Services;

internal static class CpuWorkBudgetTests
{
    internal static async Task RunAsync()
    {
        TestTopologySnapshots();
        Require(CpuTopology.AvailableWorkers >= 1 && CpuTopology.AvailableWorkers <= Environment.ProcessorCount,
            "Live CPU topology exceeds the runtime process ceiling.");
        foreach (int available in new[] { 1, 3, 64, 65, 1024, 1025, 4096, int.MaxValue })
        {
            Require(CpuWorkBudget.CalculateAvailableGrant(available, 0, available, 0) == available,
                "Pure budget arithmetic contains a fixed CPU cap.");
            Require(CpuWorkBudget.CalculateAvailableGrant(available, available, 1, 0) == 0,
                "Exhausted capacity granted another worker.");
            if (available > 1)
                Require(CpuWorkBudget.CalculateAvailableGrant(available, 0, available, 1) == available - 1,
                    "Parent headroom arithmetic lost capacity or overflowed.");
        }
        Require(!CpuWorkBudget.IsOwnedByCurrentContext, "CPU context leaked before the test.");
        using (CpuWorkBudget.Lease marked = await CpuWorkBudget.AcquireAsync(1, 1, default))
        {
            Require(!CpuWorkBudget.IsOwnedByCurrentContext, "Acquiring a child-process lease marked its parent context.");
            using (marked.EnterScope())
            {
                Require(CpuWorkBudget.IsOwnedByCurrentContext, "Synchronous lease scope was lost.");
                await Task.Yield();
                Require(await Task.Run(() => CpuWorkBudget.IsOwnedByCurrentContext), "Owned CPU context did not flow through a worker.");
                marked.Dispose();
                Require(!CpuWorkBudget.IsOwnedByCurrentContext, "A disposed lease falsely authorized CPU reuse.");
            }
        }
        Require(!CpuWorkBudget.IsOwnedByCurrentContext, "CPU context was not restored after scope disposal.");
        using (CpuWorkBudget.Lease single = await CpuWorkBudget.AcquireAsync(1, 1, default))
        using (single.EnterScope())
        {
            int completed = 0;
            await CpuWorkBudget.RunIndependentAsync(default,
                () => completed++, () => completed++, () => completed++);
            Require(completed == 3 && CpuWorkBudget.ActiveWorkersForTests == 1,
                "Nested hash families reacquired or escaped their existing CPU permit.");
        }
        int joined = 0;
        try
        {
            await CpuWorkBudget.RunIndependentAsync(default,
                () => throw new IOException("public hash worker fault"),
                () => Interlocked.Increment(ref joined), () => Interlocked.Increment(ref joined));
            throw new InvalidOperationException("Independent hash worker failure was hidden.");
        }
        catch (IOException) { }
        Require(joined == 2 && CpuWorkBudget.ActiveWorkersForTests == 0,
            "Failed hash work returned before its accepted siblings joined.");
        int cap = Math.Clamp(Environment.ProcessorCount, 1, 4);
        using (CpuWorkBudget.Lease full = await CpuWorkBudget.AcquireAsync(cap, cap, default))
        {
            Require(full.Workers == cap, "The aggregate budget did not grant available workers.");
            using var cancelled = new CancellationTokenSource();
            Task<CpuWorkBudget.Lease> waiter = CpuWorkBudget.AcquireAsync(cap, 1, cancelled.Token).AsTask();
            Require(!waiter.IsCompleted, "A second team exceeded the aggregate CPU budget.");
            cancelled.Cancel();
            try { using var unexpected = await waiter; throw new InvalidOperationException("Cancelled reservation succeeded."); }
            catch (OperationCanceledException) { }
        }
        Require(CpuWorkBudget.ActiveWorkersForTests == 0, "Cancelled waiter or completed team leaked CPU permits.");
        if (cap >= 2)
        {
            using CpuWorkBudget.Lease low = await CpuWorkBudget.AcquireAsync(1, 1, default);
            Task<CpuWorkBudget.Lease> high = CpuWorkBudget.AcquireAsync(cap, cap, default).AsTask();
            Require(!high.IsCompleted, "A higher policy overrode an active lower ceiling.");
            low.Dispose();
            using CpuWorkBudget.Lease granted = await high;
            Require(granted.Workers == cap, "The lower ceiling was not removed after release.");
        }
        if (cap >= 2)
        {
            using CpuWorkBudget.Lease child = await CpuWorkBudget.AcquireAsync(cap, cap - 1, default, reservedHeadroom: 1);
            Task<CpuWorkBudget.Lease> secondChild = CpuWorkBudget.AcquireAsync(cap, cap - 1, default, reservedHeadroom: 1).AsTask();
            Require(!secondChild.IsCompleted, "A second native child consumed the reserved parent worker.");
            using (CpuWorkBudget.Lease parent = await CpuWorkBudget.AcquireAsync(cap, 1, default))
                Require(parent.Workers == 1, "Native child reservation starved its parent RPC worker.");
            child.Dispose();
            using CpuWorkBudget.Lease second = await secondChild;
            Require(second.Workers == cap - 1, "Pending native child could not start after the first joined.");
        }
        if (cap >= 2)
        {
            using CpuWorkBudget.Lease lower = await CpuWorkBudget.AcquireAsync(1, 1, default);
            Task<CpuWorkBudget.Lease> child = CpuWorkBudget.AcquireAsync(cap, cap, default, reservedHeadroom: 1).AsTask();
            Require(!child.IsCompleted, "Lower active ceiling must queue a child with parent headroom.");
            lower.Dispose();
            using CpuWorkBudget.Lease ready = await child;
            Require(ready.Workers == cap-1, "Child headroom was not preserved after the lower ceiling left.");
        }
        Require(CpuWorkBudget.ActiveWorkersForTests == 0, "CPU reservation release is unbalanced.");
        int active = 0, peak = 0;
        Task[] jobs = Enumerable.Range(0, 17).Select(async _ =>
        {
            using CpuWorkBudget.Lease lease = await CpuWorkBudget.AcquireAsync(cap, 2, default);
            int now = Interlocked.Add(ref active, lease.Workers);
            int old;
            do { old = Volatile.Read(ref peak); if (old >= now) break; }
            while (Interlocked.CompareExchange(ref peak, now, old) != old);
            await Task.Yield();
            Interlocked.Add(ref active, -lease.Workers);
        }).ToArray();
        await Task.WhenAll(jobs);
        Require(peak <= cap && active == 0 && CpuWorkBudget.ActiveWorkersForTests == 0,
            "Concurrent native team reservations exceeded their shared worker cap.");
        int availability = 4;
        CpuTopology.AvailabilityForTests = () => Volatile.Read(ref availability);
        try
        {
            using (CpuWorkBudget.Lease running = await CpuWorkBudget.AcquireAsync(8, 8, default))
            {
                Require(running.Workers == 4, "Initial synthetic availability was ignored.");
                Volatile.Write(ref availability, 2);
                Task<CpuWorkBudget.Lease> pending = CpuWorkBudget.AcquireAsync(8, 8, default).AsTask();
                Require(!pending.IsCompleted && CpuWorkBudget.ActiveWorkersForTests == 4,
                    "Downscale revoked a live permit or oversubscribed the smaller host.");
                running.Dispose();
                using CpuWorkBudget.Lease smaller = await pending;
                Require(smaller.Workers == 2, "Queued team did not re-read availability after join.");
            }
            Volatile.Write(ref availability, 8);
            using (CpuWorkBudget.Lease larger = await CpuWorkBudget.AcquireAsync(8, 8, default))
                Require(larger.Workers == 8, "Completed topology change retained a stale fixed cap.");
            Volatile.Write(ref availability, 1);
            try
            {
                using var impossible = await CpuWorkBudget.AcquireAsync(8, 8, default, reservedHeadroom: 1);
                throw new InvalidOperationException("Impossible parent/child team was granted.");
            }
            catch (IOException) { }
        }
        finally { CpuTopology.AvailabilityForTests = null; }
        Require(CpuWorkBudget.ActiveWorkersForTests == 0, "Topology changes leaked permits.");
    }

    private static void TestTopologySnapshots()
    {
        var values = new Dictionary<string, int>
        {
            ["hw.logicalcpu"] = 12, ["hw.physicalcpu"] = 8, ["hw.logicalcpu_max"] = 16,
            ["hw.nperflevels"] = 2,
            ["hw.perflevel0.logicalcpu"] = 8, ["hw.perflevel0.physicalcpu"] = 4,
            ["hw.perflevel1.logicalcpu"] = 4, ["hw.perflevel1.physicalcpu"] = 4,
        };
        int? Read(string name) => values.TryGetValue(name, out int value) ? value : null;
        CpuTopologySnapshot topology = CpuTopology.ReadMacSnapshot(10, Read);
        Require(topology.ProcessLimit == 10 && topology.AvailableWorkers == 10
            && topology.EnabledLogicalProcessors == 12 && topology.EnabledPhysicalProcessors == 8
            && topology.HasSimultaneousMultithreading == true && !topology.ChangedDuringRead,
            "Topological hardware counts were confused with the process worker ceiling.");
        Require(topology.PerformanceLevels.Count == 2
            && topology.PerformanceLevels[0] == new CpuPerformanceLevel(0, 8, 4)
            && topology.PerformanceLevels[1] == new CpuPerformanceLevel(1, 4, 4)
            && topology.PerformanceLevels[0].HasSimultaneousMultithreading == true
            && topology.PerformanceLevels[1].HasSimultaneousMultithreading == false,
            "OS performance ranks or their independent SMT descriptions changed.");
        Require(topology.PerformanceLevels is not CpuPerformanceLevel[], "Topology exposed its mutable level array.");

        values["hw.logicalcpu"] = 5;
        values["hw.physicalcpu"] = 5;
        values["hw.perflevel0.logicalcpu"] = 1;
        values["hw.perflevel0.physicalcpu"] = 1;
        CpuTopologySnapshot smaller = CpuTopology.ReadMacSnapshot(10, Read);
        Require(smaller.AvailableWorkers == 5 && smaller.HasSimultaneousMultithreading == false
            && topology.AvailableWorkers == 10 && topology.PerformanceLevels[0].EnabledLogicalProcessors == 8,
            "A fresh topology query was cached or mutated an earlier immutable snapshot.");
        CpuTopologySnapshot unknown = CpuTopology.ReadMacSnapshot(7, _ => null);
        Require(unknown.AvailableWorkers == 7 && unknown.EnabledLogicalProcessors is null
            && unknown.EnabledPhysicalProcessors is null && unknown.HasSimultaneousMultithreading is null
            && unknown.PerformanceLevels.Count == 0,
            "Unsupported sysctl values fabricated physical cores, SMT or performance classes.");
        CpuTopologySnapshot malformed = CpuTopology.ReadMacSnapshot(7, name => name switch
        {
            "hw.logicalcpu" => 4, "hw.physicalcpu" => 9, "hw.logicalcpu_max" => -1,
            "hw.nperflevels" => int.MaxValue, _ => 0,
        });
        Require(malformed.AvailableWorkers == 4 && malformed.EnabledPhysicalProcessors is null
            && malformed.HasSimultaneousMultithreading is null && malformed.PerformanceLevels.Count == 0,
            "Malformed optional topology fields authorized workers or an unbounded level allocation.");
        CpuTopologySnapshot partial = CpuTopology.ReadMacSnapshot(20, name => name switch
        {
            "hw.logicalcpu" => 8, "hw.physicalcpu" => 8, "hw.logicalcpu_max" => 8,
            "hw.nperflevels" => 3,
            "hw.perflevel0.logicalcpu" => 4, "hw.perflevel0.physicalcpu" => 4,
            "hw.perflevel1.logicalcpu" => 4, "hw.perflevel1.physicalcpu" => null,
            "hw.perflevel2.logicalcpu" => 0, "hw.perflevel2.physicalcpu" => 0, _ => null,
        });
        Require(partial.AvailableWorkers == 8 && partial.PerformanceLevels.Count == 3
            && partial.PerformanceLevels[1].HasSimultaneousMultithreading is null
            && partial.PerformanceLevels[2].EnabledLogicalProcessors == 0
            && partial.PerformanceLevels[2].HasSimultaneousMultithreading is null,
            "An absent field or disabled performance class was silently invented or discarded.");
        int logicalReads = 0;
        CpuTopologySnapshot changed = CpuTopology.ReadMacSnapshot(16, name => name switch
        {
            "hw.logicalcpu" => ++logicalReads == 1 ? 12 : 6,
            "hw.physicalcpu" => 6, "hw.logicalcpu_max" => 12, "hw.nperflevels" => 1,
            "hw.perflevel0.logicalcpu" => 12, "hw.perflevel0.physicalcpu" => 6, _ => null,
        });
        Require(changed.ChangedDuringRead && changed.AvailableWorkers == 6
            && changed.HasSimultaneousMultithreading is null && changed.PerformanceLevels.Count == 0,
            "A non-atomic topology change granted stale capacity or asserted incoherent SMT metadata.");
        foreach (int cores in new[] { 65, 1025, 4096, int.MaxValue })
        {
            CpuTopologySnapshot large = CpuTopology.ReadMacSnapshot(cores,
                name => name is "hw.logicalcpu" or "hw.physicalcpu" ? cores : null);
            Require(large.AvailableWorkers == cores && large.HasSimultaneousMultithreading == false,
                "Topology interpretation inserted a fixed core limit.");
        }
        CpuTopologySnapshot live = CpuTopology.Capture();
        Require(live.AvailableWorkers >= 1 && live.AvailableWorkers <= Environment.ProcessorCount,
            "Live topology escaped the process ceiling.");
        foreach (CpuPerformanceLevel level in live.PerformanceLevels)
            Require(level.Rank >= 0 && level.Rank < live.PerformanceLevels.Count
                && (level.EnabledPhysicalProcessors is null || level.EnabledLogicalProcessors is null
                    || level.EnabledPhysicalProcessors <= level.EnabledLogicalProcessors),
                "Live optional topology metadata is internally invalid.");
    }

    private static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
}
