using KalynaArchiver.Services;

internal static class CpuWorkBudgetTests
{
    internal static async Task RunAsync()
    {
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

    private static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
}
