using KalynaArchiver.Services;

internal static class OperationProgressTests
{
    internal static IReadOnlyList<TestCase> Tests =>
    [
        new("v13-time-no-wall", "monotonic four-hour, day and multi-day observations have no deadline authority", NoTimeLimits, TestResource.Light, "Resources"),
        new("v13-time-no-cpu", "parent and child CPU beyond 32 hours remain observations", NoCpuLimit, TestResource.Light, "Resources"),
        new("v13-time-no-stall-abort", "long stalls affect estimates without cancelling work", Stall, TestResource.Light, "Resources"),
        new("v13-progress-counts", "disjoint sources aggregate absolute counts exactly once", Counts, TestResource.Light, "Progress"),
        new("v13-progress-order", "stale source, phase, operation and terminal messages cannot overwrite ownership", Order, TestResource.Light, "Progress"),
        new("v13-progress-unknown", "unknown totals and KDF do not gain a fabricated ETA", Unknown, TestResource.Light, "Progress"),
        new("v13-progress-eta", "independent constant-rate example, EWMA, zero-work intervals and warmup", Eta, TestResource.Light, "Progress"),
        new("v13-progress-stale", "heartbeats do not refresh work, stalls recover without time abort", Stale, TestResource.Light, "Progress"),
        new("v13-progress-clock", "UTC jumps, resource pause, resume and invalid monotonic observations", Clock, TestResource.Light, "Progress"),
        new("v13-progress-overlap", "mixed-unit phases and unknown future work have no invented overall duration", Overlap, TestResource.Light, "Progress"),
        new("v13-progress-finish", "full data phase cannot authorize success before outer commit and cleanup", Finish, TestResource.Light, "Progress"),
        new("v13-progress-bounds", "size seams, Int64 overflow, bounded sources and impossible counts", Bounds, TestResource.Light, "Progress"),
    ];
    private static void Require(bool value, string message) { if (!value) throw new Exception(message); }
    private static ArchiveOperationPolicy Policy()
    {
        string path = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return new(path, path);
    }
    private static Task NoTimeLimits()
    {
        TimeSpan elapsed = TimeSpan.Zero;
        using var lifetime = new OperationExecutionBudget(Policy(), default, () => elapsed, () => TimeSpan.Zero);
        foreach (TimeSpan at in new[] { TimeSpan.FromHours(4)-TimeSpan.FromTicks(1), TimeSpan.FromHours(4), TimeSpan.FromHours(24), TimeSpan.FromDays(100) })
        {
            elapsed = at;
            Require(lifetime.Observe().Elapsed == at && !lifetime.Token.IsCancellationRequested, "Clock acquired deadline authority.");
            lifetime.RecordProgress(1);
        }
        return Task.CompletedTask;
    }
    private static Task NoCpuLimit()
    {
        using var lifetime = new OperationExecutionBudget(Policy(), default, () => TimeSpan.FromSeconds(1), () => TimeSpan.FromHours(24));
        lifetime.RecordChildCpu(TimeSpan.FromHours(40));
        Require(lifetime.Observe().Cpu == TimeSpan.FromHours(64) && !lifetime.Token.IsCancellationRequested, "CPU observation cancelled work.");
        return Task.CompletedTask;
    }
    private static Task Stall()
    {
        TimeSpan elapsed = TimeSpan.Zero;
        using var lifetime = new OperationExecutionBudget(Policy(), default, () => elapsed, () => TimeSpan.Zero);
        elapsed = TimeSpan.FromDays(4);
        Require(lifetime.Observe().SinceProgress == elapsed && !lifetime.Token.IsCancellationRequested, "Silent work was killed.");
        lifetime.RecordProgress(1);
        Require(lifetime.Observe().SinceProgress == TimeSpan.Zero && lifetime.Failure is null, "Late work was refused.");
        return Task.CompletedTask;
    }
    private static Task Counts()
    {
        using var tracker = new OperationProgressTracker(new ClockSource());
        using var a = tracker.BeginPhase(OperationPhase.GlobalVerification, totalUnits: 100, origin: ProgressTotalOrigin.KnownInput)!;
        using var b = tracker.RegisterSource()!;
        a.Report(10, 2); b.Report(20, 0); a.Report(10, 2); a.Report(9, 1);
        Require(tracker.Snapshot().CompletedUnits == 30, "Sources counted duplicate or out-of-order work.");
        b.Dispose(); a.Advance(7);
        Require(tracker.Snapshot().CompletedUnits == 37, "Retiring a source lost completed work.");
        a.Report(101, 3);
        Require(tracker.Snapshot().CompletedUnits == 37, "An impossible count changed progress.");
        return Task.CompletedTask;
    }
    private static Task Order()
    {
        using var tracker = new OperationProgressTracker(new ClockSource());
        using var old = tracker.BeginPhase(OperationPhase.GlobalVerification)!;
        old.Report(20, 0);
        using var current = tracker.BeginPhase(OperationPhase.Extraction)!;
        old.Report(500, 1); current.Report(10, 0);
        Require(tracker.Snapshot().CompletedUnits == 10, "Old pass overwrote new pass.");
        using var other = new OperationProgressTracker(new ClockSource());
        using var unrelated = other.BeginPhase(OperationPhase.Extraction)!;
        unrelated.Advance(1000);
        Require(tracker.Snapshot().CompletedUnits == 10, "Other operation overwrote the active one.");
        tracker.SetState(OperationProgressState.Failed);
        current.Report(900, 100); tracker.Complete(); tracker.SetState(OperationProgressState.Running);
        Require(tracker.Snapshot().State == OperationProgressState.Failed, "Late telemetry replaced terminal failure.");
        return Task.CompletedTask;
    }
    private static Task Unknown()
    {
        var clock = new ClockSource();
        using var tracker = new OperationProgressTracker(clock);
        using var source = tracker.BeginPhase(OperationPhase.Extraction)!;
        for (int i = 1; i <= 6; i++) { clock.Advance(1); source.Report(i * 1000, i); _ = tracker.Snapshot(); }
        Require(tracker.Snapshot().TotalUnits is null && tracker.Snapshot().PhaseRemaining is null, "Unknown output gained a fake total.");
        using var kdf = tracker.BeginPhase(OperationPhase.KeyDerivation, ProgressUnit.Steps, 4, ProgressTotalOrigin.ValidatedPlan)!;
        for (int i = 0; i < 5; i++) { clock.Advance(1); _ = tracker.Snapshot(); }
        kdf.Advance(1);
        Require(tracker.Snapshot().PhaseRemaining is null, "A KDF prediction used secret-dependent timing.");
        return Task.CompletedTask;
    }
    private static Task Eta()
    {
        const long mib = 1L << 20, gib = 1L << 30;
        var clock = new ClockSource();
        using var tracker = new OperationProgressTracker(clock);
        using var source = tracker.BeginPhase(OperationPhase.Extraction, totalUnits: 1024*gib, origin: ProgressTotalOrigin.KnownInput)!;
        long units = 240*gib - 800*mib;
        source.Report(units, 0);
        tracker.RevisePlan(1024*gib, ProgressTotalOrigin.KnownInput);
        for (int i = 1; i <= 4; i++)
        {
            clock.Advance(0.5); units += 200*mib; source.Report(units, i);
            OperationProgressSnapshot snapshot = tracker.Snapshot();
            if (i < 4) Require(snapshot.PhaseRemaining is null, "ETA appeared before four intervals and two seconds.");
        }
        OperationProgressSnapshot constant = tracker.Snapshot();
        Require(Math.Abs(constant.PhaseRemaining!.Value.TotalSeconds - 2007.04) < 0.001, "Independent 400 MiB/s example differs.");
        double previous = constant.RatePerSecond!.Value;
        clock.Advance(1); _ = tracker.Snapshot();
        double independentlySmoothed = Math.Exp(-1.0/15) * previous;
        Require(Math.Abs(tracker.Snapshot().RatePerSecond!.Value / independentlySmoothed - 1) < 1e-10,
            "Zero-work I/O wait was excluded or EWMA used the wrong elapsed interval.");
        Require(tracker.Snapshot().PhaseRemaining > constant.PhaseRemaining, "Slower throughput did not increase ETA.");
        return Task.CompletedTask;
    }
    private static Task Stale()
    {
        var clock = new ClockSource();
        using var tracker = new OperationProgressTracker(clock);
        using var source = tracker.BeginPhase(OperationPhase.Compression, totalUnits: 10000, origin: ProgressTotalOrigin.KnownInput)!;
        for (int i = 1; i <= 4; i++) { clock.Advance(1); source.Report(i*100, i); _ = tracker.Snapshot(); }
        clock.Advance(31); source.Report(400, 5);
        Require(tracker.Snapshot().EstimateState == ProgressEstimateState.Stale && tracker.Snapshot().PhaseRemaining is null,
            "A heartbeat kept an old ETA fresh.");
        Require(tracker.Snapshot().State == OperationProgressState.Running, "Staleness stopped the operation.");
        clock.Advance(1); source.Report(500, 6);
        Require(tracker.Snapshot().State == OperationProgressState.Running && tracker.Snapshot().CompletedUnits == 500,
            "Legitimate later progress was refused.");
        return Task.CompletedTask;
    }
    private static Task Clock()
    {
        var clock = new ClockSource();
        using var tracker = new OperationProgressTracker(clock);
        using var source = tracker.BeginPhase(OperationPhase.Compression)!;
        clock.Advance(3); source.Advance(10); _ = tracker.Snapshot();
        clock.Utc = DateTimeOffset.MinValue;
        Require(tracker.Snapshot().ElapsedDuration == TimeSpan.FromSeconds(3), "UTC affected elapsed work.");
        tracker.SetState(OperationProgressState.WaitingForResource); clock.Advance(86400);
        Require(tracker.Snapshot().PausedDuration == TimeSpan.FromDays(1), "Resource pause disappeared.");
        tracker.SetState(OperationProgressState.Running); clock.Advance(1);
        Require(tracker.Snapshot().ActivePhaseDuration == TimeSpan.FromSeconds(4), "Pause inflated the work rate denominator.");
        tracker.RecalibrateAfterSuspend();
        Require(tracker.Snapshot().PhaseRemaining is null, "Wake retained an old ETA.");
        clock.Ticks = -1;
        Require(tracker.Snapshot().StatusCode == ProgressStatusCode.ClockUnavailable && tracker.Snapshot().State == OperationProgressState.Running,
            "Invalid monotonic time affected operation authority.");
        return Task.CompletedTask;
    }
    private static Task Overlap()
    {
        var clock = new ClockSource();
        using var tracker = new OperationProgressTracker(clock);
        using var bytes = tracker.BeginPhase(OperationPhase.Compression, totalUnits: 1000, origin: ProgressTotalOrigin.KnownInput)!;
        bytes.Advance(500);
        using var stripes = tracker.BeginPhase(OperationPhase.Recovery, ProgressUnit.Stripes, 100, ProgressTotalOrigin.ValidatedPlan)!;
        bytes.Advance(400); stripes.Advance(10);
        Require(tracker.Snapshot().CompletedUnits == 10 && tracker.Snapshot().Unit == ProgressUnit.Stripes
            && tracker.Snapshot().OverallRemaining is null, "Overlapping unlike units were added into fabricated total work.");
        return Task.CompletedTask;
    }
    private static Task Finish()
    {
        using var tracker = new OperationProgressTracker(new ClockSource());
        using var source = tracker.BeginPhase(OperationPhase.Encryption, totalUnits: 10, origin: ProgressTotalOrigin.KnownInput)!;
        source.Advance(10);
        Require(tracker.Snapshot().State == OperationProgressState.Running, "Last chunk declared global success.");
        using var commit = tracker.BeginPhase(OperationPhase.Commit)!;
        Require(tracker.Snapshot().State == OperationProgressState.Finalizing && tracker.Snapshot().PhaseRemaining is null,
            "Commit was shown as a completed zero-second operation.");
        using var cleanup = tracker.BeginPhase(OperationPhase.Cleanup)!;
        Require(tracker.Snapshot().State == OperationProgressState.Finalizing, "Cleanup was skipped for progress.");
        tracker.Complete();
        Require(tracker.Snapshot().State == OperationProgressState.Completed, "Outer successful lifetime could not finish.");
        return Task.CompletedTask;
    }
    private static Task Bounds()
    {
        foreach (long total in new[] { 0L, 1024L, (16L<<20)-1, 16L<<20, (16L<<20)+1, 4L<<40, long.MaxValue })
        {
            using var tracker = new OperationProgressTracker(new ClockSource());
            using var source = tracker.BeginPhase(OperationPhase.GlobalVerification, totalUnits: total, origin: ProgressTotalOrigin.KnownInput)!;
            source.Report(total, 0); source.Advance(1); source.Advance(-1);
            Require(tracker.Snapshot().CompletedUnits == total && tracker.Snapshot().State == OperationProgressState.Running,
                "A size seam overflowed or granted success.");
        }
        using var bounded = new OperationProgressTracker(new ClockSource());
        for (int i = 0; i < 100000; i++) bounded.RegisterSource();
        Require(bounded.Snapshot().StatusCode == ProgressStatusCode.InvalidObservation, "Source cardinality was unbounded.");
        return Task.CompletedTask;
    }
    private sealed class ClockSource : TimeProvider
    {
        internal long Ticks;
        internal DateTimeOffset Utc = DateTimeOffset.UnixEpoch;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => Ticks;
        public override DateTimeOffset GetUtcNow() => Utc;
        internal void Advance(double seconds) => Ticks += TimeSpan.FromSeconds(seconds).Ticks;
    }
}
