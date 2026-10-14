using System.Diagnostics;
using KalynaArchiver.Services;

internal static class ProgressIsolationTests
{
    internal static IReadOnlyList<TestCase> Tests =>
    [
        new("v13-progress-equivalence", "twelve actual suite outputs remain byte-identical with a polling observer and a broken clock", EquivalenceAsync, TestResource.EntropyGlobal, "Progress"),
        new("v13-progress-privacy", "progress DTO permits only public counters, identifiers, enums and durations", PrivacyAsync, TestResource.Light, "Progress"),
        new("v13-progress-perf", "hot updates allocate no per-message objects; polling storage remains bounded", PerformanceAsync, TestResource.CpuHeavy, "Progress"),
    ];

    // Public deterministic fixtures only. The small KDF override checks observer
    // equivalence; it is not evidence for production Argon2 memory requirements.
    private const string Password = "N!r7$Vq2#Lm8%Tx3&Jd9*Wp4+Kg5=Zu6?Ce";
    private const string Pin = "428317";
    private static readonly string FactorA = new('A', 256), FactorB = new('B', 256);

    private static async Task EquivalenceAsync()
    {
        string directory = Path.Combine(Path.GetTempPath(), "keepvault-progress-equivalence-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        directory = MacSafeFileSystem.ResolveExistingRealPath(directory);
        try
        {
            using IDisposable memory = V13MasterKdf.UseMemoryCostForTests(8192);
            byte[] payload = Enumerable.Range(0, 1024).Select(i => unchecked((byte)(i * 43 + 13))).ToArray();
            foreach (EncryptionSuite suite in Enum.GetValues<EncryptionSuite>())
            {
                byte[]? baseline = null;
                for (int mode = 0; mode < 3; mode++)
                {
                    using var tracker = mode == 0 ? null : new OperationProgressTracker(mode == 2 ? new BrokenClock() : null);
                    using IDisposable? scope = tracker?.EnterScope();
                    using var stop = new CancellationTokenSource();
                    Task polling = tracker is null ? Task.CompletedTask : Task.Run(async () =>
                    {
                        while (!stop.IsCancellationRequested)
                        {
                            _ = tracker.Snapshot();
                            try { await Task.Delay(mode == 1 ? 1 : 17, stop.Token); }
                            catch (OperationCanceledException) when (stop.IsCancellationRequested) { break; }
                        }
                    });
                    try
                    {
                        string path = Path.Combine(directory, $"{suite}-{mode}.kzpaq");
                        using GeneratedArchiveEntropy entropy = CreateEntropy();
                        using var input = new MemoryStream(payload, writable: false);
                        await new KalynaContainerService().EncryptZpaqStreamWithPreparedEntropyAsync(input, path,
                            Password, Pin, FactorA, FactorB, suite, entropy, "progress-fixture", null, default);
                        byte[] actual = await File.ReadAllBytesAsync(path);
                        if (baseline is null) baseline = actual;
                        else Require(actual.AsSpan().SequenceEqual(baseline), "Progress changed container bytes for " + suite);
                        using var output = new MemoryStream();
                        await new KalynaContainerService().DecryptToStreamAsync(path, Password, Pin, FactorA, FactorB, output, null, default);
                        Require(output.ToArray().AsSpan().SequenceEqual(payload), "Observed extraction changed plaintext for " + suite);
                        if (tracker is not null) Require(tracker.Snapshot().State != OperationProgressState.Completed,
                            "An internal producer claimed outer success.");
                    }
                    finally { stop.Cancel(); await polling; }
                }
            }
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    private static GeneratedArchiveEntropy CreateEntropy()
    {
        var salt1 = LockedSensitiveBuffer.Create(128); var salt2 = LockedSensitiveBuffer.Create(128);
        var nonce1 = LockedSensitiveBuffer.Create(320); var nonce2 = LockedSensitiveBuffer.Create(320);
        Fill(salt1.Bytes, 29, 23); Fill(salt2.Bytes, 61, 161);
        Fill(nonce1.Bytes, 43, 43); Fill(nonce2.Bytes, 73, 211);
        return new GeneratedArchiveEntropy(FactorA, FactorB, salt1, nonce1, salt2, nonce2);
    }
    private static void Fill(byte[] buffer, int multiplier, int seed)
    { for (int i = 0; i < buffer.Length; i++) buffer[i] = unchecked((byte)(i * multiplier + seed)); }

    private static Task PrivacyAsync()
    {
        string[] expected = ["OperationId", "PlanRevision", "PhaseId", "Phase", "PassId", "Sequence", "State", "Unit",
            "CompletedUnits", "TotalUnits", "TotalOrigin", "MonotonicTimestamp", "ActivePhaseDuration", "ElapsedDuration",
            "PausedDuration", "RatePerSecond", "PhaseRemaining", "OverallRemaining", "EstimateState", "StatusCode"];
        var properties = typeof(OperationProgressSnapshot).GetProperties();
        Require(properties.Select(p => p.Name).Order().SequenceEqual(expected.Order()), "Progress DTO acquired an unreviewed field.");
        foreach (var property in properties)
        {
            Type type = Nullable.GetUnderlyingType(property.PropertyType) ?? property.PropertyType;
            Require(type.IsEnum || type == typeof(Guid) || type == typeof(long) || type == typeof(int)
                || type == typeof(double) || type == typeof(TimeSpan), "Progress acquired a path, credential or byte payload.");
        }
        return Task.CompletedTask;
    }

    private static Task PerformanceAsync()
    {
        using var tracker = new OperationProgressTracker();
        using var source = tracker.BeginPhase(OperationPhase.Compression)!;
        for (int i = 0; i < 10000; i++) source.Advance(1); // JIT warmup, outside measurement.
        long allocated = GC.GetAllocatedBytesForCurrentThread();
        var watch = Stopwatch.StartNew();
        for (int i = 0; i < 1_000_000; i++) source.Advance(1);
        watch.Stop();
        long difference = GC.GetAllocatedBytesForCurrentThread() - allocated;
        Require(difference < 4096, "Hot progress messages allocated per-update storage.");
        Require(tracker.Snapshot().CompletedUnits == 1_010_000, "Observer lost hot progress counts.");
        // No speed deadline is imposed: the measurement is reproducible evidence,
        // while the allocation ceiling tests a concrete bounded-state contract.
        Console.WriteLine($"PROGRESS_HOT_UPDATES count=1000000 allocatedBytes={difference} elapsedMs={watch.Elapsed.TotalMilliseconds:F3}");
        File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "progress-overhead-public.json"),
            System.Text.Json.JsonSerializer.Serialize(new
            {
                runUtc = DateTimeOffset.UtcNow,
                updates = 1_000_000,
                allocatedBytes = difference,
                elapsedMilliseconds = watch.Elapsed.TotalMilliseconds,
                scope = "Single macOS process, hot producer updates only; no many-core or UI performance claim",
            }));
        return Task.CompletedTask;
    }

    private static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private sealed class BrokenClock : TimeProvider
    { public override long GetTimestamp() => throw new IOException("Injected public test clock failure."); }
}
