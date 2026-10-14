using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using KalynaArchiver.Services;

internal static class MacPhasePerformanceTests
{
    internal static IReadOnlyList<TestCase> All =>
    [
        new("performance.mac-root-phases", "actual v13 dual-MAC leaf/root/serial remainder timing", RunAsync, TestResource.ProcessGlobal, "Performance", IsPerformance: true),
    ];

    private static async Task RunAsync()
    {
        const int payloadBytes = 64 * 1024 * 1024;
        const int repetitions = 5;
        byte[] payload = new byte[payloadBytes];
        for (int i = 0; i < payload.Length; ++i) payload[i] = (byte)(i * 37 + 11);
        byte[] sha3Key = Enumerable.Range(0, 64).Select(i => (byte)(i * 13 + 7)).ToArray();
        byte[] skeinKey = Enumerable.Range(0, 128).Select(i => (byte)(i * 29 + 3)).ToArray();
        byte[] prefix = "Public v13 dual-MAC phase benchmark, no archive credentials"u8.ToArray();
        byte[]? expectedSha3 = null, expectedSkein = null;
        var results = new List<object>();
        int available = Math.Min(CpuTopology.AvailableWorkers, ArchiveOperationPolicy.Current.MaxCpuWorkers);
        try
        {
            // No enclosing CPU lease: ComputeAsync owns its actual per-leaf
            // and root leases/scopes. A full outer lease would deadlock them.
            foreach (int workers in new[] { 1, available }.Distinct())
            {
                using IDisposable workerScope = ParallelContainerAuthenticator.UseWorkerCountForTests(workers);
                var wall = new List<double>();
                var phases = new List<Dictionary<string, double>>();
                var cpu = new List<double>();
                var allocations = new List<long>();
                for (int run = -1; run < repetitions; ++run)
                {
                    using var stream = new MemoryStream(payload, writable: false);
                    var measurement = new ParallelContainerAuthenticator.PhaseMeasurementsForTests();
                    using IDisposable observer = ParallelContainerAuthenticator.ObservePhasesForTests(measurement);
                    long allocatedBefore = GC.GetTotalAllocatedBytes(true);
                    TimeSpan cpuBefore = Process.GetCurrentProcess().TotalProcessorTime;
                    var timer = Stopwatch.StartNew();
                    (byte[] sha3, byte[] skein) = await ParallelContainerAuthenticator.ComputeAsync(
                        stream, 0, [prefix], sha3Key, skeinKey, CancellationToken.None).ConfigureAwait(false);
                    timer.Stop();
                    double cpuSeconds = (Process.GetCurrentProcess().TotalProcessorTime - cpuBefore).TotalSeconds;
                    long allocated = GC.GetTotalAllocatedBytes(true) - allocatedBefore;
                    try
                    {
                        expectedSha3 ??= sha3.ToArray();
                        expectedSkein ??= skein.ToArray();
                        if (!CryptographicOperations.FixedTimeEquals(sha3, expectedSha3)
                            || !CryptographicOperations.FixedTimeEquals(skein, expectedSkein))
                            throw new InvalidOperationException("MAC phase instrumentation/worker count changed a tag.");
                        if (run >= 0)
                        {
                            Dictionary<string, double> values = measurement.Seconds();
                            if (values.Values.Any(value => value < 0)
                                || values.Values.Sum() > timer.Elapsed.TotalSeconds + 0.001)
                                throw new InvalidOperationException("MAC phase intervals overlap or exceed operation wall time.");
                            phases.Add(values); wall.Add(timer.Elapsed.TotalSeconds);
                            cpu.Add(cpuSeconds); allocations.Add(allocated);
                        }
                    }
                    finally { CryptographicOperations.ZeroMemory(sha3); CryptographicOperations.ZeroMemory(skein); }
                }
                double[] rootSeconds = phases.Select(value => value["RootInitialization"] + value["OrderedRoot"] + value["FinalTags"]).ToArray();
                double[] nonLeaf = phases.Select((value, index) => Math.Max(0, wall[index] - value["LeafBatches"])).ToArray();
                results.Add(new
                {
                    worker_count = workers, payload_bytes = payloadBytes, authenticated_prefix_bytes = prefix.Length,
                    leaf_bytes = ParallelContainerAuthenticator.LeafBytes,
                    leaf_count = (payloadBytes + prefix.Length + ParallelContainerAuthenticator.LeafBytes - 1) / ParallelContainerAuthenticator.LeafBytes,
                    warmup_runs = 1, measured_runs = repetitions, wall_seconds = wall, cpu_seconds = cpu,
                    phases_seconds = phases, root_seconds = rootSeconds, non_leaf_wall_seconds = nonLeaf,
                    root_fraction = rootSeconds.Select((value, index) => value / wall[index]).ToArray(),
                    median_wall_seconds = Median(wall), median_root_seconds = Median(rootSeconds),
                    median_non_leaf_wall_seconds = Median(nonLeaf), managed_allocated_bytes = allocations,
                    sha3_tag = Convert.ToHexString(expectedSha3!), skein_tag = Convert.ToHexString(expectedSkein!),
                });
            }
            // Control with the observer entirely absent, same actual product path.
            using var controlStream = new MemoryStream(payload, writable: false);
            (byte[] controlSha3, byte[] controlSkein) = await ParallelContainerAuthenticator.ComputeAsync(
                controlStream, 0, [prefix], sha3Key, skeinKey, CancellationToken.None).ConfigureAwait(false);
            try
            {
                if (!controlSha3.SequenceEqual(expectedSha3!) || !controlSkein.SequenceEqual(expectedSkein!))
                    throw new InvalidOperationException("The timing-disabled MAC control differs.");
            }
            finally { CryptographicOperations.ZeroMemory(controlSha3); CryptographicOperations.ZeroMemory(controlSkein); }
            if (CpuWorkBudget.ActiveWorkersForTests != 0)
                throw new InvalidOperationException("The completed MAC phase run retained CPU leases.");
            Console.WriteLine("    MAC_PHASE_RESULT_JSON=" + JsonSerializer.Serialize(new
            {
                schema = 1, status = "PASS", scope = "actual ParallelContainerAuthenticator.ComputeAsync over public in-memory ciphertext",
                leaf_interval = "batch scheduling, CPU permit wait, both leaf MAC families and join wall time",
                non_leaf_interval = "operation wall minus measured leaf batches; includes ordered root, key setup, memory-stream reads, cleanup, uninstrumented overhead and permit waits; not a universal serial CPU fraction",
                observer = "optional AsyncLocal timing-only seam; absent-observer control produces identical tags",
                stopwatch_frequency = Stopwatch.Frequency, results,
            }));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload); CryptographicOperations.ZeroMemory(sha3Key);
            CryptographicOperations.ZeroMemory(skeinKey); CryptographicOperations.ZeroMemory(prefix);
            if (expectedSha3 is not null) CryptographicOperations.ZeroMemory(expectedSha3);
            if (expectedSkein is not null) CryptographicOperations.ZeroMemory(expectedSkein);
        }
    }

    private static double Median(IEnumerable<double> values)
    {
        double[] ordered = values.Order().ToArray(); return ordered[ordered.Length / 2];
    }
}
