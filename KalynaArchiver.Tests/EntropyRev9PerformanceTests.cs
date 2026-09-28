using System.Buffers.Binary;
using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using KalynaArchiver.Services;

// Manual measurement of public synthetic records through production store,
// shuffle, replay and cleanup APIs. OS randomness and derived bytes are never logged.
internal static class EntropyRev9PerformanceTests
{
    internal static IReadOnlyList<TestCase> Tests =>
    [
        new("entropy.rev9-finalization-golden", "REV9 isolated P1/P2 finalization and 320-byte XOR against frozen Python values", FinalizationGoldenAsync, TestResource.Light, "Entropy"),
        new("entropy.rev9-cache-equivalence", "REV9 4/16/64 KiB shuffle caches consume equivalent public streams", CacheEquivalenceAsync, TestResource.ProcessGlobal, "Entropy"),
        new("performance.entropy-rev9-phases", "REV9 eleven-pool capture/shuffle/replay/cleanup phase measurements", MeasureAsync, TestResource.ProcessGlobal, "Performance", IsPerformance: true),
    ];

    private delegate void XorBuffers(Span<byte> destination, ReadOnlySpan<byte> source);
    private static Task FinalizationGoldenAsync()
    {
        string path = Path.Combine(RepositoryLayout.FindRepositoryRoot(), "KeepVaultMac.Tests", "Fixtures", "V13Reference", "pool_finalization_rev9_vectors.json");
        byte[] fixture = File.ReadAllBytes(path);
        Require(Convert.ToHexString(SHA256.HashData(fixture)) == "87156EC384CC129F233E93BB07BC23C9FF5C0F61ABA1F0E2F70852EB491FABBD", "Frozen finalization fixture hash changed.");
        using var document = JsonDocument.Parse(fixture);
        var root = document.RootElement;
        byte[] firstNonce = new byte[320], secondNonce = new byte[320];
        long baseline = SecureMemory.LockedAllocationsForTests;
        foreach (var item in root.GetProperty("pools").EnumerateArray())
        {
            int purpose = item.GetProperty("purpose").GetInt32();
            ulong epoch = ulong.Parse(item.GetProperty("epoch").GetString()!, System.Globalization.CultureInfo.InvariantCulture);
            byte[] accumulator = Convert.FromHexString(item.GetProperty("accumulator").GetString()!);
            foreach (bool sha512 in new[] { false, true })
            {
                byte[] output = new byte[64];
                ConsumedEntropySnapshot.FinalizePoolOutput(accumulator, epoch, purpose, sha512, output);
                Require(Convert.ToHexString(output).Equals(item.GetProperty(sha512 ? "second" : "first").GetString(), StringComparison.OrdinalIgnoreCase), "Pool finalization differs from frozen independent transcript.");
                if (purpose >= 6) output.CopyTo(sha512 ? secondNonce : firstNonce, (purpose - 6) * 64);
            }
        }
        var xor = typeof(EntropyMixer).GetMethod("XorInPlace", BindingFlags.NonPublic | BindingFlags.Static)!.CreateDelegate<XorBuffers>();
        byte[] os = Convert.FromHexString(root.GetProperty("os320").GetString()!);
        xor(firstNonce, os); xor(secondNonce, os);
        Require(Convert.ToHexString(firstNonce).Equals(root.GetProperty("firstNonce").GetString(), StringComparison.OrdinalIgnoreCase)
            && Convert.ToHexString(secondNonce).Equals(root.GetProperty("secondNonce").GetString(), StringComparison.OrdinalIgnoreCase), "Actual 320-byte pool XOR differs from frozen independent values.");
        Require(SecureMemory.LockedAllocationsForTests == baseline, "Finalization retained a transcript buffer.");
        return Task.CompletedTask;
    }

    private static Task CacheEquivalenceAsync()
    {
        byte[]? expected = null;
        long baseline = SecureMemory.LockedAllocationsForTests;
        using var store = CreateStore(65536, 7);
        foreach (int bufferBytes in new[] { 4096, 16384, 65536 })
        {
            store.InitializeIndices(default);
            byte[] results = new byte[64 + 64 + 32 + 32];
            try
            {
                using (var random = new PoolShuffleRandomSource(EntropyRandomRole.PoolShuffleRound1, new PublicStream(0xA731B294).Fill, bufferBytes))
                    random.Shuffle(store, default);
                ConsumedEntropySnapshot.Replay(store, 7, 19, false, results.AsSpan(0, 64), default);
                HashIndices(store).CopyTo(results, 128);
                using (var random = new PoolShuffleRandomSource(EntropyRandomRole.PoolShuffleRound2, new PublicStream(0x94B231A7).Fill, bufferBytes))
                    random.Shuffle(store, default);
                ConsumedEntropySnapshot.Replay(store, 7, 19, true, results.AsSpan(64, 64), default);
                HashIndices(store).CopyTo(results, 160);
                if (expected is null) expected = (byte[])results.Clone();
                else Require(results.SequenceEqual(expected), "Cache refill width changed the permutation or replay bytes for an identical source stream.");
            }
            finally { CryptographicOperations.ZeroMemory(results); }
        }
        CryptographicOperations.ZeroMemory(expected!);
        store.Dispose();
        Require(SecureMemory.LockedAllocationsForTests == baseline, "Cache comparison leaked protected storage.");
        return Task.CompletedTask;
    }

    private sealed class PublicStream(ulong seed)
    {
        private ulong _state = seed;
        // Synthetic test-only byte stream. This is never a production RNG.
        internal void Fill(byte[] bytes, EntropyRandomRole role)
        {
            for (int offset = 0; offset < bytes.Length; offset += 8)
            {
                _state += 0x9E3779B97F4A7C15UL;
                ulong z = _state;
                z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9UL;
                z = (z ^ (z >> 27)) * 0x94D049BB133111EBUL;
                BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(offset), z ^ (z >> 31));
            }
        }
    }

    private static byte[] HashIndices(SensitiveMouseRecordStore store)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> indexBytes = stackalloc byte[8];
        for (long i = 0; i < store.Count; ++i)
        {
            BinaryPrimitives.WriteInt64LittleEndian(indexBytes, store.ReadIndex(i));
            hash.AppendData(indexBytes);
        }
        return hash.GetHashAndReset();
    }

    private static async Task MeasureAsync()
    {
        Require(EntropyMixer.RandomFillForTests is null && EntropyMixer.GetPoolStatus().Total == 0,
            "Performance measurement requires a clean real OS-RNG state.");
        var fill = typeof(EntropyMixer).GetMethod("FillRandom", BindingFlags.Static | BindingFlags.NonPublic)!
            .CreateDelegate<Action<byte[], EntropyRandomRole>>();
        ArchiveOperationPolicy policy = ArchiveOperationPolicy.Current;
        using OperationMemoryBudget.Lease memory = await OperationMemoryBudget.AcquireAsync(policy, default);
        using IDisposable memoryScope = memory.EnterScope();
        long baselineLocks = SecureMemory.LockedAllocationsForTests;
        long baselineBytes = SecureMemory.LockedBytesForTests;
        var cases = new List<object>();
        int[][] counts = [.. new[] { 1024, 4096, 16384, 65536 }.Select(n => Enumerable.Repeat(n, 11).ToArray()),
            [1024, 1025, 2048, 4096, 4097, 8192, 16384, 16385, 32768, 65535, 65536]];
        // Warm both replay families and the complete shuffle path enough to
        // include steady-state tiered JIT code in the repeated phase samples.
        int warmupIterations = 0;
        var warmupClock = Stopwatch.StartNew();
        using (var warm = CreateStore(1024, 0))
        {
            byte[] output = new byte[64];
            try
            {
                while (warmupIterations < 64 || warmupClock.Elapsed < TimeSpan.FromSeconds(3))
                {
                    warm.InitializeIndices(default);
                    using (var rng = new PoolShuffleRandomSource(EntropyRandomRole.PoolShuffleRound1, fill)) rng.Shuffle(warm, default);
                    ConsumedEntropySnapshot.Replay(warm, 0, 1, false, output, default);
                    using (var rng = new PoolShuffleRandomSource(EntropyRandomRole.PoolShuffleRound2, fill)) rng.Shuffle(warm, default);
                    ConsumedEntropySnapshot.Replay(warm, 0, 1, true, output, default);
                    warmupIterations++;
                }
            }
            finally { CryptographicOperations.ZeroMemory(output); }
        }
        warmupClock.Stop();
        foreach (int[] shape in counts)
        for (int repetition = 0; repetition < 5; ++repetition)
        {
            var pools = new SensitiveMouseRecordStore[11];
            byte[] digest = new byte[64];
            double capture = 0, indices = 0, fy1 = 0, sha3 = 0, fy2 = 0, sha512 = 0, cleanup = 0;
            long rngTicks = 0, rngCalls = 0, rngBytes = 0, peakLocked = baselineBytes, peakReserved = 0;
            void Observe()
            {
                peakLocked = Math.Max(peakLocked, SecureMemory.LockedBytesForTests);
                peakReserved = Math.Max(peakReserved, SensitiveMouseRecordStore.Segment.ReservedBytes);
            }
            void OsFill(byte[] bytes, EntropyRandomRole role)
            {
                long start = Stopwatch.GetTimestamp();
                fill(bytes, role);
                rngTicks += Stopwatch.GetTimestamp() - start;
                rngCalls++; rngBytes += bytes.Length; Observe();
            }
            static double Measure(Action action)
            {
                var timer = Stopwatch.StartNew(); action(); return timer.Elapsed.TotalMilliseconds;
            }
            try
            {
                capture = Measure(() => { for (int purpose = 0; purpose < 11; ++purpose) pools[purpose] = CreateStore(shape[purpose], purpose); });
                Observe();
                using CpuWorkBudget.Lease cpu = await CpuWorkBudget.AcquireAsync(policy.MaxCpuWorkers, 1, default);
                // Sequential phase isolation gives additive timings. Production
                // parallel snapshot scheduling has separate end-to-end evidence.
                for (int purpose = 0; purpose < 11; ++purpose)
                {
                    SensitiveMouseRecordStore pool = pools[purpose];
                    indices += Measure(() => pool.InitializeIndices(default));
                    fy1 += Measure(() => { using var rng = new PoolShuffleRandomSource(EntropyRandomRole.PoolShuffleRound1, OsFill); Observe(); rng.Shuffle(pool, default); });
                    sha3 += Measure(() => ConsumedEntropySnapshot.Replay(pool, purpose, 29, false, digest, default));
                    fy2 += Measure(() => { using var rng = new PoolShuffleRandomSource(EntropyRandomRole.PoolShuffleRound2, OsFill); Observe(); rng.Shuffle(pool, default); });
                    sha512 += Measure(() => ConsumedEntropySnapshot.Replay(pool, purpose, 29, true, digest, default));
                }
            }
            finally
            {
                cleanup = Measure(() => SecureMemory.DisposeAll(pools));
                CryptographicOperations.ZeroMemory(digest);
            }
            Require(SecureMemory.LockedAllocationsForTests == baselineLocks
                && SensitiveMouseRecordStore.Segment.ReservedBytes == 0, "Measured lifecycle did not release every protected record/index/cache.");
            cases.Add(new { repetition, recordsPerPool = shape, totalRecords = shape.Sum(), rawRecordBytes = checked(shape.Sum() * 80L),
                cacheBytes = 4096, actualOsRng = true, captureMs = capture, initializeIndexMs = indices,
                shuffle1Ms = fy1, replaySha3Ms = sha3, shuffle2Ms = fy2, replaySha512Ms = sha512,
                cleanupMs = cleanup, osRngMsIncludedInShuffle = rngTicks * 1000.0 / Stopwatch.Frequency,
                osRngCalls = rngCalls, osRngBytes = rngBytes, observedPeakLockedBytes = peakLocked - baselineBytes,
                peakReservedRecordStorageBytes = peakReserved });
        }
        var cacheMeasurements = new List<object>();
        foreach (int cacheBytes in new[] { 4096, 16384, 65536 })
        {
            using var store = CreateStore(65536, 4);
            using CpuWorkBudget.Lease cpu = await CpuWorkBudget.AcquireAsync(policy.MaxCpuWorkers, 1, default);
            var repeats = new List<object>();
            for (int sample = 0; sample < 5; ++sample)
            {
                store.InitializeIndices(default);
                long rngTicks = 0, rngCalls = 0, rngBytes = 0;
                void TimedFill(byte[] buffer, EntropyRandomRole role)
                {
                    long start = Stopwatch.GetTimestamp(); fill(buffer, role);
                    rngTicks += Stopwatch.GetTimestamp() - start; rngCalls++; rngBytes += buffer.Length;
                }
                var timer = Stopwatch.StartNew();
                using (var random = new PoolShuffleRandomSource(EntropyRandomRole.PoolShuffleRound1, TimedFill, cacheBytes))
                    random.Shuffle(store, default);
                repeats.Add(new { sample, shuffleIncludingOsRngAndCacheCleanupMs = timer.Elapsed.TotalMilliseconds,
                    osRngMs = rngTicks * 1000.0 / Stopwatch.Frequency, rngCalls, rngBytes });
            }
            cacheMeasurements.Add(new { cacheBytes, count = 65536, repetitions = repeats });
        }
        var isolated = new List<object>();
        var xor = typeof(EntropyMixer).GetMethod("XorInPlace", BindingFlags.NonPublic | BindingFlags.Static)!.CreateDelegate<XorBuffers>();
        using (CpuWorkBudget.Lease cpu = await CpuWorkBudget.AcquireAsync(policy.MaxCpuWorkers, 1, default))
        using (var accumulator = LockedSensitiveBuffer.Create(64))
        using (var result = LockedSensitiveBuffer.Create(64))
        using (var poolBytes = LockedSensitiveBuffer.Create(320))
        using (var randomBytes = LockedSensitiveBuffer.Create(320))
        {
            const int calls = 4096;
            for (int sample = 0; sample < 5; ++sample)
            {
                double FinalizeMany(bool sha512)
                {
                    var timer = Stopwatch.StartNew();
                    for (int i = 0; i < calls; ++i)
                        ConsumedEntropySnapshot.FinalizePoolOutput(accumulator.Bytes, (ulong)i, i % 11, sha512, result.Bytes);
                    return timer.Elapsed.TotalMilliseconds;
                }
                double sha3Ms = FinalizeMany(false), sha512Ms = FinalizeMany(true);
                long osTicks = 0, xorTicks = 0;
                var total = Stopwatch.StartNew();
                for (int i = 0; i < calls; ++i)
                {
                    poolBytes.Bytes.AsSpan().Fill(0x3D);
                    long start = Stopwatch.GetTimestamp(); fill(randomBytes.Bytes, EntropyRandomRole.OutputXor);
                    osTicks += Stopwatch.GetTimestamp() - start;
                    start = Stopwatch.GetTimestamp(); xor(poolBytes.Bytes, randomBytes.Bytes);
                    xorTicks += Stopwatch.GetTimestamp() - start;
                }
                isolated.Add(new { sample, calls, finalizeSha3IncludingLockedTranscriptCleanupMs = sha3Ms,
                    finalizeSha512IncludingLockedTranscriptCleanupMs = sha512Ms,
                    outputXor320IncludingOsRngAndPoolResetMs = total.Elapsed.TotalMilliseconds,
                    outputOsRng320Ms = osTicks * 1000.0 / Stopwatch.Frequency,
                    outputXor320Ms = xorTicks * 1000.0 / Stopwatch.Frequency });
            }
        }
        Require(SecureMemory.LockedAllocationsForTests == baselineLocks
            && SensitiveMouseRecordStore.Segment.ReservedBytes == 0, "Isolated measurements leaked protected storage.");
        string path = Path.Combine(RepositoryLayout.FindRepositoryRoot(), "work", "v13-evidence", "entropy-rev9-phase-performance.json");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(new { schemaVersion = 2,
            warmup = "at least3seconds and64complete1024-record dual-shuffle/replay lifecycles before phase samples",
            warmupIterations, warmupMs = warmupClock.Elapsed.TotalMilliseconds,
            phaseRepetitions = 5,
            utc = DateTimeOffset.UtcNow, processArchitecture = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture.ToString(),
            processorCount = Environment.ProcessorCount, measurement = "sequential production-component microbenchmark; no archive/release throughput claim",
            cacheEquivalenceSizes = new[] {4096,16384,65536},
            replayTimingIncludesFinalPoolHash = true,
            cacheMeasurement = "same public records/count, real fresh OS randomness per run; deterministic stream equality is a separate correctness gate",
            cases, cacheMeasurements, isolated }, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine($"REV9 entropy phase measurements: {path}");
    }

    private static SensitiveMouseRecordStore CreateStore(int count, int purpose)
    {
        var store = new SensitiveMouseRecordStore();
        SensitiveMouseRecordStore.Segment? spare = null;
        Span<byte> record = stackalloc byte[80];
        try
        {
            for (int index = 0; index < count; ++index)
            {
                if (store.NeedsSegment)
                {
                    store.ReserveSegmentMetadata();
                    spare = new SensitiveMouseRecordStore.Segment(ArchiveOperationPolicy.Current.EntropyCaptureBudgetBytes);
                }
                for (int offset = 0; offset < 72; ++offset) record[offset] = unchecked((byte)(purpose * 37 + index * 11 + offset * 7));
                BinaryPrimitives.WriteInt64LittleEndian(record[72..], index);
                store.Append(record, ref spare);
            }
            store.Seal(); return store;
        }
        catch { store.Dispose(); throw; }
        finally { spare?.Dispose(); CryptographicOperations.ZeroMemory(record); }
    }
    private static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
}
