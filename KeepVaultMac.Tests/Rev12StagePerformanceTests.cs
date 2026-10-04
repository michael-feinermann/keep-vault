using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using KalynaArchiver.Services;

internal static class Rev12StagePerformanceTests
{
    internal static TestCase Test => new("performance.rev12-stage-profile",
        "public 256 MiB stage/cascade medians, actual granted teams and observation overhead",
        RunAsync, TestResource.CpuHeavy, "Performance", IsPerformance: true)
    { Cost = new TestCost(9, 1536, true, TestConstraint.HostExclusive) };

    private static Task RunAsync()
    {
#if DEBUG
        throw new InvalidOperationException("Release configuration is required for the native stage profile.");
#endif
        const int bytes = 256 * 1024 * 1024, chunk = 16 * 1024 * 1024, runs = 5;
        EncryptionSuite[] suites = [EncryptionSuite.Aes256, EncryptionSuite.Mars448,
            EncryptionSuite.Camellia256, EncryptionSuite.Serpent256, EncryptionSuite.Shacal2_512,
            EncryptionSuite.Kalyna512_512, EncryptionSuite.Threefish1024, EncryptionSuite.XChaCha20Poly1305,
            EncryptionSuite.StandardCascade, EncryptionSuite.ParanoiaCascade];
        byte[] input = new byte[bytes], output = new byte[bytes];
        byte[] blockInput = new byte[chunk], blockOutput = new byte[chunk], tag = new byte[16];
        for (int i = 0; i < bytes; i++) input[i] = (byte)((i * 31 + i / 251) & 255);
        var rows = new List<object>();
        var expected = new Dictionary<EncryptionSuite, (byte[] Hash, byte[] Tags)>();
        string[] nativeNames = ["libaes_ref.dylib", "libmars_ref.dylib", "libcamellia_v13.dylib",
            "libserpent_v13.dylib", "libshacal2_ref.dylib", "libkalyna_v13.dylib",
            "libthreefish_ref.dylib", "libxchachapoly_v13.dylib"];
        var nativeBefore = nativeNames.ToDictionary(n => n, n => HashFile(Path.Combine(AppContext.BaseDirectory, "Native", n)));
        try
        {
            int available = ArchiveOperationPolicy.Current.MaxCpuWorkers;
            foreach (int requested in new[] { available, 1, Math.Min(4, available) }.Distinct())
            {
                var permitTimer = Stopwatch.StartNew();
                using CpuWorkBudget.Lease lease = CpuWorkBudget.AcquireAsync(requested, requested, default).GetAwaiter().GetResult();
                permitTimer.Stop();
                using IDisposable cpuScope = lease.EnterScope();
                using IDisposable workerScope = NativeCipherWorkerBudget.EnterScope(lease.Workers);
                foreach (EncryptionSuite suite in suites)
                {
                    EncryptionSuiteParameters p = EncryptionSuiteCatalog.Get(suite);
                    byte[] key = PublicBytes(p.EncryptionKeyBytes, 7 + (int)suite);
                    byte[] nonce = PublicBytes(p.StageNonceBytes, 17 + (int)suite);
                    byte[] archiveNonce = PublicBytes(p.ArchiveNonceBytes, 29 + (int)suite);
                    byte[] tweak = KalynaContainerService.CreateSuiteTweak(p, archiveNonce);
                    byte[] aad = "Public REV12 cipher scheduling profile"u8.ToArray();
                    byte[] allTags = new byte[(bytes / chunk) * tag.Length];
                    var wall = new List<double>();
                    var cpu = new List<double>();
                    var defaultWall = new List<double>();
                    var defaultCpu = new List<double>();
                    var phaseProfiles = new List<OperationPhaseProfile.ProfileSnapshot>();
                    var scheduling = new List<object>();
                    try
                    {
                        // One complete warm-up for each variant, then five
                        // interleaved pairs in a fixed alternating order. No
                        // outcome selects, discards or adds a sample.
                        for (int run = -1; run < runs; run++)
                        foreach (bool enabled in run % 2 == 0 ? new[] { false, true } : new[] { true, false })
                        {
                            NativeCipherExecutor.Measurements? observation = enabled ? new() : null;
                            OperationPhaseProfile.Measurements? phases = enabled ? new() : null;
                            using IDisposable? observer = observation is null ? null : NativeCipherExecutor.ObserveForTests(observation);
                            using IDisposable? phaseObserver = phases is null ? null : OperationPhaseProfile.ObserveForTests(phases);
                            using Process process = Process.GetCurrentProcess();
                            TimeSpan cpuBefore = process.TotalProcessorTime;
                            Stopwatch timer = Stopwatch.StartNew();
                            for (int offset = 0, index = 0; offset < bytes; offset += chunk, index++)
                            {
                                // Fixed distinct public stage counters, identical across worker grants.
                                byte[] counter = nonce.ToArray();
                                if (p.Cascade is { } cascade)
                                {
                                    int start = 0;
                                    foreach (CascadeStage stage in cascade.Stages)
                                    { counter[start] ^= (byte)index; start += stage.NonceBytes; }
                                }
                                else counter[0] ^= (byte)index;
                                try
                                {
                                    input.AsSpan(offset, chunk).CopyTo(blockInput);
                                    Array.Clear(tag);
                                    KalynaContainerService.EncryptSuiteChunkForTests(p, key, tweak, counter,
                                        blockInput, blockOutput, chunk, aad, tag);
                                    blockOutput.CopyTo(output, offset);
                                    tag.CopyTo(allTags, index * tag.Length);
                                }
                                finally { CryptographicOperations.ZeroMemory(counter); }
                            }
                            timer.Stop();
                            process.Refresh();
                            double cpuSeconds = (process.TotalProcessorTime - cpuBefore).TotalSeconds;
                            byte[] digest = SHA256.HashData(output);
                            if (!expected.TryGetValue(suite, out var reference))
                                expected.Add(suite, (digest.ToArray(), allTags.ToArray()));
                            else if (!CryptographicOperations.FixedTimeEquals(reference.Hash, digest)
                                || !CryptographicOperations.FixedTimeEquals(reference.Tags, allTags))
                                throw new InvalidOperationException("Cipher/tag output changed across equal inputs, repeats or worker grants.");
                            CryptographicOperations.ZeroMemory(digest);
                            if (run >= 0)
                            {
                                if (enabled)
                                {
                                    wall.Add(timer.Elapsed.TotalSeconds); cpu.Add(cpuSeconds);
                                    NativeCipherExecutor.SchedulingSnapshot sample = observation!.Snapshot();
                                    if (!sample.observationAvailable || sample.activeCallbacks != 0
                                        || sample.maximumGrant > lease.Workers || sample.peakActiveCallbacks > lease.Workers)
                                        throw new InvalidOperationException("Native scheduling observation is unavailable, incomplete or exceeds the granted team.");
                                    OperationPhaseProfile.ProfileSnapshot profile = phases!.Snapshot();
                                    if (!profile.ObservationAvailable)
                                        throw new InvalidOperationException("The stage phase observation is unavailable.");
                                    scheduling.Add(sample); phaseProfiles.Add(profile);
                                }
                                else { defaultWall.Add(timer.Elapsed.TotalSeconds); defaultCpu.Add(cpuSeconds); }
                            }
                        }
                        double median = defaultWall.Order().ElementAt(runs / 2);
                        double profiledMedian = wall.Order().ElementAt(runs / 2);
                        double rate = 256 / median;
                        Console.WriteLine($"    REV12 {suite} granted={lease.Workers} default median={rate:F2} MiB/s range={256 / defaultWall.Max():F2}..{256 / defaultWall.Min():F2}; observed={256 / profiledMedian:F2} MiB/s");
                        rows.Add(new { suite = suite.ToString(), mode = requested == available ? "ResolvedCpuCeiling" : "FixedCpuGrant",
                            configuredCpuMode = ArchiveOperationPolicy.Current.Preferences.CpuMode.ToString(),
                            requestedWorkers = requested, direction = "Encryption",
                            grantedWorkers = lease.Workers, payloadBytes = bytes, chunkBytes = chunk,
                            warmupsPerVariant = 1, measuredRunsPerVariant = runs, medianMiBPerSecond = rate,
                            method = "default and enabled observers paired in fixed alternating order; equal public chunk input/AAD, ciphertext and tags; cipher-only without container framing",
                            wallSeconds = defaultWall, processCpuSeconds = defaultCpu,
                            profiledMedianMiBPerSecond = 256 / profiledMedian,
                            profiledWallSeconds = wall, profiledProcessCpuSeconds = cpu,
                            observedMedianTimeOverheadFraction = profiledMedian / median - 1,
                            permitAcquireSeconds = permitTimer.Elapsed.TotalSeconds,
                            phaseProfiles, nativeScheduling = scheduling, outputSha256 = Convert.ToHexString(expected[suite].Hash),
                            tagSequenceSha256 = Convert.ToHexString(SHA256.HashData(expected[suite].Tags)) });
                    }
                    finally
                    {
                        foreach (byte[] material in new[] { key, nonce, archiveNonce, tweak, aad, allTags })
                            CryptographicOperations.ZeroMemory(material);
                    }
                }
            }
            foreach (string name in nativeNames)
                if (HashFile(Path.Combine(AppContext.BaseDirectory, "Native", name)) != nativeBefore[name])
                    throw new InvalidOperationException("A loaded native profile input changed during measurement.");
            string root = Environment.GetEnvironmentVariable("KEEPVAULT_TEST_REPOSITORY_ROOT")
                ?? throw new InvalidOperationException("The profile needs an explicit source root.");
            string directory = Path.Combine(root, "work", "v13-evidence");
            Directory.CreateDirectory(directory);
            var report = new { schemaVersion = 1, measuredUtc = DateTimeOffset.UtcNow,
                scope = "Managed Release harness calling production native cipher routes; cipher-only, includes chunk copies. Not an installed GUI/KDF/ZPAQ/whole-workflow result.",
                processArchitecture = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture.ToString(),
                os = System.Runtime.InteropServices.RuntimeInformation.OSDescription,
                assemblySha256 = HashFile(typeof(KalynaContainerService).Assembly.Location), nativeSha256 = nativeBefore,
                aesProvider = NativeAes.RuntimeProvider.ToString(),
                payloadSha256 = Convert.ToHexString(SHA256.HashData(input)), results = rows };
            string artifact = Path.Combine(directory,
                "rev12-cipher-stage-profile-" + DateTimeOffset.UtcNow.ToString("yyyyMMddTHHmmssfff") + "-" + Guid.NewGuid().ToString("N") + ".json");
            using (var file = new FileStream(artifact, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                JsonSerializer.Serialize(file, report, new JsonSerializerOptions { WriteIndented = true });
            Console.WriteLine("REV12_STAGE_PROFILE_ARTIFACT=" + artifact);
        }
        finally
        {
            foreach (byte[] buffer in new[] { input, output, blockInput, blockOutput, tag }) CryptographicOperations.ZeroMemory(buffer);
            foreach (var pair in expected.Values)
            { CryptographicOperations.ZeroMemory(pair.Hash); CryptographicOperations.ZeroMemory(pair.Tags); }
        }
        return Task.CompletedTask;
    }
    private static byte[] PublicBytes(int count, int seed) => Enumerable.Range(0, count).Select(i => (byte)((i * 37 + seed) & 255)).ToArray();
    private static string HashFile(string path)
    { using var stream = File.OpenRead(path); return Convert.ToHexString(SHA256.HashData(stream)); }
}
