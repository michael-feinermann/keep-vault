using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using KalynaArchiver.Services;

/// <summary>
/// Manual §4.13 control matrix. One actual complete measured workflow per
/// expensive case, never reported as five repeats or installed-GUI evidence.
/// No test KDF override, disabled MAC, precooked compressed archive or cipher
/// shortcut is used. Generated fixtures and passwords belong only to the test.
/// </summary>
internal static class Rev12ArchiveWorkflowPerformanceTests
{
    private const int Level = ArchiveWorkflowTestSettings.CompressionLevel;
    private const long LongBytes = 256L << 20;
    // This is a separate, explicitly authorized test exception, not a new
    // default for the existing 4-KiB/256-MiB workflow fixtures or the product.
    private const long OneGiBBytes = 1L << 30;
    private const string Password = "N!r7$Vq2#Lm8%Tx3&Jd9*Wp4+Kg5=Zu6?Ce";
    private const string Pin = "428317";
    private static readonly EncryptionSuite[] Suites =
    [EncryptionSuite.StandardCascade, EncryptionSuite.ParanoiaCascade, EncryptionSuite.Camellia256, EncryptionSuite.Serpent256];

    internal static IReadOnlyList<TestCase> Tests =>
    [
        .. (from suite in Suites
            from bytes in new[] { 4_096L, LongBytes }
            from requested in new[] { 0, 1, 4 }
            select MakeCase(suite, bytes, requested)).ToArray(),
        .. MakeOneGiBCases(),
    ];

    private static IReadOnlyList<TestCase> MakeOneGiBCases()
    {
        EncryptionSuite[] catalog = [.. EncryptionSuiteCatalog.DisplayOrder];
        Require(catalog.Length == 12 && catalog.Distinct().Count() == 12
            && catalog.OrderBy(suite => (int)suite).SequenceEqual(Enum.GetValues<EncryptionSuite>().OrderBy(suite => (int)suite)),
            "The explicit one-GiB workflow matrix must cover the complete closed twelve-suite catalog exactly once.");
        string SuiteName(EncryptionSuite suite) => suite switch
        {
            EncryptionSuite.StandardCascade => "standard",
            EncryptionSuite.ParanoiaCascade => "paranoia",
            EncryptionSuite.XChaChaOverAes => "xchacha-aes",
            EncryptionSuite.MixedCascade => "mixed",
            EncryptionSuite.XChaCha20Poly1305 => "xchacha20-poly1305",
            EncryptionSuite.Kalyna512_512 => "kalyna512-512",
            EncryptionSuite.Threefish1024 => "threefish1024",
            EncryptionSuite.Aes256 => "aes256",
            EncryptionSuite.Mars448 => "mars448",
            EncryptionSuite.Shacal2_512 => "shacal2-512",
            EncryptionSuite.Camellia256 => "camellia",
            EncryptionSuite.Serpent256 => "serpent",
            _ => throw new InvalidOperationException("An unsupported suite cannot enter the explicit one-GiB workflow matrix."),
        };
        Require(catalog.Select(SuiteName).Distinct(StringComparer.Ordinal).Count() == 12,
            "The explicit one-GiB workflow suite names must be unique.");
        return catalog.Select(suite =>
        {
            string id = $"performance.rev12-workflow-1gib-{SuiteName(suite)}-auto";
            return new TestCase(id, $"explicit public one-GiB production-KDF level-{Level} complete archive/KPAR2/original-compare workflow: " + SuiteName(suite) + "/auto",
                () => RunAsync(id, suite, OneGiBBytes, 0), TestResource.ArgonPeakMemory, "Performance", IsPerformance: true)
            { Cost = new TestCost(9, 8_960, true, TestConstraint.HostExclusive | TestConstraint.EntropyState | TestConstraint.ZpaqProcess) };
        }).ToArray();
    }

    private static TestCase MakeCase(EncryptionSuite suite, long bytes, int requested)
    {
        string mode = requested == 0 ? "auto" : "manual" + requested;
        string size = bytes == LongBytes ? "256mib" : "4kib";
        string name = suite switch
        {
            EncryptionSuite.StandardCascade => "standard", EncryptionSuite.ParanoiaCascade => "paranoia",
            EncryptionSuite.Camellia256 => "camellia", _ => "serpent",
        };
        string id = $"performance.rev12-workflow-{size}-{name}-{mode}";
        return new TestCase(id, $"production-KDF level-{Level} complete archive/KPAR2/original-compare matrix: " + size + "/" + name + "/" + mode,
            () => RunAsync(id, suite, bytes, requested), TestResource.ArgonPeakMemory, "Performance", IsPerformance: true)
        { Cost = new TestCost(9, 8_960, true, TestConstraint.HostExclusive | TestConstraint.EntropyState | TestConstraint.ZpaqProcess) };
    }

    private static async Task RunAsync(string id, EncryptionSuite suite, long sourceBytes, int requested)
    {
#if DEBUG
        throw new InvalidOperationException("Release configuration is required for the production workflow matrix.");
#endif
        var native = PublicNativeProfileEvidence.Capture();
        string assemblySha256 = PublicNativeProfileEvidence.AssemblySha256();
        string repository = Environment.GetEnvironmentVariable("KEEPVAULT_TEST_REPOSITORY_ROOT")
            ?? throw new InvalidOperationException("The matrix requires an explicit repository evidence root.");
        bool headAvailable = TestRunner.TryRunGit(["rev-parse", "HEAD"], out string head, repository);
        long workingBaseline = OperationMemoryBudget.WorkingReservedBytesForTests;
        int cpuBaseline = CpuWorkBudget.ActiveWorkersForTests;
        ArchiveOperationPolicy? observedPolicy = null;
        string root = MacSafeFileSystem.ResolveExistingRealPath(Directory.CreateTempSubdirectory("keep-vault-rev12-workflow-").FullName);
        File.SetUnixFileMode(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        string source = Path.Combine(root, "fixture");
        string output = Path.Combine(root, "public.kzpaq");
        string extracted = Path.Combine(root, "extracted");
        var phases = new OperationPhaseProfile.Measurements();
        var macs = new ParallelContainerAuthenticator.PhaseMeasurementsForTests();
        var scheduling = new NativeCipherExecutor.Measurements();
        Stopwatch workflow = new();
        var phaseTimes = new Dictionary<string, double>(StringComparer.Ordinal);
        var macroTimeline = new List<WorkflowInterval>(8);
        double lastMacroBoundary = 0;
        void FinishMacro(string phase)
        {
            double end = workflow.Elapsed.TotalSeconds;
            if (macroTimeline.Count >= 8 || end < lastMacroBoundary)
                throw new InvalidOperationException("The bounded public workflow timeline is invalid.");
            macroTimeline.Add(new WorkflowInterval(phase, lastMacroBoundary, end, end - lastMacroBoundary));
            lastMacroBoundary = end;
        }
        Exception? failure = null;
        WorkflowReceipt? receipt = null;
        double setupSeconds = 0, preparationSeconds = 0, processCpuSeconds = 0;
        double? processAndObservedChildCpuSeconds = null;
        try
        {
            Stopwatch setup = Stopwatch.StartNew();
            await CreateFixtureAsync(source, sourceBytes).ConfigureAwait(false);
            Manifest expected = await ManifestAsync(source).ConfigureAwait(false);
            Require(expected.Bytes == sourceBytes, "The fixture exceeded or missed its exact public source-byte budget.");
            setup.Stop(); setupSeconds = setup.Elapsed.TotalSeconds;

            var preferences = new ResourcePreferences
            {
                CpuMode = requested == 0 ? ResourceMode.Auto : ResourceMode.Manual,
                ManualCpuLimit = requested == 0 ? null : requested,
                MemoryMode = ResourceMode.Auto, IoMode = ResourceMode.Auto, QueueMode = ResourceMode.Auto,
                WorkingDirectory = Path.Combine(root, "work"),
                MaxExtractedTotalBytes = sourceBytes, MaxSingleFileBytes = sourceBytes,
            };
            Directory.CreateDirectory(preferences.WorkingDirectory);
            var policy = new ArchiveOperationPolicy(preferences.WorkingDirectory, root, preferences: preferences);
            observedPolicy = policy;
            using IDisposable policyScope = policy.EnterScope();
            using IDisposable phaseScope = OperationPhaseProfile.ObserveForTests(phases);
            using IDisposable macScope = ParallelContainerAuthenticator.ObservePhasesForTests(macs);
            using IDisposable schedulingScope = NativeCipherExecutor.ObserveForTests(scheduling);

            // Preparation is explicit and reported separately, matching the
            // user's generated factors before the Archive operation starts.
            Stopwatch preparation = Stopwatch.StartNew();
            AddPublicMouseSamples();
            using GeneratedArchiveEntropy entropy = EntropyMixer.CreateArchiveEntropy(
                suite == EncryptionSuite.ParanoiaCascade ? EntropyPreparationKind.DualRound : EntropyPreparationKind.SingleRound);
            preparation.Stop(); preparationSeconds = preparation.Elapsed.TotalSeconds;
            string factorA = entropy.FirstPassword, factorB = entropy.SecondPassword;
            var zpaq = new ZpaqService(); var containers = new KalynaContainerService(); var recovery = new RecoveryService();
            using Process process = Process.GetCurrentProcess();
            TimeSpan processCpuBefore = process.TotalProcessorTime;
            workflow.Start();
            using OperationMemoryBudget.Lease operationMemory = await OperationMemoryBudget.AcquireAsync(policy, CancellationToken.None).ConfigureAwait(false);
            using IDisposable memoryScope = operationMemory.EnterScope();
            Stopwatch step = Stopwatch.StartNew();
            using MacOriginalDeletionService.CreationSnapshot beforeCreation =
                MacOriginalDeletionService.CaptureCreationSnapshot([source], CancellationToken.None);
            phaseTimes["originalCreationSnapshot"] = step.Elapsed.TotalSeconds;
            FinishMacro("memoryAdmissionAndOriginalCreationSnapshot");

            step.Restart();
            ProcessResult created = await zpaq.AddStreamingAsync([source], Level,
                (input, token) => containers.EncryptZpaqStreamWithPreparedEntropyAsync(input, output,
                    Password, Pin, factorA, factorB, suite, entropy, "public REV12 workflow", null, token),
                null, CancellationToken.None).ConfigureAwait(false);
            phaseTimes["archiveAndEncrypt"] = step.Elapsed.TotalSeconds;
            Require(created.Succeeded && File.Exists(output), $"The complete level-{Level} archive operation failed.");
            long containerBytes = new FileInfo(output).Length;
            long compressedPayloadBytes = phases.Snapshot().Aggregates.Single(x => x.Phase == "PayloadRead").PublicBytesSum;
            FinishMacro("archiveAndEncrypt");
            step.Restart();
            string containerSha256 = await HashAsync(output).ConfigureAwait(false);
            phaseTimes["supplementalContainerHash"] = step.Elapsed.TotalSeconds;
            FinishMacro("supplementalContainerHash");

            step.Restart();
            string sidecar = await recovery.CreateAuthenticatedAsync(output, Password, Pin, factorA, factorB, null,
                CancellationToken.None).ConfigureAwait(false);
            phaseTimes["recoveryCreate"] = step.Elapsed.TotalSeconds;
            Require(File.Exists(sidecar), "The archive workflow failed to create authenticated KPAR2.");
            long recoveryBytes = new FileInfo(sidecar).Length;
            FinishMacro("recoveryCreate");

            step.Restart();
            RecoveryRepairResult verified = await recovery.VerifyAndRepairAuthenticatedAsync(output, Password, Pin,
                factorA, factorB, null, CancellationToken.None).ConfigureAwait(false);
            phaseTimes["supplementalRecoveryHealthyVerification"] = step.Elapsed.TotalSeconds;
            Require(verified.Authenticated && verified.RecoveryAvailable && verified.ArchiveHealthy && !verified.Repaired,
                "The freshly generated KPAR2 failed authenticated verification.");
            FinishMacro("supplementalRecoveryHealthyVerification");

            step.Restart();
            MacOriginalDeletionService.ArchiveIdentity archiveIdentity = MacOriginalDeletionService.CaptureArchiveIdentity(output);
            ProcessResult extraction = await zpaq.ExtractStreamingAsync(
                (destination, token) => containers.DecryptToStreamAsync(output, Password, Pin, factorA, factorB,
                    destination, null, token), extracted, null, CancellationToken.None).ConfigureAwait(false);
            phaseTimes["decryptAndExtractForOriginalComparison"] = step.Elapsed.TotalSeconds;
            Require(extraction.Succeeded, "The verification extraction failed.");
            FinishMacro("decryptAndExtractForOriginalComparison");

            step.Restart();
            using (OperationPhaseProfile.Measure(OperationPhaseProfile.Phase.OriginalTreeComparison, sourceBytes))
            {
                MacOriginalDeletionService.VerificationResult comparison = await MacOriginalDeletionService.VerifyExtractionAsync(
                    [source], extracted, null, CancellationToken.None, beforeCreation).ConfigureAwait(false);
                Require(comparison.Verified && comparison.BytesCompared == sourceBytes && comparison.FilesCompared == expected.Files.Count,
                    "The production original comparison did not reproduce all source files exactly.");
                Manifest actual = await ManifestAsync(Path.Combine(extracted, "fixture")).ConfigureAwait(false);
                Require(expected.Bytes == actual.Bytes && expected.Directories.SequenceEqual(actual.Directories)
                    && expected.Files.SequenceEqual(actual.Files), "Extracted hashes or empty/hidden/Unicode directory topology differ.");
            }
            phaseTimes["originalComparisonAndIndependentHashTopologyCheck"] = step.Elapsed.TotalSeconds;
            FinishMacro("originalComparisonAndIndependentHashTopologyCheck");
            // No original is deleted in this measurement. The exact production
            // comparison path is used, while its irreversible action is omitted.
            _ = archiveIdentity;
            process.Refresh(); processCpuSeconds = (process.TotalProcessorTime - processCpuBefore).TotalSeconds;
            processAndObservedChildCpuSeconds = operationMemory._root.Runtime.Observe().Cpu?.TotalSeconds;
            receipt = new WorkflowReceipt(expected.Files.Count, expected.Directories.Length, sourceBytes, compressedPayloadBytes, containerBytes,
                recoveryBytes, expected.Sha256(), containerSha256, policy.MaxCpuWorkers,
                policy.InitialPlan.ThrottleReason, policy.OutputVolumeIdentity);
        }
        catch (Exception ex) { failure = ex; throw; }
        finally
        {
            Stopwatch cleanup = Stopwatch.StartNew();
            try { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
            catch (Exception error)
            {
                if (failure is null) throw;
                throw new IOException("The measured workflow failed and its private public-data fixture could not be removed.",
                    new AggregateException(failure, error));
            }
            phaseTimes["fixtureCleanup"] = cleanup.Elapsed.TotalSeconds;
            workflow.Stop();
            FinishMacro("ownedResourcesAndFixtureCleanup");
        }
        Require(macroTimeline.Count == 8 && macroTimeline[0].StartSeconds == 0
            && macroTimeline[^1].EndSeconds == workflow.Elapsed.TotalSeconds
            && Math.Abs(macroTimeline.Sum(x => x.DurationSeconds) - workflow.Elapsed.TotalSeconds) < 1e-7,
            "The complete bounded outer workflow timeline does not cover the measured workflow walltime.");
        WorkflowReceipt finalReceipt = receipt ?? throw new InvalidOperationException("A complete workflow receipt is unavailable.");
        Require(OperationMemoryBudget.WorkingReservedBytesForTests == workingBaseline
            && CpuWorkBudget.ActiveWorkersForTests == cpuBaseline
            && observedPolicy!.Usage.LeasedMemoryBytes == 0,
            "The complete measured workflow did not restore its operation memory/CPU leases.");
        JsonElement nativeSnapshot = JsonSerializer.SerializeToElement(scheduling.Snapshot());
        Require(nativeSnapshot.GetProperty("observationAvailable").GetBoolean()
            && nativeSnapshot.GetProperty("activeCallbacks").GetInt32() == 0
            && nativeSnapshot.GetProperty("maximumGrant").GetInt32() <= finalReceipt.InitialCpuCeiling
            && nativeSnapshot.GetProperty("peakActiveCallbacks").GetInt32() <= finalReceipt.InitialCpuCeiling,
            "Native scheduling observation is unavailable, unfinished or exceeds the approved CPU ceiling.");
        PublicNativeProfileEvidence.RequireUnchanged(native);
        OperationPhaseProfile.ProfileSnapshot profile = phases.Snapshot();
        Require(profile.ObservationAvailable && profile.Aggregates.Single(x => x.Phase == "KdfRound1").Calls > 0,
            "The measured workflow has no real KDF observation.");
        Require((profile.Aggregates.Single(x => x.Phase == "KdfRound2").Calls > 0) == (suite == EncryptionSuite.ParanoiaCascade),
            "The measured production KDF round contract does not match the selected suite.");
        var report = new
        {
            schemaVersion = 1, measuredUtc = DateTimeOffset.UtcNow, testId = id,
            scope = $"Managed Release final service/native archive paths: level-{Level} streaming creation, production KDF, both global MACs, authenticated KPAR2 creation and healthy verification, production original comparison plus independent hash/topology verification, and fixture cleanup. No original deletion. Installed AOT GUI phase profile NOT RUN.",
            measuredWorkflows = 1, warmups = 0, repetitions = 1,
            kdfComparison = "Fresh independently generated factors/salts per case produce potentially different credential-dependent KDF work. The one-run matrix measures actual complete workflows; differences across CPU modes are not a controlled causal CPU-scaling result. Fixed public cipher/tag equivalence and five-run cipher-only comparisons are separate.",
            leaseCleanupVerified = true, median = "NOT APPLICABLE: one expensive complete workflow",
            suite = suite.ToString(), compressionLevel = Level, requestedCpuMode = requested == 0 ? "Auto" : "Manual",
            requestedWorkers = requested == 0 ? (int?)null : requested,
            processArchitecture = RuntimeInformation.ProcessArchitecture.ToString(), osArchitecture = RuntimeInformation.OSArchitecture.ToString(),
            operatingSystem = RuntimeInformation.OSDescription, runtimeProcessorCount = Environment.ProcessorCount,
            energyState = "NOT OBSERVED by this harness; no power setting was changed",
            aesProvider = NativeAes.RuntimeProvider.ToString(), assemblySha256,
            sourceHead = headAvailable ? head.Trim() : "NOT AVAILABLE", sourceBinding = "Assembly SHA-256 binds the built code; Git HEAD alone does not cover the dirty working tree. Bind this artifact to the isolated build's complete source snapshot evidence.",
            nativeTrustedInputSha256 = native, nativeProvenance = PublicNativeProfileEvidence.Interpretation,
            fixturePattern = sourceBytes == OneGiBBytes
                ? $"Explicitly authorized exact 1 GiB total source size including short Unicode text and an empty file; the entire payload.bin remainder is deterministic public SplitMix64 synthetic pseudorandom bytes, with empty, hidden, nested and Unicode paths; normal level-{Level} compression remains enabled"
                : sourceBytes == LongBytes
                ? "Exact 256 MiB source size; roughly75% fixed repeating patterns and 25% deterministic synthetic pseudorandom bytes, with empty, hidden, nested and Unicode paths"
                : "Exact 4 KiB source size; fixed repeating bytes and short Unicode text, with empty, hidden, nested and Unicode paths",
            receipt = finalReceipt, setupSeconds, preparationSeconds, workflowWallSeconds = workflow.Elapsed.TotalSeconds,
            sourceMiBPerSecondCompleteWorkflow = Rate(sourceBytes, workflow.Elapsed.TotalSeconds),
            sourceMiBPerSecondArchiveAndEncrypt = Rate(sourceBytes, phaseTimes["archiveAndEncrypt"]),
            phaseWallSeconds = phaseTimes, outerWorkflowTimeline = macroTimeline,
            outerTimelineInterpretation = "Eight monotonic, contiguous outer intervals partition the complete observed workflow walltime, including owner/fixture cleanup. Each interval includes all public checks and bookkeeping between its actual FinishMacro boundaries; service-only phaseWallSeconds can exclude those checks. This is sequential outer workflow ordering only, not a complete internal parallel critical-path analysis. The separate 4096-entry internal timeline can omit later intervals; its aggregates remain complete.",
            managedProcessCpuSecondsThroughOriginalComparison = processCpuSeconds,
            processAndObservedZpaqChildCpuSecondsThroughOriginalComparison = processAndObservedChildCpuSeconds,
            cpuInterpretation = "Managed process CPU includes native libraries in this process. The separate combined observation adds sampled ZPAQ child CPU counters; it may omit an unsampled terminal interval. Fixture cleanup CPU is outside both counters. Overlapping phase sums are neither CPU time nor additive end-to-end duration; no per-cipher CPU split is asserted.",
            phaseProfile = profile, globalMacPhasesWallSecondsSum = macs.Seconds(), nativeScheduling = nativeSnapshot,
            observedKdfBranchCalls = profile.Aggregates.Where(phase => phase.Phase is "KdfRound1" or "KdfRound2"
                or "Argon2Sha3Round1" or "Argon2SkeinRound1" or "Argon2Sha3Round2" or "Argon2SkeinRound2")
                .Select(phase => new { phase.Phase, phase.Calls }).ToArray(),
            byteInterpretation = "Source throughput counts each original byte once. Compressed ciphertext/container/KPAR2 and repeatedly read/verified bytes are separate levels; repeated reads or two MACs never increase the source denominator. Each phase aggregate carries its own actual public processed-byte basis.",
        };
        string directory = Path.Combine(repository, "work", "v13-evidence"); Directory.CreateDirectory(directory);
        string artifact = Path.Combine(directory, id + "-" + DateTimeOffset.UtcNow.ToString("yyyyMMddTHHmmssfff") + "-" + Guid.NewGuid().ToString("N") + ".json");
        await using (var stream = new FileStream(artifact, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            await JsonSerializer.SerializeAsync(stream, report, new JsonSerializerOptions { WriteIndented = true }).ConfigureAwait(false);
        Console.WriteLine($"    REV12 workflow {suite} requested={(requested == 0 ? "Auto" : requested.ToString())} {sourceBytes} source bytes: archive+encrypt {phaseTimes["archiveAndEncrypt"]:F3} s ({Rate(sourceBytes, phaseTimes["archiveAndEncrypt"]):F2} MiB/s); complete with KPAR2/original compare/cleanup {workflow.Elapsed.TotalSeconds:F3} s ({Rate(sourceBytes, workflow.Elapsed.TotalSeconds):F2} MiB/s), one measured run");
        Console.WriteLine("REV12_WORKFLOW_PROFILE_ARTIFACT=" + artifact);
    }

    private static async Task CreateFixtureAsync(string source, long bytes)
    {
        Directory.CreateDirectory(Path.Combine(source, "empty", "nested", "still empty"));
        Directory.CreateDirectory(Path.Combine(source, ".hidden", "Unicode_Grüße_日本_🙂"));
        string text = "Öffentliche synthetische Keep Vault REV12 Daten.\n";
        byte[] small = Encoding.UTF8.GetBytes(text);
        await File.WriteAllBytesAsync(Path.Combine(source, ".hidden", "Unicode_Grüße_日本_🙂", "small.txt"), small).ConfigureAwait(false);
        await File.WriteAllBytesAsync(Path.Combine(source, "empty-file.bin"), []).ConfigureAwait(false);
        byte[] buffer = new byte[1 << 20]; ulong state = 0x4B56313352455612UL; long written = 0;
        await using var stream = new FileStream(Path.Combine(source, "payload.bin"), FileMode.CreateNew, FileAccess.Write, FileShare.None,
            buffer.Length, FileOptions.Asynchronous | FileOptions.SequentialScan);
        while (written < bytes - small.Length)
        {
            int length = (int)Math.Min(buffer.Length, bytes - small.Length - written);
            if (bytes == OneGiBBytes || (written / (16L << 20)) % 4 == 2)
            {
                for (int at = 0; at < length; at += 8)
                {
                    state += 0x9E3779B97F4A7C15UL; ulong value = state;
                    value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9UL;
                    value = (value ^ (value >> 27)) * 0x94D049BB133111EBUL; value ^= value >> 31;
                    int count = Math.Min(8, length - at);
                    for (int i = 0; i < count; i++) buffer[at + i] = (byte)(value >> (8 * i));
                }
            }
            else for (int at = 0; at < length; at++) buffer[at] = (byte)((written + at) & 255);
            await stream.WriteAsync(buffer.AsMemory(0, length)).ConfigureAwait(false); written += length;
        }
    }

    private static void AddPublicMouseSamples()
    {
        for (int i = 0; Enum.GetValues<EntropyPurpose>().Any(p => !EntropyMixer.HasRequiredSamples(p)); i++)
            EntropyMixer.AddMouseSample(319.125 + i * .003, 811.875 + i * .007, Environment.TickCount ^ i,
                (i & 1) != 0, (i & 2) != 0, (i & 4) != 0);
    }

    private static async Task<Manifest> ManifestAsync(string root)
    {
        string[] directories = Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories)
            .Select(path => Path.GetRelativePath(root, path).Replace('\\', '/')).Order(StringComparer.Ordinal).ToArray();
        var files = new List<ManifestFile>(); long bytes = 0;
        foreach (string path in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
        { long count = new FileInfo(path).Length; bytes = checked(bytes + count);
          files.Add(new(Path.GetRelativePath(root, path).Replace('\\', '/'), count, await HashAsync(path).ConfigureAwait(false))); }
        return new Manifest(directories, files, bytes);
    }
    private static async Task<string> HashAsync(string path)
    { await using FileStream stream = File.OpenRead(path); return Convert.ToHexString(await SHA256.HashDataAsync(stream).ConfigureAwait(false)); }
    private static double Rate(long bytes, double seconds) => bytes / 1048576d / seconds;
    private static void Require(bool value, string error) { if (!value) throw new InvalidOperationException(error); }
    private sealed record WorkflowInterval(string Phase, double StartSeconds, double EndSeconds, double DurationSeconds);
    private sealed record ManifestFile(string RelativePath, long Bytes, string Sha256);
    private sealed record Manifest(string[] Directories, List<ManifestFile> Files, long Bytes)
    { internal string Sha256() => Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(this))); }
    private sealed record WorkflowReceipt(int InputFiles, int InputDirectories, long InputBytes, long CompressedPayloadBytesDuringCreation, long ContainerBytes, long RecoveryBytes,
        string InputManifestSha256, string ContainerSha256, int InitialCpuCeiling, string InitialThrottleReason, string OutputVolumeIdentity);
}
