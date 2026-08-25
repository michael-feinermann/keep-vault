using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text.Json;

/// <summary>
/// The command line, the selection rules and the timing cache around
/// <see cref="TestCoordinator"/>.
/// </summary>
/// <remarks>
/// The Windows suite used to be a single script: twenty-seven phases in fixed
/// order, one process, stop at the first failure. On this machine that is about
/// twelve minutes of mostly idle cores, and a failure in phase three hides
/// whatever phases four through twenty-seven would have said.
///
/// This is the macOS runner's arrangement, translated. The two suites keep
/// their own copies for the reason the differential tests do: they share no
/// harness, and the code that decides what runs is worth reading in the place
/// it runs.
/// </remarks>
internal static class TestRunner
{
    private static readonly object ConsoleLock = new();

    internal static async Task<int> RunAsync(
        string[] args,
        IReadOnlyList<TestCase> smokeTests,
        IReadOnlyList<TestCase> comprehensiveTests)
    {
        bool listOnly = false;
        bool fullRequested = false;
        bool quickRequested = false;
        bool changedRequested = false;
        bool performanceRequested = false;
        bool noSmokeRequested = false;
        bool smokeRequested = false;
        string? onlyFilter = null;
        string? smokeOnlyFilter = null;
        string? categoryFilter = null;
        int repeatCount = 1;
        int? parallelOverride = null;
        uint? seedOverride = null;
        string? baseRef = null;
        bool failFast = false;
        bool rerunFailures = false;
        bool inProcess = false;
        bool workerMode = false;
        string? workerTestId = null;
        string timingsPath = Path.Combine(AppContext.BaseDirectory, ".test-timings.json");
        string resultsPath = Path.Combine(AppContext.BaseDirectory, ".test-results.json");

        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            switch (arg.ToLowerInvariant())
            {
                case "--list":
                    listOnly = true;
                    break;
                case "--fail-fast":
                    failFast = true;
                    break;
                case "--rerun-failures":
                    rerunFailures = true;
                    fullRequested = true;
                    noSmokeRequested = true;
                    break;
                case "--in-process":
                    inProcess = true;
                    break;
                case "--worker":
                    workerMode = true;
                    break;
                case "--test-id":
                    if (i + 1 >= args.Length || args[i + 1].StartsWith("--", StringComparison.Ordinal))
                    {
                        Console.Error.WriteLine("Usage error: Missing value for --test-id.");
                        return 64;
                    }
                    workerTestId = args[++i];
                    break;
                case "--full":
                    fullRequested = true;
                    break;
                case "--quick":
                    quickRequested = true;
                    break;
                case "--changed":
                    changedRequested = true;
                    break;
                case "--performance":
                    performanceRequested = true;
                    noSmokeRequested = true;
                    break;
                case "--no-smoke":
                    noSmokeRequested = true;
                    break;
                case "--smoke":
                    smokeRequested = true;
                    break;
                case "--only":
                    if (i + 1 >= args.Length || args[i + 1].StartsWith("--", StringComparison.Ordinal))
                    {
                        Console.Error.WriteLine("Usage error: Missing value for --only.");
                        return 64;
                    }
                    onlyFilter = args[++i];
                    break;
                case "--smoke-only":
                    if (i + 1 >= args.Length || args[i + 1].StartsWith("--", StringComparison.Ordinal))
                    {
                        Console.Error.WriteLine("Usage error: Missing value for --smoke-only.");
                        return 64;
                    }
                    smokeOnlyFilter = args[++i];
                    break;
                case "--category":
                    if (i + 1 >= args.Length || args[i + 1].StartsWith("--", StringComparison.Ordinal))
                    {
                        Console.Error.WriteLine("Usage error: Missing value for --category.");
                        return 64;
                    }
                    categoryFilter = args[++i];
                    break;
                case "--repeat":
                    if (i + 1 >= args.Length || !int.TryParse(args[i + 1], out int r) || r < 1)
                    {
                        Console.Error.WriteLine("Usage error: --repeat requires an integer >= 1.");
                        return 64;
                    }
                    repeatCount = r;
                    i++;
                    break;
                case "--parallel":
                    if (i + 1 >= args.Length || !int.TryParse(args[i + 1], out int p) || p < 1 || p > 128)
                    {
                        Console.Error.WriteLine("Usage error: --parallel requires an integer between 1 and 128.");
                        return 64;
                    }
                    parallelOverride = p;
                    i++;
                    break;
                case "--seed":
                    if (i + 1 >= args.Length)
                    {
                        Console.Error.WriteLine("Usage error: Missing value for --seed.");
                        return 64;
                    }
                    string seedText = args[++i];
                    uint? parsedSeed = seedText.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                        ? (uint.TryParse(seedText[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out uint hex) ? hex : null)
                        : (uint.TryParse(seedText, out uint dec) ? dec : null);
                    if (parsedSeed is null)
                    {
                        Console.Error.WriteLine($"Usage error: Invalid seed value '{seedText}'. Expected a 32-bit unsigned integer or hex (e.g. 0x12345678).");
                        return 64;
                    }
                    seedOverride = parsedSeed;
                    break;
                case "--base":
                    if (i + 1 >= args.Length || args[i + 1].StartsWith("--", StringComparison.Ordinal))
                    {
                        Console.Error.WriteLine("Usage error: Missing value for --base.");
                        return 64;
                    }
                    baseRef = args[++i];
                    break;
                case "--timings":
                    if (i + 1 >= args.Length || args[i + 1].StartsWith("--", StringComparison.Ordinal))
                    {
                        Console.Error.WriteLine("Usage error: Missing value for --timings.");
                        return 64;
                    }
                    timingsPath = args[++i];
                    break;
                default:
                    Console.Error.WriteLine($"Usage error: Unrecognized argument '{arg}'.");
                    return 64;
            }
        }

        IReadOnlyList<TestCase> everyTest = [.. smokeTests, .. comprehensiveTests];

        if (performanceRequested && (quickRequested || changedRequested || smokeRequested || smokeOnlyFilter is not null || rerunFailures))
        {
            Console.Error.WriteLine(
                "Usage error: --performance cannot be combined with --quick, --changed, --smoke, --smoke-only or --rerun-failures.");
            return 64;
        }

        try
        {
            TestInventory.Validate(smokeTests, comprehensiveTests);
        }
        catch (InvalidOperationException ex)
        {
            Console.Error.WriteLine("Test inventory error: " + ex.Message);
            return 70;
        }

        // A worker runs exactly one test and reports one machine-readable line.
        // It must short-circuit before any selection logic: the coordinator
        // addresses it by id, not by the filters a human would use.
        if (workerMode)
        {
            if (string.IsNullOrEmpty(workerTestId))
            {
                Console.Error.WriteLine("Usage error: --worker requires --test-id.");
                return 64;
            }

            return await TestCoordinator.RunWorkerModeAsync(everyTest, workerTestId, seedOverride ?? 1u).ConfigureAwait(false);
        }

        if (listOnly)
        {
            Console.WriteLine("Available smoke tests:");
            foreach (TestCase test in smokeTests)
            {
                Console.WriteLine($"  {test.Id,-48} [Smoke] [{test.Resource,-15}] {test.Name}");
            }

            Console.WriteLine();
            Console.WriteLine("Available comprehensive tests:");
            foreach (TestCase test in comprehensiveTests.Where(IsAutomaticComprehensive))
            {
                Console.WriteLine($"  {test.Id,-48} [{test.Category,-11}] [{test.Resource,-15}] {test.Name}");
            }

            TestCase[] performanceTests = [.. comprehensiveTests.Where(test => test.IsPerformance)];
            if (performanceTests.Length > 0)
            {
                Console.WriteLine();
                Console.WriteLine("Available manual performance gates:");
                foreach (TestCase test in performanceTests)
                {
                    Console.WriteLine($"  {test.Id,-48} [Performance] [{test.Resource,-15}] {test.Name}");
                }
            }

            return 0;
        }

        var selectedSmoke = new List<TestCase>();
        var selectedComprehensive = new List<TestCase>();

        if (rerunFailures)
        {
            IReadOnlyList<string> failedIds;
            try
            {
                failedIds = TestCoordinator.ReadFailedIds(resultsPath, everyTest);
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
            {
                Console.Error.WriteLine($"Cannot re-run failures from {Path.GetFileName(resultsPath)}: {ex.Message}");
                return 65;
            }

            if (failedIds.Count == 0)
            {
                Console.WriteLine($"No failures recorded in {Path.GetFileName(resultsPath)}; nothing to re-run.");
                return 0;
            }

            var failedSet = new HashSet<string>(failedIds, StringComparer.Ordinal);
            selectedSmoke.AddRange(smokeTests.Where(t => failedSet.Contains(t.Id)));
            selectedComprehensive.AddRange(comprehensiveTests.Where(t => failedSet.Contains(t.Id)));
            Console.WriteLine($"Re-running {selectedSmoke.Count + selectedComprehensive.Count} previously failing test(s).");
        }
        else if (performanceRequested)
        {
            IEnumerable<TestCase> performance = comprehensiveTests.Where(test => test.IsPerformance);
            if (onlyFilter is not null)
            {
                performance = performance.Where(test => MatchesSelector(test, onlyFilter));
            }

            if (categoryFilter is not null)
            {
                performance = performance.Where(test =>
                    string.Equals(test.Category, categoryFilter, StringComparison.OrdinalIgnoreCase)
                    || string.Equals(test.Resource.ToString(), categoryFilter, StringComparison.OrdinalIgnoreCase));
            }

            selectedComprehensive.AddRange(performance);
        }
        else if (changedRequested)
        {
            HashSet<string>? affected = DetermineAffectedTestsFromGit(baseRef);
            if (affected is null)
            {
                Console.WriteLine("Note: git impact detection could not determine changed files; running the full suite.");
                selectedSmoke.AddRange(smokeTests);
                selectedComprehensive.AddRange(comprehensiveTests.Where(IsAutomaticComprehensive));
            }
            else if (affected.Count == 0)
            {
                selectedSmoke.AddRange(smokeTests);
                selectedComprehensive.AddRange(comprehensiveTests.Where(t => IsAutomaticComprehensive(t) && t.Resource == TestResource.Light));
            }
            else
            {
                // A mapping entry that names no existing test would silently
                // select nothing for the file that produced it, so a renamed
                // security test could stop running without anyone noticing.
                // Refuse the run instead of quietly covering less.
                var known = new HashSet<string>(
                    smokeTests.Select(t => t.Id).Concat(comprehensiveTests.Select(t => t.Id)),
                    StringComparer.Ordinal)
                {
                    "ALL_SMOKE",
                    "ALL_COMPREHENSIVE",
                    "ALL_CONTAINER_SUITES",
                    "ALL_RECOVERY_SUITES",
                };
                string[] unknown = [.. affected.Where(name => !known.Contains(name)).OrderBy(name => name, StringComparer.Ordinal)];
                if (unknown.Length > 0)
                {
                    Console.Error.WriteLine(
                        "The changed-file impact map names tests that do not exist: "
                        + string.Join(", ", unknown)
                        + ". Update the map in TestDefinitions.cs.");
                    return 1;
                }

                if (affected.Contains("performance.cipher-suites"))
                {
                    Console.WriteLine(
                        "Note: cipher/native/build changes require the manual release gate; "
                        + "run this suite again with --performance on an otherwise idle host before release.");
                }

                selectedSmoke.AddRange(smokeTests.Where(t => affected.Contains(t.Id) || affected.Contains("ALL_SMOKE")));
                selectedComprehensive.AddRange(comprehensiveTests.Where(t =>
                    !t.IsPerformance
                    && (affected.Contains(t.Id)
                    || affected.Contains("ALL_COMPREHENSIVE")
                    || (affected.Contains("ALL_CONTAINER_SUITES") && string.Equals(t.Category, "Containers", StringComparison.Ordinal))
                    || (affected.Contains("ALL_RECOVERY_SUITES") && string.Equals(t.Category, "Recovery", StringComparison.Ordinal)))));
                if (selectedSmoke.Count == 0 && selectedComprehensive.Count == 0)
                {
                    selectedSmoke.AddRange(smokeTests);
                    selectedComprehensive.AddRange(comprehensiveTests.Where(t => IsAutomaticComprehensive(t) && t.Resource == TestResource.Light));
                }
            }
        }
        else if (quickRequested)
        {
            selectedSmoke.AddRange(smokeTests);
            selectedComprehensive.AddRange(comprehensiveTests.Where(t => IsAutomaticComprehensive(t) && t.Resource == TestResource.Light));
        }
        else
        {
            if (!noSmokeRequested && (onlyFilter is null || smokeOnlyFilter is not null || smokeRequested))
            {
                if (smokeOnlyFilter is not null)
                {
                    selectedSmoke.AddRange(smokeTests.Where(t => MatchesSelector(t, smokeOnlyFilter)));
                }
                else
                {
                    selectedSmoke.AddRange(smokeTests);
                }
            }

            // No selector at all means the whole suite. The old script had no
            // arguments and ran everything, and a bare run must keep meaning
            // that - a runner that quietly covered less than the script it
            // replaced would be the worst possible outcome of this change.
            bool anySelector = fullRequested || onlyFilter is not null || categoryFilter is not null
                || smokeRequested || smokeOnlyFilter is not null || performanceRequested;
            if (fullRequested || onlyFilter is not null || categoryFilter is not null || !anySelector)
            {
                IEnumerable<TestCase> comprehensive = comprehensiveTests.Where(test =>
                    IsSelectedByManualPerformanceMode(test, performanceRequested, onlyFilter, categoryFilter));
                if (onlyFilter is not null)
                {
                    comprehensive = comprehensive.Where(t => MatchesSelector(t, onlyFilter));
                }

                if (categoryFilter is not null)
                {
                    comprehensive = comprehensive.Where(t =>
                        string.Equals(t.Category, categoryFilter, StringComparison.OrdinalIgnoreCase)
                        || string.Equals(t.Resource.ToString(), categoryFilter, StringComparison.OrdinalIgnoreCase));
                }

                selectedComprehensive.AddRange(comprehensive);
            }
        }

        if (selectedSmoke.Count == 0 && selectedComprehensive.Count == 0)
        {
            Console.WriteLine("No tests matched the specified criteria.");
            bool explicitSelector = onlyFilter is not null || smokeOnlyFilter is not null
                || categoryFilter is not null || performanceRequested;
            return explicitSelector ? 64 : 0;
        }

        int workerCount;
        if (parallelOverride is int cliWorkers)
        {
            workerCount = cliWorkers;
        }
        else if (Environment.GetEnvironmentVariable("KEEPVAULT_TEST_WORKERS") is { Length: > 0 } workerEnvironment)
        {
            if (!int.TryParse(workerEnvironment, NumberStyles.None, CultureInfo.InvariantCulture, out workerCount)
                || workerCount < 1 || workerCount > 128)
            {
                Console.Error.WriteLine("Usage error: KEEPVAULT_TEST_WORKERS requires an integer between 1 and 128.");
                return 64;
            }
        }
        else
        {
            workerCount = Math.Clamp(Environment.ProcessorCount / 2, 2, 8);
        }

        Dictionary<string, double> cachedTimings = LoadTimings(timingsPath);
        var currentRunTimings = new ConcurrentDictionary<string, double>(cachedTimings);

        for (int iteration = 1; iteration <= repeatCount; iteration++)
        {
            if (repeatCount > 1)
            {
                Console.WriteLine($"=== Test iteration {iteration} of {repeatCount} ===");
            }

            Stopwatch totalTimer = Stopwatch.StartNew();
            HardwareBudget budget = HardwareBudget.Detect();
            var iterationOutcomes = new List<TestOutcome>();
            Console.WriteLine(
                $"scheduler: {budget.CpuCount} logical CPUs, {budget.TotalRamBytes / (1024 * 1024 * 1024)} GiB; "
                + $"budget {budget.CpuTokens} CPU tokens / {budget.MemoryMiB} MiB, "
                + $"{budget.ArgonSlots} Argon slot(s), {budget.ZpaqSlots} ZPAQ slot(s), max {workerCount} worker(s)"
                + (inProcess ? ", in-process" : string.Empty));

            bool smokeFailed = false;
            if (selectedSmoke.Count > 0)
            {
                IReadOnlyList<TestOutcome> smokeOutcomes = await TestCoordinator.RunAsync(
                    selectedSmoke,
                    budget,
                    workerCount,
                    cachedTimings,
                    seedOverride,
                    failFast,
                    inProcess,
                    CancellationToken.None).ConfigureAwait(false);
                iterationOutcomes.AddRange(smokeOutcomes);
                foreach (TestOutcome outcome in smokeOutcomes.Where(outcome => outcome.Status == TestStatus.Pass))
                {
                    currentRunTimings[outcome.Id] = outcome.Seconds;
                }

                smokeFailed = smokeOutcomes.Any(outcome => outcome.Status != TestStatus.Pass);
                Console.WriteLine(
                    $"{smokeOutcomes.Count} Windows smoke tests: "
                    + $"{smokeOutcomes.Count(outcome => outcome.Status == TestStatus.Pass)} passed, "
                    + $"{smokeOutcomes.Count(outcome => outcome.Status == TestStatus.Fail)} failed, "
                    + $"{smokeOutcomes.Count(outcome => outcome.Status == TestStatus.Blocked)} blocked.");
            }

            if (selectedComprehensive.Count > 0 && ShouldRunComprehensive(smokeFailed, failFast))
            {
                IReadOnlyList<TestOutcome> outcomes = await TestCoordinator.RunAsync(
                    selectedComprehensive,
                    budget,
                    workerCount,
                    cachedTimings,
                    seedOverride,
                    failFast,
                    inProcess,
                    CancellationToken.None).ConfigureAwait(false);
                iterationOutcomes.AddRange(outcomes);

                foreach (TestOutcome outcome in outcomes.Where(o => o.Status == TestStatus.Pass))
                {
                    currentRunTimings[outcome.Id] = outcome.Seconds;
                }
            }
            else if (selectedComprehensive.Count > 0)
            {
                foreach (TestCase blocked in selectedComprehensive)
                {
                    iterationOutcomes.Add(new TestOutcome(
                        blocked.Id,
                        blocked.Name,
                        TestStatus.Blocked,
                        0,
                        0,
                        seedOverride ?? 0,
                        "not run: --fail-fast stopped after a smoke failure"));
                }
            }

            totalTimer.Stop();
            try
            {
                TestCoordinator.WriteResults(resultsPath, iterationOutcomes, budget, workerCount, everyTest);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Console.Error.WriteLine($"Could not write test results: {ex.Message}");
                SaveTimings(timingsPath, currentRunTimings);
                return 1;
            }

            int passed = iterationOutcomes.Count(outcome => outcome.Status == TestStatus.Pass);
            int failed = iterationOutcomes.Count(outcome => outcome.Status == TestStatus.Fail);
            int blockedCount = iterationOutcomes.Count(outcome => outcome.Status == TestStatus.Blocked);
            double sumSeconds = iterationOutcomes.Sum(outcome => outcome.Seconds);
            Console.WriteLine();
            Console.WriteLine($"{iterationOutcomes.Count} Windows groups: {passed} passed, {failed} failed, {blockedCount} blocked.");
            Console.WriteLine(
                $"wall clock {totalTimer.Elapsed.TotalSeconds:F1}s; sum of test times {sumSeconds:F1}s; "
                + $"parallel speedup {(totalTimer.Elapsed.TotalSeconds > 0 ? sumSeconds / totalTimer.Elapsed.TotalSeconds : 0):F2}x");
            Console.WriteLine($"results written to {resultsPath}");

            if (failed > 0 || blockedCount > 0)
            {
                Console.WriteLine();
                Console.WriteLine("Failing tests:");
                foreach (TestOutcome outcome in iterationOutcomes.Where(outcome => outcome.Status != TestStatus.Pass))
                {
                    Console.WriteLine($"  {outcome.Status.ToString().ToUpperInvariant()} {outcome.Id} — {outcome.Name}");
                }

                SaveTimings(timingsPath, currentRunTimings);
                return 1;
            }
        }

        SaveTimings(timingsPath, currentRunTimings);
        return 0;
    }

    internal static bool ShouldRunComprehensive(bool smokeFailed, bool failFast) =>
        !smokeFailed || !failFast;

    internal static bool IsAutomaticComprehensive(TestCase test) => !test.IsPerformance;

    internal static bool IsSelectedByManualPerformanceMode(
        TestCase test,
        bool performanceRequested,
        string? onlyFilter,
        string? categoryFilter) =>
        !test.IsPerformance
        || performanceRequested
        || (onlyFilter is not null && MatchesSelector(test, onlyFilter))
        || string.Equals(categoryFilter, "Performance", StringComparison.OrdinalIgnoreCase);

    internal static bool MatchesSelector(TestCase test, string selector) =>
        string.Equals(test.Id, selector, StringComparison.Ordinal)
        || test.Name.Contains(selector, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Which tests the working tree's changes can plausibly have broken.
    /// </summary>
    /// <remarks>
    /// A file that matches nothing selects everything, which is the only safe
    /// default: an unmapped file is an unknown blast radius, not an empty one.
    /// </remarks>
    private static HashSet<string>? DetermineAffectedTestsFromGit(string? baseRef)
    {
        var affected = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            var diffCommands = new List<string[]>();
            if (!string.IsNullOrWhiteSpace(baseRef))
            {
                diffCommands.Add(["diff", "--name-only", $"{baseRef}...HEAD"]);
            }
            else
            {
                diffCommands.Add(["diff", "--name-only", "HEAD"]);
                diffCommands.Add(["diff", "--name-only", "--cached"]);
                diffCommands.Add(["diff", "--name-only", "HEAD~1...HEAD"]);
            }

            var files = new HashSet<string>(StringComparer.Ordinal);
            bool anySucceeded = false;
            foreach (string[] arguments in diffCommands)
            {
                var startInfo = new ProcessStartInfo
                {
                    FileName = "git",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                };
                foreach (string argument in arguments)
                {
                    startInfo.ArgumentList.Add(argument);
                }

                using Process? process = Process.Start(startInfo);
                if (process is null)
                {
                    continue;
                }

                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();
                if (process.ExitCode != 0)
                {
                    continue;
                }

                anySucceeded = true;
                foreach (string file in output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    files.Add(file);
                }
            }

            if (!anySucceeded)
            {
                return null;
            }

            if (files.Count == 0)
            {
                return affected;
            }

            foreach (string file in files)
            {
                bool matched = false;

                if (Mentions(file, "V11MasterKdf", "KdfPrimitives", "KdfSalts", "SuiteKeySchedule",
                        "PasswordKeyService", "ContainerKeyDerivation", "SecureMemory", "EntropyMixer"))
                {
                    matched = true;
                    affected.Add("entropy.generated-factors-pools-locks");
                    affected.Add("kdf.argon2-reference-cli");
                    affected.Add("ALL_CONTAINER_SUITES");
                }

                if (Mentions(file, "ZpaqService", "SecureFile", "CryptographicEraseService"))
                {
                    matched = true;
                    affected.Add("zpaq.path-traversal-extraction");
                    affected.Add("zpaq.input-binding");
                    affected.Add("zpaq.malformed-pipe-corpus");
                    affected.Add("zpaq.compression-level-matrix");
                    affected.Add("zpaq.child-process-containment");
                    affected.Add("erase.cryptographic");
                }

                if (Mentions(file, "RecoveryService", "Kpar2", "KPAR2"))
                {
                    matched = true;
                    affected.Add("ALL_RECOVERY_SUITES");
                }

                if (Mentions(file, "MainWindow", "AppSettingsStore", "KeySheetService", "WindowProtection"))
                {
                    matched = true;
                    affected.Add("gui.settings-drop-key-sheets");
                    affected.Add("smoke.localization-defaults");
                }

                if (Mentions(file, "IntegrityService", "SigningTrustPolicy", "HybridSignatureService",
                        "Mldsa87", "NativeToolTargets", "Sign-Binaries", "Generate-ReleaseManifests",
                        "Sign-ManagedOutput", "KalynaReleaseVerifier"))
                {
                    matched = true;
                    affected.Add("integrity.native-tools-signatures");
                    affected.Add("integrity.companion-qr");
                    affected.Add("smoke.release-native-tool-coverage");
                    affected.Add("signing.mldsa87-interop");
                }

                if (Mentions(file, "WindowsCompanionVerification", "QrCodeScannerWindows", "QR-Scanner"))
                {
                    matched = true;
                    affected.Add("integrity.companion-qr");
                }

                if (Mentions(file, "ProcessHardening"))
                {
                    matched = true;
                    affected.Add("hardening.process");
                }

                if (Mentions(file, "Threefish", "Kalyna", "Sha3", "Skein", "Mars", "Shacal",
                        "chachapoly", "aes_ref", "cryptopp_ctr_common", "EncryptionSuite"))
                {
                    matched = true;
                    affected.Add("smoke.sha3-512-vectors");
                    affected.Add("smoke.skein-1024-vectors");
                    affected.Add("smoke.kalyna-512-vector");
                    affected.Add("crypto.kalyna-parallel-ctr");
                    affected.Add("crypto.kalyna-table-differential");
                    affected.Add("crypto.chacha20-split-differential");
                    affected.Add("smoke.chacha20-poly1305-rfc8439");
                    affected.Add("smoke.threefish-1024-vectors");
                    affected.Add("crypto.threefish-parallel-ctr");
                    affected.Add("crypto.ctr-counter-exhaustion");
                    affected.Add("ALL_CONTAINER_SUITES");
                }

                if (IsPerformanceSensitiveFile(file))
                {
                    affected.Add("performance.cipher-suites");
                }

                if (IsSourceOrBuildFile(file))
                {
                    affected.Add("smoke.localization-defaults");
                    affected.Add("smoke.release-native-tool-coverage");
                }

                if (!matched && !IsBenignFile(file))
                {
                    affected.Add("ALL_SMOKE");
                    affected.Add("ALL_COMPREHENSIVE");
                }
            }

            return affected;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            return null;
        }
    }

    private static bool Mentions(string file, params string[] fragments) =>
        fragments.Any(fragment => file.Contains(fragment, StringComparison.OrdinalIgnoreCase));

    private static bool IsPerformanceSensitiveFile(string file)
    {
        string normalized = file.Replace('\\', '/');
        return Mentions(
            normalized,
            "kalyna_fast.c",
            "kalyna_ref_export.c",
            "threefish_ref_export.c",
            "chachapoly_ref_export.cpp",
            "aes_ref_export.cpp",
            "mars_ref_export.cpp",
            "shacal2_ref_export.cpp",
            "cryptopp_ctr_common.hpp",
            "external/cryptopp/cpu.cpp",
            "Build-Native.cmd",
            "Build-Native-macOS.sh",
            "NativeCascadeCiphers.cs",
            "CipherSuitePerformanceTests.cs");
    }

    private static bool IsSourceOrBuildFile(string file)
    {
        string extension = Path.GetExtension(file);
        return extension.Equals(".cs", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".c", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".cc", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".cpp", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".cxx", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".h", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".hh", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".hpp", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".hxx", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".swift", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".xaml", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".axaml", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".ps1", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".fsx", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".sh", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".cmd", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".bat", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".props", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".targets", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".csproj", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Files that cannot change what any test observes.
    /// </summary>
    /// <remarks>
    /// Deliberately short. Everything not listed here selects the whole suite,
    /// so the cost of forgetting an entry is a slower run, and the cost of
    /// adding a wrong one is a defect that ships.
    /// </remarks>
    private static bool IsBenignFile(string file)
    {
        string normalized = file.Replace('\\', '/');
        return normalized.StartsWith(".github/", StringComparison.OrdinalIgnoreCase)
            || normalized.StartsWith("docs/", StringComparison.OrdinalIgnoreCase)
            || normalized.StartsWith("build-analysis/", StringComparison.OrdinalIgnoreCase)
            || normalized.EndsWith(".gitignore", StringComparison.OrdinalIgnoreCase)
            || normalized.EndsWith(".gitattributes", StringComparison.OrdinalIgnoreCase);
    }

    private static Dictionary<string, double> LoadTimings(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return new Dictionary<string, double>(StringComparer.Ordinal);
            }

            Dictionary<string, double>? loaded = JsonSerializer.Deserialize<Dictionary<string, double>>(File.ReadAllText(path));
            return loaded is null
                ? new Dictionary<string, double>(StringComparer.Ordinal)
                : new Dictionary<string, double>(loaded, StringComparer.Ordinal);
        }
        catch (Exception ex) when (ex is IOException or JsonException)
        {
            return new Dictionary<string, double>(StringComparer.Ordinal);
        }
    }

    private static void SaveTimings(string path, ConcurrentDictionary<string, double> timings)
    {
        try
        {
            File.WriteAllText(
                path,
                JsonSerializer.Serialize(
                    timings.ToDictionary(entry => entry.Key, entry => Math.Round(entry.Value, 3)),
                    new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (IOException)
        {
        }
    }
}
