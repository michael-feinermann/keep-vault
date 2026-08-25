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
                    if (i + 1 >= args.Length || !int.TryParse(args[i + 1], out int p) || (p != -1 && (p < 1 || p > 128)))
                    {
                        Console.Error.WriteLine("Usage error: --parallel requires -1 or an integer between 1 and 128.");
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

            IReadOnlyList<TestCase> everyTest = [.. smokeTests, .. comprehensiveTests];
            return await TestCoordinator.RunWorkerModeAsync(everyTest, workerTestId, seedOverride ?? 1u).ConfigureAwait(false);
        }

        if (listOnly)
        {
            Console.WriteLine("Available smoke tests:");
            foreach (TestCase test in smokeTests)
            {
                Console.WriteLine($"  [Smoke] [{test.Resource,-15}] {test.Name}");
            }

            Console.WriteLine();
            Console.WriteLine("Available comprehensive tests:");
            foreach (TestCase test in comprehensiveTests)
            {
                Console.WriteLine($"  [{test.Category,-11}] [{test.Resource,-15}] {test.Name}");
            }

            return 0;
        }

        var selectedSmoke = new List<TestCase>();
        var selectedComprehensive = new List<TestCase>();

        if (rerunFailures)
        {
            IReadOnlyList<string> failedIds = TestCoordinator.ReadFailedIds(resultsPath);
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
        else if (changedRequested)
        {
            HashSet<string>? affected = DetermineAffectedTestsFromGit(baseRef);
            if (affected is null)
            {
                Console.WriteLine("Note: git impact detection could not determine changed files; running the full suite.");
                selectedSmoke.AddRange(smokeTests);
                selectedComprehensive.AddRange(comprehensiveTests);
            }
            else if (affected.Count == 0)
            {
                selectedSmoke.AddRange(smokeTests);
                selectedComprehensive.AddRange(comprehensiveTests.Where(t => t.Resource == TestResource.Light));
            }
            else
            {
                // A mapping entry that names no existing test would silently
                // select nothing for the file that produced it, so a renamed
                // security test could stop running without anyone noticing.
                // Refuse the run instead of quietly covering less.
                var known = new HashSet<string>(
                    smokeTests.Select(t => t.Name).Concat(comprehensiveTests.Select(t => t.Name)),
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

                selectedSmoke.AddRange(smokeTests.Where(t => affected.Contains(t.Name) || affected.Contains("ALL_SMOKE")));
                selectedComprehensive.AddRange(comprehensiveTests.Where(t =>
                    affected.Contains(t.Name)
                    || affected.Contains("ALL_COMPREHENSIVE")
                    || (affected.Contains("ALL_CONTAINER_SUITES") && string.Equals(t.Category, "Containers", StringComparison.Ordinal))
                    || (affected.Contains("ALL_RECOVERY_SUITES") && string.Equals(t.Category, "Recovery", StringComparison.Ordinal))));
                if (selectedSmoke.Count == 0 && selectedComprehensive.Count == 0)
                {
                    selectedSmoke.AddRange(smokeTests);
                    selectedComprehensive.AddRange(comprehensiveTests.Where(t => t.Resource == TestResource.Light));
                }
            }
        }
        else if (quickRequested)
        {
            selectedSmoke.AddRange(smokeTests);
            selectedComprehensive.AddRange(comprehensiveTests.Where(t => t.Resource == TestResource.Light));
        }
        else
        {
            if (!noSmokeRequested && (onlyFilter is null || smokeOnlyFilter is not null || smokeRequested))
            {
                if (smokeOnlyFilter is not null)
                {
                    selectedSmoke.AddRange(smokeTests.Where(t => t.Name.Contains(smokeOnlyFilter, StringComparison.OrdinalIgnoreCase)));
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
                || smokeRequested || smokeOnlyFilter is not null;
            if (fullRequested || onlyFilter is not null || categoryFilter is not null || !anySelector)
            {
                IEnumerable<TestCase> comprehensive = comprehensiveTests;
                if (onlyFilter is not null)
                {
                    comprehensive = comprehensive.Where(t => t.Name.Contains(onlyFilter, StringComparison.OrdinalIgnoreCase));
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
            bool explicitSelector = onlyFilter is not null || smokeOnlyFilter is not null || categoryFilter is not null;
            return explicitSelector ? 64 : 0;
        }

        int workerCount = parallelOverride
            ?? (int.TryParse(Environment.GetEnvironmentVariable("KEEPVAULT_TEST_WORKERS"), out int envWorkers)
                ? Math.Clamp(envWorkers, 1, 32)
                : Math.Clamp(Environment.ProcessorCount / 2, 2, 8));

        Dictionary<string, double> cachedTimings = LoadTimings(timingsPath);
        var currentRunTimings = new ConcurrentDictionary<string, double>(cachedTimings);

        for (int iteration = 1; iteration <= repeatCount; iteration++)
        {
            if (repeatCount > 1)
            {
                Console.WriteLine($"=== Test iteration {iteration} of {repeatCount} ===");
            }

            Stopwatch totalTimer = Stopwatch.StartNew();

            if (selectedSmoke.Count > 0)
            {
                bool smokePassed = await RunSmokeBatchAsync(selectedSmoke, workerCount, cachedTimings, currentRunTimings).ConfigureAwait(false);
                if (!smokePassed)
                {
                    SaveTimings(timingsPath, currentRunTimings);
                    return 1;
                }

                Console.WriteLine($"{selectedSmoke.Count} Windows smoke tests passed.");
            }

            if (selectedComprehensive.Count > 0)
            {
                HardwareBudget budget = HardwareBudget.Detect();
                Console.WriteLine(
                    $"scheduler: {budget.CpuCount} logical CPUs, {budget.TotalRamBytes / (1024 * 1024 * 1024)} GiB; "
                    + $"budget {budget.CpuTokens} CPU tokens / {budget.MemoryMiB} MiB, "
                    + $"{budget.ArgonSlots} Argon slot(s), {budget.ZpaqSlots} ZPAQ slot(s)"
                    + (inProcess ? ", in-process" : string.Empty));

                IReadOnlyList<TestOutcome> outcomes = await TestCoordinator.RunAsync(
                    selectedComprehensive,
                    budget,
                    cachedTimings,
                    seedOverride,
                    failFast,
                    inProcess,
                    CancellationToken.None).ConfigureAwait(false);

                foreach (TestOutcome outcome in outcomes.Where(o => o.Status == TestStatus.Pass))
                {
                    currentRunTimings[outcome.Name] = outcome.Seconds;
                }

                TestCoordinator.WriteResults(resultsPath, outcomes, budget);

                int passed = outcomes.Count(o => o.Status == TestStatus.Pass);
                int failed = outcomes.Count(o => o.Status == TestStatus.Fail);
                int blocked = outcomes.Count(o => o.Status == TestStatus.Blocked);
                double sumSeconds = outcomes.Sum(o => o.Seconds);
                totalTimer.Stop();

                Console.WriteLine();
                Console.WriteLine($"{outcomes.Count} comprehensive Windows groups: {passed} passed, {failed} failed, {blocked} blocked.");
                Console.WriteLine(
                    $"wall clock {totalTimer.Elapsed.TotalSeconds:F1}s; sum of test times {sumSeconds:F1}s; "
                    + $"parallel speedup {(totalTimer.Elapsed.TotalSeconds > 0 ? sumSeconds / totalTimer.Elapsed.TotalSeconds : 0):F2}x");
                Console.WriteLine($"results written to {resultsPath}");

                if (failed > 0 || blocked > 0)
                {
                    Console.WriteLine();
                    Console.WriteLine("Failing tests:");
                    foreach (TestOutcome outcome in outcomes.Where(o => o.Status != TestStatus.Pass))
                    {
                        Console.WriteLine($"  {outcome.Status.ToString().ToUpperInvariant()} {outcome.Name}");
                    }

                    SaveTimings(timingsPath, currentRunTimings);
                    return 1;
                }

                Console.WriteLine($"{selectedComprehensive.Count} comprehensive Windows functional/cryptographic groups passed.");
            }

            totalTimer.Stop();
        }

        SaveTimings(timingsPath, currentRunTimings);
        return 0;
    }

    /// <remarks>
    /// Longest first, across the CPU budget. Smoke tests are Light by
    /// definition and run in this process: they exist to fail in seconds, and a
    /// worker launch each would cost more than the test.
    /// </remarks>
    private static async Task<bool> RunSmokeBatchAsync(
        IReadOnlyList<TestCase> tests,
        int workerCount,
        Dictionary<string, double> cachedTimings,
        ConcurrentDictionary<string, double> currentTimings)
    {
        var sorted = tests
            .OrderByDescending(t => cachedTimings.GetValueOrDefault(t.Name, 0.0))
            .ToList();

        bool allPassed = true;

        await Parallel.ForEachAsync(
            sorted,
            new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, workerCount) },
            async (test, _) =>
            {
                Stopwatch stopwatch = Stopwatch.StartNew();
                try
                {
                    await test.Run().ConfigureAwait(false);
                    stopwatch.Stop();
                    currentTimings[test.Name] = stopwatch.Elapsed.TotalSeconds;
                    lock (ConsoleLock)
                    {
                        Console.WriteLine($"PASS {test.Name}");
                    }
                }
                catch (Exception ex)
                {
                    stopwatch.Stop();
                    allPassed = false;
                    lock (ConsoleLock)
                    {
                        Console.WriteLine();
                        Console.WriteLine($"FAIL smoke: {test.Name}");
                        Console.WriteLine($"  {ex.GetType().Name}: {ex.Message}");
                        if (ex.InnerException is not null)
                        {
                            Console.WriteLine($"  Inner: {ex.InnerException.Message}");
                        }

                        Console.WriteLine();
                        Console.WriteLine("Re-run:");
                        Console.WriteLine($"  dotnet run --no-build --no-restore --project KalynaArchiver.Tests -c Release -- --smoke-only \"{test.Name}\"");
                        Console.WriteLine();
                    }
                }
            }).ConfigureAwait(false);

        return allPassed;
    }

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
                    affected.Add("generated factors, entropy pools and locked-page accounting");
                    affected.Add("Argon2id PHC reference-CLI comparison");
                    affected.Add("ALL_CONTAINER_SUITES");
                }

                if (Mentions(file, "ZpaqService", "SecureFile", "CryptographicEraseService"))
                {
                    matched = true;
                    affected.Add("ZPAQ path traversal and extraction directories");
                    affected.Add("ZPAQ input binding: reparse points, post-check insertion, leases");
                    affected.Add("mutated ZPAQ pipe-parser crash and hang corpus");
                    affected.Add("ZPAQ compression levels 0-5 for file and RAM-pipe paths");
                    affected.Add("child-process cancellation and bounded output");
                    affected.Add("cryptographic erase");
                }

                if (Mentions(file, "RecoveryService", "Kpar2", "KPAR2"))
                {
                    matched = true;
                    affected.Add("ALL_RECOVERY_SUITES");
                }

                if (Mentions(file, "MainWindow", "AppSettingsStore", "KeySheetService", "WindowProtection"))
                {
                    matched = true;
                    affected.Add("settings persistence, drag-and-drop and key sheets");
                    affected.Add("MainWindow design-time text against the installed strings");
                }

                if (Mentions(file, "IntegrityService", "SigningTrustPolicy", "HybridSignatureService",
                        "Mldsa87", "NativeToolTargets", "Sign-Binaries", "Generate-ReleaseManifests",
                        "Sign-ManagedOutput", "KalynaReleaseVerifier"))
                {
                    matched = true;
                    affected.Add("native tool integrity and signatures");
                    affected.Add("the companion QR scanner is checked against the pinned keys");
                    affected.Add("release scripts cover the required native tool set");
                    affected.Add("ML-DSA-87 FIPS 204 interoperability and tamper rejection");
                }

                if (Mentions(file, "WindowsCompanionVerification", "QrCodeScannerWindows", "QR-Scanner"))
                {
                    matched = true;
                    affected.Add("the companion QR scanner is checked against the pinned keys");
                }

                if (Mentions(file, "ProcessHardening"))
                {
                    matched = true;
                    affected.Add("process hardening");
                }

                if (Mentions(file, "Threefish", "Kalyna", "Sha3", "Skein", "Mars", "Shacal",
                        "chachapoly", "aes_ref", "cryptopp_ctr_common", "EncryptionSuite"))
                {
                    matched = true;
                    affected.Add("SHA3-512 reference vectors");
                    affected.Add("Skein-1024 hash and MAC vectors");
                    affected.Add("Kalyna-512/512 reference vector");
                    affected.Add("Kalyna-512/512 parallel CTR equivalence");
                    affected.Add("Kalyna-512/512 table path against the reference over 256 MiB");
                    affected.Add("ChaCha20 worker split against the serial keystream over 256 MiB");
                    affected.Add("ChaCha20-Poly1305 framing against RFC 8439");
                    affected.Add("Threefish-1024 official vectors and an independent implementation");
                    affected.Add("Threefish-1024 parallel CTR equivalence");
                    affected.Add("ALL_CONTAINER_SUITES");
                }

                if (file.EndsWith(".cs", StringComparison.OrdinalIgnoreCase)
                    || file.EndsWith(".c", StringComparison.OrdinalIgnoreCase)
                    || file.EndsWith(".h", StringComparison.OrdinalIgnoreCase)
                    || file.EndsWith(".hpp", StringComparison.OrdinalIgnoreCase)
                    || file.EndsWith(".cpp", StringComparison.OrdinalIgnoreCase))
                {
                    affected.Add("MainWindow design-time text against the installed strings");
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
