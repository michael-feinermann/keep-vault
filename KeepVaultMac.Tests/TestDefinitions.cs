using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;

internal enum TestResource
{
    Light,          // Thread-safe, low RAM/CPU: pure KATs, policies, non-conflicting descriptors
    CpuHeavy,       // Thread-safe CPU-intensive: ML-DSA, differential testing, per-chunk nonces
    ProcessGlobal,  // Serial preflight: modifies or measures process-wide state
                    // (process hardening, locked-page accounting)
    ArgonHeavy,     // Serial: 1-2 GiB matrices, Argon2id equivalence
    ArgonPeakMemory,// Strictly exclusive: peak memory / RSS measurement
    EntropyGlobal,  // Serial: consumes shared EntropyMixer state
    ZpaqGlobal,     // Serial: ZPAQ extraction & limit testing
    Gui             // Serial: Avalonia headless UI-thread worker
}

internal sealed record TestCase(
    string Id,
    string Name,
    Func<Task> Run,
    TestResource Resource,
    string Category = "General",
    bool IsSmoke = false,
    bool IsPerformance = false)
{
    public TestCost Cost { get; init; } = TestCost.FromResource(Resource);
}

internal static class TestInventory
{
    internal static void Validate(
        IReadOnlyList<TestCase> smokeTests,
        IReadOnlyList<TestCase> comprehensiveTests)
    {
        TestCase[] allTests = [.. smokeTests, .. comprehensiveTests];
        if (allTests.Length == 0)
        {
            throw new InvalidOperationException("The test inventory is empty.");
        }

        foreach (TestCase test in allTests)
        {
            if (string.IsNullOrWhiteSpace(test.Id)
                || test.Id.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '.' or '-'))
                || !char.IsAsciiLetterOrDigit(test.Id[0]))
            {
                throw new InvalidOperationException(
                    $"Test id '{test.Id}' is invalid. Use a stable lower-case ASCII literal containing letters, digits, dots or hyphens.");
            }

            if (!string.Equals(test.Id, test.Id.ToLowerInvariant(), StringComparison.Ordinal))
            {
                throw new InvalidOperationException($"Test id '{test.Id}' must be lower-case ASCII.");
            }

            if (string.IsNullOrWhiteSpace(test.Name))
            {
                throw new InvalidOperationException($"Test '{test.Id}' has no display name.");
            }
        }

        string[] duplicateIds =
        [
            .. allTests
                .GroupBy(test => test.Id, StringComparer.Ordinal)
                .Where(group => group.Count() != 1)
                .Select(group => group.Key)
                .OrderBy(id => id, StringComparer.Ordinal),
        ];
        if (duplicateIds.Length > 0)
        {
            throw new InvalidOperationException("Duplicate test id(s): " + string.Join(", ", duplicateIds));
        }

        TestCase[] wronglyClassified =
        [
            .. smokeTests.Where(test => !test.IsSmoke),
            .. comprehensiveTests.Where(test => test.IsSmoke),
        ];
        if (wronglyClassified.Length > 0)
        {
            throw new InvalidOperationException(
                "Smoke classification does not match inventory membership: "
                + string.Join(", ", wronglyClassified.Select(test => test.Id)));
        }

        TestCase[] invalidPerformance =
        [
            .. allTests.Where(test => test.IsPerformance
                && (test.IsSmoke
                    || !string.Equals(test.Category, "Performance", StringComparison.Ordinal))),
        ];
        if (invalidPerformance.Length > 0)
        {
            throw new InvalidOperationException(
                "Performance tests must be non-smoke tests in the Performance category: "
                + string.Join(", ", invalidPerformance.Select(test => test.Id)));
        }
    }

    internal static string ComputeHash(IReadOnlyList<TestCase> tests)
    {
        var canonical = new System.Text.StringBuilder();
        foreach (TestCase test in tests.OrderBy(test => test.Id, StringComparer.Ordinal))
        {
            canonical.Append(test.Id).Append('\n');
        }

        return Convert.ToHexString(
            SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(canonical.ToString())))
            .ToLowerInvariant();
    }
}

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
        string? dumpKeySheetsDir = null;
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
                    if (i + 1 >= args.Length || args[i + 1].StartsWith("--"))
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
                    if (i + 1 >= args.Length || args[i + 1].StartsWith("--"))
                    {
                        Console.Error.WriteLine("Usage error: Missing value for --only.");
                        return 64;
                    }
                    onlyFilter = args[++i];
                    break;
                case "--smoke-only":
                    if (i + 1 >= args.Length || args[i + 1].StartsWith("--"))
                    {
                        Console.Error.WriteLine("Usage error: Missing value for --smoke-only.");
                        return 64;
                    }
                    smokeOnlyFilter = args[++i];
                    break;
                case "--category":
                    if (i + 1 >= args.Length || args[i + 1].StartsWith("--"))
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
                    string seedStr = args[++i];
                    uint? parsedSeed = seedStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                        ? (uint.TryParse(seedStr[2..], System.Globalization.NumberStyles.HexNumber, null, out uint sHex) ? sHex : null)
                        : (uint.TryParse(seedStr, out uint sDec) ? sDec : null);
                    if (parsedSeed == null)
                    {
                        Console.Error.WriteLine($"Usage error: Invalid seed value '{seedStr}'. Expected 32-bit unsigned integer or hex (e.g. 0x12345678).");
                        return 64;
                    }
                    seedOverride = parsedSeed;
                    break;
                case "--base":
                    if (i + 1 >= args.Length || args[i + 1].StartsWith("--"))
                    {
                        Console.Error.WriteLine("Usage error: Missing value for --base.");
                        return 64;
                    }
                    baseRef = args[++i];
                    break;
                case "--dump-key-sheets":
                    if (i + 1 >= args.Length || args[i + 1].StartsWith("--"))
                    {
                        Console.Error.WriteLine("Usage error: Missing value for --dump-key-sheets.");
                        return 64;
                    }
                    dumpKeySheetsDir = args[++i];
                    break;
                case "--timings":
                    if (i + 1 >= args.Length || args[i + 1].StartsWith("--"))
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

        // A worker runs exactly one test and reports one machine-readable
        // line. It must short-circuit before any selection logic: the
        // coordinator addresses it by id, not by the filters a human would use.
        if (workerMode)
        {
            if (string.IsNullOrEmpty(workerTestId))
            {
                Console.Error.WriteLine("Usage error: --worker requires --test-id.");
                return 64;
            }

            return await TestCoordinator.RunWorkerModeAsync(everyTest, workerTestId, seedOverride ?? 1u);
        }

        if (listOnly)
        {
            Console.WriteLine("Available Smoke Tests:");
            foreach (var test in smokeTests)
            {
                Console.WriteLine($"  {test.Id,-48} [Smoke] [{test.Resource,-13}] {test.Name}");
            }
            Console.WriteLine();
            Console.WriteLine("Available Comprehensive Tests:");
            foreach (var test in comprehensiveTests.Where(IsAutomaticComprehensive))
            {
                Console.WriteLine($"  {test.Id,-48} [{test.Category,-11}] [{test.Resource,-15}] {test.Name}");
            }

            TestCase[] performanceTests = [.. comprehensiveTests.Where(test => test.IsPerformance)];
            if (performanceTests.Length > 0)
            {
                Console.WriteLine();
                Console.WriteLine("Available Manual Performance Gates:");
                foreach (TestCase test in performanceTests)
                {
                    Console.WriteLine($"  {test.Id,-48} [Performance] [{test.Resource,-15}] {test.Name}");
                }
            }
            return 0;
        }

        // Determine which tests to include
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
            HashSet<string>? affectedNames = DetermineAffectedTestsFromGit(baseRef);
            if (affectedNames == null)
            {
                Console.WriteLine("Note: Git impact detection could not determine changed files; running full test suite.");
                selectedSmoke.AddRange(smokeTests);
                selectedComprehensive.AddRange(comprehensiveTests.Where(IsAutomaticComprehensive));
            }
            else if (affectedNames.Count == 0)
            {
                // Fallback: run smoke + light tests
                selectedSmoke.AddRange(smokeTests);
                selectedComprehensive.AddRange(comprehensiveTests.Where(t => IsAutomaticComprehensive(t) && t.Resource == TestResource.Light));
            }
            else
            {
                // A mapping entry that names no existing test would silently
                // select nothing for the file that produced it, so a renamed
                // security test could stop running without anyone noticing.
                // Refuse the run instead of quietly covering less.
                var knownNames = new HashSet<string>(
                    smokeTests.Select(t => t.Id).Concat(comprehensiveTests.Select(t => t.Id)),
                    StringComparer.Ordinal)
                {
                    "ALL_SMOKE",
                    "ALL_COMPREHENSIVE",
                    "ALL_CONTAINER_SUITES",
                    "ALL_RECOVERY_SUITES",
                };
                string[] unknown = [.. affectedNames.Where(name => !knownNames.Contains(name)).OrderBy(name => name, StringComparer.Ordinal)];
                if (unknown.Length > 0)
                {
                    Console.Error.WriteLine(
                        "The changed-file impact map names tests that do not exist: "
                        + string.Join(", ", unknown)
                        + ". Update the map in TestDefinitions.cs.");
                    return 1;
                }

                if (affectedNames.Contains("performance.cipher-suites"))
                {
                    Console.WriteLine(
                        "Note: cipher/native/build changes require the manual release gate; "
                        + "run this suite again with --performance on an otherwise idle host before release.");
                }

                selectedSmoke.AddRange(smokeTests.Where(t => affectedNames.Contains(t.Id) || affectedNames.Contains("ALL_SMOKE")));
                selectedComprehensive.AddRange(comprehensiveTests.Where(t =>
                    !t.IsPerformance
                    && (affectedNames.Contains(t.Id)
                    || affectedNames.Contains("ALL_COMPREHENSIVE")
                    || (affectedNames.Contains("ALL_CONTAINER_SUITES") && string.Equals(t.Category, "Containers", StringComparison.Ordinal))
                    || (affectedNames.Contains("ALL_RECOVERY_SUITES") && string.Equals(t.Category, "Recovery", StringComparison.Ordinal)))));
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
            // Smoke test selection
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

            // Comprehensive test selection
            if (fullRequested || onlyFilter is not null || categoryFilter is not null)
            {
                IEnumerable<TestCase> comp = comprehensiveTests.Where(test =>
                    IsSelectedByManualPerformanceMode(test, performanceRequested, onlyFilter, categoryFilter));
                if (onlyFilter is not null)
                {
                    comp = comp.Where(t => MatchesSelector(t, onlyFilter));
                }
                if (categoryFilter is not null)
                {
                    comp = comp.Where(t =>
                        string.Equals(t.Category, categoryFilter, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(t.Resource.ToString(), categoryFilter, StringComparison.OrdinalIgnoreCase));
                }
                selectedComprehensive.AddRange(comp);
            }
        }

        if (selectedSmoke.Count == 0 && selectedComprehensive.Count == 0)
        {
            Console.WriteLine("No tests matched the specified criteria.");
            bool explicitSelector = onlyFilter != null || smokeOnlyFilter != null
                || categoryFilter != null || performanceRequested;
            return explicitSelector ? 64 : 0;
        }

        // Determine worker count
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

        // Load cached timings for Longest-Processing-Time (LPT) scheduling
        Dictionary<string, double> cachedTimings = LoadTimings(timingsPath);
        var currentRunTimings = new ConcurrentDictionary<string, double>(cachedTimings);

        // Run iterations (if --repeat N)
        for (int iteration = 1; iteration <= repeatCount; iteration++)
        {
            if (repeatCount > 1)
            {
                Console.WriteLine($"=== Test Iteration {iteration} of {repeatCount} ===");
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
                    $"{smokeOutcomes.Count} macOS smoke tests: "
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
            Console.WriteLine($"{iterationOutcomes.Count} macOS groups: {passed} passed, {failed} failed, {blockedCount} blocked.");
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

        if (!string.IsNullOrEmpty(dumpKeySheetsDir))
        {
            DumpKeySheets(dumpKeySheetsDir);
        }

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

    private static HashSet<string>? DetermineAffectedTestsFromGit(string? baseRef)
    {
        var affected = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            List<string> diffArgsList = new();
            if (!string.IsNullOrWhiteSpace(baseRef))
            {
                diffArgsList.Add($"diff --name-only {baseRef}...HEAD");
            }
            else
            {
                diffArgsList.Add("diff --name-only HEAD");
                diffArgsList.Add("diff --name-only --cached");
                diffArgsList.Add("diff --name-only HEAD~1...HEAD");
            }

            var allFiles = new HashSet<string>(StringComparer.Ordinal);
            bool anySuccess = false;

            foreach (string gitArg in diffArgsList)
            {
                using var proc = new Process();
                proc.StartInfo.FileName = "git";
                proc.StartInfo.Arguments = gitArg;
                proc.StartInfo.UseShellExecute = false;
                proc.StartInfo.RedirectStandardOutput = true;
                proc.StartInfo.RedirectStandardError = true;
                proc.StartInfo.CreateNoWindow = true;
                if (proc.Start())
                {
                    string output = proc.StandardOutput.ReadToEnd();
                    proc.WaitForExit();
                    if (proc.ExitCode == 0)
                    {
                        anySuccess = true;
                        string[] files = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                        foreach (var f in files) allFiles.Add(f);
                    }
                }
            }

            if (!anySuccess)
            {
                return null;
            }

            if (allFiles.Count == 0)
            {
                return affected;
            }

            foreach (string file in allFiles)
            {
                bool matched = false;
                if (file.Contains("V11MasterKdf") || file.Contains("KdfPrimitives") || file.Contains("KdfSalts") || file.Contains("SuiteKeySchedule") || file.Contains("PasswordKeyService") || file.Contains("ContainerKeyDerivation") || file.Contains("SecureMemory"))
                {
                    matched = true;
                    affected.Add("crypto.kdf-primitives");
                    affected.Add("kdf.properties");
                    affected.Add("kdf.v11-master-factor-split");
                    affected.Add("kdf.argon2-equivalence");
                    affected.Add("kdf.peak-memory-and-header");
                    affected.Add("policy.password");
                    affected.Add("policy.pin-creation");
                    affected.Add("ALL_CONTAINER_SUITES");
                    affected.Add("containers.v11-kpar2-roundtrip");
                }
                if (file.Contains("ZpaqService") || file.Contains("MacPlatformSecurity") || file.Contains("MacSecureFile") || file.Contains("MacOriginalDeletionService"))
                {
                    matched = true;
                    affected.Add("zpaq.full-matrix");
                    affected.Add("deletion.original-verification");
                    affected.Add("deletion.cryptographic-erase");
                    affected.Add("smoke.descriptor-identity");
                    affected.Add("smoke.symlink-rejection");
                    affected.Add("smoke.archive-input-symlink");
                    affected.Add("smoke.archive-input-snapshot-location");
                    affected.Add("smoke.overlapping-input-normalization");
                    affected.Add("smoke.descriptor-bound-snapshot");
                }
                if (file.Contains("RecoveryService") || file.Contains("Kpar2"))
                {
                    matched = true;
                    affected.Add("recovery.kpar2-v4-adversarial");
                    affected.Add("ALL_RECOVERY_SUITES");
                }
                if (file.Contains("MainWindow") || file.Contains("MacGuiTests") || file.Contains("Avalonia"))
                {
                    matched = true;
                    affected.Add("gui.entropy-display");
                    affected.Add("gui.encryption-toggle-target");
                    affected.Add("gui.folder-target");
                    affected.Add("gui.password-policy");
                    affected.Add("gui.original-deletion-localization");
                    affected.Add("gui.control-inventory");
                    affected.Add("gui.factor-normalization");
                    affected.Add("gui.secret-clearing");
                    affected.Add("gui.kdf-entropy-localization");
                    affected.Add("gui.full-creation-flow");
                }
                if (file.EndsWith(".md", StringComparison.OrdinalIgnoreCase))
                {
                    matched = true;
                    affected.Add("spec.normative-v11-docs");
                    affected.Add("spec.no-legacy-source");
                }
                if (file.Contains("QrCodeScanner") || file.Contains("QR-Scanner") || file.Contains("Verify-QR-Scanner"))
                {
                    matched = true;
                    affected.Add("packaging.companion-qr");
                    affected.Add("smoke.release-companion-version");
                }
                if (file.Contains("Packaging") || file.Contains("HybridSigner") || file.Contains("Integrity"))
                {
                    matched = true;
                    affected.Add("trust.native-tools");
                    affected.Add("packaging.macho-signature-closure");
                    affected.Add("crypto.mldsa87-interop");
                }
                if (file.Contains("Threefish", StringComparison.OrdinalIgnoreCase)
                    || file.Contains("Kalyna", StringComparison.OrdinalIgnoreCase)
                    || file.Contains("Sha3", StringComparison.OrdinalIgnoreCase)
                    || file.Contains("Skein", StringComparison.OrdinalIgnoreCase)
                    || file.Contains("Mars", StringComparison.OrdinalIgnoreCase)
                    || file.Contains("Shacal", StringComparison.OrdinalIgnoreCase)
                    || file.Contains("ChaCha", StringComparison.OrdinalIgnoreCase)
                    || file.Contains("aes_ref", StringComparison.OrdinalIgnoreCase)
                    || file.Contains("cryptopp_ctr_common", StringComparison.OrdinalIgnoreCase))
                {
                    matched = true;
                    affected.Add("crypto.primitive-vectors");
                    affected.Add("crypto.cascade-layering");
                    affected.Add("crypto.two-round-derivation");
                    affected.Add("crypto.unprepared-parameters");
                    affected.Add("crypto.per-chunk-nonces");
                    affected.Add("crypto.mars-shacal-vectors");
                    affected.Add("crypto.reference-differential");
                    affected.Add("crypto.kalyna-fast-path-differential");
                    affected.Add("crypto.chacha20-fast-path-differential");
                    affected.Add("crypto.chacha20-poly1305-rfc8439");
                }

                if (IsPerformanceSensitiveFile(file))
                {
                    affected.Add("performance.cipher-suites");
                }

                if (IsSourceOrBuildFile(file))
                {
                    affected.Add("spec.no-legacy-source");
                    affected.Add("spec.normative-v11-docs");
                }

                if (!matched && !IsBenignFile(file))
                {
                    affected.Add("ALL_SMOKE");
                    affected.Add("ALL_COMPREHENSIVE");
                }
            }
            return affected;
        }
        catch
        {
            return null;
        }
    }

    private static bool IsBenignFile(string file)
    {
        string normalized = file.Replace('\\', '/');

        // Licensing and repository metadata. README and docs/ are deliberately
        // absent: they state the normative security architecture, and a README
        // that contradicts the code is how a later reader "fixes" the working
        // side. They select the spec-consistency gate instead, which is fast.
        if (string.Equals(normalized, "LICENSE", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(normalized, "LICENSE.txt", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(normalized, "NOTICE", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(normalized, "NOTICE.txt", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(normalized, ".gitignore", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(normalized, ".gitattributes", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(normalized, ".editorconfig", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // Purely visual graphic assets
        if (normalized.EndsWith(".png", StringComparison.OrdinalIgnoreCase) ||
            normalized.EndsWith(".icns", StringComparison.OrdinalIgnoreCase) ||
            normalized.EndsWith(".ico", StringComparison.OrdinalIgnoreCase) ||
            normalized.EndsWith(".svg", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return false;
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
            || extension.Equals(".m", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".mm", StringComparison.OrdinalIgnoreCase)
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

    private static bool IsPerformanceSensitiveFile(string file)
    {
        string normalized = file.Replace('\\', '/');
        string[] sensitiveNames =
        [
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
            "CipherSuitePerformanceTests.cs",
        ];
        return sensitiveNames.Any(name => normalized.Contains(name, StringComparison.OrdinalIgnoreCase));
    }

    private static Dictionary<string, double> LoadTimings(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                string json = File.ReadAllText(path);
                return JsonSerializer.Deserialize<Dictionary<string, double>>(json) ?? [];
            }
        }
        catch
        {
        }
        return [];
    }

    private static void SaveTimings(string path, ConcurrentDictionary<string, double> timings)
    {
        try
        {
            string? dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            string json = JsonSerializer.Serialize(new Dictionary<string, double>(timings), new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(path, json);
        }
        catch
        {
        }
    }

    private static void DumpKeySheets(string outputDirectory)
    {
        Directory.CreateDirectory(outputDirectory);
        string first = string.Concat(Enumerable.Range(0, 256).Select(i => "0123456789abcdef"[(i * 7) % 16]));
        string second = string.Concat(Enumerable.Range(0, 256).Select(i => "0123456789abcdef"[(i * 11 + 3) % 16]));
        foreach (bool english in new[] { false, true })
        {
            var service = new KalynaArchiver.Services.KeySheetService();
            string suffix = english ? "en" : "de";
            string firstTarget = Path.Combine(outputDirectory, $"key-sheet-a-{suffix}.pdf");
            string secondTarget = Path.Combine(outputDirectory, $"key-sheet-b-{suffix}.pdf");
            service.SaveTestPdf(
                new KalynaArchiver.Services.KeySheetData(
                    Path.Combine(outputDirectory, "beispiel-archiv.kzpaq"),
                    KalynaArchiver.Services.EncryptionSuite.ParanoiaCascade,
                    first,
                    second,
                    DateTime.Now,
                    english,
                    string.Empty),
                firstTarget,
                secondTarget);
            Console.WriteLine($"key_sheets={firstTarget}");
            Console.WriteLine($"key_sheets={secondTarget}");
        }
    }
}
