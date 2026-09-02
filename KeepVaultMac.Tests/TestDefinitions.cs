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
            .. allTests.Where(test =>
                (test.IsPerformance
                    && (test.IsSmoke
                        || !string.Equals(test.Category, "Performance", StringComparison.Ordinal)))
                || (!test.IsPerformance
                    && string.Equals(test.Category, "Performance", StringComparison.Ordinal))),
        ];
        if (invalidPerformance.Length > 0)
        {
            throw new InvalidOperationException(
                "The Performance category and IsPerformance flag must identify exactly the same non-smoke tests: "
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

        if (onlyFilter is not null && smokeOnlyFilter is not null)
        {
            Console.Error.WriteLine("Usage error: --only and --smoke-only are mutually exclusive.");
            return 64;
        }

        if (onlyFilter is not null
            && (quickRequested || changedRequested || rerunFailures))
        {
            Console.Error.WriteLine(
                "Usage error: --only cannot be combined with --quick, --changed or --rerun-failures.");
            return 64;
        }

        if (onlyFilter is not null
            && categoryFilter is not null
            && !performanceRequested)
        {
            Console.Error.WriteLine(
                "Usage error: --only and --category are alternative selectors outside the performance gate.");
            return 64;
        }

        if (!performanceRequested
            && string.Equals(categoryFilter, "Performance", StringComparison.OrdinalIgnoreCase))
        {
            Console.Error.WriteLine("Usage error: performance tests require the explicit --performance gate.");
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

            return await TestCoordinator.RunWorkerModeAsync(
                everyTest,
                workerTestId,
                seedOverride ?? 1u,
                performanceRequested);
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

            if (ContainsManualPerformanceTest(failedIds, comprehensiveTests))
            {
                Console.Error.WriteLine(
                    "Cannot re-run a manual performance failure without --performance. "
                    + "Run the performance gate explicitly on an otherwise idle host.");
                return 64;
            }

            var failedSet = new HashSet<string>(failedIds, StringComparer.Ordinal);
            selectedSmoke.AddRange(smokeTests.Where(t => failedSet.Contains(t.Id)));
            selectedComprehensive.AddRange(comprehensiveTests.Where(t => failedSet.Contains(t.Id)));
            Console.WriteLine($"Re-running {selectedSmoke.Count + selectedComprehensive.Count} previously failing test(s).");
        }
        else if (performanceRequested)
        {
            selectedComprehensive.AddRange(
                SelectManualPerformanceTests(comprehensiveTests, onlyFilter, categoryFilter));
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
        else if (onlyFilter is not null)
        {
            // --only is the stable primary-key selector for the complete
            // inventory. It must never fall back to display-name matching, and
            // a manual performance gate still requires --performance.
            if (!noSmokeRequested)
            {
                selectedSmoke.AddRange(smokeTests.Where(test => MatchesSelector(test, onlyFilter)));
            }
            selectedComprehensive.AddRange(comprehensiveTests.Where(test =>
                IsAutomaticComprehensive(test) && MatchesSelector(test, onlyFilter)));
        }
        else
        {
            // Smoke test selection
            if (!noSmokeRequested)
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
            if (fullRequested || categoryFilter is not null)
            {
                IEnumerable<TestCase> comp = comprehensiveTests.Where(test =>
                    IsSelectedByManualPerformanceMode(test, performanceRequested, onlyFilter, categoryFilter));
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

        // Determine the one global worker cap used by both phases. CLI wins
        // before the environment is even parsed, which makes the precedence
        // deterministic even if a stale environment value is malformed.
        int workerCount;
        try
        {
            workerCount = ResolveWorkerCount(
                parallelOverride,
                Environment.GetEnvironmentVariable("KEEPVAULT_TEST_WORKERS"),
                Environment.ProcessorCount);
        }
        catch (ArgumentException)
        {
            Console.Error.WriteLine("Usage error: KEEPVAULT_TEST_WORKERS requires an integer between 1 and 128.");
            return 64;
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
        || performanceRequested;

    internal static bool MatchesSelector(TestCase test, string selector) =>
        string.Equals(test.Id, selector, StringComparison.Ordinal);

    internal static int ResolveWorkerCount(
        int? parallelOverride,
        string? workerEnvironment,
        int processorCount)
    {
        if (parallelOverride is int cliWorkers)
        {
            if (cliWorkers is < 1 or > 128)
            {
                throw new ArgumentOutOfRangeException(nameof(parallelOverride));
            }

            return cliWorkers;
        }

        if (!string.IsNullOrEmpty(workerEnvironment))
        {
            if (!int.TryParse(workerEnvironment, NumberStyles.None, CultureInfo.InvariantCulture, out int environmentWorkers)
                || environmentWorkers is < 1 or > 128)
            {
                throw new ArgumentException("Invalid worker environment value.", nameof(workerEnvironment));
            }

            return environmentWorkers;
        }

        return Math.Clamp(processorCount / 2, 2, 8);
    }

    internal static bool ContainsManualPerformanceTest(
        IReadOnlyList<string> selectedIds,
        IReadOnlyList<TestCase> comprehensiveTests)
    {
        var selected = new HashSet<string>(selectedIds, StringComparer.Ordinal);
        return comprehensiveTests.Any(test => test.IsPerformance && selected.Contains(test.Id));
    }

    internal static IReadOnlyList<TestCase> SelectManualPerformanceTests(
        IReadOnlyList<TestCase> comprehensiveTests,
        string? onlyFilter,
        string? categoryFilter)
    {
        IEnumerable<TestCase> selected = comprehensiveTests.Where(test => test.IsPerformance);
        if (onlyFilter is not null)
        {
            selected = selected.Where(test => MatchesSelector(test, onlyFilter));
        }

        if (categoryFilter is not null)
        {
            selected = selected.Where(test =>
                string.Equals(test.Category, categoryFilter, StringComparison.OrdinalIgnoreCase)
                || string.Equals(test.Resource.ToString(), categoryFilter, StringComparison.OrdinalIgnoreCase));
        }

        return [.. selected];
    }

    internal static HashSet<string>? DetermineAffectedTestsFromGit(
        string? baseRef,
        string? workingDirectory = null)
    {
        try
        {
            List<string[]> diffArgumentLists = new();
            if (!string.IsNullOrWhiteSpace(baseRef))
            {
                diffArgumentLists.Add(
                [
                    "diff",
                    "--name-status",
                    "-z",
                    "--find-renames",
                    "--find-copies",
                    "--end-of-options",
                    $"{baseRef}...HEAD",
                    "--",
                ]);
            }
            else
            {
                diffArgumentLists.Add(
                [
                    "diff",
                    "--name-status",
                    "-z",
                    "--find-renames",
                    "--find-copies",
                    "HEAD",
                    "--",
                ]);
                diffArgumentLists.Add(
                [
                    "diff",
                    "--name-status",
                    "-z",
                    "--find-renames",
                    "--find-copies",
                    "--cached",
                    "--",
                ]);
                diffArgumentLists.Add(
                [
                    "diff",
                    "--name-status",
                    "-z",
                    "--find-renames",
                    "--find-copies",
                    "HEAD~1...HEAD",
                    "--",
                ]);
            }

            var allFiles = new HashSet<string>(StringComparer.Ordinal);
            var addedOrCopiedFiles = new HashSet<string>(StringComparer.Ordinal);
            bool anyDiffSucceeded = false;
            foreach (IReadOnlyList<string> arguments in diffArgumentLists)
            {
                if (!TryRunGit(arguments, out string output, workingDirectory))
                {
                    continue;
                }

                anyDiffSucceeded = true;
                allFiles.UnionWith(ParseGitNameStatusZ(output));
                addedOrCopiedFiles.UnionWith(ParseGitAddedOrCopiedPathsZ(output));
            }

            if (!anyDiffSucceeded)
            {
                return null;
            }

            // Untracked files are outside every diff, including an explicit
            // base...HEAD comparison. Omitting them lets a newly added security
            // boundary bypass --changed entirely.
            if (!TryRunGit(
                ["ls-files", "--others", "--exclude-standard", "-z"],
                out string untrackedOutput,
                workingDirectory))
            {
                return null;
            }

            HashSet<string> untrackedFiles = ParseGitPathListZ(untrackedOutput);
            allFiles.UnionWith(untrackedFiles);
            HashSet<string> affected = MapChangedPathsToTests(allFiles);
            if (addedOrCopiedFiles.Concat(untrackedFiles).Any(IsSourceOrBuildFile))
            {
                // A new source/build boundary is not equivalent to a change in
                // an existing, mapped file. Even if its name contains a known
                // substring, its complete interaction surface is still new.
                affected.Add("ALL_SMOKE");
                affected.Add("ALL_COMPREHENSIVE");
            }

            return affected;
        }
        catch
        {
            // Git/process/parser failures must widen test coverage, never
            // silently produce an incomplete impacted-test selection.
            return null;
        }
    }

    internal static bool TryRunGit(
        IReadOnlyList<string> arguments,
        out string output,
        string? workingDirectory = null)
    {
        output = string.Empty;
        using var process = new Process();
        process.StartInfo.FileName = "git";
        process.StartInfo.UseShellExecute = false;
        process.StartInfo.RedirectStandardOutput = true;
        process.StartInfo.RedirectStandardError = true;
        process.StartInfo.CreateNoWindow = true;
        process.StartInfo.StandardOutputEncoding =
            new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
        if (workingDirectory is not null)
        {
            process.StartInfo.WorkingDirectory = Path.GetFullPath(workingDirectory);
        }

        foreach (string argument in arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }

        if (!process.Start())
        {
            return false;
        }

        Task<string> standardOutput = process.StandardOutput.ReadToEndAsync();
        Task<string> standardError = process.StandardError.ReadToEndAsync();
        process.WaitForExit();
        Task.WaitAll(standardOutput, standardError);
        if (process.ExitCode != 0)
        {
            return false;
        }

        output = standardOutput.Result;
        return true;
    }

    internal static HashSet<string> ParseGitNameStatusZ(string output)
    {
        var paths = new HashSet<string>(StringComparer.Ordinal);
        foreach ((_, string[] recordPaths) in ParseGitNameStatusRecordsZ(output))
        {
            paths.UnionWith(recordPaths);
        }

        return paths;
    }

    internal static HashSet<string> ParseGitAddedOrCopiedPathsZ(string output)
    {
        var paths = new HashSet<string>(StringComparer.Ordinal);
        foreach ((char kind, string[] recordPaths) in ParseGitNameStatusRecordsZ(output))
        {
            if (kind == 'A')
            {
                paths.Add(recordPaths[0]);
            }
            else if (kind == 'C')
            {
                paths.Add(recordPaths[1]);
            }
        }

        return paths;
    }

    private static List<(char Kind, string[] Paths)> ParseGitNameStatusRecordsZ(string output)
    {
        string[] fields = SplitGitZOutput(output);
        var records = new List<(char Kind, string[] Paths)>();
        int index = 0;
        while (index < fields.Length)
        {
            string status = fields[index++];
            if (status.Length == 0
                || "ACDMRTUXB".IndexOf(status[0], StringComparison.Ordinal) < 0
                || status.AsSpan(1).ContainsAnyExceptInRange('0', '9'))
            {
                throw new InvalidDataException("Git emitted an invalid name-status field.");
            }

            int pathCount = status[0] is 'R' or 'C' ? 2 : 1;
            if (fields.Length - index < pathCount)
            {
                throw new InvalidDataException("Git emitted a truncated name-status record.");
            }

            var recordPaths = new string[pathCount];
            for (int pathIndex = 0; pathIndex < pathCount; pathIndex++)
            {
                recordPaths[pathIndex] = RequireNormalizedChangedPath(fields[index++]);
            }

            records.Add((status[0], recordPaths));
        }

        return records;
    }

    internal static HashSet<string> ParseGitPathListZ(string output)
    {
        string[] fields = SplitGitZOutput(output);
        var paths = new HashSet<string>(StringComparer.Ordinal);
        foreach (string field in fields)
        {
            paths.Add(RequireNormalizedChangedPath(field));
        }

        return paths;
    }

    private static string[] SplitGitZOutput(string output)
    {
        ArgumentNullException.ThrowIfNull(output);
        if (output.Length == 0)
        {
            return [];
        }

        if (output[^1] != '\0')
        {
            throw new InvalidDataException("Git -z output was not NUL-terminated.");
        }

        string[] fields = output[..^1].Split('\0');
        if (fields.Any(static field => field.Length == 0))
        {
            throw new InvalidDataException("Git -z output contained an empty field.");
        }

        return fields;
    }

    private static string RequireNormalizedChangedPath(string path) =>
        NormalizeChangedPath(path)
        ?? throw new InvalidDataException("Git emitted an unsafe repository-relative path.");

    internal static string? NormalizeChangedPath(string path)
    {
        if (string.IsNullOrEmpty(path) || path.IndexOf('\0') >= 0)
        {
            return null;
        }

        string portable = path.Replace('\\', '/');
        if (portable.StartsWith("/", StringComparison.Ordinal)
            || (portable.Length >= 2 && portable[1] == ':'))
        {
            return null;
        }

        var segments = new List<string>();
        foreach (string segment in portable.Split('/'))
        {
            if (segment.Length == 0 || string.Equals(segment, ".", StringComparison.Ordinal))
            {
                continue;
            }

            if (string.Equals(segment, "..", StringComparison.Ordinal))
            {
                return null;
            }

            segments.Add(segment);
        }

        return segments.Count == 0 ? null : string.Join('/', segments);
    }

    internal static HashSet<string> MapChangedPathsToTests(IEnumerable<string> changedPaths)
    {
        ArgumentNullException.ThrowIfNull(changedPaths);
        var affected = new HashSet<string>(StringComparer.Ordinal);
        var normalizedFiles = new HashSet<string>(StringComparer.Ordinal);
        foreach (string changedPath in changedPaths)
        {
            string? normalized = NormalizeChangedPath(changedPath);
            if (normalized is null)
            {
                affected.Add("ALL_SMOKE");
                affected.Add("ALL_COMPREHENSIVE");
                continue;
            }

            normalizedFiles.Add(normalized);
        }

        foreach (string file in normalizedFiles)
        {
            bool matched = false;
            if (file.Contains("V12MasterKdf") || file.Contains("KdfPrimitives") || file.Contains("KdfSalts") || file.Contains("SuiteKeySchedule") || file.Contains("PasswordKeyService") || file.Contains("ContainerKeyDerivation") || file.Contains("SecureMemory"))
            {
                matched = true;
                if (file.Contains("SecureMemory", StringComparison.Ordinal))
                {
                    affected.Add("security.secure-memory-unlock-accounting");
                }
                affected.Add("crypto.kdf-primitives");
                affected.Add("kdf.properties");
                affected.Add("kdf.v12-master-factor-split");
                affected.Add("kdf.argon2-equivalence");
                affected.Add("kdf.peak-memory-and-header");
                affected.Add("policy.password");
                affected.Add("policy.pin-creation");
                affected.Add("ALL_CONTAINER_SUITES");
                affected.Add("containers.v12-kpar2-roundtrip");
                affected.Add("containers.v12-production-worker-equivalence");
            }
            if (file.Contains("KalynaContainerService") || file.Contains("ParallelContainerAuthenticator"))
            {
                matched = true;
                affected.Add("crypto.v12-parallel-mac-kat");
                affected.Add("ALL_CONTAINER_SUITES");
                affected.Add("containers.v12-kpar2-roundtrip");
                affected.Add("containers.v12-production-worker-equivalence");
                affected.Add("performance.cipher-suites");
            }
            if (file.Contains("ZpaqService") || file.Contains("BoundFileTransaction") || file.Contains("MacPlatformSecurity") || file.Contains("MacSecureFile") || file.Contains("MacOriginalDeletionService"))
            {
                matched = true;
                affected.Add("zpaq.full-matrix");
                affected.Add("zpaq.process-resource-limits");
                affected.Add("zpaq.fail-fast-error-preservation");
                affected.Add("zpaq.three-file-commit-binding");
                affected.Add("containers.v12-kpar2-roundtrip");
                affected.Add("deletion.original-verification");
                affected.Add("deletion.cryptographic-erase");
                affected.Add("smoke.descriptor-identity");
                affected.Add("smoke.symlink-rejection");
                affected.Add("smoke.archive-input-symlink");
                affected.Add("smoke.archive-input-snapshot-location");
                affected.Add("smoke.overlapping-input-normalization");
                affected.Add("smoke.descriptor-bound-snapshot");
                affected.Add("smoke.private-snapshot-cleanup-identity");
                affected.Add("smoke.private-snapshot-race-failclosed");
                affected.Add("smoke.private-snapshot-resource-failures");
                affected.Add("smoke.private-authenticated-snapshot");
            }
            if (file.Contains("MacPrivateFileSnapshot", StringComparison.OrdinalIgnoreCase)
                || file.Contains("NativeCascadeCiphers", StringComparison.OrdinalIgnoreCase)
                || file.Contains("chachapoly_ref_export", StringComparison.OrdinalIgnoreCase))
            {
                matched = true;
                affected.Add("smoke.descriptor-bound-snapshot");
                affected.Add("smoke.private-snapshot-cleanup-identity");
                affected.Add("smoke.private-snapshot-race-failclosed");
                affected.Add("smoke.private-snapshot-resource-failures");
                affected.Add("smoke.private-authenticated-snapshot");
            }
            if (file.Contains("RecoveryService") || file.Contains("Kpar2") || file.Contains("ParallelRecoveryTests"))
            {
                matched = true;
                affected.Add("recovery.kpar2-v4-adversarial");
                affected.Add("recovery.parallel-worker-equivalence");
                affected.Add("recovery.physical-eio-repair");
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
                affected.Add("spec.normative-v12-docs");
                affected.Add("spec.no-legacy-source");
            }
            if (file.Contains("QrCodeScanner") || file.Contains("QR-Scanner") || file.Contains("Verify-QR-Scanner"))
            {
                matched = true;
                affected.Add("packaging.companion-qr");
                affected.Add("smoke.release-companion-version");
            }
            if (file.Contains("Packaging") || file.Contains("HybridSigner") || file.Contains("Protect-HybridKeys") || file.Contains("Integrity"))
            {
                matched = true;
                affected.Add("packaging.keychain-secret-not-in-argv");
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
                affected.Add("crypto.aes-ctr-differential");
                affected.Add("crypto.v12-parallel-mac-kat");
                affected.Add("containers.v12-production-worker-equivalence");
            }

            foreach (string impactedTest in GetPerformanceSensitiveImpact(file))
            {
                affected.Add(impactedTest);
            }

            if (IsSourceOrBuildFile(file))
            {
                affected.Add("spec.no-legacy-source");
                affected.Add("spec.normative-v12-docs");
            }

            if (!matched && !IsBenignFile(file))
            {
                affected.Add("ALL_SMOKE");
                affected.Add("ALL_COMPREHENSIVE");
            }
        }

        return affected;
    }

    private static bool IsBenignFile(string file)
    {
        string normalized = file.Replace('\\', '/');

        // Licensing and repository metadata. README and docs/ are deliberately
        // absent: they state the normative security architecture, and a README
        // that contradicts the code is how a later reader "fixes" the working
        // side. They select the spec-consistency gate instead, which is fast.
        if (string.Equals(normalized, "LICENSE", StringComparison.Ordinal) ||
            string.Equals(normalized, "LICENSE.txt", StringComparison.Ordinal) ||
            string.Equals(normalized, "NOTICE", StringComparison.Ordinal) ||
            string.Equals(normalized, "NOTICE.txt", StringComparison.Ordinal) ||
            string.Equals(normalized, ".gitignore", StringComparison.Ordinal) ||
            string.Equals(normalized, ".gitattributes", StringComparison.Ordinal) ||
            string.Equals(normalized, ".editorconfig", StringComparison.Ordinal))
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
        string extension = Path.GetExtension(normalized);
        if (normalized.Contains("external/cryptopp/", StringComparison.OrdinalIgnoreCase)
            && (extension.Equals(".cpp", StringComparison.OrdinalIgnoreCase)
                || extension.Equals(".h", StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        string[] sensitiveNames =
        [
            "kalyna_v12_export.cpp",
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

    internal static IReadOnlySet<string> GetPerformanceSensitiveImpact(string file)
    {
        if (!IsPerformanceSensitiveFile(file))
        {
            return new HashSet<string>(StringComparer.Ordinal);
        }

        return new HashSet<string>(StringComparer.Ordinal)
        {
            "performance.cipher-suites",
            "trust.native-tools",
            "crypto.primitive-vectors",
            "crypto.cascade-layering",
            "crypto.mars-shacal-vectors",
            "crypto.reference-differential",
            "crypto.kalyna-fast-path-differential",
            "crypto.chacha20-fast-path-differential",
            "crypto.chacha20-poly1305-rfc8439",
            "crypto.aes-ctr-differential",
            "crypto.v12-parallel-mac-kat",
            "containers.v12-production-worker-equivalence",
        };
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
