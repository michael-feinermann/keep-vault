using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

/// <summary>
/// What a test needs exclusively, independent of what it costs.
/// </summary>
/// <remarks>
/// A single resource category cannot describe these tests. A container test
/// consumes the shared entropy state <em>and</em> a full-cost Argon2id matrix;
/// under one enum it had to be filed as one or the other, and everything in the
/// same file ran strictly one after another. Splitting the exclusivity from the
/// cost lets the scheduler run an entropy test beside an Argon test when the
/// budget allows it, and still keep two Argon matrices from becoming three.
///
/// The macOS suite carries the same split; this is its Windows counterpart.
/// </remarks>
[Flags]
internal enum TestConstraint
{
    None = 0,

    /// <summary>Modifies or measures process-wide state; needs its own process.</summary>
    ProcessExclusive = 1 << 0,

    /// <summary>Consumes the shared entropy mixer state.</summary>
    EntropyState = 1 << 1,

    /// <summary>Starts ZPAQ child processes and writes large staging trees.</summary>
    ZpaqProcess = 1 << 2,

    /// <summary>Drives WPF on a single-threaded apartment.</summary>
    Gui = 1 << 3,

    /// <summary>Measures host-wide behaviour; nothing else may run at the same time.</summary>
    HostExclusive = 1 << 4,
}

internal enum TestResource
{
    /// <summary>Thread-safe, low RAM/CPU: pure KATs, policies, source lints.</summary>
    Light,

    /// <summary>Thread-safe but CPU-intensive: ML-DSA, differential testing.</summary>
    CpuHeavy,

    /// <summary>Modifies or measures process-wide state: hardening, locked pages.</summary>
    ProcessGlobal,

    /// <summary>1-2 GiB matrices, Argon2id equivalence.</summary>
    ArgonHeavy,

    /// <summary>Peak memory measurement; nothing else may run beside it.</summary>
    ArgonPeakMemory,

    /// <summary>Consumes the shared EntropyMixer state.</summary>
    EntropyGlobal,

    /// <summary>ZPAQ child processes and large staging trees.</summary>
    ZpaqGlobal,

    /// <summary>Drives the WPF window on an STA thread.</summary>
    Gui,
}

/// <summary>
/// What a test costs the machine, and what it needs to itself.
/// </summary>
internal sealed record TestCost(int CpuTokens, int MemoryMiB, bool UsesArgon, TestConstraint Constraints)
{
    /// <remarks>
    /// The reservations are deliberately static minimums rather than measured
    /// values: a full-cost v11 Argon2id call can allocate just under 2 GiB, and
    /// a scheduler that trusted a small historical measurement would happily
    /// start three of them.
    /// </remarks>
    public static TestCost FromResource(TestResource resource) => resource switch
    {
        TestResource.Light => new TestCost(1, 256, false, TestConstraint.None),
        TestResource.CpuHeavy => new TestCost(2, 512, false, TestConstraint.None),
        TestResource.ProcessGlobal => new TestCost(1, 512, false, TestConstraint.ProcessExclusive),
        TestResource.ArgonHeavy => new TestCost(4, 2560, true, TestConstraint.None),
        TestResource.ArgonPeakMemory => new TestCost(4, 2560, true, TestConstraint.HostExclusive),
        TestResource.EntropyGlobal => new TestCost(4, 2560, true, TestConstraint.EntropyState),
        TestResource.ZpaqGlobal => new TestCost(2, 1024, false, TestConstraint.ZpaqProcess),
        TestResource.Gui => new TestCost(1, 1024, false, TestConstraint.Gui),
        _ => new TestCost(1, 256, false, TestConstraint.None),
    };
}

internal enum TestStatus
{
    Pass,
    Fail,
    Blocked,
}

internal sealed record TestOutcome(
    string Id,
    string Name,
    TestStatus Status,
    double Seconds,
    int PeakRssMiB,
    uint Seed,
    string? Failure)
{
    /// <summary>Whatever the test printed for a reader, verbatim.</summary>
    public string? Output { get; init; }
}

internal sealed record TestCase(
    string Name,
    Func<Task> Run,
    TestResource Resource,
    string Category = "General",
    bool IsSmoke = false)
{
    /// <summary>
    /// A stable identifier a worker process can be told to run.
    /// </summary>
    /// <remarks>
    /// Derived from the category and the name rather than stored separately, so
    /// a new test cannot be registered without one and two tests cannot quietly
    /// share it. Renaming a test changes its id, which is correct: the rerun
    /// list and the historical timings are about that test, not about a slot.
    /// </remarks>
    public string Id { get; } = BuildId(Category, Name);

    public TestCost Cost { get; init; } = TestCost.FromResource(Resource);

    private static string BuildId(string category, string name)
    {
        var builder = new StringBuilder(category.Length + name.Length + 1);
        AppendSlug(builder, category);
        builder.Append('.');
        AppendSlug(builder, name);
        return builder.ToString();
    }

    private static void AppendSlug(StringBuilder builder, string value)
    {
        bool separatorPending = false;
        foreach (char c in value)
        {
            if (char.IsLetterOrDigit(c))
            {
                if (separatorPending && builder.Length > 0)
                {
                    builder.Append('-');
                }

                builder.Append(char.ToLowerInvariant(c));
                separatorPending = false;
            }
            else
            {
                separatorPending = true;
            }
        }
    }
}

/// <summary>
/// The CPU and memory the coordinator is allowed to spend, read from the
/// machine rather than assumed.
/// </summary>
internal sealed record HardwareBudget(
    int CpuCount,
    long TotalRamBytes,
    int CpuTokens,
    int MemoryMiB,
    int ArgonSlots,
    int ZpaqSlots)
{
    public static HardwareBudget Detect()
    {
        int cpuCount = Environment.ProcessorCount;
        long totalRam = ReadInstalledMemoryBytes() ?? 8L * 1024 * 1024 * 1024;

        // One core stays with Windows and the coordinator itself.
        int cpuTokens = Math.Max(1, cpuCount - 1);

        // Roughly 55 percent of physical memory, capped at 9 GiB. The rest is
        // left to the kernel, the file cache and the .NET hosts; deliberately
        // driving a 16 GiB machine into the page file makes the run slower, not
        // faster.
        long budgetBytes = (long)(totalRam * 0.55);
        int memoryMiB = (int)Math.Clamp(budgetBytes / (1024 * 1024), 2048, 9216);

        // Each full-cost Argon2id call can hold just under 2 GiB and uses p=4.
        // Two of them plus overhead fit comfortably on 16 GiB; three do not.
        int argonSlots = memoryMiB >= 5120 && cpuTokens >= 8 ? 2 : 1;

        int zpaqSlots = 1;
        return new HardwareBudget(cpuCount, totalRam, cpuTokens, memoryMiB, argonSlots, zpaqSlots);
    }

    /// <remarks>
    /// GlobalMemoryStatusEx rather than a managed API: what the budget needs is
    /// the memory physically installed, not what this process has been given or
    /// what the GC believes is available.
    /// </remarks>
    private static long? ReadInstalledMemoryBytes()
    {
        try
        {
            var status = new MemoryStatusEx { Length = (uint)Marshal.SizeOf<MemoryStatusEx>() };
            if (GlobalMemoryStatusEx(ref status) && status.TotalPhys > 0)
            {
                return (long)status.TotalPhys;
            }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
        }

        return null;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryStatusEx
    {
        internal uint Length;
        internal uint MemoryLoad;
        internal ulong TotalPhys;
        internal ulong AvailPhys;
        internal ulong TotalPageFile;
        internal ulong AvailPageFile;
        internal ulong TotalVirtual;
        internal ulong AvailVirtual;
        internal ulong AvailExtendedVirtual;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MemoryStatusEx buffer);
}

/// <summary>
/// Runs the comprehensive suite across child processes under a CPU and memory
/// budget, collecting every failure instead of stopping at the first.
/// </summary>
/// <remarks>
/// Two things make child processes the right unit here. The native Argon2id
/// adapter serialises on a process-wide mutex, so two Argon tests in threads of
/// one process never actually run at the same time no matter how many workers
/// the scheduler thinks it has. And several tests read or write process-global
/// state - the entropy mixer, locked-page accounting, process hardening - which
/// in one process forces them into a single serial chain and, worse, lets them
/// mask each other's defects.
/// </remarks>
internal static class TestCoordinator
{
    private static readonly object ConsoleLock = new();

    internal const string WorkerResultMarker = "##KVTEST ";

    internal static async Task<IReadOnlyList<TestOutcome>> RunAsync(
        IReadOnlyList<TestCase> tests,
        HardwareBudget budget,
        Dictionary<string, double> cachedTimings,
        uint? seedOverride,
        bool failFast,
        bool inProcess,
        CancellationToken cancellationToken)
    {
        var outcomes = new List<TestOutcome>();

        // Longest first. With static reservations the schedule is only as good
        // as its order, and the long pole finishing last is what decides the
        // wall clock.
        var pending = tests
            .OrderByDescending(t => cachedTimings.GetValueOrDefault(t.Name, 0.0))
            .ToList();

        int freeCpu = budget.CpuTokens;
        int freeMemory = budget.MemoryMiB;
        int freeArgon = budget.ArgonSlots;
        int freeZpaq = budget.ZpaqSlots;
        int freeGui = 1;
        int freeEntropy = 1;
        bool hostExclusiveRunning = false;
        bool processExclusiveRunning = false;
        bool argonFallbackUsed = false;

        // Process isolation is what makes process-local global state safe to
        // run in parallel: a child process has its own entropy mixer, its own
        // locked-page accounting and its own hardening. Without it those
        // constraints have to serialise instead, or tests silently corrupt each
        // other's measurements.
        bool isolatesProcessState = !inProcess;

        var running = new List<(Task<TestOutcome> Task, TestCase Test)>();
        bool stopStarting = false;

        while (pending.Count > 0 || running.Count > 0)
        {
            bool started = false;
            if (!stopStarting)
            {
                for (int index = 0; index < pending.Count; index++)
                {
                    TestCase candidate = pending[index];
                    TestCost cost = candidate.Cost;

                    // A test that needs the whole host waits for an empty machine.
                    if (cost.Constraints.HasFlag(TestConstraint.HostExclusive))
                    {
                        if (running.Count > 0 || index != 0)
                        {
                            continue;
                        }
                    }
                    else if (hostExclusiveRunning)
                    {
                        continue;
                    }

                    if (cost.CpuTokens > freeCpu || cost.MemoryMiB > freeMemory)
                    {
                        continue;
                    }

                    if (cost.UsesArgon && freeArgon <= 0)
                    {
                        continue;
                    }

                    if (cost.Constraints.HasFlag(TestConstraint.ZpaqProcess) && freeZpaq <= 0)
                    {
                        continue;
                    }

                    if (cost.Constraints.HasFlag(TestConstraint.Gui) && freeGui <= 0)
                    {
                        continue;
                    }

                    if (!isolatesProcessState)
                    {
                        if (cost.Constraints.HasFlag(TestConstraint.ProcessExclusive) && running.Count > 0)
                        {
                            continue;
                        }

                        if (processExclusiveRunning)
                        {
                            continue;
                        }

                        if (cost.Constraints.HasFlag(TestConstraint.EntropyState) && freeEntropy <= 0)
                        {
                            continue;
                        }
                    }

                    pending.RemoveAt(index);
                    freeCpu -= cost.CpuTokens;
                    freeMemory -= cost.MemoryMiB;
                    if (cost.UsesArgon) freeArgon--;
                    if (cost.Constraints.HasFlag(TestConstraint.ZpaqProcess)) freeZpaq--;
                    if (cost.Constraints.HasFlag(TestConstraint.Gui)) freeGui--;
                    if (cost.Constraints.HasFlag(TestConstraint.HostExclusive)) hostExclusiveRunning = true;
                    if (!isolatesProcessState)
                    {
                        if (cost.Constraints.HasFlag(TestConstraint.ProcessExclusive)) processExclusiveRunning = true;
                        if (cost.Constraints.HasFlag(TestConstraint.EntropyState)) freeEntropy--;
                    }

                    uint seed = seedOverride ?? NextSeed();
                    Task<TestOutcome> task = inProcess
                        ? RunInProcessAsync(candidate, seed)
                        : RunWorkerAsync(candidate, seed, cancellationToken);
                    running.Add((task, candidate));
                    started = true;
                    break;
                }
            }

            if (running.Count == 0)
            {
                if (pending.Count == 0)
                {
                    break;
                }

                if (stopStarting)
                {
                    foreach (TestCase skipped in pending)
                    {
                        outcomes.Add(new TestOutcome(skipped.Id, skipped.Name, TestStatus.Blocked, 0, 0, 0, "not run: --fail-fast stopped the run"));
                    }

                    pending.Clear();
                    break;
                }

                if (!started)
                {
                    // Nothing fits an empty machine: the static reservation is
                    // larger than the whole budget. Run it alone rather than
                    // deadlocking or quietly skipping it.
                    TestCase oversized = pending[0];
                    pending.RemoveAt(0);
                    argonFallbackUsed = true;
                    uint seed = seedOverride ?? NextSeed();
                    running.Add((inProcess ? RunInProcessAsync(oversized, seed) : RunWorkerAsync(oversized, seed, cancellationToken), oversized));
                }

                continue;
            }

            if (started && running.Count < budget.CpuTokens)
            {
                continue;
            }

            Task<TestOutcome> completed = await Task.WhenAny(running.Select(r => r.Task)).ConfigureAwait(false);
            int completedIndex = running.FindIndex(r => r.Task == completed);
            TestCase finishedTest = running[completedIndex].Test;
            running.RemoveAt(completedIndex);

            TestCost finishedCost = finishedTest.Cost;
            freeCpu += finishedCost.CpuTokens;
            freeMemory += finishedCost.MemoryMiB;
            if (finishedCost.UsesArgon) freeArgon++;
            if (finishedCost.Constraints.HasFlag(TestConstraint.ZpaqProcess)) freeZpaq++;
            if (finishedCost.Constraints.HasFlag(TestConstraint.Gui)) freeGui++;
            if (finishedCost.Constraints.HasFlag(TestConstraint.HostExclusive)) hostExclusiveRunning = false;
            if (!isolatesProcessState)
            {
                if (finishedCost.Constraints.HasFlag(TestConstraint.ProcessExclusive)) processExclusiveRunning = false;
                if (finishedCost.Constraints.HasFlag(TestConstraint.EntropyState)) freeEntropy++;
            }

            TestOutcome outcome = await completed.ConfigureAwait(false);
            outcomes.Add(outcome);
            Report(outcome);

            if (outcome.Status == TestStatus.Fail && failFast)
            {
                stopStarting = true;
            }
        }

        if (argonFallbackUsed)
        {
            Console.WriteLine("scheduler: a test reserved more than the whole budget and was run alone at full cost.");
        }

        return outcomes;
    }

    private static uint NextSeed() =>
        checked((uint)System.Security.Cryptography.RandomNumberGenerator.GetInt32(1, int.MaxValue));

    private static void Report(TestOutcome outcome)
    {
        lock (ConsoleLock)
        {
            if (outcome.Status == TestStatus.Pass)
            {
                Console.WriteLine($"PASS {outcome.Name} ({outcome.Seconds:F1}s)");
                if (!string.IsNullOrEmpty(outcome.Output))
                {
                    Console.WriteLine(outcome.Output);
                }

                return;
            }

            Console.WriteLine();
            Console.WriteLine($"FAIL {outcome.Name}");
            Console.WriteLine($"  seed=0x{outcome.Seed:X8}");
            Console.WriteLine($"  {outcome.Failure}");
            Console.WriteLine();
            Console.WriteLine("Re-run:");
            Console.WriteLine($"  dotnet run --no-build --no-restore --project KalynaArchiver.Tests -c Release -- --full --no-smoke --only \"{outcome.Name}\" --seed 0x{outcome.Seed:X8}");
            Console.WriteLine();
        }
    }

    private static async Task<TestOutcome> RunInProcessAsync(TestCase test, uint seed)
    {
        TestState.Seed = seed;
        Stopwatch stopwatch = Stopwatch.StartNew();
        try
        {
            await test.Run().ConfigureAwait(false);
            stopwatch.Stop();
            return new TestOutcome(test.Id, test.Name, TestStatus.Pass, stopwatch.Elapsed.TotalSeconds, 0, seed, null);
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            return new TestOutcome(test.Id, test.Name, TestStatus.Fail, stopwatch.Elapsed.TotalSeconds, 0, seed, Describe(ex));
        }
    }

    private static async Task<TestOutcome> RunWorkerAsync(TestCase test, uint seed, CancellationToken cancellationToken)
    {
        (string fileName, List<string> arguments) = BuildWorkerCommand();
        arguments.Add("--worker");
        arguments.Add("--test-id");
        arguments.Add(test.Id);
        arguments.Add("--seed");
        arguments.Add($"0x{seed:X8}");

        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            WorkingDirectory = Environment.CurrentDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (string argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        Stopwatch stopwatch = Stopwatch.StartNew();
        using Process process = Process.Start(startInfo)
            ?? throw new InvalidOperationException($"Could not start a test worker for {test.Id}.");

        Task<string> stdout = process.StandardOutput.ReadToEndAsync(cancellationToken);
        Task<string> stderr = process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        string output = await stdout.ConfigureAwait(false);
        string errors = await stderr.ConfigureAwait(false);
        stopwatch.Stop();

        string[] outputLines = output.Split('\n');
        string? marker = outputLines
            .LastOrDefault(line => line.StartsWith(WorkerResultMarker, StringComparison.Ordinal));

        if (marker is not null)
        {
            try
            {
                JsonNode? node = JsonNode.Parse(marker[WorkerResultMarker.Length..]);
                if (node is not null)
                {
                    string status = node["status"]?.GetValue<string>() ?? "FAIL";

                    // Anything the test itself printed. Several of them report
                    // measurements the assertions deliberately do not make -
                    // the throughput each fast path reached, the sample file
                    // that was used - and moving the run into workers would
                    // otherwise have thrown all of that away, leaving a suite
                    // that says a fast path is correct but no longer whether it
                    // is fast.
                    string chatter = string.Join(
                        Environment.NewLine,
                        outputLines
                            .Select(line => line.TrimEnd('\r'))
                            .Where(line => line.Length > 0 && !line.StartsWith(WorkerResultMarker, StringComparison.Ordinal)));

                    return new TestOutcome(
                        test.Id,
                        test.Name,
                        status == "PASS" ? TestStatus.Pass : TestStatus.Fail,
                        node["seconds"]?.GetValue<double>() ?? stopwatch.Elapsed.TotalSeconds,
                        node["peakRssMiB"]?.GetValue<int>() ?? 0,
                        seed,
                        node["failure"]?.GetValue<string>())
                    {
                        Output = chatter,
                    };
                }
            }
            catch (JsonException)
            {
            }
        }

        // No structured result: the worker died before it could report. That is
        // a failure of this test, not of the run, and the captured output is
        // the only evidence there is.
        string detail = string.Join(
            Environment.NewLine,
            new[] { $"worker exited with code {process.ExitCode} and reported no result", errors.Trim(), output.Trim() }
                .Where(part => !string.IsNullOrWhiteSpace(part)));
        return new TestOutcome(test.Id, test.Name, TestStatus.Fail, stopwatch.Elapsed.TotalSeconds, 0, seed, detail);
    }

    private static (string FileName, List<string> Arguments) BuildWorkerCommand()
    {
        string? host = Environment.ProcessPath;
        string assembly = Assembly.GetEntryAssembly()?.Location
            ?? throw new InvalidOperationException("The test assembly location is unknown.");

        if (!string.IsNullOrEmpty(host)
            && string.Equals(Path.GetFileNameWithoutExtension(host), "dotnet", StringComparison.OrdinalIgnoreCase))
        {
            return (host, ["exec", assembly]);
        }

        if (!string.IsNullOrEmpty(host))
        {
            return (host, []);
        }

        return ("dotnet", ["exec", assembly]);
    }

    /// <summary>
    /// Runs exactly one test and prints a machine-readable result line.
    /// </summary>
    internal static async Task<int> RunWorkerModeAsync(IReadOnlyList<TestCase> allTests, string testId, uint seed)
    {
        TestCase? test = allTests.FirstOrDefault(t => string.Equals(t.Id, testId, StringComparison.Ordinal));
        if (test is null)
        {
            Console.Out.WriteLine(WorkerResultMarker + JsonSerializer.Serialize(new
            {
                id = testId,
                status = "FAIL",
                seconds = 0.0,
                peakRssMiB = 0,
                failure = $"unknown test id: {testId}",
            }));
            return 1;
        }

        TestState.Seed = seed;

        Stopwatch stopwatch = Stopwatch.StartNew();
        string? failure = null;
        try
        {
            await test.Run().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            failure = Describe(ex);
        }

        stopwatch.Stop();
        int peakRssMiB = 0;
        try
        {
            using Process self = Process.GetCurrentProcess();
            self.Refresh();
            peakRssMiB = (int)(self.PeakWorkingSet64 / (1024 * 1024));
        }
        catch (SystemException)
        {
        }

        Console.Out.WriteLine(WorkerResultMarker + JsonSerializer.Serialize(new
        {
            id = test.Id,
            status = failure is null ? "PASS" : "FAIL",
            seconds = stopwatch.Elapsed.TotalSeconds,
            peakRssMiB,
            failure,
        }));
        return failure is null ? 0 : 1;
    }

    private static string Describe(Exception ex)
    {
        var builder = new StringBuilder();
        builder.Append(ex.GetType().Name).Append(": ").Append(ex.Message);
        if (ex.InnerException is not null)
        {
            builder.AppendLine().Append("  Inner: ").Append(ex.InnerException.Message);
        }

        if (!string.IsNullOrEmpty(ex.StackTrace))
        {
            builder.AppendLine().Append(ex.StackTrace);
        }

        return builder.ToString();
    }

    /// <summary>
    /// Writes the run result beside the test binary. No credential value ever
    /// reaches this file: only ids, statuses, timings and seeds.
    /// </summary>
    internal static void WriteResults(string path, IReadOnlyList<TestOutcome> outcomes, HardwareBudget budget)
    {
        try
        {
            var document = new
            {
                head = ReadHead(),
                hardware = $"{budget.CpuCount} logical CPUs, {budget.TotalRamBytes / (1024 * 1024 * 1024)} GiB, "
                    + $"{RuntimeInformation.OSDescription}",
                budget = new
                {
                    cpuTokens = budget.CpuTokens,
                    memoryMiB = budget.MemoryMiB,
                    argonSlots = budget.ArgonSlots,
                    zpaqSlots = budget.ZpaqSlots,
                },
                tests = outcomes.Select(o => new
                {
                    id = o.Id,
                    name = o.Name,
                    status = o.Status.ToString().ToUpperInvariant(),
                    seconds = Math.Round(o.Seconds, 3),
                    peakRssMiB = o.PeakRssMiB,
                    seed = $"0x{o.Seed:X8}",
                    failure = o.Failure,
                }).ToArray(),
            };

            File.WriteAllText(path, JsonSerializer.Serialize(document, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (IOException)
        {
        }
    }

    internal static IReadOnlyList<string> ReadFailedIds(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return [];
            }

            JsonNode? document = JsonNode.Parse(File.ReadAllText(path));
            if (document?["tests"] is not JsonArray tests)
            {
                return [];
            }

            var failed = new List<string>();
            foreach (JsonNode? entry in tests)
            {
                string? status = entry?["status"]?.GetValue<string>();
                string? id = entry?["id"]?.GetValue<string>();
                if (id is not null && status is not null && !string.Equals(status, "PASS", StringComparison.Ordinal))
                {
                    failed.Add(id);
                }
            }

            return failed;
        }
        catch (Exception ex) when (ex is IOException or JsonException)
        {
            return [];
        }
    }

    private static string ReadHead()
    {
        try
        {
            using Process? process = Process.Start(new ProcessStartInfo
            {
                FileName = "git",
                ArgumentList = { "rev-parse", "HEAD" },
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            if (process is null)
            {
                return "unknown";
            }

            string head = process.StandardOutput.ReadToEnd().Trim();
            process.WaitForExit();
            return process.ExitCode == 0 && head.Length > 0 ? head : "unknown";
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            return "unknown";
        }
    }
}

/// <summary>
/// Per-run state a worker inherits from the coordinator.
/// </summary>
/// <remarks>
/// The seed is reported with every failure and accepted back through --seed, so
/// a randomised test that failed once can be made to fail again.
/// </remarks>
internal static class TestState
{
    public static uint Seed { get; set; } = 1u;
}
