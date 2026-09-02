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
    /// values: a full-cost v12 Argon2id call can allocate just under 2 GiB, and
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

/// <summary>
/// Validates and fingerprints the test inventory used by workers, reruns and
/// timing history. The id is deliberately a literal supplied at registration:
/// display text may change without invalidating historical results.
/// </summary>
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
        var canonical = new StringBuilder();
        foreach (TestCase test in tests.OrderBy(test => test.Id, StringComparer.Ordinal))
        {
            canonical.Append(test.Id).Append('\n');
        }

        return Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(canonical.ToString())))
            .ToLowerInvariant();
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
/// The exact resources deducted for one running test. Release consumes this
/// token; it never reconstructs a reservation from the test's declared cost.
/// </summary>
internal sealed class ReservationToken
{
    internal ReservationToken(
        int cpuTokens,
        int memoryMiB,
        int argonSlots,
        int zpaqSlots,
        int guiSlots,
        int entropySlots,
        bool hostExclusive,
        bool processExclusive,
        bool oversized)
    {
        CpuTokens = cpuTokens;
        MemoryMiB = memoryMiB;
        ArgonSlots = argonSlots;
        ZpaqSlots = zpaqSlots;
        GuiSlots = guiSlots;
        EntropySlots = entropySlots;
        HostExclusive = hostExclusive;
        ProcessExclusive = processExclusive;
        Oversized = oversized;
    }

    internal int CpuTokens { get; }
    internal int MemoryMiB { get; }
    internal int ArgonSlots { get; }
    internal int ZpaqSlots { get; }
    internal int GuiSlots { get; }
    internal int EntropySlots { get; }
    internal bool HostExclusive { get; }
    internal bool ProcessExclusive { get; }
    internal bool Oversized { get; }
    internal bool Released { get; set; }
}

/// <summary>
/// Owns all scheduler counters and enforces their bounds after every mutation.
/// </summary>
internal sealed class SchedulerResourceLedger
{
    private readonly HardwareBudget _budget;
    private readonly int _maxWorkers;
    private readonly bool _isolatesProcessState;
    private int _freeCpu;
    private int _freeMemory;
    private int _freeArgon;
    private int _freeZpaq;
    private int _freeGui = 1;
    private int _freeEntropy = 1;
    private bool _hostExclusiveRunning;
    private bool _processExclusiveRunning;

    internal SchedulerResourceLedger(HardwareBudget budget, int maxWorkers, bool isolatesProcessState)
    {
        if (budget.CpuTokens < 1 || budget.MemoryMiB < 1 || budget.ArgonSlots < 1 || budget.ZpaqSlots < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(budget), "Every schedulable budget dimension must be positive.");
        }

        if (maxWorkers < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(maxWorkers));
        }

        _budget = budget;
        _maxWorkers = maxWorkers;
        _isolatesProcessState = isolatesProcessState;
        _freeCpu = budget.CpuTokens;
        _freeMemory = budget.MemoryMiB;
        _freeArgon = budget.ArgonSlots;
        _freeZpaq = budget.ZpaqSlots;
        AssertInvariants();
    }

    internal int RunningWorkers { get; private set; }
    internal bool CanStartAnother => RunningWorkers < _maxWorkers && !_hostExclusiveRunning;
    internal int FreeCpu => _freeCpu;
    internal int FreeMemory => _freeMemory;

    internal bool TryReserve(TestCase test, out ReservationToken? reservation)
    {
        reservation = null;
        TestCost cost = test.Cost;
        if (RunningWorkers >= _maxWorkers)
        {
            return false;
        }

        bool hostExclusive = cost.Constraints.HasFlag(TestConstraint.HostExclusive);
        if ((hostExclusive && RunningWorkers > 0) || (!hostExclusive && _hostExclusiveRunning))
        {
            return false;
        }

        if (cost.CpuTokens > _freeCpu || cost.MemoryMiB > _freeMemory)
        {
            return false;
        }

        int argonSlots = cost.UsesArgon ? 1 : 0;
        int zpaqSlots = cost.Constraints.HasFlag(TestConstraint.ZpaqProcess) ? 1 : 0;
        int guiSlots = cost.Constraints.HasFlag(TestConstraint.Gui) ? 1 : 0;
        int entropySlots = !_isolatesProcessState && cost.Constraints.HasFlag(TestConstraint.EntropyState) ? 1 : 0;
        bool processExclusive = !_isolatesProcessState && cost.Constraints.HasFlag(TestConstraint.ProcessExclusive);

        if (argonSlots > _freeArgon || zpaqSlots > _freeZpaq || guiSlots > _freeGui || entropySlots > _freeEntropy)
        {
            return false;
        }

        if (!_isolatesProcessState
            && ((processExclusive && RunningWorkers > 0) || (!processExclusive && _processExclusiveRunning)))
        {
            return false;
        }

        reservation = new ReservationToken(
            cost.CpuTokens,
            cost.MemoryMiB,
            argonSlots,
            zpaqSlots,
            guiSlots,
            entropySlots,
            hostExclusive,
            processExclusive,
            oversized: false);
        Apply(reservation);
        return true;
    }

    /// <summary>
    /// Reserves the entire schedulable host for a test whose declared static
    /// cost is larger than the detected budget. The token records exactly the
    /// counters deducted, so completion cannot over-release them.
    /// </summary>
    internal ReservationToken ReserveOversizedExclusive(TestCase test)
    {
        if (RunningWorkers != 0)
        {
            throw new InvalidOperationException("An oversized test can start only on an empty scheduler.");
        }

        TestCost cost = test.Cost;
        if (cost.CpuTokens <= _budget.CpuTokens && cost.MemoryMiB <= _budget.MemoryMiB)
        {
            throw new InvalidOperationException($"Test '{test.Id}' fits the CPU/memory budget and is not oversized.");
        }

        int argonSlots = cost.UsesArgon ? 1 : 0;
        int zpaqSlots = cost.Constraints.HasFlag(TestConstraint.ZpaqProcess) ? 1 : 0;
        int guiSlots = cost.Constraints.HasFlag(TestConstraint.Gui) ? 1 : 0;
        int entropySlots = !_isolatesProcessState && cost.Constraints.HasFlag(TestConstraint.EntropyState) ? 1 : 0;
        bool processExclusive = !_isolatesProcessState && cost.Constraints.HasFlag(TestConstraint.ProcessExclusive);
        if (argonSlots > _freeArgon || zpaqSlots > _freeZpaq || guiSlots > _freeGui || entropySlots > _freeEntropy)
        {
            throw new InvalidOperationException($"Test '{test.Id}' requests an unavailable exclusive scheduler slot.");
        }

        var reservation = new ReservationToken(
            _budget.CpuTokens,
            _budget.MemoryMiB,
            argonSlots,
            zpaqSlots,
            guiSlots,
            entropySlots,
            hostExclusive: true,
            processExclusive,
            oversized: true);
        Apply(reservation);
        return reservation;
    }

    internal void Release(ReservationToken reservation)
    {
        if (reservation.Released)
        {
            throw new InvalidOperationException("A scheduler reservation was released twice.");
        }

        reservation.Released = true;
        _freeCpu += reservation.CpuTokens;
        _freeMemory += reservation.MemoryMiB;
        _freeArgon += reservation.ArgonSlots;
        _freeZpaq += reservation.ZpaqSlots;
        _freeGui += reservation.GuiSlots;
        _freeEntropy += reservation.EntropySlots;
        if (reservation.HostExclusive)
        {
            _hostExclusiveRunning = false;
        }

        if (reservation.ProcessExclusive)
        {
            _processExclusiveRunning = false;
        }

        RunningWorkers--;
        AssertInvariants();
    }

    private void Apply(ReservationToken reservation)
    {
        _freeCpu -= reservation.CpuTokens;
        _freeMemory -= reservation.MemoryMiB;
        _freeArgon -= reservation.ArgonSlots;
        _freeZpaq -= reservation.ZpaqSlots;
        _freeGui -= reservation.GuiSlots;
        _freeEntropy -= reservation.EntropySlots;
        _hostExclusiveRunning = reservation.HostExclusive;
        if (reservation.ProcessExclusive)
        {
            _processExclusiveRunning = true;
        }

        RunningWorkers++;
        AssertInvariants();
    }

    private void AssertInvariants()
    {
        if (RunningWorkers < 0 || RunningWorkers > _maxWorkers
            || _freeCpu < 0 || _freeCpu > _budget.CpuTokens
            || _freeMemory < 0 || _freeMemory > _budget.MemoryMiB
            || _freeArgon < 0 || _freeArgon > _budget.ArgonSlots
            || _freeZpaq < 0 || _freeZpaq > _budget.ZpaqSlots
            || _freeGui is < 0 or > 1
            || _freeEntropy is < 0 or > 1
            || (_hostExclusiveRunning && RunningWorkers != 1)
            || (_processExclusiveRunning && (_isolatesProcessState || RunningWorkers != 1)))
        {
            throw new InvalidOperationException("Scheduler resource counters left their declared bounds.");
        }
    }
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
    internal const int WorkerResultSchemaVersion = 1;
    internal const int RunResultSchemaVersion = 2;

    internal static async Task<IReadOnlyList<TestOutcome>> RunAsync(
        IReadOnlyList<TestCase> tests,
        HardwareBudget budget,
        int maxWorkers,
        Dictionary<string, double> cachedTimings,
        uint? seedOverride,
        bool failFast,
        bool inProcess,
        CancellationToken cancellationToken,
        bool reportOutcomes = true)
    {
        var outcomes = new List<TestOutcome>();

        // Longest first. With static reservations the schedule is only as good
        // as its order, and the long pole finishing last is what decides the
        // wall clock.
        var pending = tests
            .OrderByDescending(t => cachedTimings.GetValueOrDefault(t.Id, 0.0))
            .ToList();

        // Process isolation is what makes process-local global state safe to
        // run in parallel: a child process has its own entropy mixer, its own
        // locked-page accounting and its own hardening. Without it those
        // constraints have to serialise instead, or tests silently corrupt each
        // other's measurements.
        bool isolatesProcessState = !inProcess;
        var resources = new SchedulerResourceLedger(budget, maxWorkers, isolatesProcessState);

        var running = new List<(Task<TestOutcome> Task, TestCase Test, ReservationToken Reservation)>();
        bool stopStarting = false;
        bool oversizedReservationUsed = false;

        while (pending.Count > 0 || running.Count > 0)
        {
            bool started = false;
            if (!stopStarting)
            {
                for (int index = 0; index < pending.Count; index++)
                {
                    TestCase candidate = pending[index];
                    if (candidate.Cost.Constraints.HasFlag(TestConstraint.HostExclusive) && index != 0)
                    {
                        continue;
                    }

                    if (!resources.TryReserve(candidate, out ReservationToken? normalReservation))
                    {
                        continue;
                    }

                    pending.RemoveAt(index);

                    uint seed = seedOverride ?? NextSeed();
                    Task<TestOutcome> task = RunSafelyAsync(candidate, seed, inProcess, cancellationToken);
                    running.Add((task, candidate, normalReservation!));
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
                    ReservationToken oversizedReservation = resources.ReserveOversizedExclusive(oversized);
                    oversizedReservationUsed = true;
                    uint seed = seedOverride ?? NextSeed();
                    running.Add((RunSafelyAsync(oversized, seed, inProcess, cancellationToken), oversized, oversizedReservation));
                }

                continue;
            }

            if (started && resources.CanStartAnother)
            {
                continue;
            }

            Task<TestOutcome> completed = await Task.WhenAny(running.Select(r => r.Task)).ConfigureAwait(false);
            int completedIndex = running.FindIndex(r => r.Task == completed);
            (Task<TestOutcome> _, TestCase finishedTest, ReservationToken reservation) = running[completedIndex];
            running.RemoveAt(completedIndex);
            resources.Release(reservation);

            TestOutcome outcome = await completed.ConfigureAwait(false);
            outcomes.Add(outcome);
            if (reportOutcomes)
            {
                Report(outcome, finishedTest);
            }

            if (outcome.Status == TestStatus.Fail && failFast)
            {
                stopStarting = true;
            }
        }

        if (oversizedReservationUsed)
        {
            Console.WriteLine("scheduler: an oversized test held an explicit exclusive reservation for the whole schedulable budget.");
        }

        return outcomes;
    }

    private static uint NextSeed() =>
        checked((uint)System.Security.Cryptography.RandomNumberGenerator.GetInt32(1, int.MaxValue));

    /// <summary>
    /// Fast, deterministic regression checks for the scheduler and result-file
    /// protocol. Registered as a smoke test so both CI and local full runs gate
    /// the infrastructure that decides what all other tests mean.
    /// </summary>
    internal static async Task RunInfrastructureRegressionTestsAsync()
    {
        var budget = new HardwareBudget(8, 16L * 1024 * 1024 * 1024, 8, 8192, 2, 1);
        var light = new TestCase(
            "infra.synthetic-light",
            "synthetic light",
            () => Task.CompletedTask,
            TestResource.Light,
            "Infrastructure",
            IsSmoke: true);
        var second = new TestCase(
            "infra.synthetic-second",
            "synthetic second",
            () => Task.CompletedTask,
            TestResource.Light,
            "Infrastructure",
            IsSmoke: true);

        var singleWorker = new SchedulerResourceLedger(budget, maxWorkers: 1, isolatesProcessState: true);
        Require(singleWorker.TryReserve(light, out ReservationToken? firstReservation), "The first worker could not reserve resources.");
        Require(!singleWorker.TryReserve(second, out _), "The global max-worker limit allowed a second worker.");
        singleWorker.Release(firstReservation!);
        Require(singleWorker.FreeCpu == budget.CpuTokens && singleWorker.FreeMemory == budget.MemoryMiB, "A regular release did not restore the budget exactly.");

        var tinyBudget = new HardwareBudget(2, 4L * 1024 * 1024 * 1024, 1, 2048, 1, 1);
        var oversized = light with
        {
            Id = "infra.synthetic-oversized",
            Name = "synthetic oversized",
            Cost = new TestCost(4, 2560, true, TestConstraint.HostExclusive),
        };
        var oversizedLedger = new SchedulerResourceLedger(tinyBudget, maxWorkers: 4, isolatesProcessState: true);
        Require(!oversizedLedger.TryReserve(oversized, out _), "An oversized test received an ordinary reservation.");
        ReservationToken oversizedReservation = oversizedLedger.ReserveOversizedExclusive(oversized);
        Require(oversizedReservation.Oversized, "The oversized reservation was not marked explicit.");
        Require(oversizedLedger.FreeCpu == 0 && oversizedLedger.FreeMemory == 0, "The oversized test did not reserve the whole schedulable budget.");
        oversizedLedger.Release(oversizedReservation);
        Require(oversizedLedger.FreeCpu == tinyBudget.CpuTokens && oversizedLedger.FreeMemory == tinyBudget.MemoryMiB, "The oversized release over- or under-restored the budget.");
        RequireThrows<InvalidOperationException>(() => oversizedLedger.Release(oversizedReservation), "A reservation could be released twice.");

        var duplicate = second with { Id = light.Id };
        RequireThrows<InvalidOperationException>(
            () => TestInventory.Validate([light, duplicate], []),
            "Duplicate inventory ids were accepted.");
        TestInventory.Validate([light, second], []);

        var performance = light with
        {
            Id = "performance.synthetic-cipher-suites",
            Name = "synthetic cipher-suite performance gate",
            Category = "Performance",
            IsSmoke = false,
            IsPerformance = true,
        };
        TestInventory.Validate([light, second], [performance]);
        RequireThrows<InvalidOperationException>(
            () => TestInventory.Validate([light, second], [performance with { Category = "Crypto" }]),
            "A performance test outside the Performance category was accepted.");

        string root = Directory.CreateTempSubdirectory("keep-vault-result-schema-").FullName;
        string resultPath = Path.Combine(root, "results.json");
        try
        {
            TestCase[] inventory = [light, second];
            TestOutcome[] outcomes =
            [
                new(light.Id, light.Name, TestStatus.Fail, 0.1, 1, 7, "synthetic failure"),
            ];
            WriteResults(resultPath, outcomes, budget, maxWorkers: 1, inventory);
            IReadOnlyList<string> failed = ReadFailedIds(resultPath, inventory);
            Require(failed.Count == 1 && failed[0] == light.Id, "A valid failure result did not round-trip.");

            JsonNode validDocument = JsonNode.Parse(File.ReadAllText(resultPath))
                ?? throw new InvalidOperationException("The self-test result file is empty.");
            validDocument["schemaVersion"] = RunResultSchemaVersion + 1;
            File.WriteAllText(resultPath, validDocument.ToJsonString());
            RequireThrows<InvalidDataException>(
                () => ReadFailedIds(resultPath, inventory),
                "An unknown result schema was accepted.");

            WriteResults(resultPath, outcomes, budget, maxWorkers: 1, inventory);
            JsonNode staleDocument = JsonNode.Parse(File.ReadAllText(resultPath))
                ?? throw new InvalidOperationException("The self-test result file is empty.");
            staleDocument["tests"]![0]!["id"] = "infra.removed-test";
            File.WriteAllText(resultPath, staleDocument.ToJsonString());
            RequireThrows<InvalidDataException>(
                () => ReadFailedIds(resultPath, inventory),
                "A stale result test id was accepted.");
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }

        Require(TestRunner.ShouldRunComprehensive(smokeFailed: true, failFast: false), "A normal full run would stop after a smoke failure.");
        Require(!TestRunner.ShouldRunComprehensive(smokeFailed: true, failFast: true), "--fail-fast would continue after a smoke failure.");
        Require(TestRunner.MatchesSelector(light, light.Id), "--only did not match an exact stable test id.");
        Require(TestRunner.MatchesSelector(light, "synthetic light"), "--only no longer supports a display-name substring.");
        Require(TestRunner.MatchesSelector(performance, performance.Id), "--only did not match a stable performance-test id.");
        Require(!TestRunner.IsAutomaticComprehensive(performance), "A manual performance gate was included in an automatic run.");
        Require(TestRunner.IsAutomaticComprehensive(light), "A normal comprehensive test was excluded as a performance gate.");
        Require(
            !TestRunner.IsSelectedByManualPerformanceMode(performance, false, null, "CpuHeavy"),
            "A resource-category selection implicitly included a manual performance gate.");
        Require(
            TestRunner.IsSelectedByManualPerformanceMode(performance, true, null, null)
                && TestRunner.IsSelectedByManualPerformanceMode(performance, false, performance.Id, null)
                && TestRunner.IsSelectedByManualPerformanceMode(performance, false, null, "Performance"),
            "An explicit performance selector did not include the manual gate.");

        int executedAfterFailure = 0;
        var failing = light with
        {
            Id = "infra.synthetic-failure",
            Name = "synthetic failure",
            IsSmoke = false,
            Run = () => throw new InvalidOperationException("expected synthetic failure"),
        };
        var afterFailure = second with
        {
            Id = "infra.synthetic-after-failure",
            Name = "synthetic after failure",
            IsSmoke = false,
            Run = () =>
            {
                Interlocked.Increment(ref executedAfterFailure);
                return Task.CompletedTask;
            },
        };
        IReadOnlyList<TestOutcome> collectAll = await RunAsync(
            [failing, afterFailure],
            budget,
            maxWorkers: 1,
            cachedTimings: [],
            seedOverride: 1,
            failFast: false,
            inProcess: true,
            CancellationToken.None,
            reportOutcomes: false).ConfigureAwait(false);
        Require(
            collectAll.Count == 2
                && collectAll.Count(outcome => outcome.Status == TestStatus.Fail) == 1
                && executedAfterFailure == 1,
            "Collect-all stopped after the first failure.");
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private static void RequireThrows<TException>(Action action, string message)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException)
        {
            return;
        }

        throw new InvalidOperationException(message);
    }

    private static async Task<TestOutcome> RunSafelyAsync(
        TestCase test,
        uint seed,
        bool inProcess,
        CancellationToken cancellationToken)
    {
        try
        {
            return await (inProcess
                ? RunInProcessAsync(test, seed)
                : RunWorkerAsync(test, seed, cancellationToken)).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            return new TestOutcome(test.Id, test.Name, TestStatus.Fail, 0, 0, seed, "worker infrastructure failure: " + Describe(ex));
        }
    }

    private static void Report(TestOutcome outcome, TestCase test)
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
            Console.WriteLine(test.IsSmoke
                ? $"  dotnet run --no-build --no-restore --project KalynaArchiver.Tests -c Release -- --smoke-only \"{outcome.Id}\" --seed 0x{outcome.Seed:X8}"
                : $"  dotnet run --no-build --no-restore --project KalynaArchiver.Tests -c Release -- --full --no-smoke --only \"{outcome.Id}\" --seed 0x{outcome.Seed:X8}");
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
                    int schemaVersion = node["schemaVersion"]?.GetValue<int>() ?? 0;
                    string id = node["id"]?.GetValue<string>() ?? string.Empty;
                    string status = node["status"]?.GetValue<string>() ?? string.Empty;
                    string? failure = node["failure"]?.GetValue<string>();
                    uint reportedSeed = node["seed"]?.GetValue<uint>() ?? 0;
                    bool validStatus = status is "PASS" or "FAIL";
                    bool validExit = (status == "PASS" && process.ExitCode == 0)
                        || (status == "FAIL" && process.ExitCode != 0);
                    if (schemaVersion != WorkerResultSchemaVersion
                        || !string.Equals(id, test.Id, StringComparison.Ordinal)
                        || reportedSeed != seed
                        || !validStatus
                        || !validExit
                        || (status == "PASS" && failure is not null)
                        || (status == "FAIL" && string.IsNullOrWhiteSpace(failure)))
                    {
                        throw new JsonException(
                            $"invalid worker result envelope for {test.Id}: schema={schemaVersion}, id={id}, status={status}, exit={process.ExitCode}");
                    }

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
                        failure)
                    {
                        Output = chatter,
                    };
                }
            }
            catch (Exception ex) when (ex is JsonException or InvalidOperationException or FormatException)
            {
                errors = string.Join(Environment.NewLine, new[] { errors.Trim(), ex.Message }.Where(part => part.Length > 0));
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
        string? assemblyName = Assembly.GetEntryAssembly()?.GetName().Name;
        string assembly = string.IsNullOrEmpty(assemblyName)
            ? throw new InvalidOperationException("The test assembly name is unknown.")
            : Path.Combine(AppContext.BaseDirectory, assemblyName + ".dll");

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
        TestCase? test = allTests.SingleOrDefault(t => string.Equals(t.Id, testId, StringComparison.Ordinal));
        if (test is null)
        {
            Console.Out.WriteLine(WorkerResultMarker + JsonSerializer.Serialize(new
            {
                schemaVersion = WorkerResultSchemaVersion,
                id = testId,
                status = "FAIL",
                seconds = 0.0,
                peakRssMiB = 0,
                seed,
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
            schemaVersion = WorkerResultSchemaVersion,
            id = test.Id,
            status = failure is null ? "PASS" : "FAIL",
            seconds = stopwatch.Elapsed.TotalSeconds,
            peakRssMiB,
            seed,
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
    internal static void WriteResults(
        string path,
        IReadOnlyList<TestOutcome> outcomes,
        HardwareBudget budget,
        int maxWorkers,
        IReadOnlyList<TestCase> inventory)
    {
        string platform = CurrentPlatform();
        string architecture = RuntimeInformation.OSArchitecture.ToString().ToLowerInvariant();
        var document = new
        {
            schemaVersion = RunResultSchemaVersion,
            head = ReadHead(),
            testInventoryHash = TestInventory.ComputeHash(inventory),
            platform,
            architecture,
            hardware = $"{budget.CpuCount} logical CPUs, {budget.TotalRamBytes / (1024 * 1024 * 1024)} GiB, "
                + $"{RuntimeInformation.OSDescription}",
            budget = new
            {
                maxWorkers,
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

        string fullPath = Path.GetFullPath(path);
        string? directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        string temporaryPath = fullPath + $".tmp-{Guid.NewGuid():N}";
        try
        {
            File.WriteAllText(temporaryPath, JsonSerializer.Serialize(document, new JsonSerializerOptions { WriteIndented = true }));
            File.Move(temporaryPath, fullPath, overwrite: true);
        }
        finally
        {
            File.Delete(temporaryPath);
        }
    }

    internal static IReadOnlyList<string> ReadFailedIds(string path, IReadOnlyList<TestCase> inventory)
    {
        if (!File.Exists(path))
        {
            throw new InvalidDataException($"Result file does not exist: {path}");
        }

        try
        {
            JsonNode? document = JsonNode.Parse(File.ReadAllText(path));
            if (document is not JsonObject)
            {
                throw new InvalidDataException("Result file root is not an object.");
            }

            int schemaVersion = document["schemaVersion"]?.GetValue<int>() ?? 0;
            if (schemaVersion != RunResultSchemaVersion)
            {
                throw new InvalidDataException(
                    $"Unsupported result schema {schemaVersion}; expected {RunResultSchemaVersion}.");
            }

            string expectedInventoryHash = TestInventory.ComputeHash(inventory);
            string inventoryHash = document["testInventoryHash"]?.GetValue<string>() ?? string.Empty;
            if (!string.Equals(inventoryHash, expectedInventoryHash, StringComparison.Ordinal))
            {
                throw new InvalidDataException("Result file belongs to a different test inventory.");
            }

            string platform = document["platform"]?.GetValue<string>() ?? string.Empty;
            string architecture = document["architecture"]?.GetValue<string>() ?? string.Empty;
            if (!string.Equals(platform, CurrentPlatform(), StringComparison.Ordinal)
                || !string.Equals(architecture, RuntimeInformation.OSArchitecture.ToString().ToLowerInvariant(), StringComparison.Ordinal))
            {
                throw new InvalidDataException("Result file belongs to a different platform or architecture.");
            }

            string recordedHead = document["head"]?.GetValue<string>() ?? string.Empty;
            string currentHead = ReadHead();
            if (recordedHead.Length == 0
                || (!string.Equals(recordedHead, "unknown", StringComparison.Ordinal)
                    && !string.Equals(currentHead, "unknown", StringComparison.Ordinal)
                    && !string.Equals(recordedHead, currentHead, StringComparison.Ordinal)))
            {
                throw new InvalidDataException("Result file belongs to a different Git HEAD.");
            }

            if (document?["tests"] is not JsonArray tests)
            {
                throw new InvalidDataException("Result file has no tests array.");
            }

            var knownIds = new HashSet<string>(inventory.Select(test => test.Id), StringComparer.Ordinal);
            var seenIds = new HashSet<string>(StringComparer.Ordinal);
            var failed = new List<string>();
            foreach (JsonNode? entry in tests)
            {
                string? status = entry?["status"]?.GetValue<string>();
                string? id = entry?["id"]?.GetValue<string>();
                if (string.IsNullOrEmpty(id) || status is not ("PASS" or "FAIL" or "BLOCKED"))
                {
                    throw new InvalidDataException("Result file contains a malformed test entry.");
                }

                if (!knownIds.Contains(id))
                {
                    throw new InvalidDataException($"Result file refers to unknown test id '{id}'.");
                }

                if (!seenIds.Add(id))
                {
                    throw new InvalidDataException($"Result file repeats test id '{id}'.");
                }

                if (!string.Equals(status, "PASS", StringComparison.Ordinal))
                {
                    failed.Add(id);
                }
            }

            return failed;
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or FormatException)
        {
            throw new InvalidDataException("Result file is malformed.", ex);
        }
    }

    private static string CurrentPlatform() =>
        OperatingSystem.IsWindows() ? "windows" : OperatingSystem.IsMacOS() ? "macos" : "other";

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
