using System.Threading;
using System.IO;
using System.Runtime.InteropServices;

namespace KalynaArchiver.Services;

/// <summary>
/// Aggregate in-process CPU reservations. A native team includes its calling
/// thread and receives only its granted reservation. No child worker acquires a
/// second reservation. Lower active policy ceilings constrain every new lease.
/// </summary>
internal static class CpuWorkBudget
{
    private static readonly object Gate = new();
    private static readonly SortedDictionary<int, int> ActiveCeilings = new();
    private static TaskCompletionSource Changed = NewSignal();
    private static int _used;
    private static readonly AsyncLocal<Lease?> Ambient = new();

    internal static bool IsOwnedByCurrentContext
    {
        get { lock (Gate) return Ambient.Value is { _disposed: false }; }
    }

    internal static int ActiveWorkersForTests { get { lock (Gate) return _used; } }

    internal static async ValueTask<Lease> AcquireAsync(int maximum, int preferred, CancellationToken cancellationToken, int reservedHeadroom = 0)
    {
        if (maximum < 1 || preferred < 1) throw new ArgumentOutOfRangeException(nameof(maximum));
        preferred = Math.Min(preferred, maximum);
        if (reservedHeadroom < 0 || reservedHeadroom >= maximum) throw new ArgumentOutOfRangeException(nameof(reservedHeadroom));
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            // Re-evaluate at a safe team boundary. Already running teams retain
            // their permits until joined; a smaller host never grants more work
            // while those outstanding permits exceed the new availability.
            int currentMaximum = Math.Min(maximum, CpuTopology.AvailableWorkers);
            if (reservedHeadroom >= currentMaximum)
                throw new IOException("Current CPU availability cannot accommodate the native worker and its required parent headroom.");
            Task wait;
            lock (Gate)
            {
                int ceiling = ActiveCeilings.Count == 0 ? currentMaximum : Math.Min(currentMaximum, ActiveCeilings.First().Key);
                int grant = CalculateAvailableGrant(ceiling, _used, preferred, reservedHeadroom);
                if (grant > 0)
                {
                    int committedUsed = checked(_used + grant);
                    ActiveCeilings.TryGetValue(currentMaximum, out int owners);
                    int committedOwners = checked(owners + 1);
                    var lease = new Lease(currentMaximum, grant);
                    // Dictionary insertion may allocate. Commit the counter
                    // only after every potentially allocating acquisition step.
                    ActiveCeilings[currentMaximum] = committedOwners;
                    _used = committedUsed;
                    return lease;
                }
                wait = Changed.Task;
            }
            await wait.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    // Hash families are independent, but a caller already executing under one
    // owned permit must not create more unreserved work or reacquire itself.
    // No native-child lease enters such a parent context.
    internal static async Task RunIndependentAsync(CancellationToken token, params Action[] actions)
    {
        ArgumentNullException.ThrowIfNull(actions);
        if (IsOwnedByCurrentContext)
        {
            foreach (Action action in actions) { token.ThrowIfCancellationRequested(); RunSynchronousWorker(action); }
            return;
        }
        int maximum = ArchiveOperationPolicy.Current.MaxCpuWorkers;
        var tasks = new Task[actions.Length];
        Exception? failure = null;
        int started = 0;
        try
        {
            for (; started < actions.Length; ++started)
            {
                Action action = actions[started];
                tasks[started] = Task.Run(async () =>
                {
                    using Lease cpu = await AcquireAsync(maximum, 1, token).ConfigureAwait(false);
                    using IDisposable scope = cpu.EnterScope();
                    token.ThrowIfCancellationRequested(); RunSynchronousWorker(action);
                }, token);
            }
        }
        catch (Exception error) { failure = error; }
        // Join individually even after a partial scheduling failure. This loop
        // requires no new task array/list while accepted workers own inputs.
        for (int i = 0; i < started; ++i)
        {
            try { await tasks[i].ConfigureAwait(false); }
            catch (Exception error) { failure ??= error; }
        }
        if (failure is not null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw();
    }

    private static void RunSynchronousWorker(Action action)
    {
        using var qos = MacCpuWorkerQos.EnterSynchronousScope();
        action();
    }

    // Pure arithmetic seam permits >1024-worker validation without creating
    // those threads on a small host. Production uses the exact same function.
    internal static int CalculateAvailableGrant(int ceiling, int used, int preferred, int headroom)
    {
        if (ceiling < 1 || used < 0 || preferred < 1 || headroom < 0)
            throw new ArgumentOutOfRangeException(nameof(ceiling));
        if (used >= ceiling || headroom >= ceiling - used) return 0;
        return Math.Min(preferred, ceiling - used - headroom);
    }

    private static TaskCompletionSource NewSignal() => new(TaskCreationOptions.RunContinuationsAsynchronously);

    internal sealed class Lease(int maximum, int workers) : IDisposable
    {
        internal bool _disposed;
        internal IDisposable EnterScope()
        {
            lock (Gate) ObjectDisposedException.ThrowIf(_disposed, this);
            Lease? previous = Ambient.Value;
            var scope = new ContextScope(previous);
            Ambient.Value = this;
            return scope;
        }
        internal int Workers { get; } = workers;
        public void Dispose()
        {
            TaskCompletionSource signal;
            lock (Gate)
            {
                if (_disposed) return;
                // Allocate before changing ownership. If allocation fails,
                // the caller retains this lease and may retry disposal.
                TaskCompletionSource replacement = NewSignal();
                _disposed = true;
                _used -= Workers;
                int owners = ActiveCeilings[maximum] - 1;
                if (owners == 0) ActiveCeilings.Remove(maximum); else ActiveCeilings[maximum] = owners;
                signal = Changed;
                Changed = replacement;
            }
            signal.TrySetResult();
        }
    }
    private sealed class ContextScope(Lease? previous) : IDisposable
    {
        private bool _disposed;
        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            Ambient.Value = previous;
        }
    }
}

/// <summary>
/// A point-in-time OS observation, not an affinity map or a promise of dedicated
/// CPUs. Performance-level indexes are OS ranks (zero is highest), not invented
/// P/E, processor-group or NUMA identities. Missing fields remain unknown.
/// </summary>
internal sealed record CpuTopologySnapshot(
    int ProcessLimit,
    int AvailableWorkers,
    int? EnabledLogicalProcessors,
    int? EnabledPhysicalProcessors,
    bool ChangedDuringRead,
    IReadOnlyList<CpuPerformanceLevel> PerformanceLevels)
{
    internal bool? HasSimultaneousMultithreading =>
        !ChangedDuringRead && EnabledLogicalProcessors is int logical && EnabledPhysicalProcessors is int physical
            ? logical > physical : null;
}

internal sealed record CpuPerformanceLevel(int Rank, int? EnabledLogicalProcessors, int? EnabledPhysicalProcessors)
{
    internal bool? HasSimultaneousMultithreading =>
        EnabledLogicalProcessors is int logical && EnabledPhysicalProcessors is int physical && physical > 0
            ? logical > physical : null;
}

/// <summary>Fresh documented macOS counts, constrained by the runtime process ceiling.</summary>
internal static class CpuTopology
{
    // No product configuration exposes this synthetic topology seam.
    internal static Func<int>? AvailabilityForTests;
    internal static int AvailableWorkers
    {
        get
        {
            Func<int>? synthetic = Volatile.Read(ref AvailabilityForTests);
            if (synthetic is not null) return Math.Max(1, synthetic());
            return Capture().AvailableWorkers;
        }
    }

    internal static CpuTopologySnapshot Capture()
    {
        int processLimit = Math.Max(1, Environment.ProcessorCount);
        return OperatingSystem.IsMacOS()
            ? ReadMacSnapshot(processLimit, ReadInt32)
            : new CpuTopologySnapshot(processLimit, processLimit, null, null, false, Array.Empty<CpuPerformanceLevel>());
    }

    // Pure source seam: tests exercise the exact production interpretation of
    // missing, changing, malformed, homogeneous and heterogeneous OS counts.
    internal static CpuTopologySnapshot ReadMacSnapshot(int processLimit, Func<string, int?> read)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(processLimit, 1);
        ArgumentNullException.ThrowIfNull(read);
        int? logical = Positive(read("hw.logicalcpu"));
        int? physical = Positive(read("hw.physicalcpu"));
        int? maximumLogical = Positive(read("hw.logicalcpu_max"));
        int? levelCount = Positive(read("hw.nperflevels"));
        CpuPerformanceLevel[] levels = [];
        // A core type requires at least one possible core. This bound follows
        // OS-reported hardware size, not a fixed 64/1024-worker array limit.
        int possibleCores = maximumLogical ?? logical ?? processLimit;
        if (levelCount is int count && count <= possibleCores && count <= Array.MaxLength)
        {
            levels = new CpuPerformanceLevel[count];
            for (int index = 0; index < count; ++index)
            {
                string prefix = "hw.perflevel" + index.ToString(System.Globalization.CultureInfo.InvariantCulture);
                int? levelLogical = Nonnegative(read(prefix + ".logicalcpu"));
                int? levelPhysical = Nonnegative(read(prefix + ".physicalcpu"));
                if (levelLogical > possibleCores) levelLogical = null;
                if (levelPhysical > possibleCores || levelPhysical > levelLogical
                    || (levelPhysical == 0 && levelLogical > 0)) levelPhysical = null;
                levels[index] = new CpuPerformanceLevel(index, levelLogical, levelPhysical);
            }
        }
        int? finalLogical = Positive(read("hw.logicalcpu"));
        int? finalPhysical = Positive(read("hw.physicalcpu"));
        bool changed = logical != finalLogical || physical != finalPhysical;
        // sysctl reads are not an atomic topology transaction. If the host
        // changes mid-read, grant only the smaller observed logical capacity
        // and withhold derived SMT/performance-level metadata until next read.
        int? conservativeLogical = logical is int first && finalLogical is int last
            ? Math.Min(first, last) : logical ?? finalLogical;
        if (changed)
        {
            physical = null;
            levels = [];
        }
        else if (physical > conservativeLogical)
            physical = null;
        return new CpuTopologySnapshot(processLimit,
            Math.Min(processLimit, conservativeLogical ?? processLimit), conservativeLogical, physical, changed,
            Array.AsReadOnly(levels));
    }

    private static int? Positive(int? value) => value > 0 ? value : null;
    private static int? Nonnegative(int? value) => value >= 0 ? value : null;

    private static int? ReadInt32(string name)
    {
        nuint bytes = sizeof(int);
        int status = sysctlbyname(name, out int value, ref bytes, IntPtr.Zero, 0);
        return status == 0 && bytes == sizeof(int) ? value : null;
    }

    [DllImport("/usr/lib/libSystem.B.dylib", CallingConvention = CallingConvention.Cdecl)]
    private static extern int sysctlbyname([MarshalAs(UnmanagedType.LPUTF8Str)] string name,
        out int value, ref nuint length, IntPtr newValue, nuint newLength);
}
