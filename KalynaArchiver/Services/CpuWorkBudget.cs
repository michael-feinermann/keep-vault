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
            foreach (Action action in actions) { token.ThrowIfCancellationRequested(); action(); }
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
                    token.ThrowIfCancellationRequested(); action();
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

/// <summary>Runtime process ceiling plus fresh macOS enabled-core availability.</summary>
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
            int processLimit = Math.Max(1, Environment.ProcessorCount);
            if (!OperatingSystem.IsMacOS()) return processLimit;
            // hw.logicalcpu is Apple's enabled logical-core count, also exposed
            // as hw.activecpu. It does not describe a thread's affinity hint or
            // promise dedicated CPU time. Keep the runtime process ceiling.
            nuint bytes = sizeof(int);
            int status = sysctlbyname("hw.logicalcpu", out int enabled, ref bytes, IntPtr.Zero, 0);
            return status == 0 && bytes == sizeof(int) && enabled > 0
                ? Math.Min(processLimit, enabled) : processLimit;
        }
    }

    [DllImport("/usr/lib/libSystem.B.dylib", CallingConvention = CallingConvention.Cdecl)]
    private static extern int sysctlbyname([MarshalAs(UnmanagedType.LPUTF8Str)] string name,
        out int value, ref nuint length, IntPtr newValue, nuint newLength);
}
