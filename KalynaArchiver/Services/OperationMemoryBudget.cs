using System.Threading;

namespace KalynaArchiver.Services;

/// <summary>
/// Process-wide approved memory reservations. Nested archive services share the
/// outer reservation; live and detached entropy segments are charged separately.
/// </summary>
internal static class OperationMemoryBudget
{
    private static readonly object Gate = new();
    private static readonly AsyncLocal<Lease?> Ambient = new();
    private static readonly SortedDictionary<long, int> EntropyCeilings = new();
    private static TaskCompletionSource Changed = NewSignal();
    private static long _workingBytes;
    private static long _entropyBytes;
    // This runtime value reflects the process/container memory limit where the
    // runtime supports it. Reserve one quarter for OS, GUI, runtime and caches.
    internal static readonly long HostMemoryCeilingBytes = GetHostCeiling();
    internal static long EntropyReservedBytes { get { lock (Gate) return _entropyBytes; } }
    internal static long WorkingReservedBytesForTests { get { lock (Gate) return _workingBytes; } }
    internal static Action<string>? ConstructionHookForTests;

    private static long GetHostCeiling()
    {
        long available = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes;
        if (available <= 0) throw new InvalidOperationException("The process memory limit is unavailable.");
        return checked(available - available / 4);
    }

    internal static async ValueTask<Lease> AcquireAsync(ArchiveOperationPolicy policy, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(policy);
        long bytes = checked(policy.MemoryBudgetBytes - policy.EntropyCaptureBudgetBytes);
        if (bytes <= 0 || policy.MemoryBudgetBytes > HostMemoryCeilingBytes)
            throw new InvalidOperationException("The approved operation memory exceeds the process memory ceiling.");
        for (;;)
        {
            token.ThrowIfCancellationRequested();
            Task wait;
            lock (Gate)
            {
                if (_entropyBytes > policy.EntropyCaptureBudgetBytes)
                    throw new InvalidOperationException("Existing protected mouse records exceed this operation's entropy budget. Finish or explicitly reset preparation first.");
                if (Ambient.Value is Lease parent)
                {
                    ObjectDisposedException.ThrowIf(parent._disposed, parent);
                    if (policy.MemoryBudgetBytes > parent._root.ApprovedBytes
                        || bytes > parent._root.Bytes
                        || policy.WorkingBufferBudgetBytes > parent._root.WorkingBufferCapacity)
                        throw new InvalidOperationException("A nested operation cannot raise the approved memory reservation.");
                    int owners = checked(parent._root.Owners + 1);
                    var nested = new Lease(parent._root, policy.EntropyCaptureBudgetBytes, token);
                    try
                    {
                        ConstructionHookForTests?.Invoke("nested-lease");
                        AddEntropyCeiling(nested._entropyCeiling);
                        parent._root.Owners = owners;
                        return nested;
                    }
                    catch { nested.AbortConstruction(); throw; }
                }
                if (bytes <= HostMemoryCeilingBytes - _workingBytes - _entropyBytes)
                {
                    long working = checked(_workingBytes + bytes);
                    var runtime = new OperationExecutionBudget(policy, token);
                    Lease? lease = null;
                    try
                    {
                        ConstructionHookForTests?.Invoke("runtime");
                        lease = new Lease(new Reservation(bytes, policy.MemoryBudgetBytes,
                            policy.HeavyWorkerMemoryBudgetBytes, policy.WorkingBufferBudgetBytes,
                            runtime), policy.EntropyCaptureBudgetBytes, token);
                        ConstructionHookForTests?.Invoke("lease");
                        AddEntropyCeiling(lease._entropyCeiling);
                        _workingBytes = working;
                        return lease;
                    }
                    catch
                    {
                        lease?.AbortConstruction();
                        runtime.Dispose();
                        throw;
                    }
                }
                wait = Changed.Task;
            }
            await wait.WaitAsync(token).ConfigureAwait(false);
        }
    }

    internal static void ReportProgress(long bytes) => Ambient.Value?._root.Runtime.RecordProgress(bytes);
    internal static void ReportChildCpu(TimeSpan delta) => Ambient.Value?._root.Runtime.RecordChildCpu(delta);

    /// <summary>
    /// Charges allocations which may overlap inside one archive operation, such
    /// as the native compressor and an Argon2 matrix. Nested service scopes do
    /// not create more capacity. A cancelled wait never acquires a reservation.
    /// </summary>
    internal static async ValueTask<HeavyLease> AcquireHeavyAsync(long bytes, CancellationToken token)
    {
        if (bytes <= 0) throw new ArgumentOutOfRangeException(nameof(bytes));
        Lease parent = Ambient.Value ?? throw new InvalidOperationException("A heavy allocation requires an operation memory reservation.");
        for (;;)
        {
            token.ThrowIfCancellationRequested();
            Task wait;
            lock (Gate)
            {
                ObjectDisposedException.ThrowIf(parent._disposed, parent);
                long capacity = Math.Min(parent._root.HeavyCapacity,
                    ArchiveOperationPolicy.Current.HeavyWorkerMemoryBudgetBytes);
                if (bytes > capacity)
                    throw new IOException("A native worker or Argon2 matrix exceeds the approved heavy-worker memory budget.");
                if (bytes <= capacity - parent._root.HeavyBytes)
                {
                    int owners = checked(parent._root.Owners + 1);
                    long heavy = checked(parent._root.HeavyBytes + bytes);
                    var lease = new HeavyLease(parent._root, parent._entropyCeiling, bytes);
                    AddEntropyCeiling(parent._entropyCeiling);
                    parent._root.Owners = owners;
                    parent._root.HeavyBytes = heavy;
                    return lease;
                }
                wait = Changed.Task;
            }
            await wait.WaitAsync(token).ConfigureAwait(false);
        }
    }

    internal static IDisposable ReserveEntropy(long bytes, long approvedEntropyBytes)
    {
        if (bytes <= 0 || approvedEntropyBytes <= 0) throw new ArgumentOutOfRangeException(nameof(bytes));
        lock (Gate)
        {
            long ceiling = EntropyCeilings.Count == 0 ? approvedEntropyBytes
                : Math.Min(approvedEntropyBytes, EntropyCeilings.First().Key);
            ceiling = Math.Min(ceiling, HostMemoryCeilingBytes - _workingBytes);
            if (bytes > ceiling - _entropyBytes)
                throw new IOException("The shared protected mouse-record budget is exhausted. Finish or explicitly reset preparation before collecting more events.");
            var reservation = new EntropyReservation(bytes);
            _entropyBytes = checked(_entropyBytes + bytes);
            return reservation;
        }
    }

    private static void AddEntropyCeiling(long ceiling)
    {
        EntropyCeilings.TryGetValue(ceiling, out int count);
        EntropyCeilings[ceiling] = checked(count + 1);
    }
    private static TaskCompletionSource NewSignal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
    private static void WakeWaiters(TaskCompletionSource replacement)
    {
        TaskCompletionSource signal = Changed;
        Changed = replacement;
        signal.TrySetResult();
    }
    private static void ReleaseOwner(Reservation root, long entropyCeiling, TaskCompletionSource replacement)
    {
        int count = EntropyCeilings[entropyCeiling] - 1;
        if (count == 0) EntropyCeilings.Remove(entropyCeiling); else EntropyCeilings[entropyCeiling] = count;
        if (--root.Owners == 0)
        {
            _workingBytes -= root.Bytes;
            root.Runtime.Dispose();
        }
        WakeWaiters(replacement);
    }
    internal sealed class Reservation(long bytes, long approvedBytes, long heavyCapacity, long workingBufferCapacity,
        OperationExecutionBudget runtime)
    {
        internal readonly long Bytes = bytes;
        internal readonly long ApprovedBytes = approvedBytes;
        internal readonly long HeavyCapacity = heavyCapacity;
        internal readonly long WorkingBufferCapacity = workingBufferCapacity;
        internal readonly OperationExecutionBudget Runtime = runtime;
        internal long HeavyBytes;
        internal int Owners = 1;
    }
    internal sealed class HeavyLease(Reservation root, long entropyCeiling, long bytes) : IDisposable
    {
        private bool _disposed;
        internal long Bytes => bytes;
        public void Dispose()
        {
            lock (Gate)
            {
                if (_disposed) return;
                TaskCompletionSource replacement = NewSignal();
                _disposed = true;
                root.HeavyBytes -= bytes;
                ReleaseOwner(root, entropyCeiling, replacement);
            }
        }
    }
    internal sealed class Lease : IDisposable
    {
        internal readonly Reservation _root;
        internal readonly long _entropyCeiling;
        private readonly CancellationTokenSource _cancellation;
        internal bool _disposed;
        internal Lease(Reservation root, long entropyCeiling, CancellationToken token)
        {
            _root = root;
            _entropyCeiling = entropyCeiling;
            _cancellation = CancellationTokenSource.CreateLinkedTokenSource(root.Runtime.Token, token);
        }
        internal CancellationToken Token => _cancellation.Token;
        internal void AbortConstruction()
        {
            _disposed = true;
            _cancellation.Dispose();
        }
        internal IDisposable EnterScope()
        {
            lock (Gate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                var scope = new Scope(Ambient.Value);
                Ambient.Value = this;
                return scope;
            }
        }
        public void Dispose()
        {
            lock (Gate)
            {
                if (_disposed) return;
                TaskCompletionSource replacement = NewSignal();
                _disposed = true;
                _cancellation.Dispose();
                ReleaseOwner(_root, _entropyCeiling, replacement);
            }
        }
    }
    private sealed class Scope(Lease? previous) : IDisposable
    {
        private bool _disposed;
        public void Dispose() { if (_disposed) return; Ambient.Value = previous; _disposed = true; }
    }
    private sealed class EntropyReservation(long bytes) : IDisposable
    {
        private bool _disposed;
        public void Dispose()
        {
            lock (Gate)
            {
                if (_disposed) return;
                TaskCompletionSource replacement = NewSignal();
                _disposed = true;
                _entropyBytes -= bytes;
                WakeWaiters(replacement);
            }
        }
    }
}
