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
    private static long _pendingBytes;
    internal static long HostMemoryCeilingBytes => ResourcePlanner.HostCeiling(PlatformResourceObserver.Capture());
    internal static long EntropyReservedBytes { get { lock (Gate) return _entropyBytes; } }
    internal static long WorkingReservedBytesForTests { get { lock (Gate) return _workingBytes; } }
    internal static object? CurrentContextIdentity => Ambient.Value?._root;
    internal static Action<string>? ConstructionHookForTests;

    /// <summary>
    /// Read-only admission of the known KDF lower bound before entropy transfer.
    /// This neither reserves memory nor waits, and does not derive the secret PMI.
    /// Actual matrix admission is still repeated at the existing allocation boundary.
    /// </summary>
    internal static void RequireKnownMinimumKdfAdmission(ArchiveOperationPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        long matrixBytes = checked((long)V13MasterKdf.AdmissionMinimumMemoryKiB * 1024);
        lock (Gate)
        {
            Lease? parent = Ambient.Value;
            if (parent is not null) ObjectDisposedException.ThrowIf(parent._disposed, parent);
            Reservation? root = parent?._root;
            // Observation/ownership failures remain ordinary fatal errors. Only
            // a positively established capacity refusal uses the dedicated type.
            ResourceObservation observed = PlatformResourceObserver.Capture();
            long host = ResourcePlanner.HostCeiling(observed);
            long approved = Math.Min(host, Math.Min(root?.ApprovedBytes ?? policy.MemoryBudgetBytes,
                policy.MemoryBudgetBytes));
            long held = Math.Max(policy.Usage.LeasedMemoryBytes,
                root is null ? 0 : checked(root.Bytes + root.HeavyBytes));
            long mandatory = Math.Max(ResourcePlanner.OperationBaseBytes, held);
            if (mandatory > approved || _entropyBytes > approved - mandatory
                || matrixBytes > approved - mandatory - _entropyBytes)
                throw new KdfMinimumAdmissionRefusalException(
                    "The known minimum Argon2 matrix cannot fit the approved memory allowance alongside current operation buffers and protected records. Increase the resource allowance; no encryption entropy was consumed.");

            long additional = checked(matrixBytes + (root is null ? ResourcePlanner.OperationBaseBytes : 0));
            if (_workingBytes > host || _entropyBytes > host - _workingBytes
                || additional > host - _workingBytes - _entropyBytes
                || additional > ResourcePlanner.AdditionalAdmission(observed, _pendingBytes))
                throw new KdfMinimumAdmissionRefusalException(
                    "Current memory capacity cannot admit the known minimum Argon2 matrix. Retry when capacity is available; no encryption entropy was consumed.");
        }
    }

    internal static async ValueTask<Lease> AcquireAsync(ArchiveOperationPolicy policy, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(policy);
        long bytes = ResourcePlanner.OperationBaseBytes;
        if (policy.MemoryBudgetBytes < bytes || policy.MemoryBudgetBytes > HostMemoryCeilingBytes)
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
)
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
                    RequireCurrentOsAdmission(bytes);
                    long working = checked(_workingBytes + bytes);
                    var runtime = new OperationExecutionBudget(policy, token);
                    Lease? lease = null;
                    try
                    {
                        ConstructionHookForTests?.Invoke("runtime");
                        lease = new Lease(new Reservation(bytes, policy.MemoryBudgetBytes,
                            policy.HeavyWorkerMemoryBudgetBytes, policy.WorkingBufferBudgetBytes,
                            runtime, policy.Usage), policy.EntropyCaptureBudgetBytes, token);
                        ConstructionHookForTests?.Invoke("lease");
                        AddEntropyCeiling(lease._entropyCeiling);
                        _workingBytes = working;
                        policy.Usage.AddMemory(bytes);
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
    internal static ValueTask<HeavyLease> AcquireHeavyAsync(long bytes, CancellationToken token)
        => AcquireComponentAsync(bytes, token, requireOwner: true);

    internal static ValueTask<HeavyLease> AcquireWorkingAsync(long bytes, CancellationToken token)
        => AcquireComponentAsync(bytes, token, requireOwner: false);

    internal static HeavyLease AcquireWorking(long bytes)
        => AcquireWorkingAsync(bytes, CancellationToken.None).AsTask().GetAwaiter().GetResult();

    private static async ValueTask<HeavyLease> AcquireComponentAsync(long bytes, CancellationToken token, bool requireOwner)
    {
        if (bytes <= 0) throw new ArgumentOutOfRangeException(nameof(bytes));
        Lease? parent = Ambient.Value;
        if (requireOwner && parent is null) throw new InvalidOperationException("A heavy allocation requires an operation owner.");
        ArchiveOperationPolicy policy = ArchiveOperationPolicy.Current;
        for (;;)
        {
            token.ThrowIfCancellationRequested();
            Task wait;
            lock (Gate)
            {
                if (parent is not null) ObjectDisposedException.ThrowIf(parent._disposed, parent);
                Reservation? root = parent?._root;
                long approved = Math.Min(root?.ApprovedBytes ?? policy.MemoryBudgetBytes, policy.MemoryBudgetBytes);
                long held = Math.Max(policy.Usage.LeasedMemoryBytes, root is null ? 0 : checked(root.Bytes + root.HeavyBytes));
                long entropy = Math.Min(_entropyBytes, approved);
                if (bytes > approved - ResourcePlanner.OperationBaseBytes - entropy)
                    throw new IOException("The actual allocation cannot fit the approved memory allowance alongside live protected records.");
                // Waiting for our own currently held buffers can deadlock a
                // synchronous index/producer which is their sole releaser.
                // A caller must spill/replan or fail at this safe boundary.
                if (bytes > approved - held - entropy)
                    throw new IOException("Current operation allocations leave insufficient room for the requested component; replan or release optional buffers first.");
                if (bytes <= HostMemoryCeilingBytes - _workingBytes - _entropyBytes)
                {
                    RequireCurrentOsAdmission(bytes);
                    int owners = root is null ? 0 : checked(root.Owners + 1);
                    long heavy = root is null ? 0 : checked(root.HeavyBytes + bytes);
                    long working = checked(_workingBytes + bytes);
                    long pending = checked(_pendingBytes + bytes);
                    var lease = new HeavyLease(root, policy.EntropyCaptureBudgetBytes, bytes, policy.Usage);
                    if (root is not null)
                    {
                        AddEntropyCeiling(policy.EntropyCaptureBudgetBytes);
                        root.Owners = owners;
                        root.HeavyBytes = heavy;
                    }
                    _workingBytes = working;
                    _pendingBytes = pending;
                    policy.Usage.AddMemory(bytes);
                    return lease;
                }
                wait = Changed.Task;
            }
            await wait.WaitAsync(token).ConfigureAwait(false);
        }
    }

    private static void RequireCurrentOsAdmission(long bytes)
    {
        ResourceObservation observed = PlatformResourceObserver.Capture();
        if (bytes > ResourcePlanner.AdditionalAdmission(observed, _pendingBytes))
            throw new IOException("Current operating-system memory pressure cannot admit this allocation. Existing records remain intact; no cryptographic parameter was reduced.");
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
            RequireCurrentOsAdmission(bytes);
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
            root.Usage.AddMemory(-root.Bytes);
            root.Runtime.Dispose();
        }
        WakeWaiters(replacement);
    }
    internal sealed class Reservation(long bytes, long approvedBytes, long heavyCapacity, long workingBufferCapacity,
        OperationExecutionBudget runtime, ResourceUsage usage)
    {
        internal readonly long Bytes = bytes;
        internal readonly long ApprovedBytes = approvedBytes;
        internal readonly long HeavyCapacity = heavyCapacity;
        internal readonly long WorkingBufferCapacity = workingBufferCapacity;
        internal readonly OperationExecutionBudget Runtime = runtime;
        internal readonly ResourceUsage Usage = usage;
        internal long HeavyBytes;
        internal int Owners = 1;
    }
    internal sealed class HeavyLease(Reservation? root, long entropyCeiling, long bytes, ResourceUsage usage) : IDisposable
    {
        private bool _disposed;
        private bool _allocated;
        internal long Bytes => bytes;
        // Call only after the represented allocation actually exists. Opaque
        // native routines retain a conservative pending charge until their
        // allocate/use/wipe/free invocation returns and this lease is released.
        internal void CommitAllocation()
        {
            lock (Gate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                if (_allocated) return;
                _allocated = true;
                _pendingBytes -= bytes;
                WakeWaiters(NewSignal());
            }
        }
        public void Dispose()
        {
            lock (Gate)
            {
                if (_disposed) return;
                TaskCompletionSource replacement = NewSignal();
                _disposed = true;
                _workingBytes -= bytes;
                if (!_allocated) _pendingBytes -= bytes;
                usage.AddMemory(-bytes);
                if (root is not null)
                {
                    root.HeavyBytes -= bytes;
                    ReleaseOwner(root, entropyCeiling, replacement);
                }
                else WakeWaiters(replacement);
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

/// <summary>Only a confirmed public minimum-capacity refusal, never an arbitrary I/O error.</summary>
internal sealed class KdfMinimumAdmissionRefusalException(string message) : IOException(message);
