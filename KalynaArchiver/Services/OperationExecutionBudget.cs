using System.Diagnostics;

namespace KalynaArchiver.Services;

/// <summary>Shared operation lifetime and observations, with no elapsed-time authority.</summary>
internal sealed class OperationExecutionBudget : IDisposable
{
    private static int _activeOwners;
    internal static int ActiveOwnersForTests => Volatile.Read(ref _activeOwners);
    private readonly object _gate = new();
    private readonly CancellationTokenSource _cancellation;
    private readonly Func<TimeSpan> _elapsed;
    private readonly Func<TimeSpan> _cpu;
    private readonly Process? _process;
    private TimeSpan _lastProgress;
    private long _childCpuTicks;
    private Exception? _failure;
    private bool _disposed;

    internal OperationExecutionBudget(ArchiveOperationPolicy policy, CancellationToken token,
        Func<TimeSpan>? elapsedForTests = null, Func<TimeSpan>? cpuForTests = null)
    {
        ArgumentNullException.ThrowIfNull(policy);
        _cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
        try
        {
            var clock = Stopwatch.StartNew();
            _elapsed = elapsedForTests ?? (() => clock.Elapsed);
            if (cpuForTests is null)
            {
                _process = Process.GetCurrentProcess();
                TimeSpan initialCpu = _process.TotalProcessorTime;
                _cpu = () => { _process.Refresh(); return _process.TotalProcessorTime - initialCpu; };
            }
            else _cpu = cpuForTests;
            Interlocked.Increment(ref _activeOwners);
        }
        catch
        {
            _process?.Dispose();
            _cancellation.Dispose();
            throw;
        }
    }

    internal CancellationToken Token => _cancellation.Token;
    internal Exception? Failure { get { lock (_gate) return _failure; } }
    internal void RecordProgress(long bytes)
    {
        if (bytes <= 0) return;
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            // Measurement failure has no cancellation authority.
            try { _lastProgress = _elapsed(); } catch { }
        }
    }
    internal void RecordChildCpu(TimeSpan delta)
    {
        if (delta < TimeSpan.Zero) return;
        lock (_gate)
        {
            if (_disposed) return;
            _childCpuTicks = delta.Ticks > long.MaxValue - _childCpuTicks
                ? long.MaxValue : _childCpuTicks + delta.Ticks;
        }
    }
    internal (TimeSpan? Elapsed, TimeSpan? Cpu, TimeSpan? SinceProgress) Observe()
    {
        lock (_gate)
        {
            if (_disposed) return (null, null, null);
            try
            {
                TimeSpan elapsed = _elapsed();
                TimeSpan parentCpu = _cpu();
                if (elapsed < _lastProgress || parentCpu < TimeSpan.Zero) return (null, null, null);
                long cpuTicks = checked(parentCpu.Ticks + _childCpuTicks);
                return (elapsed, TimeSpan.FromTicks(cpuTicks), elapsed - _lastProgress);
            }
            catch { return (null, null, null); }
        }
    }
    internal void ReportFailure(Exception failure)
    {
        ArgumentNullException.ThrowIfNull(failure);
        lock (_gate)
        {
            if (_disposed || _failure is not null) return;
            _failure = failure;
        }
        try { _cancellation.Cancel(); }
        catch (ObjectDisposedException) { }
        catch (AggregateException cancellationFailure)
        { lock (_gate) _failure = new AggregateException(failure, cancellationFailure); }
    }
    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            _process?.Dispose();
            _cancellation.Dispose();
            Interlocked.Decrement(ref _activeOwners);
        }
    }
}
