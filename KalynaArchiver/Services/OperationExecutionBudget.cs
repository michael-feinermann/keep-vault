using System.Diagnostics;

namespace KalynaArchiver.Services;

/// <summary>One finite, shared runtime budget for an outer archive operation.</summary>
internal sealed class OperationExecutionBudget : IDisposable
{
    private static int _activeOwners;
    internal static int ActiveOwnersForTests => Volatile.Read(ref _activeOwners);
    private readonly object _gate = new();
    private readonly ArchiveOperationPolicy _policy;
    private readonly CancellationTokenSource _cancellation;
    private readonly Func<TimeSpan> _elapsed;
    private readonly Func<TimeSpan> _cpu;
    private readonly Process? _process;
    private readonly Timer? _timer;
    private TimeSpan _lastProgress;
    private long _childCpuTicks;
    private Exception? _failure;
    private bool _disposed;

    internal OperationExecutionBudget(ArchiveOperationPolicy policy, CancellationToken token,
        Func<TimeSpan>? elapsedForTests = null, Func<TimeSpan>? cpuForTests = null, bool enableTimer = true)
    {
        _policy = policy;
        _cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
        try
        {
        if (elapsedForTests is null)
        {
            var clock = Stopwatch.StartNew();
            _elapsed = () => clock.Elapsed;
        }
        else _elapsed = elapsedForTests;
        if (cpuForTests is null)
        {
            _process = Process.GetCurrentProcess();
            TimeSpan initialCpu = _process.TotalProcessorTime;
            _cpu = () => { _process.Refresh(); return _process.TotalProcessorTime - initialCpu; };
        }
        else _cpu = cpuForTests;
        if (enableTimer) _timer = new Timer(static value => ((OperationExecutionBudget)value!).CheckLimits(), this,
            TimeSpan.FromMilliseconds(100), TimeSpan.FromMilliseconds(100));
        Interlocked.Increment(ref _activeOwners);
        }
        catch
        {
            _timer?.Dispose();
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
        Exception? expired = null;
        lock (_gate)
        {
            if (_failure is not null) throw new TimeoutException("The archive operation exceeded its approved runtime budget.", _failure);
            if (_disposed) throw new ObjectDisposedException(nameof(OperationExecutionBudget));
            TimeSpan elapsed = _elapsed();
            if (elapsed >= _policy.WallTimeBudget)
                expired = new TimeoutException("The archive operation exhausted its approved wall-time budget.");
            else if (elapsed - _lastProgress >= _policy.NoProgressTimeout)
                expired = new TimeoutException("The archive operation exceeded its approved progress-stall interval.");
            if (expired is null) _lastProgress = elapsed;
            else _failure = expired;
        }
        if (expired is not null)
        {
            CancelAfterFailure();
            throw new TimeoutException("Late byte progress cannot renew an expired operation budget.", expired);
        }
    }

    internal void RecordChildCpu(TimeSpan delta)
    {
        if (delta < TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(delta));
        lock (_gate) _childCpuTicks = checked(_childCpuTicks + delta.Ticks);
    }

    internal void CheckLimits()
    {
        bool cancel = false;
        lock (_gate)
        {
            if (_disposed || _failure is not null) return;
            try
            {
                TimeSpan elapsed = _elapsed();
                TimeSpan cpu = _cpu() + TimeSpan.FromTicks(_childCpuTicks);
                if (elapsed < TimeSpan.Zero || cpu < TimeSpan.Zero || elapsed < _lastProgress)
                    throw new IOException("The archive operation clock moved backwards.");
                if (elapsed >= _policy.WallTimeBudget)
                    throw new TimeoutException("The archive operation exhausted its approved wall-time budget.");
                if (cpu >= _policy.CpuTimeBudget)
                    throw new TimeoutException("The archive operation exhausted its cumulative parent/child CPU-time budget.");
                if (elapsed - _lastProgress >= _policy.NoProgressTimeout)
                    throw new TimeoutException("The archive operation made no byte, frame or stripe progress within its approved timeout.");
            }
            catch (Exception failure)
            {
                _failure = failure;
                cancel = true;
            }
        }
        if (cancel) CancelAfterFailure();
    }

    private void CancelAfterFailure()
    {
        try { _cancellation.Cancel(); }
        catch (ObjectDisposedException) { }
        catch (AggregateException failure)
        {
            lock (_gate) _failure = new AggregateException(_failure!, failure);
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            _timer?.Dispose();
            _process?.Dispose();
            _cancellation.Dispose();
            Interlocked.Decrement(ref _activeOwners);
        }
    }
}
