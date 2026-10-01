using System.Runtime.InteropServices;

namespace KalynaArchiver.Services;

internal enum OperationPhase
{
    Inventory, Entropy, KeyDerivation, GlobalVerification, Compression,
    Encryption, Extraction, Recovery, ResultVerification, Commit, Cleanup,
}
internal enum ProgressUnit { Bytes, Records, Files, Stripes, Steps }
internal enum ProgressTotalOrigin { Unknown, KnownInput, ValidatedPlan }
internal enum OperationProgressState
{
    Running, WaitingForResource, AwaitingUser, Finalizing, Cancelling, Failed, Cancelled, Completed,
}
internal enum ProgressEstimateState { WarmingUp, Estimated, Unavailable, Paused, Stale }
internal enum ProgressStatusCode { Normal, InvalidObservation, ClockUnavailable }

internal sealed record OperationProgressSnapshot(
    Guid OperationId, long PlanRevision, long PhaseId, OperationPhase Phase, int PassId,
    long Sequence, OperationProgressState State, ProgressUnit Unit, long CompletedUnits,
    long? TotalUnits, ProgressTotalOrigin TotalOrigin, long MonotonicTimestamp,
    TimeSpan ActivePhaseDuration, TimeSpan ElapsedDuration, TimeSpan PausedDuration,
    double? RatePerSecond, TimeSpan? PhaseRemaining, TimeSpan? OverallRemaining,
    ProgressEstimateState EstimateState, ProgressStatusCode StatusCode);

/// <summary>
/// Bounded, observational progress. No callback, cancellation, resource authority,
/// nonce counter or integrity decision belongs to this object. Consumers poll it.
/// Ordinary pipeline/I/O waits remain in the measured wall duration.
/// </summary>
internal sealed class OperationProgressTracker : IDisposable
{
    private static readonly AsyncLocal<OperationProgressTracker?> Ambient = new();
    private readonly object _gate = new();
    private readonly TimeProvider _clock;
    private readonly long _started;
    private readonly Dictionary<long, SourceState> _sources = new();
    private const int MaxActiveSources = 64;
    private long _nextSource, _phaseId, _revision = 1, _sequence, _retired, _completed;
    private long _phaseStarted, _sampleAt, _lastWorkAt, _pauseStarted;
    private TimeSpan _phasePaused, _allPaused, _samplePaused, _sampledActive;
    private long _sampledUnits;
    private double? _rate;
    private int _intervals;
    private OperationPhase _phase = OperationPhase.Inventory;
    private ProgressUnit _unit = ProgressUnit.Bytes;
    private ProgressTotalOrigin _origin;
    private long? _total;
    private OperationProgressState _state = OperationProgressState.Running;
    private ProgressStatusCode _status;
    private bool _disposed;
    private TimeSpan _observedSuspend;
    private long? _finishedAt;

    internal OperationProgressTracker(TimeProvider? clock = null)
    {
        try { _clock = clock ?? (OperatingSystem.IsMacOS() ? new MacContinuousProgressClock() : TimeProvider.System); }
        catch { _clock = TimeProvider.System; _status = ProgressStatusCode.ClockUnavailable; }
        _started = _phaseStarted = _sampleAt = _lastWorkAt = Timestamp();
    }

    internal Guid OperationId { get; } = Guid.NewGuid();
    internal static OperationProgressTracker? Current => Ambient.Value;
    private static bool Terminal(OperationProgressState state) => state is
        OperationProgressState.Completed or OperationProgressState.Failed or OperationProgressState.Cancelled;
    private static bool Paused(OperationProgressState state) => state is
        OperationProgressState.WaitingForResource or OperationProgressState.AwaitingUser;

    internal IDisposable EnterScope()
    {
        var scope = new Scope(Ambient.Value);
        Ambient.Value = this;
        return scope;
    }

    internal OperationProgressSource? BeginPhase(OperationPhase phase,
        ProgressUnit unit = ProgressUnit.Bytes, long? totalUnits = null,
        ProgressTotalOrigin origin = ProgressTotalOrigin.Unknown, int passId = 0)
    {
        lock (_gate)
        {
            if (_disposed || Terminal(_state) || _state == OperationProgressState.Cancelling) return null;
            if (totalUnits < 0 || passId < 0 || (totalUnits.HasValue && origin == ProgressTotalOrigin.Unknown))
            { _status = ProgressStatusCode.InvalidObservation; return null; }
            long now = Timestamp();
            ObserveSuspend(now);
            EndPause(now);
            _sources.Clear();
            _phaseId = checked(_phaseId + 1);
            _phase = phase;
            _unit = unit;
            _total = totalUnits;
            _origin = totalUnits.HasValue ? origin : ProgressTotalOrigin.Unknown;
            PassId = passId;
            _retired = _completed = 0;
            _phasePaused = TimeSpan.Zero;
            _phaseStarted = now;
            _state = phase is OperationPhase.Commit or OperationPhase.Cleanup
                ? OperationProgressState.Finalizing : OperationProgressState.Running;
            _status = ProgressStatusCode.Normal;
            ResetEstimator(now);
            return RegisterSourceLocked();
        }
    }

    private int PassId { get; set; }

    internal OperationProgressSource? RegisterSource()
    {
        lock (_gate) return _disposed || Terminal(_state) ? null : RegisterSourceLocked();
    }

    private OperationProgressSource? RegisterSourceLocked()
    {
        if (_sources.Count >= MaxActiveSources) { _status = ProgressStatusCode.InvalidObservation; return null; }
        long id = checked(++_nextSource);
        _sources.Add(id, new SourceState());
        return new OperationProgressSource(this, _phaseId, id);
    }

    // Only the trusted planner may change a total. Native telemetry has no such API.
    internal void RevisePlan(long? totalUnits, ProgressTotalOrigin origin)
    {
        lock (_gate)
        {
            if (_disposed || Terminal(_state)) return;
            if (totalUnits < _completed || totalUnits.HasValue && origin == ProgressTotalOrigin.Unknown)
            { _status = ProgressStatusCode.InvalidObservation; return; }
            _total = totalUnits;
            _origin = totalUnits.HasValue ? origin : ProgressTotalOrigin.Unknown;
            _revision = checked(_revision + 1);
            ResetEstimator(Timestamp());
        }
    }

    internal void SetState(OperationProgressState state)
    {
        lock (_gate)
        {
            if (_disposed || Terminal(_state) || state == OperationProgressState.Completed) return;
            if (_state == OperationProgressState.Cancelling && !Terminal(state)) return;
            ChangeState(state);
        }
    }

    // Called exclusively by the outer lifecycle owner after verification/commit/cleanup.
    internal void Complete()
    {
        lock (_gate)
        {
            if (_disposed || Terminal(_state)) return;
            ChangeState(_state == OperationProgressState.Cancelling
                ? OperationProgressState.Cancelled : OperationProgressState.Completed);
        }
    }

    internal void RecalibrateAfterSuspend()
    {
        lock (_gate)
        {
            if (_disposed || Terminal(_state)) return;
            _revision = checked(_revision + 1);
            ResetEstimator(Timestamp());
        }
    }

    internal void RecordSystemSuspend(TimeSpan duration)
    {
        lock (_gate)
        {
            if (_disposed || Terminal(_state) || duration < TimeSpan.Zero) return;
            RecordSuspend(duration, Timestamp());
        }
    }

    private void ObserveSuspend(long now)
    {
        if (_clock is not MacContinuousProgressClock clock || Terminal(_state)) return;
        try
        {
            TimeSpan accumulated = clock.AccumulatedSuspend;
            TimeSpan difference = accumulated - _observedSuspend;
            // Compare the two documented Mach clocks, not timer delay or wall time.
            // A 100-ms threshold excludes sampling skew between the two reads.
            if (difference > TimeSpan.FromMilliseconds(100))
            {
                _observedSuspend = accumulated;
                RecordSuspend(difference, now);
            }
        }
        catch { _status = ProgressStatusCode.ClockUnavailable; }
    }

    private void RecordSuspend(TimeSpan duration, long now)
    {
        if (!Paused(_state)) { _phasePaused += duration; _allPaused += duration; }
        _revision = checked(_revision + 1);
        ResetEstimator(now);
    }

    private void ChangeState(OperationProgressState state)
    {
        long now = Timestamp();
        bool wasPaused = Paused(_state);
        if (wasPaused && !Paused(state)) { EndPause(now); ResetEstimator(now); }
        if (!wasPaused && Paused(state)) _pauseStarted = now;
        _state = state;
        if (Terminal(state)) _finishedAt = now;
        _sequence = checked(_sequence + 1);
    }

    private void EndPause(long now)
    {
        if (!Paused(_state)) return;
        TimeSpan interval = Duration(_pauseStarted, now);
        _phasePaused += interval;
        _allPaused += interval;
    }

    internal void Report(long phaseId, long sourceId, long completed, long sequence, bool delta)
    {
        lock (_gate)
        {
            if (_disposed || Terminal(_state) || phaseId != _phaseId || !_sources.TryGetValue(sourceId, out SourceState? source)) return;
            if (!delta && sequence <= source.Sequence) return;
            try
            {
                long next = delta ? checked(source.Completed + completed) : completed;
                long aggregate = checked(_completed - source.Completed + next);
                if (completed < 0 || next < source.Completed || aggregate < 0 || aggregate > _total)
                { _status = ProgressStatusCode.InvalidObservation; return; }
                if (next > source.Completed) _lastWorkAt = Timestamp();
                source.Sequence = delta ? checked(source.Sequence + 1) : sequence;
                source.Completed = next;
                _completed = aggregate;
                _sequence = checked(_sequence + 1);
            }
            catch (OverflowException) { _status = ProgressStatusCode.InvalidObservation; }
        }
    }

    internal void Retire(long phaseId, long sourceId)
    {
        lock (_gate)
        {
            if (phaseId == _phaseId && _sources.Remove(sourceId, out SourceState? source))
                _retired = checked(_retired + source.Completed);
        }
    }

    internal OperationProgressSnapshot Snapshot()
    {
        lock (_gate)
        {
            long now = _finishedAt ?? Timestamp();
            ObserveSuspend(now);
            TimeSpan currentPause = Paused(_state) ? Duration(_pauseStarted, now) : TimeSpan.Zero;
            TimeSpan paused = _phasePaused + currentPause;
            TimeSpan active = Duration(_phaseStarted, now) - paused;
            if (active < TimeSpan.Zero) { active = TimeSpan.Zero; _status = ProgressStatusCode.ClockUnavailable; }
            TimeSpan dt = Duration(_sampleAt, now) - (paused - _samplePaused);
            if (!Paused(_state) && !Terminal(_state) && dt >= TimeSpan.FromMilliseconds(250))
            {
                long dx = _completed - _sampledUnits;
                double instantaneous = dx / dt.TotalSeconds;
                double alpha = 1 - Math.Exp(-dt.TotalSeconds / 15);
                _rate = _rate is double previous ? alpha * instantaneous + (1 - alpha) * previous : instantaneous;
                _sampledActive += dt;
                _intervals = Math.Min(_intervals + 1, 4);
                _sampleAt = now;
                _samplePaused = paused;
                _sampledUnits = _completed;
            }
            ProgressEstimateState estimate = ProgressEstimateState.Unavailable;
            TimeSpan? remaining = null;
            bool fresh = Duration(_lastWorkAt, now) < TimeSpan.FromSeconds(30);
            if (Paused(_state)) estimate = ProgressEstimateState.Paused;
            else if (!fresh) estimate = ProgressEstimateState.Stale;
            else if (_intervals < 4 || _sampledActive < TimeSpan.FromSeconds(2)) estimate = ProgressEstimateState.WarmingUp;
            else if (!Terminal(_state) && _state != OperationProgressState.Cancelling
                && _phase is not (OperationPhase.KeyDerivation or OperationPhase.Commit or OperationPhase.Cleanup)
                && _status == ProgressStatusCode.Normal && _rate is > 0 && double.IsFinite(_rate.Value)
                && _total is long total && total > _completed)
            {
                double seconds = (total - _completed) / _rate.Value;
                if (double.IsFinite(seconds) && seconds >= 0 && seconds < TimeSpan.MaxValue.TotalSeconds)
                { remaining = TimeSpan.FromSeconds(seconds); estimate = ProgressEstimateState.Estimated; }
            }
            return new(OperationId, _revision, _phaseId, _phase, PassId, _sequence, _state, _unit,
                _completed, _total, _origin, now, active, Duration(_started, now), _allPaused + currentPause,
                !Paused(_state) && !Terminal(_state) && fresh && _intervals >= 4
                    && _sampledActive >= TimeSpan.FromSeconds(2) && _status == ProgressStatusCode.Normal
                    && _phase != OperationPhase.KeyDerivation && _rate is >= 0 && double.IsFinite(_rate.Value)
                    ? _rate : null, remaining, null, estimate, _status);
        }
    }

    private void ResetEstimator(long now)
    {
        _sampleAt = _lastWorkAt = now;
        _sampledUnits = _completed;
        _samplePaused = _phasePaused;
        _sampledActive = TimeSpan.Zero;
        _rate = null;
        _intervals = 0;
    }

    private long Timestamp()
    {
        try { return _clock.GetTimestamp(); }
        catch { _status = ProgressStatusCode.ClockUnavailable; return _sampleAt; }
    }
    private TimeSpan Duration(long from, long to)
    {
        try
        {
            TimeSpan value = _clock.GetElapsedTime(from, to);
            if (value >= TimeSpan.Zero) return value;
        }
        catch { }
        _status = ProgressStatusCode.ClockUnavailable;
        return TimeSpan.Zero;
    }

    public void Dispose() { lock (_gate) { _disposed = true; _sources.Clear(); } }
    private sealed class SourceState { internal long Completed; internal long Sequence = -1; }
    private sealed class Scope(OperationProgressTracker? previous) : IDisposable
    {
        private bool _disposed;
        public void Dispose() { if (_disposed) return; _disposed = true; Ambient.Value = previous; }
    }
}

/// <summary>
/// Darwin's documented continuous clock includes suspend; absolute time excludes
/// it. Their difference identifies actual sleep without confusing a slow observer
/// or blocked I/O with sleep. No UTC clock enters duration or rate arithmetic.
/// </summary>
internal sealed class MacContinuousProgressClock : TimeProvider
{
    private readonly long _frequency;
    private readonly double _initialDifference;
    internal MacContinuousProgressClock()
    {
        if (mach_timebase_info(out Timebase info) != 0 || info.Numerator == 0 || info.Denominator == 0)
            throw new IOException("The monotonic macOS timebase is unavailable.");
        _frequency = checked((long)(1_000_000_000UL * info.Denominator / info.Numerator));
        _initialDifference = DifferenceSeconds();
    }
    public override long TimestampFrequency => _frequency;
    public override long GetTimestamp() => checked((long)mach_continuous_time());
    private double DifferenceSeconds()
    {
        ulong continuous = mach_continuous_time();
        ulong active = mach_absolute_time();
        return ((double)continuous - active) / _frequency;
    }
    internal TimeSpan AccumulatedSuspend => TimeSpan.FromSeconds(Math.Max(0, DifferenceSeconds() - _initialDifference));
    [StructLayout(LayoutKind.Sequential)] private struct Timebase { internal uint Numerator, Denominator; }
    [DllImport("/usr/lib/libSystem.B.dylib")] private static extern int mach_timebase_info(out Timebase info);
    [DllImport("/usr/lib/libSystem.B.dylib")] private static extern ulong mach_continuous_time();
    [DllImport("/usr/lib/libSystem.B.dylib")] private static extern ulong mach_absolute_time();
}

internal sealed class OperationProgressSource(OperationProgressTracker tracker, long phaseId, long sourceId) : IDisposable
{
    private int _disposed;
    internal void Report(long completedUnits, long sequence)
    { if (Volatile.Read(ref _disposed) == 0) tracker.Report(phaseId, sourceId, completedUnits, sequence, delta: false); }
    internal void Advance(long delta)
    { if (Volatile.Read(ref _disposed) == 0) tracker.Report(phaseId, sourceId, delta, 0, delta: true); }
    public void Dispose() { if (Interlocked.Exchange(ref _disposed, 1) == 0) tracker.Retire(phaseId, sourceId); }
}
