using System.Diagnostics;

namespace KalynaArchiver.Services;

/// <summary>
/// Internal, opt-in diagnostic seam. Production has no activation through
/// arguments, environment, settings, UI, IPC or files. No observer callbacks.
/// </summary>
internal static class OperationPhaseProfile
{
    internal enum Phase
    {
        ArchiveEncryption, ArchiveDecryption, PayloadEncryption, PayloadDecryption,
        CredentialSha3, CredentialSkein, KdfPmiDerivation, KdfRound1, KdfRound2,
        Argon2Sha3Round1, Argon2SkeinRound1, Argon2Sha3Round2, Argon2SkeinRound2,
        KeySchedule, ChunkNonce, CpuPermitWait, ResourceObservation, ResourcePlanning, WindowDecision,
        CipherAes, CipherMars, CipherCamellia, CipherSerpent, CipherShacal2, CipherKalyna, CipherThreefish,
        AeadEncryptAndTag, AeadVerifyAndDecrypt,
        GlobalAuthentication, PayloadRead, PayloadWrite,
        ZpaqArchive, ZpaqExtract, ZpaqList, ZpaqNativeExitWait, ZpaqPipeConsumer, ZpaqPipeProducer,
        PipeRead, PipeWrite, RecoveryOutputWrite,
        RecoveryCreate, RecoveryVerifyRepair, RecoveryMatchOriginal,
        OriginalTreeComparison, FinalOutputCommit, VerifiedGlobalBinding, LocalRangeTags, LocalRangeVerification,
    }

    private static readonly AsyncLocal<Measurements?> Observer = new();
    internal static bool IsEnabledForTests => Observer.Value is not null;

    internal static IDisposable ObserveForTests(Measurements measurements)
    {
        ArgumentNullException.ThrowIfNull(measurements);
        var scope = new ObservationScope(Observer.Value);
        Observer.Value = measurements;
        return scope;
    }

    private sealed class ObservationScope(Measurements? previous) : IDisposable
    {
        private bool _disposed;
        public void Dispose()
        {
            if (_disposed) return;
            Observer.Value = previous;
            _disposed = true;
        }
    }

    internal static Timer Measure(Phase phase, long publicBytes = 0)
    {
        Measurements? measurements = Observer.Value;
        if (measurements is null || !measurements.AcceptsPhase(phase)) return default;
        try { return new Timer(new Ticket(measurements, phase, Math.Max(0, publicBytes))); }
        catch { measurements.MarkUnavailable(); return default; }
    }

    internal static void RecordWindowDecision(int previous, int requested, int resolved, int admitted,
        int active, bool completeBatch, long publicBytes, double publicRate, AdaptiveWindowReason reason,
        in AdaptiveChunkWindow feedback)
    {
        Measurements? measurements = Observer.Value;
        if (measurements is null) return;
        try { measurements.RecordWindow(previous, requested, resolved, admitted, active, completeBatch,
            publicBytes, publicRate, reason, feedback); }
        catch { measurements.MarkUnavailable(); }
    }

    internal readonly struct Timer(Ticket? ticket) : IDisposable
    {
        public void Dispose() => ticket?.Complete();
        internal void Complete(long publicBytes) => ticket?.Complete(Math.Max(0, publicBytes));
    }

    internal sealed class Ticket(Measurements measurements, Phase phase, long bytes)
    {
        private readonly long _start = Stopwatch.GetTimestamp();
        private int _completed;
        internal void Complete(long? observedBytes = null)
        {
            if (Interlocked.Exchange(ref _completed, 1) != 0) return;
            try { measurements.Record(phase, _start, Stopwatch.GetTimestamp(), observedBytes ?? bytes); }
            catch { measurements.MarkUnavailable(); }
        }
    }

    internal sealed class Measurements
    {
        internal const int MaximumTimelineEntries = 4_096;
        private readonly object _gate = new();
        private readonly long _origin = Stopwatch.GetTimestamp();
        private readonly long[] _calls = new long[Enum.GetValues<Phase>().Length];
        private readonly long[] _ticks = new long[Enum.GetValues<Phase>().Length];
        private readonly long[] _bytes = new long[Enum.GetValues<Phase>().Length];
        private readonly TimelineEntry[] _timeline;
        private readonly WindowDecisionEntry[] _windows;
        private readonly bool _pipelineOnly;
        private int _timelineCount;
        private int _windowCount;
        private long _omitted;
        private long _omittedWindows;
        private int _unavailable;

        internal Measurements(int timelineCapacity = MaximumTimelineEntries, bool pipelineOnly = false)
        {
            if (timelineCapacity is < 0 or > MaximumTimelineEntries) throw new ArgumentOutOfRangeException(nameof(timelineCapacity));
            _timeline = new TimelineEntry[timelineCapacity];
            _windows = new WindowDecisionEntry[timelineCapacity];
            _pipelineOnly = pipelineOnly;
        }

        internal bool AcceptsPhase(Phase phase) => !_pipelineOnly || phase is Phase.ResourceObservation or Phase.ResourcePlanning or Phase.WindowDecision;

        internal void MarkUnavailable() => Volatile.Write(ref _unavailable, 1);
        internal void Record(Phase phase, long start, long end, long bytes)
        {
            if (Volatile.Read(ref _unavailable) != 0) return;
            lock (_gate)
            {
                int index = (int)phase;
                if ((uint)index >= (uint)_calls.Length) { MarkUnavailable(); return; }
                long duration = Math.Max(0, end - start);
                bytes = Math.Max(0, bytes);
                _calls[index] = Add(_calls[index], 1);
                _ticks[index] = Add(_ticks[index], duration);
                _bytes[index] = Add(_bytes[index], bytes);
                if (_timelineCount < _timeline.Length)
                    _timeline[_timelineCount++] = new TimelineEntry(phase.ToString(),
                        (double)Math.Max(0, start - _origin) / Stopwatch.Frequency,
                        (double)duration / Stopwatch.Frequency, bytes);
                else _omitted = Add(_omitted, 1);
            }
        }

        internal void RecordWindow(int previous, int requested, int resolved, int admitted,
            int active, bool completeBatch, long publicBytes, double publicRate, AdaptiveWindowReason reason,
            in AdaptiveChunkWindow feedback)
        {
            if (Volatile.Read(ref _unavailable) != 0) return;
            long point = Stopwatch.GetTimestamp();
            lock (_gate)
            {
                if (_windowCount < _windows.Length)
                    _windows[_windowCount++] = new WindowDecisionEntry(
                        (double)Math.Max(0, point - _origin) / Stopwatch.Frequency,
                        previous, requested, resolved, admitted, active, completeBatch, Math.Max(0, publicBytes),
                        double.IsFinite(publicRate) && publicRate > 0 ? publicRate : 0,
                        double.IsFinite(publicRate) && publicRate > 0, reason.ToString(),
                        feedback.AcceptedSlots, feedback.ProbeSlots, feedback.RejectedSlots);
                else _omittedWindows = Add(_omittedWindows, 1);
            }
        }

        internal ProfileSnapshot Snapshot()
        {
            try { return SnapshotCore(); }
            catch
            {
                MarkUnavailable();
                return new ProfileSnapshot(2, false, _timeline.Length, 0, [], [], [], 0,
                    "Diagnostic observation unavailable; product operations are unaffected.");
            }
        }

        private ProfileSnapshot SnapshotCore()
        {
            lock (_gate)
            {
                return new ProfileSnapshot(2, Volatile.Read(ref _unavailable) == 0,
                    _timeline.Length, _omitted,
                    Enum.GetValues<Phase>().Select(phase => new PhaseAggregate(phase.ToString(), _calls[(int)phase],
                        (double)_ticks[(int)phase] / Stopwatch.Frequency, _bytes[(int)phase])).ToArray(),
                    _timeline.AsSpan(0, _timelineCount).ToArray().OrderBy(entry => entry.StartSeconds).ToArray(),
                    _windows.AsSpan(0, _windowCount).ToArray(), _omittedWindows,
                    "Monotonic wall intervals. Nested phases and parallel workers overlap. Aggregate sums are neither CPU time nor additive workflow duration. Bytes identify each interval's public processed-byte basis and can count the same bytes in several phases. Timeline retains its first bounded entries; aggregates include later completed intervals.");
            }
        }
        private static long Add(long a, long b) => b > long.MaxValue - a ? long.MaxValue : a + b;
    }

    internal sealed record PhaseAggregate(string Phase, long Calls, double WallSecondsSum, long PublicBytesSum);
    internal readonly record struct TimelineEntry(string Phase, double StartSeconds, double DurationSeconds, long PublicBytes);
    internal readonly record struct WindowDecisionEntry(double AtSeconds, int PreviousSlots, int RequestedSlots,
        int ResolvedSlots, int AdmittedSlotCeiling, int ActiveChunks, bool CompleteBatch, long PublicBytes,
        double PublicRateBytesPerSecond, bool RateValid, string Reason, int AcceptedSlots, int ProbeSlots, int RejectedSlots);
    internal sealed record ProfileSnapshot(int SchemaVersion, bool ObservationAvailable, int TimelineCapacity,
        long OmittedTimelineEntries, PhaseAggregate[] Aggregates, TimelineEntry[] Timeline,
        WindowDecisionEntry[] WindowDecisions, long OmittedWindowDecisions, string Interpretation);
}
