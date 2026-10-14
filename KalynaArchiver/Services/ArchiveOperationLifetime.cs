namespace KalynaArchiver.Services;

/// <summary>Records irreversible work at the owner that actually begins it.</summary>
internal sealed class ArchiveOperationLifetime
{
    private int _executionStarted;
    private int _consumptionStarted;
    private int _fatalFailure;

    internal bool ConsumptionStarted => Volatile.Read(ref _consumptionStarted) != 0;
    internal bool MustClearCredentials => Volatile.Read(ref _executionStarted) != 0
        || ConsumptionStarted || Volatile.Read(ref _fatalFailure) != 0;

    // UI gate ownership and validation never call these transitions. An owner
    // marks consumption before attempting a destructive handoff, so a later
    // exception cannot make its nonces appear available again.
    internal void BeginExecution() => Interlocked.Exchange(ref _executionStarted, 1);
    internal void BeginConsumption() => Interlocked.Exchange(ref _consumptionStarted, 1);
    internal void MarkFatalFailure() => Interlocked.Exchange(ref _fatalFailure, 1);
}

internal enum ArchivePreflightReason
{
    Input,
    Credentials,
    KeySheet,
    Resources,
    Destination,
    OutputReservation,
    DraftChanged,
}

/// <summary>An expected refusal that proves no cryptographic consumption began.</summary>
internal sealed class ArchivePreflightException(ArchivePreflightReason reason, string message)
    : InvalidOperationException(message)
{
    internal ArchivePreflightReason Reason { get; } = reason;
}
