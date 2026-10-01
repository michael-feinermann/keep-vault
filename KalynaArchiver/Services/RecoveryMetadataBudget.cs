using System.IO;
using System.Threading;
using System.Runtime.CompilerServices;

namespace KalynaArchiver.Services;

/// <summary>Shared trusted disk budget for every live metadata table in an operation.</summary>
internal sealed class RecoveryMetadataBudget
{
    private static readonly AsyncLocal<RecoveryMetadataBudget?> Ambient = new();
    private static readonly ConditionalWeakTable<object, RecoveryMetadataBudget> OperationBudgets = new();
    internal const long DefaultResidentBytes = 16L * 1024 * 1024;
    internal static readonly AsyncLocal<long?> ResidentLimitForTests = new();
    private readonly object _gate = new();
    private readonly long _maximum;
    private long _reserved;
    private long _resident;
    private readonly long _residentMaximum;

    private RecoveryMetadataBudget(long maximum)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximum);
        _maximum = maximum;
        _residentMaximum = Math.Min(maximum, ResidentLimitForTests.Value ?? DefaultResidentBytes);
    }

    internal static IDisposable Begin(long maximum)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximum);
        RecoveryMetadataBudget? previous = Ambient.Value;
        Ambient.Value = previous ?? Capture(maximum);
        return new Scope(previous);
    }

    internal static RecoveryMetadataBudget Capture(long maximum) => Ambient.Value
        ?? (OperationMemoryBudget.CurrentContextIdentity is object identity
            ? OperationBudgets.GetValue(identity, _ => new(maximum)) : new(maximum));
    internal long AvailableResidentBytes { get { lock (_gate) return _residentMaximum - _resident; } }
    internal bool TryReserveResident(long bytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(bytes);
        lock (_gate)
        {
            if (bytes > _residentMaximum - _resident) return false;
            _resident = checked(_resident + bytes); return true;
        }
    }
    internal void ReleaseResident(long bytes)
    {
        lock (_gate)
        {
            if (bytes < 0 || bytes > _resident) throw new InvalidOperationException("Unbalanced resident metadata release.");
            _resident -= bytes;
        }
    }
    internal long ReservedBytes { get { lock (_gate) return _reserved; } }
    internal static long CurrentReservedBytes => Ambient.Value?.ReservedBytes ?? 0;

    internal void Reserve(long bytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(bytes);
        lock (_gate)
        {
            long next = checked(_reserved + bytes);
            if (next > _maximum) throw new IOException("Combined recovery metadata exceeds the approved operation disk budget.");
            _reserved = next;
        }
    }

    internal void Release(long bytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(bytes);
        lock (_gate)
        {
            if (bytes > _reserved) throw new InvalidOperationException("Recovery metadata budget release is unbalanced.");
            _reserved -= bytes;
        }
    }

    private sealed class Scope(RecoveryMetadataBudget? previous) : IDisposable
    {
        private bool _disposed;
        public void Dispose()
        {
            if (_disposed) return;
            Ambient.Value = previous;
            _disposed = true;
        }
    }
}
