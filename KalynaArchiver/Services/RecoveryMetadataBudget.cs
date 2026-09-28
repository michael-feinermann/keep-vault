using System.IO;
using System.Threading;

namespace KalynaArchiver.Services;

/// <summary>Shared trusted disk budget for every live metadata table in an operation.</summary>
internal sealed class RecoveryMetadataBudget
{
    private static readonly AsyncLocal<RecoveryMetadataBudget?> Ambient = new();
    private readonly object _gate = new();
    private readonly long _maximum;
    private long _reserved;

    private RecoveryMetadataBudget(long maximum)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximum);
        _maximum = maximum;
    }

    internal static IDisposable Begin(long maximum)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximum);
        RecoveryMetadataBudget? previous = Ambient.Value;
        Ambient.Value = previous ?? new RecoveryMetadataBudget(maximum);
        return new Scope(previous);
    }

    internal static RecoveryMetadataBudget Capture(long maximum) => Ambient.Value ?? new(maximum);
    internal long ReservedBytes { get { lock (_gate) return _reserved; } }

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
