using System.Buffers.Binary;
using System.Security.Cryptography;

namespace KalynaArchiver.Services;

/// <summary>Locked append-only original records and an exclusively owned shuffle index.</summary>
internal sealed class SensitiveMouseRecordStore : IDisposable
{
    internal const int RecordBytes = 80;
    internal const int RecordsPerSegment = 256;
    private readonly List<Segment> _segments = [];
    private bool _sealed;
    private bool _disposed;
    internal long Count { get; private set; }
    internal bool NeedsSegment => Count % RecordsPerSegment == 0;

    internal sealed class Segment : IDisposable
    {
        // Managed arrays may begin at any address. Charge worst-case page
        // coverage of both separately pinned arrays, plus segment/list metadata.
        private static readonly long AllocationBytes = checked(
            MaximumLockedCoverage(RecordsPerSegment * RecordBytes)
            + MaximumLockedCoverage(RecordsPerSegment * sizeof(long)) + 1024);
        private static long MaximumLockedCoverage(long bytes)
        {
            long page = Environment.SystemPageSize;
            return checked(((bytes + page - 2) / page + 1) * page);
        }
        private IDisposable? _reservation;
        private LockedSensitiveBuffer? _records;
        private LockedSensitiveBuffer? _indices;
        internal byte[] Records => _records!.Bytes;
        internal byte[] Indices => _indices!.Bytes;
        internal static long ReservationBytes => AllocationBytes;
        internal static long ReservedBytes => OperationMemoryBudget.EntropyReservedBytes;

        internal Segment(long budget)
        {
            _reservation = OperationMemoryBudget.ReserveEntropy(AllocationBytes, budget);
            try
            {
                _records = LockedSensitiveBuffer.Create(RecordsPerSegment * RecordBytes);
                // Reserve the eventual 64-bit index capacity before accepting
                // records. Small collections use 32-bit entries in this buffer.
                _indices = LockedSensitiveBuffer.Create(RecordsPerSegment * sizeof(long));
            }
            catch (Exception failure)
            {
                EntropyMixer.DisposeEntropyOwners(failure, "Mouse segment initialization cleanup failed.", this);
                throw;
            }
        }

        public void Dispose()
        {
            SecureMemory.ZeroAndDisposeAll(_records, _indices);
            _records = null;
            _indices = null;
            _reservation?.Dispose();
            _reservation = null;
        }
    }

    // Called before choosing a random pool, so capacity failure cannot bias routing.
    internal void ReserveSegmentMetadata() => _segments.EnsureCapacity(checked(_segments.Count + 1));

    internal void Append(ReadOnlySpan<byte> record, ref Segment? spare)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_sealed || record.Length != RecordBytes) throw new InvalidOperationException("Invalid mouse-record append.");
        long next = checked(Count + 1);
        if (NeedsSegment)
        {
            if (spare is null) throw new InvalidOperationException("Mouse record capacity was not reserved before routing.");
            _segments.Add(spare);
            spare = null;
        }
        record.CopyTo(_segments[checked((int)(Count / RecordsPerSegment))].Records.AsSpan(
            checked((int)(Count % RecordsPerSegment) * RecordBytes), RecordBytes));
        Count = next;
    }

    internal void Seal() { ObjectDisposedException.ThrowIf(_disposed, this); _sealed = true; }

    internal void InitializeIndices(CancellationToken token)
    {
        if (!_sealed) throw new InvalidOperationException("Only a detached record store may be shuffled.");
        for (long index = 0; index < Count; ++index)
        {
            token.ThrowIfCancellationRequested();
            WriteIndex(index, index);
        }
    }

    private Span<byte> IndexBytes(long position)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!_sealed || position < 0 || position >= Count) throw new ArgumentOutOfRangeException(nameof(position));
        int width = Count <= int.MaxValue ? sizeof(int) : sizeof(long);
        return _segments[checked((int)(position / RecordsPerSegment))].Indices.AsSpan(
            checked((int)(position % RecordsPerSegment) * width), width);
    }

    internal long ReadIndex(long position)
    {
        Span<byte> bytes = IndexBytes(position);
        long value = bytes.Length == sizeof(int) ? BinaryPrimitives.ReadInt32LittleEndian(bytes) : BinaryPrimitives.ReadInt64LittleEndian(bytes);
        if (value < 0 || value >= Count) throw new InvalidDataException("A shuffled record index is outside its snapshot.");
        return value;
    }

    internal void WriteIndex(long position, long value)
    {
        if (value < 0 || value >= Count) throw new ArgumentOutOfRangeException(nameof(value));
        Span<byte> bytes = IndexBytes(position);
        if (bytes.Length == sizeof(int)) BinaryPrimitives.WriteInt32LittleEndian(bytes, checked((int)value));
        else BinaryPrimitives.WriteInt64LittleEndian(bytes, value);
    }

    internal void CopyRecord(long position, Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!_sealed || position < 0 || position >= Count || destination.Length != RecordBytes)
            throw new ArgumentOutOfRangeException(nameof(position));
        _segments[checked((int)(position / RecordsPerSegment))].Records.AsSpan(
            checked((int)(position % RecordsPerSegment) * RecordBytes), RecordBytes).CopyTo(destination);
    }

    public void Dispose()
    {
        if (_disposed) return;
        List<Exception>? failures = null;
        foreach (Segment segment in _segments)
        {
            try { segment.Dispose(); }
            catch (Exception failure) { (failures ??= []).Add(failure); }
        }
        if (failures is not null) throw new AggregateException("Mouse-record cleanup failed.", failures);
        _segments.Clear();
        Count = 0;
        _disposed = true;
    }
}
