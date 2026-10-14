using System.IO;
using System.Security.Cryptography;

namespace KalynaArchiver.Services;

/// <summary>
/// Storage for already authenticated public records. Both backends preserve the
/// identical record bytes; authentication belongs to their protected owner.
/// Never re-reads the source to manufacture replacement records during a spill.
/// </summary>
internal sealed class AuthenticatedRangeIndex : IDisposable
{
    internal static readonly AsyncLocal<bool> ForceDiskForTests = new();
    private const int SegmentBytes = 16 * 1024;
    private const int SegmentAccountingBytes = 128;
    private readonly object _gate = new();
    private readonly ArchiveOperationPolicy _policy;
    private readonly RecoveryMetadataBudget _budget;
    private readonly List<Segment> _segments = [];
    private readonly long? _expectedLength;
    private BoundFileTransaction? _file;
    private BoundFileTransaction? _pendingFile;
    private long _length;
    private bool _sealed, _failed, _disposed;
    private sealed record Segment(byte[] Bytes, OperationMemoryBudget.HeavyLease Lease, long Charge);

    internal AuthenticatedRangeIndex(ArchiveOperationPolicy policy, RecoveryMetadataBudget budget, long? expectedLength = null)
    {
        if (expectedLength < 0) throw new ArgumentOutOfRangeException(nameof(expectedLength));
        _policy = policy; _budget = budget; _expectedLength = expectedLength;
    }

    internal long Length { get { lock (_gate) { RequireUsable(); ValidateLength(); return _length; } } }
    internal long ResidentBytes { get { lock (_gate) return _segments.Sum(x => (long)x.Bytes.Length); } }
    internal long DiskBytes { get { lock (_gate) return _file is null ? 0 : _length; } }
    internal BoundFileTransaction? FileForTests => _file;

    internal void WriteAt(ReadOnlySpan<byte> bytes, long offset)
    {
        lock (_gate)
        {
            RequireUsable();
            if (_sealed) throw new InvalidOperationException("The authenticated index is frozen.");
            ArgumentOutOfRangeException.ThrowIfNegative(offset);
            long end = checked(offset + bytes.Length);
            if (end > _policy.MaxMetadataBytes || (_expectedLength is long expected && end > expected))
                throw new IOException("Authenticated metadata exceeds its approved bound.");
            try
            {
                ValidateLength();
                EnsureCapacity(end);
                if (_file is not null)
                {
                    _policy.RequireCaptureCapacity(0, Math.Max(0, end - _length), copyInput: false);
                    using IDisposable write = _policy.ReserveWorkingWrite(_file.Stream.SafeFileHandle, bytes.Length);
                    RandomAccess.Write(_file.Stream.SafeFileHandle, bytes, offset);
                }
                else Transfer(bytes, default, offset, write: true);
                _length = Math.Max(_length, end);
                ValidateLength();
            }
            catch { _failed = true; throw; }
        }
    }

    internal void ReadExactlyAt(Span<byte> bytes, long offset)
    {
        lock (_gate)
        {
            RequireUsable();
            if (offset < 0 || checked(offset + bytes.Length) > _length) throw new EndOfStreamException("Missing authenticated metadata.");
            try
            {
                ValidateLength();
                if (_file is null) Transfer(default, bytes, offset, write: false);
                else
                {
                    int read = 0;
                    while (read < bytes.Length)
                    {
                        int count = RandomAccess.Read(_file.Stream.SafeFileHandle, bytes[read..], checked(offset + read));
                        if (count == 0) throw new EndOfStreamException("Truncated authenticated metadata.");
                        read += count;
                    }
                }
                ValidateLength();
            }
            catch { CryptographicOperations.ZeroMemory(bytes); _failed = true; throw; }
        }
    }

    internal void Seal()
    {
        lock (_gate)
        {
            RequireUsable();
            try
            {
                ValidateLength();
                if (_expectedLength is long expected && _length != expected) throw new IOException("Incomplete authenticated range index.");
                if (_file is not null) { _file.Stream.Flush(true); _file.SealReadOnly(); }
                _sealed = true;
            }
            catch { _failed = true; throw; }
        }
    }

    private void EnsureCapacity(long end)
    {
        if (_file is not null || end == 0) return;
        if (ForceDiskForTests.Value) { Spill(end); return; }
        if (_segments.Count == 0 && _expectedLength is long expected)
        {
            long segments = expected / SegmentBytes + (expected % SegmentBytes == 0 ? 0 : 1);
            long residentNeed = checked(expected + segments * SegmentAccountingBytes);
            if (residentNeed > _budget.AvailableResidentBytes) { Spill(end); return; }
        }
        while ((long)_segments.Count * SegmentBytes < end)
        {
            int count = checked((int)Math.Min(SegmentBytes, (_expectedLength ?? long.MaxValue) - (long)_segments.Count * SegmentBytes));
            long charge = checked(count + SegmentAccountingBytes);
            if (!_budget.TryReserveResident(charge)) { Spill(end); return; }
            OperationMemoryBudget.HeavyLease? lease = null;
            byte[]? allocation = null;
            try
            {
                lease = OperationMemoryBudget.AcquireWorking(charge);
                allocation = new byte[count];
                lease.CommitAllocation();
                _segments.Add(new Segment(allocation, lease, charge));
                lease = null; allocation = null;
            }
            catch
            {
                if (allocation is not null) CryptographicOperations.ZeroMemory(allocation);
                lease?.Dispose(); _budget.ReleaseResident(charge); throw;
            }
        }
    }

    private void Spill(long requiredLength)
    {
        long needed = Math.Max(_length, _expectedLength ?? requiredLength);
        _policy.RequireCaptureCapacity(0, needed, copyInput: false);
        Directory.CreateDirectory(_policy.WorkingDirectory);
        BoundFileTransaction candidate = BoundFileTransaction.CreateNew(Path.Combine(_policy.WorkingDirectory,
            $".keep-vault-record-index.{Guid.NewGuid():N}"), 1, FileOptions.RandomAccess);
        _pendingFile = candidate;
        try
        {
            candidate.PrepareReadOnly();
            _policy.RequireWorkingFileVolume(candidate.Stream.SafeFileHandle);
            candidate.DeleteBound();
            long offset = 0;
            foreach (Segment segment in _segments)
            {
                int take = checked((int)Math.Min(segment.Bytes.Length, _length - offset));
                if (take <= 0) break;
                using IDisposable write = _policy.ReserveWorkingWrite(candidate.Stream.SafeFileHandle, take);
                RandomAccess.Write(candidate.Stream.SafeFileHandle, segment.Bytes.AsSpan(0, take), offset);
                offset += take;
            }
            candidate.Stream.Flush(true);
            if (candidate.Stream.Length != _length) throw new IOException("Index migration was incomplete.");
        }
        catch (Exception failure)
        {
            try { candidate.Dispose(); _pendingFile = null; }
            catch (Exception cleanup) { throw new AggregateException("Index migration and bound cleanup failed.", failure, cleanup); }
            throw;
        }
        _file = candidate; _pendingFile = null; // Only the complete copied record set becomes authoritative.
        ReleaseSegments();
    }

    private void Transfer(ReadOnlySpan<byte> input, Span<byte> output, long offset, bool write)
    {
        int copied = 0, total = write ? input.Length : output.Length;
        while (copied < total)
        {
            long position = checked(offset + copied);
            Segment segment = _segments[checked((int)(position / SegmentBytes))];
            int inside = checked((int)(position % SegmentBytes));
            int take = Math.Min(total - copied, segment.Bytes.Length - inside);
            if (write) input.Slice(copied, take).CopyTo(segment.Bytes.AsSpan(inside, take));
            else segment.Bytes.AsSpan(inside, take).CopyTo(output.Slice(copied, take));
            copied += take;
        }
    }

    private void ValidateLength()
    {
        if (_file is not null && _file.Stream.Length != _length) throw new IOException("The authenticated index length changed.");
    }
    private void RequireUsable()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_failed) throw new InvalidOperationException("The authenticated index failed closed.");
    }
    private void ReleaseSegments()
    {
        foreach (Segment segment in _segments) CryptographicOperations.ZeroMemory(segment.Bytes);
        while (_segments.Count != 0)
        {
            Segment segment = _segments[^1];
            CryptographicOperations.ZeroMemory(segment.Bytes);
            segment.Lease.Dispose(); _budget.ReleaseResident(segment.Charge);
            _segments.RemoveAt(_segments.Count - 1);
        }
    }
    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _failed = true;
            List<Exception> failures = [];
            try { _file?.Dispose(); _file = null; } catch (Exception failure) { failures.Add(failure); }
            try { _pendingFile?.Dispose(); _pendingFile = null; } catch (Exception failure) { failures.Add(failure); }
            try { ReleaseSegments(); } catch (Exception failure) { failures.Add(failure); }
            if (failures.Count != 0) throw new AggregateException("Authenticated metadata cleanup failed; ownership is retained for retry.", failures);
            _disposed = true;
        }
    }
}
