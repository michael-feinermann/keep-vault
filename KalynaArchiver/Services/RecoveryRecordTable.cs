using System.Buffers.Binary;
using System.Collections;
using System.IO;
using System.Security.Cryptography;
using KalynaArchiver.Signing;

namespace KalynaArchiver.Services;

/// <summary>
/// Append-only, bounded-memory recovery metadata. A complete fixed-width record
/// is authenticated into private memory before any value is decoded or returned.
/// The backing file contains public digests/coordinates, never archive plaintext.
/// </summary>
internal sealed class RecoveryRecordTable<T> : IReadOnlyList<T>, IDisposable
{
    private const int DigestBytes = 192;
    internal const int MaximumByteRecordLength = 65536;
    private const int PrefixBytes = 48;
    private const int TagBytes = 192;
    private static readonly byte[] HmacDomain = LengthPrefix.Encode("Kalyna-ZPAQ/v13/RecoveryRecordTable/HMAC-SHA3-512");
    private const string SkeinDomain = "Kalyna-ZPAQ/v13/RecoveryRecordTable/Skein-MAC-1024-1024";
    private readonly object _gate = new();
    private readonly ArchiveOperationPolicy _policy;
    private readonly RecoveryMetadataBudget _budget;
    private long _reservedBytes;
    private readonly int _kind;
    private readonly int _payloadBytes;
    private readonly int _recordBytes;
    private BoundFileTransaction? _file;
    private LockedSensitiveBuffer? _hmacKey;
    private LockedSensitiveBuffer? _skeinKey;
    private LockedSensitiveBuffer? _operationId;
    private LockedSensitiveBuffer? _record;
    private int _count;
    private bool _failed;
    private bool _disposed;

    internal RecoveryRecordTable(ArchiveOperationPolicy? policy = null)
    {
        _policy = policy ?? ArchiveOperationPolicy.Current;
        _budget = RecoveryMetadataBudget.Capture(_policy.MaxMetadataBytes);
        _kind = typeof(T) == typeof(string) ? 1 : typeof(T) == typeof(RecoveryParityShard) ? 2 : typeof(T) == typeof(byte[]) ? 3
            : throw new NotSupportedException("Only fixed-width recovery digest, parity and bounded byte records are supported.");
        _payloadBytes = _kind switch { 1 => DigestBytes, 2 => 20 + DigestBytes, _ => 4 + MaximumByteRecordLength };
        _recordBytes = checked(PrefixBytes + _payloadBytes + TagBytes);
        try
        {
            _hmacKey = LockedSensitiveBuffer.Create(64);
            _skeinKey = LockedSensitiveBuffer.Create(128);
            _operationId = LockedSensitiveBuffer.Create(32);
            _record = LockedSensitiveBuffer.Create(_recordBytes);
            RandomNumberGenerator.Fill(_hmacKey.Bytes);
            RandomNumberGenerator.Fill(_skeinKey.Bytes);
            RandomNumberGenerator.Fill(_operationId.Bytes);
            Directory.CreateDirectory(_policy.WorkingDirectory);
            _file = BoundFileTransaction.CreateNew(Path.Combine(_policy.WorkingDirectory,
                $".keep-vault-recovery-index.{Guid.NewGuid():N}"), 1, FileOptions.RandomAccess);
            _policy.RequireWorkingFileVolume(_file.Stream.SafeFileHandle);
            _file.DeleteBound();
        }
        catch { Dispose(); throw; }
    }

    public int Count { get { lock (_gate) { RequireUsable(); return _count; } } }
    internal long StorageBytes { get { lock (_gate) { RequireUsable(); return checked((long)_count * _recordBytes); } } }

    internal void Add(T value)
    {
        lock (_gate)
        {
            RequireUsable();
            try
            {
                int next = checked(_count + 1);
                long nextLength = checked((long)next * _recordBytes);
                if (nextLength > _policy.MaxMetadataBytes)
                    throw new IOException("Recovery metadata exceeds the approved disk budget.");
                ValidateLength();
                Span<byte> record = _record!.Bytes;
                _operationId!.Bytes.CopyTo(record);
                BinaryPrimitives.WriteInt64BigEndian(record[32..], _count);
                BinaryPrimitives.WriteInt32BigEndian(record[40..], _kind);
                BinaryPrimitives.WriteInt32BigEndian(record[44..], _payloadBytes);
                Encode(value, record.Slice(PrefixBytes, _payloadBytes));
                ComputeTags(record[..(PrefixBytes + _payloadBytes)], record[(PrefixBytes + _payloadBytes)..]);
                _file!.Stream.Position = checked((long)_count * _recordBytes);
                _budget.Reserve(_recordBytes);
                try
                {
                    _file.Stream.Write(record);
                    _reservedBytes = checked(_reservedBytes + _recordBytes);
                }
                catch { _budget.Release(_recordBytes); throw; }
                _count = next;
                ValidateLength();
            }
            catch { _failed = true; throw; }
            finally { if (_record is not null) CryptographicOperations.ZeroMemory(_record.Bytes); }
        }
    }

    public T this[int index]
    {
        get
        {
            lock (_gate)
            {
                RequireUsable();
                if ((uint)index >= (uint)_count) throw new ArgumentOutOfRangeException(nameof(index));
                try
                {
                    ValidateLength();
                    Span<byte> record = _record!.Bytes;
                    _file!.Stream.Position = checked((long)index * _recordBytes);
                    _file.Stream.ReadExactly(record);
                    Span<byte> expected = stackalloc byte[TagBytes];
                    ComputeTags(record[..(PrefixBytes + _payloadBytes)], expected);
                    bool first = CryptographicOperations.FixedTimeEquals(record.Slice(PrefixBytes + _payloadBytes, 64), expected[..64]);
                    bool second = CryptographicOperations.FixedTimeEquals(record.Slice(PrefixBytes + _payloadBytes + 64, 128), expected[64..]);
                    bool identity = CryptographicOperations.FixedTimeEquals(record[..32], _operationId!.Bytes)
                        && BinaryPrimitives.ReadInt64BigEndian(record[32..]) == index
                        && BinaryPrimitives.ReadInt32BigEndian(record[40..]) == _kind
                        && BinaryPrimitives.ReadInt32BigEndian(record[44..]) == _payloadBytes;
                    if (!(first & second & identity)) throw new CryptographicException("Recovery metadata changed in the private working file.");
                    ValidateLength();
                    return Decode(record.Slice(PrefixBytes, _payloadBytes));
                }
                catch { _failed = true; throw; }
                finally { if (_record is not null) CryptographicOperations.ZeroMemory(_record.Bytes); }
            }
        }
    }

    private void ComputeTags(ReadOnlySpan<byte> transcript, Span<byte> tags)
    {
        using (var hmac = new HmacSha3_512(_hmacKey!.Bytes))
        {
            hmac.AppendData(HmacDomain);
            hmac.AppendData(transcript);
            hmac.GetHashAndReset(tags[..64]);
        }
        KeyedSkein1024.Compute(_skeinKey!.Bytes, SkeinDomain, transcript, tags[64..]);
    }

    private void Encode(T value, Span<byte> payload)
    {
        if (_kind == 1) { EncodeDigest((string)(object)value!, payload); return; }
        if (_kind == 3)
        {
            byte[] bytes = (byte[])(object)value!;
            if (bytes.Length > MaximumByteRecordLength) throw new InvalidDataException("Recovery byte record exceeds 64 KiB.");
            payload.Clear();
            BinaryPrimitives.WriteInt32BigEndian(payload, bytes.Length);
            bytes.CopyTo(payload[4..]);
            return;
        }
        RecoveryParityShard shard = (RecoveryParityShard)(object)value!;
        if (shard.Stripe < 0 || shard.ParityIndex < 0 || shard.Offset < 0 || shard.Length < 0)
            throw new InvalidDataException("Recovery parity coordinates cannot be negative.");
        BinaryPrimitives.WriteInt32BigEndian(payload, shard.Stripe);
        BinaryPrimitives.WriteInt32BigEndian(payload[4..], shard.ParityIndex);
        BinaryPrimitives.WriteInt64BigEndian(payload[8..], shard.Offset);
        BinaryPrimitives.WriteInt32BigEndian(payload[16..], shard.Length);
        EncodeDigest(shard.Digest, payload[20..]);
    }

    private static void EncodeDigest(string value, Span<byte> output)
    {
        if (value is not { Length: 261 } || value[88] != ':'
            || !Convert.TryFromBase64Chars(value.AsSpan(0, 88), output[..64], out int first) || first != 64
            || !Convert.TryFromBase64Chars(value.AsSpan(89), output[64..], out int second) || second != 128
            || !string.Equals(DecodeDigest(output), value, StringComparison.Ordinal))
            throw new InvalidDataException("A recovery digest must be canonical base64(SHA3-512):base64(Skein-1024).");
    }

    private static string DecodeDigest(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value[..64]) + ":" + Convert.ToBase64String(value[64..]);

    private T Decode(ReadOnlySpan<byte> payload)
    {
        if (_kind == 1) return (T)(object)DecodeDigest(payload);
        if (_kind == 3)
        {
            int length = BinaryPrimitives.ReadInt32BigEndian(payload);
            if ((uint)length > MaximumByteRecordLength || payload[(4 + length)..].IndexOfAnyExcept((byte)0) >= 0)
                throw new InvalidDataException("Recovery byte record has invalid length or padding.");
            return (T)(object)payload.Slice(4, length).ToArray();
        }
        return (T)(object)new RecoveryParityShard(BinaryPrimitives.ReadInt32BigEndian(payload),
            BinaryPrimitives.ReadInt32BigEndian(payload[4..]), BinaryPrimitives.ReadInt64BigEndian(payload[8..]),
            BinaryPrimitives.ReadInt32BigEndian(payload[16..]), DecodeDigest(payload[20..]));
    }

    private void RequireUsable()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_failed) throw new InvalidOperationException("The recovery metadata table has failed closed.");
    }

    private void ValidateLength()
    {
        if (_file!.Stream.Length != checked((long)_count * _recordBytes))
            throw new IOException("The recovery metadata file was truncated or extended.");
    }

    public IEnumerator<T> GetEnumerator()
    {
        int count = Count;
        for (int index = 0; index < count; ++index) yield return this[index];
    }
    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _failed = true;
            List<Exception> failures = [];
            // Erase every sensitive member before the first unlock, and retain
            // owners on any failure so Dispose can be retried after a denied unlock.
            try { SecureMemory.ZeroAndDisposeAll(_record, _operationId, _skeinKey, _hmacKey); }
            catch (Exception failure) { failures.Add(failure); }
            try
            {
                _file?.Dispose();
                _file = null;
                _budget.Release(_reservedBytes);
                _reservedBytes = 0;
            }
            catch (Exception failure) { failures.Add(failure); }
            if (failures.Count != 0)
                throw new AggregateException("Recovery metadata cleanup failed; retained owners allow a retry.", failures);
            _disposed = true;
        }
    }
}
