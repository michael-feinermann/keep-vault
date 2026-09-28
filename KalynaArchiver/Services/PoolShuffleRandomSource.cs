using System.Buffers.Binary;
using System.Security.Cryptography;

namespace KalynaArchiver.Services;

internal enum EntropyRandomRole { PoolRouting, PoolShuffleRound1, PoolShuffleRound2, OutputXor }
internal enum EntropyPreparationKind { SingleRound, DualRound }

/// <summary>A single pool/round owns this cache; its remaining OS bytes are never reused.</summary>
internal sealed class PoolShuffleRandomSource : IDisposable
{
    private readonly LockedSensitiveBuffer _buffer;
    private readonly Action<byte[], EntropyRandomRole> _fill;
    private readonly EntropyRandomRole _role;
    private int _cursor;

    internal PoolShuffleRandomSource(EntropyRandomRole role, Action<byte[], EntropyRandomRole> fill, int bufferBytes = 4096)
    {
        if (role is not (EntropyRandomRole.PoolShuffleRound1 or EntropyRandomRole.PoolShuffleRound2)
            || bufferBytes < 8 || bufferBytes % 8 != 0)
            throw new ArgumentOutOfRangeException(nameof(role));
        _role = role;
        _fill = fill;
        _buffer = LockedSensitiveBuffer.Create(bufferBytes);
        _cursor = bufferBytes;
    }

    internal ulong NextBelow(ulong bound, CancellationToken token)
    {
        if (bound == 0 || bound > long.MaxValue) throw new ArgumentOutOfRangeException(nameof(bound));
        int width = bound <= (1UL << 32) ? sizeof(uint) : sizeof(ulong);
        UInt128 space = (UInt128)1 << (width * 8);
        UInt128 limit = space - space % bound;
        for (int attempt = 0; attempt < 128; ++attempt)
        {
            token.ThrowIfCancellationRequested();
            if (_cursor > _buffer.Bytes.Length - width)
            {
                CryptographicOperations.ZeroMemory(_buffer.Bytes);
                _fill(_buffer.Bytes, _role);
                _cursor = 0;
            }
            Span<byte> candidate = _buffer.Bytes.AsSpan(_cursor, width);
            ulong value = width == sizeof(uint) ? BinaryPrimitives.ReadUInt32LittleEndian(candidate) : BinaryPrimitives.ReadUInt64LittleEndian(candidate);
            CryptographicOperations.ZeroMemory(candidate);
            _cursor += width;
            if ((UInt128)value < limit) return value % bound;
        }
        throw new CryptographicException("The entropy shuffle random source exceeded its rejection budget.");
    }

    internal void Shuffle(SensitiveMouseRecordStore records, CancellationToken token)
    {
        for (long index = records.Count - 1; index > 0; --index)
        {
            token.ThrowIfCancellationRequested();
            long other = checked((long)NextBelow(checked((ulong)index + 1), token));
            if (index == other) continue;
            long saved = records.ReadIndex(index);
            records.WriteIndex(index, records.ReadIndex(other));
            records.WriteIndex(other, saved);
        }
    }

    public void Dispose() => EntropyMixer.DisposeEntropyOwners(null, "Shuffle random cache cleanup failed.", _buffer);
}
