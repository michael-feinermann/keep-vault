using System.IO;
using System.Security.Cryptography;

namespace KalynaArchiver.Services;

/// <summary>Append, seal, then bounded authenticated reads of public recovery metadata.</summary>
internal sealed class RecoveryMetadataStream : Stream
{
    private const int ChunkBytes = RecoveryRecordTable<byte[]>.MaximumByteRecordLength;
    private readonly RecoveryRecordTable<byte[]> _chunks = new();
    private readonly byte[] _pending = new byte[ChunkBytes];
    private byte[]? _cache;
    private int _cacheIndex = -1;
    private int _pendingCount;
    private long _length;
    private long _position;
    private bool _sealed;
    private bool _disposed;
    private bool _failed;

    internal void Seal()
    {
        RequireUsable();
        if (_sealed) throw new InvalidOperationException("Metadata cannot be sealed twice.");
        FlushPending();
        _sealed = true;
        _position = 0;
    }

    private void FlushPending()
    {
        if (_pendingCount == 0) return;
        byte[] bytes = _pending.AsSpan(0, _pendingCount).ToArray();
        try { _chunks.Add(bytes); }
        finally { CryptographicOperations.ZeroMemory(bytes); CryptographicOperations.ZeroMemory(_pending); }
        _pendingCount = 0;
    }

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        RequireUsable();
        if (_sealed) throw new InvalidOperationException("Sealed metadata is immutable.");
        while (!buffer.IsEmpty)
        {
            int take = Math.Min(ChunkBytes - _pendingCount, buffer.Length);
            long nextLength = checked(_length + take);
            if (nextLength > ArchiveOperationPolicy.Current.MaxMetadataBytes)
                throw new IOException("Recovery metadata exceeds the approved byte budget.");
            buffer[..take].CopyTo(_pending.AsSpan(_pendingCount));
            _pendingCount += take;
            _length = nextLength;
            buffer = buffer[take..];
            if (_pendingCount == ChunkBytes) FlushPending();
        }
    }
    public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    { cancellationToken.ThrowIfCancellationRequested(); Write(buffer.Span); return ValueTask.CompletedTask; }
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override int Read(Span<byte> destination)
    {
        RequireUsable();
        if (!_sealed) throw new InvalidOperationException("Recovery metadata must be sealed before reading.");
        int requested = checked((int)Math.Min(destination.Length, _length - _position));
        int copied = 0;
        try
        {
        while (copied < requested)
        {
            int index = checked((int)(_position / ChunkBytes));
            if (_cacheIndex != index)
            {
                if (_cache is not null) CryptographicOperations.ZeroMemory(_cache);
                _cache = _chunks[index];
                _cacheIndex = index;
                int expectedLength = checked((int)Math.Min(ChunkBytes, _length - (long)index * ChunkBytes));
                if (_cache.Length != expectedLength) throw new InvalidDataException("Authenticated metadata chunk has an inconsistent length.");
            }
            int inside = checked((int)(_position % ChunkBytes));
            int take = Math.Min(requested - copied, _cache!.Length - inside);
            _cache.AsSpan(inside, take).CopyTo(destination[copied..]);
            copied += take;
            _position += take;
        }
        return copied;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(destination[..requested]);
            _failed = true;
            throw;
        }
    }
    private void RequireUsable()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_failed) throw new InvalidOperationException("Recovery metadata stream has failed closed.");
    }
    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    { cancellationToken.ThrowIfCancellationRequested(); return ValueTask.FromResult(Read(buffer.Span)); }
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    public override bool CanRead => _sealed && !_disposed && !_failed;
    public override bool CanSeek => _sealed && !_disposed && !_failed;
    public override bool CanWrite => !_sealed && !_disposed && !_failed;
    public override long Length { get { RequireUsable(); return _length; } }
    public override long Position
    {
        get { RequireUsable(); return _position; }
        set { RequireUsable(); if (!_sealed || value < 0 || value > _length) throw new ArgumentOutOfRangeException(nameof(value)); _position = value; }
    }
    public override long Seek(long offset, SeekOrigin origin)
    {
        Position = origin switch { SeekOrigin.Begin => offset, SeekOrigin.Current => checked(_position + offset),
            SeekOrigin.End => checked(_length + offset), _ => throw new ArgumentOutOfRangeException(nameof(origin)) };
        return _position;
    }
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Flush() { ObjectDisposedException.ThrowIf(_disposed, this); }
    protected override void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        {
            _failed = true;
            CryptographicOperations.ZeroMemory(_pending);
            if (_cache is not null) CryptographicOperations.ZeroMemory(_cache);
            _chunks.Dispose();
            _disposed = true;
        }
        base.Dispose(disposing);
    }
}
