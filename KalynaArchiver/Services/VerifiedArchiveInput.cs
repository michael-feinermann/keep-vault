using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using KalynaArchiver.Signing;
using Microsoft.Win32.SafeHandles;

namespace KalynaArchiver.Services;

internal readonly record struct VerifiedArchiveAuthentication(
    byte[] ExpectedSha3, byte[] ActualSha3, byte[] ExpectedSkein, byte[] ActualSkein);

internal enum VerifiedArchiveInputState
{
    Created, Capturing, CapturedUnverified, VerifyingGlobal, Verified, Consuming, Closed, Failed, Disposed,
}

/// <summary>
/// Disk-backed ciphertext capture or descriptor-bound plaintext input with an
/// authenticated disk index. Every read authenticates complete physical
/// ranges into a private buffer before copying the requested slice to the caller.
/// No raw handle or mapping is exposed to consumers.
/// </summary>
internal sealed class VerifiedArchiveInput : Stream, IPrivateSnapshotRandomAccess
{
    internal const int RangeBytes = 1024 * 1024;
    internal const int RecordBytes = 204;
    private const int TranscriptPrefixBytes = 44;
    private static readonly byte[] HmacDomain = LengthPrefix.Encode(
        "Kalyna-ZPAQ/v13/VerifiedArchiveInput/HMAC-SHA3-512");
    private const string SkeinDomain = "Kalyna-ZPAQ/v13/VerifiedArchiveInput/Skein-MAC-1024-1024";
    // Register before allocating protected state. A failed constructor or a
    // caller losing a closed input must not lose the owner of its RAM charge.
    private static readonly object OwnersGate = new();
    private static readonly HashSet<VerifiedArchiveInput> Owners = [];
    private readonly object _gate = new();
    private readonly object _positionGate = new();
    private readonly Queue<LockedSensitiveBuffer> _availableBuffers = new();
    private LockedSensitiveBuffer?[] _buffers = [];
    private SemaphoreSlim? _readSlots;
    private SemaphoreSlim? _ioSlots;
    private int _activeReads;
    private OperationMemoryBudget.Lease? _memory;
    private readonly CancellationTokenSource _closing = new();
    internal Action<long>? RangeVerifiedForTests;
    internal static Action? CaptureReadyForTests;
    private BoundFileTransaction? _spool;
    private BoundFileTransaction? _index;
    private RecoveryMetadataBudget? _metadataBudget;
    private long _reservedIndexBytes;
    private FileStream? _original;
    // Streams own these handles until every worker/reader has joined. Resolve
    // each handle once: FileStream.SafeFileHandle flushes its buffered cursor
    // and is therefore not a thread-safe accessor during parallel file I/O.
    private SafeFileHandle? _dataHandle;
    private SafeFileHandle? _indexHandle;
    private LockedSensitiveBuffer? _hmacKey;
    private LockedSensitiveBuffer? _skeinKey;
    private LockedSensitiveBuffer? _operationId;
    private long _length;
    private long _records;
    private long _position;
    private VerifiedArchiveInputState _state;

    private readonly ArchiveOperationPolicy _policy;
    private VerifiedArchiveInput(ArchiveOperationPolicy policy)
    {
        _policy = policy;
        lock (OwnersGate) Owners.Add(this);
    }

    internal static int RetainedOwnersForTests { get { lock (OwnersGate) return Owners.Count; } }

    internal static void RetryFailedCleanup()
    {
        VerifiedArchiveInput[] owners;
        lock (OwnersGate) owners = [.. Owners];
        List<Exception>? failures = null;
        foreach (VerifiedArchiveInput owner in owners)
        {
            if (owner.State != VerifiedArchiveInputState.Closed) continue;
            try { owner.Dispose(); }
            catch (Exception failure) { (failures ??= []).Add(failure); }
        }
        if (failures is not null)
            throw new AggregateException("A previous verified input still owns resources which could not be released.", failures);
    }

    internal VerifiedArchiveInputState State { get { lock (_gate) return _state; } }

    internal static Task<VerifiedArchiveInput> CaptureAsync(
        string path, ArchiveOperationPolicy? policy, CancellationToken cancellationToken) =>
        Task.Run(() => Capture(path, policy ?? ArchiveOperationPolicy.Current, copyCiphertext: true, cancellationToken), cancellationToken);

    internal static Task<VerifiedArchiveInput> CaptureOriginalAsync(
        string path, ArchiveOperationPolicy? policy, CancellationToken cancellationToken) =>
        Task.Run(() => Capture(path, policy ?? ArchiveOperationPolicy.Current, copyCiphertext: false, cancellationToken), cancellationToken);

    private static VerifiedArchiveInput Capture(string path, ArchiveOperationPolicy policy, bool copyCiphertext, CancellationToken token)
    {
        using IDisposable policyScope = policy.EnterScope();
        token.ThrowIfCancellationRequested();
        RetryFailedCleanup();
        string fullPath = Path.GetFullPath(path);
#if KEEPVAULT_MACOS
        FileStream source = MacSafeFileSystem.OpenReadNoSymlinks(fullPath);
#else
        FileStream source = SecureFile.OpenReadNoReparse(fullPath, FileShare.Read, randomAccess: true);
#endif
        bool retainedOriginal = false;
        try
        {
        SafeFileHandle sourceHandle = source.SafeFileHandle;
#if KEEPVAULT_MACOS
        MacFileIdentity sourceIdentity = MacSafeFileSystem.GetIdentity(sourceHandle);
#endif
        _ = NativePathResolver.RequireCanonicalFilePath(sourceHandle, fullPath, "Verified archive input");
        if (copyCiphertext)
        {
            Span<byte> magic = stackalloc byte[7];
            ReadExactlyAt(sourceHandle, magic, 0);
            if (!magic.SequenceEqual("KZPAQ2\0"u8))
                throw new InvalidDataException("Verified ciphertext capture requires an encrypted Keep Vault container.");
        }
        long length = RandomAccess.GetLength(sourceHandle);
        long records = GetRecordCount(length);
        long indexLength = checked(records * RecordBytes);
        policy.RequireCaptureCapacity(length, indexLength, copyCiphertext);
        Directory.CreateDirectory(policy.WorkingDirectory);
        var input = new VerifiedArchiveInput(policy);
        try
        {
            input._state = VerifiedArchiveInputState.Capturing;
            input._memory = OperationMemoryBudget.AcquireAsync(policy, token).AsTask().GetAwaiter().GetResult();
            using IDisposable memoryScope = input._memory.EnterScope();
            token = input._memory.Token;
            input._metadataBudget = RecoveryMetadataBudget.Capture(policy.MaxMetadataBytes);
            input._metadataBudget.Reserve(indexLength);
            input._reservedIndexBytes = indexLength;
            input._length = length;
            input._records = records;
            input._hmacKey = LockedSensitiveBuffer.Create(64);
            input._skeinKey = LockedSensitiveBuffer.Create(128);
            input._operationId = LockedSensitiveBuffer.Create(32);
            RandomNumberGenerator.Fill(input._hmacKey.Bytes);
            RandomNumberGenerator.Fill(input._skeinKey.Bytes);
            RandomNumberGenerator.Fill(input._operationId.Bytes);
            if (copyCiphertext) input._spool = CreatePrivateSpool(policy.WorkingDirectory, "ciphertext");
            else input._original = source;
            input._index = CreatePrivateSpool(policy.WorkingDirectory, "index");
            input._dataHandle = input._spool?.Stream.SafeFileHandle ?? sourceHandle;
            input._indexHandle = input._index.Stream.SafeFileHandle;
            if (input._spool is not null) policy.RequireWorkingFileVolume(input._dataHandle);
            policy.RequireWorkingFileVolume(input._indexHandle);
            // One fixed private range buffer per admitted worker. Archive length
            // only changes disk offsets, never the number of live buffers/tasks.
            using CpuWorkBudget.Lease cpu = CpuWorkBudget.AcquireAsync(policy.MaxCpuWorkers,
                checked((int)Math.Max(1, Math.Min(records, policy.MaxCpuWorkers))), token).AsTask().GetAwaiter().GetResult();
            using IDisposable cpuScope = cpu.EnterScope();
            int workers = cpu.Workers;
            int buffers = checked((int)Math.Max(1, Math.Min(records, policy.MaxCpuWorkers)));
            input._buffers = new LockedSensitiveBuffer?[buffers];
            input._readSlots = new SemaphoreSlim(buffers, buffers);
            input._ioSlots = new SemaphoreSlim(policy.MaxIoRequests, policy.MaxIoRequests);
            for (int worker = 0; worker < buffers; worker++)
            {
                input._buffers[worker] = LockedSensitiveBuffer.Create(RangeBytes + TranscriptPrefixBytes);
                input._availableBuffers.Enqueue(input._buffers[worker]!);
            }
            CaptureReadyForTests?.Invoke();
            if (input._spool is not null) RandomAccess.SetLength(input._dataHandle, length);
            RandomAccess.SetLength(input._indexHandle, indexLength);
            long nextRange = -1;
            Parallel.For(0, workers, new ParallelOptions { MaxDegreeOfParallelism = workers, CancellationToken = token }, worker =>
            {
                Span<byte> record = stackalloc byte[RecordBytes];
                LockedSensitiveBuffer buffer = input._buffers[worker]!;
                for (;;)
                {
                    token.ThrowIfCancellationRequested();
                    long index = Interlocked.Increment(ref nextRange);
                    if (index >= records) break;
                    int count = input.ExpectedRangeLength(index);
                    Span<byte> captured = buffer.Bytes.AsSpan(TranscriptPrefixBytes, count);
                    input._ioSlots.Wait(token);
                    try { ReadExactlyAt(sourceHandle, captured, checked(index * RangeBytes)); }
                    finally { input._ioSlots.Release(); }
                    input.ComputeRecord(index, count, record, buffer.Bytes);
                    input._ioSlots.Wait(token);
                    try
                    {
                        if (input._spool is not null)
                            RandomAccess.Write(input._dataHandle, captured, checked(index * RangeBytes));
                        RandomAccess.Write(input._indexHandle, record, checked(index * RecordBytes));
                    }
                    finally { input._ioSlots.Release(); }
                    OperationMemoryBudget.ReportProgress(count);
                    CryptographicOperations.ZeroMemory(buffer.Bytes);
                }
            });
            token.ThrowIfCancellationRequested();
            Span<byte> eofProbe = stackalloc byte[1];
            if (RandomAccess.Read(sourceHandle, eofProbe, length) != 0 || RandomAccess.GetLength(sourceHandle) != length)
                throw new IOException("The source length changed during verified capture.");
#if KEEPVAULT_MACOS
            MacSafeFileSystem.RequirePathStillNamesHandle(sourceHandle, fullPath);
            if (!sourceIdentity.SameObjectAndMetadata(MacSafeFileSystem.GetIdentity(sourceHandle)))
                throw new IOException("The source object changed during verified capture.");
#endif
            input._spool?.Stream.Flush(flushToDisk: true);
            input._index.Stream.Flush(flushToDisk: true);
            input.ValidateLengths();
            foreach (LockedSensitiveBuffer? buffer in input._buffers) CryptographicOperations.ZeroMemory(buffer!.Bytes);
            input._state = VerifiedArchiveInputState.CapturedUnverified;
            retainedOriginal = !copyCiphertext;
            return input;
        }
        catch (Exception failure)
        {
            input._state = VerifiedArchiveInputState.Failed;
            try { input.Dispose(); }
            catch (Exception cleanupFailure)
            {
                throw new AggregateException("Verified capture failed and its resources could not all be released.", failure, cleanupFailure);
            }
            throw;
        }
        }
        finally { if (!retainedOriginal) source.Dispose(); }
    }

    private static BoundFileTransaction CreatePrivateSpool(string directory, string purpose)
    {
        BoundFileTransaction file = BoundFileTransaction.CreateNew(
            Path.Combine(directory, $".keep-vault-{purpose}.{Guid.NewGuid():N}"), 1, FileOptions.RandomAccess);
        try
        {
            // unlink on macOS; object-bound delete-on-close on Windows. This is
            // cleanup, not the security proof: existing writers are covered by MACs.
            file.DeleteBound();
            return file;
        }
        catch { file.Dispose(); throw; }
    }

    internal async Task VerifyGloballyAsync(
        Func<Stream, CancellationToken, Task<VerifiedArchiveAuthentication>> verifier,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(verifier);
        lock (_gate)
        {
            RequireState(VerifiedArchiveInputState.CapturedUnverified);
            _state = VerifiedArchiveInputState.VerifyingGlobal;
            _position = 0;
        }
        VerifiedArchiveAuthentication result = default;
        try
        {
            using IDisposable policyScope = _policy.EnterScope();
            using IDisposable? memoryScope = _memory?.EnterScope();
            using var verificationCancellation = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken, _closing.Token, _memory?.Token ?? CancellationToken.None);
            cancellationToken = verificationCancellation.Token;
            cancellationToken.ThrowIfCancellationRequested();
            using var view = new VerificationView(this);
            result = await verifier(view, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            bool hmac = result.ExpectedSha3 is { Length: 64 } && result.ActualSha3 is { Length: 64 }
                && CryptographicOperations.FixedTimeEquals(result.ExpectedSha3, result.ActualSha3);
            bool skein = result.ExpectedSkein is { Length: 128 } && result.ActualSkein is { Length: 128 }
                && CryptographicOperations.FixedTimeEquals(result.ExpectedSkein, result.ActualSkein);
            if (!(hmac & skein)) throw new CryptographicException("Wrong password or manipulated container.");
            lock (_gate)
            {
                RequireState(VerifiedArchiveInputState.VerifyingGlobal);
                ValidateLengths();
                _position = 0;
                _state = VerifiedArchiveInputState.Verified;
            }
        }
        catch
        {
            lock (_gate) if (_state is not (VerifiedArchiveInputState.Closed or VerifiedArchiveInputState.Disposed))
                _state = VerifiedArchiveInputState.Failed;
            throw;
        }
        finally
        {
            if (result.ExpectedSha3 is not null) CryptographicOperations.ZeroMemory(result.ExpectedSha3);
            if (result.ActualSha3 is not null) CryptographicOperations.ZeroMemory(result.ActualSha3);
            if (result.ExpectedSkein is not null) CryptographicOperations.ZeroMemory(result.ExpectedSkein);
            if (result.ActualSkein is not null) CryptographicOperations.ZeroMemory(result.ActualSkein);
        }
    }

    internal static long GetRecordCount(long length)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        // Avoid length + RangeBytes - 1, which overflows near Int64.MaxValue.
        return length / RangeBytes + (length % RangeBytes == 0 ? 0 : 1);
    }

    private int ExpectedRangeLength(long index)
    {
        if (index < 0 || index >= _records) throw new InvalidDataException("Invalid verified range index.");
        long offset = checked(index * RangeBytes);
        return checked((int)Math.Min(RangeBytes, _length - offset));
    }

    private void ComputeRecord(long index, int count, Span<byte> record, Span<byte> transcript)
    {
        Span<byte> message = transcript[..(TranscriptPrefixBytes + count)];
        _operationId!.Bytes.CopyTo(message);
        BinaryPrimitives.WriteInt64BigEndian(message[32..], index);
        BinaryPrimitives.WriteInt32BigEndian(message[40..], count);
        BinaryPrimitives.WriteInt64BigEndian(record, index);
        BinaryPrimitives.WriteInt32BigEndian(record[8..], count);
        ComputeLocalTags(_hmacKey!.Bytes, _skeinKey!.Bytes, message, record[12..]);
    }

    internal static void ComputeLocalTags(ReadOnlySpan<byte> hmacKey, ReadOnlySpan<byte> skeinKey,
        ReadOnlySpan<byte> transcript, Span<byte> tags)
    {
        if (hmacKey.Length != 64 || skeinKey.Length != 128 || tags.Length != 192
            || transcript.Length <= TranscriptPrefixBytes || transcript.Length > TranscriptPrefixBytes + RangeBytes
            || BinaryPrimitives.ReadInt64BigEndian(transcript[32..]) < 0
            || BinaryPrimitives.ReadInt32BigEndian(transcript[40..]) != transcript.Length - TranscriptPrefixBytes)
            throw new ArgumentException("Invalid local range authentication parameters.");
        using (var hmac = new HmacSha3_512(hmacKey))
        {
            hmac.AppendData(HmacDomain);
            hmac.AppendData(transcript);
            hmac.GetHashAndReset(tags[..64]);
        }
        KeyedSkein1024.Compute(skeinKey, SkeinDomain, transcript, tags[64..]);
    }

    private void ValidateLengths()
    {
        if (RandomAccess.GetLength(_dataHandle!) != _length || RandomAccess.GetLength(_indexHandle!) != checked(_records * RecordBytes))
            throw new IOException("The verified spool or range index was truncated or extended.");
    }

    private int ReadProtected(Span<byte> destination, long offset, bool verification, CancellationToken token)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        lock (_gate) RequireLiveContext();
        using var readCancellation = CancellationTokenSource.CreateLinkedTokenSource(token, _closing.Token,
            _memory?.Token ?? CancellationToken.None);
        token = readCancellation.Token;
        using IDisposable policyScope = _policy.EnterScope();
        using IDisposable? memoryScope = _memory?.EnterScope();
        using CpuWorkBudget.Lease? cpu = CpuWorkBudget.IsOwnedByCurrentContext ? null
            : CpuWorkBudget.AcquireAsync(_policy.MaxCpuWorkers, 1, token).AsTask().GetAwaiter().GetResult();
        using IDisposable? cpuScope = cpu?.EnterScope();
        _readSlots!.Wait(token);
        LockedSensitiveBuffer? privateBuffer = null;
        int requested = 0;
        try
        {
            lock (_gate)
            {
                if (verification) RequireState(VerifiedArchiveInputState.VerifyingGlobal);
                else
                {
                    if (_state is not (VerifiedArchiveInputState.Verified or VerifiedArchiveInputState.Consuming))
                        throw new InvalidOperationException("Archive bytes are unavailable before both global MACs pass.");
                    _state = VerifiedArchiveInputState.Consuming;
                }
                requested = checked((int)Math.Min(destination.Length, Math.Max(0, _length - offset)));
                privateBuffer = _availableBuffers.Dequeue();
                _activeReads++;
            }
            int copied = 0;
            Span<byte> stored = stackalloc byte[RecordBytes];
            Span<byte> actual = stackalloc byte[RecordBytes];
            while (copied < requested)
            {
                token.ThrowIfCancellationRequested();
                long position = checked(offset + copied);
                long index = position / RangeBytes;
                int inside = checked((int)(position % RangeBytes));
                int count = ExpectedRangeLength(index);
                Span<byte> bytes = privateBuffer.Bytes.AsSpan(TranscriptPrefixBytes, count);
                _ioSlots!.Wait(token);
                try
                {
                    ValidateLengths();
                    ReadExactlyAt(_dataHandle!, bytes, checked(index * RangeBytes));
                    ReadExactlyAt(_indexHandle!, stored, checked(index * RecordBytes));
                }
                finally { _ioSlots.Release(); }
                // Neither untrusted index field determines an allocation or offset.
                if (BinaryPrimitives.ReadInt64BigEndian(stored) != index
                    || BinaryPrimitives.ReadInt32BigEndian(stored[8..]) != count)
                    throw new CryptographicException("The verified range record has an invalid position or length.");
                ComputeRecord(index, count, actual, privateBuffer.Bytes);
                bool hmac = CryptographicOperations.FixedTimeEquals(stored.Slice(12, 64), actual.Slice(12, 64));
                bool skein = CryptographicOperations.FixedTimeEquals(stored.Slice(76, 128), actual.Slice(76, 128));
                if (!(hmac & skein)) throw new CryptographicException("The captured archive range changed.");
                RangeVerifiedForTests?.Invoke(index);
                int take = Math.Min(requested - copied, count - inside);
                bytes.Slice(inside, take).CopyTo(destination[copied..]);
                copied += take;
                OperationMemoryBudget.ReportProgress(take);
            }
            _ioSlots!.Wait(token);
            try { ValidateLengths(); }
            finally { _ioSlots.Release(); }
            lock (_gate)
            {
                if (verification) RequireState(VerifiedArchiveInputState.VerifyingGlobal);
                else if (_state is not (VerifiedArchiveInputState.Verified or VerifiedArchiveInputState.Consuming))
                    throw new InvalidOperationException("The verified input closed or failed while a read was pending.");
            }
            return copied;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(destination[..requested]);
            if (privateBuffer is not null)
                lock (_gate) if (_state is not (VerifiedArchiveInputState.Closed or VerifiedArchiveInputState.Disposed))
                    _state = VerifiedArchiveInputState.Failed;
            throw;
        }
        finally
        {
            if (privateBuffer is not null)
            {
                CryptographicOperations.ZeroMemory(privateBuffer.Bytes);
                lock (_gate)
                {
                    _availableBuffers.Enqueue(privateBuffer);
                    _activeReads--;
                    Monitor.PulseAll(_gate);
                }
            }
            _readSlots.Release();
        }
    }

    private static void ReadExactlyAt(SafeFileHandle handle, Span<byte> destination, long offset)
    {
        int read = 0;
        while (read < destination.Length)
        {
            int n = RandomAccess.Read(handle, destination[read..], checked(offset + read));
            if (n == 0) throw new EndOfStreamException("A captured archive range or index record is missing.");
            read += n;
        }
    }

    public ValueTask<int> ReadAtAsync(Memory<byte> destination, long offset, CancellationToken cancellationToken) =>
        ValueTask.FromResult(ReadProtected(destination.Span, offset, false, cancellationToken));

    public override int Read(Span<byte> buffer)
    {
        lock (_positionGate)
        {
            int count = ReadProtected(buffer, _position, false, CancellationToken.None);
            _position = checked(_position + count);
            return count;
        }
    }
    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        lock (_positionGate)
        {
            int count = ReadProtected(buffer.Span, _position, false, cancellationToken);
            _position = checked(_position + count);
            return ValueTask.FromResult(count);
        }
    }
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    public override bool CanRead => State is VerifiedArchiveInputState.Verified or VerifiedArchiveInputState.Consuming;
    public override bool CanSeek => State is not (VerifiedArchiveInputState.Disposed or VerifiedArchiveInputState.Failed or VerifiedArchiveInputState.Closed);
    public override bool CanWrite => false;
    public override long Length { get { lock (_gate) { RequireLiveContext(); return _length; } } }
    public override long Position
    {
        get { lock (_positionGate) lock (_gate) { RequireLiveContext(); return _position; } }
        set { lock (_positionGate) lock (_gate) { RequireLiveContext(); if (value < 0 || value > _length) throw new ArgumentOutOfRangeException(nameof(value)); _position = value; } }
    }
    public override long Seek(long offset, SeekOrigin origin)
    {
        lock (_positionGate) lock (_gate)
        {
            Position = origin switch { SeekOrigin.Begin => offset, SeekOrigin.Current => checked(_position + offset),
                SeekOrigin.End => checked(_length + offset), _ => throw new ArgumentOutOfRangeException(nameof(origin)) };
            return _position;
        }
    }
    public override void Flush() { }
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    private void RequireState(VerifiedArchiveInputState expected)
    {
        if (_state != expected) throw new InvalidOperationException($"Verified input state {_state}; required {expected}.");
    }

    private void RequireLiveContext()
    {
        ObjectDisposedException.ThrowIf(_state is VerifiedArchiveInputState.Disposed or VerifiedArchiveInputState.Closed, this);
        if (_state == VerifiedArchiveInputState.Failed)
            throw new InvalidOperationException("The verified input failed and cannot be reused.");
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) lock (_gate)
        {
            if (_state == VerifiedArchiveInputState.Disposed) return;
            _state = VerifiedArchiveInputState.Closed;
            _closing.Cancel();
            // No key or buffer can be released until all already admitted
            // parallel readers have stopped. Waiting releases the state gate.
            while (_activeReads > 0) Monitor.Wait(_gate);
            foreach (LockedSensitiveBuffer? buffer in _buffers) buffer?.ZeroForDisposal();
            _hmacKey?.ZeroForDisposal();
            _skeinKey?.ZeroForDisposal();
            _operationId?.ZeroForDisposal();
            // Retain owners in Closed after a cleanup failure. Reads stay
            // forbidden, while a later Dispose can retry every failed resource.
            SecureMemory.DisposeAll([.. _buffers, _hmacKey, _skeinKey, _operationId, _spool, _index, _original]);
            _metadataBudget?.Release(_reservedIndexBytes);
            _reservedIndexBytes = 0;
            _metadataBudget = null;
            _buffers = []; _availableBuffers.Clear(); _hmacKey = null; _skeinKey = null; _operationId = null;
            _spool = null; _index = null; _original = null;
            _dataHandle = null; _indexHandle = null;
            _memory?.Dispose(); _memory = null;
            _state = VerifiedArchiveInputState.Disposed;
            lock (OwnersGate) Owners.Remove(this);
        }
        base.Dispose(disposing);
    }

    private sealed class VerificationView(VerifiedArchiveInput owner) : Stream, IPrivateSnapshotRandomAccess
    {
        private bool _closed;
        public override bool CanRead => !_closed;
        public override bool CanSeek => !_closed;
        public override bool CanWrite => false;
        public override long Length { get { ObjectDisposedException.ThrowIf(_closed, this); return owner.Length; } }
        public override long Position
        {
            get { ObjectDisposedException.ThrowIf(_closed, this); return owner.Position; }
            set { ObjectDisposedException.ThrowIf(_closed, this); owner.Position = value; }
        }
        public override int Read(Span<byte> buffer)
        {
            ObjectDisposedException.ThrowIf(_closed, this);
            lock (owner._positionGate)
            {
                int count = owner.ReadProtected(buffer, owner._position, true, CancellationToken.None);
                owner._position = checked(owner._position + count);
                return count;
            }
        }
        public ValueTask<int> ReadAtAsync(Memory<byte> buffer, long offset, CancellationToken cancellationToken)
        {
            ObjectDisposedException.ThrowIf(_closed, this);
            return ValueTask.FromResult(owner.ReadProtected(buffer.Span, offset, true, cancellationToken));
        }
        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(_closed, this);
            lock (owner._positionGate)
            {
                int count = owner.ReadProtected(buffer.Span, owner._position, true, cancellationToken);
                owner._position = checked(owner._position + count);
                return ValueTask.FromResult(count);
            }
        }
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
        public override long Seek(long offset, SeekOrigin origin)
        {
            ObjectDisposedException.ThrowIf(_closed, this);
            return owner.Seek(offset, origin);
        }
        public override void Flush() { }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { _closed = true; base.Dispose(disposing); }
    }
}
