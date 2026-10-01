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
    Created, BoundUntrusted, PreflightBoundedHeader, IndexingAndGlobalVerify, Capturing, CapturedUnverified,
    LocalCaptureSealed, PlainIntegrityVerified, VerifyingGlobal, Verified, Consuming, Closed, Failed, Disposed,
}

/// <summary>
/// Descriptor-bound original input with a RAM-first authenticated range index.
/// The fused first pass binds its bounded header and both global transcripts. Every read authenticates complete physical
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
    private readonly Dictionary<LockedSensitiveBuffer, long> _verifiedBufferRanges = [];
    private long _secondPassBytes;
    internal long SecondPassBytesForTests { get { lock (_gate) return _secondPassBytes; } }
    private LockedSensitiveBuffer?[] _buffers = [];
    private SemaphoreSlim? _readSlots;
    private SemaphoreSlim? _ioSlots;
    private int _activeReads;
    private OperationMemoryBudget.Lease? _memory;
    private readonly CancellationTokenSource _closing = new();
    internal Action<long>? RangeVerifiedForTests;
    internal static Action? CaptureReadyForTests;
    private static readonly AsyncLocal<Action<VerifiedArchiveInput>?> BeforeSealHook = new();
    internal static Action<VerifiedArchiveInput>? BeforeSealForTests
    { get => BeforeSealHook.Value; set => BeforeSealHook.Value = value; }
    private AuthenticatedRangeIndex? _index;
    private readonly List<OperationMemoryBudget.HeavyLease> _bufferMemory = [];
    private OperationMemoryBudget.HeavyLease? _contextMemory;
    private string? _originalPath;
#if KEEPVAULT_MACOS
    private MacFileIdentity _originalIdentity;
#endif
    private bool _fused;
    private bool _plainIntegrity;
    private bool _repairOnlyCapture;
    private RecoveryRecordTable<byte[]>? _repairErasures;
    private long _unreadableBlocks;
    internal long CapturedUnreadableBlocks => _unreadableBlocks;
    internal static readonly AsyncLocal<Func<long, int, bool>?> RepairReadFaultForTests = new();
    private long _capturedRecords;
    private long _firstPassBytes;
    internal long FirstPassBytesForTests => Interlocked.Read(ref _firstPassBytes);
    internal long ResidentIndexBytes => _index?.ResidentBytes ?? 0;
    internal long DiskIndexBytes => _index?.DiskBytes ?? 0;
    internal static Action? BeforeFirstPassForTests;
    internal static readonly AsyncLocal<Action<VerifiedArchiveInput>?> FirstPassStartedForTests = new();
    private RecoveryMetadataBudget? _metadataBudget;
    private long _reservedIndexBytes;
    private FileStream? _original;
    // Streams own these handles until every worker/reader has joined. Resolve
    // each handle once: FileStream.SafeFileHandle flushes its buffered cursor
    // and is therefore not a thread-safe accessor during parallel file I/O.
    private SafeFileHandle? _dataHandle;
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

    // Conservative, copy-free three-pass comparison oracle. Production encrypted
    // readers use BindEncryptedAsync and the fused first-pass view below.
    internal static Task<VerifiedArchiveInput> CaptureAsync(
        string path, ArchiveOperationPolicy? policy, CancellationToken cancellationToken) =>
        CaptureOriginalAsync(path, policy, cancellationToken);

    internal static Task<VerifiedArchiveInput> CaptureOriginalAsync(
        string path, ArchiveOperationPolicy? policy, CancellationToken cancellationToken) =>
        Task.Run(() => CaptureLocally(path, policy ?? ArchiveOperationPolicy.Current, cancellationToken), cancellationToken);

    internal static Task<VerifiedArchiveInput> CaptureForRepairAsync(
        string path, ArchiveOperationPolicy? policy, CancellationToken cancellationToken) =>
        Task.Run(() => CaptureLocally(path, policy ?? ArchiveOperationPolicy.Current, cancellationToken, repairOnly: true), cancellationToken);

    internal static Task<VerifiedArchiveInput> BindEncryptedAsync(
        string path, ArchiveOperationPolicy? policy, CancellationToken cancellationToken) =>
        Task.FromResult(Bind(path, policy ?? ArchiveOperationPolicy.Current, cancellationToken));

    internal static Task<VerifiedArchiveInput> BindPlainAsync(
        string path, ArchiveOperationPolicy? policy, CancellationToken cancellationToken) =>
        BindEncryptedAsync(path, policy, cancellationToken);

    private static VerifiedArchiveInput Bind(string path, ArchiveOperationPolicy policy, CancellationToken token)
    {
        using IDisposable policyScope = policy.EnterScope();
        token.ThrowIfCancellationRequested();
        RetryFailedCleanup();
        string fullPath = Path.GetFullPath(path);
        var input = new VerifiedArchiveInput(policy);
        try
        {
#if KEEPVAULT_MACOS
            input._original = MacSafeFileSystem.OpenReadNoSymlinks(fullPath);
#else
            input._original = SecureFile.OpenReadNoReparse(fullPath, FileShare.Read, randomAccess: true);
#endif
            input._dataHandle = input._original.SafeFileHandle;
            input._originalPath = fullPath;
#if KEEPVAULT_MACOS
            input._originalIdentity = MacSafeFileSystem.GetIdentity(input._dataHandle);
#endif
            _ = NativePathResolver.RequireCanonicalFilePath(input._dataHandle, fullPath, "Verified archive input");
            input._length = RandomAccess.GetLength(input._dataHandle);
            if (input._length > policy.MaxContainerBytes) throw new IOException("The input exceeds the approved container byte limit.");
            input._records = GetRecordCount(input._length);
            long indexLength = checked(input._records * RecordBytes);
            if (indexLength > policy.MaxMetadataBytes) throw new IOException("The range index exceeds the approved metadata limit.");
            input._memory = OperationMemoryBudget.AcquireAsync(policy, token).AsTask().GetAwaiter().GetResult();
            using IDisposable memoryScope = input._memory.EnterScope();
            input._metadataBudget = RecoveryMetadataBudget.Capture(policy.MaxMetadataBytes);
            input._metadataBudget.Reserve(indexLength);
            input._reservedIndexBytes = indexLength;
            input._contextMemory = OperationMemoryBudget.AcquireWorking(224);
            input._hmacKey = LockedSensitiveBuffer.Create(64);
            input._skeinKey = LockedSensitiveBuffer.Create(128);
            input._operationId = LockedSensitiveBuffer.Create(32);
            input._contextMemory.CommitAllocation();
            RandomNumberGenerator.Fill(input._hmacKey.Bytes);
            RandomNumberGenerator.Fill(input._skeinKey.Bytes);
            RandomNumberGenerator.Fill(input._operationId.Bytes);
            input._state = VerifiedArchiveInputState.BoundUntrusted;
            return input;
        }
        catch (Exception failure)
        {
            input._state = VerifiedArchiveInputState.Failed;
            try { input.Dispose(); }
            catch (Exception cleanup) { throw new AggregateException("Input binding and cleanup failed.", failure, cleanup); }
            throw;
        }
    }

    private void InitializeIndexAndBuffers()
    {
        if (_index is not null) return;
        _index = new AuthenticatedRangeIndex(_policy, _metadataBudget!, checked(_records * RecordBytes));
        // Re-resolve the joined first-pass boundary from the real bound length
        // and fresh pressure, instead of freezing the initial one-slot plan.
        ArchiveOperationPolicy phase = _policy.ForPhase(new PhaseResourceDemand(
            checked(224 + Math.Min(_length, RangeBytes) + TranscriptPrefixBytes), _length));
        int buffers = checked((int)Math.Max(1, Math.Min(_records, Math.Min(phase.MaxIoRequests, phase.MaxCpuWorkers))));
        _buffers = new LockedSensitiveBuffer?[buffers];
        _readSlots = new SemaphoreSlim(buffers, buffers);
        _ioSlots = new SemaphoreSlim(phase.MaxIoRequests, phase.MaxIoRequests);
        // Establish owner slots before acquiring a lease; a List growth failure
        // must not strand an admitted RAM charge outside the retryable owner.
        _bufferMemory.EnsureCapacity(buffers);
        for (int worker = 0; worker < buffers; worker++)
        {
            int size = checked((int)Math.Min(RangeBytes, Math.Max(1, _length)) + TranscriptPrefixBytes + RecordBytes);
            OperationMemoryBudget.HeavyLease lease = OperationMemoryBudget.AcquireWorking(size);
            _bufferMemory.Add(lease);
            _buffers[worker] = LockedSensitiveBuffer.Create(size);
            lease.CommitAllocation();
            _availableBuffers.Enqueue(_buffers[worker]!);
            _verifiedBufferRanges.Add(_buffers[worker]!, -1);
        }
    }

    private static VerifiedArchiveInput CaptureLocally(string path, ArchiveOperationPolicy policy, CancellationToken token, bool repairOnly = false)
    {
        VerifiedArchiveInput input = Bind(path, policy, token);
        try
        {
            using IDisposable memoryScope = input._memory!.EnterScope();
            using IDisposable policyScope = policy.EnterScope();
            input._repairOnlyCapture = repairOnly;
            input._state = VerifiedArchiveInputState.Capturing;
            input.InitializeIndexAndBuffers();
            using OperationProgressSource? captureProgress = OperationProgressTracker.Current?.BeginPhase(
                repairOnly ? OperationPhase.Recovery : OperationPhase.Inventory, ProgressUnit.Bytes,
                input._length, ProgressTotalOrigin.KnownInput, passId: 1);
            CaptureReadyForTests?.Invoke();
            Span<byte> record = stackalloc byte[RecordBytes];
            for (long index = 0; index < input._records; index++)
            {
                token.ThrowIfCancellationRequested();
                int count = input.ExpectedRangeLength(index);
                LockedSensitiveBuffer buffer = input._buffers[0]!;
                input.CaptureRange(index, buffer.Bytes.AsSpan(TranscriptPrefixBytes, count));
                using (CpuWorkBudget.Lease? localCpu = CpuWorkBudget.IsOwnedByCurrentContext ? null
                    : CpuWorkBudget.AcquireAsync(policy.MaxCpuWorkers, 1, token).AsTask().GetAwaiter().GetResult())
                using (IDisposable? localScope = localCpu?.EnterScope())
                    input.ComputeRecord(index, count, record, buffer.Bytes);
                input._index!.WriteAt(record, checked(index * RecordBytes));
                input._capturedRecords++;
                input._firstPassBytes = checked(input._firstPassBytes + count);
                captureProgress?.Advance(count);
                OperationMemoryBudget.ReportProgress(count);
                CryptographicOperations.ZeroMemory(buffer.Bytes);
            }
            input.CompleteCapture();
            input._state = VerifiedArchiveInputState.CapturedUnverified;
            return input;
        }
        catch (Exception failure)
        {
            input._state = VerifiedArchiveInputState.Failed;
            try { input.Dispose(); }
            catch (Exception cleanup) { throw new AggregateException("Local capture and cleanup failed.", failure, cleanup); }
            throw;
        }
    }

    private void ReadOriginal(Span<byte> bytes, long offset)
    {
        if (_repairOnlyCapture && RepairReadFaultForTests.Value?.Invoke(offset, bytes.Length) == true)
            throw new IOException("Injected original-source read failure.");
        ReadExactlyAt(_dataHandle!, bytes, offset);
    }

    private void CaptureRange(long index, Span<byte> bytes)
    {
        ValidateSource();
        long offset = checked(index * RangeBytes);
        try { ReadOriginal(bytes, offset); }
        catch (IOException) when (_repairOnlyCapture)
        {
            // Erasures are an explicit property of the repair capability only.
            // A new candidate must still satisfy its independently certified
            // manifest and both full container MACs before publication.
            ValidateSource();
            byte[] mask = new byte[40];
            BinaryPrimitives.WriteInt64BigEndian(mask, index);
            try
            {
                for (int inside = 0; inside < bytes.Length; inside += 4096)
                {
                    int count = Math.Min(4096, bytes.Length - inside);
                    try { ReadOriginal(bytes.Slice(inside, count), checked(offset + inside)); }
                    catch (IOException)
                    {
                        ValidateSource();
                        bytes.Slice(inside, count).Clear();
                        int block = inside / 4096;
                        mask[8 + block / 8] |= (byte)(1 << (block % 8));
                        _unreadableBlocks = checked(_unreadableBlocks + 1);
                    }
                }
                if (mask.AsSpan(8).IndexOfAnyExcept((byte)0) >= 0)
                {
                    _repairErasures ??= new RecoveryRecordTable<byte[]>(_policy);
                    _repairErasures.Add(mask);
                }
            }
            finally { CryptographicOperations.ZeroMemory(mask); }
        }
    }

    private bool FindErasureMask(long range, Span<byte> mask)
    {
        if (_repairErasures is null) return false;
        int lower = 0, upper = _repairErasures.Count - 1;
        while (lower <= upper)
        {
            int middle = lower + (upper - lower) / 2;
            byte[] record = _repairErasures[middle];
            try
            {
                if (record.Length != 40) throw new CryptographicException("Invalid authenticated repair-erasure record.");
                long index = BinaryPrimitives.ReadInt64BigEndian(record);
                if (index < 0 || index >= _records) throw new CryptographicException("Invalid repair-erasure position.");
                if (index == range) { record.AsSpan(8).CopyTo(mask); return true; }
                if (index < range) lower = middle + 1; else upper = middle - 1;
            }
            finally { CryptographicOperations.ZeroMemory(record); }
        }
        return false;
    }

    private void ReadCapturedRange(long index, Span<byte> bytes)
    {
        Span<byte> mask = stackalloc byte[32];
        if (!_repairOnlyCapture || !FindErasureMask(index, mask))
        { ReadOriginal(bytes, checked(index * RangeBytes)); return; }
        // Only captured erasures can be substituted. No later read failure
        // creates a new expected range tag or widens this frozen mask.
        long offset = checked(index * RangeBytes);
        for (int inside = 0; inside < bytes.Length; inside += 4096)
        {
            int count = Math.Min(4096, bytes.Length - inside), block = inside / 4096;
            if ((mask[block / 8] & (1 << (block % 8))) != 0) bytes.Slice(inside, count).Clear();
            else ReadOriginal(bytes.Slice(inside, count), checked(offset + inside));
        }
    }

    private void CompleteCapture()
    {
        ValidateSource();
        if (_capturedRecords != _records || _firstPassBytes != _length)
            throw new IOException("The original input was not completely captured.");
        Span<byte> probe = stackalloc byte[1];
        if (RandomAccess.Read(_dataHandle!, probe, _length) != 0) throw new IOException("The source grew during capture.");
        BeforeSealForTests?.Invoke(this);
        _index!.Seal();
        ValidateLengths();
    }

    internal Task VerifyPlainIntegrityAsync(
        Func<Stream, CancellationToken, Task<VerifiedArchiveAuthentication>> verifier, CancellationToken token)
    {
        _plainIntegrity = true;
        return VerifyGloballyAsync(verifier, token);
    }

    internal async Task VerifyGloballyAsync(
        Func<Stream, CancellationToken, Task<VerifiedArchiveAuthentication>> verifier,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(verifier);
        lock (_gate)
        {
            if (_repairOnlyCapture || _state is not (VerifiedArchiveInputState.CapturedUnverified or VerifiedArchiveInputState.BoundUntrusted))
                throw new InvalidOperationException("Input is not available for first verification.");
            _fused = _state == VerifiedArchiveInputState.BoundUntrusted;
            _state = _fused ? VerifiedArchiveInputState.PreflightBoundedHeader : VerifiedArchiveInputState.VerifyingGlobal;
            _position = 0;
            _activeReads++; // Own every first-pass buffer until callback and hash jobs have joined.
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
            using Stream view = _fused ? new FirstPassView(this, cancellationToken) : new VerificationView(this);
            if (_plainIntegrity && view is FirstPassView plainView) plainView.BeginFirstPass(0);
            result = await verifier(view, cancellationToken).ConfigureAwait(false);
            if (_fused) ((FirstPassView)view).Complete();
            cancellationToken.ThrowIfCancellationRequested();
            bool hmac = result.ExpectedSha3 is { Length: 64 } && result.ActualSha3 is { Length: 64 }
                && CryptographicOperations.FixedTimeEquals(result.ExpectedSha3, result.ActualSha3);
            bool skein = result.ExpectedSkein is { Length: 128 } && result.ActualSkein is { Length: 128 }
                && CryptographicOperations.FixedTimeEquals(result.ExpectedSkein, result.ActualSkein);
            if (!(hmac & skein)) throw new CryptographicException("Wrong password or manipulated container.");
            lock (_gate)
            {
                RequireState(_fused ? VerifiedArchiveInputState.IndexingAndGlobalVerify : VerifiedArchiveInputState.VerifyingGlobal);
                ValidateLengths();
                _position = 0;
                _state = _plainIntegrity ? VerifiedArchiveInputState.PlainIntegrityVerified : VerifiedArchiveInputState.Verified;
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
            lock (_gate) { _activeReads--; Monitor.PulseAll(_gate); }
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
        ValidateSource();
        if (_index is null || _index.Length != checked(_records * RecordBytes))
            throw new IOException("The range index was truncated or extended.");
    }

    internal void ValidateSource()
    {
        if (RandomAccess.GetLength(_dataHandle!) != _length) throw new IOException("The bound source length changed.");
#if KEEPVAULT_MACOS
        MacSafeFileSystem.RequirePathStillNamesHandle(_dataHandle!, _originalPath!);
        if (!_originalIdentity.SameObjectAndMetadata(MacSafeFileSystem.GetIdentity(_dataHandle!)))
            throw new IOException("The bound source identity or metadata changed.");
#endif
    }

    private int ReadProtected(Span<byte> destination, long offset, bool verification, CancellationToken token, bool localCapture = false)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        lock (_gate) RequireLiveContext();
        using var readCancellation = CancellationTokenSource.CreateLinkedTokenSource(token, _closing.Token,
            _memory?.Token ?? CancellationToken.None);
        token = readCancellation.Token;
        using IDisposable policyScope = _policy.EnterScope();
        using IDisposable? memoryScope = _memory?.EnterScope();
        _readSlots!.Wait(token);
        LockedSensitiveBuffer? privateBuffer = null;
        int requested = 0;
        long cachedRange = -1;
        bool succeeded = false;
        try
        {
            lock (_gate)
            {
                if (localCapture) RequireState(VerifiedArchiveInputState.LocalCaptureSealed);
                else if (verification) RequireState(VerifiedArchiveInputState.VerifyingGlobal);
                else
                {
                    if (_state is not (VerifiedArchiveInputState.Verified or VerifiedArchiveInputState.PlainIntegrityVerified or VerifiedArchiveInputState.Consuming))
                        throw new InvalidOperationException("Archive bytes are unavailable before both global MACs pass.");
                    _state = VerifiedArchiveInputState.Consuming;
                }
                requested = checked((int)Math.Min(destination.Length, Math.Max(0, _length - offset)));
                // Prefer the immutable verified range already held by this
                // pool. Only the exclusive borrower may replace its contents.
                long requestedRange = offset / RangeBytes;
                LockedSensitiveBuffer? preferred = _availableBuffers.FirstOrDefault(buffer => _verifiedBufferRanges[buffer] == requestedRange);
                if (preferred is not null)
                    while (!ReferenceEquals(_availableBuffers.Peek(), preferred)) _availableBuffers.Enqueue(_availableBuffers.Dequeue());
                privateBuffer = _availableBuffers.Dequeue();
                cachedRange = _verifiedBufferRanges[privateBuffer];
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
                    if (cachedRange != index)
                    {
                        ReadCapturedRange(index, bytes);
                        lock (_gate) _secondPassBytes = checked(_secondPassBytes + count);
                    }
                    _index!.ReadExactlyAt(stored, checked(index * RecordBytes));
                }
                finally { _ioSlots.Release(); }
                // Neither untrusted index field determines an allocation or offset.
                if (BinaryPrimitives.ReadInt64BigEndian(stored) != index
                    || BinaryPrimitives.ReadInt32BigEndian(stored[8..]) != count)
                    throw new CryptographicException("The verified range record has an invalid position or length.");
                using (CpuWorkBudget.Lease? cpu = CpuWorkBudget.IsOwnedByCurrentContext ? null
                    : CpuWorkBudget.AcquireAsync(_policy.MaxCpuWorkers, 1, token).AsTask().GetAwaiter().GetResult())
                using (IDisposable? cpuScope = cpu?.EnterScope())
                {
                    if (cachedRange == index) privateBuffer.Bytes.AsSpan(privateBuffer.Bytes.Length - RecordBytes).CopyTo(actual);
                    else ComputeRecord(index, count, actual, privateBuffer.Bytes);
                    bool hmac = CryptographicOperations.FixedTimeEquals(stored.Slice(12, 64), actual.Slice(12, 64));
                    bool skein = CryptographicOperations.FixedTimeEquals(stored.Slice(76, 128), actual.Slice(76, 128));
                    if (!(hmac & skein)) throw new CryptographicException("The captured archive range changed.");
                }
                actual.CopyTo(privateBuffer.Bytes.AsSpan(privateBuffer.Bytes.Length - RecordBytes));
                cachedRange = index;
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
                if (localCapture) RequireState(VerifiedArchiveInputState.LocalCaptureSealed);
                else if (verification) RequireState(VerifiedArchiveInputState.VerifyingGlobal);
                else if (_state is not (VerifiedArchiveInputState.Verified or VerifiedArchiveInputState.PlainIntegrityVerified or VerifiedArchiveInputState.Consuming))
                    throw new InvalidOperationException("The verified input closed or failed while a read was pending.");
            }
            succeeded = true;
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
                if (!succeeded) CryptographicOperations.ZeroMemory(privateBuffer.Bytes);
                lock (_gate)
                {
                    _verifiedBufferRanges[privateBuffer] = succeeded ? cachedRange : -1;
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
    public override bool CanRead => State is VerifiedArchiveInputState.Verified or VerifiedArchiveInputState.PlainIntegrityVerified or VerifiedArchiveInputState.Consuming;
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
            SecureMemory.DisposeAll([.. _buffers, _hmacKey, _skeinKey, _operationId, _index, _repairErasures, _original]);
            _metadataBudget?.Release(_reservedIndexBytes);
            _reservedIndexBytes = 0;
            _metadataBudget = null;
            _buffers = []; _availableBuffers.Clear(); _verifiedBufferRanges.Clear(); _hmacKey = null; _skeinKey = null; _operationId = null;
            _index = null; _repairErasures = null; _original = null;
            _dataHandle = null;
            foreach (OperationMemoryBudget.HeavyLease lease in _bufferMemory) lease.Dispose();
            _bufferMemory.Clear();
            _contextMemory?.Dispose(); _contextMemory = null;
            _memory?.Dispose(); _memory = null;
            _state = VerifiedArchiveInputState.Disposed;
            lock (OwnersGate) Owners.Remove(this);
        }
        base.Dispose(disposing);
    }

    internal Stream OpenPlainCapture()
    {
        lock (_gate)
        {
            RequireState(VerifiedArchiveInputState.CapturedUnverified);
            if (_repairOnlyCapture) throw new InvalidOperationException("A repair capture cannot authorize a plain archive consumer.");
            _state = VerifiedArchiveInputState.LocalCaptureSealed;
            return new PlainCapturedRead(this);
        }
    }

    internal RepairCiphertextRead OpenRepairCiphertext()
    {
        lock (_gate)
        {
            RequireState(VerifiedArchiveInputState.CapturedUnverified);
            _state = VerifiedArchiveInputState.LocalCaptureSealed;
            return new RepairCiphertextRead(this);
        }
    }

    // These local capabilities cannot make the owner globally verified. The
    // repair caller can read only captured ciphertext and must independently
    // bind/authenticate a completed candidate before publication.
    internal sealed class RepairCiphertextRead : LocalCapturedRead
    { internal RepairCiphertextRead(VerifiedArchiveInput owner) : base(owner) { } }
    private sealed class PlainCapturedRead(VerifiedArchiveInput owner) : LocalCapturedRead(owner);
    internal abstract class LocalCapturedRead(VerifiedArchiveInput owner) : Stream, IPrivateSnapshotRandomAccess
    {
        private readonly object _positionGate = new();
        private long _position;
        private bool _closed;
        public override bool CanRead => !_closed;
        public override bool CanSeek => !_closed;
        public override bool CanWrite => false;
        public override long Length { get { ObjectDisposedException.ThrowIf(_closed, this); return owner.Length; } }
        public override long Position
        {
            get { lock (_positionGate) return _position; }
            set { lock (_positionGate) { if (value < 0 || value > Length) throw new ArgumentOutOfRangeException(nameof(value)); _position = value; } }
        }
        internal int ReadAt(Span<byte> bytes, long offset, CancellationToken token = default)
        { ObjectDisposedException.ThrowIf(_closed, this); return owner.ReadProtected(bytes, offset, false, token, localCapture: true); }
        public ValueTask<int> ReadAtAsync(Memory<byte> bytes, long offset, CancellationToken cancellationToken) =>
            ValueTask.FromResult(ReadAt(bytes.Span, offset, cancellationToken));
        public override int Read(Span<byte> bytes)
        { lock (_positionGate) { int count = ReadAt(bytes, _position); _position += count; return count; } }
        public override int Read(byte[] bytes, int offset, int count) => Read(bytes.AsSpan(offset, count));
        public override ValueTask<int> ReadAsync(Memory<byte> bytes, CancellationToken cancellationToken = default)
        { lock (_positionGate) { int count = ReadAt(bytes.Span, _position, cancellationToken); _position += count; return ValueTask.FromResult(count); } }
        public override Task<int> ReadAsync(byte[] bytes, int offset, int count, CancellationToken cancellationToken) => ReadAsync(bytes.AsMemory(offset, count), cancellationToken).AsTask();
        public override long Seek(long offset, SeekOrigin origin)
        { lock (_positionGate) { Position = origin switch { SeekOrigin.Begin => offset, SeekOrigin.Current => checked(_position + offset), SeekOrigin.End => checked(Length + offset), _ => throw new ArgumentOutOfRangeException(nameof(origin)) }; return Position; } }
        public override void Flush() { }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] bytes, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { _closed = true; base.Dispose(disposing); }
    }

    internal static void BeginFusedAuthentication(Stream stream, long ciphertextOffset)
    {
        if (stream is FirstPassView first) first.BeginFirstPass(ciphertextOffset);
    }

    private sealed class FirstPassView : Stream
    {
        private const int MaximumPreflightBytes = 16 * 1024 + 7 + 4 + 64 + 128;
        private readonly VerifiedArchiveInput owner;
        private readonly MemoryStream _header;
        private readonly CancellationToken _token;
        private readonly OperationMemoryBudget.HeavyLease _headerMemory;
        internal FirstPassView(VerifiedArchiveInput input, CancellationToken token)
        {
            owner = input; _token = token;
            _headerMemory = OperationMemoryBudget.AcquireWorking(MaximumPreflightBytes);
            try { _header = new MemoryStream(MaximumPreflightBytes); _headerMemory.CommitAllocation(); }
            catch { _headerMemory.Dispose(); throw; }
        }
        private long _position;
        private long _batchStart = -1;
        private int _batchCount;
        private long _nextRange;
        private bool _started, _closed;
        private OperationProgressSource? _progress;
        public override bool CanRead => !_closed;
        public override bool CanSeek => !_closed;
        public override bool CanWrite => false;
        public override long Length => owner.Length;
        public override long Position
        {
            get => _position;
            set { if (value != _position) throw new InvalidOperationException("The fused verification view is strictly ordered."); }
        }
        internal void BeginFirstPass(long offset)
        {
            _token.ThrowIfCancellationRequested();
            if (_closed || _started || offset != _position || offset != _header.Length)
                throw new InvalidOperationException("Invalid frozen header boundary.");
            owner.InitializeIndexAndBuffers();
            lock (owner._gate)
            {
                owner.RequireState(VerifiedArchiveInputState.PreflightBoundedHeader);
                owner._state = VerifiedArchiveInputState.IndexingAndGlobalVerify;
            }
            BeforeFirstPassForTests?.Invoke();
            FirstPassStartedForTests.Value?.Invoke(owner);
            _progress = OperationProgressTracker.Current?.BeginPhase(OperationPhase.GlobalVerification,
                ProgressUnit.Bytes, owner._length, ProgressTotalOrigin.KnownInput, passId: 1);
            _started = true;
            // Header-only physical ranges must be captured too, even when the
            // logical global transcript starts after a physical range boundary.
            for (long range = 0; range <= offset / RangeBytes && range < owner._records; range++) Load(range);
        }
        private LockedSensitiveBuffer BufferForRange(long range) => owner._buffers[checked((int)(range - _batchStart))]!;
        private void Load(long range)
        {
            if (range >= _batchStart && range < _batchStart + _batchCount) return;
            if (range != _nextRange) throw new InvalidOperationException("A fused range may be captured exactly once, in order.");
            _token.ThrowIfCancellationRequested();
            int count = checked((int)Math.Min(owner._buffers.Length, owner._records - range));
            int workers = CpuWorkBudget.IsOwnedByCurrentContext ? 1 : count;
            Parallel.For(0, count, new ParallelOptions { MaxDegreeOfParallelism = workers, CancellationToken = _token }, slot =>
            {
#if KEEPVAULT_MACOS
                using var qos = MacCpuWorkerQos.EnterSynchronousScope();
#endif
                long index = checked(range + slot);
                owner.ValidateSource();
                int length = owner.ExpectedRangeLength(index);
                LockedSensitiveBuffer buffer = owner._buffers[slot]!;
                Span<byte> bytes = buffer.Bytes.AsSpan(TranscriptPrefixBytes, length);
                ReadExactlyAt(owner._dataHandle!, bytes, checked(index * RangeBytes));
                long start = checked(index * RangeBytes);
                int prefixCount = checked((int)Math.Max(0, Math.Min(length, _header.Length - start)));
                if (prefixCount != 0 && !CryptographicOperations.FixedTimeEquals(bytes[..prefixCount],
                        _header.GetBuffer().AsSpan(checked((int)start), prefixCount)))
                    throw new CryptographicException("The preflight header or stored authentication tags changed during KDF.");
                Span<byte> record = stackalloc byte[RecordBytes];
                using (CpuWorkBudget.Lease? cpu = CpuWorkBudget.IsOwnedByCurrentContext ? null
                    : CpuWorkBudget.AcquireAsync(owner._policy.MaxCpuWorkers, 1, _token).AsTask().GetAwaiter().GetResult())
                using (IDisposable? cpuScope = cpu?.EnterScope())
                    owner.ComputeRecord(index, length, record, buffer.Bytes);
                owner._index!.WriteAt(record, checked(index * RecordBytes));
                lock (owner._gate)
                {
                    owner._capturedRecords = checked(owner._capturedRecords + 1);
                    owner._firstPassBytes = checked(owner._firstPassBytes + length);
                }
                _progress?.Advance(length);
            });
            _batchStart = range; _batchCount = count; _nextRange = checked(range + count);
        }
        public override int Read(Span<byte> destination)
        {
            ObjectDisposedException.ThrowIf(_closed, this);
            _token.ThrowIfCancellationRequested();
            lock (owner._gate) owner.RequireState(_started ? VerifiedArchiveInputState.IndexingAndGlobalVerify : VerifiedArchiveInputState.PreflightBoundedHeader);
            int count = checked((int)Math.Min(destination.Length, owner._length - _position));
            if (!_started)
            {
                if (checked(_position + count) > MaximumPreflightBytes) throw new InvalidDataException("Preflight exceeds the bounded container header.");
                ReadExactlyAt(owner._dataHandle!, destination[..count], _position);
                _header.Write(destination[..count]);
                _position += count;
                return count;
            }
            int copied = 0;
            while (copied < count)
            {
                long range = _position / RangeBytes;
                Load(range);
                int inside = checked((int)(_position % RangeBytes));
                int take = Math.Min(count - copied, owner.ExpectedRangeLength(range) - inside);
                BufferForRange(range).Bytes.AsSpan(TranscriptPrefixBytes + inside, take).CopyTo(destination[copied..]);
                _position += take; copied += take;
                OperationMemoryBudget.ReportProgress(take);
            }
            return copied;
        }
        internal void Complete()
        {
            if (!_started || _position != owner._length) throw new IOException("The global verifier did not consume the complete first pass.");
            owner.CompleteCapture();
            foreach (LockedSensitiveBuffer? buffer in owner._buffers) CryptographicOperations.ZeroMemory(buffer!.Bytes);
        }
        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        { cancellationToken.ThrowIfCancellationRequested(); return ValueTask.FromResult(Read(buffer.Span)); }
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
        public override long Seek(long offset, SeekOrigin origin)
        {
            long target = origin switch { SeekOrigin.Begin => offset, SeekOrigin.Current => checked(_position + offset),
                SeekOrigin.End => checked(Length + offset), _ => throw new ArgumentOutOfRangeException(nameof(origin)) };
            Position = target; return target;
        }
        public override void Flush() { }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing)
        {
            if (!_closed) { CryptographicOperations.ZeroMemory(_header.GetBuffer()); _header.Dispose(); _headerMemory.Dispose(); _progress?.Dispose(); _closed = true; }
            base.Dispose(disposing);
        }
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
