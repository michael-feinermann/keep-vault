using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Pipes;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace KalynaArchiver.Services;

/// <summary>One bounded, local, process-bound native control connection.</summary>
internal sealed partial class ZpaqControlSession : IDisposable
{
    internal const int HeaderBytes = 48;
    internal const int MaximumPayloadBytes = 1 << 20;
    private const uint Response = 0x80000000;
    private readonly ArchiveOperationPolicy _policy;
    private readonly Dictionary<ulong, CpuWorkBudget.Lease> _cpu = [];
    private readonly Dictionary<ulong, OperationMemoryBudget.HeavyLease> _memory = [];
    private readonly Dictionary<ulong, (IDisposable Lease, long Bytes)> _outputs = [];
    private SafeFileHandle? _outputRoot;
    private ArchiveOperationPolicy? _outputPolicy;
    private long _outputAuthorized, _outputWritten;
    private readonly HashSet<Task> _pending = [];
    private readonly object _gate = new();
    private readonly SemaphoreSlim _writes = new(1);
    private readonly byte[] _replyHeader = new byte[HeaderBytes];
    private readonly CancellationTokenSource _stop = new();
    private readonly TaskCompletionSource _failure = new(TaskCreationOptions.RunContinuationsAsynchronously);
#if KEEPVAULT_MACOS
    private readonly Socket? _listener;
    private readonly string? _directory;
    private readonly MacFileIdentity _directoryIdentity;
    private readonly MacFileIdentity _socketIdentity;
#else
    private readonly NamedPipeServerStream? _pipe;
#endif
    private Stream? _stream;
    private ulong _lastSequence;
    private bool _disposed;
    private bool _closed;
    private int _activeActions;
    private long _lastProgressTicks;
    internal string Address { get; }
    internal sealed class Payload(byte[] bytes, IDisposable? memory = null) : IDisposable
    {
        internal byte[] Bytes => bytes;
        public void Dispose() { CryptographicOperations.ZeroMemory(bytes); memory?.Dispose(); }
    }
    internal Func<ulong, CancellationToken, ValueTask<Payload>>? ReadSourceEntry { get; init; }
    internal Func<ulong, ulong, int, CancellationToken, ValueTask<Payload>>? ReadSourceBytes { get; init; }
    internal Action<ulong, ulong, ulong>? ObserveProgress { get; init; }

    internal ZpaqControlSession(ArchiveOperationPolicy policy)
    {
        _policy = policy;
#if KEEPVAULT_MACOS
        // This is a transport endpoint only, never a source/output/payload file.
        using (SafeFileHandle parent = MacSafeFileSystem.OpenDirectoryHandle("/private/tmp"))
        {
            string name = "kvctl-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
            MacSafeFileSystem.MkdirAt(parent, name, 0x1C0);
            _directory = Path.Combine("/private/tmp", name);
        }
        using (SafeFileHandle root = MacSafeFileSystem.OpenDirectoryHandle(_directory))
            _directoryIdentity = MacSafeFileSystem.GetIdentity(root);
        Address = Path.Combine(_directory, "control");
        _listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        try
        {
            _listener.Bind(new UnixDomainSocketEndPoint(Address));
            using SafeFileHandle root = MacSafeFileSystem.OpenDirectoryHandle(_directory);
            _socketIdentity = MacSafeFileSystem.GetIdentityAt(root, "control");
            _listener.Listen(1);
        }
        catch (Exception failure)
        {
            _listener.Dispose();
            try
            {
                using SafeFileHandle root = MacSafeFileSystem.OpenDirectoryHandle(_directory);
                if (!MacSafeFileSystem.GetIdentity(root).SameObject(_directoryIdentity))
                    throw new IOException("The failed native control endpoint changed identity.");
                var entries = MacSafeFileSystem.ReadDirectoryEntriesNoFollow(root);
                if (_socketIdentity != default && entries.Count == 1 && entries[0].Name == "control"
                    && entries[0].Identity.SameObject(_socketIdentity) && (entries[0].Identity.Mode & 0xF000) == 0xC000)
                    MacSafeFileSystem.UnlinkAt(root, "control");
                else if (entries.Count != 0) throw new IOException("Unexpected object in failed native control endpoint.");
                using SafeFileHandle parent = MacSafeFileSystem.OpenDirectoryHandle("/private/tmp");
                if (!MacSafeFileSystem.GetIdentityAt(parent, Path.GetFileName(_directory)).SameObject(_directoryIdentity))
                    throw new IOException("The failed native control endpoint name changed.");
                MacSafeFileSystem.UnlinkAt(parent, Path.GetFileName(_directory), 0x80);
            }
            catch (Exception cleanup) { throw new AggregateException(failure, cleanup); }
            throw;
        }
#else
        string name = "KeepVault-v13-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
        Address = @"\\.\pipe\" + name;
        _pipe = new NamedPipeServerStream(name, PipeDirection.InOut, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly,
            MaximumPayloadBytes, MaximumPayloadBytes);
#endif
    }

    internal void BindOutput(string directory, long authorizedBytes)
    {
        if (authorizedBytes <= 0 || _outputRoot is not null) throw new InvalidDataException("Invalid output authorization.");
        _outputPolicy = _policy.WithOutputDirectory(directory);
#if KEEPVAULT_MACOS
        _outputRoot = MacSafeFileSystem.OpenDirectoryHandle(directory);
#else
        _outputRoot = WindowsSafeFileSystem.OpenDirectoryBound(directory, denyRename: true, requestCreateAccess: true);
#endif
        _outputAuthorized = authorizedBytes;
    }

    internal async Task RunAsync(int expectedProcessId, CancellationToken token)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, _stop.Token);
        CancellationToken ct = linked.Token;
        Exception? primary = null;
        try
        {
#if KEEPVAULT_MACOS
            Socket accepted = await _listener!.AcceptAsync(ct).ConfigureAwait(false);
            try
            {
                uint length = sizeof(int);
                if (GetPeerProcessId(checked((int)accepted.Handle), 0, 2, out int actual, ref length) != 0
                    || length != sizeof(int) || actual != expectedProcessId)
                    throw new IOException("The native control peer is not the launched child.");
                _stream = new NetworkStream(accepted, ownsSocket: true);
            }
            catch { accepted.Dispose(); throw; }
#else
            await _pipe!.WaitForConnectionAsync(ct).ConfigureAwait(false);
            if (!GetNamedPipeClientProcessId(_pipe.SafePipeHandle, out uint actual) || actual != expectedProcessId)
                throw new IOException("The native control peer is not the launched child.");
            _stream = _pipe;
#endif
            byte[] header = new byte[HeaderBytes];
            while (true)
            {
                Task<int> read = _stream.ReadAsync(header.AsMemory(0, 1), ct).AsTask();
                if (await Task.WhenAny(read, _failure.Task).ConfigureAwait(false) == _failure.Task)
                    await _failure.Task.ConfigureAwait(false);
                if (await read.ConfigureAwait(false) == 0) break;
                await _stream.ReadExactlyAsync(header.AsMemory(1), ct).ConfigureAwait(false);
                Message message = Decode(header);
                if (_closed) throw new InvalidDataException("Native requests followed the close handshake.");
                if (message.Sequence <= _lastSequence)
                    throw new InvalidDataException("The native control sequence repeated or moved backwards.");
                _lastSequence = message.Sequence;
                lock (_gate)
                {
                    _pending.RemoveWhere(static task => task.IsCompletedSuccessfully);
                    if (_pending.Count >= checked(_policy.MaxCpuWorkers + 8))
                        throw new InvalidDataException("The native control request window exceeded its bound.");
                }
                // Waiting for a CPU permit cannot block the reader: another
                // worker may need to release its permit on this connection.
                if (message.Kind == 5)
                {
                    // Telemetry never creates queued tasks. Even a noisy child
                    // has one fixed header and one synchronous drain path.
                    await HandleAsync(message, ct).ConfigureAwait(false);
                }
                else
                {
                    Task operation = HandleAsync(message, ct);
                    lock (_gate) _pending.Add(operation);
                }
            }
            Task[] drained;
            lock (_gate)
            {
                if (!_closed || _cpu.Count != 0) throw new IOException("The child closed its control channel without an orderly drain.");
                drained = _pending.ToArray();
            }
            await Task.WhenAll(drained).ConfigureAwait(false);
        }
        catch (Exception failure)
        {
            primary = _failure.Task.Exception?.InnerException ?? failure;
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(primary).Throw();
            throw;
        }
        finally
        {
            // No CPU lease is released here while its child could still run.
            // Runner kills/joins the process before disposing this owner.
            linked.Cancel();
            _stream?.Dispose();
            Task[] pending;
            lock (_gate) pending = _pending.ToArray();
            try { await Task.WhenAll(pending).ConfigureAwait(false); }
            catch when (primary is not null) { }
        }
    }

    private async Task HandleAsync(Message request, CancellationToken token)
    {
        bool actionActive = request.Kind != 9;
        if (actionActive) Interlocked.Increment(ref _activeActions);
        try
        {
            ulong a = 0;
            Payload payload = new([]);
            switch (request.Kind)
            {
                case 1:
                    RequireZero(request.A | request.B | request.C);
                    CpuWorkBudget.Lease lease = await CpuWorkBudget.AcquireAsync(_policy.MaxCpuWorkers, 1, token).ConfigureAwait(false);
                    try { lock (_gate) _cpu.Add(request.Sequence, lease); }
                    catch { lease.Dispose(); throw; }
                    a = request.Sequence;
                    break;
                case 2:
                    RequireZero(request.B | request.C);
                    CpuWorkBudget.Lease release;
                    lock (_gate)
                    {
                        if (!_cpu.Remove(request.A, out release!)) throw new InvalidDataException("Unknown or repeated native CPU release.");
                    }
                    release.Dispose();
                    break;
                case 3:
                    RequireZero(request.B | request.C);
                    if (ReadSourceEntry is null) throw new InvalidDataException("This operation has no source catalog capability.");
                    payload = await ReadSourceEntry(request.A, token).ConfigureAwait(false);
                    break;
                case 4:
                    if (request.C == 0 || request.C > MaximumPayloadBytes || ReadSourceBytes is null)
                        throw new InvalidDataException("Invalid native source read capability or window.");
                    payload = await ReadSourceBytes(request.A, request.B, checked((int)request.C), token).ConfigureAwait(false);
                    if (payload.Bytes.Length != (int)request.C) { payload.Dispose(); throw new EndOfStreamException("The bound source read was incomplete."); }
                    break;
                case 5:
                    // Invalid observer state is diagnostic only. It cannot grant
                    // bytes, modify limits, claim success or stop archive work.
                    if (request.C == 0 && request.A is 1 or 2)
                    {
                        long now = Stopwatch.GetTimestamp();
                        long before = Interlocked.Read(ref _lastProgressTicks);
                        if (before == 0 || Stopwatch.GetElapsedTime(before, now) >= TimeSpan.FromMilliseconds(250))
                        {
                            Interlocked.Exchange(ref _lastProgressTicks, now);
                            try { ObserveProgress?.Invoke(request.A, request.B, request.Sequence); } catch { }
                        }
                    }
                    break;
                case 6:
                    RequireZero(request.A | request.C);
                    if (_outputRoot is null || _outputPolicy is null || request.B is 0 or > (64 << 10))
                        throw new InvalidDataException("Invalid native output capability or write window.");
                    lock (_gate)
                    {
                        long pendingBytes = _outputs.Values.Sum(static value => value.Bytes);
                        long bytes = checked((long)request.B);
                        if (_outputWritten > _outputAuthorized - pendingBytes || bytes > _outputAuthorized - pendingBytes - _outputWritten)
                            throw new IOException("Native output exceeds its finite authorization.");
                        IDisposable window = _outputPolicy.ReserveOutputWrite(_outputRoot, bytes);
                        try { _outputs.Add(request.Sequence, (window, bytes)); }
                        catch { window.Dispose(); throw; }
                    }
                    a = request.Sequence;
                    break;
                case 7:
                    RequireZero(request.B | request.C);
                    if (request.A == 0 || request.A > (ulong)_policy.MemoryBudgetBytes)
                        throw new InvalidDataException("Invalid native allocation demand.");
                    OperationMemoryBudget.HeavyLease allocation = await OperationMemoryBudget.AcquireWorkingAsync(checked((long)request.A), token).ConfigureAwait(false);
                    try { lock (_gate) _memory.Add(request.Sequence, allocation); }
                    catch { allocation.Dispose(); throw; }
                    a = request.Sequence;
                    break;
                case 8:
                    RequireZero(request.B | request.C);
                    OperationMemoryBudget.HeavyLease freed;
                    lock (_gate)
                    {
                        if (!_memory.Remove(request.A, out freed!)) throw new InvalidDataException("Unknown native allocation release.");
                    }
                    freed.Dispose();
                    break;
                case 10:
                    RequireZero(request.C);
                    lock (_gate)
                    {
                        if (!_outputs.TryGetValue(request.A, out var window) || request.B > (ulong)window.Bytes)
                            throw new InvalidDataException("Unknown or oversized native write completion.");
                        _outputs.Remove(request.A);
                        try { _outputWritten = checked(_outputWritten + (long)request.B); }
                        finally { window.Lease.Dispose(); }
                    }
                    break;
                case 9:
                    RequireZero(request.A | request.B | request.C);
                    Task[] previous;
                    lock (_gate)
                    {
                        if (_closed || _cpu.Count != 0 || _memory.Count != 0 || _outputs.Count != 0 || Volatile.Read(ref _activeActions) != 0)
                            throw new InvalidDataException("Native close arrived with outstanding authority requests.");
                        _closed = true;
                        previous = _pending.ToArray();
                    }
                    await Task.WhenAll(previous).ConfigureAwait(false);
                    break;
                default: throw new InvalidDataException("Unknown native control operation.");
            }
            if (actionActive) { Interlocked.Decrement(ref _activeActions); actionActive = false; }
            try { await ReplyAsync(request, a, payload.Bytes, token).ConfigureAwait(false); }
            finally { payload.Dispose(); }
        }
        catch (Exception failure)
        {
            _failure.TrySetException(failure);
            // Wake a reader blocked in ANY part of a truncated frame, not only
            // the first-byte read. Process owner still kills and joins child.
            try { _stop.Cancel(); } catch { }
            throw;
        }
        finally { if (actionActive) Interlocked.Decrement(ref _activeActions); }
    }

    private async Task ReplyAsync(Message request, ulong a, byte[] payload, CancellationToken token)
    {
        if (payload.Length > MaximumPayloadBytes) throw new InvalidDataException("Oversize native control reply.");
        await _writes.WaitAsync(token).ConfigureAwait(false);
        try
        {
            byte[] header = _replyHeader;
            Array.Clear(header);
            "KV13CTL1"u8.CopyTo(header);
            BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(8), request.Kind | Response);
            BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(12), checked((uint)payload.Length));
            BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(16), request.Sequence);
            BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(24), a);
            await _stream!.WriteAsync(header, token).ConfigureAwait(false);
            if (payload.Length != 0) await _stream.WriteAsync(payload, token).ConfigureAwait(false);
            await _stream.FlushAsync(token).ConfigureAwait(false);
        }
        finally { _writes.Release(); }
    }

    internal readonly record struct Message(uint Kind, ulong Sequence, ulong A, ulong B, ulong C);
    internal static Message Decode(ReadOnlySpan<byte> header)
    {
        if (header.Length != HeaderBytes || !header[..8].SequenceEqual("KV13CTL1"u8)
            || BinaryPrimitives.ReadUInt32BigEndian(header[12..]) != 0)
            throw new InvalidDataException("Invalid native control header.");
        uint kind = BinaryPrimitives.ReadUInt32BigEndian(header[8..]);
        ulong sequence = BinaryPrimitives.ReadUInt64BigEndian(header[16..]);
        if (kind is < 1 or > 10 || sequence == 0) throw new InvalidDataException("Invalid native control kind or sequence.");
        return new(kind, sequence, BinaryPrimitives.ReadUInt64BigEndian(header[24..]),
            BinaryPrimitives.ReadUInt64BigEndian(header[32..]), BinaryPrimitives.ReadUInt64BigEndian(header[40..]));
    }
    private static void RequireZero(ulong value)
    { if (value != 0) throw new InvalidDataException("Reserved native control fields must be zero."); }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _stop.Cancel();
        _stream?.Dispose();
#if KEEPVAULT_MACOS
        _listener?.Dispose();
#else
        _pipe?.Dispose();
#endif
        lock (_gate)
        {
            foreach (var lease in _cpu.Values) lease.Dispose(); _cpu.Clear();
            foreach (var lease in _memory.Values) lease.Dispose(); _memory.Clear();
            foreach (var window in _outputs.Values) window.Lease.Dispose(); _outputs.Clear();
        }
        _outputRoot?.Dispose();
        _stop.Dispose(); _writes.Dispose();
#if KEEPVAULT_MACOS
        if (_directory is not null)
        {
            using SafeFileHandle root = MacSafeFileSystem.OpenDirectoryHandle(_directory);
            if (!MacSafeFileSystem.GetIdentity(root).SameObject(_directoryIdentity))
                throw new IOException("The native control directory identity changed before cleanup.");
            var entries = MacSafeFileSystem.ReadDirectoryEntriesNoFollow(root);
            if (entries.Count == 1 && entries[0].Name == "control"
                && entries[0].Identity.SameObject(_socketIdentity)
                && (entries[0].Identity.Mode & 0xF000) == 0xC000)
                MacSafeFileSystem.UnlinkAt(root, "control");
            else if (entries.Count != 0)
                throw new IOException("The native control directory contains an unexpected object; cleanup preserved it.");
            if (MacSafeFileSystem.ReadDirectoryEntriesNoFollow(root).Count != 0)
                throw new IOException("The native control directory changed during cleanup.");
            using SafeFileHandle parent = MacSafeFileSystem.OpenDirectoryHandle(Path.GetDirectoryName(_directory)!);
            if (!MacSafeFileSystem.GetIdentityAt(parent, Path.GetFileName(_directory)).SameObject(_directoryIdentity))
                throw new IOException("The native control directory name changed during cleanup.");
            // unlinkat(AT_REMOVEDIR) only removes the empty directory. Never
            // recursively remove an unexpected object introduced during cleanup.
            MacSafeFileSystem.UnlinkAt(parent, Path.GetFileName(_directory), 0x80);
        }
#endif
    }
#if KEEPVAULT_MACOS
    [LibraryImport("/usr/lib/libSystem.B.dylib", EntryPoint = "getsockopt", SetLastError = true)]
    private static partial int GetPeerProcessId(int socket, int level, int option, out int pid, ref uint size);
#else
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint processId);
#endif
}
