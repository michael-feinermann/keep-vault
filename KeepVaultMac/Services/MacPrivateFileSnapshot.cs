using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace KalynaArchiver.Services;

/// <summary>
/// Owns a stable, anonymous read-only copy of a sensitive input file.
/// </summary>
/// <remarks>
/// The copy lives in an unlinked POSIX-SHM object. It never has a filesystem
/// path, and its random 96-bit namespace name is removed before any source byte
/// is copied. A separately opened read-only descriptor and a PROT_READ mapping
/// survive; no writable descriptor or namespace name does.
/// </remarks>
internal sealed class MacPrivateFileSnapshot : IDisposable
{
    // The container and plain-ZPAQ paths already impose a 500 GiB extraction
    // ceiling. Leave 12 GiB of framing headroom while refusing values that are
    // not practical to represent or stage on supported Macs.
    private const ulong MaximumSnapshotBytes = 512UL * 1024 * 1024 * 1024;
    private const uint TestInjectEnospc = 1;
    private const uint TestForceSingleWorker = 1U << 1;
    private const uint TestRequireParallelWorkers = 1U << 2;

    private const int SnapshotSuccess = 0;
    private const int SnapshotInvalidArgument = 1;
    private const int SnapshotInvalidSource = 2;
    private const int SnapshotSourceChanged = 3;
    private const int SnapshotSystemError = 4;
    private const int SnapshotTooLarge = 5;
    private const int SnapshotInternalError = 6;

    private FileStream? _stream;

    private MacPrivateFileSnapshot(FileStream stream)
    {
        _stream = stream;
    }

    internal FileStream Stream => _stream ?? throw new ObjectDisposedException(nameof(MacPrivateFileSnapshot));

    internal static MacPrivateFileSnapshot Capture(string sourcePath)
    {
        string fullPath = Path.GetFullPath(sourcePath);
        using FileStream source = MacSafeFileSystem.OpenReadNoSymlinks(fullPath);
        _ = NativePathResolver.RequireCanonicalFilePath(source.SafeFileHandle, fullPath, "Sensitive input");
        return Capture(source, Path.GetFileName(fullPath));
    }

    internal static MacPrivateFileSnapshot Capture(FileStream source, string fileName)
    {
        ArgumentNullException.ThrowIfNull(fileName);
        return CaptureCore(
            source,
            MaximumSnapshotBytes,
            testFlags: 0,
            afterCopyBeforeSourceValidation: null,
            useTestExport: false);
    }

    /// <summary>
    /// Deterministic native fault/race seam. The callback runs synchronously
    /// after the descriptor copy and before the final source fstat.
    /// </summary>
    internal static MacPrivateFileSnapshot CaptureForTests(
        FileStream source,
        ulong maximumBytes,
        Action? afterCopyBeforeSourceValidation = null,
        bool injectEnospcAfterFirstBlock = false,
        bool forceSingleWorker = false,
        bool requireParallelWorkers = false)
    {
        if (forceSingleWorker && requireParallelWorkers)
        {
            throw new ArgumentException(
                "A snapshot test cannot force one worker and require parallel workers at the same time.");
        }

        uint testFlags = 0;
        if (injectEnospcAfterFirstBlock)
        {
            testFlags |= TestInjectEnospc;
        }
        if (forceSingleWorker)
        {
            testFlags |= TestForceSingleWorker;
        }
        if (requireParallelWorkers)
        {
            testFlags |= TestRequireParallelWorkers;
        }

        return CaptureCore(
            source,
            maximumBytes,
            testFlags,
            afterCopyBeforeSourceValidation,
            useTestExport: afterCopyBeforeSourceValidation is not null || testFlags != 0);
    }

    internal static Task<MacPrivateFileSnapshot> CaptureAsync(
        string sourcePath,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sourcePath);
        cancellationToken.ThrowIfCancellationRequested();

        // Descriptor-bound copying into SHM is real I/O rather than the former
        // APFS clone, so keep it off the UI thread. Native validation remains
        // synchronous and fail-closed once a copy has begun.
        return Task.Run(() => Capture(sourcePath), cancellationToken);
    }

    public void Dispose()
    {
        Interlocked.Exchange(ref _stream, null)?.Dispose();
    }

    private static unsafe MacPrivateFileSnapshot CaptureCore(
        FileStream source,
        ulong maximumBytes,
        uint testFlags,
        Action? afterCopyBeforeSourceValidation,
        bool useTestExport)
    {
        ArgumentNullException.ThrowIfNull(source);
        if (!source.CanRead || !source.CanSeek)
        {
            throw new ArgumentException(
                "A private input snapshot requires a readable, seekable file.",
                nameof(source));
        }

        SnapshotHookState? callbackState = afterCopyBeforeSourceValidation is null
            ? null
            : new SnapshotHookState(afterCopyBeforeSourceValidation);
        GCHandle callbackHandle = default;
        bool callbackHandleAllocated = false;
        bool sourceHandleAdded = false;
        int snapshotDescriptor = -1;
        ulong mappingAddress = 0;
        ulong logicalSize = 0;
        int osError = 0;
        int status;
        try
        {
            source.SafeFileHandle.DangerousAddRef(ref sourceHandleAdded);
            int sourceDescriptor = checked((int)source.SafeFileHandle.DangerousGetHandle());

            if (useTestExport)
            {
                delegate* unmanaged[Cdecl]<nint, void> callback = null;
                nint callbackContext = 0;
                if (callbackState is not null)
                {
                    callbackHandle = GCHandle.Alloc(callbackState, GCHandleType.Normal);
                    callbackHandleAllocated = true;
                    callback = &InvokeSnapshotHook;
                    callbackContext = GCHandle.ToIntPtr(callbackHandle);
                }

                status = NativeChaChaPoly.CreateMacAnonymousSnapshotForTests(
                    sourceDescriptor,
                    maximumBytes,
                    testFlags,
                    callback,
                    callbackContext,
                    out snapshotDescriptor,
                    out mappingAddress,
                    out logicalSize,
                    out osError);
            }
            else
            {
                status = NativeChaChaPoly.CreateMacAnonymousSnapshot(
                    sourceDescriptor,
                    maximumBytes,
                    out snapshotDescriptor,
                    out mappingAddress,
                    out logicalSize,
                    out osError);
            }
        }
        finally
        {
            if (callbackHandleAllocated)
            {
                callbackHandle.Free();
            }
            if (sourceHandleAdded)
            {
                source.SafeFileHandle.DangerousRelease();
            }
        }

        if (callbackState?.Error is not null)
        {
            CleanupUnexpectedSnapshot(snapshotDescriptor, mappingAddress, logicalSize);
            throw new InvalidOperationException(
                "The private-snapshot test hook failed inside the native copy boundary.",
                callbackState.Error);
        }

        if (status != SnapshotSuccess)
        {
            CleanupUnexpectedSnapshot(snapshotDescriptor, mappingAddress, logicalSize);
            ThrowSnapshotFailure(status, osError, maximumBytes);
        }
        if (snapshotDescriptor < 0)
        {
            throw new IOException("The native snapshot succeeded without returning a read-only descriptor.");
        }
        if (logicalSize > maximumBytes || logicalSize > long.MaxValue)
        {
            CleanupUnexpectedSnapshot(snapshotDescriptor, mappingAddress, logicalSize);
            throw new IOException("The native snapshot returned an invalid logical byte length.");
        }
        if ((mappingAddress == 0) != (logicalSize == 0))
        {
            CleanupUnexpectedSnapshot(snapshotDescriptor, mappingAddress, logicalSize);
            throw new IOException("The native snapshot returned an invalid read-only mapping.");
        }

        SafeFileHandle? snapshotHandle = new((nint)snapshotDescriptor, ownsHandle: true);
        SafeMacSnapshotMapping? mappingHandle = new(mappingAddress, logicalSize);
        try
        {
            var stream = new MappedSnapshotFileStream(
                snapshotHandle,
                mappingHandle,
                checked((long)logicalSize));
            snapshotHandle = null;
            mappingHandle = null;
            return new MacPrivateFileSnapshot(stream);
        }
        finally
        {
            mappingHandle?.Dispose();
            snapshotHandle?.Dispose();
        }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void InvokeSnapshotHook(nint context)
    {
        try
        {
            if (context == 0
                || GCHandle.FromIntPtr(context).Target is not SnapshotHookState state)
            {
                return;
            }
            state.Callback();
        }
        catch (Exception ex)
        {
            if (context != 0
                && GCHandle.FromIntPtr(context).Target is SnapshotHookState state)
            {
                state.Error = ex;
            }
        }
    }

    private static void ThrowSnapshotFailure(int status, int osError, ulong maximumBytes)
    {
        switch (status)
        {
            case SnapshotInvalidArgument:
                throw new InvalidOperationException("The native anonymous-snapshot ABI rejected its arguments.");
            case SnapshotInvalidSource:
                throw new IOException(
                    "The snapshot source must be a regular file opened through a read-only descriptor.");
            case SnapshotSourceChanged:
                throw new InvalidOperationException(
                    "The source file changed while its anonymous snapshot was copied.");
            case SnapshotSystemError:
                throw new IOException(
                    "macOS could not create or populate the anonymous private snapshot.",
                    new Win32Exception(osError));
            case SnapshotTooLarge:
                throw new IOException(
                    $"The input is larger than the private-snapshot limit of {maximumBytes} bytes.");
            case SnapshotInternalError:
                throw new IOException(
                    "The native snapshot did not satisfy its anonymous read-only invariants.");
            default:
                throw new IOException($"The native anonymous-snapshot ABI returned unknown status {status}.");
        }
    }

    private static void CleanupUnexpectedSnapshot(
        int descriptor,
        ulong mappingAddress,
        ulong logicalSize)
    {
        if ((mappingAddress == 0) == (logicalSize == 0))
        {
            _ = NativeChaChaPoly.ReleaseMacAnonymousSnapshot(
                mappingAddress,
                logicalSize,
                out _);
        }
        if (descriptor >= 0)
        {
            using var unexpected = new SafeFileHandle((nint)descriptor, ownsHandle: true);
        }
    }

    private sealed class SnapshotHookState(Action callback)
    {
        internal Action Callback { get; } = callback;
        internal Exception? Error { get; set; }
    }

    /// <summary>
    /// Darwin POSIX-SHM descriptors are mmap-only: read/pread fail with ESPIPE.
    /// This FileStream keeps the independently opened O_RDONLY descriptor for
    /// identity and lifetime while serving bytes exclusively from the complete
    /// PROT_READ mapping. Its logical EOF hides the VM-page-rounded tail.
    /// </summary>
    private sealed class MappedSnapshotFileStream : FileStream, IPrivateSnapshotRandomAccess
    {
        private readonly long _logicalLength;
        private SafeMacSnapshotMapping? _mapping;
        private long _position;

        internal MappedSnapshotFileStream(
            SafeFileHandle descriptor,
            SafeMacSnapshotMapping mapping,
            long logicalLength)
            : base(descriptor, FileAccess.Read, bufferSize: 1, isAsync: false)
        {
            if (logicalLength < 0 || mapping.LogicalLength != (ulong)logicalLength)
            {
                throw new IOException("The anonymous snapshot mapping has an invalid logical length.");
            }
            _mapping = mapping;
            _logicalLength = logicalLength;
        }

        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => _logicalLength;

        public override long Position
        {
            get => _position;
            set
            {
                if ((ulong)value > (ulong)_logicalLength)
                {
                    throw new ArgumentOutOfRangeException(nameof(value));
                }
                _position = value;
            }
        }

        public override int Read(byte[] array, int offset, int count)
        {
            ArgumentNullException.ThrowIfNull(array);
            ArgumentOutOfRangeException.ThrowIfNegative(offset);
            ArgumentOutOfRangeException.ThrowIfNegative(count);
            if (array.Length - offset < count)
            {
                throw new ArgumentException("The destination range escapes its array.", nameof(count));
            }
            return Read(array.AsSpan(offset, count));
        }

        public override int Read(Span<byte> buffer)
        {
            int count = ClampReadCount(buffer.Length, _position);
            if (count == 0)
            {
                return 0;
            }
            RequiredMapping.CopyTo(_position, buffer[..count]);
            _position += count;
            return count;
        }

        public override Task<int> ReadAsync(
            byte[] buffer,
            int offset,
            int count,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return Task.FromResult(Read(buffer, offset, count));
            }
            catch (Exception ex)
            {
                return Task.FromException<int>(ex);
            }
        }

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(Read(buffer.Span));
        }

        public ValueTask<int> ReadAtAsync(
            Memory<byte> destination,
            long offset,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (offset < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(offset));
            }
            int count = ClampReadCount(destination.Length, offset);
            if (count != 0)
            {
                RequiredMapping.CopyTo(offset, destination.Span[..count]);
            }
            return ValueTask.FromResult(count);
        }

        public override int ReadByte()
        {
            if (_position >= _logicalLength)
            {
                return -1;
            }
            Span<byte> value = stackalloc byte[1];
            _ = Read(value);
            return value[0];
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            long target = origin switch
            {
                SeekOrigin.Begin => offset,
                SeekOrigin.Current => checked(_position + offset),
                SeekOrigin.End => checked(_logicalLength + offset),
                _ => throw new ArgumentOutOfRangeException(nameof(origin)),
            };
            Position = target;
            return target;
        }

        public override void Flush()
        {
        }

        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }

        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Write(ReadOnlySpan<byte> buffer) => throw new NotSupportedException();

        public override void CopyTo(Stream destination, int bufferSize)
        {
            ArgumentNullException.ThrowIfNull(destination);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(bufferSize);
            byte[] buffer = new byte[bufferSize];
            try
            {
                int read;
                while ((read = Read(buffer, 0, buffer.Length)) != 0)
                {
                    destination.Write(buffer, 0, read);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(buffer);
            }
        }

        public override async Task CopyToAsync(
            Stream destination,
            int bufferSize,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(destination);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(bufferSize);
            byte[] buffer = new byte[bufferSize];
            try
            {
                int read;
                while ((read = await ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) != 0)
                {
                    await destination.WriteAsync(
                        buffer.AsMemory(0, read),
                        cancellationToken).ConfigureAwait(false);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(buffer);
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                Interlocked.Exchange(ref _mapping, null)?.Dispose();
            }
            base.Dispose(disposing);
        }

        public override async ValueTask DisposeAsync()
        {
            Interlocked.Exchange(ref _mapping, null)?.Dispose();
            await base.DisposeAsync().ConfigureAwait(false);
        }

        private SafeMacSnapshotMapping RequiredMapping =>
            _mapping ?? throw new ObjectDisposedException(nameof(MappedSnapshotFileStream));

        private int ClampReadCount(int requested, long offset)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(requested);
            if (offset < 0 || offset > _logicalLength)
            {
                throw new ArgumentOutOfRangeException(nameof(offset));
            }
            long remaining = _logicalLength - offset;
            return remaining <= 0 ? 0 : (int)Math.Min(requested, remaining);
        }
    }

    private sealed class SafeMacSnapshotMapping : SafeHandle
    {
        internal SafeMacSnapshotMapping(ulong mappingAddress, ulong logicalLength)
            : base(IntPtr.Zero, ownsHandle: true)
        {
            LogicalLength = logicalLength;
            SetHandle(new IntPtr(unchecked((long)mappingAddress)));
        }

        internal ulong LogicalLength { get; }
        public override bool IsInvalid => handle == IntPtr.Zero;

        internal unsafe void CopyTo(long offset, Span<byte> destination)
        {
            if (destination.IsEmpty)
            {
                return;
            }
            if (offset < 0
                || (ulong)offset > LogicalLength
                || (ulong)destination.Length > LogicalLength - (ulong)offset)
            {
                throw new ArgumentOutOfRangeException(nameof(offset));
            }

            bool added = false;
            try
            {
                DangerousAddRef(ref added);
                byte* source = (byte*)DangerousGetHandle() + offset;
                new ReadOnlySpan<byte>(source, destination.Length).CopyTo(destination);
            }
            finally
            {
                if (added)
                {
                    DangerousRelease();
                }
            }
        }

        protected override bool ReleaseHandle()
        {
            try
            {
                return NativeChaChaPoly.ReleaseMacAnonymousSnapshot(
                    unchecked((ulong)handle.ToInt64()),
                    LogicalLength,
                    out _) == SnapshotSuccess;
            }
            catch
            {
                return false;
            }
        }
    }
}

internal interface IPrivateSnapshotRandomAccess
{
    ValueTask<int> ReadAtAsync(
        Memory<byte> destination,
        long offset,
        CancellationToken cancellationToken);
}

/// <summary>
/// Holds the exact macOS source descriptor used by physical-error KPAR2 repair.
/// Unlike <see cref="MacPrivateFileSnapshot"/>, this lease deliberately does not
/// copy the source first: a sector that returns EIO must remain reachable by the
/// recovery copier so it can substitute only that 4096-byte block and let RS
/// reconstruction repair it in a separate candidate.
/// </summary>
internal sealed class MacRecoveryReadLease : IDisposable
{
    private readonly string _canonicalPath;
    private readonly MacFileIdentity _initialIdentity;
    private FileStream? _stream;

    private MacRecoveryReadLease(
        string canonicalPath,
        MacFileIdentity initialIdentity,
        FileStream stream)
    {
        _canonicalPath = canonicalPath;
        _initialIdentity = initialIdentity;
        _stream = stream;
    }

    internal FileStream Stream =>
        _stream ?? throw new ObjectDisposedException(nameof(MacRecoveryReadLease));

    internal static MacRecoveryReadLease Open(string sourcePath, long maximumBytes)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourcePath);
        ArgumentOutOfRangeException.ThrowIfNegative(maximumBytes);

        string canonicalPath = Path.GetFullPath(sourcePath);
        FileStream? stream = null;
        try
        {
            stream = MacSafeFileSystem.OpenReadNoSymlinks(canonicalPath);
            _ = NativePathResolver.RequireCanonicalFilePath(
                stream.SafeFileHandle,
                canonicalPath,
                "KPAR2 recovery source");
            MacFileIdentity identity = MacSafeFileSystem.GetIdentity(stream.SafeFileHandle);
            if (identity.Size is < 0 || identity.Size > maximumBytes)
            {
                throw new IOException(
                    $"The KPAR2 recovery source is outside the supported 0 to {maximumBytes} byte range.");
            }

            var lease = new MacRecoveryReadLease(canonicalPath, identity, stream);
            stream = null;
            return lease;
        }
        finally
        {
            stream?.Dispose();
        }
    }

    /// <summary>
    /// Proves that the complete tolerant copy came from the same, unchanged
    /// object that was no-follow-opened. Physical media errors do not alter this
    /// metadata; namespace substitution, truncation and in-place writes do.
    /// </summary>
    internal void ValidateUnchanged()
    {
        FileStream stream = Stream;
        MacFileIdentity handleIdentity = MacSafeFileSystem.GetIdentity(stream.SafeFileHandle);
        MacFileIdentity pathIdentity = MacSafeFileSystem.GetPathIdentityNoFollow(_canonicalPath);
        if (!handleIdentity.SameObjectAndMetadata(_initialIdentity)
            || !pathIdentity.SameObjectAndMetadata(handleIdentity))
        {
            throw new InvalidOperationException(
                "The descriptor-bound KPAR2 recovery source changed while its candidate was copied.");
        }
    }

    public void Dispose()
    {
        Interlocked.Exchange(ref _stream, null)?.Dispose();
    }
}
