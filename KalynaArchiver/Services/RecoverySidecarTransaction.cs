using System.ComponentModel;
using System.IO;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace KalynaArchiver.Services;

/// <summary>
/// Windows KPAR2 replacement transaction. Both the generated sidecar and a
/// previous sidecar remain bound by handles across rename, rollback and secure
/// deletion.
/// </summary>
internal sealed class RecoverySidecarTransaction : IDisposable
{
    private const int DestructionBytes = 1024 * 1024;

    private readonly string _recoveryPath;
    private readonly string _quarantinePath;
    private readonly IProgress<string>? _progress;
    private readonly SafeFileHandle _parentHandle;
    private readonly BoundFileTransaction _temporary;
    private FileStream? _previous;
    private WindowsFileIdentity _previousIdentity;
    private string? _previousCurrentPath;
    private bool _previousQuarantined;
    private bool _temporaryInstalled;
    private bool _temporaryDeleted;
    private bool _preserveTemporary;
    private bool _committed;
    private bool _disposed;

    private RecoverySidecarTransaction(
        string temporaryPath,
        string recoveryPath,
        IProgress<string>? progress,
        SafeFileHandle parentHandle,
        BoundFileTransaction temporary)
    {
        _recoveryPath = recoveryPath;
        _quarantinePath = Path.Combine(
            Path.GetDirectoryName(recoveryPath) ?? Environment.CurrentDirectory,
            $".{Path.GetFileName(recoveryPath)}.{Guid.NewGuid():N}.previous");
        _progress = progress;
        _parentHandle = parentHandle;
        _temporary = temporary;
    }

    internal FileStream Stream => _temporary.Stream;

    internal static RecoverySidecarTransaction Create(
        string temporaryPath,
        string recoveryPath,
        IProgress<string>? progress)
    {
        string fullTemporaryPath = Path.GetFullPath(temporaryPath);
        string fullRecoveryPath = Path.GetFullPath(recoveryPath);
        string temporaryDirectory = Path.GetDirectoryName(fullTemporaryPath) ?? Environment.CurrentDirectory;
        string recoveryDirectory = Path.GetDirectoryName(fullRecoveryPath) ?? Environment.CurrentDirectory;
        if (!string.Equals(temporaryDirectory, recoveryDirectory, StringComparison.OrdinalIgnoreCase))
        {
            throw new IOException("A KPAR2 replacement must keep its temporary and final names in one directory.");
        }

        SafeFileHandle? parentHandle = null;
        BoundFileTransaction? temporary = null;
        try
        {
            parentHandle = WindowsSafeFileSystem.OpenDirectoryBound(
                recoveryDirectory,
                denyRename: true);
            temporary = BoundFileTransaction.CreateNew(
                fullTemporaryPath,
                bufferSize: 1024 * 1024,
                FileOptions.RandomAccess | FileOptions.Asynchronous);
            var transaction = new RecoverySidecarTransaction(
                fullTemporaryPath,
                fullRecoveryPath,
                progress,
                parentHandle,
                temporary);
            parentHandle = null;
            temporary = null;
            return transaction;
        }
        catch (Exception operationError)
        {
            if (temporary is not null)
            {
                try
                {
                    temporary.DeleteBound();
                }
                catch (Exception cleanupError)
                {
                    temporary.Dispose();
                    parentHandle?.Dispose();
                    throw new IOException(
                        "KPAR2 transaction creation failed and its exact temporary object could not be removed.",
                        new AggregateException(operationError, cleanupError));
                }
                temporary.Dispose();
            }

            parentHandle?.Dispose();
            throw;
        }
    }

    internal async Task CommitAsync(
        Func<FileStream, CancellationToken, Task> fullValidator,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(fullValidator);

        RecoveryService.SidecarHookBeforeCommitValidation?.Invoke(Stream);
        await fullValidator(Stream, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        BindPreviousIfPresent();

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_previous is not null)
            {
                QuarantinePrevious();
            }

            RecoveryService.SidecarHookAfterQuarantine?.Invoke();
            cancellationToken.ThrowIfCancellationRequested();
            RecoveryService.SidecarHookBeforeInstallRename?.Invoke();
            cancellationToken.ThrowIfCancellationRequested();
            _temporary.RenameTo(_recoveryPath, overwrite: false);
            _temporaryInstalled = true;
            RecoveryService.SidecarHookAfterInstall?.Invoke();
            await fullValidator(Stream, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (_previous is not null)
            {
                RecoveryService.SidecarHookBeforeBackupDestruction?.Invoke(Stream);
                cancellationToken.ThrowIfCancellationRequested();
                await fullValidator(Stream, cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
            }
        }
        catch
        {
            RollBackBeforeCommit();
            throw;
        }

        // The installed object passed a final complete validation after every
        // pre-commit scheduling boundary, and RenameTo proved that the final
        // name identifies that exact file record. The cleanup hook below is
        // deliberately post-commit: a cleanup failure preserves both objects
        // and must never roll back the validated new sidecar. Reusing the
        // validator does not repeat Argon2id because RecoveryService retains
        // the already-derived recovery keys.
        _committed = true;
        if (_previous is null)
        {
            return;
        }

        RecoveryService.SidecarHookBeforePostCommitBackupCleanup?.Invoke();
        try
        {
            DestroyPreviousBound();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            _progress?.Report(
                $"The new KPAR2 file is installed, but the previous one could not be destroyed and remains at: {_quarantinePath}. {ex.Message}");
        }
    }

    private void BindPreviousIfPresent()
    {
        try
        {
            _previous = SecureFile.OpenVerifiedSingleLinkFileForDestruction(
                _recoveryPath,
                asynchronous: false);
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode is 2 or 3)
        {
            return;
        }

        _previousIdentity = WindowsSafeFileSystem.GetIdentity(_previous.SafeFileHandle);
        _previousCurrentPath = _recoveryPath;
    }

    private void QuarantinePrevious()
    {
        FileStream previous = _previous
            ?? throw new InvalidOperationException("No previous KPAR2 sidecar is bound.");
        WindowsSafeFileSystem.RequireSameObject(
            previous.SafeFileHandle,
            _previousIdentity,
            _recoveryPath,
            directory: false);

        RecoveryService.SidecarHookBeforeOldQuarantineRename?.Invoke();
        WindowsSafeFileSystem.RenameBoundObject(
            previous.SafeFileHandle,
            _parentHandle,
            Path.GetFileName(_quarantinePath),
            replaceExisting: false);
        _previousCurrentPath = _quarantinePath;
        WindowsSafeFileSystem.RequireSameObject(
            previous.SafeFileHandle,
            _previousIdentity,
            _quarantinePath,
            directory: false);
        _previousQuarantined = true;
    }

    private void RollBackBeforeCommit()
    {
        bool temporaryMovedAside = false;
        if (_temporaryInstalled)
        {
            string failedPath = Path.Combine(
                Path.GetDirectoryName(_recoveryPath) ?? Environment.CurrentDirectory,
                $".{Path.GetFileName(_recoveryPath)}.{Guid.NewGuid():N}.failed-new");
            try
            {
                _temporary.RenameTo(failedPath, overwrite: false);
                _temporaryInstalled = false;
                temporaryMovedAside = true;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
            {
                _preserveTemporary = true;
                _progress?.Report(
                    $"The validated new KPAR2 object could not be moved aside during rollback and was preserved at {_recoveryPath}. {ex.Message}");
            }
        }

        if (_previousQuarantined && _previous is not null)
        {
            try
            {
                WindowsSafeFileSystem.RequireSameObject(
                    _previous.SafeFileHandle,
                    _previousIdentity,
                    _quarantinePath,
                    directory: false);
                WindowsSafeFileSystem.RenameBoundObject(
                    _previous.SafeFileHandle,
                    _parentHandle,
                    Path.GetFileName(_recoveryPath),
                    replaceExisting: false);
                _previousCurrentPath = _recoveryPath;
                WindowsSafeFileSystem.RequireSameObject(
                    _previous.SafeFileHandle,
                    _previousIdentity,
                    _recoveryPath,
                    directory: false);
                _previousQuarantined = false;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
            {
                _progress?.Report(
                    $"The previous KPAR2 file could not be restored to its name and is preserved at: {_quarantinePath}. {ex.Message}");
            }
        }

        if (temporaryMovedAside)
        {
            TryDestroyTemporaryBound();
        }
    }

    private void DestroyPreviousBound()
    {
        FileStream previous = _previous
            ?? throw new InvalidOperationException("No previous KPAR2 sidecar is bound.");
        string previousPath = _previousCurrentPath
            ?? throw new InvalidOperationException("The previous KPAR2 sidecar has no bound name.");
        WindowsSafeFileSystem.RequireSameObject(
            previous.SafeFileHandle,
            _previousIdentity,
            previousPath,
            directory: false);
        OverwriteSensitiveRegions(previous);
        WindowsSafeFileSystem.RequireSameObject(
            previous.SafeFileHandle,
            _previousIdentity,
            previousPath,
            directory: false);
        WindowsSafeFileSystem.MarkForDeletion(previous.SafeFileHandle);
        _previousQuarantined = false;
    }

    private void TryDestroyTemporaryBound()
    {
        if (_temporaryDeleted || _preserveTemporary)
        {
            return;
        }

        try
        {
            OverwriteSensitiveRegions(Stream);
            _temporary.DeleteBound();
            _temporaryDeleted = true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            _preserveTemporary = true;
            _progress?.Report(
                $"A failed new KPAR2 object could not be securely destroyed and was preserved for manual cleanup. {ex.Message}");
        }
    }

    private static void OverwriteSensitiveRegions(FileStream stream)
    {
        byte[] buffer = new byte[DestructionBytes];
        using IDisposable memoryLock = SecureMemory.TryLock(buffer);
        try
        {
            int prefixLength = checked((int)Math.Min(buffer.Length, stream.Length));
            RandomNumberGenerator.Fill(buffer.AsSpan(0, prefixLength));
            stream.Position = 0;
            stream.Write(buffer, 0, prefixLength);

            int suffixLength = checked((int)Math.Min(buffer.Length, stream.Length));
            RandomNumberGenerator.Fill(buffer.AsSpan(0, suffixLength));
            stream.Position = stream.Length - suffixLength;
            stream.Write(buffer, 0, suffixLength);
            stream.Flush(flushToDisk: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (!_committed && !_temporaryDeleted && !_preserveTemporary)
        {
            TryDestroyTemporaryBound();
        }

        _previous?.Dispose();
        _temporary.Dispose();
        _parentHandle.Dispose();
    }
}
