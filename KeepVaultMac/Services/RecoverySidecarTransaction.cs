using System.ComponentModel;
using System.IO;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace KalynaArchiver.Services;

/// <summary>
/// Descriptor-relative macOS KPAR2 replacement transaction. Every namespace
/// mutation is checked against the inode held by the corresponding descriptor.
/// </summary>
internal sealed class RecoverySidecarTransaction : IDisposable
{
    private const int DestructionBytes = 1024 * 1024;

    private readonly string _recoveryPath;
    private readonly string _quarantinePath;
    private readonly IProgress<string>? _progress;
    private readonly SafeFileHandle _parentHandle;
    private readonly MacFileIdentity _parentIdentity;
    private readonly BoundFileTransaction _temporary;
    private readonly MacFileIdentity _temporaryIdentity;
    private FileStream? _previous;
    private MacFileIdentity _previousIdentity;
    private string? _previousCurrentPath;
    private string _temporaryCurrentPath;
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
        _temporaryCurrentPath = temporaryPath;
        _recoveryPath = recoveryPath;
        _quarantinePath = Path.Combine(
            Path.GetDirectoryName(recoveryPath) ?? Environment.CurrentDirectory,
            $".{Path.GetFileName(recoveryPath)}.{Guid.NewGuid():N}.previous");
        _progress = progress;
        _parentHandle = parentHandle;
        _parentIdentity = MacSafeFileSystem.GetIdentity(parentHandle);
        _temporary = temporary;
        _temporaryIdentity = MacSafeFileSystem.GetIdentity(temporary.Stream.SafeFileHandle);
        RequireEntryIdentity(Path.GetFileName(temporaryPath), _temporaryIdentity, "generated KPAR2 temporary file");
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
        if (!string.Equals(temporaryDirectory, recoveryDirectory, StringComparison.Ordinal))
        {
            throw new IOException("A KPAR2 replacement must keep its temporary and final names in one directory.");
        }

        SafeFileHandle? parentHandle = null;
        BoundFileTransaction? temporary = null;
        try
        {
            // Open the path as supplied with O_NOFOLLOW_ANY before the shared
            // helper canonicalizes it. This rejects a symlink in any parent
            // component instead of accepting the symlink's realpath target.
            parentHandle = MacSafeFileSystem.OpenDirectoryHandle(recoveryDirectory);
            temporary = BoundFileTransaction.CreateNew(
                fullTemporaryPath,
                bufferSize: 1024 * 1024,
                FileOptions.RandomAccess);
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
            VerifyParentIdentity();
            RequireEntryIdentity(
                Path.GetFileName(_temporaryCurrentPath),
                _temporaryIdentity,
                "generated KPAR2 temporary file");
            RecoveryService.SidecarHookBeforeInstallRename?.Invoke();
            cancellationToken.ThrowIfCancellationRequested();
            _temporary.RenameTo(_recoveryPath, overwrite: false);
            _temporaryCurrentPath = _recoveryPath;
            RequireEntryIdentity(
                Path.GetFileName(_recoveryPath),
                _temporaryIdentity,
                "installed KPAR2 sidecar");
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

        // The installed descriptor passed a final complete validation after
        // every pre-commit scheduling boundary. This closes the macOS window
        // where a same-inode in-place write after the first post-rename gate
        // could otherwise survive identity checks. The cleanup hook below is
        // deliberately post-commit: a cleanup failure preserves both objects
        // and must never roll back the validated new sidecar.
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
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or Win32Exception)
        {
            _progress?.Report(
                $"The new KPAR2 file is installed, but the previous one could not be destroyed and remains in transaction quarantine. {ex.Message}");
        }
    }

    private void BindPreviousIfPresent()
    {
        try
        {
            _previous = MacSafeFileSystem.OpenReadWriteNoSymlinks(
                _recoveryPath,
                requireSingleLink: true);
        }
        catch (IOException ex) when (IsMissingPath(ex))
        {
            return;
        }

        _previousIdentity = MacSafeFileSystem.GetIdentity(_previous.SafeFileHandle);
        _previousCurrentPath = _recoveryPath;
        VerifyParentIdentity();
        RequireEntryIdentity(
            Path.GetFileName(_recoveryPath),
            _previousIdentity,
            "previous KPAR2 sidecar");
    }

    private void QuarantinePrevious()
    {
        _ = _previous ?? throw new InvalidOperationException("No previous KPAR2 sidecar is bound.");
        VerifyParentIdentity();
        RequireEntryIdentity(
            Path.GetFileName(_recoveryPath),
            _previousIdentity,
            "previous KPAR2 sidecar");

        RecoveryService.SidecarHookBeforeOldQuarantineRename?.Invoke();
        VerifyParentIdentity();
        RequireEntryIdentity(
            Path.GetFileName(_recoveryPath),
            _previousIdentity,
            "previous KPAR2 sidecar");
        MacSafeFileSystem.RenameAtExclusive(
            _parentHandle,
            Path.GetFileName(_recoveryPath),
            _parentHandle,
            Path.GetFileName(_quarantinePath));
        _previousCurrentPath = _quarantinePath;
        _previousQuarantined = true;
        RequireEntryIdentity(
            Path.GetFileName(_quarantinePath),
            _previousIdentity,
            "quarantined previous KPAR2 sidecar");
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
                _temporaryCurrentPath = failedPath;
                _temporaryInstalled = false;
                temporaryMovedAside = true;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or Win32Exception)
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
                VerifyParentIdentity();
                RequireEntryIdentity(
                    Path.GetFileName(_quarantinePath),
                    _previousIdentity,
                    "quarantined previous KPAR2 sidecar");
                MacSafeFileSystem.RenameAtExclusive(
                    _parentHandle,
                    Path.GetFileName(_quarantinePath),
                    _parentHandle,
                    Path.GetFileName(_recoveryPath));
                _previousCurrentPath = _recoveryPath;
                RequireEntryIdentity(
                    Path.GetFileName(_recoveryPath),
                    _previousIdentity,
                    "restored previous KPAR2 sidecar");
                _previousQuarantined = false;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or Win32Exception)
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
        VerifyParentIdentity();
        RequireEntryIdentity(
            Path.GetFileName(previousPath),
            _previousIdentity,
            "quarantined previous KPAR2 sidecar");
        OverwriteSensitiveRegions(previous);
        RequireEntryIdentity(
            Path.GetFileName(previousPath),
            _previousIdentity,
            "quarantined previous KPAR2 sidecar");
        SecureFile.MarkForDeletion(previous, previousPath);
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
            VerifyParentIdentity();
            RequireEntryIdentity(
                Path.GetFileName(_temporaryCurrentPath),
                _temporaryIdentity,
                "failed generated KPAR2 sidecar");
            OverwriteSensitiveRegions(Stream);
            RequireEntryIdentity(
                Path.GetFileName(_temporaryCurrentPath),
                _temporaryIdentity,
                "failed generated KPAR2 sidecar");
            SecureFile.MarkForDeletion(Stream, _temporaryCurrentPath);
            _temporaryDeleted = true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or Win32Exception)
        {
            _preserveTemporary = true;
            _progress?.Report(
                $"A failed new KPAR2 object could not be securely destroyed and was preserved for manual cleanup. {ex.Message}");
        }
    }

    private void VerifyParentIdentity()
    {
        MacFileIdentity current = MacSafeFileSystem.GetIdentity(_parentHandle);
        if (!current.SameObject(_parentIdentity))
        {
            throw new IOException("The bound KPAR2 parent directory identity changed during the transaction.");
        }
    }

    private void RequireEntryIdentity(
        string entryName,
        MacFileIdentity expectedIdentity,
        string label)
    {
        MacFileIdentity entryIdentity = MacSafeFileSystem.GetIdentityAt(_parentHandle, entryName);
        if (!entryIdentity.SameObject(expectedIdentity))
        {
            throw new IOException($"The directory entry for the {label} no longer identifies its bound inode.");
        }
    }

    private static bool IsMissingPath(IOException exception) =>
        exception.InnerException is Win32Exception { NativeErrorCode: 2 };

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
            MacSafeFileSystem.FullSync(stream.SafeFileHandle);
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
