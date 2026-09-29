using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace KalynaArchiver.Services;

/// <summary>
/// Descriptor-relative file creation, validation and commit for shared v13
/// writer code on macOS.
/// </summary>
internal sealed class BoundFileTransaction : IDisposable
{
    private const int OwnerReadWriteMode = 0x0180; // 0600

    private readonly SafeFileHandle _parentHandle;
    private readonly string _parentPath;
    private readonly MacFileIdentity _identity;
    private FileStream? _stream;
    private FileStream? _preparedReadOnly;
    private string _currentName;
    private bool _deleted;

    private BoundFileTransaction(
        string parentPath,
        string currentName,
        SafeFileHandle parentHandle,
        FileStream stream)
    {
        _parentPath = parentPath;
        _currentName = currentName;
        _parentHandle = parentHandle;
        _stream = stream;
        _identity = MacSafeFileSystem.GetIdentity(stream.SafeFileHandle);
    }

    internal FileStream Stream => _stream
        ?? throw new ObjectDisposedException(nameof(BoundFileTransaction));

    internal bool IsCommitted { get; private set; }
    internal static Action<string>? BeforeReadOnlyOpenForTests;

    /// <summary>Acquire an independent kernel read-only handle before unlinking.</summary>
    internal void PrepareReadOnly()
    {
        if (_deleted || _preparedReadOnly is not null || !Stream.CanWrite)
            throw new InvalidOperationException("Read-only preparation requires a named writable transaction.");
        SafeFileHandle writer = Stream.SafeFileHandle;
        BeforeReadOnlyOpenForTests?.Invoke(Path.Combine(_parentPath, _currentName));
        FileStream reader = MacSafeFileSystem.OpenReadAt(_parentHandle, _currentName);
        try
        {
            MacFileIdentity original = MacSafeFileSystem.GetIdentity(writer);
            MacFileIdentity opened = MacSafeFileSystem.GetIdentity(reader.SafeFileHandle);
            if (!original.SameObject(_identity) || !opened.SameObject(_identity))
                throw new IOException("The read-only handle does not identify the exclusively created working file.");
            _preparedReadOnly = reader;
        }
        catch (Exception failure)
        {
            try { reader.Dispose(); }
            catch (Exception cleanupFailure)
            {
                throw new AggregateException("Read-only binding failed and its reader could not be closed.", failure, cleanupFailure);
            }
            throw;
        }
    }

    /// <summary>After joined writes and durable flush, revoke our write capability.</summary>
    internal void SealReadOnly()
    {
        FileStream reader = _preparedReadOnly
            ?? throw new InvalidOperationException("No bound read-only handle was prepared.");
        Stream.Dispose();
        _stream = reader;
        _preparedReadOnly = null;
    }

    internal static BoundFileTransaction CreateNew(
        string path,
        int bufferSize,
        FileOptions options)
    {
        string fullPath = Path.GetFullPath(path);
        string parentPath = MacSafeFileSystem.ResolveExistingRealPath(
            Path.GetDirectoryName(fullPath) ?? Environment.CurrentDirectory);
        string fileName = RequireFileName(fullPath);
        SafeFileHandle? parentHandle = null;
        SafeFileHandle? fileHandle = null;
        FileStream? stream = null;
        try
        {
            parentHandle = MacSafeFileSystem.OpenDirectoryHandle(parentPath);
            fileHandle = MacSafeFileSystem.CreateFileAtExclusive(
                parentHandle,
                fileName,
                checked((ushort)OwnerReadWriteMode));
            MacSafeFileSystem.ValidateRegularFile(fileHandle, requireSingleLink: true, fullPath);
            stream = new FileStream(fileHandle, FileAccess.ReadWrite, bufferSize, isAsync: false);
            fileHandle = null;
            var transaction = new BoundFileTransaction(parentPath, fileName, parentHandle, stream);
            stream = null;
            parentHandle = null;
            return transaction;
        }
        catch
        {
            SafeFileHandle? createdHandle = stream?.SafeFileHandle ?? fileHandle;
            if (parentHandle is { IsInvalid: false, IsClosed: false }
                && createdHandle is { IsInvalid: false, IsClosed: false })
            {
                try
                {
                    MacFileIdentity handleIdentity = MacSafeFileSystem.GetIdentity(createdHandle);
                    MacFileIdentity entryIdentity = MacSafeFileSystem.GetIdentityAt(parentHandle, fileName);
                    if (handleIdentity.SameObject(entryIdentity))
                    {
                        MacSafeFileSystem.UnlinkAt(parentHandle, fileName);
                    }
                }
                catch
                {
                    // Preserve the construction failure and never unlink a
                    // name whose identity could not be proven.
                }
            }

            stream?.Dispose();
            fileHandle?.Dispose();
            parentHandle?.Dispose();
            throw;
        }
    }

    internal static BoundFileTransaction OpenExistingForCommit(
        string path,
        int bufferSize = 4096)
    {
        string fullPath = Path.GetFullPath(path);
        string parentPath = MacSafeFileSystem.ResolveExistingRealPath(
            Path.GetDirectoryName(fullPath) ?? Environment.CurrentDirectory);
        string fileName = RequireFileName(fullPath);
        SafeFileHandle? parentHandle = null;
        SafeFileHandle? fileHandle = null;
        FileStream? stream = null;
        try
        {
            parentHandle = MacSafeFileSystem.OpenDirectoryHandle(parentPath);
            int descriptor = OpenAt(
                parentHandle,
                fileName,
                MacSafeFileSystem.OpenReadOnly
                    | MacSafeFileSystem.OpenCloseOnExec
                    | MacSafeFileSystem.OpenNoFollowAny,
                0);
            if (descriptor < 0)
            {
                throw new IOException(
                    $"macOS could not bind the completed temporary file '{fileName}'.",
                    new Win32Exception(Marshal.GetLastPInvokeError()));
            }

            fileHandle = new SafeFileHandle(descriptor, ownsHandle: true);
            MacSafeFileSystem.ValidateRegularFile(fileHandle, requireSingleLink: true, fullPath);
            stream = new FileStream(fileHandle, FileAccess.Read, bufferSize, isAsync: false);
            fileHandle = null;
            var transaction = new BoundFileTransaction(parentPath, fileName, parentHandle, stream);
            stream = null;
            parentHandle = null;
            return transaction;
        }
        catch
        {
            stream?.Dispose();
            fileHandle?.Dispose();
            parentHandle?.Dispose();
            throw;
        }
    }

    internal void RenameTo(string destinationPath, bool overwrite)
    {
        if (_deleted)
        {
            throw new InvalidOperationException("A deleted bound file cannot be renamed.");
        }

        string fullDestination = Path.GetFullPath(destinationPath);
        string destinationParent = MacSafeFileSystem.ResolveExistingRealPath(
            Path.GetDirectoryName(fullDestination) ?? Environment.CurrentDirectory);
        if (!string.Equals(_parentPath, destinationParent, StringComparison.Ordinal))
        {
            throw new IOException("A bound commit must remain in its original directory.");
        }

        MacFileIdentity handleIdentity = MacSafeFileSystem.GetIdentity(Stream.SafeFileHandle);
        MacFileIdentity entryIdentity = MacSafeFileSystem.GetIdentityAt(_parentHandle, _currentName);
        if (!handleIdentity.SameObject(_identity) || !entryIdentity.SameObject(_identity))
        {
            throw new IOException("The temporary file name no longer identifies the bound object.");
        }

        string destinationName = RequireFileName(fullDestination);
        if (overwrite)
        {
            MacSafeFileSystem.RenameAt(_parentHandle, _currentName, _parentHandle, destinationName);
        }
        else
        {
            MacSafeFileSystem.RenameAtExclusive(_parentHandle, _currentName, _parentHandle, destinationName);
        }

        _currentName = destinationName;
        MacFileIdentity installedIdentity = MacSafeFileSystem.GetIdentityAt(_parentHandle, _currentName);
        if (!installedIdentity.SameObject(_identity))
        {
            throw new IOException("The installed file is not the bound temporary object.");
        }

        IsCommitted = true;
    }

    internal void DeleteBound()
    {
        if (_deleted)
        {
            return;
        }

        MacFileIdentity handleIdentity = MacSafeFileSystem.GetIdentity(Stream.SafeFileHandle);
        MacFileIdentity entryIdentity = MacSafeFileSystem.GetIdentityAt(_parentHandle, _currentName);
        if (!handleIdentity.SameObject(_identity) || !entryIdentity.SameObject(_identity))
        {
            throw new IOException("Refusing to delete a name that no longer identifies the bound file.");
        }

        MacSafeFileSystem.UnlinkAt(_parentHandle, _currentName);
        _deleted = true;
        IsCommitted = false;
    }

    /// <summary>
    /// Proves that the transaction's current public name still denotes the
    /// exact held object. Multi-file commits call this for every member after
    /// all renames, and again after their final content validation.
    /// </summary>
    internal void RequireStillInstalled()
    {
        if (_deleted)
        {
            throw new InvalidOperationException("A deleted bound file cannot be revalidated.");
        }
        if (!IsCommitted)
        {
            throw new InvalidOperationException("A bound file cannot be revalidated as installed before commit.");
        }

        MacFileIdentity handleIdentity = MacSafeFileSystem.GetIdentity(Stream.SafeFileHandle);
        MacFileIdentity entryIdentity = MacSafeFileSystem.GetIdentityAt(_parentHandle, _currentName);
        if (!handleIdentity.SameObject(_identity) || !entryIdentity.SameObject(_identity))
        {
            throw new IOException("A committed file name no longer identifies its bound transaction object.");
        }
    }

    private static string RequireFileName(string path)
    {
        string name = Path.GetFileName(path);
        if (string.IsNullOrWhiteSpace(name)
            || !string.Equals(name, Path.GetFileName(name), StringComparison.Ordinal))
        {
            throw new ArgumentException("The transaction path must end in one file name.", nameof(path));
        }

        return name;
    }

    private static int OpenAt(SafeFileHandle parentHandle, string name, int flags, int mode)
    {
        bool added = false;
        try
        {
            parentHandle.DangerousAddRef(ref added);
            int parentDescriptor = checked((int)parentHandle.DangerousGetHandle());
            return MacSafeFileSystem.PInvokeOpenAt(parentDescriptor, name, flags, mode);
        }
        finally
        {
            if (added)
            {
                parentHandle.DangerousRelease();
            }
        }
    }

    public void Dispose()
    {
        // Both owners exist before sealing. Failure of one close must not skip
        // the other descriptor or the directory owner.
        SecureMemory.DisposeAll(_stream, _preparedReadOnly, _parentHandle);
        _stream = null;
        _preparedReadOnly = null;
    }
}
