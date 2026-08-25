using System.IO;
using Microsoft.Win32.SafeHandles;

namespace KalynaArchiver.Services;

/// <summary>
/// Keeps a temporary file and its parent directory bound from creation or
/// validation through the final rename.
/// </summary>
internal sealed class BoundFileTransaction : IDisposable
{
    private readonly SafeFileHandle _parentHandle;
    private readonly string _parentPath;
    private readonly WindowsFileIdentity _identity;
    private FileStream? _stream;
    private string _currentPath;
    private bool _deleted;

    private BoundFileTransaction(
        string path,
        SafeFileHandle parentHandle,
        FileStream stream)
    {
        _currentPath = Path.GetFullPath(path);
        _parentPath = Path.GetDirectoryName(_currentPath) ?? Environment.CurrentDirectory;
        _parentHandle = parentHandle;
        _stream = stream;
        _identity = WindowsSafeFileSystem.GetIdentity(stream.SafeFileHandle);
    }

    internal FileStream Stream => _stream
        ?? throw new ObjectDisposedException(nameof(BoundFileTransaction));

    internal bool IsCommitted { get; private set; }

    internal static BoundFileTransaction CreateNew(
        string path,
        int bufferSize,
        FileOptions options)
    {
        string fullPath = Path.GetFullPath(path);
        string parentPath = Path.GetDirectoryName(fullPath) ?? Environment.CurrentDirectory;
        SafeFileHandle? parentHandle = null;
        SafeFileHandle? fileHandle = null;
        FileStream? stream = null;
        try
        {
            parentHandle = WindowsSafeFileSystem.OpenDirectoryBound(parentPath, denyRename: true);
            bool asynchronous = (options & FileOptions.Asynchronous) != 0;
            fileHandle = WindowsSafeFileSystem.CreateRegularFileBound(
                fullPath,
                asynchronous,
                writeThrough: (options & FileOptions.WriteThrough) != 0,
                sequential: (options & FileOptions.RandomAccess) == 0);
            stream = new FileStream(
                fileHandle,
                FileAccess.ReadWrite,
                bufferSize,
                isAsync: asynchronous);
            fileHandle = null;
            var transaction = new BoundFileTransaction(fullPath, parentHandle, stream);
            stream = null;
            parentHandle = null;
            return transaction;
        }
        catch
        {
            SafeFileHandle? createdHandle = stream?.SafeFileHandle ?? fileHandle;
            if (createdHandle is { IsInvalid: false, IsClosed: false })
            {
                try
                {
                    WindowsSafeFileSystem.MarkForDeletion(createdHandle);
                }
                catch
                {
                    // Preserve the construction failure. The object remains
                    // handle-bound until the disposal immediately below.
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
        string parentPath = Path.GetDirectoryName(fullPath) ?? Environment.CurrentDirectory;
        SafeFileHandle? parentHandle = null;
        SafeFileHandle? fileHandle = null;
        FileStream? stream = null;
        try
        {
            parentHandle = WindowsSafeFileSystem.OpenDirectoryBound(parentPath, denyRename: true);
            fileHandle = WindowsSafeFileSystem.OpenRegularFileForCommit(fullPath);
            stream = new FileStream(fileHandle, FileAccess.Read, bufferSize, isAsync: false);
            fileHandle = null;
            var transaction = new BoundFileTransaction(fullPath, parentHandle, stream);
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
        string destinationParent = Path.GetDirectoryName(fullDestination) ?? Environment.CurrentDirectory;
        if (!string.Equals(_parentPath, destinationParent, StringComparison.OrdinalIgnoreCase))
        {
            throw new IOException("A bound commit must remain in its original directory.");
        }

        FileStream stream = Stream;
        WindowsSafeFileSystem.RequireSameObject(
            stream.SafeFileHandle,
            _identity,
            _currentPath,
            directory: false);
        WindowsSafeFileSystem.RenameBoundObject(
            stream.SafeFileHandle,
            _parentHandle,
            Path.GetFileName(fullDestination),
            overwrite);

        _currentPath = fullDestination;
        WindowsSafeFileSystem.RequireSameObject(
            stream.SafeFileHandle,
            _identity,
            _currentPath,
            directory: false);
        IsCommitted = true;
    }

    internal void DeleteBound()
    {
        if (_deleted)
        {
            return;
        }

        FileStream stream = Stream;
        WindowsSafeFileSystem.RequireSameObject(
            stream.SafeFileHandle,
            _identity,
            _currentPath,
            directory: false);
        WindowsSafeFileSystem.MarkForDeletion(stream.SafeFileHandle);
        _deleted = true;
        IsCommitted = false;
    }

    public void Dispose()
    {
        Interlocked.Exchange(ref _stream, null)?.Dispose();
        _parentHandle.Dispose();
    }
}
