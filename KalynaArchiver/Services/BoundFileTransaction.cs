using System.IO;
using System.Runtime.ExceptionServices;
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

    /// <summary>Creates a set of new files and rolls back only the held originals on failure.</summary>
    internal static void WriteNewBatch(IEnumerable<(string Path, byte[] Contents)> files)
    {
        var parents = new List<SafeFileHandle>();
        var created = new List<BoundFileTransaction>();
        Exception? failure = null;
        var cleanupFailures = new List<Exception>();
        try
        {
            foreach ((string path, byte[] contents) in files)
            {
                // Keep every ancestor and every created file through the final
                // member, so a later failure cannot target a substituted name.
                var ancestors = new Stack<string>();
                for (string? current = System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(path));
                     !string.IsNullOrEmpty(current); current = System.IO.Path.GetDirectoryName(current))
                    ancestors.Push(current);
                while (ancestors.Count != 0)
                    parents.Add(WindowsSafeFileSystem.OpenDirectoryBound(ancestors.Pop(), denyRename: true, requestCreateAccess: false));
                BoundFileTransaction output = CreateNew(path, 4096, FileOptions.WriteThrough);
                created.Add(output);
                output.Stream.Write(contents);
                output.Stream.Flush(true);
            }
        }
        catch (Exception exception)
        {
            failure = exception;
            for (int index = created.Count - 1; index >= 0; index--)
            {
                try { created[index].DeleteBound(); }
                catch (Exception cleanupFailure) { cleanupFailures.Add(cleanupFailure); }
            }
        }
        finally
        {
            for (int index = created.Count - 1; index >= 0; index--)
            {
                try { created[index].Dispose(); }
                catch (Exception cleanupFailure) { cleanupFailures.Add(cleanupFailure); }
            }
            for (int index = parents.Count - 1; index >= 0; index--)
            {
                try { parents[index].Dispose(); }
                catch (Exception cleanupFailure) { cleanupFailures.Add(cleanupFailure); }
            }
        }
        if (failure is not null && cleanupFailures.Count == 0) ExceptionDispatchInfo.Capture(failure).Throw();
        if (failure is not null) cleanupFailures.Insert(0, failure);
        if (cleanupFailures.Count != 0)
            throw new AggregateException("The new-file batch or its bound cleanup failed.", cleanupFailures);
    }

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

        FileStream stream = Stream;
        WindowsSafeFileSystem.RequireSameObject(
            stream.SafeFileHandle,
            _identity,
            _currentPath,
            directory: false);
    }

    public void Dispose()
    {
        try { Interlocked.Exchange(ref _stream, null)?.Dispose(); }
        finally { _parentHandle.Dispose(); }
    }
}
