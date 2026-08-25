using System.Collections;
using System.IO;
using Microsoft.Win32.SafeHandles;

namespace KalynaArchiver.Services;

/// <summary>
/// Holds the Windows extraction root, its parent and any pre-existing empty
/// destination by handle for the complete native-extraction transaction.
/// </summary>
internal sealed class WindowsExtractionStaging : IDisposable
{
    private readonly SafeFileHandle _parentHandle;
    private SafeFileHandle? _stagingHandle;
    private SafeFileHandle? _emptyDestinationHandle;
    private readonly WindowsFileIdentity _stagingIdentity;
    private readonly WindowsFileIdentity? _emptyDestinationIdentity;
    private string _currentStagingPath;
    private bool _committed;
    private bool _disposed;

    internal static Action? TestHookBeforeInstallRename { get; set; }

    internal WindowsExtractionStaging(string outputFolder)
    {
        DestinationPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(outputFolder));
        if (File.Exists(DestinationPath))
        {
            throw new InvalidOperationException("Extraction target must be a directory path.");
        }

        string parentPath = Path.GetDirectoryName(DestinationPath) ?? Environment.CurrentDirectory;
        Directory.CreateDirectory(parentPath);
        _parentHandle = WindowsSafeFileSystem.OpenDirectoryBound(parentPath, denyRename: true);

        try
        {
            if (Directory.Exists(DestinationPath))
            {
                _emptyDestinationHandle = WindowsSafeFileSystem.OpenDirectoryBound(
                    DestinationPath,
                    denyRename: true,
                    requestDeleteAccess: true);
                _emptyDestinationIdentity = WindowsSafeFileSystem.GetIdentity(_emptyDestinationHandle);
                if (Directory.EnumerateFileSystemEntries(DestinationPath).Any())
                {
                    throw new InvalidOperationException("Extraction target must be a new or empty directory.");
                }
            }

            StagingName = $".{Path.GetFileName(DestinationPath)}.{Guid.NewGuid():N}.extract-part";
            StagingPath = Path.Combine(parentPath, StagingName);
            if (File.Exists(StagingPath) || Directory.Exists(StagingPath))
            {
                throw new IOException("The random extraction staging name already exists.");
            }

            Directory.CreateDirectory(StagingPath);
            _stagingHandle = WindowsSafeFileSystem.OpenDirectoryBound(
                StagingPath,
                denyRename: true,
                requestDeleteAccess: true);
            _stagingIdentity = WindowsSafeFileSystem.GetIdentity(_stagingHandle);
            _currentStagingPath = StagingPath;
        }
        catch
        {
            // Never clean a constructor failure by its pathname. If creation
            // succeeded but binding failed, another local actor could already
            // have exchanged that random name; deleting it would target an
            // object whose identity this transaction never owned. Once a
            // handle exists, mark only that exact object for deletion.
            if (_stagingHandle is { IsInvalid: false, IsClosed: false })
            {
                try
                {
                    WindowsSafeFileSystem.MarkForDeletion(_stagingHandle);
                }
                catch
                {
                    // Preserve the construction error. The still-bound object
                    // remains protected from rename until disposal below.
                }
            }

            _stagingHandle?.Dispose();
            _emptyDestinationHandle?.Dispose();
            _parentHandle.Dispose();
            throw;
        }
    }

    internal string DestinationPath { get; }

    internal string StagingPath { get; private set; } = string.Empty;

    internal string StagingName { get; private set; } = string.Empty;

    internal WindowsFileIdentity StagingIdentity => _stagingIdentity;

    internal DirectoryTreeMeasurement MeasureTree(bool allowWriters)
    {
        ThrowIfDisposed();
        SafeFileHandle stagingHandle = _stagingHandle
            ?? throw new InvalidOperationException("The extraction staging handle is unavailable.");
        WindowsSafeFileSystem.RequireSameObject(
            stagingHandle,
            _stagingIdentity,
            _currentStagingPath,
            directory: true);
        return MeasureTreeNoFollow(
            _currentStagingPath,
            _stagingIdentity,
            allowWriters,
            stagingHandle);
    }

    internal void Install()
    {
        ThrowIfDisposed();
        if (_committed)
        {
            throw new InvalidOperationException("Extraction staging was already installed.");
        }

        SafeFileHandle stagingHandle = _stagingHandle
            ?? throw new InvalidOperationException("The extraction staging handle is unavailable.");
        WindowsSafeFileSystem.RequireSameObject(
            stagingHandle,
            _stagingIdentity,
            _currentStagingPath,
            directory: true);

        if (_emptyDestinationHandle is not null)
        {
            WindowsSafeFileSystem.RequireSameObject(
                _emptyDestinationHandle,
                _emptyDestinationIdentity!.Value,
                DestinationPath,
                directory: true);
            if (Directory.EnumerateFileSystemEntries(DestinationPath).Any())
            {
                throw new IOException("The extraction target changed while extraction was running.");
            }

            WindowsSafeFileSystem.MarkForDeletion(_emptyDestinationHandle);
            _emptyDestinationHandle.Dispose();
            _emptyDestinationHandle = null;
            if (Directory.Exists(DestinationPath) || File.Exists(DestinationPath))
            {
                throw new IOException("The bound empty extraction target could not be removed.");
            }
        }

        TestHookBeforeInstallRename?.Invoke();
        WindowsSafeFileSystem.RenameBoundObject(
            stagingHandle,
            _parentHandle,
            Path.GetFileName(DestinationPath),
            replaceExisting: false);
        _currentStagingPath = DestinationPath;
        WindowsSafeFileSystem.RequireSameObject(
            stagingHandle,
            _stagingIdentity,
            DestinationPath,
            directory: true);
        _committed = true;
    }

    internal void Cleanup()
    {
        if (_disposed || _committed || _stagingHandle is null)
        {
            return;
        }

        SafeFileHandle stagingHandle = _stagingHandle;
        WindowsSafeFileSystem.RequireSameObject(
            stagingHandle,
            _stagingIdentity,
            _currentStagingPath,
            directory: true);

        string cleanupName = $".{Path.GetFileName(DestinationPath)}.{Guid.NewGuid():N}.extract-cleanup";
        string cleanupPath = Path.Combine(
            Path.GetDirectoryName(DestinationPath) ?? Environment.CurrentDirectory,
            cleanupName);
        WindowsSafeFileSystem.RenameBoundObject(
            stagingHandle,
            _parentHandle,
            cleanupName,
            replaceExisting: false);
        _currentStagingPath = cleanupPath;
        WindowsSafeFileSystem.RequireSameObject(
            stagingHandle,
            _stagingIdentity,
            cleanupPath,
            directory: true);

        stagingHandle.Dispose();
        _stagingHandle = null;
        DeleteTreeNoFollow(cleanupPath, _stagingIdentity);
    }

    internal static DirectoryTreeMeasurement MeasureTreeNoFollow(
        string rootPath,
        bool allowWriters)
    {
        using SafeFileHandle rootHandle = WindowsSafeFileSystem.OpenDirectoryBound(
            rootPath,
            denyRename: true);
        WindowsFileIdentity identity = WindowsSafeFileSystem.GetIdentity(rootHandle);
        return MeasureTreeNoFollow(rootPath, identity, allowWriters, rootHandle);
    }

    internal static DirectoryTreeMeasurement MeasureTreeNoFollow(
        string rootPath,
        WindowsFileIdentity expectedRootIdentity,
        bool allowWriters)
    {
        return MeasureTreeNoFollow(
            rootPath,
            expectedRootIdentity,
            allowWriters,
            boundRootHandle: null);
    }

    private static DirectoryTreeMeasurement MeasureTreeNoFollow(
        string rootPath,
        WindowsFileIdentity expectedRootIdentity,
        bool allowWriters,
        SafeFileHandle? boundRootHandle)
    {
        SafeFileHandle? rootHandle = null;
        var frames = new Stack<DirectoryFrame>();
        long totalBytes = 0;
        long maxFileBytes = 0;
        int fileCount = 0;
        try
        {
            rootHandle = boundRootHandle
                ?? WindowsSafeFileSystem.OpenDirectoryBound(rootPath, denyRename: true);
            WindowsSafeFileSystem.RequireSameObject(
                rootHandle,
                expectedRootIdentity,
                rootPath,
                directory: true);
            frames.Push(new DirectoryFrame(
                rootPath,
                rootHandle,
                ownsHandle: boundRootHandle is null));
            rootHandle = null;

            while (frames.Count > 0)
            {
                DirectoryFrame frame = frames.Peek();
                if (!frame.Entries.MoveNext())
                {
                    frames.Pop().Dispose();
                    continue;
                }

                string entry = frame.Entries.Current;
                FileAttributes attributes = File.GetAttributes(entry);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                {
                    throw new InvalidDataException(
                        $"The extracted tree contains a reparse point that ZPAQ cannot have created: {entry}");
                }

                if ((attributes & FileAttributes.Directory) != 0)
                {
                    SafeFileHandle directory = WindowsSafeFileSystem.OpenDirectoryBound(entry, denyRename: true);
                    frames.Push(new DirectoryFrame(entry, directory, ownsHandle: true));
                    continue;
                }

                using SafeFileHandle file = WindowsSafeFileSystem.OpenRegularFileForInspection(
                    entry,
                    allowWriters,
                    denyRename: true);
                long length = WindowsSafeFileSystem.GetLength(file);
                totalBytes = checked(totalBytes + length);
                maxFileBytes = Math.Max(maxFileBytes, length);
                fileCount = checked(fileCount + 1);
            }

            return new DirectoryTreeMeasurement(fileCount, totalBytes, maxFileBytes);
        }
        finally
        {
            rootHandle?.Dispose();
            while (frames.Count > 0)
            {
                frames.Pop().Dispose();
            }
        }
    }

    private static void DeleteTreeNoFollow(
        string rootPath,
        WindowsFileIdentity expectedRootIdentity)
    {
        SafeFileHandle? rootHandle = null;
        var frames = new Stack<DeletionFrame>();
        try
        {
            rootHandle = WindowsSafeFileSystem.OpenDirectoryBound(
                rootPath,
                denyRename: true,
                requestDeleteAccess: true);
            WindowsSafeFileSystem.RequireSameObject(
                rootHandle,
                expectedRootIdentity,
                rootPath,
                directory: true);
            frames.Push(new DeletionFrame(rootPath, rootHandle));
            rootHandle = null;

            while (frames.Count > 0)
            {
                DeletionFrame frame = frames.Peek();
                if (frame.Entries.MoveNext())
                {
                    string entry = frame.Entries.Current;
                    SafeFileHandle entryHandle = WindowsSafeFileSystem.OpenEntryForDeletion(entry);
                    WindowsSafeFileSystem.ByHandleFileInformation information =
                        WindowsSafeFileSystem.GetInformation(entryHandle, entry);
                    bool isDirectory = (information.FileAttributes & (uint)FileAttributes.Directory) != 0;
                    bool isReparse = (information.FileAttributes & (uint)FileAttributes.ReparsePoint) != 0;
                    if (isDirectory && !isReparse)
                    {
                        frames.Push(new DeletionFrame(entry, entryHandle));
                    }
                    else
                    {
                        using (entryHandle)
                        {
                            WindowsSafeFileSystem.MarkForDeletion(entryHandle);
                        }
                    }

                    continue;
                }

                frames.Pop();
                frame.Entries.Dispose();
                WindowsSafeFileSystem.MarkForDeletion(frame.Handle);
                frame.Dispose();
            }
        }
        finally
        {
            rootHandle?.Dispose();
            while (frames.Count > 0)
            {
                frames.Pop().Dispose();
            }
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        try
        {
            Cleanup();
        }
        catch
        {
            // Explicit operation paths call Cleanup() themselves so they can
            // preserve and report both the primary and cleanup failures.
            // Dispose must never replace an exception already in flight.
        }
        finally
        {
            _disposed = true;
            _stagingHandle?.Dispose();
            _emptyDestinationHandle?.Dispose();
            _parentHandle.Dispose();
        }
    }

    private sealed class DirectoryFrame : IDisposable
    {
        internal DirectoryFrame(string path, SafeFileHandle handle, bool ownsHandle)
        {
            Handle = handle;
            _ownsHandle = ownsHandle;
            Entries = Directory.EnumerateFileSystemEntries(path).GetEnumerator();
        }

        private readonly bool _ownsHandle;

        internal SafeFileHandle Handle { get; }

        internal IEnumerator<string> Entries { get; }

        public void Dispose()
        {
            Entries.Dispose();
            if (_ownsHandle)
            {
                Handle.Dispose();
            }
        }
    }

    private sealed class DeletionFrame : IDisposable
    {
        internal DeletionFrame(string path, SafeFileHandle handle)
        {
            Handle = handle;
            Entries = Directory.EnumerateFileSystemEntries(path).GetEnumerator();
        }

        internal SafeFileHandle Handle { get; }

        internal IEnumerator<string> Entries { get; }

        public void Dispose()
        {
            Entries.Dispose();
            Handle.Dispose();
        }
    }
}

internal readonly record struct DirectoryTreeMeasurement(
    int FileCount,
    long TotalBytes,
    long MaxFileBytes);
