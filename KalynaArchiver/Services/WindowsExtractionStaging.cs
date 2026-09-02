using System.Collections;
using System.IO;
using System.Security.Cryptography;
using System.Text;
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
    private string? _validatedTreeFingerprint;

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
        DirectoryTreeMeasurement measurement = MeasureTreeNoFollow(
            _currentStagingPath,
            _stagingIdentity,
            allowWriters,
            stagingHandle);
        if (!allowWriters)
        {
            _validatedTreeFingerprint = measurement.TreeFingerprint;
        }

        return measurement;
    }

    /// <summary>
    /// Renames the validated staging tree onto its destination.
    /// </summary>
    /// <remarks>
    /// The macOS counterpart re-measures the tree at this gate and refuses to
    /// install if its fingerprint moved since validation. Windows used to check
    /// only that the staging directory was still the same object, which says
    /// nothing about the files inside it: another process running as this user
    /// could add, replace or truncate an extracted file between the limit
    /// validation and this rename, and the changed tree would be installed as
    /// though it had been checked. The same final gate now runs here.
    /// </remarks>
    internal void Install(Action<DirectoryTreeMeasurement>? validateFinalTree = null)
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

        string expectedTreeFingerprint = _validatedTreeFingerprint
            ?? MeasureTree(allowWriters: false).TreeFingerprint;

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

        // The hook sits before the last complete bound-tree gate, so a
        // deterministic substitution is caught here rather than merely making
        // the rename below fail by chance.
        TestHookBeforeInstallRename?.Invoke();

        DirectoryTreeMeasurement finalTree = MeasureTreeNoFollow(
            _currentStagingPath,
            _stagingIdentity,
            allowWriters: false,
            stagingHandle);
        validateFinalTree?.Invoke(finalTree);
        if (!string.Equals(finalTree.TreeFingerprint, expectedTreeFingerprint, StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The extracted tree changed after its final validation and before installation.");
        }

        _validatedTreeFingerprint = finalTree.TreeFingerprint;
        WindowsSafeFileSystem.RequireSameObject(
            stagingHandle,
            _stagingIdentity,
            _currentStagingPath,
            directory: true);

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
        var fingerprintEntries = new List<TreeFingerprintEntry>
        {
            new(string.Empty, IsDirectory: true, expectedRootIdentity, Length: 0, LastWriteUtcTicks: 0),
        };
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
                    // FileCount is the common extraction entry budget and
                    // deliberately includes directories.
                    fileCount = checked(fileCount + 1);
                    SafeFileHandle directory = WindowsSafeFileSystem.OpenDirectoryBound(entry, denyRename: true);
                    fingerprintEntries.Add(new TreeFingerprintEntry(
                        Path.GetRelativePath(rootPath, entry),
                        IsDirectory: true,
                        WindowsSafeFileSystem.GetIdentity(directory),
                        Length: 0,
                        Directory.GetLastWriteTimeUtc(entry).Ticks));
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
                fingerprintEntries.Add(new TreeFingerprintEntry(
                    Path.GetRelativePath(rootPath, entry),
                    IsDirectory: false,
                    WindowsSafeFileSystem.GetIdentity(file),
                    length,
                    File.GetLastWriteTimeUtc(entry).Ticks));
            }

            // macOS re-reads the root after the walk so a root replaced during
            // measurement is caught. The bound path is the one that matters
            // here; the unbound overload opens and closes its own root handle.
            if (boundRootHandle is not null)
            {
                WindowsSafeFileSystem.RequireSameObject(
                    boundRootHandle,
                    expectedRootIdentity,
                    rootPath,
                    directory: true);
            }

            return new DirectoryTreeMeasurement(
                fileCount,
                totalBytes,
                maxFileBytes,
                ComputeTreeFingerprint(fingerprintEntries));
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

    /// <summary>
    /// Hashes the whole measured tree into one value, so a later measurement
    /// can be compared against it in constant space.
    /// </summary>
    /// <remarks>
    /// Mirrors <c>MacPlatformSecurity.ComputeTreeFingerprint</c>: entries are
    /// sorted by their relative path so enumeration order cannot influence the
    /// result, and each entry contributes its kind, its object identity, its
    /// length and its modification time. The Windows identity is the volume
    /// serial number and the 64-bit file index, which is what
    /// <c>RequireSameObject</c> compares elsewhere; macOS uses device and
    /// inode for the same purpose.
    ///
    /// This is an integrity check against concurrent modification, not an
    /// authenticator: nothing here is keyed, and an attacker who can write into
    /// the staging tree can also produce a file with the same length and
    /// timestamp. The point is that the object identity has to match too, and
    /// a replaced file gets a new file index.
    /// </remarks>
    private static string ComputeTreeFingerprint(List<TreeFingerprintEntry> entries)
    {
        entries.Sort(static (left, right) => string.CompareOrdinal(left.RelativePath, right.RelativePath));
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        Span<byte> numbers = stackalloc byte[40];
        foreach (TreeFingerprintEntry entry in entries)
        {
            byte[] relativePath = Encoding.UTF8.GetBytes(entry.RelativePath);
            numbers.Clear();
            numbers[0] = entry.IsDirectory ? (byte)1 : (byte)0;
            BitConverter.TryWriteBytes(numbers[1..5], relativePath.Length);
            BitConverter.TryWriteBytes(numbers[5..9], entry.Identity.VolumeSerialNumber);
            BitConverter.TryWriteBytes(numbers[9..13], entry.Identity.FileIndexHigh);
            BitConverter.TryWriteBytes(numbers[13..17], entry.Identity.FileIndexLow);
            BitConverter.TryWriteBytes(numbers[17..25], entry.Length);
            BitConverter.TryWriteBytes(numbers[25..33], entry.LastWriteUtcTicks);
            hash.AppendData(numbers);
            hash.AppendData(relativePath);
        }

        numbers.Clear();
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private readonly record struct TreeFingerprintEntry(
        string RelativePath,
        bool IsDirectory,
        WindowsFileIdentity Identity,
        long Length,
        long LastWriteUtcTicks);

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

// Same shape and member order as the macOS DirectoryTreeMeasurement, so the
// shared validators in ZpaqService read the same fields on both platforms.
internal readonly record struct DirectoryTreeMeasurement(
    // Counts regular files and directories below the held root.
    int FileCount,
    long TotalBytes,
    long MaxFileBytes,
    string TreeFingerprint);
