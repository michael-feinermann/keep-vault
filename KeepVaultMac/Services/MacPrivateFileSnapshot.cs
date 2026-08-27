using Microsoft.Win32.SafeHandles;

namespace KalynaArchiver.Services;

internal sealed class MacPrivateFileSnapshot : IDisposable
{
    private FileStream? _stream;
    private string? _directory;
    private SafeFileHandle? _directoryHandle;
    private readonly MacFileIdentity _directoryIdentity;

    private MacPrivateFileSnapshot(
        string path,
        string directory,
        FileStream stream,
        SafeFileHandle directoryHandle,
        MacFileIdentity directoryIdentity)
    {
        SnapshotPath = path;
        _directory = directory;
        _stream = stream;
        _directoryHandle = directoryHandle;
        _directoryIdentity = directoryIdentity;
    }

    internal string SnapshotPath { get; }
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
        ArgumentNullException.ThrowIfNull(source);
        if (!source.CanRead || !source.CanSeek)
        {
            throw new ArgumentException("A private input snapshot requires a readable, seekable file.", nameof(source));
        }

        string directory = MacSafeFileSystem.ResolveExistingRealPath(
            Directory.CreateTempSubdirectory("keep-vault-file-").FullName);
        string safeName = string.IsNullOrWhiteSpace(fileName) ? "input.bin" : Path.GetFileName(fileName);
        string target = Path.Combine(directory, safeName);
        FileStream? verified = null;
        SafeFileHandle? directoryHandle = null;
        try
        {
            directoryHandle = MacSafeFileSystem.OpenDirectoryHandle(directory);
            MacFileIdentity directoryIdentity = MacSafeFileSystem.GetIdentity(directoryHandle);
            MacSafeFileSystem.RequirePathStillNamesHandle(directoryHandle, directory);
            MacSafeFileSystem.SetUnixFileMode(directoryHandle, 0x01C0 /* 0700 */);

            MacSafeFileSystem.CloneOpenedFileIntoDirectory(
                source.SafeFileHandle,
                directoryHandle,
                safeName);
            verified = MacSafeFileSystem.OpenReadAt(directoryHandle, safeName);
            MacSafeFileSystem.SetUnixFileMode(verified.SafeFileHandle, 0x0100 /* 0400 */);
            _ = NativePathResolver.RequireCanonicalFilePath(verified.SafeFileHandle, target, "Private input snapshot");
            MacSafeFileSystem.RequirePathStillNamesHandle(directoryHandle, directory);
            var snapshot = new MacPrivateFileSnapshot(
                target,
                directory,
                verified,
                directoryHandle,
                directoryIdentity);
            verified = null;
            directoryHandle = null;
            return snapshot;
        }
        catch (Exception operationError)
        {
            verified?.Dispose();
            try
            {
                DeleteBound(directory, directoryHandle);
                directoryHandle = null;
            }
            catch (Exception cleanupError)
            {
                throw new IOException(
                    "Private input snapshot creation failed and its exact bound directory could not be cleaned up.",
                    new AggregateException(operationError, cleanupError));
            }
            throw;
        }
        finally
        {
            directoryHandle?.Dispose();
        }
    }

    internal static Task<MacPrivateFileSnapshot> CaptureAsync(
        string sourcePath,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string fullPath = Path.GetFullPath(sourcePath);
        using FileStream source = MacSafeFileSystem.OpenReadNoSymlinks(fullPath);
        _ = NativePathResolver.RequireCanonicalFilePath(source.SafeFileHandle, fullPath, "Sensitive input");
        return Task.FromResult(Capture(source, Path.GetFileName(fullPath)));
    }

    public void Dispose()
    {
        Interlocked.Exchange(ref _stream, null)?.Dispose();
        string? directory = Interlocked.Exchange(ref _directory, null);
        SafeFileHandle? directoryHandle = Interlocked.Exchange(ref _directoryHandle, null);
        if (directory is not null && directoryHandle is not null)
        {
            try
            {
                MacSafeFileSystem.DeleteDirectoryContentsDescriptor(directoryHandle);
                directoryHandle.Dispose();
                directoryHandle = null;
                MacSafeFileSystem.DeleteDirectoryTreeBound(directory, _directoryIdentity);
            }
            finally
            {
                directoryHandle?.Dispose();
            }
        }
    }

    private static void DeleteBound(string directory, SafeFileHandle? directoryHandle)
    {
        if (directoryHandle is null)
        {
            return;
        }

        MacFileIdentity identity = MacSafeFileSystem.GetIdentity(directoryHandle);
        try
        {
            MacSafeFileSystem.DeleteDirectoryContentsDescriptor(directoryHandle);
            directoryHandle.Dispose();
            directoryHandle = null;
            MacSafeFileSystem.DeleteDirectoryTreeBound(directory, identity);
        }
        finally
        {
            directoryHandle?.Dispose();
        }
    }
}
