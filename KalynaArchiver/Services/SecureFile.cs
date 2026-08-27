using System.IO;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace KalynaArchiver.Services;

public static partial class SecureFile
{
    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint DeleteAccess = 0x00010000;
    private const uint OpenExisting = 3;
    private const uint FileAttributeNormal = 0x00000080;
    private const uint FileFlagWriteThrough = 0x80000000;
    private const uint FileFlagOverlapped = 0x40000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagSequentialScan = 0x08000000;
    private const uint FileFlagRandomAccess = 0x10000000;

    public static void DestroyPrefixAndDelete(string? path, int prefixBytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(prefixBytes);
        DestroyPrefixAndSuffixAndDelete(path, prefixBytes, prefixBytes);
    }

    /// <summary>
    /// Overwrites the head and tail of a file and deletes it, with the
    /// overwrite and the deletion bound to the same verified object.
    /// </summary>
    /// <remarks>
    /// The handle is opened once, with DELETE access and no sharing, and it
    /// stays open until the deletion has been recorded against it. Closing it
    /// first and then calling <c>File.Delete(path)</c> would hand the name back
    /// to whoever can write in that directory: the object this method just
    /// destroyed could survive under a new name while a substituted one is
    /// deleted in its place. Delete-on-close names the file record, not the
    /// path, so no such window exists.
    /// </remarks>
    public static void DestroyPrefixAndSuffixAndDelete(
        string? path,
        int prefixBytes,
        int suffixBytes)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return;
        }

        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(prefixBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(suffixBytes);

        int bufferLength = Math.Max(prefixBytes, suffixBytes);
        byte[] buffer = new byte[bufferLength];
        using IDisposable bufferLock = SecureMemory.TryLock(buffer);
        try
        {
            using FileStream stream = OpenVerifiedSingleLinkFileForDestruction(path, asynchronous: false);

            int prefixCount = (int)Math.Min(prefixBytes, stream.Length);
            RandomNumberGenerator.Fill(buffer.AsSpan(0, prefixCount));
            stream.Position = 0;
            stream.Write(buffer, 0, prefixCount);

            int suffixCount = (int)Math.Min(suffixBytes, stream.Length);
            RandomNumberGenerator.Fill(buffer.AsSpan(0, suffixCount));
            stream.Position = stream.Length - suffixCount;
            stream.Write(buffer, 0, suffixCount);
            stream.Flush(flushToDisk: true);

            // Same handle, same object: the name is never resolved again.
            MarkForDeletion(stream);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    [SuppressMessage(
        "Reliability",
        "CA2000:Dispose objects before losing scope",
        Justification = "FileStream takes ownership of the SafeFileHandle on success; the catch path disposes it before rethrowing.")]
    internal static FileStream OpenVerifiedSingleLinkFileForDestruction(string path, bool asynchronous = true)
    {
        string fullPath = Path.GetFullPath(path);
        uint flags = FileAttributeNormal
            | FileFlagWriteThrough
            | FileFlagOpenReparsePoint
            | FileFlagSequentialScan;
        if (asynchronous)
        {
            flags |= FileFlagOverlapped;
        }

        SafeFileHandle handle = CreateFileHandle(
            fullPath,
            GenericRead | GenericWrite | DeleteAccess,
            0,
            0,
            OpenExisting,
            flags,
            0);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            throw new Win32Exception(error, "Could not exclusively open the secure-delete target.");
        }

        try
        {
            ValidateSingleLinkHandle(handle, fullPath);
            return new FileStream(handle, FileAccess.ReadWrite, bufferSize: 4096, isAsync: asynchronous);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    internal static void MarkForDeletion(FileStream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var disposition = new FileDispositionInformation { DeleteFile = 1 };
        if (!SetFileInformationByHandle(
                stream.SafeFileHandle,
                FileInformationClass.FileDispositionInfo,
                ref disposition,
                checked((uint)Marshal.SizeOf<FileDispositionInformation>())))
        {
            throw new Win32Exception(
                Marshal.GetLastPInvokeError(),
                "Could not mark the securely corrupted file for deletion.");
        }
    }

    /// <summary>
    /// Opens a file for reading bound to the object the name resolved to, with
    /// no reparse point followed anywhere along the way.
    /// </summary>
    /// <remarks>
    /// <c>new FileStream(path, ...)</c> follows symbolic links, junctions and
    /// every other reparse point without saying so. The recovery sidecar and
    /// the archive both sit next to each other in a directory the user chose,
    /// which is exactly where a link planted under the expected name redirects
    /// the read somewhere else. macOS already opens both no-follow; this is the
    /// Windows counterpart, so the same guarantee holds on both platforms:
    /// the bytes that get parsed come from the object at the path that was
    /// asked for, or the open fails.
    /// </remarks>
    internal static FileStream OpenReadNoReparse(
        string path,
        FileShare share,
        int bufferSize = 4096,
        bool randomAccess = false,
        bool requireSingleLink = false)
    {
        string fullPath = Path.GetFullPath(path);
        uint flags = FileAttributeNormal | FileFlagOpenReparsePoint
            | (randomAccess ? FileFlagRandomAccess : FileFlagSequentialScan);

        SafeFileHandle handle = CreateFileHandle(
            fullPath,
            GenericRead,
            ToShareMode(share),
            0,
            OpenExisting,
            flags,
            0);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastPInvokeError();
            handle.Dispose();

            // IOException, not the bare Win32Exception: the callers around the
            // recovery and archive opens catch IOException, and a missing or
            // locked file has to keep landing in those handlers rather than
            // escaping as an unhandled crash.
            throw new IOException(
                $"Could not open the file bound to its own object: {fullPath}",
                new Win32Exception(error));
        }

        try
        {
            ValidateReadableRegularFile(handle, fullPath, requireSingleLink);
            return new FileStream(handle, FileAccess.Read, bufferSize, isAsync: false);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Proves an already opened path is a plain file, optionally with exactly
    /// one name, without resolving the path a second time.
    /// </summary>
    internal static void RequireReadableRegularFile(string path, bool requireSingleLink)
    {
        using FileStream stream = OpenReadNoReparse(
            path,
            FileShare.Read | FileShare.Delete,
            requireSingleLink: requireSingleLink);
    }

    private static uint ToShareMode(FileShare share)
    {
        uint mode = 0;
        if ((share & FileShare.Read) != 0) mode |= 0x00000001;
        if ((share & FileShare.Write) != 0) mode |= 0x00000002;
        if ((share & FileShare.Delete) != 0) mode |= 0x00000004;
        return mode;
    }

    private static void ValidateReadableRegularFile(
        SafeFileHandle handle,
        string fullPath,
        bool requireSingleLink)
    {
        if (!GetFileInformationByHandle(handle, out ByHandleFileInformation information))
        {
            throw new IOException(
                $"Could not inspect the opened file handle: {fullPath}",
                new Win32Exception(Marshal.GetLastPInvokeError()));
        }

        if ((information.FileAttributes
                & (uint)(FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
        {
            throw new IOException($"The path is a directory or a reparse point: {fullPath}");
        }

        if (requireSingleLink && information.NumberOfLinks != 1)
        {
            throw new IOException(
                $"The file has more than one hard link and will not be used here: {fullPath}");
        }

        _ = NativePathResolver.RequireCanonicalFilePath(handle, fullPath, "File");
    }

    private static void ValidateSingleLinkHandle(SafeFileHandle handle, string fullPath)
    {
        if (!GetFileInformationByHandle(handle, out ByHandleFileInformation information))
        {
            throw new Win32Exception(
                Marshal.GetLastPInvokeError(),
                "Could not inspect the secure-delete target handle.");
        }

        if ((information.FileAttributes
                & (uint)(FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0
            || information.NumberOfLinks != 1)
        {
            throw new IOException(
                "Secure deletion refuses reparse points and files with multiple hard links.");
        }

        _ = NativePathResolver.RequireCanonicalFilePath(handle, fullPath, "Secure-delete target");
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeFileTime
    {
        public uint LowDateTime;
        public uint HighDateTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public NativeFileTime CreationTime;
        public NativeFileTime LastAccessTime;
        public NativeFileTime LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileDispositionInformation
    {
        public int DeleteFile;
    }

    private enum FileInformationClass
    {
        FileDispositionInfo = 4,
    }

    [LibraryImport(
        "kernel32.dll",
        EntryPoint = "CreateFileW",
        SetLastError = true,
        StringMarshalling = StringMarshalling.Utf16)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial SafeFileHandle CreateFileHandle(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        nint securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        nint templateFile);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetFileInformationByHandle(
        SafeFileHandle file,
        FileInformationClass fileInformationClass,
        ref FileDispositionInformation fileInformation,
        uint bufferSize);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation information);
}
