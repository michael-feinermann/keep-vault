using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace KalynaArchiver.Services;

/// <summary>
/// Handle-bound Windows filesystem primitives used at security-sensitive
/// write/rename/install boundaries.
/// </summary>
internal static partial class WindowsSafeFileSystem
{
    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint DeleteAccess = 0x00010000;
    private const uint FileReadAttributes = 0x00000080;
    private const uint FileListDirectory = 0x00000001;
    private const uint FileAddFile = 0x00000002;
    private const uint FileAddSubdirectory = 0x00000004;
    private const uint FileTraverse = 0x00000020;

    private const uint ShareRead = 0x00000001;
    private const uint ShareWrite = 0x00000002;
    private const uint ShareDelete = 0x00000004;

    private const uint CreateNew = 1;
    private const uint OpenExisting = 3;

    private const uint FileAttributeNormal = 0x00000080;
    private const uint FileFlagWriteThrough = 0x80000000;
    private const uint FileFlagOverlapped = 0x40000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagSequentialScan = 0x08000000;
    private const uint FileFlagRandomAccess = 0x10000000;

    internal static SafeFileHandle OpenDirectoryBound(
        string path,
        bool denyRename,
        bool requestDeleteAccess = false)
    {
        string fullPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        uint desiredAccess = FileListDirectory
            | FileAddFile
            | FileAddSubdirectory
            | FileTraverse
            | FileReadAttributes;
        if (requestDeleteAccess)
        {
            desiredAccess |= DeleteAccess;
        }

        uint shareMode = ShareRead | ShareWrite | (denyRename ? 0u : ShareDelete);
        SafeFileHandle handle = CreateFile(
            fullPath,
            desiredAccess,
            shareMode,
            nint.Zero,
            OpenExisting,
            FileFlagBackupSemantics | FileFlagOpenReparsePoint,
            nint.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            throw new IOException(
                $"Could not bind the directory object: {fullPath}",
                new Win32Exception(error));
        }

        try
        {
            ByHandleFileInformation information = GetInformation(handle, fullPath);
            if ((information.FileAttributes & (uint)FileAttributes.Directory) == 0
                || (information.FileAttributes & (uint)FileAttributes.ReparsePoint) != 0)
            {
                throw new IOException($"The path is not a plain directory: {fullPath}");
            }

            _ = NativePathResolver.RequireCanonicalFilePath(handle, fullPath, "Directory");
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    internal static SafeFileHandle CreateRegularFileBound(
        string path,
        bool asynchronous,
        bool writeThrough,
        bool sequential)
    {
        string fullPath = Path.GetFullPath(path);
        uint flags = FileAttributeNormal | FileFlagOpenReparsePoint;
        if (asynchronous) flags |= FileFlagOverlapped;
        if (writeThrough) flags |= FileFlagWriteThrough;
        flags |= sequential ? FileFlagSequentialScan : FileFlagRandomAccess;

        SafeFileHandle handle = CreateFile(
            fullPath,
            GenericRead | GenericWrite | DeleteAccess,
            0,
            nint.Zero,
            CreateNew,
            flags,
            nint.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            throw new IOException(
                $"Could not create the bound temporary file: {fullPath}",
                new Win32Exception(error));
        }

        try
        {
            ValidateRegularFile(handle, fullPath, requireSingleLink: true);
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    internal static SafeFileHandle OpenRegularFileForCommit(string path, bool asynchronous = false)
    {
        string fullPath = Path.GetFullPath(path);
        uint flags = FileAttributeNormal | FileFlagOpenReparsePoint | FileFlagSequentialScan;
        if (asynchronous) flags |= FileFlagOverlapped;

        SafeFileHandle handle = CreateFile(
            fullPath,
            GenericRead | DeleteAccess,
            ShareRead,
            nint.Zero,
            OpenExisting,
            flags,
            nint.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            throw new IOException(
                $"Could not bind the completed temporary file: {fullPath}",
                new Win32Exception(error));
        }

        try
        {
            ValidateRegularFile(handle, fullPath, requireSingleLink: true);
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    internal static SafeFileHandle OpenRegularFileForInspection(
        string path,
        bool allowWriters,
        bool denyRename,
        bool requestDeleteAccess = false,
        bool requestReadAccess = false)
    {
        string fullPath = Path.GetFullPath(path);
        uint desiredAccess = FileReadAttributes
            | (requestReadAccess ? GenericRead : 0u)
            | (requestDeleteAccess ? DeleteAccess : 0u);
        uint shareMode = ShareRead
            | (allowWriters ? ShareWrite : 0u)
            | (denyRename ? 0u : ShareDelete);
        SafeFileHandle handle = CreateFile(
            fullPath,
            desiredAccess,
            shareMode,
            nint.Zero,
            OpenExisting,
            FileAttributeNormal | FileFlagOpenReparsePoint,
            nint.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            throw new IOException(
                $"Could not bind the file for no-follow inspection: {fullPath}",
                new Win32Exception(error));
        }

        try
        {
            ValidateRegularFile(handle, fullPath, requireSingleLink: true);
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    internal static SafeFileHandle OpenEntryForDeletion(string path)
    {
        string fullPath = Path.GetFullPath(path);
        SafeFileHandle handle = CreateFile(
            fullPath,
            FileReadAttributes | DeleteAccess,
            ShareRead | ShareWrite,
            nint.Zero,
            OpenExisting,
            FileFlagBackupSemantics | FileFlagOpenReparsePoint,
            nint.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            throw new IOException(
                $"Could not bind the cleanup entry: {fullPath}",
                new Win32Exception(error));
        }

        try
        {
            _ = NativePathResolver.RequireCanonicalFilePath(handle, fullPath, "Cleanup entry");
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    internal static WindowsFileIdentity GetIdentity(SafeFileHandle handle)
    {
        ByHandleFileInformation information = GetInformation(handle, "opened filesystem object");
        return new WindowsFileIdentity(
            information.VolumeSerialNumber,
            information.FileIndexHigh,
            information.FileIndexLow);
    }

    internal static long GetLength(SafeFileHandle handle)
    {
        ByHandleFileInformation information = GetInformation(handle, "opened file");
        return checked(((long)information.FileSizeHigh << 32) | information.FileSizeLow);
    }

    internal static ByHandleFileInformation GetInformation(SafeFileHandle handle, string displayPath)
    {
        if (!GetFileInformationByHandle(handle, out ByHandleFileInformation information))
        {
            throw new IOException(
                $"Could not inspect the bound filesystem object: {displayPath}",
                new Win32Exception(Marshal.GetLastPInvokeError()));
        }

        return information;
    }

    internal static void ValidateRegularFile(
        SafeFileHandle handle,
        string expectedPath,
        bool requireSingleLink)
    {
        ByHandleFileInformation information = GetInformation(handle, expectedPath);
        if ((information.FileAttributes
                & (uint)(FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
        {
            throw new IOException($"The path is not a plain file: {expectedPath}");
        }

        if (requireSingleLink && information.NumberOfLinks != 1)
        {
            throw new IOException($"The file has more than one hard link: {expectedPath}");
        }

        _ = NativePathResolver.RequireCanonicalFilePath(handle, expectedPath, "File");
    }

    internal static void RequireSameObject(
        SafeFileHandle handle,
        WindowsFileIdentity expectedIdentity,
        string expectedPath,
        bool directory)
    {
        ByHandleFileInformation information = GetInformation(handle, expectedPath);
        uint forbidden = (uint)FileAttributes.ReparsePoint;
        bool isDirectory = (information.FileAttributes & (uint)FileAttributes.Directory) != 0;
        if ((information.FileAttributes & forbidden) != 0 || isDirectory != directory)
        {
            throw new IOException($"The bound object changed type or became a reparse point: {expectedPath}");
        }

        WindowsFileIdentity actualIdentity = new(
            information.VolumeSerialNumber,
            information.FileIndexHigh,
            information.FileIndexLow);
        if (actualIdentity != expectedIdentity)
        {
            throw new IOException($"The bound filesystem object identity changed: {expectedPath}");
        }

        _ = NativePathResolver.RequireCanonicalFilePath(handle, expectedPath, directory ? "Directory" : "File");
    }

    internal static void RenameBoundObject(
        SafeFileHandle objectHandle,
        SafeFileHandle destinationParentHandle,
        string destinationName,
        bool replaceExisting)
    {
        if (string.IsNullOrWhiteSpace(destinationName)
            || !string.Equals(destinationName, Path.GetFileName(destinationName), StringComparison.Ordinal))
        {
            throw new ArgumentException("The rename destination must be one file name.", nameof(destinationName));
        }

        byte[] nameBytes = System.Text.Encoding.Unicode.GetBytes(destinationName);
        int rootOffset = IntPtr.Size == 8 ? 8 : 4;
        int lengthOffset = rootOffset + IntPtr.Size;
        int nameOffset = lengthOffset + sizeof(uint);
        // FILE_RENAME_INFO ends in WCHAR FileName[1] and is padded to the
        // platform's pointer alignment.  SetFileInformationByHandle rejects a
        // buffer that only reaches the last byte named by FileNameLength on
        // current Windows versions (ERROR_INVALID_PARAMETER).  Keep the native
        // minimum structure size and a trailing UTF-16 NUL in the zeroed
        // allocation; FileNameLength still deliberately excludes that NUL.
        int nativeMinimumSize = IntPtr.Size == 8 ? 24 : 16;
        int bufferLength = checked(Math.Max(
            nativeMinimumSize,
            nameOffset + nameBytes.Length + sizeof(char)));
        nint buffer = Marshal.AllocHGlobal(bufferLength);
        bool parentAdded = false;
        try
        {
            Marshal.Copy(new byte[bufferLength], 0, buffer, bufferLength);
            Marshal.WriteByte(buffer, replaceExisting ? (byte)1 : (byte)0);
            destinationParentHandle.DangerousAddRef(ref parentAdded);
            Marshal.WriteIntPtr(buffer, rootOffset, destinationParentHandle.DangerousGetHandle());
            Marshal.WriteInt32(buffer, lengthOffset, nameBytes.Length);
            Marshal.Copy(nameBytes, 0, buffer + nameOffset, nameBytes.Length);

            int status = NtSetInformationFile(
                objectHandle,
                out _,
                buffer,
                checked((uint)bufferLength),
                NtFileRenameInformation);
            if (status < 0)
            {
                int win32Error = checked((int)RtlNtStatusToDosError(status));
                throw new IOException(
                    $"Could not rename the bound object to '{destinationName}'.",
                    new Win32Exception(win32Error));
            }
        }
        finally
        {
            if (parentAdded)
            {
                destinationParentHandle.DangerousRelease();
            }

            Marshal.FreeHGlobal(buffer);
        }
    }

    internal static void MarkForDeletion(SafeFileHandle handle)
    {
        int deleteFile = 1;
        nint buffer = Marshal.AllocHGlobal(sizeof(int));
        try
        {
            Marshal.WriteInt32(buffer, deleteFile);
            if (!SetFileInformationByHandle(
                    handle,
                    FileInformationClass.FileDispositionInfo,
                    buffer,
                    sizeof(int)))
            {
                throw new IOException(
                    "Could not mark the bound filesystem object for deletion.",
                    new Win32Exception(Marshal.GetLastPInvokeError()));
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private enum FileInformationClass
    {
        FileDispositionInfo = 4,
    }

    private const int NtFileRenameInformation = 10;

    [StructLayout(LayoutKind.Sequential)]
    private struct IoStatusBlock
    {
        internal nint Status;
        internal nuint Information;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ByHandleFileInformation
    {
        internal uint FileAttributes;
        internal uint CreationTimeLow;
        internal uint CreationTimeHigh;
        internal uint LastAccessTimeLow;
        internal uint LastAccessTimeHigh;
        internal uint LastWriteTimeLow;
        internal uint LastWriteTimeHigh;
        internal uint VolumeSerialNumber;
        internal uint FileSizeHigh;
        internal uint FileSizeLow;
        internal uint NumberOfLinks;
        internal uint FileIndexHigh;
        internal uint FileIndexLow;
    }

    [LibraryImport(
        "kernel32.dll",
        EntryPoint = "CreateFileW",
        SetLastError = true,
        StringMarshalling = StringMarshalling.Utf16)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial SafeFileHandle CreateFile(
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
    private static partial bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation information);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetFileInformationByHandle(
        SafeFileHandle file,
        FileInformationClass fileInformationClass,
        nint fileInformation,
        uint bufferSize);

    [LibraryImport("ntdll.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial int NtSetInformationFile(
        SafeFileHandle file,
        out IoStatusBlock ioStatusBlock,
        nint fileInformation,
        uint length,
        int fileInformationClass);

    [LibraryImport("ntdll.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial uint RtlNtStatusToDosError(int status);
}

internal readonly record struct WindowsFileIdentity(
    uint VolumeSerialNumber,
    uint FileIndexHigh,
    uint FileIndexLow);
