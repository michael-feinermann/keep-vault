using System.ComponentModel;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace KalynaArchiver.Services;

internal static partial class MacSafeFileSystem
{
    internal const int OpenReadOnly = 0x0000;
    internal const int OpenReadWrite = 0x0002;
    internal const int OpenDirectory = 0x00100000;
    internal const int OpenCloseOnExec = 0x01000000;
    internal const int OpenNoFollowAny = 0x20000000;
    private const uint CloneNoOwnerCopy = 0x0002;
    private const uint CloneNoFollowAny = 0x0008;
    private const uint CloneResolveBeneath = 0x0010;
    private const int FFullFsync = 51;
    private const uint RegularFileMode = 0x8000;
    private const uint DirectoryMode = 0x4000;
    private const uint SymbolicLinkMode = 0xA000;
    private const uint FileTypeMask = 0xF000;

    internal static Action<string>? TestHookBeforeDirectoryDescend { get; set; }

    internal static FileStream OpenReadNoSymlinks(string path, bool requireSingleLink = false)
    {
        SafeFileHandle handle = OpenHandleNoSymlinks(path, write: false);
        try
        {
            ValidateRegularFile(handle, requireSingleLink, path);
            return new FileStream(handle, FileAccess.Read, bufferSize: 1024 * 1024, isAsync: false);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    internal static FileStream OpenReadWriteNoSymlinks(string path, bool requireSingleLink)
    {
        SafeFileHandle handle = OpenHandleNoSymlinks(path, write: true);
        try
        {
            ValidateRegularFile(handle, requireSingleLink, path);

            // The descriptor comes from a plain open(2) and is therefore
            // synchronous. Constructing the stream with isAsync: true would
            // throw, because FileStream requires a handle that was opened for
            // overlapped I/O — a Windows concept with no macOS equivalent.
            // Asynchronous reads and writes still work; .NET runs them on the
            // thread pool, exactly as for the read-only path above.
            return new FileStream(handle, FileAccess.ReadWrite, bufferSize: 1024 * 1024, isAsync: false);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    internal static SafeFileHandle OpenHandleNoSymlinks(string path, bool write)
    {
        if (!OperatingSystem.IsMacOS())
        {
            throw new PlatformNotSupportedException();
        }

        string fullPath = Path.GetFullPath(path);
        int descriptor = Open(fullPath, (write ? OpenReadWrite : OpenReadOnly) | OpenCloseOnExec | OpenNoFollowAny);
        if (descriptor < 0)
        {
            int error = Marshal.GetLastPInvokeError();
            throw new IOException(
                $"macOS refused the symlink-safe open: {fullPath}",
                new Win32Exception(error));
        }

        return new SafeFileHandle(descriptor, ownsHandle: true);
    }

    internal static void CloneOpenedFileIntoDirectory(
        SafeFileHandle sourceHandle,
        string destinationDirectory,
        string destinationFileName)
    {
        ArgumentNullException.ThrowIfNull(sourceHandle);
        using SafeFileHandle directoryHandle = OpenDirectoryHandle(destinationDirectory);
        CloneOpenedFileIntoDirectory(sourceHandle, directoryHandle, destinationFileName);
    }

    internal static void CloneOpenedFileIntoDirectory(
        SafeFileHandle sourceHandle,
        SafeFileHandle destinationDirectoryHandle,
        string destinationFileName)
    {
        ArgumentNullException.ThrowIfNull(sourceHandle);
        ArgumentNullException.ThrowIfNull(destinationDirectoryHandle);
        if (string.IsNullOrWhiteSpace(destinationFileName)
            || !string.Equals(destinationFileName, Path.GetFileName(destinationFileName), StringComparison.Ordinal))
        {
            throw new ArgumentException("A private clone destination must be a single file name.", nameof(destinationFileName));
        }

        bool sourceAdded = false;
        bool directoryAdded = false;
        try
        {
            sourceHandle.DangerousAddRef(ref sourceAdded);
            destinationDirectoryHandle.DangerousAddRef(ref directoryAdded);
            int sourceDescriptor = checked((int)sourceHandle.DangerousGetHandle());
            int targetDescriptor = checked((int)destinationDirectoryHandle.DangerousGetHandle());
            if (FCloneFileAt(
                    sourceDescriptor,
                    targetDescriptor,
                    destinationFileName,
                    CloneNoOwnerCopy | CloneNoFollowAny | CloneResolveBeneath) != 0)
            {
                int errorCode = Marshal.GetLastPInvokeError();
                const int Exdev = 18;
                const int Enotsup = 45;
                const int Eopnotsupp = 102;
                if (errorCode == Exdev || errorCode == Enotsup || errorCode == Eopnotsupp)
                {
                    StreamCopyDescriptorIntoPrivateDirectory(
                        sourceDescriptor,
                        destinationDirectoryHandle,
                        destinationFileName);
                }
                else
                {
                    throw new IOException(
                        "macOS could not create the required descriptor-bound atomic copy-on-write snapshot.",
                        new Win32Exception(errorCode));
                }
            }
        }
        finally
        {
            if (directoryAdded)
            {
                destinationDirectoryHandle.DangerousRelease();
            }

            if (sourceAdded)
            {
                sourceHandle.DangerousRelease();
            }
        }
    }

    private static unsafe void StreamCopyDescriptorIntoPrivateDirectory(
        int sourceDescriptor,
        SafeFileHandle targetDirectoryHandle,
        string destinationFileName)
    {
        if (FStat(sourceDescriptor, out DarwinStat beforeStat) != 0)
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), "macOS could not stat source descriptor before copy.");
        }

        using SafeFileHandle targetFileHandle = CreateFileAtExclusive(
            targetDirectoryHandle,
            destinationFileName,
            0x0180 /* 0600 */);
        int targetFileFd = checked((int)targetFileHandle.DangerousGetHandle());

        using var hashStream = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        byte[] buffer = new byte[64 * 1024];
        long sourceOffset = 0;
        long totalRead = 0;
        try
        {
            fixed (byte* pBuf = buffer)
            {
                while (sourceOffset < beforeStat.Size)
                {
                    int toRead = checked((int)Math.Min(buffer.Length, beforeStat.Size - sourceOffset));
                    nint bytesRead;
                    while (true)
                    {
                        bytesRead = PRead(sourceDescriptor, pBuf, (nuint)toRead, sourceOffset);
                        if (bytesRead < 0)
                        {
                            int err = Marshal.GetLastPInvokeError();
                            if (err == 4 /* EINTR */) continue;
                            throw new Win32Exception(err, "macOS pread failed during cross-volume snapshot.");
                        }
                        break;
                    }
                    if (bytesRead == 0)
                    {
                        break;
                    }

                    long chunkWritten = 0;
                    while (chunkWritten < bytesRead)
                    {
                        nint written = PWrite(targetFileFd, pBuf + chunkWritten, (nuint)(bytesRead - chunkWritten), sourceOffset + chunkWritten);
                        if (written < 0)
                        {
                            int err = Marshal.GetLastPInvokeError();
                            if (err == 4 /* EINTR */) continue;
                            throw new Win32Exception(err, "macOS pwrite failed during cross-volume snapshot.");
                        }
                        if (written == 0)
                        {
                            throw new IOException("macOS pwrite made no progress during cross-volume snapshot.");
                        }
                        chunkWritten += written;
                    }

                    hashStream.AppendData(buffer, 0, (int)bytesRead);
                    sourceOffset += bytesRead;
                    totalRead += bytesRead;
                }
            }
            MacSafeFileSystem.FullSync(targetFileHandle);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
        byte[] writtenHash = hashStream.GetHashAndReset();

        using var verifyHashStream = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        long verifyOffset = 0;
        try
        {
            fixed (byte* pBuf = buffer)
            {
                while (verifyOffset < beforeStat.Size)
                {
                    int toRead = checked((int)Math.Min(buffer.Length, beforeStat.Size - verifyOffset));
                    nint bytesRead;
                    while (true)
                    {
                        bytesRead = PRead(sourceDescriptor, pBuf, (nuint)toRead, verifyOffset);
                        if (bytesRead < 0)
                        {
                            int err = Marshal.GetLastPInvokeError();
                            if (err == 4 /* EINTR */) continue;
                            throw new Win32Exception(err, "macOS pread verification pass failed.");
                        }
                        break;
                    }
                    if (bytesRead == 0)
                    {
                        break;
                    }
                    verifyHashStream.AppendData(buffer, 0, (int)bytesRead);
                    verifyOffset += bytesRead;
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
        byte[] verifyHash = verifyHashStream.GetHashAndReset();

        if (FStat(sourceDescriptor, out DarwinStat afterStat) != 0)
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), "macOS could not stat source descriptor after copy.");
        }

        bool stable = beforeStat.Device == afterStat.Device
            && beforeStat.Inode == afterStat.Inode
            && beforeStat.Size == afterStat.Size
            && beforeStat.ModificationTime.Seconds == afterStat.ModificationTime.Seconds
            && beforeStat.ModificationTime.Nanoseconds == afterStat.ModificationTime.Nanoseconds
            && beforeStat.ChangeTime.Seconds == afterStat.ChangeTime.Seconds
            && beforeStat.ChangeTime.Nanoseconds == afterStat.ChangeTime.Nanoseconds
            && totalRead == beforeStat.Size
            && verifyOffset == beforeStat.Size
            && CryptographicOperations.FixedTimeEquals(writtenHash, verifyHash);

        if (!stable)
        {
            MacFileIdentity targetIdentity = GetIdentity(targetFileHandle);
            MacFileIdentity entryIdentity = GetIdentityAt(targetDirectoryHandle, destinationFileName);
            if (targetIdentity.SameObject(entryIdentity)
                && targetIdentity.LinkCount == 1
                && entryIdentity.LinkCount == 1)
            {
                UnlinkAt(targetDirectoryHandle, destinationFileName);
            }
            throw new InvalidOperationException("Source file metadata or content mutated concurrently during cross-volume snapshot copy.");
        }
    }

    [LibraryImport("libSystem.B.dylib", EntryPoint = "pread", SetLastError = true)]
    private static unsafe partial nint PRead(int descriptor, byte* buffer, nuint count, long offset);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "pwrite", SetLastError = true)]
    private static unsafe partial nint PWrite(int descriptor, byte* buffer, nuint count, long offset);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "dup", SetLastError = true)]
    private static partial int Dup(int descriptor);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "fdopendir", SetLastError = true)]
    private static partial nint FdOpenDir(int descriptor);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "readdir", SetLastError = true)]
    private static partial nint ReadDir(nint dirp);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "rewinddir")]
    private static partial void RewindDir(nint dirp);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "closedir", SetLastError = true)]
    private static partial int CloseDir(nint dirp);

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct DarwinDirent
    {
        public ulong d_ino;
        public ulong d_seekoff;
        public ushort d_reclen;
        public ushort d_namlen;
        public byte d_type;
        public fixed byte d_name[1024];
    }

    internal static MacFileIdentity GetIdentity(SafeFileHandle handle)
    {
        ArgumentNullException.ThrowIfNull(handle);
        bool added = false;
        try
        {
            handle.DangerousAddRef(ref added);
            int descriptor = checked((int)handle.DangerousGetHandle());
            if (FStat(descriptor, out DarwinStat status) != 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "macOS could not inspect the open file descriptor.");
            }

            return IdentityFromStat(status);
        }
        finally
        {
            if (added)
            {
                handle.DangerousRelease();
            }
        }
    }

    private static MacFileIdentity IdentityFromStat(DarwinStat status) => new(
        status.Device,
        status.Inode,
        status.LinkCount,
        status.Mode,
        status.Size,
        status.ModificationTime.Seconds,
        status.ModificationTime.Nanoseconds,
        status.ChangeTime.Seconds,
        status.ChangeTime.Nanoseconds);

    internal static MacFileIdentity GetPathIdentityNoFollow(string path)
    {
        if (LStat(Path.GetFullPath(path), out DarwinStat status) != 0)
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), "macOS could not inspect the file path without following links.");
        }

        return IdentityFromStat(status);
    }

    internal static string ResolveExistingRealPath(string path)
    {
        string fullPath = Path.GetFullPath(path);
        nint resolved = RealPath(fullPath, 0);
        if (resolved == 0)
        {
            throw new IOException(
                $"macOS could not canonicalize an existing private path: {fullPath}",
                new Win32Exception(Marshal.GetLastPInvokeError()));
        }

        try
        {
            return Marshal.PtrToStringUTF8(resolved)
                ?? throw new IOException("macOS returned an invalid canonical private path.");
        }
        finally
        {
            Free(resolved);
        }
    }

    internal static void ValidateRegularFile(SafeFileHandle handle, bool requireSingleLink, string displayPath)
    {
        MacFileIdentity identity = GetIdentity(handle);
        if ((identity.Mode & FileTypeMask) != RegularFileMode)
        {
            throw new IOException($"Only a regular file is accepted: {displayPath}");
        }

        if (requireSingleLink && identity.LinkCount != 1)
        {
            throw new IOException($"The operation refuses files with multiple hard links: {displayPath}");
        }
    }

    internal static void RequirePathStillNamesHandle(SafeFileHandle handle, string path)
    {
        MacFileIdentity handleIdentity = GetIdentity(handle);
        MacFileIdentity pathIdentity = GetPathIdentityNoFollow(path);
        if (!handleIdentity.SameObject(pathIdentity))
        {
            throw new IOException("The file path was replaced while its security properties were being verified.");
        }
    }

    /// <summary>
    /// Reports whether <paramref name="path"/> still names the exact object
    /// behind <paramref name="handle"/>.
    /// </summary>
    /// <remarks>
    /// A pathname that now names a different object, or names nothing at all,
    /// answers false instead of raising. Callers that must refuse to unlink a
    /// foreign replacement need that as an outcome they can act on, not as an
    /// error that would mask the reason they were rolling back.
    /// </remarks>
    internal static bool PathStillNamesHandle(SafeFileHandle handle, string path)
    {
        MacFileIdentity handleIdentity = GetIdentity(handle);
        if (LStat(Path.GetFullPath(path), out DarwinStat status) != 0)
        {
            return false;
        }

        return handleIdentity.SameObject(IdentityFromStat(status));
    }

    internal static void FullSync(SafeFileHandle handle)
    {
        bool added = false;
        try
        {
            handle.DangerousAddRef(ref added);
            int descriptor = checked((int)handle.DangerousGetHandle());
            if (FcntlNoArgument(descriptor, FFullFsync) != 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "F_FULLFSYNC failed for sensitive file data.");
            }
        }
        finally
        {
            if (added)
            {
                handle.DangerousRelease();
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DarwinTimespec
    {
        internal long Seconds;
        internal long Nanoseconds;
    }

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct DarwinStat
    {
        internal int Device;
        internal ushort Mode;
        internal ushort LinkCount;
        internal ulong Inode;
        internal uint Uid;
        internal uint Gid;
        internal int Rdev;
        internal DarwinTimespec AccessTime;
        internal DarwinTimespec ModificationTime;
        internal DarwinTimespec ChangeTime;
        internal DarwinTimespec BirthTime;
        internal long Size;
        internal long Blocks;
        internal int BlockSize;
        internal uint Flags;
        internal uint Generation;
        internal int Spare;
        internal fixed long Reserved[2];
    }

    internal static SafeFileHandle OpenDirectoryHandle(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        int descriptor = Open(path, OpenReadOnly | OpenDirectory | OpenCloseOnExec | OpenNoFollowAny);
        if (descriptor < 0)
        {
            throw new IOException(
                $"macOS could not open directory handle for '{path}'.",
                new Win32Exception(Marshal.GetLastPInvokeError()));
        }
        return new SafeFileHandle(descriptor, ownsHandle: true);
    }

    internal static SafeFileHandle OpenDirectoryHandleAt(SafeFileHandle parentHandle, string relativePath)
    {
        ArgumentNullException.ThrowIfNull(parentHandle);
        ArgumentException.ThrowIfNullOrWhiteSpace(relativePath);
        bool added = false;
        try
        {
            parentHandle.DangerousAddRef(ref added);
            int parentFd = checked((int)parentHandle.DangerousGetHandle());
            int descriptor = PInvokeOpenAt(parentFd, relativePath, OpenReadOnly | OpenDirectory | OpenCloseOnExec | OpenNoFollowAny, 0);
            if (descriptor < 0)
            {
                throw new IOException(
                    $"macOS could not open directory handle for '{relativePath}' relative to parent descriptor.",
                    new Win32Exception(Marshal.GetLastPInvokeError()));
            }
            return new SafeFileHandle(descriptor, ownsHandle: true);
        }
        finally
        {
            if (added)
            {
                parentHandle.DangerousRelease();
            }
        }
    }

    internal static FileStream OpenReadAt(
        SafeFileHandle parentHandle,
        string name,
        bool requireSingleLink = true)
    {
        ArgumentNullException.ThrowIfNull(parentHandle);
        if (string.IsNullOrWhiteSpace(name)
            || !string.Equals(name, Path.GetFileName(name), StringComparison.Ordinal))
        {
            throw new ArgumentException("A descriptor-relative file open requires one entry name.", nameof(name));
        }

        bool added = false;
        SafeFileHandle? fileHandle = null;
        try
        {
            parentHandle.DangerousAddRef(ref added);
            int parentFd = checked((int)parentHandle.DangerousGetHandle());
            int fileFd = PInvokeOpenAt(
                parentFd,
                name,
                OpenReadOnly | OpenCloseOnExec | OpenNoFollowAny,
                0);
            if (fileFd < 0)
            {
                throw new IOException(
                    $"macOS could not open '{name}' relative to the bound directory.",
                    new Win32Exception(Marshal.GetLastPInvokeError()));
            }

            fileHandle = new SafeFileHandle(fileFd, ownsHandle: true);
            ValidateRegularFile(fileHandle, requireSingleLink, name);
            var stream = new FileStream(fileHandle, FileAccess.Read, bufferSize: 1024 * 1024, isAsync: false);
            fileHandle = null;
            return stream;
        }
        finally
        {
            fileHandle?.Dispose();
            if (added)
            {
                parentHandle.DangerousRelease();
            }
        }
    }

    internal static void SetUnixFileMode(SafeFileHandle fileHandle, ushort mode)
    {
        ArgumentNullException.ThrowIfNull(fileHandle);
        if ((mode & ~0x01FF) != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(mode), "Only POSIX permission bits 0000 through 0777 are accepted.");
        }

        bool added = false;
        try
        {
            fileHandle.DangerousAddRef(ref added);
            int fd = checked((int)fileHandle.DangerousGetHandle());
            if (PInvokeFChmod(fd, mode) != 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "macOS fchmod failed for the bound file.");
            }
        }
        finally
        {
            if (added)
            {
                fileHandle.DangerousRelease();
            }
        }
    }

    /// <summary>
    /// Creates one private regular file below a bound directory without calling
    /// the variadic openat(2) entry point from managed code.
    /// </summary>
    /// <remarks>
    /// Apple's arm64 ABI puts variadic arguments on the stack. A conventional
    /// four-argument P/Invoke therefore does not pass openat's optional mode
    /// where libc reads it. mkostempsat_np has a fixed signature and atomically
    /// returns a descriptor for a 0600 file. The random name is then moved to
    /// the requested name with RENAME_EXCL and every namespace boundary is
    /// checked against that descriptor.
    /// </remarks>
    internal static unsafe SafeFileHandle CreateFileAtExclusive(
        SafeFileHandle parentHandle,
        string name,
        ushort mode = 0x0180 /* 0600 */)
    {
        ArgumentNullException.ThrowIfNull(parentHandle);
        if (string.IsNullOrWhiteSpace(name)
            || !string.Equals(name, Path.GetFileName(name), StringComparison.Ordinal))
        {
            throw new ArgumentException("A descriptor-relative file create requires one entry name.", nameof(name));
        }
        if ((mode & ~0x0180) != 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(mode),
                "A private file may grant only owner read and owner write permissions.");
        }

        const int TemporaryNameCharacters = 24;
        byte[] temporaryNameBytes = Encoding.ASCII.GetBytes(
            $".keep-vault-create.{new string('X', TemporaryNameCharacters)}\0");
        bool parentAdded = false;
        SafeFileHandle? createdHandle = null;
        string? currentName = null;
        try
        {
            parentHandle.DangerousAddRef(ref parentAdded);
            int parentFd = checked((int)parentHandle.DangerousGetHandle());
            MacFileIdentity parentIdentity = GetIdentity(parentHandle);
            int createdFd;
            fixed (byte* template = temporaryNameBytes)
            {
                createdFd = PInvokeMkOStempsAtNp(
                    parentFd,
                    template,
                    suffixLength: 0,
                    OpenCloseOnExec);
            }
            if (createdFd < 0)
            {
                throw new IOException(
                    "macOS could not create a descriptor-bound private temporary file.",
                    new Win32Exception(Marshal.GetLastPInvokeError()));
            }

            int terminator = Array.IndexOf(temporaryNameBytes, (byte)0);
            if (terminator <= 0)
            {
                CloseDescriptor(createdFd);
                throw new IOException("macOS returned an invalid private temporary file name.");
            }
            currentName = Encoding.ASCII.GetString(temporaryNameBytes, 0, terminator);
            createdHandle = new SafeFileHandle(createdFd, ownsHandle: true);
            ValidateRegularFile(createdHandle, requireSingleLink: true, currentName);
            SetUnixFileMode(createdHandle, mode);
            MacFileIdentity createdIdentity = GetIdentity(createdHandle);
            if ((createdIdentity.Mode & 0x01FF) != mode)
            {
                throw new IOException("The private temporary file does not have the requested owner-only mode.");
            }

            if (!parentIdentity.SameObject(GetIdentity(parentHandle)))
            {
                throw new IOException("The private-file parent directory changed during creation.");
            }
            MacFileIdentity temporaryEntry = GetIdentityAt(parentHandle, currentName);
            if (!createdIdentity.SameObject(temporaryEntry)
                || temporaryEntry.LinkCount != 1)
            {
                throw new IOException("The private temporary file name no longer identifies the created descriptor.");
            }

            RenameAtExclusive(parentHandle, currentName, parentHandle, name);
            currentName = name;
            if (!parentIdentity.SameObject(GetIdentity(parentHandle)))
            {
                throw new IOException("The private-file parent directory changed during installation.");
            }
            MacFileIdentity installedEntry = GetIdentityAt(parentHandle, name);
            MacFileIdentity installedHandle = GetIdentity(createdHandle);
            if (!installedHandle.SameObject(installedEntry)
                || installedHandle.LinkCount != 1
                || installedEntry.LinkCount != 1
                || (installedHandle.Mode & 0x01FF) != mode)
            {
                throw new IOException("The installed private file does not identify the created descriptor.");
            }

            SafeFileHandle result = createdHandle;
            createdHandle = null;
            currentName = null;
            return result;
        }
        catch
        {
            if (createdHandle is not null && currentName is not null)
            {
                try
                {
                    MacFileIdentity handleIdentity = GetIdentity(createdHandle);
                    MacFileIdentity entryIdentity = GetIdentityAt(parentHandle, currentName);
                    if (handleIdentity.SameObject(entryIdentity)
                        && handleIdentity.LinkCount == 1
                        && entryIdentity.LinkCount == 1)
                    {
                        UnlinkAt(parentHandle, currentName);
                    }
                }
                catch
                {
                    // Preserve the construction error and never unlink an
                    // entry whose identity cannot be proved.
                }
            }
            throw;
        }
        finally
        {
            createdHandle?.Dispose();
            CryptographicOperations.ZeroMemory(temporaryNameBytes);
            if (parentAdded)
            {
                parentHandle.DangerousRelease();
            }
        }
    }

    internal static void MkdirAt(SafeFileHandle parentHandle, string relativePath, int mode)
    {
        ArgumentNullException.ThrowIfNull(parentHandle);
        ArgumentException.ThrowIfNullOrWhiteSpace(relativePath);
        bool added = false;
        try
        {
            parentHandle.DangerousAddRef(ref added);
            int parentFd = checked((int)parentHandle.DangerousGetHandle());
            if (PInvokeMkdirAt(parentFd, relativePath, (uint)mode) != 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), $"macOS could not mkdir '{relativePath}' relative to parent descriptor.");
            }
        }
        finally
        {
            if (added)
            {
                parentHandle.DangerousRelease();
            }
        }
    }

    internal static bool IsDirectoryEmptyDescriptor(SafeFileHandle dirHandle)
    {
        ArgumentNullException.ThrowIfNull(dirHandle);
        bool added = false;
        try
        {
            dirHandle.DangerousAddRef(ref added);
            int fd = checked((int)dirHandle.DangerousGetHandle());
            int dupFd = Dup(fd);
            if (dupFd < 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "macOS could not dup directory descriptor.");
            }
            nint dirp = FdOpenDir(dupFd);
            if (dirp == 0)
            {
                CloseDescriptor(dupFd);
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "macOS fdopendir failed.");
            }
            RewindDir(dirp);
            try
            {
                while (true)
                {
                    nint entryPtr = ReadDir(dirp);
                    if (entryPtr == 0)
                    {
                        break;
                    }
                    unsafe
                    {
                        var entry = (DarwinDirent*)entryPtr;
                        string name = Marshal.PtrToStringUTF8((nint)entry->d_name, entry->d_namlen);
                        if (name is not ("." or ".."))
                        {
                            return false;
                        }
                    }
                }
                return true;
            }
            finally
            {
                CloseDir(dirp);
            }
        }
        finally
        {
            if (added)
            {
                dirHandle.DangerousRelease();
            }
        }
    }

    internal static IReadOnlyList<MacDirectoryEntry> ReadDirectoryEntriesNoFollow(
        SafeFileHandle dirHandle)
    {
        ArgumentNullException.ThrowIfNull(dirHandle);
        MacFileIdentity directoryIdentity = GetIdentity(dirHandle);
        if ((directoryIdentity.Mode & FileTypeMask) != DirectoryMode)
        {
            throw new IOException("A descriptor-relative directory read requires a directory handle.");
        }

        var entries = new List<MacDirectoryEntry>();
        bool added = false;
        try
        {
            dirHandle.DangerousAddRef(ref added);
            int fd = checked((int)dirHandle.DangerousGetHandle());
            int dupFd = Dup(fd);
            if (dupFd < 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "macOS could not dup directory descriptor.");
            }

            nint dirp = FdOpenDir(dupFd);
            if (dirp == 0)
            {
                CloseDescriptor(dupFd);
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "macOS fdopendir failed.");
            }
            RewindDir(dirp);

            try
            {
                while (true)
                {
                    nint entryPtr = ReadDir(dirp);
                    if (entryPtr == 0)
                    {
                        break;
                    }

                    unsafe
                    {
                        var entry = (DarwinDirent*)entryPtr;
                        string name = Marshal.PtrToStringUTF8((nint)entry->d_name, entry->d_namlen)
                            ?? throw new IOException("macOS returned an invalid directory entry name.");
                        if (name is "." or "..")
                        {
                            continue;
                        }

                        // Never trust d_type. The no-follow stat is the
                        // classification that every later descriptor open must
                        // still match.
                        entries.Add(new MacDirectoryEntry(name, GetIdentityAt(dirHandle, name)));
                    }
                }
            }
            finally
            {
                CloseDir(dirp);
            }
        }
        finally
        {
            if (added)
            {
                dirHandle.DangerousRelease();
            }
        }

        if (!GetIdentity(dirHandle).SameObject(directoryIdentity))
        {
            throw new IOException("The bound directory changed identity while it was enumerated.");
        }

        entries.Sort(static (left, right) => string.CompareOrdinal(left.Name, right.Name));
        return entries;
    }

    internal static List<(string FullPath, string RelativePath)> EnumerateDirectoryTreeNoFollow(string rootDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootDirectory);
        string fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(rootDirectory));
        using SafeFileHandle rootHandle = OpenDirectoryHandle(fullRoot);
        RequirePathStillNamesHandle(rootHandle, fullRoot);
        MacFileIdentity rootIdentity = GetIdentity(rootHandle);
        var results = new List<(string FullPath, string RelativePath)>();
        var visitedDirectories = new HashSet<(int Device, ulong Inode)>
        {
            (rootIdentity.Device, rootIdentity.Inode),
        };
        EnumerateDirectoryTreeNoFollowDescriptor(
            rootHandle,
            fullRoot,
            string.Empty,
            results,
            visitedDirectories);
        RequirePathStillNamesHandle(rootHandle, fullRoot);
        return results;
    }

    private static void EnumerateDirectoryTreeNoFollowDescriptor(
        SafeFileHandle dirHandle,
        string currentFullPath,
        string relativePrefix,
        List<(string FullPath, string RelativePath)> results,
        HashSet<(int Device, ulong Inode)> visitedDirectories)
    {
        ArgumentNullException.ThrowIfNull(dirHandle);
        bool added = false;
        try
        {
            dirHandle.DangerousAddRef(ref added);
            int fd = checked((int)dirHandle.DangerousGetHandle());
            int dupFd = Dup(fd);
            if (dupFd < 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "macOS could not dup directory descriptor.");
            }
            nint dirp = FdOpenDir(dupFd);
            if (dirp == 0)
            {
                CloseDescriptor(dupFd);
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "macOS fdopendir failed.");
            }
            RewindDir(dirp);
            try
            {
                while (true)
                {
                    nint entryPtr = ReadDir(dirp);
                    if (entryPtr == 0)
                    {
                        break;
                    }
                    unsafe
                    {
                        var entry = (DarwinDirent*)entryPtr;
                        string name = Marshal.PtrToStringUTF8((nint)entry->d_name, entry->d_namlen);
                        if (name is "." or "..")
                        {
                            continue;
                        }

                        string itemRelPath = string.IsNullOrEmpty(relativePrefix) ? name : Path.Combine(relativePrefix, name);
                        string itemFullPath = Path.Combine(currentFullPath, name);

                        // d_type is only a directory-stream hint. Classify the
                        // exact name without following links and then prove the
                        // descriptor opened for use still denotes that inode.
                        // This closes the readdir-to-open substitution window.
                        MacFileIdentity entryIdentity = GetIdentityAt(dirHandle, name);
                        uint fileType = (uint)(entryIdentity.Mode & FileTypeMask);
                        if (fileType == SymbolicLinkMode)
                        {
                            throw new IOException($"Die Eingabe enthält einen symbolischen Link: {itemFullPath}");
                        }

                        if (fileType == DirectoryMode)
                        {
                            TestHookBeforeDirectoryDescend?.Invoke(itemFullPath);
                            int subFd = PInvokeOpenAt(fd, name, OpenReadOnly | OpenDirectory | OpenCloseOnExec | OpenNoFollowAny, 0);
                            if (subFd < 0)
                            {
                                int err = Marshal.GetLastPInvokeError();
                                throw new IOException(
                                    $"macOS could not open subdirectory '{itemFullPath}' without following symlinks.",
                                    new Win32Exception(err));
                            }
                            using (var subHandle = new SafeFileHandle(subFd, ownsHandle: true))
                            {
                                MacFileIdentity openedIdentity = GetIdentity(subHandle);
                                if (!openedIdentity.SameObject(entryIdentity)
                                    || (openedIdentity.Mode & FileTypeMask) != DirectoryMode)
                                {
                                    throw new IOException(
                                        $"Der Verzeichniseintrag wurde vor dem sicheren Abstieg ausgetauscht: {itemFullPath}");
                                }

                                if (!visitedDirectories.Add((openedIdentity.Device, openedIdentity.Inode)))
                                {
                                    throw new IOException($"Die Eingabe enthält einen Verzeichniszyklus: {itemFullPath}");
                                }

                                try
                                {
                                    EnumerateDirectoryTreeNoFollowDescriptor(
                                        subHandle,
                                        itemFullPath,
                                        itemRelPath,
                                        results,
                                        visitedDirectories);
                                }
                                finally
                                {
                                    visitedDirectories.Remove((openedIdentity.Device, openedIdentity.Inode));
                                }

                                MacFileIdentity afterWalkIdentity = GetIdentity(subHandle);
                                MacFileIdentity finalEntryIdentity = GetIdentityAt(dirHandle, name);
                                if (!afterWalkIdentity.SameObject(openedIdentity)
                                    || !finalEntryIdentity.SameObject(openedIdentity))
                                {
                                    throw new IOException(
                                        $"Der Verzeichniseintrag wurde während des sicheren Walks ausgetauscht: {itemFullPath}");
                                }
                            }
                        }
                        else if (fileType == RegularFileMode)
                        {
                            if (entryIdentity.LinkCount != 1)
                            {
                                throw new IOException($"Die Eingabe enthält eine Datei mit mehreren Hardlinks: {itemFullPath}");
                            }

                            int fileFd = PInvokeOpenAt(
                                fd,
                                name,
                                OpenReadOnly | OpenCloseOnExec | OpenNoFollowAny,
                                0);
                            if (fileFd < 0)
                            {
                                throw new IOException(
                                    $"macOS could not bind input file '{itemFullPath}' without following links.",
                                    new Win32Exception(Marshal.GetLastPInvokeError()));
                            }

                            using var fileHandle = new SafeFileHandle(fileFd, ownsHandle: true);
                            MacFileIdentity openedIdentity = GetIdentity(fileHandle);
                            MacFileIdentity finalEntryIdentity = GetIdentityAt(dirHandle, name);
                            if (!openedIdentity.SameObject(entryIdentity)
                                || !finalEntryIdentity.SameObject(openedIdentity)
                                || openedIdentity.LinkCount != 1
                                || (openedIdentity.Mode & FileTypeMask) != RegularFileMode)
                            {
                                throw new IOException(
                                    $"Der Dateieintrag wurde während des sicheren Walks ausgetauscht: {itemFullPath}");
                            }

                            results.Add((itemFullPath, itemRelPath));
                        }
                        else
                        {
                            throw new IOException($"Eingabe ist weder eine reguläre Datei noch ein Verzeichnis: {itemFullPath}");
                        }
                    }
                }
            }
            finally
            {
                CloseDir(dirp);
            }
        }
        finally
        {
            if (added)
            {
                dirHandle.DangerousRelease();
            }
        }
    }

    internal static void DeleteDirectoryContentsDescriptor(SafeFileHandle dirHandle)
    {
        ArgumentNullException.ThrowIfNull(dirHandle);
        bool added = false;
        try
        {
            dirHandle.DangerousAddRef(ref added);
            int fd = checked((int)dirHandle.DangerousGetHandle());
            int dupFd = Dup(fd);
            if (dupFd < 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "macOS could not dup directory descriptor.");
            }
            nint dirp = FdOpenDir(dupFd);
            if (dirp == 0)
            {
                CloseDescriptor(dupFd);
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "macOS fdopendir failed.");
            }
            RewindDir(dirp);
            try
            {
                while (true)
                {
                    nint entryPtr = ReadDir(dirp);
                    if (entryPtr == 0)
                    {
                        break;
                    }
                    unsafe
                    {
                        var entry = (DarwinDirent*)entryPtr;
                        string name = Marshal.PtrToStringUTF8((nint)entry->d_name, entry->d_namlen);
                        if (name is "." or "..")
                        {
                            continue;
                        }

                        MacFileIdentity entryIdentity = GetIdentityAt(dirHandle, name);
                        uint fileType = (uint)(entryIdentity.Mode & FileTypeMask);
                        if (fileType == DirectoryMode)
                        {
                            int subFd = PInvokeOpenAt(fd, name, OpenReadOnly | OpenDirectory | OpenCloseOnExec | OpenNoFollowAny, 0);
                            if (subFd < 0)
                            {
                                throw new IOException(
                                    $"Could not bind cleanup directory '{name}'.",
                                    new Win32Exception(Marshal.GetLastPInvokeError()));
                            }

                            using (var subHandle = new SafeFileHandle(subFd, ownsHandle: true))
                            {
                                MacFileIdentity openedIdentity = GetIdentity(subHandle);
                                if (!openedIdentity.SameObject(entryIdentity)
                                    || (openedIdentity.Mode & FileTypeMask) != DirectoryMode)
                                {
                                    throw new IOException($"Cleanup directory '{name}' changed before descent.");
                                }

                                DeleteDirectoryContentsDescriptor(subHandle);
                                MacFileIdentity finalEntryIdentity = GetIdentityAt(dirHandle, name);
                                if (!finalEntryIdentity.SameObject(openedIdentity))
                                {
                                    throw new IOException($"Cleanup directory '{name}' changed before removal.");
                                }
                            }

                            if (PInvokeUnlinkAt(fd, name, 0x0080 /* AT_REMOVEDIR */) != 0)
                            {
                                int err = Marshal.GetLastPInvokeError();
                                if (err != 2 /* ENOENT */)
                                {
                                    throw new Win32Exception(err, $"Could not remove directory '{name}'.");
                                }
                            }
                        }
                        else
                        {
                            if (fileType != RegularFileMode || entryIdentity.LinkCount != 1)
                            {
                                throw new IOException(
                                    $"Cleanup refused a non-regular or multiply linked entry '{name}'.");
                            }

                            int fileFd = PInvokeOpenAt(fd, name, OpenReadOnly | OpenCloseOnExec | OpenNoFollowAny, 0);
                            if (fileFd < 0)
                            {
                                throw new IOException(
                                    $"Could not bind cleanup file '{name}'.",
                                    new Win32Exception(Marshal.GetLastPInvokeError()));
                            }

                            using (var fileHandle = new SafeFileHandle(fileFd, ownsHandle: true))
                            {
                                MacFileIdentity openedIdentity = GetIdentity(fileHandle);
                                MacFileIdentity finalEntryIdentity = GetIdentityAt(dirHandle, name);
                                if (!openedIdentity.SameObject(entryIdentity)
                                    || !finalEntryIdentity.SameObject(openedIdentity)
                                    || openedIdentity.LinkCount != 1
                                    || (openedIdentity.Mode & FileTypeMask) != RegularFileMode)
                                {
                                    throw new IOException($"Cleanup file '{name}' changed before removal.");
                                }
                            }

                            if (PInvokeUnlinkAt(fd, name, 0) != 0)
                            {
                                int err = Marshal.GetLastPInvokeError();
                                if (err != 2 /* ENOENT */)
                                {
                                    throw new Win32Exception(err, $"Could not unlink entry '{name}'.");
                                }
                            }
                        }
                    }
                }
            }
            finally
            {
                CloseDir(dirp);
            }
        }
        finally
        {
            if (added)
            {
                dirHandle.DangerousRelease();
            }
        }
    }

    internal static DirectoryTreeMeasurement MeasureDirectoryTreeNoFollow(
        SafeFileHandle rootHandle,
        MacFileIdentity expectedRootIdentity,
        bool allowWriters)
    {
        ArgumentNullException.ThrowIfNull(rootHandle);
        MacFileIdentity currentRootIdentity = GetIdentity(rootHandle);
        if (!currentRootIdentity.SameObject(expectedRootIdentity)
            || (currentRootIdentity.Mode & FileTypeMask) != DirectoryMode)
        {
            throw new IOException("The bound extraction root no longer identifies the expected directory.");
        }

        var visitedDirectories = new HashSet<(int Device, ulong Inode)>
        {
            (currentRootIdentity.Device, currentRootIdentity.Inode),
        };
        var fingerprintEntries = new List<MacTreeFingerprintEntry>
        {
            new(string.Empty, IsDirectory: true, currentRootIdentity),
        };
        DirectoryTreeMeasurement measurement = MeasureDirectoryTreeNoFollowDescriptor(
            rootHandle,
            allowWriters,
            visitedDirectories,
            string.Empty,
            fingerprintEntries);
        MacFileIdentity finalRootIdentity = GetIdentity(rootHandle);
        if (!finalRootIdentity.SameObject(expectedRootIdentity)
            || (!allowWriters && !finalRootIdentity.SameObjectAndMetadata(currentRootIdentity)))
        {
            throw new IOException("The bound extraction root changed while it was being measured.");
        }

        return measurement with
        {
            TreeFingerprint = ComputeTreeFingerprint(fingerprintEntries),
        };
    }

    private static DirectoryTreeMeasurement MeasureDirectoryTreeNoFollowDescriptor(
        SafeFileHandle dirHandle,
        bool allowWriters,
        HashSet<(int Device, ulong Inode)> visitedDirectories,
        string relativePrefix,
        List<MacTreeFingerprintEntry> fingerprintEntries)
    {
        bool added = false;
        int fileCount = 0;
        long totalBytes = 0;
        long maxFileBytes = 0;
        try
        {
            dirHandle.DangerousAddRef(ref added);
            int fd = checked((int)dirHandle.DangerousGetHandle());
            int dupFd = Dup(fd);
            if (dupFd < 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "macOS could not dup extraction directory descriptor.");
            }

            nint dirp = FdOpenDir(dupFd);
            if (dirp == 0)
            {
                CloseDescriptor(dupFd);
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "macOS fdopendir failed for extraction measurement.");
            }
            RewindDir(dirp);

            try
            {
                while (true)
                {
                    nint entryPtr = ReadDir(dirp);
                    if (entryPtr == 0)
                    {
                        break;
                    }

                    unsafe
                    {
                        var entry = (DarwinDirent*)entryPtr;
                        string name = Marshal.PtrToStringUTF8((nint)entry->d_name, entry->d_namlen);
                        if (name is "." or "..")
                        {
                            continue;
                        }

                        string relativePath = string.IsNullOrEmpty(relativePrefix)
                            ? name
                            : Path.Combine(relativePrefix, name);

                        MacFileIdentity entryIdentity = GetIdentityAt(dirHandle, name);
                        uint fileType = (uint)(entryIdentity.Mode & FileTypeMask);
                        if (fileType == SymbolicLinkMode)
                        {
                            throw new InvalidDataException(
                                $"The extracted tree contains a symbolic link that ZPAQ cannot have created: {name}");
                        }

                        if (fileType == DirectoryMode)
                        {
                            int subFd = PInvokeOpenAt(
                                fd,
                                name,
                                OpenReadOnly | OpenDirectory | OpenCloseOnExec | OpenNoFollowAny,
                                0);
                            if (subFd < 0)
                            {
                                throw new IOException(
                                    $"macOS could not bind extracted directory '{name}'.",
                                    new Win32Exception(Marshal.GetLastPInvokeError()));
                            }

                            using var subHandle = new SafeFileHandle(subFd, ownsHandle: true);
                            MacFileIdentity openedIdentity = GetIdentity(subHandle);
                            if (!openedIdentity.SameObject(entryIdentity)
                                || (openedIdentity.Mode & FileTypeMask) != DirectoryMode)
                            {
                                throw new IOException($"Extracted directory '{name}' changed before descent.");
                            }

                            if (!visitedDirectories.Add((openedIdentity.Device, openedIdentity.Inode)))
                            {
                                throw new IOException($"The extracted tree contains a directory cycle at '{name}'.");
                            }

                            DirectoryTreeMeasurement child;
                            try
                            {
                                child = MeasureDirectoryTreeNoFollowDescriptor(
                                    subHandle,
                                    allowWriters,
                                    visitedDirectories,
                                    relativePath,
                                    fingerprintEntries);
                            }
                            finally
                            {
                                visitedDirectories.Remove((openedIdentity.Device, openedIdentity.Inode));
                            }

                            MacFileIdentity afterWalkIdentity = GetIdentity(subHandle);
                            MacFileIdentity finalEntryIdentity = GetIdentityAt(dirHandle, name);
                            if (!afterWalkIdentity.SameObject(openedIdentity)
                                || !finalEntryIdentity.SameObject(openedIdentity)
                                || (!allowWriters
                                    && (!afterWalkIdentity.SameObjectAndMetadata(openedIdentity)
                                        || !finalEntryIdentity.SameObjectAndMetadata(afterWalkIdentity))))
                            {
                                throw new IOException($"Extracted directory '{name}' changed during measurement.");
                            }

                            fingerprintEntries.Add(new MacTreeFingerprintEntry(
                                relativePath,
                                IsDirectory: true,
                                finalEntryIdentity));

                            fileCount = checked(fileCount + child.FileCount);
                            totalBytes = checked(totalBytes + child.TotalBytes);
                            maxFileBytes = Math.Max(maxFileBytes, child.MaxFileBytes);
                            continue;
                        }

                        if (fileType != RegularFileMode || entryIdentity.LinkCount != 1)
                        {
                            throw new InvalidDataException(
                                $"The extracted tree contains a non-regular or multiply linked entry: {name}");
                        }

                        int fileFd = PInvokeOpenAt(fd, name, OpenReadOnly | OpenCloseOnExec | OpenNoFollowAny, 0);
                        if (fileFd < 0)
                        {
                            throw new IOException(
                                $"macOS could not bind extracted file '{name}'.",
                                new Win32Exception(Marshal.GetLastPInvokeError()));
                        }

                        using var fileHandle = new SafeFileHandle(fileFd, ownsHandle: true);
                        MacFileIdentity openedFileIdentity = GetIdentity(fileHandle);
                        MacFileIdentity finalFileIdentity = GetIdentity(fileHandle);
                        MacFileIdentity finalFileEntryIdentity = GetIdentityAt(dirHandle, name);
                        if (!openedFileIdentity.SameObject(entryIdentity)
                            || !finalFileIdentity.SameObject(openedFileIdentity)
                            || !finalFileEntryIdentity.SameObject(openedFileIdentity)
                            || openedFileIdentity.LinkCount != 1
                            || finalFileIdentity.LinkCount != 1
                            || finalFileEntryIdentity.LinkCount != 1
                            || (openedFileIdentity.Mode & FileTypeMask) != RegularFileMode
                            || (!allowWriters
                                && (!finalFileIdentity.SameObjectAndMetadata(openedFileIdentity)
                                    || !finalFileEntryIdentity.SameObjectAndMetadata(finalFileIdentity))))
                        {
                            throw new IOException($"Extracted file '{name}' changed during measurement.");
                        }

                        fingerprintEntries.Add(new MacTreeFingerprintEntry(
                            relativePath,
                            IsDirectory: false,
                            finalFileEntryIdentity));

                        fileCount = checked(fileCount + 1);
                        totalBytes = checked(totalBytes + finalFileIdentity.Size);
                        maxFileBytes = Math.Max(maxFileBytes, finalFileIdentity.Size);
                    }
                }
            }
            finally
            {
                CloseDir(dirp);
            }
        }
        finally
        {
            if (added)
            {
                dirHandle.DangerousRelease();
            }
        }

        return new DirectoryTreeMeasurement(fileCount, totalBytes, maxFileBytes, string.Empty);
    }

    private static string ComputeTreeFingerprint(List<MacTreeFingerprintEntry> entries)
    {
        entries.Sort(static (left, right) => string.CompareOrdinal(left.RelativePath, right.RelativePath));
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        Span<byte> numbers = stackalloc byte[64];
        foreach (MacTreeFingerprintEntry entry in entries)
        {
            byte[] relativePath = Encoding.UTF8.GetBytes(entry.RelativePath);
            try
            {
                numbers.Clear();
                numbers[0] = entry.IsDirectory ? (byte)1 : (byte)0;
                BitConverter.TryWriteBytes(numbers[1..5], relativePath.Length);
                BitConverter.TryWriteBytes(numbers[5..9], entry.Identity.Device);
                BitConverter.TryWriteBytes(numbers[9..17], entry.Identity.Inode);
                BitConverter.TryWriteBytes(numbers[17..19], entry.Identity.LinkCount);
                BitConverter.TryWriteBytes(numbers[19..21], entry.Identity.Mode);
                BitConverter.TryWriteBytes(numbers[21..29], entry.Identity.Size);
                BitConverter.TryWriteBytes(numbers[29..37], entry.Identity.ModificationSeconds);
                BitConverter.TryWriteBytes(numbers[37..45], entry.Identity.ModificationNanoseconds);
                BitConverter.TryWriteBytes(numbers[45..53], entry.Identity.ChangeSeconds);
                BitConverter.TryWriteBytes(numbers[53..61], entry.Identity.ChangeNanoseconds);
                hash.AppendData(numbers);
                hash.AppendData(relativePath);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(relativePath);
            }
        }

        numbers.Clear();
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private readonly record struct MacTreeFingerprintEntry(
        string RelativePath,
        bool IsDirectory,
        MacFileIdentity Identity);

    /// <summary>
    /// Removes a private directory only when its parent entry still denotes the
    /// expected bound inode. A replacement at the same path is never traversed
    /// or removed.
    /// </summary>
    internal static void DeleteDirectoryTreeBound(string directoryPath, MacFileIdentity expectedIdentity)
    {
        string fullPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directoryPath));
        string parentPath = Path.GetDirectoryName(fullPath)
            ?? throw new InvalidOperationException("A bound directory cleanup requires a parent directory.");
        string name = Path.GetFileName(fullPath);
        using SafeFileHandle parentHandle = OpenDirectoryHandle(parentPath);
        MacFileIdentity entryIdentity = GetIdentityAt(parentHandle, name);
        if (!entryIdentity.SameObject(expectedIdentity)
            || (entryIdentity.Mode & FileTypeMask) != DirectoryMode)
        {
            throw new IOException("Refusing to clean a directory path that no longer identifies the bound object.");
        }

        using SafeFileHandle directoryHandle = OpenDirectoryHandleAt(parentHandle, name);
        MacFileIdentity openedIdentity = GetIdentity(directoryHandle);
        if (!openedIdentity.SameObject(expectedIdentity))
        {
            throw new IOException("The cleanup directory changed while it was being opened.");
        }

        DeleteDirectoryTreeBound(
            parentHandle,
            GetIdentity(parentHandle),
            name,
            directoryHandle,
            expectedIdentity);
    }

    /// <summary>
    /// Cleans the exact held directory even if its pathname was displaced, but
    /// removes the original parent entry only when it still denotes that inode.
    /// A foreign replacement is preserved and reported to the caller.
    /// </summary>
    internal static void DeleteDirectoryTreeBound(
        SafeFileHandle parentHandle,
        MacFileIdentity expectedParentIdentity,
        string directoryName,
        SafeFileHandle directoryHandle,
        MacFileIdentity expectedDirectoryIdentity)
    {
        ArgumentNullException.ThrowIfNull(parentHandle);
        ArgumentNullException.ThrowIfNull(directoryHandle);
        if (string.IsNullOrWhiteSpace(directoryName)
            || !string.Equals(directoryName, Path.GetFileName(directoryName), StringComparison.Ordinal))
        {
            throw new ArgumentException("A bound directory cleanup requires one entry name.", nameof(directoryName));
        }

        MacFileIdentity openedIdentity = GetIdentity(directoryHandle);
        if (!openedIdentity.SameObject(expectedDirectoryIdentity)
            || (openedIdentity.Mode & FileTypeMask) != DirectoryMode)
        {
            throw new IOException("The held cleanup directory no longer identifies the expected object.");
        }
        if (!GetIdentity(parentHandle).SameObject(expectedParentIdentity))
        {
            throw new IOException("The held cleanup parent no longer identifies the expected directory.");
        }

        DeleteDirectoryContentsDescriptor(directoryHandle);

        MacFileIdentity finalHandleIdentity = GetIdentity(directoryHandle);
        if (!finalHandleIdentity.SameObject(expectedDirectoryIdentity))
        {
            throw new IOException("The held cleanup directory changed while its contents were removed.");
        }
        if (!GetIdentity(parentHandle).SameObject(expectedParentIdentity))
        {
            throw new IOException("The held cleanup parent changed before final removal.");
        }

        MacFileIdentity finalEntryIdentity = GetIdentityAt(parentHandle, directoryName);
        if (!finalEntryIdentity.SameObject(expectedDirectoryIdentity)
            || (finalEntryIdentity.Mode & FileTypeMask) != DirectoryMode)
        {
            throw new IOException(
                "Refusing to remove a private-directory name that now identifies a foreign replacement.");
        }

        UnlinkAt(parentHandle, directoryName, 0x0080 /* AT_REMOVEDIR */);
    }

    internal static long GetFreeDiskSpaceBytes(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (StatVfs(path, out DarwinStatVfs stat) != 0)
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), $"macOS could not stat filesystem at '{path}'.");
        }
        return checked((long)(stat.f_bavail * stat.f_frsize));
    }

    internal static MacFileIdentity GetIdentityAt(SafeFileHandle parentHandle, string relativePath)
    {
        ArgumentNullException.ThrowIfNull(parentHandle);
        ArgumentException.ThrowIfNullOrWhiteSpace(relativePath);
        bool added = false;
        try
        {
            parentHandle.DangerousAddRef(ref added);
            int parentFd = checked((int)parentHandle.DangerousGetHandle());
            // 0x0020 is AT_SYMLINK_NOFOLLOW on macOS
            if (FStatAt(parentFd, relativePath, out DarwinStat status, 0x0020) != 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), $"macOS could not inspect '{relativePath}' relative to directory descriptor.");
            }
            return IdentityFromStat(status);
        }
        finally
        {
            if (added)
            {
                parentHandle.DangerousRelease();
            }
        }
    }

    internal static void RenameAt(SafeFileHandle fromDirHandle, string fromPath, SafeFileHandle toDirHandle, string toPath)
    {
        ArgumentNullException.ThrowIfNull(fromDirHandle);
        ArgumentNullException.ThrowIfNull(toDirHandle);
        ArgumentException.ThrowIfNullOrWhiteSpace(fromPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(toPath);

        bool fromAdded = false;
        bool toAdded = false;
        try
        {
            fromDirHandle.DangerousAddRef(ref fromAdded);
            toDirHandle.DangerousAddRef(ref toAdded);
            int fromFd = checked((int)fromDirHandle.DangerousGetHandle());
            int toFd = checked((int)toDirHandle.DangerousGetHandle());
            if (PInvokeRenameAt(fromFd, fromPath, toFd, toPath) != 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), $"macOS renameat failed from '{fromPath}' to '{toPath}'.");
            }
        }
        finally
        {
            if (toAdded) toDirHandle.DangerousRelease();
            if (fromAdded) fromDirHandle.DangerousRelease();
        }
    }

    internal static void RenameAtExclusive(SafeFileHandle fromDirHandle, string fromPath, SafeFileHandle toDirHandle, string toPath)
    {
        ArgumentNullException.ThrowIfNull(fromDirHandle);
        ArgumentNullException.ThrowIfNull(toDirHandle);
        ArgumentException.ThrowIfNullOrWhiteSpace(fromPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(toPath);

        bool fromAdded = false;
        bool toAdded = false;
        try
        {
            fromDirHandle.DangerousAddRef(ref fromAdded);
            toDirHandle.DangerousAddRef(ref toAdded);
            int fromFd = checked((int)fromDirHandle.DangerousGetHandle());
            int toFd = checked((int)toDirHandle.DangerousGetHandle());
            // 0x00000004 is RENAME_EXCL on macOS
            if (PInvokeRenameAtxNp(fromFd, fromPath, toFd, toPath, 0x00000004) != 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), $"macOS renameatx_np(RENAME_EXCL) failed from '{fromPath}' to '{toPath}'.");
            }
        }
        finally
        {
            if (toAdded) toDirHandle.DangerousRelease();
            if (fromAdded) fromDirHandle.DangerousRelease();
        }
    }

    internal static void UnlinkAt(SafeFileHandle parentHandle, string relativePath, int flags = 0)
    {
        ArgumentNullException.ThrowIfNull(parentHandle);
        ArgumentException.ThrowIfNullOrWhiteSpace(relativePath);
        bool added = false;
        try
        {
            parentHandle.DangerousAddRef(ref added);
            int parentFd = checked((int)parentHandle.DangerousGetHandle());
            if (PInvokeUnlinkAt(parentFd, relativePath, flags) != 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), $"macOS could not unlink '{relativePath}' relative to directory descriptor.");
            }
        }
        finally
        {
            if (added) parentHandle.DangerousRelease();
        }
    }

    internal static void CloseDescriptor(int descriptor)
    {
        if (descriptor >= 0)
        {
            Close(descriptor);
        }
    }

    [LibraryImport("libSystem.B.dylib", EntryPoint = "open", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int Open(string path, int flags);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "close", SetLastError = true)]
    private static partial int Close(int fd);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "fcntl", SetLastError = true)]
    private static partial int FcntlNoArgument(int descriptor, int command);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "fclonefileat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int FCloneFileAt(int sourceDescriptor, int destinationDirectoryDescriptor, string destinationFileName, uint flags);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "fstat", SetLastError = true)]
    private static partial int FStat(int descriptor, out DarwinStat status);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "fstatat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int FStatAt(int dirfd, string path, out DarwinStat status, int flags);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "lstat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int LStat(string path, out DarwinStat status);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "realpath", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial nint RealPath(string path, nint resolvedPath);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "free")]
    private static partial void Free(nint pointer);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "openat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int PInvokeOpenAt(int dirfd, string path, int flags, int mode);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "mkdirat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int PInvokeMkdirAt(int dirfd, string path, uint mode);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "fchmod", SetLastError = true)]
    private static partial int PInvokeFChmod(int fd, uint mode);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "mkostempsat_np", SetLastError = true)]
    private static unsafe partial int PInvokeMkOStempsAtNp(
        int dirfd,
        byte* template,
        int suffixLength,
        int openFlags);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "renameat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int PInvokeRenameAt(int fromDirFd, string fromPath, int toDirFd, string toPath);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "renameatx_np", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int PInvokeRenameAtxNp(int fromDirFd, string fromPath, int toDirFd, string toPath, uint flags);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "unlinkat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int PInvokeUnlinkAt(int dirfd, string path, int flags);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "statvfs", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int StatVfs(string path, out DarwinStatVfs buf);
}

[StructLayout(LayoutKind.Sequential)]
internal struct DarwinStatVfs
{
    public ulong f_bsize;
    public ulong f_frsize;
    public uint f_blocks;
    public uint f_bfree;
    public uint f_bavail;
    public uint f_files;
    public uint f_ffree;
    public uint f_favail;
    public ulong f_fsid;
    public ulong f_flag;
    public ulong f_namemax;
}

internal readonly record struct MacFileIdentity(
    int Device,
    ulong Inode,
    ushort LinkCount,
    ushort Mode,
    long Size,
    long ModificationSeconds,
    long ModificationNanoseconds,
    long ChangeSeconds,
    long ChangeNanoseconds)
{
    internal bool SameObject(MacFileIdentity other) => Device == other.Device && Inode == other.Inode;

    internal bool SameObjectAndMetadata(MacFileIdentity other) =>
        SameObject(other)
        && LinkCount == other.LinkCount
        && Mode == other.Mode
        && Size == other.Size
        && ModificationSeconds == other.ModificationSeconds
        && ModificationNanoseconds == other.ModificationNanoseconds
        && ChangeSeconds == other.ChangeSeconds
        && ChangeNanoseconds == other.ChangeNanoseconds;
}

internal readonly record struct MacDirectoryEntry(
    string Name,
    MacFileIdentity Identity);

internal readonly record struct DirectoryTreeMeasurement(
    int FileCount,
    long TotalBytes,
    long MaxFileBytes,
    string TreeFingerprint);

internal static partial class NativePathResolver
{
    internal static string ResolveExistingPath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return MacSafeFileSystem.ResolveExistingRealPath(path);
    }

    internal static string ResolveFinalDosPath(SafeFileHandle handle) =>
        throw new PlatformNotSupportedException(
            "Descriptor-only pathname recovery is intentionally unavailable on macOS. Pass the already no-follow-opened expected path and compare file identity instead.");

    internal static string RequireCanonicalFilePath(SafeFileHandle handle, string expectedPath, string label)
    {
        string expected = Path.GetFullPath(expectedPath);
        MacSafeFileSystem.RequirePathStillNamesHandle(handle, expected);
        return expected;
    }
}

internal static partial class MacCodeSignature
{
    private const uint CheckAllArchitectures = 1U << 0;
    private const uint CheckNestedCode = 1U << 3;
    private const uint StrictValidate = 1U << 4;
    private const uint Utf8Encoding = 0x08000100;
    private const string TeamMetadataKey = "KeepVaultAppleTeamIdentifier";

    internal static MacSignatureInfo Check(string path, bool nestedBundle = false)
    {
        if (!OperatingSystem.IsMacOS())
        {
            return new MacSignatureInfo(SignatureState.Missing, null, "Apple code-signature validation is available only on macOS.");
        }

        string? team = typeof(MacCodeSignature).Assembly
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .FirstOrDefault(attribute => string.Equals(attribute.Key, TeamMetadataKey, StringComparison.Ordinal))
            ?.Value;
        if (string.IsNullOrWhiteSpace(team) || team.Any(character => !(char.IsAsciiLetterOrDigit(character))))
        {
            return new MacSignatureInfo(SignatureState.PresentButUntrustedOrInvalid, null, "The pinned Apple Team ID is missing or invalid.");
        }

        nint url = 0;
        nint code = 0;
        nint requirementText = 0;
        nint requirement = 0;
        nint errors = 0;
        byte[] utf8Path = Encoding.UTF8.GetBytes(Path.GetFullPath(path));
        byte[] requirementBytes = Encoding.UTF8.GetBytes($"anchor apple generic and certificate leaf[subject.OU] = \"{team}\"");
        try
        {
            url = CFURLCreateFromFileSystemRepresentation(0, utf8Path, checked((nint)utf8Path.Length), false);
            if (url == 0)
            {
                return new MacSignatureInfo(SignatureState.PresentButUntrustedOrInvalid, team, "CoreFoundation could not create the code URL.");
            }

            int status = SecStaticCodeCreateWithPath(url, 0, out code);
            if (status != 0 || code == 0)
            {
                return new MacSignatureInfo(SignatureState.Missing, team, $"SecStaticCodeCreateWithPath failed with OSStatus {status}.");
            }

            requirementText = CFStringCreateWithBytes(0, requirementBytes, checked((nint)requirementBytes.Length), Utf8Encoding, false);
            if (requirementText == 0)
            {
                return new MacSignatureInfo(SignatureState.PresentButUntrustedOrInvalid, team, "CoreFoundation could not create the signing requirement.");
            }

            status = SecRequirementCreateWithString(requirementText, 0, out requirement);
            if (status != 0 || requirement == 0)
            {
                return new MacSignatureInfo(SignatureState.PresentButUntrustedOrInvalid, team, $"SecRequirementCreateWithString failed with OSStatus {status}.");
            }

            uint flags = CheckAllArchitectures | StrictValidate | (nestedBundle ? CheckNestedCode : 0U);
            status = SecStaticCodeCheckValidityWithErrors(code, flags, requirement, out errors);
            return status == 0
                ? new MacSignatureInfo(SignatureState.Trusted, team, "Apple code signature, all architectures, and pinned Team ID are valid.")
                : new MacSignatureInfo(SignatureState.PresentButUntrustedOrInvalid, team, $"Apple code-signature validation failed with OSStatus {status}.");
        }
        finally
        {
            if (errors != 0) CFRelease(errors);
            if (requirement != 0) CFRelease(requirement);
            if (requirementText != 0) CFRelease(requirementText);
            if (code != 0) CFRelease(code);
            if (url != 0) CFRelease(url);
        }
    }

    [LibraryImport("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", EntryPoint = "CFURLCreateFromFileSystemRepresentation")]
    private static partial nint CFURLCreateFromFileSystemRepresentation(nint allocator, byte[] bytes, nint length, [MarshalAs(UnmanagedType.I1)] bool isDirectory);

    [LibraryImport("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", EntryPoint = "CFStringCreateWithBytes")]
    private static partial nint CFStringCreateWithBytes(nint allocator, byte[] bytes, nint length, uint encoding, [MarshalAs(UnmanagedType.I1)] bool isExternalRepresentation);

    [LibraryImport("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", EntryPoint = "CFRelease")]
    private static partial void CFRelease(nint value);

    [LibraryImport("/System/Library/Frameworks/Security.framework/Security", EntryPoint = "SecStaticCodeCreateWithPath")]
    private static partial int SecStaticCodeCreateWithPath(nint path, uint flags, out nint staticCode);

    [LibraryImport("/System/Library/Frameworks/Security.framework/Security", EntryPoint = "SecRequirementCreateWithString")]
    private static partial int SecRequirementCreateWithString(nint text, uint flags, out nint requirement);

    [LibraryImport("/System/Library/Frameworks/Security.framework/Security", EntryPoint = "SecStaticCodeCheckValidityWithErrors")]
    private static partial int SecStaticCodeCheckValidityWithErrors(nint staticCode, uint flags, nint requirement, out nint errors);
}

internal sealed class MacExtractionStaging : IDisposable
{
    private readonly SafeFileHandle _parentHandle;
    private readonly string _parentPath;
    private readonly MacFileIdentity _parentIdentity;
    private readonly SafeFileHandle _stagingHandle;
    private readonly MacFileIdentity _stagingIdentity;
    public string DestinationPath { get; }
    public string StagingPath { get; }
    public string StagingName { get; }
    public MacFileIdentity StagingIdentity => _stagingIdentity;
    private bool _installed;
    private bool _cleaned;
    private string? _validatedTreeFingerprint;

    internal static Action? TestHookBeforeInstallRename { get; set; }
    internal static Action? TestHookAfterEmptyDestinationCheck { get; set; }

    public MacExtractionStaging(string destinationPath)
    {
        string requestedDestination = Path.GetFullPath(destinationPath);
        if (File.Exists(requestedDestination))
        {
            throw new InvalidOperationException("Extraction target must be a directory path.");
        }

        string destinationName = Path.GetFileName(requestedDestination);
        if (string.IsNullOrWhiteSpace(destinationName))
        {
            throw new InvalidOperationException("Extraction target must end in a directory name.");
        }

        string parentDir = Path.GetDirectoryName(requestedDestination) ?? Environment.CurrentDirectory;
        Directory.CreateDirectory(parentDir);
        // Open the caller-supplied parent before canonicalizing it. macOS
        // O_NOFOLLOW_ANY then rejects a symlink in any parent component.
        SafeFileHandle openedParent = MacSafeFileSystem.OpenDirectoryHandle(parentDir);
        string canonicalParent;
        MacFileIdentity parentIdentity;
        try
        {
            canonicalParent = MacSafeFileSystem.ResolveExistingRealPath(parentDir);
            parentIdentity = MacSafeFileSystem.GetIdentity(openedParent);
            MacSafeFileSystem.RequirePathStillNamesHandle(openedParent, canonicalParent);
        }
        catch
        {
            openedParent.Dispose();
            throw;
        }

        _parentHandle = openedParent;
        _parentPath = canonicalParent;
        _parentIdentity = parentIdentity;
        DestinationPath = Path.Combine(canonicalParent, destinationName);
        StagingName = $".{destinationName}.{Guid.NewGuid():N}.extract-part";
        StagingPath = Path.Combine(canonicalParent, StagingName);

        bool parentAdded = false;
        bool stagingCreated = false;
        int stagingFd = -1;
        try
        {
            _parentHandle.DangerousAddRef(ref parentAdded);
            int parentFd = checked((int)_parentHandle.DangerousGetHandle());
            // 0x1C0 is POSIX octal 0700 (S_IRWXU: rwx------)
            if (MacSafeFileSystem.PInvokeMkdirAt(parentFd, StagingName, 0x1C0) != 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "Could not create extraction staging directory.");
            }
            stagingCreated = true;

            stagingFd = MacSafeFileSystem.PInvokeOpenAt(
                parentFd,
                StagingName,
                0x0000 /* O_RDONLY */ | 0x00100000 /* O_DIRECTORY */ | 0x20000000 /* O_NOFOLLOW_ANY */ | 0x01000000 /* O_CLOEXEC */,
                0);
            if (stagingFd < 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "Could not open extraction staging directory descriptor.");
            }

            _stagingHandle = new SafeFileHandle(stagingFd, ownsHandle: true);
            stagingFd = -1; // Transferred ownership
            _stagingIdentity = MacSafeFileSystem.GetIdentity(_stagingHandle);
        }
        catch
        {
            if (stagingFd >= 0)
            {
                MacSafeFileSystem.CloseDescriptor(stagingFd);
            }
            _stagingHandle?.Dispose();
            if (stagingCreated && parentAdded)
            {
                int parentFd = checked((int)_parentHandle.DangerousGetHandle());
                // 0x0080 is AT_REMOVEDIR on macOS
                _ = MacSafeFileSystem.PInvokeUnlinkAt(parentFd, StagingName, 0x0080);
            }
            _parentHandle?.Dispose();
            throw;
        }
        finally
        {
            if (parentAdded)
            {
                _parentHandle.DangerousRelease();
            }
        }
    }

    public void VerifyIdentity()
    {
        VerifyParentIdentity();
        MacSafeFileSystem.RequirePathStillNamesHandle(_stagingHandle, StagingPath);
        MacFileIdentity current = MacSafeFileSystem.GetIdentity(_stagingHandle);
        MacFileIdentity entry = MacSafeFileSystem.GetIdentityAt(_parentHandle, StagingName);
        if (!current.SameObject(_stagingIdentity) || !entry.SameObject(_stagingIdentity))
        {
            throw new InvalidOperationException("Extraction staging directory identity changed during extraction.");
        }
    }

    internal DirectoryTreeMeasurement MeasureTree(bool allowWriters)
    {
        VerifyIdentity();
        DirectoryTreeMeasurement measurement = MacSafeFileSystem.MeasureDirectoryTreeNoFollow(
            _stagingHandle,
            _stagingIdentity,
            allowWriters);
        if (!allowWriters)
        {
            _validatedTreeFingerprint = measurement.TreeFingerprint;
        }

        return measurement;
    }

    public void Install(Action<DirectoryTreeMeasurement>? validateFinalTree = null)
    {
        VerifyIdentity();
        string destName = Path.GetFileName(DestinationPath);

        // Verify that Staging directory entry under parent matches our descriptor before rename
        MacFileIdentity parentStagingIdentity = MacSafeFileSystem.GetIdentityAt(_parentHandle, StagingName);
        if (!parentStagingIdentity.SameObject(_stagingIdentity))
        {
            throw new InvalidOperationException("Extraction staging directory entry changed before installation.");
        }

        string expectedTreeFingerprint = _validatedTreeFingerprint
            ?? MeasureTree(allowWriters: false).TreeFingerprint;

        // The hook is intentionally before the last complete bound-tree gate,
        // so a deterministic substitution is caught rather than merely making
        // the subsequent rename fail by chance.
        TestHookBeforeInstallRename?.Invoke();
        VerifyParentIdentity();
        DirectoryTreeMeasurement finalTree = MacSafeFileSystem.MeasureDirectoryTreeNoFollow(
            _stagingHandle,
            _stagingIdentity,
            allowWriters: false);
        validateFinalTree?.Invoke(finalTree);
        if (!string.Equals(
                finalTree.TreeFingerprint,
                expectedTreeFingerprint,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The extracted tree changed after its final validation and before installation.");
        }

        _validatedTreeFingerprint = finalTree.TreeFingerprint;
        parentStagingIdentity = MacSafeFileSystem.GetIdentityAt(_parentHandle, StagingName);
        if (!parentStagingIdentity.SameObject(_stagingIdentity))
        {
            throw new InvalidOperationException("Extraction staging directory changed at the final install gate.");
        }

        // Attempt atomic exclusive rename
        try
        {
            MacSafeFileSystem.RenameAtExclusive(_parentHandle, StagingName, _parentHandle, destName);
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 17 /* EEXIST */)
        {
            bool parentAdded = false;
            bool removed = false;
            try
            {
                _parentHandle.DangerousAddRef(ref parentAdded);
                int parentFd = checked((int)_parentHandle.DangerousGetHandle());
                int destFd = MacSafeFileSystem.PInvokeOpenAt(
                    parentFd,
                    destName,
                    MacSafeFileSystem.OpenReadOnly | MacSafeFileSystem.OpenDirectory | MacSafeFileSystem.OpenNoFollowAny | MacSafeFileSystem.OpenCloseOnExec,
                    0);
                if (destFd >= 0)
                {
                    using (var existingHandle = new SafeFileHandle(destFd, ownsHandle: true))
                    {
                        MacFileIdentity existingIdentity = MacSafeFileSystem.GetIdentity(existingHandle);
                        if (MacSafeFileSystem.IsDirectoryEmptyDescriptor(existingHandle))
                        {
                            TestHookAfterEmptyDestinationCheck?.Invoke();
                            VerifyParentIdentity();
                            MacFileIdentity finalHandleIdentity = MacSafeFileSystem.GetIdentity(existingHandle);
                            MacFileIdentity finalEntryIdentity = MacSafeFileSystem.GetIdentityAt(_parentHandle, destName);
                            if (finalHandleIdentity.SameObject(existingIdentity)
                                && finalEntryIdentity.SameObject(existingIdentity)
                                && MacSafeFileSystem.PInvokeUnlinkAt(parentFd, destName, 0x0080 /* AT_REMOVEDIR */) == 0)
                            {
                                removed = true;
                            }
                        }
                    }
                }
            }
            finally
            {
                if (parentAdded)
                {
                    _parentHandle.DangerousRelease();
                }
            }

            if (removed)
            {
                MacSafeFileSystem.RenameAtExclusive(_parentHandle, StagingName, _parentHandle, destName);
            }
            else
            {
                throw new IOException("The extraction target changed or is not empty before installation.", ex);
            }
        }

        // Post-rename identity verification
        MacFileIdentity postRenameIdentity = MacSafeFileSystem.GetIdentityAt(_parentHandle, destName);
        if (!postRenameIdentity.SameObject(_stagingIdentity))
        {
            throw new InvalidOperationException(
                "Installed directory identity mismatch after atomic rename. The foreign destination was preserved untouched.");
        }

        _installed = true;
    }

    public void Cleanup()
    {
        if (_installed || _cleaned)
        {
            return;
        }

        try
        {
            MacSafeFileSystem.DeleteDirectoryTreeBound(
                _parentHandle,
                _parentIdentity,
                StagingName,
                _stagingHandle,
                _stagingIdentity);
            _cleaned = true;
        }
        catch
        {
            // The descriptor-bound contents have either been removed or the
            // operation failed closed before touching a foreign name. Report
            // the cleanup failure once; Dispose must not silently retry and
            // mask the original exception at a later boundary.
            _cleaned = true;
            throw;
        }
    }

    public void Dispose()
    {
        if (!_installed)
        {
            Cleanup();
        }
        _stagingHandle?.Dispose();
        _parentHandle?.Dispose();
    }

    private void VerifyParentIdentity()
    {
        MacFileIdentity current = MacSafeFileSystem.GetIdentity(_parentHandle);
        if (!current.SameObject(_parentIdentity))
        {
            throw new IOException("Extraction target parent identity changed.");
        }

        MacSafeFileSystem.RequirePathStillNamesHandle(_parentHandle, _parentPath);
    }
}

internal sealed record MacSignatureInfo(SignatureState State, string? TeamIdentifier, string Message);
