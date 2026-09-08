using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

// Package adapters operate on held descriptors, not a second resolution of an
// untrusted payload pathname. O_NOFOLLOW_ANY includes every parent component.
internal sealed class MacBoundFile : IDisposable
{
    private const int OpenFlags = 0x01000000 | 0x20000000 | 0x00000004; // CLOEXEC, NOFOLLOW_ANY, NONBLOCK
    private readonly FileIdentity identity;
    private readonly string path;
    internal FileStream Stream { get; }
    internal long Length => identity.Size;
    internal int Mode => identity.Mode & 0xFFF;
    internal void RequireRootOwned()
    {
        if (identity.Uid != 0) throw new InvalidDataException("The staged installation file is not root-owned: " + path);
        RequireReadOnlyAcl(Stream.SafeFileHandle);
        AssertStable();
    }

    private MacBoundFile(string path, SafeFileHandle handle, FileIdentity identity)
    {
        this.path = path;
        this.identity = identity;
        Stream = new FileStream(handle, FileAccess.Read, 64 * 1024, isAsync: false);
    }

    internal static MacBoundFile Open(string path, long maximumBytes = 8L * 1024 * 1024 * 1024)
    {
        if (!OperatingSystem.IsMacOS()) throw new PlatformNotSupportedException("The installation adapter requires macOS.");
        string fullPath = Path.GetFullPath(path);
        SafeFileHandle handle = OpenHandle(fullPath);
        try
        {
            FileIdentity before = Identity(handle);
            if ((before.Mode & 0xF000) != 0x8000 || (before.Mode & 0x0E12) != 0
                || before.LinkCount != 1 || before.Size < 0 || before.Size > maximumBytes)
            {
                throw new InvalidDataException("Expected a bounded, single-link regular file without group or other write access: " + fullPath);
            }
            using SafeFileHandle reopened = OpenHandle(fullPath);
            if (before != Identity(reopened)) throw new IOException("File identity changed while opening: " + fullPath);
            return new MacBoundFile(fullPath, handle, before);
        }
        catch { handle.Dispose(); throw; }
    }

    internal byte[] ReadAll(int maximumBytes)
    {
        if (Length > maximumBytes) throw new InvalidDataException("File exceeds its bounded read size.");
        Stream.Position = 0;
        byte[] bytes = new byte[checked((int)Length)];
        try
        {
            Stream.ReadExactly(bytes);
            if (Stream.ReadByte() != -1) throw new IOException("File length changed during read.");
            AssertStable();
            return bytes;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw;
        }
    }

    internal void AssertStable()
    {
        using SafeFileHandle reopened = OpenHandle(path);
        if (identity != Identity(Stream.SafeFileHandle) || identity != Identity(reopened))
            throw new IOException("File descriptor or pathname changed during verification: " + path);
    }

    public void Dispose() => Stream.Dispose();

    internal Action CaptureNamespaceCheck() => () =>
    {
        using SafeFileHandle reopened = OpenHandle(path);
        if (identity != Identity(reopened)) throw new IOException("An already checked file changed before verification completed: " + path);
    };

    internal static DirectoryLease OpenDirectory(string path) => new(path);

    internal sealed class DirectoryLease : IDisposable
    {
        private readonly string path;
        private readonly SafeFileHandle handle;
        private readonly FileIdentity identity;
        internal int Mode => identity.Mode & 0xFFF;
        internal void RequireRootOwned()
        {
            if (identity.Uid != 0) throw new InvalidDataException("The staged installation directory is not root-owned: " + path);
            RequireReadOnlyAcl(handle);
            AssertStable();
        }
        internal DirectoryLease(string path)
        {
            this.path = Path.GetFullPath(path);
            handle = OpenHandle(this.path, directory: true);
            try
            {
                identity = Identity(handle);
                if ((identity.Mode & 0xF000) != 0x4000 || (identity.Mode & 0x0012) != 0
                    || (identity.Mode & 0x0140) != 0x0140 || (identity.Mode & 0x0E00) != 0)
                    throw new InvalidDataException("Expected a physical protected directory: " + this.path);
            }
            catch { handle.Dispose(); throw; }
        }
        internal void AssertStable()
        {
            using SafeFileHandle reopened = OpenHandle(path, directory: true);
            if (identity != Identity(handle) || identity != Identity(reopened))
                throw new IOException("Directory identity changed during package verification: " + path);
        }
        internal Action CaptureNamespaceCheck() => () =>
        {
            using SafeFileHandle reopened = OpenHandle(path, directory: true);
            if (identity != Identity(reopened)) throw new IOException("An already checked directory changed before verification completed: " + path);
        };
        public void Dispose() => handle.Dispose();
    }

    private static SafeFileHandle OpenHandle(string path, bool directory = false)
    {
        int descriptor = NativeOpen(path, OpenFlags | (directory ? 0x00100000 : 0));
        if (descriptor < 0) throw NativeError("Cannot open without symbolic links: " + path);
        return new SafeFileHandle((nint)descriptor, ownsHandle: true);
    }

    private static FileIdentity Identity(SafeFileHandle handle)
    {
        if (FStat(handle, out DarwinStat value) != 0) throw NativeError("Cannot inspect the held descriptor.");
        return new(value.Device, value.Mode, value.LinkCount, value.Inode, value.Uid, value.Gid,
            value.Size, value.ModificationTime.Seconds, value.ModificationTime.Nanoseconds,
            value.ChangeTime.Seconds, value.ChangeTime.Nanoseconds, value.Flags, value.Generation);
    }

    private static IOException NativeError(string message) => new(message, new Win32Exception(Marshal.GetLastPInvokeError()));

    internal static void RequireReadOnlyAcl(SafeFileHandle handle)
    {
        nint acl = AclGetFd(handle, 0x100); // ACL_TYPE_EXTENDED
        if (acl == 0)
        {
            // A held valid descriptor with no extended ACL returns ENOENT on
            // macOS. Unsupported ACL retrieval and every other error fail.
            if (Marshal.GetLastPInvokeError() == 2) return;
            throw NativeError("Cannot inspect the staged object's extended ACL.");
        }
        try
        {
            if (AclValid(acl) != 0) throw NativeError("Invalid staged-object ACL.");
            for (int index = 0; index <= 128; index++)
            {
                if (AclGetEntry(acl, index, out nint entry) != 0)
                {
                    if (Marshal.GetLastPInvokeError() == 22) return; // Darwin end-of-ACL convention.
                    throw NativeError("Cannot enumerate the staged object's ACL.");
                }
                if (index == 128) throw new InvalidDataException("The staged object's ACL is too large.");
                if (AclGetTag(entry, out int tag) != 0 || AclGetMask(entry, out ulong mask) != 0)
                    throw NativeError("Cannot inspect an ACL permission entry.");
                const ulong ReadOnlyMask = (1UL << 1) | (1UL << 3) | (1UL << 7)
                    | (1UL << 9) | (1UL << 11) | (1UL << 20);
                if (tag is not (1 or 2) || (tag == 1 && (mask & ~ReadOnlyMask) != 0))
                    throw new InvalidDataException("A staged-object ACL grants write, deletion, ownership or unknown permissions.");
            }
        }
        finally { AclFree(acl); }
    }
    private readonly record struct FileIdentity(int Device, ushort Mode, ushort LinkCount, ulong Inode,
        uint Uid, uint Gid, long Size, long MTime, long MTimeNs, long CTime, long CTimeNs, uint Flags, uint Generation);
    [StructLayout(LayoutKind.Sequential)] private struct Timespec { internal long Seconds; internal long Nanoseconds; }
    [StructLayout(LayoutKind.Sequential)] private struct DarwinStat
    {
        internal int Device; internal ushort Mode; internal ushort LinkCount; internal ulong Inode;
        internal uint Uid; internal uint Gid; internal int Rdev;
        internal Timespec AccessTime; internal Timespec ModificationTime; internal Timespec ChangeTime; internal Timespec BirthTime;
        internal long Size; internal long Blocks; internal int BlockSize; internal uint Flags; internal uint Generation;
        internal int Spare; internal long Reserved0; internal long Reserved1;
    }
    [DllImport("libSystem.B.dylib", EntryPoint = "open", SetLastError = true)]
    private static extern int NativeOpen(string path, int flags);
    [DllImport("libSystem.B.dylib", EntryPoint = "fstat", SetLastError = true)]
    private static extern int FStatArm64(SafeFileHandle descriptor, out DarwinStat status);
    [DllImport("libSystem.B.dylib", EntryPoint = "fstat$INODE64", SetLastError = true)]
    private static extern int FStatX64(SafeFileHandle descriptor, out DarwinStat status);
    private static int FStat(SafeFileHandle descriptor, out DarwinStat status) => RuntimeInformation.ProcessArchitecture switch
    {
        Architecture.Arm64 => FStatArm64(descriptor, out status),
        Architecture.X64 => FStatX64(descriptor, out status),
        _ => throw new PlatformNotSupportedException("Unsupported macOS stat ABI.")
    };
    [DllImport("libSystem.B.dylib", EntryPoint = "acl_get_fd_np", SetLastError = true)]
    private static extern nint AclGetFd(SafeFileHandle descriptor, int type);
    [DllImport("libSystem.B.dylib", EntryPoint = "acl_valid", SetLastError = true)]
    private static extern int AclValid(nint acl);
    [DllImport("libSystem.B.dylib", EntryPoint = "acl_get_entry", SetLastError = true)]
    private static extern int AclGetEntry(nint acl, int entryId, out nint entry);
    [DllImport("libSystem.B.dylib", EntryPoint = "acl_get_tag_type", SetLastError = true)]
    private static extern int AclGetTag(nint entry, out int tag);
    [DllImport("libSystem.B.dylib", EntryPoint = "acl_get_permset_mask_np", SetLastError = true)]
    private static extern int AclGetMask(nint entry, out ulong mask);
    [DllImport("libSystem.B.dylib", EntryPoint = "acl_free")]
    private static extern int AclFree(nint acl);
}
