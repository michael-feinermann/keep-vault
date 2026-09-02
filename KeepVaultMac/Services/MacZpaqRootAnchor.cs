#if KEEPVAULT_MACOS
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace KalynaArchiver.Services;

/// <summary>
/// Defines the only macOS pathname from which Keep Vault v12 may execute ZPAQ.
/// The installer owns this hierarchy as root:wheel, so another process running
/// as the signed-in user cannot replace the executable between validation and
/// sandbox-exec opening it by pathname.
/// </summary>
internal static partial class MacZpaqRootAnchor
{
    internal const string DirectoryPath = "/Library/Application Support/Keep Vault/v12";
    internal const string ExecutablePath = DirectoryPath + "/zpaq";

    private static readonly string[] SidecarSuffixes =
        [".sha3", ".skein", ".khsig", ".sha3.khsig", ".skein.khsig"];

    internal static void RequireSecureInstalledSet(FileStream executable)
    {
        ArgumentNullException.ThrowIfNull(executable);
        RequireDirectory("/", requireWheel: true, exactMode: 0x01ED /* 0755 */);
        RequireDirectory("/Library", requireWheel: true, exactMode: 0x01ED /* 0755 */);
        // Apple's system-owned Application Support directory is root:admin on
        // stock macOS. Ownership by root and absence of group/world write are
        // the security boundary; changing this system directory's group would
        // be both unnecessary and invasive.
        RequireDirectory("/Library/Application Support", requireWheel: false, exactMode: null);
        RequireDirectory("/Library/Application Support/Keep Vault", requireWheel: true, exactMode: 0x01ED /* 0755 */);
        RequireDirectory(DirectoryPath, requireWheel: true, exactMode: 0x01ED /* 0755 */);

        RequireLeaf(executable, ExecutablePath, executableMode: true);
        foreach (string suffix in SidecarSuffixes)
        {
            string path = ExecutablePath + suffix;
            using FileStream sidecar = MacSafeFileSystem.OpenReadNoSymlinks(path);
            RequireLeaf(sidecar, path, executableMode: false);
        }
    }

    internal static void RequireMatchesSealedApplicationCopy(FileStream installedExecutable)
    {
        string expectedPath = Path.Combine(AppContext.BaseDirectory, "Native", "zpaq");
        using FileStream expected = MacSafeFileSystem.OpenReadNoSymlinks(expectedPath);
        ToolIntegrityStatus expectedStatus = IntegrityService.CheckFile(expected, expectedPath, requireManifest: true);
        if (!expectedStatus.IsTrusted)
        {
            throw new InvalidOperationException(
                "The application ZPAQ reference failed its pinned hybrid and Apple-signature checks.");
        }

        byte[] installedSha256 = HashSha256(installedExecutable);
        byte[] expectedSha256 = HashSha256(expected);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(installedSha256, expectedSha256))
            {
                throw new InvalidOperationException(
                    "The installed root-owned ZPAQ does not match the SHA-256 pin from this authenticated application copy.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(installedSha256);
            CryptographicOperations.ZeroMemory(expectedSha256);
        }
        MacSafeFileSystem.RequirePathStillNamesHandle(expected.SafeFileHandle, expectedPath);
    }

    private static byte[] HashSha256(FileStream stream)
    {
        long originalPosition = stream.Position;
        try
        {
            stream.Position = 0;
            return SHA256.HashData(stream);
        }
        finally
        {
            stream.Position = originalPosition;
        }
    }

    private static void RequireDirectory(string path, bool requireWheel, ushort? exactMode)
    {
        string canonical = MacSafeFileSystem.ResolveExistingRealPath(path);
        if (!string.Equals(canonical, path, StringComparison.Ordinal))
        {
            throw new IOException($"The ZPAQ anchor component resolves through an alias or symbolic link: {path}");
        }
        using SafeFileHandle handle = MacSafeFileSystem.OpenDirectoryHandle(path);
        MacSafeFileSystem.RequirePathStillNamesHandle(handle, path);
        DarwinStat status = GetStatus(handle);
        ushort permissions = (ushort)(status.Mode & 0x01FF);
        if ((status.Mode & 0xF000) != 0x4000
            || status.Uid != 0
            || (requireWheel && status.Gid != 0)
            || (permissions & 0x0012) != 0
            || (exactMode is { } required && permissions != required))
        {
            throw new IOException(
                $"The ZPAQ anchor directory has unsafe type, ownership, group, or permissions: {path}");
        }
    }

    private static void RequireLeaf(FileStream stream, string path, bool executableMode)
    {
        MacSafeFileSystem.RequirePathStillNamesHandle(stream.SafeFileHandle, path);
        DarwinStat status = GetStatus(stream.SafeFileHandle);
        ushort permissions = (ushort)(status.Mode & 0x01FF);
        bool validPermissions = executableMode
            ? permissions is 0x016D or 0x01ED // 0555 or 0755
            : permissions == 0x0124;          // 0444
        if ((status.Mode & 0xF000) != 0x8000
            || status.Uid != 0
            || status.Gid != 0
            || status.LinkCount != 1
            || !validPermissions)
        {
            throw new IOException(
                $"The ZPAQ anchor leaf has unsafe type, ownership, link count, or permissions: {path}");
        }
    }

    private static DarwinStat GetStatus(SafeFileHandle handle)
    {
        bool added = false;
        try
        {
            handle.DangerousAddRef(ref added);
            int descriptor = checked((int)handle.DangerousGetHandle());
            if (FStat(descriptor, out DarwinStat status) != 0)
            {
                throw new Win32Exception(
                    Marshal.GetLastPInvokeError(),
                    "Could not inspect the root-owned ZPAQ anchor.");
            }
            return status;
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

    [StructLayout(LayoutKind.Sequential)]
    private struct DarwinTimespec
    {
        internal long Seconds;
        internal long Nanoseconds;
    }

    [LibraryImport("libSystem.B.dylib", EntryPoint = "fstat", SetLastError = true)]
    private static partial int FStat(int descriptor, out DarwinStat status);
}
#endif
