using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace KalynaArchiver.Services;

/// <summary>Descriptor-bound filesystem requirements for private operation files.</summary>
internal static partial class MacOperationVolume
{
    internal readonly record struct Info(string Identity, string Format, uint Flags, long AvailableBytes);

    internal static Info Inspect(string directory, bool workingDirectory)
    {
        string requested = Path.GetFullPath(directory);
        string existing = requested;
        while (!Directory.Exists(existing))
            existing = Path.GetDirectoryName(existing) ?? throw new DirectoryNotFoundException("The operation volume is unavailable.");
        string canonical = MacSafeFileSystem.ResolveExistingRealPath(existing);
        string resolved = Path.Combine(canonical, Path.GetRelativePath(existing, requested));
        if (workingDirectory)
        {
            RequireNonCloudWorkingPath(resolved);
            RequireNotUbiquitous(canonical);
        }
        using var handle = MacSafeFileSystem.OpenDirectoryHandle(canonical);
        Info info = Inspect(handle);
        MacSafeFileSystem.RequirePathStillNamesHandle(handle, canonical);
        return info;
    }

    internal static unsafe Info Inspect(SafeFileHandle handle)
    {
        MacFileIdentity identity = MacSafeFileSystem.GetIdentity(handle);
        bool added = false;
        try
        {
            handle.DangerousAddRef(ref added);
            int descriptor = checked((int)handle.DangerousGetHandle());
            DarwinStatFs stat;
            int status = RuntimeInformation.ProcessArchitecture == Architecture.X64
                ? FStatFsInode64(descriptor, out stat) : FStatFs(descriptor, out stat);
            if (status != 0)
                throw new IOException("The operation filesystem could not be inspected.", new Win32Exception(Marshal.GetLastPInvokeError()));
            string format = Encoding.ASCII.GetString(new ReadOnlySpan<byte>(stat.Format, 16)).TrimEnd('\0');
            RequireSupported(format, stat.Flags);
            if (stat.BlockSize == 0 || stat.AvailableBlocks == ulong.MaxValue)
                throw new IOException("The operation filesystem did not report a valid free-space budget.");
            long available = checked((long)(stat.AvailableBlocks * stat.BlockSize));
            return new("device:" + identity.Device.ToString(System.Globalization.CultureInfo.InvariantCulture), format, stat.Flags, available);
        }
        finally { if (added) handle.DangerousRelease(); }
    }

    internal static void RequireSupported(string format, uint flags)
    {
        // The shipped no-follow, owner-only and exclusive-rename contracts are
        // approved for local APFS/HFS+. Unknown filesystems need separate review.
        if (format is not ("apfs" or "hfs") || (flags & 0x1000) == 0
            || (flags & (0x1 | 0x00200000)) != 0)
            throw new IOException("Keep Vault operation files require a writable local APFS/HFS+ volume with ownership enabled.");
    }

    internal static void RequireNonCloudWorkingPath(string path)
    {
        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string root in new[] {
            Path.Combine(home, "Library", "CloudStorage"),
            Path.Combine(home, "Library", "Mobile Documents"),
            Path.Combine(home, "Dropbox"), Path.Combine(home, "OneDrive"),
            Path.Combine(home, "Google Drive"), Path.Combine(home, "Box") })
        {
            if (string.Equals(path, root, StringComparison.OrdinalIgnoreCase)
                || path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new IOException("Choose a local, non-synchronized working directory for Keep Vault private operation files.");
        }
    }

    private const string CoreFoundation = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";
    private static readonly Lazy<nint> UbiquitousKey = new(() =>
        Marshal.ReadIntPtr(NativeLibrary.GetExport(NativeLibrary.Load(CoreFoundation), "kCFURLIsUbiquitousItemKey")));

    private static void RequireNotUbiquitous(string path)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(path);
        nint url = CFURLCreateFromFileSystemRepresentation(0, bytes, bytes.Length, true);
        if (url == 0) throw new IOException("The working directory's cloud status could not be queried.");
        nint value = 0, error = 0;
        try
        {
            if (!CFURLCopyResourcePropertyForKey(url, UbiquitousKey.Value, out value, out error))
                throw new IOException("The working directory's iCloud status could not be verified.");
            // Apple's API returns success + NULL when this resource property
            // is unavailable, including ordinary local directories. That is
            // not an iCloud assertion. Known cloud roots are rejected above;
            // unknown third-party synchronization cannot be inferred here.
            if (value == 0) return;
            if (CFGetTypeID(value) != CFBooleanGetTypeID())
                throw new IOException("The working directory returned an invalid iCloud status.");
            if (CFBooleanGetValue(value))
                throw new IOException("Choose a working directory outside iCloud storage for Keep Vault private operation files.");
        }
        finally
        {
            if (value != 0) CFRelease(value);
            if (error != 0) CFRelease(error);
            CFRelease(url);
        }
    }

    // Darwin's 64-bit-inode ABI from the macOS SDK sys/mount.h. Both shipped
    // architectures use this 2168-byte layout; tests compare it with the C SDK.
    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct DarwinStatFs
    {
        public uint BlockSize;
        public int IoSize;
        public ulong Blocks, FreeBlocks, AvailableBlocks, Files, FreeFiles;
        public int FileSystemId0, FileSystemId1;
        public uint Owner, Type, Flags, Subtype;
        public fixed byte Format[16];
        public fixed byte MountedOn[1024];
        public fixed byte MountedFrom[1024];
        public uint ExtendedFlags;
        public fixed uint Reserved[7];
    }

    internal static int NativeLayoutBytes => Marshal.SizeOf<DarwinStatFs>();

    [LibraryImport("/usr/lib/libSystem.B.dylib", EntryPoint = "fstatfs", SetLastError = true)]
    private static partial int FStatFs(int descriptor, out DarwinStatFs status);
    [LibraryImport("/usr/lib/libSystem.B.dylib", EntryPoint = "fstatfs$INODE64", SetLastError = true)]
    private static partial int FStatFsInode64(int descriptor, out DarwinStatFs status);
    [LibraryImport(CoreFoundation)]
    private static partial nint CFURLCreateFromFileSystemRepresentation(nint allocator, byte[] bytes, nint length, [MarshalAs(UnmanagedType.I1)] bool isDirectory);
    [LibraryImport(CoreFoundation)]
    [return: MarshalAs(UnmanagedType.I1)]
    private static partial bool CFURLCopyResourcePropertyForKey(nint url, nint key, out nint value, out nint error);
    [LibraryImport(CoreFoundation)]
    private static partial nuint CFGetTypeID(nint value);
    [LibraryImport(CoreFoundation)]
    private static partial nuint CFBooleanGetTypeID();
    [LibraryImport(CoreFoundation)]
    [return: MarshalAs(UnmanagedType.I1)]
    private static partial bool CFBooleanGetValue(nint value);
    [LibraryImport(CoreFoundation)]
    private static partial void CFRelease(nint value);
}
