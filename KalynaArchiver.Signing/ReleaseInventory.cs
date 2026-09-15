using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

[assembly: InternalsVisibleTo("KalynaArchiver.Tests")]

namespace KalynaArchiver.Signing;

public sealed record ReleaseInventoryDocument(string Product, string Version, string Runtime, ReleaseInventoryEntry[] Files);
public sealed record ReleaseInventoryEntry(string Path, long Length, string Sha512);

/// <summary>A complete, authenticated package whose files and parent directories remain held open.</summary>
public sealed class VerifiedReleaseInventory : IDisposable
{
    public const string InventoryName = "RELEASE-INVENTORY.json";
    private readonly List<IDisposable> _leases = [];
    private readonly Dictionary<string, FileStream> _files = new(StringComparer.OrdinalIgnoreCase);
    public string Root { get; }
    public ReleaseInventoryDocument Document { get; private set; } = null!;
    public string InventoryDigest { get; private set; } = string.Empty;
    internal Action<string>? TestHookAfterCopyWriterClosed { get; set; }

    public VerifiedReleaseInventory(string root, HybridSignaturePolicy policy)
    {
        Root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        try
        {
            HoldParents(Root, denyLeafWriters: true);
            var pending = new Stack<string>();
            pending.Push(Root);
            var directories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            while (pending.Count != 0)
            {
                string directory = pending.Pop();
                foreach (string child in Directory.EnumerateFileSystemEntries(directory))
                {
                    if (_files.Count + directories.Count > 4096) throw new InvalidDataException("The package has too many entries.");
                    FileAttributes attributes = File.GetAttributes(child);
                    if ((attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Package links are forbidden.");
                    string relative = Path.GetRelativePath(Root, child).Replace('\\', '/');
                    ValidateRelativePath(relative);
                    if ((attributes & FileAttributes.Directory) != 0)
                    {
                        if (!directories.Add(relative)) throw new InvalidDataException("Ambiguous package directory name.");
                        _leases.Add(HoldDirectory(child, denyWriters: true));
                        pending.Push(child);
                    }
                    else
                    {
                        FileStream stream = OpenRegularFile(child);
                        _leases.Add(stream);
                        if (!_files.TryAdd(relative, stream)) throw new InvalidDataException("Ambiguous package file name.");
                    }
                }
            }

            FileStream inventoryStream = Require(InventoryName);
            if (inventoryStream.Length is <= 0 or > 2 * 1024 * 1024) throw new InvalidDataException("Invalid package inventory length.");
            Require(InventoryName + ".khsig");
            if (!HybridSignatureService.VerifyFile(Path.Combine(Root, InventoryName), Path.Combine(Root, InventoryName + ".khsig"), policy).IsTrusted)
                throw new CryptographicException("The complete release inventory is not signed by the pinned release keys.");
            InventoryDigest = Convert.ToHexString(SHA256.HashData(inventoryStream));
            inventoryStream.Position = 0;
            Document = JsonSerializer.Deserialize<ReleaseInventoryDocument>(inventoryStream)
                ?? throw new InvalidDataException("The release inventory is empty.");
            if (Document.Product != "Keep Vault" || Document.Version != "5.0.2" || Document.Runtime != "win-x64"
                || Document.Files is null || Document.Files.Length is < 1 or > 4094)
                throw new InvalidDataException("The package product, version, architecture, or inventory does not match this installer.");

            var expected = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { InventoryName, InventoryName + ".khsig" };
            var expectedDirectories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (ReleaseInventoryEntry entry in Document.Files)
            {
                ValidateRelativePath(entry.Path);
                if (!expected.Add(entry.Path) || entry.Length < 0 || entry.Length > 4L * 1024 * 1024 * 1024
                    || entry.Sha512 is null || entry.Sha512.Length != 128 || !entry.Sha512.All(Uri.IsHexDigit))
                    throw new InvalidDataException("The release inventory contains a duplicate or invalid file record.");
                string? parent = Path.GetDirectoryName(entry.Path);
                while (!string.IsNullOrEmpty(parent))
                {
                    expectedDirectories.Add(parent.Replace('\\', '/'));
                    parent = Path.GetDirectoryName(parent);
                }
                FileStream stream = Require(entry.Path);
                if (stream.Length != entry.Length) throw new CryptographicException("Package file length differs from the signed inventory.");
                stream.Position = 0;
                string digest = Convert.ToHexString(SHA512.HashData(stream));
                stream.Position = 0;
                if (!string.Equals(digest, entry.Sha512, StringComparison.OrdinalIgnoreCase))
                    throw new CryptographicException("Package file bytes differ from the signed inventory.");
            }
            if (!expected.SetEquals(_files.Keys) || !expectedDirectories.SetEquals(directories))
                throw new CryptographicException("The package has additional or missing files or directories.");
            foreach (string required in new[] { "Keep Vault.exe", "Keep Vault Release Verifier.exe", "Keep Vault Setup.exe", "QR-Scanner/QR-Scanner.exe", "PORTABLE_README.txt" })
                Require(required);
        }
        catch { Dispose(); throw; }
    }

    public void CopyToNewDirectory(string destination)
    {
        destination = Path.TrimEndingDirectorySeparator(Path.GetFullPath(destination));
        string destinationParent = Path.GetDirectoryName(destination) ?? throw new IOException("The destination has no parent.");
        SafeFileHandle parentHandle = HoldParents(destinationParent);
        var createdDirectories = new Dictionary<string, SafeFileHandle>(StringComparer.OrdinalIgnoreCase);
        SafeFileHandle rootHandle = CreateEntryBound(parentHandle, Path.GetFileName(destination), destination, directory: true);
        _leases.Add(rootHandle);
        createdDirectories.Add(string.Empty, rootHandle);
        var parents = new SortedSet<string>(Comparer<string>.Create((left, right) =>
            left.Length != right.Length ? left.Length.CompareTo(right.Length) : StringComparer.OrdinalIgnoreCase.Compare(left, right)));
        foreach (string relative in _files.Keys)
        {
            string? parent = Path.GetDirectoryName(relative);
            while (!string.IsNullOrEmpty(parent)) { parents.Add(parent); parent = Path.GetDirectoryName(parent); }
        }
        foreach (string relative in parents)
        {
            string parent = Path.GetDirectoryName(relative) ?? string.Empty;
            SafeFileHandle handle = CreateEntryBound(createdDirectories[parent], Path.GetFileName(relative), Path.Combine(destination, relative), directory: true);
            _leases.Add(handle);
            createdDirectories.Add(relative, handle);
        }
        foreach ((string relative, FileStream input) in _files)
        {
            string outputPath = Path.Combine(destination, relative.Replace('/', Path.DirectorySeparatorChar));
            // No existing object is ever opened for writing, including a partial install.
            FileInformation created;
            FileStream identityGuard;
            string parent = Path.GetDirectoryName(relative.Replace('/', Path.DirectorySeparatorChar)) ?? string.Empty;
            using (SafeFileHandle outputHandle = CreateEntryBound(createdDirectories[parent], Path.GetFileName(outputPath), outputPath, directory: false))
            using (var output = new FileStream(outputHandle, FileAccess.Write))
            {
                created = GetInformation(output.SafeFileHandle);
                input.Position = 0;
                input.CopyTo(output);
                output.Flush(true);
                // Overlap a read lease with the creator before closing its write
                // access. This guard denies rename throughout the transition.
                identityGuard = OpenRegularFile(outputPath, allowWriters: true);
                _leases.Add(identityGuard);
                RequireIdentity(identityGuard.SafeFileHandle, created);
            }
            TestHookAfterCopyWriterClosed?.Invoke(outputPath);
            FileStream lockedOutput = OpenRegularFile(outputPath);
            _leases.Add(lockedOutput);
            RequireIdentity(lockedOutput.SafeFileHandle, created);
            input.Position = 0;
            if (lockedOutput.Length != input.Length
                || !CryptographicOperations.FixedTimeEquals(SHA512.HashData(lockedOutput), SHA512.HashData(input)))
                throw new CryptographicException("The installed copy changed before it could be locked for verification.");
            lockedOutput.Position = 0;
            input.Position = 0;
        }
    }

    public static void ValidateRelativePath(string path)
    {
        if (string.IsNullOrEmpty(path) || path.Length > 240 || path.Contains('\\') || Path.IsPathRooted(path)
            || path.Split('/').Any(component => component is "" or "." or ".."
                || component.EndsWith('.') || component.EndsWith(' ') || component.Any(c => c < 32 || "<>:\"|?*".Contains(c))
                || IsDeviceName(component)))
            throw new InvalidDataException("The release inventory contains an unsafe or ambiguous relative path.");
    }

    private static bool IsDeviceName(string name)
    {
        string stem = name.Split('.')[0].ToUpperInvariant();
        return stem is "CON" or "PRN" or "AUX" or "NUL"
            || stem.Length == 4 && (stem.StartsWith("COM", StringComparison.Ordinal) || stem.StartsWith("LPT", StringComparison.Ordinal))
                && (stem[3] is >= '1' and <= '9' or '¹' or '²' or '³');
    }

    private FileStream Require(string relative) => _files.TryGetValue(relative, out FileStream? stream)
        ? stream : throw new InvalidDataException("The package is incomplete: " + relative);

    private SafeFileHandle HoldParents(string path, bool denyLeafWriters = false)
    {
        var parents = new Stack<string>();
        for (string? current = path; !string.IsNullOrEmpty(current); current = Path.GetDirectoryName(current))
            parents.Push(current);
        SafeFileHandle? handle = null;
        while (parents.Count != 0)
        {
            string current = parents.Pop();
            handle = HoldDirectory(current, denyWriters: denyLeafWriters && parents.Count == 0);
            _leases.Add(handle);
        }
        return handle ?? throw new IOException("The package path has no directory.");
    }

    public static SafeFileHandle HoldDirectory(string path, bool denyWriters = false)
    {
        // FILE_LIST_DIRECTORY is essential: metadata-only handles do not
        // reliably enforce the requested share-mode exclusion on Windows.
        SafeFileHandle handle = CreateFileW(path, 0x81, denyWriters ? 1u : 3u, 0, 3, 0x02200000, 0);
        try
        {
            if (handle.IsInvalid || !GetFileInformationByHandle(handle, out FileInformation info)
                || (info.Attributes & (uint)FileAttributes.Directory) == 0 || (info.Attributes & (uint)FileAttributes.ReparsePoint) != 0)
                throw new IOException("A package parent is not a regular directory.");
            RequireCanonicalPath(handle, path);
            return handle;
        }
        catch { handle.Dispose(); throw; }
    }

    private static FileStream OpenRegularFile(string path, bool allowWriters = false)
    {
        SafeFileHandle handle = CreateFileW(path, 0x80000000, allowWriters ? 3u : 1u, 0, 3, 0x00200000, 0);
        try
        {
            if (handle.IsInvalid || !GetFileInformationByHandle(handle, out FileInformation info)
                || info.Links != 1 || (info.Attributes & (uint)(FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
                throw new IOException("A package file is not a regular single-link file.");
            RequireCanonicalPath(handle, path);
            return new FileStream(handle, FileAccess.Read);
        }
        catch { handle.Dispose(); throw; }
    }

    private static SafeFileHandle CreateEntryBound(SafeFileHandle parent, string name, string path, bool directory)
    {
        ValidateRelativePath(name);
        if (name.Contains('/')) throw new IOException("A bound creation requires a single component.");
        nint nameBuffer = Marshal.StringToHGlobalUni(name);
        nint unicodeBuffer = 0;
        SafeFileHandle? result = null;
        bool parentReferenced = false;
        try
        {
            var unicode = new UnicodeString
            {
                Length = checked((ushort)(name.Length * 2)),
                MaximumLength = checked((ushort)((name.Length + 1) * 2)),
                Buffer = nameBuffer,
            };
            unicodeBuffer = Marshal.AllocHGlobal(Marshal.SizeOf<UnicodeString>());
            Marshal.StructureToPtr(unicode, unicodeBuffer, false);
            parent.DangerousAddRef(ref parentReferenced);
            var attributes = new ObjectAttributes
            {
                Length = Marshal.SizeOf<ObjectAttributes>(),
                RootDirectory = parent.DangerousGetHandle(),
                ObjectName = unicodeBuffer,
                Attributes = 0x40, // OBJ_CASE_INSENSITIVE
            };
            // FILE_CREATE atomically returns the newly created object relative
            // to its held parent, without a create-then-open substitution gap.
            int status = NtCreateFile(out result, directory ? 0x00100081u : 0x40100080u, ref attributes, out _, 0,
                directory ? (uint)FileAttributes.Directory : (uint)FileAttributes.Normal,
                1, 2, directory ? 0x00200021u : 0x00200060u, 0, 0);
            if (status < 0 || result.IsInvalid) throw new IOException("Cannot create an exclusive bound install object.");
            FileInformation info = GetInformation(result);
            if (((info.Attributes & (uint)FileAttributes.Directory) != 0) != directory
                || (info.Attributes & (uint)FileAttributes.ReparsePoint) != 0 || (!directory && info.Links != 1))
                throw new IOException("The new install object is not a regular object of the expected type.");
            RequireCanonicalPath(result, path);
            SafeFileHandle created = result;
            result = null;
            return created;
        }
        finally
        {
            result?.Dispose();
            if (parentReferenced) parent.DangerousRelease();
            if (unicodeBuffer != 0) Marshal.FreeHGlobal(unicodeBuffer);
            Marshal.FreeHGlobal(nameBuffer);
        }
    }

    private static FileInformation GetInformation(SafeFileHandle handle) => GetFileInformationByHandle(handle, out FileInformation information)
        ? information : throw new IOException("Cannot inspect the held package object.");

    private static void RequireIdentity(SafeFileHandle handle, FileInformation expected)
    {
        FileInformation actual = GetInformation(handle);
        if (actual.Volume != expected.Volume || actual.IndexHigh != expected.IndexHigh || actual.IndexLow != expected.IndexLow)
            throw new IOException("The installed object changed identity.");
    }

    private static void RequireCanonicalPath(SafeFileHandle handle, string expected)
    {
        var buffer = new StringBuilder(32768);
        uint length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 0);
        if (length == 0 || length >= buffer.Capacity) throw new IOException("Cannot resolve a held package object.");
        string actual = buffer.ToString();
        if (actual.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) actual = @"\\" + actual[8..];
        else if (actual.StartsWith(@"\\?\", StringComparison.Ordinal)) actual = actual[4..];
        if (!string.Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(expected)),
                Path.TrimEndingDirectorySeparator(Path.GetFullPath(actual)), StringComparison.OrdinalIgnoreCase))
            throw new IOException("A package path resolved through an alias or changed during inspection.");
    }

    public void Dispose()
    {
        for (int index = _leases.Count - 1; index >= 0; index--) _leases[index].Dispose();
        _leases.Clear();
        _files.Clear();
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME Created, Accessed, Written;
        public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString { public ushort Length, MaximumLength; public nint Buffer; }
    [StructLayout(LayoutKind.Sequential)]
    private struct ObjectAttributes
    {
        public int Length;
        public nint RootDirectory, ObjectName;
        public uint Attributes;
        public nint SecurityDescriptor, SecurityQualityOfService;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct IoStatusBlock { public nint Status; public nuint Information; }
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("ntdll.dll")]
    private static extern int NtCreateFile(out SafeFileHandle file, uint access, ref ObjectAttributes attributes,
        out IoStatusBlock status, nint allocationSize, uint fileAttributes, uint share, uint disposition,
        uint options, nint extendedAttributes, uint extendedAttributesLength);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, nint attributes, uint disposition, uint flags, nint template);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle file, out FileInformation information);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder path, uint length, uint flags);
}
