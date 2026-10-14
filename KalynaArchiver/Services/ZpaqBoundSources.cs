using System.Buffers.Binary;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace KalynaArchiver.Services;

/// <summary>
/// Public source metadata plus bounded reads of the exact inventoried objects.
/// No cloned tree, hardlinks, source file copies, shared mapping or payload spool.
/// This proves identity and detects mutation; it is not a database snapshot.
/// </summary>
internal sealed partial class ZpaqBoundSources : IDisposable
{
    private sealed record Entry(string Path, string Relative, bool Directory, long Length, long Date, long Attributes,
#if KEEPVAULT_MACOS
        MacFileIdentity Identity,
#else
        WindowsSourceIdentity Identity,
#endif
        OperationMemoryBudget.HeavyLease Memory);
    private readonly List<Entry> _entries = [];
    private readonly HashSet<string> _names = new(StringComparer.Ordinal);
    private readonly HashSet<string> _portableNames = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _readGate = new(1);
    private FileStream? _currentFile;
    private Entry? _currentEntry;
    private readonly ArchiveOperationPolicy _policy;
    internal long TotalBytes { get; private set; }
    internal long LargestFileBytes { get; private set; }
    internal long NativeMetadataBytes { get; private set; }
    internal int Count => _entries.Count;

    private ZpaqBoundSources(ArchiveOperationPolicy policy) { _policy = policy; }

    internal static ZpaqBoundSources Bind(string commonRoot, IReadOnlyList<string> inputPaths, CancellationToken token)
    {
        var result = new ZpaqBoundSources(ArchiveOperationPolicy.Current);
        try
        {
            foreach (string input in inputPaths)
                result.Visit(Path.GetFullPath(input), Path.GetRelativePath(commonRoot, input).Replace('\\', '/'), token);
            result.ValidateAll();
            return result;
        }
        catch { result.Dispose(); throw; }
    }

    private void Visit(string path, string relative, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (relative.Length == 0 || relative.StartsWith('/') || relative.Split('/').Any(static part => part is "" or "." or "..")
            || relative.Contains('\0') || Encoding.UTF8.GetByteCount(relative) > 32766)
            throw new IOException("The source name is outside the portable archive path contract.");
        if (!_names.Add(relative)) return; // normalized overlapping user selections
        if (!_portableNames.Add(relative.Normalize(NormalizationForm.FormC)))
            throw new IOException("Source paths collide under portable Unicode/case comparison.");
        foreach (string component in relative.Split('/')) ValidatePortableComponent(component);
        if (_entries.Count >= _policy.MaxEntryCount)
            throw new IOException("The selected sources exceed the approved entry limit.");
        OperationMemoryBudget.HeavyLease memory = OperationMemoryBudget.AcquireWorking(checked(1024L + path.Length * 4L + relative.Length * 4L));
        bool owned = false;
        try
        {
#if KEEPVAULT_MACOS
            // Bind before enumerating. Every child identity comes from this
            // directory descriptor, never from a later native pathname open.
            using SafeFileHandle parent = MacSafeFileSystem.OpenDirectoryHandle(Path.GetDirectoryName(path)!);
            MacFileIdentity identity = MacSafeFileSystem.GetIdentityAt(parent, Path.GetFileName(path));
            int type = identity.Mode & 0xF000;
            bool directory = type == 0x4000;
            if (!directory && (type != 0x8000 || identity.LinkCount != 1))
                throw new IOException("The source is not a single-link regular file or plain directory.");
            long size = directory ? 0 : identity.Size;
            long date = long.Parse(DateTimeOffset.FromUnixTimeSeconds(identity.ModificationSeconds).UtcDateTime
                .ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture), CultureInfo.InvariantCulture);
            long attributes = ((long)identity.Mode << 8) | 'u';
#else
            FileAttributes attrs = File.GetAttributes(path);
            bool directory = (attrs & FileAttributes.Directory) != 0;
            if ((attrs & FileAttributes.ReparsePoint) != 0) throw new IOException("Source reparse points are not permitted.");
            using SafeFileHandle handle = directory
                ? WindowsSafeFileSystem.OpenDirectoryBound(path, denyRename: true, requestCreateAccess: false)
                : File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.Read, FileOptions.RandomAccess);
            _ = NativePathResolver.RequireCanonicalFilePath(handle, path, "Archive source");
            if (!directory) WindowsSafeFileSystem.ValidateRegularFile(handle, path, requireSingleLink: true);
            WindowsSourceIdentity identity = CaptureWindows(handle);
            long size = directory ? 0 : RandomAccess.GetLength(handle);
            long date = long.Parse(DateTime.FromFileTimeUtc(identity.WriteTime).ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture), CultureInfo.InvariantCulture);
            long attributes = ((long)attrs << 8) | 'w';
#endif
            if (size < 0) throw new IOException("The source reported a negative length.");
            var entry = new Entry(path, relative + (directory ? "/" : ""), directory, size, date, attributes, identity, memory);
            _entries.Add(entry); owned = true; memory.CommitAllocation();
            TotalBytes = checked(TotalBytes + size);
            LargestFileBytes = Math.Max(LargestFileBytes, size);
            NativeMetadataBytes = checked(NativeMetadataBytes + 4096L + Encoding.UTF8.GetByteCount(entry.Relative) * 8L);
            if (directory)
            {
#if KEEPVAULT_MACOS
                using SafeFileHandle bound = MacSafeFileSystem.OpenDirectoryHandle(path);
                if (!MacSafeFileSystem.GetIdentity(bound).SameObjectAndMetadata(identity)) throw new IOException("Source directory changed before inventory.");
                foreach (MacDirectoryEntry child in MacSafeFileSystem.ReadDirectoryEntriesNoFollow(bound))
                    Visit(Path.Combine(path, child.Name), relative + "/" + child.Name, token);
                if (!MacSafeFileSystem.GetIdentity(bound).SameObjectAndMetadata(identity)) throw new IOException("Source directory changed during inventory.");
#else
                foreach (string child in Directory.EnumerateFileSystemEntries(path))
                    Visit(child, relative + "/" + Path.GetFileName(child), token);
                if (CaptureWindows(handle) != identity) throw new IOException("Source directory changed during inventory.");
#endif
            }
        }
        finally { if (!owned) memory.Dispose(); }
    }

    private static void ValidatePortableComponent(string component)
    {
        if (component.Length == 0 || component is "." or ".." || component.EndsWith('.') || component.EndsWith(' ')
            || component.Any(character => character < 32 || "<>:\"|?*\\".Contains(character)))
            throw new IOException("The source name is not portable between macOS and Windows.");
        string name = component.Split('.', 2)[0].ToUpperInvariant();
        if (name is "CON" or "PRN" or "AUX" or "NUL" || (name.Length == 4
            && (name.StartsWith("COM", StringComparison.Ordinal) || name.StartsWith("LPT", StringComparison.Ordinal))
            && name[3] is >= '1' and <= '9'))
            throw new IOException("The source uses a reserved Windows device name.");
    }

    internal ValueTask<ZpaqControlSession.Payload> EntryAsync(ulong index, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (index == (ulong)_entries.Count) return ValueTask.FromResult(new ZpaqControlSession.Payload([]));
        if (index > (ulong)_entries.Count) throw new InvalidDataException("Source catalog index is outside the inventory.");
        Entry entry = _entries[(int)index];
        byte[] name = Encoding.UTF8.GetBytes(entry.Relative);
        int length = checked(40 + name.Length);
        OperationMemoryBudget.HeavyLease memory = OperationMemoryBudget.AcquireWorking(length);
        byte[] encoded;
        try { encoded = new byte[length]; memory.CommitAllocation(); }
        catch { memory.Dispose(); throw; }
        BinaryPrimitives.WriteUInt64BigEndian(encoded, index);
        BinaryPrimitives.WriteInt64BigEndian(encoded.AsSpan(8), entry.Length);
        BinaryPrimitives.WriteInt64BigEndian(encoded.AsSpan(16), entry.Date);
        BinaryPrimitives.WriteInt64BigEndian(encoded.AsSpan(24), entry.Attributes);
        BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(32), entry.Directory ? 1u : 0u);
        BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(36), checked((uint)name.Length));
        name.CopyTo(encoded, 40);
        return ValueTask.FromResult(new ZpaqControlSession.Payload(encoded, memory));
    }

    internal async ValueTask<ZpaqControlSession.Payload> ReadAsync(ulong index, ulong offset, int count, CancellationToken token)
    {
        if (index >= (ulong)_entries.Count || count <= 0 || count > ZpaqControlSession.MaximumPayloadBytes)
            throw new InvalidDataException("The native source read is outside its capability.");
        Entry entry = _entries[(int)index];
        if (entry.Directory || offset > (ulong)entry.Length || (ulong)count > (ulong)entry.Length - offset)
            throw new InvalidDataException("The native source read exceeds the inventoried file.");
        await _readGate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            if (!ReferenceEquals(entry, _currentEntry))
            {
                CloseCurrent();
#if KEEPVAULT_MACOS
                _currentFile = MacSafeFileSystem.OpenReadNoSymlinks(entry.Path, requireSingleLink: true);
#else
                _currentFile = new FileStream(entry.Path, FileMode.Open, FileAccess.Read, FileShare.Read,
                    1, FileOptions.Asynchronous | FileOptions.RandomAccess);
#endif
                _currentEntry = entry;
            }
            ValidateHandle(entry, _currentFile!.SafeFileHandle);
            OperationMemoryBudget.HeavyLease memory = await OperationMemoryBudget.AcquireWorkingAsync(count, token).ConfigureAwait(false);
            byte[]? bytes = null;
            try
            {
                bytes = new byte[count]; memory.CommitAllocation();
                int read = 0;
                while (read < count)
                {
                    int n = await RandomAccess.ReadAsync(_currentFile.SafeFileHandle, bytes.AsMemory(read),
                        checked((long)offset + read), token).ConfigureAwait(false);
                    if (n == 0) throw new EndOfStreamException("An inventoried source was truncated.");
                    read = checked(read + n);
                }
                ValidateHandle(entry, _currentFile.SafeFileHandle);
                return new ZpaqControlSession.Payload(bytes, memory);
            }
            catch { if (bytes is not null) System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); memory.Dispose(); throw; }
        }
        finally { _readGate.Release(); }
    }

    private static void ValidateHandle(Entry entry, SafeFileHandle handle)
    {
        _ = NativePathResolver.RequireCanonicalFilePath(handle, entry.Path, "Archive source");
#if KEEPVAULT_MACOS
        if (!MacSafeFileSystem.GetIdentity(handle).SameObjectAndMetadata(entry.Identity))
#else
        if (!entry.Directory) WindowsSafeFileSystem.ValidateRegularFile(handle, entry.Path, requireSingleLink: true);
        if (CaptureWindows(handle) != entry.Identity)
#endif
            throw new IOException("An inventoried source object or its metadata changed.");
    }
    private void CloseCurrent()
    {
        try { if (_currentFile is not null) ValidateHandle(_currentEntry!, _currentFile.SafeFileHandle); }
        finally { _currentFile?.Dispose(); _currentFile = null; _currentEntry = null; }
    }
    internal void ValidateAll()
    {
        CloseCurrent();
        foreach (Entry entry in _entries)
        {
#if KEEPVAULT_MACOS
            using FileStream? file = entry.Directory ? null : MacSafeFileSystem.OpenReadNoSymlinks(entry.Path, requireSingleLink: true);
            using SafeFileHandle? directory = entry.Directory ? MacSafeFileSystem.OpenDirectoryHandle(entry.Path) : null;
            SafeFileHandle handle = file?.SafeFileHandle ?? directory!;
#else
            using SafeFileHandle handle = entry.Directory ? WindowsSafeFileSystem.OpenDirectoryBound(entry.Path, true, requestCreateAccess: false)
                : File.OpenHandle(entry.Path, FileMode.Open, FileAccess.Read, FileShare.Read, FileOptions.RandomAccess);
#endif
            ValidateHandle(entry, handle);
        }
    }
    public void Dispose()
    {
        _currentFile?.Dispose(); _currentFile = null; _currentEntry = null;
        foreach (Entry entry in _entries) entry.Memory.Dispose();
        _entries.Clear(); _names.Clear(); _portableNames.Clear(); _readGate.Dispose();
    }
#if !KEEPVAULT_MACOS
    private readonly record struct WindowsSourceIdentity(WindowsFileIdentity Object, long WriteTime, long ChangeTime);
    [StructLayout(LayoutKind.Sequential)]
    private struct BasicInfo { internal long Creation, Access, Write, Change; internal uint Attributes; }
    private static WindowsSourceIdentity CaptureWindows(SafeFileHandle handle)
    {
        if (!GetBasicInformation(handle, 0, out BasicInfo info, (uint)Marshal.SizeOf<BasicInfo>()))
            throw new IOException("The bound source metadata could not be read.");
        return new(WindowsSafeFileSystem.GetIdentity(handle), info.Write, info.Change);
    }
    [LibraryImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetBasicInformation(SafeFileHandle handle, int informationClass, out BasicInfo info, uint bytes);
#endif
}
