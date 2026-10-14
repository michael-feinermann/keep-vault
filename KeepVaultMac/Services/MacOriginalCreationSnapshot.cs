using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace KalynaArchiver.Services;

internal sealed partial class MacOriginalDeletionService
{
    /// <summary>A bounded metadata inventory taken before archive creation, never a payload copy.</summary>
    internal sealed class CreationSnapshot : IDisposable
    {
        private readonly List<OperationMemoryBudget.HeavyLease> _leases = [];
        private readonly Dictionary<string, MacFileIdentity> _files = new(StringComparer.Ordinal);
        private readonly Dictionary<string, (MacFileIdentity Identity, bool Strict)> _directories = new(StringComparer.Ordinal);
        private long _charged;
        private bool _disposed;
        internal IReadOnlyDictionary<string, MacFileIdentity> Files => _files;
        internal IReadOnlyDictionary<string, (MacFileIdentity Identity, bool Strict)> Directories => _directories;
        internal string[] Roots { get; }
        internal string WorkingDirectory { get; }
        internal bool IsDisposed => _disposed;

        internal CreationSnapshot(string[] roots)
        {
            Roots = roots;
            WorkingDirectory = ZpaqService.GetArchiveWorkingDirectory(roots);
        }

        private void ChargeEntry(string path)
        {
            ArchiveOperationPolicy policy = ArchiveOperationPolicy.Current;
            if (checked((long)_files.Count + _directories.Count + 1) > policy.MaxEntryCount)
                throw new IOException("The original-creation inventory exceeds the approved entry allowance.");
            // Per admitted entry: identities, dictionary capacity/growth, later
            // digest state and relative-name sets. No allowance-wide allocation.
            long bytes = checked(2048 + 12L * path.Length);
            long total = checked(_charged + bytes);
            if (total > policy.MaxMetadataBytes)
                throw new IOException("The original-creation inventory exceeds the approved metadata allowance.");
            OperationMemoryBudget.HeavyLease lease = OperationMemoryBudget.AcquireWorking(bytes);
            try { _leases.Add(lease); _charged = total; }
            catch { lease.Dispose(); throw; }
            // CLR object/capacity accounting is an upper bound, not a byte-exact
            // resident allocator ACK. Keep this small derived charge pending.
        }

        internal void AddFile(string path, MacFileIdentity identity)
        {
            if (_files.ContainsKey(path)) throw new IOException("Duplicate original file in creation inventory.");
            ChargeEntry(path);
            _files.Add(path, identity);
        }
        internal void AddDirectory(string path, MacFileIdentity identity, bool strict)
        {
            if (_directories.TryGetValue(path, out var old))
            {
                if (!old.Identity.SameObject(identity) || old.Strict && !old.Identity.SameObjectAndMetadata(identity))
                    throw new IOException("An original directory changed during creation inventory.");
                if (strict && !old.Strict) _directories[path] = (identity, true);
                return;
            }
            ChargeEntry(path);
            _directories.Add(path, (identity, strict));
        }

        internal void RequireUnchanged(IReadOnlyList<string> originals, CancellationToken token)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            string[] roots = NormalizeCreationRoots(originals);
            if (!roots.SequenceEqual(Roots, StringComparer.Ordinal))
                throw new IOException("The selected original set differs from archive creation.");
            int files = 0, directories = 0;
            WalkCreationRoots(roots, (path, identity, directory) =>
            {
                token.ThrowIfCancellationRequested();
                if (directory)
                {
                    if (!_directories.TryGetValue(path, out var expected) || !expected.Strict
                        || !identity.SameObjectAndMetadata(expected.Identity))
                        throw new IOException($"An original directory changed since archive creation: {path}");
                    directories++;
                }
                else
                {
                    if (!_files.TryGetValue(path, out MacFileIdentity expected) || !identity.SameObjectAndMetadata(expected))
                        throw new IOException($"An original file changed since archive creation: {path}");
                    files++;
                }
            }, token);
            if (files != _files.Count || directories != _directories.Count(entry => entry.Value.Strict))
                throw new IOException("Original creation topology lost an entry.");
            foreach ((string path, var expected) in _directories)
            {
                using SafeFileHandle handle = MacSafeFileSystem.OpenDirectoryHandle(path);
                MacSafeFileSystem.RequirePathStillNamesHandle(handle, path);
                MacFileIdentity current = MacSafeFileSystem.GetIdentity(handle);
                if (!current.SameObject(expected.Identity) || expected.Strict && !current.SameObjectAndMetadata(expected.Identity))
                    throw new IOException($"An original parent directory changed identity: {path}");
            }
        }

        internal void RequireParentIdentity(string path, MacFileIdentity current)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (!_directories.TryGetValue(path, out var expected) || !current.SameObject(expected.Identity))
                throw new IOException($"An original parent differs from its creation identity: {path}");
        }

        internal HashSet<string> ExpectedDirectories()
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            void AddParents(string relative)
            {
                while (!string.IsNullOrEmpty(relative) && relative != ".")
                {
                    names.Add(relative);
                    relative = Path.GetDirectoryName(relative) ?? string.Empty;
                }
            }
            foreach ((string path, var directory) in _directories)
                if (directory.Strict) AddParents(Path.GetRelativePath(WorkingDirectory, path));
            foreach (string path in _files.Keys)
                AddParents(Path.GetDirectoryName(Path.GetRelativePath(WorkingDirectory, path)) ?? string.Empty);
            return names;
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            _files.Clear(); _directories.Clear();
            foreach (OperationMemoryBudget.HeavyLease lease in _leases) lease.Dispose();
            _leases.Clear();
        }
    }

    internal static CreationSnapshot CaptureCreationSnapshot(IReadOnlyList<string> originals, CancellationToken token)
    {
        string[] roots = NormalizeCreationRoots(originals);
        var snapshot = new CreationSnapshot(roots);
        try
        {
            WalkCreationRoots(roots, (path, identity, directory) =>
            {
                if (directory) snapshot.AddDirectory(path, identity, strict: true);
                else
                {
                    snapshot.AddFile(path, identity);
                    string parent = Path.GetDirectoryName(path) ?? throw new IOException("Original parent is unavailable.");
                    using SafeFileHandle handle = MacSafeFileSystem.OpenDirectoryHandle(parent);
                    MacSafeFileSystem.RequirePathStillNamesHandle(handle, parent);
                    snapshot.AddDirectory(parent, MacSafeFileSystem.GetIdentity(handle), strict: false);
                }
            }, token);
            snapshot.RequireUnchanged(originals, token);
            return snapshot;
        }
        catch { snapshot.Dispose(); throw; }
    }

    private static string[] NormalizeCreationRoots(IReadOnlyList<string> originals)
    {
        ArgumentNullException.ThrowIfNull(originals);
        string[] all = originals.Select(path => Path.TrimEndingDirectorySeparator(Path.GetFullPath(path)))
            .Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        // ZPAQ also stores overlapping inputs once. Retain exactly one traversal
        // while preserving the same common naming anchor for the selected roots.
        var selectedDirectories = new HashSet<string>(StringComparer.Ordinal);
        var roots = new List<string>();
        foreach (string path in all)
        {
            bool covered = false;
            for (string? parent = Path.GetDirectoryName(path); parent is not null; parent = Path.GetDirectoryName(parent))
                if (selectedDirectories.Contains(parent)) { covered = true; break; }
            if (covered) continue;
            roots.Add(path);
            if (Directory.Exists(path)) selectedDirectories.Add(path);
        }
        return roots.ToArray();
    }

    private static void WalkCreationRoots(string[] roots, Action<string, MacFileIdentity, bool> visit, CancellationToken token)
    {
        var activeDirectories = new HashSet<(int, ulong)>();
        void WalkDirectory(SafeFileHandle handle, string path, MacFileIdentity expected)
        {
            token.ThrowIfCancellationRequested();
            MacFileIdentity before = MacSafeFileSystem.GetIdentity(handle);
            if (!before.SameObjectAndMetadata(expected) || (before.Mode & 0xF000) != 0x4000
                || !activeDirectories.Add((before.Device, before.Inode)))
                throw new IOException($"Original directory changed or contains a cycle: {path}");
            try
            {
                visit(path, before, true);
                MacSafeFileSystem.VisitDeletionEntriesNoFollow(handle, entry =>
                {
                    token.ThrowIfCancellationRequested();
                    using OperationMemoryBudget.HeavyLease pathMemory = OperationMemoryBudget.AcquireWorking(
                        checked(512 + 4L * (path.Length + entry.Name.Length + 1)));
                    string child = Path.Combine(path, entry.Name);
                    if ((entry.Identity.Mode & 0xF000) == 0x4000)
                    {
                        using SafeFileHandle sub = MacSafeFileSystem.OpenDirectoryHandleAt(handle, entry.Name);
                        WalkDirectory(sub, child, entry.Identity);
                    }
                    else if ((entry.Identity.Mode & 0xF000) == 0x8000 && entry.Identity.LinkCount == 1)
                    {
                        using FileStream file = MacSafeFileSystem.OpenReadAt(handle, entry.Name, requireSingleLink: true);
                        MacFileIdentity opened = MacSafeFileSystem.GetIdentity(file.SafeFileHandle);
                        if (!opened.SameObjectAndMetadata(entry.Identity))
                            throw new IOException($"Original file changed during inventory: {child}");
                        visit(child, opened, false);
                        if (!MacSafeFileSystem.GetIdentity(file.SafeFileHandle).SameObjectAndMetadata(opened))
                            throw new IOException($"Original file changed during inventory: {child}");
                    }
                    else throw new IOException($"Original inventory refuses a linked or special entry: {child}");
                    if (!MacSafeFileSystem.GetIdentityAt(handle, entry.Name).SameObjectAndMetadata(entry.Identity))
                        throw new IOException($"Original entry changed during inventory: {child}");
                });
                MacSafeFileSystem.RequirePathStillNamesHandle(handle, path);
                if (!MacSafeFileSystem.GetIdentity(handle).SameObjectAndMetadata(before))
                    throw new IOException($"Original directory topology changed during inventory: {path}");
            }
            finally { activeDirectories.Remove((before.Device, before.Inode)); }
        }
        foreach (string path in roots)
        {
            token.ThrowIfCancellationRequested();
            MacFileIdentity before = MacSafeFileSystem.GetPathIdentityNoFollow(path);
            if ((before.Mode & 0xF000) == 0x4000)
            {
                using SafeFileHandle directory = MacSafeFileSystem.OpenDirectoryHandle(path);
                WalkDirectory(directory, path, before);
            }
            else if ((before.Mode & 0xF000) == 0x8000 && before.LinkCount == 1)
            {
                using FileStream file = MacSafeFileSystem.OpenReadNoSymlinks(path, requireSingleLink: true);
                MacFileIdentity opened = MacSafeFileSystem.GetIdentity(file.SafeFileHandle);
                if (!opened.SameObjectAndMetadata(before)) throw new IOException("Original input changed before inventory.");
                visit(path, opened, false);
                MacSafeFileSystem.RequirePathStillNamesHandle(file.SafeFileHandle, path);
                if (!MacSafeFileSystem.GetIdentity(file.SafeFileHandle).SameObjectAndMetadata(opened))
                    throw new IOException("Original input changed during inventory.");
            }
            else throw new IOException($"Original inventory refuses a linked or special input: {path}");
        }
    }
}

internal static partial class MacSafeFileSystem
{
    // Stream one descriptor-bound entry at a time: deletion inventories must
    // not first allocate an unchecked complete directory listing.
    internal static void VisitDeletionEntriesNoFollow(SafeFileHandle handle, Action<MacDirectoryEntry> visit)
    {
        bool added = false;
        try
        {
            handle.DangerousAddRef(ref added);
            int duplicate = Dup(checked((int)handle.DangerousGetHandle()));
            if (duplicate < 0) throw new Win32Exception(Marshal.GetLastPInvokeError());
            nint directory = FdOpenDir(duplicate);
            if (directory == 0) { CloseDescriptor(duplicate); throw new Win32Exception(Marshal.GetLastPInvokeError()); }
            RewindDir(directory);
            try
            {
                while (true)
                {
                    Marshal.SetLastPInvokeError(0);
                    nint next = ReadDir(directory);
                    if (next == 0)
                    {
                        int error = Marshal.GetLastPInvokeError();
                        if (error != 0) throw new Win32Exception(error, "Original directory enumeration failed.");
                        break;
                    }
                    unsafe
                    {
                        DarwinDirent* entry = (DarwinDirent*)next;
                        using OperationMemoryBudget.HeavyLease nameMemory = OperationMemoryBudget.AcquireWorking(checked(1024 + 4L * entry->d_namlen));
                        string name = Marshal.PtrToStringUTF8((nint)entry->d_name, entry->d_namlen)
                            ?? throw new IOException("Invalid original directory entry name.");
                        if (name is not ("." or "..")) visit(new(name, GetIdentityAt(handle, name)));
                    }
                }
            }
            finally { CloseDir(directory); }
        }
        finally { if (added) handle.DangerousRelease(); }
    }
}
