using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace KalynaArchiver.Services;

/// <summary>
/// Proves that a Windows archive reproduces its inputs byte for byte before
/// moving the originals to a handle-bound quarantine and deleting them.
/// </summary>
internal sealed class WindowsOriginalDeletionService
{
    private const int CompareBufferBytes = 1024 * 1024;

    internal sealed record VerificationResult(
        bool Verified,
        int FilesCompared,
        long BytesCompared,
        string? Failure,
        OriginalSnapshot? Originals = null);

    internal readonly record struct OriginalFileState(
        long Length,
        long ModifiedUtcTicks,
        string Digest);

    internal sealed record OriginalSnapshot(
        IReadOnlyDictionary<string, OriginalFileState> Files);

    internal readonly record struct ArchiveIdentity(long Length, string Digest);

    internal static async Task<VerificationResult> VerifyExtractionAsync(
        IReadOnlyList<string> originals,
        string extractedRoot,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(originals);
        ArgumentException.ThrowIfNullOrWhiteSpace(extractedRoot);

        Dictionary<string, string> expected = new(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var entry in ZpaqService.BuildArchiveEntryMap(originals))
            {
                if (!expected.TryAdd(entry.Key, entry.Value))
                {
                    return new VerificationResult(
                        false,
                        0,
                        0,
                        $"The input contains archive entries that collide on Windows: {entry.Key}");
                }
            }
        }
        catch (Exception ex)
        {
            return new VerificationResult(false, 0, 0, $"Could not enumerate archive inputs: {ex.Message}");
        }

        if (expected.Count == 0)
        {
            return new VerificationResult(false, 0, 0, "No original files were found for comparison.");
        }

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var states = new Dictionary<string, OriginalFileState>(StringComparer.OrdinalIgnoreCase);
        int compared = 0;
        long bytes = 0;

        foreach (string extracted in ZpaqService.EnumerateDirectoryTreeNoFollowWindows(extractedRoot))
        {
            cancellationToken.ThrowIfCancellationRequested();
            string relative = Path.GetRelativePath(extractedRoot, extracted);
            if (!expected.TryGetValue(relative, out string? original))
            {
                return new VerificationResult(
                    false,
                    compared,
                    bytes,
                    $"The archive contains an unexpected file: {relative}");
            }

            progress?.Report(relative);
            (long length, string? digest) = await CompareAsync(original, extracted, cancellationToken)
                .ConfigureAwait(false);
            if (length < 0 || digest is null)
            {
                return new VerificationResult(
                    false,
                    compared,
                    bytes,
                    $"The byte-for-byte comparison failed: {relative}");
            }

            string fullOriginal = Path.GetFullPath(original);
            states[fullOriginal] = new OriginalFileState(
                length,
                File.GetLastWriteTimeUtc(fullOriginal).Ticks,
                digest);
            seen.Add(relative);
            compared++;
            bytes = checked(bytes + length);
        }

        if (seen.Count != expected.Count)
        {
            string missing = expected.Keys.First(key => !seen.Contains(key));
            return new VerificationResult(
                false,
                compared,
                bytes,
                $"The archive does not contain an original file: {missing}");
        }

        return new VerificationResult(true, compared, bytes, null, new OriginalSnapshot(states));
    }

    private static async Task<(long Length, string? Digest)> CompareAsync(
        string original,
        string extracted,
        CancellationToken cancellationToken)
    {
        using FileStream left = SecureFile.OpenReadNoReparse(
            original,
            FileShare.Read,
            bufferSize: CompareBufferBytes,
            requireSingleLink: true);
        using FileStream right = SecureFile.OpenReadNoReparse(
            extracted,
            FileShare.Read,
            bufferSize: CompareBufferBytes,
            requireSingleLink: true);
        if (left.Length != right.Length)
        {
            return (-1, null);
        }

        byte[] leftBuffer = new byte[CompareBufferBytes];
        byte[] rightBuffer = new byte[CompareBufferBytes];
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                int leftRead = await left.ReadAsync(leftBuffer, cancellationToken).ConfigureAwait(false);
                if (leftRead == 0)
                {
                    break;
                }

                await right.ReadExactlyAsync(
                    rightBuffer.AsMemory(0, leftRead),
                    cancellationToken).ConfigureAwait(false);
                if (!leftBuffer.AsSpan(0, leftRead).SequenceEqual(rightBuffer.AsSpan(0, leftRead)))
                {
                    return (-1, null);
                }

                digest.AppendData(leftBuffer.AsSpan(0, leftRead));
            }

            return (left.Length, Convert.ToHexString(digest.GetHashAndReset()));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(leftBuffer);
            CryptographicOperations.ZeroMemory(rightBuffer);
        }
    }

    internal static ArchiveIdentity CaptureArchiveIdentity(string archivePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(archivePath);
        using FileStream stream = SecureFile.OpenReadNoReparse(
            archivePath,
            FileShare.Read,
            requireSingleLink: true);
        return new ArchiveIdentity(stream.Length, Convert.ToHexString(SHA512.HashData(stream)));
    }

    internal static IReadOnlyList<string> DeleteOriginals(
        IReadOnlyList<string> originals,
        string archivePath,
        ArchiveIdentity verified,
        OriginalSnapshot originalsVerified)
    {
        ArgumentNullException.ThrowIfNull(originals);
        ArgumentNullException.ThrowIfNull(originalsVerified);
        ArgumentException.ThrowIfNullOrWhiteSpace(archivePath);

        FileStream archiveStream;
        WindowsFileIdentity archiveIdentity;
        try
        {
            archiveStream = SecureFile.OpenReadNoReparse(
                archivePath,
                FileShare.Read,
                requireSingleLink: true);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return [$"{Path.GetFileName(archivePath)}: {exception.Message}"];
        }

        using (archiveStream)
        {
            try
            {
                archiveIdentity = WindowsSafeFileSystem.GetIdentity(archiveStream.SafeFileHandle);
                byte[] digest = SHA512.HashData(archiveStream);
                if (archiveStream.Length != verified.Length
                    || !CryptographicOperations.FixedTimeEquals(
                        digest,
                        Convert.FromHexString(verified.Digest)))
                {
                    return ["The archive changed between verification and deletion; nothing was deleted."];
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                return [$"{Path.GetFileName(archivePath)}: {exception.Message}"];
            }

            string? drift = FindOriginalDrift(originals, originalsVerified);
            if (drift is not null)
            {
                return [drift];
            }

            return DeleteVerifiedFiles(
                originalsVerified,
                archivePath,
                archiveStream,
                archiveIdentity,
                verified);
        }
    }

    private static string? FindOriginalDrift(
        IReadOnlyList<string> originals,
        OriginalSnapshot verified)
    {
        var present = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string original in originals)
        {
            string full = Path.GetFullPath(original);
            if (File.Exists(full))
            {
                string? mismatch = DescribeFileDrift(full, verified);
                if (mismatch is not null)
                {
                    return mismatch;
                }

                present.Add(full);
                continue;
            }

            if (!Directory.Exists(full))
            {
                return $"The input no longer exists: {full}. Nothing was deleted.";
            }

            List<string> treeFiles;
            try
            {
                treeFiles = ZpaqService.EnumerateDirectoryTreeNoFollowWindows(full);
            }
            catch (Exception ex)
            {
                return $"Could not securely recheck input directory {full}: {ex.Message}. Nothing was deleted.";
            }

            foreach (string file in treeFiles)
            {
                string? mismatch = DescribeFileDrift(file, verified);
                if (mismatch is not null)
                {
                    return mismatch;
                }

                present.Add(Path.GetFullPath(file));
            }
        }

        if (present.Count != verified.Files.Count)
        {
            string missing = verified.Files.Keys.First(key => !present.Contains(key));
            return $"A verified original file is now missing: {missing}. Nothing was deleted.";
        }

        return null;
    }

    private static string? DescribeFileDrift(
        string path,
        OriginalSnapshot verified)
    {
        string full = Path.GetFullPath(path);
        if (!verified.Files.TryGetValue(full, out OriginalFileState expected))
        {
            return $"A new file appeared since verification: {full}. It is not in the archive. Nothing was deleted.";
        }

        try
        {
            using FileStream stream = SecureFile.OpenReadNoReparse(
                full,
                FileShare.Read,
                requireSingleLink: true);
            if (stream.Length != expected.Length)
            {
                return $"An original file changed since verification: {full}. Nothing was deleted.";
            }

            byte[] digest = SHA512.HashData(stream);
            bool same = CryptographicOperations.FixedTimeEquals(
                digest,
                Convert.FromHexString(expected.Digest));
            if (!same || File.GetLastWriteTimeUtc(full).Ticks != expected.ModifiedUtcTicks)
            {
                return $"An original file changed since verification: {full}. Nothing was deleted.";
            }

            return null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return $"An original file could not be rechecked before deletion: {full} ({exception.Message}). Nothing was deleted.";
        }
    }

    private static IReadOnlyList<string> DeleteVerifiedFiles(
        OriginalSnapshot verified,
        string archivePath,
        FileStream archiveStream,
        WindowsFileIdentity archiveIdentity,
        ArchiveIdentity verifiedArchive)
    {
        var failures = new List<string>();
        var quarantined = new List<QuarantinedItem>();
        var parentContexts = new Dictionary<string, QuarantineParentContext>(StringComparer.OrdinalIgnoreCase);

        try
        {
            foreach (string path in verified.Files.Keys)
            {
                string fullPath = Path.GetFullPath(path);
                string? parentDirectory = Path.GetDirectoryName(fullPath);
                if (string.IsNullOrWhiteSpace(parentDirectory))
                {
                    throw new DirectoryNotFoundException($"Could not find the parent directory for {fullPath}.");
                }

                string canonicalParent = Path.TrimEndingDirectorySeparator(Path.GetFullPath(parentDirectory));
                if (!parentContexts.TryGetValue(canonicalParent, out QuarantineParentContext? context))
                {
                    context = CreateQuarantineContext(canonicalParent);
                    parentContexts.Add(canonicalParent, context);
                }

                context.RequireParent();
                string fileName = Path.GetFileName(fullPath);
                SafeFileHandle? sourceHandle = null;
                try
                {
                    sourceHandle = WindowsSafeFileSystem.OpenRegularFileForInspection(
                        fullPath,
                        allowWriters: false,
                        denyRename: true,
                        requestDeleteAccess: true,
                        requestReadAccess: true);
                    WindowsFileIdentity sourceIdentity = WindowsSafeFileSystem.GetIdentity(sourceHandle);

                    // The macOS side re-reads the source through the bound
                    // descriptor before it moves anything, and only then
                    // renames. Doing it in that order means a file that no
                    // longer matches what was verified is never moved out of
                    // its directory in the first place, so there is nothing to
                    // roll back for it. Windows now does the same; the handle
                    // above already denies writers and renames, so this reads
                    // exactly the object that is about to be quarantined.
                    RequireBoundOriginalMatches(
                        sourceHandle,
                        fullPath,
                        verified.Files[fullPath]);

                    WindowsSafeFileSystem.RenameBoundObject(
                        sourceHandle,
                        context.QuarantineDirectoryHandle,
                        fileName,
                        replaceExisting: false);

                    // Register immediately after the successful move so every
                    // moved object is included in rollback even if validation fails.
                    var item = new QuarantinedItem(
                        fullPath,
                        fileName,
                        context,
                        sourceIdentity,
                        sourceHandle);
                    quarantined.Add(item);
                    sourceHandle = null;
                    WindowsSafeFileSystem.RequireSameObject(
                        item.ObjectHandle,
                        item.Identity,
                        item.QuarantinePath,
                        directory: false);
                }
                finally
                {
                    sourceHandle?.Dispose();
                }
            }

            foreach (QuarantinedItem item in quarantined)
            {
                OriginalFileState expected = verified.Files[item.OriginalPath];
                WindowsSafeFileSystem.RequireSameObject(
                    item.ObjectHandle,
                    item.Identity,
                    item.QuarantinePath,
                    directory: false);
                RequireBoundOriginalMatches(item.ObjectHandle, item.OriginalPath, expected);
                item.ParentContext.RequireQuarantineEntry(item);
            }

            // The archive handle has denied writes and deletion since the
            // beginning of this method; validate its object and bytes again at
            // the boundary immediately before the irreversible commit.
            WindowsSafeFileSystem.RequireSameObject(
                archiveStream.SafeFileHandle,
                archiveIdentity,
                archivePath,
                directory: false);
            archiveStream.Position = 0;
            byte[] finalDigest = SHA512.HashData(archiveStream);
            if (archiveStream.Length != verifiedArchive.Length
                || !CryptographicOperations.FixedTimeEquals(
                    finalDigest,
                    Convert.FromHexString(verifiedArchive.Digest)))
            {
                throw new InvalidOperationException("The archive changed before the final deletion commit.");
            }
        }
        catch (Exception ex)
        {
            var rollbackErrors = new List<string>();
            foreach (QuarantinedItem item in quarantined.AsEnumerable().Reverse())
            {
                if (item.Restored)
                {
                    continue;
                }

                try
                {
                    item.ParentContext.RequireParent();
                    WindowsSafeFileSystem.RequireSameObject(
                        item.ObjectHandle,
                        item.Identity,
                        item.QuarantinePath,
                        directory: false);
                    WindowsSafeFileSystem.RenameBoundObject(
                        item.ObjectHandle,
                        item.ParentContext.ParentHandle,
                        item.FileName,
                        replaceExisting: false);
                    item.Restored = true;
                    WindowsSafeFileSystem.RequireSameObject(
                        item.ObjectHandle,
                        item.Identity,
                        item.OriginalPath,
                        directory: false);
                }
                catch (Exception rollbackError)
                {
                    rollbackErrors.Add(
                        $"Could not restore {item.OriginalPath} from quarantine: {rollbackError.Message}. "
                        + $"The original remains protected at {item.QuarantinePath}.");
                }
            }

            failures.Add($"Deletion was aborted before commit: {DescribeException(ex)}");
            failures.AddRange(rollbackErrors);
        }

        if (failures.Count == 0)
        {
            foreach (QuarantinedItem item in quarantined)
            {
                try
                {
                    item.ParentContext.RequireQuarantineEntry(item);
                    WindowsSafeFileSystem.MarkForDeletion(item.ObjectHandle);
                }
                catch (Exception ex)
                {
                    failures.Add(
                        $"Could not delete the quarantined original {item.OriginalPath}: {ex.Message}.");
                }
            }
        }

        foreach (QuarantinedItem item in quarantined)
        {
            item.Dispose();
        }

        foreach (QuarantineParentContext context in parentContexts.Values)
        {
            context.DeleteIfEmpty();
            context.Dispose();
        }

        return failures;
    }

    private static QuarantineParentContext CreateQuarantineContext(string parentDirectory)
    {
        SafeFileHandle parentHandle = WindowsSafeFileSystem.OpenDirectoryBound(
            parentDirectory,
            denyRename: true,
            requestDeleteAccess: true);
        WindowsFileIdentity parentIdentity = WindowsSafeFileSystem.GetIdentity(parentHandle);
        string name = ".keepvault_quarantine_" + Guid.NewGuid().ToString("N");
        string path = Path.Combine(parentDirectory, name);
        SafeFileHandle? quarantineHandle = null;
        try
        {
            if (File.Exists(path) || Directory.Exists(path))
            {
                throw new IOException("The random quarantine directory name already exists.");
            }

            CreatePrivateDirectory(path);
            quarantineHandle = WindowsSafeFileSystem.OpenDirectoryBound(
                path,
                denyRename: true,
                requestDeleteAccess: true);
            return new QuarantineParentContext(
                parentDirectory,
                path,
                parentHandle,
                parentIdentity,
                quarantineHandle,
                WindowsSafeFileSystem.GetIdentity(quarantineHandle));
        }
        catch
        {
            // If binding succeeded, cleanup remains handle-bound. If binding
            // failed, leave the random directory in place rather than deleting
            // a pathname that may now name another object.
            quarantineHandle?.Dispose();
            parentHandle.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Creates the quarantine directory readable and writable by this user
    /// only.
    /// </summary>
    /// <remarks>
    /// macOS creates the same directory with <c>mkdirat</c> and mode 0700, so
    /// the verified originals are never briefly parked somewhere the parent
    /// folder's permissions would have opened up. A plain
    /// <c>Directory.CreateDirectory</c> inherits whatever the parent grants,
    /// which for a shared or published folder is not the same thing. The
    /// discretionary list below is protected, so no inherited entry survives,
    /// and it names the current user, SYSTEM and the local administrators, who
    /// can take ownership of any file on the volume regardless.
    /// </remarks>
    private static void CreatePrivateDirectory(string path)
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        SecurityIdentifier owner = identity.User
            ?? throw new IOException("The current Windows identity has no user SID.");

        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(owner);
        foreach (SecurityIdentifier trustee in new[]
        {
            owner,
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
        })
        {
            security.AddAccessRule(new FileSystemAccessRule(
                trustee,
                FileSystemRights.FullControl,
                InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        }

        new DirectoryInfo(path).Create(security);
    }

    private static string DescribeException(Exception exception) =>
        exception.InnerException is null
            ? exception.Message
            : $"{exception.Message} ({exception.InnerException.Message})";

    /// <summary>
    /// Re-reads a handle-bound original and requires it to be exactly what the
    /// verification pass recorded.
    /// </summary>
    /// <remarks>
    /// The counterpart of <c>MacOriginalDeletionService.RequireBoundOriginalMatches</c>.
    /// Length and digest are compared, and the digest comparison runs in
    /// constant time even though nothing secret is involved, because the same
    /// helper is used on the pre-move and the post-move check and only one of
    /// them should ever differ in cost from the other.
    /// </remarks>
    private static void RequireBoundOriginalMatches(
        SafeFileHandle handle,
        string originalPath,
        OriginalFileState expected)
    {
        (long length, string digest) = HashBoundFile(handle);
        if (length != expected.Length)
        {
            throw new InvalidDataException(
                $"The bound original differs in length from the verified original: {originalPath}");
        }

        if (!CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(digest),
                Convert.FromHexString(expected.Digest)))
        {
            throw new InvalidDataException(
                $"The bound original differs in content from the verified original: {originalPath}");
        }
    }

    private static (long Length, string Digest) HashBoundFile(SafeFileHandle handle)
    {
        long length = WindowsSafeFileSystem.GetLength(handle);
        byte[] buffer = new byte[CompareBufferBytes];
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        try
        {
            long offset = 0;
            while (offset < length)
            {
                int requested = (int)Math.Min(buffer.Length, length - offset);
                int read = RandomAccess.Read(handle, buffer.AsSpan(0, requested), offset);
                if (read != requested)
                {
                    throw new IOException("The quarantined file ended while it was being checked.");
                }

                digest.AppendData(buffer.AsSpan(0, read));
                offset = checked(offset + read);
            }

            return (length, Convert.ToHexString(digest.GetHashAndReset()));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    private sealed class QuarantineParentContext : IDisposable
    {
        internal string ParentPath { get; }
        internal string QuarantineDirectoryPath { get; }
        internal SafeFileHandle ParentHandle { get; }
        internal WindowsFileIdentity ParentIdentity { get; }
        internal SafeFileHandle QuarantineDirectoryHandle { get; }
        internal WindowsFileIdentity QuarantineDirectoryIdentity { get; }

        internal QuarantineParentContext(
            string parentPath,
            string quarantineDirectoryPath,
            SafeFileHandle parentHandle,
            WindowsFileIdentity parentIdentity,
            SafeFileHandle quarantineDirectoryHandle,
            WindowsFileIdentity quarantineDirectoryIdentity)
        {
            ParentPath = parentPath;
            QuarantineDirectoryPath = quarantineDirectoryPath;
            ParentHandle = parentHandle;
            ParentIdentity = parentIdentity;
            QuarantineDirectoryHandle = quarantineDirectoryHandle;
            QuarantineDirectoryIdentity = quarantineDirectoryIdentity;
        }

        internal void RequireParent() => WindowsSafeFileSystem.RequireSameObject(
            ParentHandle,
            ParentIdentity,
            ParentPath,
            directory: true);

        internal void RequireQuarantine() => WindowsSafeFileSystem.RequireSameObject(
            QuarantineDirectoryHandle,
            QuarantineDirectoryIdentity,
            QuarantineDirectoryPath,
            directory: true);

        internal void RequireQuarantineEntry(QuarantinedItem item)
        {
            RequireQuarantine();
            WindowsSafeFileSystem.RequireSameObject(
                item.ObjectHandle,
                item.Identity,
                item.QuarantinePath,
                directory: false);
        }

        internal void DeleteIfEmpty()
        {
            try
            {
                RequireParent();
                RequireQuarantine();
                if (!Directory.EnumerateFileSystemEntries(QuarantineDirectoryPath).Any())
                {
                    WindowsSafeFileSystem.MarkForDeletion(QuarantineDirectoryHandle);
                }
            }
            catch
            {
                // A non-empty or otherwise changed quarantine is deliberately
                // preserved for the user instead of being path-deleted.
            }
        }

        public void Dispose()
        {
            QuarantineDirectoryHandle.Dispose();
            ParentHandle.Dispose();
        }
    }

    private sealed class QuarantinedItem : IDisposable
    {
        internal string OriginalPath { get; }
        internal string FileName { get; }
        internal QuarantineParentContext ParentContext { get; }
        internal WindowsFileIdentity Identity { get; }
        internal SafeFileHandle ObjectHandle { get; }
        internal string QuarantinePath => Path.Combine(ParentContext.QuarantineDirectoryPath, FileName);
        internal bool Restored { get; set; }

        internal QuarantinedItem(
            string originalPath,
            string fileName,
            QuarantineParentContext parentContext,
            WindowsFileIdentity identity,
            SafeFileHandle objectHandle)
        {
            OriginalPath = originalPath;
            FileName = fileName;
            ParentContext = parentContext;
            Identity = identity;
            ObjectHandle = objectHandle;
        }

        public void Dispose() => ObjectHandle.Dispose();
    }
}
