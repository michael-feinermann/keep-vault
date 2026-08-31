using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace KalynaArchiver.Services;

public sealed partial class ZpaqService
{
    private const int StreamMethodBlockSize = 4;
    private const int MaxCapturedProcessTextCharacters = 1024 * 1024;
    private const int MaxProcessLineCharacters = 16 * 1024;
    internal const int MaxProgressLinesPerStream = 2_000;
    private const int MaxProgressCharactersPerStream = 256 * 1024;
#if KEEPVAULT_MACOS
    private const StringComparison FileSystemPathComparison = StringComparison.Ordinal;
#else
    private const StringComparison FileSystemPathComparison = StringComparison.OrdinalIgnoreCase;
#endif
    private readonly string? _configuredPath;
    private readonly ArchiveIntegrityService _archiveIntegrity = new();

    public ZpaqService(string? configuredPath = null)
    {
        _configuredPath = configuredPath;
    }

#if KEEPVAULT_MACOS
    internal static void ValidatePortableInputTreeForTests(string root) =>
        MacInputSnapshot.ValidatePortableTree(root);

    internal static Action<string>? InputSnapshotHookBeforeSourceEntryOpenForTests { get; set; }
    internal static Action<string>? InputSnapshotHookAfterReadyForTests { get; set; }

    internal static IDisposable CaptureInputSnapshotForTests(
        string workingDirectory,
        IReadOnlyList<string> inputPaths,
        out string snapshotWorkingDirectory,
        out string[] snapshotPaths)
    {
        MacInputSnapshot snapshot = MacInputSnapshot.Create(workingDirectory, inputPaths);
        snapshotWorkingDirectory = snapshot.WorkingDirectory;
        snapshotPaths = snapshot.InputPaths;
        return snapshot;
    }
#else
    internal static IDisposable CaptureInputSnapshotForTests(
        string workingDirectory,
        IReadOnlyList<string> inputPaths,
        out string snapshotWorkingDirectory,
        out string[] snapshotPaths)
    {
        WindowsInputSnapshot snapshot = WindowsInputSnapshot.Create(workingDirectory, inputPaths);
        snapshotWorkingDirectory = snapshot.WorkingDirectory;
        snapshotPaths = snapshot.InputPaths;
        return snapshot;
    }

    /// <summary>
    /// Leases still held because their snapshot hard link could not be removed.
    /// Zero in normal operation; anything else means a cleanup failed and this
    /// process is holding the user's file open to keep it write-protected.
    /// </summary>
    internal static int RetainedInputSnapshotLeases => WindowsInputSnapshot.RetainedLeaseCount;
#endif

    public string? ResolveExecutable()
    {
        string baseDirectory = AppContext.BaseDirectory;
        string[] candidates =
        [
            _configuredPath ?? string.Empty,
#if KEEPVAULT_MACOS
            Path.Combine(baseDirectory, "Native", "zpaq"),
            Path.Combine(baseDirectory, "Resources", "Native", "zpaq"),
            Path.Combine(baseDirectory, "zpaq"),
#else
            Path.Combine(baseDirectory, "tools", "zpaq.exe"),
            Path.Combine(baseDirectory, "zpaq.exe"),
#endif
        ];

        foreach (string candidate in candidates)
        {
            if (!string.IsNullOrWhiteSpace(candidate) && File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }

    public async Task<ProcessResult> AddAsync(
        string archivePath,
        IReadOnlyList<string> inputPaths,
        int compressionLevel,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(inputPaths);
        if (inputPaths.Count == 0)
        {
            throw new ArgumentException("Mindestens eine Eingabedatei oder ein Ordner ist erforderlich.", nameof(inputPaths));
        }

        ValidateCompressionLevel(compressionLevel);
        string[] normalizedInputs = NormalizeAndValidateInputPaths(inputPaths);
        string workingDirectory = GetArchiveWorkingDirectory(normalizedInputs);
        string fullArchivePath = Path.GetFullPath(archivePath);
        ValidateArchiveTarget(fullArchivePath, normalizedInputs);
        if (File.Exists(fullArchivePath) || Directory.Exists(fullArchivePath))
        {
            throw new IOException("The ZPAQ archive target already exists.");
        }

        string targetDirectory = Path.GetDirectoryName(fullArchivePath) ?? Environment.CurrentDirectory;
        if (!Directory.Exists(targetDirectory))
        {
            throw new DirectoryNotFoundException($"The ZPAQ archive target directory does not exist: {targetDirectory}");
        }

        string temporaryArchivePath = Path.Combine(
            targetDirectory,
            $".{Path.GetFileName(fullArchivePath)}.{Guid.NewGuid():N}.zpaq-part");
        string temporarySha3Path = ArchiveIntegrityService.GetSha3ManifestPath(temporaryArchivePath);
        string temporarySkeinPath = ArchiveIntegrityService.GetSkeinManifestPath(temporaryArchivePath);
        string finalSha3Path = ArchiveIntegrityService.GetSha3ManifestPath(fullArchivePath);
        string finalSkeinPath = ArchiveIntegrityService.GetSkeinManifestPath(fullArchivePath);
        BoundFileTransaction? archiveObject = null;
        BoundFileTransaction? sha3Object = null;
        BoundFileTransaction? skeinObject = null;
#if KEEPVAULT_MACOS
        using MacInputSnapshot inputSnapshot = MacInputSnapshot.Create(workingDirectory, normalizedInputs);
#else
        using WindowsInputSnapshot inputSnapshot = WindowsInputSnapshot.Create(workingDirectory, normalizedInputs);
#endif
        workingDirectory = inputSnapshot.WorkingDirectory;
        normalizedInputs = inputSnapshot.InputPaths;
        using TrustedNativeFileLease executable = AcquireExecutable();
        var arguments = new List<string> { "add", temporaryArchivePath };
        arguments.AddRange(normalizedInputs.Select(path => Path.GetRelativePath(workingDirectory, path)));
        arguments.Add($"-m{compressionLevel}");
        try
        {
            inputSnapshot.RequireReadyForUse();
            ProcessResult result = await RunTextProcessAsync(executable.Path, arguments, workingDirectory, progress, cancellationToken).ConfigureAwait(false);
            inputSnapshot.RequireReadyForUse();
            if (!result.Succeeded)
            {
                return PreserveUnboundProducerOutput(result, temporaryArchivePath, progress);
            }

            // Bind the completed ZPAQ object before hashing it, then create both
            // manifests as held objects.  Thus no verify-close-reopen gap exists
            // anywhere in the three-file commit.
            archiveObject = BoundFileTransaction.OpenExistingForCommit(
                temporaryArchivePath,
                bufferSize: 1024 * 1024);
            byte[] sha3 = [];
            byte[] skein = [];
            try
            {
                archiveObject.Stream.Position = 0;
                (sha3, skein) = await IntegrityService
                    .HashStreamAsync(archiveObject.Stream, cancellationToken)
                    .ConfigureAwait(false);
                sha3Object = await ArchiveIntegrityService.CreateBoundManifestAsync(
                    temporarySha3Path,
                    sha3,
                    cancellationToken).ConfigureAwait(false);
                skeinObject = await ArchiveIntegrityService.CreateBoundManifestAsync(
                    temporarySkeinPath,
                    skein,
                    cancellationToken).ConfigureAwait(false);
                await ArchiveIntegrityService.VerifyBoundAsync(
                    archiveObject.Stream,
                    sha3Object.Stream,
                    skeinObject.Stream,
                    cancellationToken).ConfigureAwait(false);

                sha3Object.RenameTo(finalSha3Path, overwrite: false);
                skeinObject.RenameTo(finalSkeinPath, overwrite: false);
                archiveObject.RenameTo(fullArchivePath, overwrite: false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(sha3);
                CryptographicOperations.ZeroMemory(skein);
            }

            return result;
        }
        catch (Exception operationError)
        {
            var cleanupErrors = new List<Exception>();
            if (archiveObject is null)
            {
                try
                {
                    _ = ReportPreservedUnboundProducerOutput(temporaryArchivePath, progress);
                }
                catch (Exception reportError)
                {
                    cleanupErrors.Add(reportError);
                }
            }

            DeleteBoundObjectOrCollect(archiveObject, cleanupErrors);
            DeleteBoundObjectOrCollect(skeinObject, cleanupErrors);
            DeleteBoundObjectOrCollect(sha3Object, cleanupErrors);
            if (cleanupErrors.Count > 0)
            {
                throw new AggregateException(
                    "Plain ZPAQ installation failed and one or more exact transaction objects could not be cleaned up.",
                    [operationError, .. cleanupErrors]);
            }

            throw;
        }
        finally
        {
            archiveObject?.Dispose();
            skeinObject?.Dispose();
            sha3Object?.Dispose();
        }
    }

    private static void DeleteBoundObjectOrCollect(
        BoundFileTransaction? boundObject,
        List<Exception> cleanupErrors)
    {
        if (boundObject is null)
        {
            return;
        }

        try
        {
            boundObject.DeleteBound();
        }
        catch (Exception cleanupError)
        {
            cleanupErrors.Add(cleanupError);
        }
    }

    private static ProcessResult PreserveUnboundProducerOutput(
        ProcessResult result,
        string path,
        IProgress<string>? progress)
    {
        string? warning = ReportPreservedUnboundProducerOutput(path, progress);
        if (warning is null)
        {
            return result;
        }

        string separator = string.IsNullOrEmpty(result.StandardError) ? string.Empty : Environment.NewLine;
        return result with { StandardError = result.StandardError + separator + warning };
    }

    private static string? ReportPreservedUnboundProducerOutput(
        string path,
        IProgress<string>? progress)
    {
        if (!File.Exists(path) && !Directory.Exists(path))
        {
            return null;
        }

        // A failed native producer never handed us a file handle or identity.
        // Opening whatever currently occupies its random pathname and deleting
        // it would turn cleanup into a check/use race against an unrelated
        // object. Preserve and report the name; successful output is bound
        // before it can reach this point and is cleaned through that handle.
        string warning =
            "ZPAQ failed before ownership of its temporary output could be bound. "
            + $"The unverified path was preserved instead of path-deleted: {path}";
        progress?.Report(warning);
        return warning;
    }

    internal static ProcessResult PreserveUnboundProducerOutputForTests(
        ProcessResult result,
        string path) =>
        PreserveUnboundProducerOutput(result, path, progress: null);

    public async Task<ProcessResult> ExtractAsync(
        string archivePath,
        string outputFolder,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        using ArchiveIntegrityLease archive = await _archiveIntegrity.AcquireVerifiedAsync(archivePath, cancellationToken).ConfigureAwait(false);
        using TrustedNativeFileLease executable = AcquireExecutable();
#if KEEPVAULT_MACOS
        using var staging = new MacExtractionStaging(outputFolder);
        try
        {
            ProcessResult result = await RunTextProcessAsync(
                executable.Path,
                new[] { "extract", archive.Path },
                staging.StagingPath,
                progress,
                cancellationToken,
                monitorStagingDirectory: staging.StagingPath,
                macStaging: staging).ConfigureAwait(false);
            if (result.Succeeded)
            {
                ValidateExtractedDirectoryLimits(staging.StagingPath, staging);
                staging.Install(ValidateExtractedTreeMeasurement);
            }
            else
            {
                staging.Cleanup();
            }

            return result;
        }
        catch (Exception operationError)
        {
            try
            {
                staging.Cleanup();
            }
            catch (Exception cleanupError)
            {
                throw new IOException(
                    "macOS extraction failed and the exact bound staging tree could not be cleaned up.",
                    new AggregateException(operationError, cleanupError));
            }
            throw;
        }
#else
        using var target = new WindowsExtractionStaging(outputFolder);
        try
        {
            ProcessResult result = await RunTextProcessAsync(
                executable.Path,
                new[] { "extract", archive.Path },
                target.StagingPath,
                progress,
                cancellationToken,
                monitorStagingDirectory: target.StagingPath,
                windowsStaging: target).ConfigureAwait(false);
            if (result.Succeeded)
            {
                ValidateExtractedDirectoryLimits(target.StagingPath, target);
                target.Install();
            }
            else
            {
                target.Cleanup();
            }

            return result;
        }
        catch (Exception operationError)
        {
            try
            {
                target.Cleanup();
            }
            catch (Exception cleanupError)
            {
                throw new IOException(
                    "Windows extraction failed and the exact bound staging directory could not be cleaned up.",
                    new AggregateException(operationError, cleanupError));
            }

            throw;
        }
#endif
    }

    public async Task<ProcessResult> ListAsync(
        string archivePath,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        using ArchiveIntegrityLease archive = await _archiveIntegrity.AcquireVerifiedAsync(archivePath, cancellationToken).ConfigureAwait(false);
        using TrustedNativeFileLease executable = AcquireExecutable();
        return await RunTextProcessAsync(executable.Path, new[] { "list", archive.Path }, Environment.CurrentDirectory, progress, cancellationToken).ConfigureAwait(false);
    }

    public async Task<ProcessResult> AddStreamingAsync(
        IReadOnlyList<string> inputPaths,
        int compressionLevel,
        Func<Stream, CancellationToken, Task> consumeArchive,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(inputPaths);
        ArgumentNullException.ThrowIfNull(consumeArchive);
        if (inputPaths.Count == 0)
        {
            throw new ArgumentException("Mindestens eine Eingabedatei oder ein Ordner ist erforderlich.", nameof(inputPaths));
        }

        ValidateCompressionLevel(compressionLevel);
        string[] normalizedInputs = NormalizeAndValidateInputPaths(inputPaths);
        string workingDirectory = GetArchiveWorkingDirectory(normalizedInputs);
#if KEEPVAULT_MACOS
        using MacInputSnapshot inputSnapshot = MacInputSnapshot.Create(workingDirectory, normalizedInputs);
#else
        using WindowsInputSnapshot inputSnapshot = WindowsInputSnapshot.Create(workingDirectory, normalizedInputs);
#endif
        workingDirectory = inputSnapshot.WorkingDirectory;
        normalizedInputs = inputSnapshot.InputPaths;
        using TrustedNativeFileLease executable = AcquireExecutable();
        var arguments = new List<string> { "--pipe", "add", "-" };
        arguments.AddRange(normalizedInputs.Select(path => Path.GetRelativePath(workingDirectory, path)));
        arguments.Add("-method");
        arguments.Add(GetStreamingMethod(compressionLevel));
        inputSnapshot.RequireReadyForUse();
        ProcessResult result = await RunStdoutPipeAsync(
            executable.Path,
            arguments,
            workingDirectory,
            consumeArchive,
            progress,
            cancellationToken).ConfigureAwait(false);
        inputSnapshot.RequireReadyForUse();
        return result;
    }

    public async Task<ProcessResult> ExtractStreamingAsync(
        Func<Stream, CancellationToken, Task> writeArchive,
        string outputFolder,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(writeArchive);
        using TrustedNativeFileLease executable = AcquireExecutable();
#if KEEPVAULT_MACOS
        using var staging = new MacExtractionStaging(outputFolder);
        try
        {
            ProcessResult result = await RunStdinPipeAsync(
                executable.Path,
                new[] { "--pipe", "extract", "-" },
                staging.StagingPath,
                writeArchive,
                progress,
                cancellationToken,
                monitorStagingDirectory: staging.StagingPath,
                macStaging: staging).ConfigureAwait(false);
            if (result.Succeeded)
            {
                ValidateExtractedDirectoryLimits(staging.StagingPath, staging);
                staging.Install(ValidateExtractedTreeMeasurement);
            }
            else
            {
                staging.Cleanup();
            }

            return result;
        }
        catch (Exception operationError)
        {
            try
            {
                staging.Cleanup();
            }
            catch (Exception cleanupError)
            {
                throw new IOException(
                    "macOS streaming extraction failed and the exact bound staging tree could not be cleaned up.",
                    new AggregateException(operationError, cleanupError));
            }
            throw;
        }
#else
        using var target = new WindowsExtractionStaging(outputFolder);
        try
        {
            ProcessResult result = await RunStdinPipeAsync(
                executable.Path,
                new[] { "--pipe", "extract", "-" },
                target.StagingPath,
                writeArchive,
                progress,
                cancellationToken,
                monitorStagingDirectory: target.StagingPath,
                windowsStaging: target).ConfigureAwait(false);
            if (result.Succeeded)
            {
                ValidateExtractedDirectoryLimits(target.StagingPath, target);
                target.Install();
            }
            else
            {
                target.Cleanup();
            }

            return result;
        }
        catch (Exception operationError)
        {
            try
            {
                target.Cleanup();
            }
            catch (Exception cleanupError)
            {
                throw new IOException(
                    "Windows streaming extraction failed and the exact bound staging directory could not be cleaned up.",
                    new AggregateException(operationError, cleanupError));
            }

            throw;
        }
#endif
    }

    public async Task<ProcessResult> ListStreamingAsync(
        Func<Stream, CancellationToken, Task> writeArchive,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(writeArchive);
        using TrustedNativeFileLease executable = AcquireExecutable();
        return await RunStdinPipeAsync(executable.Path, new[] { "--pipe", "list", "-" }, Environment.CurrentDirectory, writeArchive, progress, cancellationToken).ConfigureAwait(false);
    }

    private TrustedNativeFileLease AcquireExecutable()
    {
        string executable = ResolveExecutable()
            ?? throw new FileNotFoundException("Die fest eingebundene ZPAQ-Komponente wurde nicht gefunden.");
        return NativeToolIntegrity.AcquireTrustedFile(executable);
    }

    public static Dictionary<string, string> BuildArchiveEntryMap(IReadOnlyList<string> inputPaths)
    {
        ArgumentNullException.ThrowIfNull(inputPaths);
        if (inputPaths.Count == 0)
        {
            return new Dictionary<string, string>(StringComparer.Ordinal);
        }

        string[] normalized = NormalizeAndValidateInputPaths(inputPaths);
        string workingDirectory = GetArchiveWorkingDirectory(normalized);
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string full in normalized)
        {
            if (File.Exists(full))
            {
#if KEEPVAULT_MACOS
                using (var _ = MacSafeFileSystem.OpenReadNoSymlinks(full)) { }
#else
                if (new FileInfo(full).LinkTarget is not null)
                {
                    throw new IOException($"Die Eingabe enthält einen symbolischen Link: {full}");
                }
#endif
                string rel = Path.GetRelativePath(workingDirectory, full);
                map[rel] = full;
            }
            else if (Directory.Exists(full))
            {
#if KEEPVAULT_MACOS
                var files = MacSafeFileSystem.EnumerateDirectoryTreeNoFollow(full);
                foreach (var (filePath, _) in files)
                {
                    string rel = Path.GetRelativePath(workingDirectory, filePath);
                    map[rel] = filePath;
                }
#else
                var files = EnumerateDirectoryTreeNoFollowWindows(full);
                foreach (string filePath in files)
                {
                    string rel = Path.GetRelativePath(workingDirectory, filePath);
                    map[rel] = filePath;
                }
#endif
            }
        }

        return map;
    }

    internal static List<string> EnumerateDirectoryTreeNoFollowWindows(string rootDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootDirectory);
        string fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(rootDirectory));
        if (!Directory.Exists(fullRoot))
        {
            throw new DirectoryNotFoundException($"Directory not found: {fullRoot}");
        }

        FileAttributes rootAttr = File.GetAttributes(fullRoot);
        if ((rootAttr & FileAttributes.ReparsePoint) != 0 || new DirectoryInfo(fullRoot).LinkTarget is not null)
        {
            throw new IOException($"Die Eingabe enthält einen symbolischen Link oder Reparse Point: {fullRoot}");
        }

        var results = new List<string>();
        var pending = new Stack<string>();
        pending.Push(fullRoot);

        while (pending.Count > 0)
        {
            string current = pending.Pop();
            foreach (string entry in Directory.EnumerateFileSystemEntries(current))
            {
                FileAttributes attr = File.GetAttributes(entry);
                if ((attr & FileAttributes.ReparsePoint) != 0 || new FileInfo(entry).LinkTarget is not null || new DirectoryInfo(entry).LinkTarget is not null)
                {
                    throw new IOException($"Die Eingabe enthält einen symbolischen Link oder Reparse Point: {entry}");
                }

                if ((attr & FileAttributes.Directory) != 0)
                {
                    pending.Push(entry);
                }
                else
                {
                    results.Add(entry);
                }
            }
        }

        return results;
    }

    private static string GetArchiveWorkingDirectory(IEnumerable<string> inputPaths)
    {
        string[] anchors = inputPaths
            .Select(path =>
            {
                string fullPath = Path.GetFullPath(path);
                return Directory.Exists(fullPath)
                    ? Directory.GetParent(fullPath)?.FullName ?? fullPath
                    : Path.GetDirectoryName(fullPath) ?? Environment.CurrentDirectory;
            })
            .ToArray();

        if (anchors.Length == 0)
        {
            return Environment.CurrentDirectory;
        }

        string root = Path.GetPathRoot(anchors[0]) ?? string.Empty;
        if (anchors.Any(anchor => !string.Equals(Path.GetPathRoot(anchor), root, FileSystemPathComparison)))
        {
            throw new ArgumentException(
                "All ZPAQ inputs must be located on the same volume so archive entry names remain relative.",
                nameof(inputPaths));
        }

        string[] firstParts = anchors[0].TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            .Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        int commonLength = firstParts.Length;

        foreach (string anchor in anchors.Skip(1))
        {
            string[] parts = anchor.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                .Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            commonLength = Math.Min(commonLength, parts.Length);
            for (int i = 0; i < commonLength; i++)
            {
                if (!string.Equals(firstParts[i], parts[i], FileSystemPathComparison))
                {
                    commonLength = i;
                    break;
                }
            }
        }

        string common = string.Join(Path.DirectorySeparatorChar, firstParts.Take(commonLength));
        if (commonLength <= 1 && !string.IsNullOrWhiteSpace(root))
        {
            return root;
        }

        return string.IsNullOrWhiteSpace(common) ? root : common;
    }

    private static string[] NormalizeAndValidateInputPaths(IReadOnlyList<string> inputPaths)
    {
        var normalized = new string[inputPaths.Count];
        for (int index = 0; index < inputPaths.Count; index++)
        {
            string path = inputPaths[index];
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentException("ZPAQ input paths must not be empty.", nameof(inputPaths));
            }

            string fullPath = Path.GetFullPath(path);
            if (!File.Exists(fullPath) && !Directory.Exists(fullPath))
            {
                throw new FileNotFoundException("ZPAQ input does not exist.", fullPath);
            }

            // A directory chosen through the folder picker arrives as
            // "/path/to/folder/". Left in place, the trailing separator makes
            // the snapshot's own parent directory equal to the destination it
            // is about to check for collisions, and archiving a folder fails
            // outright. Canonicalise it once, here, so nothing downstream has
            // to know about it. A volume root keeps its separator.
            normalized[index] = Path.TrimEndingDirectorySeparator(fullPath);
        }

        return normalized;
    }

    private static void ValidateArchiveTarget(string archivePath, IReadOnlyList<string> inputPaths)
    {
        if (Directory.Exists(archivePath))
        {
            throw new ArgumentException("The ZPAQ archive target must be a file path.", nameof(archivePath));
        }

        foreach (string inputPath in inputPaths)
        {
            if (PathsEqual(archivePath, inputPath))
            {
                throw new ArgumentException("The ZPAQ archive target must differ from every input path.", nameof(archivePath));
            }

            if (Directory.Exists(inputPath) && IsPathWithinDirectory(archivePath, inputPath))
            {
                throw new ArgumentException("The ZPAQ archive target must not be located inside an input directory.", nameof(archivePath));
            }
        }
    }

    private static bool IsPathWithinDirectory(string candidatePath, string directoryPath)
    {
        string candidate = Path.GetFullPath(candidatePath);
        string directory = Path.GetFullPath(directoryPath)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        string prefix = directory.EndsWith(Path.DirectorySeparatorChar)
            ? directory
            : directory + Path.DirectorySeparatorChar;
        return candidate.StartsWith(prefix, FileSystemPathComparison);
    }

    private static bool PathsEqual(string first, string second)
    {
        return string.Equals(Path.GetFullPath(first), Path.GetFullPath(second), FileSystemPathComparison);
    }

    public const long DefaultMaxExtractedBytes = 500L * 1024 * 1024 * 1024; // 500 GiB
    public const long DefaultMaxSingleFileBytes = 500L * 1024 * 1024 * 1024; // 500 GiB
    public const int DefaultMaxExtractedFiles = 500_000;
    public const long DefaultMinFreeDiskSpaceBytes = 256L * 1024 * 1024; // 256 MiB

    internal static long MaxExtractedBytesOverride = -1;
    internal static long MaxSingleFileBytesOverride = -1;
    internal static int MaxExtractedFilesOverride = -1;
    internal static long MinFreeDiskSpaceBytesOverride = -1;

    private static void ValidateExtractedTreeMeasurement(DirectoryTreeMeasurement measurement)
    {
        long maxBytes = MaxExtractedBytesOverride > 0 ? MaxExtractedBytesOverride : DefaultMaxExtractedBytes;
        long maxSingleBytes = MaxSingleFileBytesOverride > 0 ? MaxSingleFileBytesOverride : DefaultMaxSingleFileBytes;
        int maxFiles = MaxExtractedFilesOverride > 0 ? MaxExtractedFilesOverride : DefaultMaxExtractedFiles;

        if (measurement.MaxFileBytes > maxSingleBytes)
        {
            throw new InvalidDataException($"ZPAQ-Extraktionsgrenze für Einzeldateigröße überschritten ({maxSingleBytes} Bytes). Mögliche Decompression-Bomb abgelehnt.");
        }

        if (measurement.FileCount > maxFiles)
        {
            throw new InvalidDataException($"ZPAQ-Extraktionsgrenze für Dateianzahl überschritten ({maxFiles}). Mögliche Decompression-Bomb abgelehnt.");
        }

        if (measurement.TotalBytes > maxBytes)
        {
            throw new InvalidDataException($"ZPAQ-Extraktionsgrenze für Gesamtgröße überschritten ({maxBytes} Bytes). Mögliche Decompression-Bomb abgelehnt.");
        }
    }

    internal static void ValidateExtractedDirectoryLimits(
        string stagingDirectory
#if KEEPVAULT_MACOS
        , MacExtractionStaging? macStaging = null
#else
        , WindowsExtractionStaging? windowsStaging = null
#endif
    )
    {
#if KEEPVAULT_MACOS
        if (macStaging is null)
        {
            throw new ArgumentNullException(nameof(macStaging), "macOS extraction limits require the descriptor-bound staging object.");
        }
#else
        if (!Directory.Exists(stagingDirectory) && windowsStaging is null)
        {
            return;
        }
#endif

        long minFreeSpace = MinFreeDiskSpaceBytesOverride > 0 ? MinFreeDiskSpaceBytesOverride : DefaultMinFreeDiskSpaceBytes;

#if KEEPVAULT_MACOS
        DirectoryTreeMeasurement measurement = macStaging.MeasureTree(allowWriters: false);
        ValidateExtractedTreeMeasurement(measurement);

        long freeSpace = macStaging.GetFreeDiskSpaceBytes();
        if (freeSpace < 0 || freeSpace < minFreeSpace)
        {
            throw new IOException($"ZPAQ-Extraktion abgebrochen: Unzureichender freier Speicherplatz auf dem Ziellaufwerk ({freeSpace} Bytes verbleibend).");
        }
#else
        DirectoryTreeMeasurement measurement = windowsStaging?.MeasureTree(allowWriters: false)
            ?? WindowsExtractionStaging.MeasureTreeNoFollow(stagingDirectory, allowWriters: false);
        ValidateExtractedTreeMeasurement(measurement);
#endif
    }

#if !KEEPVAULT_MACOS
    /// <summary>
    /// Walks the staged extraction tree one level at a time and refuses any
    /// reparse point, without ever descending through one.
    /// </summary>
    private static void RequireNoReparsePointsWindows(string stagingDirectory)
    {
        var pending = new Stack<string>();
        pending.Push(Path.TrimEndingDirectorySeparator(Path.GetFullPath(stagingDirectory)));
        while (pending.Count > 0)
        {
            string current = pending.Pop();
            foreach (string entry in Directory.EnumerateFileSystemEntries(current))
            {
                FileAttributes attributes = File.GetAttributes(entry);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                {
                    throw new InvalidDataException(
                        $"Das entpackte Verzeichnis enthält einen Reparse Point, den ZPAQ nicht erzeugt haben kann: {entry}");
                }

                if ((attributes & FileAttributes.Directory) != 0)
                {
                    pending.Push(entry);
                }
            }
        }
    }

#endif
    private static async Task MonitorExtractionLimitsAsync(
        string stagingDirectory,
        Process process,
        CancellationTokenSource linkedCts,
        CancellationToken cancellationToken
#if KEEPVAULT_MACOS
        , MacExtractionStaging? macStaging = null
#else
        , WindowsExtractionStaging? windowsStaging = null
#endif
    )
    {
#if KEEPVAULT_MACOS
        ArgumentNullException.ThrowIfNull(macStaging);
#endif
        long minFreeSpace = MinFreeDiskSpaceBytesOverride > 0 ? MinFreeDiskSpaceBytesOverride : DefaultMinFreeDiskSpaceBytes;

        Exception? limitViolation = null;
        int consecutiveErrors = 0;
        const int maxConsecutiveTransientErrors = 3;
        object checkLock = new object();

        void CheckLimits()
        {
            bool hasExited;
            try
            {
                hasExited = process.HasExited;
            }
            catch (InvalidOperationException)
            {
                return;
            }

            if (hasExited)
            {
                return;
            }

#if KEEPVAULT_MACOS
            if (macStaging is null)
            {
                limitViolation ??= new IOException("The descriptor-bound macOS extraction staging object is unavailable.");
                linkedCts.Cancel();
                try { process.Kill(entireProcessTree: true); } catch { }
                return;
            }
#else
            if (!Directory.Exists(stagingDirectory) && windowsStaging is null)
            {
                return;
            }
#endif

            if (!Monitor.TryEnter(checkLock))
            {
                return; // Another check is currently running (debounced)
            }

            try
            {
#if KEEPVAULT_MACOS
                DirectoryTreeMeasurement measurement = macStaging.MeasureTree(allowWriters: true);
                ValidateExtractedTreeMeasurement(measurement);

                long freeSpace = macStaging.GetFreeDiskSpaceBytes();
                if (freeSpace < 0 || freeSpace < minFreeSpace)
                {
                    linkedCts.Cancel();
                    try { process.Kill(entireProcessTree: true); } catch { }
                    limitViolation ??= new IOException($"ZPAQ-Extraktion abgebrochen: Unzureichender freier Speicherplatz auf dem Ziellaufwerk ({freeSpace} Bytes verbleibend).");
                    return;
                }
#else
                DirectoryTreeMeasurement measurement = windowsStaging?.MeasureTree(allowWriters: true)
                    ?? WindowsExtractionStaging.MeasureTreeNoFollow(stagingDirectory, allowWriters: true);
                ValidateExtractedTreeMeasurement(measurement);
#endif
                consecutiveErrors = 0;
            }
            catch (Exception ex) when (ex is InvalidDataException or IOException)
            {
                linkedCts.Cancel();
                try { process.Kill(entireProcessTree: true); } catch { }
                limitViolation ??= ex;
            }
            catch (Exception ex) when (ex is not InvalidDataException && ex is not IOException)
            {
                consecutiveErrors++;
                if (consecutiveErrors > maxConsecutiveTransientErrors)
                {
                    linkedCts.Cancel();
                    try { process.Kill(entireProcessTree: true); } catch { }
                    limitViolation ??= new InvalidOperationException($"Decompression-Überwachung nach wiederholten Fehlern abgebrochen: {ex.Message}", ex);
                }
            }
            catch (Exception ex)
            {
                linkedCts.Cancel();
                try { process.Kill(entireProcessTree: true); } catch { }
                limitViolation ??= ex;
            }
            finally
            {
                Monitor.Exit(checkLock);
            }
        }

        using var watcher = new FileSystemWatcher();
        if (Directory.Exists(stagingDirectory))
        {
            try
            {
                watcher.Path = stagingDirectory;
                watcher.IncludeSubdirectories = true;
                watcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.Size | NotifyFilters.LastWrite;
                watcher.Created += (_, _) => CheckLimits();
                watcher.Changed += (_, _) => CheckLimits();
                watcher.EnableRaisingEvents = true;
            }
            catch
            {
                // Fallback to high-frequency polling
            }
        }

        while (!process.HasExited && !cancellationToken.IsCancellationRequested)
        {
            if (limitViolation != null)
            {
                throw limitViolation;
            }

            try
            {
                await Task.Delay(20, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            if (limitViolation != null)
            {
                throw limitViolation;
            }

            if (process.HasExited)
            {
                break;
            }

            CheckLimits();

            if (limitViolation != null)
            {
                throw limitViolation;
            }
        }

        if (limitViolation != null)
        {
            throw limitViolation;
        }
    }

    internal static async Task<ProcessResult> RunTextProcessAsync(
        string executable,
        IEnumerable<string> arguments,
        string workingDirectory,
        IProgress<string>? progress,
        CancellationToken cancellationToken,
        string? monitorStagingDirectory = null
#if KEEPVAULT_MACOS
        , MacExtractionStaging? macStaging = null
#else
        , WindowsExtractionStaging? windowsStaging = null
#endif
    )
    {
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        using var process = CreateProcess(executable, arguments, workingDirectory);
        process.StartInfo.UseShellExecute = false;
        process.StartInfo.RedirectStandardOutput = true;
        process.StartInfo.RedirectStandardError = true;
        var output = new BoundedTextBuffer(MaxCapturedProcessTextCharacters);
        var errors = new BoundedTextBuffer(MaxCapturedProcessTextCharacters);

        if (!process.Start())
        {
            throw new InvalidOperationException("zpaq konnte nicht gestartet werden.");
        }

        Task outputTask = ReadLinesAsync(process.StandardOutput, output, progress, linkedCts.Token);
        Task errorTask = ReadLinesAsync(process.StandardError, errors, progress, linkedCts.Token);
        Task? monitorTask = monitorStagingDirectory != null
            ? MonitorExtractionLimitsAsync(
                monitorStagingDirectory,
                process,
                linkedCts,
                linkedCts.Token
#if KEEPVAULT_MACOS
                , macStaging
#else
                , windowsStaging
#endif
              )
            : null;

        var tasks = monitorTask != null
            ? new[] { process.WaitForExitAsync(linkedCts.Token), outputTask, errorTask, monitorTask }
            : new[] { process.WaitForExitAsync(linkedCts.Token), outputTask, errorTask };

        await AwaitProcessTasksFailFastAsync(process, tasks).ConfigureAwait(false);

        return new ProcessResult(process.ExitCode, output.ToString(), errors.ToString());
    }

    private static async Task<ProcessResult> RunStdoutPipeAsync(
        string executable,
        IEnumerable<string> arguments,
        string workingDirectory,
        Func<Stream, CancellationToken, Task> consumeArchive,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        using var process = CreateProcess(executable, arguments, workingDirectory);
        process.StartInfo.RedirectStandardOutput = true;
        process.StartInfo.RedirectStandardError = true;

        var errors = new BoundedTextBuffer(MaxCapturedProcessTextCharacters);

        if (!process.Start())
        {
            throw new InvalidOperationException("zpaq konnte nicht gestartet werden.");
        }

        Task consumeTask = consumeArchive(process.StandardOutput.BaseStream, cancellationToken);
        Task errorTask = ReadLinesAsync(process.StandardError, errors, progress, cancellationToken);

        await AwaitProcessTasksFailFastAsync(
            process,
            consumeTask,
            process.WaitForExitAsync(cancellationToken),
            errorTask).ConfigureAwait(false);

        return new ProcessResult(process.ExitCode, string.Empty, errors.ToString());
    }

    private static async Task<ProcessResult> RunStdinPipeAsync(
        string executable,
        IEnumerable<string> arguments,
        string workingDirectory,
        Func<Stream, CancellationToken, Task> writeArchive,
        IProgress<string>? progress,
        CancellationToken cancellationToken,
        string? monitorStagingDirectory = null
#if KEEPVAULT_MACOS
        , MacExtractionStaging? macStaging = null
#else
        , WindowsExtractionStaging? windowsStaging = null
#endif
    )
    {
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        using var process = CreateProcess(executable, arguments, workingDirectory);
        process.StartInfo.RedirectStandardInput = true;
        process.StartInfo.RedirectStandardOutput = true;
        process.StartInfo.RedirectStandardError = true;

        var output = new BoundedTextBuffer(MaxCapturedProcessTextCharacters);
        var errors = new BoundedTextBuffer(MaxCapturedProcessTextCharacters);

        if (!process.Start())
        {
            throw new InvalidOperationException("zpaq konnte nicht gestartet werden.");
        }

        Task inputTask = WriteInputAndCloseAsync(process.StandardInput, writeArchive, linkedCts.Token);
        Task outputTask = ReadLinesAsync(process.StandardOutput, output, progress, linkedCts.Token);
        Task errorTask = ReadLinesAsync(process.StandardError, errors, progress, linkedCts.Token);
        Task? monitorTask = monitorStagingDirectory != null
            ? MonitorExtractionLimitsAsync(
                monitorStagingDirectory,
                process,
                linkedCts,
                linkedCts.Token
#if KEEPVAULT_MACOS
                , macStaging
#else
                , windowsStaging
#endif
              )
            : null;

        var tasks = monitorTask != null
            ? new[] { inputTask, process.WaitForExitAsync(linkedCts.Token), outputTask, errorTask, monitorTask }
            : new[] { inputTask, process.WaitForExitAsync(linkedCts.Token), outputTask, errorTask };

        await AwaitProcessTasksFailFastAsync(process, tasks).ConfigureAwait(false);

        return new ProcessResult(process.ExitCode, output.ToString(), errors.ToString());
    }

    private static Process CreateProcess(string executable, IEnumerable<string> arguments, string workingDirectory)
    {
        var process = new Process();
        process.StartInfo.FileName = executable;
        process.StartInfo.WorkingDirectory = workingDirectory;
        process.StartInfo.UseShellExecute = false;
        process.StartInfo.CreateNoWindow = true;

        foreach (string argument in arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }

        return process;
    }

    private static async Task WriteInputAndCloseAsync(
        StreamWriter standardInput,
        Func<Stream, CancellationToken, Task> writeArchive,
        CancellationToken cancellationToken)
    {
        try
        {
            await writeArchive(standardInput.BaseStream, cancellationToken).ConfigureAwait(false);
            await standardInput.BaseStream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            standardInput.Close();
        }
    }

    private static async Task ReadLinesAsync(
        StreamReader reader,
        BoundedTextBuffer destination,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        char[] readBuffer = new char[4096];
        char[] lineBuffer = new char[MaxProcessLineCharacters];
        int lineLength = 0;
        bool lineTruncated = false;
        int progressLines = 0;
        int progressCharacters = 0;
        bool progressTruncationReported = false;
        try
        {
            int read;
            while ((read = await reader.ReadAsync(readBuffer.AsMemory(), cancellationToken).ConfigureAwait(false)) > 0)
            {
                for (int index = 0; index < read; index++)
                {
                    char character = readBuffer[index];
                    if (character == '\r')
                    {
                        continue;
                    }

                    if (character == '\n')
                    {
                        ReportLine(
                            destination,
                            progress,
                            lineBuffer,
                            lineLength,
                            lineTruncated,
                            ref progressLines,
                            ref progressCharacters,
                            ref progressTruncationReported);
                        lineLength = 0;
                        lineTruncated = false;
                        continue;
                    }

                    if (lineLength < lineBuffer.Length)
                    {
                        lineBuffer[lineLength++] = character;
                    }
                    else
                    {
                        lineTruncated = true;
                    }
                }
            }

            if (lineLength > 0 || lineTruncated)
            {
                ReportLine(
                    destination,
                    progress,
                    lineBuffer,
                    lineLength,
                    lineTruncated,
                    ref progressLines,
                    ref progressCharacters,
                    ref progressTruncationReported);
            }
        }
        finally
        {
            Array.Clear(readBuffer);
            Array.Clear(lineBuffer);
        }
    }

    private static void ReportLine(
        BoundedTextBuffer destination,
        IProgress<string>? progress,
        char[] lineBuffer,
        int lineLength,
        bool lineTruncated,
        ref int progressLines,
        ref int progressCharacters,
        ref bool progressTruncationReported)
    {
        string line = new(lineBuffer, 0, lineLength);
        if (lineTruncated)
        {
            line += " [line truncated]";
        }

        destination.AppendLine(line, lineTruncated);
        if (progress is null)
        {
            return;
        }

        if (progressLines < MaxProgressLinesPerStream
            && progressCharacters <= MaxProgressCharactersPerStream - line.Length)
        {
            progress.Report(line);
            progressLines++;
            progressCharacters += line.Length;
        }
        else if (!progressTruncationReported)
        {
            progress.Report("[process progress output truncated]");
            progressTruncationReported = true;
        }
    }

    private static async Task StopProcessAsync(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (InvalidOperationException)
        {
        }
        catch (Win32Exception ex)
        {
            throw new InvalidOperationException("The child process could not be terminated.", ex);
        }
        catch (NotSupportedException ex)
        {
            throw new InvalidOperationException("The platform cannot terminate the child process tree.", ex);
        }

        using var waitTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try
        {
            await process.WaitForExitAsync(waitTimeout.Token).ConfigureAwait(false);
        }
        catch (InvalidOperationException)
        {
        }
        catch (OperationCanceledException ex)
        {
            throw new TimeoutException("The terminated child process did not exit within five seconds.", ex);
        }
    }

    private static async Task AwaitProcessTasksFailFastAsync(Process process, params Task[] tasks)
    {
        var pending = new HashSet<Task>(tasks);
        while (pending.Count > 0)
        {
            Task completed = await Task.WhenAny(pending).ConfigureAwait(false);
            pending.Remove(completed);
            try
            {
                await completed.ConfigureAwait(false);
            }
            catch
            {
                try
                {
                    await StopProcessAsync(process).ConfigureAwait(false);
                }
                finally
                {
                    ObserveFutureFaults(pending);
                }

                throw;
            }
        }
    }

    private static void ObserveFutureFaults(IEnumerable<Task> tasks)
    {
        foreach (Task task in tasks)
        {
            _ = task.ContinueWith(
                completed => _ = completed.Exception,
                CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
        }
    }

    private static string GetStreamingMethod(int compressionLevel)
    {
        ValidateCompressionLevel(compressionLevel);
        return compressionLevel switch
        {
            0 => $"s{StreamMethodBlockSize}",
            1 => $"s{StreamMethodBlockSize}.1.5.0.3.22",
            2 => $"s{StreamMethodBlockSize}.1.4.0.8.25",
            3 => $"s{StreamMethodBlockSize}.2.12.0.8.25c0.0.511.255",
            4 => $"s{StreamMethodBlockSize}.3ci1",
            _ => $"s{StreamMethodBlockSize}.0ci1.1.1.1.2am",
        };
    }

    private static void ValidateCompressionLevel(int compressionLevel)
    {
        if (compressionLevel is < 0 or > 5)
        {
            throw new ArgumentOutOfRangeException(nameof(compressionLevel), "ZPAQ compression must be between 0 and 5.");
        }
    }

    private sealed class BoundedTextBuffer
    {
        private const string TruncationMarker = "[process output truncated]";
        private readonly int _maxCharacters;
        private readonly StringBuilder _text = new();
        private bool _truncated;

        public BoundedTextBuffer(int maxCharacters)
        {
            _maxCharacters = maxCharacters > TruncationMarker.Length
                ? maxCharacters
                : throw new ArgumentOutOfRangeException(nameof(maxCharacters));
        }

        public void AppendLine(string line, bool sourceLineTruncated)
        {
            ArgumentNullException.ThrowIfNull(line);
            _truncated |= sourceLineTruncated;
            if (_text.Length >= _maxCharacters)
            {
                _truncated = true;
                return;
            }

            if (_text.Length > 0)
            {
                AppendWithinLimit(Environment.NewLine);
            }

            int available = _maxCharacters - _text.Length;
            int take = Math.Min(available, line.Length);
            _text.Append(line.AsSpan(0, take));
            if (take != line.Length)
            {
                _truncated = true;
            }
        }

        public override string ToString()
        {
            if (!_truncated)
            {
                return _text.ToString();
            }

            string prefix = _text.Length == 0 ? string.Empty : Environment.NewLine;
            return string.Concat(_text.ToString(), prefix, TruncationMarker);
        }

        private void AppendWithinLimit(string value)
        {
            int take = Math.Min(_maxCharacters - _text.Length, value.Length);
            _text.Append(value.AsSpan(0, take));
            if (take != value.Length)
            {
                _truncated = true;
            }
        }
    }

#if KEEPVAULT_MACOS
    private sealed partial class MacInputSnapshot : IDisposable
    {
        private const ushort OwnerDirectoryMode = 0x01C0; // 0700
        private const ushort OwnerReadMode = 0x0100; // 0400
        private const ushort FileTypeMask = 0xF000;
        private const ushort RegularFileMode = 0x8000;
        private const ushort DirectoryMode = 0x4000;
        private const ushort SymbolicLinkMode = 0xA000;
        private const int AtRemoveDirectory = 0x0080;

        private readonly string _snapshotRootPath;
        private readonly string _snapshotName;
        private SafeFileHandle? _snapshotParentHandle;
        private SafeFileHandle? _snapshotRootHandle;
        private readonly MacFileIdentity _snapshotParentIdentity;
        private readonly MacFileIdentity _snapshotRootIdentity;
        private readonly string _treeFingerprint;
        private bool _disposed;

        private MacInputSnapshot(
            string snapshotRootPath,
            string snapshotName,
            SafeFileHandle snapshotParentHandle,
            MacFileIdentity snapshotParentIdentity,
            SafeFileHandle snapshotRootHandle,
            MacFileIdentity snapshotRootIdentity,
            string treeFingerprint,
            IReadOnlyList<string> relativeInputs)
        {
            _snapshotRootPath = snapshotRootPath;
            _snapshotName = snapshotName;
            _snapshotParentHandle = snapshotParentHandle;
            _snapshotParentIdentity = snapshotParentIdentity;
            _snapshotRootHandle = snapshotRootHandle;
            _snapshotRootIdentity = snapshotRootIdentity;
            _treeFingerprint = treeFingerprint;

            // macOS exposes directory descriptors below /dev/fd for stat, but
            // does not permit path traversal or chdir through them. Keep the
            // unpredictable private pathname for ProcessStartInfo; the held
            // root descriptor remains the identity and cleanup authority, and
            // the child process binds the directory as its cwd at spawn.
            WorkingDirectory = snapshotRootPath;
            InputPaths = relativeInputs
                .Select(relative => Path.Combine(WorkingDirectory, relative))
                .ToArray();
        }

        internal string WorkingDirectory { get; }
        internal string[] InputPaths { get; }

        internal void RequireReadyForUse()
        {
            SafeFileHandle parentHandle = _snapshotParentHandle
                ?? throw new ObjectDisposedException(nameof(MacInputSnapshot));
            SafeFileHandle rootHandle = _snapshotRootHandle
                ?? throw new ObjectDisposedException(nameof(MacInputSnapshot));
            MacFileIdentity parentIdentity = MacSafeFileSystem.GetIdentity(parentHandle);
            MacFileIdentity rootIdentity = MacSafeFileSystem.GetIdentity(rootHandle);
            MacFileIdentity entryIdentity = MacSafeFileSystem.GetIdentityAt(parentHandle, _snapshotName);
            if (!parentIdentity.SameObject(_snapshotParentIdentity)
                || !rootIdentity.SameObjectAndMetadata(_snapshotRootIdentity)
                || !entryIdentity.SameObjectAndMetadata(rootIdentity))
            {
                throw new IOException("The private archive-input root changed before native ZPAQ use.");
            }

            DirectoryTreeMeasurement current = MacSafeFileSystem.MeasureDirectoryTreeNoFollow(
                rootHandle,
                _snapshotRootIdentity,
                allowWriters: false);
            if (!string.Equals(current.TreeFingerprint, _treeFingerprint, StringComparison.Ordinal))
            {
                throw new IOException("The private archive-input tree changed before native ZPAQ use.");
            }
        }

        internal static MacInputSnapshot Create(string workingDirectory, IReadOnlyList<string> inputPaths)
        {
            string sourceRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(workingDirectory));
            string[] snapshotSources = NormalizeSnapshotSources(inputPaths);
            using SafeFileHandle sourceRootHandle = MacSafeFileSystem.OpenDirectoryHandle(sourceRoot);
            MacSafeFileSystem.RequirePathStillNamesHandle(sourceRootHandle, sourceRoot);
            MacFileIdentity sourceRootIdentity = MacSafeFileSystem.GetIdentity(sourceRootHandle);

            string temporaryParentPath = Path.TrimEndingDirectorySeparator(
                MacSafeFileSystem.ResolveExistingRealPath(Path.GetTempPath()));
            SafeFileHandle? snapshotParentHandle = null;
            SafeFileHandle? snapshotRootHandle = null;
            MacFileIdentity snapshotParentIdentity = default;
            MacFileIdentity snapshotRootIdentity = default;
            string snapshotName = string.Empty;
            string snapshotRootPath = string.Empty;
            try
            {
                snapshotParentHandle = MacSafeFileSystem.OpenDirectoryHandle(temporaryParentPath);
                MacSafeFileSystem.RequirePathStillNamesHandle(snapshotParentHandle, temporaryParentPath);
                snapshotParentIdentity = MacSafeFileSystem.GetIdentity(snapshotParentHandle);
                snapshotRootHandle = CreatePrivateSnapshotDirectory(
                    snapshotParentHandle,
                    snapshotParentIdentity,
                    out snapshotName,
                    out snapshotRootIdentity);
                snapshotRootPath = Path.Combine(temporaryParentPath, snapshotName);

                var relativeInputs = new string[snapshotSources.Length];
                var selectionRoot = new SnapshotSelectionNode();
                for (int index = 0; index < snapshotSources.Length; index++)
                {
                    string source = snapshotSources[index];
                    string relative = Path.GetRelativePath(sourceRoot, source);
                    ValidateRelativeSnapshotPath(relative);
                    string[] components = SplitRelativePath(relative);
                    AddSelection(selectionRoot, components, relative);
                    relativeInputs[index] = string.Join(Path.DirectorySeparatorChar, components);
                }

                var visitedDirectories = new HashSet<(int Device, ulong Inode)>
                {
                    (sourceRootIdentity.Device, sourceRootIdentity.Inode),
                };
                MirrorSelectionDirectory(
                    sourceRootHandle,
                    snapshotRootHandle,
                    selectionRoot,
                    string.Empty,
                    visitedDirectories);

                MacFileIdentity finalSourceRootIdentity = MacSafeFileSystem.GetIdentity(sourceRootHandle);
                if (!finalSourceRootIdentity.SameObjectAndMetadata(sourceRootIdentity))
                {
                    throw new IOException("The bound archive-input working directory changed during snapshot creation.");
                }

                ValidatePortableTree(snapshotRootHandle, snapshotRootIdentity);
                DirectoryTreeMeasurement validatedTree = MacSafeFileSystem.MeasureDirectoryTreeNoFollow(
                    snapshotRootHandle,
                    snapshotRootIdentity,
                    allowWriters: false);
                MacFileIdentity validatedSnapshotIdentity =
                    MacSafeFileSystem.GetIdentity(snapshotRootHandle);

                InputSnapshotHookAfterReadyForTests?.Invoke(snapshotRootPath);
                MacFileIdentity finalSnapshotHandleIdentity =
                    MacSafeFileSystem.GetIdentity(snapshotRootHandle);
                MacFileIdentity finalSnapshotEntryIdentity =
                    MacSafeFileSystem.GetIdentityAt(snapshotParentHandle, snapshotName);
                if (!finalSnapshotHandleIdentity.SameObjectAndMetadata(validatedSnapshotIdentity)
                    || !finalSnapshotEntryIdentity.SameObjectAndMetadata(finalSnapshotHandleIdentity)
                    || !MacSafeFileSystem.GetIdentity(snapshotParentHandle).SameObject(snapshotParentIdentity))
                {
                    throw new IOException(
                        "The private archive-input root changed after final validation and before use.");
                }
                var snapshot = new MacInputSnapshot(
                    snapshotRootPath,
                    snapshotName,
                    snapshotParentHandle,
                    snapshotParentIdentity,
                    snapshotRootHandle,
                    validatedSnapshotIdentity,
                    validatedTree.TreeFingerprint,
                    relativeInputs);
                snapshotParentHandle = null;
                snapshotRootHandle = null;
                return snapshot;
            }
            catch (Exception operationError)
            {
                Exception? cleanupError = null;
                if (snapshotParentHandle is not null && snapshotRootHandle is not null)
                {
                    try
                    {
                        MacSafeFileSystem.DeleteDirectoryTreeBound(
                            snapshotParentHandle,
                            snapshotParentIdentity,
                            snapshotName,
                            snapshotRootHandle,
                            snapshotRootIdentity);
                    }
                    catch (Exception error)
                    {
                        cleanupError = error;
                    }
                }

                snapshotRootHandle?.Dispose();
                snapshotParentHandle?.Dispose();
                if (cleanupError is not null)
                {
                    throw new IOException(
                        "Archive-input snapshot creation failed and the exact bound private tree could not be cleaned up.",
                        new AggregateException(operationError, cleanupError));
                }
                throw;
            }
        }

        private static string[] NormalizeSnapshotSources(IReadOnlyList<string> inputPaths)
        {
            string[] distinct = inputPaths
                .Select(path => Path.TrimEndingDirectorySeparator(Path.GetFullPath(path)))
                .Distinct(StringComparer.Ordinal)
                .ToArray();
            return distinct
                .Where(source => !distinct.Any(candidate =>
                    !string.Equals(candidate, source, StringComparison.Ordinal)
                    && IsPathWithinDirectory(source, candidate)))
                .ToArray();
        }

        private static void ValidateRelativeSnapshotPath(string relative)
        {
            if (string.IsNullOrWhiteSpace(relative)
                || Path.IsPathRooted(relative)
                || string.Equals(relative, ".", StringComparison.Ordinal)
                || relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                    .Any(component => string.Equals(component, "..", StringComparison.Ordinal)))
            {
                throw new IOException("An input path escapes the secure snapshot root.");
            }
        }

        private static string[] SplitRelativePath(string relative)
        {
            string[] components = relative.Split(
                [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
                StringSplitOptions.RemoveEmptyEntries);
            if (components.Length == 0)
            {
                throw new IOException("An input path does not name an entry below the bound working directory.");
            }
            foreach (string component in components)
            {
                ValidatePortableComponent(component);
            }
            return components;
        }

        internal static void ValidatePortableTree(string root)
        {
            string fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
            using SafeFileHandle rootHandle = MacSafeFileSystem.OpenDirectoryHandle(fullRoot);
            MacSafeFileSystem.RequirePathStillNamesHandle(rootHandle, fullRoot);
            ValidatePortableTree(rootHandle, MacSafeFileSystem.GetIdentity(rootHandle));
        }

        private static void ValidatePortableTree(
            SafeFileHandle rootHandle,
            MacFileIdentity rootIdentity)
        {
            var visited = new HashSet<(int Device, ulong Inode)>
            {
                (rootIdentity.Device, rootIdentity.Inode),
            };
            ValidatePortableDirectory(rootHandle, string.Empty, visited);
            if (!MacSafeFileSystem.GetIdentity(rootHandle).SameObject(rootIdentity))
            {
                throw new IOException("The bound portable-tree root changed during validation.");
            }
        }

        private static void ValidatePortableDirectory(
            SafeFileHandle directoryHandle,
            string relativePrefix,
            HashSet<(int Device, ulong Inode)> visited)
        {
            MacFileIdentity beforeDirectory = MacSafeFileSystem.GetIdentity(directoryHandle);
            IReadOnlyList<MacDirectoryEntry> beforeEntries =
                MacSafeFileSystem.ReadDirectoryEntriesNoFollow(directoryHandle);
            ValidatePortableNames(beforeEntries, relativePrefix);

            foreach (MacDirectoryEntry entry in beforeEntries)
            {
                string relativePath = CombineRelative(relativePrefix, entry.Name);
                ushort type = (ushort)(entry.Identity.Mode & FileTypeMask);
                if (type == SymbolicLinkMode)
                {
                    throw new IOException(
                        $"The input contains a symbolic link and cannot be archived safely: {relativePath}");
                }
                if (type == RegularFileMode)
                {
                    if (entry.Identity.LinkCount != 1)
                    {
                        throw new IOException($"The input contains a multiply linked file: {relativePath}");
                    }
                    using FileStream file = MacSafeFileSystem.OpenReadAt(directoryHandle, entry.Name);
                    MacFileIdentity opened = MacSafeFileSystem.GetIdentity(file.SafeFileHandle);
                    MacFileIdentity finalEntry = MacSafeFileSystem.GetIdentityAt(directoryHandle, entry.Name);
                    if (!opened.SameObjectAndMetadata(entry.Identity)
                        || !finalEntry.SameObjectAndMetadata(opened)
                        || opened.LinkCount != 1)
                    {
                        throw new IOException($"The portable-tree file changed during validation: {relativePath}");
                    }
                    continue;
                }
                if (type != DirectoryMode)
                {
                    throw new IOException($"The input contains a non-regular object: {relativePath}");
                }

                using SafeFileHandle child = MacSafeFileSystem.OpenDirectoryHandleAt(directoryHandle, entry.Name);
                MacFileIdentity openedChild = MacSafeFileSystem.GetIdentity(child);
                if (!openedChild.SameObjectAndMetadata(entry.Identity))
                {
                    throw new IOException($"The portable-tree directory changed before descent: {relativePath}");
                }
                if (!visited.Add((openedChild.Device, openedChild.Inode)))
                {
                    throw new IOException($"The input contains a directory cycle: {relativePath}");
                }
                try
                {
                    ValidatePortableDirectory(child, relativePath, visited);
                }
                finally
                {
                    visited.Remove((openedChild.Device, openedChild.Inode));
                }

                MacFileIdentity finalChild = MacSafeFileSystem.GetIdentity(child);
                MacFileIdentity finalEntryIdentity = MacSafeFileSystem.GetIdentityAt(directoryHandle, entry.Name);
                if (!finalChild.SameObjectAndMetadata(openedChild)
                    || !finalEntryIdentity.SameObjectAndMetadata(finalChild))
                {
                    throw new IOException($"The portable-tree directory changed during validation: {relativePath}");
                }
            }

            IReadOnlyList<MacDirectoryEntry> afterEntries =
                MacSafeFileSystem.ReadDirectoryEntriesNoFollow(directoryHandle);
            RequireSameEntries(beforeEntries, afterEntries, relativePrefix);
            if (!MacSafeFileSystem.GetIdentity(directoryHandle).SameObjectAndMetadata(beforeDirectory))
            {
                throw new IOException($"The portable-tree directory changed during validation: {relativePrefix}");
            }
        }

        private static void MirrorSelectionDirectory(
            SafeFileHandle sourceDirectory,
            SafeFileHandle destinationDirectory,
            SnapshotSelectionNode selection,
            string relativePrefix,
            HashSet<(int Device, ulong Inode)> visitedDirectories)
        {
            MacFileIdentity beforeDirectory = MacSafeFileSystem.GetIdentity(sourceDirectory);
            ValidatePortableSelectionNames(selection.Children.Keys, relativePrefix);
            foreach ((string name, SnapshotSelectionNode childSelection) in
                     selection.Children.OrderBy(pair => pair.Key, StringComparer.Ordinal))
            {
                MacFileIdentity entryIdentity = MacSafeFileSystem.GetIdentityAt(sourceDirectory, name);
                string relativePath = CombineRelative(relativePrefix, name);
                MirrorBoundEntry(
                    sourceDirectory,
                    destinationDirectory,
                    name,
                    relativePath,
                    entryIdentity,
                    childSelection.Selected ? null : childSelection,
                    visitedDirectories);
            }

            if (!MacSafeFileSystem.GetIdentity(sourceDirectory).SameObjectAndMetadata(beforeDirectory))
            {
                throw new IOException($"The selected archive-input directory changed: {relativePrefix}");
            }
        }

        private static void MirrorWholeDirectory(
            SafeFileHandle sourceDirectory,
            SafeFileHandle destinationDirectory,
            string relativePrefix,
            HashSet<(int Device, ulong Inode)> visitedDirectories)
        {
            MacFileIdentity beforeDirectory = MacSafeFileSystem.GetIdentity(sourceDirectory);
            IReadOnlyList<MacDirectoryEntry> beforeEntries =
                MacSafeFileSystem.ReadDirectoryEntriesNoFollow(sourceDirectory);
            ValidatePortableNames(beforeEntries, relativePrefix);
            foreach (MacDirectoryEntry entry in beforeEntries)
            {
                string relativePath = CombineRelative(relativePrefix, entry.Name);
                MirrorBoundEntry(
                    sourceDirectory,
                    destinationDirectory,
                    entry.Name,
                    relativePath,
                    entry.Identity,
                    childSelection: null,
                    visitedDirectories);
            }

            IReadOnlyList<MacDirectoryEntry> afterEntries =
                MacSafeFileSystem.ReadDirectoryEntriesNoFollow(sourceDirectory);
            RequireSameEntries(beforeEntries, afterEntries, relativePrefix);
            if (!MacSafeFileSystem.GetIdentity(sourceDirectory).SameObjectAndMetadata(beforeDirectory))
            {
                throw new IOException($"The archive-input directory changed during snapshot creation: {relativePrefix}");
            }
        }

        private static void MirrorBoundEntry(
            SafeFileHandle sourceDirectory,
            SafeFileHandle destinationDirectory,
            string name,
            string relativePath,
            MacFileIdentity entryIdentity,
            SnapshotSelectionNode? childSelection,
            HashSet<(int Device, ulong Inode)> visitedDirectories)
        {
            InputSnapshotHookBeforeSourceEntryOpenForTests?.Invoke(relativePath);
            ushort type = (ushort)(entryIdentity.Mode & FileTypeMask);
            if (type == SymbolicLinkMode)
            {
                throw new IOException($"The input contains a symbolic link: {relativePath}");
            }

            if (type == RegularFileMode)
            {
                if (childSelection is not null)
                {
                    throw new IOException($"An archive input traverses through a regular file: {relativePath}");
                }
                if (entryIdentity.LinkCount != 1)
                {
                    throw new IOException($"The input contains a file with multiple hard links: {relativePath}");
                }

                using FileStream source = MacSafeFileSystem.OpenReadAt(sourceDirectory, name);
                MacFileIdentity openedIdentity = MacSafeFileSystem.GetIdentity(source.SafeFileHandle);
                if (!openedIdentity.SameObjectAndMetadata(entryIdentity)
                    || openedIdentity.LinkCount != 1)
                {
                    throw new IOException($"The archive-input file changed before cloning: {relativePath}");
                }

                MacSafeFileSystem.CloneOpenedFileIntoDirectory(
                    source.SafeFileHandle,
                    destinationDirectory,
                    name);

                MacFileIdentity finalHandleIdentity = MacSafeFileSystem.GetIdentity(source.SafeFileHandle);
                MacFileIdentity finalEntryIdentity = MacSafeFileSystem.GetIdentityAt(sourceDirectory, name);
                if (!finalHandleIdentity.SameObjectAndMetadata(openedIdentity)
                    || !finalEntryIdentity.SameObjectAndMetadata(finalHandleIdentity)
                    || finalHandleIdentity.LinkCount != 1
                    || finalEntryIdentity.LinkCount != 1)
                {
                    throw new IOException($"The archive-input file changed while it was cloned: {relativePath}");
                }

                using FileStream destination = MacSafeFileSystem.OpenReadAt(destinationDirectory, name);
                MacSafeFileSystem.SetUnixFileMode(destination.SafeFileHandle, OwnerReadMode);
                MacFileIdentity destinationIdentity = MacSafeFileSystem.GetIdentity(destination.SafeFileHandle);
                MacFileIdentity destinationEntry = MacSafeFileSystem.GetIdentityAt(destinationDirectory, name);
                if (!destinationIdentity.SameObject(destinationEntry)
                    || destinationIdentity.LinkCount != 1
                    || destinationEntry.LinkCount != 1
                    || (destinationIdentity.Mode & FileTypeMask) != RegularFileMode
                    || (destinationIdentity.Mode & 0x01FF) != OwnerReadMode)
                {
                    throw new IOException($"The private archive-input clone is not bound safely: {relativePath}");
                }
                return;
            }

            if (type != DirectoryMode)
            {
                throw new IOException($"The input is neither a regular file nor a directory: {relativePath}");
            }

            using SafeFileHandle sourceChild = MacSafeFileSystem.OpenDirectoryHandleAt(sourceDirectory, name);
            MacFileIdentity openedDirectory = MacSafeFileSystem.GetIdentity(sourceChild);
            if (!openedDirectory.SameObjectAndMetadata(entryIdentity))
            {
                throw new IOException($"The archive-input directory changed before descent: {relativePath}");
            }
            if (!visitedDirectories.Add((openedDirectory.Device, openedDirectory.Inode)))
            {
                throw new IOException($"The input contains a directory cycle: {relativePath}");
            }

            using SafeFileHandle destinationChild = CreatePrivateDirectoryAt(destinationDirectory, name);
            try
            {
                if (childSelection is null)
                {
                    MirrorWholeDirectory(
                        sourceChild,
                        destinationChild,
                        relativePath,
                        visitedDirectories);
                }
                else
                {
                    MirrorSelectionDirectory(
                        sourceChild,
                        destinationChild,
                        childSelection,
                        relativePath,
                        visitedDirectories);
                }
            }
            finally
            {
                visitedDirectories.Remove((openedDirectory.Device, openedDirectory.Inode));
            }

            MacFileIdentity finalDirectory = MacSafeFileSystem.GetIdentity(sourceChild);
            MacFileIdentity finalDirectoryEntry = MacSafeFileSystem.GetIdentityAt(sourceDirectory, name);
            if (!finalDirectory.SameObjectAndMetadata(openedDirectory)
                || !finalDirectoryEntry.SameObjectAndMetadata(finalDirectory))
            {
                throw new IOException($"The archive-input directory changed during cloning: {relativePath}");
            }
        }

        private static SafeFileHandle CreatePrivateSnapshotDirectory(
            SafeFileHandle parentHandle,
            MacFileIdentity parentIdentity,
            out string name,
            out MacFileIdentity identity)
        {
            for (int attempt = 0; attempt < 64; attempt++)
            {
                byte[] random = RandomNumberGenerator.GetBytes(16);
                try
                {
                    name = $"keep-vault-input-{Convert.ToHexString(random).ToLowerInvariant()}";
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(random);
                }

                try
                {
                    MacSafeFileSystem.MkdirAt(parentHandle, name, OwnerDirectoryMode);
                }
                catch (Win32Exception exception) when (exception.NativeErrorCode == 17 /* EEXIST */)
                {
                    continue;
                }

                SafeFileHandle? directoryHandle = null;
                try
                {
                    MacFileIdentity entryIdentity = MacSafeFileSystem.GetIdentityAt(parentHandle, name);
                    directoryHandle = MacSafeFileSystem.OpenDirectoryHandleAt(parentHandle, name);
                    MacSafeFileSystem.SetUnixFileMode(directoryHandle, OwnerDirectoryMode);
                    identity = MacSafeFileSystem.GetIdentity(directoryHandle);
                    MacFileIdentity finalEntry = MacSafeFileSystem.GetIdentityAt(parentHandle, name);
                    if (!identity.SameObject(entryIdentity)
                        || !finalEntry.SameObject(identity)
                        || (identity.Mode & FileTypeMask) != DirectoryMode
                        || (identity.Mode & 0x01FF) != OwnerDirectoryMode
                        || !MacSafeFileSystem.GetIdentity(parentHandle).SameObject(parentIdentity))
                    {
                        throw new IOException("The private archive-input root changed while it was bound.");
                    }

                    SafeFileHandle result = directoryHandle;
                    directoryHandle = null;
                    return result;
                }
                catch (Exception operationError)
                {
                    Exception? cleanupError = null;
                    try
                    {
                        MacFileIdentity entryIdentity = MacSafeFileSystem.GetIdentityAt(parentHandle, name);
                        if (directoryHandle is not null
                            && MacSafeFileSystem.GetIdentity(directoryHandle).SameObject(entryIdentity))
                        {
                            MacSafeFileSystem.UnlinkAt(parentHandle, name, AtRemoveDirectory);
                        }
                    }
                    catch (Exception error)
                    {
                        cleanupError = error;
                    }
                    finally
                    {
                        directoryHandle?.Dispose();
                    }

                    if (cleanupError is not null)
                    {
                        throw new IOException(
                            "Private archive-input root creation failed and its exact directory could not be removed.",
                            new AggregateException(operationError, cleanupError));
                    }
                    throw;
                }
            }

            throw new IOException("macOS could not allocate a unique private archive-input directory.");
        }

        private static SafeFileHandle CreatePrivateDirectoryAt(
            SafeFileHandle parentHandle,
            string name)
        {
            MacSafeFileSystem.MkdirAt(parentHandle, name, OwnerDirectoryMode);
            SafeFileHandle? directoryHandle = null;
            try
            {
                MacFileIdentity entryIdentity = MacSafeFileSystem.GetIdentityAt(parentHandle, name);
                directoryHandle = MacSafeFileSystem.OpenDirectoryHandleAt(parentHandle, name);
                MacSafeFileSystem.SetUnixFileMode(directoryHandle, OwnerDirectoryMode);
                MacFileIdentity openedIdentity = MacSafeFileSystem.GetIdentity(directoryHandle);
                MacFileIdentity finalEntryIdentity = MacSafeFileSystem.GetIdentityAt(parentHandle, name);
                if (!openedIdentity.SameObject(entryIdentity)
                    || !finalEntryIdentity.SameObject(openedIdentity)
                    || (openedIdentity.Mode & FileTypeMask) != DirectoryMode
                    || (openedIdentity.Mode & 0x01FF) != OwnerDirectoryMode)
                {
                    throw new IOException($"The private snapshot directory changed while it was created: {name}");
                }

                SafeFileHandle result = directoryHandle;
                directoryHandle = null;
                return result;
            }
            catch (Exception operationError)
            {
                Exception? cleanupError = null;
                try
                {
                    MacFileIdentity entryIdentity = MacSafeFileSystem.GetIdentityAt(parentHandle, name);
                    if (directoryHandle is not null
                        && MacSafeFileSystem.GetIdentity(directoryHandle).SameObject(entryIdentity))
                    {
                        MacSafeFileSystem.UnlinkAt(parentHandle, name, AtRemoveDirectory);
                    }
                }
                catch (Exception error)
                {
                    cleanupError = error;
                }
                finally
                {
                    directoryHandle?.Dispose();
                }

                if (cleanupError is not null)
                {
                    throw new IOException(
                        "Private snapshot directory creation failed and its exact entry could not be removed.",
                        new AggregateException(operationError, cleanupError));
                }
                throw;
            }
        }

        private static void AddSelection(
            SnapshotSelectionNode root,
            IReadOnlyList<string> components,
            string displayPath)
        {
            SnapshotSelectionNode current = root;
            foreach (string component in components)
            {
                if (current.Selected)
                {
                    throw new IOException($"An archive input is nested below another selected input: {displayPath}");
                }
                if (!current.Children.TryGetValue(component, out SnapshotSelectionNode? child))
                {
                    child = new SnapshotSelectionNode();
                    current.Children.Add(component, child);
                }
                current = child;
            }

            if (current.Selected || current.Children.Count != 0)
            {
                throw new IOException($"Two archive inputs collide inside the private snapshot: {displayPath}");
            }
            current.Selected = true;
        }

        private static void ValidatePortableSelectionNames(
            IEnumerable<string> names,
            string relativePrefix)
        {
            var portableNames = new HashSet<string>(StringComparer.Ordinal);
            foreach (string name in names)
            {
                ValidatePortableComponent(name);
                string collisionKey = name.Normalize(NormalizationForm.FormC).ToUpperInvariant();
                if (!portableNames.Add(collisionKey))
                {
                    throw new IOException(
                        $"The input contains names that collide after portable Unicode/case normalization: {relativePrefix}");
                }
            }
        }

        private static void ValidatePortableNames(
            IEnumerable<MacDirectoryEntry> entries,
            string relativePrefix) =>
            ValidatePortableSelectionNames(entries.Select(entry => entry.Name), relativePrefix);

        private static void RequireSameEntries(
            IReadOnlyList<MacDirectoryEntry> before,
            IReadOnlyList<MacDirectoryEntry> after,
            string relativePrefix)
        {
            if (before.Count != after.Count)
            {
                throw new IOException($"The archive-input directory changed during enumeration: {relativePrefix}");
            }
            for (int index = 0; index < before.Count; index++)
            {
                if (!string.Equals(before[index].Name, after[index].Name, StringComparison.Ordinal)
                    || !before[index].Identity.SameObjectAndMetadata(after[index].Identity))
                {
                    throw new IOException(
                        $"The archive-input directory changed during enumeration: {relativePrefix}; "
                        + $"before={before[index].Name}:{before[index].Identity}; "
                        + $"after={after[index].Name}:{after[index].Identity}");
                }
            }
        }

        private static string CombineRelative(string prefix, string name) =>
            string.IsNullOrEmpty(prefix) ? name : Path.Combine(prefix, name);

        private static void ValidatePortableComponent(string component)
        {
            if (component.Length == 0
                || component is "." or ".."
                || component.EndsWith('.')
                || component.EndsWith(' ')
                || component.Any(character => character < 32 || "<>:\"|?*".Contains(character)))
            {
                throw new IOException($"The input name is not portable between macOS and Windows: {component}");
            }

            string baseName = component.Split('.', 2)[0].ToUpperInvariant();
            bool reserved = baseName is "CON" or "PRN" or "AUX" or "NUL"
                || (baseName.Length == 4
                    && (baseName.StartsWith("COM", StringComparison.Ordinal)
                        || baseName.StartsWith("LPT", StringComparison.Ordinal))
                    && baseName[3] is >= '1' and <= '9');
            if (reserved)
            {
                throw new IOException($"The input uses a Windows-reserved device name: {component}");
            }
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            SafeFileHandle? rootHandle = Interlocked.Exchange(ref _snapshotRootHandle, null);
            SafeFileHandle? parentHandle = Interlocked.Exchange(ref _snapshotParentHandle, null);
            try
            {
                if (rootHandle is not null && parentHandle is not null)
                {
                    MacSafeFileSystem.DeleteDirectoryTreeBound(
                        parentHandle,
                        _snapshotParentIdentity,
                        _snapshotName,
                        rootHandle,
                        _snapshotRootIdentity);
                }
            }
            finally
            {
                rootHandle?.Dispose();
                parentHandle?.Dispose();
            }
        }

        private sealed class SnapshotSelectionNode
        {
            internal Dictionary<string, SnapshotSelectionNode> Children { get; } =
                new(StringComparer.Ordinal);

            internal bool Selected { get; set; }
        }
    }
#endif

#if !KEEPVAULT_MACOS
    /// <summary>
    /// Binds the tree native ZPAQ actually reads to exactly the objects this
    /// process validated, for the whole duration of the operation.
    /// </summary>
    /// <remarks>
    /// Leasing the files a path walk happened to find is not enough. The walk
    /// runs over a namespace that keeps changing, and native ZPAQ afterwards
    /// enumerates those same live directories a second time. Anything that
    /// appears in between - a new file, a junction pointing out of the
    /// selection - is invisible to the check and fully visible to ZPAQ.
    ///
    /// So the checked objects and the archived objects are made the same set:
    /// <list type="bullet">
    /// <item>every directory is opened no-follow, and its own handle has to
    /// resolve back to the path we meant, which rejects a reparse point at the
    /// directory itself and a junction swapped into any ancestor;</item>
    /// <item>every regular file is opened <see cref="FileShare.Read"/> and held
    /// open until ZPAQ is finished, so it can be neither replaced, renamed nor
    /// written while it is being archived;</item>
    /// <item>a private mirror is built from those verified objects - hard links
    /// where the volume allows them, otherwise a copy read out of the open
    /// handle - and ZPAQ is pointed at the mirror, never at the live tree.</item>
    /// </list>
    /// A hard link names a file record, not a path, so no later rename in the
    /// live tree can change what the mirror contains. Nothing in the mirror is
    /// ever a reparse point, because the mirror only ever gets directories this
    /// process created and links or copies of files it verified.
    /// </remarks>
    private sealed partial class WindowsInputSnapshot : IDisposable
    {
        private const uint FileListDirectory = 0x00000001;
        private const uint FileReadAttributes = 0x00000080;
        private const uint ShareRead = 0x00000001;
        private const uint ShareWrite = 0x00000002;
        private const uint ShareDelete = 0x00000004;
        private const uint OpenExisting = 3;
        private const uint FileFlagBackupSemantics = 0x02000000;
        private const uint FileFlagOpenReparsePoint = 0x00200000;
        private const uint FileAttributeDirectory = 0x00000010;
        private const uint FileAttributeReparsePoint = 0x00000400;

        private readonly string _snapshotRoot;
        private readonly List<SnapshotFile> _files = [];

        /// <summary>
        /// Leases whose snapshot hard link outlived the cleanup, kept open on
        /// purpose so the write block on the user's file survives with them.
        /// </summary>
        private static readonly List<FileStream> RetainedLeases = [];
        private readonly List<string> _readOnlyCopies = [];
        private bool _disposed;

        private WindowsInputSnapshot(string snapshotRoot)
        {
            _snapshotRoot = snapshotRoot;
            WorkingDirectory = snapshotRoot;
            InputPaths = [];
        }

        internal string WorkingDirectory { get; }
        internal string[] InputPaths { get; private set; }

        internal void RequireReadyForUse()
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            RequireNoReparsePointsWindows(_snapshotRoot);
            foreach (SnapshotFile file in _files)
            {
                if (!file.Lease.CanRead)
                {
                    throw new IOException("A leased Windows archive-input file is no longer readable.");
                }
            }
        }

        internal static WindowsInputSnapshot Create(string workingDirectory, IReadOnlyList<string> inputPaths)
        {
            string sourceRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(workingDirectory));
            string[] sources = NormalizeSnapshotSources(inputPaths);
            var snapshot = new WindowsInputSnapshot(Directory.CreateTempSubdirectory("keep-vault-input-").FullName);
            try
            {
                var staged = new string[sources.Length];
                for (int index = 0; index < sources.Length; index++)
                {
                    string source = sources[index];
                    string relative = Path.GetRelativePath(sourceRoot, source);
                    ValidateRelativeSnapshotPath(relative);
                    string destination = Path.GetFullPath(Path.Combine(snapshot._snapshotRoot, relative));
                    snapshot.EnsureWithinSnapshot(destination);

                    string? parent = Path.GetDirectoryName(destination);
                    if (string.IsNullOrWhiteSpace(parent))
                    {
                        throw new IOException("A secure input snapshot destination has no parent directory.");
                    }

                    Directory.CreateDirectory(parent);
                    if (File.Exists(destination) || Directory.Exists(destination))
                    {
                        throw new IOException($"Two archive inputs collide inside the private snapshot: {relative}");
                    }

                    FileAttributes attributes = File.GetAttributes(source);
                    if ((attributes & FileAttributes.ReparsePoint) != 0)
                    {
                        throw new IOException($"Die Eingabe enthält einen symbolischen Link oder Reparse Point: {source}");
                    }

                    if ((attributes & FileAttributes.Directory) != 0)
                    {
                        snapshot.MirrorDirectoryTree(source, destination);
                    }
                    else
                    {
                        snapshot.MirrorFile(source, destination);
                    }

                    staged[index] = destination;
                }

                // The mirror can only contain directories this process created
                // and links or copies of files it verified, so a reparse point
                // in it means something else wrote into the private tree.
                RequireNoReparsePointsWindows(snapshot._snapshotRoot);
                snapshot.InputPaths = staged;
                return snapshot;
            }
            catch
            {
                snapshot.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Drops duplicates and inputs already covered by a selected directory,
        /// so one object is never mirrored twice under two names.
        /// </summary>
        private static string[] NormalizeSnapshotSources(IReadOnlyList<string> inputPaths)
        {
            string[] distinct = inputPaths
                .Select(Path.GetFullPath)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            return distinct
                .Where(source => !distinct.Any(candidate =>
                    !string.Equals(candidate, source, StringComparison.OrdinalIgnoreCase)
                    && Directory.Exists(candidate)
                    && IsPathWithinDirectory(source, candidate)))
                .ToArray();
        }

        private static void ValidateRelativeSnapshotPath(string relative)
        {
            if (string.IsNullOrWhiteSpace(relative)
                || Path.IsPathRooted(relative)
                || string.Equals(relative, ".", StringComparison.Ordinal)
                || relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                    .Any(component => string.Equals(component, "..", StringComparison.Ordinal)))
            {
                throw new IOException("An input path escapes the secure snapshot root.");
            }
        }

        private void EnsureWithinSnapshot(string path)
        {
            string prefix = Path.TrimEndingDirectorySeparator(_snapshotRoot) + Path.DirectorySeparatorChar;
            if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                throw new IOException("An input snapshot path escapes its private root.");
            }
        }

        private void MirrorDirectoryTree(string sourceDirectory, string destinationDirectory)
        {
            Directory.CreateDirectory(destinationDirectory);
            var pending = new Stack<(string Source, string Destination)>();
            pending.Push((sourceDirectory, destinationDirectory));
            while (pending.Count > 0)
            {
                (string currentSource, string currentDestination) = pending.Pop();

                // The handle stays open for the whole enumeration of this
                // directory, and it is the handle - not the path - that had to
                // prove it is a real, non-reparse directory reachable under the
                // name we walked to.
                using SafeFileHandle directory = OpenDirectoryNoFollow(currentSource);
                foreach (string entry in Directory.EnumerateFileSystemEntries(currentSource))
                {
                    string name = Path.GetFileName(entry);
                    if (string.IsNullOrEmpty(name) || name is "." or "..")
                    {
                        throw new IOException($"Die Eingabe enthält einen unzulässigen Verzeichniseintrag: {entry}");
                    }

                    string destinationEntry = Path.GetFullPath(Path.Combine(currentDestination, name));
                    EnsureWithinSnapshot(destinationEntry);

                    FileAttributes attributes = File.GetAttributes(entry);
                    if ((attributes & FileAttributes.ReparsePoint) != 0)
                    {
                        throw new IOException($"Die Eingabe enthält einen symbolischen Link oder Reparse Point: {entry}");
                    }

                    if ((attributes & FileAttributes.Directory) != 0)
                    {
                        Directory.CreateDirectory(destinationEntry);
                        pending.Push((entry, destinationEntry));
                    }
                    else
                    {
                        MirrorFile(entry, destinationEntry);
                    }
                }
            }
        }

        /// <summary>
        /// Opens one directory without following a final reparse point and
        /// proves the handle really is the directory the walk meant.
        /// </summary>
        /// <remarks>
        /// The sharing mode is deliberately permissive: the handle is an
        /// identity proof, not a lock. What makes the result trustworthy is the
        /// final-path comparison, which also catches a junction swapped into an
        /// ancestor after the walk passed through it.
        /// </remarks>
        private static SafeFileHandle OpenDirectoryNoFollow(string directoryPath)
        {
            string fullPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directoryPath));
            SafeFileHandle handle = CreateFile(
                fullPath,
                FileListDirectory | FileReadAttributes,
                ShareRead | ShareWrite | ShareDelete,
                nint.Zero,
                OpenExisting,
                FileFlagBackupSemantics | FileFlagOpenReparsePoint,
                nint.Zero);
            if (handle.IsInvalid)
            {
                int error = Marshal.GetLastPInvokeError();
                handle.Dispose();
                throw new IOException(
                    $"Das Eingabeverzeichnis konnte nicht gebunden geöffnet werden: {fullPath}",
                    new Win32Exception(error));
            }

            try
            {
                ByHandleFileInformation information = GetFileInformationOrThrow(handle, fullPath);
                if ((information.FileAttributes & FileAttributeReparsePoint) != 0)
                {
                    throw new IOException($"Die Eingabe enthält einen symbolischen Link oder Reparse Point: {fullPath}");
                }

                if ((information.FileAttributes & FileAttributeDirectory) == 0)
                {
                    throw new IOException($"Der Eingabepfad ist kein Verzeichnis: {fullPath}");
                }

                string resolvedPath = Path.TrimEndingDirectorySeparator(
                    NativePathResolver.ResolveFinalDosPath(handle));
                if (!PathsEqual(fullPath, resolvedPath))
                {
                    throw new IOException(
                        $"Das Eingabeverzeichnis wird über einen Reparse Point aufgelöst: {fullPath} -> {resolvedPath}");
                }

                return handle;
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Leases one input file and mirrors it into the private snapshot.
        /// </summary>
        private void MirrorFile(string sourceFile, string destinationFile)
        {
            FileStream? lease = null;
            try
            {
                lease = AcquireVerifiedFileLease(sourceFile);
                FileStream owned = lease;
                lease = null;

                // Registered before the mirror is built, so a failure below
                // still hands the lease to Dispose instead of leaking it.
                var entry = new SnapshotFile(owned, destinationFile);
                _files.Add(entry);

                // A hard link shares one file record with the original, so its
                // read-only flag cannot be cleared for cleanup without changing
                // the user's file. Read-only inputs therefore take the copy
                // path, which owns its own record.
                ByHandleFileInformation information = GetFileInformationOrThrow(owned.SafeFileHandle, sourceFile);
                bool readOnlySource = ((FileAttributes)information.FileAttributes & FileAttributes.ReadOnly) != 0;
                if (readOnlySource || !TryCreateVerifiedHardLink(sourceFile, destinationFile, owned))
                {
                    CopyFromLease(owned, destinationFile);
                    if (readOnlySource)
                    {
                        File.SetAttributes(destinationFile, File.GetAttributes(destinationFile) | FileAttributes.ReadOnly);
                        _readOnlyCopies.Add(destinationFile);
                    }
                }
                else
                {
                    entry.IsHardLink = true;
                }
            }
            finally
            {
                lease?.Dispose();
            }
        }

        /// <summary>
        /// Opens an input file so that it cannot be replaced, renamed, deleted
        /// or written while it is archived, and proves the path did not resolve
        /// through a link.
        /// </summary>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The stream is returned to the caller, which transfers it into the lease list; every failing path disposes it here.")]
        private static FileStream AcquireVerifiedFileLease(string filePath)
        {
            FileAttributes attributes = File.GetAttributes(filePath);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new IOException($"Die Eingabedatei ist ein Reparse Point oder symbolischer Link: {filePath}");
            }

            FileStream? stream = null;
            try
            {
                // FileShare.Read keeps every other writer out for as long as
                // the lease is held. FileShare.Delete is added so that this
                // process can unlink the snapshot's hard link - a second name
                // for the same file record - while the lease is still blocking
                // writes. Without it the snapshot names could only be removed
                // after the leases were closed, and in that window a hard link
                // to the user's file would sit unprotected in a directory
                // another process can reach.
                stream = new FileStream(
                    filePath, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
                _ = NativePathResolver.RequireCanonicalFilePath(stream.SafeFileHandle, filePath, "ZPAQ input");
                FileStream leased = stream;
                stream = null;
                return leased;
            }
            finally
            {
                stream?.Dispose();
            }
        }

        /// <summary>
        /// Hard-links the leased file into the snapshot and proves the new name
        /// really refers to the leased file record.
        /// </summary>
        /// <returns>
        /// false when the volume cannot provide a hard link at all, which is the
        /// only case the caller may answer with a copy. A link that appears but
        /// names a different object is an attack, not a limitation, and throws.
        /// </returns>
        private static bool TryCreateVerifiedHardLink(string sourceFile, string destinationFile, FileStream lease)
        {
            if (!CreateHardLink(destinationFile, sourceFile, nint.Zero))
            {
                return false;
            }

            try
            {
                using SafeFileHandle linked = CreateFile(
                    destinationFile,
                    FileReadAttributes,
                    ShareRead | ShareWrite | ShareDelete,
                    nint.Zero,
                    OpenExisting,
                    FileFlagOpenReparsePoint,
                    nint.Zero);
                if (linked.IsInvalid)
                {
                    throw new IOException(
                        $"Die gebundene Kopie konnte nicht geprüft werden: {destinationFile}",
                        new Win32Exception(Marshal.GetLastPInvokeError()));
                }

                ByHandleFileInformation linkInformation = GetFileInformationOrThrow(linked, destinationFile);
                ByHandleFileInformation sourceInformation = GetFileInformationOrThrow(lease.SafeFileHandle, sourceFile);
                if (linkInformation.VolumeSerialNumber != sourceInformation.VolumeSerialNumber
                    || linkInformation.FileIndexHigh != sourceInformation.FileIndexHigh
                    || linkInformation.FileIndexLow != sourceInformation.FileIndexLow)
                {
                    throw new IOException(
                        $"Die gebundene Kopie verweist nicht auf die geprüfte Eingabedatei: {sourceFile}");
                }

                return true;
            }
            catch
            {
                TryDeleteSnapshotFile(destinationFile);
                throw;
            }
        }

        /// <summary>
        /// Copies the bytes out of the already verified handle, never off the
        /// path, for volumes that cannot hard-link.
        /// </summary>
        private static void CopyFromLease(FileStream lease, string destinationFile)
        {
            lease.Position = 0;
            try
            {
                using (var destination = new FileStream(destinationFile, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    lease.CopyTo(destination);
                }

                ByHandleFileInformation information = GetFileInformationOrThrow(lease.SafeFileHandle, destinationFile);
                File.SetLastWriteTimeUtc(destinationFile, FileTimeToUtc(information.LastWriteTimeHigh, information.LastWriteTimeLow));
            }
            finally
            {
                lease.Position = 0;
            }
        }

        private static DateTime FileTimeToUtc(uint high, uint low)
        {
            long fileTime = ((long)high << 32) | low;
            return fileTime <= 0 ? DateTime.UnixEpoch : DateTime.FromFileTimeUtc(fileTime);
        }

        private static ByHandleFileInformation GetFileInformationOrThrow(SafeFileHandle handle, string path)
        {
            if (!GetFileInformationByHandle(handle, out ByHandleFileInformation information))
            {
                throw new IOException(
                    $"Die Dateiidentität konnte nicht gelesen werden: {path}",
                    new Win32Exception(Marshal.GetLastPInvokeError()));
            }

            return information;
        }

        private static void TryDeleteSnapshotFile(string path)
        {
            try
            {
                File.Delete(path);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        /// <summary>
        /// Removes the private mirror, retrying briefly because the usual
        /// reason this fails is a scanner or an indexer holding a handle for a
        /// moment, not a permanent condition.
        /// </summary>
        private static void TryDeletePrivateTree(string path)
        {
            for (int attempt = 0; ; attempt++)
            {
                try
                {
                    if (Directory.Exists(path))
                    {
                        Directory.Delete(path, recursive: true);
                    }

                    return;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    if (attempt >= 4)
                    {
                        return;
                    }

                    Thread.Sleep(50 * (attempt + 1));
                }
            }
        }

        private sealed class SnapshotFile(FileStream lease, string destination)
        {
            internal FileStream Lease { get; } = lease;

            internal string Destination { get; } = destination;

            /// <summary>
            /// True when the snapshot name shares the user's file record, so
            /// removing that name is what ends the second path to it.
            /// </summary>
            internal bool IsHardLink { get; set; }
        }

        /// <summary>
        /// How many leases this process is still holding because their snapshot
        /// hard link could not be removed. Anything above zero is a cleanup
        /// failure worth investigating, not normal operation.
        /// </summary>
        internal static int RetainedLeaseCount
        {
            get
            {
                lock (RetainedLeases)
                {
                    return RetainedLeases.Count;
                }
            }
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;

            // Order matters. The snapshot's hard links name the same file
            // records as the user's originals, so they are removed first,
            // while the leases still deny every other writer. Only then are
            // the leases released. Reversing this leaves writable second names
            // for the user's files in a directory this process no longer
            // guards.
            foreach (string copy in _readOnlyCopies)
            {
                try
                {
                    if (File.Exists(copy))
                    {
                        File.SetAttributes(copy, File.GetAttributes(copy) & ~FileAttributes.ReadOnly);
                    }
                }
                catch (IOException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                }
            }

            _readOnlyCopies.Clear();
            TryDeletePrivateTree(_snapshotRoot);

            for (int index = _files.Count - 1; index >= 0; index--)
            {
                SnapshotFile file = _files[index];

                // A snapshot hard link that survived the cleanup is a second,
                // writable name for the user's file, and this lease is the only
                // thing still denying writes through it. Closing it now would
                // reopen exactly the window the cleanup order exists to close,
                // silently. Holding a handle until the process exits is the
                // cheaper of the two failures, so the lease is retained instead
                // of released - and counted, so it cannot pass unnoticed.
                if (file.IsHardLink && File.Exists(file.Destination))
                {
                    lock (RetainedLeases)
                    {
                        RetainedLeases.Add(file.Lease);
                    }

                    continue;
                }

                file.Lease.Dispose();
            }

            _files.Clear();
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ByHandleFileInformation
        {
            public uint FileAttributes;
            public uint CreationTimeLow;
            public uint CreationTimeHigh;
            public uint LastAccessTimeLow;
            public uint LastAccessTimeHigh;
            public uint LastWriteTimeLow;
            public uint LastWriteTimeHigh;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
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

        [LibraryImport("kernel32.dll", EntryPoint = "CreateHardLinkW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool CreateHardLink(
            string fileName,
            string existingFileName,
            nint securityAttributes);
    }
#endif

}
