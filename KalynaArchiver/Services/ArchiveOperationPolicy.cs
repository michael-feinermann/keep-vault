using System.IO;
using System.Threading;

namespace KalynaArchiver.Services;

/// <summary>Trusted, immutable resource decisions. Archive bytes never raise these limits.</summary>
public sealed class ArchiveOperationPolicy
{
    private static readonly AsyncLocal<ArchiveOperationPolicy?> Ambient = new();
    private static readonly Lazy<ArchiveOperationPolicy> Default = new(() => new ArchiveOperationPolicy(
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "KeepVault", "Work"),
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)));

    public ArchiveOperationPolicy(
        string workingDirectory, string outputDirectory,
        long maxContainerBytes = 512L << 30, long maxExtractedTotalBytes = 500L << 30,
        long maxSingleFileBytes = 500L << 30, long maxRecoveryBytes = 1L << 40,
        long maxMetadataBytes = 2L << 30, long maxEntryCount = 500_000,
        long memoryBudgetBytes = 0, int maxCpuWorkers = 0,
        int maxIoRequests = 2, int maxQueuedChunks = 4,
        TimeSpan? wallTimeBudget = null, TimeSpan? cpuTimeBudget = null,
        TimeSpan? noProgressTimeout = null, long? entropyCaptureBudgetBytes = null)
    {
        if (memoryBudgetBytes == 0) memoryBudgetBytes = Math.Min(6L << 30, OperationMemoryBudget.HostMemoryCeilingBytes);
        WorkingDirectory = Path.GetFullPath(workingDirectory);
        OutputDirectory = Path.GetFullPath(outputDirectory);
        if (maxContainerBytes <= 0 || maxExtractedTotalBytes <= 0 || maxSingleFileBytes <= 0
            || maxSingleFileBytes > maxExtractedTotalBytes || maxRecoveryBytes <= 0
            || maxMetadataBytes <= 0 || maxEntryCount <= 0 || maxEntryCount > int.MaxValue)
            throw new ArgumentOutOfRangeException(nameof(maxContainerBytes), "Resource budgets must be positive and the single-file budget must fit the total budget.");
        if (memoryBudgetBytes < (256L << 20) || maxCpuWorkers < 0
            || maxIoRequests < 1 || maxQueuedChunks < 1)
            throw new ArgumentOutOfRangeException(nameof(memoryBudgetBytes), "Invalid bounded memory, worker or queue budget.");
        // Worker contexts are separate from the two 16-MiB buffers per queued
        // chunk. A user-approved ceiling is constrained by the process CPU
        // availability and this operation's memory, never by a fixed core count.
        long slotAndIoBuffers = checked((long)maxQueuedChunks * (32L << 20)
            + (long)maxIoRequests * (2L << 20));
        long memoryWorkerCapacity = (memoryBudgetBytes / 2 - slotAndIoBuffers) / (2L << 20);
        if (memoryWorkerCapacity < 1)
            throw new ArgumentException("Queued chunks and I/O leave no approved worker memory.");
        int availableWorkers = CpuTopology.AvailableWorkers;
        int approvedWorkers = maxCpuWorkers == 0 ? availableWorkers : Math.Min(maxCpuWorkers, availableWorkers);
        MaxCpuWorkers = checked((int)Math.Min(approvedWorkers, memoryWorkerCapacity));
        long boundedBuffers = checked(slotAndIoBuffers + (long)MaxCpuWorkers * (2L << 20));
        if (boundedBuffers > memoryBudgetBytes / 2)
            throw new ArgumentException("Worker and queue buffers exceed half of the operation memory budget.");
        WallTimeBudget = RequireDuration(wallTimeBudget ?? TimeSpan.FromHours(4));
        CpuTimeBudget = RequireDuration(cpuTimeBudget ?? TimeSpan.FromHours(32));
        NoProgressTimeout = RequireDuration(noProgressTimeout ?? TimeSpan.FromMinutes(10));
        MaxContainerBytes = maxContainerBytes;
        MaxExtractedTotalBytes = maxExtractedTotalBytes;
        MaxSingleFileBytes = maxSingleFileBytes;
        MaxRecoveryBytes = maxRecoveryBytes;
        MaxMetadataBytes = maxMetadataBytes;
        MaxEntryCount = maxEntryCount;
        if (memoryBudgetBytes > OperationMemoryBudget.HostMemoryCeilingBytes)
            throw new ArgumentOutOfRangeException(nameof(memoryBudgetBytes), "The operation memory budget exceeds the available process memory ceiling after its operating-system reserve.");
        MemoryBudgetBytes = memoryBudgetBytes;
        EntropyCaptureBudgetBytes = entropyCaptureBudgetBytes ?? memoryBudgetBytes / 8;
        WorkingBufferBudgetBytes = boundedBuffers;
        if (EntropyCaptureBudgetBytes <= 0 || EntropyCaptureBudgetBytes >= memoryBudgetBytes - boundedBuffers)
            throw new ArgumentOutOfRangeException(nameof(entropyCaptureBudgetBytes), "Entropy capture must fit the operation memory budget alongside worker buffers.");
        MaxIoRequests = maxIoRequests;
        MaxQueuedChunks = maxQueuedChunks;
        WorkingVolumeIdentity = GetVolumeIdentity(WorkingDirectory);
        OutputVolumeIdentity = GetVolumeIdentity(OutputDirectory);
    }

    public string WorkingDirectory { get; }
    public string OutputDirectory { get; }
    public string WorkingVolumeIdentity { get; }
    public string OutputVolumeIdentity { get; }
    internal long ReservedExtractionBytes { get; private init; }
    internal string? ReservedExtractionDirectory { get; private init; }
    internal string? ReservedExtractionVolumeIdentity { get; private init; }
    internal long ReservedMetadataBytes { get; private init; }
    private long RemainingMetadataBytes => Math.Max(0, ReservedMetadataBytes - RecoveryMetadataBudget.CurrentReservedBytes);
    public long MaxContainerBytes { get; }
    public long MaxExtractedTotalBytes { get; }
    public long MaxSingleFileBytes { get; }
    public long MaxRecoveryBytes { get; }
    public long MaxMetadataBytes { get; }
    public long MaxEntryCount { get; }
    public long MemoryBudgetBytes { get; }
    public long EntropyCaptureBudgetBytes { get; }
    internal long WorkingBufferBudgetBytes { get; }
    internal long HeavyWorkerMemoryBudgetBytes => checked(MemoryBudgetBytes - EntropyCaptureBudgetBytes - WorkingBufferBudgetBytes);
    internal void RequireKdfMatrixFits(uint memoryKiB)
    {
        long bytes = checked((long)memoryKiB * 1024);
        if (bytes <= 0 || bytes > HeavyWorkerMemoryBudgetBytes)
            throw new IOException("The required Argon2 matrix exceeds the approved memory budget after protected entropy and worker-buffer reservations. Increase the resource budget; KDF parameters are never reduced.");
    }
    public int MaxCpuWorkers { get; }
    public int MaxIoRequests { get; }
    public int MaxQueuedChunks { get; }
    public TimeSpan WallTimeBudget { get; }
    public TimeSpan CpuTimeBudget { get; }
    public TimeSpan NoProgressTimeout { get; }
    public static ArchiveOperationPolicy Current => Ambient.Value ?? Default.Value;

    private ArchiveOperationPolicy(ArchiveOperationPolicy source, string outputDirectory,
        bool reserveExtraction = false, bool reserveMetadata = false)
        : this(source.WorkingDirectory, outputDirectory, source.MaxContainerBytes, source.MaxExtractedTotalBytes,
            source.MaxSingleFileBytes, source.MaxRecoveryBytes, source.MaxMetadataBytes, source.MaxEntryCount,
            source.MemoryBudgetBytes, source.MaxCpuWorkers, source.MaxIoRequests, source.MaxQueuedChunks,
            source.WallTimeBudget, source.CpuTimeBudget, source.NoProgressTimeout, source.EntropyCaptureBudgetBytes)
    {
        ReservedExtractionBytes = reserveExtraction ? MaxExtractedTotalBytes : source.ReservedExtractionBytes;
        ReservedExtractionDirectory = reserveExtraction ? OutputDirectory : source.ReservedExtractionDirectory;
        ReservedExtractionVolumeIdentity = reserveExtraction ? OutputVolumeIdentity : source.ReservedExtractionVolumeIdentity;
        ReservedMetadataBytes = reserveMetadata ? MaxMetadataBytes : source.ReservedMetadataBytes;
    }

    public ArchiveOperationPolicy WithOutputDirectory(string outputDirectory) => new(this, outputDirectory);

    internal ArchiveOperationPolicy ForExtraction(string outputDirectory)
    {
        // Unknown decompressed size is bounded by the explicit trusted budget.
        // The later rename of this staging tree consumes no second U allocation.
        var bound = new ArchiveOperationPolicy(this, outputDirectory, reserveExtraction: true);
        bound.RequireVolumeCapacity(bound.OutputDirectory, bound.OutputVolumeIdentity,
            bound.ReservedBytesOnVolume(bound.OutputVolumeIdentity), workingDirectory: false);
        return bound;
    }

    internal ArchiveOperationPolicy ForRecovery(string outputDirectory)
    {
        // A sidecar/candidate is next to its archive, independently of the
        // eventual extraction destination. Never move an existing U plan.
        var bound = new ArchiveOperationPolicy(this, outputDirectory, reserveMetadata: true);
        bound.RequireVolumeCapacity(bound.WorkingDirectory, bound.WorkingVolumeIdentity,
            bound.ReservedBytesOnVolume(bound.WorkingVolumeIdentity), workingDirectory: true);
        bound.RequireSeparateExtractionCapacity();
        return bound;
    }

    internal static long ReservedBytesForVolume(string volumeIdentity, string workingIdentity,
        string? extractionIdentity, long extractionBytes, long metadataBytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(extractionBytes);
        ArgumentOutOfRangeException.ThrowIfNegative(metadataBytes);
        return checked((volumeIdentity == extractionIdentity ? extractionBytes : 0)
            + (volumeIdentity == workingIdentity ? metadataBytes : 0));
    }

    private long ReservedBytesOnVolume(string volumeIdentity) => ReservedBytesForVolume(
        volumeIdentity, WorkingVolumeIdentity, ReservedExtractionVolumeIdentity,
        ReservedExtractionBytes, RemainingMetadataBytes);

    private void RequireSeparateExtractionCapacity()
    {
        if (ReservedExtractionBytes != 0 && ReservedExtractionVolumeIdentity != WorkingVolumeIdentity)
            RequireVolumeCapacity(ReservedExtractionDirectory!, ReservedExtractionVolumeIdentity!,
                ReservedExtractionBytes, workingDirectory: false);
    }

    /// <summary>Flows one validated policy through managed operations and native argument construction.</summary>
    public IDisposable EnterScope()
    {
        ArchiveOperationPolicy? previous = Ambient.Value;
        Ambient.Value = this;
        return new PolicyScope(previous);
    }

    internal void RequireCaptureCapacity(long length, long indexLength, bool copyInput = true)
    {
        if (length < 0 || indexLength < 0 || length > MaxContainerBytes || indexLength > MaxMetadataBytes)
            throw new IOException("The input or its verification index exceeds the approved operation resource budget.");
        long additional = CaptureAdditionalBytes(length, indexLength, copyInput);
        RequireVolumeCapacity(WorkingDirectory, WorkingVolumeIdentity, additional, workingDirectory: true);
        RequireSeparateExtractionCapacity();
    }

    internal long CaptureAdditionalBytes(long length, long indexLength, bool copyInput)
    {
        if (length < 0 || indexLength < 0) throw new ArgumentOutOfRangeException(nameof(length));
        // The shared metadata budget already includes this capture index.
        long metadata = ReservedMetadataBytes == 0 ? indexLength : RemainingMetadataBytes;
        return checked((copyInput ? length : 0) + ReservedBytesForVolume(WorkingVolumeIdentity,
            WorkingVolumeIdentity, ReservedExtractionVolumeIdentity, ReservedExtractionBytes, metadata));
    }

    internal void RequireOutputCapacity(string directory, long additionalBytes)
    {
        if (additionalBytes < 0) throw new ArgumentOutOfRangeException(nameof(additionalBytes));
        RequireVolumeCapacity(directory, OutputVolumeIdentity,
            checked(additionalBytes + ReservedBytesOnVolume(OutputVolumeIdentity)), workingDirectory: false);
    }

    internal void RequireBoundOutputFileVolume(Microsoft.Win32.SafeHandles.SafeFileHandle fileHandle, long additionalBytes)
    {
        ArgumentNullException.ThrowIfNull(fileHandle);
        ArgumentOutOfRangeException.ThrowIfNegative(additionalBytes);
#if KEEPVAULT_MACOS
        RequireBoundOutputVolume(MacOperationVolume.Inspect(fileHandle), additionalBytes);
#else
        string identity = "volume:" + WindowsSafeFileSystem.GetIdentity(fileHandle).VolumeSerialNumber
            .ToString(System.Globalization.CultureInfo.InvariantCulture);
        if (!string.Equals(identity, OutputVolumeIdentity, StringComparison.Ordinal))
            throw new IOException("The bound output file differs from the approved operation volume.");
        RequireOutputCapacity(OutputDirectory, additionalBytes);
#endif
    }

    internal static long RequiredAdditionalCapacity(long spool, long extraction, long parity, long repair, long metadata)
    {
        if (spool < 0 || extraction < 0 || parity < 0 || repair < 0 || metadata < 0)
            throw new ArgumentOutOfRangeException(nameof(spool));
        return checked(spool + extraction + parity + repair + metadata + (256L << 20));
    }

    internal void RequireRemainingExtractionCapacity(long freeBytes, long writtenBytes)
    {
        if (freeBytes < 0 || writtenBytes < 0) throw new IOException("Invalid extraction capacity measurement.");
        long remaining = Math.Max(0, ReservedExtractionBytes - writtenBytes);
        long needed = RequiredAdditionalCapacity(0, remaining, 0, 0,
            WorkingVolumeIdentity == ReservedExtractionVolumeIdentity ? RemainingMetadataBytes : 0);
        if (freeBytes < needed)
            throw new IOException($"The extraction budget needs {needed} more bytes including reserve; only {freeBytes} remain on the bound volume.");
    }

#if KEEPVAULT_MACOS
    internal void RequireBoundOutputVolume(MacOperationVolume.Info volume, long additionalBytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(additionalBytes);
        if (!string.Equals(volume.Identity, OutputVolumeIdentity, StringComparison.Ordinal))
            throw new IOException("The bound output file differs from the approved operation volume.");
        MacOperationVolume.RequireSupported(volume.Format, volume.Flags);
        long needed = RequiredAdditionalCapacity(additionalBytes, ReservedBytesOnVolume(OutputVolumeIdentity), 0, 0, 0);
        if (volume.AvailableBytes < needed)
            throw new IOException($"The bound output volume needs {needed} additional bytes including extraction, metadata and reserve; only {volume.AvailableBytes} bytes are available.");
    }

    internal void RequireBoundExtractionVolume(MacOperationVolume.Info volume)
    {
        if (!string.Equals(volume.Identity, ReservedExtractionVolumeIdentity ?? OutputVolumeIdentity, StringComparison.Ordinal))
            throw new IOException("The bound extraction staging volume differs from the approved operation volume.");
        MacOperationVolume.RequireSupported(volume.Format, volume.Flags);
        RequireRemainingExtractionCapacity(volume.AvailableBytes, 0);
    }
#endif

    private void RequireVolumeCapacity(string directory, string expectedIdentity, long additionalBytes, bool workingDirectory)
    {
        string path = Path.GetFullPath(directory);
        long free;
#if KEEPVAULT_MACOS
        MacOperationVolume.Info volume = MacOperationVolume.Inspect(path, workingDirectory);
        if (!string.Equals(volume.Identity, expectedIdentity, StringComparison.Ordinal))
            throw new IOException("The approved operation volume is unavailable or has changed.");
        free = volume.AvailableBytes;
#else
        DriveInfo volume = FindVolume(path);
        if (!volume.IsReady || volume.DriveType is DriveType.Network or DriveType.CDRom
            || !string.Equals(GetVolumeIdentity(path), expectedIdentity, StringComparison.Ordinal))
            throw new IOException("The approved output volume is unavailable or has changed.");
        free = volume.AvailableFreeSpace;
#endif
        long needed = RequiredAdditionalCapacity(additionalBytes, 0, 0, 0, 0);
        if (free < needed)
            throw new IOException($"The operation needs {needed} additional bytes on this volume; {free} bytes are available. Select a larger volume or lower the extraction budget in Resources. Existing archives are not counted twice or deleted.");
    }

    internal void RequireWorkingFileVolume(Microsoft.Win32.SafeHandles.SafeFileHandle fileHandle)
    {
#if KEEPVAULT_MACOS
        MacOperationVolume.Info approved = MacOperationVolume.Inspect(WorkingDirectory, workingDirectory: true);
        string identity = MacOperationVolume.Inspect(fileHandle).Identity;
        if (!string.Equals(approved.Identity, identity, StringComparison.Ordinal))
            throw new IOException("The private working file and approved directory are on different volumes.");
#else
        string identity = "volume:" + WindowsSafeFileSystem.GetIdentity(fileHandle).VolumeSerialNumber.ToString(System.Globalization.CultureInfo.InvariantCulture);
#endif
        if (!string.Equals(identity, WorkingVolumeIdentity, StringComparison.Ordinal))
            throw new IOException("The private working file was created on a different volume than the approved operation policy.");
    }

    private static TimeSpan RequireDuration(TimeSpan value) => value > TimeSpan.Zero && value <= TimeSpan.FromDays(3650)
        ? value : throw new ArgumentOutOfRangeException(nameof(value), "An explicit finite positive time budget is required.");

    private static string GetVolumeIdentity(string path)
    {
        string existing = path;
        while (!Directory.Exists(existing))
            existing = Path.GetDirectoryName(existing) ?? throw new DirectoryNotFoundException("The operation volume is unavailable.");
#if KEEPVAULT_MACOS
        using var handle = MacSafeFileSystem.OpenDirectoryHandle(MacSafeFileSystem.ResolveExistingRealPath(existing));
        return "device:" + MacSafeFileSystem.GetIdentity(handle).Device.ToString(System.Globalization.CultureInfo.InvariantCulture);
#else
        using var handle = WindowsSafeFileSystem.OpenDirectoryBound(existing, denyRename: false, requestCreateAccess: false);
        return "volume:" + WindowsSafeFileSystem.GetIdentity(handle).VolumeSerialNumber.ToString(System.Globalization.CultureInfo.InvariantCulture);
#endif
    }

    private static DriveInfo FindVolume(string path) => DriveInfo.GetDrives()
        .Where(drive => path.StartsWith(Path.EndsInDirectorySeparator(drive.Name) ? drive.Name : drive.Name + Path.DirectorySeparatorChar,
            OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal)
            || string.Equals(path, Path.TrimEndingDirectorySeparator(drive.Name), StringComparison.OrdinalIgnoreCase))
        .OrderByDescending(drive => drive.Name.Length).FirstOrDefault()
        ?? throw new IOException("The operation directory does not belong to an available local volume.");

    private sealed class PolicyScope(ArchiveOperationPolicy? previous) : IDisposable
    {
        private bool _disposed;
        public void Dispose()
        {
            if (_disposed) return;
            Ambient.Value = previous;
            _disposed = true;
        }
    }
}
