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

    public ArchiveOperationPolicy WithOutputDirectory(string outputDirectory) => new(
        WorkingDirectory, outputDirectory, MaxContainerBytes, MaxExtractedTotalBytes,
        MaxSingleFileBytes, MaxRecoveryBytes, MaxMetadataBytes, MaxEntryCount,
        MemoryBudgetBytes, MaxCpuWorkers, MaxIoRequests, MaxQueuedChunks,
        WallTimeBudget, CpuTimeBudget, NoProgressTimeout, EntropyCaptureBudgetBytes);

    /// <summary>Flows one validated policy through managed operations and native argument construction.</summary>
    public IDisposable EnterScope()
    {
        ArchiveOperationPolicy? previous = Ambient.Value;
        Ambient.Value = this;
        return new PolicyScope(previous);
    }

    internal void RequireCaptureCapacity(long length, long indexLength, bool copyInput = true)
    {
        if (length < 0 || length > MaxContainerBytes || indexLength > MaxMetadataBytes)
            throw new IOException("The input or its verification index exceeds the approved operation resource budget.");
        DriveInfo drive = FindVolume(WorkingDirectory);
        if (!drive.IsReady || drive.DriveType is DriveType.Network or DriveType.CDRom
            || !string.Equals(GetVolumeIdentity(WorkingDirectory), WorkingVolumeIdentity, StringComparison.Ordinal))
            throw new IOException("The approved local working volume is not available.");
        long needed = checked((copyInput ? length : 0) + indexLength + (256L << 20));
        if (drive.AvailableFreeSpace < needed)
            throw new IOException($"The working volume needs {needed} additional bytes for verified input and reserve.");
    }

    internal void RequireOutputCapacity(string directory, long additionalBytes)
    {
        if (additionalBytes < 0) throw new ArgumentOutOfRangeException(nameof(additionalBytes));
        string path = Path.GetFullPath(directory);
        DriveInfo volume = FindVolume(path);
        if (!volume.IsReady || volume.DriveType is DriveType.Network or DriveType.CDRom
            || !string.Equals(GetVolumeIdentity(path), OutputVolumeIdentity, StringComparison.Ordinal))
            throw new IOException("The approved output volume is unavailable or has changed.");
        long needed = checked(additionalBytes + (256L << 20));
        if (volume.AvailableFreeSpace < needed)
            throw new IOException($"The output volume needs {needed} additional bytes including its safety reserve.");
    }

    internal void RequireWorkingFileVolume(Microsoft.Win32.SafeHandles.SafeFileHandle fileHandle)
    {
#if KEEPVAULT_MACOS
        string identity = "device:" + MacSafeFileSystem.GetIdentity(fileHandle).Device.ToString(System.Globalization.CultureInfo.InvariantCulture);
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
