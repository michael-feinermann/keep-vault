using System.IO;
using System.Threading;

namespace KalynaArchiver.Services;

/// <summary>Trusted, immutable resource decisions. Archive bytes never raise these limits.</summary>
public sealed class ArchiveOperationPolicy
{
    // Read-side bounds derive from the existing v13 usage limit. They authorize
    // parsing only; never allocate or pre-reserve this many RAM/disk bytes.
    public const long DefaultMaxContainerBytes = CryptoUsageBudget.MaximumAuthenticatedBytes + 192;
    public const long DefaultMaxRecoveryBytes = DefaultMaxContainerBytes;
    public const long DefaultMaxMetadataBytes = ((DefaultMaxContainerBytes + (1L << 20) - 1) / (1L << 20)) * 204 * 4;
    public const long DefaultMaxExtractedTotalBytes = 256L << 20;
    private static readonly AsyncLocal<ArchiveOperationPolicy?> Ambient = new();
    private static readonly Lazy<ArchiveOperationPolicy> Default = new(() => new ArchiveOperationPolicy(
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "KeepVault", "Work"),
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)));

    public ArchiveOperationPolicy(
        string workingDirectory, string outputDirectory,
        long maxContainerBytes = DefaultMaxContainerBytes, long maxExtractedTotalBytes = DefaultMaxExtractedTotalBytes,
        long maxSingleFileBytes = 0, long maxRecoveryBytes = DefaultMaxRecoveryBytes,
        long maxMetadataBytes = DefaultMaxMetadataBytes, long maxEntryCount = 500_000,
        long memoryBudgetBytes = 0, int maxCpuWorkers = 0,
        int maxIoRequests = 0, int maxQueuedChunks = 0,
        long? entropyCaptureBudgetBytes = null,
        ResourcePreferences? preferences = null)
    {
        Preferences = preferences ?? new ResourcePreferences
        {
            CpuMode = maxCpuWorkers == 0 ? ResourceMode.Auto : ResourceMode.Manual,
            ManualCpuLimit = maxCpuWorkers == 0 ? null : maxCpuWorkers,
            MemoryMode = memoryBudgetBytes == 0 ? ResourceMode.Auto : ResourceMode.Manual,
            ManualMemoryLimitBytes = memoryBudgetBytes == 0 ? null : memoryBudgetBytes,
            IoMode = maxIoRequests == 0 ? ResourceMode.Auto : ResourceMode.Manual,
            ManualIoLimit = maxIoRequests == 0 ? null : maxIoRequests,
            QueueMode = maxQueuedChunks == 0 ? ResourceMode.Auto : ResourceMode.Manual,
            ManualQueueLimit = maxQueuedChunks == 0 ? null : maxQueuedChunks,
            WorkingDirectory = string.IsNullOrWhiteSpace(workingDirectory) ? null : Path.GetFullPath(workingDirectory),
        };
        Preferences.Validate();
        maxContainerBytes = Preferences.MaxContainerBytes ?? maxContainerBytes;
        maxExtractedTotalBytes = Preferences.MaxExtractedTotalBytes ?? maxExtractedTotalBytes;
        maxSingleFileBytes = Preferences.MaxSingleFileBytes ?? (maxSingleFileBytes == 0
            ? maxExtractedTotalBytes : maxSingleFileBytes);
        maxRecoveryBytes = Preferences.MaxRecoveryBytes ?? maxRecoveryBytes;
        maxMetadataBytes = Preferences.MaxMetadataBytes ?? maxMetadataBytes;
        maxEntryCount = Preferences.MaxEntryCount ?? maxEntryCount;
        WorkingDirectory = Preferences.WorkingDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "KeepVault", "Work");
        OutputDirectory = Path.GetFullPath(outputDirectory);
        if (maxContainerBytes <= 0 || maxExtractedTotalBytes <= 0 || maxSingleFileBytes <= 0
            || maxSingleFileBytes > maxExtractedTotalBytes || maxRecoveryBytes <= 0
            || maxMetadataBytes <= 0 || maxEntryCount <= 0 || maxEntryCount > int.MaxValue)
            throw new ArgumentOutOfRangeException(nameof(maxContainerBytes), "Resource authorizations must be positive and the single-file allowance must fit the total allowance.");
        ResourceObservation observation = PlatformResourceObserver.Capture();
        InitialPlan = ResourcePlanner.Resolve(Preferences, observation, new(ResourcePlanner.OperationBaseBytes))
            with { ApprovedOutputLimit = maxExtractedTotalBytes };
        if (Preferences.MemoryMode == ResourceMode.Manual
            && Preferences.ManualMemoryLimitBytes > ResourcePlanner.HostCeiling(observation))
            throw new ArgumentOutOfRangeException(nameof(memoryBudgetBytes), "The manual memory limit exceeds the process/OS ceiling.");
        MemoryBudgetBytes = InitialPlan.MemoryCeilingBytes;
        MaxCpuWorkers = InitialPlan.EffectiveCpuCeiling;
        MaxIoRequests = InitialPlan.IoRequests;
        MaxQueuedChunks = InitialPlan.ActiveSlots;
        // Permission to retain records, not a blind reservation. Live segments
        // compete with concrete KDF, buffer and child allocations when acquired.
        EntropyCaptureBudgetBytes = entropyCaptureBudgetBytes ?? MemoryBudgetBytes;
        if (EntropyCaptureBudgetBytes <= 0 || EntropyCaptureBudgetBytes > MemoryBudgetBytes)
            throw new ArgumentOutOfRangeException(nameof(entropyCaptureBudgetBytes));
        MaxContainerBytes = maxContainerBytes;
        MaxExtractedTotalBytes = maxExtractedTotalBytes;
        MaxSingleFileBytes = maxSingleFileBytes;
        MaxRecoveryBytes = maxRecoveryBytes;
        MaxMetadataBytes = maxMetadataBytes;
        MaxEntryCount = maxEntryCount;
        _workingVolumeIdentity = new Lazy<string>(BindWorkingVolume);
        OutputVolumeIdentity = GetVolumeIdentity(OutputDirectory);
    }

    public ResourcePreferences Preferences { get; }
    public ResolvedOperationPlan InitialPlan { get; private init; }
    public ResourceUsage Usage { get; private init; } = new();
    public int RequestedCpuWorkers => Preferences.CpuMode == ResourceMode.Auto ? 0 : Preferences.ManualCpuLimit!.Value;
    public long RequestedMemoryBudgetBytes => Preferences.MemoryMode == ResourceMode.Auto ? 0 : Preferences.ManualMemoryLimitBytes!.Value;
    private readonly Lazy<string> _workingVolumeIdentity;

    public string WorkingDirectory { get; }
    public string OutputDirectory { get; }
    public string WorkingVolumeIdentity => _workingVolumeIdentity.Value;
    public string OutputVolumeIdentity { get; }
    internal long ReservedExtractionBytes { get; private init; }
    internal string? ReservedExtractionDirectory { get; private init; }
    internal string? ReservedExtractionVolumeIdentity { get; private init; }
    internal long ReservedMetadataBytes { get; private init; }
    public long MaxContainerBytes { get; }
    public long MaxExtractedTotalBytes { get; }
    public long MaxSingleFileBytes { get; }
    public long MaxRecoveryBytes { get; }
    public long MaxMetadataBytes { get; }
    public long MaxEntryCount { get; }
    public long MemoryBudgetBytes { get; private init; }
    public long EntropyCaptureBudgetBytes { get; private init; }
    internal long WorkingBufferBudgetBytes => ResourcePlanner.OperationBaseBytes;
    internal long HeavyWorkerMemoryBudgetBytes => Math.Max(0, MemoryBudgetBytes - ResourcePlanner.OperationBaseBytes - OperationMemoryBudget.EntropyReservedBytes);
    internal void RequireKdfMatrixFits(uint memoryKiB)
    {
        long bytes = checked((long)memoryKiB * 1024);
        if (bytes <= 0 || bytes > HeavyWorkerMemoryBudgetBytes)
            throw new IOException("The required Argon2 matrix exceeds the approved memory budget alongside the current protected records. Increase the resource allowance; KDF parameters are never reduced.");
    }
    public int MaxCpuWorkers { get; private init; }
    public int MaxIoRequests { get; private init; }
    public int MaxQueuedChunks { get; private init; }
    public static ArchiveOperationPolicy Current => Ambient.Value ?? Default.Value;

    private ArchiveOperationPolicy(ArchiveOperationPolicy source, string outputDirectory,
        bool reserveExtraction = false, bool reserveMetadata = false, ResourcePreferences? preferences = null)
        : this(source.WorkingDirectory, outputDirectory, source.MaxContainerBytes, source.MaxExtractedTotalBytes,
            source.MaxSingleFileBytes, source.MaxRecoveryBytes, source.MaxMetadataBytes, source.MaxEntryCount,
            entropyCaptureBudgetBytes: source.EntropyCaptureBudgetBytes == source.MemoryBudgetBytes ? null : source.EntropyCaptureBudgetBytes,
            preferences: preferences ?? source.Preferences)
    {
        // An authorization is never a concrete disk reservation.
        ReservedExtractionBytes = source.ReservedExtractionBytes;
        ReservedExtractionDirectory = reserveExtraction ? OutputDirectory : source.ReservedExtractionDirectory;
        ReservedExtractionVolumeIdentity = reserveExtraction ? OutputVolumeIdentity : source.ReservedExtractionVolumeIdentity;
        ReservedMetadataBytes = source.ReservedMetadataBytes;
        Usage = source.Usage;
    }

    public ArchiveOperationPolicy WithOutputDirectory(string outputDirectory) => new(this, outputDirectory);
    public ArchiveOperationPolicy WithPreferences(ResourcePreferences preferences)
        => new(WorkingDirectory, OutputDirectory, preferences: preferences);
    internal ArchiveOperationPolicy ForPhase(PhaseResourceDemand demand)
    {
        ResolvedOperationPlan plan = ResourcePlanner.Resolve(Preferences, PlatformResourceObserver.Capture(), demand)
            with { ApprovedOutputLimit = MaxExtractedTotalBytes };
        long entropyLimit = EntropyCaptureBudgetBytes == MemoryBudgetBytes ? plan.MemoryCeilingBytes : EntropyCaptureBudgetBytes;
        if (entropyLimit > plan.MemoryCeilingBytes)
            throw new IOException("The approved record allowance exceeds the current process memory ceiling.");
        return new(this, OutputDirectory)
        {
            InitialPlan = plan, MaxQueuedChunks = plan.ActiveSlots, MaxIoRequests = plan.IoRequests,
            MemoryBudgetBytes = plan.MemoryCeilingBytes, MaxCpuWorkers = plan.EffectiveCpuCeiling,
            EntropyCaptureBudgetBytes = entropyLimit,
        };
    }
    internal ArchiveOperationPolicy ForExtraction(string outputDirectory) => new(this, outputDirectory, reserveExtraction: true);
    internal ArchiveOperationPolicy ForRecovery(string outputDirectory) => new(this, outputDirectory, reserveMetadata: true);

    internal static long ReservedBytesForVolume(string volumeIdentity, string workingIdentity,
        string? extractionIdentity, long extractionBytes, long metadataBytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(extractionBytes);
        ArgumentOutOfRangeException.ThrowIfNegative(metadataBytes);
        return checked((volumeIdentity == extractionIdentity ? extractionBytes : 0)
            + (volumeIdentity == workingIdentity ? metadataBytes : 0));
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
        if (additional > 0) RequireVolumeCapacity(WorkingDirectory, WorkingVolumeIdentity, additional, workingDirectory: true);
    }

    internal long CaptureAdditionalBytes(long length, long indexLength, bool copyInput)
    {
        if (length < 0 || indexLength < 0) throw new ArgumentOutOfRangeException(nameof(length));
        return checked((copyInput ? length : 0) + indexLength);
    }

    internal void RequireOutputCapacity(string directory, long additionalBytes)
    {
        if (additionalBytes < 0) throw new ArgumentOutOfRangeException(nameof(additionalBytes));
        RequireVolumeCapacity(directory, OutputVolumeIdentity,
            additionalBytes, workingDirectory: false);
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
        long bytes = checked(spool + extraction + parity + repair + metadata);
        // Up to sixteen 4-KiB filesystem blocks cover the directory entry,
        // private transaction and commit bookkeeping of this write window.
        // This is additional headroom, not a promise of an OS disk reservation.
        return bytes == 0 ? 0 : checked(((bytes + 4095) / 4096) * 4096 + (64L << 10));
    }

    internal void RequireRemainingExtractionCapacity(long freeBytes, long writtenBytes)
    {
        if (freeBytes < 0 || writtenBytes < 0) throw new IOException("Invalid extraction capacity measurement.");
        if (writtenBytes > MaxExtractedTotalBytes)
            throw new IOException("The extracted output exceeds its explicit finite authorization.");
        // Unknown expansion is checked by the native writer against its finite
        // byte allowance; do not invent a whole-output free-space requirement.
        long needed = RequiredAdditionalCapacity(Math.Min(64L << 10, MaxExtractedTotalBytes - writtenBytes),
            0, 0, 0, 0);
        if (freeBytes < checked(needed + OperationVolumeLedger.PendingBytes(ReservedExtractionVolumeIdentity ?? OutputVolumeIdentity)))
            throw new IOException("The bound extraction volume cannot admit its next write window.");
    }

#if KEEPVAULT_MACOS
    internal void RequireBoundOutputVolume(MacOperationVolume.Info volume, long additionalBytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(additionalBytes);
        if (!string.Equals(volume.Identity, OutputVolumeIdentity, StringComparison.Ordinal))
            throw new IOException("The bound output file differs from the approved operation volume.");
        MacOperationVolume.RequireSupported(volume.Format, volume.Flags);
        long needed = RequiredAdditionalCapacity(checked(additionalBytes + OperationVolumeLedger.PendingBytes(OutputVolumeIdentity)), 0, 0, 0, 0);
        if (volume.AvailableBytes < needed)
            throw new IOException($"The bound output volume needs {needed} additional bytes including outstanding writes and transaction headroom; only {volume.AvailableBytes} bytes are available.");
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
        long needed = RequiredAdditionalCapacity(checked(additionalBytes + OperationVolumeLedger.PendingBytes(expectedIdentity)), 0, 0, 0, 0);
        if (free < needed)
            throw new IOException($"The operation needs {needed} additional bytes on this volume; {free} bytes are available. Select a volume with room for the actual pending output. Existing archives are not counted twice or deleted.");
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

    internal IDisposable ReserveOutputWrite(Microsoft.Win32.SafeHandles.SafeFileHandle handle, long bytes)
        => ReserveBoundWrite(handle, bytes, OutputVolumeIdentity, OutputDirectory);

    internal IDisposable ReserveWorkingWrite(Microsoft.Win32.SafeHandles.SafeFileHandle handle, long bytes)
        => ReserveBoundWrite(handle, bytes, WorkingVolumeIdentity, WorkingDirectory);

    private IDisposable ReserveBoundWrite(Microsoft.Win32.SafeHandles.SafeFileHandle handle, long bytes,
        string expectedIdentity, string directory)
    {
#if KEEPVAULT_MACOS
        return OperationVolumeLedger.Reserve(expectedIdentity, bytes, () =>
        {
            MacOperationVolume.Info volume = MacOperationVolume.Inspect(handle);
            if (volume.Identity != expectedIdentity) throw new IOException("The bound write volume changed.");
            return volume.AvailableBytes;
        });
#else
        return OperationVolumeLedger.Reserve(expectedIdentity, bytes, () =>
        {
            string identity = "volume:" + WindowsSafeFileSystem.GetIdentity(handle).VolumeSerialNumber
                .ToString(System.Globalization.CultureInfo.InvariantCulture);
            if (identity != expectedIdentity) throw new IOException("The bound write volume changed.");
            return FindVolume(directory).AvailableFreeSpace;
        });
#endif
    }

    private string BindWorkingVolume()
    {
        if (Preferences.WorkingDirectory is not null && !Directory.Exists(WorkingDirectory))
            throw new DirectoryNotFoundException("The explicitly selected metadata working directory is unavailable.");
        return GetVolumeIdentity(WorkingDirectory);
    }

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
