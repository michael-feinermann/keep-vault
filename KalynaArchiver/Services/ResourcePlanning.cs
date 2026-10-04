using System.Diagnostics;
using System.Runtime.InteropServices;

namespace KalynaArchiver.Services;

public enum ResourceMode { Auto, Manual }

/// <summary>Persistable user intent. Resolved observations must never be saved here.</summary>
public sealed record ResourcePreferences
{
    public ResourceMode CpuMode { get; init; }
    public int? ManualCpuLimit { get; init; }
    public ResourceMode MemoryMode { get; init; }
    public long? ManualMemoryLimitBytes { get; init; }
    public ResourceMode IoMode { get; init; }
    public int? ManualIoLimit { get; init; }
    public ResourceMode QueueMode { get; init; }
    public int? ManualQueueLimit { get; init; }
    public string? WorkingDirectory { get; init; }
    public long? MaxContainerBytes { get; init; }
    public long? MaxExtractedTotalBytes { get; init; }
    public long? MaxSingleFileBytes { get; init; }
    public long? MaxRecoveryBytes { get; init; }
    public long? MaxMetadataBytes { get; init; }
    public long? MaxEntryCount { get; init; }

    public void Validate()
    {
        if (!Enum.IsDefined(CpuMode) || !Enum.IsDefined(MemoryMode) || !Enum.IsDefined(IoMode) || !Enum.IsDefined(QueueMode)
            || (CpuMode == ResourceMode.Manual && ManualCpuLimit is not >= 1)
            || (MemoryMode == ResourceMode.Manual && ManualMemoryLimitBytes is not >= (16L << 20))
            || (IoMode == ResourceMode.Manual && ManualIoLimit is not >= 1)
            || (QueueMode == ResourceMode.Manual && ManualQueueLimit is not >= 1))
            throw new ArgumentException("Invalid manual resource preference.");
        if (MaxContainerBytes is <= 0 || MaxExtractedTotalBytes is <= 0 || MaxSingleFileBytes is <= 0
            || MaxRecoveryBytes is <= 0 || MaxMetadataBytes is <= 0 || MaxEntryCount is <= 0 or > int.MaxValue)
            throw new ArgumentException("Explicit size permissions must be positive and bounded.");
        if (WorkingDirectory is not null && !Path.IsPathFullyQualified(WorkingDirectory))
            throw new ArgumentException("An explicitly selected working directory must be absolute.");
    }
}

internal enum MemoryPressure { Normal, Elevated, Critical }
internal sealed record ResourceObservation(int AvailableCpuWorkers, long PhysicalMemoryBytes,
    long ProcessLimitBytes, long ProcessResidentBytes, long ReclaimableMemoryBytes,
    MemoryPressure Pressure, bool Reliable);
internal sealed record PhaseResourceDemand(long MandatoryBytes, long ReadyBytes = 0, int ReadyWorkers = 1,
    int PreviousSlots = 1, int HealthySamples = 0, bool ThroughputImproved = false,
    bool ThroughputRegressed = false, int? RequestedSlots = null);

/// <summary>Public, non-secret resolved information. No credential-dependent matrix sizes.</summary>
public sealed record ResolvedOperationPlan(int EffectiveCpuCeiling, int ActiveSlots, int IoRequests,
    long MemoryCeilingBytes, long MandatoryBytes, long ResidentIndexTargetBytes, string ThrottleReason)
{
    public const int PlannerRevision = 12;
    public long ApprovedOutputLimit { get; init; }
    public long? ExpectedOutputBytes { get; init; }
    public string ExpectedOutputOrigin { get; init; } = "unknown";
    public int MaximumAdmittedSlots { get; init; } = 1;
}

internal enum AdaptiveWindowReason
{
    InitialCold, ProvenLongStreamStart, Retained, IncompleteBatch, ProbeStarted, ProbePending, ProbeAccepted,
    ProbeRejectedLoss, ProbeRejectedNoBenefit, RejectedWindowHeld, InvalidRate,
    ThroughputRegression, ResourceBound, FixedRequest,
}

internal readonly record struct AdaptiveWindowDecision(int RequestedSlots, AdaptiveWindowReason Reason);

/// <summary>
/// Joined, complete batches only. A probe keeps the accepted window's rate;
/// its own slower rate can never become the comparison baseline by reset.
/// All state is bounded scalars and cannot grant resource authority.
/// </summary>
internal struct AdaptiveChunkWindow
{
    private int _acceptedSlots;
    private double _acceptedRate;
    private double _previousRate;
    private int _healthySamples;
    private double _sample1, _sample2, _sample3;
    private int _probeSlots;
    private double _probeBaseline;
    private int _probeSamples;
    private int _rejectedSlots;
    private bool _startupComplete;

    internal readonly int AcceptedSlots => Math.Max(1, _acceptedSlots);
    internal readonly int ProbeSlots => _probeSlots;
    internal readonly int RejectedSlots => _rejectedSlots;
    internal readonly double AcceptedRate => _acceptedRate;
    internal readonly bool IsCold => !_startupComplete;

    internal readonly AdaptiveWindowDecision RequestProvenLongStreamStart() =>
        new(IsCold ? 2 : AcceptedSlots, IsCold ? AdaptiveWindowReason.ProvenLongStreamStart : AdaptiveWindowReason.Retained);

    internal AdaptiveWindowDecision Observe(int currentSlots, double rate, bool completeBatch, bool allowProbe)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(currentSlots, 1);
        if (_acceptedSlots == 0) _acceptedSlots = currentSlots;
        if (currentSlots != (_probeSlots > 0 ? _probeSlots : _acceptedSlots)) ApplyResolvedWindow(currentSlots);
        if (!completeBatch) return new(currentSlots, AdaptiveWindowReason.IncompleteBatch);
        if (!double.IsFinite(rate) || rate <= 0)
        {
            if (_probeSlots > 0) return RejectProbe(AdaptiveWindowReason.InvalidRate);
            ResetAccepted(Math.Max(1, currentSlots - 1));
            return new(_acceptedSlots, AdaptiveWindowReason.InvalidRate);
        }
        // Initial one-slot work is provisional. It supplies no accepted rate
        // for the first proven longer-stream two-slot policy value.
        if (IsCold && currentSlots == 1) return new(1, AdaptiveWindowReason.Retained);
        if (_probeSlots > 0)
        {
            if (rate <= _probeBaseline * 0.90) return RejectProbe(AdaptiveWindowReason.ProbeRejectedLoss);
            AddSample(rate);
            if (++_probeSamples < 3) return new(_probeSlots, AdaptiveWindowReason.ProbePending);
            double candidateRate = Median(_sample1, _sample2, _sample3);
            if (candidateRate < _probeBaseline * 1.05)
                return RejectProbe(AdaptiveWindowReason.ProbeRejectedNoBenefit);
            _acceptedSlots = _probeSlots;
            _acceptedRate = candidateRate;
            _previousRate = rate;
            _probeSlots = _probeSamples = _healthySamples = 0;
            return new(_acceptedSlots, AdaptiveWindowReason.ProbeAccepted);
        }
        if (_acceptedRate > 0 && rate <= _acceptedRate * 0.90)
        {
            ResetAccepted(Math.Max(1, currentSlots - 1));
            return new(_acceptedSlots, AdaptiveWindowReason.ThroughputRegression);
        }
        bool healthy = _previousRate == 0 || rate >= _previousRate * 0.95;
        _previousRate = rate;
        if (!healthy) _healthySamples = 0;
        else
        {
            AddSample(rate);
            _healthySamples = Math.Min(3, _healthySamples + 1);
        }
        if (_healthySamples < 3) return new(_acceptedSlots, AdaptiveWindowReason.Retained);
        _acceptedRate = Median(_sample1, _sample2, _sample3);
        if (!allowProbe || currentSlots == int.MaxValue) return new(_acceptedSlots, AdaptiveWindowReason.Retained);
        int candidate = currentSlots + 1;
        if (candidate == _rejectedSlots) return new(_acceptedSlots, AdaptiveWindowReason.RejectedWindowHeld);
        _probeSlots = candidate;
        _probeBaseline = _acceptedRate;
        _probeSamples = _healthySamples = 0;
        return new(candidate, AdaptiveWindowReason.ProbeStarted);
    }

    internal void ApplyResolvedWindow(int slots)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(slots, 1);
        if (slots > 1) _startupComplete = true;
        if (_probeSlots > 0 && slots == _probeSlots) return;
        if (_probeSlots > 0)
        {
            _probeSlots = _probeSamples = _healthySamples = 0;
            _previousRate = 0;
        }
        if (slots != _acceptedSlots)
        {
            // A real admission change invalidates an earlier rejected-window
            // conclusion. A normal probe rollback retains it because the
            // accepted window itself has not changed.
            _rejectedSlots = 0;
            ResetAccepted(slots);
        }
    }

    private AdaptiveWindowDecision RejectProbe(AdaptiveWindowReason reason)
    {
        _rejectedSlots = _probeSlots;
        _probeSlots = _probeSamples = _healthySamples = 0;
        _previousRate = 0;
        return new(_acceptedSlots, reason);
    }
    private void ResetAccepted(int slots)
    {
        _acceptedSlots = slots;
        _acceptedRate = _previousRate = _sample1 = _sample2 = _sample3 = 0;
        _healthySamples = _probeSlots = _probeSamples = 0;
    }
    private void AddSample(double rate) { _sample1 = _sample2; _sample2 = _sample3; _sample3 = rate; }
    private static double Median(double a, double b, double c) => Math.Max(Math.Min(a, b), Math.Min(Math.Max(a, b), c));
}

/// <summary>Pure policy: snapshots are observations, never promises or allocations.</summary>
internal static class ResourcePlanner
{
    internal const long IndexCacheTargetBytes = 16L << 20;
    internal const long OperationBaseBytes = 64L << 10;
    internal const long SlotBytes = 32L << 20;
    internal static long HostCeiling(ResourceObservation observation)
    {
        if (!observation.Reliable || observation.PhysicalMemoryBytes <= 0 || observation.ProcessLimitBytes <= 0)
            throw new IOException("Reliable operating-system memory capacity is unavailable.");
        long limit = Math.Min(observation.PhysicalMemoryBytes, observation.ProcessLimitBytes);
        return checked(limit - Math.Max(128L << 20, limit / 16));
    }

    internal static long AdditionalAdmission(ResourceObservation observation, long pendingBytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(pendingBytes);
        long ceiling = HostCeiling(observation);
        // free_count already contains speculative pages. The observer never adds
        // them twice; inactive pages are a reclaimable estimate, not a guarantee.
        long osReserve = Math.Max(128L << 20, observation.PhysicalMemoryBytes / 32);
        return Math.Max(0, Math.Min(ceiling - observation.ProcessResidentBytes,
            observation.ReclaimableMemoryBytes - osReserve) - pendingBytes);
    }

    internal static ResolvedOperationPlan Resolve(ResourcePreferences preferences,
        ResourceObservation observation, PhaseResourceDemand demand)
    {
        preferences.Validate();
        if (demand.MandatoryBytes < 0 || demand.ReadyBytes < 0 || demand.ReadyWorkers < 1
            || demand.PreviousSlots < 1 || demand.HealthySamples < 0 || demand.RequestedSlots is < 1)
            throw new ArgumentOutOfRangeException(nameof(demand));
        long ceiling = HostCeiling(observation);
        if (preferences.MemoryMode == ResourceMode.Manual)
            ceiling = Math.Min(ceiling, preferences.ManualMemoryLimitBytes!.Value);
        int cpus = Math.Max(1, observation.AvailableCpuWorkers);
        if (preferences.CpuMode == ResourceMode.Manual) cpus = Math.Min(cpus, preferences.ManualCpuLimit!.Value);
        int slots = 1;
        string reason = "minimum-work-window";
        // Admit only concrete ready chunks within the current OS/CPU and RAM
        // observations. These are ceilings, not per-CPU buffer allocations.
        long headroom = Math.Min(ceiling, AdditionalAdmission(observation, 0)) - demand.MandatoryBytes;
        int allowedSlots = (int)Math.Min(cpus, Math.Max(1, headroom / SlotBytes));
        if (preferences.QueueMode == ResourceMode.Manual)
            allowedSlots = Math.Min(allowedSlots, preferences.ManualQueueLimit!.Value);
        if (observation.Pressure == MemoryPressure.Normal && demand.ReadyBytes > (16L << 20))
        {
            long readyChunks = (demand.ReadyBytes - 1) / (16L << 20) + 1;
            allowedSlots = (int)Math.Min(allowedSlots, readyChunks);
            // A stable measured window does not need a new 5% improvement on
            // every batch merely to remain available. Only an explicit
            // regression, pressure, reduced work or an admission cap shrinks it.
            slots = Math.Min(allowedSlots, Math.Max(2, demand.PreviousSlots));
            if (demand.RequestedSlots is int requested)
            {
                slots = Math.Min(allowedSlots, requested);
                reason = "measured-window-request";
            }
            else if (demand.ThroughputRegressed)
            {
                slots = Math.Min(allowedSlots, Math.Max(2, demand.PreviousSlots - 1));
                reason = "throughput-regression";
            }
            // Grow only at a joined phase/chunk boundary after three healthy
            // samples showing useful independent work. Never allocate per CPU.
            else if (demand.HealthySamples >= 3 && demand.ThroughputImproved && slots < allowedSlots)
                slots++;
            if (demand.RequestedSlots is null && !demand.ThroughputRegressed) reason = "ready-work";
        }
        else
        {
            allowedSlots = 1;
            if (observation.Pressure != MemoryPressure.Normal) reason = "memory-pressure";
        }
        int io = slots > 1 ? 2 : 1;
        if (preferences.IoMode == ResourceMode.Manual) io = Math.Min(io, preferences.ManualIoLimit!.Value);
        return new(cpus, slots, io, ceiling, demand.MandatoryBytes, IndexCacheTargetBytes, reason)
            { MaximumAdmittedSlots = allowedSlots };
    }
}

/// <summary>Fresh OS memory observations. Runtime limits are ceilings, not free RAM.</summary>
internal static class PlatformResourceObserver
{
    internal static Func<ResourceObservation>? ObservationForTests;
    internal static ResourceObservation Capture()
    {
        if (Volatile.Read(ref ObservationForTests) is { } seam) return seam();
        long processLimit = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes;
        using Process process = Process.GetCurrentProcess();
        long resident = process.WorkingSet64;
        if (OperatingSystem.IsMacOS()) return CaptureMac(processLimit, resident);
        if (OperatingSystem.IsWindows())
        {
            var status = new MemoryStatus { Length = (uint)Marshal.SizeOf<MemoryStatus>() };
            if (!GlobalMemoryStatusEx(ref status)) throw new IOException("Windows memory observation failed.");
            long physical = checked((long)status.TotalPhysical), free = checked((long)status.AvailablePhysical);
            return new(CpuTopology.AvailableWorkers, physical, processLimit, resident, free, Pressure(free, physical), true);
        }
        throw new IOException("This platform has no reviewed memory capacity observer.");
    }

    private static unsafe ResourceObservation CaptureMac(long processLimit, long resident)
    {
        nuint length = sizeof(ulong);
        if (sysctlbyname("hw.memsize", out ulong physicalValue, ref length, 0, 0) != 0 || length != sizeof(ulong))
            throw new IOException("macOS physical memory observation failed.");
        uint host = mach_host_self();
        try
        {
            if (host_page_size(host, out uint pageSize) != 0 || pageSize == 0)
                throw new IOException("macOS VM page size is unavailable.");
            // HOST_VM_INFO64 revision 1 prefix from the public macOS SDK.
            // Request the latest-sized buffer, consume only documented prefix.
            uint* info = stackalloc uint[128];
            uint count = 128;
            if (host_statistics64(host, HostVmInfo64, info, ref count) != 0 || count < sizeof(DarwinVmStatisticsPrefix) / sizeof(uint))
                throw new IOException("macOS VM capacity observation failed.");
            long physical = checked((long)physicalValue);
            DarwinVmStatisticsPrefix statistics = *(DarwinVmStatisticsPrefix*)info;
            long reclaimable = checked(((long)statistics.FreeCount + statistics.InactiveCount) * pageSize);
            if (reclaimable < 0 || reclaimable > physical) throw new IOException("Invalid macOS VM capacity observation.");
            return new(CpuTopology.AvailableWorkers, physical, processLimit, resident, reclaimable,
                Pressure(reclaimable, physical), true);
        }
        finally { _ = mach_port_deallocate(mach_task_self(), host); }
    }

    private const int HostVmInfo64 = 4; // mach/host_info.h, HOST_VM_INFO64
    // mach/vm_statistics.h, public vm_statistics64 revision-1 prefix. The
    // 64-bit counters require natural 8-byte alignment on both shipped ABIs.
    [StructLayout(LayoutKind.Sequential)]
    private struct DarwinVmStatisticsPrefix
    {
        internal uint FreeCount, ActiveCount, InactiveCount, WireCount;
        internal ulong ZeroFillCount, Reactivations, PageIns, PageOuts, Faults, CowFaults, Lookups, Hits, Purges;
        internal uint PurgeableCount, SpeculativeCount;
        internal ulong Decompressions, Compressions, SwapIns, SwapOuts;
        internal uint CompressorPageCount, ThrottledCount, ExternalPageCount, InternalPageCount;
        internal ulong TotalUncompressedPagesInCompressor;
    }
    internal static int MacVmPrefixBytes => Marshal.SizeOf<DarwinVmStatisticsPrefix>();

    private static MemoryPressure Pressure(long free, long physical) => free < physical / 16
        ? MemoryPressure.Critical : free < physical / 8 ? MemoryPressure.Elevated : MemoryPressure.Normal;
    [DllImport("/usr/lib/libSystem.B.dylib")] private static extern uint mach_host_self();
    [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint = "mach_task_self")] private static extern uint mach_task_self();
    [DllImport("/usr/lib/libSystem.B.dylib")] private static extern int mach_port_deallocate(uint task, uint name);
    [DllImport("/usr/lib/libSystem.B.dylib")] private static extern int host_page_size(uint host, out uint size);
    [DllImport("/usr/lib/libSystem.B.dylib")] private static extern unsafe int host_statistics64(uint host, int flavor, uint* info, ref uint count);
    [DllImport("/usr/lib/libSystem.B.dylib")] private static extern int sysctlbyname([MarshalAs(UnmanagedType.LPUTF8Str)] string name, out ulong value, ref nuint length, nint newValue, nuint newLength);
    [StructLayout(LayoutKind.Sequential)] private struct MemoryStatus
    {
        internal uint Length, Load;
        internal ulong TotalPhysical, AvailablePhysical, TotalPageFile, AvailablePageFile, TotalVirtual, AvailableVirtual, AvailableExtended;
    }
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GlobalMemoryStatusEx(ref MemoryStatus status);
}

/// <summary>Actual bounded writes shared by every operation on a device.</summary>
internal static class OperationVolumeLedger
{
    private static readonly object Gate = new();
    private static readonly Dictionary<string, long> Pending = new(StringComparer.Ordinal);
    internal static long PendingBytes(string identity) { lock (Gate) return Pending.GetValueOrDefault(identity); }
    internal static IDisposable Reserve(string identity, long bytes, Func<long> readFreeBytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(bytes);
        lock (Gate)
        {
            long old = Pending.GetValueOrDefault(identity);
            long total = checked(old + bytes);
            if (readFreeBytes() < ArchiveOperationPolicy.RequiredAdditionalCapacity(total, 0, 0, 0, 0))
                throw new IOException("The bound volume cannot admit this write alongside other outstanding writes.");
            var lease = new WriteLease(identity, bytes);
            Pending[identity] = total;
            return lease;
        }
    }
    private sealed class WriteLease(string identity, long bytes) : IDisposable
    {
        private bool _disposed;
        public void Dispose()
        {
            lock (Gate)
            {
                if (_disposed) return;
                _disposed = true;
                long remaining = Pending[identity] - bytes;
                if (remaining == 0) Pending.Remove(identity); else Pending[identity] = remaining;
            }
        }
    }
}

public sealed class ResourceUsage
{
    private long _leasedMemoryBytes;
    public long LeasedMemoryBytes => Interlocked.Read(ref _leasedMemoryBytes);
    internal void AddMemory(long bytes) => Interlocked.Add(ref _leasedMemoryBytes, bytes);
}
