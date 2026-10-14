using KalynaArchiver.Services;

internal static class OperationStoragePolicyTests
{
    internal static IReadOnlyList<TestCase> Tests =>
    [
        new("resources.operation-storage-plan", "real additional writes, live shared volume ledger and lazy workspace", RunAsync, TestResource.Light, "Security"),
        new("resources.rev11-auto-planner", "persistent Auto, phase slots, real OS observations and pressure hysteresis", PlannerAsync, TestResource.Light, "Resources"),
        new("resources.rev11-chunk-window", "small locked buffers, actual leases, short-read aggregation and exact chunk boundaries", ChunkWindowAsync, TestResource.ProcessGlobal, "Resources"),
        new("zpaq.small-volume-capacity", "64 MiB plain and streaming extraction on private 256 MiB APFS, with real capacity exhaustion", ZpaqExtractionCapacityTests.RunAsync, TestResource.ZpaqGlobal, "ZPAQ"),
    ];

    private static Task PlannerAsync()
    {
        var auto = new ResourcePreferences();
        ResourceObservation large = new(1031, 1L << 40, 1L << 40, 64L << 20, 500L << 30, MemoryPressure.Normal, true);
        ResolvedOperationPlan small = ResourcePlanner.Resolve(auto, large, new(64L << 10, 1024));
        Require(small.ActiveSlots == 1 && small.IoRequests == 1 && small.EffectiveCpuCeiling == 1031,
            "Tiny work created per-core slots or imposed a fixed global CPU cap.");
        var longWork = new PhaseResourceDemand(64L << 10, 256L << 20, ReadyWorkers: 7);
        Require(ResourcePlanner.Resolve(auto, large, longWork).ActiveSlots == 2, "Longer input did not begin with two slots.");
        Require(ResourcePlanner.Resolve(auto, large, longWork with { HealthySamples = 2, ThroughputImproved = true, PreviousSlots = 2 }).ActiveSlots == 2,
            "Insufficient healthy samples bypassed growth hysteresis.");
        Require(ResourcePlanner.Resolve(auto, large, longWork with { HealthySamples = 3, ThroughputImproved = true, PreviousSlots = 2 }).ActiveSlots == 3,
            "Measured beneficial growth was not admitted.");
        Require(ResourcePlanner.Resolve(auto, large with { Pressure = MemoryPressure.Elevated }, longWork).ActiveSlots == 1,
            "Pressure retained optional pipeline slots.");
        foreach (int cpu in new[] { 1, 2, 7, 2049 })
        {
            var manual = auto with { CpuMode = ResourceMode.Manual, ManualCpuLimit = cpu };
            Require(ResourcePlanner.Resolve(manual, large, longWork).EffectiveCpuCeiling == Math.Min(cpu, 1031),
                "Manual CPU authority or topology clamp failed.");
        }
        Throws<IOException>(() => ResourcePlanner.Resolve(auto, large with { Reliable = false }, longWork));
        Require(PlatformResourceObserver.MacVmPrefixBytes == 152, "Darwin VM revision-1 ABI prefix changed.");
        ResourceObservation actual = PlatformResourceObserver.Capture();
        Require(actual.Reliable && actual.PhysicalMemoryBytes > 0 && actual.ReclaimableMemoryBytes >= 0
            && actual.ReclaimableMemoryBytes <= actual.PhysicalMemoryBytes && actual.ProcessResidentBytes > 0,
            "Live macOS observer did not report sane documented OS quantities.");
        string root = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var policy = new ArchiveOperationPolicy("", root, preferences: auto);
        var copy = policy.WithOutputDirectory(root);
        Require(copy.RequestedCpuWorkers == 0 && copy.RequestedMemoryBudgetBytes == 0
            && copy.Preferences == auto && copy.Preferences.WorkingDirectory is null,
            "Resolving or copying persisted effective values as manual preferences.");
        var manualPolicy = policy.WithPreferences(auto with { CpuMode = ResourceMode.Manual, ManualCpuLimit = 1, MaxExtractedTotalBytes = 128L << 20 });
        Require(manualPolicy.MaxCpuWorkers == 1 && manualPolicy.MaxExtractedTotalBytes == 128L << 20,
            "Applying manual preferences did not resolve their independent caps.");
        Require(manualPolicy.WithPreferences(auto).MaxExtractedTotalBytes == 256L << 20,
            "Clearing a manual output cap silently preserved its old effective value.");
        var larger = policy.WithPreferences(auto with { MaxExtractedTotalBytes = 1024L << 20 });
        Require(larger.MaxSingleFileBytes == larger.MaxExtractedTotalBytes,
            "An empty single-file preference did not follow the explicit total allowance.");
        Require(larger.WithPreferences(larger.Preferences with { MaxSingleFileBytes = 4L << 20 }).MaxSingleFileBytes == (4L << 20),
            "An independent explicit single-file allowance was ignored.");
        int observation = 0;
        PlatformResourceObserver.ObservationForTests = () => large with { AvailableCpuWorkers = ++observation == 1 ? 7 : 3 };
        try
        {
            ArchiveOperationPolicy phase = policy.ForPhase(longWork);
            Require(phase.MaxCpuWorkers == phase.InitialPlan.EffectiveCpuCeiling
                && phase.MemoryBudgetBytes == phase.InitialPlan.MemoryCeilingBytes,
                "The phase's published limits differ from its resolved observation.");
        }
        finally { PlatformResourceObserver.ObservationForTests = null; }
        return Task.CompletedTask;
    }

    private static async Task ChunkWindowAsync()
    {
        long baseline = OperationMemoryBudget.WorkingReservedBytesForTests;
        long locked = SecureMemory.LockedAllocationsForTests;
        string path = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var policy = new ArchiveOperationPolicy("", path, memoryBudgetBytes: 128L << 20);
        using (policy.EnterScope())
        {
            foreach (int length in new[] { 1024, (16 << 20) - 1, 16 << 20, (16 << 20) + 1 })
            {
                byte[] data = new byte[length];
                for (int i = 0; i < data.Length; ++i) data[i] = (byte)(i * 17 + 165);
                using var source = new ShortReadStream(data);
                using var slot = new KalynaContainerService.ContainerChunkSlot(1024, 0, 24);
                int first = await KalynaContainerService.ReadChunkAsync(source, slot, 16 << 20, default);
                Require(first == Math.Min(length, 16 << 20) && data.AsSpan(0, first).SequenceEqual(slot.Input.AsSpan(0, first)),
                    "Short reads changed a product chunk or its bytes.");
                slot.EnsureOutputCapacity(first);
                slot.Prepare(0, first);
                if (length == 1024)
                    Require(slot.Input.Length == 1024 && slot.Output.Length == 1024
                        && policy.Usage.LeasedMemoryBytes < 4096, "A tiny complete input allocated a full product chunk.");
                slot.ClearForReuse();
                int last = await KalynaContainerService.ReadChunkAsync(source, slot, 16 << 20, default);
                Require(last == length - first && data.AsSpan(first).SequenceEqual(slot.Input.AsSpan(0, last)),
                    "Exact chunk boundary or actual EOF was lost.");
                Require(slot.Input.Length <= (16 << 20), "A slot exceeded the unchanged product chunk limit.");
            }
        }
        Require(OperationMemoryBudget.WorkingReservedBytesForTests == baseline && SecureMemory.LockedAllocationsForTests == locked,
            "A grown slot retained memory ownership or a sensitive-memory lock.");
    }

    private sealed class ShortReadStream(byte[] bytes) : Stream
    {
        private int _offset;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => _offset; set => throw new NotSupportedException(); }
        public override ValueTask<int> ReadAsync(Memory<byte> destination, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int count = Math.Min(Math.Min(destination.Length, 97 + _offset % 4096), bytes.Length - _offset);
            bytes.AsMemory(_offset, count).CopyTo(destination);
            _offset += count;
            return ValueTask.FromResult(count);
        }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private static Task RunAsync()
    {
        Require(ArchiveOperationPolicy.RequiredAdditionalCapacity(11, 23, 37, 41, 53) == 4096 + (64L << 10),
            "Actual additional bytes were lost, duplicated or charged as maxima.");
        Require(ArchiveOperationPolicy.RequiredAdditionalCapacity(0, 0, 0, 0, 0) == 0,
            "An idle operation reserved phantom disk space.");
        Throws<ArgumentOutOfRangeException>(() => ArchiveOperationPolicy.RequiredAdditionalCapacity(1, 1, -1, 1, 1));
        Throws<OverflowException>(() => ArchiveOperationPolicy.RequiredAdditionalCapacity(long.MaxValue, 1, 0, 0, 0));
        string root = Path.Combine(MacSafeFileSystem.ResolveExistingRealPath(Path.GetTempPath()), "keep-vault-storage-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            Throws<ArgumentOutOfRangeException>(() => new ArchiveOperationPolicy(root, root, maxExtractedTotalBytes: 1, maxSingleFileBytes: 2));
            var policy = new ArchiveOperationPolicy(Path.Combine(root, "missing-workspace"), root,
                maxExtractedTotalBytes: 500L << 30, maxSingleFileBytes: 500L << 30,
                maxRecoveryBytes: 1L << 40, maxMetadataBytes: 2L << 30);
            ArchiveOperationPolicy extraction = policy.ForExtraction(root);
            ArchiveOperationPolicy recovery = extraction.ForRecovery(root);
            Require(extraction.ReservedExtractionBytes == 0 && recovery.ReservedMetadataBytes == 0,
                "Allowed output or metadata maxima became disk reservations.");
            policy.RequireCaptureCapacity(1024, 0, copyInput: false);
            Require(policy.CaptureAdditionalBytes(1024, 204, false) == 204,
                "The original or extraction authorization was counted as an index allocation.");
            Throws<DirectoryNotFoundException>(() => policy.RequireCaptureCapacity(1024, 204, copyInput: false));
            MacOperationVolume.Info actual = MacOperationVolume.Inspect(root, false);
            long need = ArchiveOperationPolicy.RequiredAdditionalCapacity(1024, 0, 0, 0, 0);
            extraction.RequireBoundOutputVolume(actual with { AvailableBytes = need }, 1024);
            Throws<IOException>(() => extraction.RequireBoundOutputVolume(actual with { AvailableBytes = need - 1 }, 1024));
            Throws<IOException>(() => extraction.RequireBoundOutputVolume(actual with { Identity = "foreign" }, 1024));
            Throws<IOException>(() => extraction.RequireBoundOutputVolume(actual with { Flags = 0x1001 }, 1024));
            Throws<IOException>(() => extraction.RequireBoundOutputVolume(actual with { Format = "exfat" }, 1024));
            extraction.RequireRemainingExtractionCapacity(128L << 10, 1024);
            Throws<IOException>(() => extraction.RequireRemainingExtractionCapacity((128L << 10) - 1, 1024));
            Throws<IOException>(() => extraction.RequireRemainingExtractionCapacity(1, 1024));
            Throws<IOException>(() => extraction.RequireRemainingExtractionCapacity(1L << 30, (500L << 30) + 1));
            extraction.RequireRemainingExtractionCapacity(64L << 10, 1024, extractionComplete: true);
            Throws<IOException>(() => extraction.RequireRemainingExtractionCapacity((64L << 10) - 1, 1024, extractionComplete: true));
            extraction.RequireRemainingExtractionCapacity(64L << 10, extraction.MaxExtractedTotalBytes);
            Throws<IOException>(() => extraction.RequireRemainingExtractionCapacity((64L << 10) - 1, extraction.MaxExtractedTotalBytes));
            Throws<IOException>(() => extraction.RequireRemainingExtractionCapacity(-1, 1024, extractionComplete: true));
            Throws<IOException>(() => extraction.RequireRemainingExtractionCapacity(1L << 30, -1, extractionComplete: true));
            Throws<IOException>(() => extraction.RequireRemainingExtractionCapacity(1L << 30, extraction.MaxExtractedTotalBytes + 1, extractionComplete: true));
            // A one-byte outstanding write must reserve its filesystem block;
            // completion releases no other operation's live volume ownership.
            using (OperationVolumeLedger.Reserve(actual.Identity, 1, () => 1L << 30))
            {
                extraction.RequireRemainingExtractionCapacity((64L << 10) + 4096, 1024, extractionComplete: true);
                Throws<IOException>(() => extraction.RequireRemainingExtractionCapacity((64L << 10) + 4095, 1024, extractionComplete: true));
                extraction.RequireRemainingExtractionCapacity((128L << 10) + 4096, 1024);
                Throws<IOException>(() => extraction.RequireRemainingExtractionCapacity((128L << 10) + 4095, 1024));
            }
            long simulatedFree = ArchiveOperationPolicy.RequiredAdditionalCapacity(4096, 0, 0, 0, 0);
            using (OperationVolumeLedger.Reserve("test-volume", 4096, () => simulatedFree))
            {
                Require(OperationVolumeLedger.PendingBytes("test-volume") == 4096, "The live write was not reserved.");
                Throws<IOException>(() => OperationVolumeLedger.Reserve("test-volume", 4096, () => simulatedFree));
                simulatedFree = 0;
                Throws<IOException>(() => OperationVolumeLedger.Reserve("test-volume", 1, () => simulatedFree));
            }
            Require(OperationVolumeLedger.PendingBytes("test-volume") == 0, "Completed/failed writes retained volume reservations.");
            using BoundFileTransaction output = BoundFileTransaction.CreateNew(Path.Combine(root, "result"), 1, FileOptions.RandomAccess);
            using (policy.ReserveOutputWrite(output.Stream.SafeFileHandle, 1024)) output.Stream.Write(new byte[1024]);
            Require(OperationVolumeLedger.PendingBytes(actual.Identity) == 0, "Descriptor write did not release the live volume charge.");
            output.DeleteBound();
            const string capacityFixture = "/Volumes/KEEPVAULT REV11 RESOURCE TEST";
            if (Directory.Exists(capacityFixture))
            {
                string separateWork = Path.Combine(capacityFixture, "rev11-resource-volume-" + Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(separateWork);
                try
                {
                    var split = new ArchiveOperationPolicy(separateWork, root);
                    Require(split.WorkingVolumeIdentity != split.OutputVolumeIdentity, "The named capacity fixture is not a separate device.");
                    using BoundFileTransaction index = BoundFileTransaction.CreateNew(Path.Combine(separateWork, "index"), 1, FileOptions.RandomAccess);
                    Throws<IOException>(() => split.ReserveOutputWrite(index.Stream.SafeFileHandle, 204));
                    using (split.ReserveWorkingWrite(index.Stream.SafeFileHandle, 204)) index.Stream.Write(new byte[204]);
                    index.DeleteBound();
                    Console.WriteLine("separate_working_volume_write=PASS (owned 256-MiB capacity fixture)");
                }
                finally { Directory.Delete(separateWork, recursive: true); }
            }
            else Console.WriteLine("separate_working_volume_write=NOT_RUN (optional owned capacity fixture not mounted)");
        }
        finally { Directory.Delete(root, recursive: true); }
        return Task.CompletedTask;
    }
    private static void Require(bool condition, string message) { if (!condition) throw new Exception(message); }
    private static void Throws<T>(Action action) where T : Exception
    { try { action(); } catch (T) { return; } throw new Exception($"Expected {typeof(T).Name}."); }
}
