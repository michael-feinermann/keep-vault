using KalynaArchiver.Services;

internal static class OperationStoragePolicyTests
{
    internal static IReadOnlyList<TestCase> Tests =>
    [
        new("resources.operation-storage-plan", "combined per-volume space budgets and descriptor-bound filesystem approval", RunAsync, TestResource.Light, "Security"),
    ];

    private static Task RunAsync()
    {
        const long reserve = 256L << 20;
        // Existing A and a rename target are deliberately absent: only five
        // simultaneously additional allocations and one reserve are counted.
        Require(ArchiveOperationPolicy.RequiredAdditionalCapacity(11, 23, 37, 41, 53) == reserve + 165,
            "The per-volume plan omitted or duplicated an additional allocation.");
        Require(ArchiveOperationPolicy.RequiredAdditionalCapacity(0, 0, 0, 0, 0) == reserve,
            "The safety reserve is not applied exactly once.");
        Throws<ArgumentOutOfRangeException>(() => ArchiveOperationPolicy.RequiredAdditionalCapacity(1, 1, -1, 1, 1));
        Throws<OverflowException>(() => ArchiveOperationPolicy.RequiredAdditionalCapacity(long.MaxValue, 1, 0, 0, 0));
        // These are abstract device identities, not a claimed multi-mount run.
        Require(ArchiveOperationPolicy.ReservedBytesForVolume("repair", "work", "extract", 23, 53) == 0
            && ArchiveOperationPolicy.ReservedBytesForVolume("work", "work", "extract", 23, 53) == 53
            && ArchiveOperationPolicy.ReservedBytesForVolume("extract", "work", "extract", 23, 53) == 23
            && ArchiveOperationPolicy.ReservedBytesForVolume("shared", "shared", "shared", 23, 53) == 76,
            "Recovery output rebinding moved extraction or metadata onto the wrong device.");
        Require(ArchiveOperationPolicy.ReservedBytesForVolume("work", "work", null, 0, 53) == 53,
            "A missing extraction reservation changed the working metadata budget.");
        Throws<ArgumentOutOfRangeException>(() => ArchiveOperationPolicy.ReservedBytesForVolume("w", "w", "u", -1, 1));
        Throws<OverflowException>(() => ArchiveOperationPolicy.ReservedBytesForVolume("w", "w", "w", long.MaxValue, 1));
        Require(MacOperationVolume.NativeLayoutBytes == 2168, "Darwin statfs ABI width differs from the SDK.");
        foreach (string supported in new[] { "apfs", "hfs" }) MacOperationVolume.RequireSupported(supported, 0x1000);
        foreach ((string format, uint flags) in new[] { ("smbfs", 0u), ("exfat", 0x1000u),
            ("apfs", 0u), ("apfs", 0x1001u), ("apfs", 0x00201000u), ("unknown", 0x1000u) })
            Throws<IOException>(() => MacOperationVolume.RequireSupported(format, flags));
        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string relative in new[] { "Library/CloudStorage/OneDrive/test", "Library/Mobile Documents/test", "Dropbox/test", "OneDrive/test" })
            Throws<IOException>(() => MacOperationVolume.RequireNonCloudWorkingPath(Path.Combine(home, relative)));
        MacOperationVolume.RequireNonCloudWorkingPath(Path.Combine(home, "Dropbox-not-synchronized"));

        string root = Path.Combine(MacSafeFileSystem.ResolveExistingRealPath(Path.GetTempPath()), "keep-vault-storage-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using (BoundFileTransaction descriptor = BoundFileTransaction.CreateNew(
                Path.Combine(root, "descriptor"), 1, FileOptions.RandomAccess))
            {
                var identity = MacSafeFileSystem.GetIdentity(descriptor.Stream.SafeFileHandle);
                foreach (bool enabled in new[] { false, true, false, true })
                {
                    MacSafeFileSystem.SetCloseOnExec(descriptor.Stream.SafeFileHandle, enabled);
                    Require(identity.SameObject(MacSafeFileSystem.GetIdentity(descriptor.Stream.SafeFileHandle)),
                        "Descriptor flag changes switched the held object.");
                }
                descriptor.DeleteBound();
            }
            var policy = new ArchiveOperationPolicy(root, root, maxContainerBytes: 64L << 20,
                maxExtractedTotalBytes: 256L << 20, maxSingleFileBytes: 128L << 20);
            MacOperationVolume.Info actual = MacOperationVolume.Inspect(root, workingDirectory: true);
            Require(actual.Identity == policy.WorkingVolumeIdentity && actual.AvailableBytes > reserve,
                "The held directory's volume and free-space result differ from its approved identity.");
            var extraction = policy.ForExtraction(root);
            Require(extraction.ReservedExtractionBytes == 256L << 20 && policy.ReservedExtractionBytes == 0
                && extraction.ReservedExtractionDirectory == root
                && extraction.ReservedExtractionVolumeIdentity == actual.Identity,
                "The immutable extraction plan was not created independently.");
            extraction.RequireCaptureCapacity(17, 204);
            Require(extraction.CaptureAdditionalBytes(17, 204, true) == (256L << 20) + 221,
                "Capture did not include both the ciphertext copy and extraction allowance.");
            Require(extraction.CaptureAdditionalBytes(17, 204, false) == (256L << 20) + 204,
                "Plain input was incorrectly counted as an additional copy.");
            extraction.RequireBoundExtractionVolume(actual);
            Throws<IOException>(() => extraction.RequireBoundExtractionVolume(actual with { Identity = "device:foreign" }));
            Throws<IOException>(() => extraction.RequireBoundExtractionVolume(actual with { Flags = 0x1001 }));
            long boundOutputNeed = reserve + (256L << 20) + 17;
            extraction.RequireBoundOutputVolume(actual with { AvailableBytes = boundOutputNeed }, 17);
            Throws<IOException>(() => extraction.RequireBoundOutputVolume(actual with { AvailableBytes = boundOutputNeed - 1 }, 17));
            Throws<IOException>(() => extraction.RequireBoundOutputVolume(actual with { Identity = "device:foreign" }, 17));
            Throws<IOException>(() => extraction.RequireBoundOutputVolume(actual with { Flags = 0x1001 }, 17));
            Throws<IOException>(() => extraction.RequireBoundOutputVolume(actual with { Format = "exfat" }, 17));
            Throws<ArgumentOutOfRangeException>(() => extraction.RequireBoundOutputVolume(actual, -1));
            Throws<OverflowException>(() => extraction.RequireBoundOutputVolume(actual, long.MaxValue));
            using (BoundFileTransaction boundOutput = BoundFileTransaction.CreateNew(
                Path.Combine(root, "bound-output"), 1, FileOptions.RandomAccess))
            {
                // A removed name cannot influence the descriptor-based check.
                boundOutput.DeleteBound();
                extraction.RequireBoundOutputFileVolume(boundOutput.Stream.SafeFileHandle, 17);
                Require(boundOutput.Stream.Length == 0, "Output-volume approval wrote to its candidate.");
            }
            using (var staging = new MacExtractionStaging(Path.Combine(root, "output")))
            {
                extraction.RequireBoundExtractionVolume(staging.GetOperationVolume());
                staging.Cleanup();
            }
            extraction.RequireRemainingExtractionCapacity(reserve + (128L << 20), 128L << 20);
            Throws<IOException>(() => extraction.RequireRemainingExtractionCapacity(reserve + (128L << 20) - 1, 128L << 20));
            extraction.RequireRemainingExtractionCapacity(reserve, 256L << 20);
            Throws<IOException>(() => extraction.RequireRemainingExtractionCapacity(reserve - 1, 256L << 20));
            Throws<IOException>(() => policy.RequireCaptureCapacity(0, -1));
            using (RecoveryMetadataBudget.Begin(policy.MaxMetadataBytes))
            {
                var recovery = extraction.ForRecovery(root);
                Require(recovery.ReservedMetadataBytes == policy.MaxMetadataBytes
                    && recovery.ReservedExtractionBytes == extraction.ReservedExtractionBytes,
                    "Recovery dropped the shared output or working-metadata reservation.");
                RecoveryMetadataBudget budget = RecoveryMetadataBudget.Capture(policy.MaxMetadataBytes);
                budget.Reserve(204);
                Require(RecoveryMetadataBudget.CurrentReservedBytes == 204,
                    "Already existing metadata was not available to the remaining-capacity plan.");
                Require(recovery.CaptureAdditionalBytes(17, 204, true)
                    == 17 + (256L << 20) + policy.MaxMetadataBytes - 204,
                    "The capture index or already stored metadata was counted twice.");
                long recoveryOutputNeed = reserve + 37 + (256L << 20) + policy.MaxMetadataBytes - 204;
                recovery.RequireBoundOutputVolume(actual with { AvailableBytes = recoveryOutputNeed }, 37);
                Throws<IOException>(() => recovery.RequireBoundOutputVolume(
                    actual with { AvailableBytes = recoveryOutputNeed - 1 }, 37));
                budget.Release(204);
            }
            string recoveryDirectory = Path.Combine(root, "separate-recovery-output");
            Directory.CreateDirectory(recoveryDirectory);
            try
            {
                ArchiveOperationPolicy recovery = extraction.ForRecovery(recoveryDirectory);
                Require(recovery.OutputDirectory == recoveryDirectory
                    && recovery.OutputVolumeIdentity == MacOperationVolume.Inspect(recoveryDirectory, false).Identity
                    && recovery.ReservedExtractionDirectory == root
                    && recovery.ReservedExtractionVolumeIdentity == extraction.ReservedExtractionVolumeIdentity
                    && extraction.OutputDirectory == root,
                    "Binding the actual recovery directory mutated or moved the existing extraction plan.");
                using (recovery.EnterScope())
                    Require(ArchiveOperationPolicy.Current.OutputDirectory == recoveryDirectory
                        && ArchiveOperationPolicy.Current.ReservedExtractionDirectory == root,
                        "The recovery scope did not retain two independent output-directory decisions.");
                ArchiveOperationPolicy copied = recovery.WithOutputDirectory(root);
                Require(copied.ReservedExtractionDirectory == root
                    && copied.ReservedExtractionVolumeIdentity == extraction.ReservedExtractionVolumeIdentity,
                    "Changing an output preference reassigned a live extraction reservation.");
            }
            finally { Directory.Delete(recoveryDirectory); }
            var impossible = new ArchiveOperationPolicy(root, root,
                maxExtractedTotalBytes: long.MaxValue - reserve, maxSingleFileBytes: 1);
            Throws<IOException>(() => impossible.ForExtraction(root));
            Require(!Directory.EnumerateFileSystemEntries(root).Any(), "A failed capacity plan created output data.");
        }
        finally { Directory.Delete(root); }
        return Task.CompletedTask;
    }

    private static void Require(bool valid, string message) { if (!valid) throw new InvalidOperationException(message); }
    private static void Throws<T>(Action action) where T : Exception
    {
        try { action(); } catch (T) { return; }
        throw new InvalidOperationException("Expected " + typeof(T).Name);
    }
}
