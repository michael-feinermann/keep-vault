using KalynaArchiver.Services;
using System.Security.Cryptography;

internal static class OriginalDeletionCreationTests
{
    internal static IReadOnlyList<TestCase> Tests =>
    [new("deletion.rev11-creation-binding", "pre-creation file/directory identities, topology, bounded inventory and final deletion authority",
        RunAsync, TestResource.ProcessGlobal, "Deletion")];

    private static async Task RunAsync()
    {
        long baseline = OperationMemoryBudget.WorkingReservedBytesForTests;
        string root = Path.Combine(MacSafeFileSystem.ResolveExistingRealPath(Path.GetTempPath()), "keepvault-creation-proof-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            // A sibling archive changes parent metadata, but a selected file's
            // parent identity is stable and a clean verified deletion must work.
            string file = Path.Combine(root, "selected.bin");
            string extracted = Path.Combine(root, "extracted");
            Directory.CreateDirectory(extracted);
            byte[] payload = RandomNumberGenerator.GetBytes(2048);
            await File.WriteAllBytesAsync(file, payload);
            await File.WriteAllBytesAsync(Path.Combine(extracted, "selected.bin"), payload);
            string archive = Path.Combine(root, "archive.kzpaq");
            using (var creation = MacOriginalDeletionService.CaptureCreationSnapshot([file], default))
            {
                Require(OperationMemoryBudget.WorkingReservedBytesForTests > baseline, "Creation inventory has no working-memory ownership.");
                await File.WriteAllBytesAsync(archive, new byte[64]);
                var archiveIdentity = MacOriginalDeletionService.CaptureArchiveIdentity(archive);
                var plain = await MacOriginalDeletionService.VerifyExtractionAsync([file], extracted, null, default);
                Require(plain.Verified && plain.Originals is not null, "Comparison-only fixture did not verify.");
                Require(MacOriginalDeletionService.DeleteOriginals([file], archive, archiveIdentity, plain.Originals!).Count > 0
                    && File.Exists(file), "Comparison without creation snapshot granted deletion.");
                var verified = await MacOriginalDeletionService.VerifyExtractionAsync([file], extracted, null, default, creation);
                Require(verified.Verified && verified.Originals is not null, $"Creation-bound fixture did not verify: {verified.Failure}");
                Require(MacOriginalDeletionService.DeleteOriginals([file], archive, archiveIdentity, verified.Originals!).Count == 0
                    && !File.Exists(file), "Stable selected-file creation identity failed clean deletion.");
            }
            Require(OperationMemoryBudget.WorkingReservedBytesForTests == baseline, "Creation inventory retained working leases.");

            await File.WriteAllBytesAsync(file, payload);
            using (var creation = MacOriginalDeletionService.CaptureCreationSnapshot([file], default))
            {
                DateTime modified = File.GetLastWriteTimeUtc(file);
                File.Move(file, file + ".before");
                await File.WriteAllBytesAsync(file, payload);
                File.SetLastWriteTimeUtc(file, modified);
                var swapped = await MacOriginalDeletionService.VerifyExtractionAsync([file], extracted, null, default, creation);
                Require(!swapped.Verified && File.Exists(file) && File.Exists(file + ".before"),
                    "Identical-byte replacement after creation received verification authority.");
            }
            using (var creation = MacOriginalDeletionService.CaptureCreationSnapshot([file], default))
            {
                var verified = await MacOriginalDeletionService.VerifyExtractionAsync([file], extracted, null, default, creation);
                Require(verified.Verified && verified.Originals is not null, "Pre-delete swap fixture did not verify.");
                DateTime modified = File.GetLastWriteTimeUtc(file);
                File.Move(file, file + ".verified");
                await File.WriteAllBytesAsync(file, payload);
                File.SetLastWriteTimeUtc(file, modified);
                var archiveIdentity = MacOriginalDeletionService.CaptureArchiveIdentity(archive);
                Require(MacOriginalDeletionService.DeleteOriginals([file], archive, archiveIdentity, verified.Originals!).Count > 0
                    && File.Exists(file) && File.Exists(file + ".verified"), "Identical replacement after verification was deleted.");
            }

            string folder = Path.Combine(root, "source-tree");
            string treeExtraction = Path.Combine(root, "tree-extraction");
            Directory.CreateDirectory(Path.Combine(folder, ".hidden", "leer_ä"));
            Directory.CreateDirectory(Path.Combine(treeExtraction, "source-tree", ".hidden", "leer_ä"));
            await File.WriteAllBytesAsync(Path.Combine(folder, "Datei_中.bin"), payload);
            await File.WriteAllBytesAsync(Path.Combine(treeExtraction, "source-tree", "Datei_中.bin"), payload);
            using (var creation = MacOriginalDeletionService.CaptureCreationSnapshot([folder], default))
            {
                var matching = await MacOriginalDeletionService.VerifyExtractionAsync([folder], treeExtraction, null, default, creation);
                Require(matching.Verified, $"Complete empty/Unicode directory tree did not verify: {matching.Failure}");
                Directory.Delete(Path.Combine(treeExtraction, "source-tree", ".hidden", "leer_ä"));
                var missingEmpty = await MacOriginalDeletionService.VerifyExtractionAsync([folder], treeExtraction, null, default, creation);
                Require(!missingEmpty.Verified, "Missing empty extracted directory received verification authority.");
                Directory.CreateDirectory(Path.Combine(treeExtraction, "source-tree", ".hidden", "leer_ä"));
                Directory.Move(folder, folder + ".before");
                Directory.CreateDirectory(Path.Combine(folder, ".hidden", "leer_ä"));
                await File.WriteAllBytesAsync(Path.Combine(folder, "Datei_中.bin"), payload);
                var replaced = await MacOriginalDeletionService.VerifyExtractionAsync([folder], treeExtraction, null, default, creation);
                Require(!replaced.Verified, "Recreated identical source directory adopted new identities.");
            }
            using (var invalid = MacOriginalDeletionService.CaptureCreationSnapshot([file], default))
            {
                invalid.Dispose();
                Require(!(await MacOriginalDeletionService.VerifyExtractionAsync([file], extracted, null, default, invalid)).Verified,
                    "Disposed creation snapshot remained usable.");
            }
            await RejectCommitRaceAsync(root, payload, beforeUnlink: false, changeSameObject: false);
            await RejectCommitRaceAsync(root, payload, beforeUnlink: true, changeSameObject: false);
            await RejectCommitRaceAsync(root, payload, beforeUnlink: true, changeSameObject: true);
            using (var cancel = new CancellationTokenSource())
            {
                cancel.Cancel();
                try { using var ignored = MacOriginalDeletionService.CaptureCreationSnapshot([folder], cancel.Token); throw new Exception("Cancelled inventory proceeded."); }
                catch (OperationCanceledException) { }
            }
            var limited = new ArchiveOperationPolicy(root, root, maxEntryCount: 1);
            using (limited.EnterScope())
            {
                try { using var ignored = MacOriginalDeletionService.CaptureCreationSnapshot([folder], default); throw new Exception("Inventory bypassed entry allowance."); }
                catch (IOException) { }
            }
            Require(OperationMemoryBudget.WorkingReservedBytesForTests == baseline, "Failed/disposed creation inventories retained leases.");
            CryptographicOperations.ZeroMemory(payload);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    private static async Task RejectCommitRaceAsync(string root, byte[] payload, bool beforeUnlink, bool changeSameObject)
    {
        string directory = Path.Combine(root, $"race-{beforeUnlink}-{changeSameObject}");
        string extracted = Path.Combine(directory, "extracted");
        Directory.CreateDirectory(extracted);
        string file = Path.Combine(directory, "original.bin");
        string retained = Path.Combine(directory, "retained.bin");
        string archive = Path.Combine(directory, "archive.kzpaq");
        await File.WriteAllBytesAsync(file, payload);
        await File.WriteAllBytesAsync(Path.Combine(extracted, "original.bin"), payload);
        using var creation = MacOriginalDeletionService.CaptureCreationSnapshot([file], default);
        await File.WriteAllBytesAsync(archive, new byte[64]);
        var archiveIdentity = MacOriginalDeletionService.CaptureArchiveIdentity(archive);
        var verified = await MacOriginalDeletionService.VerifyExtractionAsync([file], extracted, null, default, creation);
        Require(verified.Verified && verified.Originals is not null, "Commit race fixture did not verify.");
        string? changedPath = null;
        Action<string> change = path =>
        {
            changedPath = beforeUnlink
                ? Path.Combine(Directory.GetDirectories(directory, ".keepvault_quarantine_*").Single(), Path.GetFileName(path))
                : path;
            DateTime modified = File.GetLastWriteTimeUtc(changedPath);
            if (changeSameObject)
            {
                using var write = new FileStream(changedPath, FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
                write.WriteByte((byte)(payload[0] ^ 0x80));
                write.Flush(flushToDisk: true);
            }
            else
            {
                File.Move(changedPath, retained);
                File.WriteAllBytes(changedPath, payload);
            }
            File.SetLastWriteTimeUtc(changedPath, modified);
        };
        try
        {
            if (beforeUnlink) MacOriginalDeletionService.TestHookBeforeFinalUnlink = change;
            else MacOriginalDeletionService.TestHookBeforeQuarantineRename = change;
            var failures = MacOriginalDeletionService.DeleteOriginals([file], archive, archiveIdentity, verified.Originals!);
            Require(changedPath is not null && failures.Count > 0 && File.Exists(changedPath),
                "A replaced or modified entry crossed the final deletion boundary.");
            Require(changeSameObject || File.Exists(retained), "Commit race deleted the retained original object.");
        }
        finally
        {
            MacOriginalDeletionService.TestHookBeforeQuarantineRename = null;
            MacOriginalDeletionService.TestHookBeforeFinalUnlink = null;
        }
    }
    private static void Require(bool condition, string message) { if (!condition) throw new Exception(message); }
}
