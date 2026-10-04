using System.Diagnostics;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using KalynaArchiver.Services;

internal static class ZpaqExtractionCapacityTests
{
    private const long PayloadBytes = 64L << 20;
    private const long ImageBytes = 256L << 20;

    internal static async Task RunAsync()
    {
        string root = MacSafeFileSystem.ResolveExistingRealPath(
            Directory.CreateTempSubdirectory("keep-vault-small-volume-").FullName);
        string mount = Path.Combine(root, "volume");
        string image = Path.Combine(root, "capacity.sparseimage");
        bool mounted = false;
        Exception? failure = null;
        try
        {
            Directory.CreateDirectory(mount);
            await RunDiskToolAsync("create", "-size", "256m", "-fs", "APFS", "-type", "SPARSE",
                "-volname", "KeepVaultCapacityTest", image).ConfigureAwait(false);
            // An attach failure can occur after the mount became visible.
            // Attempt detachment before any recursive host-directory cleanup.
            mounted = true;
            await RunDiskToolAsync("attach", image, "-mountpoint", mount, "-nobrowse", "-owners", "on").ConfigureAwait(false);
            MacOperationVolume.Info initialVolume = MacOperationVolume.Inspect(mount, workingDirectory: false);
            MacOperationVolume.RequireSupported(initialVolume.Format, initialVolume.Flags);
            Require(initialVolume.Identity != MacOperationVolume.Inspect(root, false).Identity,
                "The small-volume fixture did not mount a separate filesystem.");
            Require(initialVolume.AvailableBytes < ImageBytes && initialVolume.AvailableBytes > 2 * PayloadBytes + (4L << 20),
                "The real APFS fixture is not below the historical 256 MiB floor with room for both outputs.");
            string ownedOutput = Path.Combine(mount, "owned-test-output");
            Directory.CreateDirectory(ownedOutput);

            byte[] block = new byte[1 << 20];
            for (int i = 0; i < block.Length; i++) block[i] = (byte)((i * 31 + i / 251) & 255);
            string source = Path.Combine(root, "public-64mib.bin");
            await using (var file = new FileStream(source, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                for (long written = 0; written < PayloadBytes; written += block.Length)
                    await file.WriteAsync(block).ConfigureAwait(false);
            byte[] expectedHash = await HashAsync(source).ConfigureAwait(false);

            string missingWorkspace = Path.Combine(root, "unused-workspace");
            var creationPolicy = new ArchiveOperationPolicy(missingWorkspace, root, maxCpuWorkers: 2);
            var extractionPolicy = creationPolicy.WithOutputDirectory(ownedOutput);
            var producer = new ZpaqService(operationPolicy: creationPolicy);
            var extractor = new ZpaqService(operationPolicy: extractionPolicy);
            string plainArchive = Path.Combine(root, "plain.zpaq");
            ProcessResult added = await producer.AddAsync(plainArchive, [source], 0, null, default).ConfigureAwait(false);
            Require(added.Succeeded, "Small-volume plain archive creation failed: " + added.StandardError);
            string plainOutput = Path.Combine(ownedOutput, "plain-output");
            ProcessResult plain = await extractor.ExtractAsync(plainArchive, plainOutput, null, default).ConfigureAwait(false);
            Require(plain.Succeeded, "Plain extraction rejected sufficient space below 256 MiB: " + plain.StandardError);
            await RequireExactOutputAsync(plainOutput, expectedHash).ConfigureAwait(false);

            string streamArchive = Path.Combine(root, "stream.zpaq");
            await using (var output = new FileStream(streamArchive, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                ProcessResult streamed = await producer.AddStreamingAsync([source], 0,
                    (input, token) => input.CopyToAsync(output, token), null, default).ConfigureAwait(false);
                Require(streamed.Succeeded, "Small-volume streaming archive creation failed: " + streamed.StandardError);
            }
            string streamOutput = Path.Combine(ownedOutput, "stream-output");
            await using (var input = new FileStream(streamArchive, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                ProcessResult streamed = await extractor.ExtractStreamingAsync(
                    (output, token) => input.CopyToAsync(output, token), streamOutput, null, default).ConfigureAwait(false);
                Require(streamed.Succeeded, "Streaming extraction rejected sufficient space below 256 MiB: " + streamed.StandardError);
            }
            await RequireExactOutputAsync(streamOutput, expectedHash).ConfigureAwait(false);
            Require(!Directory.Exists(missingWorkspace), "The small extraction unnecessarily created its metadata workspace.");

            // Consume only this disposable image's actual blocks, leaving about
            // 1 MiB: enough to start a write window, insufficient for 64 MiB.
            // A native ENOSPC or the descriptor-bound monitor must reject and
            // clean its private output instead of publishing a partial tree.
            string filler = Path.Combine(ownedOutput, "owned-capacity-filler.bin");
            await using (var file = new FileStream(filler, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                long filled = 0;
                while (true)
                {
                    long available = MacOperationVolume.Inspect(mount, false).AvailableBytes;
                    if (available <= (1L << 20)) break;
                    int count = checked((int)Math.Min(block.Length, available - (1L << 20)));
                    Require(filled <= ImageBytes - count, "The private capacity fixture exceeded its bounded fill size.");
                    try
                    {
                        await file.WriteAsync(block.AsMemory(0, count)).ConfigureAwait(false);
                        file.Flush(flushToDisk: true);
                    }
                    catch (IOException) when (MacOperationVolume.Inspect(mount, false).AvailableBytes < PayloadBytes)
                    {
                        // APFS can need allocation metadata before the last
                        // reported free bytes. The negative extraction still
                        // runs against the actual remaining filesystem space.
                        break;
                    }
                    filled += count;
                }
            }
            MacOperationVolume.Info constrained = MacOperationVolume.Inspect(mount, false);
            Require(constrained.AvailableBytes < PayloadBytes,
                "The real filesystem still has capacity for the complete negative fixture.");
            RequireThrows<IOException>(() => extractionPolicy.RequireBoundOutputVolume(constrained, PayloadBytes),
                "An actual pending write larger than the real free space was admitted.");
            string rejectedOutput = Path.Combine(ownedOutput, "must-not-install");
            bool rejected;
            try
            {
                ProcessResult result = await extractor.ExtractAsync(plainArchive, rejectedOutput, null, default).ConfigureAwait(false);
                rejected = !result.Succeeded;
            }
            catch (IOException) { rejected = true; }
            Require(rejected && !Directory.Exists(rejectedOutput), "Real capacity exhaustion installed a partial extraction.");
            Require(Directory.EnumerateFileSystemEntries(ownedOutput).Count() == 3,
                "Failed extraction left an additional staging tree or changed the existing entries.");
            await RequireExactOutputAsync(plainOutput, expectedHash).ConfigureAwait(false);
            await RequireExactOutputAsync(streamOutput, expectedHash).ConfigureAwait(false);
            Require((await HashAsync(source).ConfigureAwait(false)).SequenceEqual(expectedHash),
                "Capacity failure altered the original input.");
            Console.WriteLine($"small_apfs_capacity=PASS initial_free={initialVolume.AvailableBytes} exhausted_free={constrained.AvailableBytes} source_bytes={PayloadBytes} plain_and_streaming=true");
        }
        catch (Exception exception) { failure = exception; }
        finally
        {
            if (mounted)
            {
                try
                {
                    await RunDiskToolAsync("detach", mount).ConfigureAwait(false);
                    mounted = false;
                }
                catch (Exception cleanup) { failure = failure is null ? cleanup : new AggregateException(failure, cleanup); }
            }
            // Never recurse into an image which failed to detach.
            if (!mounted)
            {
                try { Directory.Delete(root, recursive: true); }
                catch (Exception cleanup) { failure = failure is null ? cleanup : new AggregateException(failure, cleanup); }
            }
        }
        if (failure is not null) ExceptionDispatchInfo.Capture(failure).Throw();
    }

    private static async Task RequireExactOutputAsync(string directory, byte[] expectedHash)
    {
        string[] entries = Directory.GetFileSystemEntries(directory, "*", SearchOption.AllDirectories);
        Require(entries.Length == 1 && Path.GetFileName(entries[0]) == "public-64mib.bin"
            && new FileInfo(entries[0]).Length == PayloadBytes, "Small-volume extraction changed the expected topology or length.");
        Require((await HashAsync(entries[0]).ConfigureAwait(false)).SequenceEqual(expectedHash),
            "Small-volume extraction changed the file bytes.");
    }

    private static async Task<byte[]> HashAsync(string path)
    {
        await using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return await SHA256.HashDataAsync(input).ConfigureAwait(false);
    }

    private static async Task RunDiskToolAsync(params string[] arguments)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo("/usr/bin/hdiutil")
            { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true }
        };
        foreach (string argument in arguments) process.StartInfo.ArgumentList.Add(argument);
        Require(process.Start(), "Could not start the private APFS test fixture tool.");
        Task<string> output = process.StandardOutput.ReadToEndAsync();
        Task<string> error = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync().ConfigureAwait(false);
        string[] text = await Task.WhenAll(output, error).ConfigureAwait(false);
        Require(process.ExitCode == 0, "Private APFS test fixture command failed: " + string.Join(Environment.NewLine, text));
    }

    private static void Require(bool condition, string message)
    { if (!condition) throw new InvalidOperationException(message); }
    private static void RequireThrows<T>(Action action, string message) where T : Exception
    { try { action(); } catch (T) { return; } throw new InvalidOperationException(message); }
}
