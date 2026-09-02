using System.Security.Cryptography;
using KalynaArchiver.Services;
using KalynaArchiver.Signing;

internal static class ParallelRecoveryTests
{
    internal static IReadOnlyList<TestCase> Tests { get; } =
    [
        new(
            "recovery.parallel-worker-equivalence",
            "KPAR2 parity and reconstruction are byte-identical with one and all production workers",
            RunWorkerEquivalenceAsync,
            TestResource.CpuHeavy,
            "Recovery")
        {
            Cost = new TestCost(4, 192, false, TestConstraint.None),
        },
        new(
            "recovery.physical-eio-repair",
            "descriptor-bound KPAR2 repairs one physical EIO shard and rejects four",
            RunPhysicalEioRecoveryAsync,
            TestResource.CpuHeavy,
            "Recovery")
        {
            Cost = new TestCost(4, 128, false, TestConstraint.None),
        },
        new(
            "recovery.key-derivation-failure-cleanup",
            "KPAR2 child-key derivation zeroes every completed secret when either branch boundary fails",
            RunRecoveryKeyDerivationFailureCleanupAsync,
            TestResource.Light,
            "Recovery"),
        new(
            "recovery.parallel-copy-fail-fast",
            "KPAR2 parallel candidate copying cancels and joins sibling workers after the first failure",
            RunParallelCopyFailFastAsync,
            TestResource.Light,
            "Recovery"),
        new(
            "recovery.parallel-copy-concurrency",
            "KPAR2 starts every configured copy worker before synchronous chunk work can monopolize the queue",
            RunParallelCopyConcurrencyAsync,
            TestResource.Light,
            "Recovery"),
        new(
            "recovery.parallel-copy-scheduling-failure",
            "KPAR2 cancels and joins already-scheduled copy workers when later worker scheduling fails",
            RunParallelCopySchedulingFailureAsync,
            TestResource.Light,
            "Recovery"),
    ];

    private static Task RunWorkerEquivalenceAsync()
    {
        const int dataShardCount = 20;
        const int shardBytes = (3 * 256 * 1024) + 97;
        int productionWorkers = Math.Clamp(Environment.ProcessorCount, 1, 64);
        byte[][] original = new byte[dataShardCount][];
        byte[][]? oneWorkerParity = null;
        byte[][]? productionParity = null;
        byte[][]? oneWorkerData = null;
        byte[][]? productionData = null;
        try
        {
            using var generator = RandomNumberGenerator.Create();
            for (int index = 0; index < original.Length; index++)
            {
                original[index] = new byte[shardBytes];
                generator.GetBytes(original[index]);
            }

            oneWorkerParity = RecoveryService.ComputeParityForWorkerEquivalenceTests(
                original,
                workers: 1);
            productionParity = RecoveryService.ComputeParityForWorkerEquivalenceTests(
                original,
                productionWorkers);
            RequireShardSetsEqual(
                oneWorkerParity,
                productionParity,
                "Parallel KPAR2 parity differs from the one-worker reference.");

            oneWorkerData = CloneShards(original);
            productionData = CloneShards(original);
            int[] missing = [1, 7, 19];
            foreach (int index in missing)
            {
                RandomNumberGenerator.Fill(oneWorkerData[index]);
                RandomNumberGenerator.Fill(productionData[index]);
            }

            RecoveryService.RecoverForWorkerEquivalenceTests(
                oneWorkerData,
                oneWorkerParity,
                missing,
                workers: 1);
            RecoveryService.RecoverForWorkerEquivalenceTests(
                productionData,
                productionParity,
                missing,
                productionWorkers);

            foreach (int index in missing)
            {
                MacComprehensiveTests.Require(
                    CryptographicOperations.FixedTimeEquals(
                        oneWorkerData[index],
                        original[index]),
                    $"One-worker KPAR2 reconstruction failed for data shard {index}.");
                MacComprehensiveTests.Require(
                    CryptographicOperations.FixedTimeEquals(
                        productionData[index],
                        original[index]),
                    $"Parallel KPAR2 reconstruction failed for data shard {index}.");
                MacComprehensiveTests.Require(
                    CryptographicOperations.FixedTimeEquals(
                        oneWorkerData[index],
                        productionData[index]),
                    $"Parallel KPAR2 reconstruction differs for data shard {index}.");
            }

            return Task.CompletedTask;
        }
        finally
        {
            ZeroShards(original);
            ZeroShards(oneWorkerParity);
            ZeroShards(productionParity);
            ZeroShards(oneWorkerData);
            ZeroShards(productionData);
        }
    }

    private static async Task RunPhysicalEioRecoveryAsync()
    {
        const int blockBytes = 4096;
        string root = MacSafeFileSystem.ResolveExistingRealPath(
            Directory.CreateTempSubdirectory("keep-vault-kpar2-physical-eio-").FullName);
        File.SetUnixFileMode(
            root,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

        byte[] original = RandomNumberGenerator.GetBytes((2 * 1024 * 1024) + 333);
        "ZPAQv12"u8.CopyTo(original);
        byte[] expectedSha3 = Sha3_512Compat.HashData(original);
        byte[] expectedSkein = Skein1024Digest.HashData(original);
        byte[]? recoveredBytes = null;
        byte[]? recoveredSha3 = null;
        byte[]? recoveredSkein = null;
        byte[]? originalAfter = null;
        try
        {
            string archivePath = Path.Combine(root, "physical-eio.zpaq");
            await File.WriteAllBytesAsync(archivePath, original).ConfigureAwait(false);

            var recovery = new RecoveryService();
            string sidecarPath = await recovery.CreateAsync(
                archivePath,
                progress: null,
                CancellationToken.None).ConfigureAwait(false);
            MacComprehensiveTests.Require(
                File.Exists(sidecarPath),
                "The physical-EIO fixture did not create its KPAR2 sidecar.");

            const long recoverableOffset = 2L * blockBytes;
            int recoverableFaultReads = 0;
            RecoveryRepairResult repaired;
            using (RecoveryService.UseRecoverySourceReadFaultForTests((offset, length) =>
                   {
                       bool intersects = RangeIntersects(
                           offset,
                           length,
                           recoverableOffset,
                           blockBytes);
                       if (intersects)
                       {
                           Interlocked.Increment(ref recoverableFaultReads);
                       }
                       return intersects;
                   }))
            {
                repaired = await recovery.VerifyAndRepairAsync(
                    archivePath,
                    progress: null,
                    CancellationToken.None).ConfigureAwait(false);
            }

            MacComprehensiveTests.Require(
                recoverableFaultReads > 0,
                "The deterministic physical-EIO seam did not intercept any descriptor read.");
            MacComprehensiveTests.Require(
                repaired.RecoveryAvailable
                && !repaired.ArchiveHealthy
                && repaired.Repaired
                && repaired.RepairedShards == 1
                && repaired.OutputPath is not null,
                "KPAR2 did not report exactly one reconstructed physical-EIO shard.");
            MacComprehensiveTests.Require(
                !string.Equals(repaired.OutputPath, archivePath, StringComparison.Ordinal),
                "KPAR2 attempted to repair the physical-EIO source in place.");

            recoveredBytes = await File.ReadAllBytesAsync(repaired.OutputPath!).ConfigureAwait(false);
            recoveredSha3 = Sha3_512Compat.HashData(recoveredBytes);
            recoveredSkein = Skein1024Digest.HashData(recoveredBytes);
            MacComprehensiveTests.Require(
                CryptographicOperations.FixedTimeEquals(original, recoveredBytes)
                && CryptographicOperations.FixedTimeEquals(expectedSha3, recoveredSha3)
                && CryptographicOperations.FixedTimeEquals(expectedSkein, recoveredSkein),
                "The physical-EIO recovery candidate is not byte- and dual-digest-identical to the source fixture.");

            originalAfter = await File.ReadAllBytesAsync(archivePath).ConfigureAwait(false);
            MacComprehensiveTests.Require(
                CryptographicOperations.FixedTimeEquals(original, originalAfter),
                "KPAR2 modified the physical-EIO source instead of writing a separate candidate.");
            CryptographicOperations.ZeroMemory(originalAfter);
            originalAfter = null;

            File.Delete(repaired.OutputPath!);
            CryptographicOperations.ZeroMemory(recoveredBytes);
            recoveredBytes = null;
            CryptographicOperations.ZeroMemory(recoveredSha3);
            recoveredSha3 = null;
            CryptographicOperations.ZeroMemory(recoveredSkein);
            recoveredSkein = null;

            long[] unrecoverableOffsets = [0, blockBytes, 2L * blockBytes, 3L * blockBytes];
            int unrecoverableFaultReads = 0;
            bool rejected = false;
            using (RecoveryService.UseRecoverySourceReadFaultForTests((offset, length) =>
                   {
                       bool intersects = unrecoverableOffsets.Any(
                           badOffset => RangeIntersects(
                               offset,
                               length,
                               badOffset,
                               blockBytes));
                       if (intersects)
                       {
                           Interlocked.Increment(ref unrecoverableFaultReads);
                       }
                       return intersects;
                   }))
            {
                try
                {
                    _ = await recovery.VerifyAndRepairAsync(
                        archivePath,
                        progress: null,
                        CancellationToken.None).ConfigureAwait(false);
                }
                catch (InvalidDataException)
                {
                    rejected = true;
                }
            }

            MacComprehensiveTests.Require(
                rejected && unrecoverableFaultReads >= unrecoverableOffsets.Length,
                "KPAR2 did not fail closed when physical EIO exceeded RS(20,3).");
            MacComprehensiveTests.Require(
                Directory.GetFiles(
                    root,
                    "physical-eio.recovered*.zpaq",
                    SearchOption.TopDirectoryOnly).Length == 0,
                "A failed physical-EIO repair left a partial recovery candidate behind.");

            originalAfter = await File.ReadAllBytesAsync(archivePath).ConfigureAwait(false);
            MacComprehensiveTests.Require(
                CryptographicOperations.FixedTimeEquals(original, originalAfter),
                "An unrecoverable physical-EIO attempt modified the source archive.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(original);
            CryptographicOperations.ZeroMemory(expectedSha3);
            CryptographicOperations.ZeroMemory(expectedSkein);
            ZeroIfNotNull(recoveredBytes);
            ZeroIfNotNull(recoveredSha3);
            ZeroIfNotNull(recoveredSkein);
            ZeroIfNotNull(originalAfter);
            Directory.Delete(root, recursive: true);
        }
    }

    private static Task RunRecoveryKeyDerivationFailureCleanupAsync()
    {
        foreach (RecoveryKeyDerivationTestStage injectedStage in Enum.GetValues<RecoveryKeyDerivationTestStage>())
        {
            byte[] parentSha3 = Enumerable.Range(1, 64).Select(value => (byte)value).ToArray();
            byte[] parentSkein = Enumerable.Range(1, 128).Select(value => (byte)(value ^ 0x5a)).ToArray();
            byte[] sha3Message = "KPAR2 recovery SHA3 cleanup fixture"u8.ToArray();
            byte[] skeinMessage = "KPAR2 recovery Skein cleanup fixture"u8.ToArray();
            byte[]? observedSha3 = null;
            byte[]? observedSkein = null;
            bool rejected = false;
            try
            {
                using (RecoveryService.UseRecoveryKeyDerivationHookForTests((stage, sha3, skein) =>
                       {
                           if (stage != injectedStage)
                           {
                               return;
                           }

                           observedSha3 = sha3;
                           observedSkein = skein;
                           throw new InvalidOperationException($"injected recovery-key failure after {stage}");
                       }))
                {
                    try
                    {
                        using IDisposable unexpected =
                            RecoveryService.DeriveRecoveryCertificationKeysForTests(
                                parentSha3,
                                parentSkein,
                                sha3Message,
                                skeinMessage);
                    }
                    catch (InvalidOperationException ex)
                        when (ex.Message.Contains("injected recovery-key failure", StringComparison.Ordinal))
                    {
                        rejected = true;
                    }
                }

                MacComprehensiveTests.Require(
                    rejected && observedSha3 is not null,
                    $"The {injectedStage} KPAR2 derivation-failure seam did not execute.");
                MacComprehensiveTests.Require(
                    observedSha3!.All(value => value == 0),
                    $"The completed SHA3 recovery key survived the {injectedStage} failure.");
                if (injectedStage == RecoveryKeyDerivationTestStage.AfterSkein)
                {
                    MacComprehensiveTests.Require(
                        observedSkein is not null && observedSkein.All(value => value == 0),
                        "The completed Skein recovery key survived a post-derivation failure.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(parentSha3);
                CryptographicOperations.ZeroMemory(parentSkein);
                CryptographicOperations.ZeroMemory(sha3Message);
                CryptographicOperations.ZeroMemory(skeinMessage);
                ZeroIfNotNull(observedSha3);
                ZeroIfNotNull(observedSkein);
            }
        }

        return Task.CompletedTask;
    }

    private static async Task RunParallelCopyFailFastAsync()
    {
        const int workers = 4;
        const int sourceBytes = 8 * 1024 * 1024;
        string root = MacSafeFileSystem.ResolveExistingRealPath(
            Directory.CreateTempSubdirectory("keep-vault-kpar2-copy-failfast-").FullName);
        File.SetUnixFileMode(
            root,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try
        {
            string sourcePath = Path.Combine(root, "source.bin");
            string destinationPath = Path.Combine(root, "candidate.bin");
            await using var source = new FileStream(
                sourcePath,
                FileMode.CreateNew,
                FileAccess.ReadWrite,
                FileShare.None,
                bufferSize: 4096,
                FileOptions.Asynchronous | FileOptions.RandomAccess);
            await using var destination = new FileStream(
                destinationPath,
                FileMode.CreateNew,
                FileAccess.ReadWrite,
                FileShare.None,
                bufferSize: 4096,
                FileOptions.Asynchronous | FileOptions.RandomAccess);
            source.SetLength(sourceBytes);

            var allWorkersEntered = new TaskCompletionSource(
                TaskCreationOptions.RunContinuationsAsynchronously);
            int entered = 0;
            var enteredWorkers = new List<int>();
            var enteredGate = new object();
            bool rejected = false;
            CancellationTokenRegistration cancellationRegistration = default;
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            try
            {
                using (RecoveryService.UseRecoveryCopyChunkHookForTests(async (workerIndex, chunkIndex, token) =>
                       {
                           lock (enteredGate)
                           {
                               enteredWorkers.Add(workerIndex);
                           }
                           if (Interlocked.Increment(ref entered) == workers)
                           {
                               allWorkersEntered.TrySetResult();
                           }

                           await allWorkersEntered.Task.ConfigureAwait(false);
                           if (chunkIndex == 0)
                           {
                               cancellationRegistration = token.Register(
                                   static () => throw new InvalidOperationException(
                                       "injected KPAR2 cancellation-cleanup failure"));
                               throw new IOException("injected primary KPAR2 copy failure");
                           }

                           await Task.Delay(Timeout.InfiniteTimeSpan, token).ConfigureAwait(false);
                       }))
                {
                    try
                    {
                        _ = await RecoveryService.CopyArchiveForRecoveryForTestsAsync(
                            source,
                            destination,
                            sourceBytes,
                            workers,
                            CancellationToken.None).ConfigureAwait(false);
                    }
                    catch (AggregateException ex)
                    {
                        Exception[] failures = ex.Flatten().InnerExceptions.ToArray();
                        rejected = failures.Any(failure =>
                                       failure is IOException
                                       && string.Equals(
                                           failure.Message,
                                           "injected primary KPAR2 copy failure",
                                           StringComparison.Ordinal))
                                   && failures.Any(failure =>
                                       failure is InvalidOperationException
                                       && string.Equals(
                                           failure.Message,
                                           "injected KPAR2 cancellation-cleanup failure",
                                           StringComparison.Ordinal));
                    }
                }
            }
            finally
            {
                cancellationRegistration.Dispose();
            }
            stopwatch.Stop();

            int[] assigned;
            lock (enteredGate)
            {
                assigned = enteredWorkers.Order().ToArray();
            }
            MacComprehensiveTests.Require(
                rejected,
                "The primary parallel KPAR2 copy failure and cancellation-cleanup failure were not both preserved.");
            MacComprehensiveTests.Require(
                assigned.SequenceEqual(Enumerable.Range(0, workers)),
                "KPAR2 did not join exactly the workers blocked at the deterministic failure barrier.");
            MacComprehensiveTests.Require(
                destination.Length == 0,
                "A KPAR2 sibling worker continued writing after the primary copy failure.");
            MacComprehensiveTests.Require(
                stopwatch.Elapsed < TimeSpan.FromSeconds(5),
                "KPAR2 parallel copy did not fail fast after cancelling its sibling workers.");
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static async Task RunParallelCopyConcurrencyAsync()
    {
        const int workers = 4;
        const int sourceBytes = 8 * 1024 * 1024;
        string root = MacSafeFileSystem.ResolveExistingRealPath(
            Directory.CreateTempSubdirectory("keep-vault-kpar2-copy-concurrency-").FullName);
        File.SetUnixFileMode(
            root,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try
        {
            string sourcePath = Path.Combine(root, "source.bin");
            string destinationPath = Path.Combine(root, "candidate.bin");
            await using var source = new FileStream(
                sourcePath,
                FileMode.CreateNew,
                FileAccess.ReadWrite,
                FileShare.None,
                bufferSize: 4096,
                FileOptions.Asynchronous | FileOptions.RandomAccess);
            await using var destination = new FileStream(
                destinationPath,
                FileMode.CreateNew,
                FileAccess.ReadWrite,
                FileShare.None,
                bufferSize: 4096,
                FileOptions.Asynchronous | FileOptions.RandomAccess);
            source.SetLength(sourceBytes);

            var allWorkersEntered = new TaskCompletionSource(
                TaskCreationOptions.RunContinuationsAsynchronously);
            var gate = new object();
            var seenWorkers = new bool[workers];
            int firstEntries = 0;
            int activeWorkers = 0;
            int maximumConcurrentWorkers = 0;
            using (RecoveryService.UseRecoveryCopyChunkHookForTests(
                   async (workerIndex, _, token) =>
                   {
                       bool firstEntry;
                       lock (gate)
                       {
                           firstEntry = !seenWorkers[workerIndex];
                           if (firstEntry)
                           {
                               seenWorkers[workerIndex] = true;
                               firstEntries++;
                               activeWorkers++;
                               maximumConcurrentWorkers = Math.Max(
                                   maximumConcurrentWorkers,
                                   activeWorkers);
                               if (firstEntries == workers)
                               {
                                   allWorkersEntered.TrySetResult();
                               }
                           }
                       }

                       if (!firstEntry)
                       {
                           return;
                       }

                       try
                       {
                           await allWorkersEntered.Task
                               .WaitAsync(TimeSpan.FromSeconds(5), token)
                               .ConfigureAwait(false);
                       }
                       finally
                       {
                           lock (gate)
                           {
                               activeWorkers--;
                           }
                       }
                   }))
            {
                int unreadable = await RecoveryService.CopyArchiveForRecoveryForTestsAsync(
                    source,
                    destination,
                    sourceBytes,
                    workers,
                    CancellationToken.None).ConfigureAwait(false);
                MacComprehensiveTests.Require(
                    unreadable == 0,
                    "The concurrency fixture unexpectedly reported unreadable source blocks.");
            }

            lock (gate)
            {
                MacComprehensiveTests.Require(
                    seenWorkers.All(seen => seen)
                    && firstEntries == workers
                    && maximumConcurrentWorkers == workers,
                    "KPAR2 did not make every configured copy worker concurrently runnable before chunk processing.");
            }
            MacComprehensiveTests.Require(
                destination.Length == sourceBytes,
                "The parallel-copy concurrency fixture did not publish the complete candidate length.");
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static async Task RunParallelCopySchedulingFailureAsync()
    {
        const int workers = 4;
        const int sourceBytes = 8 * 1024 * 1024;
        string root = MacSafeFileSystem.ResolveExistingRealPath(
            Directory.CreateTempSubdirectory("keep-vault-kpar2-copy-scheduling-").FullName);
        File.SetUnixFileMode(
            root,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try
        {
            string sourcePath = Path.Combine(root, "source.bin");
            string destinationPath = Path.Combine(root, "candidate.bin");
            await using var source = new FileStream(
                sourcePath,
                FileMode.CreateNew,
                FileAccess.ReadWrite,
                FileShare.None,
                bufferSize: 4096,
                FileOptions.Asynchronous | FileOptions.RandomAccess);
            await using var destination = new FileStream(
                destinationPath,
                FileMode.CreateNew,
                FileAccess.ReadWrite,
                FileShare.None,
                bufferSize: 4096,
                FileOptions.Asynchronous | FileOptions.RandomAccess);
            source.SetLength(sourceBytes);

            var scheduled = new List<int>();
            var scheduleGate = new object();
            int enteredChunks = 0;
            bool rejected = false;
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            using (RecoveryService.UseRecoveryCopyWorkerScheduleHookForTests(workerIndex =>
                   {
                       lock (scheduleGate)
                       {
                           scheduled.Add(workerIndex);
                       }
                       if (workerIndex == 2)
                       {
                           throw new IOException("injected KPAR2 worker-scheduling failure");
                       }
                   }))
            using (RecoveryService.UseRecoveryCopyChunkHookForTests((_, _, _) =>
                   {
                       Interlocked.Increment(ref enteredChunks);
                       return ValueTask.CompletedTask;
                   }))
            {
                try
                {
                    _ = await RecoveryService.CopyArchiveForRecoveryForTestsAsync(
                        source,
                        destination,
                        sourceBytes,
                        workers,
                        CancellationToken.None).ConfigureAwait(false);
                }
                catch (IOException ex)
                    when (string.Equals(
                        ex.Message,
                        "injected KPAR2 worker-scheduling failure",
                        StringComparison.Ordinal))
                {
                    rejected = true;
                }
            }
            stopwatch.Stop();

            int[] scheduleAttempts;
            lock (scheduleGate)
            {
                scheduleAttempts = scheduled.ToArray();
            }
            MacComprehensiveTests.Require(
                rejected,
                "The deterministic KPAR2 worker-scheduling failure was not preserved as the primary error.");
            MacComprehensiveTests.Require(
                scheduleAttempts.SequenceEqual([0, 1, 2]),
                "KPAR2 continued scheduling workers after the injected partial-scheduling failure.");
            MacComprehensiveTests.Require(
                enteredChunks == 0 && destination.Length == 0,
                "A previously scheduled KPAR2 worker processed or wrote a chunk after scheduling failed.");
            MacComprehensiveTests.Require(
                stopwatch.Elapsed < TimeSpan.FromSeconds(5),
                "KPAR2 did not cancel and join partially scheduled workers within the fail-fast bound.");
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static bool RangeIntersects(
        long requestOffset,
        int requestLength,
        long badOffset,
        int badLength)
    {
        if (requestLength <= 0 || badLength <= 0)
        {
            return false;
        }

        long requestEnd = checked(requestOffset + requestLength);
        long badEnd = checked(badOffset + badLength);
        return requestOffset < badEnd && badOffset < requestEnd;
    }

    private static byte[][] CloneShards(byte[][] source) =>
        source.Select(shard => shard.ToArray()).ToArray();

    private static void RequireShardSetsEqual(
        byte[][] expected,
        byte[][] actual,
        string message)
    {
        MacComprehensiveTests.Require(expected.Length == actual.Length, message);
        for (int index = 0; index < expected.Length; index++)
        {
            MacComprehensiveTests.Require(
                CryptographicOperations.FixedTimeEquals(expected[index], actual[index]),
                $"{message} Parity shard {index} differs.");
        }
    }

    private static void ZeroShards(byte[][]? shards)
    {
        if (shards is null)
        {
            return;
        }

        foreach (byte[]? shard in shards)
        {
            if (shard is not null)
            {
                CryptographicOperations.ZeroMemory(shard);
            }
        }
    }

    private static void ZeroIfNotNull(byte[]? value)
    {
        if (value is not null)
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }
}
