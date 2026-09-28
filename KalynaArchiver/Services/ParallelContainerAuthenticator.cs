using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
using KalynaArchiver.Signing;

namespace KalynaArchiver.Services;

/// <summary>
/// Computes the two v13 container authentication tags as a bounded parallel
/// tree.  Leaves are independent MACs over fixed-size pieces of the logical
/// authenticated stream; a very small ordered root transcript binds every
/// leaf, its position, its exact length and the complete stream length.
/// </summary>
/// <remarks>
/// Standard incremental HMAC-SHA3-512 and Skein-MAC-1024 each have a serial
/// chaining dependency.  Running only those two chains beside one another
/// still limits a fast cipher to one core per MAC.  v13 deliberately changes
/// the authenticated format instead: independent, domain-separated leaves can
/// occupy all processors, while the root processes only 204 bytes per MiB of
/// archive data. There is no compatibility path for an older container
/// generation in this implementation.
/// </remarks>
internal static class ParallelContainerAuthenticator
{
    internal const int LeafBytes = 1024 * 1024;
    private const int Sha3Bytes = 64;
    private const int SkeinBytes = 128;

    private static readonly byte[] LeafDomain =
        "Kalyna-ZPAQ/v13/Parallel-Tree-MAC/Leaf"u8.ToArray();
    private static readonly byte[] RootDomain =
        "Kalyna-ZPAQ/v13/Parallel-Tree-MAC/Root"u8.ToArray();
    private static readonly byte[] Sha3LeafKeyDomain =
        "Kalyna-ZPAQ/v13/Parallel-Tree-MAC/HMAC-SHA3-512/Leaf-Key"u8.ToArray();
    private static readonly byte[] Sha3RootKeyDomain =
        "Kalyna-ZPAQ/v13/Parallel-Tree-MAC/HMAC-SHA3-512/Root-Key"u8.ToArray();
    private const string SkeinKeyDomain =
        "Kalyna-ZPAQ/v13/Parallel-Tree-MAC/Skein-MAC-1024-1024/Key-Derivation";
    private static readonly byte[] SkeinLeafKeyLabel = "Leaf-Key"u8.ToArray();
    private static readonly byte[] SkeinRootKeyLabel = "Root-Key"u8.ToArray();

    private static readonly AsyncLocal<int?> WorkerOverride = new();
    private static readonly AsyncLocal<PhaseMeasurementsForTests?> PhaseObserver = new();
    internal static Action? BeforeDerivedKeyCleanupForTests { get; set; }

    // Optional timing-only test seam. No keys, tags, data or schedule decisions
    // enter this observer; disabled operation does not read the clock.
    internal enum PhaseForTests { KeyPreparation, RootInitialization, InputRead, LeafBatches, OrderedRoot, FinalTags, Cleanup }
    internal sealed class PhaseMeasurementsForTests
    {
        private readonly long[] _ticks = new long[Enum.GetValues<PhaseForTests>().Length];
        internal void Record(PhaseForTests phase, long ticks) => Interlocked.Add(ref _ticks[(int)phase], ticks);
        internal Dictionary<string, double> Seconds() => Enum.GetValues<PhaseForTests>()
            .ToDictionary(phase => phase.ToString(), phase => (double)Volatile.Read(ref _ticks[(int)phase]) / Stopwatch.Frequency);
    }
    internal static IDisposable ObservePhasesForTests(PhaseMeasurementsForTests observer)
    {
        ArgumentNullException.ThrowIfNull(observer);
        PhaseMeasurementsForTests? previous = PhaseObserver.Value;
        PhaseObserver.Value = observer;
        return new PhaseObserverScope(previous);
    }
    private static PhaseTimer Measure(PhaseForTests phase) => new(PhaseObserver.Value, phase);
    private readonly struct PhaseTimer(PhaseMeasurementsForTests? observer, PhaseForTests phase) : IDisposable
    {
        private readonly long _started = observer is null ? 0 : Stopwatch.GetTimestamp();
        public void Dispose()
        {
            if (observer is not null) observer.Record(phase, Stopwatch.GetTimestamp() - _started);
        }
    }
    private sealed class PhaseObserverScope(PhaseMeasurementsForTests? previous) : IDisposable
    {
        private bool _disposed;
        public void Dispose()
        {
            if (_disposed) return;
            PhaseObserver.Value = previous;
            _disposed = true;
        }
    }

    /// <summary>
    /// Selects the production worker count for the current asynchronous flow.
    /// It is a test seam, not a user setting: v13 KATs use it to prove that a
    /// one-worker and an all-core traversal produce identical bytes.
    /// </summary>
    internal static IDisposable UseWorkerCountForTests(int workers)
    {
        if (workers < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(workers));
        }

        int? previous = WorkerOverride.Value;
        WorkerOverride.Value = workers;
        return new WorkerOverrideScope(previous);
    }

    internal static int ProductionWorkerCount =>
        Math.Max(1, Math.Min(Environment.ProcessorCount, ArchiveOperationPolicy.Current.MaxCpuWorkers));

    internal static async Task<(byte[] Sha3Tag, byte[] SkeinTag)> ComputeAsync(
        Stream ciphertextStream,
        long ciphertextOffset,
        IReadOnlyList<ReadOnlyMemory<byte>> authenticatedPrefix,
        byte[] sha3MacKey,
        byte[] skeinMacKey,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(ciphertextStream);
        ArgumentNullException.ThrowIfNull(authenticatedPrefix);
        ArgumentNullException.ThrowIfNull(sha3MacKey);
        ArgumentNullException.ThrowIfNull(skeinMacKey);
        if (!ciphertextStream.CanRead || !ciphertextStream.CanSeek)
        {
            throw new ArgumentException(
                "The authenticated ciphertext stream must be readable and seekable.",
                nameof(ciphertextStream));
        }

        if (ciphertextOffset < 0 || ciphertextOffset > ciphertextStream.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(ciphertextOffset));
        }

        if (sha3MacKey.Length != Sha3Bytes)
        {
            throw new ArgumentException($"The SHA3 MAC key must be {Sha3Bytes} bytes.", nameof(sha3MacKey));
        }

        if (skeinMacKey.Length != SkeinBytes)
        {
            throw new ArgumentException($"The Skein MAC key must be {SkeinBytes} bytes.", nameof(skeinMacKey));
        }

        long prefixLength = 0;
        foreach (ReadOnlyMemory<byte> part in authenticatedPrefix)
        {
            prefixLength = checked(prefixLength + part.Length);
        }

        long ciphertextLength = checked(ciphertextStream.Length - ciphertextOffset);
        long logicalLength = checked(prefixLength + ciphertextLength);
        CryptoUsageBudget.ValidateAuthenticationLength(logicalLength);
        if (logicalLength <= 0)
        {
            throw new InvalidDataException("A container authentication stream cannot be empty.");
        }

        long leafCount = checked((logicalLength + LeafBytes - 1) / LeafBytes);
        int workers = WorkerOverride.Value ?? ProductionWorkerCount;
        workers = checked((int)Math.Min(workers, leafCount));

        LockedSensitiveBuffer? sha3LeafKey = null;
        LockedSensitiveBuffer? sha3RootKey = null;
        LockedSensitiveBuffer? skeinLeafKey = null;
        LockedSensitiveBuffer? skeinRootKey = null;
        byte[]? completedSha3Tag = null;
        byte[]? completedSkeinTag = null;
        Exception? operationFailure = null;
        try
        {
            using (Measure(PhaseForTests.KeyPreparation))
            {
                sha3LeafKey = LockedSensitiveBuffer.Create(Sha3Bytes);
                sha3RootKey = LockedSensitiveBuffer.Create(Sha3Bytes);
                skeinLeafKey = LockedSensitiveBuffer.Create(SkeinBytes);
                skeinRootKey = LockedSensitiveBuffer.Create(SkeinBytes);
                DeriveSubkeys(
                    sha3MacKey,
                    skeinMacKey,
                    sha3LeafKey.Bytes,
                    sha3RootKey.Bytes,
                    skeinLeafKey.Bytes,
                    skeinRootKey.Bytes);
            }

            PhaseTimer rootInitialization = Measure(PhaseForTests.RootInitialization);
            using var rootSha3 = new HmacSha3_512(sha3RootKey.Bytes);
            using NativeSkein1024Mac rootSkein = NativeThreefish.CreateSkeinMac(skeinRootKey.Bytes);
            byte[] rootHeader = new byte[RootDomain.Length + sizeof(long) + sizeof(long) + sizeof(int)];
            RootDomain.AsSpan().CopyTo(rootHeader);
            int rootHeaderOffset = RootDomain.Length;
            BinaryPrimitives.WriteInt64BigEndian(rootHeader.AsSpan(rootHeaderOffset), logicalLength);
            rootHeaderOffset += sizeof(long);
            BinaryPrimitives.WriteInt64BigEndian(rootHeader.AsSpan(rootHeaderOffset), leafCount);
            rootHeaderOffset += sizeof(long);
            BinaryPrimitives.WriteInt32BigEndian(rootHeader.AsSpan(rootHeaderOffset), LeafBytes);
            rootSha3.AppendData(rootHeader);
            rootSkein.AppendData(rootHeader);
            rootInitialization.Dispose();

            ciphertextStream.Position = ciphertextOffset;
            var reader = new LogicalStreamReader(authenticatedPrefix, ciphertextStream, ciphertextLength);
            long nextLeaf = 0;
            try
            {
                while (nextLeaf < leafCount)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    int batchCount = checked((int)Math.Min(workers, leafCount - nextLeaf));
                    var inputs = new LeafInput[batchCount];
                    int initializedInputs = 0;
                    try
                    {
                        using (Measure(PhaseForTests.InputRead))
                        {
                            for (int index = 0; index < batchCount; index++)
                            {
                                int length = checked((int)Math.Min(LeafBytes, logicalLength - reader.BytesRead));
                                byte[] data = new byte[length];
                                try
                                {
                                    await reader.ReadExactlyAsync(data, cancellationToken).ConfigureAwait(false);
                                    inputs[index] = new LeafInput(nextLeaf + index, data);
                                    initializedInputs++;
                                }
                                catch
                                {
                                    CryptographicOperations.ZeroMemory(data);
                                    throw;
                                }
                            }
                        }

                        PhaseTimer leafBatches = Measure(PhaseForTests.LeafBatches);
                        LeafResult[] results = workers == 1
                            ? await ComputeSerialBatchAsync(inputs, sha3LeafKey.Bytes, skeinLeafKey.Bytes, cancellationToken).ConfigureAwait(false)
                            : await ComputeParallelBatchAsync(
                                inputs,
                                sha3LeafKey.Bytes,
                                skeinLeafKey.Bytes,
                                cancellationToken).ConfigureAwait(false);
                        leafBatches.Dispose();
                        try
                        {
                            using CpuWorkBudget.Lease rootCpu = await CpuWorkBudget.AcquireAsync(
                                ArchiveOperationPolicy.Current.MaxCpuWorkers, 1, cancellationToken).ConfigureAwait(false);
                            using IDisposable rootCpuScope = rootCpu.EnterScope();
                            using PhaseTimer rootTimer = Measure(PhaseForTests.OrderedRoot);
                            foreach (LeafResult result in results)
                            {
                                AppendRootLeaf(rootSha3, rootSkein, result);
                            }
                        }
                        finally
                        {
                            using PhaseTimer resultCleanup = Measure(PhaseForTests.Cleanup);
                            foreach (LeafResult result in results)
                            {
                                result.Dispose();
                            }
                        }
                    }
                    finally
                    {
                        using PhaseTimer inputCleanup = Measure(PhaseForTests.Cleanup);
                        for (int index = 0; index < initializedInputs; index++)
                        {
                            inputs[index].Dispose();
                        }
                    }

                    nextLeaf += batchCount;
                }

                if (reader.BytesRead != logicalLength
                    || ciphertextStream.Length != ciphertextOffset + ciphertextLength)
                {
                    throw new EndOfStreamException("The container authentication stream changed while it was read.");
                }

                using CpuWorkBudget.Lease finalCpu = await CpuWorkBudget.AcquireAsync(
                    ArchiveOperationPolicy.Current.MaxCpuWorkers, 1, cancellationToken).ConfigureAwait(false);
                using IDisposable finalCpuScope = finalCpu.EnterScope();
                using PhaseTimer finalTags = Measure(PhaseForTests.FinalTags);
                completedSha3Tag = rootSha3.GetHashAndReset();
                completedSkeinTag = rootSkein.GetTag();
                return (completedSha3Tag, completedSkeinTag);
            }
            catch
            {
                if (completedSha3Tag is not null)
                {
                    CryptographicOperations.ZeroMemory(completedSha3Tag);
                }

                if (completedSkeinTag is not null)
                {
                    CryptographicOperations.ZeroMemory(completedSkeinTag);
                }

                throw;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(rootHeader);
            }
        }
        catch (Exception failure)
        {
            operationFailure = failure;
            throw;
        }
        finally
        {
            using PhaseTimer keyCleanup = Measure(PhaseForTests.Cleanup);
            BeforeDerivedKeyCleanupForTests?.Invoke();
            try
            {
                SecureMemory.ZeroAndDisposeAllPreservingFailure(
                    operationFailure,
                    "Parallel container authentication failed and one or more derived MAC-key buffers could not be released.",
                    skeinRootKey,
                    skeinLeafKey,
                    sha3RootKey,
                    sha3LeafKey);
            }
            catch
            {
                if (completedSha3Tag is not null)
                {
                    CryptographicOperations.ZeroMemory(completedSha3Tag);
                }

                if (completedSkeinTag is not null)
                {
                    CryptographicOperations.ZeroMemory(completedSkeinTag);
                }

                throw;
            }
        }
    }

    private static void DeriveSubkeys(
        byte[] sha3MacKey,
        byte[] skeinMacKey,
        Span<byte> sha3LeafKey,
        Span<byte> sha3RootKey,
        Span<byte> skeinLeafKey,
        Span<byte> skeinRootKey)
    {
        using (var leaf = new HmacSha3_512(sha3MacKey))
        {
            leaf.AppendData(Sha3LeafKeyDomain);
            byte[] value = leaf.GetHashAndReset();
            try
            {
                value.CopyTo(sha3LeafKey);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(value);
            }
        }

        using (var root = new HmacSha3_512(sha3MacKey))
        {
            root.AppendData(Sha3RootKeyDomain);
            byte[] value = root.GetHashAndReset();
            try
            {
                value.CopyTo(sha3RootKey);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(value);
            }
        }

        KeyedSkein1024.Compute(skeinMacKey, SkeinKeyDomain, SkeinLeafKeyLabel, skeinLeafKey);
        KeyedSkein1024.Compute(skeinMacKey, SkeinKeyDomain, SkeinRootKeyLabel, skeinRootKey);
    }

    private static async Task<LeafResult[]> ComputeSerialBatchAsync(
        LeafInput[] inputs,
        byte[] sha3LeafKey,
        byte[] skeinLeafKey, CancellationToken cancellationToken)
    {
        using CpuWorkBudget.Lease lease = await CpuWorkBudget.AcquireAsync(ArchiveOperationPolicy.Current.MaxCpuWorkers, 1, cancellationToken).ConfigureAwait(false);
        using IDisposable cpuScope = lease.EnterScope();
        var results = new LeafResult[inputs.Length];
        int completed = 0;
        try
        {
            for (; completed < inputs.Length; completed++)
            {
                results[completed] = ComputeLeaf(inputs[completed], sha3LeafKey, skeinLeafKey);
            }

            return results;
        }
        catch
        {
            for (int index = 0; index < completed; index++)
            {
                results[index].Dispose();
            }

            throw;
        }
    }

    private static async Task<LeafResult[]> ComputeParallelBatchAsync(
        LeafInput[] inputs,
        byte[] sha3LeafKey,
        byte[] skeinLeafKey,
        CancellationToken cancellationToken,
        Func<LeafInput, LeafResult>? computeOverride = null)
    {
        var tasks = new Task<LeafResult>[inputs.Length];
        int started = 0;
        try
        {
            for (; started < inputs.Length; started++)
            {
                LeafInput input = inputs[started];
                tasks[started] = Task.Run(
                    async () =>
                    {
                        using CpuWorkBudget.Lease lease = await CpuWorkBudget.AcquireAsync(
                            ArchiveOperationPolicy.Current.MaxCpuWorkers, 1, cancellationToken).ConfigureAwait(false);
                        using IDisposable cpuScope = lease.EnterScope();
                        return computeOverride is null ? ComputeLeaf(input, sha3LeafKey, skeinLeafKey) : computeOverride(input);
                    },
                    cancellationToken);
            }
        }
        catch (Exception schedulingFailure)
        {
            // A scheduler can fail after accepting an earlier worker. Those
            // workers still own the leaf inputs and both derived keys, so join
            // them before the caller's finally blocks erase either resource.
            Task<LeafResult>[] startedTasks = tasks.AsSpan(0, started).ToArray();
            Exception? joinFailure = null;
            try
            {
                await Task.WhenAll(startedTasks).ConfigureAwait(false);
            }
            catch (Exception failure)
            {
                joinFailure = failure;
            }

            foreach (Task<LeafResult> task in startedTasks)
            {
                if (task.Status == TaskStatus.RanToCompletion)
                {
                    task.Result.Dispose();
                }
            }

            Exception[] workerFailures = CollectTaskFailuresDeterministically(
                startedTasks,
                joinFailure);
            if (workerFailures.Length != 0)
            {
                throw new AggregateException(
                    "A parallel MAC worker could not be scheduled and an already-started worker also failed.",
                    CombineDistinctFailures(schedulingFailure, workerFailures));
            }

            ExceptionDispatchInfo.Capture(schedulingFailure).Throw();
            throw new UnreachableException();
        }

        Task<LeafResult[]> allWorkers = Task.WhenAll(tasks);
        try
        {
            return await allWorkers.ConfigureAwait(false);
        }
        catch (Exception awaitFailure)
        {
            // WhenAll observes and joins every worker.  Dispose results from
            // workers that completed before a sibling failed.
            foreach (Task<LeafResult> task in tasks)
            {
                if (task.Status == TaskStatus.RanToCompletion)
                {
                    task.Result.Dispose();
                }
            }

            Exception[] failures = CollectTaskFailuresDeterministically(tasks, awaitFailure);
            if (failures.Length == 1)
            {
                ExceptionDispatchInfo.Capture(failures[0]).Throw();
            }

            throw new AggregateException(
                "Multiple parallel MAC workers failed.",
                failures);
        }
    }

    internal static async Task RunLeafWorkersForFailureTestsAsync(
        IReadOnlyList<Exception> workerFailures)
    {
        ArgumentNullException.ThrowIfNull(workerFailures);
        if (workerFailures.Count < 2)
        {
            throw new ArgumentOutOfRangeException(nameof(workerFailures));
        }

        byte[] sha3Key = new byte[Sha3Bytes];
        byte[] skeinKey = new byte[SkeinBytes];
        var inputs = new LeafInput[workerFailures.Count];
        LeafResult[]? results = null;
        try
        {
            for (int index = 0; index < inputs.Length; index++)
            {
                inputs[index] = new LeafInput(index, [(byte)index]);
            }

            results = await ComputeParallelBatchAsync(
                inputs,
                sha3Key,
                skeinKey,
                CancellationToken.None,
                input => throw workerFailures[checked((int)input.Index)]).ConfigureAwait(false);
            throw new InvalidOperationException("The injected parallel MAC workers unexpectedly succeeded.");
        }
        finally
        {
            if (results is not null)
            {
                foreach (LeafResult result in results)
                {
                    result.Dispose();
                }
            }

            foreach (LeafInput? input in inputs)
            {
                input?.Dispose();
            }
            CryptographicOperations.ZeroMemory(sha3Key);
            CryptographicOperations.ZeroMemory(skeinKey);
        }
    }

    private static Exception[] CollectTaskFailuresDeterministically(
        IReadOnlyList<Task> tasks,
        Exception? fallback)
    {
        var failures = new List<Exception>();
        var seen = new HashSet<Exception>(ReferenceEqualityComparer.Instance);
        foreach (Task task in tasks)
        {
            if (task.Exception is not { } aggregate)
            {
                continue;
            }

            foreach (Exception failure in aggregate.Flatten().InnerExceptions)
            {
                if (seen.Add(failure))
                {
                    failures.Add(failure);
                }
            }
        }

        if (failures.Count == 0 && fallback is not null && seen.Add(fallback))
        {
            failures.Add(fallback);
        }

        return failures.ToArray();
    }

    private static Exception[] CombineDistinctFailures(
        Exception primary,
        IReadOnlyList<Exception> additional)
    {
        var combined = new List<Exception>(additional.Count + 1) { primary };
        var seen = new HashSet<Exception>(ReferenceEqualityComparer.Instance) { primary };
        foreach (Exception failure in additional)
        {
            if (seen.Add(failure))
            {
                combined.Add(failure);
            }
        }

        return combined.ToArray();
    }

    private static LeafResult ComputeLeaf(
        LeafInput input,
        byte[] sha3LeafKey,
        byte[] skeinLeafKey)
    {
        Span<byte> header = stackalloc byte[LeafDomain.Length + sizeof(long) + sizeof(int)];
        LeafDomain.CopyTo(header);
        int offset = LeafDomain.Length;
        BinaryPrimitives.WriteInt64BigEndian(header[offset..], input.Index);
        offset += sizeof(long);
        BinaryPrimitives.WriteInt32BigEndian(header[offset..], input.Data.Length);

        byte[]? sha3 = null;
        try
        {
            using (var hmac = new HmacSha3_512(sha3LeafKey))
            {
                hmac.AppendData(header);
                hmac.AppendData(input.Data);
                sha3 = hmac.GetHashAndReset();
            }

            using NativeSkein1024Mac skein = NativeThreefish.CreateSkeinMac(skeinLeafKey);
            skein.AppendData(header);
            skein.AppendData(input.Data);
            byte[] skeinTag = skein.GetTag();
            OperationMemoryBudget.ReportProgress(input.Data.Length);
            return new LeafResult(input.Index, input.Data.Length, sha3, skeinTag);
        }
        catch
        {
            if (sha3 is not null)
            {
                CryptographicOperations.ZeroMemory(sha3);
            }

            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(header);
        }
    }

    private static void AppendRootLeaf(
        HmacSha3_512 rootSha3,
        NativeSkein1024Mac rootSkein,
        LeafResult result)
    {
        Span<byte> header = stackalloc byte[sizeof(long) + sizeof(int)];
        BinaryPrimitives.WriteInt64BigEndian(header, result.Index);
        BinaryPrimitives.WriteInt32BigEndian(header[sizeof(long)..], result.Length);
        rootSha3.AppendData(header);
        rootSha3.AppendData(result.Sha3);
        rootSha3.AppendData(result.Skein);
        rootSkein.AppendData(header);
        rootSkein.AppendData(result.Sha3);
        rootSkein.AppendData(result.Skein);
        CryptographicOperations.ZeroMemory(header);
    }

    private sealed class LogicalStreamReader(
        IReadOnlyList<ReadOnlyMemory<byte>> prefix,
        Stream ciphertext,
        long ciphertextLength)
    {
        private int _prefixIndex;
        private int _prefixOffset;
        private long _ciphertextRead;

        internal long BytesRead { get; private set; }

        internal async Task ReadExactlyAsync(byte[] destination, CancellationToken cancellationToken)
        {
            int written = 0;
            while (written < destination.Length && _prefixIndex < prefix.Count)
            {
                ReadOnlyMemory<byte> current = prefix[_prefixIndex];
                int available = current.Length - _prefixOffset;
                if (available == 0)
                {
                    _prefixIndex++;
                    _prefixOffset = 0;
                    continue;
                }

                int take = Math.Min(available, destination.Length - written);
                current.Span.Slice(_prefixOffset, take).CopyTo(destination.AsSpan(written));
                _prefixOffset += take;
                written += take;
                BytesRead = checked(BytesRead + take);
            }

            while (written < destination.Length)
            {
                long remainingCiphertext = ciphertextLength - _ciphertextRead;
                if (remainingCiphertext <= 0)
                {
                    throw new EndOfStreamException("The ciphertext ended inside an authentication leaf.");
                }

                int requested = checked((int)Math.Min(destination.Length - written, remainingCiphertext));
                int read = await ciphertext.ReadAsync(
                    destination.AsMemory(written, requested),
                    cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    throw new EndOfStreamException("The ciphertext ended inside an authentication leaf.");
                }

                written += read;
                _ciphertextRead = checked(_ciphertextRead + read);
                BytesRead = checked(BytesRead + read);
            }
        }
    }

    private sealed class LeafInput(long index, byte[] data) : IDisposable
    {
        internal long Index { get; } = index;
        internal byte[] Data { get; } = data;

        public void Dispose() => CryptographicOperations.ZeroMemory(Data);
    }

    private sealed class LeafResult(
        long index,
        int length,
        byte[] sha3,
        byte[] skein) : IDisposable
    {
        internal long Index { get; } = index;
        internal int Length { get; } = length;
        internal byte[] Sha3 { get; } = sha3;
        internal byte[] Skein { get; } = skein;

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(Sha3);
            CryptographicOperations.ZeroMemory(Skein);
        }
    }

    private sealed class WorkerOverrideScope(int? previous) : IDisposable
    {
        private int _disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                WorkerOverride.Value = previous;
            }
        }
    }
}
