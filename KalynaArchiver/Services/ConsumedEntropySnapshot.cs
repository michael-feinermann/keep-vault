using System.Buffers.Binary;
using System.Security.Cryptography;
using KalynaArchiver.Signing;

namespace KalynaArchiver.Services;

/// <summary>Owns exactly one detached collection until all workers and cleanup finish.</summary>
internal sealed class ConsumedEntropySnapshot(
    SensitiveMouseRecordStore[] records, ulong[] epochs, EntropyPreparationKind kind, CancellationToken token) : IDisposable
{
    private readonly CancellationTokenSource _cancel = CancellationTokenSource.CreateLinkedTokenSource(token);
    private readonly object _disposeGate = new();
    private bool _disposed;
    private bool _running;
    private bool _started;
    private readonly TaskCompletionSource _completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal Task Completion => _completion.Task;
    internal void Cancel() { lock (_disposeGate) { if (!_disposed) _cancel.Cancel(); } }

    internal (LockedSensitiveBuffer First, LockedSensitiveBuffer? Second) Generate(
        Action<byte[], EntropyRandomRole> fill, Action<string>? phase = null)
    {
        lock (_disposeGate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_started) throw new InvalidOperationException("An entropy snapshot can be consumed only once.");
            _started = true;
            _running = true;
        }
        LockedSensitiveBuffer? first = null;
        LockedSensitiveBuffer? second = null;
        Exception? failure = null;
        try
        {
            using OperationProgressSource? progress = OperationProgressTracker.Current?.BeginPhase(
                OperationPhase.Entropy, ProgressUnit.Steps,
                checked(records.Length * (kind == EntropyPreparationKind.DualRound ? 2L : 1L)),
                ProgressTotalOrigin.ValidatedPlan);
            first = LockedSensitiveBuffer.Create(checked(records.Length * 64));
            second = kind == EntropyPreparationKind.DualRound ? LockedSensitiveBuffer.Create(checked(records.Length * 64)) : null;
            ArchiveOperationPolicy policy = ArchiveOperationPolicy.Current;
            Parallel.For(0, records.Length, new ParallelOptions
            {
                CancellationToken = _cancel.Token,
                MaxDegreeOfParallelism = Math.Min(records.Length, policy.MaxCpuWorkers),
            }, purpose =>
            {
                using CpuWorkBudget.Lease cpu = CpuWorkBudget.AcquireAsync(policy.MaxCpuWorkers, 1, _cancel.Token).AsTask().GetAwaiter().GetResult();
                using IDisposable cpuScope = cpu.EnterScope();
                using var qos = MacCpuWorkerQos.EnterSynchronousScope();
                Exception? poolFailure = null;
                try
                {
                    SensitiveMouseRecordStore pool = records[purpose];
                    pool.InitializeIndices(_cancel.Token);
                    phase?.Invoke("shuffle1");
                    Shuffle(pool, EntropyRandomRole.PoolShuffleRound1, fill, _cancel.Token);
                    phase?.Invoke("sha3");
                    Replay(pool, purpose, epochs[purpose], sha512: false, first.Bytes.AsSpan(purpose * 64, 64), _cancel.Token);
                    progress?.Advance(1);
                    if (second is not null)
                    {
                        // Round one has fully returned, including the disposal
                        // of every replay temporary and its exclusive RNG cache.
                        phase?.Invoke("shuffle2");
                        Shuffle(pool, EntropyRandomRole.PoolShuffleRound2, fill, _cancel.Token);
                        phase?.Invoke("sha512");
                        Replay(pool, purpose, epochs[purpose], sha512: true, second.Bytes.AsSpan(purpose * 64, 64), _cancel.Token);
                        progress?.Advance(1);
                    }
                }
                catch (Exception error) { poolFailure = error; _cancel.Cancel(); throw; }
                finally
                {
                    try { phase?.Invoke("cleanup"); records[purpose].Dispose(); }
                    catch (Exception cleanup)
                    {
                        _cancel.Cancel();
                        if (poolFailure is not null) throw new AggregateException(poolFailure, cleanup);
                        throw;
                    }
                }
            });
            _cancel.Token.ThrowIfCancellationRequested();
            DisposeRecords(); // includes never-started pools; success is a publication gate.
            var result = (first, second);
            first = null;
            second = null;
            return result;
        }
        catch (Exception error) { failure = error; throw; }
        finally
        {
            List<Exception> cleanupFailures = [];
            try { DisposeRecords(); } catch (Exception cleanup) { cleanupFailures.Add(cleanup); }
            try { EntropyMixer.DisposeEntropyOwners(null, "Consumed entropy digest cleanup failed.", first, second); } catch (Exception cleanup) { cleanupFailures.Add(cleanup); }
            lock (_disposeGate) _running = false;
            CryptographicOperations.ZeroMemory(System.Runtime.InteropServices.MemoryMarshal.AsBytes(epochs.AsSpan()));
            if (cleanupFailures.Count != 0)
            {
                var cleanup = new AggregateException("Consumed entropy cleanup failed.", failure is null ? cleanupFailures : [failure, .. cleanupFailures]);
                _completion.TrySetException(cleanup);
                throw cleanup;
            }
            _completion.TrySetResult();
        }
    }

    private static void Shuffle(SensitiveMouseRecordStore pool, EntropyRandomRole role,
        Action<byte[], EntropyRandomRole> fill, CancellationToken token)
    {
        var random = new PoolShuffleRandomSource(role, fill);
        Exception? failure = null;
        try { random.Shuffle(pool, token); }
        catch (Exception error) { failure = error; throw; }
        finally { EntropyMixer.DisposeEntropyOwners(failure, "Entropy shuffle cleanup failed.", random); }
    }

    internal static void Replay(SensitiveMouseRecordStore pool, int purpose, ulong epoch,
        bool sha512, Span<byte> output, CancellationToken token)
    {
        LockedSensitiveBuffer? accumulator = null, transcript = null;
        Exception? failure = null;
        try
        {
            accumulator = LockedSensitiveBuffer.Create(64);
            transcript = LockedSensitiveBuffer.Create(156);
            for (long position = 0; position < pool.Count; ++position)
            {
                token.ThrowIfCancellationRequested();
                accumulator.Bytes.CopyTo(transcript.Bytes, 0);
                pool.CopyRecord(pool.ReadIndex(position), transcript.Bytes.AsSpan(64, 80));
                transcript.Bytes.AsSpan(136, 8).CopyTo(transcript.Bytes.AsSpan(144, 8));
                BinaryPrimitives.WriteInt32LittleEndian(transcript.Bytes.AsSpan(152), purpose);
                int written = sha512 ? Sha512Compat.HashData(transcript.Bytes, accumulator.Bytes)
                    : Sha3_512Compat.HashData(transcript.Bytes, accumulator.Bytes);
                if (written != 64) throw new CryptographicException("Entropy replay returned an invalid digest width.");
            }
            token.ThrowIfCancellationRequested();
            FinalizePoolOutput(accumulator.Bytes, epoch, purpose, sha512, output);

        }
        catch (Exception error) { failure = error; throw; }
        finally { EntropyMixer.DisposeEntropyOwners(failure, "Entropy replay cleanup failed.", accumulator, transcript); }
    }

    internal static void FinalizePoolOutput(ReadOnlySpan<byte> accumulator, ulong epoch,
        int purpose, bool sha512, Span<byte> output)
    {
        if (accumulator.Length != 64 || output.Length != 64 || purpose is < 0 or > 10)
            throw new ArgumentException("A pool finalization requires a 64-byte accumulator/output and purpose 0..10.");
        LockedSensitiveBuffer? final = null;
        Exception? failure = null;
        try
        {
            final = LockedSensitiveBuffer.Create(80);
            accumulator.CopyTo(final.Bytes);
            BinaryPrimitives.WriteUInt64LittleEndian(final.Bytes.AsSpan(64), epoch);
            BinaryPrimitives.WriteInt32LittleEndian(final.Bytes.AsSpan(72), 0);
            BinaryPrimitives.WriteInt32LittleEndian(final.Bytes.AsSpan(76), purpose);
            int written = sha512 ? Sha512Compat.HashData(final.Bytes, output) : Sha3_512Compat.HashData(final.Bytes, output);
            if (written != 64) throw new CryptographicException("Entropy finalization returned an invalid digest width.");
        }
        catch (Exception error) { failure = error; CryptographicOperations.ZeroMemory(output); throw; }
        finally
        {
            try { EntropyMixer.DisposeEntropyOwners(failure, "Pool finalization cleanup failed.", final); }
            catch { CryptographicOperations.ZeroMemory(output); throw; }
        }
    }

    private void DisposeRecords()
    {
        EntropyMixer.DisposeEntropyOwners(null, "Pool cleanup is incomplete.", records);
    }

    public void Dispose()
    {
        lock (_disposeGate)
        {
            if (_disposed) return;
            if (_running) throw new InvalidOperationException("An active entropy snapshot must be joined before disposal.");
            DisposeRecords();
            _cancel.Dispose();
            _disposed = true;
        }
    }
}
