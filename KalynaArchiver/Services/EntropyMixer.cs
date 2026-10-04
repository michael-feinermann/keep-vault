using System.Buffers.Binary;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using KalynaArchiver.Signing;
#if WINDOWS
using System.Windows.Input;
#endif

namespace KalynaArchiver.Services;

public static partial class EntropyMixer
{
    private const int BcryptUseSystemPreferredRng = 0x00000002;
    internal const int PurposeCount = 11;
    public const long RequiredMouseSamplesPerPurpose = 1024;
    private static readonly object Gate = new();
    private static readonly object ResetGate = new();
    private static readonly HashSet<PreparationLease> ActivePreparations = [];
    private static long _collectionStartSequence;
    private static ulong _resetVersion;
    private static readonly EntropyPurpose[] SamplePurposes = Enum.GetValues<EntropyPurpose>();
    private static SensitiveMouseRecordStore[] MousePools = CreateMousePools();
    private static readonly long[] PurposeSampleCounts = new long[PurposeCount];
    private static readonly ulong[] DerivationCounters = new ulong[PurposeCount];
    private static readonly HashSet<ConsumedEntropySnapshot> ActiveSnapshots = [];
    private static readonly HashSet<IDisposable> PendingCleanup = [];
    private static long _systemRandomCallCount;
    private static long _sampleSequence;
    private static int _lastSystemRandomRequestBytes;
    private static bool _healthy = true;
    internal static Action<byte[], EntropyRandomRole>? RandomFillForTests;
    internal static Action<string>? PreparationPhaseForTests;

    public static long SampleCount => GetPoolStatus().Total;
    public static long FirstGeneratedPasswordSampleCount => Math.Min(
        GetSampleCount(EntropyPurpose.FactorA1), GetSampleCount(EntropyPurpose.FactorA2));
    public static long SecondGeneratedPasswordSampleCount => Math.Min(
        GetSampleCount(EntropyPurpose.FactorB1), GetSampleCount(EntropyPurpose.FactorB2));
    public static long SaltSampleCount => Math.Min(
        GetSampleCount(EntropyPurpose.SaltSha3), GetSampleCount(EntropyPurpose.SaltSkein));
    public static long NonceFirstSampleCount => GetSampleCount(EntropyPurpose.NonceFirst);
    public static long NonceSecondSampleCount => GetSampleCount(EntropyPurpose.NonceSecond);
    public static long NonceThirdSampleCount => GetSampleCount(EntropyPurpose.NonceThird);
    public static long NonceFourthSampleCount => GetSampleCount(EntropyPurpose.NonceFourth);
    public static long NonceFifthSampleCount => GetSampleCount(EntropyPurpose.NonceFifth);
    internal static long SystemRandomCallCountForTests => Interlocked.Read(ref _systemRandomCallCount);
    internal static int PendingCleanupCountForTests { get { lock (Gate) return PendingCleanup.Count; } }
    internal static int LastSystemRandomRequestBytesForTests => Volatile.Read(ref _lastSystemRandomRequestBytes);
    public static bool HasRequiredSamples(EntropyPurpose purpose) => GetSampleCount(purpose) >= RequiredMouseSamplesPerPurpose;
    public static long MissingSamples(EntropyPurpose purpose) => Math.Max(0, RequiredMouseSamplesPerPurpose - GetSampleCount(purpose));

    public static EntropyPoolStatus GetPoolStatus()
    {
        lock (Gate)
        {
            long total = 0;
            foreach (long count in PurposeSampleCounts)
            {
                total = checked(total + count);
            }

            return new EntropyPoolStatus(
                total,
                PurposeSampleCounts[(int)EntropyPurpose.FactorA1],
                PurposeSampleCounts[(int)EntropyPurpose.FactorA2],
                PurposeSampleCounts[(int)EntropyPurpose.FactorB1],
                PurposeSampleCounts[(int)EntropyPurpose.FactorB2],
                PurposeSampleCounts[(int)EntropyPurpose.SaltSha3],
                PurposeSampleCounts[(int)EntropyPurpose.SaltSkein],
                PurposeSampleCounts[(int)EntropyPurpose.NonceFirst],
                PurposeSampleCounts[(int)EntropyPurpose.NonceSecond],
                PurposeSampleCounts[(int)EntropyPurpose.NonceThird],
                PurposeSampleCounts[(int)EntropyPurpose.NonceFourth],
                PurposeSampleCounts[(int)EntropyPurpose.NonceFifth], _healthy);
        }
    }

    public static long GetSampleCount(EntropyPurpose purpose)
    {
        int purposeIndex = (int)purpose;
        if (purposeIndex < 0 || purposeIndex >= PurposeCount)
        {
            throw new ArgumentOutOfRangeException(nameof(purpose), "Unbekannter Entropiezweck.");
        }

        return Interlocked.Read(ref PurposeSampleCounts[purposeIndex]);
    }

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The next pool is transferred into MousePools only after successful hashing; every pre-transfer path disposes it, and all using declarations are compiler-generated finally blocks.")]
#if WINDOWS
    public static void AddMouseSample(
        double x,
        double y,
        int timestamp,
        MouseButtonState left,
        MouseButtonState right,
        MouseButtonState middle)
    {
        AddMouseSampleCore(x, y, timestamp, (int)left, (int)right, (int)middle);
    }
#endif

    public static void AddMouseSample(
        double x,
        double y,
        int timestamp,
        bool leftPressed,
        bool rightPressed,
        bool middlePressed)
    {
        AddMouseSampleCore(
            x,
            y,
            timestamp,
            leftPressed ? 1 : 0,
            rightPressed ? 1 : 0,
            middlePressed ? 1 : 0);
    }

    private static void AddMouseSampleCore(double x, double y, int timestamp, int left, int right, int middle)
    {
        if (!double.IsFinite(x) || !double.IsFinite(y)) return;
        LockedSensitiveBuffer sample = LockedSensitiveBuffer.Create(80);
        Exception? transientFailure = null;
        try
        {
        BinaryPrimitives.WriteInt64LittleEndian(sample.Bytes.AsSpan(0, 8), BitConverter.DoubleToInt64Bits(x));
        BinaryPrimitives.WriteInt64LittleEndian(sample.Bytes.AsSpan(8, 8), BitConverter.DoubleToInt64Bits(y));
        BinaryPrimitives.WriteInt32LittleEndian(sample.Bytes.AsSpan(16, 4), timestamp);
        BinaryPrimitives.WriteInt64LittleEndian(sample.Bytes.AsSpan(20, 8), Environment.TickCount64);
        BinaryPrimitives.WriteInt64LittleEndian(sample.Bytes.AsSpan(28, 8), DateTime.UtcNow.Ticks);
        BinaryPrimitives.WriteInt32LittleEndian(sample.Bytes.AsSpan(36, 4), left);
        BinaryPrimitives.WriteInt32LittleEndian(sample.Bytes.AsSpan(40, 4), right);
        BinaryPrimitives.WriteInt32LittleEndian(sample.Bytes.AsSpan(44, 4), middle);
        BinaryPrimitives.WriteInt32LittleEndian(sample.Bytes.AsSpan(48, 4), Environment.CurrentManagedThreadId);
        BinaryPrimitives.WriteInt32LittleEndian(sample.Bytes.AsSpan(52, 4), Environment.ProcessId);
        BinaryPrimitives.WriteInt64LittleEndian(sample.Bytes.AsSpan(56, 8), Stopwatch.GetTimestamp());
        BinaryPrimitives.WriteInt64LittleEndian(sample.Bytes.AsSpan(64, 8), GC.GetTotalMemory(forceFullCollection: false));
        AddCanonicalRecord(sample.Bytes);

        }
        catch (Exception error) { transientFailure = error; throw; }
        finally { DisposeEntropyOwners(transientFailure, "Entropy event temporary cleanup failed.", sample); }
    }

    internal static void AddCanonicalRecord(ReadOnlySpan<byte> original)
    {
        if (original.Length != 80) throw new ArgumentException("A mouse record is exactly 80 bytes.");
        LockedSensitiveBuffer sample = LockedSensitiveBuffer.Create(80);
        Exception? transientFailure = null;
        try
        {
        original.CopyTo(sample.Bytes);
        lock (Gate)
        {
            if (!_healthy) throw new InvalidOperationException("The mouse collection failed. Reset it before collecting again.");
            SensitiveMouseRecordStore.Segment? spare = null;
            Exception? failure = null;
            try
            {
                long nextSequence = checked(_sampleSequence + 1);
                foreach (SensitiveMouseRecordStore pool in MousePools)
                    if (pool.NeedsSegment) pool.ReserveSegmentMetadata();
                if (MousePools.Any(pool => pool.NeedsSegment))
                    spare = new SensitiveMouseRecordStore.Segment(ArchiveOperationPolicy.Current.EntropyCaptureBudgetBytes);
                int purpose = (int)SelectUniformPurpose(SamplePurposes, CancellationToken.None);
                long nextCount = checked(PurposeSampleCounts[purpose] + 1);
                BinaryPrimitives.WriteInt64LittleEndian(sample.Bytes.AsSpan(72), _sampleSequence);
                MousePools[purpose].Append(sample.Bytes, ref spare);
                PurposeSampleCounts[purpose] = nextCount;
                _sampleSequence = nextSequence;
            }
            catch (Exception error) { _healthy = false; failure = error; throw; }
            finally
            {
                try { DisposeEntropyOwners(null, "Unused entropy segment cleanup failed.", spare); }
                catch (Exception cleanup)
                {
                    _healthy = false;
                    if (failure is not null) throw new AggregateException(failure, cleanup);
                    throw;
                }
            }
        }

        }
        catch (Exception error) { transientFailure = error; throw; }
        finally { DisposeEntropyOwners(transientFailure, "Entropy event temporary cleanup failed.", sample); }
    }

    internal static EntropyPurpose SelectUniformPurpose(ReadOnlySpan<EntropyPurpose> catalog, CancellationToken token)
    {
        int slot = SelectUniformPurposeSlot(catalog.Length, token);
        return catalog[slot];
    }

    internal static int SelectUniformPurposeSlot(int count, CancellationToken token)
    {
        if (count <= 0) throw new ArgumentOutOfRangeException(nameof(count));
        ulong space = 1UL << 32;
        ulong limit = space - space % (uint)count;
        LockedSensitiveBuffer candidate = LockedSensitiveBuffer.Create(4);
        Exception? transientFailure = null;
        try
        {
        for (int attempt = 0; attempt < 128; ++attempt)
        {
            token.ThrowIfCancellationRequested();
            FillRandom(candidate.Bytes, EntropyRandomRole.PoolRouting);
            uint value = BinaryPrimitives.ReadUInt32LittleEndian(candidate.Bytes);
            CryptographicOperations.ZeroMemory(candidate.Bytes);
            if ((ulong)value < limit) return checked((int)((ulong)value % (uint)count));
        }
        throw new CryptographicException("The mouse routing random source exceeded its rejection budget.");

        }
        catch (Exception error) { transientFailure = error; throw; }
        finally { DisposeEntropyOwners(transientFailure, "Entropy event temporary cleanup failed.", candidate); }
    }

    // Reset joins the complete operation, including output XOR and publication,
    // rather than only its record readers. It never waits while holding Gate.
    public static void Reset()
    {
        lock (ResetGate)
        {
            PreparationLease[] active;
            lock (Gate)
            {
                ulong nextVersion = checked(_resetVersion + 1);
                ulong[] nextEpochs = DerivationCounters.Select(epoch => checked(epoch + 1)).ToArray();
                SensitiveMouseRecordStore[] replacement = CreateMousePools();
                PendingCleanup.EnsureCapacity(checked(PendingCleanup.Count + MousePools.Length));
                // Register every old owner before detaching it. A failed unlock
                // must remain reachable for the next explicit cleanup attempt.
                foreach (SensitiveMouseRecordStore pool in MousePools) PendingCleanup.Add(pool);
                MousePools = replacement;
                Array.Clear(PurposeSampleCounts);
                nextEpochs.CopyTo(DerivationCounters, 0);
                _collectionStartSequence = _sampleSequence;
                _resetVersion = nextVersion;
                active = [.. ActivePreparations];
                _healthy = false;
            }
            List<Exception> errors = [];
            foreach (PreparationLease operation in active)
                try { operation.Cancel(); } catch (Exception error) { errors.Add(error); }
            foreach (PreparationLease operation in active)
                try { operation.Completion.GetAwaiter().GetResult(); } catch (Exception error) { errors.Add(error); }
            IDisposable[] pending;
            lock (Gate) pending = [.. PendingCleanup, .. ActiveSnapshots];
            foreach (IDisposable owner in pending.Distinct())
                try { DisposeEntropyOwners(null, "Entropy reset cleanup failed.", owner); }
                catch (Exception error) { errors.Add(error); }
            lock (Gate) _healthy = errors.Count == 0 && PendingCleanup.Count == 0 && ActiveSnapshots.Count == 0;
            if (errors.Count != 0) throw new AggregateException("Entropy reset cleanup failed.", errors);
        }
    }

    // Cleanup attempts every owner and retains failed objects, not just their
    // underlying memory locks, so accounting and cancellation sources can retry.
    internal static void DisposeEntropyOwners(Exception? original, string message, params IDisposable?[] owners)
    {
        foreach (IDisposable? owner in owners)
            if (owner is LockedSensitiveBuffer buffer) buffer.ZeroForDisposal();
        List<Exception> errors = [];
        foreach (IDisposable? owner in owners)
        {
            if (owner is null) continue;
            try
            {
                owner.Dispose();
                lock (Gate)
                {
                    PendingCleanup.Remove(owner);
                    if (owner is ConsumedEntropySnapshot snapshot) ActiveSnapshots.Remove(snapshot);
                }
            }
            catch (Exception cleanup)
            {
                lock (Gate) { PendingCleanup.Add(owner); _healthy = false; }
                errors.Add(cleanup);
            }
        }
        if (errors.Count != 0)
            throw new AggregateException(message, original is null ? errors : [original, .. errors]);
    }

    private sealed class PreparationLease : IDisposable
    {
        private readonly CancellationTokenSource _cancel;
        private readonly TaskCompletionSource _completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly ulong _version;
        private bool _disposed;
        private bool _committed;
        internal CancellationToken Token => _cancel.Token;
        internal Task Completion => _completion.Task;
        internal PreparationLease(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            _cancel = CancellationTokenSource.CreateLinkedTokenSource(token);
            lock (Gate)
            {
                if (!_healthy) { _cancel.Dispose(); throw new InvalidOperationException("Reset the failed mouse collection before generation."); }
                _version = _resetVersion;
                ActivePreparations.Add(this);
            }
        }
        internal void Cancel() { lock (Gate) { if (!_disposed && !_committed) _cancel.Cancel(); } }
        internal void CommitPublication()
        {
            lock (Gate)
            {
                Token.ThrowIfCancellationRequested();
                if (!_healthy || _version != _resetVersion) throw new OperationCanceledException("Entropy preparation was reset.");
                _committed = true;
            }
        }
        public void Dispose()
        {
            lock (Gate)
            {
                if (_disposed) return;
                _disposed = true;
                ActivePreparations.Remove(this);
                _cancel.Dispose();
                _completion.TrySetResult();
            }
        }
    }

    internal const int SaltPairBytes = 128;
    private const int PoolDrawBytes = 64;

    internal static GeneratedArchiveEntropy CreateArchiveEntropy(EntropyPreparationKind kind = EntropyPreparationKind.DualRound, CancellationToken cancellationToken = default, IProgress<string>? progress = null)
    {
        if (kind is not (EntropyPreparationKind.SingleRound or EntropyPreparationKind.DualRound)) throw new ArgumentOutOfRangeException(nameof(kind));
        using var operation = new PreparationLease(cancellationToken);
        // A fixed preparation plan consumes all eleven record pools once.
        // DualRound performs fresh shuffles and independent replay accumulators
        // over that same immutable record snapshot before clearing it.
        LockedSensitiveBuffer? firstMouse = null;
        LockedSensitiveBuffer? secondMouse = null;
        LockedSensitiveBuffer? passwordBytes = null;
        LockedSensitiveBuffer? salt = null;
        LockedSensitiveBuffer? fullNonce = null;
        LockedSensitiveBuffer? secondSalt = null;
        LockedSensitiveBuffer? secondFullNonce = null;
        GeneratedArchiveEntropy? completed = null;
        Exception? operationFailure = null;
        try
        {
            (firstMouse, secondMouse) = ExpandAndConsumeMousePoolsCore(PoolDrawBytes, SamplePurposes, kind == EntropyPreparationKind.DualRound, operation.Token, progress);
            passwordBytes = LockedSensitiveBuffer.Create(4 * Sha3_512Compat.HashSizeInBytes);
            FillSystemRandom(passwordBytes.Bytes);
            // A factor is 1024 bits and comes from two pools laid end to
            // end: A = A1 || A2, B = B1 || B2. Splitting a factor across two
            // pools is defence in depth, not a claim that either pool holds 512
            // bits of real entropy; the system CSPRNG XORed in below stays the
            // primary source.
            //
            // Both factors come from the first expansion only. They have to be
            // identical across both Paranoia rounds -- that is what makes round
            // two a second key rather than a second archive.
            const int Half = 64;
            for (int half = 0; half < 4; half++)
            {
                XorInPlace(
                    passwordBytes.Bytes.AsSpan(half * Half, Half),
                    firstMouse.Bytes.AsSpan(half * PoolDrawBytes, Half));
            }

            (salt, fullNonce) = SplitPreparedSaltAndNonce(firstMouse);
            if (secondMouse is not null) (secondSalt, secondFullNonce) = SplitPreparedSaltAndNonce(secondMouse);

            string firstPassword = Convert.ToHexString(passwordBytes.Bytes.AsSpan(0, 128));
            string secondPassword = Convert.ToHexString(passwordBytes.Bytes.AsSpan(128, 128));
            if (string.Equals(firstPassword, secondPassword, StringComparison.Ordinal))
            {
                throw new CryptographicException("The independently generated password factors unexpectedly match.");
            }

            completed = new GeneratedArchiveEntropy(
                firstPassword,
                secondPassword,
                salt,
                fullNonce,
                secondSalt,
                secondFullNonce);
            salt = null;
            fullNonce = null;
            secondSalt = null;
            secondFullNonce = null;
            DisposeEntropyOwners(null, "Archive entropy temporaries could not be released.", passwordBytes, secondMouse, firstMouse);
            passwordBytes = null; secondMouse = null; firstMouse = null;
            PreparationPhaseForTests?.Invoke("before-publication");
            operation.CommitPublication();
            return completed;
        }
        catch (Exception failure)
        {
            operationFailure = failure;
            throw;
        }
        finally
        {
            DisposeEntropyOwners(operationFailure, "Entropy preparation cleanup failed.",
                secondFullNonce, secondSalt, fullNonce, salt, passwordBytes, secondMouse, firstMouse,
                operationFailure is null ? null : completed);
        }
    }

    /// <summary>
    /// Takes a full-width salt pair and nonce out of one expanded pool block.
    /// </summary>
    /// <remarks>
    /// The salt buffer is the pair: the SHA3 branch's salt followed by the
    /// Skein branch's, each from its own pool. They travel together because
    /// every path that handles a salt handles both of them.
    /// </remarks>
    private static (LockedSensitiveBuffer Salt, LockedSensitiveBuffer Nonce) SplitPreparedSaltAndNonce(
        LockedSensitiveBuffer mouseBytes)
    {
        LockedSensitiveBuffer? salt = null;
        LockedSensitiveBuffer? nonce = null;
        LockedSensitiveBuffer? sha3Csprng = null;
        LockedSensitiveBuffer? skeinCsprng = null;
        LockedSensitiveBuffer? completedSalt = null;
        LockedSensitiveBuffer? completedNonce = null;
        Exception? operationFailure = null;
        try
        {
            sha3Csprng = LockedSensitiveBuffer.Create(Sha3_512Compat.HashSizeInBytes);
            skeinCsprng = LockedSensitiveBuffer.Create(Sha3_512Compat.HashSizeInBytes);
            FillSystemRandom(sha3Csprng.Bytes);
            FillSystemRandom(skeinCsprng.Bytes);

            salt = LockedSensitiveBuffer.Create(SaltPairBytes);
            sha3Csprng.Bytes.CopyTo(salt.Bytes.AsSpan(0, Sha3_512Compat.HashSizeInBytes));
            skeinCsprng.Bytes.CopyTo(salt.Bytes.AsSpan(Sha3_512Compat.HashSizeInBytes, Sha3_512Compat.HashSizeInBytes));

            XorInPlace(
                salt.Bytes.AsSpan(0, Sha3_512Compat.HashSizeInBytes),
                mouseBytes.Bytes.AsSpan(4 * PoolDrawBytes, Sha3_512Compat.HashSizeInBytes));
            XorInPlace(
                salt.Bytes.AsSpan(Sha3_512Compat.HashSizeInBytes, Sha3_512Compat.HashSizeInBytes),
                mouseBytes.Bytes.AsSpan(5 * PoolDrawBytes, Sha3_512Compat.HashSizeInBytes));

            nonce = LockedSensitiveBuffer.Create(EncryptionSuiteCatalog.ArchiveNonceBytes);
            FillSystemRandom(nonce.Bytes);
            XorInPlace(
                nonce.Bytes,
                mouseBytes.Bytes.AsSpan(6 * PoolDrawBytes, EncryptionSuiteCatalog.ArchiveNonceBytes));

            completedSalt = salt;
            completedNonce = nonce;
            salt = null;
            nonce = null;
            return (completedSalt, completedNonce);
        }
        catch (Exception failure)
        {
            operationFailure = failure;
            throw;
        }
        finally
        {
            try
            {
                DisposeEntropyOwners(
                    operationFailure,
                    "Prepared salt/nonce derivation failed and one or more sensitive buffers could not be released.",
                    nonce,
                    salt,
                    skeinCsprng,
                    sha3Csprng);
            }
            catch (Exception cleanupFailure)
            {
                if (completedSalt is null && completedNonce is null)
                {
                    throw;
                }

                DisposeEntropyOwners(
                    cleanupFailure,
                    "Prepared salt/nonce cleanup failed and the completed result could not be released.",
                    completedNonce,
                    completedSalt);
                throw;
            }
        }
    }

    /// <summary>
    /// Salt and nonce for both Argon2id rounds of a two-round suite.
    /// </summary>
    /// <remarks>
    /// Only the paranoia cascade needs this. Every other suite runs one round
    /// and keeps using <see cref="CreateEncryptionParameters"/>.
    ///
    /// Both rounds are drawn from a single pool consumption, because consuming
    /// the pools twice would mean asking the user to collect the whole mouse
    /// entropy a second time. Each pool is shuffled independently in each
    /// round, then replayed from zero with SHA3-512 or SHA-512 respectively,
    /// and each is XORed with its own independent draw from the system
    /// generator, so neither salt nor either nonce set can be derived from the
    /// other.
    ///
    /// Both salts and both nonce sets have to reach the container header. An
    /// archive whose header carries only the first round cannot be decrypted by
    /// anyone, including the machine that wrote it.
    /// </remarks>
    internal static TwoRoundEncryptionParameters CreateTwoRoundEncryptionParameters(EncryptionSuite suite, CancellationToken cancellationToken = default)
    {
        using var operation = new PreparationLease(cancellationToken);
        if (!EncryptionSuiteCatalog.IsKnown(suite))
        {
            throw new ArgumentOutOfRangeException(nameof(suite), suite, "Unbekanntes Verschluesselungsverfahren.");
        }
        if (!EncryptionSuiteCatalog.Get(suite).UsesTwoKdfRounds)
            throw new ArgumentException("This suite requires single-round preparation.", nameof(suite));

        LockedSensitiveBuffer? firstMouse = null;
        LockedSensitiveBuffer? secondMouse = null;
        LockedSensitiveBuffer? firstSalt = null;
        LockedSensitiveBuffer? firstNonce = null;
        LockedSensitiveBuffer? secondSalt = null;
        LockedSensitiveBuffer? secondNonce = null;
        TwoRoundEncryptionParameters? completed = null;
        Exception? operationFailure = null;
        try
        {
            (firstMouse, secondMouse) = ExpandAndConsumeMousePoolsDual(
                PoolDrawBytes,
                [
                    EntropyPurpose.SaltSha3,
                    EntropyPurpose.SaltSkein,
                    EntropyPurpose.NonceFirst,
                    EntropyPurpose.NonceSecond,
                    EntropyPurpose.NonceThird,
                    EntropyPurpose.NonceFourth,
                    EntropyPurpose.NonceFifth,
                ], operation.Token);
            (firstSalt, firstNonce) = SplitSaltAndNonce(firstMouse, suite);
            (secondSalt, secondNonce) = SplitSaltAndNonce(secondMouse, suite);

            // Two rounds that produced the same salt would mean the pools, the
            // two hashes and two independent system draws had all coincided.
            // That cannot happen by chance, so if it happens something is
            // broken badly enough that no archive should be written.
            if (CryptographicOperations.FixedTimeEquals(firstSalt.Bytes, secondSalt.Bytes))
            {
                throw new CryptographicException("Both Argon2id rounds produced the same salt.");
            }

            completed = new TwoRoundEncryptionParameters(firstSalt, firstNonce, secondSalt, secondNonce);
            firstSalt = null;
            firstNonce = null;
            secondSalt = null;
            secondNonce = null;
            DisposeEntropyOwners(null, "Two-round entropy temporaries could not be released.", secondMouse, firstMouse);
            secondMouse = null; firstMouse = null;
            PreparationPhaseForTests?.Invoke("before-publication");
            operation.CommitPublication();
            return completed;
        }
        catch (Exception failure)
        {
            operationFailure = failure;
            throw;
        }
        finally
        {
            DisposeEntropyOwners(operationFailure, "Entropy preparation cleanup failed.",
                secondNonce, secondSalt, firstNonce, firstSalt, secondMouse, firstMouse,
                operationFailure is null ? null : completed);
        }
    }

    /// <summary>
    /// Turns one expanded pool block into a salt and a nonce, each XORed with
    /// its own draw from the system generator.
    /// </summary>
    private static (LockedSensitiveBuffer Salt, LockedSensitiveBuffer Nonce) SplitSaltAndNonce(
        LockedSensitiveBuffer mouseBytes,
        EncryptionSuite suite)
    {
        LockedSensitiveBuffer? salt = null;
        LockedSensitiveBuffer? fullNonce = null;
        LockedSensitiveBuffer? selectedNonce = null;
        LockedSensitiveBuffer? sha3Csprng = null;
        LockedSensitiveBuffer? skeinCsprng = null;
        LockedSensitiveBuffer? completedSalt = null;
        LockedSensitiveBuffer? completedNonce = null;
        Exception? operationFailure = null;
        try
        {
            sha3Csprng = LockedSensitiveBuffer.Create(Sha3_512Compat.HashSizeInBytes);
            skeinCsprng = LockedSensitiveBuffer.Create(Sha3_512Compat.HashSizeInBytes);
            FillSystemRandom(sha3Csprng.Bytes);
            FillSystemRandom(skeinCsprng.Bytes);

            salt = LockedSensitiveBuffer.Create(SaltPairBytes);
            sha3Csprng.Bytes.CopyTo(salt.Bytes.AsSpan(0, Sha3_512Compat.HashSizeInBytes));
            skeinCsprng.Bytes.CopyTo(salt.Bytes.AsSpan(Sha3_512Compat.HashSizeInBytes, Sha3_512Compat.HashSizeInBytes));

            XorInPlace(
                salt.Bytes.AsSpan(0, Sha3_512Compat.HashSizeInBytes),
                mouseBytes.Bytes.AsSpan(0, Sha3_512Compat.HashSizeInBytes));
            XorInPlace(
                salt.Bytes.AsSpan(Sha3_512Compat.HashSizeInBytes, Sha3_512Compat.HashSizeInBytes),
                mouseBytes.Bytes.AsSpan(PoolDrawBytes, Sha3_512Compat.HashSizeInBytes));

            // All suites keep all five 64-byte pool digests in the header basis.
            fullNonce = LockedSensitiveBuffer.Create(EncryptionSuiteCatalog.ArchiveNonceBytes);
            FillSystemRandom(fullNonce.Bytes);
            XorInPlace(
                fullNonce.Bytes,
                mouseBytes.Bytes.AsSpan(2 * PoolDrawBytes, EncryptionSuiteCatalog.ArchiveNonceBytes));

            if (EncryptionSuiteCatalog.Get(suite).ArchiveNonceBytes != fullNonce.Bytes.Length)
                throw new CryptographicException("Archive nonce width differs from the fixed v13 basis.");
            selectedNonce = fullNonce;
            fullNonce = null;

            completedSalt = salt;
            completedNonce = selectedNonce;
            salt = null;
            selectedNonce = null;
            return (completedSalt, completedNonce);
        }
        catch (Exception failure)
        {
            operationFailure = failure;
            throw;
        }
        finally
        {
            try
            {
                DisposeEntropyOwners(
                    operationFailure,
                    "Salt/nonce derivation failed and one or more sensitive buffers could not be released.",
                    selectedNonce,
                    fullNonce,
                    salt,
                    skeinCsprng,
                    sha3Csprng);
            }
            catch (Exception cleanupFailure)
            {
                if (completedSalt is null && completedNonce is null)
                {
                    throw;
                }

                DisposeEntropyOwners(
                    cleanupFailure,
                    "Salt/nonce cleanup failed and the completed result could not be released.",
                    completedNonce,
                    completedSalt);
                throw;
            }
        }
    }

    internal static (LockedSensitiveBuffer Salt, LockedSensitiveBuffer Nonce) CreateEncryptionParameters(EncryptionSuite suite, CancellationToken cancellationToken = default)
    {
        using var operation = new PreparationLease(cancellationToken);
        if (!EncryptionSuiteCatalog.IsKnown(suite))
        {
            throw new ArgumentOutOfRangeException(nameof(suite), suite, "Unbekanntes Verschluesselungsverfahren.");
        }
        if (EncryptionSuiteCatalog.Get(suite).UsesTwoKdfRounds)
            throw new ArgumentException("This suite requires dual-round preparation.", nameof(suite));

        LockedSensitiveBuffer? mouseBytes = null;
        LockedSensitiveBuffer? salt = null;
        LockedSensitiveBuffer? nonce = null;
        LockedSensitiveBuffer? completedSalt = null;
        LockedSensitiveBuffer? completedNonce = null;
        Exception? operationFailure = null;
        try
        {
            mouseBytes = ExpandAndConsumeMousePools(
                PoolDrawBytes,
                [
                    EntropyPurpose.SaltSha3,
                    EntropyPurpose.SaltSkein,
                    EntropyPurpose.NonceFirst,
                    EntropyPurpose.NonceSecond,
                    EntropyPurpose.NonceThird,
                    EntropyPurpose.NonceFourth,
                    EntropyPurpose.NonceFifth,
                ], operation.Token);
            (salt, nonce) = SplitSaltAndNonce(mouseBytes, suite);
            completedSalt = salt;
            completedNonce = nonce;
            salt = null;
            nonce = null;
            DisposeEntropyOwners(null, "Direct entropy temporaries could not be released.", mouseBytes);
            mouseBytes = null;
            PreparationPhaseForTests?.Invoke("before-publication");
            operation.CommitPublication();
            return (completedSalt, completedNonce);
        }
        catch (Exception failure)
        {
            operationFailure = failure;
            throw;
        }
        finally
        {
            DisposeEntropyOwners(operationFailure, "Entropy preparation cleanup failed.",
                nonce, salt, mouseBytes,
                operationFailure is null ? null : completedSalt, operationFailure is null ? null : completedNonce);
        }
    }

    private static void XorInPlace(Span<byte> destination, ReadOnlySpan<byte> source)
    {
        if (destination.Length != source.Length)
        {
            throw new ArgumentException("Entropy inputs must have identical lengths.", nameof(source));
        }

        for (int index = 0; index < destination.Length; index++)
        {
            destination[index] ^= source[index];
        }
    }

    private static LockedSensitiveBuffer ExpandAndConsumeMousePools(
        int byteCountPerPool,
        EntropyPurpose[] purposes, CancellationToken token)
        => ExpandAndConsumeMousePoolsCore(byteCountPerPool, purposes, secondRound: false, token).First;

    /// <summary>
    /// Expands the pools twice in one pass: once through SHA3-512 and once
    /// through SHA-512.
    /// </summary>
    /// <remarks>
    /// The paranoia suite runs Argon2id twice, and the second round
    /// needs its own salt and its own nonces. It cannot simply call the
    /// single-round expansion again: that call *consumes* the pools — it swaps
    /// in fresh buffers and resets every sample count to zero — so a second
    /// call would demand another <see cref="RequiredMouseSamplesPerPurpose"/>
    /// mouse samples per pool from a user who has already collected them once.
    ///
    /// Both rounds therefore come from the same snapshot, separated by the hash
    /// that expands it. SHA3-512 and SHA-512 are different constructions —
    /// Keccak against Merkle-Damgard — so neither output tells anything about
    /// the other, and no second pool has to be filled.
    /// </remarks>
    private static (LockedSensitiveBuffer First, LockedSensitiveBuffer Second) ExpandAndConsumeMousePoolsDual(
        int byteCountPerPool,
        EntropyPurpose[] purposes, CancellationToken token)
    {
        (LockedSensitiveBuffer first, LockedSensitiveBuffer? second) =
            ExpandAndConsumeMousePoolsCore(byteCountPerPool, purposes, secondRound: true, token);
        return (first, second!);
    }

    private static (LockedSensitiveBuffer First, LockedSensitiveBuffer? Second) ExpandAndConsumeMousePoolsCore(
        int byteCountPerPool, EntropyPurpose[] purposes, bool secondRound, CancellationToken token, IProgress<string>? progress = null)
    {
        if (byteCountPerPool != 64) throw new ArgumentOutOfRangeException(nameof(byteCountPerPool));
        ArgumentNullException.ThrowIfNull(purposes);
        if (purposes.Length == 0 || purposes.Distinct().Count() != purposes.Length
            || purposes.Any(purpose => !SamplePurposes.Contains(purpose)))
            throw new ArgumentException("Invalid entropy purpose selection.", nameof(purposes));
        ConsumedEntropySnapshot snapshot;
        lock (Gate)
        {
            token.ThrowIfCancellationRequested();
            if (!_healthy || PurposeSampleCounts.Any(count => count < RequiredMouseSamplesPerPurpose))
                throw new InvalidOperationException("All eleven mouse pools need at least 1024 stored records before generation.");
            long total = 0;
            for (int i = 0; i < PurposeCount; ++i)
            {
                if (MousePools[i].Count != PurposeSampleCounts[i])
                    throw new InvalidOperationException("Mouse-record count does not match the committed snapshot.");
                total = checked(total + PurposeSampleCounts[i]);
            }
            if (total <= 0 || total != checked(_sampleSequence - _collectionStartSequence)) throw new InvalidOperationException("Mouse snapshot sequence does not match committed counts.");
            ulong[] epochs = (ulong[])DerivationCounters.Clone();
            ulong[] next = epochs.Select(epoch => checked(epoch + 1)).ToArray();
            SensitiveMouseRecordStore[] replacement = CreateMousePools();
            ActiveSnapshots.EnsureCapacity(checked(ActiveSnapshots.Count + 1));
            snapshot = new ConsumedEntropySnapshot(MousePools, epochs,
                secondRound ? EntropyPreparationKind.DualRound : EntropyPreparationKind.SingleRound, token);
            ActiveSnapshots.Add(snapshot);
            foreach (SensitiveMouseRecordStore pool in MousePools) pool.Seal();
            MousePools = replacement;
            _collectionStartSequence = _sampleSequence;
            next.CopyTo(DerivationCounters, 0);
            Array.Clear(PurposeSampleCounts);
        }
        LockedSensitiveBuffer? allFirst = null;
        LockedSensitiveBuffer? allSecond = null;
        LockedSensitiveBuffer? selectedFirst = null;
        LockedSensitiveBuffer? selectedSecond = null;
        Exception? failure = null;
        try
        {
            (allFirst, allSecond) = snapshot.Generate(FillRandom, phase => { PreparationPhaseForTests?.Invoke(phase); progress?.Report(phase); });
            selectedFirst = LockedSensitiveBuffer.Create(checked(purposes.Length * 64));
            selectedSecond = secondRound ? LockedSensitiveBuffer.Create(checked(purposes.Length * 64)) : null;
            for (int i = 0; i < purposes.Length; ++i)
            {
                allFirst.Bytes.AsSpan((int)purposes[i] * 64, 64).CopyTo(selectedFirst.Bytes.AsSpan(i * 64, 64));
                if (selectedSecond is not null) allSecond!.Bytes.AsSpan((int)purposes[i] * 64, 64).CopyTo(selectedSecond.Bytes.AsSpan(i * 64, 64));
            }
            DisposeEntropyOwners(null, "Entropy digest cleanup failed.", allFirst, allSecond);
            allFirst = null; allSecond = null;
            DisposeEntropyOwners(null, "Entropy snapshot cleanup failed.", snapshot);
            var result = (selectedFirst, selectedSecond);
            selectedFirst = null; selectedSecond = null;
            return result;
        }
        catch (Exception error) { failure = error; throw; }
        finally
        {
            DisposeEntropyOwners(failure, "Entropy snapshot/result cleanup failed.",
                snapshot, allFirst, allSecond, selectedFirst, selectedSecond);
        }
    }

    private static void FillRandom(byte[] buffer, EntropyRandomRole role)
    {
        if (RandomFillForTests is { } testFill) { testFill(buffer, role); return; }
        FillSystemRandomCore(buffer);
        if (role == EntropyRandomRole.OutputXor)
        {
            Volatile.Write(ref _lastSystemRandomRequestBytes, buffer.Length);
            Interlocked.Increment(ref _systemRandomCallCount);
        }
    }

    private static void FillSystemRandom(byte[] buffer) => FillRandom(buffer, EntropyRandomRole.OutputXor);

    private static void FillSystemRandomCore(byte[] buffer)
    {
        int status = OperatingSystem.IsWindows()
            ? BCryptGenRandom(0, buffer, buffer.Length, BcryptUseSystemPreferredRng)
            : OperatingSystem.IsMacOS()
                ? SecRandomCopyBytes(0, checked((nuint)buffer.Length), buffer)
                : throw new PlatformNotSupportedException("A reviewed operating-system CSPRNG adapter is required.");
        if (status != 0)
        {
            throw new CryptographicException($"The operating-system CSPRNG failed: 0x{status:X8}");
        }

    }

    private static SensitiveMouseRecordStore[] CreateMousePools() =>
        Enumerable.Range(0, PurposeCount).Select(_ => new SensitiveMouseRecordStore()).ToArray();

    [LibraryImport("bcrypt.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial int BCryptGenRandom(nint hAlgorithm, [Out] byte[] pbBuffer, int cbBuffer, int dwFlags);

    [LibraryImport("/System/Library/Frameworks/Security.framework/Security")]
    private static partial int SecRandomCopyBytes(nint random, nuint count, [Out] byte[] bytes);
}

/// <summary>
/// Committed counts of the eleven independently routed pools.
/// </summary>
/// <remarks>
/// A1/A2 and B1/B2 are reported separately because they are separate pools, but
/// the interface must not present them as four user factors: the user has two,
/// each 1024 bits wide.
/// </remarks>
public readonly record struct EntropyPoolStatus(
    long Total,
    long FactorA1,
    long FactorA2,
    long FactorB1,
    long FactorB2,
    long SaltSha3,
    long SaltSkein,
    long NonceFirst,
    long NonceSecond,
    long NonceThird,
    long NonceFourth,
    long NonceFifth,
    bool Healthy = true)
{
    private long[] All =>
        [FactorA1, FactorA2, FactorB1, FactorB2, SaltSha3, SaltSkein, NonceFirst, NonceSecond, NonceThird, NonceFourth, NonceFifth];

    public long Minimum => All.Min();

    public long Maximum => All.Max();

    public bool IsReady => Healthy && Minimum >= EntropyMixer.RequiredMouseSamplesPerPurpose;

    /// <summary>The lower of the two halves that make up factor A.</summary>
    public long FactorA => Math.Min(FactorA1, FactorA2);

    /// <summary>The lower of the two halves that make up factor B.</summary>
    public long FactorB => Math.Min(FactorB1, FactorB2);
}

/// <summary>
/// Salt and nonce for each of the two Argon2id rounds of a two-round suite.
/// </summary>
/// <remarks>
/// Written out as four separate values rather than two concatenated blobs. An
/// off-by-one that handed round two round one's salt would still encrypt and
/// still decrypt on the same build, and would only surface as an unreadable
/// archive somewhere else — which, with no backward compatibility, is
/// unrecoverable.
/// </remarks>
internal sealed class TwoRoundEncryptionParameters : IDisposable
{
    internal TwoRoundEncryptionParameters(
        LockedSensitiveBuffer firstSalt,
        LockedSensitiveBuffer firstNonce,
        LockedSensitiveBuffer secondSalt,
        LockedSensitiveBuffer secondNonce)
    {
        FirstSalt = firstSalt;
        FirstNonce = firstNonce;
        SecondSalt = secondSalt;
        SecondNonce = secondNonce;
    }

    internal LockedSensitiveBuffer FirstSalt { get; }

    internal LockedSensitiveBuffer FirstNonce { get; }

    internal LockedSensitiveBuffer SecondSalt { get; }

    internal LockedSensitiveBuffer SecondNonce { get; }

    public void Dispose()
    {
        SecureMemory.ZeroAndDisposeAll(
            SecondNonce,
            SecondSalt,
            FirstNonce,
            FirstSalt);
    }
}

/// <summary>
/// The eleven independent mouse-entropy pools an archive draws on.
/// </summary>
/// <remarks>
/// A1/A2 and B1/B2 are internal sources, not four user-facing factors: each
/// pair is concatenated into one 1024-bit factor that the user ever sees. The
/// two salt purposes are separate because the two Argon2id branches of a round
/// must not share a salt.
///
/// The count of mouse samples is not a proof of entropy. The operating-system
/// CSPRNG remains the primary source; these pools are defence in depth.
/// </remarks>
public enum EntropyPurpose
{
    FactorA1 = 0,
    FactorA2 = 1,
    FactorB1 = 2,
    FactorB2 = 3,
    SaltSha3 = 4,
    SaltSkein = 5,
    NonceFirst = 6,
    NonceSecond = 7,
    NonceThird = 8,
    NonceFourth = 9,
    NonceFifth = 10,
}

internal sealed class GeneratedArchiveEntropy : IDisposable
{
    internal static Action? TestHookAfterConsumption { get; set; }
    private readonly object _gate = new();
    private LockedSensitiveBuffer? _salt;
    private LockedSensitiveBuffer? _fullNonce;
    private LockedSensitiveBuffer? _secondSalt;
    private LockedSensitiveBuffer? _secondFullNonce;
    private LockedSensitiveBuffer? _firstFactor;
    private LockedSensitiveBuffer? _secondFactor;
    private bool _consumptionStarted;
    private bool _disposed;

    /// <remarks>
    /// Both rounds are prepared here, from one consumption of the pools, because
    /// the suite is not known when the user generates the factors. A suite that
    /// derives one round simply never asks for the second pair, and it is wiped
    /// with the rest.
    /// </remarks>
    internal GeneratedArchiveEntropy(
        string firstPassword,
        string secondPassword,
        LockedSensitiveBuffer salt,
        LockedSensitiveBuffer fullNonce,
        LockedSensitiveBuffer? secondSalt,
        LockedSensitiveBuffer? secondFullNonce)
    {
        ArgumentNullException.ThrowIfNull(firstPassword);
        ArgumentNullException.ThrowIfNull(secondPassword);
        _salt = salt ?? throw new ArgumentNullException(nameof(salt));
        _fullNonce = fullNonce ?? throw new ArgumentNullException(nameof(fullNonce));
        _secondSalt = secondSalt;
        _secondFullNonce = secondFullNonce;
        if (_salt.Bytes.Length != EntropyMixer.SaltPairBytes
            || (_secondSalt is null) != (_secondFullNonce is null)
            || (_secondSalt is not null && _secondSalt.Bytes.Length != EntropyMixer.SaltPairBytes)
            || _fullNonce.Bytes.Length != EncryptionSuiteCatalog.ArchiveNonceBytes
            || (_secondFullNonce is not null && _secondFullNonce.Bytes.Length != EncryptionSuiteCatalog.ArchiveNonceBytes))
        {
            throw new ArgumentException("Prepared archive entropy has an invalid length.");
        }

        if (_secondSalt is not null && CryptographicOperations.FixedTimeEquals(_salt.Bytes, _secondSalt.Bytes))
        {
            throw new CryptographicException("Both prepared Argon2id rounds carry the same salt.");
        }

        LockedSensitiveBuffer? first = null;
        LockedSensitiveBuffer? second = null;
        Exception? operationFailure = null;
        try
        {
            first = ContainerKeyDerivation.ParseFactor(firstPassword, nameof(firstPassword));
            second = ContainerKeyDerivation.ParseFactor(secondPassword, nameof(secondPassword));

            _firstFactor = first;
            first = null; // ownership transferred to this instance

            _secondFactor = second;
            second = null; // ownership transferred to this instance
        }
        catch (Exception failure)
        {
            operationFailure = failure;
            throw;
        }
        finally
        {
            SecureMemory.ZeroAndDisposeAllPreservingFailure(
                operationFailure,
                "Prepared-factor parsing failed and one or more factor buffers could not be released.",
                second,
                first);
        }
    }

    /// <summary>
    /// Hands out both rounds' salt and nonce for a two-round suite.
    /// </summary>
    internal TwoRoundEncryptionParameters ConsumeTwoRoundEncryptionParameters(
        EncryptionSuite suite,
        string firstPassword,
        string secondPassword,
        ArchiveOperationLifetime? lifetime = null)
    {
        ArgumentNullException.ThrowIfNull(firstPassword);
        ArgumentNullException.ThrowIfNull(secondPassword);
        EncryptionSuiteParameters parameters = EncryptionSuiteCatalog.Get(suite);
        if (!parameters.UsesTwoKdfRounds)
        {
            throw new ArgumentOutOfRangeException(nameof(suite), suite, "This suite derives a single Argon2id round.");
        }

        LockedSensitiveBuffer? salt;
        LockedSensitiveBuffer? fullNonce;
        LockedSensitiveBuffer? secondSalt;
        LockedSensitiveBuffer? secondFullNonce;
        lock (_gate)
        {
            if (_consumptionStarted || _disposed)
                throw new InvalidOperationException("Prepared salt and nonce parameters were already consumed or disposed.");
            if (_firstFactor is null || _secondFactor is null)
            {
                throw new ObjectDisposedException(nameof(GeneratedArchiveEntropy));
            }

            ValidateSuppliedFactorsLocked(firstPassword, secondPassword);

            salt = _salt ?? throw new InvalidOperationException("Prepared salt and nonce parameters were already consumed.");
            fullNonce = _fullNonce ?? throw new InvalidOperationException("Prepared salt and nonce parameters were already consumed.");
            secondSalt = _secondSalt ?? throw new InvalidOperationException("Prepared salt and nonce parameters were already consumed.");
            secondFullNonce = _secondFullNonce ?? throw new InvalidOperationException("Prepared salt and nonce parameters were already consumed.");
            _consumptionStarted = true;
            lifetime?.BeginConsumption();
            _salt = null;
            _fullNonce = null;
            _secondSalt = null;
            _secondFullNonce = null;
        }

        LockedSensitiveBuffer? firstNonce = null;
        LockedSensitiveBuffer? secondNonce = null;
        Exception? operationFailure = null;
        try
        {
            TestHookAfterConsumption?.Invoke();
            firstNonce = TakeNonce(fullNonce, parameters.ArchiveNonceBytes);
            fullNonce = null;
            secondNonce = TakeNonce(secondFullNonce, parameters.ArchiveNonceBytes);
            secondFullNonce = null;
            var result = new TwoRoundEncryptionParameters(salt, firstNonce, secondSalt, secondNonce);
            salt = null;
            firstNonce = null;
            secondSalt = null;
            secondNonce = null;
            return result;
        }
        catch (Exception failure)
        {
            operationFailure = failure;
            throw;
        }
        finally
        {
            SecureMemory.ZeroAndDisposeAllPreservingFailure(
                operationFailure,
                "Prepared two-round entropy could not be consumed or completely released.",
                secondNonce,
                firstNonce,
                secondFullNonce,
                secondSalt,
                fullNonce,
                salt);
        }
    }

    /// <summary>
    /// Takes a suite's nonce off the front of the prepared block, disposing the
    /// block when it is wider than the suite needs.
    /// </summary>
    private static LockedSensitiveBuffer TakeNonce(LockedSensitiveBuffer fullNonce, int nonceBytes)
    {
        if (nonceBytes != EncryptionSuiteCatalog.ArchiveNonceBytes || fullNonce.Bytes.Length != nonceBytes)
            throw new InvalidDataException("Prepared archive bases must contain exactly 320 bytes.");
        return fullNonce;
    }

    public string FirstPassword
    {
        get
        {
            lock (_gate)
            {
                if (_firstFactor is null)
                {
                    throw new ObjectDisposedException(nameof(GeneratedArchiveEntropy));
                }
                return Convert.ToHexString(_firstFactor.Bytes);
            }
        }
    }

    public string SecondPassword
    {
        get
        {
            lock (_gate)
            {
                if (_secondFactor is null)
                {
                    throw new ObjectDisposedException(nameof(GeneratedArchiveEntropy));
                }
                return Convert.ToHexString(_secondFactor.Bytes);
            }
        }
    }

    public bool HasPendingEncryptionParameters
    {
        get
        {
            lock (_gate)
            {
                return !_consumptionStarted && !_disposed && _salt is not null && _fullNonce is not null;
            }
        }
    }

    internal bool ConsumptionStarted { get { lock (_gate) return _consumptionStarted; } }

    /// <summary>Checks ownership without transferring or regenerating any entropy.</summary>
    internal void ValidateForEncryption(EncryptionSuite suite, string firstFactor, string secondFactor)
    {
        EncryptionSuiteParameters parameters = EncryptionSuiteCatalog.Get(suite);
        lock (_gate)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(GeneratedArchiveEntropy));
            if (_consumptionStarted || _salt is null || _fullNonce is null)
                throw new InvalidOperationException("Prepared salt and nonce parameters were already consumed.");
            if (parameters.UsesTwoKdfRounds && (_secondSalt is null || _secondFullNonce is null))
                throw new InvalidOperationException("This suite requires a newly prepared dual-round entropy set.");
            ValidateSuppliedFactorsLocked(firstFactor, secondFactor);
        }
    }

    internal (LockedSensitiveBuffer Salt, LockedSensitiveBuffer Nonce) ConsumeEncryptionParameters(
        EncryptionSuite suite,
        string firstPassword,
        string secondPassword,
        ArchiveOperationLifetime? lifetime = null)
    {
        if (!EncryptionSuiteCatalog.IsKnown(suite))
        {
            throw new ArgumentOutOfRangeException(nameof(suite), suite, "Unbekanntes Verschluesselungsverfahren.");
        }

        ArgumentNullException.ThrowIfNull(firstPassword);
        ArgumentNullException.ThrowIfNull(secondPassword);

        LockedSensitiveBuffer salt;
        LockedSensitiveBuffer fullNonce;
        lock (_gate)
        {
            if (_consumptionStarted || _disposed)
                throw new InvalidOperationException("Prepared salt and nonce parameters were already consumed or disposed.");
            if (_firstFactor is null || _secondFactor is null)
            {
                throw new ObjectDisposedException(nameof(GeneratedArchiveEntropy));
            }

            ValidateSuppliedFactorsLocked(firstPassword, secondPassword);

            salt = _salt ?? throw new InvalidOperationException("Prepared salt and nonce parameters were already consumed.");
            fullNonce = _fullNonce ?? throw new InvalidOperationException("Prepared salt and nonce parameters were already consumed.");
            _consumptionStarted = true;
            lifetime?.BeginConsumption();

            // A one-round suite never asks for the prepared second round, so it
            // is wiped here rather than left sitting in locked memory. Keep the
            // fields until every unlock succeeds so a failed lock stays
            // explicitly retryable through Dispose as well as the global retry
            // registry.
            SecureMemory.ZeroAndDisposeAll(_secondFullNonce, _secondSalt);
            _secondSalt = null;
            _secondFullNonce = null;

            _salt = null;
            _fullNonce = null;
        }

        int nonceBytes = EncryptionSuiteCatalog.Get(suite).ArchiveNonceBytes;
        LockedSensitiveBuffer? selectedNonce = null;
        Exception? operationFailure = null;
        try
        {
            TestHookAfterConsumption?.Invoke();
            selectedNonce = TakeNonce(fullNonce, nonceBytes);
            LockedSensitiveBuffer completedNonce = selectedNonce;
            selectedNonce = null;
            return (salt, completedNonce);
        }
        catch (Exception failure)
        {
            operationFailure = failure;
            throw;
        }
        finally
        {
            SecureMemory.ZeroAndDisposeAllPreservingFailure(
                operationFailure,
                "Prepared single-round entropy could not be consumed or completely released.",
                selectedNonce,
                operationFailure is null ? null : fullNonce,
                operationFailure is null ? null : salt);
        }
    }

    private void ValidateSuppliedFactorsLocked(string firstPassword, string secondPassword)
    {
        LockedSensitiveBuffer? suppliedFirst = null;
        LockedSensitiveBuffer? suppliedSecond = null;
        Exception? operationFailure = null;
        try
        {
            suppliedFirst = ContainerKeyDerivation.ParseFactor(firstPassword, nameof(firstPassword));
            suppliedSecond = ContainerKeyDerivation.ParseFactor(secondPassword, nameof(secondPassword));
            if (!CryptographicOperations.FixedTimeEquals(_firstFactor!.Bytes, suppliedFirst.Bytes)
                || !CryptographicOperations.FixedTimeEquals(_secondFactor!.Bytes, suppliedSecond.Bytes))
            {
                throw new InvalidOperationException(
                    "Prepared salt and nonce parameters do not belong to the supplied generated password factors.");
            }
        }
        catch (Exception failure)
        {
            operationFailure = failure;
            throw;
        }
        finally
        {
            SecureMemory.ZeroAndDisposeAllPreservingFailure(
                operationFailure,
                "Generated-factor validation failed and supplied factor buffers could not be completely released.",
                suppliedSecond,
                suppliedFirst);
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _disposed = true;
            SecureMemory.ZeroAndDisposeAll(
                _secondFullNonce,
                _secondSalt,
                _fullNonce,
                _salt,
                _secondFactor,
                _firstFactor);
            _salt = null;
            _fullNonce = null;
            _secondSalt = null;
            _secondFullNonce = null;
            _firstFactor = null;
            _secondFactor = null;
        }
    }
}
