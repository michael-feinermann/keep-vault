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
    // Nine pools: one per 512-bit factor half, one per salt branch, and three
    // nonce parts. Each factor half draws from its own pool so that the v12
    // split - A1+B1 into one SHA3 half, A2+B2 into the other - is backed by
    // separately collected material rather than by one pool cut in two. The
    // third nonce pool exists for the cascade, whose two layers each need their
    // own nonce - 64 bytes for Kalyna and 128 for Threefish. Deriving the
    // second nonce from the first would make one layer's keystream a function
    // of the other's, and the whole point of the cascade is that the two are
    // independent.
    private const int PurposeCount = 9;
    /// <summary>
    /// Mouse samples each pool needs before factors can be generated.
    /// </summary>
    /// <remarks>
    /// Raised from 512 to 1024. The pools are the only entropy the app gathers
    /// that an attacker cannot model, and doubling the requirement costs the
    /// user seconds of pointer movement once per archive.
    /// </remarks>
    public const long RequiredMouseSamplesPerPurpose = 1024;
    private static readonly object Gate = new();
    private static readonly EntropyPurpose[] SamplePurposes =
    [
        EntropyPurpose.FactorA1,
        EntropyPurpose.FactorA2,
        EntropyPurpose.FactorB1,
        EntropyPurpose.FactorB2,
        EntropyPurpose.SaltSha3,
        EntropyPurpose.SaltSkein,
        EntropyPurpose.NonceFirst,
        EntropyPurpose.NonceSecond,
        EntropyPurpose.NonceThird,
    ];
    private static readonly LockedSensitiveBuffer[] MousePools = CreateMousePools();
    private static readonly long[] PurposeSampleCounts = new long[PurposeCount];
    private static readonly ulong[] DerivationCounters = new ulong[PurposeCount];
    private static long _systemRandomCallCount;
    private static long _sampleSequence;
    private static int _lastSystemRandomRequestBytes;
    private static int _nextPurposeIndex;

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
    internal static long SystemRandomCallCountForTests => Interlocked.Read(ref _systemRandomCallCount);
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
                PurposeSampleCounts[(int)EntropyPurpose.NonceThird]);
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

    private static void AddMouseSampleCore(
        double x,
        double y,
        int timestamp,
        int left,
        int right,
        int middle)
    {
        LockedSensitiveBuffer? sample = null;
        LockedSensitiveBuffer? sampleCountBytes = null;
        LockedSensitiveBuffer? purposeBytes = null;
        LockedSensitiveBuffer? combined = null;
        LockedSensitiveBuffer? nextPool = null;
        LockedSensitiveBuffer? oldPool = null;
        Exception? operationFailure = null;
        try
        {
            sample = LockedSensitiveBuffer.Create(80);
            BinaryPrimitives.WriteInt64LittleEndian(sample.Bytes.AsSpan(0, 8), BitConverter.DoubleToInt64Bits(x));
            BinaryPrimitives.WriteInt64LittleEndian(sample.Bytes.AsSpan(8, 8), BitConverter.DoubleToInt64Bits(y));
            BinaryPrimitives.WriteInt32LittleEndian(sample.Bytes.AsSpan(16, 4), timestamp);
            BinaryPrimitives.WriteInt64LittleEndian(sample.Bytes.AsSpan(20, 8), Environment.TickCount64);
            BinaryPrimitives.WriteInt64LittleEndian(sample.Bytes.AsSpan(28, 8), DateTime.UtcNow.Ticks);
            BinaryPrimitives.WriteInt32LittleEndian(sample.Bytes.AsSpan(36, 4), (int)left);
            BinaryPrimitives.WriteInt32LittleEndian(sample.Bytes.AsSpan(40, 4), (int)right);
            BinaryPrimitives.WriteInt32LittleEndian(sample.Bytes.AsSpan(44, 4), (int)middle);
            BinaryPrimitives.WriteInt32LittleEndian(sample.Bytes.AsSpan(48, 4), Environment.CurrentManagedThreadId);
            BinaryPrimitives.WriteInt32LittleEndian(sample.Bytes.AsSpan(52, 4), Environment.ProcessId);
            BinaryPrimitives.WriteInt64LittleEndian(sample.Bytes.AsSpan(56, 8), Stopwatch.GetTimestamp());
            BinaryPrimitives.WriteInt64LittleEndian(sample.Bytes.AsSpan(64, 8), GC.GetTotalMemory(forceFullCollection: false));

            lock (Gate)
            {
                int selectedPurposeIndex = SelectNextPurposeIndex();
                EntropyPurpose purpose = SamplePurposes[selectedPurposeIndex];
                int purposeIndex = (int)purpose;
                long sampleSequence = _sampleSequence;
                long nextSampleSequence = checked(sampleSequence + 1);
                BinaryPrimitives.WriteInt64LittleEndian(sample.Bytes.AsSpan(72, 8), sampleSequence);
                sampleCountBytes = LockedSensitiveBuffer.Create(sizeof(long));
                purposeBytes = LockedSensitiveBuffer.Create(sizeof(int));
                BinaryPrimitives.WriteInt64LittleEndian(sampleCountBytes.Bytes, sampleSequence);
                BinaryPrimitives.WriteInt32LittleEndian(purposeBytes.Bytes, purposeIndex);
                combined = LockedSensitiveBuffer.Create(
                    MousePools[purposeIndex].Bytes.Length
                    + sample.Bytes.Length
                    + sampleCountBytes.Bytes.Length
                    + purposeBytes.Bytes.Length);
                WriteCombined(
                    combined.Bytes,
                    MousePools[purposeIndex].Bytes,
                    sample.Bytes,
                    sampleCountBytes.Bytes,
                    purposeBytes.Bytes);

                nextPool = LockedSensitiveBuffer.Create(Sha3_512Compat.HashSizeInBytes);
                int written = Sha3_512Compat.HashData(combined.Bytes, nextPool.Bytes);
                if (written != Sha3_512Compat.HashSizeInBytes)
                {
                    throw new CryptographicException("SHA3-512 returned an invalid entropy-pool digest length.");
                }

                oldPool = MousePools[purposeIndex];
                MousePools[purposeIndex] = nextPool;
                nextPool = null;
                PurposeSampleCounts[purposeIndex]++;
                _sampleSequence = nextSampleSequence;
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
                "Mouse-entropy pool update failed and one or more sensitive buffers could not be released.",
                oldPool,
                nextPool,
                combined,
                purposeBytes,
                sampleCountBytes,
                sample);
        }
    }

    private static int SelectNextPurposeIndex()
    {
        long minimumCount = PurposeSampleCounts.Min();
        for (int offset = 0; offset < SamplePurposes.Length; offset++)
        {
            int index = (_nextPurposeIndex + offset) % SamplePurposes.Length;
            if (PurposeSampleCounts[index] != minimumCount)
            {
                continue;
            }

            _nextPurposeIndex = (index + 1) % SamplePurposes.Length;
            return index;
        }

        throw new InvalidOperationException("No mouse-entropy pool could be selected.");
    }

    /// <summary>
    /// Bytes drawn from each pool.
    /// </summary>
    /// <remarks>
    /// One digest per pool was enough while every suite's nonce fitted in three
    /// of them. The six-layer cascade needs a wider one, so the draw is sized
    /// from the catalogue: three pools have to cover the widest nonce any suite
    /// asks for. Every pool is expanded by the same amount because the
    /// expansion takes one size for all of them, and the extra bytes in the
    /// password and salt pools are simply not used.
    /// </remarks>
    /// <summary>
    /// One salt pair: the SHA3 branch's 512-bit salt followed by the Skein
    /// branch's.
    /// </summary>
    internal const int SaltPairBytes = 2 * 64;

    private static readonly int PoolDrawBytes = Math.Max(
        Sha3_512Compat.HashSizeInBytes,
        (EncryptionSuiteCatalog.MaxNonceBytes + 2) / 3);

    internal static GeneratedArchiveEntropy CreateArchiveEntropy()
    {
        // One consumption of the pools yields both Argon2id rounds: the first
        // expansion uses SHA3-512, the second SHA-512 over the same snapshot.
        // That gives the paranoia suite a computationally domain-diverse
        // second round without asking the user for another 512 samples per pool.
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
            (firstMouse, secondMouse) = ExpandAndConsumeMousePoolsDual(PoolDrawBytes, SamplePurposes);
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
            (secondSalt, secondFullNonce) = SplitPreparedSaltAndNonce(secondMouse);

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
            return completed;
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
                SecureMemory.ZeroAndDisposeAllPreservingFailure(
                    operationFailure,
                    "Archive-entropy creation failed and one or more sensitive buffers could not be released.",
                    secondFullNonce,
                    secondSalt,
                    fullNonce,
                    salt,
                    passwordBytes,
                    secondMouse,
                    firstMouse);
            }
            catch (Exception cleanupFailure)
            {
                if (completed is null)
                {
                    throw;
                }

                try
                {
                    completed.Dispose();
                }
                catch (Exception resultCleanupFailure)
                {
                    throw new AggregateException(
                        "Archive-entropy temporaries and the completed entropy object could not be released.",
                        cleanupFailure,
                        resultCleanupFailure);
                }

                throw;
            }
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

            nonce = LockedSensitiveBuffer.Create(EncryptionSuiteCatalog.MaxNonceBytes);
            FillSystemRandom(nonce.Bytes);
            XorInPlace(
                nonce.Bytes,
                mouseBytes.Bytes.AsSpan(6 * PoolDrawBytes, EncryptionSuiteCatalog.MaxNonceBytes));

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
                SecureMemory.ZeroAndDisposeAllPreservingFailure(
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

                SecureMemory.ZeroAndDisposeAllPreservingFailure(
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
    /// entropy a second time. The two rounds differ by the hash that expands
    /// the shared snapshot — SHA3-512 for the first, SHA-512 for the second —
    /// and each is XORed with its own independent draw from the system
    /// generator, so neither salt nor either nonce set can be derived from the
    /// other.
    ///
    /// Both salts and both nonce sets have to reach the container header. An
    /// archive whose header carries only the first round cannot be decrypted by
    /// anyone, including the machine that wrote it.
    /// </remarks>
    internal static TwoRoundEncryptionParameters CreateTwoRoundEncryptionParameters(EncryptionSuite suite)
    {
        if (!EncryptionSuiteCatalog.IsKnown(suite))
        {
            throw new ArgumentOutOfRangeException(nameof(suite), suite, "Unbekanntes Verschluesselungsverfahren.");
        }

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
                ]);
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
            return completed;
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
                SecureMemory.ZeroAndDisposeAllPreservingFailure(
                    operationFailure,
                    "Two-round entropy derivation failed and one or more sensitive buffers could not be released.",
                    secondNonce,
                    secondSalt,
                    firstNonce,
                    firstSalt,
                    secondMouse,
                    firstMouse);
            }
            catch (Exception cleanupFailure)
            {
                if (completed is null)
                {
                    throw;
                }

                try
                {
                    completed.Dispose();
                }
                catch (Exception resultCleanupFailure)
                {
                    throw new AggregateException(
                        "Two-round entropy temporaries and the completed result could not be released.",
                        cleanupFailure,
                        resultCleanupFailure);
                }

                throw;
            }
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

            // Sized from the catalogue, not from three digests: the six-layer
            // cascade needs 268 nonce bytes and the old fixed 192 would have
            // silently starved it.
            fullNonce = LockedSensitiveBuffer.Create(EncryptionSuiteCatalog.MaxNonceBytes);
            FillSystemRandom(fullNonce.Bytes);
            XorInPlace(
                fullNonce.Bytes,
                mouseBytes.Bytes.AsSpan(2 * PoolDrawBytes, EncryptionSuiteCatalog.MaxNonceBytes));

            int nonceBytes = EncryptionSuiteCatalog.Get(suite).NonceBytes;
            if (nonceBytes == fullNonce.Bytes.Length)
            {
                selectedNonce = fullNonce;
                fullNonce = null;
            }
            else
            {
                selectedNonce = LockedSensitiveBuffer.Create(nonceBytes);
                fullNonce.Bytes.AsSpan(0, nonceBytes).CopyTo(selectedNonce.Bytes);
            }

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
                SecureMemory.ZeroAndDisposeAllPreservingFailure(
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

                SecureMemory.ZeroAndDisposeAllPreservingFailure(
                    cleanupFailure,
                    "Salt/nonce cleanup failed and the completed result could not be released.",
                    completedNonce,
                    completedSalt);
                throw;
            }
        }
    }

    internal static (LockedSensitiveBuffer Salt, LockedSensitiveBuffer Nonce) CreateEncryptionParameters(EncryptionSuite suite)
    {
        if (!EncryptionSuiteCatalog.IsKnown(suite))
        {
            throw new ArgumentOutOfRangeException(nameof(suite), suite, "Unbekanntes Verschluesselungsverfahren.");
        }

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
                ]);
            (salt, nonce) = SplitSaltAndNonce(mouseBytes, suite);
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
                SecureMemory.ZeroAndDisposeAllPreservingFailure(
                    operationFailure,
                    "Encryption-parameter creation failed and one or more sensitive buffers could not be released.",
                    nonce,
                    salt,
                    mouseBytes);
            }
            catch (Exception cleanupFailure)
            {
                if (completedSalt is null && completedNonce is null)
                {
                    throw;
                }

                SecureMemory.ZeroAndDisposeAllPreservingFailure(
                    cleanupFailure,
                    "Encryption-parameter cleanup failed and the completed result could not be released.",
                    completedNonce,
                    completedSalt);
                throw;
            }
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
        EntropyPurpose[] purposes)
        => ExpandAndConsumeMousePoolsCore(byteCountPerPool, purposes, secondRound: false).First;

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
        EntropyPurpose[] purposes)
    {
        (LockedSensitiveBuffer first, LockedSensitiveBuffer? second) =
            ExpandAndConsumeMousePoolsCore(byteCountPerPool, purposes, secondRound: true);
        return (first, second!);
    }

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The returned outputs transfer ownership to the caller; all failure paths dispose them, replacement-pool transfer is guarded, and loop buffers use compiler-generated finally blocks.")]
    private static (LockedSensitiveBuffer First, LockedSensitiveBuffer? Second) ExpandAndConsumeMousePoolsCore(
        int byteCountPerPool,
        EntropyPurpose[] purposes,
        bool secondRound)
    {
        if (byteCountPerPool <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(byteCountPerPool), "Die Byteanzahl muss positiv sein.");
        }

        ArgumentNullException.ThrowIfNull(purposes);
        if (purposes.Length == 0)
        {
            throw new ArgumentException("Mindestens ein Entropiepool ist erforderlich.", nameof(purposes));
        }

        var uniquePurposes = new HashSet<EntropyPurpose>();
        foreach (EntropyPurpose purpose in purposes)
        {
            int purposeIndex = (int)purpose;
            if (purposeIndex < 0 || purposeIndex >= PurposeCount)
            {
                throw new ArgumentOutOfRangeException(nameof(purposes), purpose, "Unbekannter Entropiezweck.");
            }

            if (!uniquePurposes.Add(purpose))
            {
                throw new ArgumentException("Jeder Entropiepool darf pro Ableitung nur einmal verwendet werden.", nameof(purposes));
            }
        }

        int totalByteCount = checked(byteCountPerPool * purposes.Length);
        LockedSensitiveBuffer? output = null;
        LockedSensitiveBuffer? secondOutput = null;
        LockedSensitiveBuffer? completedFirst = null;
        LockedSensitiveBuffer? completedSecond = null;
        var snapshots = new LockedSensitiveBuffer?[purposes.Length];
        var replacements = new LockedSensitiveBuffer?[PurposeCount];
        var oldPools = new LockedSensitiveBuffer?[PurposeCount];
        var baseCounters = new ulong[purposes.Length];
        var nextCounters = new ulong[PurposeCount];
        Exception? operationFailure = null;
        try
        {
            output = LockedSensitiveBuffer.Create(totalByteCount);
            secondOutput = secondRound ? LockedSensitiveBuffer.Create(totalByteCount) : null;

            for (int index = 0; index < purposes.Length; index++)
            {
                snapshots[index] = LockedSensitiveBuffer.Create(Sha3_512Compat.HashSizeInBytes);
            }

            for (int index = 0; index < PurposeCount; index++)
            {
                replacements[index] = LockedSensitiveBuffer.Create(Sha3_512Compat.HashSizeInBytes);
            }

            lock (Gate)
            {
                foreach (EntropyPurpose purpose in purposes)
                {
                    long current = PurposeSampleCounts[(int)purpose];
                    if (current < RequiredMouseSamplesPerPurpose)
                    {
                        throw new InvalidOperationException($"Nicht genug Maus-Entropie-Samples fuer {purpose}: {current}/{RequiredMouseSamplesPerPurpose}.");
                    }
                }

                for (int index = 0; index < purposes.Length; index++)
                {
                    int purposeIndex = (int)purposes[index];
                    MousePools[purposeIndex].Bytes.CopyTo(snapshots[index]!.Bytes, 0);
                    baseCounters[index] = DerivationCounters[purposeIndex];
                }

                for (int purposeIndex = 0; purposeIndex < PurposeCount; purposeIndex++)
                {
                    nextCounters[purposeIndex] = checked(DerivationCounters[purposeIndex] + 1);
                }

                for (int purposeIndex = 0; purposeIndex < PurposeCount; purposeIndex++)
                {
                    oldPools[purposeIndex] = MousePools[purposeIndex];
                    MousePools[purposeIndex] = replacements[purposeIndex]!;
                    replacements[purposeIndex] = null;
                    DerivationCounters[purposeIndex] = nextCounters[purposeIndex];
                    PurposeSampleCounts[purposeIndex] = 0;
                }
            }

            SecureMemory.ZeroAndDisposeAll(oldPools);
            Array.Clear(oldPools);

            for (int poolIndex = 0; poolIndex < purposes.Length; poolIndex++)
            {
                int poolOffset = checked(poolIndex * byteCountPerPool);
                int localOffset = 0;
                int purposeIndex = (int)purposes[poolIndex];
                for (uint blockIndex = 0; localOffset < byteCountPerPool; blockIndex++)
                {
                    LockedSensitiveBuffer? baseCounterBytes = null;
                    LockedSensitiveBuffer? blockIndexBytes = null;
                    LockedSensitiveBuffer? purposeBytes = null;
                    LockedSensitiveBuffer? combined = null;
                    LockedSensitiveBuffer? block = null;
                    LockedSensitiveBuffer? secondBlock = null;
                    Exception? blockFailure = null;
                    try
                    {
                        baseCounterBytes = LockedSensitiveBuffer.Create(sizeof(ulong));
                        blockIndexBytes = LockedSensitiveBuffer.Create(sizeof(uint));
                        purposeBytes = LockedSensitiveBuffer.Create(sizeof(int));
                        BinaryPrimitives.WriteUInt64LittleEndian(baseCounterBytes.Bytes, baseCounters[poolIndex]);
                        BinaryPrimitives.WriteUInt32LittleEndian(blockIndexBytes.Bytes, blockIndex);
                        BinaryPrimitives.WriteInt32LittleEndian(purposeBytes.Bytes, purposeIndex);
                        combined = LockedSensitiveBuffer.Create(
                            snapshots[poolIndex]!.Bytes.Length
                            + baseCounterBytes.Bytes.Length
                            + blockIndexBytes.Bytes.Length
                            + purposeBytes.Bytes.Length);
                        WriteCombined(
                            combined.Bytes,
                            snapshots[poolIndex]!.Bytes,
                            baseCounterBytes.Bytes,
                            blockIndexBytes.Bytes,
                            purposeBytes.Bytes);
                        block = LockedSensitiveBuffer.Create(Sha3_512Compat.HashSizeInBytes);
                        int written = Sha3_512Compat.HashData(combined.Bytes, block.Bytes);
                        if (written != Sha3_512Compat.HashSizeInBytes)
                        {
                            throw new CryptographicException("SHA3-512 returned an invalid mouse-entropy expansion length.");
                        }

                        int count = Math.Min(block.Bytes.Length, byteCountPerPool - localOffset);
                        Buffer.BlockCopy(block.Bytes, 0, output.Bytes, poolOffset + localOffset, count);
                        localOffset += count;

                        if (secondOutput is null)
                        {
                            continue;
                        }

                        // The same block input, expanded through a computationally domain-diverse hash.
                        // SHA3-512 is a sponge and SHA-512 is Merkle-Damgard; both are
                        // domain-diverse expansions of the same pool snapshot (with genuine
                        // entropy ensured by distinct OS CSPRNG draws for each round's salt).
                        secondBlock = LockedSensitiveBuffer.Create(Sha512Compat.HashSizeInBytes);
                        int secondWritten = Sha512Compat.HashData(combined.Bytes, secondBlock.Bytes);
                        if (secondWritten != Sha512Compat.HashSizeInBytes)
                        {
                            throw new CryptographicException("SHA-512 returned an invalid mouse-entropy expansion length.");
                        }

                        Buffer.BlockCopy(
                            secondBlock.Bytes,
                            0,
                            secondOutput.Bytes,
                            poolOffset + localOffset - count,
                            count);
                    }
                    catch (Exception failure)
                    {
                        blockFailure = failure;
                        throw;
                    }
                    finally
                    {
                        SecureMemory.ZeroAndDisposeAllPreservingFailure(
                            blockFailure,
                            "Mouse-entropy expansion failed and one or more per-block secrets could not be released.",
                            secondBlock,
                            block,
                            combined,
                            purposeBytes,
                            blockIndexBytes,
                            baseCounterBytes);
                    }
                }
            }

            completedFirst = output;
            completedSecond = secondOutput;
            output = null;
            secondOutput = null;
            return (completedFirst, completedSecond);
        }
        catch (Exception failure)
        {
            operationFailure = failure;
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(baseCounters.AsSpan()));
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(nextCounters.AsSpan()));
            try
            {
                SecureMemory.ZeroAndDisposeAllPreservingFailure(
                    operationFailure,
                    "Mouse-entropy expansion failed and one or more composite secrets could not be released.",
                    [output, secondOutput, .. snapshots, .. replacements, .. oldPools]);
            }
            catch (Exception cleanupFailure)
            {
                if (completedFirst is null && completedSecond is null)
                {
                    throw;
                }

                SecureMemory.ZeroAndDisposeAllPreservingFailure(
                    cleanupFailure,
                    "Mouse-entropy temporary cleanup failed and the completed expansion could not be released.",
                    completedSecond,
                    completedFirst);
                throw;
            }
        }
    }

    private static void FillSystemRandom(byte[] buffer)
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

        Volatile.Write(ref _lastSystemRandomRequestBytes, buffer.Length);
        Interlocked.Increment(ref _systemRandomCallCount);
    }

    private static void WriteCombined(byte[] destination, params byte[][] arrays)
    {
        int expectedLength = arrays.Sum(array => array.Length);
        if (destination.Length != expectedLength)
        {
            throw new ArgumentException("Combined entropy buffer has an invalid length.", nameof(destination));
        }

        int offset = 0;
        foreach (byte[] array in arrays)
        {
            Buffer.BlockCopy(array, 0, destination, offset, array.Length);
            offset += array.Length;
        }
    }

    private static LockedSensitiveBuffer[] CreateMousePools()
    {
        var pools = new List<LockedSensitiveBuffer>(PurposeCount);
        try
        {
            for (int index = 0; index < PurposeCount; index++)
            {
                pools.Add(LockedSensitiveBuffer.Create(Sha3_512Compat.HashSizeInBytes));
            }

            return [.. pools];
        }
        catch
        {
            SecureMemory.ZeroAndDisposeAll([.. pools]);
            throw;
        }
    }

    [LibraryImport("bcrypt.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial int BCryptGenRandom(nint hAlgorithm, [Out] byte[] pbBuffer, int cbBuffer, int dwFlags);

    [LibraryImport("/System/Library/Frameworks/Security.framework/Security")]
    private static partial int SecRandomCopyBytes(nint random, nuint count, [Out] byte[] bytes);
}

/// <summary>
/// How full each of the nine pools is.
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
    long NonceThird)
{
    private long[] All =>
        [FactorA1, FactorA2, FactorB1, FactorB2, SaltSha3, SaltSkein, NonceFirst, NonceSecond, NonceThird];

    public long Minimum => All.Min();

    public long Maximum => All.Max();

    public bool IsBalanced => Maximum - Minimum <= 1;

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
/// The nine independent mouse-entropy pools an archive draws on.
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
}

internal sealed class GeneratedArchiveEntropy : IDisposable
{
    private readonly object _gate = new();
    private LockedSensitiveBuffer? _salt;
    private LockedSensitiveBuffer? _fullNonce;
    private LockedSensitiveBuffer? _secondSalt;
    private LockedSensitiveBuffer? _secondFullNonce;
    private LockedSensitiveBuffer? _firstFactor;
    private LockedSensitiveBuffer? _secondFactor;

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
        LockedSensitiveBuffer secondSalt,
        LockedSensitiveBuffer secondFullNonce)
    {
        ArgumentNullException.ThrowIfNull(firstPassword);
        ArgumentNullException.ThrowIfNull(secondPassword);
        _salt = salt ?? throw new ArgumentNullException(nameof(salt));
        _fullNonce = fullNonce ?? throw new ArgumentNullException(nameof(fullNonce));
        _secondSalt = secondSalt ?? throw new ArgumentNullException(nameof(secondSalt));
        _secondFullNonce = secondFullNonce ?? throw new ArgumentNullException(nameof(secondFullNonce));
        if (_salt.Bytes.Length != EntropyMixer.SaltPairBytes
            || _secondSalt.Bytes.Length != EntropyMixer.SaltPairBytes
            || _fullNonce.Bytes.Length != EncryptionSuiteCatalog.MaxNonceBytes
            || _secondFullNonce.Bytes.Length != EncryptionSuiteCatalog.MaxNonceBytes)
        {
            throw new ArgumentException("Prepared archive entropy has an invalid length.");
        }

        if (CryptographicOperations.FixedTimeEquals(_salt.Bytes, _secondSalt.Bytes))
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
        string secondPassword)
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
            if (_firstFactor is null || _secondFactor is null)
            {
                throw new ObjectDisposedException(nameof(GeneratedArchiveEntropy));
            }

            ValidateSuppliedFactorsLocked(firstPassword, secondPassword);

            salt = _salt ?? throw new InvalidOperationException("Prepared salt and nonce parameters were already consumed.");
            fullNonce = _fullNonce ?? throw new InvalidOperationException("Prepared salt and nonce parameters were already consumed.");
            secondSalt = _secondSalt ?? throw new InvalidOperationException("Prepared salt and nonce parameters were already consumed.");
            secondFullNonce = _secondFullNonce ?? throw new InvalidOperationException("Prepared salt and nonce parameters were already consumed.");
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
            firstNonce = TakeNonce(fullNonce, parameters.NonceBytes);
            fullNonce = null;
            secondNonce = TakeNonce(secondFullNonce, parameters.NonceBytes);
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
        if (nonceBytes == fullNonce.Bytes.Length)
        {
            return fullNonce;
        }

        LockedSensitiveBuffer? selected = null;
        Exception? operationFailure = null;
        try
        {
            selected = LockedSensitiveBuffer.Create(nonceBytes);
            fullNonce.Bytes.AsSpan(0, nonceBytes).CopyTo(selected.Bytes);
            SecureMemory.ZeroAndDisposeAll(fullNonce);
            LockedSensitiveBuffer completed = selected;
            selected = null;
            return completed;
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
                "Prepared nonce selection failed and its buffers could not be completely released.",
                selected,
                operationFailure is null ? null : fullNonce);
        }
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
                return _salt is not null && _fullNonce is not null
                    && _secondSalt is not null && _secondFullNonce is not null;
            }
        }
    }

    internal (LockedSensitiveBuffer Salt, LockedSensitiveBuffer Nonce) ConsumeEncryptionParameters(
        EncryptionSuite suite,
        string firstPassword,
        string secondPassword)
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
            if (_firstFactor is null || _secondFactor is null)
            {
                throw new ObjectDisposedException(nameof(GeneratedArchiveEntropy));
            }

            ValidateSuppliedFactorsLocked(firstPassword, secondPassword);

            // A one-round suite never asks for the prepared second round, so it
            // is wiped here rather than left sitting in locked memory. Keep the
            // fields until every unlock succeeds so a failed lock stays
            // explicitly retryable through Dispose as well as the global retry
            // registry.
            SecureMemory.ZeroAndDisposeAll(_secondFullNonce, _secondSalt);
            _secondSalt = null;
            _secondFullNonce = null;

            salt = _salt ?? throw new InvalidOperationException("Prepared salt and nonce parameters were already consumed.");
            fullNonce = _fullNonce ?? throw new InvalidOperationException("Prepared salt and nonce parameters were already consumed.");
            _salt = null;
            _fullNonce = null;
        }

        int nonceBytes = EncryptionSuiteCatalog.Get(suite).NonceBytes;
        if (nonceBytes == fullNonce.Bytes.Length)
        {
            return (salt, fullNonce);
        }

        LockedSensitiveBuffer? selectedNonce = null;
        Exception? operationFailure = null;
        try
        {
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
