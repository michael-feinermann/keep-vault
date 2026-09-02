using System.Diagnostics;
using System.Security.Cryptography;
using KalynaArchiver.Services;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

/// <summary>
/// The shipped parallel cipher paths against independent implementations over
/// buffers the size of a real archive.
/// </summary>
/// <remarks>
/// The v12 Kalyna adapter verifies an official DSTU 7624:2014 vector at
/// start-up. Bouncy Castle supplies an independently implemented block cipher
/// for this gate. A self-check on one block cannot reach the mode
/// wrapped around the block function: the counter arithmetic across a quarter of
/// a gigabyte, the carry out of a counter that starts near its own limit, the
/// tail block of a length that is not a multiple of the block size, and the
/// boundaries where the driver switches from one thread to many and from one
/// claimed chunk to the next. Those are where a fast path that passes every
/// vector still writes a container that will not open.
///
/// This test therefore drives 256 MiB through the shipped Crypto++ export and
/// through Bouncy Castle under several keys, nonces and starting counters, and
/// requires byte-for-byte agreement. It also compares the native scalar and
/// parallel entry points, so an independent algorithm check cannot hide a
/// broken worker split.
/// </remarks>
internal static class FastPathDifferentialTests
{
    /// <summary>
    /// The headline size, fixed rather than configurable.
    /// </summary>
    /// <remarks>
    /// A knob here would be turned down on the machine where it mattered, and
    /// the run would still report a pass.
    /// </remarks>
    private const int LargeBytes = 256 * 1024 * 1024;

    private const int AesBlockBytes = 16;
    private const int KalynaBlockBytes = 64;
    private const int ChaChaBlockBytes = 64;

    /// <summary>Where the CTR drivers stop being serial.</summary>
    private const int ParallelThresholdBytes = 1024 * 1024;

    /// <summary>What one worker claims at a time, for the 64-byte block ciphers.</summary>
    private const int ChunkBytes = 256 * 1024;

    internal static TestCase[] Tests =>
    [
        new("crypto.aes-ctr-differential", "AES-256 Crypto++ CTR against independent platform AES over 256 MiB",
            AesAgainstIndependentReferenceAsync, TestResource.CpuHeavy, "Crypto")
        {
            Cost = new TestCost(4, 1536, false, TestConstraint.None),
        },
        new("crypto.kalyna-fast-path-differential", "Kalyna-512/512 Crypto++ against independent Bouncy Castle over 256 MiB",
            KalynaAgainstReferenceAsync, TestResource.CpuHeavy, "Crypto"),
        new("crypto.chacha20-fast-path-differential", "ChaCha20 worker split against the serial keystream over 256 MiB",
            ChaChaAgainstSerialAsync, TestResource.CpuHeavy, "Crypto"),
        new("crypto.chacha20-poly1305-rfc8439", "ChaCha20-Poly1305 RFC KAT, worker differential and 256 MiB Poly1305",
            AeadFramingAsync, TestResource.CpuHeavy, "Crypto")
        {
            Cost = new TestCost(4, 768, false, TestConstraint.None),
        },
        new("keysheet.full-factor-print", "the key sheet prints every character of the factor",
            KeySheetFactorIsCompleteAsync, TestResource.Light, "Packaging"),
    ];

    /// <summary>
    /// The printed factor has to be the whole factor.
    /// </summary>
    /// <remarks>
    /// The sheet used to lay the block out in a rectangle of a hand-picked
    /// height, one line short of what a 1024-bit factor needs. XTextFormatter
    /// drops lines that do not fit without saying so, so the sheet printed 224
    /// of 256 hexadecimal characters and looked entirely normal. The QR codes
    /// still held the whole factor, which is why nothing else noticed.
    ///
    /// Two things are checked. The grouping must lose nothing, and the height
    /// the layout reserves must cover every line the grouping produced — which
    /// is the property the old constant violated.
    /// </remarks>
    private static Task KeySheetFactorIsCompleteAsync()
    {
        string factor = string.Concat(Enumerable.Repeat("0123456789ABCDEF", 16));
        MacComprehensiveTests.Require(factor.Length == 256, "A 1024-bit factor is 256 hexadecimal characters.");

        string grouped = KeySheetService.GroupGeneratedPasswordForSheet(factor);
        string[] lines = grouped.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        string rejoined = string.Concat(lines.Select(line => line.Replace(" ", string.Empty).Trim()));

        MacComprehensiveTests.Require(
            string.Equals(rejoined, factor, StringComparison.Ordinal),
            $"The sheet grouping changed the factor: {rejoined.Length} characters instead of {factor.Length}.");
        MacComprehensiveTests.Require(
            lines.Length == 7,
            $"A 256-character factor is seven rows of five groups; the grouping produced {lines.Length}.");

        KeySheetService.EnsurePdfFontResolver();
        var monoFont = new PdfSharp.Drawing.XFont("Courier New", 14, PdfSharp.Drawing.XFontStyleEx.Bold);
        double reserved = KeySheetService.FactorBlockHeight(monoFont, grouped);
        double needed = lines.Length * monoFont.GetHeight();
        MacComprehensiveTests.Require(
            reserved >= needed,
            $"The factor block reserves {reserved:F1}pt for {lines.Length} lines that need {needed:F1}pt; "
            + "the last lines would be dropped without a word.");

        Console.WriteLine($"    all {factor.Length} characters survive the sheet grouping, {lines.Length} lines, {reserved:F1}pt reserved");
        return Task.CompletedTask;
    }

    /// <summary>
    /// A counter block for Kalyna, whose whole 64-byte nonce is the counter.
    /// </summary>
    /// <remarks>
    /// The leading bytes carry the nonce and the trailing eight the numeric
    /// start, so a case can place the run anywhere in the counter's range —
    /// including just below a carry that has to propagate through every byte
    /// above it.
    /// </remarks>
    private static byte[] BuildCounterBlock(ulong nonceSeed, ulong counterStart)
    {
        byte[] block = new byte[KalynaBlockBytes];
        FillDerived(block.AsSpan(0, 56), nonceSeed);
        for (int i = 0; i < 8; i++)
        {
            block[63 - i] = (byte)(counterStart >> (i * 8));
        }

        return block;
    }

    /// <summary>
    /// Fills a span from a counter run through a 64-bit mix.
    /// </summary>
    /// <remarks>
    /// Derived rather than random so a failure names a case that can be run
    /// again, and rather than a frozen table so the material is not four
    /// constants somebody once picked.
    /// </remarks>
    private static void FillDerived(Span<byte> destination, ulong seed)
    {
        for (int i = 0; i < destination.Length; i += 8)
        {
            ulong word = Mix(seed + (ulong)(i / 8));
            int count = Math.Min(8, destination.Length - i);
            for (int b = 0; b < count; b++)
            {
                destination[i + b] = (byte)(word >> (b * 8));
            }
        }
    }

    private static ulong Mix(ulong value)
    {
        value += 0x9E3779B97F4A7C15UL;
        value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9UL;
        value = (value ^ (value >> 27)) * 0x94D049BB133111EBUL;
        return value ^ (value >> 31);
    }

    private static byte[] DerivedBytes(int length, ulong seed)
    {
        byte[] buffer = new byte[length];
        FillDerived(buffer, seed);
        return buffer;
    }

    /// <summary>
    /// Lengths that sit on every boundary the drivers change behaviour at.
    /// </summary>
    private static int[] BoundaryLengths =>
    [
        1,
        KalynaBlockBytes - 1,
        KalynaBlockBytes,
        KalynaBlockBytes + 1,
        ChunkBytes - 1,
        ChunkBytes,
        ChunkBytes + 1,
        ParallelThresholdBytes - 1,
        ParallelThresholdBytes,
        ParallelThresholdBytes + 1,
        (4 * 1024 * 1024) + 63,
    ];

    private static void RequireIdentical(
        byte[] reference,
        byte[] fast,
        int length,
        string label)
    {
        // Not SequenceEqual: on a mismatch the offset is what says whether the
        // fault is in the block function, in the tail, or at a chunk boundary,
        // and a bool cannot say which.
        for (int i = 0; i < length; i++)
        {
            if (reference[i] != fast[i])
            {
                throw new InvalidOperationException(
                    $"{label}: the fast path and the reference differ at byte {i} "
                    + $"(reference {reference[i]:x2}, fast {fast[i]:x2}) over {length} bytes.");
            }
        }
    }

    /// <summary>
    /// Holds the production Crypto++ CTR adapter against the platform AES block
    /// primitive. The reference constructs the full-width big-endian counter
    /// itself, so a wrong mode, endian choice, worker offset or tail cannot be
    /// hidden by using the same adapter for encryption and decryption.
    /// </summary>
    private static Task AesAgainstIndependentReferenceAsync()
    {
        MacComprehensiveTests.Require(
            NativeAes.IsAvailable(),
            $"AES reference library unavailable: {NativeAes.LastLoadError}");

        NativeAesRuntimeProvider provider = NativeAes.RuntimeProvider;
        if (OperatingSystem.IsMacOS()
            && System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture
                == System.Runtime.InteropServices.Architecture.Arm64)
        {
            MacComprehensiveTests.Require(
                provider == NativeAesRuntimeProvider.ArmV8,
                $"Apple-silicon AES selected {provider} instead of the mandatory Crypto++ ArmV8 provider.");
        }

        int[] lengths =
        [
            1,
            AesBlockBytes - 1,
            AesBlockBytes,
            AesBlockBytes + 1,
            ChunkBytes - 1,
            ChunkBytes,
            ChunkBytes + 1,
            ParallelThresholdBytes - 1,
            ParallelThresholdBytes,
            ParallelThresholdBytes + 1,
            (4 * 1024 * 1024) + 17,
        ];

        for (int trial = 0; trial < 3; trial++)
        {
            byte[] key = DerivedBytes(32, 0x4145534B4559UL + (ulong)trial);
            byte[] counter = BuildAesCounterBlock(
                0x4145534E4F4E4345UL + (ulong)trial,
                trial switch
                {
                    0 => 0,
                    1 => 0xFFFFFFFFUL,
                    _ => 1UL << 63,
                });
            try
            {
                foreach (int length in lengths)
                {
                    byte[] input = DerivedBytes(length, 0x414553494E505554UL + (ulong)length + (ulong)trial);
                    byte[] expected = new byte[length];
                    byte[] actual = new byte[length];
                    byte[] inPlace = input.ToArray();
                    try
                    {
                        BuildAesCtrReference(key, counter, input, expected);
                        NativeAes.XCryptCtr256(key, counter, input, actual, length);
                        RequireIdentical(expected, actual, length, $"AES trial {trial}, length {length}");

                        NativeAes.XCryptCtr256(key, counter, inPlace, inPlace, length);
                        RequireIdentical(expected, inPlace, length, $"AES in-place trial {trial}, length {length}");
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(input);
                        CryptographicOperations.ZeroMemory(expected);
                        CryptographicOperations.ZeroMemory(actual);
                        CryptographicOperations.ZeroMemory(inPlace);
                    }
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
                CryptographicOperations.ZeroMemory(counter);
            }
        }

        const int largeLength = LargeBytes + 37;
        byte[] largeKey = DerivedBytes(32, 0x4145534C41524745UL);
        byte[] largeCounter = BuildAesCounterBlock(0x414553435452UL, 0x0123456789ABCDEFUL);
        byte[] largeInput = DerivedBytes(largeLength, 0x414553323536UL);
        byte[] largeExpected = new byte[largeLength];
        byte[] largeActual = new byte[largeLength];
        try
        {
            var stopwatch = Stopwatch.StartNew();
            BuildAesCtrReference(largeKey, largeCounter, largeInput, largeExpected);
            TimeSpan referenceElapsed = stopwatch.Elapsed;
            stopwatch.Restart();
            NativeAes.XCryptCtr256(largeKey, largeCounter, largeInput, largeActual, largeLength);
            TimeSpan nativeElapsed = stopwatch.Elapsed;
            RequireIdentical(largeExpected, largeActual, largeLength, "AES 256 MiB + 37 bytes");
            Console.WriteLine(
                $"    AES 256 MiB + 37 bytes: independent CTR identical "
                + $"({Rate(largeLength, referenceElapsed)} platform reference, "
                + $"{Rate(largeLength, nativeElapsed)} Crypto++ {provider})");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(largeKey);
            CryptographicOperations.ZeroMemory(largeCounter);
            CryptographicOperations.ZeroMemory(largeInput);
            CryptographicOperations.ZeroMemory(largeExpected);
            CryptographicOperations.ZeroMemory(largeActual);
        }

        RequireBlockCounterBoundary(
            "AES-256",
            AesBlockBytes,
            (nonce, input, output) => NativeAes.XCryptCtr256(
                new byte[32], nonce, input, output, input.Length));
        Console.WriteLine(
            $"    AES boundary lengths and in-place buffers agree; provider={provider}; counter exhaustion is preflighted");
        return Task.CompletedTask;
    }

    private static byte[] BuildAesCounterBlock(ulong nonceSeed, ulong counterStart)
    {
        byte[] block = new byte[AesBlockBytes];
        FillDerived(block.AsSpan(0, 8), nonceSeed);
        for (int index = 0; index < 8; index++)
        {
            block[block.Length - 1 - index] = (byte)(counterStart >> (index * 8));
        }

        return block;
    }

    private static void BuildAesCtrReference(
        byte[] key,
        byte[] initialCounter,
        byte[] input,
        byte[] output)
    {
        const int BatchBytes = 1024 * 1024;
        byte[] counter = initialCounter.ToArray();
        byte[] counterBlocks = new byte[BatchBytes];
        byte[] keystream = new byte[BatchBytes];
        using Aes aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        try
        {
            for (int offset = 0; offset < input.Length;)
            {
                int byteCount = Math.Min(BatchBytes, input.Length - offset);
                int blocks = (byteCount + AesBlockBytes - 1) / AesBlockBytes;
                int encryptedBytes = checked(blocks * AesBlockBytes);
                for (int block = 0; block < blocks; block++)
                {
                    counter.CopyTo(counterBlocks, block * AesBlockBytes);
                    int blockOffset = offset + (block * AesBlockBytes);
                    if (blockOffset + AesBlockBytes < input.Length)
                    {
                        IncrementBigEndianCounter(counter);
                    }
                }

                int written = aes.EncryptEcb(
                    counterBlocks.AsSpan(0, encryptedBytes),
                    keystream.AsSpan(0, encryptedBytes),
                    PaddingMode.None);
                MacComprehensiveTests.Require(
                    written == encryptedBytes,
                    $"Independent AES ECB wrote {written} of {encryptedBytes} counter bytes.");
                for (int index = 0; index < byteCount; index++)
                {
                    output[offset + index] = (byte)(input[offset + index] ^ keystream[index]);
                }

                offset += byteCount;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(counter);
            CryptographicOperations.ZeroMemory(counterBlocks);
            CryptographicOperations.ZeroMemory(keystream);
        }
    }

    private static void IncrementBigEndianCounter(byte[] counter)
    {
        for (int index = counter.Length - 1; index >= 0; index--)
        {
            counter[index]++;
            if (counter[index] != 0)
            {
                return;
            }
        }

        throw new InvalidOperationException("The independent CTR counter overflowed unexpectedly.");
    }

    private static void RequireBlockCounterBoundary(
        string algorithm,
        int blockBytes,
        Action<byte[], byte[], byte[]> xcrypt)
    {
        byte[] maximumCounter = Enumerable.Repeat((byte)0xFF, blockBytes).ToArray();
        byte[] finalInput = Enumerable.Repeat((byte)0x3C, blockBytes).ToArray();
        byte[] finalOutput = new byte[blockBytes];
        xcrypt(maximumCounter, finalInput, finalOutput);

        byte[] crossingInput = Enumerable.Repeat((byte)0x5A, checked(blockBytes * 2)).ToArray();
        byte[] crossingOutput = Enumerable.Repeat((byte)0xA5, crossingInput.Length).ToArray();
        bool rejected = false;
        try
        {
            xcrypt(maximumCounter, crossingInput, crossingOutput);
        }
        catch (CryptographicException)
        {
            rejected = true;
        }

        MacComprehensiveTests.Require(rejected, $"{algorithm} accepted a CTR request that wraps the counter.");
        MacComprehensiveTests.Require(
            crossingOutput.All(value => value == 0xA5),
            $"{algorithm} wrote output before refusing CTR counter exhaustion.");
    }

    private static Task KalynaAgainstReferenceAsync()
    {
        MacComprehensiveTests.Require(
            NativeKalyna.IsAvailable(),
            $"Kalyna v12 library unavailable: {NativeKalyna.LastLoadError}");

        byte[] plaintext = DerivedBytes(LargeBytes + 37, 0xABCDEF);
        byte[] fromIndependent = new byte[plaintext.Length];
        byte[] fromProduction = new byte[plaintext.Length];
        byte[] fromScalar = new byte[plaintext.Length];

        // Four keys, four nonces, four places in the counter's range. The last
        // two start high enough that the 256 MiB run carries out of the low
        // 32 and 40 bits respectively, which is the arithmetic a worker has to
        // reproduce when it jumps straight to the block it claimed.
        (string Name, ulong KeySeed, ulong NonceSeed, ulong CounterStart, int Length)[] cases =
        [
            ("256 MiB, counter 0", 1, 1001, 0, LargeBytes),
            ("256 MiB, counter 2^32-1", 2, 1002, 0xFFFFFFFFUL, LargeBytes),
            ("256 MiB, counter crossing 2^40", 3, 1003, 0xFFFFFFFFFFUL - 7, LargeBytes),
            ("256 MiB, counter at 2^63", 4, 1004, 1UL << 63, LargeBytes),
            ("256 MiB + 37 bytes, unaligned tail", 5, 1005, 0x0123456789ABCDEFUL, LargeBytes + 37),
        ];

        foreach ((string name, ulong keySeed, ulong nonceSeed, ulong counterStart, int length) in cases)
        {
            byte[] key = DerivedBytes(64, keySeed);
            byte[] counter = BuildCounterBlock(nonceSeed, counterStart);

            var stopwatch = Stopwatch.StartNew();
            BouncyKalynaCtr(key, counter, plaintext, fromIndependent, length);
            TimeSpan independentElapsed = stopwatch.Elapsed;
            stopwatch.Restart();
            NativeKalyna.XCryptCtr512(key, counter, plaintext, fromProduction, length);
            TimeSpan productionElapsed = stopwatch.Elapsed;
            NativeKalyna.XCryptCtr512Scalar(key, counter, plaintext, fromScalar, length);

            RequireIdentical(fromIndependent, fromProduction, length, $"Kalyna independent {name}");
            RequireIdentical(fromScalar, fromProduction, length, $"Kalyna scalar/parallel {name}");
            Console.WriteLine(
                $"    Kalyna {name}: identical "
                + $"({Rate(length, independentElapsed)} Bouncy Castle, {Rate(length, productionElapsed)} Crypto++)");
        }

        // The same comparison at every length where the driver changes gear.
        // One key is enough here: what is under test is the boundary, not the
        // key schedule, and each of these costs a reference pass.
        byte[] boundaryKey = DerivedBytes(64, 9);
        byte[] boundaryCounter = BuildCounterBlock(9009, 0xFFFFFFFEUL);
        foreach (int length in BoundaryLengths)
        {
            BouncyKalynaCtr(boundaryKey, boundaryCounter, plaintext, fromIndependent, length);
            NativeKalyna.XCryptCtr512(boundaryKey, boundaryCounter, plaintext, fromProduction, length);
            NativeKalyna.XCryptCtr512Scalar(boundaryKey, boundaryCounter, plaintext, fromScalar, length);
            RequireIdentical(fromIndependent, fromProduction, length, $"Kalyna boundary length {length}");
            RequireIdentical(fromScalar, fromProduction, length, $"Kalyna scalar boundary length {length}");

            byte[] inPlace = plaintext.AsSpan(0, length).ToArray();
            try
            {
                NativeKalyna.XCryptCtr512(boundaryKey, boundaryCounter, inPlace, inPlace, length);
                RequireIdentical(fromIndependent, inPlace, length, $"Kalyna in-place boundary length {length}");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(inPlace);
            }
        }

        RequireBlockCounterBoundary(
            "Kalyna-512/512",
            KalynaBlockBytes,
            (nonce, input, output) => NativeKalyna.XCryptCtr512(
                new byte[64], nonce, input, output, input.Length));
        Console.WriteLine($"    Kalyna boundary lengths identical: {string.Join(", ", BoundaryLengths)}");
        Console.WriteLine("    Kalyna in-place output agrees and counter exhaustion is rejected before output");
        return Task.CompletedTask;
    }

    private static void BouncyKalynaCtr(
        byte[] key,
        byte[] nonce,
        byte[] input,
        byte[] output,
        int length)
    {
        var cipher = new Dstu7624Engine(512);
        byte[] counter = nonce.ToArray();
        byte[] stream = new byte[KalynaBlockBytes];
        try
        {
            cipher.Init(true, new KeyParameter(key));
            for (int offset = 0; offset < length; offset += KalynaBlockBytes)
            {
                cipher.ProcessBlock(counter, 0, stream, 0);
                int blockLength = Math.Min(KalynaBlockBytes, length - offset);
                for (int index = 0; index < blockLength; index++)
                {
                    output[offset + index] = (byte)(input[offset + index] ^ stream[index]);
                }

                if (offset + blockLength < length)
                {
                    IncrementBigEndianCounter(counter);
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(counter);
            CryptographicOperations.ZeroMemory(stream);
        }
    }

    private static Task ChaChaAgainstSerialAsync()
    {
        MacComprehensiveTests.Require(
            NativeChaChaPoly.IsAvailable(),
            $"ChaCha20-Poly1305 reference library unavailable: {NativeChaChaPoly.LastLoadError}");

        byte[] plaintext = DerivedBytes(LargeBytes + 37, 0x5A5A5A);
        byte[] fromSerial = new byte[plaintext.Length];
        byte[] fromParallel = new byte[plaintext.Length];

        const uint largeBlocks = LargeBytes / ChaChaBlockBytes;
        (string Name, ulong KeySeed, ulong NonceSeed, uint Counter, int Length)[] cases =
        [
            ("256 MiB, counter 0", 1, 2001, 0, LargeBytes),
            ("256 MiB, counter 1 (where the AEAD starts)", 2, 2002, 1, LargeBytes),
            ("256 MiB, counter 2^31-1", 3, 2003, 0x7FFFFFFF, LargeBytes),
            ("256 MiB, ending one block below 2^32", 4, 2004, uint.MaxValue - largeBlocks, LargeBytes),
            ("256 MiB + 37 bytes, unaligned tail", 5, 2005, 12345, LargeBytes + 37),
        ];

        foreach ((string name, ulong keySeed, ulong nonceSeed, uint counter, int length) in cases)
        {
            byte[] key = DerivedBytes(32, keySeed);
            byte[] nonce = DerivedBytes(12, nonceSeed);

            var stopwatch = Stopwatch.StartNew();
            int serialResult = NativeChaChaPoly.XCryptSerial(key, nonce, counter, plaintext, fromSerial, length);
            TimeSpan serialElapsed = stopwatch.Elapsed;
            stopwatch.Restart();
            int parallelResult = NativeChaChaPoly.XCrypt(key, nonce, counter, plaintext, fromParallel, length);
            TimeSpan parallelElapsed = stopwatch.Elapsed;

            MacComprehensiveTests.Require(
                serialResult == 0 && parallelResult == 0,
                $"ChaCha20 {name}: serial returned {serialResult}, worker split returned {parallelResult}.");
            RequireIdentical(fromSerial, fromParallel, length, $"ChaCha20 {name}");
            Console.WriteLine(
                $"    ChaCha20 {name}: identical "
                + $"({Rate(length, serialElapsed)} serial, {Rate(length, parallelElapsed)} split)");
        }

        byte[] boundaryKey = DerivedBytes(32, 19);
        byte[] boundaryNonce = DerivedBytes(12, 1919);
        foreach (int length in BoundaryLengths)
        {
            const uint counter = 7;
            int serialResult = NativeChaChaPoly.XCryptSerial(boundaryKey, boundaryNonce, counter, plaintext, fromSerial, length);
            int parallelResult = NativeChaChaPoly.XCrypt(boundaryKey, boundaryNonce, counter, plaintext, fromParallel, length);
            MacComprehensiveTests.Require(
                serialResult == 0 && parallelResult == 0,
                $"ChaCha20 boundary length {length}: serial returned {serialResult}, worker split returned {parallelResult}.");
            RequireIdentical(fromSerial, fromParallel, length, $"ChaCha20 boundary length {length}");

            byte[] inPlace = plaintext.AsSpan(0, length).ToArray();
            try
            {
                int inPlaceResult = NativeChaChaPoly.XCrypt(
                    boundaryKey, boundaryNonce, counter, inPlace, inPlace, length);
                MacComprehensiveTests.Require(
                    inPlaceResult == 0,
                    $"ChaCha20 in-place boundary length {length} returned {inPlaceResult}.");
                RequireIdentical(fromSerial, inPlace, length, $"ChaCha20 in-place boundary length {length}");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(inPlace);
            }
        }

        Console.WriteLine($"    ChaCha20 boundary lengths identical: {string.Join(", ", BoundaryLengths)}");

        // RFC 8439 gives the block counter 32 bits. A request that would run
        // past its end must be refused, not served with keystream that repeats
        // under the same key: two plaintext blocks XORed with one keystream
        // block is the classic two-time pad.
        byte[] exhaustionKey = DerivedBytes(32, 99);
        byte[] exhaustionNonce = DerivedBytes(12, 98);
        byte[] finalCounterInput = plaintext.AsSpan(0, ChaChaBlockBytes).ToArray();
        byte[] finalCounterSerial = new byte[ChaChaBlockBytes];
        byte[] finalCounterSplit = new byte[ChaChaBlockBytes];
        int finalSerialResult = NativeChaChaPoly.XCryptSerial(
            exhaustionKey,
            exhaustionNonce,
            uint.MaxValue,
            finalCounterInput,
            finalCounterSerial,
            finalCounterInput.Length);
        int finalSplitResult = NativeChaChaPoly.XCrypt(
            exhaustionKey,
            exhaustionNonce,
            uint.MaxValue,
            finalCounterInput,
            finalCounterSplit,
            finalCounterInput.Length);
        MacComprehensiveTests.Require(
            finalSerialResult == 0
                && finalSplitResult == 0
                && CryptographicOperations.FixedTimeEquals(finalCounterSerial, finalCounterSplit),
            "ChaCha20 must permit exactly one final block at counter 2^32-1 and both paths must agree.");

        fromParallel.AsSpan(0, 3 * ChaChaBlockBytes).Fill(0xA5);
        int refused = NativeChaChaPoly.XCrypt(
            exhaustionKey, exhaustionNonce, uint.MaxValue - 1, plaintext, fromParallel, 3 * ChaChaBlockBytes);
        MacComprehensiveTests.Require(
            refused == 4,
            $"ChaCha20 must refuse a run that would exhaust the block counter; it returned {refused}.");
        MacComprehensiveTests.Require(
            fromParallel.AsSpan(0, 3 * ChaChaBlockBytes).IndexOfAnyExcept((byte)0xA5) < 0,
            "ChaCha20 split wrote output before refusing counter exhaustion.");

        fromSerial.AsSpan(0, 3 * ChaChaBlockBytes).Fill(0x5A);
        int serialRefused = NativeChaChaPoly.XCryptSerial(
            exhaustionKey, exhaustionNonce, uint.MaxValue - 1, plaintext, fromSerial, 3 * ChaChaBlockBytes);
        MacComprehensiveTests.Require(
            serialRefused == 4
                && fromSerial.AsSpan(0, 3 * ChaChaBlockBytes).IndexOfAnyExcept((byte)0x5A) < 0,
            "ChaCha20 serial did not refuse counter exhaustion before writing output.");
        Console.WriteLine("    ChaCha20 permits the final counter and refuses exhaustion before either path writes output");

        // And the split has to reproduce this library's own RFC 8439 AEAD,
        // whose keystream starts at block 1. That anchors it to the standard
        // rather than only to the implementation it replaced.
        const int aeadLength = 16 * 1024 * 1024;
        byte[] aeadTag = new byte[NativeChaChaPoly.TagBytes];
        for (int trial = 0; trial < 4; trial++)
        {
            byte[] key = DerivedBytes(32, 3000 + (ulong)trial);
            byte[] nonce = DerivedBytes(12, 4000 + (ulong)trial);
            NativeChaChaPoly.Encrypt(key, nonce, ReadOnlySpan<byte>.Empty, plaintext, fromSerial, aeadLength, aeadTag);
            int parallelResult = NativeChaChaPoly.XCrypt(key, nonce, 1, plaintext, fromParallel, aeadLength);
            MacComprehensiveTests.Require(
                parallelResult == 0,
                $"ChaCha20 AEAD cross-check trial {trial}: the worker split returned {parallelResult}.");
            RequireIdentical(fromSerial, fromParallel, aeadLength, $"ChaCha20 against the AEAD, trial {trial}");
        }

        Console.WriteLine("    ChaCha20 worker split reproduces the RFC 8439 AEAD keystream");
        return Task.CompletedTask;
    }

    /// <summary>
    /// The authenticated pair against the published vector and its own rules.
    /// </summary>
    /// <remarks>
    /// This suite used to call Crypto++'s ChaCha20Poly1305, and the framing -
    /// associated data padded to 16, ciphertext padded to 16, then both lengths
    /// little-endian - came with it. It is assembled here now, so the vector in
    /// RFC 8439 section 2.8.2 is what holds it: a padding or length-encoding
    /// slip produces a tag that is merely different, and nothing else in the
    /// suite would notice, because both sides of a round trip would be wrong in
    /// the same way.
    ///
    /// The rejection cases matter for the same reason. A tag check is only
    /// worth having if it fails, and the failure must leave nothing behind:
    /// unauthenticated plaintext in the caller's buffer is exactly what an
    /// AEAD exists to prevent.
    /// </remarks>
    private static Task AeadFramingAsync()
    {
        MacComprehensiveTests.Require(
            NativeChaChaPoly.IsAvailable(),
            $"ChaCha20-Poly1305 reference library unavailable: {NativeChaChaPoly.LastLoadError}");

        byte[] key = new byte[32];
        for (int i = 0; i < key.Length; i++)
        {
            key[i] = (byte)(0x80 + i);
        }

        byte[] nonce = Convert.FromHexString("070000004041424344454647");
        byte[] associated = Convert.FromHexString("50515253c0c1c2c3c4c5c6c7");
        byte[] plaintext = System.Text.Encoding.ASCII.GetBytes(
            "Ladies and Gentlemen of the class of '99: If I could offer you only "
            + "one tip for the future, sunscreen would be it.");
        byte[] expectedCiphertext = Convert.FromHexString(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
            + "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
            + "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
            + "3ff4def08e4b7a9de576d26586cec64b6116");

        byte[] expectedTag = Convert.FromHexString("1ae10b594f09e26a7e902ecbd0600691");

        MacComprehensiveTests.Require(plaintext.Length == 114, "The RFC 8439 vector plaintext is 114 bytes.");
        MacComprehensiveTests.Require(
            expectedCiphertext.Length == plaintext.Length,
            "The RFC 8439 vector ciphertext is as long as its plaintext.");

        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[NativeChaChaPoly.TagBytes];
        NativeChaChaPoly.Encrypt(key, nonce, associated, plaintext, ciphertext, plaintext.Length, tag);

        MacComprehensiveTests.Require(
            ciphertext.AsSpan().SequenceEqual(expectedCiphertext),
            "ChaCha20-Poly1305 did not reproduce the RFC 8439 section 2.8.2 ciphertext.");
        MacComprehensiveTests.Require(
            tag.AsSpan().SequenceEqual(expectedTag),
            "ChaCha20-Poly1305 did not reproduce the RFC 8439 section 2.8.2 tag.");
        Console.WriteLine("    RFC 8439 section 2.8.2 ciphertext and tag reproduced");

        byte[] recovered = new byte[plaintext.Length];
        NativeChaChaPoly.Decrypt(key, nonce, associated, ciphertext, recovered, ciphertext.Length, tag);
        MacComprehensiveTests.Require(
            recovered.AsSpan().SequenceEqual(plaintext),
            "ChaCha20-Poly1305 did not recover the RFC 8439 vector plaintext.");

        RequireRejected("a flipped tag bit", key, nonce, associated, ciphertext, tag, mutateTag: true);
        RequireRejected("a flipped ciphertext bit", key, nonce, associated, ciphertext, tag, mutateCiphertext: true);
        RequireRejected("altered associated data", key, nonce, associated, ciphertext, tag, mutateAssociated: true);
        Console.WriteLine("    a changed tag, ciphertext or associated data is refused");

        // The container hands the same buffer in and out for both directions.
        // The tag covers the ciphertext, so encryption has to take it after
        // writing and decryption has to take it before overwriting; getting
        // either backwards works out-of-place and fails only here.
        byte[] scratch = plaintext.ToArray();
        byte[] inPlaceTag = new byte[NativeChaChaPoly.TagBytes];
        NativeChaChaPoly.Encrypt(key, nonce, associated, scratch, scratch, scratch.Length, inPlaceTag);
        MacComprehensiveTests.Require(
            scratch.AsSpan().SequenceEqual(expectedCiphertext) && inPlaceTag.AsSpan().SequenceEqual(expectedTag),
            "In-place ChaCha20-Poly1305 encryption did not match the out-of-place result.");
        NativeChaChaPoly.Decrypt(key, nonce, associated, scratch, scratch, scratch.Length, inPlaceTag);
        MacComprehensiveTests.Require(
            scratch.AsSpan().SequenceEqual(plaintext),
            "In-place ChaCha20-Poly1305 decryption did not recover the plaintext.");
        Console.WriteLine("    in-place encryption and decryption match the out-of-place result");

        RunParallelPoly1305Matrix();
        RunAeadReferenceMatrix();
        RunLargePoly1305Probe();
        return Task.CompletedTask;
    }

    /// <summary>
    /// Holds the fixed-limb worker implementation against both Crypto++'s
    /// scalar Poly1305 and .NET's independent RFC 8439 implementation.
    /// </summary>
    private static void RunParallelPoly1305Matrix()
    {
        int[] criticalPayloadLengths =
        [
            0, 1, 15, 16, 17, 31, 32, 33,
            63, 64, 65, 127, 128, 129, 255, 256, 257, 4095, 4096,
        ];
        int[] criticalAadLengths = [0, 1, 15, 16, 17, 31, 32, 33, 63, 64];
        var cases = new HashSet<(int PayloadLength, int AadLength)>();

        // Every payload length, with AAD cycling through every value 0..64.
        for (int payloadLength = 0; payloadLength <= 4096; payloadLength++)
        {
            cases.Add((payloadLength, payloadLength % 65));
        }

        // Every AAD length gets a second, deliberately unrelated payload.
        for (int aadLength = 0; aadLength <= 64; aadLength++)
        {
            cases.Add((criticalPayloadLengths[aadLength % criticalPayloadLengths.Length], aadLength));
        }

        // Full cross-product exactly where either RFC field crosses pad16 and
        // common power-of-two boundaries.
        foreach (int payloadLength in criticalPayloadLengths)
        {
            foreach (int aadLength in criticalAadLengths)
            {
                cases.Add((payloadLength, aadLength));
            }
        }

        uint parallelWorkers = (uint)Math.Clamp(Environment.ProcessorCount, 2, 8);
        byte[] key = DerivedBytes(NativeChaChaPoly.KeyBytes, 0x504F4C5931333035UL);
        using var reference = new ChaCha20Poly1305(key);
        int checkedCases = 0;
        try
        {
            foreach ((int payloadLength, int aadLength) in cases)
            {
                byte[] nonce = DerivedBytes(
                    NativeChaChaPoly.NonceBytes,
                    0x4E4F4E43454D4154UL ^ ((ulong)(uint)payloadLength << 16) ^ (uint)aadLength);
                byte[] plaintext = DerivedBytes(
                    payloadLength,
                    0x5041594C4F4144UL ^ ((ulong)(uint)payloadLength << 8) ^ (uint)aadLength);
                byte[] associated = DerivedBytes(
                    aadLength,
                    0x414144UL ^ ((ulong)(uint)aadLength << 24) ^ (uint)payloadLength);
                byte[] expectedCiphertext = new byte[payloadLength];
                byte[] expectedTag = new byte[NativeChaChaPoly.TagBytes];
                byte[] serialCiphertext = new byte[payloadLength];
                byte[] serialTag = new byte[NativeChaChaPoly.TagBytes];
                byte[] oneWorkerCiphertext = new byte[payloadLength];
                byte[] oneWorkerTag = new byte[NativeChaChaPoly.TagBytes];
                byte[] manyWorkerCiphertext = new byte[payloadLength];
                byte[] manyWorkerTag = new byte[NativeChaChaPoly.TagBytes];
                byte[] authenticatedOnlyTag = new byte[NativeChaChaPoly.TagBytes];
                try
                {
                    reference.Encrypt(nonce, plaintext, expectedCiphertext, expectedTag, associated);
                    NativeChaChaPoly.EncryptSerial(
                        key, nonce, associated, plaintext, serialCiphertext, payloadLength, serialTag);
                    NativeChaChaPoly.EncryptWithPoly1305Workers(
                        key, nonce, associated, plaintext, oneWorkerCiphertext, payloadLength, oneWorkerTag, 1);
                    NativeChaChaPoly.EncryptWithPoly1305Workers(
                        key,
                        nonce,
                        associated,
                        plaintext,
                        manyWorkerCiphertext,
                        payloadLength,
                        manyWorkerTag,
                        parallelWorkers);
                    NativeChaChaPoly.AuthenticateWithPoly1305Workers(
                        key,
                        nonce,
                        associated,
                        expectedCiphertext,
                        payloadLength,
                        authenticatedOnlyTag,
                        parallelWorkers);

                    RequireIdentical(
                        expectedCiphertext,
                        serialCiphertext,
                        payloadLength,
                        $"scalar AEAD payload {payloadLength}, AAD {aadLength}");
                    RequireIdentical(
                        expectedCiphertext,
                        oneWorkerCiphertext,
                        payloadLength,
                        $"one-worker AEAD payload {payloadLength}, AAD {aadLength}");
                    RequireIdentical(
                        expectedCiphertext,
                        manyWorkerCiphertext,
                        payloadLength,
                        $"many-worker AEAD payload {payloadLength}, AAD {aadLength}");
                    MacComprehensiveTests.Require(
                        CryptographicOperations.FixedTimeEquals(expectedTag, serialTag)
                            && CryptographicOperations.FixedTimeEquals(expectedTag, oneWorkerTag)
                            && CryptographicOperations.FixedTimeEquals(expectedTag, manyWorkerTag)
                            && CryptographicOperations.FixedTimeEquals(expectedTag, authenticatedOnlyTag),
                        $"Poly1305 scalar/1-worker/{parallelWorkers}-worker tags differ at payload "
                        + $"{payloadLength}, AAD {aadLength}.");
                    checkedCases++;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(nonce);
                    CryptographicOperations.ZeroMemory(plaintext);
                    CryptographicOperations.ZeroMemory(associated);
                    CryptographicOperations.ZeroMemory(expectedCiphertext);
                    CryptographicOperations.ZeroMemory(expectedTag);
                    CryptographicOperations.ZeroMemory(serialCiphertext);
                    CryptographicOperations.ZeroMemory(serialTag);
                    CryptographicOperations.ZeroMemory(oneWorkerCiphertext);
                    CryptographicOperations.ZeroMemory(oneWorkerTag);
                    CryptographicOperations.ZeroMemory(manyWorkerCiphertext);
                    CryptographicOperations.ZeroMemory(manyWorkerTag);
                    CryptographicOperations.ZeroMemory(authenticatedOnlyTag);
                }
            }

            RequirePoly1305WorkerPreflight(key, parallelWorkers);
            RequirePoly1305WorkerInPlace(key, parallelWorkers);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }

        MacComprehensiveTests.Require(
            checkedCases == cases.Count,
            $"The exhaustive Poly1305 matrix ran {checkedCases} of {cases.Count} cases.");
        Console.WriteLine(
            $"    Poly1305 scalar/1-worker/{parallelWorkers}-worker matrix: {checkedCases} cases; "
            + "all payload lengths 0..4096, all AAD lengths 0..64 and critical cross-boundaries");
    }

    private static void RequirePoly1305WorkerPreflight(byte[] key, uint parallelWorkers)
    {
        byte[] nonce = DerivedBytes(NativeChaChaPoly.NonceBytes, 0x505245464C494748UL);
        byte[] associated = DerivedBytes(17, 0x505245414144UL);
        byte[] ciphertext = DerivedBytes(33, 0x50524543495048UL);
        byte[] tag = Enumerable.Repeat((byte)0xA7, NativeChaChaPoly.TagBytes).ToArray();
        bool rejected = false;
        try
        {
            NativeChaChaPoly.AuthenticateWithPoly1305Workers(
                key, nonce, associated, ciphertext, ciphertext.Length, tag, 65);
        }
        catch (CryptographicException)
        {
            rejected = true;
        }

        MacComprehensiveTests.Require(
            rejected && tag.All(value => value == 0xA7),
            "Poly1305 accepted more than 64 workers or modified its output before rejecting the argument.");

        byte[] validTag = new byte[NativeChaChaPoly.TagBytes];
        NativeChaChaPoly.AuthenticateWithPoly1305Workers(
            key, nonce, associated, ciphertext, ciphertext.Length, validTag, parallelWorkers);
        byte[] manipulatedTag = validTag.ToArray();
        manipulatedTag[0] ^= 0x80;
        byte[] output = Enumerable.Repeat((byte)0x5C, ciphertext.Length).ToArray();
        rejected = false;
        try
        {
            NativeChaChaPoly.DecryptWithPoly1305Workers(
                key,
                nonce,
                associated,
                ciphertext,
                output,
                ciphertext.Length,
                manipulatedTag,
                parallelWorkers);
        }
        catch (CryptographicException)
        {
            rejected = true;
        }

        MacComprehensiveTests.Require(
            rejected && output.All(value => value == 0x5C),
            "Parallel Poly1305 decryption emitted plaintext before rejecting a manipulated tag.");
        CryptographicOperations.ZeroMemory(nonce);
        CryptographicOperations.ZeroMemory(associated);
        CryptographicOperations.ZeroMemory(ciphertext);
        CryptographicOperations.ZeroMemory(tag);
        CryptographicOperations.ZeroMemory(validTag);
        CryptographicOperations.ZeroMemory(manipulatedTag);
        CryptographicOperations.ZeroMemory(output);
    }

    private static void RequirePoly1305WorkerInPlace(byte[] key, uint parallelWorkers)
    {
        byte[] nonce = DerivedBytes(NativeChaChaPoly.NonceBytes, 0x494E504C414345UL);
        byte[] associated = DerivedBytes(64, 0x494E504C414144UL);
        byte[] plaintext = DerivedBytes(4096, 0x494E504C504159UL);
        byte[] scratch = plaintext.ToArray();
        byte[] tag = new byte[NativeChaChaPoly.TagBytes];
        byte[] serialRecovered = new byte[plaintext.Length];
        try
        {
            NativeChaChaPoly.EncryptWithPoly1305Workers(
                key,
                nonce,
                associated,
                scratch,
                scratch,
                scratch.Length,
                tag,
                parallelWorkers);
            NativeChaChaPoly.DecryptSerial(
                key,
                nonce,
                associated,
                scratch,
                serialRecovered,
                scratch.Length,
                tag);
            RequireIdentical(
                plaintext,
                serialRecovered,
                plaintext.Length,
                "scalar Crypto++ decrypt of parallel Poly1305 output");
            NativeChaChaPoly.DecryptWithPoly1305Workers(
                key,
                nonce,
                associated,
                scratch,
                scratch,
                scratch.Length,
                tag,
                parallelWorkers);
            RequireIdentical(plaintext, scratch, plaintext.Length, "parallel Poly1305 in-place roundtrip");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(associated);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(scratch);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(serialRecovered);
        }
    }

    private static void RunLargePoly1305Probe()
    {
        uint parallelWorkers = (uint)Math.Clamp(Environment.ProcessorCount, 2, 8);
        byte[] key = DerivedBytes(NativeChaChaPoly.KeyBytes, 0x4C41524745504F4CUL);
        byte[] nonce = DerivedBytes(NativeChaChaPoly.NonceBytes, 0x4C415247454E4F4EUL);
        byte[] associated = DerivedBytes(64, 0x4C41524745414144UL);
        byte[] ciphertext = DerivedBytes(LargeBytes, 0x4C41524745434950UL);
        byte[] scalarTag = new byte[NativeChaChaPoly.TagBytes];
        byte[] oneWorkerTag = new byte[NativeChaChaPoly.TagBytes];
        byte[] manyWorkerTag = new byte[NativeChaChaPoly.TagBytes];
        byte[] automaticTag = new byte[NativeChaChaPoly.TagBytes];
        try
        {
            var stopwatch = Stopwatch.StartNew();
            NativeChaChaPoly.AuthenticateSerial(
                key, nonce, associated, ciphertext, ciphertext.Length, scalarTag);
            TimeSpan scalarElapsed = stopwatch.Elapsed;
            stopwatch.Restart();
            NativeChaChaPoly.AuthenticateWithPoly1305Workers(
                key, nonce, associated, ciphertext, ciphertext.Length, oneWorkerTag, 1);
            TimeSpan oneWorkerElapsed = stopwatch.Elapsed;
            stopwatch.Restart();
            NativeChaChaPoly.AuthenticateWithPoly1305Workers(
                key, nonce, associated, ciphertext, ciphertext.Length, manyWorkerTag, parallelWorkers);
            TimeSpan manyWorkerElapsed = stopwatch.Elapsed;
            NativeChaChaPoly.AuthenticateWithPoly1305Workers(
                key, nonce, associated, ciphertext, ciphertext.Length, automaticTag, 0);

            MacComprehensiveTests.Require(
                CryptographicOperations.FixedTimeEquals(scalarTag, oneWorkerTag)
                    && CryptographicOperations.FixedTimeEquals(scalarTag, manyWorkerTag)
                    && CryptographicOperations.FixedTimeEquals(scalarTag, automaticTag),
                "The 256 MiB Poly1305 scalar, fixed-worker and automatic tags differ.");
            Console.WriteLine(
                $"    Poly1305 256 MiB tags identical "
                + $"({Rate(LargeBytes, scalarElapsed)} Crypto++, "
                + $"{Rate(LargeBytes, oneWorkerElapsed)} fixed-limb 1-worker, "
                + $"{Rate(LargeBytes, manyWorkerElapsed)} fixed-limb {parallelWorkers}-worker)");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(associated);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(scalarTag);
            CryptographicOperations.ZeroMemory(oneWorkerTag);
            CryptographicOperations.ZeroMemory(manyWorkerTag);
            CryptographicOperations.ZeroMemory(automaticTag);
        }
    }

    /// <summary>
    /// Compares the shipped framing against .NET's independent RFC 8439
    /// implementation at every pad16 boundary used by the audit contract.
    /// </summary>
    private static void RunAeadReferenceMatrix()
    {
        int[] payloadLengths =
        [
            0, 1, 15, 16, 17, 31, 32, 33,
            63, 64, 65,
            255, 256, 257,
            4095, 4096, 4097,
            (1024 * 1024) - 1, 1024 * 1024, (1024 * 1024) + 1,
            16 * 1024 * 1024,
        ];
        int[] aadLengths = [0, 1, 15, 16, 17, 31, 32, 33, 255, 256];
        int checkedCases = 0;

        for (int trial = 0; trial < 3; trial++)
        {
            byte[] key = DerivedBytes(32, 0x414541444B4559UL + (ulong)trial);
            byte[] nonce = DerivedBytes(12, 0x414541444E4F4E43UL + (ulong)trial);
            using var reference = new ChaCha20Poly1305(key);
            try
            {
                foreach (int payloadLength in payloadLengths)
                {
                    byte[] plaintext = DerivedBytes(
                        payloadLength,
                        0x5041594C4F4144UL + (ulong)payloadLength + (ulong)trial);
                    foreach (int aadLength in aadLengths)
                    {
                        byte[] associated = DerivedBytes(
                            aadLength,
                            0x414144UL + (ulong)aadLength + ((ulong)trial << 32));
                        byte[] expectedCiphertext = new byte[payloadLength];
                        byte[] expectedTag = new byte[NativeChaChaPoly.TagBytes];
                        byte[] nativeCiphertext = new byte[payloadLength];
                        byte[] nativeTag = new byte[NativeChaChaPoly.TagBytes];
                        byte[] recovered = new byte[payloadLength];
                        byte[] independentRecovered = new byte[payloadLength];
                        byte[] inPlace = plaintext.ToArray();
                        byte[] inPlaceTag = new byte[NativeChaChaPoly.TagBytes];
                        try
                        {
                            reference.Encrypt(
                                nonce,
                                plaintext,
                                expectedCiphertext,
                                expectedTag,
                                associated);
                            NativeChaChaPoly.Encrypt(
                                key,
                                nonce,
                                associated,
                                plaintext,
                                nativeCiphertext,
                                payloadLength,
                                nativeTag);
                            RequireIdentical(
                                expectedCiphertext,
                                nativeCiphertext,
                                payloadLength,
                                $"ChaCha20-Poly1305 payload {payloadLength}, AAD {aadLength}, trial {trial}");
                            MacComprehensiveTests.Require(
                                CryptographicOperations.FixedTimeEquals(expectedTag, nativeTag),
                                $"ChaCha20-Poly1305 tag differs from the independent RFC implementation "
                                + $"at payload {payloadLength}, AAD {aadLength}, trial {trial}.");

                            NativeChaChaPoly.Decrypt(
                                key,
                                nonce,
                                associated,
                                nativeCiphertext,
                                recovered,
                                payloadLength,
                                nativeTag);
                            reference.Decrypt(
                                nonce,
                                nativeCiphertext,
                                nativeTag,
                                independentRecovered,
                                associated);
                            RequireIdentical(
                                plaintext,
                                recovered,
                                payloadLength,
                                $"Native AEAD decrypt payload {payloadLength}, AAD {aadLength}, trial {trial}");
                            RequireIdentical(
                                plaintext,
                                independentRecovered,
                                payloadLength,
                                $"Independent AEAD decrypt payload {payloadLength}, AAD {aadLength}, trial {trial}");

                            NativeChaChaPoly.Encrypt(
                                key,
                                nonce,
                                associated,
                                inPlace,
                                inPlace,
                                payloadLength,
                                inPlaceTag);
                            RequireIdentical(
                                expectedCiphertext,
                                inPlace,
                                payloadLength,
                                $"In-place AEAD payload {payloadLength}, AAD {aadLength}, trial {trial}");
                            MacComprehensiveTests.Require(
                                CryptographicOperations.FixedTimeEquals(expectedTag, inPlaceTag),
                                $"In-place AEAD tag differs at payload {payloadLength}, AAD {aadLength}, trial {trial}.");
                            NativeChaChaPoly.Decrypt(
                                key,
                                nonce,
                                associated,
                                inPlace,
                                inPlace,
                                payloadLength,
                                inPlaceTag);
                            RequireIdentical(
                                plaintext,
                                inPlace,
                                payloadLength,
                                $"In-place AEAD roundtrip payload {payloadLength}, AAD {aadLength}, trial {trial}");

                            RequireRejected(
                                $"a flipped tag at payload {payloadLength}, AAD {aadLength}, trial {trial}",
                                key,
                                nonce,
                                associated,
                                nativeCiphertext,
                                nativeTag,
                                mutateTag: true);
                            if (payloadLength != 0)
                            {
                                RequireRejected(
                                    $"a flipped ciphertext at payload {payloadLength}, AAD {aadLength}, trial {trial}",
                                    key,
                                    nonce,
                                    associated,
                                    nativeCiphertext,
                                    nativeTag,
                                    mutateCiphertext: true);
                            }
                            if (aadLength != 0)
                            {
                                RequireRejected(
                                    $"flipped AAD at payload {payloadLength}, AAD {aadLength}, trial {trial}",
                                    key,
                                    nonce,
                                    associated,
                                    nativeCiphertext,
                                    nativeTag,
                                    mutateAssociated: true);
                            }

                            checkedCases++;
                        }
                        finally
                        {
                            CryptographicOperations.ZeroMemory(associated);
                            CryptographicOperations.ZeroMemory(expectedCiphertext);
                            CryptographicOperations.ZeroMemory(expectedTag);
                            CryptographicOperations.ZeroMemory(nativeCiphertext);
                            CryptographicOperations.ZeroMemory(nativeTag);
                            CryptographicOperations.ZeroMemory(recovered);
                            CryptographicOperations.ZeroMemory(independentRecovered);
                            CryptographicOperations.ZeroMemory(inPlace);
                            CryptographicOperations.ZeroMemory(inPlaceTag);
                        }
                    }

                    CryptographicOperations.ZeroMemory(plaintext);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
                CryptographicOperations.ZeroMemory(nonce);
            }
        }

        MacComprehensiveTests.Require(
            checkedCases == 3 * payloadLengths.Length * aadLengths.Length,
            $"The AEAD padding matrix ran {checkedCases} cases instead of the complete cross product.");
        Console.WriteLine(
            $"    ChaCha20-Poly1305 independent reference matrix: {checkedCases} payload/AAD/key/nonce cases, "
            + "out-of-place, in-place and authentication-before-output");
    }

    private static void RequireRejected(
        string what,
        byte[] key,
        byte[] nonce,
        byte[] associated,
        byte[] ciphertext,
        byte[] tag,
        bool mutateTag = false,
        bool mutateCiphertext = false,
        bool mutateAssociated = false)
    {
        byte[] usedTag = tag.ToArray();
        byte[] usedCiphertext = ciphertext.ToArray();
        byte[] usedAssociated = associated.ToArray();
        if (mutateTag) { usedTag[9] ^= 0x40; }
        if (mutateCiphertext) { usedCiphertext[usedCiphertext.Length / 2] ^= 0x01; }
        if (mutateAssociated) { usedAssociated[usedAssociated.Length / 2] ^= 0x80; }

        byte[] output = new byte[usedCiphertext.Length];
        output.AsSpan().Fill(0xCC);
        bool rejected = false;
        bool outputUntouched = false;
        try
        {
            NativeChaChaPoly.Decrypt(
                key, nonce, usedAssociated, usedCiphertext, output, usedCiphertext.Length, usedTag);
        }
        catch (CryptographicException)
        {
            rejected = true;
            outputUntouched = output.All(value => value == 0xCC);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(usedTag);
            CryptographicOperations.ZeroMemory(usedCiphertext);
            CryptographicOperations.ZeroMemory(usedAssociated);
            CryptographicOperations.ZeroMemory(output);
        }

        MacComprehensiveTests.Require(rejected, $"ChaCha20-Poly1305 accepted {what}.");
        MacComprehensiveTests.Require(
            outputUntouched,
            $"ChaCha20-Poly1305 wrote into the caller's buffer while refusing {what}.");
    }

    private static string Rate(int length, TimeSpan elapsed)
    {
        double seconds = elapsed.TotalSeconds;
        if (seconds <= 0)
        {
            return "n/a";
        }

        return $"{length / (1024.0 * 1024.0) / seconds:F0} MB/s";
    }
}
