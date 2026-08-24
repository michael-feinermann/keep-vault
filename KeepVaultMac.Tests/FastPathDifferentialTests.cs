using System.Diagnostics;
using KalynaArchiver.Services;

/// <summary>
/// The shipped fast cipher paths against the reference implementations that sit
/// beside them in the same library, over buffers the size of a real archive.
/// </summary>
/// <remarks>
/// Both libraries verify themselves at start-up — Kalyna's tables against the
/// DSTU 7624:2014 vector and 64 derived key/block pairs — but a self-check runs
/// on a few blocks under a handful of keys. What it cannot reach is the mode
/// wrapped around the block function: the counter arithmetic across a quarter of
/// a gigabyte, the carry out of a counter that starts near its own limit, the
/// tail block of a length that is not a multiple of the block size, and the
/// boundaries where the driver switches from one thread to many and from one
/// claimed chunk to the next. Those are where a fast path that passes every
/// vector still writes a container that will not open.
///
/// So both tests drive 256 MiB through the shipped export and through the
/// reference export beside it, under several keys, nonces and starting block
/// counters, and require the two to agree byte for byte. They are slow — the
/// Kalyna reference computes each GF(2^8) product of the MDS multiply at run
/// time — and that slowness is the point: it is the price of holding the fast
/// path against something that was never optimised.
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

    private const int KalynaBlockBytes = 64;
    private const int ChaChaBlockBytes = 64;

    /// <summary>Where the CTR drivers stop being serial.</summary>
    private const int ParallelThresholdBytes = 1024 * 1024;

    /// <summary>What one worker claims at a time, for the 64-byte block ciphers.</summary>
    private const int ChunkBytes = 256 * 1024;

    internal static TestCase[] Tests =>
    [
        new("Kalyna-512/512 table path against the reference over 256 MiB",
            KalynaAgainstReferenceAsync, TestResource.CpuHeavy, "Crypto"),
        new("ChaCha20 worker split against the serial keystream over 256 MiB",
            ChaChaAgainstSerialAsync, TestResource.CpuHeavy, "Crypto"),
    ];

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

    private static Task KalynaAgainstReferenceAsync()
    {
        MacComprehensiveTests.Require(
            NativeKalyna.IsAvailable(),
            $"Kalyna reference library unavailable: {NativeKalyna.LastLoadError}");

        byte[] plaintext = DerivedBytes(LargeBytes + 37, 0xABCDEF);
        byte[] fromReference = new byte[plaintext.Length];
        byte[] fromFast = new byte[plaintext.Length];

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
            NativeKalyna.XCryptCtr512Reference(key, counter, plaintext, fromReference, length);
            TimeSpan referenceElapsed = stopwatch.Elapsed;
            stopwatch.Restart();
            NativeKalyna.XCryptCtr512(key, counter, plaintext, fromFast, length);
            TimeSpan fastElapsed = stopwatch.Elapsed;

            RequireIdentical(fromReference, fromFast, length, $"Kalyna {name}");
            Console.WriteLine(
                $"    Kalyna {name}: identical "
                + $"({Rate(length, referenceElapsed)} reference, {Rate(length, fastElapsed)} tables)");
        }

        // The same comparison at every length where the driver changes gear.
        // One key is enough here: what is under test is the boundary, not the
        // key schedule, and each of these costs a reference pass.
        byte[] boundaryKey = DerivedBytes(64, 9);
        byte[] boundaryCounter = BuildCounterBlock(9009, 0xFFFFFFFEUL);
        foreach (int length in BoundaryLengths)
        {
            NativeKalyna.XCryptCtr512Reference(boundaryKey, boundaryCounter, plaintext, fromReference, length);
            NativeKalyna.XCryptCtr512(boundaryKey, boundaryCounter, plaintext, fromFast, length);
            RequireIdentical(fromReference, fromFast, length, $"Kalyna boundary length {length}");
        }

        Console.WriteLine($"    Kalyna boundary lengths identical: {string.Join(", ", BoundaryLengths)}");
        return Task.CompletedTask;
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
        }

        Console.WriteLine($"    ChaCha20 boundary lengths identical: {string.Join(", ", BoundaryLengths)}");

        // RFC 8439 gives the block counter 32 bits. A request that would run
        // past its end must be refused, not served with keystream that repeats
        // under the same key: two plaintext blocks XORed with one keystream
        // block is the classic two-time pad.
        byte[] exhaustionKey = DerivedBytes(32, 99);
        byte[] exhaustionNonce = DerivedBytes(12, 98);
        int refused = NativeChaChaPoly.XCrypt(
            exhaustionKey, exhaustionNonce, uint.MaxValue - 1, plaintext, fromParallel, 3 * ChaChaBlockBytes);
        MacComprehensiveTests.Require(
            refused == 4,
            $"ChaCha20 must refuse a run that would exhaust the block counter; it returned {refused}.");
        Console.WriteLine("    ChaCha20 refuses a run that would exhaust the 32-bit block counter");

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
