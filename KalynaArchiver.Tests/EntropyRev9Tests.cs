using System.Buffers.Binary;
using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using KalynaArchiver.Services;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

// All bytes in these fixtures are public synthetic test data. No production
// RNG switch, record export, or deterministic mode is exposed by the product.
internal static class EntropyRev9Tests
{
    internal static IReadOnlyList<TestCase> All =>
    [
        new("entropy.rev9-golden", "REV9 frozen independent Python SHA3/SHA512 shuffle vectors", EntropyRev9GoldenTests.RunAsync, TestResource.ProcessGlobal, "Entropy"),
        new("entropy.rev9-routing", "REV9 routing rejection, replacement, readiness and count commit", RoutingAsync, TestResource.ProcessGlobal, "Entropy"),
        new("entropy.rev9-shuffle", "REV9 complete small permutations, 32/64-bit bounds and record replay", ShuffleAsync, TestResource.ProcessGlobal, "Entropy"),
        new("entropy.rev9-dual-composition", "REV9 all 15018 small dual-shuffle compositions including identity", DualCompositionAsync, TestResource.ProcessGlobal, "Entropy"),
        new("entropy.rev9-suite-plans", "REV9 every single-round suite, direct roles and plan rejection", SuitePlansAsync, TestResource.ProcessGlobal, "Entropy"),
        new("entropy.rev9-output", "REV9 eleven-role XOR, single/dual plan, 320-byte basis and one-time consume", OutputAsync, TestResource.ProcessGlobal, "Entropy"),
        new("entropy.rev9-faults", "REV9 overflow, bounded locked memory, cleanup failure and retry ownership", FaultsAsync, TestResource.ProcessGlobal, "Entropy"),
        new("entropy.rev9-lifecycle", "REV9 detached epoch, cancellation, reset, RNG failure and full-capacity wipe", LifecycleAsync, TestResource.ProcessGlobal, "Entropy"),
    ];

    internal static Task RoutingAsync()
    {
        EntropyMixer.Reset();
        try
        {
            Require(Enum.GetValues<EntropyPurpose>().Select(p => (int)p).SequenceEqual(Enumerable.Range(0, 11)), "Purpose IDs are not exactly 0..10.");
            int[] counts = [1, 2, 3, 5, 7, 11, 16, 17, 31, 64, 257, 65535, 65536, 65537, int.MaxValue];
            foreach (int count in counts)
            {
                ulong limit = (1UL << 32) - (1UL << 32) % (uint)count;
                foreach (uint candidate in new[] { 0U, checked((uint)(limit - 1)), uint.MaxValue })
                {
                    int calls = 0;
                    EntropyMixer.RandomFillForTests = (b, role) =>
                    {
                        Require(role == EntropyRandomRole.PoolRouting && b.Length == 4, "Selector uses another RNG role/width.");
                        BinaryPrimitives.WriteUInt32LittleEndian(b, calls++ == 0 ? candidate : 0);
                    };
                    int actual = EntropyMixer.SelectUniformPurposeSlot(count, default);
                    Require(actual == (candidate < limit ? candidate % count : 0), "Selector arithmetic differs from independent limit.");
                    Require(calls == (candidate < limit ? 1 : 2), "Rejected value or n=1 did not consume its own candidate.");
                }
            }
            foreach (uint rejected in new[] { 4294967292U, 4294967293U, 4294967294U, 4294967295U })
            {
                int calls = 0;
                EntropyMixer.RandomFillForTests = (b, _) => BinaryPrimitives.WriteUInt32LittleEndian(b, calls++ < 3 ? rejected : 9U);
                Require(EntropyMixer.SelectUniformPurposeSlot(11, default) == 9 && calls == 4, "n=11 rejection boundary changed.");
            }
            int rejectedCalls = 0;
            EntropyMixer.RandomFillForTests = (b, _) => { rejectedCalls++; b.AsSpan().Fill(255); };
            Throws<CryptographicException>(() => EntropyMixer.SelectUniformPurposeSlot(11, default));
            Require(rejectedCalls == 128, "Routing rejection budget is not 128.");
            Throws<ArgumentOutOfRangeException>(() => EntropyMixer.SelectUniformPurposeSlot(0, default));
            Require(rejectedCalls == 128, "Invalid slot count consumed randomness.");
            foreach (EntropyPurpose[] catalog in new[]
            {
                new[] { (EntropyPurpose)91 },
                new[] { (EntropyPurpose)77, (EntropyPurpose)4, (EntropyPurpose)23 },
                Enumerable.Range(0, 17).Select(i => (EntropyPurpose)(i * 13 + 29)).ToArray(),
            })
                for (int selected = 0; selected < catalog.Length; selected++)
                {
                    int current = selected;
                    EntropyMixer.RandomFillForTests = (b, _) => BinaryPrimitives.WriteUInt32LittleEndian(b, checked((uint)current));
                    Require(EntropyMixer.SelectUniformPurpose(catalog, default) == catalog[selected], "Routing confused slot position with a non-contiguous purpose ID.");
                }
            // Exhaustive reduced domains establish equal preimage cardinality,
            // rather than relying on a probabilistic chi-square threshold.
            foreach (int bits in new[] { 8, 16 })
                foreach (int n in counts.Where(n => n <= (1 << bits)))
                {
                    int space = 1 << bits, limit = space - space % n;
                    int[] bins = new int[n];
                    for (int value = 0; value < space; ++value) if (value < limit) bins[value % n]++;
                    Require(bins.All(x => x == limit / n), "Reduced rejection domain is biased.");
                }
            EntropyMixer.RandomFillForTests = (b, role) => { Require(role == EntropyRandomRole.PoolRouting, "Unexpected role during capture."); BinaryPrimitives.WriteUInt32LittleEndian(b, 8); };
            for (int i = 0; i < 1500; ++i) EntropyMixer.AddCanonicalRecord(Record(8, i));
            EntropyPoolStatus status = EntropyMixer.GetPoolStatus();
            Require(status.Total == 1500 && status.NonceThird == 1500 && status.Minimum == 0 && !status.IsReady, "Routing caps, balances, or readies one oversized pool.");
            Throws<InvalidOperationException>(() => EntropyMixer.CreateArchiveEntropy());
            Require(EntropyMixer.GetPoolStatus() == status, "Failed readiness changed committed records.");
            EntropyMixer.RandomFillForTests = (_, _) => throw new CryptographicException("public fixture RNG failure");
            Throws<CryptographicException>(() => EntropyMixer.AddCanonicalRecord(Record(0, 0)));
            Require(EntropyMixer.GetPoolStatus().Total == 1500 && !EntropyMixer.GetPoolStatus().Healthy, "Failed RNG committed a record or retained readiness.");
            for (int missing = 0; missing < 11; ++missing)
            {
                long[] c = Enumerable.Repeat(1025L, 11).ToArray(); c[missing] = 1023;
                var probe = new EntropyPoolStatus(c.Sum(), c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], c[8], c[9], c[10]);
                Require(!probe.IsReady, "A deficient role was hidden by the total.");
            }
        }
        finally { ClearSeams(); EntropyMixer.Reset(); }
        return Task.CompletedTask;
    }

    internal static Task ShuffleAsync()
    {
        long allocationBaseline = SecureMemory.LockedAllocationsForTests;
        long enumerated = 0;
        for (int count = 0; count <= 8; ++count)
        {
            using SensitiveMouseRecordStore store = Store(Enumerable.Range(0, count).Select(i => Record(2, i)).ToArray());
            var seen = new HashSet<string>(StringComparer.Ordinal);
            int[] decisions = new int[Math.Max(0, count - 1)];
            void Visit(int depth)
            {
                if (depth != decisions.Length)
                {
                    for (int candidate = 0; candidate < count - depth; ++candidate) { decisions[depth] = candidate; Visit(depth + 1); }
                    return;
                }
                store.InitializeIndices(default);
                int cursor = 0;
                using var rng = new PoolShuffleRandomSource(EntropyRandomRole.PoolShuffleRound1, (b, _) =>
                {
                    b.AsSpan().Clear();
                    for (int offset = 0; offset + 4 <= b.Length && cursor < decisions.Length; offset += 4)
                        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(offset), checked((uint)decisions[cursor++]));
                }, 32);
                rng.Shuffle(store, default);
                int[] actual = Enumerable.Range(0, count).Select(i => checked((int)store.ReadIndex(i))).ToArray();
                // Independent draw-from-prefix oracle assigns the final slot,
                // shrinking the remaining list rather than swapping a vector.
                var remaining = Enumerable.Range(0, count).ToList();
                int[] expected = new int[count];
                for (int step = 0; step < decisions.Length; ++step)
                {
                    int chosen = decisions[step]; expected[count - 1 - step] = remaining[chosen];
                    remaining[chosen] = remaining[^1]; remaining.RemoveAt(remaining.Count - 1);
                }
                if (count != 0) expected[0] = remaining[0];
                Require(actual.SequenceEqual(expected), "Production shuffle differs from the independent prefix oracle.");
                Require(seen.Add(string.Join(',', actual)), "Different legal decisions produced the same permutation.");
                enumerated++;
            }
            Visit(0);
            Require(seen.Count == Factorial(count), "Shuffle omitted a permutation, including identity.");
        }
        Require(enumerated == 46234, "Complete m=0..8 permutation inventory differs.");
        foreach (ulong bound in new ulong[] { 1, 2, 3, 11, 2147483647, 2147483648, 4294967295, 4294967296, 4294967297, long.MaxValue })
        {
            int width = bound <= 4294967296 ? 4 : 8;
            UInt128 space = (UInt128)1 << (width * 8), limit = space - space % bound;
            int fills = 0;
            using var random = new PoolShuffleRandomSource(EntropyRandomRole.PoolShuffleRound2, (b, role) =>
            {
                Require(role == EntropyRandomRole.PoolShuffleRound2, "Round two RNG role lost.");
                b.AsSpan().Clear(); ulong value = fills++ == 0 ? checked((ulong)(limit - 1)) : 0;
                if (width == 4) BinaryPrimitives.WriteUInt32LittleEndian(b, checked((uint)value)); else BinaryPrimitives.WriteUInt64LittleEndian(b, value);
            }, 8);
            Require(random.NextBelow(bound, default) == checked((ulong)(limit - 1)) % bound, "Shuffle boundary or word width differs.");
        }
        using (var failed = new PoolShuffleRandomSource(EntropyRandomRole.PoolShuffleRound1, (b, _) => b.AsSpan().Fill(255), 8))
            Throws<CryptographicException>(() => failed.NextBelow(11, default));
        foreach (int count in new[] { 0, 1, 2, 1023, 1024, 1025 })
        {
            byte[][] originals = Enumerable.Range(0, count).Select(i => Record(7, i)).ToArray();
            using var pool = Store(originals); pool.InitializeIndices(default);
            using (var rng = new PoolShuffleRandomSource(EntropyRandomRole.PoolShuffleRound1, (b, _) => b.AsSpan().Clear())) rng.Shuffle(pool, default);
            int[] firstOrder = ZeroOrder(count, 1);
            Require(Enumerable.Range(0, count).Select(i => pool.ReadIndex(i)).SequenceEqual(firstOrder.Select(i => (long)i)), "Zero-draw round one is not a full permutation.");
            byte[] actual = new byte[64];
            ConsumedEntropySnapshot.Replay(pool, 7, 0x0102030405060700, false, actual, default);
            Require(actual.SequenceEqual(ReplayOracle(originals, firstOrder, 7, 0x0102030405060700, false)), "SHA3 replay transcript is not canonical.");
            using (var rng = new PoolShuffleRandomSource(EntropyRandomRole.PoolShuffleRound2, (b, _) => b.AsSpan().Clear())) rng.Shuffle(pool, default);
            ConsumedEntropySnapshot.Replay(pool, 7, 0x0102030405060700, true, actual, default);
            Require(actual.SequenceEqual(ReplayOracle(originals, ZeroOrder(count, 2), 7, 0x0102030405060700, true)), "Round two reused SHA3 state or skipped its fresh shuffle.");
        }
        Require(SecureMemory.LockedAllocationsForTests == allocationBaseline, "Shuffle/replay leaked locked storage.");
        return Task.CompletedTask;
    }

    internal static Task DualCompositionAsync()
    {
        long pairs = 0, identitySecond = 0;
        long baseline = SecureMemory.LockedAllocationsForTests;
        for (int count = 0; count <= 5; count++)
        {
            var choices = new List<int[]>();
            int[] current = new int[Math.Max(0, count - 1)];
            void Enumerate(int depth)
            {
                if (depth == current.Length) { choices.Add((int[])current.Clone()); return; }
                for (int candidate = 0; candidate < count - depth; candidate++) { current[depth] = candidate; Enumerate(depth + 1); }
            }
            Enumerate(0);
            using var store = Store(Enumerable.Range(0, count).Select(i => Record(3, i)).ToArray());
            void Apply(int[] decisions, EntropyRandomRole role)
            {
                int cursor = 0;
                using var rng = new PoolShuffleRandomSource(role, (b, actualRole) =>
                {
                    Require(role == actualRole, "Dual composition crossed random roles.");
                    b.AsSpan().Clear();
                    for (int offset = 0; offset + 4 <= b.Length && cursor < decisions.Length; offset += 4)
                        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(offset), checked((uint)decisions[cursor++]));
                }, 32);
                rng.Shuffle(store, default);
                Require(cursor == decisions.Length, "Dual shuffle did not draw every step.");
            }
            static int[] PrefixOracle(int[] input, int[] decisions)
            {
                var remaining = input.ToList(); int[] result = new int[input.Length];
                for (int step = 0; step < decisions.Length; step++)
                {
                    int slot = decisions[step]; result[input.Length - 1 - step] = remaining[slot];
                    remaining[slot] = remaining[^1]; remaining.RemoveAt(remaining.Count - 1);
                }
                if (remaining.Count != 0) result[0] = remaining[0];
                return result;
            }
            foreach (int[] first in choices)
            {
                store.InitializeIndices(default); Apply(first, EntropyRandomRole.PoolShuffleRound1);
                int[] firstOrder = Enumerable.Range(0, count).Select(i => checked((int)store.ReadIndex(i))).ToArray();
                Require(firstOrder.SequenceEqual(PrefixOracle(Enumerable.Range(0, count).ToArray(), first)), "First composition order.");
                foreach (int[] second in choices)
                {
                    for (int i = 0; i < count; i++) store.WriteIndex(i, firstOrder[i]);
                    Apply(second, EntropyRandomRole.PoolShuffleRound2);
                    int[] order = Enumerable.Range(0, count).Select(i => checked((int)store.ReadIndex(i))).ToArray();
                    Require(order.SequenceEqual(PrefixOracle(firstOrder, second)), "Round two reset the index or used the wrong composition.");
                    if (second.Select((v, i) => v == count - 1 - i).All(v => v))
                    { Require(order.SequenceEqual(firstOrder), "Identity second round changed order one."); identitySecond++; }
                    pairs++;
                }
            }
        }
        Require(pairs == 15018 && identitySecond == 154, "Incomplete dual composition or identity inventory.");
        Require(SecureMemory.LockedAllocationsForTests == baseline, "Dual composition leaked storage.");
        return Task.CompletedTask;
    }

    internal static Task SuitePlansAsync()
    {
        EntropyMixer.Reset(); int singles = 0;
        try
        {
            foreach (EncryptionSuite suite in Enum.GetValues<EncryptionSuite>().Where(s => !EncryptionSuiteCatalog.Get(s).UsesTwoKdfRounds))
            {
                FillPools(); int r1 = 0, r2 = 0;
                EntropyMixer.RandomFillForTests = (b, role) =>
                {
                    b.AsSpan().Clear();
                    if (role == EntropyRandomRole.PoolShuffleRound1) Interlocked.Increment(ref r1);
                    if (role == EntropyRandomRole.PoolShuffleRound2) Interlocked.Increment(ref r2);
                };
                using GeneratedArchiveEntropy result = EntropyMixer.CreateArchiveEntropy(EntropyPreparationKind.SingleRound);
                var (salt, nonce) = result.ConsumeEncryptionParameters(suite, result.FirstPassword, result.SecondPassword);
                using (salt) using (nonce) Require(salt.Bytes.Length == 128 && nonce.Bytes.Length == 320, "Single suite truncated archive entropy.");
                Require(r1 >= 11 && r2 == 0 && SensitiveMouseRecordStore.Segment.ReservedBytes == 0, "Single suite ran R2 or retained records.");
                singles++;
            }
            Require(singles == 11, "Not all eleven single-round suites were exercised.");
            FillPools(); EntropyPoolStatus before = EntropyMixer.GetPoolStatus();
            Throws<ArgumentException>(() => EntropyMixer.CreateEncryptionParameters(EncryptionSuite.ParanoiaCascade));
            Throws<ArgumentException>(() => EntropyMixer.CreateTwoRoundEncryptionParameters(EncryptionSuite.StandardCascade));
            Require(EntropyMixer.GetPoolStatus() == before, "Invalid plan consumed the live collection.");
            int firstCalls = 0;
            EntropyMixer.RandomFillForTests = (b, role) =>
            {
                Require(role != EntropyRandomRole.PoolShuffleRound2, "Single direct path requested round two.");
                if (role == EntropyRandomRole.PoolShuffleRound1) Interlocked.Increment(ref firstCalls);
                b.AsSpan().Clear();
            };
            var (directSalt, directNonce) = EntropyMixer.CreateEncryptionParameters(EncryptionSuite.StandardCascade);
            using (directSalt) using (directNonce)
                Require(firstCalls >= 11 && directNonce.Bytes.Length == 320 && EntropyMixer.GetPoolStatus().Total == 0, "Direct seven-role output did not consume the complete eleven-pool snapshot.");
        }
        finally { ClearSeams(); EntropyMixer.Reset(); }
        return Task.CompletedTask;
    }

    internal static Task OutputAsync()
    {
        EntropyMixer.Reset();
        try
        {
            foreach (EntropyPreparationKind kind in Enum.GetValues<EntropyPreparationKind>())
            {
                byte[][][] originals = FillPools(extra: 1);
                ulong[] epochs = ((ulong[])typeof(EntropyMixer).GetField("DerivationCounters", BindingFlags.Static | BindingFlags.NonPublic)!.GetValue(null)!).ToArray();
                var requests = new List<int>();
                var shuffleBuffers = new System.Collections.Concurrent.ConcurrentDictionary<byte[], EntropyRandomRole>(ReferenceEqualityComparer.Instance);
                int firstShuffles = 0, secondShuffles = 0;
                EntropyMixer.RandomFillForTests = (b, role) =>
                {
                    b.AsSpan().Fill(role == EntropyRandomRole.OutputXor ? (byte)0x5A : (byte)0);
                    if (role == EntropyRandomRole.OutputXor) requests.Add(b.Length);
                    else Require(shuffleBuffers.GetOrAdd(b, role) == role, "Shuffle cache was shared between random roles.");
                    if (role == EntropyRandomRole.PoolShuffleRound1) Interlocked.Increment(ref firstShuffles);
                    if (role == EntropyRandomRole.PoolShuffleRound2) Interlocked.Increment(ref secondShuffles);
                };
                long liveStorage = SensitiveMouseRecordStore.Segment.ReservedBytes;
                Require(liveStorage > 0, "No original record storage was reserved.");
                using GeneratedArchiveEntropy result = EntropyMixer.CreateArchiveEntropy(kind);
                byte[] expected = Enumerable.Range(0, 11).SelectMany(p => ReplayOracle(originals[p], ZeroOrder(originals[p].Length, 1), p, epochs[p], false)).Select(b => (byte)(b ^ 0x5A)).ToArray();
                Require(result.FirstPassword == Convert.ToHexString(expected.AsSpan(0, 128)) && result.SecondPassword == Convert.ToHexString(expected.AsSpan(128, 128)), "Generated factors use wrong roles or XOR bytes.");
                Require(requests.SequenceEqual(kind == EntropyPreparationKind.SingleRound ? new[] { 256, 64, 64, 320 } : new[] { 256, 64, 64, 320, 64, 64, 320 }), "Output RNG groups are not separate exact-width draws.");
                Require(firstShuffles >= 11 && (kind == EntropyPreparationKind.SingleRound ? secondShuffles == 0 : secondShuffles >= 11), "Preparation plan does not enforce one/two fresh rounds.");
                Require(SensitiveMouseRecordStore.Segment.ReservedBytes == 0 && EntropyMixer.GetPoolStatus().Total == 0, "Records/indices survived successful publication.");
                Require(shuffleBuffers.Count == (kind == EntropyPreparationKind.SingleRound ? 11 : 22)
                    && shuffleBuffers.Keys.All(b => b.All(value => value == 0)), "Exclusive shuffle caches were reused or not fully cleared before publication.");
                if (kind == EntropyPreparationKind.SingleRound)
                {
                    Throws<InvalidOperationException>(() => result.ConsumeTwoRoundEncryptionParameters(EncryptionSuite.ParanoiaCascade, result.FirstPassword, result.SecondPassword));
                    var (salt, nonce) = result.ConsumeEncryptionParameters(EncryptionSuite.StandardCascade, result.FirstPassword, result.SecondPassword);
                    using (salt) using (nonce) Require(salt.Bytes.SequenceEqual(expected.AsSpan(256, 128).ToArray()) && nonce.Bytes.SequenceEqual(expected.AsSpan(384, 320).ToArray()), "Single-round salt/nonce role ordering differs.");
                }
                else
                {
                    using TwoRoundEncryptionParameters parameters = result.ConsumeTwoRoundEncryptionParameters(EncryptionSuite.ParanoiaCascade, result.FirstPassword, result.SecondPassword);
                    byte[] second = Enumerable.Range(0, 11).SelectMany(p => ReplayOracle(originals[p], ZeroOrder(originals[p].Length, 2), p, epochs[p], true)).Select(b => (byte)(b ^ 0x5A)).ToArray();
                    Require(parameters.FirstSalt.Bytes.SequenceEqual(expected.AsSpan(256, 128).ToArray()) && parameters.FirstNonce.Bytes.SequenceEqual(expected.AsSpan(384, 320).ToArray()), "First round changed in DualRound.");
                    Require(parameters.SecondSalt.Bytes.SequenceEqual(second.AsSpan(256, 128).ToArray()) && parameters.SecondNonce.Bytes.SequenceEqual(second.AsSpan(384, 320).ToArray()), "Second SHA512 replay/XOR uses wrong roles.");
                }
                Require(!result.HasPendingEncryptionParameters, "Prepared result was not consumed.");
                Throws<InvalidOperationException>(() => result.ConsumeEncryptionParameters(EncryptionSuite.StandardCascade, result.FirstPassword, result.SecondPassword));
                Throws<InvalidOperationException>(() => EntropyMixer.CreateArchiveEntropy(kind));
            }
        }
        finally { ClearSeams(); EntropyMixer.Reset(); }
        return Task.CompletedTask;
    }

    internal static Task FaultsAsync()
    {
        EntropyMixer.Reset();
        long baseline = SecureMemory.LockedAllocationsForTests;
        const BindingFlags flags = BindingFlags.NonPublic | BindingFlags.Static;
        var sequenceField = typeof(EntropyMixer).GetField("_sampleSequence", flags)!;
        var startField = typeof(EntropyMixer).GetField("_collectionStartSequence", flags)!;
        long sequence = (long)sequenceField.GetValue(null)!, start = (long)startField.GetValue(null)!;
        try
        {
            sequenceField.SetValue(null, long.MaxValue); startField.SetValue(null, long.MaxValue);
            int randomCalls = 0;
            EntropyMixer.RandomFillForTests = (b, _) => { randomCalls++; b.AsSpan().Clear(); };
            Throws<OverflowException>(() => EntropyMixer.AddCanonicalRecord(Record(0, 0)));
            Require(randomCalls == 0 && EntropyMixer.GetPoolStatus().Total == 0, "Sequence overflow reached routing or committed a record.");
        }
        finally { sequenceField.SetValue(null, sequence); startField.SetValue(null, start); ClearSeams(); EntropyMixer.Reset(); }
        long charge = SensitiveMouseRecordStore.Segment.ReservationBytes;
        Require(charge >= 256 * 88, "Protected record/index capacity is undercharged.");
        using (var exact = new SensitiveMouseRecordStore.Segment(charge))
            Throws<IOException>(() => { using var over = new SensitiveMouseRecordStore.Segment(charge); });
        using (SensitiveMouseRecordStore index = Store([Record(0, 0)]))
        {
            PropertyInfo count = typeof(SensitiveMouseRecordStore).GetProperty("Count", BindingFlags.Instance | BindingFlags.NonPublic)!;
            count.SetValue(index, (long)int.MaxValue);
            index.WriteIndex(0, int.MaxValue - 1L);
            Require(index.ReadIndex(0) == int.MaxValue - 1L, "Int32 index boundary changed.");
            count.SetValue(index, (long)int.MaxValue + 1);
            index.WriteIndex(0, int.MaxValue);
            Require(index.ReadIndex(0) == int.MaxValue, "Int64 index path truncated a logical large index.");
        }
        try
        {
            FillPools();
            ulong[] epochs = (ulong[])typeof(EntropyMixer).GetField("DerivationCounters", flags)!.GetValue(null)!;
            ulong saved = epochs[10]; long recordsBefore = EntropyMixer.SampleCount;
            epochs[10] = ulong.MaxValue;
            try { Throws<OverflowException>(() => EntropyMixer.CreateArchiveEntropy()); Require(EntropyMixer.SampleCount == recordsBefore, "Epoch overflow partially detached the record snapshot."); }
            finally { epochs[10] = saved; }
            EntropyMixer.RandomFillForTests = (b, role) => b.AsSpan().Fill(role == EntropyRandomRole.OutputXor ? (byte)0x45 : (byte)0);
            SecureMemory.SensitiveBufferBeforeUnlockForTests = () => throw new IOException("public persistent unlock failure");
            GeneratedArchiveEntropy? forbidden = null;
            ThrowsAny(() => forbidden = EntropyMixer.CreateArchiveEntropy(EntropyPreparationKind.SingleRound));
            Require(forbidden is null && !EntropyMixer.GetPoolStatus().Healthy && EntropyMixer.PendingCleanupCountForTests > 0,
                "Failed cleanup published output or lost retained resource owners.");
            SecureMemory.SensitiveBufferBeforeUnlockForTests = null;
            ClearSeams(); EntropyMixer.Reset();
            Require(EntropyMixer.PendingCleanupCountForTests == 0 && SensitiveMouseRecordStore.Segment.ReservedBytes == 0,
                "Explicit cleanup retry could not release every failed owner.");
        }
        finally { SecureMemory.SensitiveBufferBeforeUnlockForTests = null; ClearSeams(); EntropyMixer.Reset(); }
        Require(SecureMemory.LockedAllocationsForTests == baseline, "Overflow/cleanup fault paths leaked locked resources.");
        return Task.CompletedTask;
    }

    internal static async Task LifecycleAsync()
    {
        EntropyMixer.Reset();
        long baseline = SecureMemory.LockedAllocationsForTests;
        try
        {
            foreach (string stoppedPhase in new[] { "shuffle1", "sha3", "shuffle2", "sha512", "cleanup" })
            {
                FillPools(); using var stop = new CancellationTokenSource();
                EntropyMixer.RandomFillForTests = (b, _) => b.AsSpan().Clear();
                EntropyMixer.PreparationPhaseForTests = phase => { if (phase == stoppedPhase) stop.Cancel(); };
                Throws<OperationCanceledException>(() => EntropyMixer.CreateArchiveEntropy(EntropyPreparationKind.DualRound, stop.Token));
                Require(EntropyMixer.GetPoolStatus().Total == 0 && SensitiveMouseRecordStore.Segment.ReservedBytes == 0, "Cancelled snapshot survived or was restored.");
                ClearSeams(); EntropyMixer.Reset();
            }
            FillPools(); using var entered = new ManualResetEventSlim(); using var release = new ManualResetEventSlim(); int once = 0;
            EntropyMixer.RandomFillForTests = (b, role) => { b.AsSpan().Fill(role == EntropyRandomRole.OutputXor ? (byte)0x23 : (byte)0); };
            EntropyMixer.PreparationPhaseForTests = phase => { if (phase == "sha3" && Interlocked.CompareExchange(ref once, 1, 0) == 0) { entered.Set(); Require(release.Wait(TimeSpan.FromSeconds(20)), "Lifecycle barrier timed out."); } };
            Task<GeneratedArchiveEntropy> pending = Task.Run(() => EntropyMixer.CreateArchiveEntropy(EntropyPreparationKind.DualRound));
            Require(entered.Wait(TimeSpan.FromSeconds(20)), "Detached snapshot did not reach replay.");
            Throws<InvalidOperationException>(() => EntropyMixer.CreateArchiveEntropy());
            EntropyMixer.RandomFillForTests = (b, role) => { b.AsSpan().Clear(); if (role == EntropyRandomRole.OutputXor) b.AsSpan().Fill(0x23); };
            for (int i = 0; i < 37; ++i) EntropyMixer.AddCanonicalRecord(Record(0, i));
            Require(EntropyMixer.GetPoolStatus().Total == 37, "New live epoch is unavailable during replay.");
            release.Set(); using (GeneratedArchiveEntropy result = await pending) Require(result.HasPendingEncryptionParameters, "Completed result is missing.");
            Require(EntropyMixer.GetPoolStatus().Total == 37, "Old cleanup deleted new live records.");
            ClearSeams(); EntropyMixer.Reset();
            foreach (EntropyRandomRole failedRole in new[] { EntropyRandomRole.PoolShuffleRound1, EntropyRandomRole.PoolShuffleRound2, EntropyRandomRole.OutputXor })
            {
                FillPools();
                EntropyMixer.RandomFillForTests = (b, role) => { if (role == failedRole) throw new CryptographicException("public injected RNG failure"); b.AsSpan().Clear(); };
                ThrowsAny(() => EntropyMixer.CreateArchiveEntropy(EntropyPreparationKind.DualRound));
                Require(EntropyMixer.GetPoolStatus().Total == 0 && SensitiveMouseRecordStore.Segment.ReservedBytes == 0, "Failed preparation retained consumed storage.");
                ClearSeams(); EntropyMixer.Reset();
            }
            FillPools();
            using var beforePublish = new ManualResetEventSlim();
            using var allowPublish = new ManualResetEventSlim();
            EntropyMixer.RandomFillForTests = (b, role) => b.AsSpan().Fill(role == EntropyRandomRole.OutputXor ? (byte)0x31 : (byte)0);
            EntropyMixer.PreparationPhaseForTests = phase =>
            {
                if (phase == "before-publication")
                {
                    beforePublish.Set();
                    Require(allowPublish.Wait(TimeSpan.FromSeconds(20)), "Publication barrier timed out.");
                }
            };
            Task<GeneratedArchiveEntropy> publication = Task.Run(() => EntropyMixer.CreateArchiveEntropy(EntropyPreparationKind.SingleRound));
            Require(beforePublish.Wait(TimeSpan.FromSeconds(20)), "Preparation did not reach the post-cleanup publication gate.");
            Task reset = Task.Run(EntropyMixer.Reset);
            Require(SpinWait.SpinUntil(() => !EntropyMixer.GetPoolStatus().Healthy, TimeSpan.FromSeconds(10)), "Reset did not invalidate publication.");
            Require(!reset.IsCompleted, "Reset did not join the unfinished complete preparation.");
            allowPublish.Set();
            try { using var stale = await publication; throw new InvalidOperationException("A reset preparation published stale factors."); }
            catch (OperationCanceledException) { }
            await reset;
            ClearSeams();
            Require(SensitiveMouseRecordStore.Segment.ReservedBytes == 0 && EntropyMixer.GetPoolStatus().Total == 0, "Reset retained owned pool storage.");
            // Inspect owned full capacities before unlock, never freed memory.
            var segment = new SensitiveMouseRecordStore.Segment(1 << 20);
            byte[] records = segment.Records, indices = segment.Indices;
            records.AsSpan().Fill(0xA6); indices.AsSpan().Fill(0xD7); int wipes = 0;
            SecureMemory.SensitiveBufferBeforeUnlockForTests = () =>
            {
                if (Interlocked.Increment(ref wipes) == 1) Require(records.All(b => b == 0), "Record capacity tail was not wiped before unlock.");
                else Require(indices.All(b => b == 0), "Index capacity tail was not wiped before unlock.");
            };
            try { segment.Dispose(); } finally { SecureMemory.SensitiveBufferBeforeUnlockForTests = null; segment.Dispose(); }
            Require(wipes == 2, "Both owned capacities were not cleared.");
        }
        finally { ClearSeams(); SecureMemory.SensitiveBufferBeforeUnlockForTests = null; EntropyMixer.Reset(); }
        Require(SecureMemory.LockedAllocationsForTests == baseline, "Lifecycle tests leaked locked allocations.");
    }

    private static byte[][][] FillPools(int extra = 0)
    {
        Require(EntropyMixer.GetPoolStatus().Total == 0, "Fixture requires an empty live epoch.");
        long sequence = (long)typeof(EntropyMixer).GetField("_sampleSequence", BindingFlags.Static | BindingFlags.NonPublic)!.GetValue(null)!;
        byte[][][] records = new byte[11][][];
        for (int purpose = 0; purpose < 11; ++purpose)
        {
            int current = purpose;
            EntropyMixer.RandomFillForTests = (b, role) => { Require(role == EntropyRandomRole.PoolRouting, "Unexpected RNG role during capture."); BinaryPrimitives.WriteUInt32LittleEndian(b, (uint)current); };
            records[purpose] = new byte[1024 + extra + purpose][];
            for (int i = 0; i < records[purpose].Length; ++i)
            {
                byte[] record = Record(purpose, i); BinaryPrimitives.WriteInt64LittleEndian(record.AsSpan(72), sequence++);
                records[purpose][i] = record;
                EntropyMixer.AddCanonicalRecord(record);
            }
        }
        Require(EntropyMixer.GetPoolStatus().IsReady, "All eleven real record pools are not ready.");
        return records;
    }

    private static SensitiveMouseRecordStore Store(byte[][] records)
    {
        var store = new SensitiveMouseRecordStore();
        try
        {
            foreach (byte[] record in records)
            {
                SensitiveMouseRecordStore.Segment? spare = null;
                try { if (store.NeedsSegment) { store.ReserveSegmentMetadata(); spare = new SensitiveMouseRecordStore.Segment(128L << 20); } store.Append(record, ref spare); }
                finally { spare?.Dispose(); }
            }
            store.Seal(); return store;
        }
        catch { store.Dispose(); throw; }
    }

    private static byte[] Record(int purpose, int index)
    {
        byte[] r = Enumerable.Range(0, 80).Select(i => unchecked((byte)(purpose * 19 + index * 7 + i * 13))).ToArray();
        BinaryPrimitives.WriteInt64LittleEndian(r.AsSpan(72), checked((long)index * 7919 + purpose)); return r;
    }
    private static int[] ZeroOrder(int count, int rounds) => count == 0 ? [] : Enumerable.Range(0, count).Select(i => (i + rounds) % count).ToArray();
    private static byte[] ReplayOracle(byte[][] records, int[] order, int purpose, ulong epoch, bool sha512)
    {
        byte[] state = new byte[64];
        foreach (int position in order)
        {
            using var bytes = new MemoryStream(); using var writer = new BinaryWriter(bytes);
            writer.Write(state); writer.Write(records[position]); writer.Write(records[position], 72, 8); writer.Write(purpose);
            state = Hash(bytes.ToArray(), sha512);
        }
        using var final = new MemoryStream(); using var finalWriter = new BinaryWriter(final);
        finalWriter.Write(state); finalWriter.Write(epoch); finalWriter.Write(0); finalWriter.Write(purpose);
        return Hash(final.ToArray(), sha512);
    }
    private static byte[] Hash(byte[] message, bool sha512) { IDigest digest = sha512 ? new Sha512Digest() : new Sha3Digest(512); digest.BlockUpdate(message, 0, message.Length); byte[] answer = new byte[64]; digest.DoFinal(answer, 0); return answer; }
    private static int Factorial(int n) => n < 2 ? 1 : n * Factorial(n - 1);
    private static void ClearSeams() { EntropyMixer.RandomFillForTests = null; EntropyMixer.PreparationPhaseForTests = null; }
    private static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private static void Throws<T>(Action action) where T : Exception { try { action(); } catch (T) { return; } catch (AggregateException error) when (error.Flatten().InnerExceptions.All(e => e is T)) { return; } throw new InvalidOperationException("Expected " + typeof(T).Name); }
    private static void ThrowsAny(Action action) { try { action(); } catch (Exception) { return; } throw new InvalidOperationException("Expected injected failure."); }
}
