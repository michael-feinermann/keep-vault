using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using KalynaArchiver.Services;

// All bytes are synthetic and public. Expected values were independently
// encoded and hashed by CPython hashlib, never exported by the product.
internal static class EntropyRev9GoldenTests
{
    internal static Task RunAsync()
    {
        string path = Path.Combine(AppContext.BaseDirectory, "Fixtures", "V13Reference", "pool_shuffle_rev9_public_vectors.json");
        byte[] frozen = File.ReadAllBytes(path);
        Require(Convert.ToHexString(SHA256.HashData(frozen)) == "531B54B99AC4E569583E96201FF47ABF301A84DC34E2C6D8A5597D033C5CE863", "Frozen public fixture changed without an explicitly reviewed reference update.");
        using JsonDocument fixture = JsonDocument.Parse(frozen);
        Require(fixture.RootElement.GetProperty("schema").GetString() == "KeepVault.PublicShuffleFixture.v1", "Unknown public fixture schema.");
        long baseline = SecureMemory.LockedAllocationsForTests;
        JsonElement[] pools = fixture.RootElement.GetProperty("pools").EnumerateArray().ToArray();
        Require(pools.Length == 11 && fixture.RootElement.GetProperty("records").GetInt64() == 13299, "Incomplete fixture inventory.");
        void VerifyPool(int purpose)
        {
            JsonElement vector = pools[purpose];
            long sequence = checked(purpose * 1024L + 37L * purpose * (purpose - 1) / 2);
            Require(vector.GetProperty("purpose").GetInt32() == purpose, "Fixture purpose order.");
            int count = checked(1024 + 37 * purpose);
            Require(vector.GetProperty("count").GetInt32() == count, "Fixture record count.");
            ulong epoch = 0x0102030405060700UL + (uint)purpose;
            Require(vector.GetProperty("epoch").GetString() == epoch.ToString(System.Globalization.CultureInfo.InvariantCulture), "Fixture epoch.");
            using var store = new SensitiveMouseRecordStore();
            using var recordHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            for (int i = 0; i < count; i++)
            {
                byte[] record = new byte[80];
                for (int j = 0; j < 72; j++) record[j] = unchecked((byte)(purpose * 19 + i * 7 + j * 13));
                BinaryPrimitives.WriteInt64LittleEndian(record.AsSpan(72), sequence++);
                recordHash.AppendData(record);
                SensitiveMouseRecordStore.Segment? spare = null;
                try
                {
                    if (store.NeedsSegment) { store.ReserveSegmentMetadata(); spare = new SensitiveMouseRecordStore.Segment(128L << 20); }
                    store.Append(record, ref spare);
                }
                finally { spare?.Dispose(); }
            }
            Check(vector, "recordSha256", recordHash.GetHashAndReset());
            store.Seal(); store.InitializeIndices(default);
            for (int round = 1; round <= 2; round++)
            {
                var stream = new PublicStream("shuffle", purpose, round);
                EntropyRandomRole role = round == 1 ? EntropyRandomRole.PoolShuffleRound1 : EntropyRandomRole.PoolShuffleRound2;
                using (var rng = new PoolShuffleRandomSource(role, (bytes, actualRole) => { Require(actualRole == role, "Cross-round source reuse."); stream.Fill(bytes); }))
                    rng.Shuffle(store, default);
                using var orderHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                byte[] index = new byte[8];
                for (int i = 0; i < count; i++) { BinaryPrimitives.WriteUInt64LittleEndian(index, checked((ulong)store.ReadIndex(i))); orderHash.AppendData(index); }
                Check(vector, round == 1 ? "firstOrderSha256" : "secondOrderSha256", orderHash.GetHashAndReset());
                byte[] q = new byte[64];
                ConsumedEntropySnapshot.Replay(store, purpose, epoch, round == 2, q, default);
                Check(vector, "q" + round, q);
                byte[] publicXor = new byte[64]; new PublicStream("xor", purpose, round).Fill(publicXor);
                for (int i = 0; i < q.Length; i++) q[i] ^= publicXor[i];
                Check(vector, "publicXor" + round, q);
            }
            // Immutable original records remain intact after both index shuffles.
            using var after = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            byte[] copy = new byte[80];
            for (int i = 0; i < count; i++) { store.CopyRecord(i, copy); after.AppendData(copy); }
            Check(vector, "recordSha256", after.GetHashAndReset());
        }
        for (int p = 0; p < 11; p++) VerifyPool(p);
        for (int p = 10; p >= 0; p--) VerifyPool(p);
        Parallel.For(0, 11, new ParallelOptions { MaxDegreeOfParallelism = Math.Min(11, ArchiveOperationPolicy.Current.MaxCpuWorkers) }, VerifyPool);
        Require(SecureMemory.LockedAllocationsForTests == baseline, "Public fixture left locked storage.");
        Require(File.ReadAllBytes(path).AsSpan().SequenceEqual(frozen), "Product test modified its reference.");
        return Task.CompletedTask;
    }

    private sealed class PublicStream(string label, int purpose, int round)
    {
        private readonly byte[] _prefix = Encoding.ASCII.GetBytes("KeepVault REV9 public fixture v1/" + label);
        private ulong _counter;
        private byte[] _block = [];
        private int _cursor;
        internal void Fill(byte[] output)
        {
            for (int i = 0; i < output.Length; i++)
            {
                if (_cursor == _block.Length)
                {
                    byte[] input = new byte[_prefix.Length + 16]; _prefix.CopyTo(input, 0);
                    BinaryPrimitives.WriteInt32LittleEndian(input.AsSpan(_prefix.Length), purpose);
                    BinaryPrimitives.WriteInt32LittleEndian(input.AsSpan(_prefix.Length + 4), round);
                    BinaryPrimitives.WriteUInt64LittleEndian(input.AsSpan(_prefix.Length + 8), _counter++);
                    _block = SHA512.HashData(input); _cursor = 0;
                }
                output[i] = _block[_cursor++];
            }
        }
    }
    private static void Check(JsonElement row, string field, byte[] actual) => Require(Convert.ToHexString(actual) == row.GetProperty(field).GetString(), "Independent frozen reference mismatch: " + field);
    private static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
}
