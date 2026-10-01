using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using KalynaArchiver.Services;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

internal static class RecoveryRecordTableTests
{
    internal static IReadOnlyList<TestCase> Tests =>
    [
        new("recovery.record-table-layout", "bounded record codecs and independent HMAC/Skein authentication", LayoutAsync, TestResource.Light, "Security"),
        new("recovery.record-table-tamper", "dual tags, payload, replay, position, lengths and terminal failure", TamperAsync, TestResource.Light, "Security"),
        new("recovery.record-table-cleanup", "retryable all-member zeroing and cleanup after unlock failure", CleanupAsync, TestResource.ProcessGlobal, "Security"),
        new("recovery.record-table-budget", "shared metadata budget, nested scopes and release after disposal", BudgetAsync, TestResource.Light, "Security"),
    ];

    private static Task LayoutAsync()
    {
        using var disk = new DiskScope();
        using var table = new RecoveryRecordTable<string>();
        string digest = Convert.ToBase64String(Enumerable.Range(0, 64).Select(i => (byte)i).ToArray()) + ":" + Convert.ToBase64String(Enumerable.Range(64, 128).Select(i => (byte)i).ToArray());
        table.Add(digest); table.Add(digest);
        Require(table.Count == 2 && table.StorageBytes == 864 && table[1] == digest, "Digest codec framing differs.");
        byte[] record = ReadStorage(table, 432, 0);
        Require(BinaryPrimitives.ReadInt64BigEndian(record.AsSpan(32)) == 0
            && BinaryPrimitives.ReadInt32BigEndian(record.AsSpan(40)) == 1
            && BinaryPrimitives.ReadInt32BigEndian(record.AsSpan(44)) == 192, "Recovery table framing differs.");
        byte[] domain = Encoding.UTF8.GetBytes("Kalyna-ZPAQ/v13/RecoveryRecordTable/HMAC-SHA3-512");
        byte[] prefix = new byte[4]; BinaryPrimitives.WriteInt32LittleEndian(prefix, domain.Length);
        var hmac = new HMac(new Sha3Digest(512));
        hmac.Init(new KeyParameter(Secret(table, "_hmacKey")));
        hmac.BlockUpdate(prefix); hmac.BlockUpdate(domain); hmac.BlockUpdate(record, 0, 240);
        byte[] hmacResult = new byte[64]; hmac.DoFinal(hmacResult);
        var skein = new SkeinMac(SkeinEngine.SKEIN_1024, 1024);
        skein.Init(new SkeinParameters.Builder().SetKey(Secret(table, "_skeinKey"))
            .SetPersonalisation(Encoding.UTF8.GetBytes("Kalyna-ZPAQ/v13/RecoveryRecordTable/Skein-MAC-1024-1024")).Build());
        skein.BlockUpdate(record, 0, 240); byte[] skeinResult = new byte[128]; skein.DoFinal(skeinResult);
        Require(record.AsSpan(240, 64).SequenceEqual(hmacResult) && record.AsSpan(304).SequenceEqual(skeinResult),
            "Recovery record tags disagree with independent BC implementations.");
        using var parity = new RecoveryRecordTable<RecoveryParityShard>();
        var item = new RecoveryParityShard(7, 3, (1L << 40) + 1, 65536, digest);
        parity.Add(item); Require(parity[0] == item && parity.StorageBytes == 452, "64-bit parity codec differs.");
        using var bytes = new RecoveryRecordTable<byte[]>();
        foreach (int length in new[] { 0, 1, 65535, 65536 })
        {
            byte[] value = Enumerable.Range(0, length).Select(i => (byte)(i * 13)).ToArray();
            bytes.Add(value); Require(bytes[bytes.Count - 1].SequenceEqual(value), "Bounded byte record differs.");
        }
        Require(bytes.StorageBytes == 4L * (48 + 4 + 65536 + 192), "Byte table did not use fixed framing.");
        Expect<InvalidDataException>(() => bytes.Add(new byte[65537]));
        Expect<InvalidOperationException>(() => _ = bytes[0]);
        return Task.CompletedTask;
    }

    private static Task TamperAsync()
    {
        using var disk = new DiskScope();
        string digest = Convert.ToBase64String(new byte[64]) + ":" + Convert.ToBase64String(new byte[128]);
        foreach (string kind in new[] { "payload", "hmac", "skein", "identity", "position", "kind", "length", "truncate", "extend", "replay", "swap" })
        {
            using var table = new RecoveryRecordTable<string>(); table.Add(digest); table.Add(digest);
            FileStream stream = Storage(table);
            if (kind is "truncate" or "extend") stream.SetLength(stream.Length + (kind == "truncate" ? -1 : 1));
            else if (kind == "replay")
            {
                using var other = new RecoveryRecordTable<string>(); other.Add(digest);
                RandomAccess.Write(stream.SafeFileHandle, ReadStorage(other, 432, 0), 0);
            }
            else if (kind == "swap") RandomAccess.Write(stream.SafeFileHandle, ReadStorage(table, 432, 432), 0);
            else
            {
                int offset = kind switch { "payload" => 48, "hmac" => 240, "skein" => 304, "identity" => 0, "position" => 39, "kind" => 43, _ => 47 };
                byte[] value = ReadStorage(table, 1, offset); value[0] ^= 1; RandomAccess.Write(stream.SafeFileHandle, value, offset);
            }
            ExpectAny(() => _ = table[0]);
            Expect<InvalidOperationException>(() => table.Add(digest));
        }
        var disposed = new RecoveryRecordTable<string>(); disposed.Dispose();
        Expect<ObjectDisposedException>(() => _ = disposed.Count);
        return Task.CompletedTask;
    }

    private static Task BudgetAsync()
    {
        string digest = Convert.ToBase64String(new byte[64]) + ":" + Convert.ToBase64String(new byte[128]);
        using (RecoveryMetadataBudget.Begin(864))
        {
            var first = new RecoveryRecordTable<string>(); first.Add(digest);
            using (RecoveryMetadataBudget.Begin(10_000_000))
            using (var second = new RecoveryRecordTable<string>())
            {
                second.Add(digest);
                Expect<IOException>(() => second.Add(digest));
            }
            first.Dispose();
            using var replacement = new RecoveryRecordTable<string>(); replacement.Add(digest); replacement.Add(digest);
            Require(replacement.Count == 2, "Disposal did not release the shared disk reservation.");
        }
        return Task.CompletedTask;
    }

    private static Task CleanupAsync()
    {
        var table = new RecoveryRecordTable<string>();
        table.Add(Convert.ToBase64String(new byte[64]) + ":" + Convert.ToBase64String(new byte[128]));
        byte[][] secrets = [Secret(table, "_hmacKey"), Secret(table, "_skeinKey"), Secret(table, "_operationId"), Secret(table, "_record")];
        int attempts = 0;
        try
        {
            SecureMemory.SensitiveBufferBeforeUnlockForTests = () => { attempts++; throw new IOException("injected pre-unlock failure"); };
            Expect<AggregateException>(table.Dispose);
            Require(attempts == 4 && secrets.All(bytes => bytes.All(value => value == 0)),
                "Cleanup stopped before wiping and trying every sensitive member.");
            Expect<InvalidOperationException>(() => _ = table.Count);
        }
        finally
        {
            SecureMemory.SensitiveBufferBeforeUnlockForTests = null;
            table.Dispose();
        }
        Expect<ObjectDisposedException>(() => _ = table.Count);

        var stream = new RecoveryMetadataStream();
        stream.Write(new byte[65537]); stream.Seal();
        Require(stream.ReadByte() == 0, "Metadata cleanup fixture did not establish a read cache.");
        try
        {
            SecureMemory.SensitiveBufferBeforeUnlockForTests = () => throw new IOException("injected stream table unlock failure");
            Expect<AggregateException>(stream.Dispose);
            foreach (string field in new[] { "_pendingMemory", "_cacheMemory" })
                Require(typeof(RecoveryMetadataStream).GetField(field, BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(stream) is null,
                    "A failed child unlock retained a wiped public metadata buffer's RAM lease.");
            Expect<InvalidOperationException>(() => stream.ReadByte());
        }
        finally
        {
            SecureMemory.SensitiveBufferBeforeUnlockForTests = null;
            stream.Dispose();
        }
        using (RecoveryMetadataBudget.Begin(1))
        using (var failed = new RecoveryMetadataStream())
        {
            Expect<IOException>(() => failed.Write(new byte[65536]));
            Expect<InvalidOperationException>(failed.Seal);
            Expect<InvalidOperationException>(() => failed.WriteByte(1));
        }
        return Task.CompletedTask;
    }

    private sealed class DiskScope : IDisposable
    {
        private readonly bool _previous = AuthenticatedRangeIndex.ForceDiskForTests.Value;
        internal DiskScope() => AuthenticatedRangeIndex.ForceDiskForTests.Value = true;
        public void Dispose() => AuthenticatedRangeIndex.ForceDiskForTests.Value = _previous;
    }

    private static FileStream Storage<T>(RecoveryRecordTable<T> table)
    {
        FieldInfo field = typeof(RecoveryRecordTable<T>).GetField("_file", BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("Recovery table storage fixture no longer matches the production field.");
        AuthenticatedRangeIndex store = field.GetValue(table) as AuthenticatedRangeIndex
            ?? throw new InvalidOperationException("Recovery table has no record store.");
        return store.FileForTests?.Stream ?? throw new InvalidOperationException("This attack requires an explicitly spilled index.");
    }
    private static byte[] Secret<T>(RecoveryRecordTable<T> table, string name) =>
        ((LockedSensitiveBuffer)typeof(RecoveryRecordTable<T>).GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(table)!).Bytes;
    private static byte[] ReadStorage<T>(RecoveryRecordTable<T> table, int count, long offset)
    {
        byte[] bytes = new byte[count];
        Require(RandomAccess.Read(Storage(table).SafeFileHandle, bytes, offset) == count, "Incomplete record read.");
        return bytes;
    }
    private static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private static void Expect<T>(Action action) where T : Exception
    { try { action(); } catch (T) { return; } throw new InvalidOperationException($"Expected {typeof(T).Name}."); }
    private static void ExpectAny(Action action)
    { try { action(); } catch (Exception error) when (error is CryptographicException or IOException) { return; } throw new InvalidOperationException("Tampered metadata was released."); }
}
