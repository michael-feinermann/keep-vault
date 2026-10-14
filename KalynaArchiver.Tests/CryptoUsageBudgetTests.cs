using System.IO;
using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using KalynaArchiver.Services;

internal static class CryptoUsageBudgetTests
{
    internal static IReadOnlyList<TestCase> Tests =>
    [
        new("v13-usage-boundaries", "per-key payload/chunk/MAC limits independent of resource policy", BoundariesAsync, TestResource.Light, "V13"),
        new("v13-usage-writer-guard", "oversize public stream API fails before native loading, reads or output creation", WriterGuardAsync, TestResource.Light, "V13"),
        new("v13-usage-reader-guard", "oversize canonical-header API fails before native loading or ciphertext reads", ReaderGuardAsync, TestResource.Light, "V13"),
        new("v13-usage-model", "exact integer collision, interval and primitive budget arithmetic", ModelAsync, TestResource.Light, "V13"),
    ];
    private static Task BoundariesAsync()
    {
        Require(CryptoUsageBudget.MaximumPayloadBytes == 70368744177664L && CryptoUsageBudget.MaximumChunks == 4194304,
            "The approved usage profile drifted.");
        foreach (EncryptionSuite suite in EncryptionSuiteCatalog.DisplayOrder)
        {
            EncryptionSuiteParameters p = EncryptionSuiteCatalog.Get(suite);
            int tag = p.Cascade is { OutermostIsAead: true } ? 16 : 0;
            foreach (long bytes in new long[] { 1, 16*1024*1024-1, 16*1024*1024, 16*1024*1024+1,
                256L<<30, 500L<<30, 512L<<30, 1_000_000_000_000, 1L<<40, 2L<<40, 4L<<40, 8L<<40,
                CryptoUsageBudget.MaximumPayloadBytes - 1, CryptoUsageBudget.MaximumPayloadBytes })
            {
                CryptoUsageBudget.ValidatePayloadLength(bytes);
                long chunks = 1 + (bytes - 1) / CryptoUsageBudget.ChunkBytes;
                Require(CryptoUsageBudget.ValidateCiphertextLength(p, checked(bytes + chunks * tag)) == bytes,
                    "Framing accounting changed a payload size.");
            }
            long maximumCiphertext = CryptoUsageBudget.MaximumPayloadBytes + CryptoUsageBudget.MaximumChunks * tag;
            Throws<CryptographicException>(() => CryptoUsageBudget.ValidateCiphertextLength(p, maximumCiphertext + 1 + tag));
            Throws<CryptographicException>(() => CryptoUsageBudget.ValidateCiphertextLength(p, long.MaxValue));
            Throws<InvalidDataException>(() => CryptoUsageBudget.ValidateCiphertextLength(p, 0));
            if (tag != 0) Throws<InvalidDataException>(() => CryptoUsageBudget.ValidateCiphertextLength(p, tag));
        }
        CryptoUsageBudget.ValidateChunk(CryptoUsageBudget.MaximumChunks-1, CryptoUsageBudget.ChunkBytes);
        CryptoUsageBudget.ValidateChunk(CryptoUsageBudget.MaximumChunks-1, 1);
        Throws<CryptographicException>(() => CryptoUsageBudget.ValidateChunk(CryptoUsageBudget.MaximumChunks, 1));
        Throws<CryptographicException>(() => CryptoUsageBudget.ValidateChunk(long.MaxValue, 1));
        Throws<ArgumentOutOfRangeException>(() => CryptoUsageBudget.ValidateChunk(-1, 1));
        Throws<ArgumentOutOfRangeException>(() => CryptoUsageBudget.ValidateChunk(0, CryptoUsageBudget.ChunkBytes+1));
        Throws<ArgumentOutOfRangeException>(() => CryptoUsageBudget.ValidatePayloadLength(-1));
        Throws<CryptographicException>(() => CryptoUsageBudget.ValidatePayloadLength(CryptoUsageBudget.MaximumPayloadBytes+1));
        CryptoUsageBudget.ValidateAuthenticationLength(CryptoUsageBudget.MaximumAuthenticatedBytes);
        Throws<CryptographicException>(() => CryptoUsageBudget.ValidateAuthenticationLength(CryptoUsageBudget.MaximumAuthenticatedBytes+1));
        Require(CryptoUsageBudget.MaximumMacLeaves == 67108929L, "MAC leaf budget omitted framing overhead.");
        return Task.CompletedTask;
    }
    private static async Task WriterGuardAsync()
    {
        string output = Path.Combine(Path.GetTempPath(), $"keepvault-usage-guard-{Guid.NewGuid():N}.kzpaq");
        using var source = new LengthOnlyInput();
        try
        {
            await new KalynaContainerService().EncryptZpaqStreamAsync(source, output,
                "", "", "", "", null, null, default);
            throw new InvalidOperationException("Oversize API input reached the archive writer.");
        }
        catch (CryptographicException error)
        {
            Require(error.Message.Contains("cryptographic per-key usage budget", StringComparison.Ordinal),
                "Oversize API failed for an unrelated reason.");
        }
        Require(!File.Exists(output) && source.ReadCalls == 0, "Oversize API read input or created output.");
    }

    private sealed class LengthOnlyInput : Stream
    {
        internal int ReadCalls;
        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => CryptoUsageBudget.MaximumPayloadBytes + 1;
        public override long Position { get; set; }
        public override int Read(byte[] buffer, int offset, int count) { ReadCalls++; throw new InvalidOperationException("Length gate was bypassed."); }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private static async Task ReaderGuardAsync()
    {
        byte[] header = File.ReadAllBytes(Path.Combine(RepositoryLayout.FindRepositoryRoot(), "KeepVaultMac.Tests", "Fixtures", "V13Reference", "standard-header-rev9.json"));
        byte[] prefix = new byte[11 + header.Length + 192];
        "KZPAQ2\0"u8.CopyTo(prefix);
        BinaryPrimitives.WriteInt32LittleEndian(prefix.AsSpan(7), header.Length);
        header.CopyTo(prefix, 11);
        using var source = new PrefixAndLengthInput(prefix,
            checked(prefix.Length + CryptoUsageBudget.MaximumPayloadBytes + CryptoUsageBudget.MaximumChunks * 16 + 17));
        try
        {
            await new KalynaContainerService().VerifyAuthenticationAsync(source, "", "", "", "", default);
            throw new InvalidOperationException("Oversize authentication API passed the framing budget gate.");
        }
        catch (CryptographicException error)
        {
            Require(error.Message.Contains("cryptographic per-key chunk budget", StringComparison.Ordinal),
                "Oversize reader failed for an unrelated reason.");
        }
        Require(source.Position == prefix.Length, "Oversize reader consumed ciphertext before the budget check.");
    }

    private sealed class PrefixAndLengthInput(byte[] prefix, long length) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => length;
        public override long Position { get; set; }
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (Position >= prefix.Length) throw new InvalidOperationException("Reader tried to consume out-of-budget ciphertext.");
            int take = Math.Min(count, prefix.Length - checked((int)Position));
            prefix.AsSpan((int)Position, take).CopyTo(buffer.AsSpan(offset)); Position += take; return take;
        }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private static Task ModelAsync()
    {
        BigInteger q = CryptoUsageBudget.MaximumChunks;
        BigInteger blockQueries = (BigInteger)CryptoUsageBudget.MaximumPayloadBytes / 16;
        BigInteger denominator = BigInteger.One << 129;
        Require(q * (q-1) * (BigInteger.One << 85) < denominator, "128-bit start equality exceeds 2^-85.");
        Require(q * (q-1) * ((1<<21)-1) * (BigInteger.One << 64) < denominator, "CTR interval bound exceeds 2^-64.");
        Require(blockQueries * (blockQueries-1) * (BigInteger.One << 45) < denominator, "128-bit switching term exceeds 2^-45.");
        Require(4 * blockQueries * (blockQueries-1) * (BigInteger.One << 43) < denominator, "Four-stage switching union exceeds 2^-43.");
        Require(q * (q-1) * (BigInteger.One << 149) < (BigInteger.One << 193), "XChaCha nonce term exceeds 2^-149.");
        // L counts AAD+payload blocks. The bound L+1 includes the final
        // 16-byte LE64(AAD length)||LE64(ciphertext length) block exactly once.
        BigInteger l = (1<<20) + 3;
        BigInteger attempts = BigInteger.One << 32;
        Require(attempts * (l+1) * (BigInteger.One << 50) < (BigInteger.One << 103), "Modeled Poly1305 term exceeds 2^-50.");
        return Task.CompletedTask;
    }
    private static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private static void Throws<T>(Action action) where T:Exception { try { action(); } catch(T) { return; } throw new InvalidOperationException($"Expected {typeof(T).Name}."); }
}
