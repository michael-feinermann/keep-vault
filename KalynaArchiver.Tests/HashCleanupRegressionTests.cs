using System.Reflection;
using System.Security.Cryptography;
using KalynaArchiver.Signing;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

internal static class HashCleanupRegressionTests
{
    internal static IReadOnlyList<TestCase> Tests =>
    [new("crypto.hash-cleanup-regression", "SHA3/SHA512 reset, HMAC BC equivalence and owned-pad disposal", RunAsync, TestResource.Light, "Crypto")];

    private static Task RunAsync()
    {
        const BindingFlags fields = BindingFlags.Instance | BindingFlags.NonPublic;
        foreach (int keyBytes in new[] { 0, 1, 64, 71, 72, 73, 128, 257 })
        foreach (int messageBytes in new[] { 0, 1, 63, 64, 71, 72, 73, 127, 128, 135, 136, 137, 1024, 1048577 })
        {
            byte[] key = Enumerable.Range(0, keyBytes).Select(i => (byte)(i * 19 + 3)).ToArray();
            byte[] message = Enumerable.Range(0, messageBytes).Select(i => (byte)(i * 7 + 11)).ToArray();
            var reference = new HMac(new Sha3Digest(512)); reference.Init(new KeyParameter(key));
            reference.BlockUpdate(message); byte[] expected = new byte[64]; reference.DoFinal(expected);
            using var actual = new HmacSha3_512(key);
            object digest = typeof(HmacSha3_512).GetField("_digest", fields)!.GetValue(actual)!;
            byte[] inner = (byte[])typeof(HmacSha3_512).GetField("_innerPad", fields)!.GetValue(actual)!;
            byte[] outer = (byte[])typeof(HmacSha3_512).GetField("_outerPad", fields)!.GetValue(actual)!;
            for (int repetition = 0; repetition < 3; ++repetition)
            {
                int split = repetition == 0 ? 0 : repetition == 1 ? message.Length / 2 : message.Length;
                actual.AppendData(message.AsSpan(0, split)); actual.AppendData(message.AsSpan(split));
                byte[] guarded = Enumerable.Repeat((byte)0xA7, 66).ToArray();
                Require(actual.GetHashAndReset(guarded.AsSpan(1, 64)) == 64
                    && guarded[0] == 0xA7 && guarded[^1] == 0xA7
                    && guarded.AsSpan(1, 64).SequenceEqual(expected), "HMAC differs from BC or changed adjacent bytes.");
            }
            actual.AppendData(message);
            actual.Dispose(); actual.Dispose();
            Require(inner.All(b => b == 0) && outer.All(b => b == 0), "Disposed HMAC retained an owned key pad.");
            CheckZeroArrays(digest);
            Throws<ObjectDisposedException>(() => actual.AppendData(message));
            Throws<ObjectDisposedException>(() => actual.GetHashAndReset());
        }
        foreach (int bytes in new[] { 0, 1, 63, 64, 71, 72, 73, 111, 112, 127, 128, 135, 136, 156, 1024 })
        {
            byte[] message = Enumerable.Range(0, bytes).Select(i => (byte)(i * 13 + 17)).ToArray();
            using var hash = new Sha3_512Incremental();
            object digest = typeof(Sha3_512Incremental).GetField("_digest", fields)!.GetValue(hash)!;
            hash.AppendData(message); Require(hash.GetHashAndReset().SequenceEqual(Sha3_512Compat.HashData(message)), "Incremental SHA3 changed bytes.");
            CheckZeroArrays(digest);
            hash.AppendData(message); hash.Dispose(); CheckZeroArrays(digest);
            Require(Sha512Compat.HashData(message).SequenceEqual(SHA512.HashData(message)), "SHA512 wrapper changed bytes.");
            // Pin the actual BC 2.6.2 provider's documented Reset assumption.
            var sha512 = new Sha512Digest(); sha512.BlockUpdate(message); sha512.Reset(); CheckZeroArrays(sha512);
        }
        return Task.CompletedTask;
    }
    private static void CheckZeroArrays(object owner)
    {
        int inspected = 0;
        for (Type? type = owner.GetType(); type is not null; type = type.BaseType)
            foreach (FieldInfo field in type.GetFields(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.DeclaredOnly))
            {
                if (field.GetValue(owner) is byte[] bytes) { Require(bytes.All(b => b == 0), "Provider byte workspace retained state after reset."); inspected++; }
                if (field.GetValue(owner) is ulong[] words) { Require(words.All(b => b == 0), "Provider word workspace retained state after reset."); inspected++; }
            }
        Require(inspected >= 2, "Provider workspace inventory drifted; review the cleanup assertion.");
    }
    private static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private static void Throws<T>(Action action) where T : Exception { try { action(); } catch (T) { return; } throw new InvalidOperationException($"Expected {typeof(T).Name}."); }
}
