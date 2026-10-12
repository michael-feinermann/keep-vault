using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using KalynaArchiver.Services;
using KalynaArchiver.Signing;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

// Public synthetic inputs only. Null references are different from a valid
// buffer whose key bytes happen to be zero. Primitive constant keys remain
// valid; false-success faults of derived material are tested at higher owners.
internal static class NativeKeyHandoffTests
{
    internal static IReadOnlyList<TestCase> Tests =>
    [
        new("security.native-managed-null-contracts", "Actual managed null references fail before native dispatch", NullContracts, TestResource.Light, "Security"),
        new("security.native-managed-width-contracts", "Managed key/nonce/tag widths and output capacities fail without output mutation", WidthContracts, TestResource.Light, "Security"),
        new("crypto.native-constant-key-oracles", "Legitimate 00/01/FF keys: independent managed oracles, MARS composition and Botan KATs", ConstantPrimitiveKeys, TestResource.CpuHeavy, "Crypto"),
        new("kdf.native-constant-argon-inputs", "Constant Argon2id inputs and optional NULL secret agree with independent 8 MiB KAT oracle", ConstantArgonInputs, TestResource.ProcessGlobal, "Kdf"),
    ];

    private delegate void Ctr(byte[] key, byte[] nonce, byte[] input, byte[] output, int length);
    private delegate void Block(byte[] key, byte[] input, byte[] output);
    private sealed record Cipher(string Name, int KeyBytes, int BlockBytes, Ctr Crypt, Func<IBlockCipher>? Oracle);
    private static IReadOnlyList<Cipher> Ciphers =>
    [
        new("AES", 32, 16, NativeAes.XCryptCtr256, () => new AesEngine()),
        new("MARS", 56, 16, NativeMars.XCryptCtr448, null),
        new("SHACAL-2", 64, 32, NativeShacal2.XCryptCtr512, null),
        new("Kalyna", 64, 64, NativeKalyna.XCryptCtr512, () => new Dstu7624Engine(512)),
        new("Camellia", 32, 16, NativeCamellia.XCrypt, () => new CamelliaEngine()),
        new("Serpent", 32, 16, NativeSerpent.XCrypt, () => new SerpentEngine()),
    ];

    private static void Require(bool value, string message)
    {
        if (!value) throw new InvalidOperationException(message);
    }

    private static byte[] PublicBytes(int size, byte? repeated = null) => repeated.HasValue
        ? Enumerable.Repeat(repeated.Value, size).ToArray()
        : Enumerable.Range(0, size).Select(index => (byte)(index * 13 + 7)).ToArray();

    private static void Erase(params byte[][] buffers)
    {
        foreach (byte[] buffer in buffers) CryptographicOperations.ZeroMemory(buffer);
    }

    private static void MustRejectNull(string label, Action call, byte[]? output = null)
    {
        byte[]? before = output?.ToArray();
        try
        {
            try { call(); }
            catch (ArgumentNullException)
            {
                Require(before is null || output!.AsSpan().SequenceEqual(before), label + " changed output before NULL rejection.");
                return;
            }
            // NullReferenceException is deliberately not accepted: required
            // array parameters must have a deliberate fail-closed contract.
            throw new InvalidOperationException(label + " accepted an actual null reference.");
        }
        finally { if (before is not null) Erase(before); }
    }

    private static void MustRejectWidth(string label, Action call, byte[] output)
    {
        byte[] before = output.ToArray();
        try
        {
            bool rejected = false;
            try { call(); }
            catch (ArgumentException) { rejected = true; }
            catch (CryptographicException) { rejected = true; }
            Require(rejected, label + " accepted an invalid width/capacity.");
            Require(output.AsSpan().SequenceEqual(before), label + " changed output before validation rejection.");
        }
        finally { Erase(before); }
    }

    private static Task NullContracts()
    {
        foreach (Cipher cipher in Ciphers)
        {
            byte[] key = PublicBytes(cipher.KeyBytes), nonce = PublicBytes(cipher.BlockBytes);
            byte[] input = PublicBytes(17), output = PublicBytes(17, 0xA5);
            try
            {
                MustRejectNull(cipher.Name + ".key", () => cipher.Crypt(null!, nonce, input, output, input.Length), output);
                MustRejectNull(cipher.Name + ".nonce", () => cipher.Crypt(key, null!, input, output, input.Length), output);
                MustRejectNull(cipher.Name + ".input", () => cipher.Crypt(key, nonce, null!, output, input.Length), output);
                MustRejectNull(cipher.Name + ".output", () => cipher.Crypt(key, nonce, input, null!, input.Length));
            }
            finally { Erase(key, nonce, input, output); }
        }
        foreach ((string name, int width, int blockSize, Block encrypt) in new (string, int, int, Block)[]
        {
            ("AES.block", 32, 16, NativeAes.EncryptBlock), ("MARS.block", 56, 16, NativeMars.EncryptBlock),
            ("SHACAL-2.block", 64, 32, NativeShacal2.EncryptBlock), ("Camellia.block", 32, 16, NativeCamellia.EncryptBlock),
            ("Serpent.block", 32, 16, NativeSerpent.EncryptBlock),
        })
        {
            byte[] key = PublicBytes(width), input = PublicBytes(blockSize), output = PublicBytes(blockSize, 0xA5);
            try
            {
                MustRejectNull(name + ".key", () => encrypt(null!, input, output), output);
                MustRejectNull(name + ".input", () => encrypt(key, null!, output), output);
                MustRejectNull(name + ".output", () => encrypt(key, input, null!));
            }
            finally { Erase(key, input, output); }
        }
        byte[] wideKey = PublicBytes(128), wideNonce = PublicBytes(128), tweak = PublicBytes(16);
        byte[] wideInput = PublicBytes(128), wideOutput = PublicBytes(128, 0xA5);
        byte[] key32 = PublicBytes(32), nonce24 = PublicBytes(24), tag = PublicBytes(16, 0xA7), aad = PublicBytes(17);
        byte[] salt = PublicBytes(64), argonOutput = PublicBytes(64, 0xA5);
        try
        {
            MustRejectNull("Kalyna.no_length.input", () => NativeKalyna.XCryptCtr512(salt, salt, null!, wideOutput), wideOutput);
            MustRejectNull("Threefish.block.key", () => NativeThreefish.EncryptBlock1024(null!, tweak, wideInput, wideOutput), wideOutput);
            MustRejectNull("Threefish.block.tweak", () => NativeThreefish.EncryptBlock1024(wideKey, null!, wideInput, wideOutput), wideOutput);
            MustRejectNull("Threefish.block.input", () => NativeThreefish.EncryptBlock1024(wideKey, tweak, null!, wideOutput), wideOutput);
            MustRejectNull("Threefish.block.output", () => NativeThreefish.EncryptBlock1024(wideKey, tweak, wideInput, null!));
            MustRejectNull("Threefish.ctr.key", () => NativeThreefish.XCryptCtr1024(null!, tweak, wideNonce, wideInput, wideOutput, 128), wideOutput);
            MustRejectNull("Threefish.ctr.tweak", () => NativeThreefish.XCryptCtr1024(wideKey, null!, wideNonce, wideInput, wideOutput, 128), wideOutput);
            MustRejectNull("Threefish.ctr.nonce", () => NativeThreefish.XCryptCtr1024(wideKey, tweak, null!, wideInput, wideOutput, 128), wideOutput);
            MustRejectNull("Threefish.ctr.input", () => NativeThreefish.XCryptCtr1024(wideKey, tweak, wideNonce, null!, wideOutput, 128), wideOutput);
            MustRejectNull("Threefish.ctr.output", () => NativeThreefish.XCryptCtr1024(wideKey, tweak, wideNonce, wideInput, null!, 128));
            MustRejectNull("Threefish.ctr.no_length.input", () => NativeThreefish.XCryptCtr1024(wideKey, tweak, wideNonce, null!, wideOutput), wideOutput);
            MustRejectNull("Skein.create.key", () => NativeThreefish.CreateSkeinMac(null!));
            MustRejectNull("Skein.hash.input", () => NativeThreefish.HashSkein1024Reference(null!));
            MustRejectNull("Skein.mac.key", () => NativeThreefish.MacSkein1024Reference(null!, wideInput));
            MustRejectNull("Skein.mac.input", () => NativeThreefish.MacSkein1024Reference(wideKey, null!));
            for (int operation = 0; operation < 2; operation++)
            {
                void Call(byte[] key, byte[] nonce, byte[] input, byte[] output, byte[] suppliedTag)
                {
                    if (operation == 0) NativeXChaChaPoly.Encrypt(key, nonce, aad, input, output, 128, suppliedTag);
                    else NativeXChaChaPoly.Decrypt(key, nonce, aad, input, output, 128, suppliedTag);
                }
                string name = operation == 0 ? "XChaCha.encrypt" : "XChaCha.decrypt";
                MustRejectNull(name + ".key", () => Call(null!, nonce24, wideInput, wideOutput, tag), wideOutput);
                MustRejectNull(name + ".nonce", () => Call(key32, null!, wideInput, wideOutput, tag), wideOutput);
                MustRejectNull(name + ".input", () => Call(key32, nonce24, null!, wideOutput, tag), wideOutput);
                MustRejectNull(name + ".output", () => Call(key32, nonce24, wideInput, null!, tag));
                MustRejectNull(name + ".tag", () => Call(key32, nonce24, wideInput, wideOutput, null!), wideOutput);
            }
            MustRejectNull("Argon.legacy.password", () => NativeArgon2id.HashRaw(4, 1048576, 4, null!, salt, argonOutput), argonOutput);
            MustRejectNull("Argon.legacy.salt", () => NativeArgon2id.HashRaw(4, 1048576, 4, wideKey, null!, argonOutput), argonOutput);
            MustRejectNull("Argon.legacy.output", () => NativeArgon2id.HashRaw(4, 1048576, 4, wideKey, salt, null!));
            MustRejectNull("Argon.v13.password", () => NativeArgon2id.HashRaw(4, 8192, 4, null!, salt, null, aad, argonOutput, true), argonOutput);
            MustRejectNull("Argon.v13.salt", () => NativeArgon2id.HashRaw(4, 8192, 4, wideKey, null!, null, aad, argonOutput, true), argonOutput);
            MustRejectNull("Argon.v13.associated_data", () => NativeArgon2id.HashRaw(4, 8192, 4, wideKey, salt, null, null!, argonOutput, true), argonOutput);
            MustRejectNull("Argon.v13.output", () => NativeArgon2id.HashRaw(4, 8192, 4, wideKey, salt, null, aad, null!, true));
        }
        finally { Erase(wideKey, wideNonce, tweak, wideInput, wideOutput, key32, nonce24, tag, aad, salt, argonOutput); }
        return Task.CompletedTask;
    }

    private static Task WidthContracts()
    {
        foreach (Cipher cipher in Ciphers)
        {
            byte[] key = PublicBytes(cipher.KeyBytes), nonce = PublicBytes(cipher.BlockBytes), input = PublicBytes(17), output = PublicBytes(17, 0xA5), shortOutput = PublicBytes(16, 0xA5);
            try
            {
                MustRejectWidth(cipher.Name + ".key_width", () => cipher.Crypt(key[..^1], nonce, input, output, 17), output);
                MustRejectWidth(cipher.Name + ".nonce_width", () => cipher.Crypt(key, nonce[..^1], input, output, 17), output);
                MustRejectWidth(cipher.Name + ".input_capacity", () => cipher.Crypt(key, nonce, input[..^1], output, 17), output);
                MustRejectWidth(cipher.Name + ".output_capacity", () => cipher.Crypt(key, nonce, input, shortOutput, 17), shortOutput);
                MustRejectWidth(cipher.Name + ".negative_length", () => cipher.Crypt(key, nonce, input, output, -1), output);
            }
            finally { Erase(key, nonce, input, output, shortOutput); }
        }
        byte[] key128 = PublicBytes(128), nonce128 = PublicBytes(128), tweak = PublicBytes(16), input128 = PublicBytes(128), output128 = PublicBytes(128, 0xA5);
        byte[] key32 = PublicBytes(32), nonce24 = PublicBytes(24), tag = PublicBytes(16), salt = PublicBytes(64), aad = PublicBytes(17), output64 = PublicBytes(64, 0xA5), shortOutput128 = PublicBytes(127, 0xA5), shortOutput64 = PublicBytes(63, 0xA5);
        try
        {
            MustRejectWidth("Threefish.key_width", () => NativeThreefish.XCryptCtr1024(key128[..^1], tweak, nonce128, input128, output128, 128), output128);
            MustRejectWidth("Threefish.tweak_width", () => NativeThreefish.XCryptCtr1024(key128, tweak[..^1], nonce128, input128, output128, 128), output128);
            MustRejectWidth("Threefish.nonce_width", () => NativeThreefish.XCryptCtr1024(key128, tweak, nonce128[..^1], input128, output128, 128), output128);
            MustRejectWidth("Threefish.input_capacity", () => NativeThreefish.XCryptCtr1024(key128, tweak, nonce128, input128[..^1], output128, 128), output128);
            MustRejectWidth("Threefish.output_capacity", () => NativeThreefish.XCryptCtr1024(key128, tweak, nonce128, input128, shortOutput128, 128), shortOutput128);
            MustRejectWidth("XChaCha.key_width", () => NativeXChaChaPoly.Encrypt(key32[..^1], nonce24, aad, input128, output128, 128, tag), output128);
            MustRejectWidth("XChaCha.nonce_width", () => NativeXChaChaPoly.Encrypt(key32, nonce24[..^1], aad, input128, output128, 128, tag), output128);
            MustRejectWidth("XChaCha.tag_width", () => NativeXChaChaPoly.Encrypt(key32, nonce24, aad, input128, output128, 128, tag[..^1]), output128);
            MustRejectWidth("Argon.v13.password_width", () => NativeArgon2id.HashRaw(4, 8192, 4, key128[..^1], salt, null, aad, output64, true), output64);
            MustRejectWidth("Argon.v13.salt_width", () => NativeArgon2id.HashRaw(4, 8192, 4, key128, salt[..^1], null, aad, output64, true), output64);
            MustRejectWidth("Argon.v13.secret_width", () => NativeArgon2id.HashRaw(4, 8192, 4, key128, salt, key128[..^1], aad, output64, true), output64);
            MustRejectWidth("Argon.v13.output_width", () => NativeArgon2id.HashRaw(4, 8192, 4, key128, salt, null, aad, shortOutput64, true), shortOutput64);
            MustRejectWidth("Argon.v13.associated_data_empty", () => NativeArgon2id.HashRaw(4, 8192, 4, key128, salt, null, [], output64, true), output64);
        }
        finally { Erase(key128, nonce128, tweak, input128, output128, key32, nonce24, tag, salt, aad, output64, shortOutput128, shortOutput64); }
        return Task.CompletedTask;
    }

    private static Task ConstantPrimitiveKeys()
    {
        using IDisposable grant = NativeCipherWorkerBudget.EnterScope(1);
        CheckIndependentShacalReference();
        foreach (byte pattern in new byte[] { 0x00, 0x01, 0xFF })
        {
            foreach (Cipher cipher in Ciphers)
            {
                byte[] key = PublicBytes(cipher.KeyBytes, pattern), nonce = PublicBytes(cipher.BlockBytes), input = PublicBytes(257);
                byte[] actual = PublicBytes(257, 0xA5), restored = PublicBytes(257, 0xA5), expected;
                if (cipher.Oracle is not null)
                {
                    IBlockCipher engine = cipher.Oracle();
                    engine.Init(true, new KeyParameter(key));
                    expected = ReferenceCtr(engine, nonce, input);
                }
                else if (cipher.Name == "SHACAL-2")
                {
                    // BC 2.6.2 has no SHACAL-2. This independent managed
                    // SHA-256 round permutation has no native/provider calls,
                    // and is pinned first to the published NESSIE vector.
                    expected = ReferenceShacalCtr(key, nonce, input);
                }
                else
                {
                    // MARS is absent from BC. This checks native block versus
                    // native CTR composition, not an independent primitive.
                    expected = ReferenceMarsCtr(key, nonce, input);
                }
                try
                {
                    cipher.Crypt(key, nonce, input, actual, input.Length);
                    Require(actual.AsSpan().SequenceEqual(expected), cipher.Name + " constant-key CTR mismatch.");
                    cipher.Crypt(key, nonce, actual, restored, actual.Length);
                    Require(restored.AsSpan().SequenceEqual(input), cipher.Name + " constant-key roundtrip mismatch.");
                }
                finally { Erase(key, nonce, input, actual, restored, expected); }
            }
            byte[] wideKey = PublicBytes(128, pattern), tweak = PublicBytes(16), nonce128 = PublicBytes(128), inputWide = PublicBytes(257);
            byte[] wideOutput = PublicBytes(257, 0xA5), key32 = PublicBytes(32, pattern), nonce24 = PublicBytes(24), aad = PublicBytes(17);
            byte[] aeadOutput = PublicBytes(257, 0xA5), tag = PublicBytes(16, 0xA7), restoredAead = PublicBytes(257, 0xA5);
            try
            {
                var threefish = new ThreefishEngine(1024);
                threefish.Init(true, new TweakableBlockCipherParameters(new KeyParameter(wideKey), tweak));
                byte[] expected = ReferenceCtr(threefish, nonce128, inputWide);
                try
                {
                    NativeThreefish.XCryptCtr1024(wideKey, tweak, nonce128, inputWide, wideOutput, inputWide.Length);
                    Require(wideOutput.AsSpan().SequenceEqual(expected), "Threefish constant-key BC CTR mismatch.");
                }
                finally { Erase(expected); }
                byte[] xExpected = ReferenceXChaCha(key32, nonce24, aad, inputWide);
                try
                {
                    NativeXChaChaPoly.Encrypt(key32, nonce24, aad, inputWide, aeadOutput, inputWide.Length, tag);
                    Require(aeadOutput.AsSpan().SequenceEqual(xExpected.AsSpan(0, inputWide.Length))
                        && tag.AsSpan().SequenceEqual(xExpected.AsSpan(inputWide.Length)), "XChaCha constant-key independent AEAD mismatch.");
                    NativeXChaChaPoly.Decrypt(key32, nonce24, aad, aeadOutput, restoredAead, aeadOutput.Length, tag);
                    Require(restoredAead.AsSpan().SequenceEqual(inputWide), "XChaCha constant-key roundtrip mismatch.");
                }
                finally { Erase(xExpected); }
                CheckConstantMacOracles(wideKey, aad);
            }
            finally { Erase(wideKey, tweak, nonce128, inputWide, wideOutput, key32, nonce24, aad, aeadOutput, tag, restoredAead); }
        }
        CheckExistingIndependentMarsFixtures();
        return Task.CompletedTask;
    }

    private static byte[] ReferenceCtr(IBlockCipher cipher, byte[] nonce, byte[] input)
    {
        byte[] counter = nonce.ToArray(), stream = new byte[cipher.GetBlockSize()], output = new byte[input.Length];
        try
        {
            for (int offset = 0; offset < input.Length; offset += stream.Length)
            {
                Require(cipher.ProcessBlock(counter, 0, stream, 0) == stream.Length, "Independent block oracle returned the wrong width.");
                for (int index = 0; index < Math.Min(stream.Length, input.Length - offset); index++) output[offset + index] = (byte)(input[offset + index] ^ stream[index]);
                Increment(counter);
            }
            return output;
        }
        finally { Erase(counter, stream); }
    }

    private static byte[] ReferenceMarsCtr(byte[] key, byte[] nonce, byte[] input)
    {
        byte[] counter = nonce.ToArray(), stream = new byte[16], output = new byte[input.Length];
        try
        {
            for (int offset = 0; offset < input.Length; offset += 16)
            {
                NativeMars.EncryptBlock(key, counter, stream);
                for (int index = 0; index < Math.Min(16, input.Length - offset); index++) output[offset + index] = (byte)(input[offset + index] ^ stream[index]);
                Increment(counter);
            }
            return output;
        }
        finally { Erase(counter, stream); }
    }

    private static readonly uint[] ShacalRoundConstants =
    [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    // Same independently encoded primitive used by the checked-in
    // Fixtures/V13Reference/CascadeCompositionReference.cs.txt generator.
    // SHACAL-2 is SHA-256's keyed round permutation without feedforward.
    private static byte[] ReferenceShacalBlock(byte[] key, byte[] input)
    {
        Require(key.Length == 64 && input.Length == 32, "Invalid independent SHACAL-2 fixture width.");
        uint[] schedule = new uint[64];
        try
        {
            unchecked
            {
                for (int index = 0; index < 16; index++) schedule[index] = BinaryPrimitives.ReadUInt32BigEndian(key.AsSpan(index * 4));
                for (int index = 16; index < 64; index++)
                {
                    uint first = schedule[index - 15], second = schedule[index - 2];
                    schedule[index] = schedule[index - 16]
                        + (BitOperations.RotateRight(first, 7) ^ BitOperations.RotateRight(first, 18) ^ (first >> 3))
                        + schedule[index - 7]
                        + (BitOperations.RotateRight(second, 17) ^ BitOperations.RotateRight(second, 19) ^ (second >> 10));
                }
                uint a = BinaryPrimitives.ReadUInt32BigEndian(input.AsSpan(0)), b = BinaryPrimitives.ReadUInt32BigEndian(input.AsSpan(4)),
                    c = BinaryPrimitives.ReadUInt32BigEndian(input.AsSpan(8)), d = BinaryPrimitives.ReadUInt32BigEndian(input.AsSpan(12)),
                    e = BinaryPrimitives.ReadUInt32BigEndian(input.AsSpan(16)), f = BinaryPrimitives.ReadUInt32BigEndian(input.AsSpan(20)),
                    g = BinaryPrimitives.ReadUInt32BigEndian(input.AsSpan(24)), h = BinaryPrimitives.ReadUInt32BigEndian(input.AsSpan(28));
                for (int index = 0; index < 64; index++)
                {
                    uint first = h + (BitOperations.RotateRight(e, 6) ^ BitOperations.RotateRight(e, 11) ^ BitOperations.RotateRight(e, 25))
                        + ((e & f) ^ (~e & g)) + ShacalRoundConstants[index] + schedule[index];
                    uint second = (BitOperations.RotateRight(a, 2) ^ BitOperations.RotateRight(a, 13) ^ BitOperations.RotateRight(a, 22))
                        + ((a & b) ^ (a & c) ^ (b & c));
                    h = g; g = f; f = e; e = d + first; d = c; c = b; b = a; a = first + second;
                }
                byte[] output = new byte[32];
                uint[] state = [a, b, c, d, e, f, g, h];
                try { for (int index = 0; index < state.Length; index++) BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(index * 4), state[index]); }
                finally { Array.Clear(state); }
                return output;
            }
        }
        finally { Array.Clear(schedule); }
    }

    private static byte[] ReferenceShacalCtr(byte[] key, byte[] nonce, byte[] input)
    {
        byte[] counter = nonce.ToArray(), output = new byte[input.Length];
        try
        {
            for (int offset = 0; offset < input.Length; offset += 32)
            {
                byte[] stream = ReferenceShacalBlock(key, counter);
                try { for (int index = 0; index < Math.Min(32, input.Length - offset); index++) output[offset + index] = (byte)(input[offset + index] ^ stream[index]); }
                finally { Erase(stream); }
                Increment(counter);
            }
            return output;
        }
        finally { Erase(counter); }
    }

    private static void CheckIndependentShacalReference()
    {
        // NESSIE submission Set 1, vector 0, preserved in
        // external/cryptopp/TestVectors/shacal2.txt (512-bit key).
        byte[] key = new byte[64], input = new byte[32];
        key[0] = 0x80;
        byte[] expected = Convert.FromHexString("361AB6322FA9E7A7BB23818D839E01BDDAFDF47305426EDD297AEDB9F6202BAE");
        byte[] actual = ReferenceShacalBlock(key, input);
        try { Require(actual.AsSpan().SequenceEqual(expected), "Independent SHACAL-2 reference failed its NESSIE anchor."); }
        finally { Erase(key, input, expected, actual); }
    }

    private static void Increment(byte[] counter)
    {
        for (int index = counter.Length - 1; index >= 0; index--) if (++counter[index] != 0) return;
        throw new OverflowException("Public test nonce exhausted.");
    }

    private static byte[] ReferenceXChaCha(byte[] key, byte[] nonce, byte[] aad, byte[] input)
    {
        uint[] words = new uint[16];
        uint[] constants = [0x61707865U, 0x3320646eU, 0x79622d32U, 0x6b206574U];
        constants.CopyTo(words, 0);
        for (int index = 0; index < 8; index++) words[index + 4] = BinaryPrimitives.ReadUInt32LittleEndian(key.AsSpan(index * 4));
        for (int index = 0; index < 4; index++) words[index + 12] = BinaryPrimitives.ReadUInt32LittleEndian(nonce.AsSpan(index * 4));
        void Quarter(int a, int b, int c, int d)
        {
            words[a] = unchecked(words[a] + words[b]); words[d] = BitOperations.RotateLeft(words[d] ^ words[a], 16);
            words[c] = unchecked(words[c] + words[d]); words[b] = BitOperations.RotateLeft(words[b] ^ words[c], 12);
            words[a] = unchecked(words[a] + words[b]); words[d] = BitOperations.RotateLeft(words[d] ^ words[a], 8);
            words[c] = unchecked(words[c] + words[d]); words[b] = BitOperations.RotateLeft(words[b] ^ words[c], 7);
        }
        byte[] subkey = new byte[32], shortNonce = new byte[12];
        try
        {
            for (int round = 0; round < 10; round++)
            {
                Quarter(0, 4, 8, 12); Quarter(1, 5, 9, 13); Quarter(2, 6, 10, 14); Quarter(3, 7, 11, 15);
                Quarter(0, 5, 10, 15); Quarter(1, 6, 11, 12); Quarter(2, 7, 8, 13); Quarter(3, 4, 9, 14);
            }
            int[] outputWords = [0, 1, 2, 3, 12, 13, 14, 15];
            for (int index = 0; index < 8; index++) BinaryPrimitives.WriteUInt32LittleEndian(subkey.AsSpan(index * 4), words[outputWords[index]]);
            nonce.AsSpan(16, 8).CopyTo(shortNonce.AsSpan(4));
            var cipher = new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305();
            cipher.Init(true, new AeadParameters(new KeyParameter(subkey), 128, shortNonce, aad));
            byte[] output = new byte[cipher.GetOutputSize(input.Length)];
            int written = cipher.ProcessBytes(input, 0, input.Length, output, 0);
            written += cipher.DoFinal(output, written);
            Require(written == input.Length + 16, "Independent XChaCha reference output length mismatch.");
            return output;
        }
        finally { Array.Clear(words); Erase(subkey, shortNonce); }
    }

    private static void CheckConstantMacOracles(byte[] key, byte[] message)
    {
        byte[] expected = new byte[128], actual = new byte[128];
        try
        {
            var skein = new SkeinMac(1024, 1024);
            skein.Init(new KeyParameter(key)); skein.BlockUpdate(message); Require(skein.DoFinal(expected) == 128, "BC Skein output width.");
            using (NativeSkein1024Mac native = NativeThreefish.CreateSkeinMac(key))
            {
                native.AppendData(message);
                byte[] tag = native.GetTag();
                try { Require(tag.AsSpan().SequenceEqual(expected), "Constant Skein native streaming MAC mismatch."); }
                finally { Erase(tag); }
            }
            byte[] oneshot = NativeThreefish.MacSkein1024Reference(key, message);
            try { Require(oneshot.AsSpan().SequenceEqual(expected), "Constant Skein oneshot MAC mismatch."); }
            finally { Erase(oneshot); }
            const string domain = "KeepVault/PublicConstantPrimitiveTest/v13";
            skein.Init(new SkeinParameters.Builder().SetKey(key).SetPersonalisation(System.Text.Encoding.UTF8.GetBytes(domain)).Build());
            skein.BlockUpdate(message); Require(skein.DoFinal(expected) == 128, "BC personalized Skein width.");
            KeyedSkein1024.Compute(key, domain, message, actual);
            Require(actual.AsSpan().SequenceEqual(expected), "Constant personalized Skein BC mismatch.");
            var hmac = new HMac(new Sha3Digest(512)); hmac.Init(new KeyParameter(key)); hmac.BlockUpdate(message); hmac.DoFinal(expected);
            using var production = new HmacSha3_512(key); production.AppendData(message); production.GetHashAndReset(actual);
            Require(actual.AsSpan(0, 64).SequenceEqual(expected.AsSpan(0, 64)), "Constant HMAC-SHA3 BC mismatch.");
            var hkdf = new HkdfBytesGenerator(new Sha3Digest(512)); hkdf.Init(HkdfParameters.SkipExtractParameters(key, message));
            Require(hkdf.GenerateBytes(expected, 0, expected.Length) == expected.Length, "BC HKDF output width.");
            Sha3HkdfExpand.Expand(key, message, actual);
            Require(actual.AsSpan().SequenceEqual(expected), "Constant HKDF BC mismatch.");
        }
        finally { Erase(expected, actual); }
    }

    private static void CheckExistingIndependentMarsFixtures()
    {
        string fixture = Path.Combine(AppContext.BaseDirectory, "MarsKnownAnswers.txt");
        Require(File.Exists(fixture), "Independent Botan MARS fixture is missing.");
        int checked448 = 0;
        foreach (string line in File.ReadLines(fixture))
        {
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#')) continue;
            string[] fields = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            Require(fields.Length == 3, "Invalid independent MARS fixture framing.");
            if (fields[0].Length != 112) continue;
            byte[] key = Convert.FromHexString(fields[0]), input = Convert.FromHexString(fields[1]), expected = Convert.FromHexString(fields[2]), actual = new byte[16];
            try { NativeMars.EncryptBlock(key, input, actual); Require(actual.AsSpan().SequenceEqual(expected), "Independent Botan MARS-448 KAT mismatch."); checked448++; }
            finally { Erase(key, input, expected, actual); }
        }
        Require(checked448 >= 40, "Insufficient independent Botan MARS-448 fixtures.");
    }

    private static Task ConstantArgonInputs()
    {
        foreach (byte pattern in new byte[] { 0x00, 0x01, 0xFF })
        foreach (bool hasSecret in new[] { false, true })
        {
            byte[] password = PublicBytes(128, pattern), salt = PublicBytes(64), secret = PublicBytes(128, pattern), aad = PublicBytes(17);
            byte[] expected = new byte[64], actual = PublicBytes(64, 0xA5), oneCallPassword = password.ToArray(), oneCallSecret = secret.ToArray();
            try
            {
                var builder = new Argon2Parameters.Builder(Argon2Parameters.Argon2id).WithVersion(Argon2Parameters.Version13)
                    .WithMemoryAsKB(8192).WithIterations(4).WithParallelism(4).WithSalt(salt).WithAdditional(aad);
                if (hasSecret) builder.WithSecret(secret);
                var reference = new Argon2BytesGenerator(); reference.Init(builder.Build());
                Require(reference.GenerateBytes(password, expected) == 64, "Independent Argon2 KAT output width.");
                NativeArgon2id.HashRaw(4, 8192, 4, oneCallPassword, salt, hasSecret ? oneCallSecret : null, aad, actual, true, 1);
                Require(actual.AsSpan().SequenceEqual(expected), "Constant Argon2 input differs from BC 8 MiB KAT oracle.");
                Require(oneCallPassword.All(value => value == 0), "Argon2 did not erase its one-call password copy.");
                Require(!hasSecret || oneCallSecret.All(value => value == 0), "Argon2 did not erase its one-call secret copy.");
            }
            finally { Erase(password, salt, secret, aad, expected, actual, oneCallPassword, oneCallSecret); }
        }
        return Task.CompletedTask;
    }
}
