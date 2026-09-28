using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using KalynaArchiver.Services;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

// Shared by the macOS and Windows inventories. All factors/keys in this file
// are public test fixtures. Reduced KDF memory is scoped explicitly to tests.
internal static class V13StandardTests
{
    private const string Algorithm = "XChaCha20-Poly1305(Threefish-1024-CTR(Kalyna-512/512-CTR(AES-256-CTR)))+HMAC-SHA3-512+Skein-MAC-1024";
    private const string Password = "N!r7$Vq2#Lm8%Tx3&Jd9*Wp4+Kg5=Zu6?Ce";
    private const string Pin = "428317";
    private static readonly string FactorA = new('A', 256);
    private static readonly string FactorB = new('B', 256);
    private const int ChunkBytes = 16 * 1024 * 1024;

    internal static IReadOnlyList<TestCase> Tests =>
    [
        new("v13-header-canonical-fields", "strict Base64, duplicate/unknown fields and profile validation in both header APIs", CanonicalFieldsAsync, TestResource.Light, "V13"),
        new("v13-std-catalog", "V13-STD-CATALOG: twelve suites, five AEADs and stable IDs", CatalogAsync, TestResource.Light, "V13"),
        new("v13-std-layout", "V13-STD-LAYOUT: exact stage key/nonce offsets", LayoutAsync, TestResource.Light, "V13"),
        new("v13-std-rolekeys", "V13-STD-ROLEKEYS: independent context and dual-PRF derivation", RoleKeysAsync, TestResource.Light, "V13"),
        new("v13-std-tweak", "V13-STD-TWEAK: independent complete-nonce reference encoding", TweakAsync, TestResource.Light, "V13"),
        new("v13-std-nonces-aad", "v13 nonce expansion and AAD at 64-bit archive indices", NoncesAndAadAsync, TestResource.Light, "V13"),
        new("v13-std-composition", "V13-STD-COMPOSITION: independent inner CTR stages and outer native oracle", CompositionAsync, TestResource.CpuHeavy, "V13"),
        new("v13-std-default-api", "V13-STD-DEFAULT-API: public/internal defaults and explicit Kalyna", DefaultApiAsync, TestResource.EntropyGlobal, "V13"),
        new("v13-std-header", "V13-STD-HEADER: actual canonical writer header", HeaderAsync, TestResource.EntropyGlobal, "V13"),
        new("v13-std-framing", "V13-STD-FRAMING: short reads, full/partial chunks and ordered slots", FramingAsync, TestResource.EntropyGlobal, "V13"),
        new("v13-std-nolegacy", "V13-STD-NOLEGACY: old versions, algorithms, KDF and nonce widths rejected", NoLegacyAsync, TestResource.EntropyGlobal, "V13"),
        new("v13-std-tamper", "V13-STD-TAMPER: global MAC AND and independently reached local tag failure", TamperAsync, TestResource.EntropyGlobal, "V13"),
    ];

    private static async Task CanonicalFieldsAsync()
    {
        string root = Path.Combine(RepositoryLayout.FindRepositoryRoot(), "KeepVaultMac.Tests", "Fixtures", "V13Reference");
        int rejected = 0;
        foreach (string name in new[] { "standard", "paranoia", "aes" })
        {
            byte[] valid = File.ReadAllBytes(Path.Combine(root, name + "-header-rev9.json"));
            await ReadBoth(valid);
            JsonObject header = JsonNode.Parse(valid)!.AsObject();
            foreach (string field in new[] { "SaltSha3Round1", "SaltSkeinRound1", "SaltSha3Round2", "SaltSkeinRound2", "Nonce", "SecondNonce", "Tweak" })
            {
                if (header[field] is not JsonValue value) continue;
                string encoded = value.GetValue<string>();
                const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                int position = encoded.IndexOf('=') - 1;
                Require(position >= 0, "Fixture must exercise unused Base64 padding bits.");
                char changed = alphabet[alphabet.IndexOf(encoded[position]) + 1];
                foreach (string mutation in new[] { " " + encoded, encoded + "\t", encoded[..4] + " " + encoded[4..], encoded[..position] + changed + encoded[(position+1)..] })
                {
                    // Every mutation decodes to the same bytes, so rejection
                    // must be lexical; it cannot depend on a changed tweak.
                    Require(Convert.FromBase64String(mutation).SequenceEqual(Convert.FromBase64String(encoded)), "Mutation changed decoded public bytes.");
                    var copy = (JsonObject)header.DeepClone(); copy[field] = mutation;
                    await RejectBoth(Encoding.UTF8.GetBytes(copy.ToJsonString())); rejected += 2;
                }
            }
            foreach (Action<JsonObject> mutate in new Action<JsonObject>[] {
                h => h["Version"] = 12, h => h["Version"] = 14,
                h => h["Argon2Iterations"] = 3, h => h["Argon2Parallelism"] = 3,
                h => h["Argon2MemoryKiB"] = 1048576, h => h["KdfBranchOutputBits"] = 1024,
                h => h["MasterKeyBits"] = 632*8, h => h["KdfExecutionMode"] = "Parallel",
                h => h["KdfInputMode"] = "DualBranch-v12: SplitFactorsSHA3-512-1024 || KeyedSkeinMAC-1024-1024",
                h => h["NonceDerivationMode"] = "Seed320-Blockwise64-SHA3-512+AllBlocks-StageProjection-v2",
                h => h.Remove("NonceDerivationMode"), h => h["UnknownField"] = 0,
                h => h["SaltSkeinRound1"] = h["SaltSha3Round1"]!.GetValue<string>() })
            {
                var copy = (JsonObject)header.DeepClone(); mutate(copy);
                await RejectBoth(Encoding.UTF8.GetBytes(copy.ToJsonString())); rejected += 2;
            }
            string json = Encoding.UTF8.GetString(valid);
            foreach (string malformed in new[] { " " + json, json[..^1] + ",\"Version\":13}", json.Replace("\"NonceBits\":2560", "\"NonceBits\":2560.0", StringComparison.Ordinal) })
            { await RejectBoth(Encoding.UTF8.GetBytes(malformed)); rejected += 2; }
            if (name == "aes")
            {
                var copy = (JsonObject)header.DeepClone(); copy["Tweak"] = "";
                await RejectBoth(Encoding.UTF8.GetBytes(copy.ToJsonString())); rejected += 2;
            }
        }
        Require(rejected == 210, $"Strict header mutation inventory changed: {rejected} checks.");

        static MemoryStream Frame(byte[] header)
        {
            byte[] bytes = new byte[11 + header.Length + 193];
            "KZPAQ2\0"u8.CopyTo(bytes); BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(7), header.Length);
            header.CopyTo(bytes, 11); return new MemoryStream(bytes);
        }
        static async Task ReadBoth(byte[] header)
        {
            using var infoStream = Frame(header); using var kdfStream = Frame(header);
            var service = new KalynaContainerService();
            _ = await service.ReadContainerInfoAsync(infoStream, default);
            _ = await service.ReadRecoveryKdfInfoAsync(kdfStream, default);
        }
        static async Task RejectBoth(byte[] header)
        {
            foreach (bool recovery in new[] { false, true })
            {
                using var stream = Frame(header); var service = new KalynaContainerService();
                try
                {
                    if (recovery) _ = await service.ReadRecoveryKdfInfoAsync(stream, default);
                    else _ = await service.ReadContainerInfoAsync(stream, default);
                }
                catch (InvalidDataException) { continue; }
                throw new InvalidOperationException("A non-canonical or invalid header reached a metadata consumer.");
            }
        }
    }

    internal static Task CatalogAsync()
    {
        EncryptionSuite[] all = Enum.GetValues<EncryptionSuite>();
        Require(all.Length == 12 && all.Distinct().Count() == 12, "Suite count or enum aliases changed.");
        Require((int)EncryptionSuite.StandardCascade == 2 && (int)EncryptionSuite.XChaChaOverAes == 4
            && (int)EncryptionSuite.XChaCha20Poly1305 == 8 && (int)CascadeCipher.XChaCha20Poly1305 == 5, "IDs changed.");
        Require(EncryptionSuiteCatalog.Default == EncryptionSuite.StandardCascade, "Default is not ID 2.");
        Require(!Enum.TryParse<EncryptionSuite>("ThreefishOverKalyna", out _)
            && EncryptionSuiteCatalog.ParsePreference("ThreefishOverKalyna") == EncryptionSuiteCatalog.ParsePreference("unregistered")
            && EncryptionSuiteCatalog.ParsePreference("ChaChaOverAes") == EncryptionSuite.XChaChaOverAes
            && EncryptionSuiteCatalog.ParsePreference("ChaCha20Poly1305") == EncryptionSuite.XChaCha20Poly1305
            && EncryptionSuiteCatalog.ParsePreference("5") == EncryptionSuite.Aes256
            && EncryptionSuiteCatalog.ParsePreference("corrupted") == EncryptionSuite.StandardCascade
            && EncryptionSuiteCatalog.ParsePreference(null) == EncryptionSuite.StandardCascade, "Saved preference migration/default handling failed.");
        Require(all.Count(s => EncryptionSuiteCatalog.Get(s).Cascade?.OutermostIsAead == true) == 5, "Exactly five suites must use AEAD.");
        Require(EncryptionSuiteCatalog.DisplayOrder.Select(s => (int)s).SequenceEqual(new[] { 2, 4, 9, 3, 1, 0, 7, 6, 5, 10, 11, 8 }), "GUI order changed.");
        Require(EncryptionSuiteCatalog.ArchiveNonceBytes == 320 && EncryptionSuiteCatalog.MaxStageNonceBytes == 312, "Stored and active nonce widths were conflated.");
        int[] widths = [64, 128, 232, 312, 40, 16, 16, 32, 24, 168, 16, 16];
        foreach (EncryptionSuite suite in all)
        {
            EncryptionSuiteParameters p = EncryptionSuiteCatalog.Get(suite);
            Require(p.StageNonceBytes == widths[(int)suite], $"{suite} nonce width changed.");
            Require(EncryptionSuiteCatalog.FromAlgorithm(p.Algorithm).Suite == suite, "Algorithm routing differs from catalog.");
            Require(p.Sha3MacKeyBytes == 64 && p.SkeinMacKeyBytes == 128, "Both global MACs are required.");
        }
        Throws<InvalidDataException>(() => EncryptionSuiteCatalog.FromAlgorithm("Threefish-1024-CTR(Kalyna-512/512-CTR)+HMAC-SHA3-512+Skein-MAC-1024"));
        Throws<InvalidDataException>(() => EncryptionSuiteCatalog.FromAlgorithm("ChaCha20-Poly1305+HMAC-SHA3-512+Skein-MAC-1024"));
        return Task.CompletedTask;
    }

    internal static Task LayoutAsync()
    {
        EncryptionSuiteParameters p = EncryptionSuiteCatalog.Get(EncryptionSuite.StandardCascade);
        CascadeLayout layout = p.Cascade!;
        Require(p.Algorithm == Algorithm && p.DerivedKeyBytes == 448 && p.BlockBytes == 128
            && p.TweakBytes == 16 && !p.UsesTwoKdfRounds && layout.OutermostIsAead, "Standard metadata mismatch.");
        CascadeCipher[] ciphers = [CascadeCipher.Aes256, CascadeCipher.Kalyna512_512, CascadeCipher.Threefish1024, CascadeCipher.XChaCha20Poly1305];
        int[] keys = [32, 64, 128, 32], nonces = [16, 64, 128, 24], blocks = [16, 64, 128, 64];
        int[] keyOffsets = [0, 32, 96, 224], nonceOffsets = [0, 16, 80, 208];
        Require(layout.Stages.Count == 4 && layout.TotalKeyBytes == 256 && layout.TotalNonceBytes == 232, "Standard sums mismatch.");
        int k = 0, n = 0;
        for (int i = 0; i < 4; ++i)
        {
            CascadeStage stage = layout.Stages[i];
            Require(stage == new CascadeStage(ciphers[i], keys[i], nonces[i], blocks[i])
                && k == keyOffsets[i] && n == nonceOffsets[i], $"Standard stage {i} differs.");
            k += stage.KeyBytes; n += stage.NonceBytes;
        }
        Require(V13MasterKdf.MasterBytes == 128 && V13MasterKdf.BranchOutputBytes == 64
            && V13MasterKdf.Iterations == 4 && V13MasterKdf.Parallelism == 4, "Master KDF profile weakened.");
        return Task.CompletedTask;
    }

    internal static Task TweakAsync()
    {
        byte[] nonce = Bytes(320, 43, 11);
        byte[] expected = ReferenceTweak(Algorithm, 2, nonce);
        Require(expected.AsSpan().SequenceEqual(KalynaContainerService.CreateSuiteTweak(EncryptionSuite.StandardCascade, nonce)), "Tweak differs from independent encoding.");
        foreach (int index in new[] { 0, 15, 16, 79, 80, 207, 208, 231, 255, 256, 319 })
        {
            byte[] changed = (byte[])nonce.Clone(); changed[index] ^= 1;
            Require(!ReferenceTweak(Algorithm, 2, changed).SequenceEqual(expected), $"Nonce byte {index} was not bound.");
        }
        Require(!ReferenceTweak(Algorithm, 1, nonce).SequenceEqual(expected), "Stage index is not bound.");
        Require(!ReferenceTweak(Algorithm + "x", 2, nonce).SequenceEqual(expected), "Algorithm is not bound.");
        return Task.CompletedTask;
    }

    internal static byte[] ReferenceTweak(string algorithm, int index, byte[] nonce)
    {
        using var output = new MemoryStream(); using var writer = new BinaryWriter(output, Encoding.UTF8, leaveOpen: true);
        Lp(writer, Encoding.UTF8.GetBytes("Kalyna-ZPAQ/v13/Threefish-1024/CTR-Tweak"));
        Lp(writer, Encoding.UTF8.GetBytes(algorithm)); writer.Write(index); Lp(writer, nonce);
        return ReferenceSha3(output.ToArray())[..16];
    }

    internal static Task RoleKeysAsync()
    {
        byte[] master = Bytes(128, 17, 5);
        EncryptionSuiteParameters p = EncryptionSuiteCatalog.Get(EncryptionSuite.StandardCascade);
        using RoleKeyMaterial actual = SuiteKeySchedule.DeriveSuiteKeys(master, p);
        string[] ciphers = ["AES-256", "Kalyna-512/512", "Threefish-1024", "XChaCha20-Poly1305", "HMAC-SHA3-512", "Skein-MAC-1024-1024"];
        int[] bits = [256, 512, 1024, 256, 512, 1024];
        KeyRolePurpose[] purposes = [KeyRolePurpose.Encryption, KeyRolePurpose.Encryption, KeyRolePurpose.Encryption, KeyRolePurpose.Encryption, KeyRolePurpose.Sha3Mac, KeyRolePurpose.SkeinMac];
        int offset = 0;
        var seen = new HashSet<string>();
        for (int i = 0; i < ciphers.Length; ++i)
        {
            int stage = i < 4 ? i : -1;
            byte[] context = ReferenceContext(Algorithm, stage, ciphers[i], purposes[i].ToString(), bits[i]);
            Require(context.SequenceEqual(SuiteKeySchedule.BuildRoleContext(Algorithm, stage, ciphers[i], purposes[i], bits[i])), "Role context encoding mismatch.");
            Require(seen.Add(Convert.ToHexString(context)), "Duplicate role context.");
            byte[] expected = ReferenceRole(master, context)[..(bits[i] / 8)];
            byte[] key = i < 4 ? actual.EncryptionKey.Bytes.AsSpan(offset, bits[i] / 8).ToArray()
                : i == 4 ? actual.Sha3MacKey.Bytes : actual.SkeinMacKey.Bytes;
            Require(expected.SequenceEqual(key), $"Role key {i} differs from independent Bouncy Castle composition.");
            if (i < 4) offset += bits[i] / 8;
        }
        return Task.CompletedTask;
    }

    internal static byte[] ReferenceContext(string algorithm, int stage, string cipher, string purpose, int bits)
    {
        using var output = new MemoryStream(); using var writer = new BinaryWriter(output, Encoding.UTF8, leaveOpen: true);
        Lp(writer, Encoding.UTF8.GetBytes("Kalyna-ZPAQ/v13/RoleKey")); writer.Write(13);
        Lp(writer, Encoding.UTF8.GetBytes(algorithm)); writer.Write(stage);
        Lp(writer, Encoding.UTF8.GetBytes(cipher)); Lp(writer, Encoding.UTF8.GetBytes(purpose)); writer.Write(bits);
        return output.ToArray();
    }

    internal static byte[] ReferenceRole(byte[] master, byte[] context)
    {
        byte[] sha = new byte[128];
        for (int half = 0; half < 2; ++half)
        {
            using var output = new MemoryStream(); using var writer = new BinaryWriter(output, Encoding.UTF8, leaveOpen: true);
            Lp(writer, Encoding.UTF8.GetBytes("Kalyna-ZPAQ/v13/RoleKey/HKDF-HMAC-SHA3-512"));
            Lp(writer, context); Lp(writer, Encoding.UTF8.GetBytes($"Half-{half}")); writer.Write((byte)1);
            var mac = new HMac(new Sha3Digest(512)); mac.Init(new KeyParameter(master.AsSpan(half * 64, 64).ToArray()));
            mac.BlockUpdate(output.ToArray()); mac.DoFinal(sha, half * 64);
        }
        var skein = new SkeinMac(1024, 1024);
        skein.Init(new SkeinParameters.Builder().SetKey(master).SetPersonalisation(Encoding.UTF8.GetBytes("Kalyna-ZPAQ/v13/RoleKey/Skein-MAC-1024-1024")).Build());
        skein.BlockUpdate(context); byte[] result = new byte[128]; skein.DoFinal(result);
        for (int i = 0; i < result.Length; ++i) result[i] ^= sha[i];
        return result;
    }

    internal static Task NoncesAndAadAsync()
    {
        foreach (EncryptionSuite suite in EncryptionSuiteCatalog.DisplayOrder)
        {
            EncryptionSuiteParameters p = EncryptionSuiteCatalog.Get(suite);
            byte[] nonceBase = Bytes(p.ChunkNonceBaseBytes, 71, 3);
            foreach (long index in new long[] { 0, 16383, 16384, 65535, 65536, 262143, 262144, uint.MaxValue, (long)uint.MaxValue + 1, long.MaxValue })
            {
                byte[] actual = new byte[p.StageNonceBytes];
                KalynaContainerService.DeriveChunkNonce(p, nonceBase, index, actual);
                Require(actual.SequenceEqual(ReferenceNonce(p, nonceBase, index)), "64-bit chunk nonce differs from independent reference.");
                byte[] aad = KalynaContainerService.BuildChunkAssociatedData(p, nonceBase, index, 123, 13);
                Require(aad.Length == 36 && BinaryPrimitives.ReadInt32BigEndian(aad) == 13
                    && BinaryPrimitives.ReadInt32BigEndian(aad.AsSpan(4)) == (int)suite
                    && aad.AsSpan(8, 16).SequenceEqual(ReferenceSha3(nonceBase).AsSpan(0, 16))
                    && BinaryPrimitives.ReadInt64BigEndian(aad.AsSpan(24)) == index
                    && BinaryPrimitives.ReadInt32BigEndian(aad.AsSpan(32)) == 123, "AAD encoding changed.");
            }
            Throws<ArgumentOutOfRangeException>(() => KalynaContainerService.DeriveChunkNonce(p, nonceBase, -1L, new byte[p.StageNonceBytes]));
        }
        return Task.CompletedTask;
    }

    internal static byte[] ReferenceNonce(EncryptionSuiteParameters parameters, byte[] nonce, long index)
    {
        using var result = new MemoryStream();
        int width = SuiteKeySchedule.StagesOf(parameters).Sum(s => s.NonceBytes);
        int count = 1 + (width - 1) / 64;
        for (int block = 0; block < count; ++block)
        {
            using var encoded = new MemoryStream(); using var writer = new BinaryWriter(encoded, Encoding.UTF8, leaveOpen: true);
            Lp(writer, Encoding.UTF8.GetBytes("Kalyna-ZPAQ/v13/chunk-nonce/Blockwise64-ActivePrefix-SHA3-512-v3"));
            writer.Write(13); writer.Write((int)parameters.Suite); Lp(writer, Encoding.UTF8.GetBytes(parameters.Algorithm));
            writer.Write(nonce.Length / 64); writer.Write(count); writer.Write(width);
            byte[] indices = new byte[12]; BinaryPrimitives.WriteInt64BigEndian(indices, index);
            BinaryPrimitives.WriteUInt32BigEndian(indices.AsSpan(8), (uint)block); writer.Write(indices);
            writer.Write(nonce, block * 64, 64); writer.Flush(); result.Write(ReferenceSha3(encoded.ToArray()));
        }
        return result.ToArray()[..width];
    }

    internal static Task CompositionAsync()
    {
        // Bouncy Castle is independent of the production Crypto++/reference
        // CTR engines. The outer XChaCha adapter is separately validated by
        // published vectors and libsodium/Go in the native test inventory.
        byte[] key = Bytes(256, 13, 17), nonce = Bytes(232, 29, 7), tweak = Bytes(16, 43, 3);
        byte[] aad = Bytes(36, 7, 19);
        foreach (int length in new[] { 0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 65537 })
        {
            byte[] plain = Bytes(length, 19, 11);
            var aes = new Org.BouncyCastle.Crypto.Engines.AesEngine();
            aes.Init(true, new KeyParameter(key[..32]));
            byte[] aesOutput = ReferenceCtr(aes, nonce[..16], plain);
            byte[] native = new byte[length];
            NativeAes.XCryptCtr256(key[..32], nonce[..16], plain, native, length);
            Require(native.SequenceEqual(aesOutput), "Independent AES stage differs.");
            var kalyna = new Org.BouncyCastle.Crypto.Engines.Dstu7624Engine(512);
            kalyna.Init(true, new KeyParameter(key[32..96]));
            byte[] kalynaOutput = ReferenceCtr(kalyna, nonce[16..80], aesOutput);
            NativeKalyna.XCryptCtr512(key[32..96], nonce[16..80], aesOutput, native, length);
            Require(native.SequenceEqual(kalynaOutput), "Independent Kalyna stage differs.");
            var threefish = new Org.BouncyCastle.Crypto.Engines.ThreefishEngine(1024);
            threefish.Init(true, new TweakableBlockCipherParameters(new KeyParameter(key[96..224]), tweak));
            byte[] threefishOutput = ReferenceCtr(threefish, nonce[80..208], kalynaOutput);
            NativeThreefish.XCryptCtr1024(key[96..224], tweak, nonce[80..208], kalynaOutput, native, length);
            Require(native.SequenceEqual(threefishOutput), "Independent Threefish stage differs.");
            byte[] expected = new byte[length], tag = new byte[16], actual = new byte[length], actualTag = new byte[16];
            NativeXChaChaPoly.Encrypt(key[224..256], nonce[208..232], aad, threefishOutput, expected, length, tag);
            KalynaContainerService.EncryptSuiteChunkForTests(EncryptionSuiteCatalog.Get(EncryptionSuite.StandardCascade), key, tweak, nonce, plain, actual, length, aad, actualTag);
            Require(actual.SequenceEqual(expected) && actualTag.SequenceEqual(tag), "Standard slicing/composition differs from independent staged path.");
        }
        return Task.CompletedTask;
    }

    private static byte[] ReferenceCtr(Org.BouncyCastle.Crypto.IBlockCipher cipher, byte[] counter, byte[] input)
    {
        byte[] output = new byte[input.Length], block = new byte[counter.Length];
        for (int start = 0; start < input.Length; start += counter.Length)
        {
            cipher.ProcessBlock(counter, 0, block, 0);
            for (int i = 0; i < Math.Min(counter.Length, input.Length - start); ++i) output[start + i] = (byte)(input[start + i] ^ block[i]);
            for (int index = counter.Length - 1; index >= 0 && ++counter[index] == 0; --index) { }
        }
        return output;
    }

    private static async Task DefaultApiAsync()
    {
        string directory = Directory.CreateTempSubdirectory("keepvault-v13-default-").FullName;
#if KEEPVAULT_MACOS
        directory = MacSafeFileSystem.ResolveExistingRealPath(directory);
#endif
        try
        {
            using IDisposable memory = V13MasterKdf.UseMemoryCostForTests(8192);
            var service = new KalynaContainerService();
            for (int option = 0; option < 3; ++option)
            {
                int sample = 0;
                while (Enum.GetValues<EntropyPurpose>().Any(p => !EntropyMixer.HasRequiredSamples(p)))
                {
                    EntropyMixer.AddMouseSample(100.125 + sample * 0.003, 200.875 + sample * 0.007,
                        Environment.TickCount ^ sample, (sample & 1) != 0, (sample & 2) != 0, (sample & 4) != 0);
                    ++sample;
                }
                using var input = new MemoryStream(Bytes(37, 13, 7));
                string path = Path.Combine(directory, $"{option}.kzpaq");
                if (option == 0)
                    await service.EncryptZpaqStreamAsync(input, path, Password, Pin, FactorA, FactorB, null, null, CancellationToken.None);
                else if (option == 1)
                    await service.EncryptZpaqStreamWithProfileAsync(input, path, Password, Pin, FactorA, FactorB, Argon2ExecutionProfile.Default, null, null, CancellationToken.None);
                else
                    await service.EncryptZpaqStreamAsync(input, path, Password, Pin, FactorA, FactorB, EncryptionSuite.Kalyna512_512, null, null, CancellationToken.None);
                KalynaContainerInfo info = await service.ReadContainerInfoAsync(path, CancellationToken.None);
                Require(info.Version == 13 && info.Suite == (option == 2 ? EncryptionSuite.Kalyna512_512 : EncryptionSuite.StandardCascade), "Default overload or explicit suite changed.");
            }
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    private static async Task HeaderAsync()
    {
        await WithFixtureAsync(31, async (path, payload) =>
        {
            byte[] bytes = await File.ReadAllBytesAsync(path); JsonObject header = Header(bytes);
            Require(header["Version"]!.GetValue<int>() == 13 && header["Algorithm"]!.GetValue<string>() == Algorithm, "Writer did not create v13 standard.");
            Require(header["NonceBits"]!.GetValue<int>() == 2560 && Convert.FromBase64String(header["Nonce"]!.GetValue<string>()).Length == 320
                && header["NonceDerivationMode"]!.GetValue<string>() == "Seed320-Blockwise64-SHA3-512-ActivePrefix-v3", "Header nonce width mismatch.");
            Require(header["EncryptionKeyBits"]!.GetValue<int>() == 2048 && header["MasterKeyBits"]!.GetValue<int>() == 1024, "Key width is confused with master width.");
            Require(header["SecondNonce"] is null && header["SaltSha3Round2"] is null && header["SaltSkeinRound2"] is null && header["SecondNonceBits"]!.GetValue<int>() == 0, "Standard incorrectly created a second round.");
            Require((await new KalynaContainerService().ReadContainerInfoAsync(path, CancellationToken.None)).Suite == EncryptionSuite.StandardCascade, "Reader did not identify standard.");
        });
    }

    private static async Task FramingAsync()
    {
        foreach (int length in new[] { 1, ChunkBytes - 1, ChunkBytes, ChunkBytes + 1, 2 * ChunkBytes + 1 })
        {
            await WithFixtureAsync(length, async (path, payload) =>
            {
                byte[] bytes = await File.ReadAllBytesAsync(path);
                int bodyOffset = 11 + BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(7)) + 192;
                int chunks = (length + ChunkBytes - 1) / ChunkBytes;
                Require(bytes.Length - bodyOffset == length + chunks * 16, "Exactly one tag per chunk is required.");
                using var restored = new MemoryStream();
                await new KalynaContainerService().DecryptToStreamAsync(path, Password, Pin, FactorA, FactorB, restored, null, CancellationToken.None);
                Require(restored.ToArray().SequenceEqual(payload), "Short-read/boundary framing failed.");
            });
        }
    }

    private static async Task NoLegacyAsync()
    {
        await WithFixtureAsync(37, async (path, payload) =>
        {
            byte[] original = await File.ReadAllBytesAsync(path);
            var mutations = new Action<JsonObject>[]
            {
                h => h["Version"] = 12, h => h["Version"] = 14,
                h => h["Algorithm"] = "Threefish-1024-CTR(Kalyna-512/512-CTR)+HMAC-SHA3-512+Skein-MAC-1024",
                h => h["Algorithm"] = Algorithm.Replace("XChaCha", "ChaCha", StringComparison.Ordinal),
                h => h["KdfInputMode"] = V13MasterKdf.KdfInputMode.Replace("v13", "v12", StringComparison.Ordinal),
                h => { h["Nonce"] = Convert.ToBase64String(new byte[192]); h["NonceBits"] = 1536; },
                h => { h["Nonce"] = Convert.ToBase64String(new byte[232]); h["NonceBits"] = 1856; },
                h => h["NonceDerivationMode"] = "Seed320-SHA3-512-ChunkBlocks-v1",
                h => h["NonceDerivationMode"] = "Seed320-Blockwise64-SHA3-512+AllBlocks-StageProjection-v2",
                h => h.Remove("NonceDerivationMode"),
                h => h["Nonce"] = "invalid base64!", h => h["Extra"] = 1,
            };
            foreach (Action<JsonObject> mutate in mutations)
            {
                JsonObject header = Header(original); mutate(header);
                await File.WriteAllBytesAsync(path, ReplaceHeader(original, header));
                await ThrowsAsync<InvalidDataException>(() => new KalynaContainerService().ReadContainerInfoAsync(path, CancellationToken.None));
            }
        });
    }

    private static async Task TamperAsync()
    {
        await WithFixtureAsync(127, async (path, payload) =>
        {
            byte[] original = await File.ReadAllBytesAsync(path);
            int headerLength = BinaryPrimitives.ReadInt32LittleEndian(original.AsSpan(7)); int macOffset = 11 + headerLength;
            foreach (int byteIndex in new[] { macOffset, macOffset + 64, macOffset + 192, original.Length - 1 })
            {
                byte[] changed = (byte[])original.Clone(); changed[byteIndex] ^= 1;
                await File.WriteAllBytesAsync(path, changed); using var destination = new MemoryStream();
                await ThrowsAsync<CryptographicException>(() => new KalynaContainerService().DecryptToStreamAsync(path, Password, Pin, FactorA, FactorB, destination, null, CancellationToken.None));
                Require(destination.Length == 0, "Failed global authentication released plaintext.");
            }
            // Locally invalid AEAD with genuine recomputed global MACs reaches the local tag gate.
            byte[] corrupted = (byte[])original.Clone(); corrupted[^1] ^= 1;
            JsonObject h = Header(original);
            byte[] sha3Salt = Convert.FromBase64String(h["SaltSha3Round1"]!.GetValue<string>());
            byte[] skeinSalt = Convert.FromBase64String(h["SaltSkeinRound1"]!.GetValue<string>());
            byte[] qs = V13MasterKdf.DeriveSha3CredentialHash(Algorithm, Password, Pin, Convert.FromHexString(FactorA), Convert.FromHexString(FactorB));
            byte[] qk = V13MasterKdf.DeriveSkeinCredentialHash(Algorithm, Password, Pin, Convert.FromHexString(FactorA), Convert.FromHexString(FactorB));
            (_, uint memory) = V13MasterKdf.DerivePmi(Algorithm, 1, qs, qk, [], sha3Salt, skeinSalt);
            byte[] master = V13MasterKdf.DeriveRoundMaster(Algorithm, 1, qs, qk, sha3Salt, skeinSalt, null, memory);
            using RoleKeyMaterial keys = SuiteKeySchedule.DeriveSuiteKeys(master, EncryptionSuiteCatalog.Get(EncryptionSuite.StandardCascade));
            using var stream = new MemoryStream(corrupted);
            (byte[] sha, byte[] skein) = await ParallelContainerAuthenticator.ComputeAsync(stream, macOffset + 192,
                ["KZPAQ2\0"u8.ToArray(), original.AsSpan(7, 4).ToArray(), original.AsSpan(11, headerLength).ToArray()], keys.Sha3MacKey.Bytes, keys.SkeinMacKey.Bytes, CancellationToken.None);
            sha.CopyTo(corrupted, macOffset); skein.CopyTo(corrupted, macOffset + 64);
            await File.WriteAllBytesAsync(path, corrupted); using var localDestination = new MemoryStream();
            await ThrowsAsync<CryptographicException>(() => new KalynaContainerService().DecryptToStreamAsync(path, Password, Pin, FactorA, FactorB, localDestination, null, CancellationToken.None));
            Require(localDestination.Length == 0, "Failed local tag verification released plaintext.");
            foreach (byte[] secret in new[] { qs, qk, master, sha, skein }) CryptographicOperations.ZeroMemory(secret);
        });
    }

    private static async Task WithFixtureAsync(int length, Func<string, byte[], Task> test)
    {
        string directory = Path.Combine(Path.GetTempPath(), "keepvault-v13-standard-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
#if KEEPVAULT_MACOS
        directory = MacSafeFileSystem.ResolveExistingRealPath(directory);
#endif
        try
        {
            using IDisposable memory = V13MasterKdf.UseMemoryCostForTests(8192);
            using GeneratedArchiveEntropy entropy = CreateEntropy();
            byte[] payload = Bytes(length, 43, 13);
            using var input = new ShortReadStream(payload);
            string path = Path.Combine(directory, "standard.kzpaq");
            await new KalynaContainerService().EncryptZpaqStreamWithPreparedEntropyAsync(input, path, Password, Pin,
                FactorA, FactorB, EncryptionSuite.StandardCascade, entropy, "v13-test", null, CancellationToken.None);
            await test(path, payload);
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    private static GeneratedArchiveEntropy CreateEntropy()
    {
        var salt1 = LockedSensitiveBuffer.Create(128); var salt2 = LockedSensitiveBuffer.Create(128);
        var nonce1 = LockedSensitiveBuffer.Create(320); var nonce2 = LockedSensitiveBuffer.Create(320);
        Bytes(128, 29, 23).CopyTo(salt1.Bytes, 0); Bytes(128, 61, 161).CopyTo(salt2.Bytes, 0);
        Bytes(320, 43, 43).CopyTo(nonce1.Bytes, 0); Bytes(320, 73, 211).CopyTo(nonce2.Bytes, 0);
        return new GeneratedArchiveEntropy(FactorA, FactorB, salt1, nonce1, salt2, nonce2);
    }

    private static JsonObject Header(byte[] bytes) => JsonNode.Parse(bytes.AsSpan(11, BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(7))))!.AsObject();
    private static byte[] ReplaceHeader(byte[] original, JsonObject header)
    {
        byte[] replacement = JsonSerializer.SerializeToUtf8Bytes(header); int originalLength = BinaryPrimitives.ReadInt32LittleEndian(original.AsSpan(7));
        byte[] bytes = [.. original.AsSpan(0, 7), .. new byte[4], .. replacement, .. original.AsSpan(11 + originalLength)];
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(7), replacement.Length); return bytes;
    }
    private static byte[] Bytes(int length, int multiplier, int seed) => Enumerable.Range(0, length).Select(i => unchecked((byte)(i * multiplier + seed))).ToArray();
    private static void Lp(BinaryWriter writer, byte[] data) { writer.Write(data.Length); writer.Write(data); }
    private static byte[] ReferenceSha3(byte[] bytes) { var digest = new Sha3Digest(512); digest.BlockUpdate(bytes); byte[] result = new byte[64]; digest.DoFinal(result); return result; }
    private static object? Invoke(string name, params object[] args)
    {
        try { return typeof(KalynaContainerService).GetMethod(name, BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, args); }
        catch (TargetInvocationException failure) when (failure.InnerException is not null) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure.InnerException).Throw(); throw; }
    }
    private static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private static void Throws<T>(Action action) where T : Exception { try { action(); } catch (T) { return; } throw new InvalidOperationException($"Expected {typeof(T).Name}."); }
    private static async Task ThrowsAsync<T>(Func<Task> action) where T : Exception { try { await action(); } catch (T) { return; } throw new InvalidOperationException($"Expected {typeof(T).Name}."); }
    private sealed class ShortReadStream(byte[] bytes) : MemoryStream(bytes, writable: false)
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default) => base.ReadAsync(buffer[..Math.Min(65521, buffer.Length)], token);
    }
}
