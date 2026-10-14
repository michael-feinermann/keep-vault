using System.Security.Cryptography;
using System.Text.Json;
using KalynaArchiver.Services;

/// <summary>ActivePrefix-v3 contract, independently encoded public vectors and fault boundaries.</summary>
internal static class V13NonceTests
{
    internal static IReadOnlyList<TestCase> Tests =>
    [
        new("v13-nonce-vectors", "V13-NONCE-TRANSCRIPT: 84 independent Python vectors and 64-bit indices", VectorsAsync, TestResource.Light, "V13"),
        new("v13-nonce-plan", "V13-NONCE-PLAN/SLICES: twelve catalog widths and eight-stage Paranoia", PlanAsync, TestResource.Light, "V13"),
        new("v13-nonce-isolation", "V13-NONCE-BLOCK-ISOLATION/RESERVE: active input bits and all reserved bytes", IsolationAsync, TestResource.CpuHeavy, "V13"),
        new("v13-nonce-capacity", "V13-NONCE-CAPACITY/FUTURE-B2: isolated trusted layouts up to ten blocks", CapacityAsync, TestResource.Light, "V13"),
        new("v13-nonce-faults", "V13-NONCE-HASHCOUNT/FAULTS: exact jobs, overlap, cancellation and partial cleanup", FaultsAsync, TestResource.Light, "V13"),
    ];

    private static Task VectorsAsync()
    {
        string path = Path.Combine(RepositoryLayout.FindRepositoryRoot(), "KeepVaultMac.Tests", "Fixtures", "V13Reference", "nonce_rev6_public_vectors.json");
        byte[] frozen = File.ReadAllBytes(path);
        Require(Convert.ToHexString(SHA256.HashData(frozen)) == "AC9D8078DE8E1B410E1BCE6E4F1F1B7110081B3044777090FE897D2E977A7C7C",
            "Frozen public fixture changed; validation never regenerates expected values.");
        using JsonDocument document = JsonDocument.Parse(frozen);
        Require(document.RootElement.GetProperty("mode").GetString() == EncryptionSuiteCatalog.NonceDerivationMode, "Nonce mode differs from the independent reference.");
        int cases = 0;
        foreach (JsonElement item in document.RootElement.GetProperty("cases").EnumerateArray())
        {
            EncryptionSuiteParameters p = EncryptionSuiteCatalog.Get((EncryptionSuite)item.GetProperty("suite_id").GetInt32());
            Require(p.Algorithm == item.GetProperty("algorithm").GetString(), "The independently registered algorithm differs.");
            ChunkNoncePlan plan = ChunkNoncePlan.Create(p);
            byte[] basis = Convert.FromHexString(item.GetProperty("basis_hex").GetString()!);
            byte[] actual = new byte[plan.ActiveBytes];
            plan.DeriveActiveNonceBlocks(basis, item.GetProperty("chunk_index").GetInt64(), actual);
            Require(actual.SequenceEqual(Convert.FromHexString(item.GetProperty("active_rotated_hex").GetString()!)), "Active nonce blocks differ from Python hashlib.");
            byte[] stage = new byte[p.StageNonceBytes];
            plan.DeriveStageNonce(basis, item.GetProperty("chunk_index").GetInt64(), stage);
            Require(stage.SequenceEqual(Convert.FromHexString(item.GetProperty("stage_buffer_hex").GetString()!)), "The stage prefix differs from the independent reference.");
            int offset = 0;
            foreach (JsonElement expected in item.GetProperty("stage_nonce_hex").EnumerateArray())
            {
                byte[] bytes = Convert.FromHexString(expected.GetString()!);
                Require(stage.AsSpan(offset, bytes.Length).SequenceEqual(bytes), "A stage slice changed."); offset += bytes.Length;
            }
            Require(offset == stage.Length, "Stage slices do not cover the entire active prefix.");
            ++cases;
        }
        Require(cases == 84, "Independent fixture inventory must contain all 12 suites and seven indices.");
        return Task.CompletedTask;
    }

    private static Task PlanAsync()
    {
        int[] widths = [64,128,232,312,40,16,16,32,24,168,16,16];
        int[] blocks = [1,2,4,5,1,1,1,1,1,3,1,1];
        foreach (EncryptionSuite suite in EncryptionSuiteCatalog.DisplayOrder)
        {
            EncryptionSuiteParameters p = EncryptionSuiteCatalog.Get(suite); ChunkNoncePlan plan = ChunkNoncePlan.Create(p);
            Require(p.ArchiveNonceBytes == 320 && p.StageNonceBytes == widths[(int)suite]
                && p.ActiveNonceBlockCount == blocks[(int)suite] && plan.ActiveBlocks == blocks[(int)suite]
                && plan.BasisBytes == (suite == EncryptionSuite.ParanoiaCascade ? 640 : 320), "Catalog storage/active widths differ.");
            Require(p.ReservedNonceBlockCount == plan.CapacityBlocks - plan.ActiveBlocks, "Reserve count differs.");
            Throws<ArgumentException>(() => ChunkNoncePlan.Create(p with { }));
        }
        EncryptionSuiteParameters paranoia = EncryptionSuiteCatalog.Get(EncryptionSuite.ParanoiaCascade);
        Require(paranoia.Cascade!.Stages.Select(s => s.Cipher).SequenceEqual(new[] {
            CascadeCipher.Aes256, CascadeCipher.Mars448, CascadeCipher.Camellia256, CascadeCipher.Serpent256,
            CascadeCipher.Shacal2_512, CascadeCipher.Kalyna512_512, CascadeCipher.Threefish1024, CascadeCipher.XChaCha20Poly1305 })
            && paranoia.EncryptionKeyBytes == 440 && paranoia.DerivedKeyBytes == 632
            && KalynaContainerService.FindThreefishStageIndex(paranoia) == 6, "Paranoia eight-stage order or role offsets differ.");
        Require(SuiteKeySchedule.CanonicalCipherString(CascadeCipher.Camellia256) == "Camellia-256"
            && SuiteKeySchedule.CanonicalCipherString(CascadeCipher.Serpent256) == "Serpent-256", "New role labels differ.");
        return Task.CompletedTask;
    }

    private static Task IsolationAsync()
    {
        foreach (EncryptionSuite suite in EncryptionSuiteCatalog.DisplayOrder)
        {
            EncryptionSuiteParameters p = EncryptionSuiteCatalog.Get(suite); ChunkNoncePlan plan = ChunkNoncePlan.Create(p);
            byte[] basis = Enumerable.Range(0, plan.BasisBytes).Select(i => (byte)(i * 29 + 7)).ToArray();
            byte[] original = new byte[plan.ActiveBytes]; plan.DeriveActiveNonceBlocks(basis, 65536, original);
            byte[] baselineAad = KalynaContainerService.BuildChunkAssociatedData(p, basis, 65536, 113);
            bool allBits = suite is EncryptionSuite.StandardCascade or EncryptionSuite.ParanoiaCascade;
            for (int position = 0; position < basis.Length; ++position)
            for (int bit = 0; bit < (allBits && position < plan.ActiveBytes ? 8 : 1); ++bit)
            {
                basis[position] ^= (byte)(1 << bit);
                byte[] changed = new byte[plan.ActiveBytes]; plan.DeriveActiveNonceBlocks(basis, 65536, changed);
                for (int block = 0; block < plan.ActiveBlocks; ++block)
                {
                    bool same = original.AsSpan(block * 64, 64).SequenceEqual(changed.AsSpan(block * 64, 64));
                    Require(same == (position / 64 != block), "Block-local active nonce derivation read another block or ignored an active byte.");
                }
                if (position >= plan.ActiveBytes)
                    Require(!baselineAad.SequenceEqual(KalynaContainerService.BuildChunkAssociatedData(p, basis, 65536, 113)), "AAD failed to bind reserved basis bytes.");
                basis[position] ^= (byte)(1 << bit);
            }
        }
        return Task.CompletedTask;
    }

    private static Task CapacityAsync()
    {
        foreach (bool two in new[] { false, true })
        foreach (int width in new[] { 1,16,24,32,63,64,65,128,129,231,232,233,255,256,257,311,312,313,319,320,321,383,384,385,448,512,576,639,640,641 })
        {
            int capacity = two ? 640 : 320;
            if (width > capacity) { Throws<ArgumentException>(() => ChunkNoncePlan.CreateCapacityPlanForTests(width, two)); continue; }
            ChunkNoncePlan plan = ChunkNoncePlan.CreateCapacityPlanForTests(width, two);
            Require(plan.ActiveBlocks == 1 + (width - 1) / 64, "Trusted capacity plan rounded per stage instead of per total.");
            byte[] basis = new byte[capacity]; byte[] active = new byte[plan.ActiveBytes]; int hashes = 0;
            plan.DeriveActiveNonceBlocks(basis, long.MaxValue, active, beforeHashForTests: _ => ++hashes);
            Require(hashes == plan.ActiveBlocks, "A reserve block was hashed or an active block was skipped.");
            byte[] guarded = Enumerable.Repeat((byte)0xA5, width + 2).ToArray();
            plan.DeriveStageNonce(basis, long.MaxValue, guarded.AsSpan(1, width));
            Require(guarded[0] == 0xA5 && guarded[^1] == 0xA5 && guarded.AsSpan(1,width).SequenceEqual(active.AsSpan(0,width)), "Nonce output crossed its exact valid prefix.");
            for (int block = 0; block < plan.CapacityBlocks; ++block)
            {
                basis[block * 64 + 63] ^= 1;
                byte[] changed = new byte[plan.ActiveBytes]; plan.DeriveActiveNonceBlocks(basis, long.MaxValue, changed);
                Require(changed.SequenceEqual(active) == (block >= plan.ActiveBlocks), "Future B2 activation or reserve handling differs.");
                basis[block * 64 + 63] ^= 1;
            }
        }
        Throws<ArgumentOutOfRangeException>(() => ChunkNoncePlan.CreateCapacityPlanForTests(0, false));
        return Task.CompletedTask;
    }

    private static async Task FaultsAsync()
    {
        foreach (EncryptionSuite suite in EncryptionSuiteCatalog.DisplayOrder)
        {
            var p = EncryptionSuiteCatalog.Get(suite); var plan = ChunkNoncePlan.Create(p);
            byte[] basis = new byte[plan.BasisBytes], output = new byte[plan.ActiveBytes]; int count = 0;
            plan.DeriveActiveNonceBlocks(basis, 0, output, beforeHashForTests: j => Require(j == count++, "Jobs were duplicated or reordered."));
            Require(count == plan.ActiveBlocks, "Hash count differs from k.");
            for (int fail = 0; fail < plan.ActiveBlocks; ++fail)
            {
                Array.Fill(output, (byte)0xA5);
                Throws<IOException>(() => plan.DeriveActiveNonceBlocks(basis, 0, output, beforeHashForTests: j => { if(j == fail) throw new IOException("synthetic hash failure"); }));
                Require(output.AsSpan().IndexOfAnyExcept((byte)0) < 0, "Failed hash left a partial nonce output.");
            }
            Throws<ArgumentException>(() => plan.DeriveActiveNonceBlocks(basis, 0, basis.AsSpan(0, plan.ActiveBytes)));
            Throws<ArgumentException>(() => plan.DeriveActiveNonceBlocks(basis.AsSpan(1), 0, output));
            Throws<ArgumentException>(() => plan.DeriveActiveNonceBlocks(basis, 0, output.AsSpan(1)));
            Throws<ArgumentOutOfRangeException>(() => plan.DeriveActiveNonceBlocks(basis, -1, output));
            using var cancel = new CancellationTokenSource(); cancel.Cancel();
            Throws<OperationCanceledException>(() => plan.DeriveActiveNonceBlocks(basis, 0, output, cancel.Token));
            Require(output.AsSpan().IndexOfAnyExcept((byte)0) < 0, "Cancelled nonce computation left output.");
            byte[] expected = new byte[plan.ActiveBytes]; plan.DeriveActiveNonceBlocks(basis, 262144, expected);
            byte[][] ordered = await Task.WhenAll(Enumerable.Range(0, 7).Reverse().Select(_ => Task.Run(() => { byte[] actual = new byte[plan.ActiveBytes]; plan.DeriveActiveNonceBlocks(basis, 262144, actual); return actual; })));
            Require(ordered.All(actual => actual.SequenceEqual(expected)), "Nonce derivation depends on order, thread or mutable previous state.");
        }
    }

    private static void Require(bool value, string message) { if (!value) throw new InvalidOperationException(message); }
    private static void Throws<T>(Action action) where T : Exception { try { action(); } catch (T) { return; } throw new InvalidOperationException($"Expected {typeof(T).Name}."); }
}
