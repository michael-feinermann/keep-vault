using System.Security.Cryptography;
using KalynaArchiver.Services;
using KalynaArchiver.Signing;

internal static partial class Rev11VerifiedInputTests
{
    internal static IReadOnlyList<TestCase> Tests =>
    [
        new("fuzz.rev11-original-reader-10000", "10000 seeded fused original-reader cases with private-slice canaries", FusedFuzzAsync, TestResource.ProcessGlobal, "Security"),
        new("fuzz.rev11-range-index-10000", "10000 seeded identical public records across RAM/file/migrated backends", IndexFuzzAsync, TestResource.ProcessGlobal, "Security"),
        new("io.rev11-input-fused", "V13-INPUT-FUSED: unchanged global transcript from one physical original pass", FusedAsync, TestResource.ProcessGlobal, "Security"),
        new("io.rev11-index-ram-small", "V13-INDEX-RAM-SMALL: absent unused workspace and lazy resident records", SmallAsync, TestResource.ProcessGlobal, "Security"),
        new("io.rev11-index-cache-boundary", "V13-INDEX-SPILL: actual 16-MiB shared cache threshold minus/at/plus one byte", CacheBoundaryAsync, TestResource.ProcessGlobal, "Security"),
        new("io.rev11-index-identical", "V13-INDEX-IDENTICAL: fixed public keys, one/two workers and RAM/file produce the same 204-byte records", IdenticalAsync, TestResource.ProcessGlobal, "Security"),
        new("io.rev11-index-spill", "V13-INDEX-SPILL/IDENTICAL: shared resident quota, exact migration and missing-volume rejection", SpillAsync, TestResource.ProcessGlobal, "Security"),
        new("io.rev11-header-binding", "V13-INPUT-HEADER-BIND: preflight header and stored tags cannot change during KDF", HeaderBindingAsync, TestResource.ProcessGlobal, "Security"),
        new("io.rev11-repair-erasures", "V13-REPAIR-ERASURES: frozen unreadable regions cannot grant normal authenticity or widen later", RepairErasuresAsync, TestResource.ProcessGlobal, "Security"),
        new("io.rev11-repair-capability", "V13-REPAIR-CAPABILITY: local ciphertext seal cannot authorize normal consumption", RepairAsync, TestResource.ProcessGlobal, "Security"),
    ];

    private static async Task FusedAsync()
    {
        foreach (int bodyBytes in new[] { 1, 1024, (1 << 20) - 1, (1 << 20) + 1, (16 << 20) - 1, (16 << 20) + 1 })
        using (var f = new Fixture(bodyBytes))
        {
            await f.PrepareAsync();
            using VerifiedArchiveInput input = await VerifiedArchiveInput.BindEncryptedAsync(f.Path, f.Policy, default);
            Require(input.FirstPassBytesForTests == 0 && input.ResidentIndexBytes == 0 && input.DiskIndexBytes == 0, "Bind performed full I/O or eager index allocation.");
            await input.VerifyGloballyAsync(f.AuthenticateAsync, default);
            Require(input.FirstPassBytesForTests == f.Bytes.Length, "The fused verifier performed a missing or duplicate physical range read.");
            Require(input.State == VerifiedArchiveInputState.Verified, "Both global transcripts did not publish the verified state.");
            byte[] actual = new byte[f.Bytes.Length];
            for (int offset = 0; offset < actual.Length; offset += 65521)
                await input.ReadExactlyAsync(actual.AsMemory(offset, Math.Min(65521, actual.Length - offset)));
            Require(actual.AsSpan().SequenceEqual(f.Bytes), "Second-pass private slices differ from the complete source.");
            Require(input.SecondPassBytesForTests == f.Bytes.Length,
                "Fragmented sequential consumption reread full physical ranges instead of using its private verified buffer lease.");
            using VerifiedArchiveInput conservative = await VerifiedArchiveInput.CaptureOriginalAsync(f.Path, f.Policy, default);
            await conservative.VerifyGloballyAsync(f.AuthenticateAsync, default);
            byte[] comparison = new byte[actual.Length]; await conservative.ReadExactlyAsync(comparison);
            Require(comparison.AsSpan().SequenceEqual(actual), "Copy-free conservative and fused paths disagree.");
            Require(input.DiskIndexBytes == 0 && !Directory.Exists(f.Workspace), "A normal small input created a working object.");
        }
    }

    private static async Task SmallAsync()
    {
        using var f = new Fixture(1024); await f.PrepareAsync();
        using VerifiedArchiveInput input = await VerifiedArchiveInput.BindPlainAsync(f.Path, f.Policy, default);
        await input.VerifyPlainIntegrityAsync(async (view, token) =>
        {
            (byte[] sha3, byte[] skein) = await IntegrityService.HashStreamAsync(view, token);
            return new(Sha3_512Compat.HashData(f.Bytes), sha3, Skein1024Digest.HashData(f.Bytes), skein);
        }, default);
        Require(input.State == VerifiedArchiveInputState.PlainIntegrityVerified, "Plain hashes acquired encrypted-container authenticity.");
        Require(input.ResidentIndexBytes == 204 && input.DiskIndexBytes == 0 && !Directory.Exists(f.Workspace),
            "A one-range file did not use exactly its small record allocation without a workspace.");
        using var table = new RecoveryRecordTable<string>(f.Policy);
        string digest = Convert.ToBase64String(new byte[64]) + ":" + Convert.ToBase64String(new byte[128]);
        table.Add(digest);
        Require(table[0] == digest && !Directory.Exists(f.Workspace), "A small recovery manifest accessed the unused workspace.");
    }

    private static Task SpillAsync()
    {
        using var f = new Fixture(1, availableWorkspace: true);
        long? previous = RecoveryMetadataBudget.ResidentLimitForTests.Value;
        RecoveryMetadataBudget.ResidentLimitForTests.Value = 20_000;
        try
        {
            // Each fresh scope gets one shared resident ceiling, not one per table.
            using IDisposable metadata = RecoveryMetadataBudget.Begin(1 << 20);
            RecoveryMetadataBudget budget = RecoveryMetadataBudget.Capture(1 << 20);
            using var first = new AuthenticatedRangeIndex(f.Policy, budget);
            using var sibling = new AuthenticatedRangeIndex(f.Policy, budget);
            byte[] records = Enumerable.Range(0, 40_000).Select(i => (byte)(i * 31)).ToArray();
            first.WriteAt(records.AsSpan(0, 16000), 0);
            Require(first.ResidentBytes == 16384 && first.DiskBytes == 0, "First lazy segment is not bounded.");
            sibling.WriteAt(records.AsSpan(0, 1000), 0);
            Require(sibling.ResidentBytes == 0 && sibling.DiskBytes == 1000, "Nested metadata multiplied the common cache ceiling.");
            first.WriteAt(records.AsSpan(16000), 16000);
            first.Seal();
            byte[] actual = new byte[records.Length]; first.ReadExactlyAt(actual, 0);
            Require(first.ResidentBytes == 0 && first.DiskBytes == records.Length && actual.AsSpan().SequenceEqual(records),
                "Spill changed original records or retained a second RAM copy.");
            Require(Directory.GetFiles(f.Workspace).Length == 0, "An index retained a public filename.");
        }
        finally { RecoveryMetadataBudget.ResidentLimitForTests.Value = previous; }
        using var missing = new Fixture(1);
        bool disk = AuthenticatedRangeIndex.ForceDiskForTests.Value;
        AuthenticatedRangeIndex.ForceDiskForTests.Value = true;
        try
        {
            using var index = new AuthenticatedRangeIndex(missing.Policy, RecoveryMetadataBudget.Capture(1 << 20), 204);
            ExpectFailure(() => index.WriteAt(new byte[204], 0));
            Require(!Directory.Exists(missing.Workspace), "Missing explicit volume silently fell back or was created.");
        }
        finally { AuthenticatedRangeIndex.ForceDiskForTests.Value = disk; }
        return Task.CompletedTask;
    }

    private static Task CacheBoundaryAsync()
    {
        using var f = new Fixture(1, availableWorkspace: true);
        long? previous = RecoveryMetadataBudget.ResidentLimitForTests.Value;
        RecoveryMetadataBudget.ResidentLimitForTests.Value = 16L << 20;
        try
        {
            long limit = 16L << 20, low = 0, high = limit;
            while (low < high)
            {
                long middle = low + (high - low + 1) / 2;
                long segments = middle / 16384 + (middle % 16384 == 0 ? 0 : 1);
                if (middle + segments * 128 <= limit) low = middle; else high = middle - 1;
            }
            foreach (long length in new[] { low - 1, low, low + 1 })
            {
                using IDisposable metadata = RecoveryMetadataBudget.Begin(64L << 20);
                RecoveryMetadataBudget budget = RecoveryMetadataBudget.Capture(64L << 20);
                using var index = new AuthenticatedRangeIndex(f.Policy, budget, length);
                byte[] block = Enumerable.Range(0, 65536).Select(x => (byte)(x * 31)).ToArray();
                for (long offset = 0; offset < length; offset += block.Length)
                    index.WriteAt(block.AsSpan(0, (int)Math.Min(block.Length, length - offset)), offset);
                index.Seal();
                Require(length <= low ? index.DiskBytes == 0 && index.ResidentBytes == length : index.ResidentBytes == 0 && index.DiskBytes == length,
                    "The shared cache threshold differs from actual payload and management charges.");
                byte[] read = new byte[block.Length];
                for (long offset = 0; offset < length; offset += block.Length)
                {
                    int count = (int)Math.Min(block.Length, length - offset);
                    index.ReadExactlyAt(read.AsSpan(0, count), offset);
                    Require(read.AsSpan(0, count).SequenceEqual(block.AsSpan(0, count)), "Cache-boundary spill changed bytes.");
                }
                Require(Directory.GetFiles(f.Workspace).Length == 0, "Cache spill retained a named object.");
            }
        }
        finally { RecoveryMetadataBudget.ResidentLimitForTests.Value = previous; }
        return Task.CompletedTask;
    }

    private static async Task IdenticalAsync()
    {
        byte[]? reference = null;
        foreach (int workers in new[] { 1, 2 })
        foreach (bool disk in new[] { false, true })
        {
            using var f = new Fixture((16 << 20) + 37, availableWorkspace: true, workers: workers); await f.PrepareAsync();
            AuthenticatedRangeIndex.ForceDiskForTests.Value = disk;
            using VerifiedArchiveInput input = await VerifiedArchiveInput.BindEncryptedAsync(f.Path, f.Policy, default);
            foreach ((string name, int start) in new[] { ("_operationId", 0), ("_hmacKey", 32), ("_skeinKey", 96) })
            {
                var key = (KalynaArchiver.Services.LockedSensitiveBuffer)typeof(VerifiedArchiveInput)
                    .GetField(name, System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!.GetValue(input)!;
                for (int at = 0; at < key.Bytes.Length; at++) key.Bytes[at] = (byte)(start + at);
            }
            await input.VerifyGloballyAsync(f.AuthenticateAsync, default);
            var index = (AuthenticatedRangeIndex)typeof(VerifiedArchiveInput)
                .GetField("_index", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!.GetValue(input)!;
            byte[] actual = new byte[checked((int)index.Length)]; index.ReadExactlyAt(actual, 0);
            if (reference is null) reference = actual;
            else Require(reference.AsSpan().SequenceEqual(actual), "Worker/backend selection changed a local record.");
            byte[] operationId = Enumerable.Range(0, 32).Select(x => (byte)x).ToArray();
            byte[] hmacKey = Enumerable.Range(32, 64).Select(x => (byte)x).ToArray();
            byte[] skeinKey = Enumerable.Range(96, 128).Select(x => (byte)x).ToArray();
            for (int record = 0; record < actual.Length / 204; record++)
            {
                int offset = record * VerifiedArchiveInput.RangeBytes, count = Math.Min(VerifiedArchiveInput.RangeBytes, f.Bytes.Length - offset);
                byte[] message = new byte[44 + count], expected = new byte[204];
                operationId.CopyTo(message, 0);
                System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(message.AsSpan(32), record);
                System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(message.AsSpan(40), count);
                f.Bytes.AsSpan(offset, count).CopyTo(message.AsSpan(44));
                System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(expected, record);
                System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(expected.AsSpan(8), count);
                VerifiedArchiveInput.ComputeLocalTags(hmacKey, skeinKey, message, expected.AsSpan(12));
                Require(actual.AsSpan(record * 204, 204).SequenceEqual(expected), "Range record differs from the independently assembled public transcript.");
                CryptographicOperations.ZeroMemory(message);
            }
        }
    }

    private static async Task HeaderBindingAsync()
    {
        foreach (int mutation in new[] { 0, Fixture.PrefixLength - 1, Fixture.PrefixLength, Fixture.HeaderLength - 1 })
        using (var f = new Fixture((1 << 20) + 37))
        {
            await f.PrepareAsync();
            using var writer = new FileStream(f.Path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete, 1);
            using VerifiedArchiveInput input = await VerifiedArchiveInput.BindEncryptedAsync(f.Path, f.Policy, default);
            bool rejected = false;
            try
            {
                await input.VerifyGloballyAsync(async (view, token) =>
                {
                    byte[] header = new byte[Fixture.HeaderLength]; await view.ReadExactlyAsync(header, token);
                    RandomAccess.Write(writer.SafeFileHandle, new byte[] { (byte)(f.Bytes[mutation] ^ 1) }, mutation);
                    return await f.AuthenticateFromHeaderAsync(view, header, token);
                }, default);
            }
            catch (Exception error) when (error is IOException or CryptographicException
                || error is AggregateException aggregate && aggregate.Flatten().InnerExceptions.All(e => e is IOException or CryptographicException)) { rejected = true; }
            Require(rejected && input.State == VerifiedArchiveInputState.Failed, "KDF used header A with globally verified source B.");
            Require(input.FirstPassBytesForTests <= VerifiedArchiveInput.RangeBytes, "A changed preflight caused a complete source pass.");
            ExpectFailure(() => input.ReadExactly(new byte[1]));
        }
    }

    private static async Task RepairAsync()
    {
        using var f = new Fixture(8192); await f.PrepareAsync();
        f.Bytes[0] ^= 0xFF; File.WriteAllBytes(f.Path, f.Bytes); // Deliberately not a valid container header.
        using VerifiedArchiveInput input = await VerifiedArchiveInput.CaptureForRepairAsync(f.Path, f.Policy, default);
        using VerifiedArchiveInput.RepairCiphertextRead repair = input.OpenRepairCiphertext();
        Require(input.State == VerifiedArchiveInputState.LocalCaptureSealed && !input.CanRead, "Repair acquired the normal consumer capability.");
        ExpectFailure(() => input.ReadExactly(new byte[1]));
        byte[] actual = new byte[f.Bytes.Length]; await repair.ReadExactlyAsync(actual);
        Require(actual.AsSpan().SequenceEqual(f.Bytes), "Damaged-header repair lost captured ciphertext bytes.");
        bool forbidden = false;
        try { await input.VerifyGloballyAsync(f.AuthenticateAsync, default); }
        catch (InvalidOperationException) { forbidden = true; }
        Require(forbidden, "The repair owner was reused as a verified candidate context.");
    }

    private static async Task RepairErasuresAsync()
    {
        using var f = new Fixture((1 << 20) + 8192); await f.PrepareAsync();
        Func<long, int, bool>? previous = VerifiedArchiveInput.RepairReadFaultForTests.Value;
        const long damagedOffset = 4096;
        try
        {
            VerifiedArchiveInput.RepairReadFaultForTests.Value = (offset, length) => offset < damagedOffset + 4096 && offset + length > damagedOffset;
            using VerifiedArchiveInput input = await VerifiedArchiveInput.CaptureForRepairAsync(f.Path, f.Policy, default);
            Require(input.CapturedUnreadableBlocks == 1, "Repair did not freeze exactly the unreadable block.");
            bool refused = false;
            try { await input.VerifyGloballyAsync(f.AuthenticateAsync, default); }
            catch (InvalidOperationException) { refused = true; }
            Require(refused && !input.CanRead, "Repair erasures authorized a global verifier.");
            using VerifiedArchiveInput.RepairCiphertextRead repair = input.OpenRepairCiphertext();
            byte[] actual = new byte[f.Bytes.Length]; await repair.ReadExactlyAsync(actual);
            byte[] expected = f.Bytes.ToArray(); expected.AsSpan((int)damagedOffset, 4096).Clear();
            Require(actual.AsSpan().SequenceEqual(expected), "Frozen repair erasures changed readable source bytes.");
            // A subsequent new I/O failure must poison the entire protected read,
            // never silently add a second erasure and manufacture a new MAC.
            VerifiedArchiveInput.RepairReadFaultForTests.Value = (offset, length) => offset < 16384 && offset + length > 12288;
            repair.Position = 0; Array.Fill(actual, (byte)0xAC);
            bool failed = false;
            try { await repair.ReadExactlyAsync(actual); }
            catch (IOException) { failed = true; }
            Require(failed && input.State == VerifiedArchiveInputState.Failed && actual.AsSpan().IndexOfAnyExcept((byte)0) < 0,
                "A later read error widened captured erasures or leaked a partial unverified read.");
        }
        finally { VerifiedArchiveInput.RepairReadFaultForTests.Value = previous; }
    }

    private static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private static void ExpectFailure(Action action)
    { try { action(); } catch (Exception e) when (e is IOException or InvalidOperationException or CryptographicException) { return; } throw new InvalidOperationException("Expected safe rejection."); }

    private sealed class Fixture : IDisposable
    {
        internal const int PrefixLength = 97, HeaderLength = PrefixLength + 192;
        private readonly string _root = System.IO.Path.Combine(MacSafeFileSystem.ResolveExistingRealPath(System.IO.Path.GetTempPath()), "rev11-reader-" + Guid.NewGuid().ToString("N"));
        internal string Path => System.IO.Path.Combine(_root, "original.fixture");
        internal string Workspace => System.IO.Path.Combine(_root, "explicit-workspace");
        internal byte[] Bytes { get; }
        internal ArchiveOperationPolicy Policy { get; }
        private readonly byte[] _sha3 = Enumerable.Range(0, 64).Select(i => (byte)i).ToArray();
        private readonly byte[] _skein = Enumerable.Range(0, 128).Select(i => (byte)(i + 64)).ToArray();
        private readonly IDisposable _scope;
        private readonly bool _disk;
        internal Fixture(int body, bool availableWorkspace = false, int workers = 0)
        {
            Directory.CreateDirectory(_root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            if (availableWorkspace) Directory.CreateDirectory(Workspace);
            _disk = AuthenticatedRangeIndex.ForceDiskForTests.Value; AuthenticatedRangeIndex.ForceDiskForTests.Value = false;
            Policy = new ArchiveOperationPolicy(Workspace, _root, maxContainerBytes: 32L << 20, maxCpuWorkers: workers, maxIoRequests: workers);
            _scope = Policy.EnterScope();
            Bytes = Enumerable.Range(0, body + HeaderLength).Select(i => (byte)(i * 13 + 7)).ToArray();
        }
        internal async Task PrepareAsync()
        {
            using var original = new MemoryStream(Bytes, writable: false);
            (byte[] h, byte[] s) = await ParallelContainerAuthenticator.ComputeAsync(original, HeaderLength,
                [Bytes.AsMemory(0, PrefixLength)], _sha3, _skein, default);
            h.CopyTo(Bytes, PrefixLength); s.CopyTo(Bytes, PrefixLength + 64);
            File.WriteAllBytes(Path, Bytes);
        }
        internal async Task<VerifiedArchiveAuthentication> AuthenticateAsync(Stream view, CancellationToken token)
        {
            byte[] header = new byte[HeaderLength]; await view.ReadExactlyAsync(header, token);
            return await AuthenticateFromHeaderAsync(view, header, token);
        }
        internal async Task<VerifiedArchiveAuthentication> AuthenticateFromHeaderAsync(Stream view, byte[] header, CancellationToken token)
        {
            VerifiedArchiveInput.BeginFusedAuthentication(view, HeaderLength);
            (byte[] h, byte[] s) = await ParallelContainerAuthenticator.ComputeAsync(view, HeaderLength,
                [header.AsMemory(0, PrefixLength)], _sha3, _skein, token);
            return new(header.AsSpan(PrefixLength, 64).ToArray(), h, header.AsSpan(PrefixLength + 64, 128).ToArray(), s);
        }
        public void Dispose()
        { _scope.Dispose(); AuthenticatedRangeIndex.ForceDiskForTests.Value = _disk; Directory.Delete(_root, true); }
    }
}
