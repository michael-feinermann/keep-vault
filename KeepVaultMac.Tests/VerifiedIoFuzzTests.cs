using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using KalynaArchiver.Services;
using Org.BouncyCastle.Crypto.Digests;

internal static class VerifiedIoFuzzTests
{
    private const int Cases = 10_000;
    private const byte Canary = 0xA7;
    internal static IReadOnlyList<TestCase> Tests =>
    [
        new("fuzz.verified-input-10000", "10000 seeded sealed-spool states, mutations and guarded range oracles", SpoolAsync, TestResource.ProcessGlobal, "Security"),
        new("fuzz.verified-read-at-server-10000", "10000 seeded bounded read-at request frames with guarded response oracles", ReadAtServerAsync, TestResource.ProcessGlobal, "Security"),
        new("fuzz.recovery-streaming-10000", "10000 seeded canonical/hostile KPAR4 metadata streams with fragmented reads", RecoveryAsync, TestResource.ProcessGlobal, "Security"),
    ];

    private static async Task SpoolAsync()
    {
        using var scope = new Scope("spool");
        uint seed = (MacComprehensiveTests.TestSeed ?? throw new InvalidOperationException("A recorded fuzz seed is required.")) ^ 0x56494F13u;
        long bytesTotal = 0;
        int accepted = 0, rejected = 0, maximum = 0;
        for (int index = 0; index < Cases; index++)
        {
            var random = new Generator(seed, index);
            int mode = index % 12;
            int length = 7 + random.Below(4090);
            // A few real multi-range cases exercise the 1-MiB boundary, while
            // every individual fixture remains far below the user data limit.
            if (index % 1000 == 0) length = VerifiedArchiveInput.RangeBytes + 7 + random.Below(1017);
            byte[] source = new byte[length]; random.Fill(source); "KZPAQ2\0"u8.CopyTo(source);
            int start = random.Below(length);
            int count = 1 + random.Below(Math.Min(257, length - start));
            byte[] guarded = Enumerable.Repeat(Canary, count + 64).ToArray();
            try
            {
                File.WriteAllBytes(scope.Source, source);
                using VerifiedArchiveInputAttack attacker = await VerifiedArchiveInputAttack.CaptureAsync(scope.Source, scope.Policy, default);
                VerifiedArchiveInput input = attacker.Input;
                if (mode is 10 or 11)
                {
                    await RejectAsync<CryptographicException>(() => input.VerifyGloballyAsync(async (stream, token) =>
                    {
                        VerifiedArchiveAuthentication result = await GlobalOracleAsync(source, stream, token);
                        if (mode == 10) result.ActualSha3[random.Below(64)] ^= 1;
                        else result.ActualSkein[random.Below(128)] ^= 1;
                        return result;
                    }, default));
                    await RejectAsync<InvalidOperationException>(async () => await input.ReadAtAsync(guarded.AsMemory(32, count), start, default));
                    Require(guarded.All(b => b == Canary), "Unverified input changed the caller buffer.");
                    rejected++;
                }
                else
                {
                    await input.VerifyGloballyAsync((stream, token) => GlobalOracleAsync(source, stream, token), default);
                    FileStream spool = attacker.Spool, records = attacker.Index;
                    if (mode <= 2)
                    {
                        int actual = await input.ReadAtAsync(guarded.AsMemory(32, count), start, default);
                        Require(actual == count && guarded.AsSpan(32, count).SequenceEqual(source.AsSpan(start, count)), "Valid guarded range differs from original bytes.");
                        Require(await input.ReadAtAsync(Memory<byte>.Empty, random.Below(length + 1), default) == 0, "Empty read returned bytes.");
                        byte[] eof = [Canary];
                        Require(await input.ReadAtAsync(eof, length, default) == 0 && eof[0] == Canary, "EOF changed output.");
                        accepted++;
                    }
                    else
                    {
                        long record = (long)(start / VerifiedArchiveInput.RangeBytes) * VerifiedArchiveInput.RecordBytes;
                        switch (mode)
                        {
                            case 3: Flip(spool, start + random.Below(count), 1 << random.Below(8)); break;
                            case 4: Flip(records, record + random.Below(12), 1 << random.Below(8)); break;
                            case 5: Flip(records, record + 12 + random.Below(64), 1 << random.Below(8)); break;
                            case 6: Flip(records, record + 76 + random.Below(128), 1 << random.Below(8)); break;
                            case 7: spool.SetLength(length - 1 - random.Below(Math.Min(length, 7))); break;
                            case 8: records.SetLength(records.Length + 1 + random.Below(7)); break;
                            case 9:
                                using (VerifiedArchiveInput other = await VerifiedArchiveInput.CaptureAsync(scope.Source, scope.Policy, default))
                                {
                                    byte[] foreign = new byte[VerifiedArchiveInput.RecordBytes];
                                    ReadExactlyAt(Storage(other, "_index"), foreign, record);
                                    RandomAccess.Write(records.SafeFileHandle, foreign, record);
                                }
                                break;
                        }
                        bool failed = false;
                        try { _ = await input.ReadAtAsync(guarded.AsMemory(32, count), start, default); }
                        catch (Exception failure) when (failure is IOException or CryptographicException) { failed = true; }
                        Require(failed, "A mutated sealed range was accepted.");
                        Require(guarded.AsSpan(32, count).IndexOfAnyExcept((byte)0) < 0, "A failed read retained caller bytes.");
                        await RejectAsync<InvalidOperationException>(async () => await input.ReadAtAsync(new byte[1], 0, default));
                        rejected++;
                    }
                    CheckCanaries(guarded, count);
                }
                bytesTotal += length; maximum = Math.Max(maximum, length);
            }
            catch (Exception failure)
            {
                throw new InvalidOperationException($"spool fuzz seed=0x{seed:X8} case={index} mode={mode} length={length} offset={start} count={count}", failure);
            }
            if ((index + 1) % 1000 == 0) Console.WriteLine($"spool_fuzz seed=0x{seed:X8} completed={index + 1}/{Cases}");
        }
        Require(VerifiedArchiveInput.RetainedOwnersForTests == 0, "Fuzz retained an input owner.");
        Console.WriteLine($"spool_fuzz=PASS seed=0x{seed:X8} cases={Cases} accepted={accepted} rejected={rejected} source_bytes_total={bytesTotal} maximum_case_bytes={maximum} canaries=PASS oracle=BC-SHA3/Skein-and-source-bytes");
    }

    private static Task RecoveryAsync()
    {
        using var scope = new Scope("metadata");
        uint seed = (MacComprehensiveTests.TestSeed ?? throw new InvalidOperationException("A recorded fuzz seed is required.")) ^ 0x4B504134u;
        int accepted = 0, rejected = 0, maximum = 0;
        long bytesTotal = 0;
        for (int index = 0; index < Cases; index++)
        {
            var random = new Generator(seed, index);
            int mode = index % 12;
            long archiveLength = ((long)random.Next() << 8) + random.Below(256) + 1;
            byte[] digest = new byte[192]; random.Fill(digest);
            string combined = Convert.ToBase64String(digest, 0, 64) + ":" + Convert.ToBase64String(digest, 64, 128);
            string fileName = $"fixture-{index}-{random.Next():x8}-ä-\"-\\-😀.zpaq";
            // Independent anonymous-object serializer supplies the field order
            // and values. Production Deserialize/Serialize do not make the oracle.
            var sections = Enumerable.Range(0, random.Below(3)).Select(section => new
            {
                name = section == 0 ? "Header" : "Body", offset = (long)random.Next(), length = (long)random.Next(),
                shardSize = 4096, dataShardCount = 20, parityShardCount = 3, stripeCount = 1,
                dataDigests = Enumerable.Repeat(combined, random.Below(4)).ToArray(),
                parity = Enumerable.Range(0, random.Below(3)).Select(parity => new
                { stripe = 0, parityIndex = parity, offset = archiveLength + random.Below(4096), length = 4096, digest = combined }).ToArray()
            }).ToArray();
            byte[] canonical = JsonSerializer.SerializeToUtf8Bytes(new
            {
                version = 4, containerVersion = 13, algorithm = $"KPAR4-{random.Next():x8}", protectionMode = 1,
                archiveFileName = fileName, archiveLength, archiveSha3_512 = Convert.ToBase64String(digest, 0, 64),
                archiveSkein1024 = Convert.ToBase64String(digest, 64, 128), redundancyPercent = 15,
                createdUtc = new DateTimeOffset(2000, 1, 1, 0, 0, 0, TimeSpan.Zero).AddSeconds(random.Next()),
                archiveId = $"{random.Next():x8}", encryptionAlgorithm = (string?)null, encryptionSuite = -1,
                saltSha3Round1 = (string?)null, saltSkeinRound1 = (string?)null,
                saltSha3Round2 = (string?)null, saltSkeinRound2 = (string?)null,
                argon2MemoryKiB = 0, argon2Iterations = 0, argon2Parallelism = 0, sections
            });
            string json = Encoding.UTF8.GetString(canonical);
            byte[] payload = mode switch
            {
                0 or 1 or 2 => canonical,
                3 => Encoding.UTF8.GetBytes(json + new string(' ', 1 + random.Below(8))),
                4 => canonical[..random.Below(canonical.Length)],
                5 => Encoding.UTF8.GetBytes(json.Replace("\"version\":4", "\"version\":4,\"version\":4", StringComparison.Ordinal)),
                6 => Encoding.UTF8.GetBytes(json.Replace("\"version\":4", "\"version\":4.0", StringComparison.Ordinal)),
                7 => Encoding.UTF8.GetBytes(json.Replace("\"version\":4", "\"unknown\":" + random.Next() + ",\"version\":4", StringComparison.Ordinal)),
                8 => Encoding.UTF8.GetBytes(json.Replace("\"archiveId\":", "\"archiveId\": ", StringComparison.Ordinal)),
                9 => Encoding.UTF8.GetBytes(json.Replace("\"algorithm\":\"KPAR4-", "\"algorithm\":\"" + new string('x', 4097 + random.Below(31)), StringComparison.Ordinal)),
                10 => canonical,
                _ => [0xEF, 0xBB, 0xBF, .. canonical]
            };
            if (mode == 10) archiveLength++;
            byte[] guarded = Enumerable.Repeat(Canary, payload.Length + 64).ToArray(); payload.CopyTo(guarded, 32);
            byte[] unchanged = (byte[])guarded.Clone();
            int fragment = 1 + random.Below(127);
            try
            {
                using var input = new FragmentedReadStream(guarded, 32, payload.Length, fragment);
                if (mode <= 2)
                {
                    using RecoveryManifest parsed = RecoveryManifestCodec.Deserialize(input, archiveLength, default);
                    Require(parsed.ArchiveFileName == fileName && parsed.ArchiveLength == archiveLength && parsed.Sections.Count == sections.Length,
                        "Parsed metadata differs from the independent object oracle.");
                    using RecoveryMetadataStream encoded = RecoveryManifestCodec.Serialize(parsed, default);
                    byte[] returned = new byte[checked((int)encoded.Length)]; encoded.ReadExactly(returned);
                    Require(returned.AsSpan().SequenceEqual(canonical), "Canonical bytes differ from independent serialization.");
                    for (int section = 0; section < sections.Length; section++)
                    {
                        Require(parsed.Sections[section].DataDigests.SequenceEqual(sections[section].dataDigests), "Digest table differs.");
                        Require(parsed.Sections[section].Parity.Count == sections[section].parity.Length, "Parity table count differs.");
                    }
                    accepted++;
                }
                else
                {
                    bool failed = false;
                    try { using RecoveryManifest invalid = RecoveryManifestCodec.Deserialize(input, archiveLength, default); }
                    catch (InvalidDataException) { failed = true; }
                    Require(failed, "Hostile/noncanonical metadata was accepted.");
                    rejected++;
                }
                Require(guarded.AsSpan().SequenceEqual(unchanged), "Parser changed input or surrounding canaries.");
                bytesTotal += payload.Length; maximum = Math.Max(maximum, payload.Length);
            }
            catch (Exception failure)
            { throw new InvalidOperationException($"metadata fuzz seed=0x{seed:X8} case={index} mode={mode} bytes={payload.Length} fragment={fragment}", failure); }
            if ((index + 1) % 1000 == 0) Console.WriteLine($"metadata_fuzz seed=0x{seed:X8} completed={index + 1}/{Cases}");
        }
        Console.WriteLine($"metadata_fuzz=PASS seed=0x{seed:X8} cases={Cases} accepted={accepted} rejected={rejected} input_bytes_total={bytesTotal} maximum_case_bytes={maximum} canaries=PASS oracle=independent-anonymous-object-JSON");
        return Task.CompletedTask;
    }

    private static async Task ReadAtServerAsync()
    {
        using var scope = new Scope("read-at-server");
        uint seed = (MacComprehensiveTests.TestSeed ?? throw new InvalidOperationException("A recorded fuzz seed is required.")) ^ 0x52413133u;
        int accepted = 0, rejected = 0, maximum = 0;
        long requestBytes = 0, responseBytes = 0;
        for (int index = 0; index < Cases; index++)
        {
            var random = new Generator(seed, index);
            int mode = index % 12, length = 1 + random.Below(4096), number = 1 + random.Below(5);
            int faultAt = mode <= 2 ? number : random.Below(number);
            byte[] sourceGuard = Enumerable.Repeat(Canary, length + 64).ToArray(); random.Fill(sourceGuard.AsSpan(32, length));
            byte[] originalGuard = (byte[])sourceGuard.Clone();
            byte[] frames = new byte[number * 12];
            using var expected = new MemoryStream();
            byte[] header = new byte[16]; "KV13RA\0\0"u8.CopyTo(header);
            BinaryPrimitives.WriteInt64BigEndian(header.AsSpan(8), length); expected.Write(header);
            for (int request = 0; request < number; request++)
            {
                long offset = random.Below(length);
                uint count = (uint)(1 + random.Below(length - (int)offset));
                if (request < faultAt) expected.Write(sourceGuard, 32 + (int)offset, (int)count);
                if (request == faultAt)
                {
                    switch (mode)
                    {
                        case 3: offset = -1L - random.Next(); break;
                        case 4: count = 0; break;
                        case 5: count = (1u << 20) + 1 + random.Next() % 4096; break;
                        case 6: offset = length + 1L + random.Next(); break;
                        case 7: offset = length; count = 1; break;
                        case 9: count = (uint)(length - offset + 1 + random.Below(4096)); break;
                        case 10: count = uint.MaxValue - random.Next() % 4096; break;
                    }
                }
                BinaryPrimitives.WriteInt64BigEndian(frames.AsSpan(request * 12), offset);
                BinaryPrimitives.WriteUInt32BigEndian(frames.AsSpan(request * 12 + 8), count);
            }
            if (mode == 8) frames = frames[..(faultAt * 12 + 1 + random.Below(11))];
            byte[] requestGuard = Enumerable.Repeat(Canary, frames.Length + 64).ToArray(); frames.CopyTo(requestGuard, 32);
            byte[] originalRequests = (byte[])requestGuard.Clone();
            int outputCapacity = 16 + 5 * length;
            byte[] outputGuard = Enumerable.Repeat(Canary, outputCapacity + 64).ToArray();
            try
            {
                using var archive = new GuardedArchiveStream(sourceGuard, length);
                using var requests = new FragmentedReadStream(requestGuard, 32, frames.Length, 1 + random.Below(13));
                if (mode == 11) requests.BeforeRead = () => { if (requests.Position >= faultAt * 12) archive.LengthChanged = true; };
                using var responses = new MemoryStream(outputGuard, 32, outputCapacity, writable: true);
                responses.SetLength(0);
                bool failed = false;
                try { await VerifiedArchiveReadAtServer.ServeAsync(archive, requests, responses, default); }
                catch (InvalidDataException) when (mode > 2 && mode != 8) { failed = true; }
                catch (EndOfStreamException) when (mode == 8) { failed = true; }
                Require(failed == (mode > 2), "Request acceptance differs from frame oracle.");
                byte[] expectedBytes = expected.ToArray();
                Require(responses.Length == expectedBytes.Length
                    && outputGuard.AsSpan(32, expectedBytes.Length).SequenceEqual(expectedBytes), "Response differs from original-range oracle or published invalid bytes.");
                Require(archive.BytesRead == expectedBytes.Length - 16, "Rejected framing caused an archive read.");
                CheckCanaries(outputGuard, outputCapacity);
                Require(outputGuard.AsSpan(32 + expectedBytes.Length, outputCapacity - expectedBytes.Length).IndexOfAnyExcept(Canary) < 0,
                    "Server touched bytes beyond the emitted response.");
                Require(sourceGuard.AsSpan().SequenceEqual(originalGuard) && requestGuard.AsSpan().SequenceEqual(originalRequests), "Server modified request/archive input guards.");
                if (failed) rejected++; else accepted++;
                requestBytes += frames.Length; responseBytes += expectedBytes.Length; maximum = Math.Max(maximum, length);
            }
            catch (Exception failure)
            { throw new InvalidOperationException($"read-at-server fuzz seed=0x{seed:X8} case={index} mode={mode} archive_bytes={length} requests={number} fault_at={faultAt}", failure); }
            if ((index + 1) % 1000 == 0) Console.WriteLine($"read_at_server_fuzz seed=0x{seed:X8} completed={index + 1}/{Cases}");
        }
        Console.WriteLine($"read_at_server_fuzz=PASS seed=0x{seed:X8} cases={Cases} accepted={accepted} rejected={rejected} request_bytes_total={requestBytes} response_bytes_total={responseBytes} maximum_archive_bytes={maximum} canaries=PASS oracle=source-slices-and-independent-BE-framing");
    }

    private static async Task<VerifiedArchiveAuthentication> GlobalOracleAsync(byte[] original, Stream input, CancellationToken token)
    {
        byte[] captured = new byte[original.Length]; input.Position = 0; await input.ReadExactlyAsync(captured, token);
        Require(await input.ReadAsync(new byte[1], token) == 0, "Verifier read beyond bound EOF.");
        return new(Hash(original, false), Hash(captured, false), Hash(original, true), Hash(captured, true));
    }
    private static byte[] Hash(byte[] bytes, bool skein)
    {
        Org.BouncyCastle.Crypto.IDigest digest = skein ? new SkeinDigest(1024, 1024) : new Sha3Digest(512);
        digest.BlockUpdate(bytes); byte[] output = new byte[digest.GetDigestSize()]; digest.DoFinal(output); return output;
    }
    private static FileStream Storage(VerifiedArchiveInput input, string name) =>
        ((BoundFileTransaction)typeof(VerifiedArchiveInput).GetField(name, BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(input)!).Stream;
    private static void ReadExactlyAt(FileStream stream, Span<byte> target, long offset)
    {
        int read = 0;
        while (read < target.Length)
        { int count = RandomAccess.Read(stream.SafeFileHandle, target[read..], offset + read); Require(count > 0, "Short fixture read."); read += count; }
    }
    private static void Flip(FileStream stream, long offset, int mask)
    { Span<byte> value = stackalloc byte[1]; ReadExactlyAt(stream, value, offset); value[0] ^= (byte)mask; RandomAccess.Write(stream.SafeFileHandle, value, offset); }
    private static void CheckCanaries(byte[] bytes, int payload) =>
        Require(bytes.AsSpan(0, 32).IndexOfAnyExcept(Canary) < 0 && bytes.AsSpan(32 + payload).IndexOfAnyExcept(Canary) < 0, "Output guard overwritten.");
    private static void Require(bool valid, string message) { if (!valid) throw new InvalidOperationException(message); }
    private static async Task RejectAsync<T>(Func<Task> action) where T : Exception
    { try { await action(); } catch (T) { return; } throw new InvalidOperationException($"Expected {typeof(T).Name}."); }
    private sealed class FragmentedReadStream(byte[] bytes, int offset, int count, int fragment) : MemoryStream(bytes, offset, count, writable: false)
    {
        internal Action? BeforeRead;
        public override int Read(Span<byte> buffer) => base.Read(buffer[..Math.Min(buffer.Length, fragment)]);
        public override int Read(byte[] buffer, int offset, int count) => base.Read(buffer, offset, Math.Min(count, fragment));
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        { BeforeRead?.Invoke(); return base.ReadAsync(buffer[..Math.Min(buffer.Length, fragment)], cancellationToken); }
    }
    private sealed class GuardedArchiveStream(byte[] bytes, int length) : MemoryStream(bytes, 32, length, writable: false)
    {
        internal bool LengthChanged;
        internal int BytesRead;
        public override long Length => LengthChanged ? base.Length - 1 : base.Length;
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        { int read = await base.ReadAsync(buffer, cancellationToken); BytesRead = checked(BytesRead + read); return read; }
    }
    private sealed class Generator
    {
        private uint _value;
        internal Generator(uint seed, int index) { _value = seed ^ unchecked((uint)(index + 1) * 0x9E3779B9u); if (_value == 0) _value = 1; }
        internal uint Next() { uint value = _value; value ^= value << 13; value ^= value >> 17; value ^= value << 5; return _value = value; }
        internal int Below(int upper) => checked((int)(Next() % (uint)upper));
        internal void Fill(Span<byte> bytes) { for (int i = 0; i < bytes.Length; i++) bytes[i] = (byte)Next(); }
    }
    private sealed class Scope : IDisposable
    {
        internal string Root { get; } = Path.Combine(MacSafeFileSystem.ResolveExistingRealPath(Path.GetTempPath()), $"kv-fuzz-{Guid.NewGuid():N}");
        internal string Source => Path.Combine(Root, "input");
        internal ArchiveOperationPolicy Policy { get; }
        private readonly IDisposable _policy, _metadata, _memoryScope;
        private readonly OperationMemoryBudget.Lease _memory;
        internal Scope(string target)
        {
            Directory.CreateDirectory(Root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            Policy = new ArchiveOperationPolicy(Root, Root, maxContainerBytes: 4L << 20, maxMetadataBytes: 32L << 20, maxCpuWorkers: 2);
            _policy = Policy.EnterScope(); _metadata = RecoveryMetadataBudget.Begin(32L << 20);
            _memory = OperationMemoryBudget.AcquireAsync(Policy, default).AsTask().GetAwaiter().GetResult(); _memoryScope = _memory.EnterScope();
        }
        public void Dispose() { _memoryScope.Dispose(); _memory.Dispose(); _metadata.Dispose(); _policy.Dispose(); Directory.Delete(Root, true); }
    }
}
