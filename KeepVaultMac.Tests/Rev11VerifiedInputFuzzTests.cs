using System.Buffers.Binary;
using System.Security.Cryptography;
using KalynaArchiver.Services;

internal static partial class Rev11VerifiedInputTests
{
    private static async Task FusedFuzzAsync()
    {
        uint seed = (MacComprehensiveTests.TestSeed ?? throw new InvalidOperationException("A recorded fuzz seed is required.")) ^ 0x11314F52u;
        int accepted = 0, rejected = 0;
        long sourceBytes = 0;
        for (int test = 0; test < 10_000; test++)
        {
            var random = new Random(unchecked((int)(seed + (uint)test * 0x9E3779B9u)));
            int mode = test % 10, body = 1 + random.Next(2048);
            if (test % 1000 == 0) body += 1 << 20;
            using var f = new Fixture(body, availableWorkspace: true);
            random.NextBytes(f.Bytes);
            await f.PrepareAsync();
            bool disk = AuthenticatedRangeIndex.ForceDiskForTests.Value;
            AuthenticatedRangeIndex.ForceDiskForTests.Value = (test & 1) != 0;
            try
            {
                using var writer = new FileStream(f.Path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete, 1);
                using VerifiedArchiveInput input = await VerifiedArchiveInput.BindEncryptedAsync(f.Path, f.Policy, default);
                using var cancellation = new CancellationTokenSource();
                bool failed = false;
                try
                {
                    await input.VerifyGloballyAsync(async (view, token) =>
                    {
                        byte[] header = new byte[Fixture.HeaderLength]; await view.ReadExactlyAsync(header, token);
                        if (mode == 7)
                        {
                            int at = random.Next(header.Length);
                            RandomAccess.Write(writer.SafeFileHandle, new byte[] { (byte)(f.Bytes[at] ^ (1 << random.Next(8))) }, at);
                        }
                        if (mode == 9) cancellation.Cancel();
                        VerifiedArchiveAuthentication result = await f.AuthenticateFromHeaderAsync(view, header, token);
                        if (mode == 3) result.ExpectedSha3[random.Next(64)] ^= 1;
                        if (mode == 4) result.ExpectedSkein[random.Next(128)] ^= 1;
                        if (mode == 5) result.ActualSha3[random.Next(64)] ^= 1;
                        if (mode == 6) result.ActualSkein[random.Next(128)] ^= 1;
                        return result;
                    }, cancellation.Token);
                }
                catch (Exception error) when (SafeInputFailure(error)) { failed = true; }
                int start = random.Next(f.Bytes.Length), count = 1 + random.Next(Math.Min(257, f.Bytes.Length - start));
                byte[] guarded = Enumerable.Repeat((byte)0xA7, count + 64).ToArray();
                if (mode is >= 3 and <= 7 or 9)
                {
                    Require(failed && input.State == VerifiedArchiveInputState.Failed && !input.CanRead, "Failed first pass published a readable capability.");
                    ExpectFailure(() => input.ReadAtAsync(guarded.AsMemory(32, count), start, default).GetAwaiter().GetResult());
                    Require(guarded.All(value => value == 0xA7), "Pre-authentication rejection modified a caller buffer.");
                    if (mode == 9) Require(input.FirstPassBytesForTests == 0, "Cancelled preflight began full capture.");
                    rejected++;
                }
                else
                {
                    Require(!failed && input.FirstPassBytesForTests == f.Bytes.Length, "Valid fused input has a missing or duplicate physical range.");
                    if (mode == 8)
                    {
                        int at = start + random.Next(count);
                        RandomAccess.Write(writer.SafeFileHandle, new byte[] { (byte)(f.Bytes[at] ^ 1) }, at);
                        bool refused = false;
                        try { await input.ReadAtAsync(guarded.AsMemory(32, count), start, default); }
                        catch (Exception error) when (SafeInputFailure(error)) { refused = true; }
                        Require(refused && input.State == VerifiedArchiveInputState.Failed && guarded.AsSpan(32, count).IndexOfAnyExcept((byte)0) < 0,
                            "A changed second-pass source retained caller data or remained usable.");
                        rejected++;
                    }
                    else
                    {
                        int read = await input.ReadAtAsync(guarded.AsMemory(32, count), start, default);
                        Require(read == count && guarded.AsSpan(32, count).SequenceEqual(f.Bytes.AsSpan(start, count)), "Verified slice differs from its source oracle.");
                        accepted++;
                    }
                    Require(guarded.AsSpan(0, 32).IndexOfAnyExcept((byte)0xA7) < 0
                        && guarded.AsSpan(32 + count).IndexOfAnyExcept((byte)0xA7) < 0, "Reader overwrote a destination canary.");
                }
                sourceBytes += f.Bytes.Length;
            }
            catch (Exception failure) { throw new InvalidOperationException($"REV11 original fuzz seed=0x{seed:X8} case={test} mode={mode} body={body}", failure); }
            finally { AuthenticatedRangeIndex.ForceDiskForTests.Value = disk; }
            if ((test + 1) % 1000 == 0) Console.WriteLine($"rev11_original_fuzz seed=0x{seed:X8} completed={test + 1}/10000");
        }
        Require(VerifiedArchiveInput.RetainedOwnersForTests == 0, "Fused fuzz retained an owner.");
        Console.WriteLine($"rev11_original_fuzz=PASS seed=0x{seed:X8} cases=10000 accepted={accepted} rejected={rejected} source_bytes_total={sourceBytes} backends=ram,file canaries=PASS");
    }

    private static bool SafeInputFailure(Exception error) => error is IOException or CryptographicException or OperationCanceledException
        || error is AggregateException aggregate && aggregate.Flatten().InnerExceptions.All(SafeInputFailure);

    private static Task IndexFuzzAsync()
    {
        uint seed = (MacComprehensiveTests.TestSeed ?? throw new InvalidOperationException("A recorded fuzz seed is required.")) ^ 0x11494E44u;
        using var f = new Fixture(1, availableWorkspace: true);
        bool previousDisk = AuthenticatedRangeIndex.ForceDiskForTests.Value;
        long? previousLimit = RecoveryMetadataBudget.ResidentLimitForTests.Value;
        byte[] hmac = Enumerable.Range(0, 64).Select(x => (byte)x).ToArray();
        byte[] skein = Enumerable.Range(64, 128).Select(x => (byte)x).ToArray();
        try
        {
            for (int test = 0; test < 10_000; test++)
            {
                var random = new Random(unchecked((int)(seed + (uint)test * 0x9E3779B9u)));
                int count = 1 + random.Next(5), total = count * 204;
                byte[] records = new byte[total], operationId = new byte[32]; random.NextBytes(operationId);
                for (int record = 0; record < count; record++)
                {
                    int length = 1 + random.Next(1024);
                    byte[] transcript = new byte[44 + length]; random.NextBytes(transcript);
                    operationId.CopyTo(transcript, 0);
                    BinaryPrimitives.WriteInt64BigEndian(transcript.AsSpan(32), record);
                    BinaryPrimitives.WriteInt32BigEndian(transcript.AsSpan(40), length);
                    Span<byte> target = records.AsSpan(record * 204, 204);
                    BinaryPrimitives.WriteInt64BigEndian(target, record);
                    BinaryPrimitives.WriteInt32BigEndian(target[8..], length);
                    VerifiedArchiveInput.ComputeLocalTags(hmac, skein, transcript, target[12..]);
                    CryptographicOperations.ZeroMemory(transcript);
                }
                try
                {
                    RecoveryMetadataBudget.ResidentLimitForTests.Value = 1 << 20;
                    using IDisposable metadata = RecoveryMetadataBudget.Begin(1 << 20);
                    RecoveryMetadataBudget budget = RecoveryMetadataBudget.Capture(1 << 20);
                    AuthenticatedRangeIndex.ForceDiskForTests.Value = false;
                    using var ram = new AuthenticatedRangeIndex(f.Policy, budget, total);
                    ram.WriteAt(records, 0); ram.Seal();
                    using var file = new AuthenticatedRangeIndex(f.Policy, budget, total);
                    int split = random.Next(total + 1);
                    file.WriteAt(records.AsSpan(0, split), 0);
                    AuthenticatedRangeIndex.ForceDiskForTests.Value = true;
                    file.WriteAt(records.AsSpan(split), split); file.Seal();
                    int offset = random.Next(total), size = 1 + random.Next(total - offset);
                    byte[] a = Enumerable.Repeat((byte)0xD3, size + 64).ToArray(), b = a.ToArray();
                    ram.ReadExactlyAt(a.AsSpan(32, size), offset); file.ReadExactlyAt(b.AsSpan(32, size), offset);
                    Require(a.AsSpan().SequenceEqual(b) && a.AsSpan(32, size).SequenceEqual(records.AsSpan(offset, size)), "RAM/file migration changed authenticated record bytes.");
                    Require(a.AsSpan(0, 32).IndexOfAnyExcept((byte)0xD3) < 0 && a.AsSpan(32 + size).IndexOfAnyExcept((byte)0xD3) < 0, "Index overwrote a canary.");
                    Require(ram.DiskBytes == 0 && file.DiskBytes == total && file.ResidentBytes == 0, "Backend or spill ownership differs from its plan.");
                    ExpectFailure(() => ram.WriteAt([1], offset));
                    bool refused = false;
                    try { file.ReadExactlyAt(new byte[1 + random.Next(17)], total); }
                    catch (EndOfStreamException) { refused = true; }
                    Require(refused && Directory.GetFiles(f.Workspace).Length == 0, "Out-of-range metadata read succeeded or named private index remained.");
                }
                catch (Exception failure) { throw new InvalidOperationException($"REV11 index fuzz seed=0x{seed:X8} case={test} records={count} bytes={total}", failure); }
                if ((test + 1) % 1000 == 0) Console.WriteLine($"rev11_index_fuzz seed=0x{seed:X8} completed={test + 1}/10000");
            }
        }
        finally
        {
            AuthenticatedRangeIndex.ForceDiskForTests.Value = previousDisk;
            RecoveryMetadataBudget.ResidentLimitForTests.Value = previousLimit;
        }
        Console.WriteLine($"rev11_index_fuzz=PASS seed=0x{seed:X8} cases=10000 backends=ram,file,migrated canaries=PASS public_records=204");
        return Task.CompletedTask;
    }
}
