using System.Buffers.Binary;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using KalynaArchiver.Services;
using KalynaArchiver.Signing;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Microsoft.Win32.SafeHandles;

internal static class VerifiedArchiveInputTests
{
    internal static IReadOnlyList<TestCase> Tests =>
    [
        new("io.verified-input-domain-kats", "fixed local HMAC/Skein domain vectors from independent oracles", DomainKatsAsync, TestResource.Light, "Security"),
        new("io.verified-input-state", "disk input requires both global tags and revokes verifier view", StateAsync, TestResource.Light, "Security"),
        new("io.verified-input-ranges", "unaligned authenticated ranges and exact disk record framing", RangesAsync, TestResource.Light, "Security"),
        new("io.verified-input-descriptor-capture", "parallel multi-range captures retain descriptor ownership without buffered cursor races", DescriptorCaptureAsync, TestResource.ProcessGlobal, "Security"),
        new("io.verified-input-read-only-seal", "kernel read-only handles replace capture writers and reject substitution before unlink", ReadOnlySealAsync, TestResource.ProcessGlobal, "Security"),
        new("io.verified-input-tamper", "spool, index, truncation, extension and cross-operation replay rejection", TamperAsync, TestResource.Light, "Security"),
        new("io.verified-input-private-copy", "verified private bytes survive later spool mutation; reread fails", PrivateCopyAsync, TestResource.Light, "Security"),
        new("io.verified-original", "plain original index avoids plaintext copy and rejects later source mutation", OriginalAsync, TestResource.Light, "Security"),
        new("io.plain-manifest-rejection", "plain archive rejects either digest or changed bytes before lease and extraction publication", PlainManifestContractAsync, TestResource.ProcessGlobal, "Security"),
        new("io.verified-input-policy", "64-bit policy arithmetic, capacity and cancellation", PolicyAsync, TestResource.Light, "Security"),
        new("io.verified-input-parallel-lifetime", "independent sealed range readers join before key and full-buffer cleanup", ParallelLifetimeAsync, TestResource.ProcessGlobal, "Security"),
        new("io.verified-input-cleanup-retry", "failed capture retains closed owners and retries cleanup before another capture", CleanupRetryAsync, TestResource.ProcessGlobal, "Security"),
    ];

    private static async Task ReadOnlySealAsync()
    {
        using var fixture = new Fixture();
        using (var attacker = await VerifiedArchiveInputAttack.CaptureAsync(fixture.Source, fixture.Policy, default))
        {
            Require(attacker.OriginalSpoolWriter.IsClosed && attacker.OriginalIndexWriter.IsClosed,
                "Capture retained an original writable descriptor after sealing.");
            RequireKernelReadOnly(Storage(attacker.Input, "_spool"));
            RequireKernelReadOnly(Storage(attacker.Input, "_index"));
            Require(!attacker.Spool.SafeFileHandle.IsClosed && !attacker.Index.SafeFileHandle.IsClosed,
                "The adversarial pre-existing writers were accidentally closed by the product.");
            await attacker.Input.VerifyGloballyAsync(fixture.VerifyAsync, default);
            byte[] actual = new byte[fixture.Bytes.Length];
            await attacker.Input.ReadExactlyAsync(actual);
            Require(actual.AsSpan().SequenceEqual(fixture.Bytes), "Sealing changed the captured bytes.");
            CryptographicOperations.ZeroMemory(actual);
            Flip(attacker.Spool, 0);
            attacker.Input.Position = 0;
            await ExpectAsync<CryptographicException>(() => attacker.Input.ReadExactlyAsync(actual).AsTask());
            Require(actual.AsSpan().IndexOfAnyExcept((byte)0) < 0,
                "A pre-existing writer bypassed the post-seal authenticated read or its complete-slice wipe.");
        }

        SafeFileHandle? originalIndexWriter = null;
        Action<VerifiedArchiveInput>? previous = VerifiedArchiveInput.BeforeSealForTests;
        try
        {
            VerifiedArchiveInput.BeforeSealForTests = input => originalIndexWriter = Storage(input, "_index").SafeFileHandle;
            using VerifiedArchiveInput original = await VerifiedArchiveInput.CaptureOriginalAsync(fixture.Source, fixture.Policy, default);
            Require(originalIndexWriter is { IsClosed: true }, "Original-mode capture retained its index writer.");
            RequireKernelReadOnly(Storage(original, "_index"));
            RequireKernelReadOnly((FileStream)typeof(VerifiedArchiveInput).GetField("_original", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(original)!);
            await original.VerifyGloballyAsync(fixture.VerifyAsync, default);
        }
        finally { VerifiedArchiveInput.BeforeSealForTests = previous; }
        Require(Directory.GetFiles(fixture.Root).Length == 1, "Captured working objects retained public names.");

        // Fail between complete capture and handle sealing. Both the writer
        // and the separately owned reader must close; no capability may escape.
        var handles = new List<SafeFileHandle>();
        int owners = VerifiedArchiveInput.RetainedOwnersForTests;
        VerifiedArchiveInput? failedInput = null;
        try
        {
            VerifiedArchiveInput.BeforeSealForTests = input =>
            {
                failedInput = input;
                foreach (string field in new[] { "_spool", "_index" })
                {
                    var storage = (BoundFileTransaction)typeof(VerifiedArchiveInput).GetField(field, BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(input)!;
                    handles.Add(storage.Stream.SafeFileHandle);
                    handles.Add(((FileStream)typeof(BoundFileTransaction).GetField("_preparedReadOnly", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(storage)!).SafeFileHandle);
                }
                throw new IOException("injected before-seal failure");
            };
            await ExpectAsync<IOException>(async () => { using var unexpected = await fixture.CaptureAsync(); });
        }
        finally { VerifiedArchiveInput.BeforeSealForTests = previous; }
        Require(handles.Count == 4 && handles.All(handle => handle.IsClosed)
            && failedInput?.State == VerifiedArchiveInputState.Disposed
            && VerifiedArchiveInput.RetainedOwnersForTests == owners,
            "A failed seal retained a writer, reader or protected capture owner.");

        // The only pathname reopen is before unlink and must resolve to the
        // exact exclusively created object, without following a substituted link.
        foreach (bool symlink in new[] { false, true })
        {
            string path = Path.Combine(fixture.Root, symlink ? "link-race" : "object-race");
            string displaced = path + ".original";
            string foreign = path + ".foreign";
            byte[] sentinel = [0x42, 0x13, 0xA7, 0x5E];
            File.WriteAllBytes(foreign, sentinel);
            using BoundFileTransaction bound = BoundFileTransaction.CreateNew(path, 1, FileOptions.RandomAccess);
            bound.Stream.Write(sentinel);
            bound.Stream.Flush(true);
            Action<string>? priorOpen = BoundFileTransaction.BeforeReadOnlyOpenForTests;
            try
            {
                BoundFileTransaction.BeforeReadOnlyOpenForTests = openedPath =>
                {
                    Require(openedPath == path, "Identity-race fixture targeted an unrelated path.");
                    File.Move(path, displaced);
                    if (symlink) File.CreateSymbolicLink(path, foreign);
                    else File.WriteAllBytes(path, sentinel);
                };
                Expect<IOException>(bound.PrepareReadOnly);
                Expect<InvalidOperationException>(bound.SealReadOnly);
                Expect<IOException>(bound.DeleteBound);
            }
            finally { BoundFileTransaction.BeforeReadOnlyOpenForTests = priorOpen; }
            Require(File.ReadAllBytes(foreign).AsSpan().SequenceEqual(sentinel)
                && File.ReadAllBytes(path).AsSpan().SequenceEqual(sentinel)
                && File.ReadAllBytes(displaced).AsSpan().SequenceEqual(sentinel),
                "Failed read-only binding modified a foreign or displaced object.");
        }
    }

    private static void RequireKernelReadOnly(FileStream stream)
    {
        SafeFileHandle handle = stream.SafeFileHandle;
        long length = RandomAccess.GetLength(handle);
        int flags = DescriptorFlags(handle, 3); // macOS F_GETFL, no third argument
        Require(!stream.CanWrite && flags >= 0 && (flags & 3) == 0, "A sealed descriptor still has kernel write authority.");
        int descriptorFlags = DescriptorFlags(handle, 1); // F_GETFD
        Require(descriptorFlags >= 0 && (descriptorFlags & 1) != 0, "A sealed descriptor can leak across exec.");
        // Calling libc, instead of FileStream, proves the underlying FD itself
        // rejects writes; a read-only managed wrapper over O_RDWR cannot pass.
        Require(DescriptorWrite(handle, [0x7B], 1, 0) == -1 && Marshal.GetLastPInvokeError() == 9,
            "The sealed FD allowed pwrite or failed for a reason other than EBADF.");
        Require(DescriptorTruncate(handle, 0) == -1, "The sealed FD allowed ftruncate.");
        Require(RandomAccess.GetLength(handle) == length, "A denied descriptor mutation changed the length.");
    }

    [DllImport("libSystem.B.dylib", EntryPoint = "fcntl", SetLastError = true)]
    private static extern int DescriptorFlags(SafeFileHandle handle, int command);
    [DllImport("libSystem.B.dylib", EntryPoint = "pwrite", SetLastError = true)]
    private static extern nint DescriptorWrite(SafeFileHandle handle, byte[] bytes, nuint count, long offset);
    [DllImport("libSystem.B.dylib", EntryPoint = "ftruncate", SetLastError = true)]
    private static extern int DescriptorTruncate(SafeFileHandle handle, long length);

    private static async Task DescriptorCaptureAsync()
    {
        // More ranges than host workers reproduces the larger-file path which
        // exposed concurrent FileStream.SafeFileHandle/FlushRead cursor access.
        // Both cipher and original modes must deliver every original byte after
        // full callback verification, including the short final physical range.
        using var fixture = new Fixture((32 << 20) + 37);
        int owners = VerifiedArchiveInput.RetainedOwnersForTests;
        byte[] destination = new byte[VerifiedArchiveInput.RangeBytes + 19];
        try
        {
            foreach (bool original in new[] { false, true, false })
            {
                using VerifiedArchiveInput input = original
                    ? await VerifiedArchiveInput.CaptureOriginalAsync(fixture.Source, fixture.Policy, default)
                    : await fixture.CaptureAsync();
                await input.VerifyGloballyAsync(fixture.VerifyAsync, default);
                long offset = 0;
                while (offset < fixture.Bytes.Length)
                {
                    int count = await input.ReadAtAsync(destination, offset, default);
                    int expected = (int)Math.Min(destination.Length, fixture.Bytes.Length - offset);
                    Require(count == expected && destination.AsSpan(0, count).SequenceEqual(fixture.Bytes.AsSpan((int)offset, count)),
                        $"Descriptor capture changed bytes at offset {offset}; original={original}.");
                    offset += count;
                }
                Require(await input.ReadAtAsync(destination, offset, default) == 0, "Descriptor capture EOF disagrees with the bound length.");
            }
        }
        finally { CryptographicOperations.ZeroMemory(destination); }
        Require(VerifiedArchiveInput.RetainedOwnersForTests == owners, "Descriptor capture leaked a retained owner.");
    }

    private static async Task CleanupRetryAsync()
    {
        using var fixture = new Fixture();
        int owners = VerifiedArchiveInput.RetainedOwnersForTests;
        int ready = 0;
        VerifiedArchiveInput.CaptureReadyForTests = () => { ready++; throw new IOException("injected capture failure"); };
        SecureMemory.SensitiveBufferBeforeUnlockForTests = () => throw new IOException("injected cleanup failure");
        try
        {
            await ExpectAsync<AggregateException>(async () => { using var unexpected = await fixture.CaptureAsync(); });
            Require(ready == 1 && VerifiedArchiveInput.RetainedOwnersForTests == owners + 1,
                "A failed capture lost its retained resource owner.");
            VerifiedArchiveInput.CaptureReadyForTests = null;
            await ExpectAsync<AggregateException>(async () => { using var unexpected = await fixture.CaptureAsync(); });
            Require(VerifiedArchiveInput.RetainedOwnersForTests == owners + 1,
                "A new capture allocated protected state despite an unreleased previous owner.");
        }
        finally
        {
            VerifiedArchiveInput.CaptureReadyForTests = null;
            SecureMemory.SensitiveBufferBeforeUnlockForTests = null;
            VerifiedArchiveInput.RetryFailedCleanup();
        }
        Require(VerifiedArchiveInput.RetainedOwnersForTests == owners,
            "Successful retry did not remove the closed owner.");
        using var subsequent = await fixture.CaptureAsync();
    }

    private static async Task ParallelLifetimeAsync()
    {
        using var fixture = new Fixture();
        using VerifiedArchiveInput input = await fixture.CaptureAsync();
        await input.VerifyGloballyAsync((view, token) =>
        {
            Require(view is IPrivateSnapshotRandomAccess, "The global MAC verifier has no protected random-access capability.");
            return fixture.VerifyAsync(view, token);
        }, default);
        byte[] hmacKey = Secret(input, "_hmacKey");
        var owners = (LockedSensitiveBuffer?[])typeof(VerifiedArchiveInput).GetField("_buffers", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(input)!;
        Require(owners.Length >= 2, "This concurrency fixture requires at least two admitted CPU workers.");
        byte[][] buffers = owners.Select(owner => owner!.Bytes).ToArray();
        byte[] first = new byte[64], second = new byte[64];
        using var verified = new CountdownEvent(2);
        using var release = new ManualResetEventSlim();
        input.RangeVerifiedForTests = _ => { verified.Signal(); if (!release.Wait(TimeSpan.FromSeconds(10))) throw new TimeoutException("Fixture reader was not released."); };
        Task<int> left = Task.Run(async () => await input.ReadAtAsync(first, 0, default));
        Task<int> right = Task.Run(async () => await input.ReadAtAsync(second, VerifiedArchiveInput.RangeBytes, default));
        Task? disposal = null;
        try
        {
            Require(verified.Wait(TimeSpan.FromSeconds(10)), "Range readers were unnecessarily serialized.");
            disposal = Task.Run(input.Dispose);
            Require(SpinWait.SpinUntil(() => input.State == VerifiedArchiveInputState.Closed, TimeSpan.FromSeconds(5)), "Dispose did not revoke new readers.");
            Require(!disposal.IsCompleted && hmacKey.AsSpan().IndexOfAnyExcept((byte)0) >= 0,
                "A key was released while protected range reads were still active.");
            release.Set();
            await ExpectAsync<OperationCanceledException>(async () => await left);
            await ExpectAsync<OperationCanceledException>(async () => await right);
            await disposal;
            Require(first.AsSpan().IndexOfAnyExcept((byte)0) < 0 && second.AsSpan().IndexOfAnyExcept((byte)0) < 0,
                "Revoked pending reads did not clear their complete caller slices.");
            Require(hmacKey.AsSpan().IndexOfAnyExcept((byte)0) < 0
                && buffers.All(buffer => buffer.AsSpan().IndexOfAnyExcept((byte)0) < 0),
                "Joined private range buffers or keys were not wiped across their full capacity.");
        }
        finally
        {
            release.Set();
            try { await Task.WhenAll(left, right); } catch { }
            if (disposal is not null) await disposal;
            input.RangeVerifiedForTests = null;
        }
    }

    private static Task DomainKatsAsync()
    {
        byte[] hmacKey = Enumerable.Range(32, 64).Select(x => (byte)x).ToArray();
        byte[] skeinKey = Enumerable.Range(96, 128).Select(x => (byte)x).ToArray();
        byte[] message = new byte[61];
        Enumerable.Range(0, 32).Select(x => (byte)x).ToArray().CopyTo(message, 0);
        BinaryPrimitives.WriteInt64BigEndian(message.AsSpan(32), 1L << 32);
        BinaryPrimitives.WriteInt32BigEndian(message.AsSpan(40), 17);
        Enumerable.Range(224, 17).Select(x => (byte)x).ToArray().CopyTo(message, 44);
        byte[] tags = new byte[192];
        VerifiedArchiveInput.ComputeLocalTags(hmacKey, skeinKey, message, tags);
        // HMAC independently agrees between Python hashlib/OpenSSL and BC 2.6.2.
        // Skein vector was generated with BC 2.6.2; production uses the native
        // Skein reference implementation with native key personalization.
        const string hmacExpected = "717E59AA047EDCCEE4070B7C9D3BE1D39423C173BCE4A1361DE3F49EB591D511B49009B92FFA1177686E0A64D909782E668B5C1E0B4947E12D2939D88210DAA6";
        const string skeinExpected = "C731289F1DAC03D6A7E274557447CD94D7F5196E1BCEC11A78231F4CB04A287BA1D11FF94F74DADAB2BE7BE598D474985316EC0CFE4D71006F381B558F8B21F5809382D7DBA227624380C0B1FF00DC2A7E19F629C8A9F98B7F45477CEA477343894123BDCC5D0FDED0CAAFEE1690B730B6411AAB172FFA48A2E00A0753C545DC";
        Require(Convert.ToHexString(tags.AsSpan(0, 64)) == hmacExpected, "Local HMAC KAT failed.");
        Require(Convert.ToHexString(tags.AsSpan(64, 128)) == skeinExpected, "Local Skein KAT failed.");
        message[32] = 0xFF;
        Expect<ArgumentException>(() => VerifiedArchiveInput.ComputeLocalTags(hmacKey, skeinKey, message, tags));
        CryptographicOperations.ZeroMemory(hmacKey); CryptographicOperations.ZeroMemory(skeinKey);
        return Task.CompletedTask;
    }

    private static async Task StateAsync()
    {
        using var fixture = new Fixture();
        using VerifiedArchiveInput input = await fixture.CaptureAsync();
        Expect<InvalidOperationException>(() => input.ReadExactly(new byte[1]));
        Stream? retained = null;
        await input.VerifyGloballyAsync(async (view, token) =>
        {
            retained = view;
            return await fixture.VerifyAsync(view, token);
        }, default);
        Expect<ObjectDisposedException>(() => retained!.ReadExactly(new byte[1]));
        Expect<InvalidOperationException>(() => input.VerifyGloballyAsync(fixture.VerifyAsync, default).GetAwaiter().GetResult());
        foreach (bool failSha3 in new[] { true, false })
        {
            using VerifiedArchiveInput bad = await fixture.CaptureAsync();
            await ExpectAsync<CryptographicException>(() => bad.VerifyGloballyAsync(async (view, token) =>
            {
                VerifiedArchiveAuthentication result = await fixture.VerifyAsync(view, token);
                if (failSha3) result.ActualSha3[0] ^= 1; else result.ActualSkein[0] ^= 1;
                return result;
            }, default));
            Expect<InvalidOperationException>(() => bad.ReadExactly(new byte[1]));
        }
    }

    private static async Task RangesAsync()
    {
        using var fixture = new Fixture();
        using VerifiedArchiveInput input = await fixture.CaptureAsync();
        FileStream index = Storage(input, "_index");
        Require(index.Length == 3 * VerifiedArchiveInput.RecordBytes, "Index size is not ceil(length/1MiB)*204.");
        byte[] record = new byte[204];
        Require(RandomAccess.Read(index.SafeFileHandle, record, 204) == 204, "Missing index record.");
        Require(BinaryPrimitives.ReadInt64BigEndian(record) == 1 && BinaryPrimitives.ReadInt32BigEndian(record.AsSpan(8)) == 1 << 20,
            "Index position or length encoding is wrong.");
        // Independent Skein implementation and independently framed transcripts.
        byte[] message = new byte[44 + (1 << 20)];
        Secret(input, "_operationId").CopyTo(message, 0);
        BinaryPrimitives.WriteInt64BigEndian(message.AsSpan(32), 1);
        BinaryPrimitives.WriteInt32BigEndian(message.AsSpan(40), 1 << 20);
        fixture.Bytes.AsSpan(1 << 20, 1 << 20).CopyTo(message.AsSpan(44));
        var hmac = new HMac(new Sha3Digest(512));
        hmac.Init(new KeyParameter(Secret(input, "_hmacKey")));
        byte[] domain = System.Text.Encoding.UTF8.GetBytes("Kalyna-ZPAQ/v13/VerifiedArchiveInput/HMAC-SHA3-512");
        byte[] prefix = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(prefix, domain.Length);
        hmac.BlockUpdate(prefix); hmac.BlockUpdate(domain); hmac.BlockUpdate(message);
        byte[] hmacExpected = new byte[64]; hmac.DoFinal(hmacExpected);
        var skein = new SkeinMac(SkeinEngine.SKEIN_1024, 1024);
        skein.Init(new SkeinParameters.Builder().SetKey(Secret(input, "_skeinKey"))
            .SetPersonalisation(System.Text.Encoding.UTF8.GetBytes("Kalyna-ZPAQ/v13/VerifiedArchiveInput/Skein-MAC-1024-1024")).Build());
        skein.BlockUpdate(message); byte[] skeinExpected = new byte[128]; skein.DoFinal(skeinExpected);
        Require(record.AsSpan(12, 64).SequenceEqual(hmacExpected), "Local HMAC transcript differs from independent framing.");
        Require(record.AsSpan(76, 128).SequenceEqual(skeinExpected), "Native Skein local record differs from independent implementation.");
        CryptographicOperations.ZeroMemory(message);
        await input.VerifyGloballyAsync(fixture.VerifyAsync, default);
        foreach (long offset in new long[] { 0, 31, (1 << 20) - 7, 1 << 20, fixture.Bytes.Length - 9, fixture.Bytes.Length })
        {
            byte[] destination = new byte[113];
            int count = await input.ReadAtAsync(destination, offset, default);
            Require(destination.AsSpan(0, count).SequenceEqual(fixture.Bytes.AsSpan((int)offset, count)), "Protected random access returned different bytes.");
        }
    }

    private static async Task TamperAsync()
    {
        using var fixture = new Fixture();
        foreach (string mutation in new[] { "spool", "hmac", "skein", "index", "length", "truncate-spool", "append-spool", "truncate-index", "append-index", "replay" })
        {
            using VerifiedArchiveInputAttack attacker = await VerifiedArchiveInputAttack.CaptureAsync(fixture.Source, fixture.Policy, default);
            VerifiedArchiveInput input = attacker.Input;
            await input.VerifyGloballyAsync(fixture.VerifyAsync, default);
            FileStream spool = attacker.Spool;
            FileStream index = attacker.Index;
            switch (mutation)
            {
                case "spool": Flip(spool, 10); break;
                case "hmac": Flip(index, 12); break;
                case "skein": Flip(index, 76); break;
                case "index": Flip(index, 7); break;
                case "length": Flip(index, 11); break;
                case "truncate-spool": spool.SetLength(spool.Length - 1); break;
                case "append-spool": spool.SetLength(spool.Length + 1); break;
                case "truncate-index": index.SetLength(index.Length - 1); break;
                case "append-index": index.SetLength(index.Length + 1); break;
                case "replay":
                    using (VerifiedArchiveInput other = await fixture.CaptureAsync())
                    {
                        byte[] replay = new byte[204];
                        Require(RandomAccess.Read(Storage(other, "_index").SafeFileHandle, replay, 0) == replay.Length, "Replay fixture is incomplete.");
                        RandomAccess.Write(index.SafeFileHandle, replay, 0);
                    }
                    break;
            }
            byte[] output = Enumerable.Repeat((byte)0xA5, 113).ToArray();
            try { await input.ReadAtAsync(output, 0, default); throw new Exception($"Accepted {mutation}."); }
            catch (Exception failure) when (failure is CryptographicException or IOException) { }
            Require(output.All(b => b == 0), $"Rejected {mutation} left partially returned data.");
            Require(input.State == VerifiedArchiveInputState.Failed, "An integrity error did not poison the input.");
        }
    }

    private static async Task PrivateCopyAsync()
    {
        using var fixture = new Fixture();
        using VerifiedArchiveInputAttack attacker = await VerifiedArchiveInputAttack.CaptureAsync(fixture.Source, fixture.Policy, default);
        VerifiedArchiveInput input = attacker.Input;
        await input.VerifyGloballyAsync(fixture.VerifyAsync, default);
        byte[] output = new byte[113];
        await input.ReadAtAsync(output, 0, default);
        Flip(attacker.Spool, 0);
        Require(output.AsSpan().SequenceEqual(fixture.Bytes.AsSpan(0, output.Length)), "A caller's authenticated buffer aliases the mutable spool.");
        await ExpectAsync<CryptographicException>(async () => { await input.ReadAtAsync(new byte[113], 0, default); });
    }

    private static async Task PolicyAsync()
    {
        foreach (long length in new[] { 0L, 1, 1L << 20, (1L << 20) + 1, 256L << 30, 500L << 30, 512L << 30,
                     1_000_000_000_000, 1L << 40, 2L << 40, 4L << 40, 8L << 40, long.MaxValue })
        {
            long count = VerifiedArchiveInput.GetRecordCount(length);
            Require(count == length / (1 << 20) + (length % (1 << 20) == 0 ? 0 : 1), "Record count overflowed.");
            Require(checked(count * 204) >= 0, "Index length overflowed.");
        }
        Expect<ArgumentOutOfRangeException>(() => VerifiedArchiveInput.GetRecordCount(-1));
        using var fixture = new Fixture();
        var small = new ArchiveOperationPolicy(fixture.Root, fixture.Root, maxContainerBytes: 1);
        await ExpectAsync<IOException>(() => VerifiedArchiveInput.CaptureAsync(fixture.Source, small, default));
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await ExpectAsync<OperationCanceledException>(() => VerifiedArchiveInput.CaptureAsync(fixture.Source, fixture.Policy, cancelled.Token));
        Expect<ArgumentOutOfRangeException>(() => new ArchiveOperationPolicy(fixture.Root, fixture.Root, maxExtractedTotalBytes: 1, maxSingleFileBytes: 2));
        Expect<ArgumentException>(() => new ArchiveOperationPolicy(fixture.Root, fixture.Root, memoryBudgetBytes: 256L << 20, maxCpuWorkers: 64));
        var smallRecovery = new ArchiveOperationPolicy(fixture.Root, fixture.Root, maxRecoveryBytes: 1);
        using (smallRecovery.EnterScope())
            await ExpectAsync<IOException>(() => new RecoveryService().CreateAsync(fixture.Source, null, default));
        Require(Directory.GetFiles(fixture.Root).Length == 1, "Rejected capture or recovery left named temporary files.");
    }

    private static async Task OriginalAsync()
    {
        using var fixture = new Fixture();
        using VerifiedArchiveInput input = await VerifiedArchiveInput.CaptureOriginalAsync(fixture.Source, fixture.Policy, default);
        Require(typeof(VerifiedArchiveInput).GetField("_spool", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(input) is null,
            "Plain original input wrote a plaintext spool.");
        await input.VerifyGloballyAsync(fixture.VerifyAsync, default);
        byte[] bytes = new byte[64]; input.ReadExactly(bytes);
        Require(bytes.AsSpan().SequenceEqual(fixture.Bytes.AsSpan(0, 64)), "Protected original read differs.");
        using (FileStream attacker = new(fixture.Source, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite)) Flip(attacker, 0);
        input.Position = 0;
        await ExpectAsync<CryptographicException>(() => input.ReadExactlyAsync(bytes).AsTask());
        Require(bytes.AsSpan().IndexOfAnyExcept((byte)0) < 0, "Failed read did not clear the caller buffer.");
    }

    private static async Task PlainManifestContractAsync()
    {
        string root = MacSafeFileSystem.ResolveExistingRealPath(
            Directory.CreateTempSubdirectory("keep-vault-plain-manifest-").FullName);
        File.SetUnixFileMode(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        string source = Path.Combine(root, "plain.zpaq");
        byte[] original = Enumerable.Range(0, 4097).Select(index => (byte)(index * 31)).ToArray();
        var policy = new ArchiveOperationPolicy(root, root,
            maxContainerBytes: 16L << 20, maxExtractedTotalBytes: 16L << 20,
            maxSingleFileBytes: 16L << 20, maxMetadataBytes: 16L << 20);
        using IDisposable policyScope = policy.EnterScope();
        var integrity = new ArchiveIntegrityService();
        var captures = new List<VerifiedArchiveInput>();
        Action<VerifiedArchiveInput>? previous = VerifiedArchiveInput.BeforeSealForTests;
        int ownersBefore = VerifiedArchiveInput.RetainedOwnersForTests;
        try
        {
            File.WriteAllBytes(source, original);
            await integrity.CreateAsync(source, default);
            string sha3Path = ArchiveIntegrityService.GetSha3ManifestPath(source);
            string skeinPath = ArchiveIntegrityService.GetSkeinManifestPath(source);
            string validSha3 = File.ReadAllText(sha3Path);
            string validSkein = File.ReadAllText(skeinPath);
            await integrity.VerifyAsync(source, default);
            using (ArchiveIntegrityLease valid = await integrity.AcquireVerifiedAsync(source, default))
            {
                byte[] actual = new byte[original.Length];
                try
                {
                    await valid.Stream.ReadExactlyAsync(actual);
                    Require(actual.AsSpan().SequenceEqual(original), "A valid plain manifest changed the released bytes.");
                }
                finally { CryptographicOperations.ZeroMemory(actual); }
            }

            VerifiedArchiveInput.BeforeSealForTests = captures.Add;
            foreach (string mutation in new[] { "sha3", "skein", "archive" })
            {
                File.WriteAllBytes(source, original);
                File.WriteAllText(sha3Path, validSha3);
                File.WriteAllText(skeinPath, validSkein);
                if (mutation == "archive")
                {
                    using var writer = new FileStream(source, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);
                    Flip(writer, original.Length - 1);
                }
                else
                {
                    string path = mutation == "sha3" ? sha3Path : skeinPath;
                    string valid = mutation == "sha3" ? validSha3 : validSkein;
                    File.WriteAllText(path, (valid[0] == '0' ? "1" : "0") + valid[1..]);
                }

                await RequirePlainRejectionAsync(() => integrity.VerifyAsync(source, default));
                bool publishedLease = false;
                await RequirePlainRejectionAsync(async () =>
                {
                    using ArchiveIntegrityLease lease = await integrity.AcquireVerifiedAsync(source, default);
                    publishedLease = true;
                });
                Require(!publishedLease, "A damaged plain archive published a readable integrity lease.");

                string output = Path.Combine(root, mutation + "-output");
                // This forbidden executable path is a tripwire: reaching native
                // resolution fails with a different exception before any process
                // can start. No installed anchor is needed for this rejection.
                var zpaq = new ZpaqService(Path.Combine(root, "must-not-be-resolved"), policy);
                await RequirePlainRejectionAsync(() => zpaq.ExtractAsync(source, output, null, default));
                Require(!Directory.Exists(output) && !File.Exists(output),
                    "A rejected plain archive created an extraction destination.");
                Require(captures.All(capture => capture.State == VerifiedArchiveInputState.Disposed)
                    && VerifiedArchiveInput.RetainedOwnersForTests == ownersBefore,
                    "Plain manifest rejection retained a capture or readable source owner.");
            }
            Require(captures.Count == 9, "A plain manifest rejection bypassed its captured verification path.");
        }
        finally
        {
            VerifiedArchiveInput.BeforeSealForTests = previous;
            CryptographicOperations.ZeroMemory(original);
            Directory.Delete(root, recursive: true);
        }
    }

    private static async Task RequirePlainRejectionAsync(Func<Task> action)
    {
        try { await action(); }
        catch (InvalidDataException error)
        {
            Require(error.Message == "Plain ZPAQ archive failed its SHA3-512/Skein-1024 dual-integrity check.",
                "Plain archive rejection reported an unrelated validation or password failure.");
            return;
        }
        throw new Exception("A corrupted plain archive passed dual-manifest verification.");
    }

    private static FileStream Storage(VerifiedArchiveInput input, string name) =>
        ((BoundFileTransaction)typeof(VerifiedArchiveInput).GetField(name, BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(input)!).Stream;
    private static byte[] Secret(VerifiedArchiveInput input, string name) =>
        ((LockedSensitiveBuffer)typeof(VerifiedArchiveInput).GetField(name, BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(input)!).Bytes;
    private static void Flip(FileStream stream, long offset)
    {
        Span<byte> value = stackalloc byte[1];
        Require(RandomAccess.Read(stream.SafeFileHandle, value, offset) == 1, "Mutation target is missing.");
        value[0] ^= 1; RandomAccess.Write(stream.SafeFileHandle, value, offset);
    }
    private static void Require(bool condition, string message) { if (!condition) throw new Exception(message); }
    private static void Expect<T>(Action action) where T : Exception
    {
        try { action(); } catch (T) { return; }
        throw new Exception($"Expected {typeof(T).Name}.");
    }
    private static async Task ExpectAsync<T>(Func<Task> action) where T : Exception
    {
        try { await action(); } catch (T) { return; }
        throw new Exception($"Expected {typeof(T).Name}.");
    }

    private sealed class Fixture : IDisposable
    {
        internal string Root { get; } = Path.Combine(MacSafeFileSystem.ResolveExistingRealPath(Path.GetTempPath()), $"verified-input-test-{Guid.NewGuid():N}");
        internal string Source => Path.Combine(Root, "ciphertext.fixture");
        internal byte[] Bytes { get; }
        internal ArchiveOperationPolicy Policy { get; }
        private readonly OperationMemoryBudget.Lease _memory;
        private readonly IDisposable _memoryScope;
        private readonly IDisposable _policyScope;
        internal Fixture(int length = (2 << 20) + 37)
        {
            Bytes = RandomNumberGenerator.GetBytes(length);
            Directory.CreateDirectory(Root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            "KZPAQ2\0"u8.CopyTo(Bytes);
            File.WriteAllBytes(Source, Bytes);
            Policy = new ArchiveOperationPolicy(Root, Root, maxContainerBytes: Math.Max(16L << 20, length), maxMetadataBytes: 16L << 20);
            _policyScope = Policy.EnterScope();
            _memory = OperationMemoryBudget.AcquireAsync(Policy, default).AsTask().GetAwaiter().GetResult();
            _memoryScope = _memory.EnterScope();
        }
        internal Task<VerifiedArchiveInput> CaptureAsync() => VerifiedArchiveInput.CaptureAsync(Source, Policy, default);
        internal async Task<VerifiedArchiveAuthentication> VerifyAsync(Stream input, CancellationToken token)
        {
            input.Position = 0;
            using var sha3 = new Sha3_512Incremental();
            byte[] buffer = new byte[1 << 20];
            int count;
            while ((count = await input.ReadAsync(buffer, token)) != 0) sha3.AppendData(buffer.AsSpan(0, count));
            byte[] hmac = sha3.GetHashAndReset();
            CryptographicOperations.ZeroMemory(buffer);
            input.Position = 0;
            byte[] skein = await Skein1024Digest.HashDataAsync(input, token);
            return new(Sha3_512Compat.HashData(Bytes), hmac, Skein1024Digest.HashData(Bytes), skein);
        }
        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(Bytes);
            _memoryScope.Dispose(); _memory.Dispose(); _policyScope.Dispose();
            Directory.Delete(Root, recursive: true);
        }
    }
}
