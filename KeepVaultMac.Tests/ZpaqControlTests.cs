using System.Buffers.Binary;
using System.Net.Sockets;
using System.Security.Cryptography;
using KalynaArchiver.Services;

internal static class ZpaqControlTests
{
    internal static IReadOnlyList<TestCase> Tests =>
    [
        new("v13-progress-native-ipc", "bounded native control framing, CPU-one grants, orderly close and invalid write cleanup", Control, TestResource.ProcessGlobal, "Security"),
        new("v13-zpaq-bound-source", "bound original-source windows detect mutation without copying the source tree", Sources, TestResource.ProcessGlobal, "Security"),
        new("v13-zpaq-cpu-one", "native CPU-one regular archive creation and extraction through bound original reads", CpuOne, TestResource.ProcessGlobal, "Zpaq"),
        new("v13-zpaq-phase-readiness", "native launch follows preparation and failure joins the stream owner", PhaseReadiness, TestResource.ProcessGlobal, "Security"),
        new("v13-zpaq-owner-lifetime", "native ownership survives bounded cleanup while child or callbacks remain alive", OwnerLifetime, TestResource.ProcessGlobal, "Security"),
    ];
    private static void Require(bool condition, string message) { if (!condition) throw new Exception(message); }
    private static string NewRoot() => MacSafeFileSystem.ResolveExistingRealPath(Directory.CreateTempSubdirectory("kv-rev11-zpaq-").FullName);
    private static ArchiveOperationPolicy Policy(string path) => new(path, path, memoryBudgetBytes: 2L << 30, maxCpuWorkers: 1);
    private static byte[] Header(uint kind, ulong sequence, ulong a = 0, ulong b = 0, ulong c = 0)
    {
        byte[] h = new byte[48]; "KV13CTL1"u8.CopyTo(h);
        BinaryPrimitives.WriteUInt32BigEndian(h.AsSpan(8), kind);
        BinaryPrimitives.WriteUInt64BigEndian(h.AsSpan(16), sequence);
        BinaryPrimitives.WriteUInt64BigEndian(h.AsSpan(24), a);
        BinaryPrimitives.WriteUInt64BigEndian(h.AsSpan(32), b);
        BinaryPrimitives.WriteUInt64BigEndian(h.AsSpan(40), c); return h;
    }
    private static async Task<(uint Kind, ulong Sequence, ulong A)> ReadReply(Stream stream, CancellationToken token)
    {
        byte[] h = new byte[48]; await stream.ReadExactlyAsync(h, token);
        Require(h.AsSpan(0, 8).SequenceEqual("KV13CTL1"u8) && BinaryPrimitives.ReadUInt32BigEndian(h.AsSpan(12)) == 0,
            "Unexpected control reply payload.");
        return (BinaryPrimitives.ReadUInt32BigEndian(h.AsSpan(8)), BinaryPrimitives.ReadUInt64BigEndian(h.AsSpan(16)), BinaryPrimitives.ReadUInt64BigEndian(h.AsSpan(24)));
    }
    private static async Task Control()
    {
        foreach (int length in new[] { 0, 1, 47, 49, 4096 })
        {
            bool rejected = false;
            try { _ = ZpaqControlSession.Decode(new byte[length]); } catch (InvalidDataException) { rejected = true; }
            Require(rejected, "Malformed frame length was accepted.");
        }
        byte[] valid = Header(1, 1);
        for (int i = 0; i < 8; i++)
        {
            byte[] altered = (byte[])valid.Clone(); altered[i] ^= 1;
            bool rejected = false;
            try { _ = ZpaqControlSession.Decode(altered); } catch (InvalidDataException) { rejected = true; }
            Require(rejected, "Malformed control magic was accepted.");
        }
        string root = NewRoot();
        long initial = OperationMemoryBudget.WorkingReservedBytesForTests;
        try
        {
            ArchiveOperationPolicy policy = Policy(root);
            using IDisposable scope = policy.EnterScope();
            using OperationMemoryBudget.Lease memory = await OperationMemoryBudget.AcquireAsync(policy, default);
            using IDisposable memoryScope = memory.EnterScope();
            using var bound = new ZpaqControlSession(policy);
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15)); // harness deadline only
            Task server = bound.RunAsync(Environment.ProcessId, timeout.Token);
            using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            await socket.ConnectAsync(new UnixDomainSocketEndPoint(bound.Address), timeout.Token);
            using var stream = new NetworkStream(socket, false);
            await stream.WriteAsync(Header(1, 1), timeout.Token);
            var first = await ReadReply(stream, timeout.Token);
            Require(first.A == 1 && CpuWorkBudget.ActiveWorkersForTests == 1, "First native permit was not owned.");
            await stream.WriteAsync(Header(1, 2), timeout.Token);
            await stream.WriteAsync(Header(2, 3, 1), timeout.Token);
            var next = await ReadReply(stream, timeout.Token);
            var another = await ReadReply(stream, timeout.Token);
            Require(new[] { next.Sequence, another.Sequence }.Order().SequenceEqual(new ulong[] { 2, 3 }), "Release did not unblock a queued CPU-one acquisition.");
            await stream.WriteAsync(Header(2, 4, 2), timeout.Token); _ = await ReadReply(stream, timeout.Token);
            await stream.WriteAsync(Header(7, 5, 4096), timeout.Token); var allocation = await ReadReply(stream, timeout.Token);
            Require(allocation.A == 5, "Allocation owner was not identified.");
            await stream.WriteAsync(Header(8, 6, 5), timeout.Token); _ = await ReadReply(stream, timeout.Token);
            await stream.WriteAsync(Header(9, 7), timeout.Token); _ = await ReadReply(stream, timeout.Token);
            socket.Shutdown(SocketShutdown.Send);
            await server.WaitAsync(timeout.Token);
            Require(CpuWorkBudget.ActiveWorkersForTests == 0, "CPU grants leaked after orderly drain.");
            bound.Dispose();
            using var invalid = new ZpaqControlSession(policy);
            invalid.BindOutput(root, 4096);
            Task failed = invalid.RunAsync(Environment.ProcessId, timeout.Token);
            using var invalidSocket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            await invalidSocket.ConnectAsync(new UnixDomainSocketEndPoint(invalid.Address), timeout.Token);
            using var invalidStream = new NetworkStream(invalidSocket, false);
            await invalidStream.WriteAsync(Header(6, 1, 0, 128), timeout.Token);
            _ = await ReadReply(invalidStream, timeout.Token);
            // The failed handler must wake a reader already waiting for the
            // remaining 47 bytes, and preserve the outstanding write owner.
            await invalidStream.WriteAsync(Header(10, 2, 1, 129).Concat(new byte[] { (byte)'K' }).ToArray(), timeout.Token);
            bool rejected = false;
            try { await failed.WaitAsync(timeout.Token); } catch (InvalidDataException) { rejected = true; }
            Require(rejected, "Invalid completion or truncated-following-frame deadlocked/was accepted.");
            invalid.Dispose();
            Require(OperationVolumeLedger.PendingBytes(policy.OutputVolumeIdentity) == 0, "Invalid write completion leaked the volume lease.");
        }
        finally { Directory.Delete(root, true); }
        Require(OperationMemoryBudget.WorkingReservedBytesForTests == initial, "Control memory owner leaked.");
    }
    private static async Task Sources()
    {
        string root = NewRoot();
        try
        {
            string folder = Path.Combine(root, "Quelle-ß"); Directory.CreateDirectory(folder);
            Directory.CreateDirectory(Path.Combine(folder, "leer"));
            byte[] data = Enumerable.Range(0, 4097).Select(i => (byte)(i * 17)).ToArray();
            string path = Path.Combine(folder, ".hidden.bin"); await File.WriteAllBytesAsync(path, data);
            ArchiveOperationPolicy policy = Policy(root);
            using IDisposable scope = policy.EnterScope();
            using OperationMemoryBudget.Lease memory = await OperationMemoryBudget.AcquireAsync(policy, default);
            using IDisposable memoryScope = memory.EnterScope();
            using ZpaqBoundSources source = ZpaqBoundSources.Bind(root, [folder], default);
            Require(source.TotalBytes == 4097 && source.Count == 3 && Directory.GetDirectories(root).Length == 1,
                "Source inventory copied data or omitted empty directories.");
            ulong file = 0;
            for (ulong i = 0; i < (ulong)source.Count; i++)
            {
                using var entry = await source.EntryAsync(i, default);
                if (BinaryPrimitives.ReadUInt32BigEndian(entry.Bytes.AsSpan(32)) == 0) file = i;
            }
            using (var bytes = await source.ReadAsync(file, 7, 100, default))
                Require(bytes.Bytes.AsSpan().SequenceEqual(data.AsSpan(7, 100)), "Bound range bytes changed.");
            // Change the same file object; path existence alone must not pass.
            await File.WriteAllBytesAsync(path, new byte[4098]);
            bool rejected = false;
            try { using var bytes = await source.ReadAsync(file, 0, 1, default); }
            catch (IOException) { rejected = true; }
            Require(rejected, "Source mutation was accepted.");
        }
        finally { Directory.Delete(root, true); }
    }
    private static async Task CpuOne()
    {
        string root = NewRoot();
        try
        {
            string source = Path.Combine(root, "public.bin");
            byte[] data = new byte[2 << 20]; new Random(0x1311).NextBytes(data);
            await File.WriteAllBytesAsync(source, data);
            string archive = Path.Combine(root, "public.zpaq");
            var service = new ZpaqService(operationPolicy: Policy(root));
            ProcessResult created = await service.AddAsync(archive, [source], 5, null, default);
            Require(created.Succeeded, "CPU-one native creation failed.");
            string output = Path.Combine(root, "restored");
            ProcessResult extracted = await service.ExtractAsync(archive, output, null, default);
            Require(extracted.Succeeded, "CPU-one native extraction failed.");
            byte[] restored = await File.ReadAllBytesAsync(Path.Combine(output, "public.bin"));
            Require(CryptographicOperations.FixedTimeEquals(SHA256.HashData(data), SHA256.HashData(restored)), "CPU-one output differs.");
        }
        finally { Directory.Delete(root, true); }
    }

    private static async Task PhaseReadiness()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10)); // harness only
        bool prepared = false, ownerCompleted = false;
        int launches = 0;
        ProcessResult result = await ZpaqService.RunPreparedArchiveAsync(async (stream, token) =>
        {
            await Task.Yield();
            Require(launches == 0, "Native work began while preparation was active.");
            prepared = true;
            Require(stream is IPreparedArchiveSource && stream is IPreparedArchiveDestination, "Deferred stream lost its readiness contract.");
            await ((IPreparedArchiveSource)stream).PrepareForConsumptionAsync(token);
            byte[] one = new byte[1];
            Require(await stream.ReadAsync(one, token) == 1 && one[0] == 73, "Deferred stream changed bytes.");
            ownerCompleted = true;
        }, async (consume, token) =>
        {
            Require(prepared, "Native launch preceded KDF/verification readiness.");
            launches++;
            using var actual = new MemoryStream(new byte[] { 73 }, writable: false);
            await consume(actual, token);
            return new ProcessResult(0, string.Empty, string.Empty);
        }, timeout.Token);
        Require(result.Succeeded && launches == 1 && ownerCompleted, "Prepared stream did not join successfully.");

        launches = 0;
        var preparationFailure = new InvalidDataException("Synthetic preparation failure.");
        bool rejected = false;
        try
        {
            await ZpaqService.RunPreparedArchiveAsync((_, _) => Task.FromException(preparationFailure), (_, _) =>
            {
                launches++;
                return Task.FromResult(new ProcessResult(0, string.Empty, string.Empty));
            }, timeout.Token);
        }
        catch (InvalidDataException failure) when (ReferenceEquals(failure, preparationFailure)) { rejected = true; }
        Require(rejected && launches == 0, "Preparation failure launched native work or lost its cause.");

        ownerCompleted = false;
        var launchFailure = new IOException("Synthetic native-start failure.");
        rejected = false;
        try
        {
            await ZpaqService.RunPreparedArchiveAsync(async (stream, token) =>
            {
                try { await ((IPreparedArchiveDestination)stream).PrepareForConsumptionAsync(token); }
                finally { ownerCompleted = true; }
            }, (_, _) => Task.FromException<ProcessResult>(launchFailure), timeout.Token);
        }
        catch (IOException failure) when (ReferenceEquals(failure, launchFailure)) { rejected = true; }
        Require(rejected && ownerCompleted, "Failed native startup released an unjoined preparation owner.");
    }

    private static async Task OwnerLifetime()
    {
        using var process = new System.Diagnostics.Process
        {
            StartInfo = new System.Diagnostics.ProcessStartInfo("/bin/cat")
            { UseShellExecute = false, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true },
        };
        Require(process.Start(), "Lifetime fixture process did not start.");
        var callback = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task join = ZpaqService.JoinStartedOwnersAsync(process, new[] { callback.Task });
        try
        {
            await Task.Delay(75);
            Require(!join.IsCompleted, "Ownership ended before the child exited.");
            process.StandardInput.Close();
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
            await Task.Delay(75);
            Require(!join.IsCompleted, "Ownership ended while a callback still used its owner.");
            callback.SetResult();
            await join.WaitAsync(TimeSpan.FromSeconds(5));
        }
        finally
        {
            callback.TrySetResult();
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            await join.WaitAsync(TimeSpan.FromSeconds(5));
        }
    }
}
