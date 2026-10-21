using System.IO;
using KalynaArchiver.Services;
using Microsoft.Win32.SafeHandles;

internal static class WindowsFileSystemSecurityTests
{
    internal static async Task RunNativeAsync()
    {
        string destination = Path.Combine(Path.GetTempPath(), "keep-vault-native-output-" + Guid.NewGuid().ToString("N"));
        using var staging = new WindowsExtractionStaging(destination);
        string root = staging.StagingPath;
        Exception? primaryFailure = null;
        try
        {
            ProcessResult result = await ZpaqService.RunTextProcessAsync(
                Path.Combine(AppContext.BaseDirectory, "zpaq.exe"),
                ["--kv-self-test-windows-output"],
                root,
                null,
                CancellationToken.None);
            Require(result.Succeeded, "Native Windows output self-test failed: " + result.StandardError);
            foreach (string marker in new[]
            {
                "windows_output_root_identity=fail_closed",
                "windows_output_precreation=fail_closed",
                "windows_output_directory_precreation=fail_closed",
                "windows_output_junction=fail_closed",
                "windows_output_rename=denied",
                "windows_output_fragment_writer=denied",
                "windows_output_case_alias=fail_closed",
                "windows_output_utf8=fail_closed",
                "windows_output_supplementary_unicode=preserved",
                "windows_output_stream_metadata=validated",
            })
            {
                Require(result.StandardError.Contains(marker, StringComparison.Ordinal),
                    "Native Windows output self-test omitted " + marker);
            }

            foreach ((string option, string marker) in new[]
            {
                ("--kv-self-test-windows-create-failure", "windows_thread_fatal=CreateThread"),
                ("--kv-self-test-windows-wait-failure", "windows_thread_fatal=WaitForSingleObject"),
            })
            {
                ProcessResult failed = await ZpaqService.RunTextProcessAsync(
                    Path.Combine(AppContext.BaseDirectory, "zpaq.exe"), [option], root, null, CancellationToken.None);
                Require(failed.ExitCode == 70 && failed.StandardError.Contains(marker, StringComparison.Ordinal),
                    "A native thread infrastructure failure did not terminate the worker process safely: " + failed.StandardError);
            }
        }
        catch (Exception exception)
        {
            primaryFailure = exception;
            throw;
        }
        finally
        {
            try
            {
                // The native self-test deliberately leaves a real junction.
                // Remove that reparse object by its no-follow delete handle;
                // recursive Directory.Delete can attempt mount-point cleanup
                // that requires privileges absent on a normal test account.
                staging.Cleanup();
            }
            catch (Exception cleanupFailure) when (primaryFailure is not null)
            {
                throw new AggregateException("Native output validation and its bound cleanup both failed.",
                    primaryFailure, cleanupFailure);
            }
        }
    }

    internal static async Task RunStreamingMetadataAsync()
    {
        string root = Path.Combine(Path.GetTempPath(), "keep-vault-stream-metadata-" + Guid.NewGuid().ToString("N"));
        string source = Path.Combine(root, "source");
        Directory.CreateDirectory(Path.Combine(source, "empty-directory"));
        DateTime expectedTime = new(2024, 2, 29, 12, 34, 56, DateTimeKind.Utc);
        try
        {
            File.WriteAllText(Path.Combine(source, "дані-🔐.txt"), "Supplementary Unicode and original timestamps.");
            File.WriteAllBytes(Path.Combine(source, "empty.bin"), []);
            // Cross the s4 frame boundary, so continuation metadata is covered.
            File.WriteAllBytes(Path.Combine(source, "multi-frame.bin"),
                System.Security.Cryptography.RandomNumberGenerator.GetBytes(20 * 1024 * 1024));
            File.WriteAllText(Path.Combine(source, "readonly.txt"), "read-only original");
            foreach (string path in Directory.EnumerateFiles(source)) File.SetLastWriteTimeUtc(path, expectedTime);
            File.SetAttributes(Path.Combine(source, "readonly.txt"), FileAttributes.ReadOnly | FileAttributes.Archive);
            Directory.SetLastWriteTimeUtc(Path.Combine(source, "empty-directory"), expectedTime);
            Directory.SetLastWriteTimeUtc(source, expectedTime);

            var zpaq = new ZpaqService();
            using var archive = new MemoryStream();
            ProcessResult add = await zpaq.AddStreamingAsync([source], 1,
                (stream, token) => stream.CopyToAsync(archive, token), null, CancellationToken.None);
            Require(add.Succeeded, "Streaming metadata archive creation failed: " + add.StandardError);
            archive.Position = 0;
            string output = Path.Combine(root, "output");
            ProcessResult extract = await zpaq.ExtractStreamingAsync(
                (stream, token) => archive.CopyToAsync(stream, token), output, null, CancellationToken.None);
            Require(extract.Succeeded, "Streaming metadata extraction failed: " + extract.StandardError);
            string restoredRoot = Path.Combine(output, "source");
            foreach (string original in Directory.EnumerateFiles(source))
            {
                string restored = Path.Combine(restoredRoot, Path.GetFileName(original));
                Require(File.Exists(restored), "Streaming metadata restore lost a filename: " + original);
                using FileStream left = File.OpenRead(original);
                using FileStream right = File.OpenRead(restored);
                Require(System.Security.Cryptography.SHA256.HashData(left).SequenceEqual(
                    System.Security.Cryptography.SHA256.HashData(right)), "Streaming metadata restore changed bytes.");
                Require(File.GetLastWriteTimeUtc(restored) == expectedTime,
                    "Streaming metadata restore replaced the original timestamp.");
            }
            Require((File.GetAttributes(Path.Combine(restoredRoot, "readonly.txt")) & FileAttributes.ReadOnly) != 0,
                "Streaming metadata restore lost the read-only attribute.");
            Require(Directory.GetLastWriteTimeUtc(restoredRoot) == expectedTime
                    && Directory.GetLastWriteTimeUtc(Path.Combine(restoredRoot, "empty-directory")) == expectedTime,
                "Streaming metadata restore lost original directory timestamps.");
        }
        finally
        {
            if (Directory.Exists(root))
            {
                foreach (string file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                    File.SetAttributes(file, FileAttributes.Normal);
                Directory.Delete(root, recursive: true);
            }
        }
    }

    internal static void Run()
    {
        string root = Path.Combine(Path.GetTempPath(), "keep-vault-sharing-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            RunCreateValidationRollback(root);
            RunStagingOutputControlBinding(root);
            RunControlReplyPeerCloseAsync(root).GetAwaiter().GetResult();
            string path = Path.Combine(root, "payload.bin");
            File.WriteAllBytes(path, [1, 2, 3]);

            using (SafeFileHandle inspection = WindowsSafeFileSystem.OpenRegularFileForInspection(
                       path, allowWriters: false, denyRename: true))
            {
                ExpectIOException(
                    () => File.WriteAllBytes(path, [4, 5, 6]),
                    "A completed-file inspection admitted a new writer.");
                ExpectIOException(
                    () => File.Move(path, path + ".renamed"),
                    "A rename-denying inspection admitted a rename.");
            }

            Require(File.ReadAllBytes(path).SequenceEqual(new byte[] { 1, 2, 3 }),
                "The completed-file inspection allowed content mutation.");

            // Match ZPAQ's Windows writer: it grants FILE_SHARE_READ while
            // holding write-data access. Live progress scans must coexist with
            // it; final validation must refuse it until it has closed.
            using (var writer = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.Read))
            {
                ExpectIOException(
                    () => WindowsSafeFileSystem.OpenRegularFileForInspection(
                        path, allowWriters: false, denyRename: true).Dispose(),
                    "Final inspection accepted an already-open writer.");
                using SafeFileHandle progressInspection = WindowsSafeFileSystem.OpenRegularFileForInspection(
                    path, allowWriters: true, denyRename: true);
                writer.WriteByte(7);
                writer.Flush();
            }

            using (SafeFileHandle progressInspection = WindowsSafeFileSystem.OpenRegularFileForInspection(
                       path, allowWriters: true, denyRename: true))
            {
                ExpectIOException(
                    () => File.Move(path, path + ".renamed"),
                    "A live progress inspection admitted a rename despite denyRename.");
                using var writer = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.Read);
                writer.WriteByte(8);
            }

            string destination = Path.Combine(root, "extracted");
            string? cleanupPath = null;
            using (var staging = new WindowsExtractionStaging(destination))
            {
                WindowsExtractionStaging.TestHookBeforeCleanupDirectoryDelete = directory =>
                {
                    cleanupPath = directory;
                    Directory.CreateDirectory(Path.Combine(directory, "late-entry"));
                };
                try
                {
                    // Force the real NTFS ERROR_DIR_NOT_EMPTY path after the
                    // enumerator completed, rather than merely throwing from a
                    // hook. The failed cleanup must release all held objects.
                    ExpectIOException(staging.Cleanup,
                        "Cleanup unexpectedly removed a directory that became non-empty.");
                }
                finally
                {
                    WindowsExtractionStaging.TestHookBeforeCleanupDirectoryDelete = null;
                }
            }

            Require(cleanupPath is not null, "The cleanup failure boundary was not reached.");
            string retryPath = cleanupPath + ".retry";
            Directory.Move(cleanupPath!, retryPath);
            Require(Directory.Exists(Path.Combine(retryPath, "late-entry")),
                "Cleanup leaked a rename-denying handle or removed the late entry.");

            using (var staging = new WindowsExtractionStaging(Path.Combine(root, "readonly-extraction")))
            {
                string readonlyFile = Path.Combine(staging.StagingPath, "readonly.txt");
                File.WriteAllText(readonlyFile, "partial plaintext");
                File.SetAttributes(readonlyFile, FileAttributes.ReadOnly);
                staging.Cleanup();
                Require(!Directory.Exists(staging.StagingPath),
                    "Extraction cleanup retained a read-only plaintext file.");
            }

            string shortcutParent = Path.Combine(root, "shortcuts");
            Directory.CreateDirectory(shortcutParent);
            string firstLink = Path.Combine(shortcutParent, "first.lnk");
            string existingLink = Path.Combine(shortcutParent, "existing.lnk");
            File.WriteAllBytes(existingLink, [7, 8, 9]);
            IEnumerable<(string Path, byte[] Contents)> InterruptedShortcuts()
            {
                yield return (firstLink, [1, 2, 3]);
                ExpectIOException(() => File.Move(firstLink, firstLink + ".moved"),
                    "The first shortcut became replaceable before the batch completed.");
                ExpectIOException(() => Directory.Move(shortcutParent, shortcutParent + ".moved"),
                    "The shortcut parent became replaceable before the batch completed.");
                yield return (existingLink, [4, 5, 6]);
            }
            ExpectIOException(() => BoundFileTransaction.WriteNewBatch(InterruptedShortcuts()),
                "The shortcut batch overwrote an existing entry.");
            Require(!File.Exists(firstLink), "The failed shortcut batch left its created link behind.");
            Require(File.ReadAllBytes(existingLink).SequenceEqual(new byte[] { 7, 8, 9 }),
                "The shortcut rollback changed a pre-existing file.");
            BoundFileTransaction.WriteNewBatch([(firstLink, new byte[] { 1, 2, 3 })]);
            Require(File.ReadAllBytes(firstLink).SequenceEqual(new byte[] { 1, 2, 3 }),
                "The successful shortcut batch did not persist its bytes.");
        }
        finally
        {
            WindowsExtractionStaging.TestHookBeforeCleanupDirectoryDelete = null;
            Directory.Delete(root, recursive: true);
        }
    }

    internal static void RunCreateValidationRollback(string root)
    {
        string successful = Path.Combine(root, "created-success.bin");
        using (SafeFileHandle handle = WindowsSafeFileSystem.CreateRegularFileBound(
                   successful, asynchronous: false, writeThrough: true, sequential: true))
        using (var stream = new FileStream(handle, FileAccess.ReadWrite))
            stream.Write(new byte[] { 1, 2, 3 });
        Require(File.ReadAllBytes(successful).SequenceEqual(new byte[] { 1, 2, 3 }),
            "Successful bound creation lost its output.");
        ExpectIOException(() => WindowsSafeFileSystem.CreateRegularFileBound(
                successful, asynchronous: false, writeThrough: true, sequential: true).Dispose(),
            "CREATE_NEW accepted a pre-existing file.");
        Require(File.ReadAllBytes(successful).SequenceEqual(new byte[] { 1, 2, 3 }),
            "Failed CREATE_NEW deleted or changed a pre-existing file.");

        string existingDirectory = Path.Combine(root, "pre-existing-directory");
        Directory.CreateDirectory(existingDirectory);
        string canary = Path.Combine(existingDirectory, "canary.bin");
        File.WriteAllBytes(canary, [7, 8, 9]);
        ExpectIOException(() => WindowsSafeFileSystem.CreateRegularFileBound(
                existingDirectory, asynchronous: false, writeThrough: true, sequential: true).Dispose(),
            "CREATE_NEW accepted a pre-existing directory.");
        Require(File.ReadAllBytes(canary).SequenceEqual(new byte[] { 7, 8, 9 }),
            "Failed CREATE_NEW changed a pre-existing directory.");

        string alias = Path.Combine(root, "creation-alias");
        var start = new System.Diagnostics.ProcessStartInfo(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe"))
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        start.Arguments = $"/d /c mklink /J \"{alias}\" \"{existingDirectory}\"";
        try
        {
            using (System.Diagnostics.Process process = System.Diagnostics.Process.Start(start)
                       ?? throw new InvalidOperationException("Could not create the test junction."))
            {
                Task<string> stdout = process.StandardOutput.ReadToEndAsync();
                Task<string> stderr = process.StandardError.ReadToEndAsync();
                if (!process.WaitForExit(10000))
                {
                    process.Kill(entireProcessTree: true);
                    process.WaitForExit();
                    throw new InvalidOperationException("Test junction creation timed out.");
                }
                Require(process.ExitCode == 0, "Test junction creation failed: "
                    + stdout.GetAwaiter().GetResult() + stderr.GetAwaiter().GetResult());
            }

            ExpectIOException(() => WindowsSafeFileSystem.CreateRegularFileBound(
                    Path.Combine(alias, "canary.bin"), asynchronous: false, writeThrough: true, sequential: true).Dispose(),
                "CREATE_NEW accepted a pre-existing file through an alias.");
            Require(File.ReadAllBytes(canary).SequenceEqual(new byte[] { 7, 8, 9 }),
                "Failed alias CREATE_NEW changed a pre-existing file.");

            bool rejected = false;
            try
            {
                using SafeFileHandle unexpected = WindowsSafeFileSystem.CreateRegularFileBound(
                    Path.Combine(alias, "rejected.bin"), asynchronous: false, writeThrough: true, sequential: true);
            }
            catch (InvalidOperationException exception) when (exception.Message.Contains("path resolves through a reparse point or alias", StringComparison.Ordinal))
            {
                rejected = true;
            }
            Require(rejected, "The bound create accepted an alias instead of rejecting its resolved path.");
            Require(!File.Exists(Path.Combine(existingDirectory, "rejected.bin")),
                "A rejected alias creation left a zero-byte file in the resolved directory.");
            Require(File.ReadAllBytes(canary).SequenceEqual(new byte[] { 7, 8, 9 }),
                "Rejected alias cleanup changed a pre-existing file.");
        }
        finally
        {
            if (Directory.Exists(alias)) Directory.Delete(alias);
        }
    }

    private static void RunStagingOutputControlBinding(string root)
    {
        string destination = Path.Combine(root, "control-bound-extraction");
        using var staging = new WindowsExtractionStaging(destination);
        var policy = new ArchiveOperationPolicy(root, root);
        using (var control = new ZpaqControlSession(policy))
        {
            control.BindOutput(staging.StagingPath, 4096, staging);
            ExpectIOException(() => Directory.Move(staging.StagingPath, staging.StagingPath + ".renamed"),
                "Binding the control channel weakened the staging rename exclusion.");
            using SafeFileHandle duplicate = staging.DuplicateStagingHandle(staging.StagingPath);
            Require(WindowsSafeFileSystem.GetIdentity(duplicate) == staging.StagingIdentity,
                "The output capability duplicated a different directory object.");
            ExpectIOException(() => WindowsSafeFileSystem.MarkForDeletion(duplicate),
                "The control capability retained unnecessary deletion rights.");
            ExpectIOException(() => staging.DuplicateStagingHandle(root).Dispose(),
                "The staging capability admitted a different output path.");
        }
        // Disposing the control's duplicate must leave the transaction owner's
        // original handle usable for its final validation and bound rename.
        File.WriteAllText(Path.Combine(staging.StagingPath, "payload.txt"), "public synthetic output");
        staging.MeasureTree(allowWriters: false);
        staging.Install();
        Require(File.ReadAllText(Path.Combine(destination, "payload.txt")) == "public synthetic output",
            "Disposing the control capability invalidated the staging owner or its final installation.");
    }

    private static async Task RunControlReplyPeerCloseAsync(string root)
    {
        var flags = System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic;
        var reply = typeof(ZpaqControlSession).GetMethod("ReplyAsync", flags)
            ?? throw new InvalidOperationException("The native control reply method was not found.");
        var transport = typeof(ZpaqControlSession).GetField("_stream", flags)
            ?? throw new InvalidOperationException("The native control reply transport was not found.");
        async Task SendAsync(ZpaqControlSession session, ZpaqControlSession.Message message,
            byte[] payload, CancellationToken token = default)
        {
            var operation = (Task)(reply.Invoke(session, [message, 0UL, payload, token])
                ?? throw new InvalidOperationException("The native reply returned no task."));
            await operation.ConfigureAwait(false);
        }

        foreach (byte[] payload in new byte[][] { [], [7, 11, 13] })
        {
            using var session = new ZpaqControlSession(new ArchiveOperationPolicy(root, root));
            using var stream = new ClosingReplyStream(payload.Length == 0 ? 1 : 2);
            transport.SetValue(session, stream);
            uint kind = payload.Length == 0 ? 9U : 3U;
            await SendAsync(session, new ZpaqControlSession.Message(kind, 17, 0, 0, 0), payload)
                .ConfigureAwait(false);
            byte[] sent = stream.Sent;
            Require(stream.PeerClosed && stream.CompletedWrites == (payload.Length == 0 ? 1 : 2),
                "The reply returned before every asynchronous transport write completed.");
            Require(stream.FlushCalls == 0,
                "A completed unbuffered reply performed I/O after the peer's valid final close.");
            Require(sent.Length == ZpaqControlSession.HeaderBytes + payload.Length
                && sent.AsSpan(0, 8).SequenceEqual("KV13CTL1"u8)
                && System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(sent.AsSpan(8)) == (kind | 0x80000000U)
                && System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(sent.AsSpan(12)) == payload.Length
                && System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(sent.AsSpan(16)) == 17
                && sent.AsSpan(24, 24).IndexOfAnyExcept((byte)0) < 0
                && sent.AsSpan(ZpaqControlSession.HeaderBytes).SequenceEqual(payload),
                "The close-race fix changed the authenticated reply's framing or payload.");
        }

        foreach (int failingWrite in new[] { 1, 2 })
        {
            using var session = new ZpaqControlSession(new ArchiveOperationPolicy(root, root));
            using var stream = new ClosingReplyStream(2, failingWrite);
            transport.SetValue(session, stream);
            bool rejected = false;
            try { await SendAsync(session, new ZpaqControlSession.Message(3, 19, 0, 0, 0), [7]).ConfigureAwait(false); }
            catch (IOException failure) when (failure.Message == ClosingReplyStream.WriteFailure) { rejected = true; }
            Require(rejected && stream.CompletedWrites == failingWrite - 1 && stream.FlushCalls == 0,
                "A header or payload write failure was swallowed while avoiding a redundant flush.");
        }
    }

    private sealed class ClosingReplyStream(int expectedWrites, int failingWrite = 0) : Stream
    {
        internal const string WriteFailure = "Synthetic unbuffered reply write failed.";
        private readonly MemoryStream _sent = new();
        internal byte[] Sent => _sent.ToArray();
        internal bool PeerClosed { get; private set; }
        internal int CompletedWrites { get; private set; }
        internal int FlushCalls { get; private set; }
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => !PeerClosed;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken token = default)
        {
            await Task.Delay(1, token).ConfigureAwait(false);
            if (CompletedWrites + 1 == failingWrite) throw new IOException(WriteFailure);
            Require(!PeerClosed, "A reply write followed the simulated peer close.");
            _sent.Write(buffer.Span);
            if (++CompletedWrites == expectedWrites) PeerClosed = true;
        }
        public override void Flush()
        {
            FlushCalls++;
            throw new IOException(PeerClosed ? "Pipe is broken after a delivered reply." : "An unbuffered transport must not be flushed.");
        }
        public override Task FlushAsync(CancellationToken token)
        {
            FlushCalls++;
            return Task.FromException(new IOException(PeerClosed
                ? "Pipe is broken after a delivered reply." : "An unbuffered transport must not be flushed."));
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing) _sent.Dispose();
            base.Dispose(disposing);
        }
    }

    private static void ExpectIOException(Action action, string failure)
    {
        try
        {
            action();
        }
        catch (IOException)
        {
            return;
        }

        throw new InvalidOperationException(failure);
    }

    private static void Require(bool condition, string failure)
    {
        if (!condition) throw new InvalidOperationException(failure);
    }
}
