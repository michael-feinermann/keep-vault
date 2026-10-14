using System.Buffers.Binary;
using KalynaArchiver.Services;

internal static partial class MacComprehensiveTests
{
    private static async Task TestVerifiedReadAtAsync()
    {
        string root = RepositoryLayout.FindRepositoryRoot();
        string temporary = CreateTempRoot("keep-vault-v13-read-at-test-");
        try
        {
            string binary = Path.Combine(temporary, "verified-read-at-test");
            ProcessResult build = await RunProcessAsync("/usr/bin/xcrun",
                ["clang++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-O2",
                    Path.Combine(root, "KeepVaultMac.Tests", "VerifiedArchiveReaderTests.cpp"), "-o", binary], root);
            Require(build.Succeeded, "The native read-at test did not compile: " + build.StandardError);
            ProcessResult run = await RunProcessAsync(binary, [], temporary);
            Require(run.Succeeded && run.StandardOutput.Contains("verified_read_at_native=pass checks=13", StringComparison.Ordinal),
                "The native read-at protocol test failed: " + run.StandardError);

            byte[] source = Enumerable.Range(0, 513).Select(i => (byte)i).ToArray();
            using var archive = new MemoryStream(source, writable: false);
            using var requests = new MemoryStream();
            foreach ((long offset, int count) in new[] { (500L, 13), (0L, 17), (249L, 33) })
            {
                byte[] request = new byte[12];
                BinaryPrimitives.WriteInt64BigEndian(request, offset);
                BinaryPrimitives.WriteInt32BigEndian(request.AsSpan(8), count);
                requests.Write(request);
            }
            requests.Position = 0;
            using var responses = new MemoryStream();
            await VerifiedArchiveReadAtServer.ServeAsync(archive, requests, responses, CancellationToken.None);
            byte[] result = responses.ToArray();
            Require(result.AsSpan(0, 8).SequenceEqual("KV13RA\0\0"u8)
                    && BinaryPrimitives.ReadInt64BigEndian(result.AsSpan(8, 8)) == source.Length,
                "Read-at handshake changed.");
            Require(result.AsSpan(16).SequenceEqual(source[500..].Concat(source[..17]).Concat(source[249..282]).ToArray()),
                "Read-at seeks returned incorrect byte ranges.");

            foreach ((long offset, uint count) in new[] { (-1L, 1u), (0L, 0u), (0L, 1_048_577u), (512L, 2u), (long.MaxValue, 1u) })
            {
                byte[] request = new byte[12];
                BinaryPrimitives.WriteInt64BigEndian(request, offset);
                BinaryPrimitives.WriteUInt32BigEndian(request.AsSpan(8), count);
                using var invalidRequests = new MemoryStream(request);
                using var rejectedOutput = new MemoryStream();
                bool rejected = false;
                try { await VerifiedArchiveReadAtServer.ServeAsync(archive, invalidRequests, rejectedOutput, CancellationToken.None); }
                catch (InvalidDataException) { rejected = true; }
                Require(rejected && rejectedOutput.Length == 16, "Invalid native request released archive bytes.");
            }
            using var truncated = new MemoryStream(new byte[11]);
            using var truncatedOutput = new MemoryStream();
            bool truncationRejected = false;
            try { await VerifiedArchiveReadAtServer.ServeAsync(archive, truncated, truncatedOutput, CancellationToken.None); }
            catch (EndOfStreamException) { truncationRejected = true; }
            Require(truncationRejected && truncatedOutput.Length == 16, "Truncated native request released archive bytes.");
        }
        finally { Directory.Delete(temporary, recursive: true); }
    }
}
