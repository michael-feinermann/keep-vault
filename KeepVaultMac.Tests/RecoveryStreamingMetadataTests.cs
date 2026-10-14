using System.Text;
using KalynaArchiver.Services;

internal static class RecoveryStreamingMetadataTests
{
    internal static IReadOnlyList<TestCase> Tests =>
    [
        new("recovery.streaming-metadata-canonical", "bounded KPAR4 canonical streaming preserves exact wire bytes", CanonicalAsync, TestResource.Light, "Security"),
        new("recovery.streaming-metadata-negative", "streaming metadata rejects duplicate, oversized, truncated and noncanonical JSON", NegativeAsync, TestResource.Light, "Security"),
        new("recovery.streaming-metadata-large-logical", "64-bit logical archive geometry with bounded disk-backed digest tables", LogicalAsync, TestResource.Light, "Security"),
    ];

    private static Task CanonicalAsync()
    {
        using var scope = new Scope();
        using var manifest = new RecoveryManifest { Version = 4, CreatedUtc = new DateTimeOffset(2000, 1, 1, 0, 0, 0, TimeSpan.Zero) };
        const string expected = "{\"version\":4,\"algorithm\":\"\",\"protectionMode\":0,\"archiveFileName\":\"\",\"archiveLength\":0,\"archiveSha3_512\":\"\",\"archiveSkein1024\":\"\",\"redundancyPercent\":0,\"createdUtc\":\"2000-01-01T00:00:00+00:00\",\"archiveId\":\"\",\"encryptionAlgorithm\":null,\"encryptionSuite\":-1,\"saltSha3Round1\":null,\"saltSkeinRound1\":null,\"saltSha3Round2\":null,\"saltSkeinRound2\":null,\"argon2MemoryKiB\":0,\"argon2Iterations\":0,\"argon2Parallelism\":0,\"sections\":[]}";
        using RecoveryMetadataStream serialized = RecoveryManifestCodec.Serialize(manifest, default);
        byte[] bytes = new byte[checked((int)serialized.Length)]; serialized.ReadExactly(bytes);
        Require(Encoding.UTF8.GetString(bytes) == expected, "KPAR4 canonical field order/encoding changed.");
        serialized.Position = 0;
        using RecoveryManifest parsed = RecoveryManifestCodec.Deserialize(serialized, 0, default);
        Require(parsed.Version == 4 && parsed.Sections.Count == 0, "Canonical empty manifest failed.");
        return Task.CompletedTask;
    }

    private static Task NegativeAsync()
    {
        using var scope = new Scope();
        using var manifest = new RecoveryManifest { Version = 4 };
        using RecoveryMetadataStream serialized = RecoveryManifestCodec.Serialize(manifest, default);
        byte[] bytes = new byte[checked((int)serialized.Length)]; serialized.ReadExactly(bytes);
        string canonical = Encoding.UTF8.GetString(bytes);
        foreach (string json in new[] { canonical + " ", canonical[..^1], canonical.Replace("\"version\":4", "\"version\":4,\"version\":4"), canonical.Replace("\"version\":4", "\"version\":4.0"), canonical.Replace("\"algorithm\":\"\"", "\"algorithm\":\"" + new string('x', 4097) + "\"") })
        {
            using var input = new MemoryStream(Encoding.UTF8.GetBytes(json));
            Expect<InvalidDataException>(() => { using var parsed = RecoveryManifestCodec.Deserialize(input, 0, default); });
        }
        using var truncated = new RecoveryMetadataStream();
        Expect<InvalidOperationException>(() => truncated.ReadByte());
        truncated.Write(bytes); truncated.Seal();
        Expect<InvalidOperationException>(() => truncated.WriteByte(1));
        return Task.CompletedTask;
    }

    private static Task LogicalAsync()
    {
        using var scope = new Scope();
        // The archive length is logical test geometry. Only ~2 MiB metadata is
        // generated; this is not evidence of having processed a 4-TiB archive.
        using var manifest = new RecoveryManifest { Version = 4, ArchiveLength = 4L << 40 };
        var section = new RecoverySection { Name = "Header", Offset = (1L << 40) + 17, Length = 4096 };
        manifest.Sections.Add(section);
        string digest = Convert.ToBase64String(new byte[64]) + ":" + Convert.ToBase64String(new byte[128]);
        for (int i = 0; i < 4096; i++) section.DataDigests.Add(digest);
        section.Parity.Add(new RecoveryParityShard(0, 0, (4L << 40) + 4096, 4096, digest));
        using RecoveryMetadataStream serialized = RecoveryManifestCodec.Serialize(manifest, default);
        Require(serialized.Length > 1 << 20, "Fixture did not span multiple metadata windows.");
        using RecoveryManifest parsed = RecoveryManifestCodec.Deserialize(serialized, manifest.ArchiveLength, default);
        Require(parsed.Sections[0].DataDigests.Count == 4096 && parsed.Sections[0].DataDigests[4095] == digest,
            "Disk-backed digest records differ after streamed parsing.");
        Require(parsed.Sections[0].Parity[0].Offset == (4L << 40) + 4096, "Parity offset was narrowed.");
        Require(Directory.GetFiles(scope.Root).Length == 0, "Private metadata file remained named.");
        return Task.CompletedTask;
    }

    private static void Require(bool condition, string message) { if (!condition) throw new Exception(message); }
    private static void Expect<T>(Action action) where T : Exception
    { try { action(); } catch (T) { return; } throw new Exception($"Expected {typeof(T).Name}."); }

    private sealed class Scope : IDisposable
    {
        internal string Root { get; } = Path.Combine(MacSafeFileSystem.ResolveExistingRealPath(Path.GetTempPath()), $"kv-recovery-stream-{Guid.NewGuid():N}");
        private readonly IDisposable _policy;
        private readonly IDisposable _budget;
        internal Scope()
        {
            Directory.CreateDirectory(Root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            _policy = new ArchiveOperationPolicy(Root, Root, maxContainerBytes: 8L << 40, maxMetadataBytes: 64L << 20).EnterScope();
            _budget = RecoveryMetadataBudget.Begin(64L << 20);
        }
        public void Dispose() { _budget.Dispose(); _policy.Dispose(); Directory.Delete(Root, true); }
    }
}
