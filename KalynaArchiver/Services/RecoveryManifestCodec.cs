using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;

namespace KalynaArchiver.Services;

/// <summary>Canonical KPAR2 v4 JSON, streamed with bounded tokens and disk-backed lists.</summary>
internal static class RecoveryManifestCodec
{
    internal static RecoveryMetadataStream Serialize(RecoveryManifest m, CancellationToken token)
    {
        var stream = new RecoveryMetadataStream();
        try
        {
            using (var w = new Utf8JsonWriter(stream))
            {
                w.WriteStartObject();
                w.WriteNumber("version", m.Version);
                if (m.ContainerVersion is int v) w.WriteNumber("containerVersion", v);
                w.WriteString("algorithm", m.Algorithm);
                w.WriteNumber("protectionMode", (int)m.ProtectionMode);
                w.WriteString("archiveFileName", m.ArchiveFileName);
                w.WriteNumber("archiveLength", m.ArchiveLength);
                w.WriteString("archiveSha3_512", m.ArchiveSha3_512);
                w.WriteString("archiveSkein1024", m.ArchiveSkein1024);
                w.WriteNumber("redundancyPercent", m.RedundancyPercent);
                w.WriteString("createdUtc", m.CreatedUtc);
                w.WriteString("archiveId", m.ArchiveId);
                w.WriteString("encryptionAlgorithm", m.EncryptionAlgorithm);
                w.WriteNumber("encryptionSuite", m.EncryptionSuite);
                w.WriteString("saltSha3Round1", m.SaltSha3Round1);
                w.WriteString("saltSkeinRound1", m.SaltSkeinRound1);
                w.WriteString("saltSha3Round2", m.SaltSha3Round2);
                w.WriteString("saltSkeinRound2", m.SaltSkeinRound2);
                w.WriteNumber("argon2MemoryKiB", m.Argon2MemoryKiB);
                w.WriteNumber("argon2Iterations", m.Argon2Iterations);
                w.WriteNumber("argon2Parallelism", m.Argon2Parallelism);
                w.WriteStartArray("sections");
                foreach (RecoverySection s in m.Sections)
                {
                    w.WriteStartObject();
                    w.WriteString("name", s.Name);
                    w.WriteNumber("offset", s.Offset);
                    w.WriteNumber("length", s.Length);
                    w.WriteNumber("shardSize", s.ShardSize);
                    w.WriteNumber("dataShardCount", s.DataShardCount);
                    w.WriteNumber("parityShardCount", s.ParityShardCount);
                    w.WriteNumber("stripeCount", s.StripeCount);
                    w.WriteStartArray("dataDigests");
                    foreach (string digest in s.DataDigests)
                    { token.ThrowIfCancellationRequested(); w.WriteStringValue(digest); if (w.BytesPending >= 65536) w.Flush(); }
                    w.WriteEndArray();
                    w.WriteStartArray("parity");
                    foreach (RecoveryParityShard p in s.Parity)
                    {
                        token.ThrowIfCancellationRequested();
                        w.WriteStartObject(); w.WriteNumber("stripe", p.Stripe); w.WriteNumber("parityIndex", p.ParityIndex);
                        w.WriteNumber("offset", p.Offset); w.WriteNumber("length", p.Length); w.WriteString("digest", p.Digest); w.WriteEndObject();
                        if (w.BytesPending >= 65536) w.Flush();
                    }
                    w.WriteEndArray(); w.WriteEndObject();
                }
                w.WriteEndArray(); w.WriteEndObject(); w.Flush();
            }
            stream.Seal();
            return stream;
        }
        catch { stream.Dispose(); throw; }
    }

    internal static RecoveryManifest Deserialize(Stream payload, long expectedArchiveLength, CancellationToken token)
    {
        long stripes = expectedArchiveLength == 0 ? 0 : checked(2 + (expectedArchiveLength - 1) / (20L * 4 * 1024 * 1024) + 1);
        long maxData = checked(stripes * 20), maxParity = checked(stripes * 3);
        var r = new TokenReader(payload, checked(512 + maxData + 12 * maxParity), token);
        var m = new RecoveryManifest();
        try
        {
            r.Expect(JsonTokenType.StartObject);
            m.Version = r.Int32("version");
            string next = r.Property();
            if (next == "containerVersion") { m.ContainerVersion = r.Int32Value(); next = r.Property(); }
            r.Require(next == "algorithm"); m.Algorithm = r.StringValue()!;
            m.ProtectionMode = (RecoveryProtectionMode)r.Int32("protectionMode");
            m.ArchiveFileName = r.String("archiveFileName")!;
            m.ArchiveLength = r.Int64("archiveLength");
            r.Require(m.ArchiveLength == expectedArchiveLength);
            m.ArchiveSha3_512 = r.String("archiveSha3_512")!;
            m.ArchiveSkein1024 = r.String("archiveSkein1024")!;
            m.RedundancyPercent = r.Int32("redundancyPercent");
            m.CreatedUtc = DateTimeOffset.Parse(r.String("createdUtc")!, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
            m.ArchiveId = r.String("archiveId")!;
            m.EncryptionAlgorithm = r.String("encryptionAlgorithm", nullable: true);
            m.EncryptionSuite = r.Int32("encryptionSuite");
            m.SaltSha3Round1 = r.String("saltSha3Round1", nullable: true);
            m.SaltSkeinRound1 = r.String("saltSkeinRound1", nullable: true);
            m.SaltSha3Round2 = r.String("saltSha3Round2", nullable: true);
            m.SaltSkeinRound2 = r.String("saltSkeinRound2", nullable: true);
            m.Argon2MemoryKiB = r.Int32("argon2MemoryKiB"); m.Argon2Iterations = r.Int32("argon2Iterations");
            m.Argon2Parallelism = r.Int32("argon2Parallelism");
            r.ExpectProperty("sections"); r.Expect(JsonTokenType.StartArray);
            long dataCount = 0, parityCount = 0;
            while (r.Next() != JsonTokenType.EndArray)
            {
                r.Require(r.Type == JsonTokenType.StartObject && m.Sections.Count < 2);
                var s = new RecoverySection(); m.Sections.Add(s);
                s.Name = r.String("name")!; s.Offset = r.Int64("offset"); s.Length = r.Int64("length");
                s.ShardSize = r.Int32("shardSize"); s.DataShardCount = r.Int32("dataShardCount");
                s.ParityShardCount = r.Int32("parityShardCount"); s.StripeCount = r.Int32("stripeCount");
                r.ExpectProperty("dataDigests"); r.Expect(JsonTokenType.StartArray);
                while (r.Next() != JsonTokenType.EndArray)
                {
                    r.Require(r.Type == JsonTokenType.String && ++dataCount <= maxData);
                    s.DataDigests.Add(r.Text!);
                }
                r.ExpectProperty("parity"); r.Expect(JsonTokenType.StartArray);
                while (r.Next() != JsonTokenType.EndArray)
                {
                    r.Require(r.Type == JsonTokenType.StartObject && ++parityCount <= maxParity);
                    int stripe = r.Int32("stripe"), parityIndex = r.Int32("parityIndex");
                    long offset = r.Int64("offset"); int length = r.Int32("length"); string digest = r.String("digest")!;
                    r.Expect(JsonTokenType.EndObject);
                    s.Parity.Add(new RecoveryParityShard(stripe, parityIndex, offset, length, digest));
                }
                r.Expect(JsonTokenType.EndObject);
            }
            r.Expect(JsonTokenType.EndObject); r.Require(r.Next() == JsonTokenType.None);
            using RecoveryMetadataStream canonical = Serialize(m, token);
            payload.Position = 0;
            CompareExactly(payload, canonical, token);
            return m;
        }
        catch (Exception error) when (error is JsonException or FormatException or OverflowException)
        { m.Dispose(); throw new InvalidDataException("KPAR2 manifest is not valid canonical bounded JSON.", error); }
        catch { m.Dispose(); throw; }
    }

    private static void CompareExactly(Stream original, Stream canonical, CancellationToken token)
    {
        if (original.Length != canonical.Length) throw new InvalidDataException("KPAR2 manifest is not canonical.");
        byte[] left = new byte[65536], right = new byte[65536];
        try
        {
            while (original.Position < original.Length)
            {
                token.ThrowIfCancellationRequested();
                int count = checked((int)Math.Min(left.Length, original.Length - original.Position));
                original.ReadExactly(left.AsSpan(0, count)); canonical.ReadExactly(right.AsSpan(0, count));
                if (!left.AsSpan(0, count).SequenceEqual(right.AsSpan(0, count))) throw new InvalidDataException("KPAR2 manifest is not canonical.");
            }
        }
        finally { CryptographicOperations.ZeroMemory(left); CryptographicOperations.ZeroMemory(right); }
    }

    private sealed class TokenReader(Stream stream, long maxTokens, CancellationToken token)
    {
        private readonly byte[] _buffer = new byte[8192];
        private JsonReaderState _state = new(new JsonReaderOptions { MaxDepth = 8, AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow });
        private int _offset, _count;
        private bool _eof;
        private long _tokens;
        internal JsonTokenType Type { get; private set; }
        internal string? Text { get; private set; }
        private long _number;
        internal void Require(bool condition) { if (!condition) throw new InvalidDataException("KPAR2 manifest has an unexpected token, property or collection size."); }
        internal JsonTokenType Next()
        {
            for (;;)
            {
                token.ThrowIfCancellationRequested();
                var reader = new Utf8JsonReader(_buffer.AsSpan(_offset, _count - _offset), _eof, _state);
                if (reader.Read())
                {
                    Type = reader.TokenType; Text = null;
                    int limit = Type == JsonTokenType.PropertyName ? 64 : Type == JsonTokenType.Number ? 32 : 4096;
                    Require(reader.ValueSpan.Length <= limit && ++_tokens <= maxTokens);
                    if (Type is JsonTokenType.String or JsonTokenType.PropertyName) Text = reader.GetString();
                    if (Type == JsonTokenType.Number) _number = reader.GetInt64();
                    _offset += checked((int)reader.BytesConsumed); _state = reader.CurrentState;
                    return Type;
                }
                _offset += checked((int)reader.BytesConsumed); _state = reader.CurrentState;
                if (_eof) return Type = JsonTokenType.None;
                int remaining = _count - _offset;
                Require(remaining < _buffer.Length);
                _buffer.AsSpan(_offset, remaining).CopyTo(_buffer);
                _offset = 0; _count = remaining;
                int read = stream.Read(_buffer, remaining, _buffer.Length - remaining);
                _count += read; _eof = read == 0;
            }
        }
        internal void Expect(JsonTokenType type) => Require(Next() == type);
        internal string Property() { Expect(JsonTokenType.PropertyName); return Text!; }
        internal void ExpectProperty(string name) => Require(Property() == name);
        internal int Int32Value() { Expect(JsonTokenType.Number); return checked((int)_number); }
        internal int Int32(string name) { ExpectProperty(name); return Int32Value(); }
        internal long Int64(string name) { ExpectProperty(name); Expect(JsonTokenType.Number); return _number; }
        internal string? StringValue(bool nullable = false)
        { Next(); Require(Type == JsonTokenType.String || (nullable && Type == JsonTokenType.Null)); return Text; }
        internal string? String(string name, bool nullable = false) { ExpectProperty(name); return StringValue(nullable); }
    }
}
