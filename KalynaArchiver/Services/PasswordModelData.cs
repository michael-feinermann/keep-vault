using System.IO;
using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace KalynaArchiver.Services;

/// <summary>Public, versioned analysis data. This type is never required by a KDF or archive reader.</summary>
internal sealed class PasswordModelData
{
    internal const string Version = "keep-vault-password-model-2026-09-06-v1";
    internal const string ManifestSha256 = "2f6ec374c19496eb548e4270a972bde0bc3146748d20c72781c0a34c03a8f0e4";
    internal const string ResourcePrefix = "KeepVault.PasswordModel.";
    private const int MaximumResourceBytes = 2 * 1024 * 1024;
    internal Dictionary<string, string[]> Lists { get; } = new(StringComparer.Ordinal);
    internal Dictionary<string, HashSet<string>> ListSets { get; } = new(StringComparer.Ordinal);
    internal Dictionary<string, int> Bip39Indices { get; } = new(StringComparer.Ordinal);
    internal HashSet<string> Blocklist { get; } = new(StringComparer.Ordinal);
    internal Dictionary<string, Word> Words { get; } = new(StringComparer.Ordinal);
    internal TrieNode Root { get; } = new();
    internal TrieNode Bip39Root { get; } = new();
    internal int NormalizedCollisions { get; private set; }
    internal int MaximumWordLength { get; private set; }

    internal sealed record Word(double Bits, string Family, PasswordPatternReasons Reason);
    internal sealed class TrieNode
    {
        internal Dictionary<char, TrieNode> Children { get; } = new();
        internal Word? Word { get; set; }
        internal int? Bip39Index { get; set; }
    }

    internal static Stream? OpenEmbeddedResource(string file) =>
        typeof(PasswordModelData).Assembly.GetManifestResourceStream(ResourcePrefix + file);

    // The resource factory permits tests of the real parser/integrity checks; it cannot replace
    // the production Lazy instance or cause an unavailable model to accept a password.
    internal static PasswordModelData Load(Func<string, Stream?>? openResource = null)
    {
        PasswordGuessabilityService.AssertModelAccessAllowedForTesting();
        openResource ??= OpenEmbeddedResource;
        byte[] manifestBytes = ReadResource(openResource, "manifest.json");
        VerifyHash(manifestBytes, ManifestSha256);
        using JsonDocument manifest = JsonDocument.Parse(manifestBytes);
        JsonElement document = manifest.RootElement;
        if (document.GetProperty("version").GetString() != Version || document.GetProperty("schema").GetInt32() != 1)
            throw new InvalidDataException("Unsupported password model metadata.");
        var data = new PasswordModelData();
        foreach (JsonElement file in document.GetProperty("licenseFiles").EnumerateArray())
        {
            byte[] content = ReadResource(openResource, file.GetProperty("file").GetString() ?? string.Empty);
            VerifyHash(content, file.GetProperty("sha256").GetString() ?? string.Empty);
        }
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonElement file in document.GetProperty("files").EnumerateArray())
        {
            string name = file.GetProperty("file").GetString() ?? throw new InvalidDataException();
            if (Path.GetFileName(name) != name || !names.Add(name))
                throw new InvalidDataException("Invalid password model resource name.");
            byte[] bytes = ReadResource(openResource, name);
            VerifyHash(bytes, file.GetProperty("sha256").GetString() ?? string.Empty);
            string text = new UTF8Encoding(false, true).GetString(bytes);
            if (!text.EndsWith('\n') || text.Contains('\r') || text.Contains('\0'))
                throw new InvalidDataException("Invalid password model text encoding.");
            string[] entries = text[..^1].Split('\n');
            if (entries.Length != file.GetProperty("count").GetInt32()
                || entries.Any(static word => word.Length == 0 || word.Contains('\t')
                    || !word.IsNormalized(NormalizationForm.FormC) || word != word.ToLowerInvariant())
                || entries.Distinct(StringComparer.Ordinal).Count() != entries.Length)
                throw new InvalidDataException("Invalid password model entry count or normalization.");
            string kind = file.GetProperty("kind").GetString() ?? string.Empty;
            if (kind is "list" or "bip39")
            {
                int expected = kind == "bip39" ? 2048 : 7776;
                if (entries.Length != expected) throw new InvalidDataException("Wrong fixed word-list size.");
                data.Lists.Add(name, entries);
                data.ListSets.Add(name, new HashSet<string>(entries, StringComparer.Ordinal));
            }
            if (kind == "bip39")
                for (int index = 0; index < entries.Length; index++)
                {
                    data.Bip39Indices.Add(entries[index], index);
                    TrieNode node = data.Bip39Root;
                    foreach (char character in entries[index])
                    {
                        if (!node.Children.TryGetValue(character, out TrieNode? next)) node.Children.Add(character, next = new TrieNode());
                        node = next;
                    }
                    node.Bip39Index = index;
                }
            for (int index = 0; index < entries.Length; index++)
            {
                string entry = entries[index];
                if (kind == "blocklist") data.Blocklist.Add(entry);
                double bits = kind switch
                {
                    "rank" or "blocklist" => Math.Log2(index + 1),
                    "list" or "bip39" or "names" or "phrases" => Math.Log2(entries.Length),
                    _ => throw new InvalidDataException("Unknown password model entry kind."),
                };
                PasswordPatternReasons reason = kind switch
                {
                    "list" or "bip39" => PasswordPatternReasons.WordList,
                    "names" => PasswordPatternReasons.Name,
                    "phrases" => PasswordPatternReasons.KnownPhrase,
                    _ => PasswordPatternReasons.RankedWord,
                };
                data.AddWord(entry, new Word(bits, name, reason));
                if (entry.Contains(' ') && kind is "phrases" or "blocklist")
                    data.AddWord(entry.Replace(" ", string.Empty, StringComparison.Ordinal), new Word(bits + 1, name, reason));
                string ascii = TransliterateGerman(entry);
                if (ascii != entry) data.AddWord(ascii, new Word(bits + 2, name, reason | PasswordPatternReasons.UnicodeVariant));
            }
        }
        if (names.Count != 11 || data.Lists.Count != 3 || data.Bip39Indices.Count != 2048 || data.Blocklist.Count < 30000)
            throw new InvalidDataException("Incomplete password model.");
        foreach ((string word, Word info) in data.Words)
        {
            TrieNode node = data.Root;
            foreach (char character in word)
            {
                if (!node.Children.TryGetValue(character, out TrieNode? next))
                    node.Children.Add(character, next = new TrieNode());
                node = next;
            }
            node.Word = info;
            data.MaximumWordLength = Math.Max(data.MaximumWordLength, word.Length);
        }
        return data;
    }

    private void AddWord(string word, Word information)
    {
        if (Words.TryGetValue(word, out Word? existing))
        {
            NormalizedCollisions++;
            if (existing.Bits <= information.Bits) return;
        }
        Words[word] = information;
    }

    internal static string TransliterateGerman(string value) => value
        .Replace("ä", "ae", StringComparison.Ordinal).Replace("ö", "oe", StringComparison.Ordinal)
        .Replace("ü", "ue", StringComparison.Ordinal).Replace("ß", "ss", StringComparison.Ordinal);

    private static byte[] ReadResource(Func<string, Stream?> open, string name)
    {
        using Stream stream = open(name) ?? throw new InvalidDataException("Missing password model resource.");
        using var output = new MemoryStream();
        byte[] buffer = new byte[8192];
        int count;
        while ((count = stream.Read(buffer)) != 0)
        {
            if (output.Length + count > MaximumResourceBytes) throw new InvalidDataException("Oversized password model resource.");
            output.Write(buffer, 0, count);
        }
        return output.ToArray();
    }

    private static void VerifyHash(byte[] value, string expected)
    {
        if (expected.Length != 64 || !CryptographicOperations.FixedTimeEquals(SHA256.HashData(value), Convert.FromHexString(expected)))
            throw new InvalidDataException("Password model integrity check failed.");
    }
}
