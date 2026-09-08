using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using KalynaArchiver.Signing;

internal static class InstallationManifestVerifier
{
    private const string ManifestName = "installation-manifest.json";
    private const int MaximumManifestBytes = 8 * 1024 * 1024;
    private const int MaximumEntries = 20_000;
    private static readonly string[] Sidecars = [".sha3", ".skein", ".khsig", ".sha3.khsig", ".skein.khsig"];
    private sealed record Entry(string Path, bool Directory, int Mode, long Size, byte[] Sha256);

    internal static void Verify(string root, HybridSignaturePolicy policy, bool requireRootOwned = false)
    {
        if (!Path.IsPathFullyQualified(root)) throw new ArgumentException("The installation root must be absolute.");
        root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        if (root == "/") throw new ArgumentException("The filesystem root cannot be an installation kit.");
        using MacBoundFile.DirectoryLease rootLease = MacBoundFile.OpenDirectory(root);
        if (requireRootOwned) rootLease.RequireRootOwned();
        string manifestPath = Path.Combine(root, ManifestName);
        using MacBoundFile manifest = MacBoundFile.Open(manifestPath, MaximumManifestBytes);
        var namespaceChecks = new List<Action>();
        // Authenticate all six fixed manifest files before parsing an entry or
        // treating any package pathname as an expected object.
        InstallationVerifierCommands.VerifyStrictArtifact(manifestPath, manifestPath, policy, namespaceChecks);
        manifest.AssertStable();
        using JsonDocument json = JsonDocument.Parse(manifest.ReadAll(MaximumManifestBytes),
            new JsonDocumentOptions { AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow, MaxDepth = 8 });
        Dictionary<string, JsonElement> document = Object(json.RootElement, ["schemaVersion", "version", "build", "entries"]);
        if (!document["schemaVersion"].TryGetInt32(out int schema) || schema != 1
            || document["version"].GetString() != "5.0.2" || document["build"].GetString() != "13")
            throw new InvalidDataException("The installation manifest has an unsupported schema, version or build.");
        JsonElement entries = document["entries"];
        if (entries.ValueKind != JsonValueKind.Array || entries.GetArrayLength() is < 1 or > MaximumEntries)
            throw new InvalidDataException("Invalid installation inventory length.");
        var expected = new Dictionary<string, Entry>(StringComparer.Ordinal);
        var normalizedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        HashSet<string> exclusions = new(Sidecars.Select(suffix => ManifestName + suffix), StringComparer.Ordinal) { ManifestName };
        foreach (JsonElement element in entries.EnumerateArray())
        {
            Dictionary<string, JsonElement> properties = Object(element, ["path", "kind", "mode"], ["size", "sha256"]);
            string path = properties["path"].GetString() ?? throw new InvalidDataException("An inventory path is missing.");
            ValidateRelativePath(path);
            if (exclusions.Contains(path) || !normalizedPaths.Add(path.Normalize(NormalizationForm.FormC)))
                throw new InvalidDataException("Duplicate, ambiguous or self-referential installation path.");
            string kind = properties["kind"].GetString() ?? "";
            if (kind is not ("file" or "directory") || !properties["mode"].TryGetInt32(out int mode)
                || mode is < 0 or > 511 || (mode & 0x12) != 0)
                throw new InvalidDataException("Invalid inventory type or protected Unix mode.");
            bool directory = kind == "directory";
            long size = 0;
            byte[] sha256 = [];
            if (directory)
            {
                if ((mode & 0x140) != 0x140 || properties.ContainsKey("size") || properties.ContainsKey("sha256"))
                    throw new InvalidDataException("A directory entry has invalid permissions or file-only fields.");
            }
            else
            {
                if (!properties.TryGetValue("size", out JsonElement length) || !length.TryGetInt64(out size)
                    || size is < 0 or > 8L * 1024 * 1024 * 1024
                    || !properties.TryGetValue("sha256", out JsonElement digest))
                    throw new InvalidDataException("A file entry lacks a bounded size and SHA-256 digest.");
                string hex = digest.GetString() ?? "";
                if (hex.Length != 64 || !hex.All(Uri.IsHexDigit)) throw new InvalidDataException("Invalid inventory SHA-256 digest.");
                sha256 = Convert.FromHexString(hex);
            }
            if (!expected.TryAdd(path, new(path, directory, mode, size, sha256)))
                throw new InvalidDataException("Duplicate inventory path.");
        }
        RequireExactTopLevel(expected);
        var actual = new HashSet<string>(StringComparer.Ordinal);
        Walk(root, root, expected, actual, exclusions, namespaceChecks, requireRootOwned, depth: 0);
        if (actual.Count != expected.Count || expected.Keys.Any(path => !actual.Contains(path)))
            throw new InvalidDataException("The installation kit is missing an inventoried path.");
        VerifyBundleMetadata(root, "Keep Vault.app", "de.michael-feinermann.keep-vault", expected);
        VerifyBundleMetadata(root, "QR-Scanner.app", "de.michael-feinermann.qr-scanner", expected);
        VerifyBundleMetadata(root, "Keep Vault Installer.app", "de.michael-feinermann.keep-vault.installer", expected);
        foreach (Action check in namespaceChecks) check();
        manifest.AssertStable();
        rootLease.AssertStable();
        Console.WriteLine("installation_manifest=verified");
        Console.WriteLine("installation_entries=" + actual.Count);
    }

    private static void Walk(string root, string directory, Dictionary<string, Entry> expected,
        HashSet<string> actual, HashSet<string> exclusions, List<Action> namespaceChecks, bool requireRootOwned, int depth)
    {
        if (depth > 64) throw new InvalidDataException("The installation directory tree is too deep.");
        using MacBoundFile.DirectoryLease directoryLease = MacBoundFile.OpenDirectory(directory);
        if (requireRootOwned) directoryLease.RequireRootOwned();
        foreach (string path in Directory.EnumerateFileSystemEntries(directory))
        {
            string relative = Path.GetRelativePath(root, path).Replace(Path.DirectorySeparatorChar, '/');
            ValidateRelativePath(relative);
            if (exclusions.Contains(relative))
            {
                using MacBoundFile excluded = MacBoundFile.Open(path, relative == ManifestName ? MaximumManifestBytes : 65_536);
                if (requireRootOwned) excluded.RequireRootOwned();
                excluded.AssertStable();
                continue;
            }
            if (!expected.TryGetValue(relative, out Entry? entry) || !actual.Add(relative))
                throw new InvalidDataException("An additional or ambiguous object is present in the installation kit: " + relative);
            if (entry.Directory)
            {
                using MacBoundFile.DirectoryLease childLease = MacBoundFile.OpenDirectory(path);
                if (childLease.Mode != entry.Mode) throw new InvalidDataException("Directory mode differs from the signed inventory: " + relative);
                Walk(root, path, expected, actual, exclusions, namespaceChecks, requireRootOwned, depth + 1);
                childLease.AssertStable();
            }
            else
            {
                using MacBoundFile file = MacBoundFile.Open(path);
                if (requireRootOwned) file.RequireRootOwned();
                if (file.Mode != entry.Mode || file.Length != entry.Size)
                    throw new InvalidDataException("File mode or size differs from the signed inventory: " + relative);
                byte[] digest = SHA256.HashData(file.Stream);
                if (!CryptographicOperations.FixedTimeEquals(digest, entry.Sha256))
                    throw new CryptographicException("File digest differs from the signed inventory: " + relative);
                file.AssertStable();
                namespaceChecks.Add(file.CaptureNamespaceCheck());
            }
        }
        directoryLease.AssertStable();
        namespaceChecks.Add(directoryLease.CaptureNamespaceCheck());
    }

    private static void VerifyBundleMetadata(string root, string bundle, string identifier, Dictionary<string, Entry> expected)
    {
        string relative = bundle + "/Contents/Info.plist";
        if (!expected.TryGetValue(relative, out Entry? entry) || entry.Directory)
            throw new InvalidDataException("An app Info.plist is absent from the inventory.");
        using MacBoundFile file = MacBoundFile.Open(Path.Combine(root, relative), 1024 * 1024);
        byte[] bytes = file.ReadAll(1024 * 1024);
        if (file.Mode != entry.Mode || file.Length != entry.Size
            || !CryptographicOperations.FixedTimeEquals(SHA256.HashData(bytes), entry.Sha256))
            throw new IOException("App metadata changed after inventory verification.");
        using var stream = new MemoryStream(bytes, writable: false);
        using XmlReader reader = XmlReader.Create(stream, new XmlReaderSettings
        { DtdProcessing = DtdProcessing.Ignore, XmlResolver = null, MaxCharactersInDocument = 1024 * 1024, MaxCharactersFromEntities = 0 });
        XDocument plist = XDocument.Load(reader, LoadOptions.None);
        XElement dictionary = plist.Root?.Name == "plist" && plist.Root.Elements().Count() == 1
            ? plist.Root.Element("dict") ?? throw new InvalidDataException("Expected an XML property-list dictionary.")
            : throw new InvalidDataException("Expected one XML property-list dictionary.");
        XElement[] nodes = dictionary.Elements().ToArray();
        if ((nodes.Length & 1) != 0) throw new InvalidDataException("Malformed app property-list entries.");
        var values = new Dictionary<string, XElement>(StringComparer.Ordinal);
        for (int i = 0; i < nodes.Length; i += 2)
        {
            if (nodes[i].Name != "key" || !values.TryAdd(nodes[i].Value, nodes[i + 1]))
                throw new InvalidDataException("Duplicate or malformed app property-list key.");
        }
        foreach ((string key, string value) in new[] {
                     ("CFBundleIdentifier", identifier), ("CFBundleShortVersionString", "5.0.2"), ("CFBundleVersion", "13") })
        {
            if (!values.TryGetValue(key, out XElement? actual) || actual.Name != "string" || actual.HasElements || actual.Value != value)
                throw new InvalidDataException("App metadata does not match the installation manifest: " + key);
        }
        file.AssertStable();
    }

    private static void RequireExactTopLevel(Dictionary<string, Entry> entries)
    {
        var roots = new Dictionary<string, bool>(StringComparer.Ordinal)
        { ["Keep Vault.app"] = true, ["QR-Scanner.app"] = true, ["Keep Vault Installer.app"] = true, ["INSTALLATION.txt"] = false };
        foreach (string suffix in Sidecars)
        {
            roots.Add("Keep Vault.app.launcher" + suffix, false);
            roots.Add("QR-Scanner.app" + suffix, false);
        }
        string[] actualRoots = entries.Keys.Where(path => !path.Contains('/')).ToArray();
        if (actualRoots.Length != roots.Count || actualRoots.Any(path => !roots.TryGetValue(path, out bool directory) || entries[path].Directory != directory))
            throw new InvalidDataException("The installation manifest must contain the exact three-app installation kit and pair sidecars.");
        foreach (Entry entry in entries.Values)
        {
            int separator = entry.Path.LastIndexOf('/');
            if (separator >= 0 && (!entries.TryGetValue(entry.Path[..separator], out Entry? parent) || !parent.Directory))
                throw new InvalidDataException("An inventory parent directory is missing or is not a directory.");
        }
    }

    private static void ValidateRelativePath(string path)
    {
        if (path.Length is < 1 or > 4096 || Path.IsPathRooted(path) || path.Contains('\\')
            || path.Any(char.IsControl) || path.Split('/').Any(part => part is "" or "." or ".."))
            throw new InvalidDataException("Invalid relative installation path.");
    }

    private static Dictionary<string, JsonElement> Object(JsonElement element, string[] required, string[]? optional = null)
    {
        if (element.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Expected a JSON inventory object.");
        var result = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (JsonProperty property in element.EnumerateObject())
        {
            if (!(required.Contains(property.Name, StringComparer.Ordinal) || optional?.Contains(property.Name, StringComparer.Ordinal) == true)
                || !result.TryAdd(property.Name, property.Value))
                throw new InvalidDataException("Duplicate or unknown JSON inventory field.");
        }
        if (required.Any(name => !result.ContainsKey(name))) throw new InvalidDataException("A required JSON inventory field is absent.");
        return result;
    }
}
