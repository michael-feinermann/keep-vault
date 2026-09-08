using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

// A rollback comparison primitive only. The caller must separately verify
// Apple signatures, pinned hybrid signatures and release policy. This digest
// never says that a preserved app is trusted or is the current version.
internal static class PreservedAppFingerprint
{
    internal static string Compute(string app, string sidecarBase)
    {
        if (!Path.IsPathFullyQualified(app) || !Path.IsPathFullyQualified(sidecarBase))
            throw new ArgumentException("Preserved-app paths must be absolute.");
        app = Path.TrimEndingDirectorySeparator(Path.GetFullPath(app));
        sidecarBase = Path.GetFullPath(sidecarBase);
        if (!app.EndsWith(".app", StringComparison.Ordinal) || sidecarBase.StartsWith(app + "/", StringComparison.Ordinal))
            throw new ArgumentException("Expected an app directory and its external sidecar base.");
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Keep Vault/PreservedAppInventory/SHA256/v1\0"u8);
        var namespaceChecks = new List<Action>();
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        Walk(app, "app", hash, namespaceChecks, names, 0);
        foreach (string suffix in new[] { ".khsig", ".sha3", ".sha3.khsig", ".skein", ".skein.khsig" })
            FingerprintFile(sidecarBase + suffix, "sidecar" + suffix, hash, namespaceChecks, 65_536);
        foreach (Action check in namespaceChecks) check();
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private static void Walk(string path, string relative, IncrementalHash hash,
        List<Action> namespaceChecks, HashSet<string> names, int depth)
    {
        if (depth > 64 || names.Count >= 20_000) throw new InvalidDataException("The preserved app tree exceeds its bounds.");
        ValidateName(relative, names);
        using MacBoundFile.DirectoryLease directory = MacBoundFile.OpenDirectory(path);
        Header(hash, relative, 1, directory.Mode, 0);
        foreach (string child in Directory.EnumerateFileSystemEntries(path).Order(StringComparer.Ordinal))
        {
            string name = relative + "/" + Path.GetFileName(child);
            // Directory.Exists is only routing. Opening either resulting branch
            // enforces physical descriptor type and O_NOFOLLOW_ANY separately.
            if (Directory.Exists(child)) Walk(child, name, hash, namespaceChecks, names, depth + 1);
            else
            {
                ValidateName(name, names);
                FingerprintFile(child, name, hash, namespaceChecks);
            }
        }
        directory.AssertStable();
        namespaceChecks.Add(directory.CaptureNamespaceCheck());
    }

    private static void ValidateName(string name, HashSet<string> names)
    {
        if (name.Length > 4096 || name.Any(char.IsControl) || name.Contains('\\')
            || name.Split('/').Any(part => part is "" or "." or "..")
            || names.Count >= 20_000 || !names.Add(name.Normalize(NormalizationForm.FormC)))
            throw new InvalidDataException("Invalid, ambiguous or excessive preserved-app inventory path.");
    }

    private static void FingerprintFile(string path, string relative, IncrementalHash hash,
        List<Action> namespaceChecks, long maximumBytes = 8L * 1024 * 1024 * 1024)
    {
        using MacBoundFile file = MacBoundFile.Open(path, maximumBytes);
        Header(hash, relative, 2, file.Mode, file.Length);
        byte[] buffer = new byte[1024 * 1024];
        long read = 0;
        int count;
        while ((count = file.Stream.Read(buffer)) != 0)
        {
            read = checked(read + count);
            if (read > file.Length) throw new IOException("A preserved app file grew during its read.");
            hash.AppendData(buffer, 0, count);
        }
        if (read != file.Length) throw new IOException("A preserved app file shrank during its read.");
        file.AssertStable();
        namespaceChecks.Add(file.CaptureNamespaceCheck());
    }

    private static void Header(IncrementalHash hash, string path, byte type, int mode, long length)
    {
        byte[] name = new UTF8Encoding(false, true).GetBytes(path);
        Span<byte> header = stackalloc byte[17];
        header[0] = type;
        BinaryPrimitives.WriteInt32LittleEndian(header[1..], name.Length);
        BinaryPrimitives.WriteInt32LittleEndian(header[5..], mode);
        BinaryPrimitives.WriteInt64LittleEndian(header[9..], length);
        hash.AppendData(header);
        hash.AppendData(name);
    }
}
