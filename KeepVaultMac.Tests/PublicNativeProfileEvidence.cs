using System.Security.Cryptography;
using KalynaArchiver.Services;

/// <summary>Public test evidence only. It is never linked into the GUI.</summary>
internal static class PublicNativeProfileEvidence
{
    // These are the actual native routes used by the full archive workflow.
    // The separate argon2 command-line tool is not used by V13MasterKdf.
    private static readonly string[] LogicalNames =
    [
        "zpaq.exe", "kalyna_v13.dll", "threefish_ref.dll", "mars_ref.dll", "camellia_v13.dll",
        "serpent_v13.dll", "shacal2_ref.dll", "aes_ref.dll", "xchachapoly_v13.dll", "argon2_ref.dll",
    ];

    internal const string Interpretation = "SHA-256 of resolved production native inputs before and after the workflow. The trusted loader authenticates sealed files or equivalent private snapshots before loading; executable launch uses a trusted lease. This records file-byte provenance, not a digest of mapped process memory. No installed AOT GUI phase observation is claimed.";

    internal static IReadOnlyDictionary<string, string> Capture()
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string logicalName in LogicalNames)
        {
            string path = NativeToolIntegrity.ResolveKnownTool(logicalName)
                ?? throw new InvalidOperationException("A required profile native input is missing: " + logicalName);
            result.Add(Path.GetFileName(path), HashFile(path));
        }
        return result;
    }

    internal static string AssemblySha256() => HashFile(typeof(KalynaContainerService).Assembly.Location);

    internal static void RequireUnchanged(IReadOnlyDictionary<string, string> reference)
    {
        IReadOnlyDictionary<string, string> current = Capture();
        if (reference.Count != current.Count || reference.Any(pair => !current.TryGetValue(pair.Key, out string? digest) || digest != pair.Value))
            throw new InvalidOperationException("A production native profile input changed during the workflow.");
    }

    private static string HashFile(string path)
    {
        using FileStream stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }
}
