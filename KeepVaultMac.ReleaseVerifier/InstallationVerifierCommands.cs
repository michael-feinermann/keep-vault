using System.Security.Cryptography;
using System.Text;
using KalynaArchiver.Services;
using KalynaArchiver.Signing;

internal static class InstallationVerifierCommands
{
    internal static bool TryRun(string[] args, out int result)
    {
        result = 0;
        if (args[0] == "fingerprint-preserved-app")
        {
            Dictionary<string, string> values = ParseOptions(args, ["--app", "--sidecar-base"]);
            Console.WriteLine(PreservedAppFingerprint.Compute(Require(values, "--app"), Require(values, "--sidecar-base")));
            return true;
        }
        if (args[0] == "verify-installation")
        {
            Dictionary<string, string> values = ParseOptions(args, ["--root"], "--require-root-owned");
            InstallationManifestVerifier.Verify(Require(values, "--root"), Policy(), values.ContainsKey("--require-root-owned"));
            return true;
        }
        if (args[0] == "inspect-macho")
        {
            Dictionary<string, string> values = ParseOptions(args, ["--file", "--require-architectures"]);
            string file = Require(values, "--file");
            string architectures = MachOInspector.Inspect(file);
            if (values.TryGetValue("--require-architectures", out string? required) && architectures != required)
                throw new InvalidDataException("Mach-O architectures do not match the required set.");
            Console.WriteLine(architectures);
            return true;
        }
        if (args[0] == "verify-artifact")
        {
            Dictionary<string, string> values = ParseOptions(args, ["--payload", "--sidecar-base"], "--require-all-sidecars");
            if (!values.ContainsKey("--require-all-sidecars")) throw new ArgumentException("--require-all-sidecars is mandatory.");
            VerifyStrictArtifact(Require(values, "--payload"), Require(values, "--sidecar-base"), Policy());
            return true;
        }
        if (args[0] != "verify") return false;

        var targets = new List<string>();
        var options = new Dictionary<string, string>(StringComparer.Ordinal);
        for (int i = 1; i < args.Length; i++)
        {
            string key = args[i];
            if (key is not ("--target" or "--payload-root" or "--signature-root") || ++i >= args.Length)
                throw new ArgumentException("Expected --target FILE and an optional paired --payload-root/--signature-root.");
            if (key == "--target") targets.Add(Path.GetFullPath(args[i]));
            else if (!options.TryAdd(key, Path.TrimEndingDirectorySeparator(Path.GetFullPath(args[i]))))
                throw new ArgumentException("Duplicate option: " + key);
        }
        if (targets.Count is < 1 or > 256 || targets.Distinct(StringComparer.Ordinal).Count() != targets.Count)
            throw new ArgumentException("Expected one to 256 distinct explicit verification targets.");
        bool rooted = options.TryGetValue("--payload-root", out string? payloadRoot);
        if (rooted != options.TryGetValue("--signature-root", out string? signatureRoot))
            throw new ArgumentException("--payload-root and --signature-root must be supplied together.");
        if (rooted && (!Directory.Exists(payloadRoot) || !Directory.Exists(signatureRoot)))
            throw new DirectoryNotFoundException("Both verification roots must exist.");
        HybridSignaturePolicy policy = Policy();
        foreach (string target in targets)
        {
            string sidecarBase = target;
            if (rooted)
            {
                string prefix = payloadRoot == "/" ? "/" : payloadRoot + Path.DirectorySeparatorChar;
                if (!target.StartsWith(prefix, StringComparison.Ordinal) || target.Length == prefix.Length)
                    throw new InvalidDataException("Hybrid-verification target lies outside the payload root.");
                sidecarBase = Path.Combine(signatureRoot!, target[prefix.Length..]);
            }
            VerifyStrictArtifact(target, sidecarBase, policy);
        }
        return true;
    }

    private static HybridSignaturePolicy Policy() => SigningTrustPolicy.HybridPolicy
        ?? throw new InvalidOperationException("The compiled hybrid signing policy is unavailable.");

    internal static Dictionary<string, string> ParseOptions(string[] args, string[] allowed, string? flag = null)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        for (int i = 1; i < args.Length; i++)
        {
            string key = args[i];
            string value;
            if (key == flag) value = "true";
            else if (!allowed.Contains(key, StringComparer.Ordinal) || ++i >= args.Length)
                throw new ArgumentException("Unknown or incomplete option: " + key);
            else value = args[i];
            if (!result.TryAdd(key, value)) throw new ArgumentException("Duplicate option: " + key);
        }
        return result;
    }

    internal static string Require(Dictionary<string, string> values, string key) =>
        values.TryGetValue(key, out string? value) && !string.IsNullOrWhiteSpace(value)
            ? value : throw new ArgumentException("Missing required option: " + key);

    internal static void VerifyStrictArtifact(string payload, string sidecarBase, HybridSignaturePolicy policy, List<Action>? namespaceChecks = null)
    {
        using MacBoundFile file = MacBoundFile.Open(payload);
        using MacBoundFile signature = MacBoundFile.Open(sidecarBase + ".khsig", 65_536);
        using MacBoundFile sha3File = MacBoundFile.Open(sidecarBase + ".sha3", 4_096);
        using MacBoundFile skeinFile = MacBoundFile.Open(sidecarBase + ".skein", 4_096);
        using MacBoundFile sha3Signature = MacBoundFile.Open(sidecarBase + ".sha3.khsig", 65_536);
        using MacBoundFile skeinSignature = MacBoundFile.Open(sidecarBase + ".skein.khsig", 65_536);
        VerifyPair(file, signature, policy);
        VerifyPair(sha3File, sha3Signature, policy);
        VerifyPair(skeinFile, skeinSignature, policy);
        byte[] expectedSha3 = ParseHexManifest(sha3File.ReadAll(4_096), 64);
        byte[] expectedSkein = ParseHexManifest(skeinFile.ReadAll(4_096), 128);
        file.Stream.Position = 0;
        (byte[] sha256, byte[] sha3, byte[] skein) = HybridSignatureService.Fingerprint(file.Stream);
        try
        {
            if (!(CryptographicOperations.FixedTimeEquals(sha3, expectedSha3)
                & CryptographicOperations.FixedTimeEquals(skein, expectedSkein)))
                throw new CryptographicException("The signed SHA3-512/Skein-1024 manifests do not match the artifact.");
            foreach (MacBoundFile held in new[] { file, signature, sha3File, skeinFile, sha3Signature, skeinSignature })
            {
                held.AssertStable();
                namespaceChecks?.Add(held.CaptureNamespaceCheck());
            }
        }
        finally
        {
            foreach (byte[] bytes in new[] { sha256, sha3, skein, expectedSha3, expectedSkein })
                CryptographicOperations.ZeroMemory(bytes);
        }
        Console.WriteLine("hybrid_verified=" + Path.GetFullPath(payload));
    }

    private static void VerifyPair(MacBoundFile payload, MacBoundFile signature, HybridSignaturePolicy policy)
    {
        payload.Stream.Position = 0;
        using FileDigest digest = HybridSignatureService.ComputeFileDigest(payload.Stream);
        // Read through the held descriptor. Reopening /dev/fd can be denied for
        // root-owned files whose read access is provided by a macOS ACL.
        byte[] encoded = signature.ReadAll(65_536);
        try
        {
            HybridSignatureVerificationResult result = HybridSignatureService.VerifyDigest(
                digest.Length, digest.Sha512, encoded.AsSpan(), policy);
            if (!(result.IsTrusted && result.RsaPssValid && result.Mldsa87Valid))
                throw new CryptographicException("Pinned RSA-PSS/ML-DSA-87 verification failed: " + result.Message);
            payload.AssertStable();
            signature.AssertStable();
        }
        finally { CryptographicOperations.ZeroMemory(encoded); }
    }

    private static byte[] ParseHexManifest(byte[] bytes, int expectedBytes)
    {
        try
        {
            if (bytes.Length == 0 || bytes.Any(value => value > 0x7F)) throw new InvalidDataException("A digest manifest must be ASCII.");
            string text = new(Encoding.ASCII.GetString(bytes).Where(value => !char.IsWhiteSpace(value)).ToArray());
            if (text.Length != expectedBytes * 2 || !text.All(Uri.IsHexDigit)) throw new InvalidDataException("Invalid digest manifest.");
            return Convert.FromHexString(text);
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
}
