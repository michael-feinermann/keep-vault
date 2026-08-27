using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Xml.Linq;
using KalynaArchiver.Signing;

namespace KalynaArchiver.Services;

/// <summary>
/// The outcome of checking a companion application that ships with Keep Vault.
/// </summary>
/// <param name="Found">Whether a companion bundle was located at all.</param>
/// <param name="Trusted">
/// Whether it carried a valid RSA-PSS/SHA-512 and ML-DSA-87 signature from the
/// pinned release keys. Always false when <paramref name="Found"/> is false.
/// </param>
/// <param name="Path">Where it was found, or null.</param>
/// <param name="Message">A sentence naming what was checked and what came of it.</param>
public sealed record CompanionVerificationResult(
    bool Found,
    bool Trusted,
    string? Path,
    string Message);

/// <summary>
/// Verifies the QR scanner that travels with Keep Vault.
/// </summary>
/// <remarks>
/// The scanner reads the QR codes off the printed key sheets, so it handles the
/// two secret factors. It is a separate, sandboxed application that shares no
/// code with Keep Vault and cannot check itself: an app that verifies its own
/// signature proves nothing to anyone who has already replaced it. Keep Vault
/// checks it instead, against the same six compiled key fingerprints it holds
/// itself.
///
/// The scanner's sidecars sit beside its bundle rather than inside it. Apple's
/// seal covers Contents/Resources, so a signature file added there afterwards
/// would invalidate the very seal it lives under — the same reason Keep Vault's
/// own launcher signature is published next to the app.
///
/// A failure here does not stop Keep Vault. The scanner is a separate program
/// and Keep Vault never loads its code; the honest response is to say so
/// loudly, not to refuse to archive anything.
/// </remarks>
[SupportedOSPlatform("macos14.0")]
internal static class MacCompanionVerification
{
    private const string ScannerBundleName = "QR-Scanner.app";
    private const string ScannerExecutable = "Contents/MacOS/QR-Scanner";
    private const string ScannerBundleIdentifier = "de.michael-feinermann.qr-scanner";
    private const string KeepVaultBundleIdentifier = "de.michael-feinermann.keep-vault";

    /// <summary>
    /// Looks for the scanner beside Keep Vault and in /Applications, and
    /// verifies the first bundle it finds.
    /// </summary>
    public static CompanionVerificationResult VerifyQrScanner()
    {
        string? bundle = LocateScanner();
        if (bundle is null)
        {
            return new CompanionVerificationResult(
                false,
                false,
                null,
                "QR-Scanner.app was not found beside Keep Vault or in /Applications.");
        }

        string? hostBundle = LocateHostBundle();
        if (hostBundle is null)
        {
            return new CompanionVerificationResult(
                true,
                false,
                bundle,
                "Keep Vault could not locate its own signed bundle metadata for the companion-version check.");
        }

        return VerifyQrScannerPair(hostBundle, bundle);
    }

    /// <summary>
    /// Verifies one explicit release pair without consulting the running
    /// process, environment variables, adjacent paths or /Applications.
    /// </summary>
    /// <remarks>
    /// The packaging suite runs from its own test apphost, not from inside the
    /// signed Keep Vault bundle. Giving that suite the two final distribution
    /// paths keeps production discovery fail-closed while making the release
    /// artifact under test unambiguous.
    /// </remarks>
    internal static CompanionVerificationResult VerifyQrScannerPairForTests(
        string keepVaultBundle,
        string scannerBundle) =>
        VerifyQrScannerPair(keepVaultBundle, scannerBundle);

    private static CompanionVerificationResult VerifyQrScannerPair(
        string keepVaultBundle,
        string scannerBundle)
    {
        string bundle = scannerBundle;

        try
        {
            keepVaultBundle = Path.GetFullPath(keepVaultBundle);
            bundle = Path.GetFullPath(scannerBundle);
            if (!Directory.Exists(bundle) || new DirectoryInfo(bundle).LinkTarget is not null)
            {
                return new CompanionVerificationResult(
                    false,
                    false,
                    bundle,
                    "The explicitly selected QR-Scanner.app is missing or is a symbolic link.");
            }

            if (!Directory.Exists(keepVaultBundle)
                || new DirectoryInfo(keepVaultBundle).LinkTarget is not null)
            {
                return new CompanionVerificationResult(
                    true,
                    false,
                    bundle,
                    "The explicitly selected Keep Vault.app is missing or is a symbolic link.");
            }

            HybridSignaturePolicy policy = SigningTrustPolicy.HybridPolicy
                ?? throw new InvalidOperationException("The compiled hybrid signing policy is unavailable.");

            string executable = Path.Combine(
                bundle,
                ScannerExecutable.Replace('/', Path.DirectorySeparatorChar));
            if (!File.Exists(executable))
            {
                return new CompanionVerificationResult(
                    true,
                    false,
                    bundle,
                    $"QR-Scanner.app has no {ScannerExecutable}; it is not the scanner this build signs.");
            }

            // The detached hybrid signature binds the executable, not the
            // bundle metadata. Validate Apple's seal and pinned Team ID before
            // trusting Info.plist, then require the companion to be from this
            // exact marketing/build pair. Otherwise an authentic but old
            // scanner would be reported as current, and editing its plist
            // could disguise that mismatch unless the bundle seal were checked.
            MacSignatureInfo appleSignature = MacCodeSignature.Check(bundle, nestedBundle: true);
            if (appleSignature.State != SignatureState.Trusted)
            {
                return new CompanionVerificationResult(
                    true,
                    false,
                    bundle,
                    $"QR-Scanner.app failed its Apple signature or pinned Team-ID check: {appleSignature.Message}");
            }

            string? metadataFailure = VerifyMatchingReleaseMetadataForTests(keepVaultBundle, bundle);
            if (metadataFailure is not null)
            {
                return new CompanionVerificationResult(true, false, bundle, metadataFailure);
            }

            HybridSignatureVerificationResult signature = HybridSignatureService.VerifyFile(
                executable,
                bundle + HybridSignatureService.SidecarExtension,
                policy);
            if (!signature.IsTrusted || !signature.RsaPssValid || !signature.Mldsa87Valid)
            {
                return new CompanionVerificationResult(
                    true,
                    false,
                    bundle,
                    $"QR-Scanner.app failed its dual signature check: {signature.Message}");
            }

            // The hybrid signature binds a SHA-512 digest. Everything else in
            // the package is additionally held to the SHA3-512 and Skein-1024
            // dual manifest, and the scanner ships those files too -- checking
            // only the signature here would have left one component measured by
            // fewer hashes than the rest, for no reason other than that this
            // check was written later.
            string? manifestFailure = VerifyDualManifest(bundle, executable, policy);
            if (manifestFailure is not null)
            {
                return new CompanionVerificationResult(true, false, bundle, manifestFailure);
            }

            // Recheck the bundle seal after reading metadata and detached
            // artifacts. This does not make path-based LaunchServices object
            // binding, but it closes the ordinary replace/edit window and
            // ensures the state finally classified as trusted is still sealed.
            appleSignature = MacCodeSignature.Check(bundle, nestedBundle: true);
            if (appleSignature.State != SignatureState.Trusted)
            {
                return new CompanionVerificationResult(
                    true,
                    false,
                    bundle,
                    $"QR-Scanner.app changed while it was being verified: {appleSignature.Message}");
            }

            return new CompanionVerificationResult(
                true,
                true,
                bundle,
                "QR-Scanner.app matches this Keep Vault release version, its Apple Team-ID signature, "
                + "its SHA3-512/Skein-1024 manifests, and both pinned hybrid signatures.");
        }
        catch (Exception exception)
        {
            return new CompanionVerificationResult(
                true,
                false,
                bundle,
                $"QR-Scanner.app could not be checked: {exception.Message}");
        }
    }

    /// <summary>
    /// Holds the companion to the same SHA3-512 and Skein-1024 dual manifest as
    /// every other artifact, and requires both manifests to be signed by the
    /// pinned keys themselves.
    /// </summary>
    /// <remarks>
    /// Returns null when everything matches, otherwise the sentence to report.
    /// An unsigned manifest is worth nothing: whoever replaced the executable
    /// would simply write the new digests next to it.
    /// </remarks>
    private static string? VerifyDualManifest(
        string bundle,
        string executable,
        HybridSignaturePolicy policy)
    {
        const int Sha3HexLength = 128;
        const int SkeinHexLength = 256;

        foreach ((string suffix, int hexLength, string algorithm) in new[]
        {
            (".sha3", Sha3HexLength, "SHA3-512"),
            (".skein", SkeinHexLength, "Skein-1024"),
        })
        {
            string manifestPath = bundle + suffix;
            if (!File.Exists(manifestPath))
            {
                return $"QR-Scanner.app has no {algorithm} manifest ({Path.GetFileName(manifestPath)}).";
            }

            HybridSignatureVerificationResult manifestSignature = HybridSignatureService.VerifyFile(
                manifestPath,
                manifestPath + HybridSignatureService.SidecarExtension,
                policy);
            if (!manifestSignature.IsTrusted
                || !manifestSignature.RsaPssValid
                || !manifestSignature.Mldsa87Valid)
            {
                return $"The {algorithm} manifest of QR-Scanner.app is not signed by the pinned keys: "
                    + manifestSignature.Message;
            }

            string expected = new(File.ReadAllText(manifestPath)
                .Where(character => !char.IsWhiteSpace(character))
                .ToArray());
            if (expected.Length != hexLength || expected.Any(character => !Uri.IsHexDigit(character)))
            {
                return $"The {algorithm} manifest of QR-Scanner.app is not {hexLength} hexadecimal characters.";
            }

            byte[] actual = suffix == ".sha3"
                ? Sha3_512Compat.HashData(File.ReadAllBytes(executable))
                : Skein1024Digest.HashData(File.ReadAllBytes(executable));
            byte[] expectedBytes = Convert.FromHexString(expected);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(actual, expectedBytes))
                {
                    return $"QR-Scanner.app does not match its {algorithm} manifest.";
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(actual);
                CryptographicOperations.ZeroMemory(expectedBytes);
            }
        }

        return null;
    }

    /// <summary>
    /// The scanner sits beside Keep Vault in the portable package and in
    /// /Applications once installed. Both are checked, nearest first.
    /// </summary>
    private static string? LocateScanner()
    {
        foreach (string directory in CandidateDirectories())
        {
            string candidate = Path.Combine(directory, ScannerBundleName);
            if (Directory.Exists(candidate) && new DirectoryInfo(candidate).LinkTarget is null)
            {
                return Path.GetFullPath(candidate);
            }
        }

        return null;
    }

    private static string? LocateHostBundle()
    {
        string? processPath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(processPath))
        {
            return null;
        }

        DirectoryInfo? macOs = Directory.GetParent(Path.GetFullPath(processPath));
        DirectoryInfo? contents = macOs?.Parent;
        DirectoryInfo? bundle = contents?.Parent;
        return macOs?.Name == "MacOS"
            && contents?.Name == "Contents"
            && bundle?.Name.EndsWith(".app", StringComparison.OrdinalIgnoreCase) == true
                ? bundle.FullName
                : null;
    }

    /// <summary>
    /// Returns null only when the two sealed bundle metadata records form the
    /// same release pair. Kept internal so the smoke suite can exercise stale,
    /// malformed and wrong-identifier companions without launching a camera app.
    /// </summary>
    internal static string? VerifyMatchingReleaseMetadataForTests(
        string keepVaultBundle,
        string scannerBundle)
    {
        try
        {
            BundleMetadata keepVault = ReadBundleMetadata(keepVaultBundle);
            BundleMetadata scanner = ReadBundleMetadata(scannerBundle);
            if (!string.Equals(keepVault.Identifier, KeepVaultBundleIdentifier, StringComparison.Ordinal)
                || !string.Equals(scanner.Identifier, ScannerBundleIdentifier, StringComparison.Ordinal))
            {
                return "Keep Vault or QR-Scanner has the wrong release bundle identifier.";
            }

            if (!string.Equals(keepVault.MarketingVersion, scanner.MarketingVersion, StringComparison.Ordinal)
                || !string.Equals(keepVault.BuildVersion, scanner.BuildVersion, StringComparison.Ordinal))
            {
                return $"QR-Scanner.app belongs to release {scanner.MarketingVersion} ({scanner.BuildVersion}), "
                    + $"but this Keep Vault is {keepVault.MarketingVersion} ({keepVault.BuildVersion}).";
            }

            return null;
        }
        catch (Exception exception) when (exception is IOException
            or UnauthorizedAccessException
            or InvalidDataException
            or System.Xml.XmlException)
        {
            return $"Release companion metadata is missing or malformed: {exception.Message}";
        }
    }

    private static BundleMetadata ReadBundleMetadata(string bundle)
    {
        string plistPath = Path.Combine(Path.GetFullPath(bundle), "Contents", "Info.plist");
        XDocument document = XDocument.Load(plistPath, LoadOptions.None);
        XElement dictionary = document.Root?.Elements().FirstOrDefault(element => element.Name.LocalName == "dict")
            ?? throw new InvalidDataException($"Info.plist has no root dictionary: {plistPath}");
        XElement[] entries = dictionary.Elements().ToArray();

        string ReadString(string key)
        {
            for (int index = 0; index + 1 < entries.Length; index++)
            {
                if (entries[index].Name.LocalName == "key"
                    && string.Equals(entries[index].Value, key, StringComparison.Ordinal)
                    && entries[index + 1].Name.LocalName == "string"
                    && !string.IsNullOrWhiteSpace(entries[index + 1].Value))
                {
                    return entries[index + 1].Value;
                }
            }

            throw new InvalidDataException($"Info.plist has no non-empty {key}: {plistPath}");
        }

        return new BundleMetadata(
            ReadString("CFBundleIdentifier"),
            ReadString("CFBundleShortVersionString"),
            ReadString("CFBundleVersion"));
    }

    private sealed record BundleMetadata(
        string Identifier,
        string MarketingVersion,
        string BuildVersion);

    private static IEnumerable<string> CandidateDirectories()
    {
        // The directory the bundle sits in: Contents/MacOS/<binary> up to the
        // bundle, then one more to its parent.
        string? bundleParent = Path.GetDirectoryName(
            Path.GetDirectoryName(
                Path.GetDirectoryName(
                    Path.GetDirectoryName(Environment.ProcessPath))));
        if (!string.IsNullOrEmpty(bundleParent))
        {
            yield return bundleParent;
        }

        yield return "/Applications";
    }
}
