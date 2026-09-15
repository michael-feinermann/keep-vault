using System.Diagnostics;
using System.IO;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using KalynaArchiver.Signing;

namespace KalynaArchiver.Services;

/// <summary>Additional requirements for distributable Windows release executables.</summary>
public static class ReleaseExecutablePolicy
{
    public const string RequiredVersion = "5.0.2.0";
    private static readonly string[] Products =
        ["Keep Vault.exe", "Keep Vault Release Verifier.exe", "Keep Vault Setup.exe", "QR-Scanner/QR-Scanner.exe"];

    public static void RequireProductVersions(string directory)
    {
        foreach (string product in Products)
            if (FileVersionInfo.GetVersionInfo(Path.Combine(directory, product)).FileVersion != RequiredVersion)
                throw new InvalidDataException("Executable version does not match Windows 5.0.2: " + product);
    }

    public static void RequireTimestampedPe(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        ReleaseAuthenticodePolicy.RequireSha512(path);
        using var pe = new PEReader(stream, PEStreamOptions.LeaveOpen);
        var directory = pe.PEHeaders.PEHeader?.CertificateTableDirectory
            ?? throw new CryptographicException("The release executable has no PE header.");
        if (directory.Size is < 8 or > 1024 * 1024) throw new CryptographicException("Invalid certificate table size.");
        stream.Position = directory.RelativeVirtualAddress;
        using var reader = new BinaryReader(stream);
        int size = reader.ReadInt32();
        if (size < 8 || size > directory.Size) throw new CryptographicException("Invalid Authenticode certificate size.");
        _ = reader.ReadUInt16();
        _ = reader.ReadUInt16();
        byte[] encoded = reader.ReadBytes(size - 8);
        if (encoded.Length != size - 8) throw new EndOfStreamException();
        var cms = new SignedCms();
        cms.Decode(encoded);
        if (cms.SignerInfos.Count != 1) throw new CryptographicException("Exactly one primary release signer is required.");
        SignerInfo signer = cms.SignerInfos[0];
        var timestamps = signer.UnsignedAttributes.Cast<CryptographicAttributeObject>()
            .Where(attribute => attribute.Oid.Value == "1.3.6.1.4.1.311.3.3.1").ToArray();
        if (timestamps.Length != 1 || timestamps[0].Values.Count != 1)
            throw new CryptographicException("Exactly one RFC 3161 timestamp is required.");
        byte[] timestampBytes = timestamps[0].Values[0].RawData;
        if (!Rfc3161TimestampToken.TryDecode(timestampBytes, out Rfc3161TimestampToken? token, out int consumed)
            || consumed != timestampBytes.Length || token.TokenInfo.HashAlgorithmId.Value != ReleaseAuthenticodePolicy.Sha512Oid
            || !token.VerifySignatureForSignerInfo(signer, out X509Certificate2? tsaCertificate))
            throw new CryptographicException("The RFC 3161 SHA-512 timestamp is invalid or belongs to another signature.");
        using (tsaCertificate)
        using (var chain = new X509Chain())
        {
            // Validate the TSA separately from the intentionally self-signed
            // release certificate. Offline operation never installs new roots
            // or fetches certificates. This adds no fresh revocation claim.
            chain.ChainPolicy.DisableCertificateDownloads = true;
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            chain.ChainPolicy.VerificationTime = token.TokenInfo.Timestamp.UtcDateTime;
            chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.8"));
            chain.ChainPolicy.ExtraStore.AddRange(token.AsSignedCms().Certificates);
            if (tsaCertificate is null || !chain.Build(tsaCertificate))
                throw new CryptographicException("The timestamp authority does not chain to an existing Windows trust root.");
        }
    }
}
