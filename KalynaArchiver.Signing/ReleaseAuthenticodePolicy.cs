using System.Buffers.Binary;
using System.Formats.Asn1;
using System.Security.Cryptography;

namespace KalynaArchiver.Signing;

public sealed record AuthenticodeDigestAlgorithms(string PeDigest, string PrimarySignerDigest, int PeDigestLength);

/// <summary>Checks the primary CMS signature and PE digest independently of its timestamp.</summary>
public static class ReleaseAuthenticodePolicy
{
    public const string Sha512Oid = "2.16.840.1.101.3.4.2.3";
    private const int MaximumBlobBytes = 1024 * 1024;

    public static void RequireSha512(string path)
    {
        AuthenticodeDigestAlgorithms value = ReadDigestAlgorithms(path);
        if (value.PeDigest != Sha512Oid || value.PrimarySignerDigest != Sha512Oid || value.PeDigestLength != 64)
            throw new CryptographicException($"Authenticode requires SHA-512 for both the PE digest and primary CMS signer; PE={value.PeDigest}, primary CMS={value.PrimarySignerDigest}.");
    }

    public static AuthenticodeDigestAlgorithms ReadDigestAlgorithms(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var reader = new BinaryReader(stream);
        Span<byte> dos = stackalloc byte[64];
        stream.ReadExactly(dos);
        if (BinaryPrimitives.ReadUInt16LittleEndian(dos) != 0x5a4d) throw Invalid();
        int peOffset = BinaryPrimitives.ReadInt32LittleEndian(dos[0x3c..]);
        if (peOffset < 64 || peOffset > stream.Length - 24) throw Invalid();
        stream.Position = peOffset;
        Span<byte> pe = stackalloc byte[24];
        stream.ReadExactly(pe);
        if (BinaryPrimitives.ReadUInt32LittleEndian(pe) != 0x4550) throw Invalid();
        int optionalLength = BinaryPrimitives.ReadUInt16LittleEndian(pe[20..]);
        if (optionalLength is < 128 or > 4096) throw Invalid();
        byte[] optional = reader.ReadBytes(optionalLength);
        if (optional.Length != optionalLength) throw Invalid();
        int directories = BinaryPrimitives.ReadUInt16LittleEndian(optional) switch
        {
            0x10b => 96,
            0x20b => 112,
            _ => throw Invalid(),
        };
        int security = directories + 32;
        if (security > optional.Length - 8 || BinaryPrimitives.ReadUInt32LittleEndian(optional.AsSpan(directories - 4)) < 5)
            throw Invalid();
        uint offset = BinaryPrimitives.ReadUInt32LittleEndian(optional.AsSpan(security));
        uint size = BinaryPrimitives.ReadUInt32LittleEndian(optional.AsSpan(security + 4));
        if (offset == 0 || (offset & 7) != 0 || size is < 8 or > MaximumBlobBytes || offset > stream.Length - size)
            throw Invalid();
        stream.Position = offset;
        uint encodedLength = reader.ReadUInt32();
        ushort revision = reader.ReadUInt16();
        ushort certificateType = reader.ReadUInt16();
        if (encodedLength < 8 || encodedLength > size || ((encodedLength + 7) & ~7u) != size
            || revision != 0x200 || certificateType != 2) throw Invalid();
        byte[] blob = reader.ReadBytes(checked((int)size - 8));
        if (blob.Length != size - 8) throw Invalid();

        var cmsReader = new AsnReader(blob, AsnEncodingRules.BER);
        ReadOnlyMemory<byte> encodedCms = cmsReader.ReadEncodedValue();
        // WIN_CERTIFICATE includes up to seven zero bytes for 8-byte alignment.
        ReadOnlySpan<byte> padding = blob.AsSpan(encodedCms.Length);
        if (padding.Length > 7 || padding.IndexOfAnyExcept((byte)0) >= 0
            || encodedCms.Length > encodedLength - 8) throw Invalid();
        var outer = new AsnReader(encodedCms, AsnEncodingRules.BER);
        var contentInfo = outer.ReadSequence();
        outer.ThrowIfNotEmpty();
        if (contentInfo.ReadObjectIdentifier() != "1.2.840.113549.1.7.2") throw Invalid();
        var explicitData = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        contentInfo.ThrowIfNotEmpty();
        var signedData = explicitData.ReadSequence();
        explicitData.ThrowIfNotEmpty();
        _ = signedData.ReadInteger();
        var algorithms = signedData.ReadSetOf();
        string declaredDigest = ReadAlgorithm(algorithms);
        algorithms.ThrowIfNotEmpty();
        var embeddedContent = signedData.ReadSequence();
        if (embeddedContent.ReadObjectIdentifier() != "1.3.6.1.4.1.311.2.1.4") throw Invalid();
        var explicitContent = embeddedContent.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        embeddedContent.ThrowIfNotEmpty();
        var indirect = explicitContent.ReadSequence();
        explicitContent.ThrowIfNotEmpty();
        var attributes = indirect.ReadSequence();
        if (attributes.ReadObjectIdentifier() != "1.3.6.1.4.1.311.2.1.15") throw Invalid();
        if (attributes.HasData) _ = attributes.ReadEncodedValue();
        attributes.ThrowIfNotEmpty();
        var digestInfo = indirect.ReadSequence();
        indirect.ThrowIfNotEmpty();
        string peDigest = ReadAlgorithm(digestInfo);
        int digestLength = digestInfo.ReadOctetString().Length;
        digestInfo.ThrowIfNotEmpty();
        if (signedData.HasData && signedData.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
            _ = signedData.ReadEncodedValue(); // embedded certificates
        if (signedData.HasData && signedData.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
            _ = signedData.ReadEncodedValue(); // revocation information
        var signers = signedData.ReadSetOf();
        signedData.ThrowIfNotEmpty();
        var signer = signers.ReadSequence();
        signers.ThrowIfNotEmpty();
        _ = signer.ReadInteger();
        _ = signer.ReadEncodedValue(); // issuer/serial or subject-key identifier
        string primaryDigest = ReadAlgorithm(signer);
        if (primaryDigest != declaredDigest) throw Invalid();
        // The remainder, including unsigned timestamp attributes, is verified
        // by WinVerifyTrust. It cannot replace the primary signer's algorithm.
        return new AuthenticodeDigestAlgorithms(peDigest, primaryDigest, digestLength);
    }

    private static string ReadAlgorithm(AsnReader container)
    {
        var algorithm = container.ReadSequence();
        string oid = algorithm.ReadObjectIdentifier();
        if (algorithm.HasData) algorithm.ReadNull();
        algorithm.ThrowIfNotEmpty();
        return oid;
    }

    private static CryptographicException Invalid() => new("Invalid or ambiguous Authenticode PE/CMS structure.");
}
