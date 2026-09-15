using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace KalynaArchiver.Signing;

/// <summary>Signs directly with the caller's ephemeral certificate context.</summary>
public static class ReleaseAuthenticodeSigner
{
    public static unsafe void SignSha512(string path, X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        using RSA? rsa = certificate.GetRSAPrivateKey();
        if (rsa?.KeySize != 4096 || certificate.SignatureAlgorithm.Value != "1.2.840.113549.1.1.13")
            throw new CryptographicException("Authenticode requires an RSA-4096 key and SHA-512/RSA certificate.");

        // Use the numeric ALG_ID rather than CryptUI's OID lookup. A CNG-only
        // OID mapping can make CryptUI silently choose its SHA-256 default.
        string fullPath = Path.GetFullPath(path);
        nint context = 0;
        fixed (char* fileName = fullPath)
        {
            uint index = 0;
            var file = new SignerFileInfo { Size = (uint)sizeof(SignerFileInfo), FileName = fileName };
            var subject = new SignerSubjectInfo
            {
                Size = (uint)sizeof(SignerSubjectInfo), Index = &index, Choice = 1, FileInfo = &file,
            };
            var store = new SignerCertStoreInfo
            {
                Size = (uint)sizeof(SignerCertStoreInfo), Certificate = certificate.Handle, Policy = 2,
            };
            var signer = new SignerCert
            {
                Size = (uint)sizeof(SignerCert), Choice = 2, StoreInfo = &store,
            };
            var signature = new SignerSignatureInfo
            {
                Size = (uint)sizeof(SignerSignatureInfo), HashAlgorithm = 0x800e,
            };
            try
            {
                int result = SignerSignEx2(0x10, &subject, &signer, &signature,
                    0, 0, 0, 0, 0, 0, &context, 0, 0);
                if (result != 0)
                    throw new CryptographicException($"In-memory SHA-512 Authenticode signing failed: 0x{result:X8}.");
            }
            finally
            {
                if (context != 0) _ = SignerFreeSignerContext(context);
                GC.KeepAlive(certificate);
            }
        }
        ReleaseAuthenticodePolicy.RequireSha512(fullPath);
    }

    [DllImport("mssign32.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern unsafe int SignerSignEx2(uint flags, SignerSubjectInfo* subject,
        SignerCert* signer, SignerSignatureInfo* signature, nint provider, uint timestampFlags,
        nint timestampAlgorithm, nint timestampUrl, nint request, nint sipData,
        nint* context, nint cryptoPolicy, nint reserved);

    [DllImport("mssign32.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int SignerFreeSignerContext(nint context);

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct SignerFileInfo { public uint Size; public char* FileName; public nint File; }
    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct SignerSubjectInfo { public uint Size; public uint* Index; public uint Choice; public SignerFileInfo* FileInfo; }
    [StructLayout(LayoutKind.Sequential)]
    private struct SignerCertStoreInfo { public uint Size; public nint Certificate; public uint Policy; public nint Store; }
    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct SignerCert { public uint Size; public uint Choice; public SignerCertStoreInfo* StoreInfo; public nint Window; }
    [StructLayout(LayoutKind.Sequential)]
    private struct SignerSignatureInfo { public uint Size; public uint HashAlgorithm; public uint AttributeChoice; public nint Attribute; public nint Authenticated; public nint Unauthenticated; }
}
