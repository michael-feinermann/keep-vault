using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace KalynaArchiver.Signing;

/// <summary>
/// In-process release signing entry points. Passwords never cross a process
/// boundary or become immutable managed strings, and PFX keys are ephemeral.
/// </summary>
public static class ReleaseSigningOperations
{
    public static X509Certificate2 LoadCertificate(
        string pfxPath, string passwordEnvelopePath, string wrappingKeyPath)
    {
        byte[] password = ReadEnvelope(passwordEnvelopePath, wrappingKeyPath, "KVPFXP12"u8, 1, 4096);
        byte[]? pfx = null;
        char[]? characters = null;
        try
        {
            var utf8 = new UTF8Encoding(false, true);
            characters = GC.AllocateUninitializedArray<char>(utf8.GetCharCount(password), pinned: true);
            utf8.GetChars(password, characters);
            if (characters.AsSpan().Contains('\0'))
            {
                throw new CryptographicException("The PFX password envelope contains an invalid password.");
            }

            pfx = ReadBoundedFile(pfxPath, 1, 1024 * 1024);
            return X509CertificateLoader.LoadPkcs12(pfx, characters, X509KeyStorageFlags.EphemeralKeySet);
        }
        catch (DecoderFallbackException)
        {
            throw new CryptographicException("The PFX password envelope is not valid UTF-8.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(password);
            if (pfx is not null) CryptographicOperations.ZeroMemory(pfx);
            if (characters is not null) CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(characters.AsSpan()));
        }
    }

    public static void SignFile(
        string target,
        X509Certificate2 certificate,
        string privateKeyPath,
        string wrappingKeyPath,
        string publicKeyPath,
        string referencePath,
        bool developmentKey,
        string rsaSha256, string rsaSha3, string rsaSkein,
        string mldsaSha256, string mldsaSha3, string mldsaSkein)
    {
        using MldsaPrivateKeyLease key = developmentKey
            ? MldsaKeyStore.OpenDevelopmentKey(privateKeyPath, publicKeyPath)
            : MldsaKeyStore.OpenEncryptedKey(privateKeyPath, wrappingKeyPath, publicKeyPath);
        byte[] privateKey = key.PrivateKey.ToArray();
        byte[] publicKey = key.PublicKey.ToArray();
        try
        {
            var policy = new HybridSignaturePolicy(rsaSha256, rsaSha3, rsaSkein,
                mldsaSha256, mldsaSha3, mldsaSkein, publicKey);
            using HybridSignatureCreationResult result = HybridSignatureService.CreateAsync(
                target, target + HybridSignatureService.SidecarExtension, certificate,
                privateKey, publicKey).GetAwaiter().GetResult();
            using var reference = new Mldsa87Reference(referencePath);
            if (!reference.Verify(result.Payload, result.MldsaSignature, publicKey))
            {
                throw new CryptographicException("The independent ML-DSA-87 reference rejected the release signature.");
            }

            HybridSignatureVerificationResult verification = HybridSignatureService.VerifyFile(
                target, target + HybridSignatureService.SidecarExtension, policy);
            if (!verification.IsTrusted)
            {
                throw new CryptographicException("The release signature did not match the mandatory RSA/ML-DSA pins.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
            CryptographicOperations.ZeroMemory(publicKey);
        }
    }

    internal static byte[] ReadEnvelope(
        string envelopePath, string wrappingKeyPath, ReadOnlySpan<byte> magic, int minimum, int maximum)
    {
        const int headerBytes = 24;
        const int overheadBytes = 40;
        byte[] envelope = ReadBoundedFile(envelopePath, checked(minimum + overheadBytes), checked(maximum + overheadBytes));
        byte[]? encodedKey = null;
        byte[]? wrappingKey = null;
        byte[]? plaintext = null;
        try
        {
            uint length = BinaryPrimitives.ReadUInt32LittleEndian(envelope.AsSpan(8, 4));
            if (!CryptographicOperations.FixedTimeEquals(envelope.AsSpan(0, 8), magic)
                || length < minimum || length > maximum || length != envelope.Length - overheadBytes)
            {
                throw new CryptographicException("The release envelope has the wrong secret type, version, or canonical length.");
            }

            encodedKey = ReadBoundedFile(wrappingKeyPath, 1, 1024);
            Span<char> encodedCharacters = stackalloc char[encodedKey.Length];
            for (int index = 0; index < encodedKey.Length; index++) encodedCharacters[index] = (char)encodedKey[index];
            wrappingKey = GC.AllocateUninitializedArray<byte>(32, pinned: true);
            try
            {
                if (!Convert.TryFromBase64Chars(encodedCharacters, wrappingKey, out int written) || written != 32)
                {
                    throw new CryptographicException("The release wrapping key must encode exactly 32 bytes.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(encodedCharacters));
            }

            plaintext = GC.AllocateUninitializedArray<byte>(checked((int)length), pinned: true);
            using var aes = new AesGcm(wrappingKey, 16);
            aes.Decrypt(envelope.AsSpan(12, 12), envelope.AsSpan(headerBytes, plaintext.Length),
                envelope.AsSpan(headerBytes + plaintext.Length, 16), plaintext, envelope.AsSpan(0, 12));
            byte[] result = plaintext;
            plaintext = null;
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(envelope);
            if (encodedKey is not null) CryptographicOperations.ZeroMemory(encodedKey);
            if (wrappingKey is not null) CryptographicOperations.ZeroMemory(wrappingKey);
            if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private static byte[] ReadBoundedFile(string path, int minimum, int maximum)
    {
        string fullPath = Path.GetFullPath(path);
        for (string? current = fullPath; current is not null; current = Path.GetDirectoryName(current))
        {
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
            {
                throw new IOException("Release secrets cannot be read through a reparse point.");
            }
        }

        using var stream = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (!GetFileInformationByHandle(stream.SafeFileHandle, out FileInformation information)
            || information.NumberOfLinks != 1
            || (information.FileAttributes & (uint)FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException("A release key component is not a regular single-link file.");
        }
        var finalPath = new StringBuilder(32768);
        uint pathLength = GetFinalPathNameByHandleW(stream.SafeFileHandle, finalPath, (uint)finalPath.Capacity, 0);
        string expectedPath = fullPath.StartsWith(@"\\", StringComparison.Ordinal)
            ? @"\\?\UNC\" + fullPath[2..] : @"\\?\" + fullPath;
        if (pathLength == 0 || pathLength >= finalPath.Capacity
            || !string.Equals(finalPath.ToString(), expectedPath, StringComparison.OrdinalIgnoreCase))
        {
            throw new IOException("A release key component changed its resolved path.");
        }
        if (stream.Length < minimum || stream.Length > maximum)
        {
            throw new CryptographicException("A release key component has an invalid bounded length.");
        }
        byte[] contents = GC.AllocateUninitializedArray<byte>(checked((int)stream.Length), pinned: true);
        try
        {
            stream.ReadExactly(contents);
            return contents;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(contents);
            throw;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle file, out FileInformation information);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder path, uint size, uint flags);
}
