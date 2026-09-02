using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace KalynaArchiver.Signing;

public static class MldsaKeyStore
{
    private static readonly byte[] Magic = "KZVMLK01"u8.ToArray();
    private static readonly byte[] OptionalEntropy = SHA512.HashData(
        Encoding.ASCII.GetBytes("KalynaZpaqVault/ML-DSA-87/DevelopmentSigningKey/v1"));
    private static readonly byte[] ReleaseEnvelopeMagic = "KVSECRT1"u8.ToArray();
    private const int MaximumProtectedBytes = 32 * 1024;

    public static void CreateDevelopmentKey(string privateKeyPath, string publicKeyPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(privateKeyPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(publicKeyPath);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("The development ML-DSA key store requires Windows DPAPI.");
        }

        if (File.Exists(privateKeyPath) || File.Exists(publicKeyPath))
        {
            throw new IOException("Refusing to overwrite an existing ML-DSA key pair.");
        }

        (byte[] publicKey, byte[] privateKey) = Mldsa87.GenerateKeyPair();
        byte[]? protectedKey = null;
        byte[]? container = null;
        try
        {
            protectedKey = ProtectedData.Protect(privateKey, OptionalEntropy, DataProtectionScope.CurrentUser);
            if (protectedKey.Length is <= 0 or > MaximumProtectedBytes)
            {
                throw new CryptographicException("DPAPI returned an invalid ML-DSA private-key envelope.");
            }

            container = new byte[checked(Magic.Length + sizeof(int) + publicKey.Length + sizeof(int) + protectedKey.Length)];
            int offset = 0;
            Magic.CopyTo(container, offset);
            offset += Magic.Length;
            BinaryPrimitives.WriteInt32LittleEndian(container.AsSpan(offset), publicKey.Length);
            offset += sizeof(int);
            publicKey.CopyTo(container, offset);
            offset += publicKey.Length;
            BinaryPrimitives.WriteInt32LittleEndian(container.AsSpan(offset), protectedKey.Length);
            offset += sizeof(int);
            protectedKey.CopyTo(container, offset);

            WriteNewFile(privateKeyPath, container);
            try
            {
                WriteNewFile(publicKeyPath, publicKey);
            }
            catch
            {
                File.Delete(privateKeyPath);
                throw;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
            CryptographicOperations.ZeroMemory(publicKey);
            if (protectedKey is not null)
            {
                CryptographicOperations.ZeroMemory(protectedKey);
            }

            if (container is not null)
            {
                CryptographicOperations.ZeroMemory(container);
            }
        }
    }

    public static MldsaPrivateKeyLease OpenDevelopmentKey(string privateKeyPath, string expectedPublicKeyPath)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("The development ML-DSA key store requires Windows DPAPI.");
        }

        byte[] container = ReadBoundedFile(
            privateKeyPath,
            Magic.Length + (2 * sizeof(int)) + Mldsa87.PublicKeyBytes + 1,
            Magic.Length + (2 * sizeof(int)) + Mldsa87.PublicKeyBytes + MaximumProtectedBytes);
        byte[]? protectedKey = null;
        byte[]? privateKey = null;
        byte[]? embeddedPublicKey = null;
        byte[]? expectedPublicKey = null;
        try
        {
            int offset = 0;
            if (container.Length < Magic.Length + (2 * sizeof(int))
                || !CryptographicOperations.FixedTimeEquals(container.AsSpan(0, Magic.Length), Magic))
            {
                throw new InvalidDataException("The ML-DSA private-key container has an invalid header.");
            }

            offset += Magic.Length;
            int publicLength = ReadBoundedLength(container, ref offset, Mldsa87.PublicKeyBytes, Mldsa87.PublicKeyBytes);
            embeddedPublicKey = container.AsSpan(offset, publicLength).ToArray();
            offset += publicLength;
            int protectedLength = ReadBoundedLength(container, ref offset, 1, MaximumProtectedBytes);
            if (offset + protectedLength != container.Length)
            {
                throw new InvalidDataException("The ML-DSA private-key container has trailing or truncated data.");
            }

            protectedKey = container.AsSpan(offset, protectedLength).ToArray();
            privateKey = ProtectedData.Unprotect(protectedKey, OptionalEntropy, DataProtectionScope.CurrentUser);
            if (privateKey.Length != Mldsa87.PrivateKeyBytes)
            {
                throw new CryptographicException("DPAPI returned an invalid ML-DSA-87 private key length.");
            }

            expectedPublicKey = ReadBoundedFile(
                expectedPublicKeyPath,
                Mldsa87.PublicKeyBytes,
                Mldsa87.PublicKeyBytes);
            if (!CryptographicOperations.FixedTimeEquals(embeddedPublicKey, expectedPublicKey))
            {
                throw new CryptographicException("The DPAPI key container does not match the expected ML-DSA public key.");
            }

            byte[] derivedPublicKey = Mldsa87.DerivePublicKey(privateKey);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(derivedPublicKey, expectedPublicKey))
                {
                    throw new CryptographicException("The ML-DSA private key does not derive the pinned public key.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(derivedPublicKey);
            }

            var lease = new MldsaPrivateKeyLease(privateKey, expectedPublicKey);
            privateKey = null;
            expectedPublicKey = null;
            return lease;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(container);
            if (protectedKey is not null)
            {
                CryptographicOperations.ZeroMemory(protectedKey);
            }

            if (privateKey is not null)
            {
                CryptographicOperations.ZeroMemory(privateKey);
            }

            if (embeddedPublicKey is not null)
            {
                CryptographicOperations.ZeroMemory(embeddedPublicKey);
            }

            if (expectedPublicKey is not null)
            {
                CryptographicOperations.ZeroMemory(expectedPublicKey);
            }
        }
    }

    /// <summary>
    /// Opens the AES-GCM envelope used by the release key set shared with the
    /// macOS packaging tools. The private key exists only in the returned
    /// lease; the envelope and wrapping key are wiped before returning.
    /// </summary>
    public static MldsaPrivateKeyLease OpenEncryptedKey(
        string envelopePath,
        string wrappingKeyPath,
        string expectedPublicKeyPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(envelopePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(wrappingKeyPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedPublicKeyPath);

        const int nonceBytes = 12;
        const int tagBytes = 16;
        int envelopeBytes = checked(ReleaseEnvelopeMagic.Length + nonceBytes + Mldsa87.PrivateKeyBytes + tagBytes);
        byte[] envelope = ReadBoundedFile(envelopePath, envelopeBytes, envelopeBytes);
        byte[] wrappingKey = ReadWrappingKey(wrappingKeyPath);
        byte[]? privateKey = null;
        byte[]? expectedPublicKey = null;
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(
                    envelope.AsSpan(0, ReleaseEnvelopeMagic.Length),
                    ReleaseEnvelopeMagic))
            {
                throw new InvalidDataException("The encrypted ML-DSA release-key envelope has an invalid header.");
            }

            privateKey = new byte[Mldsa87.PrivateKeyBytes];
            using (var aes = new AesGcm(wrappingKey, tagBytes))
            {
                aes.Decrypt(
                    envelope.AsSpan(ReleaseEnvelopeMagic.Length, nonceBytes),
                    envelope.AsSpan(ReleaseEnvelopeMagic.Length + nonceBytes, Mldsa87.PrivateKeyBytes),
                    envelope.AsSpan(envelope.Length - tagBytes, tagBytes),
                    privateKey,
                    ReleaseEnvelopeMagic);
            }

            expectedPublicKey = ReadBoundedFile(
                expectedPublicKeyPath,
                Mldsa87.PublicKeyBytes,
                Mldsa87.PublicKeyBytes);
            byte[] derivedPublicKey = Mldsa87.DerivePublicKey(privateKey);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(derivedPublicKey, expectedPublicKey))
                {
                    throw new CryptographicException(
                        "The encrypted ML-DSA release key does not match the expected public key.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(derivedPublicKey);
            }

            var lease = new MldsaPrivateKeyLease(privateKey, expectedPublicKey);
            privateKey = null;
            expectedPublicKey = null;
            return lease;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(envelope);
            CryptographicOperations.ZeroMemory(wrappingKey);
            if (privateKey is not null)
            {
                CryptographicOperations.ZeroMemory(privateKey);
            }

            if (expectedPublicKey is not null)
            {
                CryptographicOperations.ZeroMemory(expectedPublicKey);
            }
        }
    }

    private static byte[] ReadWrappingKey(string path)
    {
        byte[] encodedBytes = ReadBoundedFile(path, 1, 1024);
        try
        {
            string encoded = Encoding.ASCII.GetString(encodedBytes).Trim();
            byte[] key = Convert.FromBase64String(encoded);
            if (key.Length != 32)
            {
                CryptographicOperations.ZeroMemory(key);
                throw new CryptographicException("The ML-DSA release wrapping key must contain 32 bytes.");
            }

            return key;
        }
        catch (FormatException exception)
        {
            throw new CryptographicException("The ML-DSA release wrapping key is not valid base64.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encodedBytes);
        }
    }

    private static int ReadBoundedLength(byte[] container, ref int offset, int minimum, int maximum)
    {
        if (offset > container.Length - sizeof(int))
        {
            throw new InvalidDataException("The ML-DSA private-key container is truncated.");
        }

        int value = BinaryPrimitives.ReadInt32LittleEndian(container.AsSpan(offset));
        offset += sizeof(int);
        if (value < minimum || value > maximum || offset > container.Length - value)
        {
            throw new InvalidDataException("The ML-DSA private-key container contains an invalid field length.");
        }

        return value;
    }

    private static byte[] ReadBoundedFile(string path, int minimumBytes, int maximumBytes)
    {
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 4096,
            FileOptions.SequentialScan);
        if (stream.Length < minimumBytes || stream.Length > maximumBytes)
        {
            throw new InvalidDataException(
                $"The ML-DSA key file has an invalid bounded length: {Path.GetFileName(path)}");
        }

        byte[] contents = new byte[checked((int)stream.Length)];
        stream.ReadExactly(contents);
        return contents;
    }

    private static void WriteNewFile(string path, byte[] contents)
    {
        string fullPath = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)
            ?? throw new InvalidOperationException("The key path has no parent directory."));
        using var stream = new FileStream(fullPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
        stream.Write(contents);
        stream.Flush(flushToDisk: true);
    }
}

public sealed class MldsaPrivateKeyLease : IDisposable
{
    private byte[]? _privateKey;
    private byte[]? _publicKey;

    internal MldsaPrivateKeyLease(byte[] privateKey, byte[] publicKey)
    {
        _privateKey = privateKey;
        _publicKey = publicKey;
    }

    public ReadOnlySpan<byte> PrivateKey => _privateKey
        ?? throw new ObjectDisposedException(nameof(MldsaPrivateKeyLease));

    public ReadOnlySpan<byte> PublicKey => _publicKey
        ?? throw new ObjectDisposedException(nameof(MldsaPrivateKeyLease));

    public void Dispose()
    {
        byte[]? privateKey = Interlocked.Exchange(ref _privateKey, null);
        byte[]? publicKey = Interlocked.Exchange(ref _publicKey, null);
        if (privateKey is not null)
        {
            CryptographicOperations.ZeroMemory(privateKey);
        }

        if (publicKey is not null)
        {
            CryptographicOperations.ZeroMemory(publicKey);
        }
    }
}
