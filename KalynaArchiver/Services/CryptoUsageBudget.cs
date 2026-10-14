using System.IO;
using System.Security.Cryptography;

namespace KalynaArchiver.Services;

/// <summary>
/// Non-configurable per-fresh-key limits, independent of disk/RAM approval.
/// The conservative common profile covers the narrowest registered CTR block.
/// See docs/KEEP_VAULT_V13_CRYPTO_USAGE.md for assumptions and quantitative terms.
/// </summary>
internal static class CryptoUsageBudget
{
    internal const long MaximumPayloadBytes = 1L << 46; // 64 TiB
    internal const int ChunkBytes = 16 * 1024 * 1024;
    internal const long MaximumChunks = MaximumPayloadBytes / ChunkBytes;
    internal const long MaximumAuthenticatedBytes = MaximumPayloadBytes + MaximumChunks * 16 + 16384 + 11;
    internal const long MaximumMacLeaves = (MaximumAuthenticatedBytes + 1048575) / 1048576;

    internal static void ValidatePayloadLength(long payloadBytes)
    {
        if (payloadBytes < 0) throw new ArgumentOutOfRangeException(nameof(payloadBytes));
        if (payloadBytes > MaximumPayloadBytes)
            throw new CryptographicException("The archive exceeds the cryptographic per-key usage budget (64 TiB payload). Create a separate archive with fresh entropy.");
    }

    internal static void ValidateChunk(long chunkIndex, int length)
    {
        if (chunkIndex < 0 || length <= 0 || length > ChunkBytes)
            throw new ArgumentOutOfRangeException(nameof(chunkIndex));
        // Divide first, avoiding overflow even for an adversarial Int64 index.
        if (chunkIndex >= MaximumChunks)
            throw new CryptographicException("The archive exceeds the cryptographic per-key chunk budget.");
        ValidatePayloadLength(checked(chunkIndex * ChunkBytes + length));
    }

    internal static long ValidateCiphertextLength(EncryptionSuiteParameters parameters, long ciphertextBytes)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        if (ciphertextBytes <= 0) throw new InvalidDataException("The encrypted archive has no payload.");
        int tag = parameters.Cascade is { OutermostIsAead: true } ? 16 : 0;
        long frame = ChunkBytes + tag;
        long full = ciphertextBytes / frame;
        long tail = ciphertextBytes % frame;
        if (tail != 0 && tail <= tag) throw new InvalidDataException("The container ends inside a chunk authentication tag.");
        long chunks = checked(full + (tail == 0 ? 0 : 1));
        if (chunks > MaximumChunks)
            throw new CryptographicException("The archive exceeds the cryptographic per-key chunk budget.");
        long payload = checked(full * ChunkBytes + (tail == 0 ? 0 : tail - tag));
        ValidatePayloadLength(payload);
        return payload;
    }

    internal static void ValidateAuthenticationLength(long bytes)
    {
        if (bytes <= 0 || bytes > MaximumAuthenticatedBytes)
            throw new CryptographicException("The archive exceeds the cryptographic per-key authentication budget.");
    }
}
