using System.Buffers.Binary;
using System.Security.Cryptography;

namespace KalynaArchiver.Services;

/// <summary>Bounded duplex protocol for the isolated native regular-ZPAQ reader.</summary>
internal static class VerifiedArchiveReadAtServer
{
    internal static async Task ServeAsync(
        Stream archive, Stream requests, Stream responses, CancellationToken cancellationToken)
    {
        long length = archive.Length;
        if (length <= 0 || !archive.CanRead || !archive.CanSeek)
            throw new InvalidDataException("Verified read-at requires a nonempty authenticated seekable stream.");
        byte[] framing = new byte[16];
        "KV13RA\0\0"u8.CopyTo(framing);
        BinaryPrimitives.WriteInt64BigEndian(framing.AsSpan(8), length);
        await responses.WriteAsync(framing, cancellationToken).ConfigureAwait(false);
        await responses.FlushAsync(cancellationToken).ConfigureAwait(false);
        using LockedSensitiveBuffer block = LockedSensitiveBuffer.Create(1024 * 1024);
        while (true)
        {
            int first = await requests.ReadAsync(framing.AsMemory(0, 1), cancellationToken).ConfigureAwait(false);
            if (first == 0) return;
            await requests.ReadExactlyAsync(framing.AsMemory(1, 11), cancellationToken).ConfigureAwait(false);
            long offset = BinaryPrimitives.ReadInt64BigEndian(framing.AsSpan(0, 8));
            uint count = BinaryPrimitives.ReadUInt32BigEndian(framing.AsSpan(8, 4));
            if (offset < 0 || count == 0 || count > block.Bytes.Length
                || offset > length || count > length - offset || archive.Length != length)
                throw new InvalidDataException("Native verified read-at request is outside its authenticated range.");
            try
            {
                archive.Position = offset;
                // VerifiedArchiveInput authenticates complete ranges into its own
                // private buffer before copying any byte into this response.
                await archive.ReadExactlyAsync(block.Bytes.AsMemory(0, (int)count), cancellationToken).ConfigureAwait(false);
                await responses.WriteAsync(block.Bytes.AsMemory(0, (int)count), cancellationToken).ConfigureAwait(false);
                await responses.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            finally { CryptographicOperations.ZeroMemory(block.Bytes); }
        }
    }
}
