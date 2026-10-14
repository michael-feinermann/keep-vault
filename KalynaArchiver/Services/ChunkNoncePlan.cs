using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using KalynaArchiver.Signing;

namespace KalynaArchiver.Services;

/// <summary>Immutable, catalog-bound ActivePrefix-v3 transcript and slice plan.</summary>
internal sealed class ChunkNoncePlan
{
    private const string Domain = "Kalyna-ZPAQ/v13/chunk-nonce/Blockwise64-ActivePrefix-SHA3-512-v3";
    private readonly byte[] _prefix;
    internal int StageNonceBytes { get; }
    internal int CapacityBlocks { get; }
    internal int ActiveBlocks { get; }
    internal int ActiveBytes => checked(ActiveBlocks * 64);
    internal int BasisBytes => checked(CapacityBlocks * 64);

    private ChunkNoncePlan(int suiteId, string algorithm, int width, int capacity)
    {
        if (width <= 0 || capacity is not (5 or 10)) throw new ArgumentOutOfRangeException(nameof(width));
        StageNonceBytes = width;
        CapacityBlocks = capacity;
        ActiveBlocks = 1 + (width - 1) / 64;
        if (ActiveBlocks > capacity) throw new ArgumentException("The stage layout exceeds the complete nonce basis.");
        byte[] domain = Encoding.UTF8.GetBytes(Domain);
        byte[] name = Encoding.UTF8.GetBytes(algorithm);
        _prefix = new byte[checked(4 + domain.Length + 4 + 4 + 4 + name.Length + 4 + 4 + 4)];
        int offset = 0;
        WriteInt(domain.Length); domain.CopyTo(_prefix, offset); offset += domain.Length;
        WriteInt(13); WriteInt(suiteId);
        WriteInt(name.Length); name.CopyTo(_prefix, offset); offset += name.Length;
        WriteInt(capacity); WriteInt(ActiveBlocks); WriteInt(width);
        void WriteInt(int value) { BinaryPrimitives.WriteInt32LittleEndian(_prefix.AsSpan(offset, 4), value); offset += 4; }
    }

    internal static ChunkNoncePlan Create(EncryptionSuiteParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        if (!ReferenceEquals(parameters, EncryptionSuiteCatalog.Get(parameters.Suite)))
            throw new ArgumentException("Only the registered suite instance may select a production nonce plan.");
        CascadeStage[] stages = SuiteKeySchedule.StagesOf(parameters).ToArray();
        if (stages.Length == 0 || stages.Sum(stage => stage.NonceBytes) != parameters.StageNonceBytes)
            throw new InvalidDataException("The registered nonce layout is inconsistent.");
        foreach (CascadeStage stage in stages)
        {
            int expected = stage.Cipher switch
            {
                CascadeCipher.Aes256 or CascadeCipher.Mars448 or CascadeCipher.Camellia256 or CascadeCipher.Serpent256 => 16,
                CascadeCipher.Shacal2_512 => 32,
                CascadeCipher.Kalyna512_512 => 64,
                CascadeCipher.Threefish1024 => 128,
                CascadeCipher.XChaCha20Poly1305 => 24,
                _ => throw new InvalidDataException("Unregistered nonce primitive."),
            };
            if (stage.NonceBytes != expected) throw new InvalidDataException("A stage has an invalid primitive nonce width.");
        }
        return new((int)parameters.Suite, parameters.Algorithm, parameters.StageNonceBytes, parameters.NonceBlockCapacity);
    }

    // Isolated capacity tests cannot add a selectable product suite or bypass Create.
    internal static ChunkNoncePlan CreateCapacityPlanForTests(int width, bool twoRounds) =>
        new(0, "KeepVault/public-capacity-test-only", width, twoRounds ? 10 : 5);

    internal void DeriveActiveNonceBlocks(ReadOnlySpan<byte> basis, long chunkIndex, Span<byte> active,
        CancellationToken cancellationToken = default, Action<int>? beforeHashForTests = null)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(chunkIndex);
        if (basis.Length != BasisBytes || active.Length != ActiveBytes)
            throw new ArgumentException("Nonce input and active output must have their exact planned lengths.");
        if (basis.Overlaps(active)) throw new ArgumentException("Nonce source and destination must not overlap.");
        Span<byte> message = stackalloc byte[checked(_prefix.Length + 8 + 4 + 64)];
        try
        {
            _prefix.CopyTo(message);
            BinaryPrimitives.WriteInt64BigEndian(message.Slice(_prefix.Length, 8), chunkIndex);
            for (int block = 0; block < ActiveBlocks; ++block)
            {
                cancellationToken.ThrowIfCancellationRequested();
                beforeHashForTests?.Invoke(block);
                cancellationToken.ThrowIfCancellationRequested();
                BinaryPrimitives.WriteUInt32BigEndian(message.Slice(_prefix.Length + 8, 4), (uint)block);
                basis.Slice(checked(block * 64), 64).CopyTo(message[^64..]);
                _ = Sha3_512Compat.HashData(message, active.Slice(checked(block * 64), 64));
            }
        }
        catch { CryptographicOperations.ZeroMemory(active); throw; }
        finally { CryptographicOperations.ZeroMemory(message); }
    }

    internal void DeriveStageNonce(ReadOnlySpan<byte> basis, long chunkIndex, Span<byte> destination,
        CancellationToken cancellationToken = default)
    {
        if (destination.Length != StageNonceBytes || basis.Overlaps(destination))
            throw new ArgumentException("The stage nonce destination has an invalid width or overlaps its source.");
        Span<byte> active = stackalloc byte[ActiveBytes];
        try
        {
            DeriveActiveNonceBlocks(basis, chunkIndex, active, cancellationToken);
            active[..StageNonceBytes].CopyTo(destination);
        }
        catch { CryptographicOperations.ZeroMemory(destination); throw; }
        finally { CryptographicOperations.ZeroMemory(active); }
    }
}
