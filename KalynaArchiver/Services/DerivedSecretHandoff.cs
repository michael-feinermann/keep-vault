using System.Security.Cryptography;

namespace KalynaArchiver.Services;

/// <summary>
/// Checks application-derived secret material before it crosses an ownership
/// or consumer boundary. This is deliberately not a cipher-primitive key policy:
/// known-answer primitive tests may use any bit pattern, including zero keys.
/// </summary>
internal static class DerivedSecretHandoff
{
    internal delegate void Mutation(string boundary, Span<byte> material);

    // Internal scoped fault injection has no configuration, environment or UI
    // entry point. Parallel tests inherit their own execution-context scope.
    private static readonly AsyncLocal<Mutation?> MutationOverride = new();

    internal static IDisposable UseMutationForTests(Mutation mutation)
    {
        ArgumentNullException.ThrowIfNull(mutation);
        Mutation? previous = MutationOverride.Value;
        MutationOverride.Value = mutation;
        return new MutationScope(previous);
    }

    internal static void Verify(string boundary, Span<byte> material, int expectedLength)
    {
        ArgumentException.ThrowIfNullOrEmpty(boundary);
        try
        {
            // Width is checked before invoking the test mutation so no missing
            // or shortened buffer can masquerade as a complete handoff.
            RequireLength(material.Length, expectedLength);
            MutationOverride.Value?.Invoke(boundary, material);
            Require(material, expectedLength);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(material);
            throw;
        }
    }

    internal static void Require(ReadOnlySpan<byte> material, int expectedLength)
    {
        RequireLength(material.Length, expectedLength);

        // Scan the complete buffer without early exits. These three specific
        // sentinels catch missing writes, cleared owners and constant faulty
        // outputs; they do not detect arbitrary corruption or certify entropy.
        int differsFromZero = 0;
        int differsFromByteOne = 0;
        int differsFromAllBitsOne = 0;
        foreach (byte value in material)
        {
            differsFromZero |= value;
            differsFromByteOne |= value ^ 0x01;
            differsFromAllBitsOne |= value ^ 0xFF;
        }

        if (differsFromZero == 0 || differsFromByteOne == 0 || differsFromAllBitsOne == 0)
        {
            throw new CryptographicException("Derived secret material failed its handoff check.");
        }
    }

    private static void RequireLength(int actualLength, int expectedLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(expectedLength);
        if (actualLength != expectedLength)
        {
            throw new ArgumentException("Derived secret material has an invalid width.");
        }
    }

    private sealed class MutationScope(Mutation? previous) : IDisposable
    {
        private int _disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                MutationOverride.Value = previous;
            }
        }
    }
}
