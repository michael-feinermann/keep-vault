using System.Buffers.Binary;
using System.Security.Cryptography;

namespace KalynaArchiver.Signing;

/// <summary>Current-user DPAPI protection for the two distinct release wrapping keys.</summary>
public static class WindowsWrappingKey
{
    private static ReadOnlySpan<byte> Magic => "KVDPAK12"u8;
    public const int MaximumEnvelopeBytes = 4096;

    public static byte[] Protect(ReadOnlySpan<byte> wrappingKey, ReadOnlySpan<byte> purpose)
    {
        RequireWindowsAndPurpose(purpose);
        if (wrappingKey.Length != 32) throw new CryptographicException("A release wrapping key must have 32 bytes.");
        byte[] copy = wrappingKey.ToArray();
        byte[] entropy = Entropy(purpose);
        byte[]? protectedBytes = null;
        try
        {
            protectedBytes = ProtectedData.Protect(copy, entropy, DataProtectionScope.CurrentUser);
            if (protectedBytes.Length > MaximumEnvelopeBytes - 20) throw new CryptographicException("DPAPI envelope is too large.");
            byte[] result = new byte[20 + protectedBytes.Length];
            Magic.CopyTo(result);
            purpose.CopyTo(result.AsSpan(8));
            BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(16), (uint)protectedBytes.Length);
            protectedBytes.CopyTo(result, 20);
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(copy);
            CryptographicOperations.ZeroMemory(entropy);
            if (protectedBytes is not null) CryptographicOperations.ZeroMemory(protectedBytes);
        }
    }

    public static byte[] Unprotect(ReadOnlySpan<byte> envelope, ReadOnlySpan<byte> purpose)
    {
        RequireWindowsAndPurpose(purpose);
        if (envelope.Length is <= 20 or > MaximumEnvelopeBytes
            || !CryptographicOperations.FixedTimeEquals(envelope[..8], Magic)
            || !CryptographicOperations.FixedTimeEquals(envelope.Slice(8, 8), purpose)
            || BinaryPrimitives.ReadUInt32LittleEndian(envelope.Slice(16, 4)) != envelope.Length - 20)
            throw new CryptographicException("The Windows release wrapping-key envelope has an invalid purpose or length.");
        byte[] protectedBytes = envelope[20..].ToArray();
        byte[] entropy = Entropy(purpose);
        byte[]? result = null;
        try
        {
            result = ProtectedData.Unprotect(protectedBytes, entropy, DataProtectionScope.CurrentUser);
            if (result.Length != 32) throw new CryptographicException("DPAPI returned an invalid wrapping key.");
            byte[] returned = result;
            result = null;
            return returned;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
            CryptographicOperations.ZeroMemory(entropy);
            if (result is not null) CryptographicOperations.ZeroMemory(result);
        }
    }

    private static byte[] Entropy(ReadOnlySpan<byte> purpose)
    {
        byte[] input = new byte[64];
        "KeepVault/ReleaseWrappingKey/Windows/CurrentUser/v1"u8.CopyTo(input);
        purpose.CopyTo(input.AsSpan(56));
        try { return SHA512.HashData(input); }
        finally { CryptographicOperations.ZeroMemory(input); }
    }

    private static void RequireWindowsAndPurpose(ReadOnlySpan<byte> purpose)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("This release key store requires Windows DPAPI.");
        if (!purpose.SequenceEqual("KVMDSA12"u8) && !purpose.SequenceEqual("KVPFXP12"u8))
            throw new CryptographicException("Unknown release wrapping-key purpose.");
    }
}
