using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace KalynaArchiver.Services;

// The aggregate scheduler grants this many CPU permits before a synchronous
// native call. This immutable ambient value flows through managed tasks; no
// environment variable or shared mutable native setting controls an operation.
internal static class NativeCipherWorkerBudget
{
    private static readonly AsyncLocal<int?> Granted = new();
    internal static int Current => Granted.Value ?? 1;
    internal static IDisposable EnterScope(int workers)
    {
        if (workers < 1) throw new ArgumentOutOfRangeException(nameof(workers));
        int? previous = Granted.Value;
        Granted.Value = workers;
        return new Scope(previous);
    }
    private sealed class Scope(int? previous) : IDisposable
    {
        private bool _disposed;
        public void Dispose()
        {
            if (_disposed) return;
            Granted.Value = previous;
            _disposed = true;
        }
    }
}

// Interop for the two cascade layers that come from Crypto++.
//
// Both follow NativeKalyna exactly: the library is loaded through
// NativeToolIntegrity so its manifests and hybrid signatures are checked before
// a single byte is executed, the entry point is resolved once behind a lock,
// and a failure to load is reported with its reason rather than as a missing
// file. A reference library that silently degrades to "unavailable" is
// indistinguishable from one that was tampered with, which is exactly the
// distinction this app exists to make.

internal static class NativeCamellia
{
    private static readonly NativeV13Ctr Cipher = new("camellia_v13.dll", "camellia");
    internal static string? LastLoadError => Cipher.LastLoadError;
    internal static bool IsAvailable() => Cipher.IsAvailable();
    internal static void XCrypt(byte[] key, byte[] nonce, byte[] input, byte[] output, int length) => Cipher.XCrypt(key, nonce, input, output, length);
    internal static void EncryptBlock(byte[] key, byte[] input, byte[] output) => Cipher.EncryptBlock(key, input, output);
}

internal static class NativeSerpent
{
    private static readonly NativeV13Ctr Cipher = new("serpent_v13.dll", "serpent");
    internal static string? LastLoadError => Cipher.LastLoadError;
    internal static bool IsAvailable() => Cipher.IsAvailable();
    internal static void XCrypt(byte[] key, byte[] nonce, byte[] input, byte[] output, int length) => Cipher.XCrypt(key, nonce, input, output, length);
    internal static void EncryptBlock(byte[] key, byte[] input, byte[] output) => Cipher.EncryptBlock(key, input, output);
}

// Both new adapters have an explicit v13 pointer/length contract, including
// output capacity and the aggregate scheduler's borrowed CPU grant.
internal sealed unsafe class NativeV13Ctr(string libraryName, string algorithm)
{
    private readonly object _loadGate = new();
    private nint _libraryHandle;
    private delegate* unmanaged[Cdecl]<byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, uint, int> _xcrypt;
    private delegate* unmanaged[Cdecl]<byte*, nuint, byte*, nuint, byte*, nuint, int> _block;
    internal string? LastLoadError { get; private set; }
    internal bool IsAvailable()
    {
        try { EnsureLoaded(); LastLoadError = null; return true; }
        catch (Exception ex) { LastLoadError = $"{ex.GetType().Name}: {ex.Message}"; return false; }
    }
    internal void XCrypt(byte[] key, byte[] nonce, byte[] input, byte[] output, int length)
    {
        ArgumentNullException.ThrowIfNull(key); ArgumentNullException.ThrowIfNull(nonce);
        ArgumentNullException.ThrowIfNull(input); ArgumentNullException.ThrowIfNull(output);
        if (key.Length != 32 || nonce.Length != 16 || length < 0 || length > 16 * 1024 * 1024 || input.Length < length || output.Length < length)
            throw new ArgumentException($"{algorithm}-256 requires key32, nonce16 and a payload of at most16MiB.");
        EnsureLoaded();
        fixed (byte* k = key) fixed (byte* n = nonce) fixed (byte* i = input) fixed (byte* o = output)
            RequireSuccess(_xcrypt(k, (nuint)key.Length, n, (nuint)nonce.Length, i, (nuint)length, o, (nuint)output.Length, (uint)NativeCipherWorkerBudget.Current));
    }
    internal void EncryptBlock(byte[] key, byte[] input, byte[] output)
    {
        if (key.Length != 32 || input.Length != 16 || output.Length < 16) throw new ArgumentException("Invalid block KAT buffers.");
        EnsureLoaded();
        fixed (byte* k = key) fixed (byte* i = input) fixed (byte* o = output)
            RequireSuccess(_block(k, (nuint)key.Length, i, (nuint)input.Length, o, (nuint)output.Length));
    }
    private void RequireSuccess(int status)
    {
        if (status != 0) throw new CryptographicException($"{algorithm}-256 v13 native error {status}.");
    }
    private void EnsureLoaded()
    {
        lock (_loadGate)
        {
            if (_libraryHandle != 0) return;
            nint handle = NativeToolIntegrity.LoadTrustedLibrary(libraryName);
            try
            {
                NativeCipherExecutor.Install(handle);
                _xcrypt = (delegate* unmanaged[Cdecl]<byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, uint, int>)NativeLibrary.GetExport(handle, $"keepvault_v13_{algorithm}_256_ctr_xcrypt");
                _block = (delegate* unmanaged[Cdecl]<byte*, nuint, byte*, nuint, byte*, nuint, int>)NativeLibrary.GetExport(handle, $"keepvault_test_v13_{algorithm}_256_encrypt_block");
                _libraryHandle = handle;
            }
            catch { _xcrypt = null; _block = null; NativeLibrary.Free(handle); throw; }
        }
    }
}

internal static unsafe class NativeMars
{
    private const string DllName = "mars_ref.dll";

    /// <summary>MARS accepts 128 to 448 bits; the cascade uses the longest.</summary>
    private const int KeyBytes = 56;

    /// <summary>MARS has a 128-bit block, so its counter is 16 bytes wide.</summary>
    internal const int BlockBytes = 16;

    private static readonly object LoadGate = new();
    private static nint _libraryHandle;
    private static delegate* unmanaged[Cdecl]<byte*, byte*, byte*, byte*, nuint, uint, int> _xcryptCtr;
    private static delegate* unmanaged[Cdecl]<byte*, nuint, byte*, byte*, int> _encryptBlock;

    public static string? LastLoadError { get; private set; }

    public static bool IsAvailable()
    {
        try
        {
            EnsureLoaded();
            LastLoadError = null;
            return true;
        }
        catch (Exception ex)
        {
            LastLoadError = $"{ex.GetType().Name}: {ex.Message}";
            return false;
        }
    }

    public static void XCryptCtr448(byte[] key, byte[] nonce, byte[] input, byte[] output, int length)
    {
        if (key.Length != KeyBytes || nonce.Length != BlockBytes
            || length < 0 || input.Length < length || output.Length < length)
        {
            throw new ArgumentException(
                $"MARS-448 requires a {KeyBytes}-byte key, a {BlockBytes}-byte nonce, and sufficiently large buffers.");
        }

        EnsureLoaded();
        // Empty managed arrays pin to NULL. The legacy CTR ABI rejects NULL,
        // while a validated empty CTR range has no blocks or counter use.
        if (length == 0) return;
        int result;
        fixed (byte* keyPointer = key)
        fixed (byte* noncePointer = nonce)
        fixed (byte* inputPointer = input)
        fixed (byte* outputPointer = output)
        {
            result = _xcryptCtr(keyPointer, noncePointer, inputPointer, outputPointer, (nuint)length, (uint)NativeCipherWorkerBudget.Current);
        }

        ThrowOnError(result, "MARS");
    }

    /// <summary>
    /// One block, no counter. Used by the tests to compare against published
    /// vectors, so that the vector check exercises the cipher rather than the
    /// mode wrapped around it.
    /// </summary>
    internal static void EncryptBlock(byte[] key, byte[] input, byte[] output)
    {
        if (input.Length != BlockBytes || output.Length < BlockBytes)
        {
            throw new ArgumentException($"MARS operates on {BlockBytes}-byte blocks.");
        }

        EnsureLoaded();
        int result;
        fixed (byte* keyPointer = key)
        fixed (byte* inputPointer = input)
        fixed (byte* outputPointer = output)
        {
            result = _encryptBlock(keyPointer, (nuint)key.Length, inputPointer, outputPointer);
        }

        ThrowOnError(result, "MARS");
    }

    private static void ThrowOnError(int result, string algorithm)
    {
        if (result == 0)
        {
            return;
        }

        throw new CryptographicException(result switch
        {
            1 => $"{algorithm} reference library received invalid buffers.",
            2 => $"{algorithm} reference library rejected the key length.",
            3 => $"{algorithm} reference library could not start CTR worker threads.",
            4 => $"{algorithm} CTR counter is exhausted or overflowed.",
            _ => $"{algorithm} reference library returned error {result}.",
        });
    }

    private static void EnsureLoaded()
    {
        lock (LoadGate)
        {
            if (_libraryHandle != 0)
            {
                return;
            }

            nint handle = NativeToolIntegrity.LoadTrustedLibrary(DllName);
            try
            {
                NativeCipherExecutor.Install(handle);
                _xcryptCtr = (delegate* unmanaged[Cdecl]<byte*, byte*, byte*, byte*, nuint, uint, int>)
                    NativeLibrary.GetExport(handle, "mars_448_ctr_xcrypt_v13_with_workers");
                _encryptBlock = (delegate* unmanaged[Cdecl]<byte*, nuint, byte*, byte*, int>)
                    NativeLibrary.GetExport(handle, "mars_encrypt_block");
                _libraryHandle = handle;
            }
            catch
            {
                NativeLibrary.Free(handle);
                _xcryptCtr = null;
                _encryptBlock = null;
                throw;
            }
        }
    }
}

internal static unsafe class NativeShacal2
{
    private const string DllName = "shacal2_ref.dll";

    private const int KeyBytes = 64;

    /// <summary>
    /// SHACAL-2 works on 256-bit blocks — twice AES's, half Kalyna's. The
    /// counter is therefore 32 bytes wide, which the cascade's nonce split has
    /// to account for.
    /// </summary>
    internal const int BlockBytes = 32;

    private static readonly object LoadGate = new();
    private static nint _libraryHandle;
    private static delegate* unmanaged[Cdecl]<byte*, byte*, byte*, byte*, nuint, uint, int> _xcryptCtr;
    private static delegate* unmanaged[Cdecl]<byte*, nuint, byte*, byte*, int> _encryptBlock;

    public static string? LastLoadError { get; private set; }

    public static bool IsAvailable()
    {
        try
        {
            EnsureLoaded();
            LastLoadError = null;
            return true;
        }
        catch (Exception ex)
        {
            LastLoadError = $"{ex.GetType().Name}: {ex.Message}";
            return false;
        }
    }

    public static void XCryptCtr512(byte[] key, byte[] nonce, byte[] input, byte[] output, int length)
    {
        if (key.Length != KeyBytes || nonce.Length != BlockBytes
            || length < 0 || input.Length < length || output.Length < length)
        {
            throw new ArgumentException(
                $"SHACAL-2-512 requires a {KeyBytes}-byte key, a {BlockBytes}-byte nonce, and sufficiently large buffers.");
        }

        EnsureLoaded();
        // Empty managed arrays pin to NULL. The legacy CTR ABI rejects NULL,
        // while a validated empty CTR range has no blocks or counter use.
        if (length == 0) return;
        int result;
        fixed (byte* keyPointer = key)
        fixed (byte* noncePointer = nonce)
        fixed (byte* inputPointer = input)
        fixed (byte* outputPointer = output)
        {
            result = _xcryptCtr(keyPointer, noncePointer, inputPointer, outputPointer, (nuint)length, (uint)NativeCipherWorkerBudget.Current);
        }

        ThrowOnError(result);
    }

    internal static void EncryptBlock(byte[] key, byte[] input, byte[] output)
    {
        if (input.Length != BlockBytes || output.Length < BlockBytes)
        {
            throw new ArgumentException($"SHACAL-2 operates on {BlockBytes}-byte blocks.");
        }

        EnsureLoaded();
        int result;
        fixed (byte* keyPointer = key)
        fixed (byte* inputPointer = input)
        fixed (byte* outputPointer = output)
        {
            result = _encryptBlock(keyPointer, (nuint)key.Length, inputPointer, outputPointer);
        }

        ThrowOnError(result);
    }

    private static void ThrowOnError(int result)
    {
        if (result == 0)
        {
            return;
        }

        throw new CryptographicException(result switch
        {
            1 => "SHACAL-2 reference library received invalid buffers.",
            2 => "SHACAL-2 reference library rejected the key length.",
            3 => "SHACAL-2 reference library could not start CTR worker threads.",
            4 => "SHACAL-2 CTR counter is exhausted or overflowed.",
            _ => $"SHACAL-2 reference library returned error {result}.",
        });
    }

    private static void EnsureLoaded()
    {
        lock (LoadGate)
        {
            if (_libraryHandle != 0)
            {
                return;
            }

            nint handle = NativeToolIntegrity.LoadTrustedLibrary(DllName);
            try
            {
                NativeCipherExecutor.Install(handle);
                _xcryptCtr = (delegate* unmanaged[Cdecl]<byte*, byte*, byte*, byte*, nuint, uint, int>)
                    NativeLibrary.GetExport(handle, "shacal2_512_ctr_xcrypt_v13_with_workers");
                _encryptBlock = (delegate* unmanaged[Cdecl]<byte*, nuint, byte*, byte*, int>)
                    NativeLibrary.GetExport(handle, "shacal2_encrypt_block");
                _libraryHandle = handle;
            }
            catch
            {
                NativeLibrary.Free(handle);
                _xcryptCtr = null;
                _encryptBlock = null;
                throw;
            }
        }
    }
}

internal enum NativeAesRuntimeProvider
{
    Unknown = 0,
    AesNi = 1,
    ArmV8 = 2,
    ArmV7 = 3,
    Power8 = 4,
    Sse2 = 5,
    PortableCpp = 6,
}

internal static unsafe class NativeAes
{
    private const string DllName = "aes_ref.dll";
    private const int KeyBytes = 32;

    internal const int BlockBytes = 16;

    private static readonly object LoadGate = new();
    private static nint _libraryHandle;
    private static delegate* unmanaged[Cdecl]<byte*, byte*, byte*, byte*, nuint, uint, int> _xcryptCtr;
    private static delegate* unmanaged[Cdecl]<byte*, nuint, byte*, byte*, int> _encryptBlock;
    private static delegate* unmanaged[Cdecl]<int> _getRuntimeProvider;

    public static string? LastLoadError { get; private set; }

    public static bool IsAvailable()
    {
        try
        {
            EnsureLoaded();
            LastLoadError = null;
            return true;
        }
        catch (Exception ex)
        {
            LastLoadError = $"{ex.GetType().Name}: {ex.Message}";
            return false;
        }
    }

    /// <summary>
    /// Reports the read-only Crypto++ provider selected by the same runtime
    /// dispatch that encrypts AES blocks.
    /// </summary>
    internal static NativeAesRuntimeProvider RuntimeProvider
    {
        get
        {
            EnsureLoaded();
            return (NativeAesRuntimeProvider)_getRuntimeProvider();
        }
    }

    /// <summary>
    /// AES-256 in CTR, as every cascade stage that names AES runs it.
    /// </summary>
    /// <remarks>
    /// This is the production path, not a fallback: there is no managed or
    /// platform AES anywhere in this application, and ApplyCtrStage calls
    /// straight into here. An earlier version of this comment claimed
    /// otherwise, and that claim is what hid the fact that macOS was building
    /// Crypto++ with its assembly and SIMD paths switched off — AES ran on
    /// tables while the comment said it ran on AES-NI.
    ///
    /// It reaches the hardware now: the *_simd translation units are built
    /// with their instruction-set flags, and which path runs is decided at
    /// load time from CPUID on Intel and from the ARM feature registers on
    /// Apple silicon.
    /// </remarks>
    public static void XCryptCtr256(byte[] key, byte[] nonce, byte[] input, byte[] output, int length)
    {
        if (key.Length != KeyBytes || nonce.Length != BlockBytes
            || length < 0 || input.Length < length || output.Length < length)
        {
            throw new ArgumentException(
                $"AES-256 requires a {KeyBytes}-byte key, a {BlockBytes}-byte nonce, and sufficiently large buffers.");
        }

        EnsureLoaded();
        // Empty managed arrays pin to NULL. The legacy CTR ABI rejects NULL,
        // while a validated empty CTR range has no blocks or counter use.
        if (length == 0) return;
        int result;
        fixed (byte* keyPointer = key)
        fixed (byte* noncePointer = nonce)
        fixed (byte* inputPointer = input)
        fixed (byte* outputPointer = output)
        {
            result = _xcryptCtr(keyPointer, noncePointer, inputPointer, outputPointer, (nuint)length, (uint)NativeCipherWorkerBudget.Current);
        }

        if (result != 0)
        {
            throw new CryptographicException($"AES reference library returned error {result}.");
        }
    }

    internal static void EncryptBlock(byte[] key, byte[] input, byte[] output)
    {
        if (input.Length != BlockBytes || output.Length < BlockBytes)
        {
            throw new ArgumentException($"AES operates on {BlockBytes}-byte blocks.");
        }

        EnsureLoaded();
        int result;
        fixed (byte* keyPointer = key)
        fixed (byte* inputPointer = input)
        fixed (byte* outputPointer = output)
        {
            result = _encryptBlock(keyPointer, (nuint)key.Length, inputPointer, outputPointer);
        }

        if (result != 0)
        {
            throw new CryptographicException($"AES reference library returned error {result}.");
        }
    }

    private static void EnsureLoaded()
    {
        lock (LoadGate)
        {
            if (_libraryHandle != 0)
            {
                return;
            }

            nint handle = NativeToolIntegrity.LoadTrustedLibrary(DllName);
            try
            {
                NativeCipherExecutor.Install(handle);
                _xcryptCtr = (delegate* unmanaged[Cdecl]<byte*, byte*, byte*, byte*, nuint, uint, int>)
                    NativeLibrary.GetExport(handle, "aes_256_ctr_xcrypt_v13_with_workers");
                _encryptBlock = (delegate* unmanaged[Cdecl]<byte*, nuint, byte*, byte*, int>)
                    NativeLibrary.GetExport(handle, "aes_encrypt_block");
                _getRuntimeProvider = (delegate* unmanaged[Cdecl]<int>)
                    NativeLibrary.GetExport(handle, "aes_get_runtime_provider");
                NativeAesRuntimeProvider provider = (NativeAesRuntimeProvider)_getRuntimeProvider();
                if (!Enum.IsDefined(provider) || provider == NativeAesRuntimeProvider.Unknown)
                {
                    throw new CryptographicException(
                        $"The AES adapter reported an invalid Crypto++ runtime provider ({(int)provider}).");
                }

                // Every Apple-silicon Mac has the ARM cryptography extension.
                // A portable result here means the SIMD translation unit was
                // omitted or Crypto++ feature detection regressed. Continuing
                // would silently ship the exact fallback the release contract
                // forbids, so native arm64 macOS treats it as a load failure.
                if (OperatingSystem.IsMacOS()
                    && RuntimeInformation.ProcessArchitecture == Architecture.Arm64
                    && provider != NativeAesRuntimeProvider.ArmV8)
                {
                    throw new PlatformNotSupportedException(
                        $"Apple-silicon AES must use the Crypto++ ArmV8 provider; the library selected {provider}.");
                }
                _libraryHandle = handle;
            }
            catch
            {
                NativeLibrary.Free(handle);
                _xcryptCtr = null;
                _encryptBlock = null;
                _getRuntimeProvider = null;
                throw;
            }
        }
    }
}

internal static unsafe class NativeXChaChaPoly
{
    private const string DllName = "xchachapoly_v13.dll";

    internal const int KeyBytes = 32;
    internal const int NonceBytes = 24;
    internal const int RawNonceBytes = 12;
    internal const int MaximumPayloadBytes = 16 * 1024 * 1024;
    internal const int TagBytes = 16;

    private static readonly object LoadGate = new();
    private static nint _libraryHandle;
    private static delegate* unmanaged[Cdecl]<byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, uint, int> _encrypt;
    private static delegate* unmanaged[Cdecl]<byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, uint, int> _decrypt;
    private static delegate* unmanaged[Cdecl]<byte*, byte*, uint, byte*, byte*, nuint, int> _xcrypt;
    private static delegate* unmanaged[Cdecl]<byte*, byte*, uint, byte*, byte*, nuint, int> _xcryptSerial;
    private static delegate* unmanaged[Cdecl]<byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, uint, int> _encryptWithWorkers;
    private static delegate* unmanaged[Cdecl]<byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, uint, int> _decryptWithWorkers;
    private static delegate* unmanaged[Cdecl]<byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, int> _encryptSerial;
    private static delegate* unmanaged[Cdecl]<byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, int> _decryptSerial;
    private static delegate* unmanaged[Cdecl]<byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, uint, int> _authWithWorkers;
    private static delegate* unmanaged[Cdecl]<byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, int> _authSerial;
    private static delegate* unmanaged[Cdecl]<int, ulong, int*, ulong*, ulong*, int*, int> _createMacSnapshot;
    private static delegate* unmanaged[Cdecl]<
        int,
        ulong,
        uint,
        delegate* unmanaged[Cdecl]<nint, void>,
        nint,
        int*,
        ulong*,
        ulong*,
        int*,
        int> _createMacSnapshotForTests;
    private static delegate* unmanaged[Cdecl]<ulong, ulong, int*, int> _releaseMacSnapshot;

    public static string? LastLoadError { get; private set; }

    public static bool IsAvailable()
    {
        try
        {
            EnsureLoaded();
            LastLoadError = null;
            return true;
        }
        catch (Exception ex)
        {
            LastLoadError = $"{ex.GetType().Name}: {ex.Message}";
            return false;
        }
    }

    /// <summary>
    /// Copies an opened macOS file into an anonymous POSIX-SHM object and
    /// returns its distinct read-only descriptor and complete read-only mapping.
    /// </summary>
    /// <remarks>
    /// The native ABI is intentionally fixed-width and returns both a stable
    /// status and the original Darwin errno. The caller owns a non-negative
    /// descriptor and mapping only when the status is zero. Darwin SHM file
    /// descriptors are not byte-readable, so callers consume the mapping.
    /// </remarks>
    internal static int CreateMacAnonymousSnapshot(
        int sourceDescriptor,
        ulong maximumBytes,
        out int snapshotReadDescriptor,
        out ulong mappingAddress,
        out ulong logicalSize,
        out int osError)
    {
        EnsureMacSnapshotExportsLoaded(includeTestExport: false);
        int output = -1;
        ulong address = 0;
        ulong size = 0;
        int error = 0;
        int status = _createMacSnapshot(
            sourceDescriptor,
            maximumBytes,
            &output,
            &address,
            &size,
            &error);
        snapshotReadDescriptor = output;
        mappingAddress = address;
        logicalSize = size;
        osError = error;
        return status;
    }

    /// <summary>
    /// Test seam for source mutation and a deterministic ENOSPC after the
    /// first copied block. The callback is synchronous and never retained.
    /// </summary>
    internal static int CreateMacAnonymousSnapshotForTests(
        int sourceDescriptor,
        ulong maximumBytes,
        uint testFlags,
        delegate* unmanaged[Cdecl]<nint, void> afterCopyHook,
        nint hookContext,
        out int snapshotReadDescriptor,
        out ulong mappingAddress,
        out ulong logicalSize,
        out int osError)
    {
        EnsureMacSnapshotExportsLoaded(includeTestExport: true);
        int output = -1;
        ulong address = 0;
        ulong size = 0;
        int error = 0;
        int status = _createMacSnapshotForTests(
            sourceDescriptor,
            maximumBytes,
            testFlags,
            afterCopyHook,
            hookContext,
            &output,
            &address,
            &size,
            &error);
        snapshotReadDescriptor = output;
        mappingAddress = address;
        logicalSize = size;
        osError = error;
        return status;
    }

    internal static int ReleaseMacAnonymousSnapshot(
        ulong mappingAddress,
        ulong logicalSize,
        out int osError)
    {
        EnsureMacSnapshotExportsLoaded(includeTestExport: false);
        int error = 0;
        int status = _releaseMacSnapshot(mappingAddress, logicalSize, &error);
        osError = error;
        return status;
    }

    public static void Encrypt(
        byte[] key,
        byte[] nonce,
        ReadOnlySpan<byte> associatedData,
        byte[] plaintext,
        byte[] ciphertext,
        int length,
        byte[] tag)
    {
        Validate(key, nonce, tag, plaintext, ciphertext, length);

        EnsureLoaded();
        int result;
        fixed (byte* keyPointer = key)
        fixed (byte* noncePointer = nonce)
        fixed (byte* aadPointer = associatedData)
        fixed (byte* inputPointer = plaintext)
        fixed (byte* outputPointer = ciphertext)
        fixed (byte* tagPointer = tag)
        {
            result = _encrypt(
                keyPointer, (nuint)key.Length, noncePointer, (nuint)nonce.Length, aadPointer, (nuint)associatedData.Length,
                inputPointer, (nuint)length, outputPointer, (nuint)ciphertext.Length, tagPointer, (nuint)tag.Length, (uint)NativeCipherWorkerBudget.Current);
        }

        ThrowOnError(result);
    }

    /// <summary>
    /// Verifies the tag and decrypts, or throws.
    /// </summary>
    /// <remarks>
    /// A failed tag is reported as its own exception rather than folded into a
    /// generic error. It is the one outcome that means the ciphertext was
    /// altered, and a caller that cannot tell it apart from a missing library
    /// cannot react correctly to either.
    /// </remarks>
    public static void Decrypt(
        byte[] key,
        byte[] nonce,
        ReadOnlySpan<byte> associatedData,
        byte[] ciphertext,
        byte[] plaintext,
        int length,
        byte[] tag)
    {
        Validate(key, nonce, tag, ciphertext, plaintext, length);

        EnsureLoaded();
        int result;
        fixed (byte* keyPointer = key)
        fixed (byte* noncePointer = nonce)
        fixed (byte* aadPointer = associatedData)
        fixed (byte* inputPointer = ciphertext)
        fixed (byte* outputPointer = plaintext)
        fixed (byte* tagPointer = tag)
        {
            result = _decrypt(
                keyPointer, (nuint)key.Length, noncePointer, (nuint)nonce.Length, aadPointer, (nuint)associatedData.Length,
                inputPointer, (nuint)length, outputPointer, (nuint)plaintext.Length, tagPointer, (nuint)tag.Length, (uint)NativeCipherWorkerBudget.Current);
        }

        if (result == 6)
        {
            throw new CryptographicException(
                "The XChaCha20-Poly1305 authentication tag does not match; the ciphertext was altered.");
        }

        ThrowOnError(result);
    }

    // Full independent Crypto++ construction. Test buffers only.
    internal static void EncryptReference(byte[] key, byte[] nonce, ReadOnlySpan<byte> associatedData,
        byte[] input, byte[] output, int length, byte[] tag)
    {
        Validate(key, nonce, tag, input, output, length);
        EnsureLoaded();
        var entry = (delegate* unmanaged[Cdecl]<byte*, nuint, byte*, nuint, byte*, nuint,
            byte*, nuint, byte*, nuint, byte*, nuint, int>)NativeLibrary.GetExport(
            _libraryHandle, "keepvault_test_xchacha20poly1305_v13_cryptopp_encrypt");
        fixed (byte* keyPointer = key)
        fixed (byte* noncePointer = nonce)
        fixed (byte* aadPointer = associatedData)
        fixed (byte* inputPointer = input)
        fixed (byte* outputPointer = output)
        fixed (byte* tagPointer = tag)
        {
            ThrowOnError(entry(keyPointer, (nuint)key.Length, noncePointer, (nuint)nonce.Length,
                aadPointer, (nuint)associatedData.Length, inputPointer, (nuint)length,
                outputPointer, (nuint)output.Length, tagPointer, (nuint)tag.Length));
        }
    }

    // Full independent Crypto++ construction. Test buffers only.
    internal static void DecryptReference(byte[] key, byte[] nonce, ReadOnlySpan<byte> associatedData,
        byte[] input, byte[] output, int length, byte[] tag)
    {
        Validate(key, nonce, tag, input, output, length);
        EnsureLoaded();
        var entry = (delegate* unmanaged[Cdecl]<byte*, nuint, byte*, nuint, byte*, nuint,
            byte*, nuint, byte*, nuint, byte*, nuint, int>)NativeLibrary.GetExport(
            _libraryHandle, "keepvault_test_xchacha20poly1305_v13_cryptopp_decrypt");
        fixed (byte* keyPointer = key)
        fixed (byte* noncePointer = nonce)
        fixed (byte* aadPointer = associatedData)
        fixed (byte* inputPointer = input)
        fixed (byte* outputPointer = output)
        fixed (byte* tagPointer = tag)
        {
            ThrowOnError(entry(keyPointer, (nuint)key.Length, noncePointer, (nuint)nonce.Length,
                aadPointer, (nuint)associatedData.Length, inputPointer, (nuint)length,
                outputPointer, (nuint)output.Length, tagPointer, (nuint)tag.Length));
        }
    }

    /// <summary>Runs the fixed-limb Poly1305 path with an explicit worker count.</summary>
    internal static void EncryptWithPoly1305Workers(
        byte[] key,
        byte[] nonce,
        ReadOnlySpan<byte> associatedData,
        byte[] plaintext,
        byte[] ciphertext,
        int length,
        byte[] tag,
        uint workerCount)
    {
        Validate(key, nonce, tag, plaintext, ciphertext, length);
        EnsureAeadTestExportsLoaded();
        int result;
        fixed (byte* keyPointer = key)
        fixed (byte* noncePointer = nonce)
        fixed (byte* aadPointer = associatedData)
        fixed (byte* inputPointer = plaintext)
        fixed (byte* outputPointer = ciphertext)
        fixed (byte* tagPointer = tag)
        {
            result = _encryptWithWorkers(
                keyPointer, (nuint)key.Length, noncePointer, (nuint)nonce.Length, aadPointer, (nuint)associatedData.Length,
                inputPointer, (nuint)length, outputPointer, (nuint)ciphertext.Length, tagPointer, (nuint)tag.Length, workerCount);
        }

        ThrowOnError(result);
    }

    /// <summary>Runs the scalar shared-composition AEAD reference export.</summary>
    internal static void EncryptSerial(
        byte[] key,
        byte[] nonce,
        ReadOnlySpan<byte> associatedData,
        byte[] plaintext,
        byte[] ciphertext,
        int length,
        byte[] tag)
    {
        Validate(key, nonce, tag, plaintext, ciphertext, length);
        EnsureAeadTestExportsLoaded();
        int result;
        fixed (byte* keyPointer = key)
        fixed (byte* noncePointer = nonce)
        fixed (byte* aadPointer = associatedData)
        fixed (byte* inputPointer = plaintext)
        fixed (byte* outputPointer = ciphertext)
        fixed (byte* tagPointer = tag)
        {
            result = _encryptSerial(
                keyPointer, (nuint)key.Length, noncePointer, (nuint)nonce.Length, aadPointer, (nuint)associatedData.Length,
                inputPointer, (nuint)length, outputPointer, (nuint)ciphertext.Length, tagPointer, (nuint)tag.Length);
        }

        ThrowOnError(result);
    }

    /// <summary>Verifies with an explicit Poly1305 worker count before decrypting.</summary>
    internal static void DecryptWithPoly1305Workers(
        byte[] key,
        byte[] nonce,
        ReadOnlySpan<byte> associatedData,
        byte[] ciphertext,
        byte[] plaintext,
        int length,
        byte[] tag,
        uint workerCount)
    {
        Validate(key, nonce, tag, ciphertext, plaintext, length);
        EnsureAeadTestExportsLoaded();
        int result;
        fixed (byte* keyPointer = key)
        fixed (byte* noncePointer = nonce)
        fixed (byte* aadPointer = associatedData)
        fixed (byte* inputPointer = ciphertext)
        fixed (byte* outputPointer = plaintext)
        fixed (byte* tagPointer = tag)
        {
            result = _decryptWithWorkers(
                keyPointer, (nuint)key.Length, noncePointer, (nuint)nonce.Length, aadPointer, (nuint)associatedData.Length,
                inputPointer, (nuint)length, outputPointer, (nuint)plaintext.Length, tagPointer, (nuint)tag.Length, workerCount);
        }

        if (result == 6)
        {
            throw new CryptographicException(
                "The XChaCha20-Poly1305 authentication tag does not match; the ciphertext was altered.");
        }
        ThrowOnError(result);
    }

    /// <summary>Verifies and decrypts through the scalar shared-composition reference.</summary>
    internal static void DecryptSerial(
        byte[] key,
        byte[] nonce,
        ReadOnlySpan<byte> associatedData,
        byte[] ciphertext,
        byte[] plaintext,
        int length,
        byte[] tag)
    {
        Validate(key, nonce, tag, ciphertext, plaintext, length);
        EnsureAeadTestExportsLoaded();
        int result;
        fixed (byte* keyPointer = key)
        fixed (byte* noncePointer = nonce)
        fixed (byte* aadPointer = associatedData)
        fixed (byte* inputPointer = ciphertext)
        fixed (byte* outputPointer = plaintext)
        fixed (byte* tagPointer = tag)
        {
            result = _decryptSerial(
                keyPointer, (nuint)key.Length, noncePointer, (nuint)nonce.Length, aadPointer, (nuint)associatedData.Length,
                inputPointer, (nuint)length, outputPointer, (nuint)plaintext.Length, tagPointer, (nuint)tag.Length);
        }

        if (result == 6)
        {
            throw new CryptographicException(
                "The XChaCha20-Poly1305 authentication tag does not match; the ciphertext was altered.");
        }
        ThrowOnError(result);
    }

    /// <summary>Computes only the RFC 8439 tag through the fixed-worker path.</summary>
    internal static void AuthenticateWithPoly1305Workers(
        byte[] key,
        byte[] nonce,
        ReadOnlySpan<byte> associatedData,
        byte[] ciphertext,
        int length,
        byte[] tag,
        uint workerCount)
    {
        ValidateAuthentication(key, nonce, tag, ciphertext, length);
        EnsureAeadTestExportsLoaded();
        int result;
        fixed (byte* keyPointer = key)
        fixed (byte* noncePointer = nonce)
        fixed (byte* aadPointer = associatedData)
        fixed (byte* inputPointer = ciphertext)
        fixed (byte* tagPointer = tag)
        {
            result = _authWithWorkers(
                keyPointer, (nuint)key.Length, noncePointer, (nuint)nonce.Length, aadPointer, (nuint)associatedData.Length,
                inputPointer, (nuint)length, tagPointer, (nuint)tag.Length, workerCount);
        }
        ThrowOnError(result);
    }

    /// <summary>Computes only the RFC 8439 tag through the scalar oracle.</summary>
    internal static void AuthenticateSerial(
        byte[] key,
        byte[] nonce,
        ReadOnlySpan<byte> associatedData,
        byte[] ciphertext,
        int length,
        byte[] tag)
    {
        ValidateAuthentication(key, nonce, tag, ciphertext, length);
        EnsureAeadTestExportsLoaded();
        int result;
        fixed (byte* keyPointer = key)
        fixed (byte* noncePointer = nonce)
        fixed (byte* aadPointer = associatedData)
        fixed (byte* inputPointer = ciphertext)
        fixed (byte* tagPointer = tag)
        {
            result = _authSerial(
                keyPointer, (nuint)key.Length, noncePointer, (nuint)nonce.Length, aadPointer, (nuint)associatedData.Length,
                inputPointer, (nuint)length, tagPointer, (nuint)tag.Length);
        }
        ThrowOnError(result);
    }

    /// <summary>
    /// Raw ChaCha20 keyed at an explicit block counter, split across workers.
    /// </summary>
    /// <remarks>
    /// Exercised by the differential test rather than by the container, which
    /// reaches ChaCha20 only through the authenticated pair above.
    /// </remarks>
    internal static int XCrypt(byte[] key, byte[] nonce, uint blockCounter, byte[] input, byte[] output, int length)
    {
        return XCrypt(key, nonce, blockCounter, input, output, length, serial: false);
    }

    /// <summary>The same keystream produced on one thread.</summary>
    internal static int XCryptSerial(byte[] key, byte[] nonce, uint blockCounter, byte[] input, byte[] output, int length)
    {
        return XCrypt(key, nonce, blockCounter, input, output, length, serial: true);
    }

    /// <remarks>
    /// Returns the native status instead of throwing: the counter-exhaustion
    /// refusal is one of the behaviours under test, and a test that has to
    /// catch an exception to observe it cannot tell it apart from a fault.
    /// </remarks>
    private static int XCrypt(byte[] key, byte[] nonce, uint blockCounter, byte[] input, byte[] output, int length, bool serial)
    {
        if (key.Length != KeyBytes || nonce.Length != RawNonceBytes
            || length < 0 || input.Length < length || output.Length < length)
        {
            throw new ArgumentException(
                $"ChaCha20 requires a {KeyBytes}-byte key, a {RawNonceBytes}-byte nonce, and sufficiently large buffers.");
        }

        EnsureRawKeystreamLoaded();
        fixed (byte* keyPointer = key)
        fixed (byte* noncePointer = nonce)
        fixed (byte* inputPointer = input)
        fixed (byte* outputPointer = output)
        {
            return serial
                ? _xcryptSerial(keyPointer, noncePointer, blockCounter, inputPointer, outputPointer, (nuint)length)
                : _xcrypt(keyPointer, noncePointer, blockCounter, inputPointer, outputPointer, (nuint)length);
        }
    }

    private static void Validate(byte[] key, byte[] nonce, byte[] tag, byte[] input, byte[] output, int length)
    {
        if (key.Length != KeyBytes || nonce.Length != NonceBytes || tag.Length != TagBytes
            || length < 0 || length > MaximumPayloadBytes || input.Length < length || output.Length < length)
        {
            throw new ArgumentException(
                $"XChaCha20-Poly1305 requires a {KeyBytes}-byte key, a {NonceBytes}-byte nonce, "
                + $"a {TagBytes}-byte tag, and sufficiently large buffers.");
        }
    }

    private static void ValidateAuthentication(
        byte[] key,
        byte[] nonce,
        byte[] tag,
        byte[] ciphertext,
        int length)
    {
        if (key.Length != KeyBytes || nonce.Length != NonceBytes || tag.Length != TagBytes
            || length < 0 || length > MaximumPayloadBytes || ciphertext.Length < length)
        {
            throw new ArgumentException(
                $"XChaCha20-Poly1305 requires a {KeyBytes}-byte key, a {NonceBytes}-byte nonce, "
                + $"a {TagBytes}-byte tag, and a sufficiently large ciphertext buffer.");
        }
    }

    private static void ThrowOnError(int result)
    {
        if (result == 0)
        {
            return;
        }

        throw new CryptographicException(result switch
        {
            1 => "XChaCha20-Poly1305 reference library received invalid buffers.",
            // The AEAD now produces its keystream through the same worker-split
            // path as the block ciphers, so it can report what that path
            // reports. Before it was one Crypto++ call that could only fail
            // internally, and these two codes were unreachable.
            3 => "XChaCha20-Poly1305 reference library could not start its keystream workers.",
            4 => "ChaCha20 block counter is exhausted; the request is larger than one nonce may cover.",
            5 => "XChaCha20-Poly1305 reference library failed internally.",
            _ => $"XChaCha20-Poly1305 reference library returned error {result}.",
        });
    }

    /// <summary>
    /// Resolves the raw keystream exports, which only the tests call.
    /// </summary>
    /// <remarks>
    /// Kept out of <see cref="EnsureLoaded"/> because these v12-only symbols
    /// are differential-test instrumentation rather than production entry
    /// points. Their absence fails the relevant test immediately.
    /// </remarks>
    private static void EnsureRawKeystreamLoaded()
    {
        EnsureLoaded();
        lock (LoadGate)
        {
            if (_xcrypt == null)
            {
                _xcrypt = (delegate* unmanaged[Cdecl]<byte*, byte*, uint, byte*, byte*, nuint, int>)
                    NativeLibrary.GetExport(_libraryHandle, "keepvault_test_chacha20_xcrypt");
            }

            if (_xcryptSerial == null)
            {
                _xcryptSerial = (delegate* unmanaged[Cdecl]<byte*, byte*, uint, byte*, byte*, nuint, int>)
                    NativeLibrary.GetExport(_libraryHandle, "keepvault_test_chacha20_xcrypt_serial");
            }
        }
    }

    private static void EnsureAeadTestExportsLoaded()
    {
        EnsureLoaded();
        lock (LoadGate)
        {
            if (_encryptWithWorkers == null)
            {
                _encryptWithWorkers = (delegate* unmanaged[Cdecl]<byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, uint, int>)
                    NativeLibrary.GetExport(_libraryHandle, "keepvault_test_xchacha20poly1305_v13_encrypt_with_workers");
            }
            if (_decryptWithWorkers == null)
            {
                _decryptWithWorkers = (delegate* unmanaged[Cdecl]<byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, uint, int>)
                    NativeLibrary.GetExport(_libraryHandle, "keepvault_test_xchacha20poly1305_v13_decrypt_with_workers");
            }
            if (_encryptSerial == null)
            {
                _encryptSerial = (delegate* unmanaged[Cdecl]<byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, int>)
                    NativeLibrary.GetExport(_libraryHandle, "keepvault_test_xchacha20poly1305_v13_encrypt_serial");
            }
            if (_decryptSerial == null)
            {
                _decryptSerial = (delegate* unmanaged[Cdecl]<byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, int>)
                    NativeLibrary.GetExport(_libraryHandle, "keepvault_test_xchacha20poly1305_v13_decrypt_serial");
            }
            if (_authWithWorkers == null)
            {
                _authWithWorkers = (delegate* unmanaged[Cdecl]<byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, uint, int>)
                    NativeLibrary.GetExport(_libraryHandle, "keepvault_test_xchacha20poly1305_v13_auth_with_workers");
            }
            if (_authSerial == null)
            {
                _authSerial = (delegate* unmanaged[Cdecl]<byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, int>)
                    NativeLibrary.GetExport(_libraryHandle, "keepvault_test_xchacha20poly1305_v13_auth_serial");
            }
        }
    }

    private static void EnsureMacSnapshotExportsLoaded(bool includeTestExport)
    {
        if (!OperatingSystem.IsMacOS())
        {
            throw new PlatformNotSupportedException(
                "Anonymous POSIX-SHM snapshots are available only on macOS.");
        }

        EnsureLoaded();
        lock (LoadGate)
        {
            if (_createMacSnapshot == null)
            {
                _createMacSnapshot = (delegate* unmanaged[Cdecl]<int, ulong, int*, ulong*, ulong*, int*, int>)
                    NativeLibrary.GetExport(_libraryHandle, "keepvault_macos_snapshot_create_v1");
            }
            if (_releaseMacSnapshot == null)
            {
                _releaseMacSnapshot = (delegate* unmanaged[Cdecl]<ulong, ulong, int*, int>)
                    NativeLibrary.GetExport(_libraryHandle, "keepvault_macos_snapshot_release_v1");
            }

            if (includeTestExport && _createMacSnapshotForTests == null)
            {
                _createMacSnapshotForTests = (delegate* unmanaged[Cdecl]<
                    int,
                    ulong,
                    uint,
                    delegate* unmanaged[Cdecl]<nint, void>,
                    nint,
                    int*,
                    ulong*,
                    ulong*,
                    int*,
                    int>)NativeLibrary.GetExport(
                        _libraryHandle,
                        "keepvault_macos_snapshot_create_test_v1");
            }
        }
    }

    private static void EnsureLoaded()
    {
        lock (LoadGate)
        {
            if (_libraryHandle != 0)
            {
                return;
            }

            nint handle = NativeToolIntegrity.LoadTrustedLibrary(DllName);
            try
            {
                NativeCipherExecutor.Install(handle);
                _encrypt = (delegate* unmanaged[Cdecl]<byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, uint, int>)
                    NativeLibrary.GetExport(handle, "keepvault_xchacha20poly1305_v13_encrypt_with_budget");
                _decrypt = (delegate* unmanaged[Cdecl]<byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, byte*, nuint, uint, int>)
                    NativeLibrary.GetExport(handle, "keepvault_xchacha20poly1305_v13_decrypt_with_budget");
                _libraryHandle = handle;
            }
            catch
            {
                NativeLibrary.Free(handle);
                _encrypt = null;
                _decrypt = null;
                _encryptWithWorkers = null;
                _decryptWithWorkers = null;
                _encryptSerial = null;
                _decryptSerial = null;
                _authWithWorkers = null;
                _authSerial = null;
                _createMacSnapshot = null;
                _createMacSnapshotForTests = null;
                _releaseMacSnapshot = null;
                throw;
            }
        }
    }
}
