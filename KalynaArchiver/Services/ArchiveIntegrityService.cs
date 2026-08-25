using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace KalynaArchiver.Services;

/// <summary>
/// Manages unkeyed dual integrity manifests (.sha3 and .skein) for plain ZPAQ archives.
/// </summary>
/// <remarks>
/// IMPORTANT SECURITY NOTICE:
/// The companion .sha3 (SHA3-512) and .skein (Skein-1024) manifest files provide unkeyed cryptographic
/// checksums designed to detect storage degradation, transmission corruption, and accidental bit rot.
/// Because they are unkeyed hashes without digital signatures or secret-key MACs, they do NOT provide
/// cryptographic origin authenticity or anti-tamper security against an active adversary who has write access
/// to overwrite both the archive and its companion manifest files.
/// Full cryptographic tamper rejection and origin authenticity is provided exclusively by authenticated
/// encrypted containers (.kzpaq) or digital hybrid signatures (.khsig).
/// </remarks>
public sealed class ArchiveIntegrityService
{
    private const int MaxManifestBytes = 4096;
    public static string GetSha3ManifestPath(string archivePath) => $"{archivePath}.sha3";

    public static string GetSkeinManifestPath(string archivePath) => $"{archivePath}.skein";

    public async Task CreateAsync(string archivePath, CancellationToken cancellationToken)
    {
        string fullPath = Path.GetFullPath(archivePath);
        byte[] sha3;
        byte[] skein;
        await using (FileStream stream =
#if KEEPVAULT_MACOS
            MacSafeFileSystem.OpenReadNoSymlinks(fullPath))
#else
            SecureFile.OpenReadNoReparse(
                fullPath,
                FileShare.Read,
                bufferSize: 1024 * 1024,
                requireSingleLink: true))
#endif
        {
            fullPath = ResolveCanonicalArchivePath(stream, fullPath);
            (sha3, skein) = await IntegrityService.HashStreamAsync(stream, cancellationToken).ConfigureAwait(false);
        }

        try
        {
            await WriteManifestAsync(GetSha3ManifestPath(fullPath), Convert.ToHexString(sha3), cancellationToken).ConfigureAwait(false);
            await WriteManifestAsync(GetSkeinManifestPath(fullPath), Convert.ToHexString(skein), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sha3);
            CryptographicOperations.ZeroMemory(skein);
        }
    }

    public async Task VerifyAsync(string archivePath, CancellationToken cancellationToken)
    {
        using ArchiveIntegrityLease lease = await AcquireVerifiedAsync(archivePath, cancellationToken).ConfigureAwait(false);
    }

    internal async Task<(BoundFileTransaction Sha3, BoundFileTransaction Skein)> CreateBoundFromVerifiedDigestsAsync(
        string archivePath,
        string sha3Hex,
        string skeinHex,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(archivePath);
        byte[] sha3 = ParseManifest(sha3Hex, 64, "SHA3-512");
        byte[] skein = ParseManifest(skeinHex, 128, "Skein-1024");
        BoundFileTransaction? sha3Manifest = null;
        BoundFileTransaction? skeinManifest = null;
        try
        {
            string fullPath = Path.GetFullPath(archivePath);
            sha3Manifest = await CreateBoundManifestAsync(
                GetSha3ManifestPath(fullPath),
                sha3,
                cancellationToken).ConfigureAwait(false);
            skeinManifest = await CreateBoundManifestAsync(
                GetSkeinManifestPath(fullPath),
                skein,
                cancellationToken).ConfigureAwait(false);
            return (sha3Manifest, skeinManifest);
        }
        catch (Exception operationError)
        {
            var cleanupErrors = new List<Exception>();
            DeleteBoundManifestOrCollect(skeinManifest, cleanupErrors);
            DeleteBoundManifestOrCollect(sha3Manifest, cleanupErrors);
            if (cleanupErrors.Count > 0)
            {
                throw new AggregateException(
                    "Creating recovery-candidate manifests failed and exact-object cleanup also failed.",
                    [operationError, .. cleanupErrors]);
            }

            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sha3);
            CryptographicOperations.ZeroMemory(skein);
        }
    }

    private static void DeleteBoundManifestOrCollect(
        BoundFileTransaction? manifest,
        List<Exception> errors)
    {
        if (manifest is null)
        {
            return;
        }

        try
        {
            manifest.DeleteBound();
        }
        catch (Exception cleanupError)
        {
            errors.Add(cleanupError);
        }
        finally
        {
            manifest.Dispose();
        }
    }

    internal async Task<ArchiveIntegrityLease> AcquireVerifiedAsync(
        string archivePath,
        CancellationToken cancellationToken)
    {
        string fullPath = Path.GetFullPath(archivePath);
        string sha3Path = GetSha3ManifestPath(fullPath);
        string skeinPath = GetSkeinManifestPath(fullPath);
        if (!File.Exists(sha3Path) || !File.Exists(skeinPath))
        {
            throw new InvalidDataException("Plain ZPAQ archive requires both SHA3-512 and Skein-1024 manifests.");
        }

        byte[] expectedSha3 = ParseManifest(await ReadManifestAsync(sha3Path, cancellationToken).ConfigureAwait(false), 64, "SHA3-512");
        byte[] expectedSkein = ParseManifest(await ReadManifestAsync(skeinPath, cancellationToken).ConfigureAwait(false), 128, "Skein-1024");
        byte[] actualSha3 = [];
        byte[] actualSkein = [];
#if KEEPVAULT_MACOS
        MacPrivateFileSnapshot? snapshot = await MacPrivateFileSnapshot
            .CaptureAsync(fullPath, cancellationToken)
            .ConfigureAwait(false);
        FileStream? stream = snapshot.Stream;
#else
        FileStream? stream = SecureFile.OpenReadNoReparse(
            fullPath,
            FileShare.Read,
            bufferSize: 1024 * 1024,
            requireSingleLink: true);
#endif
        try
        {
#if KEEPVAULT_MACOS
            string resolvedPath = snapshot.SnapshotPath;
#else
            string resolvedPath = ResolveCanonicalArchivePath(stream, fullPath);
#endif
            (actualSha3, actualSkein) = await IntegrityService.HashStreamAsync(stream, cancellationToken).ConfigureAwait(false);
            bool sha3Matches = CryptographicOperations.FixedTimeEquals(expectedSha3, actualSha3);
            bool skeinMatches = CryptographicOperations.FixedTimeEquals(expectedSkein, actualSkein);
            if (!(sha3Matches & skeinMatches))
            {
                throw new InvalidDataException("Plain ZPAQ archive failed its SHA3-512/Skein-1024 dual-integrity check.");
            }

            var lease = new ArchiveIntegrityLease(
                resolvedPath,
                stream,
#if KEEPVAULT_MACOS
                snapshot
#else
                owner: null
#endif
            );
            stream = null;
#if KEEPVAULT_MACOS
            snapshot = null;
#endif
            return lease;
        }
        finally
        {
#if KEEPVAULT_MACOS
            if (snapshot is not null)
            {
                snapshot.Dispose();
                stream = null;
            }
#endif
            if (stream is not null)
            {
                await stream.DisposeAsync().ConfigureAwait(false);
            }

            CryptographicOperations.ZeroMemory(expectedSha3);
            CryptographicOperations.ZeroMemory(expectedSkein);
            CryptographicOperations.ZeroMemory(actualSha3);
            CryptographicOperations.ZeroMemory(actualSkein);
        }
    }

    /// <summary>
    /// Verifies the exact three objects held by an object-bound plain-archive
    /// commit before any of their names are installed.
    /// </summary>
    internal static async Task VerifyBoundAsync(
        FileStream archive,
        FileStream sha3Manifest,
        FileStream skeinManifest,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(archive);
        ArgumentNullException.ThrowIfNull(sha3Manifest);
        ArgumentNullException.ThrowIfNull(skeinManifest);

        byte[] expectedSha3 = [];
        byte[] expectedSkein = [];
        byte[] actualSha3 = [];
        byte[] actualSkein = [];
        try
        {
            expectedSha3 = ParseManifest(
                await ReadManifestStreamAsync(sha3Manifest, "SHA3-512", cancellationToken).ConfigureAwait(false),
                64,
                "SHA3-512");
            expectedSkein = ParseManifest(
                await ReadManifestStreamAsync(skeinManifest, "Skein-1024", cancellationToken).ConfigureAwait(false),
                128,
                "Skein-1024");

            archive.Position = 0;
            (actualSha3, actualSkein) = await IntegrityService
                .HashStreamAsync(archive, cancellationToken)
                .ConfigureAwait(false);
            if (!(CryptographicOperations.FixedTimeEquals(expectedSha3, actualSha3)
                    & CryptographicOperations.FixedTimeEquals(expectedSkein, actualSkein)))
            {
                throw new InvalidDataException(
                    "The bound plain ZPAQ archive does not match its bound dual-integrity manifests.");
            }
        }
        finally
        {
            if (archive.CanSeek) archive.Position = 0;
            if (sha3Manifest.CanSeek) sha3Manifest.Position = 0;
            if (skeinManifest.CanSeek) skeinManifest.Position = 0;
            CryptographicOperations.ZeroMemory(expectedSha3);
            CryptographicOperations.ZeroMemory(expectedSkein);
            CryptographicOperations.ZeroMemory(actualSha3);
            CryptographicOperations.ZeroMemory(actualSkein);
        }
    }

    /// <summary>
    /// Creates and durably writes one manifest while retaining the exact file
    /// object for the caller's multi-file commit.
    /// </summary>
    internal static async Task<BoundFileTransaction> CreateBoundManifestAsync(
        string path,
        byte[] digest,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(digest);
        byte[] bytes = Encoding.ASCII.GetBytes(Convert.ToHexString(digest));
        BoundFileTransaction? manifest = null;
        try
        {
            manifest = BoundFileTransaction.CreateNew(
                path,
                bufferSize: 4096,
                FileOptions.WriteThrough);
            FileStream output = manifest.Stream;
            await output.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
#pragma warning disable CA1849 // Flush(true) requests durable media persistence before the multi-file commit.
            output.Flush(flushToDisk: true);
#if KEEPVAULT_MACOS
            MacSafeFileSystem.FullSync(output.SafeFileHandle);
#endif
#pragma warning restore CA1849
            return manifest;
        }
        catch (Exception operationError)
        {
            if (manifest is not null)
            {
                try
                {
                    manifest.DeleteBound();
                }
                catch (Exception cleanupError)
                {
                    manifest.Dispose();
                    throw new IOException(
                        "Writing a bound integrity manifest failed and its exact object could not be removed.",
                        new AggregateException(operationError, cleanupError));
                }

                manifest.Dispose();
            }

            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    public static void DeleteManifests(string archivePath)
    {
        File.Delete(GetSha3ManifestPath(archivePath));
        File.Delete(GetSkeinManifestPath(archivePath));
    }

    private static byte[] ParseManifest(string text, int expectedBytes, string algorithm)
    {
        string normalized = new(text.Where(c => !char.IsWhiteSpace(c)).ToArray());
        if (normalized.Length != expectedBytes * 2 || normalized.Any(c => !Uri.IsHexDigit(c)))
        {
            throw new InvalidDataException($"Invalid {algorithm} archive manifest.");
        }

        return Convert.FromHexString(normalized);
    }

    private static async Task<string> ReadManifestAsync(string path, CancellationToken cancellationToken)
    {
        await using FileStream stream =
#if KEEPVAULT_MACOS
            MacSafeFileSystem.OpenReadNoSymlinks(path);
#else
            SecureFile.OpenReadNoReparse(
                path,
                FileShare.Read,
                requireSingleLink: true);
#endif
        if (stream.Length is <= 0 or > MaxManifestBytes)
        {
            throw new InvalidDataException($"Archive integrity manifest has an invalid length: {Path.GetFileName(path)}");
        }

        byte[] bytes = new byte[checked((int)stream.Length)];
        try
        {
            await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
            return Encoding.ASCII.GetString(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static async Task<string> ReadManifestStreamAsync(
        FileStream stream,
        string algorithm,
        CancellationToken cancellationToken)
    {
        stream.Position = 0;
        if (stream.Length is <= 0 or > MaxManifestBytes)
        {
            throw new InvalidDataException($"Bound {algorithm} archive manifest has an invalid length.");
        }

        byte[] bytes = new byte[checked((int)stream.Length)];
        try
        {
            await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
            return Encoding.ASCII.GetString(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
            stream.Position = 0;
        }
    }

    private static async Task WriteManifestAsync(string path, string hex, CancellationToken cancellationToken)
    {
        string fullPath = Path.GetFullPath(path);
        string directory = Path.GetDirectoryName(fullPath) ?? Environment.CurrentDirectory;
        string temporaryPath = Path.Combine(directory, $".{Path.GetFileName(fullPath)}.{Guid.NewGuid():N}.integrity-part");
        byte[] bytes = Encoding.ASCII.GetBytes(hex);
        using BoundFileTransaction temporary = BoundFileTransaction.CreateNew(
            temporaryPath,
            bufferSize: 4096,
            FileOptions.WriteThrough);
        try
        {
            FileStream output = temporary.Stream;
            await output.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
#pragma warning disable CA1849 // Flush(true) is required to request durable media persistence before the atomic move.
            output.Flush(flushToDisk: true);
#if KEEPVAULT_MACOS
            MacSafeFileSystem.FullSync(output.SafeFileHandle);
#endif
#pragma warning restore CA1849
            temporary.RenameTo(fullPath, overwrite: true);
        }
        catch (Exception operationError)
        {
            try
            {
                temporary.DeleteBound();
            }
            catch (Exception cleanupError)
            {
                throw new IOException(
                    "Writing the integrity manifest failed and its exact temporary object could not be removed.",
                    new AggregateException(operationError, cleanupError));
            }

            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static string ResolveCanonicalArchivePath(FileStream stream, string expectedPath)
    {
        return NativePathResolver.RequireCanonicalFilePath(stream.SafeFileHandle, expectedPath, "Archive");
    }
}

internal sealed class ArchiveIntegrityLease : IDisposable
{
    private FileStream? _stream;
    private IDisposable? _owner;

    internal ArchiveIntegrityLease(string path, FileStream stream, IDisposable? owner = null)
    {
        Path = path;
        _stream = stream;
        _owner = owner;
    }

    public string Path { get; }

    public void Dispose()
    {
        IDisposable? owner = Interlocked.Exchange(ref _owner, null);
        if (owner is not null)
        {
            _stream = null;
            owner.Dispose();
        }
        else
        {
            Interlocked.Exchange(ref _stream, null)?.Dispose();
        }
    }
}
