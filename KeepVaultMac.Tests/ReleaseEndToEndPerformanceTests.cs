using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using KalynaArchiver.Services;

/// <summary>
/// Manual, full-cost release measurements requested for v12. These are kept
/// outside the automatic suite because every invocation performs the real
/// Paranoia Argon2id profile and processes hundreds of MiB at ZPAQ level 5.
/// </summary>
internal static class ReleaseEndToEndPerformanceTests
{
    private const int CompressionLevel = 5;
    private const long ExactBenchmarkBytes = 256L * 1024 * 1024;
    private const int IoBufferBytes = 1024 * 1024;
    private const string UserPassword = "N!r7$Vq2#Lm8%Tx3&Jd9*Wp4+Kg5=Zu6?Ce";
    private const string UserPin = "428317";
    private static readonly byte[] TextPattern = Encoding.UTF8.GetBytes(
        "Keep Vault v12 Parallelisierung: Kompression, Verschluesselung, "
        + "Authentifizierung und Fehlerkorrektur. Grüße aus Dortmund.\n");

    internal static Task RunExact256MiBAsync() =>
        RunWorkflowAsync(
            "paranoia-256mib-level5",
            CreateExact256MiBFixtureAsync,
            damageAndRepair: false);

    internal static Task RunComplexTreeAsync() =>
        RunWorkflowAsync(
            "paranoia-complex-tree-level5-repair",
            CreateComplexTreeFixtureAsync,
            damageAndRepair: true);

    private static async Task RunWorkflowAsync(
        string label,
        Func<string, Task> createFixture,
        bool damageAndRepair)
    {
        Require(
            EncryptionSuiteCatalog.Get(EncryptionSuite.ParanoiaCascade).UsesTwoKdfRounds,
            "The release E2E fixture no longer selects the two-round Paranoia suite.");
        Require(
            NativeArgon2id.IsAvailable(),
            "The signed production Argon2id adapter is unavailable for the release E2E measurement.");

        string root = MacSafeFileSystem.ResolveExistingRealPath(
            Directory.CreateTempSubdirectory("keep-vault-release-e2e-").FullName);
        File.SetUnixFileMode(
            root,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        string sourceRoot = Path.Combine(root, "fixture-root");
        string encryptedPath = Path.Combine(root, "fixture.kzpaq");
        string extractedRoot = Path.Combine(root, "extracted");
        string? repairedPath = null;
        Exception? operationFailure = null;

        try
        {
            Stopwatch setupTimer = Stopwatch.StartNew();
            await createFixture(sourceRoot).ConfigureAwait(false);
            TreeManifest expected = await BuildManifestAsync(sourceRoot).ConfigureAwait(false);
            setupTimer.Stop();
            Require(expected.TotalBytes > 0, "The release E2E fixture contains no payload bytes.");
            if (!damageAndRepair)
            {
                Require(
                    expected.TotalBytes == ExactBenchmarkBytes,
                    $"The exact performance fixture is {expected.TotalBytes} bytes instead of 256 MiB.");
            }

            AddMouseSamplesUntilReady();
            using GeneratedArchiveEntropy entropy = EntropyMixer.CreateArchiveEntropy();
            string factorA = entropy.FirstPassword;
            string factorB = entropy.SecondPassword;
            var zpaq = new ZpaqService();
            var containers = new KalynaContainerService();
            var recovery = new RecoveryService();

            Stopwatch totalTimer = Stopwatch.StartNew();
            Stopwatch phaseTimer = Stopwatch.StartNew();
            ProcessResult creation = await zpaq.AddStreamingAsync(
                [sourceRoot],
                CompressionLevel,
                (zpaqStream, cancellationToken) =>
                    containers.EncryptZpaqStreamWithPreparedEntropyAsync(
                        zpaqStream,
                        encryptedPath,
                        UserPassword,
                        UserPin,
                        factorA,
                        factorB,
                        EncryptionSuite.ParanoiaCascade,
                        entropy,
                        "v12 release E2E",
                        null,
                        cancellationToken),
                null,
                CancellationToken.None).ConfigureAwait(false);
            phaseTimer.Stop();
            Require(
                creation.Succeeded && File.Exists(encryptedPath),
                $"Level-5 archive and Paranoia encryption failed: {creation.StandardError}");
            double archiveEncryptSeconds = phaseTimer.Elapsed.TotalSeconds;
            long encryptedBytes = new FileInfo(encryptedPath).Length;
            Console.WriteLine(
                $"    {label}: archive+encrypt {archiveEncryptSeconds:F3} s, "
                + $"{Rate(expected.TotalBytes, archiveEncryptSeconds):F2} MiB/s");

            phaseTimer.Restart();
            string sidecarPath = await recovery.CreateAuthenticatedAsync(
                encryptedPath,
                UserPassword,
                UserPin,
                factorA,
                factorB,
                null,
                CancellationToken.None).ConfigureAwait(false);
            phaseTimer.Stop();
            Require(File.Exists(sidecarPath), "The authenticated KPAR2 v4 sidecar was not created.");
            double recoveryCreateSeconds = phaseTimer.Elapsed.TotalSeconds;
            long recoveryBytes = new FileInfo(sidecarPath).Length;
            Console.WriteLine(
                $"    {label}: KPAR2 create {recoveryCreateSeconds:F3} s, "
                + $"{Rate(encryptedBytes, recoveryCreateSeconds):F2} MiB/s");

            phaseTimer.Restart();
            RecoveryRepairResult healthy = await recovery.VerifyAndRepairAuthenticatedAsync(
                encryptedPath,
                UserPassword,
                UserPin,
                factorA,
                factorB,
                null,
                CancellationToken.None).ConfigureAwait(false);
            phaseTimer.Stop();
            Require(
                healthy.RecoveryAvailable && healthy.ArchiveHealthy && healthy.Authenticated
                    && !healthy.Repaired,
                "The freshly created authenticated KPAR2 v4 sidecar did not verify the archive as healthy.");
            double recoveryVerifySeconds = phaseTimer.Elapsed.TotalSeconds;
            Console.WriteLine(
                $"    {label}: KPAR2 verify {recoveryVerifySeconds:F3} s, "
                + $"{Rate(encryptedBytes, recoveryVerifySeconds):F2} MiB/s");

            double? recoveryRepairSeconds = null;
            int repairedShards = 0;
            string effectiveContainer = encryptedPath;
            if (damageAndRepair)
            {
                byte[] originalContainerHash = await HashFileAsync(encryptedPath).ConfigureAwait(false);
                try
                {
                    await DamageOneRecoveryRegionAsync(encryptedPath).ConfigureAwait(false);
                    byte[] damagedHash = await HashFileAsync(encryptedPath).ConfigureAwait(false);
                    try
                    {
                        Require(
                            !CryptographicOperations.FixedTimeEquals(originalContainerHash, damagedHash),
                            "The KPAR2 E2E damage step did not change the encrypted container.");
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(damagedHash);
                    }

                    phaseTimer.Restart();
                    RecoveryRepairResult repaired = await recovery.VerifyAndRepairAuthenticatedAsync(
                        encryptedPath,
                        UserPassword,
                        UserPin,
                        factorA,
                        factorB,
                        null,
                        CancellationToken.None).ConfigureAwait(false);
                    phaseTimer.Stop();
                    recoveryRepairSeconds = phaseTimer.Elapsed.TotalSeconds;
                    Require(
                        repaired.RecoveryAvailable && !repaired.ArchiveHealthy && repaired.Repaired
                            && repaired.Authenticated && repaired.RepairedShards > 0
                            && !string.IsNullOrEmpty(repaired.OutputPath),
                        "Authenticated KPAR2 did not repair the deliberately damaged Paranoia container.");
                    repairedPath = repaired.OutputPath;
                    effectiveContainer = repairedPath!;
                    repairedShards = repaired.RepairedShards;
                    byte[] repairedHash = await HashFileAsync(effectiveContainer).ConfigureAwait(false);
                    try
                    {
                        Require(
                            CryptographicOperations.FixedTimeEquals(originalContainerHash, repairedHash),
                            "KPAR2 repair did not reproduce the exact original encrypted container.");
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(repairedHash);
                    }
                    Console.WriteLine(
                        $"    {label}: KPAR2 repair {recoveryRepairSeconds.Value:F3} s, "
                        + $"{Rate(encryptedBytes, recoveryRepairSeconds.Value):F2} MiB/s, "
                        + $"repaired shards {repairedShards}");
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(originalContainerHash);
                }
            }

            phaseTimer.Restart();
            ProcessResult extraction = await zpaq.ExtractStreamingAsync(
                (zpaqDestination, cancellationToken) => containers.DecryptToStreamAsync(
                    effectiveContainer,
                    UserPassword,
                    UserPin,
                    factorA,
                    factorB,
                    zpaqDestination,
                    null,
                    cancellationToken),
                extractedRoot,
                null,
                CancellationToken.None).ConfigureAwait(false);
            phaseTimer.Stop();
            Require(
                extraction.Succeeded,
                $"Paranoia decryption and level-5 extraction failed: {extraction.StandardError}");
            double decryptExtractSeconds = phaseTimer.Elapsed.TotalSeconds;
            Console.WriteLine(
                $"    {label}: decrypt+extract {decryptExtractSeconds:F3} s, "
                + $"{Rate(expected.TotalBytes, decryptExtractSeconds):F2} MiB/s");

            phaseTimer.Restart();
            string extractedFixture = Path.Combine(extractedRoot, Path.GetFileName(sourceRoot));
            TreeManifest actual = await BuildManifestAsync(extractedFixture).ConfigureAwait(false);
            RequireEquivalent(expected, actual);
            phaseTimer.Stop();
            double manifestVerifySeconds = phaseTimer.Elapsed.TotalSeconds;
            totalTimer.Stop();

            var result = new EndToEndResult(
                SchemaVersion: 1,
                Label: label,
                OperatingSystem: RuntimeInformation.OSDescription,
                Architecture: RuntimeInformation.ProcessArchitecture.ToString(),
                LogicalProcessors: Environment.ProcessorCount,
                CompressionLevel: CompressionLevel,
                Suite: EncryptionSuite.ParanoiaCascade.ToString(),
                Argon2Iterations: V12MasterKdf.Iterations,
                Argon2Parallelism: V12MasterKdf.Parallelism,
                InputFiles: expected.Files.Count,
                InputDirectories: expected.Directories.Count,
                InputBytes: expected.TotalBytes,
                ContainerBytes: encryptedBytes,
                RecoveryBytes: recoveryBytes,
                SetupAndInitialManifestSeconds: setupTimer.Elapsed.TotalSeconds,
                ArchiveEncryptSeconds: archiveEncryptSeconds,
                RecoveryCreateSeconds: recoveryCreateSeconds,
                RecoveryVerifySeconds: recoveryVerifySeconds,
                RecoveryRepairSeconds: recoveryRepairSeconds,
                RepairedShards: repairedShards,
                DecryptExtractSeconds: decryptExtractSeconds,
                FinalManifestSeconds: manifestVerifySeconds,
                WorkflowSeconds: totalTimer.Elapsed.TotalSeconds);
            Console.WriteLine("    E2E_RESULT_JSON=" + JsonSerializer.Serialize(result));
        }
        catch (Exception ex)
        {
            operationFailure = ex;
            throw;
        }
        finally
        {
            try
            {
                if (Directory.Exists(root))
                {
                    Directory.Delete(root, recursive: true);
                }
            }
            catch (Exception cleanupError)
            {
                if (operationFailure is null)
                {
                    throw;
                }

                throw new IOException(
                    "The release E2E operation failed and its private fixture could not be removed.",
                    new AggregateException(operationFailure, cleanupError));
            }
        }
    }

    private static async Task CreateExact256MiBFixtureAsync(string root)
    {
        Directory.CreateDirectory(root);
        await WritePatternFileAsync(
            Path.Combine(root, "256 MiB Mischung.bin"),
            ExactBenchmarkBytes,
            DataPattern.Mixed,
            0x4B56543132504552UL).ConfigureAwait(false);
        Directory.CreateDirectory(Path.Combine(root, "leeres Verzeichnis"));
    }

    private static async Task CreateComplexTreeFixtureAsync(string root)
    {
        string deep = root;
        for (int level = 1; level <= 12; level++)
        {
            deep = Path.Combine(deep, $"Ebene {level:00}");
        }

        string unicode = Path.Combine(root, "Unicode", "Grüße_日本_🙂");
        string boundaries = Path.Combine(root, "Grenzgrößen");
        string large = Path.Combine(root, "große Dateien");
        Directory.CreateDirectory(deep);
        Directory.CreateDirectory(unicode);
        Directory.CreateDirectory(boundaries);
        Directory.CreateDirectory(large);
        Directory.CreateDirectory(Path.Combine(root, "leer", "noch leer", "wirklich leer"));
        Directory.CreateDirectory(Path.Combine(root, ".verborgenes Verzeichnis"));

        (string RelativePath, long Bytes, DataPattern Pattern, ulong Seed)[] files =
        [
            ("leer.bin", 0, DataPattern.Zero, 1),
            ("ein Byte.bin", 1, DataPattern.Counter, 2),
            (Path.Combine("Grenzgrößen", "15.bin"), 15, DataPattern.Counter, 3),
            (Path.Combine("Grenzgrößen", "16.bin"), 16, DataPattern.Counter, 4),
            (Path.Combine("Grenzgrößen", "17.bin"), 17, DataPattern.Counter, 5),
            (Path.Combine("Grenzgrößen", "4095.bin"), 4095, DataPattern.PseudoRandom, 6),
            (Path.Combine("Grenzgrößen", "4096.bin"), 4096, DataPattern.PseudoRandom, 7),
            (Path.Combine("Grenzgrößen", "4097.bin"), 4097, DataPattern.PseudoRandom, 8),
            (Path.Combine("Grenzgrößen", "1 MiB minus 1.bin"), (1L << 20) - 1, DataPattern.Mixed, 9),
            (Path.Combine("Grenzgrößen", "1 MiB.bin"), 1L << 20, DataPattern.Mixed, 10),
            (Path.Combine("Grenzgrößen", "1 MiB plus 1.bin"), (1L << 20) + 1, DataPattern.Mixed, 11),
            (Path.Combine("große Dateien", "16 MiB minus 1.bin"), (16L << 20) - 1, DataPattern.Text, 12),
            (Path.Combine("große Dateien", "16 MiB.bin"), 16L << 20, DataPattern.Zero, 13),
            (Path.Combine("große Dateien", "16 MiB plus 1.bin"), (16L << 20) + 1, DataPattern.Mixed, 14),
            (Path.Combine("große Dateien", "64 MiB plus 123 zufällig.bin"), (64L << 20) + 123, DataPattern.PseudoRandom, 15),
            (Path.Combine("Unicode", "Grüße_日本_🙂", "96 MiB gut komprimierbar.txt"), 96L << 20, DataPattern.Text, 16),
            (Path.GetRelativePath(root, Path.Combine(deep, "tief verschachtelt.dat")), 65537, DataPattern.Counter, 17),
            (Path.Combine(".verborgenes Verzeichnis", ".verborgene Datei"), 257, DataPattern.PseudoRandom, 18),
        ];

        foreach ((string relativePath, long bytes, DataPattern pattern, ulong seed) in files)
        {
            await WritePatternFileAsync(
                Path.Combine(root, relativePath),
                bytes,
                pattern,
                seed).ConfigureAwait(false);
        }
    }

    private static async Task WritePatternFileAsync(
        string path,
        long length,
        DataPattern pattern,
        ulong seed)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        byte[] buffer = new byte[IoBufferBytes];
        ulong state = seed == 0 ? 0x9E3779B97F4A7C15UL : seed;
        long written = 0;
        try
        {
            await using var output = new FileStream(
                path,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                IoBufferBytes,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            while (written < length)
            {
                int count = (int)Math.Min(buffer.Length, length - written);
                Fill(buffer.AsSpan(0, count), pattern, written, ref state);
                await output.WriteAsync(buffer.AsMemory(0, count)).ConfigureAwait(false);
                written += count;
            }
            await output.FlushAsync().ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }

        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    private static void Fill(Span<byte> destination, DataPattern pattern, long offset, ref ulong state)
    {
        if (pattern == DataPattern.Mixed)
        {
            pattern = ((offset / (16L << 20)) % 4) switch
            {
                0 => DataPattern.Zero,
                1 => DataPattern.Text,
                2 => DataPattern.PseudoRandom,
                _ => DataPattern.Counter,
            };
        }

        switch (pattern)
        {
            case DataPattern.Zero:
                destination.Clear();
                return;
            case DataPattern.Text:
                for (int index = 0; index < destination.Length; index++)
                {
                    destination[index] = TextPattern[(int)((offset + index) % TextPattern.Length)];
                }
                return;
            case DataPattern.Counter:
                for (int index = 0; index < destination.Length; index++)
                {
                    destination[index] = (byte)(((offset + index) * 131 + (long)state) & 255);
                }
                return;
            case DataPattern.PseudoRandom:
                int cursor = 0;
                while (cursor + sizeof(ulong) <= destination.Length)
                {
                    state += 0x9E3779B97F4A7C15UL;
                    ulong value = state;
                    value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9UL;
                    value = (value ^ (value >> 27)) * 0x94D049BB133111EBUL;
                    value ^= value >> 31;
                    BinaryPrimitives.WriteUInt64LittleEndian(destination[cursor..], value);
                    cursor += sizeof(ulong);
                }
                if (cursor < destination.Length)
                {
                    state += 0x9E3779B97F4A7C15UL;
                    ulong tail = state;
                    for (; cursor < destination.Length; cursor++, tail >>= 8)
                    {
                        destination[cursor] = (byte)tail;
                    }
                }
                return;
            default:
                throw new ArgumentOutOfRangeException(nameof(pattern));
        }
    }

    private static async Task DamageOneRecoveryRegionAsync(string path)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.ReadWrite,
            FileShare.None,
            4096,
            FileOptions.Asynchronous | FileOptions.RandomAccess);
        Require(stream.Length > 8192, "The encrypted fixture is too short for the KPAR2 damage test.");
        long offset = Math.Max(4096, stream.Length / 2);
        offset = Math.Min(offset, stream.Length - 1);
        stream.Position = offset;
        int original = stream.ReadByte();
        Require(original >= 0, "The KPAR2 damage position is outside the encrypted container.");
        stream.Position = offset;
        stream.WriteByte((byte)(original ^ 0xA5));
        stream.Flush(flushToDisk: true);
    }

    private static async Task<TreeManifest> BuildManifestAsync(string root)
    {
        Require(Directory.Exists(root), $"Manifest root does not exist: {Path.GetFileName(root)}");
        string[] directories = Directory
            .EnumerateDirectories(root, "*", SearchOption.AllDirectories)
            .Select(path => Normalize(Path.GetRelativePath(root, path)))
            .Order(StringComparer.Ordinal)
            .ToArray();
        var files = new List<FileManifest>();
        long totalBytes = 0;
        foreach (string path in Directory
                     .EnumerateFiles(root, "*", SearchOption.AllDirectories)
                     .Order(StringComparer.Ordinal))
        {
            var info = new FileInfo(path);
            byte[] hash = await HashFileAsync(path).ConfigureAwait(false);
            try
            {
                files.Add(new FileManifest(
                    Normalize(Path.GetRelativePath(root, path)),
                    info.Length,
                    Convert.ToHexString(hash)));
                totalBytes = checked(totalBytes + info.Length);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(hash);
            }
        }

        return new TreeManifest(directories, files, totalBytes);
    }

    private static async Task<byte[]> HashFileAsync(string path)
    {
        await using var input = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            IoBufferBytes,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        return await SHA256.HashDataAsync(input).ConfigureAwait(false);
    }

    private static void RequireEquivalent(TreeManifest expected, TreeManifest actual)
    {
        Require(
            expected.TotalBytes == actual.TotalBytes,
            $"Extracted byte count differs: {actual.TotalBytes} instead of {expected.TotalBytes}.");
        Require(
            expected.Directories.SequenceEqual(actual.Directories, StringComparer.Ordinal),
            "The extracted directory topology differs from the complex source tree.");
        Require(
            expected.Files.SequenceEqual(actual.Files),
            "The extracted path, size or SHA-256 manifest differs from the source tree.");
    }

    private static void AddMouseSamplesUntilReady()
    {
        int index = 0;
        while (Enum.GetValues<EntropyPurpose>().Any(purpose => !EntropyMixer.HasRequiredSamples(purpose)))
        {
            EntropyMixer.AddMouseSample(
                319.125 + (index * 0.003),
                811.875 + (index * 0.007),
                Environment.TickCount ^ index,
                (index & 1) != 0,
                (index & 2) != 0,
                (index & 4) != 0);
            index++;
        }
    }

    private static string Normalize(string relativePath) => relativePath.Replace('\\', '/');

    private static double Rate(long bytes, double seconds) =>
        seconds <= 0 ? 0 : bytes / (1024d * 1024d) / seconds;

    private static void Require(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private enum DataPattern
    {
        Zero,
        Text,
        Counter,
        PseudoRandom,
        Mixed,
    }

    private sealed record FileManifest(string RelativePath, long Length, string Sha256);

    private sealed record TreeManifest(
        IReadOnlyList<string> Directories,
        IReadOnlyList<FileManifest> Files,
        long TotalBytes);

    private sealed record EndToEndResult(
        int SchemaVersion,
        string Label,
        string OperatingSystem,
        string Architecture,
        int LogicalProcessors,
        int CompressionLevel,
        string Suite,
        uint Argon2Iterations,
        uint Argon2Parallelism,
        int InputFiles,
        int InputDirectories,
        long InputBytes,
        long ContainerBytes,
        long RecoveryBytes,
        double SetupAndInitialManifestSeconds,
        double ArchiveEncryptSeconds,
        double RecoveryCreateSeconds,
        double RecoveryVerifySeconds,
        double? RecoveryRepairSeconds,
        int RepairedShards,
        double DecryptExtractSeconds,
        double FinalManifestSeconds,
        double WorkflowSeconds);
}
