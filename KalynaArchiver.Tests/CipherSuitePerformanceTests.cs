using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;
using KalynaArchiver.Services;

/// <summary>
/// Separate release performance gate for every production cipher suite.
/// Functional KATs and large differential tests remain authoritative for
/// ciphertext correctness; this gate detects a correct-but-slow fallback.
/// </summary>
internal static class CipherSuitePerformanceTests
{
    private const int MeasurementBytes = 256 * 1024 * 1024;
    private const int WarmupBytes = 16 * 1024 * 1024;
    private const int DifferentialBytes = 64 * 1024 * 1024;
    private const int MeasurementRuns = 3;
    private const double AllowedBaselineRegression = 0.25;
    private const string BaselineEnvironment = "KEEPVAULT_PERF_BASELINE";
    private const string ContainerPassword = "N!r7$Vq2#Lm8%Tx3&Jd9*Wp4+Kg5=Zu6?Ce";
    private const string ContainerPin = "428317";
    private static readonly string ContainerFactorA = CreateFactor(7, 3);
    private static readonly string ContainerFactorB = CreateFactor(13, 11);
    private static readonly EncryptionSuite[] ExpectedSuites =
    [
        EncryptionSuite.Kalyna512_512,
        EncryptionSuite.Threefish1024,
        EncryptionSuite.ThreefishOverKalyna,
        EncryptionSuite.ParanoiaCascade,
        EncryptionSuite.ChaChaOverAes,
        EncryptionSuite.Aes256,
        EncryptionSuite.Mars448,
        EncryptionSuite.Shacal2_512,
        EncryptionSuite.ChaCha20Poly1305,
        EncryptionSuite.MixedCascade,
    ];

    internal static void Run()
    {
        RequireReleaseConfiguration();
        ValidateSuiteInventory();
        PerformanceHostIdentity host = CaptureHostIdentity();
        ValidateHostIdentity(host, "current performance host");
        Console.WriteLine(
            $"    performance host: OS product {host.OperatingSystemVersion} "
            + $"(build {host.OperatingSystemBuild}); {host.OperatingSystem}; "
            + $"OS {host.OsArchitecture}; process {host.ProcessArchitecture}; "
            + $"{host.LogicalProcessors} logical CPU(s); {host.CpuDescriptor}");
        Console.WriteLine(
            $"    method: Release, {MeasurementBytes / (1024 * 1024)} MiB, "
            + $"{MeasurementRuns} measured runs after {WarmupBytes / (1024 * 1024)} MiB warm-up, median");
        VerifyAesRuntimeProvider();

        // Every cascade stage briefly locks its small key and counter. On
        // Windows, releasing the last such lock restores the process working
        // set. Without a standing reservation that trims/evicts these two
        // large benchmark buffers immediately before each timed call and
        // measures page faults rather than cipher throughput. macOS does not
        // adjust its working-set quota and must not reserve/lock 512 MiB here.
        using IDisposable? benchmarkWorkingSet = OperatingSystem.IsWindows()
            ? SecureMemory.ReserveWorkingSetCapacity(2L * MeasurementBytes)
            : null;

        byte[] input = CreateDeterministicBytes(MeasurementBytes, 0x4B56504552463131UL);
        byte[] output = new byte[MeasurementBytes];
        var rates = new Dictionary<string, double>(StringComparer.Ordinal);
        try
        {
            foreach (EncryptionSuite suite in ExpectedSuites)
            {
                EncryptionSuiteParameters parameters = EncryptionSuiteCatalog.Get(suite);
                byte[] key = CreateDeterministicBytes(
                    parameters.EncryptionKeyBytes,
                    0x1000UL + (ulong)suite);
                byte[] counter = CreateDeterministicBytes(
                    parameters.NonceBytes,
                    0x2000UL + (ulong)suite);
                byte[] tweak = KalynaContainerService.CreateSuiteTweak(parameters, counter);
                byte[] associatedData = CreateDeterministicBytes(64, 0x3000UL + (ulong)suite);
                byte[] tag = new byte[NativeChaChaPoly.TagBytes];
                try
                {
                    KalynaContainerService.EncryptSuiteChunkForTests(
                        parameters,
                        key,
                        tweak,
                        counter,
                        input,
                        output,
                        WarmupBytes,
                        associatedData,
                        tag);

                    byte[]? expectedDigest = null;
                    byte[]? expectedTag = null;
                    var samples = new double[MeasurementRuns];
                    try
                    {
                        for (int run = 0; run < samples.Length; run++)
                        {
                            Array.Clear(tag);
                            Stopwatch timer = Stopwatch.StartNew();
                            KalynaContainerService.EncryptSuiteChunkForTests(
                                parameters,
                                key,
                                tweak,
                                counter,
                                input,
                                output,
                                MeasurementBytes,
                                associatedData,
                                tag);
                            timer.Stop();
                            samples[run] = RateMiBPerSecond(MeasurementBytes, timer.Elapsed);

                            byte[] digest = SHA256.HashData(output);
                            if (expectedDigest is null)
                            {
                                expectedDigest = digest;
                                expectedTag = tag.ToArray();
                            }
                            else
                            {
                                Require(
                                    CryptographicOperations.FixedTimeEquals(expectedDigest, digest)
                                        && CryptographicOperations.FixedTimeEquals(expectedTag!, tag),
                                    $"{parameters.DisplayName} produced different ciphertext or tag across identical measured runs.");
                                CryptographicOperations.ZeroMemory(digest);
                            }
                        }

                        double median = Median(samples);
                        rates[suite.ToString()] = median;
                        Console.WriteLine(
                            $"    {parameters.DisplayName,-72} {median,10:F1} MiB/s "
                            + $"({median * 1024 * 1024 / 1_000_000_000:F3} GB/s median; "
                            + $"runs {string.Join(", ", samples.Select(value => value.ToString("F1")))})");
                    }
                    finally
                    {
                        if (expectedDigest is not null)
                        {
                            CryptographicOperations.ZeroMemory(expectedDigest);
                        }

                        if (expectedTag is not null)
                        {
                            CryptographicOperations.ZeroMemory(expectedTag);
                        }
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(key);
                    CryptographicOperations.ZeroMemory(counter);
                    CryptographicOperations.ZeroMemory(tweak);
                    CryptographicOperations.ZeroMemory(associatedData);
                    CryptographicOperations.ZeroMemory(tag);
                }
            }

            ValidateSuiteRates(rates, "current performance result");
            VerifyKalynaParallelSpeedup(input, output);
            VerifyChaChaParallelSpeedup(input, output);
            CompareWithMachineBaseline(host, rates);

            var result = new PerformanceBaseline(2, host, rates);
            Console.WriteLine("    PERF_RESULT_JSON=" + JsonSerializer.Serialize(result, JsonOptions));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
            CryptographicOperations.ZeroMemory(output);
        }

        RunContainerMeasurementsAsync(host).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Measures the complete v12 encrypted-container path for every production
    /// suite. Unlike the primitive matrix above, this includes the production
    /// Argon2id profile, the bounded chunk pipeline, per-chunk AEAD where
    /// applicable, both parallel tree MACs, authenticated verification before
    /// plaintext, the immutable macOS input snapshot, and ordered decryption.
    /// The input models an already compressed ZPAQ stream; compression itself
    /// is measured by the separate level-5 release E2E gates.
    /// </summary>
    private static async Task RunContainerMeasurementsAsync(PerformanceHostIdentity host)
    {
        string root = Directory.CreateTempSubdirectory("keep-vault-container-performance-").FullName;
#if KEEPVAULT_MACOS
        root = MacSafeFileSystem.ResolveExistingRealPath(root);
#endif
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(
                root,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        byte[] payload = CreateDeterministicBytes(MeasurementBytes, 0x4B56503132434F4EUL);
        byte[] expectedHash = SHA256.HashData(payload);
        var encryptRates = new Dictionary<string, double>(StringComparer.Ordinal);
        var decryptRates = new Dictionary<string, double>(StringComparer.Ordinal);
        Exception? operationFailure = null;
        try
        {
            Console.WriteLine(
                $"    full v12 container method: {MeasurementBytes / (1024 * 1024)} MiB pre-compressed payload, "
                + $"{MeasurementRuns} runs, production Argon2id t={V12MasterKdf.Iterations}/p={V12MasterKdf.Parallelism}, median");
            var containers = new KalynaContainerService();
            foreach (EncryptionSuite suite in ExpectedSuites)
            {
                var encryptionSamples = new double[MeasurementRuns];
                var decryptionSamples = new double[MeasurementRuns];
                for (int run = 0; run < MeasurementRuns; run++)
                {
                    string containerPath = Path.Combine(root, $"{suite}-{run}.kzpaq");
                    using GeneratedArchiveEntropy entropy = CreateContainerEntropy(suite, run);
                    await using var input = new MemoryStream(payload, writable: false);

                    Stopwatch timer = Stopwatch.StartNew();
                    await containers.EncryptZpaqStreamWithPreparedEntropyAsync(
                        input,
                        containerPath,
                        ContainerPassword,
                        ContainerPin,
                        ContainerFactorA,
                        ContainerFactorB,
                        suite,
                        entropy,
                        "v12 container performance",
                        null,
                        CancellationToken.None).ConfigureAwait(false);
                    timer.Stop();
                    encryptionSamples[run] = RateMiBPerSecond(MeasurementBytes, timer.Elapsed);

                    using var sink = new HashingWriteStream();
                    timer.Restart();
                    await containers.DecryptToStreamAsync(
                        containerPath,
                        ContainerPassword,
                        ContainerPin,
                        ContainerFactorA,
                        ContainerFactorB,
                        sink,
                        null,
                        CancellationToken.None).ConfigureAwait(false);
                    timer.Stop();
                    decryptionSamples[run] = RateMiBPerSecond(MeasurementBytes, timer.Elapsed);
                    byte[] actualHash = sink.GetHashAndReset();
                    try
                    {
                        Require(
                            sink.BytesWritten == MeasurementBytes
                                && CryptographicOperations.FixedTimeEquals(expectedHash, actualHash),
                            $"{suite} full-container performance run did not reproduce the input payload.");
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(actualHash);
                    }

                    File.Delete(containerPath);
                }

                double encryptMedian = Median(encryptionSamples);
                double decryptMedian = Median(decryptionSamples);
                encryptRates[suite.ToString()] = encryptMedian;
                decryptRates[suite.ToString()] = decryptMedian;
                Console.WriteLine(
                    $"    {EncryptionSuiteCatalog.Get(suite).DisplayName,-72} "
                    + $"container encrypt {encryptMedian,8:F2} MiB/s; "
                    + $"verify+decrypt {decryptMedian,8:F2} MiB/s");
            }

            ValidateSuiteRates(encryptRates, "full-container encryption result");
            ValidateSuiteRates(decryptRates, "full-container decryption result");
            var result = new ContainerPerformanceResult(1, host, encryptRates, decryptRates);
            Console.WriteLine("    CONTAINER_PERF_RESULT_JSON=" + JsonSerializer.Serialize(result, JsonOptions));
        }
        catch (Exception failure)
        {
            operationFailure = failure;
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expectedHash);
            CryptographicOperations.ZeroMemory(payload);
            try
            {
                if (Directory.Exists(root))
                {
                    Directory.Delete(root, recursive: true);
                }
            }
            catch (Exception cleanupFailure)
            {
                if (operationFailure is null)
                {
                    throw;
                }

                throw new IOException(
                    "The container-performance run failed and its private workspace could not be removed.",
                    new AggregateException(operationFailure, cleanupFailure));
            }
        }
    }

    private static GeneratedArchiveEntropy CreateContainerEntropy(EncryptionSuite suite, int run)
    {
        LockedSensitiveBuffer? firstSalt = null;
        LockedSensitiveBuffer? firstNonce = null;
        LockedSensitiveBuffer? secondSalt = null;
        LockedSensitiveBuffer? secondNonce = null;
        Exception? operationFailure = null;
        try
        {
            firstSalt = LockedSensitiveBuffer.Create(EntropyMixer.SaltPairBytes);
            firstNonce = LockedSensitiveBuffer.Create(EncryptionSuiteCatalog.MaxNonceBytes);
            secondSalt = LockedSensitiveBuffer.Create(EntropyMixer.SaltPairBytes);
            secondNonce = LockedSensitiveBuffer.Create(EncryptionSuiteCatalog.MaxNonceBytes);

            // Keep a suite's KDF salts fixed across its measured runs so the
            // secret PMI memory cost is identical and the median is not a
            // median of three different Argon2 workloads. Nonces remain unique
            // per run, so the repeated benchmark never reuses a keystream.
            FillEntropy(firstSalt.Bytes, 17 + (int)suite, 29);
            FillEntropy(firstNonce.Bytes, 43 + (int)suite, 37 + run);
            FillEntropy(secondSalt.Bytes, 101 + (int)suite, 41);
            FillEntropy(secondNonce.Bytes, 151 + (int)suite, 47 + run);
            var result = new GeneratedArchiveEntropy(
                ContainerFactorA,
                ContainerFactorB,
                firstSalt,
                firstNonce,
                secondSalt,
                secondNonce);
            firstSalt = null;
            firstNonce = null;
            secondSalt = null;
            secondNonce = null;
            return result;
        }
        catch (Exception failure)
        {
            operationFailure = failure;
            throw;
        }
        finally
        {
            SecureMemory.ZeroAndDisposeAllPreservingFailure(
                operationFailure,
                "Container-performance entropy creation failed and one or more sensitive buffers could not be released.",
                secondNonce,
                secondSalt,
                firstNonce,
                firstSalt);
        }
    }

    private static void FillEntropy(Span<byte> destination, int seed, int multiplier)
    {
        for (int index = 0; index < destination.Length; index++)
        {
            destination[index] = unchecked((byte)(seed + (index * multiplier)));
        }
    }

    private static string CreateFactor(int multiplier, int offset)
    {
        byte[] bytes = new byte[V12MasterKdf.FactorBytes];
        try
        {
            for (int index = 0; index < bytes.Length; index++)
            {
                bytes[index] = unchecked((byte)((index * multiplier) + offset));
            }

            return Convert.ToHexString(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static void VerifyKalynaParallelSpeedup(byte[] input, byte[] output)
    {
        byte[] key = CreateDeterministicBytes(64, 0x4B414C594E41UL);
        byte[] counter = CreateDeterministicBytes(64, 0x563132504152UL);
        byte[]? scalarDigest = null;
        try
        {
            NativeKalyna.XCryptCtr512Scalar(key, counter, input, output, WarmupBytes);
            NativeKalyna.XCryptCtr512(key, counter, input, output, WarmupBytes);

            var scalarSamples = new double[MeasurementRuns];
            var parallelSamples = new double[MeasurementRuns];
            for (int run = 0; run < MeasurementRuns; run++)
            {
                Stopwatch timer = Stopwatch.StartNew();
                NativeKalyna.XCryptCtr512Scalar(
                    key,
                    counter,
                    input,
                    output,
                    DifferentialBytes);
                timer.Stop();
                scalarSamples[run] = RateMiBPerSecond(DifferentialBytes, timer.Elapsed);
                byte[] digest = SHA256.HashData(output.AsSpan(0, DifferentialBytes));
                if (scalarDigest is null)
                {
                    scalarDigest = digest;
                }
                else
                {
                    Require(
                        CryptographicOperations.FixedTimeEquals(scalarDigest, digest),
                        "Kalyna scalar output changed across identical performance runs.");
                    CryptographicOperations.ZeroMemory(digest);
                }

                timer.Restart();
                NativeKalyna.XCryptCtr512(
                    key,
                    counter,
                    input,
                    output,
                    DifferentialBytes);
                timer.Stop();
                parallelSamples[run] = RateMiBPerSecond(DifferentialBytes, timer.Elapsed);
                byte[] parallelDigest = SHA256.HashData(output.AsSpan(0, DifferentialBytes));
                try
                {
                    Require(
                        CryptographicOperations.FixedTimeEquals(scalarDigest, parallelDigest),
                        "Kalyna parallel path differs from its scalar v12 path during the performance gate.");
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(parallelDigest);
                }
            }

            double scalarMedian = Median(scalarSamples);
            double parallelMedian = Median(parallelSamples);
            Require(
                parallelMedian >= scalarMedian * 1.20,
                $"Kalyna parallel speedup disappeared: {parallelMedian:F1} MiB/s parallel vs {scalarMedian:F1} MiB/s scalar.");
            Console.WriteLine(
                $"    Kalyna v12 parallel invariant: {parallelMedian:F1} MiB/s vs "
                + $"{scalarMedian:F1} MiB/s scalar ({parallelMedian / scalarMedian:F2}x)");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(counter);
            if (scalarDigest is not null)
            {
                CryptographicOperations.ZeroMemory(scalarDigest);
            }
        }
    }

    private static void VerifyAesRuntimeProvider()
    {
        NativeAesRuntimeProvider provider = NativeAes.RuntimeProvider;
        Require(provider != NativeAesRuntimeProvider.Unknown, "The AES adapter did not report its Crypto++ runtime provider.");
        if (OperatingSystem.IsMacOS()
            && RuntimeInformation.ProcessArchitecture == Architecture.Arm64)
        {
            // Apple Silicon is a release contract, not a best-effort intrinsic
            // hint. If feature detection or the native build regresses, a
            // portable provider must fail even if managed Arm.Aes also lies.
            Require(
                provider == NativeAesRuntimeProvider.ArmV8,
                $"Apple Silicon requires the Crypto++ ArmV8 provider, but production selected {provider}.");
        }

        if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            Require(
                provider == NativeAesRuntimeProvider.AesNi,
                $"AES-NI is available but the production Crypto++ adapter selected {provider}.");
        }

        if (!OperatingSystem.IsMacOS()
            && System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            Require(
                provider == NativeAesRuntimeProvider.ArmV8,
                $"ARM AES is available but the production Crypto++ adapter selected {provider}.");
        }

        Console.WriteLine($"    AES hardware-dispatch invariant: Crypto++ provider {provider}");
    }

    private static void VerifyChaChaParallelSpeedup(byte[] input, byte[] output)
    {
        byte[] key = CreateDeterministicBytes(NativeChaChaPoly.KeyBytes, 0x434841434841UL);
        byte[] nonce = CreateDeterministicBytes(NativeChaChaPoly.NonceBytes, 0x53504C4954UL);
        byte[]? serialDigest = null;
        try
        {
            Require(
                NativeChaChaPoly.XCryptSerial(key, nonce, 1, input, output, WarmupBytes) == 0
                    && NativeChaChaPoly.XCrypt(key, nonce, 1, input, output, WarmupBytes) == 0,
                "ChaCha20 warm-up failed.");

            var serialSamples = new double[MeasurementRuns];
            var splitSamples = new double[MeasurementRuns];
            for (int run = 0; run < MeasurementRuns; run++)
            {
                Stopwatch timer = Stopwatch.StartNew();
                int serialResult = NativeChaChaPoly.XCryptSerial(
                    key,
                    nonce,
                    1,
                    input,
                    output,
                    MeasurementBytes);
                timer.Stop();
                Require(serialResult == 0, $"ChaCha20 serial path returned {serialResult}.");
                serialSamples[run] = RateMiBPerSecond(MeasurementBytes, timer.Elapsed);
                byte[] digest = SHA256.HashData(output);
                if (serialDigest is null)
                {
                    serialDigest = digest;
                }
                else
                {
                    Require(
                        CryptographicOperations.FixedTimeEquals(serialDigest, digest),
                        "ChaCha20 serial output changed across identical performance runs.");
                    CryptographicOperations.ZeroMemory(digest);
                }

                timer.Restart();
                int splitResult = NativeChaChaPoly.XCrypt(
                    key,
                    nonce,
                    1,
                    input,
                    output,
                    MeasurementBytes);
                timer.Stop();
                Require(splitResult == 0, $"ChaCha20 split path returned {splitResult}.");
                splitSamples[run] = RateMiBPerSecond(MeasurementBytes, timer.Elapsed);
                byte[] splitDigest = SHA256.HashData(output);
                try
                {
                    Require(
                        CryptographicOperations.FixedTimeEquals(serialDigest, splitDigest),
                        "ChaCha20 worker split differs from the serial path during the performance gate.");
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(splitDigest);
                }
            }

            double serialMedian = Median(serialSamples);
            double splitMedian = Median(splitSamples);
            if (Environment.ProcessorCount >= 4)
            {
                Require(
                    splitMedian >= serialMedian * 1.10,
                    $"ChaCha20 worker parallelism speedup disappeared: {splitMedian:F1} MiB/s split vs {serialMedian:F1} MiB/s serial.");
            }

            Console.WriteLine(
                $"    ChaCha20 parallel invariant: {splitMedian:F1} MiB/s vs "
                + $"{serialMedian:F1} MiB/s serial ({splitMedian / serialMedian:F2}x)");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(nonce);
            if (serialDigest is not null)
            {
                CryptographicOperations.ZeroMemory(serialDigest);
            }
        }
    }

    private static void CompareWithMachineBaseline(
        PerformanceHostIdentity currentHost,
        IReadOnlyDictionary<string, double> currentRates)
    {
        string? baselinePath = Environment.GetEnvironmentVariable(BaselineEnvironment);
        if (string.IsNullOrWhiteSpace(baselinePath))
        {
            Console.WriteLine(
                $"    no machine baseline supplied; set {BaselineEnvironment} to compare and fail on regressions over 25%");
            return;
        }

        PerformanceBaseline baseline;
        try
        {
            baseline = JsonSerializer.Deserialize<PerformanceBaseline>(
                File.ReadAllText(Path.GetFullPath(baselinePath)),
                JsonOptions)
                ?? throw new InvalidDataException("The performance baseline is empty.");
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            throw new InvalidDataException("The performance baseline could not be read.", ex);
        }

        ValidateMachineBaseline(currentHost, currentRates, baseline);
        Console.WriteLine("    all suites remain within 25% of the supplied same-machine baseline");
    }

    private static void ValidateMachineBaseline(
        PerformanceHostIdentity currentHost,
        IReadOnlyDictionary<string, double> currentRates,
        PerformanceBaseline baseline)
    {
        Require(
            baseline.SchemaVersion == 2,
            "The performance baseline schemaVersion must be 2; schema 1 did not bind rates to a machine.");
        Require(baseline.Host is not null, "The performance baseline has no host identity.");
        ValidateHostIdentity(currentHost, "current performance host");
        ValidateHostIdentity(baseline.Host!, "performance baseline host");
        Require(
            baseline.Host == currentHost,
            "The performance baseline belongs to a different physical host or host configuration.");
        ValidateSuiteRates(currentRates, "current performance result");
        Require(baseline.RatesMiBPerSecond is not null, "The performance baseline has no suite rates.");
        ValidateSuiteRates(baseline.RatesMiBPerSecond!, "machine baseline");
        foreach ((string suite, double currentRate) in currentRates)
        {
            Require(
                baseline.RatesMiBPerSecond!.TryGetValue(suite, out double baselineRate)
                    && double.IsFinite(baselineRate)
                    && baselineRate > 0,
                $"The machine baseline has no valid rate for {suite}.");
            double minimum = baselineRate * (1.0 - AllowedBaselineRegression);
            Require(
                currentRate >= minimum,
                $"{suite} regressed by more than {AllowedBaselineRegression:P0}: "
                + $"{currentRate:F1} MiB/s now, {baselineRate:F1} MiB/s baseline.");
        }

    }

    private static PerformanceHostIdentity CaptureHostIdentity()
    {
        string descriptor = GetCpuDescriptor();
        Require(!string.Equals(descriptor, "unknown-cpu", StringComparison.Ordinal), "The CPU descriptor could not be determined.");
        string osVersion = OperatingSystem.IsMacOS()
            ? ReadRequiredProcessOutput("/usr/bin/sw_vers", "-productVersion")
            : Environment.OSVersion.Version.ToString();
        string osBuild = OperatingSystem.IsMacOS()
            ? ReadRequiredProcessOutput("/usr/bin/sw_vers", "-buildVersion")
            : RuntimeInformation.OSDescription.Trim();
        return new PerformanceHostIdentity(
            RuntimeInformation.OSDescription.Trim(),
            osVersion,
            osBuild,
            RuntimeInformation.OSArchitecture.ToString(),
            RuntimeInformation.ProcessArchitecture.ToString(),
            Environment.ProcessorCount,
            descriptor,
            GetMachineIdentitySha256());
    }

    private static string GetMachineIdentitySha256()
    {
        string? machineIdentity = null;
        string identityDomain;
        if (OperatingSystem.IsMacOS())
        {
            identityDomain = "KeepVault/performance-baseline/v2/macos";
            string? registry = ReadProcessOutput(
                "/usr/sbin/ioreg",
                "-rd1",
                "-c",
                "IOPlatformExpertDevice");
            const string marker = "\"IOPlatformUUID\" = \"";
            int start = registry?.IndexOf(marker, StringComparison.Ordinal) ?? -1;
            if (start >= 0)
            {
                start += marker.Length;
                int end = registry!.IndexOf('"', start);
                if (end > start)
                {
                    string candidate = registry[start..end];
                    if (Guid.TryParse(candidate, out Guid uuid) && uuid != Guid.Empty)
                    {
                        machineIdentity = uuid.ToString("D");
                    }
                }
            }
        }
        else if (OperatingSystem.IsWindows())
        {
            identityDomain = "KeepVault/performance-baseline/v2/windows";
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Cryptography",
                writable: false);
            machineIdentity = key?.GetValue("MachineGuid") as string;
        }
        else if (OperatingSystem.IsLinux() && File.Exists("/etc/machine-id"))
        {
            identityDomain = "KeepVault/performance-baseline/v2/linux";
            machineIdentity = File.ReadAllText("/etc/machine-id").Trim();
        }
        else
        {
            identityDomain = "KeepVault/performance-baseline/v2/unknown";
        }

        Require(!string.IsNullOrWhiteSpace(machineIdentity), "A stable machine identity could not be obtained for the performance baseline.");
        byte[] identityBytes = Encoding.UTF8.GetBytes(
            identityDomain + "\0" + machineIdentity!.Trim().ToLowerInvariant());
        try
        {
            return Convert.ToHexString(SHA256.HashData(identityBytes)).ToLowerInvariant();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(identityBytes);
        }
    }

    private static string ReadRequiredProcessOutput(string executable, params string[] arguments)
    {
        string? output = ReadProcessOutput(executable, arguments)?.Trim();
        Require(!string.IsNullOrWhiteSpace(output), $"Required host metadata from {Path.GetFileName(executable)} is unavailable.");
        return output!;
    }

    private static string GetCpuDescriptor()
    {
        string? descriptor = null;
        if (OperatingSystem.IsWindows())
        {
            using RegistryKey? cpu = Registry.LocalMachine.OpenSubKey(
                @"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
                writable: false);
            descriptor = cpu?.GetValue("ProcessorNameString") as string
                ?? Environment.GetEnvironmentVariable("PROCESSOR_IDENTIFIER");
        }
        else if (OperatingSystem.IsMacOS())
        {
            descriptor = ReadProcessOutput("/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string");
        }
        else if (OperatingSystem.IsLinux() && File.Exists("/proc/cpuinfo"))
        {
            descriptor = File.ReadLines("/proc/cpuinfo")
                .Select(line => line.Split(':', 2, StringSplitOptions.TrimEntries))
                .Where(parts => parts.Length == 2 && parts[0] is "model name" or "Hardware")
                .Select(parts => parts[1])
                .FirstOrDefault();
        }

        descriptor = descriptor?.Trim();
        return string.IsNullOrWhiteSpace(descriptor) ? "unknown-cpu" : descriptor;
    }

    private static string? ReadProcessOutput(string executable, params string[] arguments)
    {
        try
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo(executable)
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                },
            };
            foreach (string argument in arguments)
            {
                process.StartInfo.ArgumentList.Add(argument);
            }

            if (!process.Start())
            {
                return null;
            }

            string output = process.StandardOutput.ReadToEnd();
            if (!process.WaitForExit(5_000) || process.ExitCode != 0)
            {
                try { process.Kill(entireProcessTree: true); } catch { }
                return null;
            }

            return output;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            return null;
        }
    }

    private static void RequireReleaseConfiguration()
    {
        string? configuration = typeof(CipherSuitePerformanceTests).Assembly
            .GetCustomAttribute<AssemblyConfigurationAttribute>()?
            .Configuration;
        Require(
            string.Equals(configuration, "Release", StringComparison.Ordinal),
            $"The performance gate requires a Release assembly, but the current configuration is {configuration ?? "unknown"}.");
    }

    private static void ValidateSuiteInventory()
    {
        EncryptionSuite[] declared = Enum.GetValues<EncryptionSuite>();
        Require(
            declared.SequenceEqual(ExpectedSuites),
            "The EncryptionSuite enum no longer contains exactly the ten performance-gated suites in its stable numeric order.");
        Require(
            EncryptionSuiteCatalog.DisplayOrder.Count == ExpectedSuites.Length
                && EncryptionSuiteCatalog.DisplayOrder.Distinct().Count() == ExpectedSuites.Length
                && EncryptionSuiteCatalog.DisplayOrder.All(ExpectedSuites.Contains),
            "The production suite display order no longer contains each of the ten performance-gated suites exactly once.");
        Require(
            ExpectedSuites.All(EncryptionSuiteCatalog.IsKnown),
            "The performance inventory contains a suite the production catalog does not recognize.");
    }

    private static void ValidateSuiteRates(
        IReadOnlyDictionary<string, double> rates,
        string source)
    {
        string[] expectedNames = [.. ExpectedSuites.Select(suite => suite.ToString())];
        Require(
            rates.Count == expectedNames.Length
                && expectedNames.All(rates.ContainsKey)
                && rates.Keys.All(expectedNames.Contains),
            $"The {source} must contain exactly one rate for all ten production suites.");
        foreach ((string suite, double rate) in rates)
        {
            Require(
                double.IsFinite(rate) && rate > 0,
                $"The {source} has an invalid rate for {suite}.");
        }
    }

    private static void ValidateHostIdentity(PerformanceHostIdentity host, string source)
    {
        Require(!string.IsNullOrWhiteSpace(host.OperatingSystem), $"The {source} has no operating-system descriptor.");
        Require(!string.IsNullOrWhiteSpace(host.OperatingSystemVersion), $"The {source} has no operating-system product version.");
        Require(!string.IsNullOrWhiteSpace(host.OperatingSystemBuild), $"The {source} has no operating-system build.");
        Require(!string.IsNullOrWhiteSpace(host.OsArchitecture), $"The {source} has no OS architecture.");
        Require(!string.IsNullOrWhiteSpace(host.ProcessArchitecture), $"The {source} has no process architecture.");
        Require(host.LogicalProcessors > 0, $"The {source} has no valid logical CPU count.");
        Require(!string.IsNullOrWhiteSpace(host.CpuDescriptor), $"The {source} has no CPU descriptor.");
        Require(
            host.MachineIdentitySha256?.Length == 64
                && host.MachineIdentitySha256.All(char.IsAsciiHexDigit),
            $"The {source} has no valid one-way machine-identity hash.");
    }

    internal static void RunContractRegressionTests()
    {
        ValidateSuiteInventory();
        PerformanceHostIdentity host = CaptureHostIdentity();
        ValidateHostIdentity(host, "current performance host");
        var currentRates = ExpectedSuites.ToDictionary(
            suite => suite.ToString(),
            _ => 100.0,
            StringComparer.Ordinal);
        var baselineRates = new Dictionary<string, double>(currentRates, StringComparer.Ordinal);
        var validBaseline = new PerformanceBaseline(2, host, baselineRates);
        ValidateMachineBaseline(host, currentRates, validBaseline);
        string serializedBaseline = JsonSerializer.Serialize(validBaseline, JsonOptions);
        Require(
            serializedBaseline.Contains("\"machineIdentitySha256\":", StringComparison.Ordinal)
                && !serializedBaseline.Contains("IOPlatformUUID", StringComparison.OrdinalIgnoreCase)
                && !serializedBaseline.Contains("MachineGuid", StringComparison.OrdinalIgnoreCase)
                && !serializedBaseline.Contains("serialNumber", StringComparison.OrdinalIgnoreCase),
            "The performance JSON does not use the one-way machine binding or exposes a raw hardware identifier field.");
        PerformanceBaseline roundTripped = JsonSerializer.Deserialize<PerformanceBaseline>(
            serializedBaseline,
            JsonOptions)
            ?? throw new InvalidOperationException("A valid performance baseline did not JSON-round-trip.");
        ValidateMachineBaseline(host, currentRates, roundTripped);

        RequireThrows<InvalidOperationException>(
            () => ValidateMachineBaseline(host, currentRates, new PerformanceBaseline(1, host, baselineRates)),
            "A schema-1 performance baseline was accepted.");

        string legacySchemaTwo = JsonSerializer.Serialize(new
        {
            schemaVersion = 2,
            host = new
            {
                host.OperatingSystem,
                host.OperatingSystemVersion,
                host.OperatingSystemBuild,
                host.OsArchitecture,
                host.ProcessArchitecture,
                host.LogicalProcessors,
                host.CpuDescriptor,
            },
            ratesMiBPerSecond = baselineRates,
        }, JsonOptions);
        PerformanceBaseline legacyWithoutMachineBinding = JsonSerializer.Deserialize<PerformanceBaseline>(
            legacySchemaTwo,
            JsonOptions)
            ?? throw new InvalidOperationException("The legacy baseline fixture did not deserialize.");
        RequireThrows<InvalidOperationException>(
            () => ValidateMachineBaseline(host, currentRates, legacyWithoutMachineBinding),
            "A schema-2 baseline without physical-machine binding was accepted.");

        char differentHashDigit = host.MachineIdentitySha256[0] == '0' ? '1' : '0';
        PerformanceHostIdentity differentMachine = host with
        {
            MachineIdentitySha256 = new string(differentHashDigit, 64),
        };
        RequireThrows<InvalidOperationException>(
            () => ValidateMachineBaseline(host, currentRates, new PerformanceBaseline(2, differentMachine, baselineRates)),
            "A performance baseline from a different physical machine was accepted.");

        var missingSuite = new Dictionary<string, double>(baselineRates, StringComparer.Ordinal);
        missingSuite.Remove(ExpectedSuites[0].ToString());
        RequireThrows<InvalidOperationException>(
            () => ValidateMachineBaseline(host, currentRates, new PerformanceBaseline(2, host, missingSuite)),
            "A performance baseline with a missing suite was accepted.");

        var unknownSuite = new Dictionary<string, double>(baselineRates, StringComparer.Ordinal)
        {
            ["UnknownSuite"] = 100.0,
        };
        RequireThrows<InvalidOperationException>(
            () => ValidateMachineBaseline(host, currentRates, new PerformanceBaseline(2, host, unknownSuite)),
            "A performance baseline with an unknown suite was accepted.");

        var invalidRate = new Dictionary<string, double>(baselineRates, StringComparer.Ordinal)
        {
            [ExpectedSuites[0].ToString()] = double.NaN,
        };
        RequireThrows<InvalidOperationException>(
            () => ValidateMachineBaseline(host, currentRates, new PerformanceBaseline(2, host, invalidRate)),
            "A performance baseline with a non-finite rate was accepted.");
        RequireThrows<InvalidOperationException>(
            () => ValidateMachineBaseline(host, currentRates, new PerformanceBaseline(2, host, null)),
            "A performance baseline without rates was accepted.");

        var thresholdRates = new Dictionary<string, double>(currentRates, StringComparer.Ordinal)
        {
            [ExpectedSuites[0].ToString()] = 75.0,
        };
        ValidateMachineBaseline(host, thresholdRates, new PerformanceBaseline(2, host, baselineRates));
        thresholdRates[ExpectedSuites[0].ToString()] = 74.0;
        RequireThrows<InvalidOperationException>(
            () => ValidateMachineBaseline(host, thresholdRates, new PerformanceBaseline(2, host, baselineRates)),
            "A regression greater than 25 percent was accepted.");
    }

    private static byte[] CreateDeterministicBytes(int length, ulong seed)
    {
        byte[] bytes = new byte[length];
        ulong state = seed == 0 ? 0x9E3779B97F4A7C15UL : seed;
        for (int index = 0; index < bytes.Length; index++)
        {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            bytes[index] = (byte)state;
        }

        return bytes;
    }

    private static double RateMiBPerSecond(int bytes, TimeSpan elapsed)
    {
        Require(elapsed > TimeSpan.Zero, "A performance timer returned a zero duration.");
        return bytes / (1024.0 * 1024.0) / elapsed.TotalSeconds;
    }

    private static double Median(double[] samples)
    {
        Require(samples.Length >= 3, "A performance median requires at least three samples.");
        double[] ordered = [.. samples.Order()];
        return ordered[ordered.Length / 2];
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private static void RequireThrows<TException>(Action action, string message)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException)
        {
            return;
        }

        throw new InvalidOperationException(message);
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        WriteIndented = false,
    };

    private sealed record PerformanceBaseline(
        int SchemaVersion,
        PerformanceHostIdentity? Host,
        Dictionary<string, double>? RatesMiBPerSecond);

    private sealed record ContainerPerformanceResult(
        int SchemaVersion,
        PerformanceHostIdentity Host,
        Dictionary<string, double> EncryptMiBPerSecond,
        Dictionary<string, double> VerifyAndDecryptMiBPerSecond);

    private sealed record PerformanceHostIdentity(
        string OperatingSystem,
        string OperatingSystemVersion,
        string OperatingSystemBuild,
        string OsArchitecture,
        string ProcessArchitecture,
        int LogicalProcessors,
        string CpuDescriptor,
        string MachineIdentitySha256);

    private sealed class HashingWriteStream : Stream
    {
        private readonly IncrementalHash _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        private bool _disposed;

        internal long BytesWritten { get; private set; }

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => !_disposed;
        public override long Length => BytesWritten;

        public override long Position
        {
            get => BytesWritten;
            set => throw new NotSupportedException();
        }

        internal byte[] GetHashAndReset()
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _hash.GetHashAndReset();
        }

        public override void Flush()
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
        }

        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return cancellationToken.IsCancellationRequested
                ? Task.FromCanceled(cancellationToken)
                : Task.CompletedTask;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            ArgumentNullException.ThrowIfNull(buffer);
            Write(buffer.AsSpan(offset, count));
        }

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _hash.AppendData(buffer);
            BytesWritten = checked(BytesWritten + buffer.Length);
        }

        public override ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (cancellationToken.IsCancellationRequested)
            {
                return ValueTask.FromCanceled(cancellationToken);
            }

            Write(buffer.Span);
            return ValueTask.CompletedTask;
        }

        public override Task WriteAsync(
            byte[] buffer,
            int offset,
            int count,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(buffer);
            if (cancellationToken.IsCancellationRequested)
            {
                return Task.FromCanceled(cancellationToken);
            }

            Write(buffer.AsSpan(offset, count));
            return Task.CompletedTask;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && !_disposed)
            {
                _hash.Dispose();
                _disposed = true;
            }

            base.Dispose(disposing);
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) =>
            throw new NotSupportedException();
    }
}
