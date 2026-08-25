using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
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

    internal static void Run()
    {
        PerformanceHostIdentity host = CaptureHostIdentity();
        Console.WriteLine(
            $"    performance host: {host.OperatingSystem}; {host.ProcessArchitecture}; "
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
            foreach (EncryptionSuite suite in Enum.GetValues<EncryptionSuite>())
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

            VerifyKalynaTableSpeedup(input, output);
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
    }

    private static void VerifyKalynaTableSpeedup(byte[] input, byte[] output)
    {
        byte[] key = CreateDeterministicBytes(64, 0x4B414C594E41UL);
        byte[] counter = CreateDeterministicBytes(64, 0x5441424C4553UL);
        byte[]? referenceDigest = null;
        try
        {
            NativeKalyna.XCryptCtr512Reference(key, counter, input, output, WarmupBytes);
            NativeKalyna.XCryptCtr512(key, counter, input, output, WarmupBytes);

            var referenceSamples = new double[MeasurementRuns];
            var tableSamples = new double[MeasurementRuns];
            for (int run = 0; run < MeasurementRuns; run++)
            {
                Stopwatch timer = Stopwatch.StartNew();
                NativeKalyna.XCryptCtr512Reference(
                    key,
                    counter,
                    input,
                    output,
                    DifferentialBytes);
                timer.Stop();
                referenceSamples[run] = RateMiBPerSecond(DifferentialBytes, timer.Elapsed);
                byte[] digest = SHA256.HashData(output.AsSpan(0, DifferentialBytes));
                if (referenceDigest is null)
                {
                    referenceDigest = digest;
                }
                else
                {
                    Require(
                        CryptographicOperations.FixedTimeEquals(referenceDigest, digest),
                        "Kalyna reference output changed across identical performance runs.");
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
                tableSamples[run] = RateMiBPerSecond(DifferentialBytes, timer.Elapsed);
                byte[] tableDigest = SHA256.HashData(output.AsSpan(0, DifferentialBytes));
                try
                {
                    Require(
                        CryptographicOperations.FixedTimeEquals(referenceDigest, tableDigest),
                        "Kalyna table path differs from the reference during the performance gate.");
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(tableDigest);
                }
            }

            double referenceMedian = Median(referenceSamples);
            double tableMedian = Median(tableSamples);
            Require(
                tableMedian >= referenceMedian * 2.0,
                $"Kalyna table path speedup disappeared: {tableMedian:F1} MiB/s tables vs {referenceMedian:F1} MiB/s reference.");
            Console.WriteLine(
                $"    Kalyna table invariant: {tableMedian:F1} MiB/s vs "
                + $"{referenceMedian:F1} MiB/s reference ({tableMedian / referenceMedian:F2}x)");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(counter);
            if (referenceDigest is not null)
            {
                CryptographicOperations.ZeroMemory(referenceDigest);
            }
        }
    }

    private static void VerifyAesRuntimeProvider()
    {
        NativeAesRuntimeProvider provider = NativeAes.RuntimeProvider;
        Require(provider != NativeAesRuntimeProvider.Unknown, "The AES adapter did not report its Crypto++ runtime provider.");
        if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            Require(
                provider == NativeAesRuntimeProvider.AesNi,
                $"AES-NI is available but the production Crypto++ adapter selected {provider}.");
        }

        if (System.Runtime.Intrinsics.Arm.Aes.IsSupported)
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

        Require(
            baseline.SchemaVersion == 2,
            "The performance baseline schemaVersion must be 2; schema 1 did not bind rates to a machine.");
        Require(baseline.Host is not null, "The performance baseline has no host identity.");
        Require(
            baseline.Host == currentHost,
            "The performance baseline belongs to a different host. "
            + $"Expected {currentHost}; received {baseline.Host}.");
        foreach ((string suite, double currentRate) in currentRates)
        {
            Require(
                baseline.RatesMiBPerSecond.TryGetValue(suite, out double baselineRate)
                    && double.IsFinite(baselineRate)
                    && baselineRate > 0,
                $"The machine baseline has no valid rate for {suite}.");
            double minimum = baselineRate * (1.0 - AllowedBaselineRegression);
            Require(
                currentRate >= minimum,
                $"{suite} regressed by more than {AllowedBaselineRegression:P0}: "
                + $"{currentRate:F1} MiB/s now, {baselineRate:F1} MiB/s baseline.");
        }

        string[] unknown =
        [
            .. baseline.RatesMiBPerSecond.Keys
                .Where(suite => !currentRates.ContainsKey(suite))
                .OrderBy(suite => suite, StringComparer.Ordinal),
        ];
        Require(unknown.Length == 0, "The machine baseline contains unknown suites: " + string.Join(", ", unknown));
        Console.WriteLine("    all suites remain within 25% of the supplied same-machine baseline");
    }

    private static PerformanceHostIdentity CaptureHostIdentity()
    {
        string descriptor = GetCpuDescriptor();
        return new PerformanceHostIdentity(
            RuntimeInformation.OSDescription.Trim(),
            RuntimeInformation.OSArchitecture.ToString(),
            RuntimeInformation.ProcessArchitecture.ToString(),
            Environment.ProcessorCount,
            descriptor);
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

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        WriteIndented = false,
    };

    private sealed record PerformanceBaseline(
        int SchemaVersion,
        PerformanceHostIdentity? Host,
        Dictionary<string, double> RatesMiBPerSecond);

    private sealed record PerformanceHostIdentity(
        string OperatingSystem,
        string OsArchitecture,
        string ProcessArchitecture,
        int LogicalProcessors,
        string CpuDescriptor);
}
