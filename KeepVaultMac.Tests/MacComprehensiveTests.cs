using System.Buffers.Binary;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using KalynaArchiver.Services;
using KalynaArchiver.Signing;
using Microsoft.Win32.SafeHandles;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

internal static partial class MacComprehensiveTests
{
    /// <summary>
    /// The Apple Team ID compiled into the app assembly, which every Apple
    /// code-signature check is pinned to. Read from assembly metadata so the
    /// test cannot drift away from the value the build actually signs with.
    /// </summary>
    private static readonly string ExpectedAppleTeamIdentifier =
        typeof(IntegrityService).Assembly
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .FirstOrDefault(attribute => string.Equals(attribute.Key, "KeepVaultAppleTeamIdentifier", StringComparison.Ordinal))
            ?.Value
        ?? throw new InvalidOperationException("The pinned Apple Team ID is not compiled into the app assembly.");

    private const string UserPassword = "N!r7$Vq2#Lm8%Tx3&Jd9*Wp4+Kg5=Zu6?Ce";

    /// <summary>
    /// The fourth credential. Every container call needs it, so it lives
    /// beside the passphrase rather than being spelled out at each call site.
    /// </summary>
    private const string UserPin = "428317";
    private const string WrongPassword = "Q!m8$Ls2#Vx7%Tp4&Jd9*Wr5+Kn6=Zu3?Ce";

    // SHA3-512 over KZPAQ2\0 || LE32(header length) || the exact canonical
    // v12 header. These values were produced independently from the C# writer
    // using Python's SHA3-512 and an explicit System.Text.Json-compatible
    // encoding of the fixed KAT entropy. Pinning every suite's prefix keeps a
    // version, field-order, domain, nonce-split or tweak change from hiding
    // behind the worker-1-vs-N byte comparison.
    private static readonly IReadOnlyDictionary<EncryptionSuite, string> V12WorkerKatHeaderPrefixSha3 =
        new Dictionary<EncryptionSuite, string>
        {
            [EncryptionSuite.ThreefishOverKalyna] =
                "C77CE0CEC527974ABF1F79C0BEADD8607BA0BBC2633FA6A5E5C74B28BBB3FA21"
                + "AA32375C1531D186FDBB9E07629F127763A227D80D47D1046382A19FB5B400C2",
            [EncryptionSuite.ChaChaOverAes] =
                "F3EF179BA200F6F857B11CFBB01FE8B27138CCE87E98B469EA90AA44812329764"
                + "0CD3A1EF840085B1DB4A1A77F4AAA062CE80ECE24E45AA642D31AA89711004D",
            [EncryptionSuite.MixedCascade] =
                "8D9BDA5AFD497A9D0B171A3082AC5F9173E54DF56AC01A0E178ECEAF6F8B25C3"
                + "851B7A8B3061C4933667A2F8199B3749B510F26C97F345570915431512669CC9",
            [EncryptionSuite.ParanoiaCascade] =
                "9BE88414B0F62B1F1C9253ABB0394775106FB0E2185C0EFD53459FD92DFC82D20"
                + "D002CDC5BB951CC4055FD69D6F2E250166F9DCE2A7F10A41EAD1071B8527899",
            [EncryptionSuite.Threefish1024] =
                "FB2F2498AFE6DEAE2161B8A6BC5B5A828EAD8581B1CB502009BC67FE5E0046F2"
                + "D10DA6A3205F6FDD744AE196FB774275DF82EBCB8589AD104880225680E8E74D",
            [EncryptionSuite.Kalyna512_512] =
                "CB55EF7ED633A9DFED45FF65F4047495C4544BD8635A39C65ABF17348BCE2F16"
                + "2C7EED5B48D581E042CA441B6D0C803F6D880D88ACAA2438F1EF477ADFAB84A2",
            [EncryptionSuite.Shacal2_512] =
                "05D8A9CE0E59D9C78848FC3A0EC7A1B4C6102358625B36945010E7627D94C0A5"
                + "8FC22445A80AB274F092A33F3B3A66014C3AF9C7CFD48E29D0C2BB802F502EA0",
            [EncryptionSuite.Mars448] =
                "334582185A69C837162C4B27D54D9A37805686715C77C19EAAB2D5778A28EC008"
                + "A291D566B172009BBD2A7344E3DD4FDBBB0A93E389F59B45FE8D8CBD588886B",
            [EncryptionSuite.Aes256] =
                "500232504124476611628586BC754BB964A22E4142883B2EAA997ABAA69A0EACF"
                + "9C59E3D99BCAD67352EF498C4494C5ACB5540260E3409183BA1552B864BD248",
            [EncryptionSuite.ChaCha20Poly1305] =
                "07318F3AB1736E90DFDB9214D0D11852E095A229F44C7F9C6DCA65D33CF7D057"
                + "C4296626FC064B2C790303013A603B72D782837D6BB93F13072AB43E417B35E7",
        };

    private static readonly AsyncLocal<Random?> CurrentPrng = new();
    internal static uint? TestSeed { get; set; }

    internal static void SetCurrentPrng(Random? random)
    {
        CurrentPrng.Value = random;
    }

    internal static byte[] GetRandomTestBytes(int count)
    {
        byte[] bytes = new byte[count];
        FillRandomTestBytes(bytes);
        return bytes;
    }

    internal static void FillRandomTestBytes(Span<byte> destination)
    {
        if (CurrentPrng.Value is { } prng)
        {
            prng.NextBytes(destination);
        }
        else
        {
            RandomNumberGenerator.Fill(destination);
        }
    }

    internal static IReadOnlyList<TestCase> AllTests =>
    [
        // Source- and documentation-level gates. Cheap enough to run on every
        // changed-file pass, including documentation-only changes.
        new("spec.no-legacy-source", "no legacy constructions in production source", SpecLintTests.NoLegacyLintAsync, TestResource.Light, "Spec"),
        new("spec.normative-v12-docs", "documentation matches the normative v12 specification", SpecLintTests.SpecConsistencyAsync, TestResource.Light, "Spec"),
        new("spec.lockfile-runtimes", "lock files match the platform their project builds on", SpecLintTests.LockFileRuntimesAsync, TestResource.Light, "Spec"),
        new("security.process-hardening", "macOS process hardening", TestProcessHardeningAsync, TestResource.ProcessGlobal, "Security"),
        new("trust.native-tools", "signed native trust and tamper rejection", TestNativeTrustAsync, TestResource.Light, "Trust"),
        new("packaging.macho-signature-closure", "every Mach-O in the release bundle carries a hybrid signature", TestBundleMachOClosureAsync, TestResource.Light, "Packaging"),
        new("packaging.companion-qr", "the companion QR scanner is checked against the pinned keys", TestCompanionScannerAsync, TestResource.Light, "Packaging"),
        new("crypto.kdf-primitives", "KDF primitives against independent second implementations", TestKdfPrimitivesAsync, TestResource.Light, "Crypto"),
        new("policy.pin-creation", "creation PIN policy and weak-pattern rejection", TestPinCreationPolicyAsync, TestResource.Light, "Policy"),
        new("policy.password", "password policy and KEEPVAULT term rejection", TestPasswordPolicyAsync, TestResource.Light, "Policy"),
        new("kdf.properties", "KDF properties: credential binding, PMI range and round chaining", TestKdfPropertiesAsync, TestResource.ArgonHeavy, "KDF"),
        new("kdf.peak-memory-and-header", "peak memory stays at one Argon2 matrix, and the header leaks nothing", TestCostAndHeaderAsync, TestResource.ArgonPeakMemory, "KDF"),
        new("crypto.primitive-vectors", "SHA3, Skein, Kalyna and Threefish reference vectors", TestPrimitiveVectorsAsync, TestResource.Light, "Crypto"),
        new("crypto.mldsa87-interop", "ML-DSA-87 managed/reference interoperability", TestMldsaInteropAsync, TestResource.CpuHeavy, "Crypto"),
        new("crypto.reference-differential", "randomised differential testing against every reference library", TestReferenceDifferentialAsync, TestResource.CpuHeavy, "Crypto"),
        new("crypto.v12-parallel-mac-kat", "v12 parallel MAC tree against an independent serial KAT", TestV12ParallelMacKatAsync, TestResource.CpuHeavy, "Crypto"),
        .. FastPathDifferentialTests.Tests,
        .. SecurityHardeningTests.Tests,
        .. HybridKeyProtectionTests.Tests,
        // Manual release gate: deliberately absent from full/quick/changed
        // selection. Run it on an otherwise idle host with --performance.
        new("performance.cipher-suites", "primitive and full-container release medians for every cipher suite and cascade", () =>
            {
                CipherSuitePerformanceTests.Run();
                return Task.CompletedTask;
            }, TestResource.CpuHeavy, "Performance", IsPerformance: true)
        {
            Cost = new TestCost(4, 3072, true, TestConstraint.HostExclusive),
        },
        new("performance.paranoia-256mib-e2e", "256 MiB level-5 Paranoia production Argon2id end-to-end measurement",
            ReleaseEndToEndPerformanceTests.RunExact256MiBAsync,
            TestResource.ArgonPeakMemory,
            "Performance",
            IsPerformance: true)
        {
            Cost = new TestCost(
                9,
                8960,
                true,
                TestConstraint.HostExclusive | TestConstraint.EntropyState | TestConstraint.ZpaqProcess),
        },
        new("performance.paranoia-complex-tree-e2e", "complex heterogeneous tree level-5 Paranoia and KPAR2 repair end-to-end measurement",
            ReleaseEndToEndPerformanceTests.RunComplexTreeAsync,
            TestResource.ArgonPeakMemory,
            "Performance",
            IsPerformance: true)
        {
            Cost = new TestCost(
                9,
                8960,
                true,
                TestConstraint.HostExclusive | TestConstraint.EntropyState | TestConstraint.ZpaqProcess),
        },
        new("kdf.argon2-equivalence", "Argon2id fixed 1 GiB profile and independent equivalence", TestArgon2Async, TestResource.ArgonHeavy, "KDF"),
        new("zpaq.seatbelt-runtime", "operation-specific Seatbelt policy, kernel canaries, lifecycle and inherited-FD gate", TestZpaqSeatbeltRuntimeAsync, TestResource.ZpaqGlobal, "ZPAQ")
        {
            Cost = new TestCost(2, 512, false, TestConstraint.HostExclusive | TestConstraint.ZpaqProcess),
        },
        new("zpaq.full-matrix", "ZPAQ levels, streaming, traversal and malformed corpus", TestZpaqAsync, TestResource.ZpaqGlobal, "ZPAQ"),
        new("zpaq.free-space-descriptor", "ZPAQ free-space gate stays bound to the extraction descriptor", TestFreeSpaceDescriptorBindingAsync, TestResource.Light, "ZPAQ"),
        new("kdf.v12-master-factor-split", "v12 master KDF and 512/512 factor split mutation isolation", TestV12MasterKdfAsync, TestResource.ArgonHeavy, "KDF"),
        new("containers.v12-production-worker-equivalence", "all ten production suites are byte-identical with one worker and production workers", TestV12ProductionWorkerEquivalenceAsync, TestResource.ProcessGlobal, "Containers")
        {
            Cost = new TestCost(4, 512, false, TestConstraint.HostExclusive),
        },
        new("containers.v12-kpar2-roundtrip", "v12 container, ZPAQ extraction and KPAR2 round trip", TestV12ContainersAsync, TestResource.EntropyGlobal, "Containers"),
        new("deletion.quarantine-symlink", "quarantine rollback object binding and symlink-safe directory traversal", TestQuarantineAndSymlinkSafetyAsync, TestResource.Light, "Deletion"),
        // Reads the process-wide locked-byte counter, so it cannot share the
        // process with another test that locks or releases memory: in parallel
        // it fails at random and, worse, can hide a real leak behind another
        // test's release.
        new("entropy.exception-safety", "GeneratedArchiveEntropy exception safety and leak prevention", TestEntropyExceptionSafetyAsync, TestResource.ProcessGlobal, "Entropy"),
        new("crypto.cascade-layering", "cascade layering: the outer layer alone reveals nothing", TestCascadeLayeringAsync, TestResource.Light, "Crypto"),
        new("crypto.two-round-derivation", "two-round key derivation from one pool consumption", TestTwoRoundDerivationAsync, TestResource.EntropyGlobal, "Crypto"),
        new("crypto.unprepared-parameters", "salt and nonce for every single-round suite without prepared entropy", TestUnpreparedEncryptionParametersAsync, TestResource.EntropyGlobal, "Crypto"),
        new("crypto.per-chunk-nonces", "per-chunk nonces across a multi-chunk archive", TestPerChunkNoncesAsync, TestResource.CpuHeavy, "Crypto"),
        new("crypto.mars-shacal-vectors", "AES, MARS, SHACAL-2 and Threefish vectors plus independent CTR behaviour", TestCascadeCipherVectorsAsync, TestResource.CpuHeavy, "Crypto"),
        new("deletion.secure-file-object-binding", "secure deletion destroys and deletes the same object", TestSecureFileObjectBoundDeletionAsync, TestResource.Light, "Deletion"),
        new("recovery.sidecar-transaction", "KPAR2 sidecar replacement survives a failure at every step", TestRecoverySidecarTransactionAsync, TestResource.Light, "Recovery"),
        new("recovery.kpar2-v4-adversarial", "KPAR2 v4 repair, authentication and transplantation rejection", TestRecoveryAsync, TestResource.EntropyGlobal, "Recovery"),
        .. ParallelRecoveryTests.Tests,
        new("deletion.cryptographic-erase", "cryptographic erase ordering and hard-link refusal", TestCryptographicEraseAsync, TestResource.EntropyGlobal, "Deletion"),
        new("deletion.original-verification", "verified original deletion refuses on any mismatch", TestVerifiedOriginalDeletionAsync, TestResource.Light, "Deletion"),
        .. ContainerSuiteCases(),
        .. RecoverySuiteCases(),
        .. MacGuiTests.Tests,
    ];

    /// <summary>
    /// Runs the comprehensive groups, optionally narrowed to those whose name
    /// contains <paramref name="only"/>. The filter exists so a single group
    /// can be re-run while fixing it; a full run passes null.
    /// </summary>
    internal static async Task RunAsync(string? only = null)
    {
        string[] args = only != null ? ["--full", "--no-smoke", "--only", only] : ["--full", "--no-smoke"];
        int exitCode = await TestRunner.RunAsync(args, [], AllTests).ConfigureAwait(false);
        if (exitCode != 0)
        {
            throw new InvalidOperationException("Comprehensive test suite reported failures.");
        }
    }

    private static Task TestProcessHardeningAsync()
    {
        Require(
            KalynaArchiver.Program.StartupConfigurationErrorExitCode == 78,
            "A startup-hardening failure is not mapped to EX_CONFIG (78).");
        MacProcessHardeningStatus status = MacProcessHardening.Apply();
        Require(status.AllRequiredApplied, "Required macOS process hardening was not applied.");
        Require(status.CoreDumpsDisabled, "Core dumps remain enabled.");
        Require(status.DebuggerDenied, "Debugger attachment was not denied.");
        Require(status.RestrictiveUmaskApplied, "Private umask was not applied.");
        Require(status.DynamicLoaderEnvironmentCleared, "Dynamic-loader environment was not cleared.");
        return Task.CompletedTask;
    }

    private static Task TestFreeSpaceDescriptorBindingAsync()
    {
        string root = MacSafeFileSystem.ResolveExistingRealPath(
            Directory.CreateTempSubdirectory("keep-vault-free-space-binding-").FullName);
        string destination = Path.Combine(root, "output");
        string? displaced = null;
        MacExtractionStaging? staging = null;
        bool descriptorQueryObserved = false;
        try
        {
            staging = new MacExtractionStaging(destination);
            MacExtractionStaging activeStaging = staging;
            string displacedPath = staging.StagingPath + ".displaced";
            displaced = displacedPath;
            MacFileIdentity expectedIdentity = staging.StagingIdentity;
            MacSafeFileSystem.TestHookAfterFreeSpaceDescriptorQuery = observed =>
            {
                descriptorQueryObserved = true;
                Require(
                    observed.SameObject(expectedIdentity),
                    "fstatvfs ran against a descriptor other than the held extraction staging directory.");
            };
            MacExtractionStaging.TestHookBeforeFreeSpaceQuery = () =>
            {
                Directory.Move(activeStaging.StagingPath, displacedPath);
                Directory.CreateDirectory(activeStaging.StagingPath);
                File.WriteAllText(Path.Combine(activeStaging.StagingPath, "foreign-canary"), "must survive");
            };

            RequireThrows<IOException>(
                () => activeStaging.GetFreeDiskSpaceBytes(),
                "The free-space gate accepted a replacement staging pathname after its descriptor query.");
            Require(descriptorQueryObserved, "The free-space gate did not execute fstatvfs on the held descriptor.");
            string canary = Path.Combine(activeStaging.StagingPath, "foreign-canary");
            Require(
                File.Exists(canary) && File.ReadAllText(canary) == "must survive",
                "The descriptor-bound free-space gate modified the replacement-path canary.");
        }
        finally
        {
            MacExtractionStaging.TestHookBeforeFreeSpaceQuery = null;
            MacSafeFileSystem.TestHookAfterFreeSpaceDescriptorQuery = null;
            if (staging is not null && displaced is not null && Directory.Exists(displaced))
            {
                if (Directory.Exists(staging.StagingPath))
                {
                    Directory.Delete(staging.StagingPath, recursive: true);
                }
                Directory.Move(displaced, staging.StagingPath);
            }
            staging?.Dispose();
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }

        return Task.CompletedTask;
    }

    private static readonly string[] SidecarSuffixes =
        [".sha3", ".skein", ".khsig", ".sha3.khsig", ".skein.khsig"];

    /// <summary>
    /// Enumerates the native components exactly as the build shipped them,
    /// inside the signed app bundle, when KEEPVAULT_SIGNED_BUNDLE names one.
    /// </summary>
    /// <remarks>
    /// These are the artifacts whose signatures actually matter, so the trust
    /// group verifies them in place. They cannot be executed here: the shipped
    /// helpers carry com.apple.security.inherit and so require a sandboxed
    /// parent, which a test runner is not. The functional groups therefore run
    /// against the locally staged, re-signed copies produced by
    /// tools/Stage-TestNatives-macOS.sh, which keep every trust gate but drop
    /// the sandbox entitlements.
    /// </remarks>
    private static string? ResolveShippedComponent(string logicalName)
    {
        string? bundle = Environment.GetEnvironmentVariable("KEEPVAULT_SIGNED_BUNDLE");
        return string.IsNullOrEmpty(bundle)
            ? null
            : NativeToolIntegrity.ResolveKnownTool(logicalName, Path.Combine(bundle, "Contents", "MacOS"))
              ?? throw new FileNotFoundException($"Signed native component is unavailable in the bundle: {logicalName}");
    }

    private static string ResolveSignedComponent(string logicalName)
        => NativeToolIntegrity.ResolveKnownTool(logicalName)
            ?? throw new FileNotFoundException($"Signed native component is unavailable: {logicalName}");

    private static Task TestNativeTrustAsync()
    {
        IReadOnlyList<string> logicalNames = NativeToolIntegrity.RequiredLogicalToolNames;
        Require(logicalNames.Count == 9, $"Production requires {logicalNames.Count} native tools instead of the normative v12 set of nine.");
        Require(
            logicalNames.Distinct(StringComparer.OrdinalIgnoreCase).Count() == logicalNames.Count,
            "Production's required native-tool inventory contains duplicate logical names.");

        Require(SigningTrustPolicy.IsConfigured, "Compiled hybrid-signature policy is not configured.");
        HybridSignaturePolicy policy = SigningTrustPolicy.HybridPolicy
            ?? throw new InvalidOperationException("Compiled ML-DSA-87 public-key policy is unavailable.");

        foreach (string logicalName in logicalNames)
        {
            string path = ResolveSignedComponent(logicalName);
            Require(File.ResolveLinkTarget(path, returnFinalTarget: false) is null, $"Native component is a symbolic link: {logicalName}");
            string sidecarBase = IntegrityService.ResolveSidecarBasePath(path);
            foreach (string suffix in SidecarSuffixes)
            {
                Require(File.Exists(sidecarBase + suffix), $"Native component sidecar is missing: {logicalName}{suffix}");
            }

            ToolIntegrityStatus status = IntegrityService.CheckFile(path, requireManifest: true);
            Require(status.IsTrusted, $"Native trust failed for {logicalName}: {status.Message} {status.HybridSignatureMessage} {status.SignatureMessage}");
            Require(status.HashMatches, $"Dual manifest failed for {logicalName}.");
            Require(status.HybridSignatureMatches, $"Hybrid RSA-PSS/ML-DSA signature failed for {logicalName}.");
            Require(IntegrityService.IsAcceptedSignatureState(status.SignatureState), $"Apple signature failed for {logicalName}.");

            // Windows pins the Authenticode signer certificate by hash. macOS
            // exposes no equivalent certificate through the Security
            // framework, so ToolIntegrityStatus deliberately reports no signer
            // hashes here. The identical RSA-SPKI and ML-DSA-87 pins are
            // enforced one assertion earlier, inside the hybrid signature
            // check, and the Apple signature is separately bound to the pinned
            // Team ID through a strict designated requirement.
            Require(
                status.SignerSha256 is null && status.SignerSha3_512 is null && status.SignerSkein1024 is null,
                $"macOS reported Authenticode-style signer hashes for {logicalName}; the trust model changed.");
            Require(
                string.Equals(status.Signer, ExpectedAppleTeamIdentifier, StringComparison.Ordinal),
                $"Apple Team ID pin mismatch for {logicalName}: {status.Signer}");

            // Assert both halves of the hybrid signature by name. The
            // post-quantum ML-DSA-87 branch must hold on its own, so a future
            // regression that silently degraded verification to the classical
            // RSA-PSS signature alone would fail here rather than pass.
            HybridSignatureVerificationResult componentSignature = HybridSignatureService.VerifyFile(
                path,
                sidecarBase + HybridSignatureService.SidecarExtension,
                policy);
            Require(componentSignature.RsaPssValid, $"RSA-PSS/SHA-512 signature failed for {logicalName}.");
            Require(componentSignature.Mldsa87Valid, $"Post-quantum ML-DSA-87 signature failed for {logicalName}.");
            Require(componentSignature.IsTrusted, $"Hybrid signature is not trusted for {logicalName}.");
            using TrustedNativeFileLease lease = NativeToolIntegrity.AcquireTrustedFile(path);
            Require(File.Exists(lease.Path), $"Authenticated private snapshot missing for {logicalName}.");

            // Repeat the cryptographic checks against the component as the
            // build actually shipped it inside the signed bundle. Those bytes
            // differ from the locally staged copy, which is re-signed without
            // the sandbox entitlements so that it can be executed at all.
            if (ResolveShippedComponent(logicalName) is not { } shippedPath)
            {
                continue;
            }

            string shippedSidecarBase = IntegrityService.ResolveSidecarBasePath(shippedPath);
            ToolIntegrityStatus shipped = IntegrityService.CheckFile(shippedPath, requireManifest: true);
            Require(shipped.IsTrusted, $"Shipped native trust failed for {logicalName}: {shipped.Message} {shipped.HybridSignatureMessage} {shipped.SignatureMessage}");
            Require(shipped.HashMatches, $"Shipped dual manifest failed for {logicalName}.");
            Require(
                string.Equals(shipped.Signer, ExpectedAppleTeamIdentifier, StringComparison.Ordinal),
                $"Shipped Apple Team ID pin mismatch for {logicalName}: {shipped.Signer}");
            HybridSignatureVerificationResult shippedSignature = HybridSignatureService.VerifyFile(
                shippedPath,
                shippedSidecarBase + HybridSignatureService.SidecarExtension,
                policy);
            Require(shippedSignature.RsaPssValid, $"Shipped RSA-PSS/SHA-512 signature failed for {logicalName}.");
            Require(shippedSignature.Mldsa87Valid, $"Shipped post-quantum ML-DSA-87 signature failed for {logicalName}.");
        }

        string signedTarget = ResolveSignedComponent("zpaq.exe");
        string root = CreateTempRoot("keep-vault-hybrid-tamper-");
        try
        {
            string targetCopy = Path.Combine(root, "zpaq");
            string sidecarCopy = targetCopy + ".khsig";
            File.Copy(signedTarget, targetCopy);
            File.Copy(IntegrityService.ResolveSidecarBasePath(signedTarget) + ".khsig", sidecarCopy);
            HybridSignatureVerificationResult intact = HybridSignatureService.VerifyFile(targetCopy, sidecarCopy, policy);
            Require(intact.IsTrusted && intact.RsaPssValid && intact.Mldsa87Valid, "Copied signed bytes failed hybrid verification.");

            FlipByte(targetCopy, new FileInfo(targetCopy).Length / 2);
            HybridSignatureVerificationResult changedTarget = HybridSignatureService.VerifyFile(targetCopy, sidecarCopy, policy);
            Require(!changedTarget.IsTrusted, "One-bit native-component corruption passed hybrid verification.");

            File.Copy(signedTarget, targetCopy, overwrite: true);
            byte[] sidecar = File.ReadAllBytes(sidecarCopy);
            try
            {
                sidecar[^1] ^= 0x01;
                File.WriteAllBytes(sidecarCopy, sidecar);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(sidecar);
            }

            HybridSignatureVerificationResult changedSignature = HybridSignatureService.VerifyFile(targetCopy, sidecarCopy, policy);
            Require(!changedSignature.IsTrusted && !changedSignature.Mldsa87Valid, "One-bit ML-DSA signature corruption was accepted.");
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Every Mach-O file in the built bundle has to carry a hybrid signature.
    /// </summary>
    /// <remarks>
    /// The signing targets used to be a hand-written list, and three libraries
    /// that Avalonia brings along were not on it. They load into the process
    /// that holds the archive keys, so they were running on Apple's signature
    /// alone -- the single layer this app is built not to depend on. The build
    /// now enumerates the bundle instead of naming files, and this asserts the
    /// result, because the failure mode is silent: a bundle missing a signature
    /// starts and works exactly like one that has it.
    /// </remarks>
    private static Task TestBundleMachOClosureAsync()
    {
        string? bundle = LocateReleaseBundle();
        Require(
            bundle is not null,
            "No built Keep Vault.app was found. Run tools/Build-KeepVault-macOS.sh before the full suite.");

        string macOs = Path.Combine(bundle!, "Contents", "MacOS");
        string signatures = Path.Combine(bundle!, "Contents", "Resources", "HybridSignatures");
        var missing = new List<string>();
        int checkedFiles = 0;
        foreach (string file in Directory.EnumerateFiles(macOs, "*", SearchOption.AllDirectories))
        {
            if (!IsMachO(file))
            {
                continue;
            }

            checkedFiles++;
            string relative = Path.GetRelativePath(macOs, file);

            // The launcher is the bundle's main executable, so codesign writes
            // the bundle seal into it; its own signature has to live outside the
            // bundle and is checked by the launcher at every start.
            if (string.Equals(relative, "Keep Vault Launcher", StringComparison.Ordinal))
            {
                Require(
                    File.Exists(bundle + ".launcher.khsig"),
                    "The launcher's hybrid signature is missing beside the bundle.");
                continue;
            }

            if (!File.Exists(Path.Combine(signatures, relative + ".khsig")))
            {
                missing.Add(relative);
            }
        }

        Require(checkedFiles >= 10, $"Only {checkedFiles} Mach-O files were found in the bundle; the walk is wrong.");
        Require(missing.Count == 0, $"Mach-O files without a hybrid signature: {string.Join(", ", missing)}");
        return Task.CompletedTask;
    }

    /// <summary>
    /// The QR scanner has to be verifiable by Keep Vault against the same
    /// pinned keys, and a tampered signature has to be refused.
    /// </summary>
    /// <remarks>
    /// The scanner reads the two secret factors off the printed sheets and
    /// cannot vouch for itself. It shipped for a while with an Apple signature
    /// and nothing else, so nothing in the package could tell a replaced
    /// scanner from the real one.
    ///
    /// The negative half matters more than the positive one: a check that only
    /// ever runs against a good copy proves nothing, so this copies the bundle,
    /// corrupts the signature and asserts the refusal.
    /// </remarks>
    private static async Task TestCompanionScannerAsync()
    {
        string releaseRoot = Environment.GetEnvironmentVariable("KEEPVAULT_TEST_RELEASE_ROOT")
            ?? Path.Combine(RepositoryRoot(), "build", "dev", "Keep Vault-macOS");
        releaseRoot = Path.GetFullPath(releaseRoot);
        string keepVaultBundle = Path.Combine(releaseRoot, "Keep Vault.app");
        string scannerBundle = Path.Combine(releaseRoot, "QR-Scanner.app");
        Require(
            Directory.Exists(keepVaultBundle),
            "The final signed dist Keep Vault.app is missing; run tools/Build-KeepVault-macOS.sh before the full suite.");
        Require(
            Directory.Exists(scannerBundle),
            "The final signed dist QR-Scanner.app is missing; run tools/Build-KeepVault-macOS.sh before the full suite.");

        CompanionVerificationResult live = MacCompanionVerification.VerifyQrScannerPairForTests(
            keepVaultBundle,
            scannerBundle);
        Require(live.Found, $"The explicit final QR scanner was not found: {live.Message}");
        Require(live.Trusted, $"The explicit final release pair is not trusted: {live.Message}");

        string root = CreateTempRoot("keep-vault-scanner-");
        try
        {
            string bundle = Path.Combine(root, "QR-Scanner.app");
            CopyDirectory(live.Path!, bundle);
            foreach (string suffix in new[] { ".khsig", ".sha3", ".skein", ".sha3.khsig", ".skein.khsig" })
            {
                string sidecar = live.Path! + suffix;
                Require(File.Exists(sidecar), $"The scanner is missing its {suffix} sidecar.");
                File.Copy(sidecar, bundle + suffix);
            }

            CompanionVerificationResult copied = MacCompanionVerification.VerifyQrScannerPairForTests(
                keepVaultBundle,
                bundle);
            Require(copied.Trusted, $"The copied explicit scanner release did not verify: {copied.Message}");

            CompanionVerificationResult missingHost = MacCompanionVerification.VerifyQrScannerPairForTests(
                Path.Combine(root, "missing-keep-vault.app"),
                bundle);
            Require(
                missingHost.Found && !missingHost.Trusted,
                "Explicit companion verification silently fell back to the running process or an installed app.");

            HybridSignaturePolicy policy = SigningTrustPolicy.HybridPolicy
                ?? throw new InvalidOperationException("The compiled hybrid signing policy is unavailable.");
            string executable = Path.Combine(bundle, "Contents", "MacOS", "QR-Scanner");
            Require(
                HybridSignatureService.VerifyFile(executable, bundle + ".khsig", policy).IsTrusted,
                "The copied scanner did not verify, so the negative cases below would prove nothing.");

            byte[] signature = await File.ReadAllBytesAsync(bundle + ".khsig").ConfigureAwait(false);
            byte[] corrupted = [.. signature];
            corrupted[^64] ^= 0xFF;
            await File.WriteAllBytesAsync(bundle + ".khsig", corrupted).ConfigureAwait(false);
            Require(
                !HybridSignatureService.VerifyFile(executable, bundle + ".khsig", policy).IsTrusted,
                "A corrupted ML-DSA-87 signature was accepted for the scanner.");
            CompanionVerificationResult corruptedPair = MacCompanionVerification.VerifyQrScannerPairForTests(
                keepVaultBundle,
                bundle);
            Require(
                corruptedPair.Found && !corruptedPair.Trusted,
                "Explicit release-pair verification accepted a corrupted scanner signature.");

            await File.WriteAllBytesAsync(bundle + ".khsig", signature).ConfigureAwait(false);
            byte[] binary = await File.ReadAllBytesAsync(executable).ConfigureAwait(false);
            byte[] patched = [.. binary];
            patched[patched.Length / 2] ^= 0x01;
            await File.WriteAllBytesAsync(executable, patched).ConfigureAwait(false);
            Require(
                !HybridSignatureService.VerifyFile(executable, bundle + ".khsig", policy).IsTrusted,
                "A modified scanner binary was accepted against its unchanged signature.");
            CompanionVerificationResult patchedPair = MacCompanionVerification.VerifyQrScannerPairForTests(
                keepVaultBundle,
                bundle);
            Require(
                patchedPair.Found && !patchedPair.Trusted,
                "Explicit release-pair verification accepted a modified scanner executable.");

            File.Delete(bundle + ".khsig");
            Require(
                !HybridSignatureService.VerifyFile(executable, bundle + ".khsig", policy).IsTrusted,
                "A missing scanner signature was treated as valid.");

            // The scanner is held to the same SHA3-512/Skein-1024 dual manifest
            // as every other artifact, so a corrupted manifest and a manifest
            // that no longer describes the binary both have to be refused --
            // otherwise this component would be measured by fewer hashes than
            // the rest of the package.
            foreach (string suffix in new[] { ".sha3", ".skein" })
            {
                string manifestPath = bundle + suffix;
                Require(File.Exists(manifestPath), $"The scanner ships no {suffix} manifest.");
                Require(
                    HybridSignatureService.VerifyFile(
                        manifestPath,
                        manifestPath + HybridSignatureService.SidecarExtension,
                        policy).IsTrusted,
                    $"The scanner's {suffix} manifest is not signed by the pinned keys.");

                string original = await File.ReadAllTextAsync(manifestPath).ConfigureAwait(false);
                string flipped = original.TrimEnd();
                flipped = flipped[..^1] + (flipped[^1] == '0' ? '1' : '0');
                await File.WriteAllTextAsync(manifestPath, flipped).ConfigureAwait(false);
                Require(
                    !HybridSignatureService.VerifyFile(
                        manifestPath,
                        manifestPath + HybridSignatureService.SidecarExtension,
                        policy).IsTrusted,
                    $"A modified {suffix} manifest still passed its own signature check.");
                await File.WriteAllTextAsync(manifestPath, original).ConfigureAwait(false);
            }

            // And the manifests must actually describe this binary: the live
            // scanner's own manifests are checked against its own bytes.
            foreach ((string suffix, int hexLength) in new[] { (".sha3", 128), (".skein", 256) })
            {
                string expected = new(
                    (await File.ReadAllTextAsync(live.Path! + suffix).ConfigureAwait(false))
                        .Where(character => !char.IsWhiteSpace(character))
                        .ToArray());
                Require(
                    expected.Length == hexLength,
                    $"The installed scanner's {suffix} manifest is not {hexLength} hex characters.");
                byte[] liveBinary = await File.ReadAllBytesAsync(
                    Path.Combine(live.Path!, "Contents", "MacOS", "QR-Scanner")).ConfigureAwait(false);
                byte[] actual = suffix == ".sha3"
                    ? Sha3_512Compat.HashData(liveBinary)
                    : Skein1024Digest.HashData(liveBinary);
                Require(
                    string.Equals(Convert.ToHexString(actual), expected, StringComparison.OrdinalIgnoreCase),
                    $"The installed scanner does not match its {suffix} manifest.");
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static void CopyDirectory(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (string directory in Directory.EnumerateDirectories(source, "*", SearchOption.AllDirectories))
        {
            Directory.CreateDirectory(Path.Combine(destination, Path.GetRelativePath(source, directory)));
        }

        foreach (string file in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories))
        {
            File.Copy(file, Path.Combine(destination, Path.GetRelativePath(source, file)), overwrite: true);
        }
    }

    private static string? LocateReleaseBundle()
    {
        string[] candidates =
        [
            "/Applications/Keep Vault.app",
            Path.Combine(RepositoryRoot(), "dist", "Keep Vault-macOS", "Keep Vault.app"),
        ];
        return candidates.FirstOrDefault(Directory.Exists);
    }

    private static string RepositoryRoot()
    {
        for (string? directory = AppContext.BaseDirectory;
            directory is not null;
            directory = Path.GetDirectoryName(directory))
        {
            if (Directory.Exists(Path.Combine(directory, ".git")))
            {
                return directory;
            }
        }

        return AppContext.BaseDirectory;
    }

    private static bool IsMachO(string path)
    {
        Span<byte> magic = stackalloc byte[4];
        using FileStream stream = File.OpenRead(path);
        if (stream.ReadAtLeast(magic, magic.Length, throwOnEndOfStream: false) < magic.Length)
        {
            return false;
        }

        uint value = BinaryPrimitives.ReadUInt32BigEndian(magic);
        return value is 0xFEEDFACE or 0xFEEDFACF or 0xCEFAEDFE or 0xCFFAEDFE or 0xCAFEBABE or 0xBEBAFECA;
    }

    /// <summary>
    /// Salt and nonce have to be derivable for every single-round suite on the
    /// path that consumes the pools directly.
    /// </summary>
    /// <remarks>
    /// That path sized its nonce block at three digests. The widest single-round
    /// nonce is exactly 192 bytes, so it fitted to the byte and no test noticed;
    /// one suite with a wider nonce would have made it throw. Asking for every
    /// suite is what makes the size a property of the catalogue rather than a
    /// coincidence.
    /// </remarks>
    private static Task TestUnpreparedEncryptionParametersAsync()
    {
        foreach (EncryptionSuite suite in EncryptionSuiteCatalog.DisplayOrder)
        {
            EncryptionSuiteParameters parameters = EncryptionSuiteCatalog.Get(suite);
            AddMouseSamplesUntilReady();
            if (parameters.UsesTwoKdfRounds)
            {
                using TwoRoundEncryptionParameters twoRound =
                    EntropyMixer.CreateTwoRoundEncryptionParameters(suite);
                Require(
                    twoRound.FirstNonce.Bytes.Length == parameters.NonceBytes
                        && twoRound.SecondNonce.Bytes.Length == parameters.NonceBytes,
                    $"{suite} produced a two-round nonce of the wrong width.");
                Require(
                    !FixedEqual(twoRound.FirstSalt.Bytes, twoRound.SecondSalt.Bytes),
                    $"{suite} produced the same salt for both Argon2id rounds.");
                continue;
            }

            (LockedSensitiveBuffer salt, LockedSensitiveBuffer nonce) =
                EntropyMixer.CreateEncryptionParameters(suite);
            try
            {
                Require(
                    salt.Bytes.Length == EntropyMixer.SaltPairBytes,
                    $"{suite} produced a salt of the wrong width.");
                Require(
                    nonce.Bytes.Length == parameters.NonceBytes,
                    $"{suite} produced a nonce of the wrong width.");
                Require(
                    nonce.Bytes.AsSpan().IndexOfAnyExcept((byte)0) >= 0,
                    $"{suite} produced an all-zero nonce.");
            }
            finally
            {
                nonce.Dispose();
                salt.Dispose();
            }
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Checks the two KDF primitives against independent implementations
    /// before anything is built on top of them.
    /// </summary>
    /// <remarks>
    /// The specification forbids assuming an external API's semantics. Both of
    /// these are easy to get subtly wrong in a way no roundtrip would reveal:
    /// a Skein MAC that silently truncates, or an HKDF that expands one block
    /// short, still produces stable keys — just not the specified ones.
    ///
    /// HKDF-Expand is therefore recomputed here straight from RFC 5869 using
    /// the project's own HMAC-SHA3-512, and compared byte for byte against
    /// Bouncy Castle's generator.
    /// </remarks>
    private static Task TestKdfPrimitivesAsync()
    {
        // --- keyed Skein-MAC-1024-1024 -------------------------------------
        byte[] key = RandomNumberGenerator.GetBytes(256);
        byte[] message = RandomNumberGenerator.GetBytes(77);
        byte[] mac = KeyedSkein1024.Compute(key, "Keep Vault v12 test domain", message);
        byte[] independentMac = BouncyPersonalisedSkein(
            key,
            "Keep Vault v12 test domain",
            message);
        Require(mac.Length == 128, $"Skein-MAC-1024-1024 returned {mac.Length} bytes, not 128.");
        Require(
            FixedEqual(mac, independentMac),
            "The locked native personalised Skein-MAC differs from the independent Bouncy Castle implementation.");

        byte[] otherKey = [.. key];
        otherKey[0] ^= 0xFF;
        Require(
            !FixedEqual(mac, KeyedSkein1024.Compute(otherKey, "Keep Vault v12 test domain", message)),
            "The Skein MAC ignored a change in its key.");
        Require(
            !FixedEqual(mac, KeyedSkein1024.Compute(key, "a different domain", message)),
            "The Skein MAC ignored its personalisation, so role separation would collapse.");
        Require(
            !FixedEqual(mac, KeyedSkein1024.Compute(key, "Keep Vault v12 test domain", [.. message, 0x00])),
            "The Skein MAC ignored a change in its message.");

        // An unkeyed digest over key||message must not coincide with the keyed
        // MAC -- that is exactly the construction the specification forbids.
        Require(
            !FixedEqual(mac, Skein1024Digest.HashData([.. key, .. message])),
            "The keyed Skein MAC equals an unkeyed hash of key||message.");

        // --- HKDF-Expand with HMAC-SHA3-512 --------------------------------
        byte[] prk = RandomNumberGenerator.GetBytes(64);
        byte[] info = RandomNumberGenerator.GetBytes(40);
        foreach (int length in new[] { 1, 32, 64, 65, 100, 128, 256, 16320 })
        {
            byte[] fromBouncyCastle = Sha3HkdfExpand.Expand(prk, info, length);
            byte[] fromRfc = Rfc5869ExpandWithHmacSha3(prk, info, length);
            try
            {
                Require(
                    FixedEqual(fromBouncyCastle, fromRfc),
                    $"HKDF-Expand disagrees with RFC 5869 at {length} bytes.");
            }
            finally
            {
                Zero(fromBouncyCastle, fromRfc);
            }
        }

        // Test boundary refusal (> 255 blocks = > 16320 bytes)
        bool threwHkdfOverflow = false;
        try
        {
            _ = Sha3HkdfExpand.Expand(prk, info, 16321);
        }
        catch (ArgumentOutOfRangeException)
        {
            threwHkdfOverflow = true;
        }
        Require(threwHkdfOverflow, "HKDF-Expand did not reject length exceeding 255 blocks (16321 bytes).");

        // --- interleaving is a permutation ---------------------------------
        byte[] left = RandomNumberGenerator.GetBytes(64);
        byte[] right = RandomNumberGenerator.GetBytes(64);
        byte[] master = MasterInterleave.Interleave(left, right);
        Require(master.Length == 128, "The interleaved master is not 128 bytes.");
        for (int i = 0; i < 64; i++)
        {
            Require(master[2 * i] == left[i] && master[(2 * i) + 1] == right[i],
                "Interleaving did not place the branch bytes where the specification says.");
        }

        // A permutation loses nothing: both inputs come back out.
        var recoveredLeft = new byte[64];
        var recoveredRight = new byte[64];
        for (int i = 0; i < 64; i++)
        {
            recoveredLeft[i] = master[2 * i];
            recoveredRight[i] = master[(2 * i) + 1];
        }

        Require(
            FixedEqual(left, recoveredLeft) && FixedEqual(right, recoveredRight),
            "Interleaving is not lossless.");

        // --- role contexts are distinct ------------------------------------
        var contexts = new List<string>();
        foreach (int stage in new[] { 0, 1, 2 })
        {
            foreach (KeyRolePurpose purpose in Enum.GetValues<KeyRolePurpose>())
            {
                foreach (int bits in new[] { 256, 512, 1024 })
                {
                    contexts.Add(Convert.ToHexString(
                        SuiteKeySchedule.RoleContext("Suite-A", stage, "Threefish-1024", purpose, bits)));
                }
            }
        }

        Require(
            contexts.Count == contexts.Distinct(StringComparer.Ordinal).Count(),
            "Two different key roles share a canonical context.");

        // Different widths must not be prefixes of one another, which is what
        // truncating a single shared context would produce.
        byte[] master2 = RandomNumberGenerator.GetBytes(128);
        byte[] narrow = SuiteKeySchedule.DeriveRoleKey(
            master2, "Suite-A", 0, "AES-256", KeyRolePurpose.Encryption, 32);
        byte[] wide = SuiteKeySchedule.DeriveRoleKey(
            master2, "Suite-A", 0, "AES-256", KeyRolePurpose.Encryption, 64);
        Require(
            !narrow.SequenceEqual(wide[..32]),
            "A narrow role key is a prefix of a wider one from the same role.");

        // The role context must carry the current schedule version, so a role
        // key can never be reproduced under an older context serialization.
        Require(SuiteKeySchedule.ContextVersion == 12, "The role-key schedule no longer identifies itself as v12.");

        // --- canonical string mappings ------------------------------------
        Require(string.Equals(SuiteKeySchedule.CanonicalPurposeString(KeyRolePurpose.Encryption), "Encryption", StringComparison.Ordinal), "Canonical purpose string mapping mismatch.");
        Require(string.Equals(SuiteKeySchedule.CanonicalPurposeString(KeyRolePurpose.Sha3Mac), "Sha3Mac", StringComparison.Ordinal), "Canonical purpose string mapping mismatch.");
        Require(string.Equals(SuiteKeySchedule.CanonicalPurposeString(KeyRolePurpose.SkeinMac), "SkeinMac", StringComparison.Ordinal), "Canonical purpose string mapping mismatch.");
        Require(string.Equals(SuiteKeySchedule.CanonicalPurposeString(KeyRolePurpose.RecoverySha3Certification), "RecoverySha3Certification", StringComparison.Ordinal), "Canonical purpose string mapping mismatch.");
        Require(string.Equals(SuiteKeySchedule.CanonicalPurposeString(KeyRolePurpose.RecoverySkeinCertification), "RecoverySkeinCertification", StringComparison.Ordinal), "Canonical purpose string mapping mismatch.");

        Require(string.Equals(SuiteKeySchedule.CanonicalCipherString(CascadeCipher.Kalyna512_512), "Kalyna-512/512", StringComparison.Ordinal), "Canonical cipher string mapping mismatch.");
        Require(string.Equals(SuiteKeySchedule.CanonicalCipherString(CascadeCipher.Threefish1024), "Threefish-1024", StringComparison.Ordinal), "Canonical cipher string mapping mismatch.");
        Require(string.Equals(SuiteKeySchedule.CanonicalCipherString(CascadeCipher.Aes256), "AES-256", StringComparison.Ordinal), "Canonical cipher string mapping mismatch.");
        Require(string.Equals(SuiteKeySchedule.CanonicalCipherString(CascadeCipher.Mars448), "MARS-448", StringComparison.Ordinal), "Canonical cipher string mapping mismatch.");
        Require(string.Equals(SuiteKeySchedule.CanonicalCipherString(CascadeCipher.Shacal2_512), "SHACAL-2-512", StringComparison.Ordinal), "Canonical cipher string mapping mismatch.");
        Require(string.Equals(SuiteKeySchedule.CanonicalCipherString(CascadeCipher.ChaCha20Poly1305), "ChaCha20-Poly1305", StringComparison.Ordinal), "Canonical cipher string mapping mismatch.");

        // --- byte-exact Known Answer Tests for the v12 role schedule ---------
        // Format: LP(D_ROLE) || LE32(12) || LP(Algorithm) || LE32(StageIndex) || LP(Cipher) || LP(Purpose) || LE32(KeyBits)
        // Both context vectors are built independently from that documented
        // format, not read back out of this implementation.
        byte[] expectedRoleContext = Convert.FromHexString(
            "170000004B616C796E612D5A5041512F7631322F526F6C654B65790C0000000A0000004B616C796E612D353132000000000E0000004B616C796E612D3531322F3531320A000000456E6372797074696F6E00020000");
        byte[] actualRoleContext = SuiteKeySchedule.RoleContext(
            "Kalyna-512", 0, "Kalyna-512/512", KeyRolePurpose.Encryption, 512);
        Require(FixedEqual(actualRoleContext, expectedRoleContext), "Byte-exact KAT for the v12 RoleContext failed.");

        byte[] expectedSkeinMacCtx = Convert.FromHexString(
            "170000004B616C796E612D5A5041512F7631322F526F6C654B65790C0000000F000000506172616E6F696143617363616465FFFFFFFF13000000536B65696E2D4D41432D313032342D3130323408000000536B65696E4D616300040000");
        byte[] actualSkeinMacCtx = SuiteKeySchedule.GlobalRoleContext(
            "ParanoiaCascade", "Skein-MAC-1024-1024", KeyRolePurpose.SkeinMac, 1024);
        Require(FixedEqual(actualSkeinMacCtx, expectedSkeinMacCtx), "Byte-exact KAT for the v12 global Skein-MAC-1024-1024 RoleContext failed.");

        byte[] syntheticMaster = new byte[128];
        for (int i = 0; i < 128; i++) syntheticMaster[i] = (byte)((i * 7 + 13) % 256);

        // Frozen v12 role value for the synthetic master above. Generated once
        // out of band and pinned here; the two PRF families it combines are
        // covered by their own published-vector tests, so what this pins is the
        // v12 composition - which domains, which halves, and the XOR.
        byte[] expectedSkeinMacRoleKey = Convert.FromHexString(
            "50FE07FE258BC56042F1B6F1CA9FE015B6E84D808EADB0E590A689B827781B512"
            + "94625A24237D9255E3F924831836E7C420ED0E8D2284901D70075A545F5A5DE7B"
            + "05E0C6BB288A2D9088B9B79B34697FA564A2E8012BEEBDFCFC801B5EDF22BC6B0"
            + "05E4A8C2B24D883D480794CC88D32EE534AE834D2DC58F532E4BD0D6F18B9");
        byte[] actualSkeinMacRoleKey = SuiteKeySchedule.DeriveRoleValue(syntheticMaster, actualSkeinMacCtx);
        Require(
            FixedEqual(actualSkeinMacRoleKey, expectedSkeinMacRoleKey),
            $"Byte-exact KAT for the v12 Skein-MAC-1024-1024 role-key derivation failed: {Convert.ToHexString(actualSkeinMacRoleKey)}");

        // --- byte-exact KAT for the v12 Threefish-1024 CTR tweak --------------
        byte[] threefishNonce = new byte[128];
        for (int i = 0; i < 128; i++) threefishNonce[i] = (byte)(i + 1);
        byte[] expectedTweak = Convert.FromHexString("AB19B54D79B86101B023082BF768C290");
        byte[] actualTweak = KalynaContainerService.CreateSuiteTweak(EncryptionSuite.Threefish1024, threefishNonce);
        Require(FixedEqual(actualTweak, expectedTweak), "Byte-exact KAT for the v12 Threefish-1024 CTR tweak failed.");

        Zero(key, message, mac, independentMac, otherKey, prk, info, left, right, master, master2, narrow, wide,
            syntheticMaster, expectedRoleContext, actualRoleContext, expectedSkeinMacCtx, actualSkeinMacCtx,
            expectedSkeinMacRoleKey, actualSkeinMacRoleKey,
            threefishNonce, expectedTweak, actualTweak);
        return Task.CompletedTask;
    }

    private static Task TestPinCreationPolicyAsync()
    {
        // Valid creation PINs
        string[] validPins = ["428317", "84920153", "19482736", "3819405627", "9274018365"];
        foreach (string pin in validPins)
        {
            PinPolicyAnalysis analysis = ContainerKeyDerivation.AnalyzePinForCreation(pin);
            Require(analysis.IsAccepted, $"Valid PIN '{pin}' was rejected: {string.Join(", ", analysis.Violations)}");
            ContainerKeyDerivation.ValidatePinForCreation(pin);
            ContainerKeyDerivation.ValidatePinSyntax(pin);
        }

        // Invalid syntax PINs
        string[] syntaxInvalidPins = ["", "12345", "12345678901234567", "12a456", "12 456", "12-456", "12345!"];
        foreach (string pin in syntaxInvalidPins)
        {
            PinPolicyAnalysis analysis = ContainerKeyDerivation.AnalyzePinForCreation(pin);
            Require(!analysis.IsAccepted, $"Syntax-invalid PIN '{pin}' was accepted.");
            bool threwCreation = false;
            try { ContainerKeyDerivation.ValidatePinForCreation(pin); } catch (Exception) { threwCreation = true; }
            Require(threwCreation, $"ValidatePinForCreation did not throw for syntax-invalid PIN '{pin}'.");

            bool threwSyntax = false;
            try { ContainerKeyDerivation.ValidatePinSyntax(pin); } catch (Exception) { threwSyntax = true; }
            Require(threwSyntax, $"ValidatePinSyntax did not throw for syntax-invalid PIN '{pin}'.");
        }

        // Creation-policy violation PINs (valid syntax 6-16 digits, but weak)
        (string Pin, PinPolicyViolation ExpectedViolation)[] weakPins =
        [
            ("000000", PinPolicyViolation.RepeatedDigitsTriple),
            ("111111", PinPolicyViolation.RepeatedDigitsTriple),
            ("111222", PinPolicyViolation.RepeatedDigitsTriple),
            ("123456", PinPolicyViolation.SequentialAscending),
            ("012345", PinPolicyViolation.SequentialAscending),
            ("987654", PinPolicyViolation.SequentialDescending),
            ("654321", PinPolicyViolation.SequentialDescending),
            ("121212", PinPolicyViolation.Blocklisted),
            ("112233", PinPolicyViolation.Blocklisted),
            ("123123", PinPolicyViolation.Blocklisted),
            ("12341234", PinPolicyViolation.Blocklisted),
            ("111234", PinPolicyViolation.RepeatedDigitsTriple),
            ("112211", PinPolicyViolation.NotEnoughDistinctDigits),
            ("112212", PinPolicyViolation.NotEnoughDistinctDigits),
            ("147258", PinPolicyViolation.Blocklisted),
            ("258147", PinPolicyViolation.Blocklisted),
            ("369258", PinPolicyViolation.Blocklisted),
            ("159357", PinPolicyViolation.Blocklisted),
            ("753951", PinPolicyViolation.Blocklisted),
        ];

        foreach (var (pin, expectedViolation) in weakPins)
        {
            PinPolicyAnalysis analysis = ContainerKeyDerivation.AnalyzePinForCreation(pin);
            Require(!analysis.IsAccepted, $"Weak PIN '{pin}' was accepted by creation policy.");
            Require(analysis.Violations.Contains(expectedViolation),
                $"Weak PIN '{pin}' did not report expected violation '{expectedViolation}'. Got: {string.Join(", ", analysis.Violations)}");

            bool threw = false;
            try { ContainerKeyDerivation.ValidatePinForCreation(pin); } catch (PinPolicyException) { threw = true; }
            Require(threw, $"ValidatePinForCreation did not throw PinPolicyException for weak PIN '{pin}'.");

            // Extraction syntax validation must pass for these weak PINs (so existing archives can still be opened)
            ContainerKeyDerivation.ValidatePinSyntax(pin);
        }

        // 13..16 digit strong PINs: valid for both syntax and creation
        string[] longCreationPins = ["1948273645019", "92740183652847", "381940562718294", "4283179501628374"];
        foreach (string pin in longCreationPins)
        {
            PinPolicyAnalysis analysis = ContainerKeyDerivation.AnalyzePinForCreation(pin);
            Require(analysis.IsAccepted, $"13..16 digit valid PIN '{pin}' was rejected: {string.Join(", ", analysis.Violations)}");
            ContainerKeyDerivation.ValidatePinForCreation(pin);
            ContainerKeyDerivation.ValidatePinSyntax(pin);
        }

        // >16 digit PINs: rejected by both creation policy and syntax
        string[] tooLongPins = ["12345678901234567", "9876543210987654321"];
        foreach (string pin in tooLongPins)
        {
            PinPolicyAnalysis analysis = ContainerKeyDerivation.AnalyzePinForCreation(pin);
            Require(!analysis.IsAccepted, $"Too-long PIN '{pin}' was accepted by creation policy.");
            Require(analysis.Violations.Contains(PinPolicyViolation.TooLong),
                $"Too-long PIN '{pin}' did not report TooLong violation.");

            bool threwCreation = false;
            try { ContainerKeyDerivation.ValidatePinForCreation(pin); } catch (Exception) { threwCreation = true; }
            Require(threwCreation, $"ValidatePinForCreation did not throw for PIN '{pin}'.");

            bool threwSyntax = false;
            try { ContainerKeyDerivation.ValidatePinSyntax(pin); } catch (Exception) { threwSyntax = true; }
            Require(threwSyntax, $"ValidatePinSyntax did not throw for PIN '{pin}'.");
        }

        return Task.CompletedTask;
    }

    private static Task TestPasswordPolicyAsync()
    {
        const string strongPass = "N!r7$Vq2#Lm8%Tx3&Jd9*Wp4+Kg5=Zu6?Ce";
        PasswordPolicyAnalysis strong = PasswordKeyService.AnalyzeUserPassword(strongPass);
        Require(strong.IsAccepted, $"Strong password was rejected: {string.Join(", ", strong.Violations)}");

        // Verify common term detection: KEEPVAULT penalizes entropy by 32 bits
        string basePassword = "KeepVault!@#$123456789XyZ#";
        PasswordPolicyAnalysis termAnalysis = PasswordKeyService.AnalyzeUserPassword(basePassword);
        Require(termAnalysis.ConservativeEntropyBits < 128.0 || !termAnalysis.IsAccepted,
            $"Password containing common term KEEPVAULT should suffer severe entropy penalty. Got: {termAnalysis.ConservativeEntropyBits} bits.");

        // Verify other weak patterns
        PasswordPolicyAnalysis hexAnalysis = PasswordKeyService.AnalyzeUserPassword("0123456789abcdef01234567");
        Require(!hexAnalysis.IsAccepted, "Predictable hex password was accepted.");

        PasswordPolicyAnalysis shortAnalysis = PasswordKeyService.AnalyzeUserPassword("short");
        Require(!shortAnalysis.IsAccepted, "Short password was accepted.");

        return Task.CompletedTask;
    }

    /// <summary>
    /// Exercises the master derivation: that every credential reaches both
    /// paths, that PMI stays inside its quantised range, and that Paranoia's
    /// second round genuinely depends on the first.
    /// </summary>
    /// <remarks>
    /// The credential and PMI checks are cheap. The Argon2id branches are not —
    /// each is at least a gibibyte — so the expensive part runs the smallest
    /// number of real rounds that can still distinguish a correct chaining from
    /// the earlier chaining defect.
    /// </remarks>
    private static async Task TestKdfPropertiesAsync()
    {
        const string Algorithm = "Test-Suite-v12-properties";
        const string Password = "N!r7$Vq2#Lm8%Tx3&Jd9*Wp4+Kg5=Zu6?Ce";
        const string Pin = "0428193";
        byte[] factorA = RandomNumberGenerator.GetBytes(128);
        byte[] factorB = RandomNumberGenerator.GetBytes(128);

        // --- credential paths ----------------------------------------------
        byte[] qs = V12MasterKdf.DeriveSha3CredentialHash(Algorithm, Password, Pin, factorA, factorB);
        byte[] qk = V12MasterKdf.DeriveSkeinCredentialHash(Algorithm, Password, Pin, factorA, factorB);
        Require(qs.Length == 128 && qk.Length == 128, "A credential hash is not 1024 bits.");
        Require(!FixedEqual(qs, qk), "Both credential paths produced the same value.");

        // Each of the four secrets has to reach each path. A path that ignores
        // one of them would still round-trip perfectly.
        byte[] otherA = [.. factorA]; otherA[0] ^= 0xFF;
        byte[] otherB = [.. factorB]; otherB[127] ^= 0xFF;
        foreach ((string label, byte[] changedQs, byte[] changedQk) in new[]
        {
            ("user password", V12MasterKdf.DeriveSha3CredentialHash(Algorithm, Password + "x", Pin, factorA, factorB),
                              V12MasterKdf.DeriveSkeinCredentialHash(Algorithm, Password + "x", Pin, factorA, factorB)),
            ("PIN",           V12MasterKdf.DeriveSha3CredentialHash(Algorithm, Password, "0428194", factorA, factorB),
                              V12MasterKdf.DeriveSkeinCredentialHash(Algorithm, Password, "0428194", factorA, factorB)),
            ("factor A",      V12MasterKdf.DeriveSha3CredentialHash(Algorithm, Password, Pin, otherA, factorB),
                              V12MasterKdf.DeriveSkeinCredentialHash(Algorithm, Password, Pin, otherA, factorB)),
            ("factor B",      V12MasterKdf.DeriveSha3CredentialHash(Algorithm, Password, Pin, factorA, otherB),
                              V12MasterKdf.DeriveSkeinCredentialHash(Algorithm, Password, Pin, factorA, otherB)),
        })
        {
            Require(!FixedEqual(qs, changedQs), $"The SHA3 credential path ignores the {label}.");
            Require(!FixedEqual(qk, changedQk), $"The Skein credential path ignores the {label}.");
        }

        // A leading zero in the PIN has to be significant.
        Require(
            !FixedEqual(qs, V12MasterKdf.DeriveSha3CredentialHash(Algorithm, Password, "428193", factorA, factorB)),
            "A leading zero in the PIN was discarded.");

        // --- PMI ------------------------------------------------------------
        byte[] saltSha3 = Enumerable.Range(0, 64).Select(i => (byte)(i * 3 + 1)).ToArray();
        byte[] saltSkein = Enumerable.Range(0, 64).Select(i => (byte)(i * 5 + 7)).ToArray();
        byte[] saltSha3Alt = Enumerable.Range(0, 64).Select(i => (byte)(i * 7 + 11)).ToArray();
        byte[] saltSkeinAlt = Enumerable.Range(0, 64).Select(i => (byte)(i * 11 + 13)).ToArray();
        (ushort pmi, uint memory) = V12MasterKdf.DerivePmi(
            Algorithm, 1, qs, qk, [], saltSha3, saltSkein);
        Require(
            memory >= V12MasterKdf.MemoryMinKiB && memory <= V12MasterKdf.MemoryMaxKiB,
            $"The derived memory cost {memory} KiB is outside 1 GiB..2 GiB-16 KiB.");
        Require(
            (memory - V12MasterKdf.MemoryMinKiB) % V12MasterKdf.MemoryStepKiB == 0,
            "The derived memory cost is not on the 16 KiB grid.");
        Require(
            memory == V12MasterKdf.MemoryMinKiB + (16u * pmi),
            "The memory cost does not follow m = 1 GiB + 16*PMI.");
        (ushort pmiAgain, _) = V12MasterKdf.DerivePmi(Algorithm, 1, qs, qk, [], saltSha3, saltSkein);
        Require(pmi == pmiAgain, "PMI is not deterministic.");
        (ushort pmiOtherSalt, _) = V12MasterKdf.DerivePmi(
            Algorithm, 1, qs, qk, [], saltSha3, saltSkeinAlt);
        (ushort pmiRound2, _) = V12MasterKdf.DerivePmi(
            Algorithm, 2, qs, qk, [], saltSha3, saltSkein);
        (ushort pmiAltSha3, _) = V12MasterKdf.DerivePmi(
            Algorithm, 1, qs, qk, [], saltSha3Alt, saltSkein);
        Require(
            pmi != pmiOtherSalt,
            "PMI ignored the second salt.");
        Require(
            pmi != pmiRound2,
            "PMI ignored the round number.");
        Require(
            pmi != pmiAltSha3,
            "PMI ignored the first salt.");

        // --- salt separation is enforced ------------------------------------
        RequireThrows<CryptographicException>(
            () => new KdfSalts(saltSha3, [.. saltSha3], null, null).Validate(paranoia: false),
            "Two identical salts were accepted.");
        RequireThrows<CryptographicException>(
            () => new KdfSalts(saltSha3, saltSkein, saltSha3, saltSkein).Validate(paranoia: true),
            "Paranoia accepted repeated salts across its two rounds.");
        new KdfSalts(saltSha3, saltSkein, null, null).Validate(paranoia: false);

        // --- associated data separates the branches --------------------------
        Require(
            !V12MasterKdf.AssociatedData(Algorithm, true, 1)
                .SequenceEqual(V12MasterKdf.AssociatedData(Algorithm, false, 1)),
            "Both Argon2 branches of a round share associated data.");
        Require(
            !V12MasterKdf.AssociatedData(Algorithm, true, 1)
                .SequenceEqual(V12MasterKdf.AssociatedData(Algorithm, true, 2)),
            "Both Paranoia rounds share associated data on the same branch.");

        // --- the real rounds -------------------------------------------------
        // Fixed salts, so the whole group is deterministic. The exact answers
        // are pinned separately by the v12 known-answer group; what this proves
        // is the chaining, which fixed vectors alone would not distinguish from
        // a round two that ignores round one.
        byte[] katSaltSha3Round1 = Enumerable.Range(0, 64).Select(i => (byte)((i * 17) + 5)).ToArray();
        byte[] katSaltSkeinRound1 = Enumerable.Range(0, 64).Select(i => (byte)((i * 19) + 23)).ToArray();
        byte[] saltSha3Round2 = Enumerable.Range(0, 64).Select(i => (byte)((i * 29) + 31)).ToArray();
        byte[] saltSkeinRound2 = Enumerable.Range(0, 64).Select(i => (byte)((i * 37) + 41)).ToArray();
        (_, uint katMemory1) = V12MasterKdf.DerivePmi(
            Algorithm, 1, qs, qk, [], katSaltSha3Round1, katSaltSkeinRound1);

        byte[] round1 = V12MasterKdf.DeriveRoundMaster(
            Algorithm, 1, qs, qk, katSaltSha3Round1, katSaltSkeinRound1, secret: null, katMemory1);
        Require(round1.Length == 128, "The round master is not 1024 bits.");
        Require(
            !round1.AsSpan(0, 64).SequenceEqual(round1.AsSpan(64, 64)),
            "Both halves of the master are identical, so the two branches agreed.");

        // Deterministic for identical inputs.
        byte[] round1Again = V12MasterKdf.DeriveRoundMaster(
            Algorithm, 1, qs, qk, katSaltSha3Round1, katSaltSkeinRound1, secret: null, katMemory1);
        Require(FixedEqual(round1, round1Again), "The round master is not deterministic.");

        // Paranoia round 2 takes round 1's whole master as the Argon2 secret.
        (_, uint memory2) = V12MasterKdf.DerivePmi(
            Algorithm, 2, qs, qk, round1, saltSha3Round2, saltSkeinRound2);
        byte[] round2 = V12MasterKdf.DeriveRoundMaster(
            Algorithm, 2, qs, qk, saltSha3Round2, saltSkeinRound2, secret: round1, memory2);

        // This is the round-chaining regression, stated the only way that proves
        // anything: the same round 2 computed with a different secret, and with
        // no secret at all, must both differ. The old defect made round 2
        // independent of what came before it.
        byte[] wrongSecret = [.. round1];
        wrongSecret[0] ^= 0xFF;
        byte[] round2WrongSecret = V12MasterKdf.DeriveRoundMaster(
            Algorithm, 2, qs, qk, saltSha3Round2, saltSkeinRound2, secret: wrongSecret, memory2);
        Require(
            !FixedEqual(round2, round2WrongSecret),
            "Paranoia round 2 ignored a one-bit change in round 1's master.");

        byte[] round2NoSecret = V12MasterKdf.DeriveRoundMaster(
            Algorithm, 2, qs, qk, saltSha3Round2, saltSkeinRound2, secret: null, memory2);
        Require(
            !FixedEqual(round2, round2NoSecret),
            "Paranoia round 2 produced the same master with and without the round-1 secret.");

        // The master buffers survive the native calls that clear their copies.
        byte[] round1AfterUse = V12MasterKdf.DeriveRoundMaster(
            Algorithm, 1, qs, qk, katSaltSha3Round1, katSaltSkeinRound1, secret: null, katMemory1);
        Require(
            FixedEqual(round1, round1AfterUse),
            "A credential master changed after being used for an Argon2 call.");

        // --- role keys off the final master ----------------------------------
        byte[] encryptionKey = SuiteKeySchedule.DeriveRoleKey(
            round2, Algorithm, 0, "AES-256", KeyRolePurpose.Encryption, 32);
        byte[] macKey = SuiteKeySchedule.DeriveGlobalKey(
            round2, Algorithm, "HMAC-SHA3-512", KeyRolePurpose.Sha3Mac, 64);
        Require(encryptionKey.Length == 32 && macKey.Length == 64, "A role key has the wrong width.");
        Require(
            !encryptionKey.SequenceEqual(macKey[..32]),
            "An encryption key and a MAC key share material.");
        Require(
            !SuiteKeySchedule.DeriveRoleKey(round2, Algorithm, 0, "AES-256", KeyRolePurpose.Encryption, 32)
                .SequenceEqual(SuiteKeySchedule.DeriveRoleKey(round2, Algorithm, 1, "AES-256", KeyRolePurpose.Encryption, 32)),
            "The same cipher in two cascade stages received the same key.");

        await Task.CompletedTask.ConfigureAwait(false);
        Zero(factorA, factorB, qs, qk, otherA, otherB, saltSha3, saltSkein,
            round1, round1Again, round2, wrongSecret, round2WrongSecret, round2NoSecret,
            round1AfterUse, katSaltSha3Round1, katSaltSkeinRound1, saltSha3Round2, saltSkeinRound2,
            encryptionKey, macKey);
    }

    /// <summary>
    /// RFC 5869 section 2.3 expand, written out directly against the project's
    /// own HMAC-SHA3-512 so it shares no code with the implementation it checks.
    /// </summary>
    private static byte[] Rfc5869ExpandWithHmacSha3(byte[] prk, byte[] info, int length)
    {
        const int HashLength = 64;
        int blocks = (length + HashLength - 1) / HashLength;
        Require(blocks <= 255, "RFC 5869 allows at most 255 blocks.");
        byte[] output = new byte[length];
        byte[] previous = [];
        int written = 0;
        for (int counter = 1; counter <= blocks; counter++)
        {
            using var hmac = new HmacSha3_512(prk);
            hmac.AppendData(previous);
            hmac.AppendData(info);
            hmac.AppendData([(byte)counter]);
            previous = hmac.GetHashAndReset();
            int take = Math.Min(HashLength, length - written);
            previous.AsSpan(0, take).CopyTo(output.AsSpan(written));
            written += take;
        }

        CryptographicOperations.ZeroMemory(previous);
        return output;
    }

    private static Task TestPrimitiveVectorsAsync()
    {
        RequireHex(
            Sha3_512Compat.HashData([]),
            "A69F73CCA23A9AC5C8B567DC185A756E97C982164FE25859E0D1DCC1475C80A615B2123AF1F5F94C11E3E9402C3AC558F500199D95B6D3E301758586281DCD26",
            "SHA3-512 empty-message FIPS 202 vector");
        RequireHex(
            Sha3_512Compat.HashData("abc"u8),
            "B751850B1A57168A5693CD924B6B096E08F621827444F70D884F5D0240D2712E10E116E9192AF3C91A7EC57647E3934057340B4CF408D5A56592F8274EEC53F0",
            "SHA3-512 abc FIPS 202 vector");

        byte[] skeinMessage = [0xFF];
        byte[] expectedSkein = Convert.FromHexString(
            "E62C05802EA0152407CDD8787FDA9E35703DE862A4FBC119CFF8590AFE79250B" +
            "CCC8B3FAF1BD2422AB5C0D263FB2F8AFB3F796F048000381531B6F00D85161BC" +
            "0FFF4BEF2486B1EBCD3773FABF50AD4AD5639AF9040E3F29C6C931301BF79832" +
            "E9DA09857E831E82EF8B4691C235656515D437D2BDA33BCEC001C67FFDE15BA8");
        byte[] managedSkein = Skein1024Digest.HashData(skeinMessage);
        byte[] nativeSkein = NativeThreefish.HashSkein1024Reference(skeinMessage);
        try
        {
            Require(FixedEqual(expectedSkein, managedSkein), "Managed Skein-1024 failed the official 8-bit KAT.");
            Require(FixedEqual(expectedSkein, nativeSkein), "Native Skein-1024 failed the official 8-bit KAT.");
        }
        finally
        {
            Zero(skeinMessage, expectedSkein, managedSkein, nativeSkein);
        }

        byte[] skeinKey = Convert.FromHexString(
            "CB41F1706CDE09651203C2D0EFBADDF847A0D315CB2E53FF8BAC41DA0002672E" +
            "920244C66E02D5F0DAD3E94C42BB65F0D14157DECF4105EF5609D5B0984457C1" +
            "935DF3061FF06E9F204192BA11E5BB2CAC0430C1C370CB3D113FEA5EC1021EB8" +
            "75E5946D7A96AC69A1626C6206B7252736F24253C9EE9B85EB852DFC81463134");
        byte[] expectedMac = Convert.FromHexString(
            "BCF37B3459C88959D6B6B58B2BFE142CEF60C6F4EC56B0702480D7893A2B0595" +
            "AA354E87102A788B61996B9CBC1EADE7DAFBF6581135572C09666D844C90F066" +
            "B800FC4F5FD1737644894EF7D588AFC5C38F5D920BDBD3B738AEA3A3267D161E" +
            "D65284D1F57DA73B68817E17E381CA169115152B869C66B812BB9A84275303F0");
        byte[] nativeMac = NativeThreefish.MacSkein1024Reference(skeinKey, []);
        byte[] independentMac = BouncySkeinMac(skeinKey, []);
        try
        {
            Require(FixedEqual(expectedMac, nativeMac), "Native Skein-1024 MAC failed the official empty-message KAT.");
            Require(FixedEqual(expectedMac, independentMac), "Independent Skein-1024 MAC failed the official KAT.");
        }
        finally
        {
            Zero(skeinKey, expectedMac, nativeMac, independentMac);
        }

        TestKalynaVectorAndParallelism();
        TestThreefishVectorAndParallelism();
        return Task.CompletedTask;
    }

    private static void TestKalynaVectorAndParallelism()
    {
        byte[] key = Enumerable.Range(0, 64).Select(value => (byte)value).ToArray();
        byte[] nonce = Enumerable.Range(0x40, 64).Select(value => (byte)value).ToArray();
        byte[] zero = new byte[64];
        byte[] actual = new byte[64];
        byte[] expected = WordsToLittleEndian(
        [
            0x6a351c811be3264aUL, 0x1a239605cad61da6UL,
            0xa1f347aa5483ba67UL, 0xb856eb20c3ee1d3eUL,
            0x66ab5b1717f4d095UL, 0x6cc815bb34f1d62fUL,
            0xb7fe6e85266a90cbUL, 0xd9d90d947264bcc5UL,
        ]);
        try
        {
            Require(NativeKalyna.IsAvailable(), "Native Kalyna is unavailable after trust validation.");
            NativeKalyna.XCryptCtr512(key, nonce, zero, actual);
            Require(FixedEqual(expected, actual), "Kalyna-512/512 failed the reference CTR block vector.");

            byte[] input = RandomNumberGenerator.GetBytes((10 * 1024 * 1024) + 333);
            byte[] parallel = new byte[input.Length];
            byte[] serial = new byte[input.Length];
            try
            {
                NativeKalyna.XCryptCtr512(key, nonce, input, parallel, input.Length);
                SerialKalyna(key, nonce, input, serial);
                Require(FixedEqual(parallel, serial), "Parallel Kalyna CTR differs from serial counter composition.");
                NativeKalyna.XCryptCtr512(key, nonce, parallel, serial, parallel.Length);
                Require(FixedEqual(input, serial), "Kalyna CTR roundtrip failed.");
            }
            finally
            {
                Zero(input, parallel, serial);
            }
        }
        finally
        {
            Zero(key, nonce, zero, actual, expected);
        }
    }

    private static void TestThreefishVectorAndParallelism()
    {
        byte[] zeroKey = new byte[128];
        byte[] zeroTweak = new byte[16];
        byte[] zeroBlock = new byte[128];
        byte[] actual = new byte[128];
        byte[] expected = WordsToLittleEndian(
        [
            0x04B3053D0A3D5CF0UL, 0x0136E0D1C7DD85F7UL,
            0x067B212F6EA78A5CUL, 0x0DA9C10B4C54E1C6UL,
            0x0F4EC27394CBACF0UL, 0x32437F0568EA4FD5UL,
            0xCFF56D1D7654B49CUL, 0xA2D5FB14369B2E7BUL,
            0x540306B460472E0BUL, 0x71C18254BCEA820DUL,
            0xC36B4068BEAF32C8UL, 0xFA4329597A360095UL,
            0xC4A36C28434A5B9AUL, 0xD54331444B1046CFUL,
            0xDF11834830B2A460UL, 0x1E39E8DFE1F7EE4FUL,
        ]);
        try
        {
            Require(NativeThreefish.IsAvailable(), "Native Threefish is unavailable after trust validation.");
            NativeThreefish.EncryptBlock1024(zeroKey, zeroTweak, zeroBlock, actual);
            Require(FixedEqual(expected, actual), "Threefish-1024 failed the official Skein 1.3 zero vector.");

            for (int index = 0; index < 24; index++)
            {
                byte[] key = RandomNumberGenerator.GetBytes(128);
                byte[] tweak = RandomNumberGenerator.GetBytes(16);
                byte[] input = RandomNumberGenerator.GetBytes(128);
                byte[] native = new byte[128];
                byte[] independent = new byte[128];
                try
                {
                    NativeThreefish.EncryptBlock1024(key, tweak, input, native);
                    var engine = new ThreefishEngine(ThreefishEngine.BLOCKSIZE_1024);
                    engine.Init(true, new TweakableBlockCipherParameters(new KeyParameter(key), tweak));
                    Require(engine.ProcessBlock(input, 0, independent, 0) == 128, "Independent Threefish wrote an invalid block length.");
                    Require(FixedEqual(native, independent), $"Native Threefish differs from Bouncy Castle at vector {index}.");
                }
                finally
                {
                    Zero(key, tweak, input, native, independent);
                }
            }

            byte[] parallelKey = RandomNumberGenerator.GetBytes(128);
            byte[] parallelTweak = RandomNumberGenerator.GetBytes(16);
            byte[] nonce = RandomNumberGenerator.GetBytes(128);
            byte[] data = RandomNumberGenerator.GetBytes((10 * 1024 * 1024) + 333);
            byte[] parallel = new byte[data.Length];
            byte[] serial = new byte[data.Length];
            try
            {
                NativeThreefish.XCryptCtr1024(parallelKey, parallelTweak, nonce, data, parallel, data.Length);
                SerialThreefish(parallelKey, parallelTweak, nonce, data, serial);
                Require(FixedEqual(parallel, serial), "Parallel Threefish CTR differs from serial counter composition.");
                NativeThreefish.XCryptCtr1024(parallelKey, parallelTweak, nonce, parallel, serial, parallel.Length);
                Require(FixedEqual(data, serial), "Threefish CTR roundtrip failed.");
            }
            finally
            {
                Zero(parallelKey, parallelTweak, nonce, data, parallel, serial);
            }
        }
        finally
        {
            Zero(zeroKey, zeroTweak, zeroBlock, actual, expected);
        }
    }

    private static Task TestMldsaInteropAsync()
    {
        string referencePath = Environment.GetEnvironmentVariable("KEEPVAULT_MLDSA_REFERENCE")
            ?? Path.Combine(AppContext.BaseDirectory, "Native", "libmldsa87_ref.dylib");
        Require(File.Exists(referencePath), $"ML-DSA-87 reference adapter is missing: {referencePath}");
        using var reference = new Mldsa87Reference(referencePath);
        (byte[] publicKey, byte[] privateKey) = reference.GenerateKeyPair();
        byte[] message = Sha3_512Compat.HashData("Keep Vault ML-DSA-87 FIPS 204 interoperability"u8);
        byte[] managedSignature = Mldsa87.Sign(message, privateKey);
        byte[] referenceSignature = reference.Sign(message, privateKey);
        try
        {
            Require(publicKey.Length == Mldsa87.PublicKeyBytes, "ML-DSA-87 public-key length mismatch.");
            Require(privateKey.Length == Mldsa87.PrivateKeyBytes, "ML-DSA-87 private-key length mismatch.");
            Require(managedSignature.Length == Mldsa87.SignatureBytes, "ML-DSA-87 signature length mismatch.");
            Require(reference.Verify(message, managedSignature, publicKey), "Official reference rejected the managed ML-DSA signature.");
            Require(Mldsa87.Verify(message, referenceSignature, publicKey), "Managed verifier rejected the official ML-DSA signature.");

            byte[] changedMessage = message.ToArray();
            byte[] changedSignature = managedSignature.ToArray();
            byte[] changedKey = publicKey.ToArray();
            try
            {
                changedMessage[0] ^= 0x80;
                changedSignature[changedSignature.Length / 2] ^= 0x01;
                changedKey[^1] ^= 0x01;
                Require(!reference.Verify(changedMessage, managedSignature, publicKey), "ML-DSA accepted a changed message.");
                Require(!reference.Verify(message, changedSignature, publicKey), "ML-DSA accepted a changed signature.");
                Require(!Mldsa87.Verify(message, managedSignature, changedKey), "ML-DSA accepted a changed public key.");
            }
            finally
            {
                Zero(changedMessage, changedSignature, changedKey);
            }

            byte[] secondSignature = Mldsa87.Sign(message, privateKey);
            try
            {
                Require(!FixedEqual(managedSignature, secondSignature), "Hedged ML-DSA signing reused identical randomness.");
                Require(reference.Verify(message, secondSignature, publicKey), "Official reference rejected a second hedged signature.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(secondSignature);
            }
        }
        finally
        {
            Zero(publicKey, privateKey, message, managedSignature, referenceSignature);
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Compares every primitive the app computes in managed code against its
    /// official reference implementation, over randomised inputs.
    /// </summary>
    /// <remarks>
    /// Fixed known-answer vectors prove a primitive agrees at a handful of
    /// points. They do not catch the failures that actually occur in practice:
    /// mishandled block boundaries, a wrong rate, incremental updates that
    /// disagree with the one-shot call, or lengths that only go wrong past a
    /// buffer size. Randomised differential testing across those boundaries
    /// does, and it matters most here because SHA3-512 and Skein-1024 come from
    /// Bouncy Castle rather than from the references — every container tag,
    /// integrity manifest and key-derivation pre-hash depends on that library
    /// being right.
    ///
    /// ZPAQ is deliberately absent: its pipeline was adapted for this app's
    /// encryption, so stock zpaq is not a valid oracle for it. Its behaviour is
    /// covered instead by the round-trip, traversal and malformed-corpus group.
    /// </remarks>
    /// <summary>
    /// Covers the gate that guards deleting a user's only copy of a file.
    /// </summary>
    /// <remarks>
    /// The archiving option deletes originals only after the archive has been
    /// extracted again and compared byte for byte. What matters is not that the
    /// happy path works but that every way the comparison can fail actually
    /// blocks the deletion, so each failure mode is provoked deliberately: a
    /// changed byte, a file the archive lost, and a file the archive gained.
    /// </remarks>
    private static async Task TestVerifiedOriginalDeletionAsync()
    {
        string root = CreateTempRoot("keep-vault-delete-verify-");
        try
        {
            string originals = Path.Combine(root, "originals");
            string extracted = Path.Combine(root, "extracted");
            Directory.CreateDirectory(originals);
            Directory.CreateDirectory(extracted);

            string firstName = "first.bin";
            string secondName = "second.bin";
            byte[] first = RandomNumberGenerator.GetBytes(64 * 1024);
            byte[] second = RandomNumberGenerator.GetBytes(4096);
            await File.WriteAllBytesAsync(Path.Combine(originals, firstName), first).ConfigureAwait(false);
            await File.WriteAllBytesAsync(Path.Combine(originals, secondName), second).ConfigureAwait(false);

            string[] inputs =
            [
                Path.Combine(originals, firstName),
                Path.Combine(originals, secondName),
            ];

            // A faithful extraction must be accepted.
            await File.WriteAllBytesAsync(Path.Combine(extracted, firstName), first).ConfigureAwait(false);
            await File.WriteAllBytesAsync(Path.Combine(extracted, secondName), second).ConfigureAwait(false);
            MacOriginalDeletionService.VerificationResult match =
                await MacOriginalDeletionService.VerifyExtractionAsync(inputs, extracted, null, CancellationToken.None)
                    .ConfigureAwait(false);
            Require(match.Verified, $"A faithful extraction was rejected: {match.Failure}");
            Require(match.FilesCompared == 2, "The comparison did not cover both files.");
            Require(match.BytesCompared == first.Length + second.Length, "The compared byte count is wrong.");

            // One flipped byte must block deletion.
            byte[] altered = first.ToArray();
            altered[altered.Length / 2] ^= 0x01;
            await File.WriteAllBytesAsync(Path.Combine(extracted, firstName), altered).ConfigureAwait(false);
            MacOriginalDeletionService.VerificationResult flipped =
                await MacOriginalDeletionService.VerifyExtractionAsync(inputs, extracted, null, CancellationToken.None)
                    .ConfigureAwait(false);
            Require(!flipped.Verified, "A single flipped byte was accepted as a faithful extraction.");

            // A file the archive lost must block deletion.
            await File.WriteAllBytesAsync(Path.Combine(extracted, firstName), first).ConfigureAwait(false);
            File.Delete(Path.Combine(extracted, secondName));
            MacOriginalDeletionService.VerificationResult missing =
                await MacOriginalDeletionService.VerifyExtractionAsync(inputs, extracted, null, CancellationToken.None)
                    .ConfigureAwait(false);
            Require(!missing.Verified, "A dropped file was accepted as a faithful extraction.");

            // A file the archive gained must block deletion too: it means the
            // extraction is not the set that was archived.
            await File.WriteAllBytesAsync(Path.Combine(extracted, secondName), second).ConfigureAwait(false);
            await File.WriteAllBytesAsync(Path.Combine(extracted, "unexpected.bin"), second).ConfigureAwait(false);
            MacOriginalDeletionService.VerificationResult extra =
                await MacOriginalDeletionService.VerifyExtractionAsync(inputs, extracted, null, CancellationToken.None)
                    .ConfigureAwait(false);
            Require(!extra.Verified, "An unexpected extra file was accepted as a faithful extraction.");

            // A truncated file has the right name and wrong length.
            File.Delete(Path.Combine(extracted, "unexpected.bin"));
            await File.WriteAllBytesAsync(
                Path.Combine(extracted, secondName),
                second.AsSpan(0, second.Length - 1).ToArray()).ConfigureAwait(false);
            MacOriginalDeletionService.VerificationResult truncated =
                await MacOriginalDeletionService.VerifyExtractionAsync(inputs, extracted, null, CancellationToken.None)
                    .ConfigureAwait(false);
            Require(!truncated.Verified, "A truncated file was accepted as a faithful extraction.");

            // Every original must still be present: no failure path deletes.
            Require(File.Exists(inputs[0]) && File.Exists(inputs[1]), "A rejected comparison removed an original.");

            await TestOriginalDriftBlocksDeletionAsync(root).ConfigureAwait(false);

            Zero(first, second, altered);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static Task TestReferenceDifferentialAsync()
    {
        string sha3ReferencePath = Environment.GetEnvironmentVariable("KEEPVAULT_SHA3_REFERENCE")
            ?? Path.Combine(AppContext.BaseDirectory, "Native", "libsha3_ref.dylib");
        Require(File.Exists(sha3ReferencePath), $"SHA3-512 reference adapter is missing: {sha3ReferencePath}");
        using var sha3 = new KeepVaultMac.Tests.Sha3Reference(sha3ReferencePath);

        Require(
            sha3.BlockSize == 72,
            $"The SHA3-512 reference reports a rate of {sha3.BlockSize} rather than 72 bytes.");

        // Lengths chosen to straddle the SHA3-512 rate (72), the Skein-1024
        // block (128) and the cipher block sizes, plus their neighbours, since
        // that is where padding and buffering mistakes surface.
        int[] lengths =
        [
            0, 1, 63, 64, 65, 71, 72, 73, 127, 128, 129, 143, 144, 145,
            255, 256, 257, 1023, 1024, 1025, 4095, 4096,
        ];

        foreach (int length in lengths)
        {
            byte[] message = GetRandomTestBytes(length);
            // HMAC accepts any key length, and varying it exercises the
            // shorter-than-block, exactly-block and longer-than-block paths.
            // Skein's keyed mode takes a fixed 128-byte key.
            byte[] key = GetRandomTestBytes(length % 97 == 0 ? 64 : (length % 97) + 1);
            byte[] skeinKey = GetRandomTestBytes(128);
            try
            {
                Require(
                    FixedEqual(Sha3_512Compat.HashData(message), sha3.Hash(message)),
                    $"Managed SHA3-512 disagrees with the FIPS 202 reference at {length} bytes.");

                using (var incremental = new Sha3_512Incremental())
                {
                    // Split at an offset that is not a multiple of the rate, so
                    // a buffering error cannot hide behind aligned chunks.
                    int split = length / 3;
                    incremental.AppendData(message.AsSpan(0, split));
                    incremental.AppendData(message.AsSpan(split));
                    Require(
                        FixedEqual(incremental.GetHashAndReset(), sha3.Hash(message)),
                        $"Incremental SHA3-512 disagrees with the reference at {length} bytes.");
                }

                using (var mac = new HmacSha3_512(key))
                {
                    mac.AppendData(message);
                    Require(
                        FixedEqual(mac.GetHashAndReset(), sha3.Hmac(key, message)),
                        $"Managed HMAC-SHA3-512 disagrees with the reference at {length} bytes.");
                }

                Require(
                    FixedEqual(Skein1024Digest.HashData(message), NativeThreefish.HashSkein1024Reference(message)),
                    $"Managed Skein-1024 disagrees with the Skein reference at {length} bytes.");

                Require(
                    FixedEqual(BouncySkeinMac(skeinKey, message), NativeThreefish.MacSkein1024Reference(skeinKey, message)),
                    $"Managed Skein-1024 MAC disagrees with the Skein reference at {length} bytes.");
            }
            finally
            {
                Zero(message, key, skeinKey);
            }
        }

        // Both ciphers run in counter mode, so a disagreement in the block
        // function or in the counter's byte order shows up as diverging
        // keystream. Sizes span the parallel-processing threshold.
        foreach (int length in new[] { 1, 63, 64, 65, 4096, 1 << 20 })
        {
            byte[] plaintext = GetRandomTestBytes(length);
            byte[] kalynaKey = GetRandomTestBytes(64);
            byte[] kalynaNonce = GetRandomTestBytes(64);
            byte[] threefishKey = GetRandomTestBytes(128);
            byte[] threefishTweak = GetRandomTestBytes(16);
            byte[] threefishNonce = GetRandomTestBytes(128);
            byte[] kalynaOut = new byte[length];
            byte[] kalynaBack = new byte[length];
            byte[] threefishOut = new byte[length];
            byte[] threefishBack = new byte[length];
            try
            {
                NativeKalyna.XCryptCtr512(kalynaKey, kalynaNonce, plaintext, kalynaOut, length);
                NativeKalyna.XCryptCtr512(kalynaKey, kalynaNonce, kalynaOut, kalynaBack, length);
                Require(
                    FixedEqual(plaintext, kalynaBack),
                    $"Kalyna-512/512 counter mode is not self-inverse at {length} bytes.");
                Require(
                    !FixedEqual(plaintext, kalynaOut) || length == 0,
                    $"Kalyna-512/512 produced its own plaintext as ciphertext at {length} bytes.");

                NativeThreefish.XCryptCtr1024(threefishKey, threefishTweak, threefishNonce, plaintext, threefishOut, length);
                NativeThreefish.XCryptCtr1024(threefishKey, threefishTweak, threefishNonce, threefishOut, threefishBack, length);
                Require(
                    FixedEqual(plaintext, threefishBack),
                    $"Threefish-1024 counter mode is not self-inverse at {length} bytes.");
                Require(
                    !FixedEqual(plaintext, threefishOut) || length == 0,
                    $"Threefish-1024 produced its own plaintext as ciphertext at {length} bytes.");
            }
            finally
            {
                Zero(plaintext, kalynaKey, kalynaNonce, threefishKey, threefishTweak, threefishNonce,
                    kalynaOut, kalynaBack, threefishOut, threefishBack);
            }
        }

        return Task.CompletedTask;
    }

    private static Task TestArgon2Async()
    {
        Require(NativeArgon2id.IsAvailable(), "Signed fixed-profile Argon2id adapter is unavailable.");
        byte[] password = Enumerable.Range(0, 128).Select(value => (byte)((value * 37) ^ 0xA5)).ToArray();
        byte[] salt = Enumerable.Range(0, 64).Select(value => (byte)(value + 1)).ToArray();
        byte[] native = new byte[64];
        byte[] independent = [];
        byte[] v12Password = Enumerable.Range(0, 128).Select(value => (byte)(value ^ 0x6D)).ToArray();
        byte[] v12AssociatedData = "KeepVault/v12/production-export-profile-check"u8.ToArray();
        byte[] v12Output = new byte[64];
        long lockedBaseline = SecureMemory.LockedBytesForTests;
        try
        {
            // The PHC adapter runs with ARGON2_FLAG_CLEAR_PASSWORD, so the
            // reference wipes the password buffer it was handed. Keep a copy
            // for the independent implementation, and assert the wipe happened
            // rather than quietly working around it.
            byte[] passwordCopy = password.ToArray();
            NativeArgon2id.HashRaw(
                Argon2ReferenceProfile.Iterations,
                Argon2ReferenceProfile.MemoryKiB,
                Argon2ReferenceProfile.Parallelism,
                password,
                salt,
                native);
            Require(
                password.All(value => value == 0),
                "Argon2id did not wipe the password buffer it was given.");
            try
            {
                independent = BouncyArgon2(passwordCopy, salt, native.Length);
                Require(FixedEqual(native, independent), "Fixed 1 GiB Argon2id output differs from independent Bouncy Castle.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(passwordCopy);
            }
            Require(SecureMemory.LockedBytesForTests == lockedBaseline, "Argon2id left secure-memory lock accounting behind.");

            bool reducedRejected = false;
            try
            {
                NativeArgon2id.HashRaw(1, 8192, 1, password, salt, new byte[64]);
            }
            catch (CryptographicException)
            {
                reducedRejected = true;
            }

            Require(reducedRejected, "Native Argon2 adapter accepted a reduced profile.");

            bool reducedV12ProductionRejected = false;
            try
            {
                NativeArgon2id.HashRaw(
                    V12MasterKdf.Iterations,
                    8 * 1024,
                    V12MasterKdf.Parallelism,
                    v12Password,
                    salt,
                    null,
                    v12AssociatedData,
                    v12Output);
            }
            catch (CryptographicException)
            {
                reducedV12ProductionRejected = true;
            }

            Require(
                reducedV12ProductionRejected,
                "The production v12 Argon2id export accepted the release KAT memory profile.");
            RequireThrows<ArgumentOutOfRangeException>(
                () => PasswordKeyService.ValidateArgon2Profile(new Argon2ExecutionProfile(1, 1)),
                "Managed KDF accepted a reduced Argon2 profile.");
        }
        finally
        {
            Zero(password, salt, native, independent, v12Password, v12AssociatedData, v12Output);
        }

        return Task.CompletedTask;
    }

    private static async Task TestZpaqAsync()
    {
        string root = CreateTempRoot("keep-vault-zpaq-full-");
        try
        {
            string source = Path.Combine(root, "compression-source.bin");
            byte[] bytes = new byte[192 * 1024];
            for (int index = 0; index < bytes.Length; index++)
            {
                bytes[index] = (byte)((index * 31) ^ (index >> 7));
            }

            await File.WriteAllBytesAsync(source, bytes).ConfigureAwait(false);
            byte[] expectedHash = Sha3_512Compat.HashData(bytes);
            CryptographicOperations.ZeroMemory(bytes);
            try
            {
                var zpaq = new ZpaqService();
                var integrity = new ArchiveIntegrityService();
                for (int level = 0; level <= 5; level++)
                {
                    string archive = Path.Combine(root, $"level-{level}.zpaq");
                    string output = Path.Combine(root, $"level-{level}-out");
                    ProcessResult add = await zpaq.AddAsync(archive, new[] { source }, level, null, CancellationToken.None).ConfigureAwait(false);
                    Require(add.Succeeded, $"ZPAQ file-mode compression level {level} failed: {add.StandardError}");
                    Require(File.Exists(archive + ".sha3") && File.Exists(archive + ".skein"), $"ZPAQ level {level} omitted dual manifests.");
                    await integrity.VerifyAsync(archive, CancellationToken.None).ConfigureAwait(false);
                    ProcessResult extract = await zpaq.ExtractAsync(archive, output, null, CancellationToken.None).ConfigureAwait(false);
                    Require(extract.Succeeded, $"ZPAQ file-mode extraction level {level} failed: {extract.StandardError}");
                    await RequireFileHashAsync(Path.Combine(output, Path.GetFileName(source)), expectedHash, $"ZPAQ level {level}").ConfigureAwait(false);

                    using var streamArchive = new MemoryStream();
                    ProcessResult streamAdd = await zpaq.AddStreamingAsync(
                        new[] { source },
                        level,
                        (input, cancellationToken) => input.CopyToAsync(streamArchive, cancellationToken),
                        null,
                        CancellationToken.None).ConfigureAwait(false);
                    Require(streamAdd.Succeeded && streamArchive.Length > 0, $"ZPAQ streaming compression level {level} failed.");
                    byte[] encoded = streamArchive.ToArray();
                    try
                    {
                        string streamOutput = Path.Combine(root, $"stream-{level}-out");
                        ProcessResult streamExtract = await zpaq.ExtractStreamingAsync(
                            (destination, cancellationToken) => destination.WriteAsync(encoded, cancellationToken).AsTask(),
                            streamOutput,
                            null,
                            CancellationToken.None).ConfigureAwait(false);
                        Require(streamExtract.Succeeded, $"ZPAQ streaming extraction level {level} failed: {streamExtract.StandardError}");
                        await RequireFileHashAsync(Path.Combine(streamOutput, Path.GetFileName(source)), expectedHash, $"streaming ZPAQ level {level}").ConfigureAwait(false);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(encoded);
                    }
                }

                string damaged = Path.Combine(root, "damaged.zpaq");
                File.Copy(Path.Combine(root, "level-1.zpaq"), damaged);
                File.Copy(Path.Combine(root, "level-1.zpaq.sha3"), damaged + ".sha3");
                File.Copy(Path.Combine(root, "level-1.zpaq.skein"), damaged + ".skein");
                FlipByte(damaged, new FileInfo(damaged).Length - 1);
                await RequireThrowsAsync<InvalidDataException>(
                    () => integrity.VerifyAsync(damaged, CancellationToken.None),
                    "A changed ZPAQ archive passed dual-manifest verification.").ConfigureAwait(false);

                await TestZpaqTraversalAsync(root).ConfigureAwait(false);
                await TestZpaqStagingSubstitutionRefusalAsync(root).ConfigureAwait(false);
                await TestZpaqDecompressionBombLimitsAsync(root).ConfigureAwait(false);
                await TestMalformedZpaqCorpusAsync(source, root).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(expectedHash);
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static async Task TestZpaqStagingSubstitutionRefusalAsync(string root)
    {
        string destDir = Path.Combine(root, "safe_target_dest");
        using var staging = new MacExtractionStaging(destDir);
        string realStaging = staging.StagingPath;
        string foreignCanaryDir = Path.Combine(root, "canary_directory");
        Directory.CreateDirectory(foreignCanaryDir);
        string canaryFile = Path.Combine(foreignCanaryDir, "valuable_user_data.txt");
        await File.WriteAllTextAsync(canaryFile, "IMPORTANT USER DATA MUST NOT BE DELETED").ConfigureAwait(false);

        string tempBackup = realStaging + ".temp";
        Directory.Move(realStaging, tempBackup);
        Directory.Move(foreignCanaryDir, realStaging);

        try
        {
            IOException? cleanupFailure = null;
            try
            {
                staging.Cleanup();
            }
            catch (IOException exception)
            {
                cleanupFailure = exception;
            }

            Require(
                cleanupFailure is not null,
                "Staging cleanup silently ignored that its public name had become a foreign directory.");
            Require(Directory.Exists(realStaging), "Staging cleanup deleted a substituted foreign directory!");
            Require(File.Exists(Path.Combine(realStaging, "valuable_user_data.txt")), "Staging cleanup deleted foreign files inside substituted directory!");
            Require(
                Directory.Exists(tempBackup)
                    && !Directory.EnumerateFileSystemEntries(tempBackup).Any(),
                "Staging cleanup did not erase the exact displaced descriptor-bound directory.");
        }
        finally
        {
            Directory.Delete(realStaging, recursive: true);
            if (Directory.Exists(tempBackup))
            {
                Directory.Delete(tempBackup, recursive: true);
            }
        }
    }

    private static async Task TestZpaqDecompressionBombLimitsAsync(string root)
    {
        string bombSource = Path.Combine(root, "bomb_src");
        Directory.CreateDirectory(bombSource);
        for (int i = 0; i < 5; i++)
        {
            await File.WriteAllTextAsync(Path.Combine(bombSource, $"file_{i}.dat"), new string('A', 1000)).ConfigureAwait(false);
        }

        string archive = Path.Combine(root, "bomb.zpaq");
        ProcessResult add = await new ZpaqService().AddAsync(
            archive,
            Directory.GetFiles(bombSource),
            0,
            null,
            CancellationToken.None).ConfigureAwait(false);
        Require(add.Succeeded, "Could not build bomb test archive.");

        string extractTarget = Path.Combine(root, "bomb_extract_target");

        ZpaqService.MaxExtractedFilesOverride = 2;
        try
        {
            await RequireThrowsAsync<Exception>(
                () => new ZpaqService().ExtractAsync(archive, extractTarget, null, CancellationToken.None),
                "ZPAQ extracted files beyond configured bomb limit without rejection.").ConfigureAwait(false);
            Require(!Directory.Exists(extractTarget), "Extraction directory was installed despite exceeding decompression bomb limit.");
        }
        finally
        {
            ZpaqService.MaxExtractedFilesOverride = -1;
            ZpaqService.MaxExtractedBytesOverride = -1;
            ZpaqService.MinFreeDiskSpaceBytesOverride = -1;
        }
    }

    private static async Task TestZpaqTraversalAsync(string root)
    {
        string build = Path.Combine(root, "traversal-build");
        string sub = Path.Combine(build, "sub");
        Directory.CreateDirectory(sub);
        await File.WriteAllTextAsync(Path.Combine(build, "payload.txt"), "must not escape").ConfigureAwait(false);
        string executable = ResolveSignedComponent("zpaq.exe");
        using TrustedNativeFileLease lease = NativeToolIntegrity.AcquireTrustedFile(executable);
        ProcessResult add = await RunProcessAsync(lease.Path, new[] { "add", "evil.zpaq", "../payload.txt", "-m0" }, sub).ConfigureAwait(false);
        Require(add.Succeeded, $"Could not construct traversal regression archive: {add.StandardError}");
        string archive = Path.Combine(sub, "evil.zpaq");
        await new ArchiveIntegrityService().CreateAsync(archive, CancellationToken.None).ConfigureAwait(false);
        string output = Path.Combine(root, "traversal-output");
        ProcessResult extract = await new ZpaqService().ExtractAsync(archive, output, null, CancellationToken.None).ConfigureAwait(false);
        Require(!extract.Succeeded, "ZPAQ extracted an unsafe ../ archive member.");
        Require(extract.StandardError.Contains("unsafe archive member path", StringComparison.OrdinalIgnoreCase), "ZPAQ did not diagnose the unsafe member.");
        Require(!File.Exists(Path.Combine(root, "payload.txt")), "Traversal archive wrote outside extraction staging.");
        Require(!Directory.Exists(output), "Failed traversal extraction left its destination behind.");
    }

    private static async Task TestMalformedZpaqCorpusAsync(string source, string root)
    {
        using var seedStream = new MemoryStream();
        ProcessResult add = await new ZpaqService().AddStreamingAsync(
            new[] { source },
            0,
            (archive, cancellationToken) => archive.CopyToAsync(seedStream, cancellationToken),
            null,
            CancellationToken.None).ConfigureAwait(false);
        Require(add.Succeeded && seedStream.Length > 64, "Malformed-corpus seed archive was not created.");
        byte[] seed = seedStream.ToArray();
        var corpus = new List<byte[]>();
        int[] lengths = [0, 1, 2, 3, 4, 7, 16, 31, 63, seed.Length / 4, seed.Length / 2, seed.Length - 1];
        corpus.AddRange(lengths.Select(length => seed[..Math.Clamp(length, 0, seed.Length)]));
#pragma warning disable CA5394
        var random = new Random(0x4B5A5041);
        for (int caseIndex = 0; caseIndex < 36; caseIndex++)
        {
            byte[] changed = seed.ToArray();
            for (int mutation = 0; mutation < 1 + (caseIndex % 8); mutation++)
            {
                int offset = random.Next(changed.Length);
                changed[offset] ^= (byte)(1 << random.Next(8));
            }

            corpus.Add(changed);
        }
#pragma warning restore CA5394

        string executable = ResolveSignedComponent("zpaq.exe");
        using TrustedNativeFileLease lease = NativeToolIntegrity.AcquireTrustedFile(executable);
        try
        {
            foreach (byte[] input in corpus)
            {
                try
                {
                    await RunMalformedZpaqCaseAsync(lease.Path, input, root).ConfigureAwait(false);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(input);
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    private static async Task RunMalformedZpaqCaseAsync(string executable, byte[] input, string root)
    {
        var start = new ProcessStartInfo
        {
            FileName = executable,
            WorkingDirectory = root,
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.ArgumentList.Add("--pipe");
        start.ArgumentList.Add("list");
        start.ArgumentList.Add("-");
        using Process process = Process.Start(start) ?? throw new InvalidOperationException("Could not start ZPAQ parser corpus case.");
        Task<string> stdout = process.StandardOutput.ReadToEndAsync();
        Task<string> stderr = process.StandardError.ReadToEndAsync();
        try
        {
            await process.StandardInput.BaseStream.WriteAsync(input).ConfigureAwait(false);
        }
        catch (IOException) when (process.HasExited)
        {
        }
        finally
        {
            process.StandardInput.Close();
        }

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        try
        {
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync().ConfigureAwait(false);
            throw new TimeoutException("Malformed ZPAQ corpus case hung for more than three seconds.");
        }

        await Task.WhenAll(stdout, stderr).ConfigureAwait(false);
        Require(process.ExitCode is >= 0 and <= 255, $"Malformed ZPAQ input ended abnormally: {process.ExitCode}");
    }

    /// <summary>
    /// The originals are re-checked immediately before deletion, and any change
    /// since the comparison stops the whole deletion.
    /// </summary>
    /// <remarks>
    /// Verification proves the archive reproduced the inputs. Between that proof
    /// and the deletion, another program can overwrite a file or drop a new one
    /// into a folder that was already walked — and the new file was never
    /// archived. Each case below is checked separately, and each has to leave
    /// every original standing, not just the one that changed.
    /// </remarks>
    private static async Task TestOriginalDriftBlocksDeletionAsync(string parent)
    {
        string root = Path.Combine(parent, "drift");
        string folder = Path.Combine(root, "folder");
        string extracted = Path.Combine(root, "extracted");
        Directory.CreateDirectory(folder);
        Directory.CreateDirectory(extracted);

        byte[] payload = RandomNumberGenerator.GetBytes(8192);
        string inside = Path.Combine(folder, "inside.bin");
        await File.WriteAllBytesAsync(inside, payload).ConfigureAwait(false);
        string[] inputs = [folder];

        Directory.CreateDirectory(Path.Combine(extracted, "folder"));
        await File.WriteAllBytesAsync(Path.Combine(extracted, "folder", "inside.bin"), payload)
            .ConfigureAwait(false);

        string archive = Path.Combine(root, "archive.kzpaq");
        await File.WriteAllBytesAsync(archive, RandomNumberGenerator.GetBytes(4096)).ConfigureAwait(false);
        MacOriginalDeletionService.ArchiveIdentity identity =
            MacOriginalDeletionService.CaptureArchiveIdentity(archive);

        MacOriginalDeletionService.VerificationResult verified =
            await MacOriginalDeletionService.VerifyExtractionAsync(inputs, extracted, null, CancellationToken.None)
                .ConfigureAwait(false);
        Require(verified.Verified && verified.Originals is not null, "The drift fixture did not verify.");

        // A file that appeared after the comparison is not in the archive.
        string appeared = Path.Combine(folder, "appeared.bin");
        await File.WriteAllBytesAsync(appeared, RandomNumberGenerator.GetBytes(64)).ConfigureAwait(false);
        IReadOnlyList<string> withExtra = MacOriginalDeletionService.DeleteOriginals(
            inputs, archive, identity, verified.Originals!);
        Require(withExtra.Count > 0, "A file that appeared after verification did not block deletion.");
        Require(
            File.Exists(inside) && File.Exists(appeared),
            "A blocked deletion removed files anyway.");

        // A file changed after the comparison.
        File.Delete(appeared);
        byte[] changed = payload.ToArray();
        changed[0] ^= 0xFF;
        await File.WriteAllBytesAsync(inside, changed).ConfigureAwait(false);
        IReadOnlyList<string> withChange = MacOriginalDeletionService.DeleteOriginals(
            inputs, archive, identity, verified.Originals!);
        Require(withChange.Count > 0, "A file changed after verification did not block deletion.");
        Require(File.Exists(inside), "A blocked deletion removed the changed original.");

        // A verified file that vanished.
        await File.WriteAllBytesAsync(inside, payload).ConfigureAwait(false);
        File.SetLastWriteTimeUtc(inside, new DateTime(verified.Originals!.Files[inside].ModifiedUtcTicks, DateTimeKind.Utc));
        string vanished = Path.Combine(folder, "second.bin");
        IReadOnlyList<string> clean = MacOriginalDeletionService.DeleteOriginals(
            inputs, archive, identity, verified.Originals!);
        Require(clean.Count == 0, $"An unchanged original set was refused: {string.Join("; ", clean)}");
        Require(!File.Exists(inside), "The verified original file was not deleted.");
        Require(!File.Exists(vanished), "The deletion invented a file.");

        Zero(payload, changed);
    }

    /// <summary>
    /// Two things the derivation promises and that nothing else checks: the
    /// two Argon2id branches never hold their matrices at the same time, and the
    /// derived memory cost never reaches the header.
    /// </summary>
    /// <remarks>
    /// Both are easy to lose by accident. A <c>Task.WhenAll</c> over the two
    /// branches would double peak memory and still produce the right key, and
    /// on a machine with enough RAM nothing would look wrong. A field added to
    /// the header later could publish the cost the derivation deliberately keeps
    /// secret, and every existing test would still pass.
    /// </remarks>
    private static async Task TestCostAndHeaderAsync()
    {
        await TestParanoiaPeakMemoryAsync().ConfigureAwait(false);
        await TestHeaderPublishesNoDerivedCostAsync().ConfigureAwait(false);
    }

    private static async Task TestParanoiaPeakMemoryAsync()
    {
        EncryptionSuiteParameters parameters =
            EncryptionSuiteCatalog.Get(EncryptionSuite.ParanoiaCascade);
        string factorA = GeneratedFactor('A');
        string factorB = GeneratedFactor('B');
        var salts = new KdfSalts(
            DeterministicSalt(0x11), DeterministicSalt(0x22),
            DeterministicSalt(0x33), DeterministicSalt(0x44));

        // The cost this credential set selects, computed the same way the
        // derivation computes it. Asserting against a fixed 2 GiB would pass
        // even if both branches ran at once and each happened to pick a small
        // profile.
        byte[] sha3Credential = V12MasterKdf.DeriveSha3CredentialHash(
            parameters.Algorithm, UserPassword, UserPin,
            HexToBytes(factorA), HexToBytes(factorB));
        byte[] skeinCredential = V12MasterKdf.DeriveSkeinCredentialHash(
            parameters.Algorithm, UserPassword, UserPin,
            HexToBytes(factorA), HexToBytes(factorB));
        (_, uint memoryKiB) = V12MasterKdf.DerivePmi(
            parameters.Algorithm, 1, sha3Credential, skeinCredential,
            ReadOnlySpan<byte>.Empty, salts.Sha3Round1, salts.SkeinRound1);
        Zero(sha3Credential, skeinCredential);

        long oneMatrixBytes = (long)memoryKiB * 1024;
        using var process = Process.GetCurrentProcess();
        process.Refresh();
        long baseline = process.WorkingSet64;
        long peak = baseline;

        using var sampling = new CancellationTokenSource();
        Task sampler = Task.Run(
            async () =>
            {
                while (!sampling.IsCancellationRequested)
                {
                    using Process current = Process.GetCurrentProcess();
                    long resident = current.WorkingSet64;
                    if (resident > Interlocked.Read(ref peak))
                    {
                        Interlocked.Exchange(ref peak, resident);
                    }

                    try
                    {
                        await Task.Delay(25, sampling.Token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        return;
                    }
                }
            },
            CancellationToken.None);

        try
        {
            using ContainerKeyDerivation.MasterResult master = ContainerKeyDerivation.DeriveMaster(
                parameters, UserPassword, UserPin, factorA, factorB, salts, null, CancellationToken.None);
        }
        finally
        {
            sampling.Cancel();
            await sampler.ConfigureAwait(false);
        }

        long growth = Interlocked.Read(ref peak) - baseline;

        // One matrix plus half of another. Four sequential rounds each stay
        // under this; two branches held at once could not.
        long ceiling = oneMatrixBytes + (oneMatrixBytes / 2);
        Require(
            growth < ceiling,
            $"Paranoia peaked at {growth / (1024 * 1024)} MiB over baseline, "
            + $"more than one {oneMatrixBytes / (1024 * 1024)} MiB Argon2 matrix allows.");

        // And it really did allocate one: a derivation that quietly ran at a
        // fraction of the cost would also stay under the ceiling.
        Require(
            growth > oneMatrixBytes / 2,
            $"Paranoia peaked at only {growth / (1024 * 1024)} MiB over baseline, "
            + "which is too little for even one Argon2 matrix.");
    }

    private static async Task TestHeaderPublishesNoDerivedCostAsync()
    {
        string root = CreateTempRoot("keep-vault-v12-header-");
        try
        {
            AddMouseSamplesUntilReady();
            using GeneratedArchiveEntropy entropy = EntropyMixer.CreateArchiveEntropy();
            var containers = new KalynaContainerService();
            string path = Path.Combine(root, "header.kzpaq");
            byte[] payload = RandomNumberGenerator.GetBytes(4096);
            await using (var source = new MemoryStream(payload, writable: false))
            {
                await containers.EncryptZpaqStreamWithPreparedEntropyAsync(
                    source,
                    path,
                    UserPassword,
                    UserPin,
                    entropy.FirstPassword,
                    entropy.SecondPassword,
                    EncryptionSuite.ParanoiaCascade,
                    entropy,
                    null,
                    null,
                    CancellationToken.None).ConfigureAwait(false);
            }

            byte[] headerBytes = ReadHeaderBytes(path);
            using JsonDocument document = JsonDocument.Parse(headerBytes);
            JsonElement header = document.RootElement;

            // The exact field set. A field added later cannot smuggle a
            // secret-derived value into the header without this failing.
            string[] expected =
            [
                "Version", "Algorithm", "BlockBits", "CounterEndian", "EncryptionKeyBits",
                "Sha3MacKeyBits", "Sha3TagBits", "SkeinMacKeyBits", "SkeinTagBits",
                "SaltSha3Round1", "SaltSkeinRound1", "SaltSha3Round2", "SaltSkeinRound2",
                "NonceBits", "Nonce", "TweakBits", "TweakMode", "Tweak",
                "Hint", "Argon2MemoryKiB", "Argon2Iterations", "Argon2Parallelism",
                "KdfBranchOutputBits", "MasterKeyBits", "KdfExecutionMode", "KdfMemoryMode",
                "PasswordMode", "KdfInputMode", "GeneratedPasswordBits",
                "GeneratedPasswordFactorCount", "KdfMode",
                "SecondNonceBits", "SecondNonce",
            ];
            string[] actual = [.. header.EnumerateObject().Select(property => property.Name)];
            Require(
                actual.Length == expected.Length && !actual.Except(expected, StringComparer.Ordinal).Any(),
                $"The v12 header field set changed: {string.Join(", ", actual.Except(expected, StringComparer.Ordinal))}");

            Require(
                header.GetProperty("Argon2MemoryKiB").GetInt32() == 0,
                "The header published the Argon2id memory cost.");

            // No integer field anywhere in the header may fall inside the range
            // the derived cost lives in. That catches a cost written under some
            // other name as well as under its own.
            foreach (JsonProperty property in header.EnumerateObject())
            {
                if (property.Value.ValueKind == JsonValueKind.Number
                    && property.Value.TryGetInt64(out long value)
                    && value >= V12MasterKdf.MemoryMinKiB
                    && value <= V12MasterKdf.MemoryMaxKiB)
                {
                    throw new InvalidOperationException(
                        $"Header field {property.Name} holds {value}, inside the derived Argon2id memory range.");
                }
            }

            Zero(payload, headerBytes);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static byte[] ReadHeaderBytes(string path)
    {
        using FileStream input = File.OpenRead(path);
        input.Position = 7;
        Span<byte> lengthBytes = stackalloc byte[4];
        input.ReadExactly(lengthBytes);
        byte[] headerBytes = new byte[BinaryPrimitives.ReadInt32LittleEndian(lengthBytes)];
        input.ReadExactly(headerBytes);
        return headerBytes;
    }

    private static byte[] DeterministicSalt(byte seed) =>
        [.. Enumerable.Range(0, KdfSalts.SaltBytes).Select(index => (byte)(seed ^ (index * 31)))];

    private static byte[] HexToBytes(string hex) => Convert.FromHexString(hex);

    /// <summary>
    /// One registered case per cipher suite.
    /// </summary>
    /// <remarks>
    /// Every suite is still covered - nothing is skipped - but the scheduler
    /// can now start the long Paranoia case first and run the cheap ones beside
    /// it. As one test that walked all ten suites in a loop, the group was a
    /// single serial block whose length was the sum of its parts.
    /// </remarks>
    internal static IEnumerable<TestCase> ContainerSuiteCases() =>
        Enum.GetValues<EncryptionSuite>().Select(suite => new TestCase(
            ContainerSuiteId(suite),
            $"v12 container roundtrip and manipulation rejection: {suite}",
            () => TestContainersAsync(suite),
            TestResource.EntropyGlobal,
            "Containers"));

    private static async Task TestContainersAsync(EncryptionSuite? onlySuite = null)
    {
        string root = CreateTempRoot("keep-vault-container-full-");
        try
        {
            string source = Path.Combine(root, "source.bin");
            byte[] sourceBytes = RandomNumberGenerator.GetBytes((2 * 1024 * 1024) + 137);
            await File.WriteAllBytesAsync(source, sourceBytes).ConfigureAwait(false);
            using var zpaqBytes = new MemoryStream();
            ProcessResult zpaqResult = await new ZpaqService().AddStreamingAsync(
                new[] { source },
                1,
                (stream, cancellationToken) => stream.CopyToAsync(zpaqBytes, cancellationToken),
                null,
                CancellationToken.None).ConfigureAwait(false);
            Require(zpaqResult.Succeeded, "Container test could not create its ZPAQ payload.");
            byte[] payload = zpaqBytes.ToArray();
            try
            {
                IEnumerable<EncryptionSuite> suites = onlySuite is { } single
                    ? [single]
                    : Enum.GetValues<EncryptionSuite>();
                foreach (EncryptionSuite suite in suites)
                {
                    await TestContainerSuiteAsync(root, payload, suite).ConfigureAwait(false);
                }
            }
            finally
            {
                Zero(sourceBytes, payload);
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static async Task TestContainerSuiteAsync(string root, byte[] payload, EncryptionSuite suite)
    {
        var containers = new KalynaContainerService();
        AddMouseSamplesUntilReady();
        using GeneratedArchiveEntropy entropy = EntropyMixer.CreateArchiveEntropy();
        string factorA = entropy.FirstPassword;
        string factorB = entropy.SecondPassword;
        string path = Path.Combine(root, $"{suite}.kzpaq");
        Stream source = suite == EncryptionSuite.Kalyna512_512
            ? new ShortReadStream(payload, 97)
            : new MemoryStream(payload, writable: false);
        await using (source.ConfigureAwait(false))
        {
            await containers.EncryptZpaqStreamWithPreparedEntropyAsync(
                source,
                path,
                UserPassword,
                UserPin,
                factorA,
                factorB,
                suite,
                entropy,
                "full-test",
                null,
                CancellationToken.None).ConfigureAwait(false);
        }

        Require(!entropy.HasPendingEncryptionParameters, $"{suite} did not consume prepared entropy exactly once.");
        ValidateContainerHeader(path, suite);
        KalynaContainerInfo info = await containers.ReadContainerInfoAsync(path, CancellationToken.None).ConfigureAwait(false);
        Require(info.Version == 12 && info.Suite == suite && info.GeneratedPasswordFactorCount == 2 && info.GeneratedPasswordBits == 1024, $"{suite} header metadata mismatch.");

        using var output = new MemoryStream();
        await containers.DecryptToStreamAsync(path, UserPassword, UserPin, factorA, factorB, output, null, CancellationToken.None).ConfigureAwait(false);
        byte[] decrypted = output.ToArray();
        try
        {
            Require(FixedEqual(payload, decrypted), $"{suite} container roundtrip changed the ZPAQ payload.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(decrypted);
        }

        await RequireAuthenticationFailureWithoutOutputAsync(
            containers,
            path,
            WrongPassword,
            UserPin,
            factorA,
            factorB,
            $"{suite} wrong user password").ConfigureAwait(false);
        await RequireAuthenticationFailureWithoutOutputAsync(
            containers,
            path,
            UserPassword,
            UserPin,
            GeneratedFactor('C'),
            factorB,
            $"{suite} wrong factor A").ConfigureAwait(false);
        await RequireAuthenticationFailureWithoutOutputAsync(
            containers,
            path,
            UserPassword,
            UserPin,
            factorA,
            GeneratedFactor('D'),
            $"{suite} wrong factor B").ConfigureAwait(false);

        string nonCanonical = CopyContainer(path, root, $"{suite}-noncanonical.kzpaq");
        AddHeaderWhitespace(nonCanonical);
        await RequireThrowsAsync<InvalidDataException>(
            () => containers.ReadContainerInfoAsync(nonCanonical, CancellationToken.None),
            $"{suite} accepted noncanonical header JSON.").ConfigureAwait(false);

        // v12 is a clean break. A container claiming any other version must be
        // refused outright rather than read on a compatibility path, and the
        // refusal must not depend on the MACs noticing the edit afterwards.
        foreach (int rejected in new[] { 8, 9, 10, 11 })
        {
            string downgraded = CopyContainer(path, root, $"{suite}-version-{rejected}.kzpaq");
            ReplaceHeaderToken(downgraded, "\"Version\":12", $"\"Version\":{rejected}");
            await RequireThrowsAsync<InvalidDataException>(
                () => containers.ReadContainerInfoAsync(downgraded, CancellationToken.None),
                $"{suite} accepted a container claiming version {rejected}.").ConfigureAwait(false);
            await RequireFailureWithoutOutputAsync(
                containers,
                downgraded,
                UserPassword,
                UserPin,
                factorA,
                factorB,
                typeof(InvalidDataException),
                $"{suite} decrypted a container claiming version {rejected}").ConfigureAwait(false);
        }

        string reducedProfile = CopyContainer(path, root, $"{suite}-reduced-profile.kzpaq");
        ReplaceHeaderToken(reducedProfile, "\"Argon2Iterations\":4", "\"Argon2Iterations\":1");
        await RequireThrowsAsync<InvalidDataException>(
            () => containers.ReadContainerInfoAsync(reducedProfile, CancellationToken.None),
            $"{suite} accepted a reduced Argon2 profile.").ConfigureAwait(false);

        foreach ((string label, Action<string> mutate, Type expected) in new[]
        {
            ("magic", new Action<string>(candidate => FlipByte(candidate, 0)), typeof(InvalidDataException)),
            ("SHA3 tag", new Action<string>(candidate => FlipContainerTag(candidate, skein: false)), typeof(CryptographicException)),
            ("Skein tag", new Action<string>(candidate => FlipContainerTag(candidate, skein: true)), typeof(CryptographicException)),
            ("ciphertext", new Action<string>(candidate => FlipByte(candidate, new FileInfo(candidate).Length - 1)), typeof(CryptographicException)),
        })
        {
            string candidate = CopyContainer(path, root, $"{suite}-{label.Replace(' ', '-')}.kzpaq");
            mutate(candidate);
            await RequireFailureWithoutOutputAsync(
                containers,
                candidate,
                UserPassword,
                UserPin,
                factorA,
                factorB,
                expected,
                $"{suite} changed {label}").ConfigureAwait(false);
        }

        string existing = Path.Combine(root, $"{suite}-existing.kzpaq");
        byte[] sentinel = "existing target survives"u8.ToArray();
        await File.WriteAllBytesAsync(existing, sentinel).ConfigureAwait(false);
        try
        {
            AddMouseSamplesUntilReady();
            using GeneratedArchiveEntropy rejectedEntropy = EntropyMixer.CreateArchiveEntropy();
            await RequireThrowsAsync<IOException>(
                async () =>
                {
                    await using var tiny = new MemoryStream([1, 2, 3, 4], writable: false);
                    await containers.EncryptZpaqStreamWithPreparedEntropyAsync(
                        tiny,
                        existing,
                        UserPassword,
                        UserPin,
                        rejectedEntropy.FirstPassword,
                        rejectedEntropy.SecondPassword,
                        suite,
                        rejectedEntropy,
                        null,
                        null,
                        CancellationToken.None).ConfigureAwait(false);
                },
                $"{suite} overwrote an existing encrypted target.").ConfigureAwait(false);
            byte[] after = await File.ReadAllBytesAsync(existing).ConfigureAwait(false);
            try
            {
                Require(FixedEqual(sentinel, after), $"{suite} modified an existing output after refusal.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(after);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sentinel);
        }
    }

    /// <summary>
    /// A KPAR2 sidecar has to be creatable and verifiable for every suite the
    /// catalogue offers.
    /// </summary>
    /// <remarks>
    /// The locator used to validate its suite id against a hard-coded 0..1
    /// range, so every suite introduced after the original two produced a
    /// container the app would archive and then refuse to protect. The two
    /// covered here are the ends of that failure: the two-round paranoia
    /// cascade, whose key material has a different shape, and the highest
    /// catalogued suite id. Both go through create and authenticated verify,
    /// which is where the range check sat on either side.
    /// </remarks>
    internal static IEnumerable<TestCase> RecoverySuiteCases() =>
        EncryptionSuiteCatalog.DisplayOrder.Select(suite => new TestCase(
            RecoverySuiteId(suite),
            $"KPAR2 v4 authenticates and rejects wrong credentials: {suite}",
            () => TestRecoveryAcrossSuitesAsync(suite),
            TestResource.EntropyGlobal,
            "Recovery"));

    private static string ContainerSuiteId(EncryptionSuite suite) => suite switch
    {
        EncryptionSuite.Kalyna512_512 => "containers.suite.kalyna512-512",
        EncryptionSuite.Threefish1024 => "containers.suite.threefish1024",
        EncryptionSuite.ThreefishOverKalyna => "containers.suite.threefish-over-kalyna",
        EncryptionSuite.ParanoiaCascade => "containers.suite.paranoia-cascade",
        EncryptionSuite.ChaChaOverAes => "containers.suite.chacha-over-aes",
        EncryptionSuite.Aes256 => "containers.suite.aes256",
        EncryptionSuite.Mars448 => "containers.suite.mars448",
        EncryptionSuite.Shacal2_512 => "containers.suite.shacal2-512",
        EncryptionSuite.ChaCha20Poly1305 => "containers.suite.chacha20-poly1305",
        EncryptionSuite.MixedCascade => "containers.suite.mixed-cascade",
        _ => throw new ArgumentOutOfRangeException(nameof(suite), suite, "No stable container test id is registered for this suite."),
    };

    private static string RecoverySuiteId(EncryptionSuite suite) => suite switch
    {
        EncryptionSuite.Kalyna512_512 => "recovery.suite.kalyna512-512",
        EncryptionSuite.Threefish1024 => "recovery.suite.threefish1024",
        EncryptionSuite.ThreefishOverKalyna => "recovery.suite.threefish-over-kalyna",
        EncryptionSuite.ParanoiaCascade => "recovery.suite.paranoia-cascade",
        EncryptionSuite.ChaChaOverAes => "recovery.suite.chacha-over-aes",
        EncryptionSuite.Aes256 => "recovery.suite.aes256",
        EncryptionSuite.Mars448 => "recovery.suite.mars448",
        EncryptionSuite.Shacal2_512 => "recovery.suite.shacal2-512",
        EncryptionSuite.ChaCha20Poly1305 => "recovery.suite.chacha20-poly1305",
        EncryptionSuite.MixedCascade => "recovery.suite.mixed-cascade",
        _ => throw new ArgumentOutOfRangeException(nameof(suite), suite, "No stable recovery test id is registered for this suite."),
    };

    private static async Task TestRecoveryAcrossSuitesAsync(EncryptionSuite? onlySuite = null)
    {
        foreach (EncryptionSuite suite in onlySuite is { } single ? [single] : EncryptionSuiteCatalog.DisplayOrder)
        {
            string root = CreateTempRoot("keep-vault-kpar2-suite-");
            try
            {
                string encrypted = Path.Combine(root, "suite.kzpaq");
                byte[] payload = RandomNumberGenerator.GetBytes(64 * 1024);
                AddMouseSamplesUntilReady();
                using GeneratedArchiveEntropy entropy = EntropyMixer.CreateArchiveEntropy();
                string factorA = entropy.FirstPassword;
                string factorB = entropy.SecondPassword;
                var containers = new KalynaContainerService();
                await using (var input = new MemoryStream(payload, writable: false))
                {
                    await containers.EncryptZpaqStreamWithPreparedEntropyAsync(
                        input,
                        encrypted,
                        UserPassword,
                        UserPin,
                        factorA,
                        factorB,
                        suite,
                        entropy,
                        null,
                        null,
                        CancellationToken.None).ConfigureAwait(false);
                }

                var recovery = new RecoveryService();
                string sidecar = await recovery.CreateAuthenticatedAsync(
                    encrypted,
                    UserPassword,
                    UserPin,
                    factorA,
                    factorB,
                    null,
                    CancellationToken.None).ConfigureAwait(false);
                Require(File.Exists(sidecar), $"No KPAR2 sidecar was written for {suite}.");
                Require(
                    await recovery.TryReadProtectionModeAsync(encrypted, CancellationToken.None).ConfigureAwait(false)
                        == RecoveryProtectionMode.DualAuthenticatedEncrypted,
                    $"KPAR2 for {suite} is not marked dual authenticated.");

                RecoveryRepairResult verified = await recovery.VerifyAndRepairAuthenticatedAsync(
                    encrypted,
                    UserPassword,
                    UserPin,
                    factorA,
                    factorB,
                    null,
                    CancellationToken.None).ConfigureAwait(false);
                Require(
                    verified.Authenticated && !verified.Repaired,
                    $"KPAR2 verification for {suite} did not authenticate an undamaged archive.");

                await RequireThrowsAsync<CryptographicException>(
                    () => recovery.VerifyAndRepairAuthenticatedAsync(
                        encrypted,
                        WrongPassword,
                        UserPin,
                        factorA,
                        factorB,
                        null,
                        CancellationToken.None),
                    $"A wrong user password authenticated the {suite} KPAR2 metadata.").ConfigureAwait(false);
                await RequireThrowsAsync<CryptographicException>(
                    () => recovery.VerifyAndRepairAuthenticatedAsync(
                        encrypted,
                        UserPassword,
                        UserPin,
                        GeneratedFactor('C'),
                        factorB,
                        null,
                        CancellationToken.None),
                    $"A wrong factor A authenticated the {suite} KPAR2 metadata.").ConfigureAwait(false);
                await RequireThrowsAsync<CryptographicException>(
                    () => recovery.VerifyAndRepairAuthenticatedAsync(
                        encrypted,
                        UserPassword,
                        UserPin,
                        factorA,
                        GeneratedFactor('D'),
                        null,
                        CancellationToken.None),
                    $"A wrong factor B authenticated the {suite} KPAR2 metadata.").ConfigureAwait(false);

                Zero(payload);
            }
            finally
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static async Task TestRecoveryAsync()
    {
        string root = CreateTempRoot("keep-vault-kpar2-full-");
        try
        {
            var recovery = new RecoveryService();
            string plain = Path.Combine(root, "plain.zpaq");
            byte[] plainBytes = RandomNumberGenerator.GetBytes((2 * 1024 * 1024) + 333);
            byte[] plainHash = Sha3_512Compat.HashData(plainBytes);
            await File.WriteAllBytesAsync(plain, plainBytes).ConfigureAwait(false);
            string sidecar = await recovery.CreateAsync(plain, null, CancellationToken.None).ConfigureAwait(false);
            Require(File.Exists(sidecar), "Plain KPAR2 error-correction sidecar was not created.");
            Require(await recovery.TryReadProtectionModeAsync(plain, CancellationToken.None).ConfigureAwait(false) == RecoveryProtectionMode.ErrorCorrectionOnly, "Plain KPAR2 protection mode mismatch.");
            FlipRange(plain, 0, 4096);
            byte[] damagedHash = await HashFileAsync(plain).ConfigureAwait(false);
            RecoveryRepairResult repaired = await recovery.VerifyAndRepairAsync(plain, null, CancellationToken.None).ConfigureAwait(false);
            Require(repaired.Repaired && repaired.OutputPath is not null, "Plain KPAR2 did not create a repair candidate.");
            byte[] repairedHash = await HashFileAsync(repaired.OutputPath!).ConfigureAwait(false);
            byte[] originalAfter = await HashFileAsync(plain).ConfigureAwait(false);
            try
            {
                Require(FixedEqual(plainHash, repairedHash), "Plain KPAR2 repair did not reconstruct exact bytes.");
                Require(FixedEqual(damagedHash, originalAfter), "Plain KPAR2 modified the damaged original.");
            }
            finally
            {
                Zero(plainBytes, plainHash, damagedHash, repairedHash, originalAfter);
            }

            string encrypted = Path.Combine(root, "authenticated.kzpaq");
            byte[] payload = RandomNumberGenerator.GetBytes((1024 * 1024) + 71);
            AddMouseSamplesUntilReady();
            using GeneratedArchiveEntropy entropy = EntropyMixer.CreateArchiveEntropy();
            string factorA = entropy.FirstPassword;
            string factorB = entropy.SecondPassword;
            var containers = new KalynaContainerService();
            await using (var input = new MemoryStream(payload, writable: false))
            {
                await containers.EncryptZpaqStreamWithPreparedEntropyAsync(
                    input,
                    encrypted,
                    UserPassword,
                    UserPin,
                    factorA,
                    factorB,
                    EncryptionSuite.Threefish1024,
                    entropy,
                    null,
                    null,
                    CancellationToken.None).ConfigureAwait(false);
            }

            byte[] encryptedHash = await HashFileAsync(encrypted).ConfigureAwait(false);
            string authenticatedSidecar = await recovery.CreateAuthenticatedAsync(
                encrypted,
                UserPassword,
                UserPin,
                factorA,
                factorB,
                null,
                CancellationToken.None).ConfigureAwait(false);
            Require(await recovery.TryReadProtectionModeAsync(encrypted, CancellationToken.None).ConfigureAwait(false) == RecoveryProtectionMode.DualAuthenticatedEncrypted, "Encrypted KPAR2 is not marked dual authenticated.");

            string transplant = Path.Combine(root, "transplant.kzpaq");
            byte[] transplantBytes = RandomNumberGenerator.GetBytes(checked((int)new FileInfo(encrypted).Length));
            await File.WriteAllBytesAsync(transplant, transplantBytes).ConfigureAwait(false);
            byte[] transplantHash = Sha3_512Compat.HashData(transplantBytes);
            File.Copy(authenticatedSidecar, RecoveryService.GetRecoveryPath(transplant));
            await RequireThrowsAsync<InvalidDataException>(
                () => recovery.VerifyAndRepairAuthenticatedAsync(transplant, UserPassword, UserPin, factorA, factorB, null, CancellationToken.None),
                "Authenticated KPAR2 sidecar transplantation was accepted.").ConfigureAwait(false);
            byte[] transplantAfter = await HashFileAsync(transplant).ConfigureAwait(false);
            Require(FixedEqual(transplantHash, transplantAfter), "Rejected KPAR2 transplant modified its target.");

            FlipRange(encrypted, 0, 4096);
            byte[] damagedEncryptedHash = await HashFileAsync(encrypted).ConfigureAwait(false);
            await RequireThrowsAsync<CryptographicException>(
                () => recovery.VerifyAndRepairAuthenticatedAsync(encrypted, WrongPassword, UserPin, factorA, factorB, null, CancellationToken.None),
                "Wrong password authenticated KPAR2 metadata.").ConfigureAwait(false);
            byte[] afterWrongPassword = await HashFileAsync(encrypted).ConfigureAwait(false);
            Require(FixedEqual(damagedEncryptedHash, afterWrongPassword), "Wrong-password KPAR2 attempt modified the original.");

            RecoveryRepairResult authenticatedRepair = await recovery.VerifyAndRepairAuthenticatedAsync(
                encrypted,
                UserPassword,
                UserPin,
                factorA,
                factorB,
                null,
                CancellationToken.None).ConfigureAwait(false);
            Require(authenticatedRepair.Repaired && authenticatedRepair.Authenticated && authenticatedRepair.OutputPath is not null, "Authenticated KPAR2 did not emit a verified repair candidate.");
            byte[] authenticatedHash = await HashFileAsync(authenticatedRepair.OutputPath!).ConfigureAwait(false);
            Require(FixedEqual(encryptedHash, authenticatedHash), "Authenticated KPAR2 did not restore exact container bytes.");
            using var decrypted = new MemoryStream();
            await containers.DecryptToStreamAsync(authenticatedRepair.OutputPath!, UserPassword, UserPin, factorA, factorB, decrypted, null, CancellationToken.None).ConfigureAwait(false);
            byte[] recoveredPayload = decrypted.ToArray();
            Require(FixedEqual(payload, recoveredPayload), "KPAR2-recovered container failed dual-MAC decryption.");

            // Verify KPAR2 v4 locator structure and container version binding
            byte[] sidecarHeader = new byte[512];
            using (var sStream = File.OpenRead(authenticatedSidecar))
            {
                await sStream.ReadExactlyAsync(sidecarHeader).ConfigureAwait(false);
            }
            int locatorFormatVersion = BinaryPrimitives.ReadInt32LittleEndian(sidecarHeader.AsSpan(8));
            Require(locatorFormatVersion == 4, $"KPAR2 format version mismatch: expected 4, got {locatorFormatVersion}");
            int locatorContainerVersion = BinaryPrimitives.ReadInt32LittleEndian(sidecarHeader.AsSpan(72));
            Require(locatorContainerVersion == 12, $"KPAR2 container version mismatch: expected 12, got {locatorContainerVersion}");

            // Targeted ContainerVersion tamper.
            //
            // The point is the container-version binding, so every cheaper
            // reason to fail is removed first: the archive keeps its original
            // base name, the container bytes are the pristine repaired ones,
            // all eight locator copies are changed together so consensus still
            // holds, and each copy's unkeyed self-hashes are recomputed so the
            // locator stays internally valid. What is left is the version field
            // itself, and with exactly one supported container generation there
            // is no second derivation for it to select.
            string tamperDirectory = Path.Combine(root, "container-version-tamper");
            Directory.CreateDirectory(tamperDirectory);
            string tamperedContainer = Path.Combine(tamperDirectory, Path.GetFileName(encrypted));
            File.Copy(authenticatedRepair.OutputPath!, tamperedContainer);
            string tamperedRecoveryPath = RecoveryService.GetRecoveryPath(tamperedContainer);
            File.Copy(authenticatedSidecar, tamperedRecoveryPath);

            Require(
                await recovery.TryReadProtectionModeAsync(tamperedContainer, CancellationToken.None).ConfigureAwait(false)
                    == RecoveryProtectionMode.DualAuthenticatedEncrypted,
                "The relocated KPAR2 sidecar is not readable before tampering, so the tamper case would prove nothing.");
            RecoveryRepairResult relocatedRepair = await recovery.VerifyAndRepairAuthenticatedAsync(
                tamperedContainer, UserPassword, UserPin, factorA, factorB, null, CancellationToken.None).ConfigureAwait(false);
            Require(
                relocatedRepair.Authenticated && relocatedRepair.ArchiveHealthy,
                "The relocated, untampered sidecar did not authenticate, so the tamper case would prove nothing.");

            // Control: rewriting all eight copies and recomputing their
            // self-hashes, but leaving the version at its real value, must
            // still authenticate. Without this the rejections below could just
            // as well mean the rewrite itself produced an invalid locator.
            byte[] rewrittenUnchanged = await File.ReadAllBytesAsync(authenticatedSidecar).ConfigureAwait(false);
            RewriteLocatorContainerVersion(rewrittenUnchanged, 12);
            await File.WriteAllBytesAsync(tamperedRecoveryPath, rewrittenUnchanged).ConfigureAwait(false);
            RecoveryRepairResult rewrittenRepair = await recovery.VerifyAndRepairAuthenticatedAsync(
                tamperedContainer, UserPassword, UserPin, factorA, factorB, null, CancellationToken.None).ConfigureAwait(false);
            Require(
                rewrittenRepair.Authenticated && rewrittenRepair.ArchiveHealthy,
                "Rewriting the locator copies with the correct version broke the sidecar, so the tamper cases prove nothing.");

            // Only the version differs from the control, and it is refused.
            byte[] sidecarAllBytes = await File.ReadAllBytesAsync(authenticatedSidecar).ConfigureAwait(false);
            RewriteLocatorContainerVersion(sidecarAllBytes, 10);
            await File.WriteAllBytesAsync(tamperedRecoveryPath, sidecarAllBytes).ConfigureAwait(false);
            Require(
                BinaryPrimitives.ReadInt32LittleEndian(sidecarAllBytes.AsSpan(72)) == 10
                && BinaryPrimitives.ReadInt32LittleEndian(sidecarAllBytes.AsSpan(8)) == 4,
                "The tampered locator does not carry KPAR2 v4 with container version 10.");
            await RequireThrowsAsync<InvalidDataException>(
                () => recovery.VerifyAndRepairAuthenticatedAsync(tamperedContainer, UserPassword, UserPin, factorA, factorB, null, CancellationToken.None),
                "KPAR2 accepted a container version this build does not support.").ConfigureAwait(false);

            // The inverse: a locator that claims a KPAR2 format version this
            // build never wrote must not find a second, weaker reader.
            byte[] legacyFormatBytes = await File.ReadAllBytesAsync(authenticatedSidecar).ConfigureAwait(false);
            RewriteLocatorFormatVersion(legacyFormatBytes, 3);
            await File.WriteAllBytesAsync(tamperedRecoveryPath, legacyFormatBytes).ConfigureAwait(false);
            await RequireThrowsAsync<InvalidDataException>(
                () => recovery.VerifyAndRepairAuthenticatedAsync(tamperedContainer, UserPassword, UserPin, factorA, factorB, null, CancellationToken.None),
                "KPAR2 accepted a legacy format version instead of refusing it.").ConfigureAwait(false);

            Zero(payload, encryptedHash, transplantBytes, transplantHash, transplantAfter, damagedEncryptedHash, afterWrongPassword, authenticatedHash, recoveredPayload, sidecarHeader, sidecarAllBytes, legacyFormatBytes, rewrittenUnchanged);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>
    /// Rewrites the ContainerVersion field in every KPAR2 v4 locator copy and
    /// repairs each copy's unkeyed self-hashes, so the locator stays valid and
    /// only the authenticated version binding can object.
    /// </summary>
    private static void RewriteLocatorFormatVersion(byte[] sidecar, int formatVersion)
        => RewriteLocatorField(sidecar, 8, formatVersion);

    private static void RewriteLocatorContainerVersion(byte[] sidecar, int containerVersion)
        => RewriteLocatorField(sidecar, 72, containerVersion);

    private static void RewriteLocatorField(byte[] sidecar, int fieldOffset, int value)
    {
        const int LocatorBlockSize = 4096;
        const int LocatorAuthenticatedBytes = 3904;
        const int LocatorSkeinOffset = 3904;
        const int LocatorSha3Offset = 4032;
        const int PrefixCopies = 4;
        const int SuffixCopies = 4;

        Require(
            sidecar.Length >= (PrefixCopies + SuffixCopies) * LocatorBlockSize,
            "The KPAR2 sidecar is too small to contain eight locator copies.");

        for (int copy = 0; copy < PrefixCopies + SuffixCopies; copy++)
        {
            int blockOffset = copy < PrefixCopies
                ? copy * LocatorBlockSize
                : sidecar.Length - (SuffixCopies * LocatorBlockSize) + ((copy - PrefixCopies) * LocatorBlockSize);
            Span<byte> block = sidecar.AsSpan(blockOffset, LocatorBlockSize);
            Require(
                block[..8].SequenceEqual("KPR2LOC2"u8),
                $"KPAR2 locator copy {copy} does not start with the locator magic.");

            BinaryPrimitives.WriteInt32LittleEndian(block[fieldOffset..], value);
            byte[] skein = Skein1024Digest.HashData(block[..LocatorAuthenticatedBytes]);
            byte[] sha3 = Sha3_512Compat.HashData(block[..LocatorAuthenticatedBytes]);
            skein.CopyTo(block[LocatorSkeinOffset..]);
            sha3.CopyTo(block[LocatorSha3Offset..]);
            Zero(skein, sha3);
        }
    }

    /// <summary>
    /// The KPAR2 sidecar replacement must never leave the archive without a
    /// valid recovery file.
    /// </summary>
    /// <remarks>
    /// The old order destroyed the existing sidecar and then moved the new one
    /// into place. Anything that failed in between - a racing creator of the
    /// target name, a permission or I/O error - left the archive with no
    /// recovery data at all even though the sidecar it already had was good.
    /// Every step of the replacement is failed here in turn, and after each one
    /// a valid sidecar has to be recoverable.
    ///
    /// The error-correction profile is used deliberately: the transaction is
    /// the same code for both profiles, and this one needs no key derivation,
    /// so the whole matrix runs in well under a second.
    /// </remarks>
    private static async Task TestRecoverySidecarTransactionAsync()
    {
        string root = CreateTempRoot("keep-vault-kpar2-txn-");
        try
        {
            var recovery = new RecoveryService();
            string archive = Path.Combine(root, "archive.zpaq");
            await File.WriteAllBytesAsync(archive, RandomNumberGenerator.GetBytes(300 * 1024)).ConfigureAwait(false);

            string sidecarPath = await recovery.CreateAsync(archive, null, CancellationToken.None).ConfigureAwait(false);
            Require(File.Exists(sidecarPath), "The initial KPAR2 sidecar was not created.");
            Require(
                (File.GetUnixFileMode(sidecarPath) & UnixFileMode.UserWrite) != 0,
                $"The initial KPAR2 sidecar is not owner-writable: {File.GetUnixFileMode(sidecarPath)}.");
            byte[] original = await File.ReadAllBytesAsync(sidecarPath).ConfigureAwait(false);

            async Task RequireSidecarUsableAsync(string because)
            {
                Require(File.Exists(sidecarPath), $"{because}: no sidecar is present at all.");
                Require(
                    await recovery.TryReadProtectionModeAsync(archive, CancellationToken.None).ConfigureAwait(false)
                        == RecoveryProtectionMode.ErrorCorrectionOnly,
                    $"{because}: the sidecar present is not readable.");
            }

            async Task<int> CountSidecarLeftoversAsync()
            {
                await Task.CompletedTask.ConfigureAwait(false);
                return Directory.GetFiles(root, ".*.previous", SearchOption.TopDirectoryOnly).Length;
            }

            // A locator-only post-install check used to accept corruption in a
            // body parity shard and then destroy the known-good sidecar. The
            // commit gate must read and dual-hash every parity shard before it
            // moves the old sidecar at all.
            RecoveryService.SidecarHookBeforeCommitValidation = generated =>
            {
                const long firstBodyParityByte = 4L * 4096;
                generated.Position = firstBodyParityByte;
                int originalByte = generated.ReadByte();
                Require(originalByte >= 0, "The generated KPAR2 parity fixture is unexpectedly short.");
                generated.Position = firstBodyParityByte;
                generated.WriteByte((byte)(originalByte ^ 0x01));
                generated.Flush(flushToDisk: true);
            };
            try
            {
                await RequireThrowsAsync<InvalidDataException>(
                    () => recovery.CreateAsync(archive, null, CancellationToken.None),
                    "A corrupted generated parity shard passed the KPAR2 commit gate.").ConfigureAwait(false);
            }
            finally
            {
                RecoveryService.SidecarHookBeforeCommitValidation = null;
            }

            byte[] afterCommitGateFailure = await File.ReadAllBytesAsync(sidecarPath).ConfigureAwait(false);
            Require(
                FixedEqual(original, afterCommitGateFailure),
                "A failed full KPAR2 commit gate changed the previous known-good sidecar.");
            Require(
                Directory.GetFiles(root, ".*.recovery-part", SearchOption.TopDirectoryOnly).Length == 0,
                "A failed full KPAR2 commit gate left its generated sidecar behind.");

            // A parity shard can carry the digest named by the manifest and
            // still be unrelated to the 20 archive data shards. Inject the
            // mutation after digest validation so only the independent
            // RS(20,3) recomputation can reject it.
            RecoveryService.GeneratedParityHookAfterDigestValidation = parity => parity[0][0] ^= 0x20;
            try
            {
                await RequireThrowsAsync<InvalidDataException>(
                    () => recovery.CreateAsync(archive, null, CancellationToken.None),
                    "Manifest-consistent but RS-inconsistent KPAR2 parity passed the commit gate.").ConfigureAwait(false);
            }
            finally
            {
                RecoveryService.GeneratedParityHookAfterDigestValidation = null;
            }

            await RequireSidecarUsableAsync("after an RS relation failure").ConfigureAwait(false);
            Require(
                (File.GetUnixFileMode(sidecarPath) & UnixFileMode.UserWrite) != 0,
                $"The known-good KPAR2 sidecar lost owner-write permission: {File.GetUnixFileMode(sidecarPath)}.");
            Require(
                !RecoveryService.ArchiveFileNamesMatchForTests("archive.zpaq", "Archive.zpaq"),
                "KPAR2 archive names were compared case-insensitively on a potentially case-sensitive APFS volume.");

            // macOS permits another process to rename an open file. Prove that
            // both namespace boundaries detect such substitutions by inode,
            // preserve foreign entries and keep the known-good sidecar.
            string displacedPrevious = Path.Combine(root, "displaced-previous.kpar2");
            bool oldRenameCompleted = false;
            bool foreignOldEntryCreated = false;
            RecoveryService.SidecarHookBeforeOldQuarantineRename = () =>
            {
                using var parent = MacSafeFileSystem.OpenDirectoryHandle(root);
                MacSafeFileSystem.RenameAt(
                    parent,
                    Path.GetFileName(sidecarPath),
                    parent,
                    Path.GetFileName(displacedPrevious));
                oldRenameCompleted = true;
                File.WriteAllBytes(sidecarPath, [0xA7]);
                foreignOldEntryCreated = true;
            };
            IOException? oldRenameFailure = null;
            try
            {
                await recovery.CreateAsync(archive, null, CancellationToken.None).ConfigureAwait(false);
            }
            catch (IOException exception)
            {
                oldRenameFailure = exception;
            }
            finally
            {
                RecoveryService.SidecarHookBeforeOldQuarantineRename = null;
            }

            Require(
                oldRenameFailure is not null,
                "A substituted old KPAR2 directory entry passed the quarantine identity check.");

            string[] oldRaceQuarantines = Directory.GetFiles(
                root,
                ".*.previous",
                SearchOption.TopDirectoryOnly);
            byte[] displacedPreviousBytes = File.Exists(displacedPrevious)
                ? await File.ReadAllBytesAsync(displacedPrevious).ConfigureAwait(false)
                : [];
            Require(
                oldRenameCompleted
                    && foreignOldEntryCreated
                    && displacedPreviousBytes.Length > 0
                    && FixedEqual(original, displacedPreviousBytes),
                $"The exact old KPAR2 inode was not preserved after source-name substitution (rename={oldRenameCompleted}, replacement={foreignOldEntryCreated}, failure={oldRenameFailure}).");
            Require(
                File.ReadAllBytes(sidecarPath) is [0xA7]
                    && oldRaceQuarantines.Length == 0,
                "The substituted old-sidecar entry was moved or deleted instead of being left untouched.");
            File.Delete(sidecarPath);
            File.Move(displacedPrevious, sidecarPath);

            string displacedGenerated = Path.Combine(root, "displaced-generated.kpar2");
            RecoveryService.SidecarHookBeforeInstallRename = () =>
            {
                string generatedPath = Directory.GetFiles(
                    root,
                    ".*.recovery-part",
                    SearchOption.TopDirectoryOnly).Single();
                using var parent = MacSafeFileSystem.OpenDirectoryHandle(root);
                MacSafeFileSystem.RenameAt(
                    parent,
                    Path.GetFileName(generatedPath),
                    parent,
                    Path.GetFileName(displacedGenerated));
                File.WriteAllBytes(generatedPath, [0xA8]);
            };
            try
            {
                await RequireThrowsAsync<IOException>(
                    () => recovery.CreateAsync(archive, null, CancellationToken.None),
                    "A substituted generated KPAR2 directory entry passed the install identity check.").ConfigureAwait(false);
            }
            finally
            {
                RecoveryService.SidecarHookBeforeInstallRename = null;
            }

            string[] foreignGeneratedEntries = Directory.GetFiles(
                root,
                ".*.recovery-part",
                SearchOption.TopDirectoryOnly);
            byte[] afterGeneratedRace = await File.ReadAllBytesAsync(sidecarPath).ConfigureAwait(false);
            Require(
                FixedEqual(original, afterGeneratedRace),
                "A generated-temp substitution did not restore the known-good KPAR2 sidecar.");
            Require(
                File.Exists(displacedGenerated)
                    && new FileInfo(displacedGenerated).Length > 4096
                    && foreignGeneratedEntries.Length == 1
                    && File.ReadAllBytes(foreignGeneratedEntries[0]) is [0xA8],
                "Generated-temp substitution cleanup touched a foreign entry or lost the bound generated inode.");
            File.Delete(foreignGeneratedEntries[0]);
            SecureFile.DestroyPrefixAndSuffixAndDelete(
                displacedGenerated,
                1024 * 1024,
                1024 * 1024);

            // 1. A failure right after the old sidecar was moved aside must put
            //    it back under its own name.
            RecoveryService.SidecarHookAfterQuarantine = () => throw new IOException("injected: after quarantine");
            try
            {
                await RequireThrowsAsync<IOException>(
                    () => recovery.CreateAsync(archive, null, CancellationToken.None),
                    "The injected post-quarantine failure was swallowed.").ConfigureAwait(false);
            }
            finally
            {
                RecoveryService.SidecarHookAfterQuarantine = null;
            }

            await RequireSidecarUsableAsync("after a post-quarantine failure").ConfigureAwait(false);
            byte[] afterQuarantineFailure = await File.ReadAllBytesAsync(sidecarPath).ConfigureAwait(false);
            Require(
                FixedEqual(original, afterQuarantineFailure),
                "A post-quarantine failure did not restore the original sidecar bytes.");
            Require(await CountSidecarLeftoversAsync().ConfigureAwait(false) == 0, "A post-quarantine failure left a stray backup behind.");

            // 2. macOS permits an in-place write through a second descriptor
            //    even though the inode is still the one we installed. The
            //    post-rename full gate must catch that content race and roll
            //    back to the old sidecar.
            RecoveryService.SidecarHookAfterInstall = () =>
            {
                using var installedWriter = new FileStream(
                    sidecarPath,
                    FileMode.Open,
                    FileAccess.ReadWrite,
                    FileShare.ReadWrite | FileShare.Delete);
                const long firstBodyParityByte = 4L * 4096;
                installedWriter.Position = firstBodyParityByte;
                int originalByte = installedWriter.ReadByte();
                Require(originalByte >= 0, "The installed KPAR2 race fixture is unexpectedly short.");
                installedWriter.Position = firstBodyParityByte;
                installedWriter.WriteByte((byte)(originalByte ^ 0x40));
                installedWriter.Flush(flushToDisk: true);
            };
            try
            {
                await RequireThrowsAsync<InvalidDataException>(
                    () => recovery.CreateAsync(archive, null, CancellationToken.None),
                    "An in-place mutation of the installed KPAR2 object passed the post-rename gate.").ConfigureAwait(false);
            }
            finally
            {
                RecoveryService.SidecarHookAfterInstall = null;
            }

            await RequireSidecarUsableAsync("after a post-install failure").ConfigureAwait(false);
            byte[] afterInstallFailure = await File.ReadAllBytesAsync(sidecarPath).ConfigureAwait(false);
            Require(
                FixedEqual(original, afterInstallFailure),
                "A post-install failure did not roll back to the original sidecar.");
            Require(await CountSidecarLeftoversAsync().ConfigureAwait(false) == 0, "A post-install failure left a stray backup behind.");

            // 3. An adversary can wait for the first installed-object gate and
            //    then mutate the same inode through another descriptor. The
            //    final pre-commit gate must catch that last-window mutation;
            //    otherwise the transaction would destroy its only good copy.
            RecoveryService.SidecarHookBeforeBackupDestruction = _ =>
            {
                using var installedWriter = new FileStream(
                    sidecarPath,
                    FileMode.Open,
                    FileAccess.ReadWrite,
                    FileShare.ReadWrite | FileShare.Delete);
                long[] locatorOffsets =
                [
                    0,
                    4096,
                    2L * 4096,
                    3L * 4096,
                    installedWriter.Length - (4L * 4096),
                ];
                foreach (long offset in locatorOffsets)
                {
                    installedWriter.Position = offset;
                    int originalByte = installedWriter.ReadByte();
                    Require(originalByte >= 0, "The final KPAR2 mutation fixture is unexpectedly short.");
                    installedWriter.Position = offset;
                    installedWriter.WriteByte((byte)(originalByte ^ 0x80));
                }

                installedWriter.Flush(flushToDisk: true);
            };
            try
            {
                await RequireThrowsAsync<InvalidDataException>(
                    () => recovery.CreateAsync(archive, null, CancellationToken.None),
                    "An in-place mutation after the first installed KPAR2 validation passed the final commit gate.").ConfigureAwait(false);
            }
            finally
            {
                RecoveryService.SidecarHookBeforeBackupDestruction = null;
            }

            await RequireSidecarUsableAsync("after a final commit-validation failure").ConfigureAwait(false);
            byte[] afterFinalCommitValidationFailure = await File.ReadAllBytesAsync(sidecarPath).ConfigureAwait(false);
            Require(
                FixedEqual(original, afterFinalCommitValidationFailure),
                "A final KPAR2 commit-validation failure did not restore the previous known-good sidecar.");
            Require(
                await CountSidecarLeftoversAsync().ConfigureAwait(false) == 0
                    && Directory.GetFiles(root, ".*.failed-new", SearchOption.TopDirectoryOnly).Length == 0
                    && Directory.GetFiles(root, ".*.recovery-part", SearchOption.TopDirectoryOnly).Length == 0,
                "A final KPAR2 commit-validation failure left transaction objects behind.");

            // 4. A racing process that occupies the target name between the
            //    quarantine and the install must not cost the old sidecar: it
            //    stays recoverable under the quarantine name.
            RecoveryService.SidecarHookAfterQuarantine = () => File.WriteAllBytes(sidecarPath, [0x00]);
            try
            {
                await RequireThrowsAsync<System.ComponentModel.Win32Exception>(
                    () => recovery.CreateAsync(archive, null, CancellationToken.None),
                    "An occupied KPAR2 target name was accepted.").ConfigureAwait(false);
            }
            finally
            {
                RecoveryService.SidecarHookAfterQuarantine = null;
            }

            string[] preserved = Directory.GetFiles(root, ".*.previous", SearchOption.TopDirectoryOnly);
            Require(preserved.Length == 1, $"The previous sidecar was not preserved after a name collision ({preserved.Length} candidates).");
            byte[] preservedBytes = await File.ReadAllBytesAsync(preserved[0]).ConfigureAwait(false);
            Require(
                FixedEqual(original, preservedBytes),
                "The preserved sidecar is not the original one.");
            File.Delete(sidecarPath);
            File.Move(preserved[0], sidecarPath);
            await RequireSidecarUsableAsync("after restoring the preserved sidecar").ConfigureAwait(false);

            // 5. A failure while destroying the old backup happens after the
            //    commit point. The new sidecar must stay installed.
            RecoveryService.SidecarHookBeforePostCommitBackupCleanup = () => throw new IOException("injected: during backup cleanup");
            try
            {
                await RequireThrowsAsync<IOException>(
                    () => recovery.CreateAsync(archive, null, CancellationToken.None),
                    "The injected backup-destruction failure was swallowed.").ConfigureAwait(false);
            }
            finally
            {
                RecoveryService.SidecarHookBeforePostCommitBackupCleanup = null;
            }

            await RequireSidecarUsableAsync("after a post-commit backup-destruction failure").ConfigureAwait(false);
            byte[] afterCommitFailure = await File.ReadAllBytesAsync(sidecarPath).ConfigureAwait(false);
            Require(
                !FixedEqual(original, afterCommitFailure),
                "A post-commit failure rolled back the verified new sidecar.");
            foreach (string leftover in Directory.GetFiles(root, ".*.previous", SearchOption.TopDirectoryOnly))
            {
                File.Delete(leftover);
            }

            // 6. A sidecar that is a symbolic link is not something to move
            //    aside and destroy; it is refused.
            byte[] current = await File.ReadAllBytesAsync(sidecarPath).ConfigureAwait(false);
            string realSidecar = Path.Combine(root, "elsewhere.kpar2");
            await File.WriteAllBytesAsync(realSidecar, current).ConfigureAwait(false);
            File.Delete(sidecarPath);
            File.CreateSymbolicLink(sidecarPath, realSidecar);
            await RequireThrowsAsync<IOException>(
                () => recovery.CreateAsync(archive, null, CancellationToken.None),
                "A symbolic-link KPAR2 sidecar was replaced instead of refused.").ConfigureAwait(false);
            Require(File.Exists(realSidecar), "Refusing a symlinked sidecar destroyed its target.");
            File.Delete(sidecarPath);

            // 7. Neither is one with a second hard link: the bytes would survive
            //    the destruction under the other name.
            File.Copy(realSidecar, sidecarPath);
            string secondLink = Path.Combine(root, "second-link.kpar2");
            Require(CreateHardLinkForTests(sidecarPath, secondLink), "Could not create a second hard link for the test.");
            await RequireThrowsAsync<IOException>(
                () => recovery.CreateAsync(archive, null, CancellationToken.None),
                "A multiply-linked KPAR2 sidecar was replaced instead of refused.").ConfigureAwait(false);
            File.Delete(secondLink);

            Zero(
                original,
                current,
                afterCommitGateFailure,
                displacedPreviousBytes,
                afterGeneratedRace,
                afterQuarantineFailure,
                afterInstallFailure,
                afterFinalCommitValidationFailure,
                preservedBytes,
                afterCommitFailure);
        }
        finally
        {
            RecoveryService.SidecarHookAfterQuarantine = null;
            RecoveryService.SidecarHookBeforeCommitValidation = null;
            RecoveryService.SidecarHookBeforeOldQuarantineRename = null;
            RecoveryService.SidecarHookBeforeInstallRename = null;
            RecoveryService.SidecarHookAfterInstall = null;
            RecoveryService.SidecarHookBeforeBackupDestruction = null;
            RecoveryService.SidecarHookBeforePostCommitBackupCleanup = null;
            RecoveryService.GeneratedParityHookAfterDigestValidation = null;
            Directory.Delete(root, recursive: true);
        }
    }

    private static bool CreateHardLinkForTests(string existingPath, string newLinkPath)
    {
        using var process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName = "/bin/ln",
            ArgumentList = { existingPath, newLinkPath },
            UseShellExecute = false,
            RedirectStandardError = true,
        });
        if (process is null)
        {
            return false;
        }

        process.WaitForExit();
        return process.ExitCode == 0 && File.Exists(newLinkPath);
    }

    /// <summary>
    /// Secure deletion must destroy and delete the same verified object.
    /// </summary>
    /// <remarks>
    /// The dangerous shape is: verify a handle, overwrite through it, close it,
    /// then delete by path. Between the close and the delete the name can point
    /// somewhere else, so the object that was destroyed survives under a new
    /// name while a substituted one is deleted in its place. Both platforms now
    /// record the deletion against the open handle instead - macOS through the
    /// descriptor-relative quarantine, Windows through delete-on-close.
    /// </remarks>
    private static Task TestSecureFileObjectBoundDeletionAsync()
    {
        string root = CreateTempRoot("keep-vault-securefile-");
        try
        {
            // 1. The ordinary case still works: the file is gone and its
            //    neighbours are untouched.
            string victim = Path.Combine(root, "victim.bin");
            string neighbour = Path.Combine(root, "neighbour.bin");
            byte[] neighbourBytes = RandomNumberGenerator.GetBytes(4096);
            File.WriteAllBytes(victim, RandomNumberGenerator.GetBytes(64 * 1024));
            File.WriteAllBytes(neighbour, neighbourBytes);
            SecureFile.DestroyPrefixAndSuffixAndDelete(victim, 4096, 4096);
            Require(!File.Exists(victim), "Secure deletion left the target in place.");
            Require(
                FixedEqual(neighbourBytes, File.ReadAllBytes(neighbour)),
                "Secure deletion altered a neighbouring file.");

            // 2. A second hard link means the bytes survive the destruction
            //    under the other name, so the whole operation is refused before
            //    anything is overwritten.
            string linked = Path.Combine(root, "linked.bin");
            string secondName = Path.Combine(root, "second-name.bin");
            byte[] linkedBytes = RandomNumberGenerator.GetBytes(32 * 1024);
            File.WriteAllBytes(linked, linkedBytes);
            Require(CreateHardLinkForTests(linked, secondName), "Could not create a second hard link for the test.");
            RequireThrows<IOException>(
                () => SecureFile.DestroyPrefixAndSuffixAndDelete(linked, 4096, 4096),
                "Secure deletion accepted a file with two hard links.");
            Require(
                FixedEqual(linkedBytes, File.ReadAllBytes(linked)),
                "A refused secure deletion still overwrote the multiply-linked file.");
            File.Delete(secondName);
            File.Delete(linked);

            // 3. A symbolic link is not the object it names.
            string realFile = Path.Combine(root, "real.bin");
            string symlink = Path.Combine(root, "symlink.bin");
            byte[] realBytes = RandomNumberGenerator.GetBytes(16 * 1024);
            File.WriteAllBytes(realFile, realBytes);
            File.CreateSymbolicLink(symlink, realFile);
            RequireThrows<IOException>(
                () => SecureFile.DestroyPrefixAndSuffixAndDelete(symlink, 4096, 4096),
                "Secure deletion followed a symbolic link.");
            Require(
                FixedEqual(realBytes, File.ReadAllBytes(realFile)),
                "A refused secure deletion still overwrote a symlink target.");
            Require(File.Exists(symlink), "A refused secure deletion removed the symbolic link.");

            // 4. A directory is never a secure-deletion target.
            string directory = Path.Combine(root, "a-directory");
            Directory.CreateDirectory(directory);
            SecureFile.DestroyPrefixAndSuffixAndDelete(directory, 4096, 4096);
            Require(Directory.Exists(directory), "Secure deletion removed a directory.");

            Zero(neighbourBytes, linkedBytes, realBytes);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }

        return Task.CompletedTask;
    }

    private static async Task TestCryptographicEraseAsync()
    {
        string root = CreateTempRoot("keep-vault-erase-full-");
        try
        {
            string container = Path.Combine(root, "erase.kzpaq");
            byte[] payload = RandomNumberGenerator.GetBytes(128 * 1024);
            AddMouseSamplesUntilReady();
            using GeneratedArchiveEntropy entropy = EntropyMixer.CreateArchiveEntropy();
            string factorA = entropy.FirstPassword;
            string factorB = entropy.SecondPassword;
            await using (var input = new MemoryStream(payload, writable: false))
            {
                await new KalynaContainerService().EncryptZpaqStreamWithPreparedEntropyAsync(
                    input,
                    container,
                    UserPassword,
                    UserPin,
                    factorA,
                    factorB,
                    EncryptionSuite.Threefish1024,
                    entropy,
                    null,
                    null,
                    CancellationToken.None).ConfigureAwait(false);
            }

            string sidecar = await new RecoveryService().CreateAuthenticatedAsync(
                container,
                UserPassword,
                UserPin,
                factorA,
                factorB,
                null,
                CancellationToken.None).ConfigureAwait(false);
            var erase = new CryptographicEraseService();
            CryptoEraseAnalysis analysis = await erase.AnalyzeAsync(container, CancellationToken.None).ConfigureAwait(false);
            Require(analysis.Exists && analysis.IsEncryptedContainer, "Valid v7 container was not classified as cryptographically erasable.");
            Require(analysis.HardwareNotice.Contains("SSD", StringComparison.Ordinal), "Erase analysis hides the SSD remanence limitation.");

            string hardLink = Path.Combine(root, "hardlink.kzpaq");
            Require(MacTestLinks.CreateHardLink(container, hardLink) == 0, "Could not create hard-link erase fixture.");
            await RequireThrowsAsync<IOException>(
                () => erase.EraseEncryptedContainerAsync(container, null, CancellationToken.None),
                "Cryptographic erase accepted a multiply-linked container.").ConfigureAwait(false);
            Require(File.Exists(container) && File.Exists(hardLink) && File.Exists(sidecar), "Hard-link refusal did not preserve container and recovery data.");
            File.Delete(hardLink);

            CryptoEraseResult result = await erase.EraseEncryptedContainerAsync(container, null, CancellationToken.None).ConfigureAwait(false);
            Require(result.Deleted, "Cryptographic erase did not report success.");
            Require(!File.Exists(container), "Cryptographic erase left the encrypted container.");
            Require(!File.Exists(sidecar), "Cryptographic erase left recoverable KPAR2 data.");

            // Test recovery path for MarkForDeletion under race substitution
            string victimPath = Path.Combine(root, "victim.txt");
            string foreignPath = Path.Combine(root, "foreign.txt");
            await File.WriteAllTextAsync(victimPath, "victim content").ConfigureAwait(false);
            await File.WriteAllTextAsync(foreignPath, "foreign content").ConfigureAwait(false);

            using (FileStream victimStream = MacSafeFileSystem.OpenReadNoSymlinks(victimPath))
            {
                SecureFile.TestHookBeforeRename = () =>
                {
                    // Simulate adversary replacing victimPath with foreign item before RenameAt
                    File.Delete(victimPath);
                    File.Move(foreignPath, victimPath);
                };

                try
                {
                    bool threw = false;
                    try
                    {
                        SecureFile.MarkForDeletion(victimStream, victimPath);
                    }
                    catch (InvalidOperationException ex)
                    {
                        threw = true;
                        Require(ex.Message.Contains("Quarantined file identity mismatch", StringComparison.Ordinal),
                            "MarkForDeletion did not report identity mismatch.");
                    }
                    Require(threw, "MarkForDeletion did not reject identity mismatch on race substitution.");
                    Require(File.Exists(victimPath), "MarkForDeletion recovery did not restore the foreign item back to its location.");
                    Require(File.ReadAllText(victimPath) == "foreign content", "Foreign item content was corrupted during recovery.");
                }
                finally
                {
                    SecureFile.TestHookBeforeRename = null;
                }
            }

            // Test MarkForDeletion rollback when victim path is occupied by another new file (squatter)
            string victimPath2 = Path.Combine(root, "victim2.txt");
            string foreignPath2 = Path.Combine(root, "foreign2.txt");
            await File.WriteAllTextAsync(victimPath2, "victim2 content").ConfigureAwait(false);
            await File.WriteAllTextAsync(foreignPath2, "foreign2 content").ConfigureAwait(false);

            using (FileStream victimStream2 = MacSafeFileSystem.OpenReadNoSymlinks(victimPath2))
            {
                SecureFile.TestHookBeforeRename = () =>
                {
                    File.Delete(victimPath2);
                    File.Move(foreignPath2, victimPath2);
                };

                SecureFile.TestHookBeforeRollback = () =>
                {
                    // Adversary introduces squatter file at original victimPath2 before rollback rename runs
                    File.WriteAllText(victimPath2, "squatter content");
                };

                try
                {
                    bool threw = false;
                    try
                    {
                        SecureFile.MarkForDeletion(victimStream2, victimPath2);
                    }
                    catch (InvalidOperationException ex)
                    {
                        threw = true;
                        Require(ex.Message.Contains("Original path", StringComparison.Ordinal)
                            && ex.Message.Contains("occupied or restore failed", StringComparison.Ordinal)
                            && ex.Message.Contains("Foreign item preserved safely in quarantine under", StringComparison.Ordinal),
                            "MarkForDeletion did not report squatter quarantine details: " + ex.Message);
                    }
                    Require(threw, "MarkForDeletion did not reject identity mismatch when squatter occupied original path.");
                    Require(File.Exists(victimPath2), "Squatter file disappeared.");
                    Require(File.ReadAllText(victimPath2) == "squatter content", "Squatter content was overwritten.");
                }
                finally
                {
                    SecureFile.TestHookBeforeRename = null;
                    SecureFile.TestHookBeforeRollback = null;
                }
            }

            // A same-sized, entirely regular replacement has identical limit
            // aggregates. Only the bound tree fingerprint exposes the changed
            // child inode between the final limit gate and installation.
            string stagingTarget = Path.Combine(root, "staging-target");
            string displacedChild = Path.Combine(root, "displaced-staging-child");
            using (var staging = new MacExtractionStaging(stagingTarget))
            {
                string child = Path.Combine(staging.StagingPath, "child");
                Directory.CreateDirectory(child);
                byte[] originalChildBytes = Enumerable.Repeat((byte)0x42, 4096).ToArray();
                await File.WriteAllBytesAsync(Path.Combine(child, "part.bin"), originalChildBytes).ConfigureAwait(false);
                DirectoryTreeMeasurement baseline = staging.MeasureTree(allowWriters: false);
                MacExtractionStaging.TestHookBeforeInstallRename = () =>
                {
                    Directory.Move(child, displacedChild);
                    Directory.CreateDirectory(child);
                    File.WriteAllBytes(Path.Combine(child, "part.bin"), originalChildBytes);
                };

                try
                {
                    RequireThrows<InvalidDataException>(
                        () => staging.Install(),
                        "A same-sized nested-directory substitution passed the final staging fingerprint gate.");
                }
                finally
                {
                    MacExtractionStaging.TestHookBeforeInstallRename = null;
                }

                DirectoryTreeMeasurement substituted = staging.MeasureTree(allowWriters: false);
                Require(
                    baseline.FileCount == substituted.FileCount
                        && baseline.TotalBytes == substituted.TotalBytes
                        && baseline.MaxFileBytes == substituted.MaxFileBytes
                        && !string.Equals(baseline.TreeFingerprint, substituted.TreeFingerprint, StringComparison.Ordinal),
                    "The same-sized staging substitution fixture did not isolate the inode-sensitive fingerprint gate.");
                Require(!Directory.Exists(stagingTarget), "A changed staging tree was installed at the destination.");
                Zero(originalChildBytes);
            }

            string limitTarget = Path.Combine(root, "limit-staging-target");
            using (var staging = new MacExtractionStaging(limitTarget))
            {
                string growingFile = Path.Combine(staging.StagingPath, "growing.bin");
                await File.WriteAllBytesAsync(growingFile, new byte[512]).ConfigureAwait(false);
                _ = staging.MeasureTree(allowWriters: false);
                MacExtractionStaging.TestHookBeforeInstallRename = () =>
                    File.WriteAllBytes(growingFile, new byte[4096]);
                bool finalLimitValidatorCalled = false;
                try
                {
                    RequireThrows<InvalidDataException>(
                        () => staging.Install(finalTree =>
                        {
                            finalLimitValidatorCalled = true;
                            if (finalTree.MaxFileBytes > 1024)
                            {
                                throw new InvalidDataException("injected final extraction limit");
                            }
                        }),
                        "A file grown past the extraction limit after the earlier gate was installed.");
                }
                finally
                {
                    MacExtractionStaging.TestHookBeforeInstallRename = null;
                }

                Require(finalLimitValidatorCalled, "Install did not invoke the final bound-tree limit validator.");
                Require(!Directory.Exists(limitTarget), "A staging tree beyond the final size limit was installed.");
            }

            // Replacing a previously empty destination after its emptiness
            // check must preserve the foreign canary rather than unlinking the
            // new directory by name.
            string emptyTarget = Path.Combine(root, "empty-target");
            string displacedEmptyTarget = Path.Combine(root, "displaced-empty-target");
            using (var staging = new MacExtractionStaging(emptyTarget))
            {
                await File.WriteAllTextAsync(Path.Combine(staging.StagingPath, "part.txt"), "part data").ConfigureAwait(false);
                _ = staging.MeasureTree(allowWriters: false);
                Directory.CreateDirectory(emptyTarget);
                string canary = Path.Combine(emptyTarget, "foreign-canary.txt");
                MacExtractionStaging.TestHookAfterEmptyDestinationCheck = () =>
                {
                    Directory.Move(emptyTarget, displacedEmptyTarget);
                    Directory.CreateDirectory(emptyTarget);
                    File.WriteAllText(canary, "foreign canary");
                };

                try
                {
                    RequireThrows<IOException>(
                        () => staging.Install(),
                        "A replacement of the empty destination passed the identity recheck.");
                }
                finally
                {
                    MacExtractionStaging.TestHookAfterEmptyDestinationCheck = null;
                }

                Require(
                    File.Exists(canary) && File.ReadAllText(canary) == "foreign canary",
                    "Empty-target race handling removed or changed the foreign canary directory.");
            }

            // Cleanup must empty the exact held plaintext tree after a root
            // rename, report that the public name was replaced, and never
            // traverse or delete the foreign replacement.
            string cleanupStagingTarget = Path.Combine(root, "cleanup-staging-target");
            string displacedStagingRoot = Path.Combine(root, "cleanup-staging-displaced");
            using (var staging = new MacExtractionStaging(cleanupStagingTarget))
            {
                await File.WriteAllTextAsync(
                    Path.Combine(staging.StagingPath, "plaintext.txt"),
                    "sensitive extracted plaintext").ConfigureAwait(false);
                Directory.Move(staging.StagingPath, displacedStagingRoot);
                Directory.CreateDirectory(staging.StagingPath);
                string replacementCanary = Path.Combine(staging.StagingPath, "foreign.txt");
                await File.WriteAllTextAsync(replacementCanary, "foreign staging root").ConfigureAwait(false);

                RequireThrows<IOException>(
                    staging.Cleanup,
                    "Extraction cleanup accepted a replacement staging-root pathname.");
                Require(
                    File.Exists(replacementCanary)
                        && File.ReadAllText(replacementCanary) == "foreign staging root",
                    "Extraction cleanup changed the replacement staging root.");
                Require(
                    !Directory.EnumerateFileSystemEntries(displacedStagingRoot).Any(),
                    "Extraction cleanup left plaintext in the displaced bound staging root.");

                Directory.Delete(staging.StagingPath, recursive: true);
                Directory.Delete(displacedStagingRoot);
            }

            // Bound recursive cleanup refuses a replacement root and can still
            // remove the original object under its new, explicitly identified
            // name.
            string cleanupRoot = Path.Combine(root, "bound-cleanup-root");
            string displacedCleanupRoot = Path.Combine(root, "bound-cleanup-displaced");
            Directory.CreateDirectory(Path.Combine(cleanupRoot, "nested"));
            await File.WriteAllTextAsync(Path.Combine(cleanupRoot, "nested", "owned.txt"), "owned").ConfigureAwait(false);
            MacFileIdentity cleanupIdentity;
            using (SafeFileHandle cleanupHandle = MacSafeFileSystem.OpenDirectoryHandle(cleanupRoot))
            {
                cleanupIdentity = MacSafeFileSystem.GetIdentity(cleanupHandle);
            }

            Directory.Move(cleanupRoot, displacedCleanupRoot);
            Directory.CreateDirectory(cleanupRoot);
            string cleanupCanary = Path.Combine(cleanupRoot, "foreign.txt");
            await File.WriteAllTextAsync(cleanupCanary, "foreign root").ConfigureAwait(false);
            RequireThrows<IOException>(
                () => MacSafeFileSystem.DeleteDirectoryTreeBound(cleanupRoot, cleanupIdentity),
                "Bound cleanup traversed a replacement root.");
            Require(
                File.Exists(cleanupCanary) && File.ReadAllText(cleanupCanary) == "foreign root",
                "Bound cleanup changed the replacement root.");
            MacSafeFileSystem.DeleteDirectoryTreeBound(displacedCleanupRoot, cleanupIdentity);
            Require(!Directory.Exists(displacedCleanupRoot), "Bound cleanup did not remove the exact displaced root.");

            // Control: an unchanged validated staging tree still installs.
            string normalTarget = Path.Combine(root, "normal-staging-target");
            using (var staging = new MacExtractionStaging(normalTarget))
            {
                await File.WriteAllTextAsync(Path.Combine(staging.StagingPath, "part.txt"), "part data").ConfigureAwait(false);
                DirectoryTreeMeasurement measured = staging.MeasureTree(allowWriters: false);
                staging.Install(final => Require(
                    final.FileCount == measured.FileCount && final.TotalBytes == measured.TotalBytes,
                    "The final install validator received different staging limits."));
                Require(Directory.Exists(normalTarget), "An unchanged staging tree did not install.");
            }

            CryptographicOperations.ZeroMemory(payload);
        }
        finally
        {
            MacExtractionStaging.TestHookBeforeInstallRename = null;
            MacExtractionStaging.TestHookAfterEmptyDestinationCheck = null;
            MacSafeFileSystem.TestHookBeforeDirectoryDescend = null;
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>
    /// Proves that defeating the outer layer alone yields nothing usable.
    /// </summary>
    /// <remarks>
    /// The cascade is only worth its second pass if both ciphers must fall. An
    /// attacker who breaks Threefish recovers the outer keystream and can strip
    /// it — and must then be left holding Kalyna ciphertext, not plaintext and
    /// not the archive's structure. This drives the two layers directly with
    /// known keys so the property is checked, not argued.
    /// </remarks>
    private static Task TestCascadeLayeringAsync()
    {
        EncryptionSuiteParameters parameters = EncryptionSuiteCatalog.Get(EncryptionSuite.ThreefishOverKalyna);
        CascadeLayout layout = parameters.Cascade
            ?? throw new InvalidOperationException("The cascade suite lost its layer layout.");
        Require(layout.Stages.Count == 2, $"The cascade has {layout.Stages.Count} stages rather than two.");
        Require(
            layout.Stages[0].Cipher == CascadeCipher.Kalyna512_512
            && layout.Stages[0].KeyBytes == 64 && layout.Stages[0].NonceBytes == 64,
            "The cascade's inner stage is not Kalyna with a 64-byte key and nonce.");
        Require(
            layout.Stages[1].Cipher == CascadeCipher.Threefish1024
            && layout.Stages[1].KeyBytes == 128 && layout.Stages[1].NonceBytes == 128,
            "The cascade's outer stage is not Threefish with a 128-byte key and nonce.");
        Require(!layout.OutermostIsAead, "The two-layer cascade must not claim an authenticated outer layer.");
        Require(parameters.DerivedKeyBytes == 384, "Cascade derived key is not 384 bytes.");

        // The six-layer suite, checked the same way: the order is the order the
        // plaintext travels, and the key and nonce shares are what the header
        // and the KDF budget were sized against.
        EncryptionSuiteParameters paranoia = EncryptionSuiteCatalog.Get(EncryptionSuite.ParanoiaCascade);
        CascadeLayout paranoiaLayout = paranoia.Cascade
            ?? throw new InvalidOperationException("The paranoia suite lost its layer layout.");
        CascadeCipher[] expectedOrder =
        [
            CascadeCipher.Aes256,
            CascadeCipher.Mars448,
            CascadeCipher.Shacal2_512,
            CascadeCipher.Kalyna512_512,
            CascadeCipher.Threefish1024,
            CascadeCipher.ChaCha20Poly1305,
        ];
        Require(
            paranoiaLayout.Stages.Select(stage => stage.Cipher).SequenceEqual(expectedOrder),
            "The paranoia cascade's layer order is not AES, MARS, SHACAL-2, Kalyna, Threefish, ChaCha20-Poly1305.");
        Require(paranoiaLayout.OutermostIsAead, "The paranoia cascade's outer layer is not authenticated.");
        Require(
            paranoiaLayout.TotalKeyBytes == 376,
            $"The paranoia cascade needs 376 key bytes, not {paranoiaLayout.TotalKeyBytes}.");
        Require(
            paranoiaLayout.TotalNonceBytes == 268,
            $"The paranoia cascade needs 268 nonce bytes, not {paranoiaLayout.TotalNonceBytes}.");
        Require(paranoia.UsesTwoKdfRounds, "The paranoia cascade must derive two Argon2id rounds.");
        Require(
            EncryptionSuiteCatalog.Default == EncryptionSuite.ThreefishOverKalyna,
            "The cascade is not the default suite.");

        // Every suite the catalogue knows must also report itself as usable,
        // or the GUI offers a suite it then refuses to run — and the default
        // suite is the one that would fail first.
        var containerService = new KalynaContainerService();
        foreach (EncryptionSuite candidate in Enum.GetValues<EncryptionSuite>())
        {
            Require(
                containerService.IsNativeSuiteAvailable(candidate),
                $"{candidate} is offered by the catalogue but reports no native support.");
        }

        // A payload with structure an attacker would recognise instantly.
        byte[] marker = "KZPAQ2\0KEEP-VAULT-PLAINTEXT-MARKER"u8.ToArray();
        byte[] plaintext = new byte[64 * 1024];
        for (int offset = 0; offset + marker.Length <= plaintext.Length; offset += marker.Length)
        {
            marker.CopyTo(plaintext, offset);
        }

        byte[] innerKey = RandomNumberGenerator.GetBytes(layout.Stages[0].KeyBytes);
        byte[] outerKey = RandomNumberGenerator.GetBytes(layout.Stages[1].KeyBytes);
        byte[] innerNonce = RandomNumberGenerator.GetBytes(layout.Stages[0].NonceBytes);
        byte[] outerNonce = RandomNumberGenerator.GetBytes(layout.Stages[1].NonceBytes);
        byte[] tweak = RandomNumberGenerator.GetBytes(parameters.TweakBytes);
        byte[] innerCiphertext = new byte[plaintext.Length];
        byte[] cascadeCiphertext = new byte[plaintext.Length];
        byte[] outerStripped = new byte[plaintext.Length];
        byte[] recovered = new byte[plaintext.Length];
        try
        {
            NativeKalyna.XCryptCtr512(innerKey, innerNonce, plaintext, innerCiphertext, plaintext.Length);
            NativeThreefish.XCryptCtr1024(outerKey, tweak, outerNonce, innerCiphertext, cascadeCiphertext, plaintext.Length);

            Require(!FixedEqual(plaintext, cascadeCiphertext), "The cascade left the plaintext unchanged.");
            Require(!FixedEqual(innerCiphertext, cascadeCiphertext), "The outer layer did nothing.");
            Require(!ContainsSequence(cascadeCiphertext, marker), "The cascade ciphertext still shows the plaintext marker.");

            // The attacker's best case: the outer keystream is known and removed.
            NativeThreefish.XCryptCtr1024(outerKey, tweak, outerNonce, cascadeCiphertext, outerStripped, plaintext.Length);
            Require(FixedEqual(outerStripped, innerCiphertext), "Stripping the outer layer did not reproduce the inner ciphertext.");
            Require(!FixedEqual(outerStripped, plaintext), "Stripping the outer layer revealed the plaintext.");
            Require(!ContainsSequence(outerStripped, marker), "Stripping the outer layer revealed plaintext structure.");

            // Only with the inner key as well does the plaintext come back.
            NativeKalyna.XCryptCtr512(innerKey, innerNonce, outerStripped, recovered, plaintext.Length);
            Require(FixedEqual(recovered, plaintext), "Both layers together did not reproduce the plaintext.");

            // A wrong inner key after a correct outer strip stays garbage.
            byte[] wrongInner = RandomNumberGenerator.GetBytes(layout.Stages[0].KeyBytes);
            byte[] wrongRecovery = new byte[plaintext.Length];
            try
            {
                NativeKalyna.XCryptCtr512(wrongInner, innerNonce, outerStripped, wrongRecovery, plaintext.Length);
                Require(!ContainsSequence(wrongRecovery, marker), "A wrong inner key still revealed plaintext structure.");
            }
            finally
            {
                Zero(wrongInner, wrongRecovery);
            }
        }
        finally
        {
            Zero(plaintext, innerKey, outerKey, innerNonce, outerNonce, tweak,
                innerCiphertext, cascadeCiphertext, outerStripped, recovered);
        }

        return Task.CompletedTask;
    }

    private static bool ContainsSequence(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        return needle.Length != 0 && haystack.IndexOf(needle) >= 0;
    }

    private static void ValidateContainerHeader(string path, EncryptionSuite suite)
    {
        using FileStream input = File.OpenRead(path);
        byte[] magic = new byte[7];
        input.ReadExactly(magic);
        Require(FixedEqual(magic, "KZPAQ2\0"u8), "Container magic mismatch.");
        Span<byte> lengthBytes = stackalloc byte[4];
        input.ReadExactly(lengthBytes);
        int length = BinaryPrimitives.ReadInt32LittleEndian(lengthBytes);
        Require(length is > 0 and <= 16 * 1024, "Container header length is unbounded.");
        byte[] headerBytes = new byte[length];
        input.ReadExactly(headerBytes);
        try
        {
            using JsonDocument document = JsonDocument.Parse(headerBytes);
            JsonElement header = document.RootElement;
            EncryptionSuiteParameters parameters = EncryptionSuiteCatalog.Get(suite);
            int version = header.GetProperty("Version").GetInt32();
            Require(version == 12, "Container version is not v12.");

            // The second-round fields are always present. Present-and-null is
            // not cosmetic: the reader compares the header against its own
            // canonical re-serialization, so a field that vanished would make
            // the app reject containers it had just written.
            bool hasSaltSha3_1 = header.TryGetProperty("SaltSha3Round1", out JsonElement saltSha3_1);
            bool hasSaltSkein_1 = header.TryGetProperty("SaltSkeinRound1", out JsonElement saltSkein_1);
            bool hasSaltSha3_2 = header.TryGetProperty("SaltSha3Round2", out JsonElement saltSha3_2);
            bool hasSaltSkein_2 = header.TryGetProperty("SaltSkeinRound2", out JsonElement saltSkein_2);
            bool hasSecondNonce = header.TryGetProperty("SecondNonce", out JsonElement secondNonce);
            Require(hasSaltSha3_1 && hasSaltSkein_1 && hasSaltSha3_2 && hasSaltSkein_2 && hasSecondNonce,
                "Container header is missing salt or second-round fields.");

            Require(saltSha3_1.ValueKind == JsonValueKind.String && saltSkein_1.ValueKind == JsonValueKind.String,
                "Container header is missing round 1 salts.");
            Require(Convert.FromBase64String(saltSha3_1.GetString()!).Length == 64, "SaltSha3Round1 length != 64");
            Require(Convert.FromBase64String(saltSkein_1.GetString()!).Length == 64, "SaltSkeinRound1 length != 64");
            Require(!string.Equals(saltSha3_1.GetString(), saltSkein_1.GetString(), StringComparison.Ordinal),
                "Round 1 salts are identical.");

            if (parameters.UsesTwoKdfRounds)
            {
                // A two-round suite must carry both rounds, or the archive is
                // undecryptable by anyone — including the machine that wrote it.
                Require(
                    saltSha3_2.ValueKind == JsonValueKind.String
                    && saltSkein_2.ValueKind == JsonValueKind.String
                    && secondNonce.ValueKind == JsonValueKind.String,
                    "Container header omits second-round material for a two-round suite.");
                Require(
                    header.GetProperty("SecondNonceBits").GetInt32() == parameters.NonceBytes * 8,
                    "Container header declares wrong second-round sizes.");
                Require(Convert.FromBase64String(saltSha3_2.GetString()!).Length == 64, "SaltSha3Round2 length != 64");
                Require(Convert.FromBase64String(saltSkein_2.GetString()!).Length == 64, "SaltSkeinRound2 length != 64");
                string[] salts = [saltSha3_1.GetString()!, saltSkein_1.GetString()!, saltSha3_2.GetString()!, saltSkein_2.GetString()!];
                Require(salts.Distinct(StringComparer.Ordinal).Count() == 4, "Container header contains repeated salts.");
                Require(
                    !string.Equals(
                        header.GetProperty("Nonce").GetString(),
                        secondNonce.GetString(),
                        StringComparison.Ordinal),
                    "Container header reuses the first round's nonce for the second.");
            }
            else
            {
                Require(
                    saltSha3_2.ValueKind == JsonValueKind.Null
                    && saltSkein_2.ValueKind == JsonValueKind.Null
                    && secondNonce.ValueKind == JsonValueKind.Null,
                    "Container header does not carry null second-round material for a single-round suite.");
                Require(
                    header.GetProperty("SecondNonceBits").GetInt32() == 0,
                    "Container header declares second-round sizes for a single-round suite.");
            }
            Require(header.GetProperty("Algorithm").GetString() == parameters.Algorithm, "Container algorithm label mismatch.");
            Require(header.GetProperty("CounterEndian").GetString() == EncryptionSuiteCatalog.CounterEndian, "Container counter endian mismatch.");
            // Zero, and asserted as zero. v12 derives the memory cost from the
            // credentials; a header that published it would give away the one
            // KDF parameter that is deliberately secret.
            Require(header.GetProperty("Argon2MemoryKiB").GetInt32() == 0, "Container header published the Argon2id memory cost.");
            const string expectedKdfMode = "DualArgon2id-SplitSHA3+Skein1024-Sequential-Master1024";
            Require(header.GetProperty("KdfMode").GetString() == expectedKdfMode, "Container KDF mode mismatch.");
            Require(header.GetProperty("Argon2Iterations").GetInt32() == Argon2ExecutionProfile.DefaultIterations, "Container Argon2 iterations mismatch.");
            Require(header.GetProperty("Argon2Parallelism").GetInt32() == Argon2ExecutionProfile.DefaultParallelism, "Container Argon2 parallelism mismatch.");
            Require(header.GetProperty("GeneratedPasswordFactorCount").GetInt32() == 2, "Container factor count mismatch.");
            Require(header.GetProperty("GeneratedPasswordBits").GetInt32() == 1024, "Container generated-factor bits mismatch.");
            Require(
                header.GetProperty("EncryptionKeyBits").GetInt32() == parameters.EncryptionKeyBytes * 8,
                "Container encryption key size mismatch.");
            Require(
                header.GetProperty("NonceBits").GetInt32() == parameters.NonceBytes * 8,
                "Container nonce size mismatch.");
            Require(
                header.GetProperty("KdfBranchOutputBits").GetInt32() == 512,
                "Container branch output size mismatch.");
            Require(
                header.GetProperty("MasterKeyBits").GetInt32() == 1024,
                "Container master key size mismatch.");
            Require(
                header.GetProperty("KdfExecutionMode").GetString() == "Sequential",
                "Container KdfExecutionMode mismatch.");
            Require(
                header.GetProperty("KdfMemoryMode").GetString() == "PMI16",
                "Container KdfMemoryMode mismatch.");
            if (suite == EncryptionSuite.ThreefishOverKalyna)
            {
                // The split the whole construction rests on, asserted against
                // the numbers rather than against the catalog that produced
                // them: 64 bytes of key and nonce for the inner Kalyna layer,
                // 128 for the outer Threefish layer, and an Argon2id output of
                // 192 cipher-key bytes plus the two MAC keys.
                Require(header.GetProperty("EncryptionKeyBits").GetInt32() == 192 * 8, "Cascade key is not 192 bytes.");
                Require(header.GetProperty("NonceBits").GetInt32() == 192 * 8, "Cascade nonce is not 192 bytes.");
                Require(header.GetProperty("MasterKeyBits").GetInt32() == 1024, "Cascade master is not 1024 bits.");
            }

            if (suite == EncryptionSuite.ParanoiaCascade)
            {
                // Six layers: 32+56+64+64+128+32 key bytes and 16+16+32+64+128+12
                // nonce bytes. The key length no longer follows from an
                // Argon2id output length: every stage key is cut from its own
                // 1024-bit role value, so the cascade could be any width.
                Require(header.GetProperty("EncryptionKeyBits").GetInt32() == 376 * 8, "Paranoia key is not 376 bytes.");
                Require(header.GetProperty("NonceBits").GetInt32() == 268 * 8, "Paranoia nonce is not 268 bytes.");
                Require(header.GetProperty("MasterKeyBits").GetInt32() == 1024, "Paranoia master is not 1024 bits.");
            }
            Require(input.Length - input.Position > 64 + 128, "Container lacks two tags and ciphertext.");
        }
        finally
        {
            Zero(magic, headerBytes);
        }
    }

    private static async Task RequireAuthenticationFailureWithoutOutputAsync(
        KalynaContainerService service,
        string path,
        string password,
        string pin,
        string factorA,
        string factorB,
        string label)
    {
        await RequireFailureWithoutOutputAsync(
            service,
            path,
            password,
            pin,
            factorA,
            factorB,
            typeof(CryptographicException),
            label).ConfigureAwait(false);
    }

    private static async Task RequireFailureWithoutOutputAsync(
        KalynaContainerService service,
        string path,
        string password,
        string pin,
        string factorA,
        string factorB,
        Type expectedException,
        string label)
    {
        byte[] sentinel = "destination-must-remain-unchanged"u8.ToArray();
        using var output = new MemoryStream();
        output.Write(sentinel);
        try
        {
            await service.DecryptToStreamAsync(path, password, pin, factorA, factorB, output, null, CancellationToken.None).ConfigureAwait(false);
            throw new InvalidOperationException($"{label} unexpectedly decrypted.");
        }
        catch (Exception ex) when (ex.GetType() == expectedException)
        {
        }

        byte[] after = output.ToArray();
        try
        {
            Require(FixedEqual(sentinel, after), $"{label} emitted plaintext before authentication.");
        }
        finally
        {
            Zero(sentinel, after);
        }
    }

    private static byte[] BouncyArgon2(byte[] password, byte[] salt, int outputLength)
    {
        var parameters = new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
            .WithVersion(Argon2Parameters.Version13)
            .WithMemoryAsKB(Argon2ReferenceProfile.MemoryKiB)
            .WithIterations(Argon2ReferenceProfile.Iterations)
            .WithParallelism(Argon2ReferenceProfile.Parallelism)
            .WithSalt(salt.ToArray())
            .Build();
        var generator = new Argon2BytesGenerator();
        generator.Init(parameters);
        byte[] output = new byte[outputLength];
        Require(generator.GenerateBytes(password, output) == outputLength, "Independent Argon2 output length mismatch.");
        return output;
    }

    private static byte[] BouncySkeinMac(byte[] key, byte[] data)
    {
        var mac = new SkeinMac(1024, 1024);
        mac.Init(new KeyParameter(key.ToArray()));
        mac.BlockUpdate(data);
        byte[] output = new byte[128];
        mac.DoFinal(output);
        return output;
    }

    private static void SerialKalyna(byte[] key, byte[] nonce, byte[] input, byte[] output)
    {
        byte[] counter = nonce.ToArray();
        try
        {
            for (int offset = 0; offset < input.Length; offset += 256 * 1024)
            {
                int count = Math.Min(256 * 1024, input.Length - offset);
                byte[] source = input.AsSpan(offset, count).ToArray();
                byte[] target = new byte[count];
                try
                {
                    NativeKalyna.XCryptCtr512(key, counter, source, target, count);
                    target.CopyTo(output, offset);
                    IncrementCounter(counter, (count + 63L) / 64L);
                }
                finally
                {
                    Zero(source, target);
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(counter);
        }
    }

    private static void SerialThreefish(byte[] key, byte[] tweak, byte[] nonce, byte[] input, byte[] output)
    {
        byte[] counter = nonce.ToArray();
        try
        {
            for (int offset = 0; offset < input.Length; offset += 256 * 1024)
            {
                int count = Math.Min(256 * 1024, input.Length - offset);
                byte[] source = input.AsSpan(offset, count).ToArray();
                byte[] target = new byte[count];
                try
                {
                    NativeThreefish.XCryptCtr1024(key, tweak, counter, source, target, count);
                    target.CopyTo(output, offset);
                    IncrementCounter(counter, (count + 127L) / 128L);
                }
                finally
                {
                    Zero(source, target);
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(counter);
        }
    }

    private static void IncrementCounter(byte[] counter, long blocks)
    {
        ulong carry = checked((ulong)blocks);
        for (int index = counter.Length - 1; index >= 0 && carry != 0; index--)
        {
            ulong sum = counter[index] + (carry & 0xFF);
            counter[index] = (byte)sum;
            carry = (carry >> 8) + (sum >> 8);
        }

        Require(carry == 0, "Test CTR counter overflowed.");
    }

    private static byte[] CreateCtrTestBytes(int length, uint seed)
    {
        byte[] output = new byte[length];
        uint state = seed == 0 ? 0x9E3779B9U : seed;
        for (int index = 0; index < output.Length; index++)
        {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            output[index] = (byte)state;
        }

        return output;
    }

    /// <summary>
    /// Constructs CTR independently from the exported block primitive. A
    /// roundtrip cannot detect a shared counter-endian or worker-offset bug;
    /// this comparison can.
    /// </summary>
    private static void AssertCtrMatchesBlockReference(
        string algorithm,
        int blockBytes,
        Action<byte[], byte[], byte[], int> xcrypt,
        Action<byte[], byte[]> encryptBlock)
    {
        const int WorkerChunkBytes = 256 * 1024;
        const int ParallelThresholdBytes = 1024 * 1024;
        int[] lengths =
        [
            1,
            blockBytes - 1,
            blockBytes,
            blockBytes + 1,
            WorkerChunkBytes - 1,
            WorkerChunkBytes,
            WorkerChunkBytes + 1,
            ParallelThresholdBytes - 1,
            ParallelThresholdBytes,
            ParallelThresholdBytes + 1,
        ];

        for (int counterTrial = 0; counterTrial < 3; counterTrial++)
        {
            byte[] nonce = CreateCtrTestBytes(blockBytes, 0x43545200U + (uint)blockBytes + (uint)counterTrial);
            if (counterTrial == 0)
            {
                Array.Clear(nonce);
            }
            else if (counterTrial == 1)
            {
                Array.Clear(nonce);
                nonce[^4] = 0xFF;
                nonce[^3] = 0xFF;
                nonce[^2] = 0xFF;
                nonce[^1] = 0xFF;
            }
            else
            {
                nonce[^8] = 0x80;
                nonce[^2] = 0x7A;
                nonce[^1] = 0xFF;
            }

            try
            {
                foreach (int length in lengths)
                {
                    byte[] input = CreateCtrTestBytes(length, 0x494E0000U + (uint)length + (uint)counterTrial);
                    byte[] expected = new byte[length];
                    byte[] actual = new byte[length];
                    byte[] inPlace = input.ToArray();
                    try
                    {
                        BuildCtrFromBlockReference(nonce, input, expected, encryptBlock, blockBytes);
                        xcrypt(nonce, input, actual, length);
                        Require(
                            CryptographicOperations.FixedTimeEquals(expected, actual),
                            $"{algorithm} CTR differs from its block reference at {length} bytes, counter trial {counterTrial}.");

                        xcrypt(nonce, inPlace, inPlace, length);
                        Require(
                            CryptographicOperations.FixedTimeEquals(expected, inPlace),
                            $"{algorithm} in-place CTR differs at {length} bytes, counter trial {counterTrial}.");
                    }
                    finally
                    {
                        Zero(input, expected, actual, inPlace);
                    }
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(nonce);
            }
        }

        Console.WriteLine(
            $"    {algorithm} CTR matches the independent block construction across "
            + $"{lengths.Length} boundary lengths, three counters and in-place buffers");
    }

    private static void BuildCtrFromBlockReference(
        byte[] nonce,
        byte[] input,
        byte[] output,
        Action<byte[], byte[]> encryptBlock,
        int blockBytes)
    {
        byte[] counter = nonce.ToArray();
        byte[] keystream = new byte[blockBytes];
        try
        {
            for (int offset = 0; offset < input.Length; offset += blockBytes)
            {
                encryptBlock(counter, keystream);
                int count = Math.Min(blockBytes, input.Length - offset);
                for (int index = 0; index < count; index++)
                {
                    output[offset + index] = (byte)(input[offset + index] ^ keystream[index]);
                }

                if (offset + count < input.Length)
                {
                    IncrementCounter(counter, 1);
                }
            }
        }
        finally
        {
            Zero(counter, keystream);
        }
    }

    private static void AssertNativeCtrCounterBoundary(
        string algorithm,
        int blockBytes,
        Action<byte[], byte[], byte[]> xcrypt)
    {
        byte[] maximumNonce = Enumerable.Repeat((byte)0xFF, blockBytes).ToArray();
        byte[] finalInput = Enumerable.Repeat((byte)0x3C, blockBytes).ToArray();
        byte[] finalOutput = new byte[blockBytes];
        byte[] crossingInput = Enumerable.Repeat((byte)0x5A, checked(blockBytes * 2)).ToArray();
        byte[] crossingOutput = Enumerable.Repeat((byte)0xA5, crossingInput.Length).ToArray();
        try
        {
            // The maximum value itself remains valid for one final block.
            xcrypt(maximumNonce, finalInput, finalOutput);

            bool rejected = false;
            try
            {
                xcrypt(maximumNonce, crossingInput, crossingOutput);
            }
            catch (CryptographicException)
            {
                rejected = true;
            }

            Require(rejected, $"{algorithm} accepted a CTR request that wraps its counter.");
            Require(
                crossingOutput.All(value => value == 0xA5),
                $"{algorithm} wrote output before refusing CTR counter exhaustion.");
            Console.WriteLine($"    {algorithm} permits the final counter and rejects wrap before output");
        }
        finally
        {
            Zero(maximumNonce, finalInput, finalOutput, crossingInput, crossingOutput);
        }
    }

    /// <summary>
    /// Proves the second Argon2id round is real, independent, and costs no
    /// extra mouse entropy.
    /// </summary>
    /// <remarks>
    /// The point of the design is that both rounds come out of a single pool
    /// consumption, separated only by SHA3-512 against SHA-512. The two things
    /// that could go wrong are therefore: the second round is not actually
    /// independent of the first, or obtaining it silently drains the pools so
    /// the user is asked to collect entropy all over again. Both are checked
    /// here.
    /// </remarks>
    /// <summary>
    /// Encrypts a payload spanning several chunks and checks that identical
    /// plaintext chunks do not produce identical ciphertext.
    /// </summary>
    /// <remarks>
    /// This is the property per-chunk nonces exist for. Under one continuous
    /// counter the keystream never repeats either — until the counter wraps,
    /// which is precisely the case an arbitrarily large archive can reach. The
    /// test cannot write an archive that large, so it checks the mechanism
    /// instead: the plaintext is the same 16 MiB block repeated, so if every
    /// chunk were encrypted under the same counter start the ciphertext chunks
    /// would be byte-identical.
    ///
    /// A roundtrip is done as well, because a nonce derivation that the writer
    /// and the reader disagree about would still produce different ciphertext
    /// per chunk and would still pass the first check.
    /// </remarks>
    /// <summary>
    /// Checks the two Crypto++-backed cascade layers against the vectors that
    /// ship with the library, and checks that their CTR mode behaves.
    /// </summary>
    /// <remarks>
    /// The vectors are read from external/cryptopp/TestVectors rather than
    /// copied in here, so a Crypto++ update brings its own expectations with it
    /// instead of being checked against numbers frozen at the time this was
    /// written.
    ///
    /// SHACAL-2's file covers the 512-bit key the cascade uses. MARS's published
    /// file stops at 256 bits, so the separate Botan-derived oracle below holds
    /// the actual 448-bit production schedule against 32 independent answers.
    /// </remarks>
    private static Task TestCascadeCipherVectorsAsync()
    {
        Require(NativeMars.IsAvailable(), $"MARS reference library unavailable: {NativeMars.LastLoadError}");
        Require(NativeShacal2.IsAvailable(), $"SHACAL-2 reference library unavailable: {NativeShacal2.LastLoadError}");
        Require(NativeThreefish.IsAvailable(), "Threefish reference library unavailable.");

        string vectorRoot = ResolveVectorDirectory();

        int marsChecked = RunBlockVectors(
            Path.Combine(vectorRoot, "mars.txt"),
            NativeMars.BlockBytes,
            NativeMars.EncryptBlock,
            "MARS");
        Require(marsChecked >= 10, $"Only {marsChecked} MARS vectors were exercised.");

        int shacalChecked = RunBlockVectors(
            Path.Combine(vectorRoot, "shacal2.txt"),
            NativeShacal2.BlockBytes,
            NativeShacal2.EncryptBlock,
            "SHACAL-2");
        Require(shacalChecked >= 1000, $"Only {shacalChecked} SHACAL-2 vectors were exercised.");

        VerifyMars448AgainstIndependentOracle();


        Require(NativeAes.IsAvailable(), $"AES reference library unavailable: {NativeAes.LastLoadError}");
        Require(NativeChaChaPoly.IsAvailable(), $"ChaCha20-Poly1305 library unavailable: {NativeChaChaPoly.LastLoadError}");

        NativeAesRuntimeProvider aesProvider = NativeAes.RuntimeProvider;
        if (OperatingSystem.IsMacOS()
            && RuntimeInformation.ProcessArchitecture == Architecture.Arm64)
        {
            Require(
                aesProvider == NativeAesRuntimeProvider.ArmV8,
                $"Apple-silicon AES selected {aesProvider} instead of the mandatory Crypto++ ArmV8 provider.");
        }
        Console.WriteLine($"    AES Crypto++ runtime provider: {aesProvider}");

        // FIPS-197 C.3: the published AES-256 known-answer.
        byte[] fipsKey = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        byte[] fipsBlock = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
        byte[] fipsActual = new byte[NativeAes.BlockBytes];
        NativeAes.EncryptBlock(fipsKey, fipsBlock, fipsActual);
        Require(
            Convert.ToHexString(fipsActual) == "8EA2B7CA516745BFEAFC49904B496089",
            $"AES-256 does not reproduce the FIPS-197 vector: {Convert.ToHexString(fipsActual)}.");

        // The native Crypto++ AES used by production and the independent .NET
        // platform AES test oracle must agree. A disagreement means one of the
        // two block implementations is wrong; a production roundtrip could
        // not reveal that because both directions would share the same fault.
        for (int trial = 0; trial < 16; trial++)
        {
            byte[] key = RandomNumberGenerator.GetBytes(32);
            byte[] block = RandomNumberGenerator.GetBytes(NativeAes.BlockBytes);
            byte[] reference = new byte[NativeAes.BlockBytes];
            NativeAes.EncryptBlock(key, block, reference);

            using var platform = Aes.Create();
            platform.Key = key;
            platform.Mode = CipherMode.ECB;
            platform.Padding = PaddingMode.None;
            byte[] managed = platform.EncryptEcb(block, PaddingMode.None);

            Require(
                reference.AsSpan().SequenceEqual(managed),
                $"The platform AES and the reference AES disagree: "
                + $"{Convert.ToHexString(managed)} against {Convert.ToHexString(reference)}.");
        }

        // RFC 8439 section 2.8.2, ciphertext and tag.
        byte[] aeadKey = Convert.FromHexString(
            "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F");
        byte[] aeadNonce = Convert.FromHexString("070000004041424344454647");
        byte[] aeadAad = Convert.FromHexString("50515253C0C1C2C3C4C5C6C7");
        byte[] aeadPlain = System.Text.Encoding.ASCII.GetBytes(
            "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
        byte[] aeadCipher = new byte[aeadPlain.Length];
        byte[] aeadTag = new byte[NativeChaChaPoly.TagBytes];
        NativeChaChaPoly.Encrypt(aeadKey, aeadNonce, aeadAad, aeadPlain, aeadCipher, aeadPlain.Length, aeadTag);
        Require(
            Convert.ToHexString(aeadTag) == "1AE10B594F09E26A7E902ECBD0600691",
            $"ChaCha20-Poly1305 does not reproduce the RFC 8439 tag: {Convert.ToHexString(aeadTag)}.");

        byte[] aeadRestored = new byte[aeadPlain.Length];
        NativeChaChaPoly.Decrypt(aeadKey, aeadNonce, aeadAad, aeadCipher, aeadRestored, aeadPlain.Length, aeadTag);
        Require(aeadRestored.AsSpan().SequenceEqual(aeadPlain), "ChaCha20-Poly1305 did not round trip.");

        // An AEAD that decrypts a tampered ciphertext is not an AEAD. Both the
        // tag and the associated data must be refused when altered.
        byte[] brokenTag = (byte[])aeadTag.Clone();
        brokenTag[0] ^= 1;
        RequireThrows<CryptographicException>(
            () => NativeChaChaPoly.Decrypt(
                aeadKey, aeadNonce, aeadAad, aeadCipher, aeadRestored, aeadPlain.Length, brokenTag),
            "ChaCha20-Poly1305 accepted a flipped authentication tag.");

        byte[] brokenAad = (byte[])aeadAad.Clone();
        brokenAad[0] ^= 1;
        RequireThrows<CryptographicException>(
            () => NativeChaChaPoly.Decrypt(
                aeadKey, aeadNonce, brokenAad, aeadCipher, aeadRestored, aeadPlain.Length, aeadTag),
            "ChaCha20-Poly1305 accepted altered associated data.");

        byte[] marsCtrKey = CreateCtrTestBytes(56, 0x4D415253);
        byte[] shacalCtrKey = CreateCtrTestBytes(64, 0x53484143);
        byte[] threefishCtrKey = CreateCtrTestBytes(128, 0x54485245);
        byte[] threefishTweak = CreateCtrTestBytes(16, 0x54574541);
        try
        {
            AssertCtrMatchesBlockReference(
                "MARS-448",
                NativeMars.BlockBytes,
                (nonce, input, output, length) => NativeMars.XCryptCtr448(
                    marsCtrKey, nonce, input, output, length),
                (input, output) => NativeMars.EncryptBlock(marsCtrKey, input, output));
            AssertCtrMatchesBlockReference(
                "SHACAL-2-512",
                NativeShacal2.BlockBytes,
                (nonce, input, output, length) => NativeShacal2.XCryptCtr512(
                    shacalCtrKey, nonce, input, output, length),
                (input, output) => NativeShacal2.EncryptBlock(shacalCtrKey, input, output));
            AssertCtrMatchesBlockReference(
                "Threefish-1024",
                128,
                (nonce, input, output, length) => NativeThreefish.XCryptCtr1024(
                    threefishCtrKey, threefishTweak, nonce, input, output, length),
                (input, output) => NativeThreefish.EncryptBlock1024(
                    threefishCtrKey, threefishTweak, input, output));
        }
        finally
        {
            Zero(marsCtrKey, shacalCtrKey, threefishCtrKey, threefishTweak);
        }

        AssertNativeCtrCounterBoundary(
            "AES-256",
            NativeAes.BlockBytes,
            (nonce, input, output) => NativeAes.XCryptCtr256(
                new byte[32], nonce, input, output, input.Length));
        AssertNativeCtrCounterBoundary(
            "MARS-448",
            NativeMars.BlockBytes,
            (nonce, input, output) => NativeMars.XCryptCtr448(
                new byte[56], nonce, input, output, input.Length));
        AssertNativeCtrCounterBoundary(
            "SHACAL-2-512",
            NativeShacal2.BlockBytes,
            (nonce, input, output) => NativeShacal2.XCryptCtr512(
                new byte[64], nonce, input, output, input.Length));
        AssertNativeCtrCounterBoundary(
            "Kalyna-512/512",
            64,
            (nonce, input, output) => NativeKalyna.XCryptCtr512(
                new byte[64], nonce, input, output, input.Length));
        AssertNativeCtrCounterBoundary(
            "Threefish-1024",
            128,
            (nonce, input, output) => NativeThreefish.XCryptCtr1024(
                new byte[128], new byte[16], nonce, input, output, input.Length));

        return Task.CompletedTask;
    }


    /// <summary>
    /// Checks MARS against answers produced by a different implementation,
    /// including the 448-bit keys the cascade actually uses.
    /// </summary>
    /// <remarks>
    /// The AES submission published vectors for 128, 192 and 256-bit keys only,
    /// so the key length this app depends on had no authoritative check. These
    /// answers come from Botan 1.10.17's MARS, an independent implementation
    /// line, and the file records its provenance and the published vector it
    /// was validated against before being trusted.
    ///
    /// The oracle had to be validated first for a concrete reason: Brian
    /// Gladman's widely mirrored mars.c predates the 22 September 1999 MARS
    /// revision and implements the older key schedule. It disagrees with
    /// Crypto++ and with the published vectors, and using it unchecked would
    /// have produced a failure that pointed at this repository instead of at
    /// the oracle.
    ///
    /// Only the raw block cipher is compared. CTR is checked separately, so a
    /// disagreement here means the MARS primitive, and a disagreement there
    /// means the counter mode — two implementations can both be correct and
    /// still differ on counter endianness.
    /// </remarks>
    private static void VerifyMars448AgainstIndependentOracle()
    {
        string path = Path.Combine(AppContext.BaseDirectory, "MarsKnownAnswers.txt");
        Require(File.Exists(path), $"The MARS known-answer file is missing: {path}");

        var perLength = new Dictionary<int, int>();
        foreach (string rawLine in File.ReadLines(path))
        {
            string line = rawLine.Trim();
            if (line.Length == 0 || line[0] == '#')
            {
                continue;
            }

            string[] parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            Require(parts.Length == 3, $"Malformed MARS known-answer line: {line}");

            byte[] key = Convert.FromHexString(parts[0]);
            byte[] plain = Convert.FromHexString(parts[1]);
            byte[] expected = Convert.FromHexString(parts[2]);

            byte[] actual = new byte[NativeMars.BlockBytes];
            NativeMars.EncryptBlock(key, plain, actual);
            Require(
                actual.AsSpan().SequenceEqual(expected),
                $"MARS disagrees with the independent oracle at a {key.Length * 8}-bit key: "
                + $"got {Convert.ToHexString(actual)}, expected {parts[2]}.");

            perLength[key.Length * 8] = perLength.GetValueOrDefault(key.Length * 8) + 1;
        }

        Require(
            perLength.GetValueOrDefault(448) >= 32,
            $"Only {perLength.GetValueOrDefault(448)} MARS answers cover the 448-bit key the cascade uses.");
        Require(perLength.Count >= 6, $"Only {perLength.Count} MARS key lengths were covered.");
    }

    /// <summary>
    /// Reads Key/Plaintext/Ciphertext triples out of a Crypto++ vector file and
    /// runs the ones whose block size matches.
    /// </summary>
    private static int RunBlockVectors(
        string path,
        int blockBytes,
        Action<byte[], byte[], byte[]> encryptBlock,
        string label)
    {
        Require(File.Exists(path), $"{label} vector file is missing: {path}");

        string? key = null;
        string? plaintext = null;
        string? ciphertext = null;
        int exercised = 0;

        foreach (string rawLine in File.ReadLines(path))
        {
            string line = rawLine.Trim();
            int separator = line.IndexOf(':');
            if (separator <= 0)
            {
                continue;
            }

            string name = line[..separator].Trim();
            string value = line[(separator + 1)..].Trim();

            switch (name)
            {
                case "Key":
                    key = value;
                    break;
                case "Plaintext":
                    plaintext = value;
                    break;
                case "Ciphertext":
                    ciphertext = value;
                    break;
                case "Test":
                    if (value == "Encrypt" && key is not null && plaintext is not null && ciphertext is not null)
                    {
                        byte[] keyBytes = Convert.FromHexString(key);
                        byte[] input = Convert.FromHexString(plaintext);
                        byte[] expected = Convert.FromHexString(ciphertext);
                        if (input.Length == blockBytes && expected.Length == blockBytes)
                        {
                            byte[] actual = new byte[blockBytes];
                            encryptBlock(keyBytes, input, actual);
                            Require(
                                actual.AsSpan().SequenceEqual(expected),
                                $"{label} vector mismatch for a {keyBytes.Length * 8}-bit key: "
                                + $"got {Convert.ToHexString(actual)}, expected {ciphertext}.");
                            exercised++;
                        }
                    }

                    plaintext = null;
                    ciphertext = null;
                    break;
            }
        }

        return exercised;
    }

    /// <summary>
    /// Finds external/cryptopp/TestVectors by walking up from the test binary.
    /// </summary>
    private static string ResolveVectorDirectory()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            string candidate = Path.Combine(directory.FullName, "external", "cryptopp", "TestVectors");
            if (Directory.Exists(candidate))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        throw new InvalidOperationException("external/cryptopp/TestVectors was not found above the test binary.");
    }

    private static async Task TestPerChunkNoncesAsync()
    {
        const int chunkSize = 16 * 1024 * 1024;
        string root = CreateTempRoot("keep-vault-chunk-nonce-");
        try
        {
            // Encryption runs directly on the ZPAQ stream, so no compression
            // sits between this payload and the cipher: two identical 16 MiB
            // halves reach the cipher as exactly two identical chunks.
            byte[] half = new byte[chunkSize];
            for (int index = 0; index < half.Length; index++)
            {
                half[index] = (byte)(index & 0xFF);
            }

            byte[] payload = new byte[2 * chunkSize];
            half.CopyTo(payload, 0);
            half.CopyTo(payload, chunkSize);

            foreach (EncryptionSuite suite in Enum.GetValues<EncryptionSuite>())
            {
                AddMouseSamplesUntilReady();
                using GeneratedArchiveEntropy entropy = EntropyMixer.CreateArchiveEntropy();
                var containers = new KalynaContainerService();
                string archive = Path.Combine(root, $"{suite}.kzpaq");

                await using (var input = new MemoryStream(payload, writable: false))
                {
                    await containers.EncryptZpaqStreamWithPreparedEntropyAsync(
                        input,
                        archive,
                        UserPassword,
                        UserPin,
                        entropy.FirstPassword,
                        entropy.SecondPassword,
                        suite,
                        entropy,
                        null,
                        null,
                        CancellationToken.None).ConfigureAwait(false);
                }

                byte[] container = await File.ReadAllBytesAsync(archive).ConfigureAwait(false);
                Require(
                    container.LongLength > chunkSize,
                    $"{suite}: the container is only {container.LongLength} bytes and cannot span two chunks.");

                // The last 1 MiB of the ciphertext against the 1 MiB exactly one
                // chunk earlier. The plaintext under both is identical, so with a
                // single counter running across the archive these would differ
                // only by the counter — and with a per-chunk nonce they differ
                // completely. Identical here would mean the nonce never moved.
                const int span = 1 << 20;
                ReadOnlySpan<byte> first = container.AsSpan(container.Length - chunkSize - span, span);
                ReadOnlySpan<byte> second = container.AsSpan(container.Length - span, span);
                Require(
                    !first.SequenceEqual(second),
                    $"{suite}: two ciphertext regions one chunk apart are identical; the chunk nonce did not change.");

                // A derivation the reader disagrees with would also produce
                // different ciphertext per chunk and would still pass the check
                // above, so the roundtrip is what proves both sides agree.
                await using var output = new MemoryStream();
                await containers.DecryptToStreamAsync(
                    archive,
                    UserPassword,
                    UserPin,
                    entropy.FirstPassword,
                    entropy.SecondPassword,
                    output,
                    null,
                    CancellationToken.None).ConfigureAwait(false);

                Require(
                    output.Length == payload.LongLength,
                    $"{suite}: the restored payload is {output.Length} bytes rather than {payload.LongLength}.");
                Require(
                    output.ToArray().AsSpan().SequenceEqual(payload),
                    $"{suite}: the restored multi-chunk payload does not match the original.");

                File.Delete(archive);
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static async Task TestTwoRoundDerivationAsync()
    {
        // SHA-512 must agree with the published digests and with the second
        // implementation before anything derived from it is trusted.
        byte[] abc = Sha512Compat.HashData("abc"u8);
        Require(
            Convert.ToHexString(abc) ==
            "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A"
            + "2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F",
            "SHA-512 did not reproduce the FIPS 180-4 digest for \"abc\".");
        Require(
            !Convert.ToHexString(Sha512Compat.HashData(ReadOnlySpan<byte>.Empty)).SequenceEqual(
                Convert.ToHexString(abc)),
            "SHA-512 returned the same digest for different messages.");

        foreach (EncryptionSuite suite in new[] { EncryptionSuite.ThreefishOverKalyna, EncryptionSuite.Kalyna512_512 })
        {
            AddMouseSamplesUntilReady();
            using TwoRoundEncryptionParameters parameters = EntropyMixer.CreateTwoRoundEncryptionParameters(suite);

            Require(
                parameters.FirstSalt.Bytes.Length == parameters.SecondSalt.Bytes.Length,
                $"{suite}: the two rounds produced salts of different lengths.");
            Require(
                !parameters.FirstSalt.Bytes.SequenceEqual(parameters.SecondSalt.Bytes),
                $"{suite}: both Argon2id rounds produced the same salt.");
            Require(
                !parameters.FirstNonce.Bytes.SequenceEqual(parameters.SecondNonce.Bytes),
                $"{suite}: both Argon2id rounds produced the same nonce.");

            int expectedNonce = EncryptionSuiteCatalog.Get(suite).NonceBytes;
            Require(
                parameters.FirstNonce.Bytes.Length == expectedNonce
                && parameters.SecondNonce.Bytes.Length == expectedNonce,
                $"{suite}: a round produced a nonce of the wrong length.");

            // Neither salt nor nonce may be all zeros or otherwise degenerate;
            // a buffer that was allocated but never filled would still be
            // "different" from the other round by accident of the XOR.
            Require(
                parameters.FirstSalt.Bytes.Any(b => b != 0)
                && parameters.SecondSalt.Bytes.Any(b => b != 0)
                && parameters.FirstNonce.Bytes.Any(b => b != 0)
                && parameters.SecondNonce.Bytes.Any(b => b != 0),
                $"{suite}: a round produced an all-zero salt or nonce.");

            // The halves must not share long runs. Independent material from two
            // different hash constructions has no reason to agree anywhere, and
            // a copy-paste in the split would show up exactly here.
            int shared = 0;
            for (int index = 0; index < parameters.FirstNonce.Bytes.Length; index++)
            {
                if (parameters.FirstNonce.Bytes[index] == parameters.SecondNonce.Bytes[index])
                {
                    shared++;
                }
            }

            Require(
                shared < parameters.FirstNonce.Bytes.Length / 4,
                $"{suite}: the two rounds' nonces agree in {shared} of {parameters.FirstNonce.Bytes.Length} bytes.");
        }

        // The whole reason both rounds share one consumption: asking for them
        // must not leave the pools needing to be refilled beyond the single
        // consumption the first round would have cost anyway.
        AddMouseSamplesUntilReady();
        using (TwoRoundEncryptionParameters _ = EntropyMixer.CreateTwoRoundEncryptionParameters(
            EncryptionSuite.ThreefishOverKalyna))
        {
        }

        Require(
            !EntropyMixer.HasRequiredSamples(EntropyPurpose.SaltSha3),
            "The two-round derivation did not consume the salt pool exactly once.");

        // The regression test that lived here proved round two no longer ran
        // over a zeroed prehash. v12 does not share a prehash between rounds at
        // all: round two takes round one's complete master as Argon2id's secret
        // input, which the KDF-properties group verifies directly by changing a
        // single bit of round one and observing round two change with it.
    }

    private static byte[] BuildLengthPrefixedMessage(params byte[][] values)
    {
        byte[] result = new byte[values.Sum(value => sizeof(int) + value.Length)];
        int offset = 0;
        foreach (byte[] value in values)
        {
            BinaryPrimitives.WriteInt32LittleEndian(result.AsSpan(offset, sizeof(int)), value.Length);
            offset += sizeof(int);
            value.CopyTo(result, offset);
            offset += value.Length;
        }

        return result;
    }

    private static void AddMouseSamplesUntilReady()
    {
        int index = 0;
        // Every purpose, read from the enumeration. Listing them by hand is how
        // a pool added later quietly stops being filled.
        while (Enum.GetValues<EntropyPurpose>().Any(purpose => !EntropyMixer.HasRequiredSamples(purpose)))
        {
            EntropyMixer.AddMouseSample(
                100.125 + (index * 0.003),
                200.875 + (index * 0.007),
                Environment.TickCount ^ index,
                (index & 1) != 0,
                (index & 2) != 0,
                (index & 4) != 0);
            index++;
        }
    }

    private static string GeneratedFactor(char value) => new(value, PasswordKeyService.GeneratedPasswordLength);

    private static string CreateTempRoot(string prefix)
    {
        string path = Directory.CreateTempSubdirectory(prefix).FullName;
        string canonical = MacSafeFileSystem.ResolveExistingRealPath(path);
        File.SetUnixFileMode(canonical, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return canonical;
    }

    private static string CopyContainer(string source, string root, string name)
    {
        string target = Path.Combine(root, name);
        File.Copy(source, target);
        return target;
    }

    private static void AddHeaderWhitespace(string path)
    {
        byte[] file = File.ReadAllBytes(path);
        byte[]? changed = null;
        try
        {
            int headerLength = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(7, 4));
            int headerOffset = 11;
            Require(headerLength > 0 && headerOffset + headerLength <= file.Length, "Mutation fixture header is invalid.");
            changed = new byte[file.Length + 1];
            file.AsSpan(0, headerOffset + 1).CopyTo(changed);
            changed[headerOffset + 1] = (byte)' ';
            file.AsSpan(headerOffset + 1).CopyTo(changed.AsSpan(headerOffset + 2));
            BinaryPrimitives.WriteInt32LittleEndian(changed.AsSpan(7, 4), headerLength + 1);
            File.WriteAllBytes(path, changed);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(file);
            if (changed is not null) CryptographicOperations.ZeroMemory(changed);
        }
    }

    private static void ReplaceHeaderToken(string path, string oldToken, string newToken)
    {
        byte[] file = File.ReadAllBytes(path);
        byte[]? replacement = null;
        try
        {
            int headerLength = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(7, 4));
            const int headerOffset = 11;
            string header = Encoding.UTF8.GetString(file, headerOffset, headerLength);
            Require(header.CountOccurrences(oldToken) == 1, $"Header mutation token is not unique: {oldToken}");
            byte[] nextHeader = Encoding.UTF8.GetBytes(header.Replace(oldToken, newToken, StringComparison.Ordinal));
            try
            {
                int suffix = headerOffset + headerLength;
                replacement = new byte[headerOffset + nextHeader.Length + file.Length - suffix];
                file.AsSpan(0, 7).CopyTo(replacement);
                BinaryPrimitives.WriteInt32LittleEndian(replacement.AsSpan(7, 4), nextHeader.Length);
                nextHeader.CopyTo(replacement.AsSpan(headerOffset));
                file.AsSpan(suffix).CopyTo(replacement.AsSpan(headerOffset + nextHeader.Length));
                File.WriteAllBytes(path, replacement);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(nextHeader);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(file);
            if (replacement is not null) CryptographicOperations.ZeroMemory(replacement);
        }
    }

    private static void FlipContainerTag(string path, bool skein)
    {
        using FileStream stream = File.Open(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        Span<byte> headerLength = stackalloc byte[4];
        stream.Position = 7;
        stream.ReadExactly(headerLength);
        long offset = 11L + BinaryPrimitives.ReadInt32LittleEndian(headerLength) + (skein ? 64 : 0);
        stream.Position = offset;
        int value = stream.ReadByte();
        Require(value >= 0, "Authentication-tag mutation offset is invalid.");
        stream.Position = offset;
        stream.WriteByte((byte)(value ^ 0x01));
        stream.Flush(flushToDisk: true);
    }

    private static void FlipRange(string path, long offset, int length)
    {
        byte[] changed = RandomNumberGenerator.GetBytes(length);
        try
        {
            using FileStream stream = File.Open(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            stream.Position = offset;
            stream.Write(changed);
            stream.Flush(flushToDisk: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(changed);
        }
    }

    private static void FlipByte(string path, long offset)
    {
        using FileStream stream = File.Open(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        stream.Position = offset;
        int value = stream.ReadByte();
        Require(value >= 0, "Mutation offset is outside the file.");
        stream.Position = offset;
        stream.WriteByte((byte)(value ^ 0x01));
        stream.Flush(flushToDisk: true);
    }

    private static async Task<byte[]> HashFileAsync(string path)
    {
        await using FileStream stream = MacSafeFileSystem.OpenReadNoSymlinks(path);
        var digest = new Org.BouncyCastle.Crypto.Digests.Sha3Digest(512);
        byte[] buffer = new byte[1024 * 1024];
        byte[] output = new byte[64];
        try
        {
            int read;
            while ((read = await stream.ReadAsync(buffer).ConfigureAwait(false)) > 0)
            {
                digest.BlockUpdate(buffer, 0, read);
            }

            digest.DoFinal(output, 0);
            return output;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(output);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    private static async Task RequireFileHashAsync(string path, byte[] expected, string label)
    {
        byte[] actual = await HashFileAsync(path).ConfigureAwait(false);
        try
        {
            Require(FixedEqual(expected, actual), $"{label} content hash mismatch.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actual);
        }
    }

    private static async Task<ProcessResult> RunProcessAsync(string executable, IReadOnlyList<string> arguments, string workingDirectory)
    {
        var start = new ProcessStartInfo
        {
            FileName = executable,
            WorkingDirectory = workingDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (string argument in arguments) start.ArgumentList.Add(argument);
        using Process process = Process.Start(start) ?? throw new InvalidOperationException($"Could not start {executable}.");
        string stdout = await process.StandardOutput.ReadToEndAsync().ConfigureAwait(false);
        string stderr = await process.StandardError.ReadToEndAsync().ConfigureAwait(false);
        await process.WaitForExitAsync().ConfigureAwait(false);
        return new ProcessResult(process.ExitCode, stdout, stderr);
    }

    private static byte[] WordsToLittleEndian(ulong[] words)
    {
        byte[] bytes = new byte[words.Length * sizeof(ulong)];
        for (int index = 0; index < words.Length; index++)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(index * sizeof(ulong)), words[index]);
        }

        return bytes;
    }

    private static bool FixedEqual(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static void RequireHex(byte[] actual, string expected, string label)
    {
        try
        {
            Require(string.Equals(Convert.ToHexString(actual), expected, StringComparison.Ordinal), $"{label} mismatch.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actual);
        }
    }

    private static void Zero(params byte[][] arrays)
    {
        foreach (byte[] array in arrays) CryptographicOperations.ZeroMemory(array);
    }

    internal static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
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

    private static async Task<TException> CaptureThrowsAsync<TException>(Func<Task> action, string message)
        where TException : Exception
    {
        try
        {
            await action().ConfigureAwait(false);
        }
        catch (TException expected)
        {
            return expected;
        }

        throw new InvalidOperationException(message);
    }

    private static async Task RequireThrowsAsync<TException>(Func<Task> action, string message)
        where TException : Exception
    {
        try
        {
            await action().ConfigureAwait(false);
        }
        catch (TException)
        {
            return;
        }

        throw new InvalidOperationException(message);
    }

    private sealed class ShortReadStream(byte[] data, int maxRead) : Stream
    {
        private int _position;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => data.Length;
        public override long Position { get => _position; set => throw new NotSupportedException(); }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int count = Math.Min(Math.Min(buffer.Length, maxRead), data.Length - _position);
            if (count <= 0) return ValueTask.FromResult(0);
            data.AsMemory(_position, count).CopyTo(buffer);
            _position += count;
            return ValueTask.FromResult(count);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int actual = Math.Min(Math.Min(count, maxRead), data.Length - _position);
            if (actual <= 0) return 0;
            Buffer.BlockCopy(data, _position, buffer, offset, actual);
            _position += actual;
            return actual;
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private static async Task TestV12MasterKdfAsync()
    {
        const string Algorithm = "Test-Suite-v12";
        const string Password = "N!r7$Vq2#Lm8%Tx3&Jd9*Wp4+Kg5=Zu6?Ce";
        const string Pin = "0428193";
        byte[] factorA = RandomNumberGenerator.GetBytes(128);
        byte[] factorB = RandomNumberGenerator.GetBytes(128);

        // --- credential paths ----------------------------------------------
        byte[] qs = V12MasterKdf.DeriveSha3CredentialHash(Algorithm, Password, Pin, factorA, factorB);
        byte[] qk = V12MasterKdf.DeriveSkeinCredentialHash(Algorithm, Password, Pin, factorA, factorB);
        Require(qs.Length == 128 && qk.Length == 128, "A v12 credential hash is not 1024 bits.");
        Require(!FixedEqual(qs, qk), "Both credential paths produced the same value.");

        // Factor role binding: (A, B) != (B, A)
        byte[] qsSwapped = V12MasterKdf.DeriveSha3CredentialHash(Algorithm, Password, Pin, factorB, factorA);
        byte[] qkSwapped = V12MasterKdf.DeriveSkeinCredentialHash(Algorithm, Password, Pin, factorB, factorA);
        Require(!FixedEqual(qs, qsSwapped), "v12 SHA3 credential path is symmetric in factors (A,B) vs (B,A).");
        Require(!FixedEqual(qk, qkSwapped), "v12 Skein credential path is symmetric in factors (A,B) vs (B,A).");

        // --- Comprehensive 256-Byte Mutation Isolation Testing (512/512 Factor Split) ---
        // Mutating each byte of factor A:
        for (int i = 0; i < 128; i++)
        {
            byte[] mutA = (byte[])factorA.Clone();
            mutA[i] ^= 0x5A;
            byte[] mutQs = V12MasterKdf.DeriveSha3CredentialHash(Algorithm, Password, Pin, mutA, factorB);
            if (i < 64)
            {
                // A1 slice: Q_S1 MUST change, Q_S2 MUST be 100% bit-exact identical
                Require(!FixedEqual(qs[..64], mutQs[..64]), $"Factor A mutation at index {i} did not change Q_S1.");
                Require(FixedEqual(qs[64..], mutQs[64..]), $"Factor A mutation at index {i} (A1) leaked into Q_S2.");
            }
            else
            {
                // A2 slice: Q_S1 MUST be 100% bit-exact identical, Q_S2 MUST change
                Require(FixedEqual(qs[..64], mutQs[..64]), $"Factor A mutation at index {i} (A2) leaked into Q_S1.");
                Require(!FixedEqual(qs[64..], mutQs[64..]), $"Factor A mutation at index {i} did not change Q_S2.");
            }
        }

        // Mutating each byte of factor B:
        for (int i = 0; i < 128; i++)
        {
            byte[] mutB = (byte[])factorB.Clone();
            mutB[i] ^= 0xA5;
            byte[] mutQs = V12MasterKdf.DeriveSha3CredentialHash(Algorithm, Password, Pin, factorA, mutB);
            if (i < 64)
            {
                // B1 slice: Q_S1 MUST change, Q_S2 MUST be 100% bit-exact identical
                Require(!FixedEqual(qs[..64], mutQs[..64]), $"Factor B mutation at index {i} did not change Q_S1.");
                Require(FixedEqual(qs[64..], mutQs[64..]), $"Factor B mutation at index {i} (B1) leaked into Q_S2.");
            }
            else
            {
                // B2 slice: Q_S1 MUST be 100% bit-exact identical, Q_S2 MUST change
                Require(FixedEqual(qs[..64], mutQs[..64]), $"Factor B mutation at index {i} (B2) leaked into Q_S1.");
                Require(!FixedEqual(qs[64..], mutQs[64..]), $"Factor B mutation at index {i} did not change Q_S2.");
            }
        }

        // Explicit boundary tests on 0, 63, 64, 127
        foreach (int idx in new[] { 0, 63, 64, 127 })
        {
            byte[] mutA = (byte[])factorA.Clone();
            mutA[idx] ^= 0xFF;
            byte[] mutQs = V12MasterKdf.DeriveSha3CredentialHash(Algorithm, Password, Pin, mutA, factorB);
            if (idx <= 63)
            {
                Require(!FixedEqual(qs[..64], mutQs[..64]) && FixedEqual(qs[64..], mutQs[64..]),
                    $"Boundary test failed at factor A index {idx}");
            }
            else
            {
                Require(FixedEqual(qs[..64], mutQs[..64]) && !FixedEqual(qs[64..], mutQs[64..]),
                    $"Boundary test failed at factor A index {idx}");
            }
        }

        // --- Skein MAC Key integrity ---------------------------------------
        // Skein key uses A || B (full 256 bytes) so ANY byte change changes full Skein credential
        for (int i = 0; i < 128; i += 31)
        {
            byte[] mutA = (byte[])factorA.Clone();
            mutA[i] ^= 0x33;
            byte[] mutQk = V12MasterKdf.DeriveSkeinCredentialHash(Algorithm, Password, Pin, mutA, factorB);
            Require(!FixedEqual(qk, mutQk), $"Skein MAC ignored mutation in factor A at index {i}.");
        }

        // --- PMI and memory cost -------------------------------------------
        byte[] saltSha3 = Enumerable.Range(0, 64).Select(i => (byte)(i * 3 + 1)).ToArray();
        byte[] saltSkein = Enumerable.Range(0, 64).Select(i => (byte)(i * 5 + 7)).ToArray();
        (ushort pmi, uint memory) = V12MasterKdf.DerivePmi(
            Algorithm, 1, qs, qk, [], saltSha3, saltSkein);
        Require(
            memory >= V12MasterKdf.MemoryMinKiB && memory <= V12MasterKdf.MemoryMaxKiB,
            $"The derived memory cost {memory} KiB is outside 1 GiB..2 GiB-16 KiB.");
        Require(
            (memory - V12MasterKdf.MemoryMinKiB) % V12MasterKdf.MemoryStepKiB == 0,
            "The derived memory cost is not on the 16 KiB grid.");
        Require(
            memory == V12MasterKdf.MemoryMinKiB + (16u * pmi),
            "The memory cost does not follow m = 1 GiB + 16*PMI.");

        // --- v12 master round derivation and exact known-answer tests ------
        //
        // The two SHA3 halves are pinned against values produced outside this
        // implementation (Python hashlib SHA3-512 over the same length-prefixed
        // message), so the 512/512 split, both domain strings and the message
        // encoding cannot drift. Q_K, the PMI values and both round masters are
        // frozen composition vectors: the primitives underneath them are
        // separately covered by the Skein-1024 official-vector tests and the
        // Argon2id PHC reference-CLI comparison, so what these pin is the way
        // v12 wires them together - key = A||B, secret K = full M1, which salt
        // feeds which branch, and the interleave order.
        const string KatAlgorithm = "Kalyna-512/Threefish-1024/v12";
        const string KatPassword = "N!r7$Vq2#Lm8%Tx3&Jd9*Wp4+Kg5=Zu6?Ce";
        const string KatPin = "428317";
        byte[] katFactorA = Enumerable.Range(0, 128).Select(i => (byte)((i * 7) + 3)).ToArray();
        byte[] katFactorB = Enumerable.Range(0, 128).Select(i => (byte)((i * 13) + 11)).ToArray();
        byte[] katSaltSha3Round1 = Enumerable.Range(0, 64).Select(i => (byte)((i * 17) + 5)).ToArray();
        byte[] katSaltSkeinRound1 = Enumerable.Range(0, 64).Select(i => (byte)((i * 19) + 23)).ToArray();
        byte[] katSaltSha3Round2 = Enumerable.Range(0, 64).Select(i => (byte)((i * 29) + 31)).ToArray();
        byte[] katSaltSkeinRound2 = Enumerable.Range(0, 64).Select(i => (byte)((i * 37) + 41)).ToArray();

        const string ExpectedQs1 =
            "92BEA2914B9F5710766E96C6376841513A12DC9D5450A814344432E147F151C8"
            + "EA2590240C84936D353BDEE85C3C6B7E33215BC0E8C175B7A6F37BA66BC1999B";
        const string ExpectedQs2 =
            "7014DB1862D3AED6338B07CAD00DB60420138BFC15E7EB5EEC9CB5C0CF47C068"
            + "3AB47D248CE5D61C4FCD7F3855D1FE4C8CA3E3A9D9C6AFA8BCF08BF854149A71";
        const string ExpectedQk =
            "5E0E22CD6C79449323DA80AF74DAE373FE56D9799887002DC1B9D89A8EF752CC"
            + "7DAB06ACE5FEEBE43A75AA98659136A1A66FB910026B1C07E6D2AA6A06E8EFC3"
            + "F03D5C0EAB0F3BFEFC6C4709A57C92B8A9EA5770C301C0926BE8E486B881FDCC"
            + "7A1184893CFBB25BBF6244D761BC0CA81C52091BBB97D08046E827907C4A6805";
        const ushort ExpectedPmi1 = 27922;
        const uint ExpectedMemory1 = 1_495_328;
        const string ExpectedMaster1 =
            "FFB0A3FAADEB67DBDB2BD90F419693300C4E165BCFC2446D76BF7D99FBDD358C"
            + "04D64A733B1012EDA348DE22F04000B2CD1EB5E41474AC9D8F9FC90EB6D86056"
            + "C33AE0C7A3614635C47305817775D92DA0910F82DEC0F5E598B9D9A9D9130332"
            + "4FBEE5B6F04570420F2CD62778FC2719D981A747D3B8878EA622D15F6FE675D1";
        const ushort ExpectedPmi2 = 3279;
        const uint ExpectedMemory2 = 1_101_040;
        const string ExpectedMaster2 =
            "CEF0250D3E7C6055EE299AAB4A72BABEFCAAD84DD57BA21ABEC4D555E33EDDD4"
            + "DDE92FB63183D9D890B052C4090A48DDCED10A52BB05915D32FA4AC09E7C9C95"
            + "32F4C11A72D0B50F300D0FEA640BF72346993782331CDAF49112B8C67CDE4CDD"
            + "8298770DA3E33AB8F20BBEB007BCAB4D67C76D9374775D62619136CB5030BDC5";

        byte[] katQs = V12MasterKdf.DeriveSha3CredentialHash(KatAlgorithm, KatPassword, KatPin, katFactorA, katFactorB);
        byte[] katQk = V12MasterKdf.DeriveSkeinCredentialHash(KatAlgorithm, KatPassword, KatPin, katFactorA, katFactorB);
        Require(katQs.Length == 128 && katQk.Length == 128, "A v12 KAT credential hash is not 1024 bits.");
        Require(
            Convert.ToHexString(katQs.AsSpan(0, 64)) == ExpectedQs1,
            $"v12 KAT Q_S1 mismatch: {Convert.ToHexString(katQs.AsSpan(0, 64))}");
        Require(
            Convert.ToHexString(katQs.AsSpan(64, 64)) == ExpectedQs2,
            $"v12 KAT Q_S2 mismatch: {Convert.ToHexString(katQs.AsSpan(64, 64))}");
        Require(
            Convert.ToHexString(katQs) == ExpectedQs1 + ExpectedQs2,
            "v12 KAT Q_S is not Q_S1 || Q_S2.");
        Require(
            Convert.ToHexString(katQk) == ExpectedQk,
            $"v12 KAT Q_K mismatch: {Convert.ToHexString(katQk)}");

        (ushort katPmi1, uint katMemory1) = V12MasterKdf.DerivePmi(
            KatAlgorithm, 1, katQs, katQk, [], katSaltSha3Round1, katSaltSkeinRound1);
        Require(
            katPmi1 == ExpectedPmi1 && katMemory1 == ExpectedMemory1,
            $"v12 KAT round 1 PMI/memory mismatch: {katPmi1}/{katMemory1}");
        Require(
            katMemory1 >= V12MasterKdf.MemoryMinKiB && katMemory1 <= V12MasterKdf.MemoryMaxKiB,
            "v12 KAT round 1 memory cost is outside 1 GiB..2 GiB-16 KiB.");
        Require(
            katMemory1 == V12MasterKdf.MemoryMinKiB + (V12MasterKdf.MemoryStepKiB * katPmi1),
            "v12 KAT round 1 memory cost does not follow m = 1 GiB + 16*PMI.");

        byte[] katRound1 = V12MasterKdf.DeriveRoundMaster(
            KatAlgorithm, 1, katQs, katQk, katSaltSha3Round1, katSaltSkeinRound1, null, katMemory1);
        Require(katRound1.Length == 128, "v12 KAT round 1 master is not 1024 bits.");
        Require(
            Convert.ToHexString(katRound1) == ExpectedMaster1,
            $"v12 KAT M1 mismatch: {Convert.ToHexString(katRound1)}");

        (ushort katPmi2, uint katMemory2) = V12MasterKdf.DerivePmi(
            KatAlgorithm, 2, katQs, katQk, katRound1, katSaltSha3Round2, katSaltSkeinRound2);
        Require(
            katPmi2 == ExpectedPmi2 && katMemory2 == ExpectedMemory2,
            $"v12 KAT round 2 PMI/memory mismatch: {katPmi2}/{katMemory2}");
        Require(
            katMemory2 >= V12MasterKdf.MemoryMinKiB && katMemory2 <= V12MasterKdf.MemoryMaxKiB,
            "v12 KAT round 2 memory cost is outside 1 GiB..2 GiB-16 KiB.");
        Require(
            katMemory2 == V12MasterKdf.MemoryMinKiB + (V12MasterKdf.MemoryStepKiB * katPmi2),
            "v12 KAT round 2 memory cost does not follow m = 1 GiB + 16*PMI.");

        byte[] katRound2 = V12MasterKdf.DeriveRoundMaster(
            KatAlgorithm, 2, katQs, katQk, katSaltSha3Round2, katSaltSkeinRound2, katRound1, katMemory2);
        Require(katRound2.Length == 128, "v12 KAT round 2 master is not 1024 bits.");
        Require(!FixedEqual(katRound1, katRound2), "v12 KAT round 1 and round 2 masters collided.");
        Require(
            Convert.ToHexString(katRound2) == ExpectedMaster2,
            $"v12 KAT M2 mismatch: {Convert.ToHexString(katRound2)}");

        // Round 2 must consume the complete 128-byte M1 as the Argon2id secret.
        // A short secret is refused outright rather than zero-padded up to the
        // master width, which would have run Argon2 over half a master plus 64
        // bytes of padding and still produced a usable-looking key.
        byte[] truncatedSecret = katRound1[..64];
        RequireThrows<ArgumentException>(
            () => V12MasterKdf.DeriveRoundMaster(
                KatAlgorithm, 2, katQs, katQk, katSaltSha3Round2, katSaltSkeinRound2, truncatedSecret, katMemory2),
            "v12 round 2 accepted a truncated M1 as the Argon2id secret.");

        // A short credential hash is refused for the same reason.
        RequireThrows<ArgumentException>(
            () => V12MasterKdf.DeriveRoundMaster(
                KatAlgorithm, 1, katQs[..64], katQk, katSaltSha3Round1, katSaltSkeinRound1, null, katMemory1),
            "v12 accepted a truncated credential hash as the Argon2id password.");

        // An off-grid or out-of-range memory cost cannot reach Argon2 either.
        RequireThrows<CryptographicException>(
            () => V12MasterKdf.DeriveRoundMaster(
                KatAlgorithm, 1, katQs, katQk, katSaltSha3Round1, katSaltSkeinRound1, null, V12MasterKdf.MemoryMinKiB - 16),
            "v12 accepted an Argon2id memory cost below the PMI range.");
        RequireThrows<CryptographicException>(
            () => V12MasterKdf.DeriveRoundMaster(
                KatAlgorithm, 1, katQs, katQk, katSaltSha3Round1, katSaltSkeinRound1, null, V12MasterKdf.MemoryMinKiB + 1),
            "v12 accepted an Argon2id memory cost off the 16 KiB grid.");

        await Task.CompletedTask.ConfigureAwait(false);
        Zero(factorA, factorB, qs, qk, qsSwapped, qkSwapped, saltSha3, saltSkein,
            katFactorA, katFactorB, katSaltSha3Round1, katSaltSkeinRound1, katSaltSha3Round2, katSaltSkeinRound2,
            katQs, katQk, katRound1, katRound2, truncatedSecret);
    }

    private static async Task TestQuarantineAndSymlinkSafetyAsync()
    {
        string root = CreateTempRoot("keep-vault-quarantine-symlink-");
        try
        {
            // 1. Symlink-safe directory traversal:
            string safeDir = Path.Combine(root, "safe_dir");
            string subDir = Path.Combine(safeDir, "subdir");
            Directory.CreateDirectory(subDir);
            string f1 = Path.Combine(safeDir, "file1.bin");
            string f2 = Path.Combine(subDir, "file2.bin");
            await File.WriteAllBytesAsync(f1, [1, 2, 3]).ConfigureAwait(false);
            await File.WriteAllBytesAsync(f2, [4, 5, 6]).ConfigureAwait(false);

            // 0. Root-symlink refusal:
            string rootSymlink = Path.Combine(root, "root_link");
            Directory.CreateSymbolicLink(rootSymlink, safeDir);
            bool caughtRootSymlink = false;
            try
            {
                MacSafeFileSystem.EnumerateDirectoryTreeNoFollow(rootSymlink);
            }
            catch (IOException ex) when (ex.ToString().Contains("symbolischen Link", StringComparison.OrdinalIgnoreCase) || ex.ToString().Contains("symbolic links", StringComparison.OrdinalIgnoreCase) || ex.ToString().Contains("symbolischer Link", StringComparison.OrdinalIgnoreCase))
            {
                caughtRootSymlink = true;
            }
            Require(caughtRootSymlink, "EnumerateDirectoryTreeNoFollow did not throw on root symlink.");
            Directory.Delete(rootSymlink);

            var items = MacSafeFileSystem.EnumerateDirectoryTreeNoFollow(safeDir);
            Require(items.Count == 2, $"Expected 2 files from safe directory traversal, found {items.Count}");

            var winItems = ZpaqService.EnumerateDirectoryTreeNoFollowWindows(safeDir);
            Require(winItems.Count == 2, $"Expected 2 files from Windows safe traversal, found {winItems.Count}");

            // Inject symlink to file
            string symlinkFile = Path.Combine(safeDir, "link_file");
            File.CreateSymbolicLink(symlinkFile, f1);
            bool caughtSymlinkFile = false;
            try
            {
                MacSafeFileSystem.EnumerateDirectoryTreeNoFollow(safeDir);
            }
            catch (IOException ex) when (ex.Message.Contains("symbolischen Link", StringComparison.OrdinalIgnoreCase))
            {
                caughtSymlinkFile = true;
            }
            Require(caughtSymlinkFile, "EnumerateDirectoryTreeNoFollow did not throw on file symlink.");

            bool caughtWinSymlinkFile = false;
            try
            {
                ZpaqService.EnumerateDirectoryTreeNoFollowWindows(safeDir);
            }
            catch (IOException)
            {
                caughtWinSymlinkFile = true;
            }
            Require(caughtWinSymlinkFile, "EnumerateDirectoryTreeNoFollowWindows did not throw on file symlink.");
            File.Delete(symlinkFile);

            // Inject symlink to directory
            string symlinkDir = Path.Combine(safeDir, "link_dir");
            Directory.CreateSymbolicLink(symlinkDir, subDir);
            bool caughtSymlinkDir = false;
            try
            {
                MacSafeFileSystem.EnumerateDirectoryTreeNoFollow(safeDir);
            }
            catch (IOException ex) when (ex.Message.Contains("symbolischen Link", StringComparison.OrdinalIgnoreCase))
            {
                caughtSymlinkDir = true;
            }
            Require(caughtSymlinkDir, "EnumerateDirectoryTreeNoFollow did not throw on directory symlink.");

            bool caughtWinSymlinkDir = false;
            try
            {
                ZpaqService.EnumerateDirectoryTreeNoFollowWindows(safeDir);
            }
            catch (IOException)
            {
                caughtWinSymlinkDir = true;
            }
            Require(caughtWinSymlinkDir, "EnumerateDirectoryTreeNoFollowWindows did not throw on directory symlink.");
            Directory.Delete(symlinkDir);

            // 2. Quarantine rollback object binding:
            string origDir = Path.Combine(root, "originals");
            string extDir = Path.Combine(root, "extracted");
            Directory.CreateDirectory(origDir);
            Directory.CreateDirectory(extDir);

            string fileToDel = Path.Combine(origDir, "victim.bin");
            string fileToDel2 = Path.Combine(origDir, "victim2.bin");
            byte[] content = RandomNumberGenerator.GetBytes(1024);
            byte[] content2 = RandomNumberGenerator.GetBytes(2048);
            await File.WriteAllBytesAsync(fileToDel, content).ConfigureAwait(false);
            await File.WriteAllBytesAsync(fileToDel2, content2).ConfigureAwait(false);
            await File.WriteAllBytesAsync(Path.Combine(extDir, "victim.bin"), content).ConfigureAwait(false);
            await File.WriteAllBytesAsync(Path.Combine(extDir, "victim2.bin"), content2).ConfigureAwait(false);

            string archivePath = Path.Combine(root, "archive.kzpaq");
            await File.WriteAllBytesAsync(archivePath, RandomNumberGenerator.GetBytes(512)).ConfigureAwait(false);
            MacOriginalDeletionService.ArchiveIdentity archiveId =
                MacOriginalDeletionService.CaptureArchiveIdentity(archivePath);

            MacOriginalDeletionService.VerificationResult ver =
                await MacOriginalDeletionService.VerifyExtractionAsync([fileToDel, fileToDel2], extDir, null, CancellationToken.None).ConfigureAwait(false);
            Require(ver.Verified && ver.Originals != null, $"Verification failed for deletion test: {ver.Failure}");

            // Corrupt archive so pre-commit stage fails and triggers rollback:
            byte[] wrongArchive = RandomNumberGenerator.GetBytes(512);
            await File.WriteAllBytesAsync(archivePath, wrongArchive).ConfigureAwait(false);

            IReadOnlyList<string> failures = MacOriginalDeletionService.DeleteOriginals(
                [fileToDel, fileToDel2], archivePath, archiveId, ver.Originals!);
            Require(failures.Count > 0, "Deletion should fail due to modified archive.");
            Require(File.Exists(fileToDel) && File.Exists(fileToDel2), "Files were not restored by rollback after pre-commit failure.");
            byte[] r1 = await File.ReadAllBytesAsync(fileToDel).ConfigureAwait(false);
            byte[] r2 = await File.ReadAllBytesAsync(fileToDel2).ConfigureAwait(false);
            Require(FixedEqual(content, r1) && FixedEqual(content2, r2), "Restored files do not match original bytes.");

            Zero(content, content2, wrongArchive, r1, r2);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static Task TestEntropyExceptionSafetyAsync()
    {
        long initialLocked = SecureMemory.LockedBytesForTests;

        // 1. Invalid first factor (too short)
        bool threw1 = false;
        try
        {
            using var salt1 = LockedSensitiveBuffer.Create(EntropyMixer.SaltPairBytes);
            using var nonce1 = LockedSensitiveBuffer.Create(EncryptionSuiteCatalog.MaxNonceBytes);
            using var salt2 = LockedSensitiveBuffer.Create(EntropyMixer.SaltPairBytes);
            using var nonce2 = LockedSensitiveBuffer.Create(EncryptionSuiteCatalog.MaxNonceBytes);
            salt2.Bytes[0] ^= 0x01;
            _ = new GeneratedArchiveEntropy("short_factor", GeneratedFactor('B'), salt1, nonce1, salt2, nonce2);
        }
        catch (ArgumentException)
        {
            threw1 = true;
        }
        Require(threw1, "GeneratedArchiveEntropy accepted short first factor.");
        Require(SecureMemory.LockedBytesForTests == initialLocked,
            $"Locked bytes leaked after first factor error: {SecureMemory.LockedBytesForTests} != {initialLocked}");

        // 2. Invalid second factor (invalid characters)
        bool threw2 = false;
        try
        {
            using var salt1 = LockedSensitiveBuffer.Create(EntropyMixer.SaltPairBytes);
            using var nonce1 = LockedSensitiveBuffer.Create(EncryptionSuiteCatalog.MaxNonceBytes);
            using var salt2 = LockedSensitiveBuffer.Create(EntropyMixer.SaltPairBytes);
            using var nonce2 = LockedSensitiveBuffer.Create(EncryptionSuiteCatalog.MaxNonceBytes);
            salt2.Bytes[0] ^= 0x01;
            _ = new GeneratedArchiveEntropy(GeneratedFactor('A'), new string('z', 256), salt1, nonce1, salt2, nonce2);
        }
        catch (ArgumentException)
        {
            threw2 = true;
        }
        Require(threw2, "GeneratedArchiveEntropy accepted invalid second factor.");
        Require(SecureMemory.LockedBytesForTests == initialLocked,
            $"Locked bytes leaked after second factor error: {SecureMemory.LockedBytesForTests} != {initialLocked}");

        // 3. Identical salts
        bool threw3 = false;
        try
        {
            using var salt1 = LockedSensitiveBuffer.Create(EntropyMixer.SaltPairBytes);
            using var nonce1 = LockedSensitiveBuffer.Create(EncryptionSuiteCatalog.MaxNonceBytes);
            using var salt2 = LockedSensitiveBuffer.Create(EntropyMixer.SaltPairBytes);
            using var nonce2 = LockedSensitiveBuffer.Create(EncryptionSuiteCatalog.MaxNonceBytes);
            _ = new GeneratedArchiveEntropy(GeneratedFactor('A'), GeneratedFactor('B'), salt1, nonce1, salt2, nonce2);
        }
        catch (CryptographicException)
        {
            threw3 = true;
        }
        Require(threw3, "GeneratedArchiveEntropy accepted identical salts.");
        Require(SecureMemory.LockedBytesForTests == initialLocked,
            $"Locked bytes leaked after identical salts error: {SecureMemory.LockedBytesForTests} != {initialLocked}");

        return Task.CompletedTask;
    }

    private static async Task TestV12ParallelMacKatAsync()
    {
        byte[] prefixOne = "KZPAQ2-v12-prefix"u8.ToArray();
        byte[] prefixTwo = new byte[193];
        byte[] ciphertext = new byte[(2 * ParallelContainerAuthenticator.LeafBytes) + 333];
        byte[] sha3Key = new byte[64];
        byte[] skeinKey = new byte[128];
        byte[] streamPadding = new byte[37];
        FillKatEntropy(prefixTwo, 0x31, 17);
        FillKatEntropy(ciphertext, 0x57, 101);
        FillKatEntropy(sha3Key, 0x83, 13);
        FillKatEntropy(skeinKey, 0xA9, 29);
        FillKatEntropy(streamPadding, 0xC7, 7);

        byte[] streamBytes = [.. streamPadding, .. ciphertext];
        (byte[] Sha3Tag, byte[] SkeinTag) reference = ([], []);
        (byte[] Sha3Tag, byte[] SkeinTag) serial = ([], []);
        (byte[] Sha3Tag, byte[] SkeinTag) production = ([], []);
        try
        {
            reference = ComputeIndependentV12MacTree(
                [prefixOne, prefixTwo], ciphertext, sha3Key, skeinKey);
            using var stream = new MemoryStream(streamBytes, writable: false);
            using (ParallelContainerAuthenticator.UseWorkerCountForTests(1))
            {
                serial = await ParallelContainerAuthenticator.ComputeAsync(
                    stream,
                    streamPadding.Length,
                    [prefixOne, prefixTwo],
                    sha3Key,
                    skeinKey,
                    CancellationToken.None).ConfigureAwait(false);
            }

            production = await ParallelContainerAuthenticator.ComputeAsync(
                stream,
                streamPadding.Length,
                [prefixOne, prefixTwo],
                sha3Key,
                skeinKey,
                CancellationToken.None).ConfigureAwait(false);

            Require(
                FixedEqual(reference.Sha3Tag, serial.Sha3Tag)
                    && FixedEqual(reference.SkeinTag, serial.SkeinTag)
                    && FixedEqual(reference.Sha3Tag, production.Sha3Tag)
                    && FixedEqual(reference.SkeinTag, production.SkeinTag),
                "The production v12 MAC tree differs from the independent serial construction.");

            const string ExpectedSha3 =
                "8CD6EB272C15BAE0163969F85252B537044FBCFBD3F81D4C7A7581D8C137FF99"
                + "64219D62D1CEE47F1460375AEA6D80487EE4E1E73A32352BEBC4AA731AD80A5B";
            const string ExpectedSkein =
                "F443D11E11D3D0EC02EED42C38197D5765BD107323AB56FF95570658A15A1C96"
                + "C5BBB60E355B60A13A4775D0DA6579272EA6387E20D24B4850CDB5E50C3C08E9"
                + "00CCCE6CC0D508E30EC326C715E83B9B98CD0FE5915844461CFE1C3A0A3E1614"
                + "8FE267A57AEAA9A20D833A31B0275C3C0775658BBB4F00B72B71146265C6FE0E";
            Require(
                Convert.ToHexString(reference.Sha3Tag) == ExpectedSha3
                    && Convert.ToHexString(reference.SkeinTag) == ExpectedSkein,
                "v12 MAC root KAT mismatch: SHA3=" + Convert.ToHexString(reference.Sha3Tag)
                    + ", Skein=" + Convert.ToHexString(reference.SkeinTag));
        }
        finally
        {
            Zero(
                prefixOne,
                prefixTwo,
                ciphertext,
                sha3Key,
                skeinKey,
                streamPadding,
                streamBytes,
                reference.Sha3Tag,
                reference.SkeinTag,
                serial.Sha3Tag,
                serial.SkeinTag,
                production.Sha3Tag,
                production.SkeinTag);
        }
    }

    private static (byte[] Sha3Tag, byte[] SkeinTag) ComputeIndependentV12MacTree(
        IReadOnlyList<byte[]> prefixes,
        byte[] ciphertext,
        byte[] sha3MacKey,
        byte[] skeinMacKey)
    {
        byte[] leafDomain = "Kalyna-ZPAQ/v12/Parallel-Tree-MAC/Leaf"u8.ToArray();
        byte[] rootDomain = "Kalyna-ZPAQ/v12/Parallel-Tree-MAC/Root"u8.ToArray();
        byte[] sha3LeafDomain = "Kalyna-ZPAQ/v12/Parallel-Tree-MAC/HMAC-SHA3-512/Leaf-Key"u8.ToArray();
        byte[] sha3RootDomain = "Kalyna-ZPAQ/v12/Parallel-Tree-MAC/HMAC-SHA3-512/Root-Key"u8.ToArray();
        byte[] skeinLeafLabel = "Leaf-Key"u8.ToArray();
        byte[] skeinRootLabel = "Root-Key"u8.ToArray();
        byte[] logical = [.. prefixes.SelectMany(static part => part), .. ciphertext];
        byte[] sha3LeafKey = BouncyHmacSha3(sha3MacKey, sha3LeafDomain);
        byte[] sha3RootKey = BouncyHmacSha3(sha3MacKey, sha3RootDomain);
        byte[] skeinLeafKey = BouncyPersonalisedSkein(
            skeinMacKey,
            "Kalyna-ZPAQ/v12/Parallel-Tree-MAC/Skein-MAC-1024-1024/Key-Derivation",
            skeinLeafLabel);
        byte[] skeinRootKey = BouncyPersonalisedSkein(
            skeinMacKey,
            "Kalyna-ZPAQ/v12/Parallel-Tree-MAC/Skein-MAC-1024-1024/Key-Derivation",
            skeinRootLabel);
        var rootTranscript = new List<byte>();
        long leafCount = (logical.LongLength + ParallelContainerAuthenticator.LeafBytes - 1)
            / ParallelContainerAuthenticator.LeafBytes;
        byte[] rootHeader = new byte[rootDomain.Length + sizeof(long) + sizeof(long) + sizeof(int)];
        rootDomain.CopyTo(rootHeader, 0);
        int rootOffset = rootDomain.Length;
        BinaryPrimitives.WriteInt64BigEndian(rootHeader.AsSpan(rootOffset), logical.LongLength);
        rootOffset += sizeof(long);
        BinaryPrimitives.WriteInt64BigEndian(rootHeader.AsSpan(rootOffset), leafCount);
        rootOffset += sizeof(long);
        BinaryPrimitives.WriteInt32BigEndian(rootHeader.AsSpan(rootOffset), ParallelContainerAuthenticator.LeafBytes);
        rootTranscript.AddRange(rootHeader);

        try
        {
            for (long leafIndex = 0; leafIndex < leafCount; leafIndex++)
            {
                int offset = checked((int)(leafIndex * ParallelContainerAuthenticator.LeafBytes));
                int length = Math.Min(ParallelContainerAuthenticator.LeafBytes, logical.Length - offset);
                byte[] leafHeader = new byte[leafDomain.Length + sizeof(long) + sizeof(int)];
                leafDomain.CopyTo(leafHeader, 0);
                BinaryPrimitives.WriteInt64BigEndian(leafHeader.AsSpan(leafDomain.Length), leafIndex);
                BinaryPrimitives.WriteInt32BigEndian(leafHeader.AsSpan(leafDomain.Length + sizeof(long)), length);
                byte[] leafMessage = [.. leafHeader, .. logical.AsSpan(offset, length)];
                byte[] sha3Leaf = BouncyHmacSha3(sha3LeafKey, leafMessage);
                byte[] skeinLeaf = BouncySkeinMac(skeinLeafKey, leafMessage);
                byte[] leafRootHeader = new byte[sizeof(long) + sizeof(int)];
                BinaryPrimitives.WriteInt64BigEndian(leafRootHeader, leafIndex);
                BinaryPrimitives.WriteInt32BigEndian(leafRootHeader.AsSpan(sizeof(long)), length);
                try
                {
                    rootTranscript.AddRange(leafRootHeader);
                    rootTranscript.AddRange(sha3Leaf);
                    rootTranscript.AddRange(skeinLeaf);
                }
                finally
                {
                    Zero(leafHeader, leafMessage, sha3Leaf, skeinLeaf, leafRootHeader);
                }
            }

            byte[] rootMessage = [.. rootTranscript];
            try
            {
                return (
                    BouncyHmacSha3(sha3RootKey, rootMessage),
                    BouncySkeinMac(skeinRootKey, rootMessage));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(rootMessage);
            }
        }
        finally
        {
            Zero(
                leafDomain,
                rootDomain,
                sha3LeafDomain,
                sha3RootDomain,
                skeinLeafLabel,
                skeinRootLabel,
                logical,
                sha3LeafKey,
                sha3RootKey,
                skeinLeafKey,
                skeinRootKey,
                rootHeader);
            CollectionsMarshal.AsSpan(rootTranscript).Clear();
        }
    }

    private static byte[] BouncyHmacSha3(byte[] key, byte[] data)
    {
        var mac = new Org.BouncyCastle.Crypto.Macs.HMac(
            new Org.BouncyCastle.Crypto.Digests.Sha3Digest(512));
        mac.Init(new KeyParameter(key));
        mac.BlockUpdate(data);
        byte[] output = new byte[mac.GetMacSize()];
        mac.DoFinal(output);
        return output;
    }

    private static byte[] BouncyPersonalisedSkein(byte[] key, string personalisation, byte[] data)
    {
        byte[] personalisationBytes = Encoding.UTF8.GetBytes(personalisation);
        var mac = new SkeinMac(1024, 1024);
        try
        {
            SkeinParameters parameters = new SkeinParameters.Builder()
                .SetKey(key)
                .SetPersonalisation(personalisationBytes)
                .Build();
            mac.Init(parameters);
            mac.BlockUpdate(data);
            byte[] output = new byte[128];
            mac.DoFinal(output);
            return output;
        }
        finally
        {
            mac.Reset();
            CryptographicOperations.ZeroMemory(personalisationBytes);
        }
    }

    private static async Task TestV12ProductionWorkerEquivalenceAsync()
    {
        const uint katMemoryKiB = 8 * 1024;
        const int payloadBytes = (16 * 1024 * 1024) + (2 * 1024 * 1024) + 137;
        Require(
            KalynaContainerService.ProductionPipelineWorkerCount > 1,
            "The production container pipeline selected only one worker; the worker-equivalence gate cannot run.");
        Require(
            ParallelContainerAuthenticator.ProductionWorkerCount > 1,
            "The production MAC tree selected only one worker; the worker-equivalence gate cannot run.");

        EncryptionSuite[] suites = [.. EncryptionSuiteCatalog.DisplayOrder];
        Require(suites.Length == 10, $"The production worker KAT requires exactly ten suites, found {suites.Length}.");

        string root = CreateTempRoot("keep-vault-v12-worker-kat-");
        byte[] payload = new byte[payloadBytes];
        for (int index = 0; index < payload.Length; index++)
        {
            payload[index] = (byte)((index * 131 + (index >> 8) + 0x5D) & 0xFF);
        }

        try
        {
            using IDisposable memoryScope = V12MasterKdf.UseMemoryCostForTests(katMemoryKiB);
            foreach (EncryptionSuite suite in suites)
            {
                string serialPath = Path.Combine(root, $"{suite}-worker-1.kzpaq");
                string productionPath = Path.Combine(root, $"{suite}-worker-production.kzpaq");
                string tamperedPath = Path.Combine(root, $"{suite}-tampered.kzpaq");
                using GeneratedArchiveEntropy serialEntropy = CreateProductionWorkerKatEntropy();
                using GeneratedArchiveEntropy productionEntropy = CreateProductionWorkerKatEntropy();
                string factorA = serialEntropy.FirstPassword;
                string factorB = serialEntropy.SecondPassword;
                Require(
                    factorA == productionEntropy.FirstPassword && factorB == productionEntropy.SecondPassword,
                    $"{suite} worker KAT did not start from identical factors.");

                var containers = new KalynaContainerService();
                using (KalynaContainerService.UsePipelineWorkerCountForTests(1))
                using (ParallelContainerAuthenticator.UseWorkerCountForTests(1))
                await using (var serialInput = new MemoryStream(payload, writable: false))
                {
                    await containers.EncryptZpaqStreamWithPreparedEntropyAsync(
                        serialInput,
                        serialPath,
                        UserPassword,
                        UserPin,
                        factorA,
                        factorB,
                        suite,
                        serialEntropy,
                        "v12-production-worker-kat",
                        null,
                        CancellationToken.None).ConfigureAwait(false);
                }

                await using (var productionInput = new MemoryStream(payload, writable: false))
                {
                    await containers.EncryptZpaqStreamWithPreparedEntropyAsync(
                        productionInput,
                        productionPath,
                        UserPassword,
                        UserPin,
                        factorA,
                        factorB,
                        suite,
                        productionEntropy,
                        "v12-production-worker-kat",
                        null,
                        CancellationToken.None).ConfigureAwait(false);
                }

                byte[] serialContainer = await File.ReadAllBytesAsync(serialPath).ConfigureAwait(false);
                byte[] productionContainer = await File.ReadAllBytesAsync(productionPath).ConfigureAwait(false);
                byte[] serialPlaintext = [];
                byte[] productionPlaintext = [];
                byte[] expectedHash = Sha3_512Compat.HashData(payload);
                byte[] serialHash = [];
                byte[] productionHash = [];
                try
                {
                    Require(
                        FixedEqual(serialContainer, productionContainer),
                        $"{suite} produced scheduling-dependent v12 container bytes.");

                    Require(
                        serialContainer.Length >= 11
                            && serialContainer.AsSpan(0, 7).SequenceEqual("KZPAQ2\0"u8),
                        $"{suite} did not produce the exclusive v12 KZPAQ2 container magic.");
                    int headerLength = BinaryPrimitives.ReadInt32LittleEndian(serialContainer.AsSpan(7, 4));
                    int headerPrefixLength = checked(11 + headerLength);
                    Require(
                        headerLength is > 0 and < 16 * 1024
                            && headerPrefixLength <= serialContainer.Length,
                        $"{suite} produced an invalid v12 header length.");
                    byte[] headerPrefixHash = Sha3_512Compat.HashData(
                        serialContainer.AsSpan(0, headerPrefixLength));
                    try
                    {
                        Require(
                            V12WorkerKatHeaderPrefixSha3.TryGetValue(suite, out string? expectedHeaderPrefixHash)
                                && Convert.ToHexString(headerPrefixHash) == expectedHeaderPrefixHash,
                            $"{suite} changed the pinned deterministic v12 header prefix: "
                                + Convert.ToHexString(headerPrefixHash));
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(headerPrefixHash);
                    }

                    using (KalynaContainerService.UsePipelineWorkerCountForTests(1))
                    using (ParallelContainerAuthenticator.UseWorkerCountForTests(1))
                    using (var serialOutput = new MemoryStream())
                    {
                        await containers.DecryptToStreamAsync(
                            serialPath,
                            UserPassword,
                            UserPin,
                            factorA,
                            factorB,
                            serialOutput,
                            null,
                            CancellationToken.None).ConfigureAwait(false);
                        serialPlaintext = serialOutput.ToArray();
                    }

                    using (var productionOutput = new MemoryStream())
                    {
                        await containers.DecryptToStreamAsync(
                            productionPath,
                            UserPassword,
                            UserPin,
                            factorA,
                            factorB,
                            productionOutput,
                            null,
                            CancellationToken.None).ConfigureAwait(false);
                        productionPlaintext = productionOutput.ToArray();
                    }

                    serialHash = Sha3_512Compat.HashData(serialPlaintext);
                    productionHash = Sha3_512Compat.HashData(productionPlaintext);
                    Require(
                        FixedEqual(payload, serialPlaintext)
                            && FixedEqual(payload, productionPlaintext)
                            && FixedEqual(expectedHash, serialHash)
                            && FixedEqual(expectedHash, productionHash),
                        $"{suite} worker-1 and production-worker decryptions did not return the same payload hash.");

                    File.Copy(productionPath, tamperedPath, overwrite: false);
                    FlipByte(tamperedPath, new FileInfo(tamperedPath).Length - 1);
                    await RequireFailureWithoutOutputAsync(
                        containers,
                        tamperedPath,
                        UserPassword,
                        UserPin,
                        factorA,
                        factorB,
                        typeof(CryptographicException),
                        $"{suite} production-worker manipulation").ConfigureAwait(false);
                }
                finally
                {
                    Zero(
                        serialContainer,
                        productionContainer,
                        serialPlaintext,
                        productionPlaintext,
                        expectedHash,
                        serialHash,
                        productionHash);
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
            Directory.Delete(root, recursive: true);
        }
    }

    private static GeneratedArchiveEntropy CreateProductionWorkerKatEntropy()
    {
        LockedSensitiveBuffer? firstSalt = LockedSensitiveBuffer.Create(EntropyMixer.SaltPairBytes);
        LockedSensitiveBuffer? firstNonce = LockedSensitiveBuffer.Create(EncryptionSuiteCatalog.MaxNonceBytes);
        LockedSensitiveBuffer? secondSalt = LockedSensitiveBuffer.Create(EntropyMixer.SaltPairBytes);
        LockedSensitiveBuffer? secondNonce = LockedSensitiveBuffer.Create(EncryptionSuiteCatalog.MaxNonceBytes);
        try
        {
            FillKatEntropy(firstSalt.Bytes, 0x17, 29);
            FillKatEntropy(firstNonce.Bytes, 0x2B, 43);
            FillKatEntropy(secondSalt.Bytes, 0xA1, 61);
            FillKatEntropy(secondNonce.Bytes, 0xD3, 73);
            var result = new GeneratedArchiveEntropy(
                GeneratedFactor('A'),
                GeneratedFactor('B'),
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
        finally
        {
            secondNonce?.Dispose();
            secondSalt?.Dispose();
            firstNonce?.Dispose();
            firstSalt?.Dispose();
        }
    }

    private static void FillKatEntropy(Span<byte> destination, int seed, int multiplier)
    {
        for (int index = 0; index < destination.Length; index++)
        {
            destination[index] = (byte)(seed + (index * multiplier));
        }
    }

    private static async Task TestV12ContainersAsync()
    {
        string root = CreateTempRoot("keep-vault-v12-containers-");
        try
        {
            var containers = new KalynaContainerService();
            string source = Path.Combine(root, "input.txt");
            byte[] sourceBytes = "Keep Vault v12 container test payload with multiple blocks."u8.ToArray();
            await File.WriteAllBytesAsync(source, sourceBytes).ConfigureAwait(false);
            byte[] sourceHash = Sha3_512Compat.HashData(sourceBytes);

            using var zpaqBytes = new MemoryStream();
            ProcessResult zpaqResult = await new ZpaqService().AddStreamingAsync(
                new[] { source },
                1,
                (stream, cancellationToken) => stream.CopyToAsync(zpaqBytes, cancellationToken),
                null,
                CancellationToken.None).ConfigureAwait(false);
            Require(zpaqResult.Succeeded, "Could not create ZPAQ payload for v12 test.");
            byte[] payload = zpaqBytes.ToArray();

            // Test v12 container creation and reading for default suite and paranoia suite
            foreach (EncryptionSuite suite in new[] { EncryptionSuite.ThreefishOverKalyna, EncryptionSuite.ParanoiaCascade })
            {
                AddMouseSamplesUntilReady();
                using GeneratedArchiveEntropy entropy = EntropyMixer.CreateArchiveEntropy();
                string factorA = entropy.FirstPassword;
                string factorB = entropy.SecondPassword;
                string path = Path.Combine(root, $"{suite}-v12.kzpaq");

                await using (var memSource = new MemoryStream(payload, writable: false))
                {
                    await containers.EncryptZpaqStreamWithPreparedEntropyAsync(
                        memSource,
                        path,
                        UserPassword,
                        UserPin,
                        factorA,
                        factorB,
                        suite,
                        entropy,
                        "v12-test",
                        null,
                        CancellationToken.None).ConfigureAwait(false);
                }

                // Verify header
                byte[] headerBytes = ReadHeaderBytes(path);
                using JsonDocument doc = JsonDocument.Parse(headerBytes);
                JsonElement header = doc.RootElement;
                Require(header.GetProperty("Version").GetInt32() == 12, "v12 container version != 12");
                Require(header.GetProperty("PasswordMode").GetString() == V12MasterKdf.PasswordMode, "v12 PasswordMode mismatch");
                Require(header.GetProperty("KdfInputMode").GetString() == V12MasterKdf.KdfInputMode, "v12 KdfInputMode mismatch");
                Require(header.GetProperty("KdfMode").GetString() == V12MasterKdf.KdfMode, "v12 KdfMode mismatch");

                // Decrypt and verify
                using var outStream = new MemoryStream();
                await containers.DecryptToStreamAsync(
                    path, UserPassword, UserPin, factorA, factorB, outStream, null, CancellationToken.None).ConfigureAwait(false);
                byte[] decrypted = outStream.ToArray();
                try
                {
                    Require(FixedEqual(payload, decrypted), $"v12 {suite} decrypted payload does not match original.");
                    string extractedDirectory = Path.Combine(root, $"{suite}-extracted");
                    ProcessResult extracted = await new ZpaqService().ExtractStreamingAsync(
                        (destination, cancellationToken) => destination.WriteAsync(decrypted, cancellationToken).AsTask(),
                        extractedDirectory,
                        null,
                        CancellationToken.None).ConfigureAwait(false);
                    Require(extracted.Succeeded, $"v12 {suite} decrypted ZPAQ stream did not extract: {extracted.StandardError}");
                    await RequireFileHashAsync(
                        Path.Combine(extractedDirectory, Path.GetFileName(source)),
                        sourceHash,
                        $"v12 {suite} container/ZPAQ end-to-end").ConfigureAwait(false);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(decrypted);
                }

                // Test KPAR2 recovery creation and verification with v12 container
                var recoveryService = new RecoveryService();
                string sidecar = await recoveryService.CreateAuthenticatedAsync(
                    path,
                    UserPassword,
                    UserPin,
                    factorA,
                    factorB,
                    null,
                    CancellationToken.None).ConfigureAwait(false);
                Require(File.Exists(sidecar), "Failed to create KPAR2 recovery file for v12 container.");

                RecoveryRepairResult recResult = await recoveryService.VerifyAndRepairAuthenticatedAsync(
                    path,
                    UserPassword,
                    UserPin,
                    factorA,
                    factorB,
                    null,
                    CancellationToken.None).ConfigureAwait(false);
                Require(recResult.RecoveryAvailable && recResult.ArchiveHealthy && recResult.Authenticated, "KPAR2 verification of v12 container failed.");
            }

            Zero(sourceBytes, sourceHash, payload);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static partial class MacTestLinks
    {
        [System.Runtime.InteropServices.LibraryImport("libSystem.B.dylib", EntryPoint = "link", SetLastError = true, StringMarshalling = System.Runtime.InteropServices.StringMarshalling.Utf8)]
        internal static partial int CreateHardLink(string existingPath, string newPath);
    }
}

file static class StringTestExtensions
{
    internal static int CountOccurrences(this string value, string token)
    {
        int count = 0;
        int offset = 0;
        while ((offset = value.IndexOf(token, offset, StringComparison.Ordinal)) >= 0)
        {
            count++;
            offset += token.Length;
        }

        return count;
    }
}
