using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using KalynaArchiver.Services;
using KeepVaultMac.Packaging;

internal static class HybridKeyProtectionTests
{
    internal static IReadOnlyList<TestCase> Tests =>
    [
        new(
            "packaging.hybrid-key-separation",
            "RSA and ML-DSA use independent Keychain identities, ACLs and v12 envelopes",
            TestHybridKeySeparationAsync,
            TestResource.ProcessGlobal,
            "Packaging"),
    ];

    private static async Task TestHybridKeySeparationAsync()
    {
        const UnixFileMode permissionMask = UnixFileMode.UserRead | UnixFileMode.UserWrite
            | UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.GroupWrite
            | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherWrite
            | UnixFileMode.OtherExecute;
        const UnixFileMode privateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        string root = RepositoryLayout.FindRepositoryRoot();
        string temporaryRoot = MacSafeFileSystem.ResolveExistingRealPath(
            Directory.CreateTempSubdirectory("keep-vault-hybrid-keys-").FullName);
        File.SetUnixFileMode(
            temporaryRoot,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        string mldsaEnvelope = Path.Combine(temporaryRoot, "mldsa.v12.enc");
        string pfxEnvelope = Path.Combine(temporaryRoot, "pfx.v12.enc");
        byte[] mldsaKey = RandomNumberGenerator.GetBytes(HybridKeyEnvelope.WrappingKeyBytes);
        byte[] pfxKey = RandomNumberGenerator.GetBytes(HybridKeyEnvelope.WrappingKeyBytes);
        byte[] mldsaPrivateKey = RandomNumberGenerator.GetBytes(HybridKeyEnvelope.MldsaPrivateKeyBytes);
        byte[] pfxPassword = Encoding.UTF8.GetBytes("test-only PFX password with UTF-8 ✓");
        try
        {
            Require(
                !CryptographicOperations.FixedTimeEquals(mldsaKey, pfxKey),
                "The test fixture accidentally generated equal wrapping keys.");
            HybridKeyEnvelope.WriteMldsaPrivateKey(mldsaEnvelope, mldsaPrivateKey, mldsaKey);
            HybridKeyEnvelope.WritePfxPassword(pfxEnvelope, pfxPassword, pfxKey);

            byte[] mldsaBytes = await File.ReadAllBytesAsync(mldsaEnvelope).ConfigureAwait(false);
            byte[] pfxBytes = await File.ReadAllBytesAsync(pfxEnvelope).ConfigureAwait(false);
            try
            {
                Require(
                    Encoding.ASCII.GetString(mldsaBytes, 0, 8) == HybridKeyEnvelope.MldsaMagicText,
                    "The ML-DSA envelope does not carry its v12 role magic.");
                Require(
                    Encoding.ASCII.GetString(pfxBytes, 0, 8) == HybridKeyEnvelope.PfxPasswordMagicText,
                    "The PFX-password envelope does not carry its v12 role magic.");
                Require(
                    !mldsaBytes.AsSpan(0, 8).SequenceEqual(pfxBytes.AsSpan(0, 8)),
                    "The two secret roles share an envelope format identifier.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(mldsaBytes);
                CryptographicOperations.ZeroMemory(pfxBytes);
            }

            using (LockedSensitiveBuffer recoveredMldsa = HybridKeyEnvelope.ReadMldsaPrivateKey(
                       mldsaEnvelope,
                       mldsaKey))
            using (LockedSensitiveBuffer recoveredPfx = HybridKeyEnvelope.ReadPfxPassword(
                       pfxEnvelope,
                       pfxKey))
            {
                Require(
                    CryptographicOperations.FixedTimeEquals(recoveredMldsa.Bytes, mldsaPrivateKey),
                    "The ML-DSA role-specific envelope failed its round trip.");
                Require(
                    CryptographicOperations.FixedTimeEquals(recoveredPfx.Bytes, pfxPassword),
                    "The PFX role-specific envelope failed its round trip.");
            }

            bool zeroObservedBeforeUnlock = false;
            LockedSensitiveBuffer zeroizationProbe = LockedSensitiveBuffer.Create(32);
            RandomNumberGenerator.Fill(zeroizationProbe.Bytes);
            SecureMemory.SensitiveBufferBeforeUnlockForTests = () =>
            {
                zeroObservedBeforeUnlock = zeroizationProbe.Bytes.All(value => value == 0);
            };
            try
            {
                zeroizationProbe.Dispose();
            }
            finally
            {
                SecureMemory.SensitiveBufferBeforeUnlockForTests = null;
            }
            Require(
                zeroObservedBeforeUnlock,
                "A signing-secret buffer was unlocked before it was zeroed.");
            TestLockedTransferFaults();

            RequireThrows<CryptographicException>(
                () => HybridKeyEnvelope.ReadMldsaPrivateKey(mldsaEnvelope, pfxKey),
                "The ML-DSA envelope accepted the RSA wrapping key.");
            RequireThrows<CryptographicException>(
                () => HybridKeyEnvelope.ReadPfxPassword(pfxEnvelope, mldsaKey),
                "The PFX envelope accepted the ML-DSA wrapping key.");
            RequireThrows<CryptographicException>(
                () => HybridKeyEnvelope.ReadPfxPassword(mldsaEnvelope, mldsaKey),
                "The PFX decrypt path accepted an ML-DSA envelope.");
            RequireThrows<CryptographicException>(
                () => HybridKeyEnvelope.ReadMldsaPrivateKey(pfxEnvelope, pfxKey),
                "The ML-DSA decrypt path accepted a PFX envelope.");

            string readRaceEnvelope = Path.Combine(temporaryRoot, "read-race.v12.enc");
            string displacedReadEnvelope = Path.Combine(temporaryRoot, "read-race-displaced.v12.enc");
            HybridKeyEnvelope.WritePfxPassword(readRaceEnvelope, pfxPassword, pfxKey);
            MacBoundSecretFile.TestHookAfterReadValidation = validatedPath =>
            {
                File.Move(validatedPath, displacedReadEnvelope);
                using var foreign = new FileStream(
                    validatedPath,
                    FileMode.CreateNew,
                    FileAccess.Write,
                    FileShare.None);
                foreign.SetLength(8L * 1024 * 1024);
                foreign.Flush(flushToDisk: true);
                File.SetUnixFileMode(validatedPath, privateMode);
            };
            try
            {
                RequireThrows<IOException>(
                    () => HybridKeyEnvelope.ReadPfxPassword(readRaceEnvelope, pfxKey),
                    "A same-UID pathname replacement survived descriptor-bound revalidation.");
            }
            finally
            {
                MacBoundSecretFile.TestHookAfterReadValidation = null;
            }
            Require(
                new FileInfo(readRaceEnvelope).Length == 8L * 1024 * 1024,
                "The descriptor-bound read modified the foreign pathname replacement.");
            Require(
                new FileInfo(displacedReadEnvelope).Length
                    <= HybridKeyEnvelope.MaximumPfxPasswordBytes + 40,
                "The bounded descriptor read followed the large pathname replacement.");

            byte[] tampered = await File.ReadAllBytesAsync(pfxEnvelope).ConfigureAwait(false);
            try
            {
                tampered[tampered.Length / 2] ^= 0x01;
                string tamperedPath = Path.Combine(temporaryRoot, "pfx-tampered.v12.enc");
                await File.WriteAllBytesAsync(tamperedPath, tampered).ConfigureAwait(false);
                File.SetUnixFileMode(tamperedPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                RequireThrows<CryptographicException>(
                    () => HybridKeyEnvelope.ReadPfxPassword(tamperedPath, pfxKey),
                    "A one-bit PFX-envelope mutation passed AES-GCM authentication.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(tampered);
            }

            byte[] before = await File.ReadAllBytesAsync(pfxEnvelope).ConfigureAwait(false);
            try
            {
                RequireThrows<IOException>(
                    () => HybridKeyEnvelope.WritePfxPassword(pfxEnvelope, "replacement"u8, pfxKey),
                    "Envelope creation overwrote an existing secret object.");
                byte[] after = await File.ReadAllBytesAsync(pfxEnvelope).ConfigureAwait(false);
                try
                {
                    Require(
                        CryptographicOperations.FixedTimeEquals(before, after),
                        "The rejected overwrite changed the existing envelope.");
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(after);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(before);
            }

            Require(
                (File.GetUnixFileMode(mldsaEnvelope) & permissionMask) == privateMode,
                $"The ML-DSA envelope was not created as mode 0600: {File.GetUnixFileMode(mldsaEnvelope)}.");
            Require(
                (File.GetUnixFileMode(pfxEnvelope) & permissionMask) == privateMode,
                $"The PFX envelope was not created as mode 0600: {File.GetUnixFileMode(pfxEnvelope)}.");

            string publicModeEnvelope = Path.Combine(temporaryRoot, "public-mode.v12.enc");
            File.Copy(pfxEnvelope, publicModeEnvelope);
            File.SetUnixFileMode(
                publicModeEnvelope,
                privateMode | UnixFileMode.GroupRead);
            RequireThrows<IOException>(
                () => HybridKeyEnvelope.ReadPfxPassword(publicModeEnvelope, pfxKey),
                "A group-readable secret envelope passed the descriptor mode check.");

            string hardLinkedEnvelope = Path.Combine(temporaryRoot, "hard-linked.v12.enc");
            Require(
                CreateHardLinkNative(pfxEnvelope, hardLinkedEnvelope) == 0,
                "The adversarial hard-link fixture could not be created.");
            RequireThrows<IOException>(
                () => HybridKeyEnvelope.ReadPfxPassword(pfxEnvelope, pfxKey),
                "A multiply linked secret envelope passed the descriptor link-count check.");
            File.Delete(hardLinkedEnvelope);

            string linkedParent = Path.Combine(temporaryRoot, "linked-parent");
            Directory.CreateSymbolicLink(linkedParent, temporaryRoot);
            string linkedEnvelope = Path.Combine(linkedParent, "must-not-be-created.v12.enc");
            RequireThrows<IOException>(
                () => HybridKeyEnvelope.WritePfxPassword(linkedEnvelope, pfxPassword, pfxKey),
                "Envelope creation followed a symbolic-link parent.");
            Require(
                !File.Exists(Path.Combine(temporaryRoot, "must-not-be-created.v12.enc")),
                "The rejected symbolic-link write created a secret file through its target.");
            File.Delete(linkedParent);

            string racedEnvelope = Path.Combine(temporaryRoot, "raced-final.v12.enc");
            string displacedEnvelope = Path.Combine(temporaryRoot, "raced-original-displaced.enc");
            byte[] foreignReplacement = "foreign replacement must survive"u8.ToArray();
            MacBoundSecretFile.TestHookAfterRename = (parent, name) =>
            {
                string installed = Path.Combine(parent, name);
                File.Move(installed, displacedEnvelope);
                File.WriteAllBytes(installed, foreignReplacement);
            };
            try
            {
                RequireThrows<IOException>(
                    () => HybridKeyEnvelope.WritePfxPassword(
                        racedEnvelope,
                        pfxPassword,
                        pfxKey),
                    "A final-path substitution survived the mandatory post-rename identity check.");
            }
            finally
            {
                MacBoundSecretFile.TestHookAfterRename = null;
            }
            byte[] survivingReplacement = await File.ReadAllBytesAsync(racedEnvelope)
                .ConfigureAwait(false);
            try
            {
                Require(
                    survivingReplacement.AsSpan().SequenceEqual(foreignReplacement),
                    "Failure cleanup deleted or wiped the foreign final-path replacement.");
            Require(
                new FileInfo(displacedEnvelope).Length == 0,
                "Failure cleanup did not wipe and truncate the held original descriptor.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(survivingReplacement);
                CryptographicOperations.ZeroMemory(foreignReplacement);
            }

            string disposeFailureEnvelope = Path.Combine(
                temporaryRoot,
                "dispose-failure.v12.enc");
            MacBoundSecretFile.TestHookBeforeDispose = () =>
            {
                MacBoundSecretFile.TestHookBeforeDispose = null;
                throw new IOException("Injected descriptor-close failure.");
            };
            try
            {
                RequireThrows<IOException>(
                    () => HybridKeyEnvelope.WritePfxPassword(
                        disposeFailureEnvelope,
                        pfxPassword,
                        pfxKey),
                    "A post-publish descriptor-close failure was reported as success.");
            }
            finally
            {
                MacBoundSecretFile.TestHookBeforeDispose = null;
            }
            Require(
                !File.Exists(disposeFailureEnvelope),
                "A post-publish descriptor-close failure left the secret envelope installed.");

            string signerSource = await File.ReadAllTextAsync(
                Path.Combine(root, "KeepVaultMac", "Packaging", "HybridSigner", "Program.cs"))
                .ConfigureAwait(false);
            string envelopeSource = await File.ReadAllTextAsync(
                Path.Combine(root, "KeepVaultMac", "Packaging", "HybridSigner", "HybridKeyEnvelope.cs"))
                .ConfigureAwait(false);
            string boundFileSource = await File.ReadAllTextAsync(
                Path.Combine(root, "KeepVaultMac", "Packaging", "HybridSigner", "MacBoundSecretFile.cs"))
                .ConfigureAwait(false);
            string helperSource = await File.ReadAllTextAsync(
                Path.Combine(root, "KeepVaultMac", "Packaging", "AddHybridWrappingKey.c"))
                .ConfigureAwait(false);
            string protectionScript = await File.ReadAllTextAsync(
                Path.Combine(root, "tools", "Protect-HybridKeys-macOS.sh"))
                .ConfigureAwait(false);
            string keepVaultBuildScript = await File.ReadAllTextAsync(
                Path.Combine(root, "tools", "Build-KeepVault-macOS.sh"))
                .ConfigureAwait(false);
            string portableBuildScript = await File.ReadAllTextAsync(
                Path.Combine(root, "tools", "Build-Portable-macOS.sh"))
                .ConfigureAwait(false);
            string nativeBuildScript = await File.ReadAllTextAsync(
                Path.Combine(root, "tools", "Build-Native-macOS.sh"))
                .ConfigureAwait(false);
            string qrBuildScript = await File.ReadAllTextAsync(
                Path.Combine(root, "QrCodeScanner", "tools", "Build-QrScanner-macOS.sh"))
                .ConfigureAwait(false);
            string installerScript = await File.ReadAllTextAsync(
                Path.Combine(root, "tools", "Install-KeepVault-macOS.sh"))
                .ConfigureAwait(false);
            string stageTestNativesScript = await File.ReadAllTextAsync(
                Path.Combine(root, "tools", "Stage-TestNatives-macOS.sh"))
                .ConfigureAwait(false);
            string keepVaultVerifierScript = await File.ReadAllTextAsync(
                Path.Combine(root, "tools", "Verify-KeepVault-macOS.sh"))
                .ConfigureAwait(false);
            string qrVerifierScript = await File.ReadAllTextAsync(
                Path.Combine(root, "tools", "Verify-QR-Scanner-macOS.sh"))
                .ConfigureAwait(false);
            string releasePairVerifierScript = await File.ReadAllTextAsync(
                Path.Combine(root, "tools", "Verify-ReleasePairMetadata-macOS.sh"))
                .ConfigureAwait(false);
            string releaseVerifierSource = await File.ReadAllTextAsync(
                Path.Combine(root, "KeepVaultMac.ReleaseVerifier", "Program.cs"))
                .ConfigureAwait(false);
            string verifiedDotnetProvisioner = await File.ReadAllTextAsync(
                Path.Combine(root, "tools", "Provision-VerifiedDotnet-macOS.sh"))
                .ConfigureAwait(false);
            string macDirectoryBuildProps = await File.ReadAllTextAsync(
                Path.Combine(root, "KeepVaultMac", "Directory.Build.props"))
                .ConfigureAwait(false);
            string testsDirectoryBuildProps = await File.ReadAllTextAsync(
                Path.Combine(root, "KeepVaultMac.Tests", "Directory.Build.props"))
                .ConfigureAwait(false);
            Require(
                signerSource.Contains("mldsa-wrapping-key-keychain-service", StringComparison.Ordinal)
                    && signerSource.Contains("pfx-wrapping-key-keychain-service", StringComparison.Ordinal)
                    && signerSource.Contains("RequireDistinctWrappingKeyIdentities", StringComparison.Ordinal)
                    && !signerSource.Contains("leg" + "acy", StringComparison.OrdinalIgnoreCase)
                    && !signerSource.Contains("wrapping-key-file", StringComparison.Ordinal)
                    && !signerSource.Contains("pfx-password-env", StringComparison.Ordinal)
                    && !signerSource.Contains("LoadPkcs12FromFile", StringComparison.Ordinal)
                    && signerSource.Contains("X509CertificateLoader.LoadPkcs12(", StringComparison.Ordinal)
                    && signerSource.Contains("LockedSensitiveBuffer", StringComparison.Ordinal)
                    && signerSource.Contains("StandardOutput.BaseStream", StringComparison.Ordinal)
                    && !signerSource.Contains("Convert.FromBase64String", StringComparison.Ordinal)
                    && !signerSource.Contains("strictUtf8.GetString", StringComparison.Ordinal),
                "The signer regained a shared, plaintext, or untyped secret fallback.");
            Require(
                !File.Exists(Path.Combine(
                    root,
                    "KeepVaultMac",
                    "Packaging",
                    "HybridSigner",
                    "Leg" + "acyHybridKeyEnvelope.cs"))
                    && !protectionScript
                        .Replace("MSBUILDLEGA" + "CYEXTENSIONSPATH", string.Empty, StringComparison.Ordinal)
                        .Contains("leg" + "acy", StringComparison.OrdinalIgnoreCase),
                "An obsolete signing-key compatibility path remains active.");
            Require(
                envelopeSource.Contains("MacBoundSecretFile.ReadPrivateBytes", StringComparison.Ordinal)
                    && boundFileSource.Contains("OpenNoFollowAny", StringComparison.Ordinal)
                    && boundFileSource.Contains("SameReadSnapshot", StringComparison.Ordinal)
                    && boundFileSource.Contains("GetEffectiveUserId", StringComparison.Ordinal),
                "Private-file reads are no longer descriptor-bound, bounded, current-user-owned and nofollow.");
            Require(
                helperSource.Contains("SecAccessCopyMatchingACLList", StringComparison.Ordinal)
                    && helperSource.Contains("CFArrayGetCount(trusted_applications) != 0", StringComparison.Ordinal)
                    && helperSource.Contains("SecRandomCopyBytes", StringComparison.Ordinal)
                    && helperSource.Contains("Keep Vault v12 ML-DSA-87 wrapping key", StringComparison.Ordinal)
                    && helperSource.Contains("Keep Vault v12 RSA PFX-password wrapping key", StringComparison.Ordinal)
                    && !helperSource.Contains("kSecAttrSynchronizable", StringComparison.Ordinal),
                "The Security.framework helper no longer verifies two role-specific prompt-only ACLs.");
            Require(
                protectionScript.Contains("ensure_role_item mldsa", StringComparison.Ordinal)
                    && protectionScript.Contains("ensure_role_item pfx", StringComparison.Ordinal)
                    && protectionScript.Contains("mldsa_service} == ${pfx_wrapping_service", StringComparison.Ordinal)
                    && protectionScript.Contains("mldsa_account} == ${pfx_wrapping_account", StringComparison.Ordinal)
                    && HasIsolatedDotnetBuildPath(protectionScript)
                    && protectionScript.Contains("self_test_private_nuget_cache_identity", StringComparison.Ordinal)
                    && protectionScript.Contains("--artifacts-path ${private_dotnet_artifacts}", StringComparison.Ordinal)
                    && protectionScript.Contains("BaseIntermediateOutputPath=${private_signer_intermediate}", StringComparison.Ordinal)
                    && protectionScript.Contains("MSBuildProjectExtensionsPath=${private_signer_intermediate}", StringComparison.Ordinal)
                    && protectionScript.Contains("--no-incremental", StringComparison.Ordinal)
                    && protectionScript.Contains("${private_dotnet_artifacts}/bin/KeepVaultMac.HybridSigner/release/", StringComparison.Ordinal)
                    && protectionScript.Contains("require_private_signer_identity", StringComparison.Ordinal)
                    && protectionScript.Contains("run_dotnet_signer_clean", StringComparison.Ordinal)
                    && !protectionScript.Contains("Packaging/HybridSigner/bin/", StringComparison.Ordinal)
                    && protectionScript.Contains("clang_path=$(${xcrun_path}", StringComparison.Ordinal)
                    && protectionScript.Contains("require_root_system_tool ${clang_path}", StringComparison.Ordinal)
                    && protectionScript.Contains("hybrid_protection_tool_paths=verified", StringComparison.Ordinal),
                "The provisioning script no longer enforces distinct services and accounts.");
            Require(
                keepVaultBuildScript.Contains("build_version='12'", StringComparison.Ordinal)
                    && keepVaultBuildScript.Contains("require_root_system_tool", StringComparison.Ordinal)
                    && HasIsolatedDotnetBuildPath(keepVaultBuildScript)
                    && keepVaultBuildScript.Contains("sysopen -r -o nofollow", StringComparison.Ordinal)
                    && keepVaultBuildScript.Contains("create,excl,nofollow,sync", StringComparison.Ordinal)
                    && keepVaultBuildScript.Contains("zstat -f ${descriptor}", StringComparison.Ordinal)
                    && keepVaultBuildScript.Contains("copy_pinned_notice_source", StringComparison.Ordinal)
                    && keepVaultBuildScript.Contains("notice_self_test_path_aba", StringComparison.Ordinal)
                    && keepVaultBuildScript.Contains("notice_self_test_inplace_aba", StringComparison.Ordinal)
                    && keepVaultBuildScript.Contains("output_mutation_status", StringComparison.Ordinal)
                    && keepVaultBuildScript.Contains(
                        "bd4bd21c7ffa79d36a4f20abb6b7af3116fc005d3971ca0be09b49e083d6f159",
                        StringComparison.Ordinal),
                "The macOS v12 release default or fixed system-tool gate regressed.");
            Require(
                HasIsolatedDotnetBuildPath(portableBuildScript)
                    && portableBuildScript.Contains(
                        "identity-bound cleanup before SDK/cache provisioning",
                        StringComparison.Ordinal)
                    && portableBuildScript.IndexOf("trap cleanup EXIT", StringComparison.Ordinal)
                        < portableBuildScript.IndexOf("create_private_nuget_cache", StringComparison.Ordinal)
                    && portableBuildScript.Contains("copy_portable_root_notice", StringComparison.Ordinal)
                    && portableBuildScript.Contains("${portable_dir}/THIRD-PARTY-NOTICES.txt", StringComparison.Ordinal)
                    && portableBuildScript.Contains("zstat -f ${descriptor}", StringComparison.Ordinal)
                    && portableBuildScript.Contains(
                        "bd4bd21c7ffa79d36a4f20abb6b7af3116fc005d3971ca0be09b49e083d6f159",
                        StringComparison.Ordinal),
                "The portable release build no longer uses a fresh verified SDK and private package cache.");
            Require(
                HasSanitizedScriptBoundary(nativeBuildScript)
                    && nativeBuildScript.Contains("native_tool_paths=verified", StringComparison.Ordinal)
                    && !nativeBuildScript.Contains("${dotnet_command}", StringComparison.Ordinal),
                "The native build regained an ambient shell, compiler or .NET execution path.");
            Require(
                qrBuildScript.Contains("mldsa87-private.key.v12.enc", StringComparison.Ordinal)
                    && qrBuildScript.Contains("hybrid-rsa4096.pfx.password.v12.enc", StringComparison.Ordinal)
                    && qrBuildScript.Contains("--mldsa-wrapping-key-keychain-service", StringComparison.Ordinal)
                    && qrBuildScript.Contains("--mldsa-wrapping-key-keychain-account", StringComparison.Ordinal)
                    && qrBuildScript.Contains("--pfx-wrapping-key-keychain-service", StringComparison.Ordinal)
                    && qrBuildScript.Contains("--pfx-wrapping-key-keychain-account", StringComparison.Ordinal)
                    && HasIsolatedDotnetBuildPath(qrBuildScript)
                    && qrBuildScript.Contains("self_test_private_nuget_cache_identity", StringComparison.Ordinal)
                    && qrBuildScript.Contains("--artifacts-path ${private_dotnet_artifacts}", StringComparison.Ordinal)
                    && qrBuildScript.Contains("BaseIntermediateOutputPath=${private_signer_intermediate}", StringComparison.Ordinal)
                    && qrBuildScript.Contains("MSBuildProjectExtensionsPath=${private_signer_intermediate}", StringComparison.Ordinal)
                    && qrBuildScript.Contains("--no-incremental", StringComparison.Ordinal)
                    && qrBuildScript.Contains("${private_dotnet_artifacts}/bin/KeepVaultMac.HybridSigner/release/", StringComparison.Ordinal)
                    && qrBuildScript.Contains("require_private_signer_identity", StringComparison.Ordinal)
                    && qrBuildScript.Contains("run_dotnet_signer_clean", StringComparison.Ordinal)
                    && !qrBuildScript.Contains("Packaging/HybridSigner/bin/", StringComparison.Ordinal)
                    && qrBuildScript.Contains("require_root_system_tool", StringComparison.Ordinal)
                    && qrBuildScript.Contains("swift_driver_path", StringComparison.Ordinal)
                    && qrBuildScript.Contains("require_root_system_tool ${developer_tool}", StringComparison.Ordinal)
                    && qrBuildScript.Contains("codesign() { ${codesign_path}", StringComparison.Ordinal)
                    && qrBuildScript.Contains("swiftc() { ARGV0=swiftc ${swift_driver_path}", StringComparison.Ordinal)
                    && qrBuildScript.Contains("notarytool() { ${notarytool_path}", StringComparison.Ordinal)
                    && qrBuildScript.Contains("qr_release_tool_paths=verified", StringComparison.Ordinal)
                    && !qrBuildScript.Contains("command -v", StringComparison.Ordinal)
                    && qrBuildScript.Split(
                        "${hybrid_secret_arguments[@]}",
                        StringSplitOptions.None).Length == 3
                    && !qrBuildScript.Contains("KEEPVAULT_MLDSA_PRIVATE_KEY:-", StringComparison.Ordinal)
                    && !qrBuildScript.Contains("--mldsa-key-keychain-service", StringComparison.Ordinal)
                    && !qrBuildScript.Contains("--mldsa-key-keychain-account", StringComparison.Ordinal)
                    && !qrBuildScript.Contains("--wrapping-key-file", StringComparison.Ordinal)
                    && !qrBuildScript.Contains("--pfx-password-keychain-service", StringComparison.Ordinal)
                    && !qrBuildScript.Contains("--pfx-keychain-account", StringComparison.Ordinal)
                    && !qrBuildScript.Contains("--pfx-password-env", StringComparison.Ordinal),
                "The QR-Scanner build regained a plaintext, shared-key or secret-environment signing fallback.");
            Require(
                HasSanitizedScriptBoundary(installerScript)
                    && installerScript.Contains("require_root_system_tool", StringComparison.Ordinal)
                    && installerScript.Contains("installer_tool_paths=verified", StringComparison.Ordinal)
                    && !installerScript.Contains("${dotnet_command}", StringComparison.Ordinal),
                "The installer no longer rejects PATH or Xcode-selector tool substitution.");
            Require(
                HasSanitizedScriptBoundary(stageTestNativesScript)
                    && stageTestNativesScript.Contains("require_root_system_tool", StringComparison.Ordinal)
                    && stageTestNativesScript.Contains("stage_test_natives_tool_paths=verified", StringComparison.Ordinal)
                    && stageTestNativesScript.Contains("destination=''", StringComparison.Ordinal)
                    && stageTestNativesScript.Contains("[[ -n ${destination} ]] || usage", StringComparison.Ordinal)
                    && !stageTestNativesScript.Contains("KeepVaultMac.Tests/bin/", StringComparison.Ordinal)
                    && !stageTestNativesScript.Contains("${dotnet_command}", StringComparison.Ordinal),
                "Native test staging no longer rejects PATH or toolchain-selector substitution.");
            Require(
                HasIsolatedDotnetBuildPath(keepVaultVerifierScript)
                    && keepVaultVerifierScript.Contains("self_test_private_nuget_cache_identity", StringComparison.Ordinal)
                    && keepVaultVerifierScript.Contains("run_dotnet_clean --direct-signer", StringComparison.Ordinal)
                    && keepVaultVerifierScript.Contains("if (( ! direct_signer )); then", StringComparison.Ordinal)
                    && keepVaultVerifierScript.Contains("shasum() { ${env_path} -i", StringComparison.Ordinal)
                    && keepVaultVerifierScript.Contains("private_dotnet_sdk_identity", StringComparison.Ordinal)
                    && keepVaultVerifierScript.Contains("--artifacts-path ${private_dotnet_artifacts}", StringComparison.Ordinal)
                    && keepVaultVerifierScript.Contains("-p:BaseIntermediateOutputPath=${signer_intermediate}/", StringComparison.Ordinal)
                    && keepVaultVerifierScript.Contains("-p:MSBuildProjectExtensionsPath=${signer_intermediate}/", StringComparison.Ordinal)
                    && keepVaultVerifierScript.Contains("${private_dotnet_artifacts}/bin/KeepVaultMac.HybridSigner/release/", StringComparison.Ordinal)
                    && keepVaultVerifierScript.Contains("require_private_signer_identity", StringComparison.Ordinal)
                    && keepVaultVerifierScript.Contains("keepvault_verifier_tool_paths=verified", StringComparison.Ordinal)
                    && keepVaultVerifierScript.Contains("sysopen -r -o nofollow", StringComparison.Ordinal)
                    && keepVaultVerifierScript.Contains("bound_verifier_notice_identity", StringComparison.Ordinal)
                    && keepVaultVerifierScript.Contains(
                        "bd4bd21c7ffa79d36a4f20abb6b7af3116fc005d3971ca0be09b49e083d6f159",
                        StringComparison.Ordinal)
                    && !keepVaultVerifierScript.Contains("${dotnet_command} restore", StringComparison.Ordinal)
                    && !keepVaultVerifierScript.Contains("${dotnet_command} build", StringComparison.Ordinal),
                "The standalone Keep Vault verifier regained an ambient SDK, package cache, interpreter or signer environment.");
            Require(
                HasIsolatedDotnetBuildPath(qrVerifierScript)
                    && qrVerifierScript.Contains("self_test_private_nuget_cache_identity", StringComparison.Ordinal)
                    && qrVerifierScript.Contains("run_dotnet_clean --direct-signer", StringComparison.Ordinal)
                    && qrVerifierScript.Contains("if (( ! direct_signer )); then", StringComparison.Ordinal)
                    && qrVerifierScript.Contains("shasum() { ${env_path} -i", StringComparison.Ordinal)
                    && qrVerifierScript.Contains("private_dotnet_sdk_identity", StringComparison.Ordinal)
                    && qrVerifierScript.Contains("--artifacts-path ${private_dotnet_artifacts}", StringComparison.Ordinal)
                    && qrVerifierScript.Contains("-p:BaseIntermediateOutputPath=${signer_intermediate}/", StringComparison.Ordinal)
                    && qrVerifierScript.Contains("-p:MSBuildProjectExtensionsPath=${signer_intermediate}/", StringComparison.Ordinal)
                    && qrVerifierScript.Contains("${private_dotnet_artifacts}/bin/KeepVaultMac.HybridSigner/release/", StringComparison.Ordinal)
                    && qrVerifierScript.Contains("require_private_signer_identity", StringComparison.Ordinal)
                    && qrVerifierScript.Contains("qr_verifier_tool_paths=verified", StringComparison.Ordinal)
                    && !qrVerifierScript.Contains("${dotnet_command} restore", StringComparison.Ordinal)
                    && !qrVerifierScript.Contains("${dotnet_command} build", StringComparison.Ordinal),
                "The standalone QR verifier regained an ambient SDK, package cache, interpreter or signer environment.");
            Require(
                releasePairVerifierScript.StartsWith("#!/bin/zsh -f\n", StringComparison.Ordinal)
                    && releasePairVerifierScript.Contains("PATH='/usr/bin:/bin:/usr/sbin:/sbin'", StringComparison.Ordinal)
                    && releasePairVerifierScript.Contains("unset DEVELOPER_DIR SDKROOT TOOLCHAINS", StringComparison.Ordinal)
                    && releasePairVerifierScript.Contains("require_root_system_tool", StringComparison.Ordinal)
                    && releasePairVerifierScript.Contains("sdk_root=$(${xcrun_path}", StringComparison.Ordinal)
                    && releasePairVerifierScript.Contains("release_pair_verifier_tool_paths=verified", StringComparison.Ordinal)
                    && !releasePairVerifierScript.Contains("command -v", StringComparison.Ordinal),
                "The release-pair metadata verifier regained a PATH, shell-startup or Xcode-selector substitution path.");
            Require(
                releaseVerifierSource.Contains("BoundNoticeFile.Read", StringComparison.Ordinal)
                    && releaseVerifierSource.Contains("OpenNoFollowAny", StringComparison.Ordinal)
                    && releaseVerifierSource.Contains("SameSnapshot", StringComparison.Ordinal)
                    && releaseVerifierSource.Contains("THIRD-PARTY-NOTICES.txt", StringComparison.Ordinal)
                    && releaseVerifierSource.Contains("portable root notice", StringComparison.Ordinal)
                    && releaseVerifierSource.Contains(
                        "BD4BD21C7FFA79D36A4F20ABB6B7AF3116FC005D3971CA0BE09B49E083D6F159",
                        StringComparison.Ordinal),
                "The standalone release verifier lost its bound app/portable notice pin.");
            Require(
                verifiedDotnetProvisioner.StartsWith("#!/bin/zsh -f\n", StringComparison.Ordinal)
                    && verifiedDotnetProvisioner.Contains("sdk_version='10.0.400'", StringComparison.Ordinal)
                    && verifiedDotnetProvisioner.Contains(
                        "e440e9a58d4ff7741c8342ac3e086fa9ee2dadc25e01c0449a88317a74cfbd63625b8092c3b2a131ae14b16ab3401e9cc470e578e4c65a72a0b5786bd2308cde",
                        StringComparison.Ordinal)
                    && verifiedDotnetProvisioner.Contains("${env_path} -i", StringComparison.Ordinal)
                    && verifiedDotnetProvisioner.Contains("${curl_path} --disable", StringComparison.Ordinal)
                    && verifiedDotnetProvisioner.Contains("private_temp_parent=/private/tmp", StringComparison.Ordinal)
                    && verifiedDotnetProvisioner.Contains("-f '%p'", StringComparison.Ordinal)
                    && verifiedDotnetProvisioner.Contains("UBF8T346G9", StringComparison.Ordinal)
                    && verifiedDotnetProvisioner.Contains("verified_dotnet_tool_paths=verified", StringComparison.Ordinal),
                "The fresh Microsoft SDK provisioner lost its pinned archive, private target or platform identity gate.");
            Require(
                macDirectoryBuildProps.Contains(
                    "'$(BaseIntermediateOutputPath)' == '' and '$(ArtifactsPath)' == ''",
                    StringComparison.Ordinal)
                    && testsDirectoryBuildProps.Contains(
                        "'$(BaseIntermediateOutputPath)' == '' and '$(ArtifactsPath)' == ''",
                        StringComparison.Ordinal),
                "A repository intermediate-output fallback overrides the private artifacts path.");

            string shadowBin = Path.Combine(temporaryRoot, "shadow-bin");
            Directory.CreateDirectory(shadowBin);
            string shadowMarker = Path.Combine(temporaryRoot, "shadow-tool-was-invoked");
            foreach (string tool in new[]
            {
                "xcrun", "codesign", "security", "plutil", "ditto", "iconutil",
                "sed", "grep", "head", "stat", "mktemp", "uname", "find",
                "spctl", "rm", "mkdir", "ln", "chmod", "mv", "rmdir",
                "shlock", "osascript", "file", "cmp", "shasum", "awk",
            })
            {
                string fakeTool = Path.Combine(shadowBin, tool);
                await File.WriteAllTextAsync(
                    fakeTool,
                    "#!/bin/sh\n: > \"$KEEPVAULT_SHADOW_MARKER\"\nexit 97\n")
                    .ConfigureAwait(false);
                File.SetUnixFileMode(
                    fakeTool,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }
            string shellStartupMarker = Path.Combine(temporaryRoot, "shadow-zshenv-was-sourced");
            await File.WriteAllTextAsync(
                Path.Combine(shadowBin, ".zshenv"),
                $": > \"{shellStartupMarker}\"\n")
                .ConfigureAwait(false);
            string msbuildMarker = Path.Combine(temporaryRoot, "shadow-msbuild-target-ran");
            string poisonedTargets = Path.Combine(shadowBin, "poisoned.targets");
            await File.WriteAllTextAsync(
                poisonedTargets,
                "<Project><Target Name=\"KeepVaultPoison\" BeforeTargets=\"PrepareForBuild\">"
                    + $"<WriteLinesToFile File=\"{System.Security.SecurityElement.Escape(msbuildMarker)}\" Lines=\"poisoned\" />"
                    + "</Target></Project>")
                .ConfigureAwait(false);
            await RequireFixedToolSelfTestAsync(
                Path.Combine(root, "tools", "Build-Native-macOS.sh"),
                "native_tool_paths=verified",
                shadowBin,
                shadowMarker).ConfigureAwait(false);
            await RequireFixedToolSelfTestAsync(
                Path.Combine(root, "tools", "Build-KeepVault-macOS.sh"),
                "release_tool_paths=verified",
                shadowBin,
                shadowMarker).ConfigureAwait(false);
            await RequireScriptSelfTestAsync(
                Path.Combine(root, "tools", "Build-KeepVault-macOS.sh"),
                "--notice-binding-self-test",
                "notice_binding=verified",
                shadowBin,
                shadowMarker).ConfigureAwait(false);
            await RequireFixedToolSelfTestAsync(
                Path.Combine(root, "QrCodeScanner", "tools", "Build-QrScanner-macOS.sh"),
                "qr_release_tool_paths=verified",
                shadowBin,
                shadowMarker).ConfigureAwait(false);
            await RequireFixedToolSelfTestAsync(
                Path.Combine(root, "tools", "Install-KeepVault-macOS.sh"),
                "installer_tool_paths=verified",
                shadowBin,
                shadowMarker).ConfigureAwait(false);
            await RequireFixedToolSelfTestAsync(
                Path.Combine(root, "tools", "Stage-TestNatives-macOS.sh"),
                "stage_test_natives_tool_paths=verified",
                shadowBin,
                shadowMarker).ConfigureAwait(false);
            await RequireFixedToolSelfTestAsync(
                Path.Combine(root, "tools", "Protect-HybridKeys-macOS.sh"),
                "hybrid_protection_tool_paths=verified",
                shadowBin,
                shadowMarker).ConfigureAwait(false);
            await RequireFixedToolSelfTestAsync(
                Path.Combine(root, "tools", "Provision-VerifiedDotnet-macOS.sh"),
                "verified_dotnet_tool_paths=verified",
                shadowBin,
                shadowMarker).ConfigureAwait(false);
            await RequireFixedToolSelfTestAsync(
                Path.Combine(root, "tools", "Verify-KeepVault-macOS.sh"),
                "keepvault_verifier_tool_paths=verified",
                shadowBin,
                shadowMarker).ConfigureAwait(false);
            await RequireFixedToolSelfTestAsync(
                Path.Combine(root, "tools", "Verify-QR-Scanner-macOS.sh"),
                "qr_verifier_tool_paths=verified",
                shadowBin,
                shadowMarker).ConfigureAwait(false);
            await RequireFixedToolSelfTestAsync(
                Path.Combine(root, "tools", "Verify-ReleasePairMetadata-macOS.sh"),
                "release_pair_verifier_tool_paths=verified",
                shadowBin,
                shadowMarker).ConfigureAwait(false);
            Require(
                !File.Exists(shellStartupMarker),
                "A release script sourced an attacker-controlled .zshenv before sanitization.");
            Require(
                !File.Exists(msbuildMarker),
                "A release script imported an attacker-controlled MSBuild target.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(mldsaKey);
            CryptographicOperations.ZeroMemory(pfxKey);
            CryptographicOperations.ZeroMemory(mldsaPrivateKey);
            CryptographicOperations.ZeroMemory(pfxPassword);
            if (Directory.Exists(temporaryRoot))
            {
                Directory.Delete(temporaryRoot, recursive: true);
            }
        }
    }

    private static bool HasSanitizedScriptBoundary(string source) =>
        source.StartsWith("#!/bin/zsh -f\n", StringComparison.Ordinal)
        && source.Contains("PATH='/usr/bin:/bin:/usr/sbin:/sbin'", StringComparison.Ordinal)
        && source.Contains("ZDOTDIR ENV BASH_ENV CDPATH", StringComparison.Ordinal)
        && source.Contains("PERL5OPT PERL5LIB PYTHONHOME PYTHONPATH", StringComparison.Ordinal)
        && source.Contains("RUBYOPT RUBYLIB NODE_OPTIONS", StringComparison.Ordinal)
        && source.Contains("OPENSSL_CONF OPENSSL_MODULES", StringComparison.Ordinal)
        && source.Contains("DEVELOPER_DIR SDKROOT TOOLCHAINS", StringComparison.Ordinal)
        && source.Contains("CCC_OVERRIDE_OPTIONS", StringComparison.Ordinal)
        && source.Contains("ADDITIONAL_SWIFT_DRIVER_FLAGS", StringComparison.Ordinal)
        && source.Contains("SWIFT_DRIVER_SWIFTSCAN_LIB", StringComparison.Ordinal)
        && source.Contains("DYLD_INSERT_LIBRARIES", StringComparison.Ordinal)
        && source.Contains("DOTNET_STARTUP_HOOKS", StringComparison.Ordinal)
        && source.Contains("CORECLR_ENABLE_PROFILING", StringComparison.Ordinal)
        && source.Contains("MSBuildSDKsPath", StringComparison.Ordinal)
        && source.Contains("CustomBeforeMicrosoftCommonTargets", StringComparison.Ordinal)
        && source.Contains("CustomBeforeMicrosoftCSharpTargets", StringComparison.Ordinal)
        && source.Contains("NUGET_PLUGIN_PATHS", StringComparison.Ordinal)
        && source.Contains("NUGET_PACKAGES", StringComparison.Ordinal)
        && source.Contains("DOTNET_EnableDiagnostics=0", StringComparison.Ordinal)
        && source.Contains("COMPlus_EnableDiagnostics=0", StringComparison.Ordinal);

    private static bool HasIsolatedDotnetBuildPath(string source) =>
        HasSanitizedScriptBoundary(source)
        && source.Contains("create_private_nuget_cache", StringComparison.Ordinal)
        && source.Contains("require_private_nuget_cache_identity", StringComparison.Ordinal)
        && source.Contains("cleanup_private_nuget_cache", StringComparison.Ordinal)
        && source.Contains("run_dotnet_clean", StringComparison.Ordinal)
        && source.Contains("${env_path} -i", StringComparison.Ordinal)
        && source.Contains("Provision-VerifiedDotnet-macOS.sh", StringComparison.Ordinal)
        && source.Contains("NUGET_PACKAGES=${private_", StringComparison.Ordinal)
        && source.Contains("--disable-build-servers", StringComparison.Ordinal)
        && source.Contains("UseSharedCompilation=false", StringComparison.Ordinal)
        && source.Contains("--artifacts-path", StringComparison.Ordinal)
        && source.Contains("--no-incremental", StringComparison.Ordinal)
        && !source.Contains("KEEPVAULT_DOTNET:-", StringComparison.Ordinal);

    private static async Task RequireFixedToolSelfTestAsync(
        string script,
        string expectedOutput,
        string shadowPath,
        string shadowMarker) =>
        await RequireScriptSelfTestAsync(
            script,
            "--tool-path-self-test",
            expectedOutput,
            shadowPath,
            shadowMarker).ConfigureAwait(false);

    private static async Task RequireScriptSelfTestAsync(
        string script,
        string argument,
        string expectedOutput,
        string shadowPath,
        string shadowMarker)
    {
        var start = new ProcessStartInfo(script)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        start.ArgumentList.Add(argument);
        start.Environment["PATH"] = shadowPath;
        start.Environment["KEEPVAULT_SHADOW_MARKER"] = shadowMarker;
        start.Environment["ZDOTDIR"] = shadowPath;
        start.Environment["ENV"] = Path.Combine(shadowPath, ".zshenv");
        start.Environment["BASH_ENV"] = Path.Combine(shadowPath, ".zshenv");
        start.Environment["CDPATH"] = shadowPath;
        start.Environment["PERL5OPT"] = "-MKeepVaultShadowModule";
        start.Environment["PERL5LIB"] = shadowPath;
        start.Environment["PYTHONHOME"] = shadowPath;
        start.Environment["PYTHONPATH"] = shadowPath;
        start.Environment["RUBYOPT"] = "-rkeep_vault_shadow_module";
        start.Environment["RUBYLIB"] = shadowPath;
        start.Environment["NODE_OPTIONS"] = "--require=keep-vault-shadow-module";
        start.Environment["OPENSSL_CONF"] = Path.Combine(shadowPath, "shadow-openssl.cnf");
        start.Environment["OPENSSL_MODULES"] = shadowPath;
        start.Environment["SSL_CERT_FILE"] = Path.Combine(shadowPath, "shadow-ca.pem");
        start.Environment["SSL_CERT_DIR"] = shadowPath;
        start.Environment["XDG_CONFIG_HOME"] = shadowPath;
        start.Environment["DEVELOPER_DIR"] = shadowPath;
        start.Environment["SDKROOT"] = shadowPath;
        start.Environment["TOOLCHAINS"] = "keep-vault-shadow-toolchain";
        start.Environment["CCC_OVERRIDE_OPTIONS"] = "^--keep-vault-shadow-invalid";
        start.Environment["COMPILER_PATH"] = shadowPath;
        start.Environment["CPATH"] = shadowPath;
        start.Environment["C_INCLUDE_PATH"] = shadowPath;
        start.Environment["CPLUS_INCLUDE_PATH"] = shadowPath;
        start.Environment["OBJC_INCLUDE_PATH"] = shadowPath;
        start.Environment["LIBRARY_PATH"] = shadowPath;
        start.Environment["GCC_EXEC_PREFIX"] = shadowPath;
        start.Environment["ADDITIONAL_SWIFT_DRIVER_FLAGS"] = "--keep-vault-shadow-invalid";
        start.Environment["SWIFT_EXEC"] = Path.Combine(shadowPath, "xcrun");
        start.Environment["SWIFT_DRIVER_SWIFT_FRONTEND_EXEC"] = Path.Combine(shadowPath, "xcrun");
        start.Environment["SWIFT_DRIVER_SWIFTSCAN_LIB"] = Path.Combine(shadowPath, "shadow-swiftscan.dylib");
        start.Environment["SWIFT_DRIVER_TOOLCHAIN_CASPLUGIN_LIB"] = Path.Combine(shadowPath, "shadow-cas-plugin.dylib");
        start.Environment["DYLD_INSERT_LIBRARIES"] = Path.Combine(shadowPath, "shadow-insert.dylib");
        start.Environment["DYLD_LIBRARY_PATH"] = shadowPath;
        start.Environment["DYLD_FRAMEWORK_PATH"] = shadowPath;
        start.Environment["DYLD_FALLBACK_LIBRARY_PATH"] = shadowPath;
        start.Environment["DYLD_FALLBACK_FRAMEWORK_PATH"] = shadowPath;
        start.Environment["DOTNET_STARTUP_HOOKS"] = Path.Combine(shadowPath, "shadow-startup-hook.dll");
        start.Environment["DOTNET_ADDITIONAL_DEPS"] = Path.Combine(shadowPath, "shadow-additional-deps.json");
        start.Environment["DOTNET_SHARED_STORE"] = shadowPath;
        start.Environment["DOTNET_ROOT"] = shadowPath;
        start.Environment["DOTNET_HOST_PATH"] = Path.Combine(shadowPath, "xcrun");
        start.Environment["DOTNET_EnableDiagnostics"] = "1";
        start.Environment["COMPlus_EnableDiagnostics"] = "1";
        start.Environment["CORECLR_ENABLE_PROFILING"] = "1";
        start.Environment["CORECLR_PROFILER"] = "{11111111-1111-1111-1111-111111111111}";
        start.Environment["CORECLR_PROFILER_PATH"] = Path.Combine(shadowPath, "shadow-profiler.dylib");
        start.Environment["MSBuildSDKsPath"] = shadowPath;
        start.Environment["CustomBeforeMicrosoftCommonTargets"] = Path.Combine(shadowPath, "poisoned.targets");
        start.Environment["CustomBeforeMicrosoftCSharpTargets"] = Path.Combine(shadowPath, "poisoned.targets");
        start.Environment["NUGET_PLUGIN_PATHS"] = Path.Combine(shadowPath, "shadow-nuget-plugin");
        start.Environment["NUGET_CREDENTIALPROVIDERS_PATH"] = shadowPath;
        start.Environment["NUGET_PACKAGES"] = Path.Combine(shadowPath, "shadow-packages");
        start.Environment["NUGET_HTTP_CACHE_PATH"] = Path.Combine(shadowPath, "shadow-http-cache");
        start.Environment["NUGET_SCRATCH"] = Path.Combine(shadowPath, "shadow-nuget-scratch");
        start.Environment["KEEPVAULT_DOTNET"] = Path.Combine(shadowPath, "xcrun");
        start.Environment["CURL_HOME"] = shadowPath;
        start.Environment["TAR_OPTIONS"] = "--keep-vault-shadow-invalid";
        using Process process = Process.Start(start)
            ?? throw new InvalidOperationException("Could not start release-tool path self-test.");
        string standardOutput = await process.StandardOutput.ReadToEndAsync().ConfigureAwait(false);
        string standardError = await process.StandardError.ReadToEndAsync().ConfigureAwait(false);
        await process.WaitForExitAsync().ConfigureAwait(false);
        Require(
            process.ExitCode == 0
                && standardOutput.Contains(expectedOutput, StringComparison.Ordinal),
            $"Release-tool path self-test failed: {standardError.Trim()}");
        Require(
            !File.Exists(shadowMarker),
            "A release build script executed a PATH-shadowed critical tool.");
    }

    private static void TestLockedTransferFaults()
    {
        int baselineRetained = SecureMemory.RetainedFailedLockRollbacksForTests;

        LockedSensitiveBuffer earlyResult = LockedSensitiveBuffer.Create(64);
        LockedSensitiveBuffer earlyTemporary = LockedSensitiveBuffer.Create(64);
        byte[] earlyResultBytes = earlyResult.Bytes;
        byte[] earlyTemporaryBytes = earlyTemporary.Bytes;
        earlyResultBytes.AsSpan().Fill(0xA5);
        earlyTemporaryBytes.AsSpan().Fill(0x5A);
        RequireThrows<AggregateException>(
            () => LockedBufferTransfer.Complete(
                earlyResult,
                null,
                "Injected early cleanup failure.",
                [earlyTemporary],
                [new FaultingDisposable()]),
            "An early descriptor cleanup fault transferred a locked result.");
        Require(
            earlyResultBytes.AsSpan().IndexOfAnyExcept((byte)0) < 0
                && earlyTemporaryBytes.AsSpan().IndexOfAnyExcept((byte)0) < 0,
            "An early cleanup fault left a result or temporary secret unerased.");

        LockedSensitiveBuffer? middleResult = null;
        LockedSensitiveBuffer? middleTemporary = null;
        byte[]? middleResultBytes = null;
        byte[]? middleTemporaryBytes = null;
        try
        {
            int largeBufferBytes = checked(Environment.SystemPageSize * 32);
            middleResult = LockedSensitiveBuffer.Create(largeBufferBytes);
            middleTemporary = LockedSensitiveBuffer.Create(largeBufferBytes);
            middleResultBytes = middleResult.Bytes;
            middleTemporaryBytes = middleTemporary.Bytes;
            middleResultBytes.AsSpan().Fill(0xA5);
            middleTemporaryBytes.AsSpan().Fill(0x5A);
            int unlockCalls = 0;
            SecureMemory.MacMemoryUnlockOverrideForTests = (_, _) =>
            {
                if (Interlocked.Increment(ref unlockCalls) == 1)
                {
                    Marshal.SetLastPInvokeError(5);
                    return -1;
                }
                return 0;
            };
            RequireThrows<AggregateException>(
                () => LockedBufferTransfer.Complete(
                    middleResult,
                    null,
                    "Injected middle cleanup failure.",
                    [middleTemporary],
                    []),
                "A temporary-secret unlock fault transferred a locked result.");
            Require(
                middleResultBytes.AsSpan().IndexOfAnyExcept((byte)0) < 0
                    && middleTemporaryBytes.AsSpan().IndexOfAnyExcept((byte)0) < 0,
                "A temporary-secret unlock fault left a secret unerased.");
            Require(
                SecureMemory.RetainedFailedLockRollbacksForTests > baselineRetained,
                "A failed temporary-secret unlock was not retained for retry.");
        }
        finally
        {
            SecureMemory.MacMemoryUnlockOverrideForTests = (_, _) => 0;
            SecureMemory.RetryRetainedFailedLockRollbacksForTests();
            middleTemporary?.Dispose();
            middleResult?.Dispose();
            SecureMemory.MacMemoryUnlockOverrideForTests = null;
        }
        Require(
            SecureMemory.RetainedFailedLockRollbacksForTests == baselineRetained,
            "The temporary-secret unlock retry did not restore the retention baseline.");

        LockedSensitiveBuffer? finalResult = null;
        byte[]? finalResultBytes = null;
        try
        {
            finalResult = LockedSensitiveBuffer.Create(
                checked(Environment.SystemPageSize * 32));
            finalResultBytes = finalResult.Bytes;
            finalResultBytes.AsSpan().Fill(0xC3);
            SecureMemory.MacMemoryUnlockOverrideForTests = (_, _) =>
            {
                Marshal.SetLastPInvokeError(5);
                return -1;
            };
            RequireThrows<AggregateException>(
                () => LockedBufferTransfer.Complete(
                    finalResult,
                    new InvalidOperationException("Injected operation failure."),
                    "Injected result cleanup failure.",
                    [],
                    []),
                "A final result-unlock fault lost the composite failure.");
            Require(
                finalResultBytes.AsSpan().IndexOfAnyExcept((byte)0) < 0,
                "A final result-unlock fault left the would-be result unerased.");
            Require(
                SecureMemory.RetainedFailedLockRollbacksForTests > baselineRetained,
                "A failed final result unlock was not retained for retry.");
        }
        finally
        {
            SecureMemory.MacMemoryUnlockOverrideForTests = (_, _) => 0;
            SecureMemory.RetryRetainedFailedLockRollbacksForTests();
            finalResult?.Dispose();
            SecureMemory.MacMemoryUnlockOverrideForTests = null;
        }
        Require(
            SecureMemory.RetainedFailedLockRollbacksForTests == baselineRetained,
            "The final result unlock retry did not restore the retention baseline.");

        var primaryFailure = new InvalidOperationException("Injected primary operation failure.");
        bool finalCleanupRan = false;
        AggregateException compositeFailure = CaptureThrows<AggregateException>(
            () => LockedBufferTransfer.CompleteVoid(
                primaryFailure,
                "Injected composite operation and cleanup failure.",
                () => throw new IOException("Injected cleanup failure."),
                () => finalCleanupRan = true),
            "A cleanup fault masked the primary operation failure.");
        Require(
            finalCleanupRan,
            "A cleanup fault prevented a later cleanup action from running.");
        Require(
            compositeFailure.InnerExceptions.Count == 2
                && ReferenceEquals(compositeFailure.InnerExceptions[0], primaryFailure)
                && compositeFailure.InnerExceptions[1] is IOException,
            "The primary and cleanup failures were not retained separately.");
    }

    private sealed class FaultingDisposable : IDisposable
    {
        public void Dispose() => throw new IOException("Injected descriptor cleanup failure.");
    }

    [DllImport("libSystem.B.dylib", EntryPoint = "link", SetLastError = true)]
    private static extern int CreateHardLinkNative(string existingPath, string newPath);

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

    private static TException CaptureThrows<TException>(Action action, string message)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException exception)
        {
            return exception;
        }

        throw new InvalidOperationException(message);
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }
}
