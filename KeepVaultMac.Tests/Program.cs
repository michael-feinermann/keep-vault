using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using KalynaArchiver.Services;
using KalynaArchiver.Signing;

[assembly: SupportedOSPlatform("macos14.0")]

var smokeTests = new List<TestCase>
{
    new("infra.runner-invariants", "test runner reservation, inventory, peak-RSS and result-schema invariants", TestCoordinator.RunInfrastructureRegressionTestsAsync, TestResource.ProcessGlobal, "Smoke", IsSmoke: true),
    new("smoke.sha3-512-fips", "SHA3-512 FIPS vector", TestSha3Async, TestResource.Light, "Smoke", IsSmoke: true),
    new("smoke.hmac-sha3-512", "HMAC-SHA3-512 vector", TestHmacSha3Async, TestResource.Light, "Smoke", IsSmoke: true),
    new("smoke.descriptor-identity", "descriptor identity", TestDescriptorIdentityAsync, TestResource.Light, "Smoke", IsSmoke: true),
    new("smoke.symlink-rejection", "symlink rejection", TestSymlinkRejectionAsync, TestResource.Light, "Smoke", IsSmoke: true),
    new("smoke.archive-input-symlink", "archive-input symlink rejection", TestArchiveInputSymlinkRejectionAsync, TestResource.Light, "Smoke", IsSmoke: true),
    new("smoke.archive-input-snapshot-location", "container-private archive-input snapshot", TestArchiveInputSnapshotLocationAsync, TestResource.Light, "Smoke", IsSmoke: true),
    new("smoke.archive-input-snapshot-races", "archive-input snapshot root and entry substitution rejection", TestArchiveInputSnapshotRacesAsync, TestResource.Light, "Smoke", IsSmoke: true),
    new("smoke.archive-input-hardlink", "archive-input hard-link alias rejection", TestArchiveInputHardLinkAsync, TestResource.Light, "Smoke", IsSmoke: true),
    new("smoke.overlapping-input-normalization", "overlapping archive-input normalization", TestOverlappingArchiveInputsAsync, TestResource.Light, "Smoke", IsSmoke: true),
    new("smoke.trailing-separator-folder", "folder input with a trailing separator", TestTrailingSeparatorFolderInputAsync, TestResource.Light, "Smoke", IsSmoke: true),
    new("smoke.descriptor-bound-snapshot", "descriptor-bound private snapshot", TestDescriptorBoundPrivateSnapshotAsync, TestResource.Light, "Smoke", IsSmoke: true),
    new("smoke.private-snapshot-cleanup-identity", "private snapshot cleanup preserves a replacement directory", TestPrivateSnapshotCleanupIdentityAsync, TestResource.Light, "Smoke", IsSmoke: true),
    new("smoke.private-authenticated-snapshot", "private authenticated-input snapshot", TestPrivateSnapshotAsync, TestResource.Light, "Smoke", IsSmoke: true),
    new("smoke.apple-signature-binding", "Apple signature framework binding", TestAppleSignatureBindingAsync, TestResource.Light, "Smoke", IsSmoke: true),
    new("smoke.locked-secret-lifecycle", "locked secret buffer lifecycle", TestLockedSecretBufferAsync, TestResource.ProcessGlobal, "Smoke", IsSmoke: true),
    new("smoke.password-policy", "password policy", TestPasswordPolicyAsync, TestResource.Light, "Smoke", IsSmoke: true),
    new("smoke.release-companion-version", "release companion version plumbing", TestReleaseCompanionVersionPlumbingAsync, TestResource.Light, "Smoke", IsSmoke: true),
    new("smoke.native-atomic-publish", "native build atomic publish and hard-link isolation", TestNativeAtomicPublishAsync, TestResource.Light, "Smoke", IsSmoke: true),
    new("smoke.qr-atomic-publish", "QR distribution atomic publish and hard-link isolation", TestQrAtomicPublishAsync, TestResource.Light, "Smoke", IsSmoke: true),
    new("smoke.release-atomic-publish", "release publish atomic exchange, exclusive create and identity binding", TestReleaseAtomicPublishAsync, TestResource.Light, "Smoke", IsSmoke: true),
    new("smoke.portable-rollback-binding", "portable publish rollback preserves substituted and linked objects", TestPortableRollbackBindingAsync, TestResource.Light, "Smoke", IsSmoke: true),
    new("smoke.native-snapshot-cleanup-identity", "native snapshot cleanup preserves a replacement directory", TestNativeSnapshotCleanupIdentityAsync, TestResource.Light, "Smoke", IsSmoke: true),
};

return await TestRunner.RunAsync(args, smokeTests, MacComprehensiveTests.AllTests).ConfigureAwait(false);

static Task TestSha3Async()
{
    string actual = Convert.ToHexString(Sha3_512Compat.HashData([]));
    const string expected = "A69F73CCA23A9AC5C8B567DC185A756E97C982164FE25859E0D1DCC1475C80A615B2123AF1F5F94C11E3E9402C3AC558F500199D95B6D3E301758586281DCD26";
    Require(string.Equals(actual, expected, StringComparison.Ordinal), "SHA3-512 empty-message KAT failed.");
    return Task.CompletedTask;
}

static Task TestHmacSha3Async()
{
    byte[] key = Enumerable.Repeat((byte)0x0B, 20).ToArray();
    byte[] message = "Hi There"u8.ToArray();
    byte[] actual;
    try
    {
        using var hmac = new HmacSha3_512(key);
        hmac.AppendData(message);
        actual = hmac.GetHashAndReset();
    }
    finally
    {
        CryptographicOperations.ZeroMemory(key);
        CryptographicOperations.ZeroMemory(message);
    }

    try
    {
        const string expected = "EB3FBD4B2EAAB8F5C504BD3A41465AACEC15770A7CABAC531E482F860B5EC7BA47CCB2C6F2AFCE8F88D22B6DC61380F23A668FD3888BB80537C0A0B86407689E";
        Require(string.Equals(Convert.ToHexString(actual), expected, StringComparison.Ordinal), "HMAC-SHA3-512 KAT failed.");
    }
    finally
    {
        CryptographicOperations.ZeroMemory(actual);
    }

    return Task.CompletedTask;
}

static async Task TestReleaseCompanionVersionPlumbingAsync()
{
    string repositoryRoot = FindRepositoryRoot();
    string scannerBuilder = Path.Combine(repositoryRoot, "QrCodeScanner", "tools", "Build-QrScanner-macOS.sh");
    string keepVaultBuilder = Path.Combine(repositoryRoot, "tools", "Build-KeepVault-macOS.sh");
    string pairVerifier = Path.Combine(repositoryRoot, "tools", "Verify-ReleasePairMetadata-macOS.sh");
    string installer = Path.Combine(repositoryRoot, "tools", "Install-KeepVault-macOS.sh");
    string installerSelfTest = Path.Combine(repositoryRoot, "tools", "Test-Installer-FailureInjection-macOS.sh");
    string installerBoundDeleteSource = Path.Combine(repositoryRoot, "tools", "InstallerBoundDelete.c");
    string installerBoundDeleteSelfTest = Path.Combine(repositoryRoot, "tools", "Test-InstallerBoundDelete-macOS.sh");
    string portableBuilder = Path.Combine(repositoryRoot, "tools", "Build-Portable-macOS.sh");
    string releasePublishRename = Path.Combine(repositoryRoot, "tools", "ReleasePublishRename.c");
    string releasePublishSelfTest = Path.Combine(repositoryRoot, "tools", "Test-ReleasePublish-macOS.sh");
    string portableRollbackSelfTest = Path.Combine(repositoryRoot, "tools", "Test-PortablePublishRollback-macOS.sh");
    Require(File.Exists(scannerBuilder), "The QR-Scanner build script is missing.");
    Require(File.Exists(keepVaultBuilder), "The Keep Vault release build script is missing.");
    Require(File.Exists(pairVerifier), "The release-pair metadata verifier is missing.");
    Require(File.Exists(installer), "The transactional macOS installer is missing.");
    Require(File.Exists(installerSelfTest), "The installer failure-injection self-test is missing.");
    Require(File.Exists(installerBoundDeleteSource), "The descriptor-bound installer rollback helper is missing.");
    Require(File.Exists(installerBoundDeleteSelfTest), "The descriptor-bound installer rollback self-test is missing.");
    Require(File.Exists(portableBuilder), "The portable macOS build script is missing.");
    Require(File.Exists(releasePublishRename), "The descriptor-relative release rename helper is missing.");
    Require(File.Exists(releasePublishSelfTest), "The release-publish adversarial self-test is missing.");
    Require(File.Exists(portableRollbackSelfTest), "The portable rollback adversarial self-test is missing.");

    (int scannerExit, string scannerOutput, _) = await RunProcessAsync(
        scannerBuilder,
        "--preflight",
        "--version", "4.0.2",
        "--build-number", "6").ConfigureAwait(false);
    Require(scannerExit == 0, "QR-Scanner rejected valid release version/build arguments.");
    Require(
        scannerOutput.Contains("preflight_version=4.0.2", StringComparison.Ordinal)
            && scannerOutput.Contains("preflight_build=6", StringComparison.Ordinal)
            && scannerOutput.Contains("preflight_single_instance=true", StringComparison.Ordinal),
        "QR-Scanner did not render the requested release metadata and single-instance policy in preflight.");

    string installerSource = await File.ReadAllTextAsync(installer).ConfigureAwait(false);
    string installerSelfTestSource = await File.ReadAllTextAsync(installerSelfTest).ConfigureAwait(false);
    string installerBoundDeleteSourceText = await File.ReadAllTextAsync(installerBoundDeleteSource).ConfigureAwait(false);
    string installerBoundDeleteSelfTestSource = await File.ReadAllTextAsync(installerBoundDeleteSelfTest).ConfigureAwait(false);
    string keepVaultBuilderSource = await File.ReadAllTextAsync(keepVaultBuilder).ConfigureAwait(false);
    string portableBuilderSource = await File.ReadAllTextAsync(portableBuilder).ConfigureAwait(false);
    string releasePublishRenameSource = await File.ReadAllTextAsync(releasePublishRename).ConfigureAwait(false);
    string[] installerFailurePoints =
    [
        "main-app-replace",
        "launcher-replace",
        "scanner-replace",
        "native-verify",
        "main-verify",
        "anchor-create",
        "anchor-replace",
        "anchor-post-check",
        "rollback-anchor",
        "rollback-app",
        "recovery-dir-create",
        "backup-move-main-app",
        "backup-move-launcher-sha3",
        "backup-move-launcher-skein",
        "backup-move-launcher-khsig",
        "backup-move-launcher-sha3-khsig",
        "backup-move-launcher-skein-khsig",
        "backup-move-scanner-app",
        "backup-move-scanner-sha3",
        "backup-move-scanner-skein",
        "backup-move-scanner-khsig",
        "backup-move-scanner-sha3-khsig",
        "backup-move-scanner-skein-khsig",
        "launch-services",
        "finder-alias",
        "exit-trap",
    ];
    string installerFailurePointBody = string.Join(
        '\n',
        installerFailurePoints.Select(static point => $"  {point}"));
    Require(installerFailurePoints.Length == 26, "The installer regression inventory must cover exactly 26 failure points.");
    Require(
        installerSource.Contains(
            $"allowed_injected_failures=(\n{installerFailurePointBody}\n)",
            StringComparison.Ordinal)
        && installerSelfTestSource.Contains(
            $"failure_points=(\n{installerFailurePointBody}\n)",
            StringComparison.Ordinal),
        "The installer and its adversarial self-test no longer share the exact 26-point failure inventory.");
    Require(
        installerSource.Contains("if [[ -n ${test_root} ]]; then", StringComparison.Ordinal)
        && installerSource.Contains(
            "--inject-failure is accepted only inside the validated installer test mode.",
            StringComparison.Ordinal)
        && installerSource.Contains(
            "if (( ! test_mode )) && [[ -x ${launch_services} ]]; then",
            StringComparison.Ordinal)
        && installerSource.Contains(
            "if (( ! test_mode )) && [[ -x ${launch_services_cleanup}",
            StringComparison.Ordinal),
        "Installer failure injection or LaunchServices mutation is no longer confined to validated test/production boundaries.");
    Require(
        installerSelfTestSource.Contains("assert_test_root_not_registered before-baseline", StringComparison.Ordinal)
        && installerSelfTestSource.Contains("assert_test_root_not_registered after-baseline", StringComparison.Ordinal)
        && installerSelfTestSource.Contains("assert_test_root_not_registered ${case_index}-${failure_point}", StringComparison.Ordinal)
        && installerSelfTestSource.Contains("assert_test_root_not_registered final", StringComparison.Ordinal)
        && !installerSelfTestSource.Contains("-dump 2>/dev/null | shasum", StringComparison.Ordinal)
        && installerSelfTestSource.Contains("installer_failure_injection_audit_points=15", StringComparison.Ordinal),
        "The installer self-test no longer proves test-root-specific LaunchServices isolation across all 15 audit categories.");
    Require(
        installerSource.Contains("bound_delete_expected ${failed_path} ${staged_app_identity:-}", StringComparison.Ordinal)
            && installerSource.Contains("bound_delete_expected ${destination} ${staged_app_identity:-}", StringComparison.Ordinal)
            && installerSource.Contains("bound_delete_expected ${scanner_failed_path} ${staged_scanner_identity:-}", StringComparison.Ordinal)
            && installerSource.Contains("bound_delete_expected ${scanner_destination} ${staged_scanner_identity:-}", StringComparison.Ordinal)
            && installerSource.Contains("expected_launcher_identity=${staged_launcher_sidecar_identities", StringComparison.Ordinal)
            && installerSource.Contains("expected_scanner_sidecar_identity=${staged_scanner_sidecar_identities", StringComparison.Ordinal)
            && installerSource.Contains("-std=c17 -Wall -Wextra -Werror -O2", StringComparison.Ordinal)
            && !installerSource.Contains("rm -rf -- ${failed_path}", StringComparison.Ordinal)
            && !installerSource.Contains("rm -rf -- ${destination}", StringComparison.Ordinal)
            && !installerSource.Contains("rm -rf -- ${scanner_failed_path}", StringComparison.Ordinal)
            && !installerSource.Contains("rm -rf -- ${scanner_destination}", StringComparison.Ordinal),
        "Installer rollback deletion is no longer routed exclusively through the expected-inode helper.");
    Require(
        installerBoundDeleteSourceText.Contains("renameatx_np(parent_descriptor", StringComparison.Ordinal)
            && installerBoundDeleteSourceText.Contains("RENAME_EXCL", StringComparison.Ordinal)
            && installerBoundDeleteSourceText.Contains("AT_SYMLINK_NOFOLLOW", StringComparison.Ordinal)
            && installerBoundDeleteSourceText.Contains("openat(parent_descriptor", StringComparison.Ordinal)
            && installerBoundDeleteSourceText.Contains("fdopendir(stream_descriptor)", StringComparison.Ordinal)
            && installerBoundDeleteSourceText.Contains("unlinkat(parent_descriptor", StringComparison.Ordinal)
            && installerBoundDeleteSourceText.Contains("ExitIdentityMismatch", StringComparison.Ordinal),
        "The installer rollback helper lost its no-follow, descriptor-relative quarantine/delete primitives.");
    Require(
        installerBoundDeleteSelfTestSource.Contains("mismatch_status == 68", StringComparison.Ordinal)
            && installerBoundDeleteSelfTestSource.Contains("foreign-object-must-survive", StringComparison.Ordinal)
            && installerBoundDeleteSelfTestSource.Contains("external-link", StringComparison.Ordinal)
            && installerSelfTestSource.Contains("installer_bound_delete_adversarial=pass", StringComparison.Ordinal),
        "The installer suite no longer proves that a substituted rollback object and symlink target survive.");
    Require(
        keepVaultBuilderSource.Contains("KEEPVAULT_TEST_RELEASE_ROOT=${dist_stage}", StringComparison.Ordinal),
        "The release gate no longer binds the companion test to its signed private staging tree.");
    Require(
        installerSource.Contains(
            "--app ${staged_app} \\",
            StringComparison.Ordinal)
        && installerSource.Contains(
            "--scanner ${install_root}/QR-Scanner.app",
            StringComparison.Ordinal)
        && installerSource.Contains(
            "--app ${destination} \\",
            StringComparison.Ordinal)
        && installerSource.Contains(
            "--scanner ${scanner_destination}",
            StringComparison.Ordinal),
        "The installer no longer checks companion metadata both before mutation and after installation.");
    Require(
        portableBuilderSource.Contains(
            "${dotnet_command} restore ${verifier_project} \\",
            StringComparison.Ordinal)
        && portableBuilderSource.Contains(
            "--locked-mode \\\n    --nologo",
            StringComparison.Ordinal)
        && !portableBuilderSource.Contains("--runtime ${runtime}", StringComparison.Ordinal)
        && portableBuilderSource.Contains(
            "${dotnet_command} publish ${verifier_project} \\",
            StringComparison.Ordinal)
        && portableBuilderSource.Contains(
            "-r ${runtime} \\\n      --no-restore \\",
            StringComparison.Ordinal)
        && portableBuilderSource.Contains(
            "${dotnet_command} restore Packaging/HybridSigner/KeepVaultMac.HybridSigner.csproj \\",
            StringComparison.Ordinal)
        && portableBuilderSource.Contains(
            "${dotnet_command} build Packaging/HybridSigner/KeepVaultMac.HybridSigner.csproj \\",
            StringComparison.Ordinal)
        && portableBuilderSource.Contains(
            "-c Release \\\n    --no-restore \\",
            StringComparison.Ordinal),
        "The portable pipeline can restore or build outside the audited locked dependency graph.");
    Require(
        keepVaultBuilderSource.Contains("ReleasePublishRename.c", StringComparison.Ordinal)
            && keepVaultBuilderSource.Contains("InstallerBoundDelete.c", StringComparison.Ordinal)
            && keepVaultBuilderSource.Contains("${publish_rename_helper} swap", StringComparison.Ordinal)
            && keepVaultBuilderSource.Contains("${publish_rename_helper} exclusive", StringComparison.Ordinal)
            && !keepVaultBuilderSource.Contains("falling back to transactional rename", StringComparison.OrdinalIgnoreCase)
            && !keepVaultBuilderSource.Contains("mv ${publish_target_dir} ${publish_old}", StringComparison.Ordinal),
        "The Keep Vault release publisher regained a path-only replacement fallback.");
    Require(
        releasePublishRenameSource.Contains("renameatx_np(source_parent_descriptor", StringComparison.Ordinal)
            && releasePublishRenameSource.Contains("RENAME_SWAP", StringComparison.Ordinal)
            && releasePublishRenameSource.Contains("RENAME_EXCL", StringComparison.Ordinal)
            && releasePublishRenameSource.Contains("AT_SYMLINK_NOFOLLOW", StringComparison.Ordinal),
        "The release rename helper lost descriptor-relative exchange, exclusive-create, or no-follow identity checks.");
    Require(
        portableBuilderSource.Contains("portable_output_root=${repo_root}/build/dev", StringComparison.Ordinal)
            && portableBuilderSource.Contains("portable_output_root=${repo_root}/dist", StringComparison.Ordinal)
            && portableBuilderSource.Contains("xcrun notarytool submit ${portable_zip}", StringComparison.Ordinal)
            && portableBuilderSource.Contains("xcrun stapler validate ${portable_dir}/Keep\\ Vault.app", StringComparison.Ordinal)
            && portableBuilderSource.Contains("delete_published_expected", StringComparison.Ordinal)
            && portableBuilderSource.Contains("--require-notarization", StringComparison.Ordinal)
            && !portableBuilderSource.Contains("rm -rf -- ${published_path}", StringComparison.Ordinal)
            && !portableBuilderSource.Contains("rm -f -- ${published_path}", StringComparison.Ordinal)
            && !portableBuilderSource.Contains("local staged_identity=$(stat", StringComparison.Ordinal),
        "Portable publication no longer separates development output, notarizes release output, or rolls back by expected inode.");
    Require(
        installerSource.Contains("installation_requires_notarization=1", StringComparison.Ordinal)
            && installerSource.Contains("kv_verify_flags+=(--require-notarization)", StringComparison.Ordinal)
            && installerSource.Contains("scanner_verify_flags+=(--require-notarization)", StringComparison.Ordinal)
            && installerSource.Contains("final_kv_verify_flags+=(--require-notarization)", StringComparison.Ordinal)
            && installerSource.Contains("final_scanner_flags+=(--require-notarization)", StringComparison.Ordinal),
        "The production installer can install Developer-ID bundles without enforcing stapled notarization before and after mutation.");

    (int invalidExit, _, _) = await RunProcessAsync(
        scannerBuilder,
        "--preflight",
        "--version", "not-a-version",
        "--build-number", "6").ConfigureAwait(false);
    Require(invalidExit != 0, "QR-Scanner accepted malformed release metadata.");

    string root = Directory.CreateTempSubdirectory("keep-vault-release-metadata-").FullName;
    string app = Path.Combine(root, "Keep Vault.app");
    string scanner = Path.Combine(root, "QR-Scanner.app");
    try
    {
        WriteTestInfoPlist(app, "de.michael-feinermann.keep-vault", "4.0.2", "6");
        WriteTestInfoPlist(scanner, "de.michael-feinermann.qr-scanner", "4.0.2", "6");
        (int matchedExit, string matchedOutput, _) = await RunProcessAsync(
            pairVerifier,
            "--app", app,
            "--scanner", scanner).ConfigureAwait(false);
        Require(matchedExit == 0, "The release-pair gate rejected matching 4.0.2/build-6 metadata.");
        Require(
            matchedOutput.Contains("release_pair_version=4.0.2", StringComparison.Ordinal)
                && matchedOutput.Contains("release_pair_build=6", StringComparison.Ordinal),
            "The release-pair gate did not report the matched metadata.");
        Require(
            MacCompanionVerification.VerifyMatchingReleaseMetadataForTests(app, scanner) is null,
            "The runtime companion classifier rejected matching release metadata.");

        WriteTestInfoPlist(scanner, "de.michael-feinermann.qr-scanner", "4.0.1", "5");
        (int mismatchExit, _, _) = await RunProcessAsync(
            pairVerifier,
            "--app", app,
            "--scanner", scanner).ConfigureAwait(false);
        Require(mismatchExit != 0, "The release-pair gate accepted a stale QR-Scanner version.");
        Require(
            MacCompanionVerification.VerifyMatchingReleaseMetadataForTests(app, scanner) is not null,
            "The runtime companion classifier accepted a stale QR-Scanner version.");

        WriteTestInfoPlist(scanner, "example.invalid.foreign-scanner", "4.0.2", "6");
        Require(
            MacCompanionVerification.VerifyMatchingReleaseMetadataForTests(app, scanner) is not null,
            "The runtime companion classifier accepted a foreign scanner bundle identifier.");
    }
    finally
    {
        Directory.Delete(root, recursive: true);
    }
}

static async Task TestNativeAtomicPublishAsync()
{
    string nativeBuilder = Path.Combine(FindRepositoryRoot(), "tools", "Build-Native-macOS.sh");
    Require(File.Exists(nativeBuilder), "The native macOS build script is missing.");

    (int exitCode, string standardOutput, string standardError) = await RunProcessAsync(
        nativeBuilder,
        "--self-test-atomic-publish").ConfigureAwait(false);
    Require(exitCode == 0, $"Atomic native publish self-test failed: {standardError}");
    Require(
        standardOutput.Contains("atomic_publish_pre_publish_failure_preserved_old_tree=true", StringComparison.Ordinal)
            && standardOutput.Contains("atomic_publish_hard_link_not_followed=true", StringComparison.Ordinal)
            && standardOutput.Contains("atomic_publish_exchange_complete=true", StringComparison.Ordinal),
        "Atomic native publish self-test did not prove failure isolation, hard-link isolation and complete exchange.");
}

static async Task TestQrAtomicPublishAsync()
{
    string scannerBuilder = Path.Combine(
        FindRepositoryRoot(),
        "QrCodeScanner",
        "tools",
        "Build-QrScanner-macOS.sh");
    Require(File.Exists(scannerBuilder), "The QR-Scanner macOS build script is missing.");

    (int exitCode, string standardOutput, string standardError) = await RunProcessAsync(
        scannerBuilder,
        "--self-test-atomic-publish").ConfigureAwait(false);
    Require(exitCode == 0, $"Atomic QR distribution publish self-test failed: {standardError}");
    Require(
        standardOutput.Contains(
            "qr_atomic_publish_pre_publish_failure_preserved_old_tree=true",
            StringComparison.Ordinal)
            && standardOutput.Contains("qr_atomic_publish_hard_link_not_followed=true", StringComparison.Ordinal)
            && standardOutput.Contains("qr_atomic_publish_exchange_complete=true", StringComparison.Ordinal)
            && standardOutput.Contains("qr_atomic_publish_first_release_exclusive=true", StringComparison.Ordinal),
        "Atomic QR publish self-test did not prove failure isolation, hard-link isolation and complete exchange.");
}

static async Task TestReleaseAtomicPublishAsync()
{
    string selfTest = Path.Combine(FindRepositoryRoot(), "tools", "Test-ReleasePublish-macOS.sh");
    Require(File.Exists(selfTest), "The release-publish adversarial self-test is missing.");

    (int exitCode, string standardOutput, string standardError) = await RunProcessAsync(selfTest).ConfigureAwait(false);
    Require(exitCode == 0, $"Release-publish adversarial self-test failed: {standardError}");
    Require(
        standardOutput.Contains("release_publish_atomic_swap=true", StringComparison.Ordinal)
            && standardOutput.Contains("release_publish_stage_substitution_rejected=true", StringComparison.Ordinal)
            && standardOutput.Contains("release_publish_mid_rename_substitution_rolled_back=true", StringComparison.Ordinal)
            && standardOutput.Contains("release_publish_first_release_exclusive=true", StringComparison.Ordinal)
            && standardOutput.Contains("release_publish_cross_directory_file=true", StringComparison.Ordinal)
            && standardOutput.Contains("release_publish_old_hard_link_preserved=true", StringComparison.Ordinal),
        "Release publish did not prove atomic swap, exclusive create, path-substitution rejection and hard-link isolation.");
}

static async Task TestPortableRollbackBindingAsync()
{
    string portableBuilder = Path.Combine(FindRepositoryRoot(), "tools", "Build-Portable-macOS.sh");
    Require(File.Exists(portableBuilder), "The portable macOS builder is missing.");

    (int exitCode, string standardOutput, string standardError) = await RunProcessAsync(
        portableBuilder,
        "--self-test-rollback").ConfigureAwait(false);
    Require(exitCode == 0, $"Portable rollback adversarial self-test failed: {standardError}");
    Require(
        standardOutput.Contains("portable_rollback_recursive_nofollow=true", StringComparison.Ordinal)
            && standardOutput.Contains("portable_rollback_hard_link_target_preserved=true", StringComparison.Ordinal)
            && standardOutput.Contains("portable_rollback_substitution_preserved=true", StringComparison.Ordinal),
        "Portable rollback did not prove no-follow recursion, hard-link preservation and substitution survival.");
}

static Task TestNativeSnapshotCleanupIdentityAsync()
{
    string native = NativeToolIntegrity.ResolveKnownTool("zpaq.exe")
        ?? throw new FileNotFoundException("The staged ZPAQ component is unavailable.");
    TrustedNativeFileLease? lease = null;
    string? snapshotDirectory = null;
    string? displacedDirectory = null;
    byte[] canary = "foreign native-directory replacement"u8.ToArray();
    try
    {
        lease = NativeToolIntegrity.AcquireTrustedFile(native);
        snapshotDirectory = Path.GetDirectoryName(lease.Path)
            ?? throw new InvalidOperationException("The trusted native lease has no parent directory.");
        Require(
            Path.GetFileName(snapshotDirectory).StartsWith("keep-vault-native-", StringComparison.Ordinal),
            "The native cleanup regression did not receive a private authenticated snapshot.");
        displacedDirectory = snapshotDirectory + ".displaced";
        Directory.Move(snapshotDirectory, displacedDirectory);
        Directory.CreateDirectory(snapshotDirectory);
        string canaryPath = Path.Combine(snapshotDirectory, "valuable.bin");
        File.WriteAllBytes(canaryPath, canary);

        bool rejectedReplacement = false;
        try
        {
            lease.Dispose();
        }
        catch (IOException)
        {
            rejectedReplacement = true;
        }

        Require(rejectedReplacement, "Native snapshot cleanup accepted a replacement root pathname.");
        Require(
            File.ReadAllBytes(canaryPath).AsSpan().SequenceEqual(canary),
            "Native snapshot cleanup removed or modified a replacement-directory canary.");
        Require(
            Directory.GetFileSystemEntries(displacedDirectory).Length == 0,
            "Native snapshot cleanup did not descriptor-delete the exact displaced executable and sidecars.");
    }
    finally
    {
        lease?.Dispose();
        CryptographicOperations.ZeroMemory(canary);
        if (snapshotDirectory is not null && Directory.Exists(snapshotDirectory))
        {
            Directory.Delete(snapshotDirectory, recursive: true);
        }
        if (displacedDirectory is not null && Directory.Exists(displacedDirectory))
        {
            Directory.Delete(displacedDirectory, recursive: true);
        }
    }

    return Task.CompletedTask;
}

static string FindRepositoryRoot() => RepositoryLayout.FindRepositoryRoot();

static void WriteTestInfoPlist(string bundle, string identifier, string version, string build)
{
    string contents = Path.Combine(bundle, "Contents");
    Directory.CreateDirectory(contents);
    string plist = $"""
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
          <key>CFBundleIdentifier</key><string>{identifier}</string>
          <key>CFBundleShortVersionString</key><string>{version}</string>
          <key>CFBundleVersion</key><string>{build}</string>
        </dict></plist>
        """;
    File.WriteAllText(Path.Combine(contents, "Info.plist"), plist);
}

static async Task<(int ExitCode, string StandardOutput, string StandardError)> RunProcessAsync(
    string executable,
    params string[] arguments)
{
    var startInfo = new System.Diagnostics.ProcessStartInfo
    {
        FileName = executable,
        UseShellExecute = false,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        CreateNoWindow = true,
    };
    foreach (string argument in arguments)
    {
        startInfo.ArgumentList.Add(argument);
    }

    using System.Diagnostics.Process process = System.Diagnostics.Process.Start(startInfo)
        ?? throw new InvalidOperationException($"Could not start {Path.GetFileName(executable)}.");
    Task<string> stdout = process.StandardOutput.ReadToEndAsync();
    Task<string> stderr = process.StandardError.ReadToEndAsync();
    await process.WaitForExitAsync().ConfigureAwait(false);
    return (process.ExitCode, await stdout.ConfigureAwait(false), await stderr.ConfigureAwait(false));
}

static Task TestDescriptorIdentityAsync()
{
    string executable = Environment.ProcessPath ?? throw new InvalidOperationException("Missing process path.");
    using FileStream stream = MacSafeFileSystem.OpenReadNoSymlinks(executable);
    MacFileIdentity handle = MacSafeFileSystem.GetIdentity(stream.SafeFileHandle);
    MacFileIdentity path = MacSafeFileSystem.GetPathIdentityNoFollow(executable);
    Require(handle.SameObject(path), "Path and descriptor do not identify the same file.");
    Require(handle.LinkCount >= 1 && handle.Size > 0, "Invalid fstat layout or values.");
    MacSafeFileSystem.RequirePathStillNamesHandle(stream.SafeFileHandle, executable);
    return Task.CompletedTask;
}

static Task TestSymlinkRejectionAsync()
{
    string root = Directory.CreateTempSubdirectory("keep-vault-link-test-").FullName;
    string target = Path.Combine(root, "target");
    string link = Path.Combine(root, "link");
    try
    {
        File.WriteAllText(target, "sentinel");
        File.CreateSymbolicLink(link, target);
        bool rejected = false;
        try
        {
            using FileStream _ = MacSafeFileSystem.OpenReadNoSymlinks(link);
        }
        catch (IOException)
        {
            rejected = true;
        }

        Require(rejected, "O_NOFOLLOW_ANY accepted a symbolic-link input.");
        Require(File.ReadAllText(target) == "sentinel", "Symlink rejection modified the target.");
    }
    finally
    {
        File.Delete(link);
        File.Delete(target);
        Directory.Delete(root);
    }

    return Task.CompletedTask;
}

static Task TestArchiveInputSymlinkRejectionAsync()
{
    string root = Directory.CreateTempSubdirectory("keep-vault-archive-link-test-").FullName;
    string target = Path.Combine(root, "target.txt");
    string link = Path.Combine(root, "linked-secret.txt");
    try
    {
        File.WriteAllText(target, "sentinel");
        File.CreateSymbolicLink(link, target);
        bool rejected = false;
        try
        {
            ZpaqService.ValidatePortableInputTreeForTests(root);
        }
        catch (IOException)
        {
            rejected = true;
        }

        Require(rejected, "An archive input tree containing a symbolic link was accepted.");
        Require(File.ReadAllText(target) == "sentinel", "Archive-input validation modified the symlink target.");
    }
    finally
    {
        File.Delete(link);
        File.Delete(target);
        Directory.Delete(root);
    }

    return Task.CompletedTask;
}

static Task TestArchiveInputSnapshotLocationAsync()
{
    string sourceRoot = MacSafeFileSystem.ResolveExistingRealPath(
        Directory.CreateTempSubdirectory("keep-vault-archive-source-").FullName);
    string source = Path.Combine(sourceRoot, "input.txt");
    File.WriteAllText(source, "sentinel");
    try
    {
        using IDisposable snapshot = ZpaqService.CaptureInputSnapshotForTests(
            sourceRoot,
            new[] { source },
            out string snapshotRoot,
            out string[] snapshotPaths);
        string sourcePrefix = Path.TrimEndingDirectorySeparator(sourceRoot) + Path.DirectorySeparatorChar;
        Require(
            !snapshotRoot.StartsWith(sourcePrefix, StringComparison.Ordinal),
            "The archive input snapshot was created beside user-selected source data.");
        Require(snapshotPaths.Length == 1, "The archive input snapshot did not preserve the selected item count.");
        Require(File.ReadAllText(snapshotPaths[0]) == "sentinel", "The private archive input snapshot changed its content.");
        Require(
            !Directory.EnumerateFileSystemEntries(sourceRoot, ".keep-vault-input-*").Any(),
            "The archive input snapshot left a sibling directory beside user data.");
    }
    finally
    {
        File.Delete(source);
        Directory.Delete(sourceRoot);
    }

    return Task.CompletedTask;
}

static Task TestArchiveInputSnapshotRacesAsync()
{
    string sourceRoot = MacSafeFileSystem.ResolveExistingRealPath(
        Directory.CreateTempSubdirectory("keep-vault-input-race-source-").FullName);
    string nested = Path.Combine(sourceRoot, "folder", "nested");
    Directory.CreateDirectory(nested);
    string source = Path.Combine(nested, "input.txt");
    string displacedSource = Path.Combine(nested, "input-displaced.txt");
    string foreignTarget = Path.Combine(sourceRoot, "foreign.txt");
    File.WriteAllText(source, "selected source bytes");
    File.WriteAllText(foreignTarget, "foreign target bytes");
    string? snapshotRoot = null;
    string? displacedSnapshotRoot = null;
    byte[] canary = "foreign snapshot replacement"u8.ToArray();
    try
    {
        ZpaqService.InputSnapshotHookBeforeSourceEntryOpenForTests = relativePath =>
        {
            if (!relativePath.EndsWith("input.txt", StringComparison.Ordinal))
            {
                return;
            }

            File.Move(source, displacedSource);
            File.CreateSymbolicLink(source, foreignTarget);
        };

        bool rejectedEntrySwap = false;
        try
        {
            using IDisposable unexpected = ZpaqService.CaptureInputSnapshotForTests(
                sourceRoot,
                new[] { Path.Combine(sourceRoot, "folder") },
                out _,
                out _);
        }
        catch (IOException)
        {
            rejectedEntrySwap = true;
        }

        Require(rejectedEntrySwap, "The archive-input snapshot followed a nested symlink substitution.");
        Require(File.ReadAllText(foreignTarget) == "foreign target bytes", "Snapshot rejection modified the symlink target.");
        File.Delete(source);
        File.Move(displacedSource, source);
        ZpaqService.InputSnapshotHookBeforeSourceEntryOpenForTests = null;

        ZpaqService.InputSnapshotHookAfterReadyForTests = path =>
        {
            snapshotRoot = path;
            displacedSnapshotRoot = path + ".displaced";
            Directory.Move(path, displacedSnapshotRoot);
            Directory.CreateDirectory(path);
            File.WriteAllBytes(Path.Combine(path, "valuable.bin"), canary);
        };

        bool rejectedRootSwap = false;
        try
        {
            using IDisposable unexpected = ZpaqService.CaptureInputSnapshotForTests(
                sourceRoot,
                new[] { source },
                out _,
                out _);
        }
        catch (IOException)
        {
            rejectedRootSwap = true;
        }

        Require(rejectedRootSwap, "The archive-input snapshot accepted a replacement private-root pathname.");
        Require(snapshotRoot is not null && displacedSnapshotRoot is not null, "The root-swap hook did not execute.");
        Require(
            File.ReadAllBytes(Path.Combine(snapshotRoot!, "valuable.bin")).AsSpan().SequenceEqual(canary),
            "Snapshot cleanup deleted or modified the replacement-root canary.");
        Require(
            !Directory.EnumerateFileSystemEntries(displacedSnapshotRoot!).Any(),
            "Snapshot cleanup left selected bytes in the displaced bound private root.");
    }
    finally
    {
        ZpaqService.InputSnapshotHookBeforeSourceEntryOpenForTests = null;
        ZpaqService.InputSnapshotHookAfterReadyForTests = null;
        CryptographicOperations.ZeroMemory(canary);
        File.Delete(source);
        if (File.Exists(displacedSource))
        {
            File.Delete(displacedSource);
        }
        if (snapshotRoot is not null && Directory.Exists(snapshotRoot))
        {
            Directory.Delete(snapshotRoot, recursive: true);
        }
        if (displacedSnapshotRoot is not null && Directory.Exists(displacedSnapshotRoot))
        {
            Directory.Delete(displacedSnapshotRoot, recursive: true);
        }
        File.Delete(foreignTarget);
        Directory.Delete(sourceRoot, recursive: true);
    }

    return Task.CompletedTask;
}

static async Task TestArchiveInputHardLinkAsync()
{
    string sourceRoot = MacSafeFileSystem.ResolveExistingRealPath(
        Directory.CreateTempSubdirectory("keep-vault-input-hardlink-").FullName);
    string source = Path.Combine(sourceRoot, "input.txt");
    string alias = Path.Combine(sourceRoot, "input-alias.txt");
    await File.WriteAllTextAsync(source, "hard-linked archive input").ConfigureAwait(false);
    try
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "/bin/ln",
                UseShellExecute = false,
            },
        };
        process.StartInfo.ArgumentList.Add(source);
        process.StartInfo.ArgumentList.Add(alias);
        Require(process.Start(), "Could not start the hard-link fixture helper.");
        await process.WaitForExitAsync().ConfigureAwait(false);
        Require(process.ExitCode == 0, "Could not create the archive-input hard-link fixture.");

        bool rejected = false;
        try
        {
            using IDisposable unexpected = ZpaqService.CaptureInputSnapshotForTests(
                sourceRoot,
                new[] { source },
                out _,
                out _);
        }
        catch (IOException)
        {
            rejected = true;
        }

        Require(rejected, "The archive-input snapshot accepted a multiply linked source file.");
        Require(File.ReadAllText(alias) == "hard-linked archive input", "Hard-link rejection modified the source inode.");
    }
    finally
    {
        File.Delete(alias);
        File.Delete(source);
        Directory.Delete(sourceRoot);
    }
}

static Task TestOverlappingArchiveInputsAsync()
{
    string sourceRoot = MacSafeFileSystem.ResolveExistingRealPath(
        Directory.CreateTempSubdirectory("keep-vault-overlap-source-").FullName);
    string folder = Path.Combine(sourceRoot, "folder");
    string first = Path.Combine(folder, "first.txt");
    string second = Path.Combine(folder, "second.txt");
    Directory.CreateDirectory(folder);
    File.WriteAllText(first, "first");
    File.WriteAllText(second, "second");
    try
    {
        using IDisposable snapshot = ZpaqService.CaptureInputSnapshotForTests(
            sourceRoot,
            new[] { first, folder },
            out _,
            out string[] snapshotPaths);
        Require(snapshotPaths.Length == 1, "A descendant input was not normalized under its selected parent folder.");
        Require(Directory.Exists(snapshotPaths[0]), "The normalized archive snapshot did not retain the parent folder.");
        Require(File.ReadAllText(Path.Combine(snapshotPaths[0], "first.txt")) == "first", "The first overlapping input is missing.");
        Require(File.ReadAllText(Path.Combine(snapshotPaths[0], "second.txt")) == "second", "A sibling file disappeared from the normalized folder snapshot.");
    }
    finally
    {
        File.Delete(first);
        File.Delete(second);
        Directory.Delete(folder);
        Directory.Delete(sourceRoot);
    }

    return Task.CompletedTask;
}

/// <summary>
/// A folder chosen through the folder picker arrives as "/path/to/folder/".
/// </summary>
/// <remarks>
/// The trailing separator used to survive normalization, and inside the private
/// snapshot the destination's own parent then resolved to the destination
/// itself - so the collision check fired against the directory the snapshot had
/// just created and archiving any folder failed. Nothing in the suite noticed,
/// because every test passed paths without the separator the picker adds.
/// </remarks>
static async Task TestTrailingSeparatorFolderInputAsync()
{
    string root = MacSafeFileSystem.ResolveExistingRealPath(
        Directory.CreateTempSubdirectory("keep-vault-trailing-separator-").FullName);
    string folder = Path.Combine(root, "folder");
    string nested = Path.Combine(folder, "sub");
    Directory.CreateDirectory(nested);
    await File.WriteAllTextAsync(Path.Combine(folder, "top.txt"), "top").ConfigureAwait(false);
    await File.WriteAllTextAsync(Path.Combine(nested, "nested.txt"), "nested").ConfigureAwait(false);
    string loose = Path.Combine(root, "loose.txt");
    await File.WriteAllTextAsync(loose, "loose").ConfigureAwait(false);

    try
    {
        using var archiveBytes = new MemoryStream();
        ProcessResult result = await new ZpaqService().AddStreamingAsync(
            [folder + Path.DirectorySeparatorChar, loose],
            1,
            (stream, cancellationToken) => stream.CopyToAsync(archiveBytes, cancellationToken),
            null,
            CancellationToken.None).ConfigureAwait(false);
        Require(
            result.Succeeded,
            $"A folder input with a trailing separator was rejected: {result.StandardError}");
        Require(archiveBytes.Length > 64, "The archive built from a trailing-separator folder input is empty.");
    }
    finally
    {
        Directory.Delete(root, recursive: true);
    }
}

static Task TestDescriptorBoundPrivateSnapshotAsync()
{
    string root = MacSafeFileSystem.ResolveExistingRealPath(
        Directory.CreateTempSubdirectory("keep-vault-descriptor-snapshot-").FullName);
    string source = Path.Combine(root, "source.bin");
    string moved = Path.Combine(root, "original.bin");
    File.WriteAllText(source, "original");
    try
    {
        using FileStream handle = MacSafeFileSystem.OpenReadNoSymlinks(source);
        File.Move(source, moved);
        File.WriteAllText(source, "replacement");
        using MacPrivateFileSnapshot snapshot = MacPrivateFileSnapshot.Capture(handle, "captured.bin");
        using var reader = new StreamReader(snapshot.Stream, leaveOpen: true);
        Require(reader.ReadToEnd() == "original", "The private snapshot followed a replaced path instead of its verified descriptor.");
    }
    finally
    {
        File.Delete(source);
        File.Delete(moved);
        Directory.Delete(root);
    }

    return Task.CompletedTask;
}

static Task TestPrivateSnapshotCleanupIdentityAsync()
{
    string root = MacSafeFileSystem.ResolveExistingRealPath(
        Directory.CreateTempSubdirectory("keep-vault-snapshot-cleanup-").FullName);
    string source = Path.Combine(root, "source.bin");
    File.WriteAllText(source, "sensitive snapshot bytes");
    MacPrivateFileSnapshot? snapshot = null;
    string? snapshotDirectory = null;
    string? displacedDirectory = null;
    byte[] canary = "foreign replacement directory"u8.ToArray();
    try
    {
        snapshot = MacPrivateFileSnapshot.Capture(source);
        snapshotDirectory = Path.GetDirectoryName(snapshot.SnapshotPath)
            ?? throw new InvalidOperationException("The private snapshot has no parent directory.");
        displacedDirectory = snapshotDirectory + ".displaced";
        Directory.Move(snapshotDirectory, displacedDirectory);
        Directory.CreateDirectory(snapshotDirectory);
        string canaryPath = Path.Combine(snapshotDirectory, "valuable.bin");
        File.WriteAllBytes(canaryPath, canary);

        bool rejectedReplacement = false;
        try
        {
            snapshot.Dispose();
        }
        catch (IOException)
        {
            rejectedReplacement = true;
        }

        Require(rejectedReplacement, "Private snapshot cleanup accepted a replacement root pathname.");
        Require(
            File.ReadAllBytes(canaryPath).AsSpan().SequenceEqual(canary),
            "Private snapshot cleanup removed or modified a replacement-directory canary.");
        Require(
            Directory.GetFileSystemEntries(displacedDirectory).Length == 0,
            "Private snapshot cleanup did not descriptor-delete the exact displaced sensitive contents.");
    }
    finally
    {
        snapshot?.Dispose();
        CryptographicOperations.ZeroMemory(canary);
        if (snapshotDirectory is not null && Directory.Exists(snapshotDirectory))
        {
            Directory.Delete(snapshotDirectory, recursive: true);
        }
        if (displacedDirectory is not null && Directory.Exists(displacedDirectory))
        {
            Directory.Delete(displacedDirectory, recursive: true);
        }
        File.Delete(source);
        Directory.Delete(root);
    }

    return Task.CompletedTask;
}

static async Task TestPrivateSnapshotAsync()
{
    string root = MacSafeFileSystem.ResolveExistingRealPath(
        Directory.CreateTempSubdirectory("keep-vault-snapshot-test-").FullName);
    string source = Path.Combine(root, "source.kzpaq");
    byte[] original = RandomNumberGenerator.GetBytes(256 * 1024);
    byte[] replacement = RandomNumberGenerator.GetBytes(original.Length);
    try
    {
        await File.WriteAllBytesAsync(source, original).ConfigureAwait(false);
        using MacPrivateFileSnapshot snapshot = await MacPrivateFileSnapshot
            .CaptureAsync(source, CancellationToken.None)
            .ConfigureAwait(false);
        await File.WriteAllBytesAsync(source, replacement).ConfigureAwait(false);
        byte[] captured = new byte[original.Length];
        try
        {
            snapshot.Stream.Position = 0;
            await snapshot.Stream.ReadExactlyAsync(captured).ConfigureAwait(false);
            Require(CryptographicOperations.FixedTimeEquals(captured, original), "The private snapshot changed with its source.");
            Require(!CryptographicOperations.FixedTimeEquals(captured, replacement), "The private snapshot aliases the mutable source.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(captured);
        }
    }
    finally
    {
        CryptographicOperations.ZeroMemory(original);
        CryptographicOperations.ZeroMemory(replacement);
        File.Delete(source);
        Directory.Delete(root);
    }
}

static Task TestAppleSignatureBindingAsync()
{
    MacSignatureInfo signature = MacCodeSignature.Check("/usr/bin/true");
    Require(signature.State != SignatureState.Unknown, "Apple Security.framework returned no signature state.");
    Require(!string.IsNullOrWhiteSpace(signature.Message), "Apple signature check returned no diagnostic.");
    return Task.CompletedTask;
}

static Task TestLockedSecretBufferAsync()
{
    long before = SecureMemory.LockedBytesForTests;
    using (LockedSensitiveBuffer buffer = LockedSensitiveBuffer.Create(4096))
    {
        RandomNumberGenerator.Fill(buffer.Bytes);
        Require(SecureMemory.LockedBytesForTests >= before + 4096, "Secret buffer was not accounted as locked.");
    }

    Require(SecureMemory.LockedBytesForTests == before, "Secret-buffer lock accounting leaked after disposal.");
    return Task.CompletedTask;
}

static Task TestPasswordPolicyAsync()
{
    const string password = "N!r7$Vq2#Lm8%Tx3&Jd9*Wp4+Kg5=Zu6?Ce";
    PasswordPolicyAnalysis valid = PasswordKeyService.AnalyzeUserPassword(password);
    Require(valid.IsAccepted, string.Join("; ", valid.Violations));
    PasswordPolicyAnalysis invalid = PasswordKeyService.AnalyzeUserPassword("0123456789abcdef01234567");
    Require(!invalid.IsAccepted, "A predictable hexadecimal password passed the policy.");
    return Task.CompletedTask;
}

static void Require(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}
