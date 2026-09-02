using System.Buffers.Binary;
using System.IO;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Windows;
using KalynaArchiver;
using KalynaArchiver.Services;
using KalynaArchiver.Signing;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

if (args is ["--check-native-trust", var trustPath])
{
    ToolIntegrityStatus status = IntegrityService.CheckFile(trustPath, requireManifest: true);
    Console.WriteLine($"trusted={status.IsTrusted}; signature={status.SignatureState}; message={status.SignatureMessage}");
    return status.IsTrusted ? 0 : 3;
}

if (args is ["--delayed-sentinel-helper", var sentinelPath])
{
    await Task.Delay(TimeSpan.FromSeconds(2));
    await File.WriteAllTextAsync(sentinelPath, "helper survived cancellation");
    return 0;
}

if (args is ["--large-output-helper"])
{
    Console.Out.WriteLine(new string('Y', 64 * 1024));
    string line = new('X', 100);
    for (int index = 0; index < 20_000; index++)
    {
        Console.Out.WriteLine(line);
    }
    return 0;
}

if (args is ["--argon2-working-set-stress", var repetitionsText])
{
    if (!int.TryParse(repetitionsText, out int repetitions) || repetitions is < 1 or > 10)
    {
        throw new ArgumentOutOfRangeException(nameof(repetitionsText), "Stress repetitions must be between 1 and 10.");
    }

    RunProcessHardeningTests();
    RunNativeIntegrityTests();
    await RunArgon2WorkingSetStressAsync(repetitions);
    Console.WriteLine($"Argon2id 1 GiB working-set stress passed for {repetitions} repetitions.");
    return 0;
}

const string TestUserPassword = TestConstants.TestUserPassword;
const string TestPin = TestConstants.TestPin;

if (args is ["--recovery-only"])
{
    RunProcessHardeningTests();
    RunNativeIntegrityTests();
    await RunRecoveryTestsAsync();
    Console.WriteLine("KPAR2 v4 focused recovery tests passed.");
    return 0;
}

// The suite, as a set of groups the scheduler may place rather than a list it
// must walk.
//
// Every group below is one of the functions this file already had; the change
// is what decides when each runs. As a script it was twenty-seven phases in
// fixed order in one process, which on this machine is about twelve minutes
// with most cores idle - and a failure in phase three hid whatever phases four
// through twenty-seven would have said.
//
// The arrangement is the macOS suite's: each group declares what it costs and
// what it needs to itself, the coordinator spends a CPU and memory budget read
// from the machine, and each group runs in its own worker process. The process
// is the unit for two reasons that no thread count can work around. The native
// Argon2id adapter serialises on a process-wide mutex, so two Argon groups in
// one process never actually overlap. And several groups read or write
// process-global state - the entropy mixer, locked-page accounting, process
// hardening - which in one process forces them into a serial chain and lets
// them mask each other's defects.
//
// Smoke first: the cheap checks that make a broken tree obvious in seconds,
// run in this process because a worker launch each would cost more than the
// test. They are not repeated in the comprehensive set, so a bare run executes
// each group exactly once.
var smokeTests = new List<TestCase>
{
    new("infra.runner-invariants", "test runner reservation, inventory and result-schema invariants", TestCoordinator.RunInfrastructureRegressionTestsAsync, TestResource.ProcessGlobal, "Smoke", IsSmoke: true),
    new("smoke.sha3-512-vectors", "SHA3-512 reference vectors", Sync(RunSha3ReferenceVectorTests), TestResource.Light, "Smoke", IsSmoke: true),
    new("smoke.skein-1024-vectors", "Skein-1024 hash and MAC vectors", Sync(RunSkein1024ReferenceTests), TestResource.Light, "Smoke", IsSmoke: true),
    new("smoke.kalyna-512-vector", "Kalyna-512/512 reference vector", Sync(RunKalynaReferenceVectorTest), TestResource.Light, "Smoke", IsSmoke: true),
    new("smoke.threefish-1024-vectors", "Threefish-1024 official vectors and an independent implementation", Sync(RunThreefishReferenceAndIndependentTests), TestResource.Light, "Smoke", IsSmoke: true),
    new("smoke.chacha20-poly1305-rfc8439", "ChaCha20-Poly1305 framing against RFC 8439", Sync(RunAeadFramingTests), TestResource.Light, "Smoke", IsSmoke: true),
    new("smoke.release-native-tool-coverage", "release scripts cover the required native tool set", Sync(RunReleaseScriptToolCoverageTests), TestResource.Light, "Smoke", IsSmoke: true),
    new("smoke.localization-defaults", "MainWindow design-time text against the installed strings", Sync(RunLocalizationDefaultsTests), TestResource.Light, "Smoke", IsSmoke: true),
};

var comprehensiveTests = new List<TestCase>
{
    // WPF wants a single-threaded apartment, and one at a time: the window
    // reads and writes the same isolated-storage settings and the same static
    // entropy mixer.
    new("gui.settings-drop-key-sheets", "settings persistence, drag-and-drop and key sheets", () => Sta(() =>
        {
            RunSettingsPersistenceTests();
            RunDropTests();
            RunKeySheetTests();
            RunFailedArchivePreservationPolicyTests();
        }), TestResource.Gui, "Gui"),

    new("entropy.generated-factors-pools-locks", "generated factors, entropy pools and locked-page accounting",
        RunEntropyGeneratorTestsAsync, TestResource.EntropyGlobal, "Entropy"),

    new("integrity.native-tools-signatures", "native tool integrity and signatures",
        Sync(RunNativeIntegrityTests), TestResource.ProcessGlobal, "Integrity"),

    new("integrity.companion-qr", "the companion QR scanner is checked against the pinned keys",
        Sync(RunCompanionScannerVerificationTests), TestResource.ProcessGlobal, "Integrity"),

    new("files.object-bound-reads", "object-bound reads: reparse points, hard links and directories",
        Sync(RunObjectBoundReadTests), TestResource.Light, "Files"),

        new("files.original-deletion-verification", "verified original deletion and quarantine safety",
        RunWindowsOriginalDeletionTestsAsync, TestResource.Light, "Files"),

    new("zpaq.path-traversal-extraction", "ZPAQ path traversal and extraction directories",
        RunZpaqTraversalTestsAsync, TestResource.ZpaqGlobal, "Zpaq"),

    new("zpaq.input-binding", "ZPAQ input binding: reparse points, post-check insertion, leases",
        RunZpaqInputBindingTestsAsync, TestResource.ZpaqGlobal, "Zpaq"),

    new("zpaq.malformed-pipe-corpus", "mutated ZPAQ pipe-parser crash and hang corpus",
        RunMalformedZpaqCorpusTestsAsync, TestResource.ZpaqGlobal, "Zpaq"),

    new("zpaq.compression-level-matrix", "ZPAQ compression levels 0-5 for file and RAM-pipe paths",
        RunCompressionLevelMatrixTestsAsync, TestResource.ZpaqGlobal, "Zpaq"),

    new("zpaq.child-process-containment", "child-process cancellation and bounded output",
        RunProcessContainmentTestsAsync, TestResource.ProcessGlobal, "Zpaq"),

    new("hardening.process", "process hardening",
        Sync(RunProcessHardeningTests), TestResource.ProcessGlobal, "Hardening"),

    new("signing.mldsa87-interop", "ML-DSA-87 FIPS 204 interoperability and tamper rejection",
        Sync(RunMldsa87ReferenceTests), TestResource.CpuHeavy, "Signing"),

    new("kdf.argon2-reference-cli", "Argon2id PHC reference-CLI comparison",
        RunArgon2ReferenceCliTestAsync, TestResource.ArgonHeavy, "Kdf"),

    new("crypto.kalyna-parallel-ctr", "Kalyna-512/512 parallel CTR equivalence",
        Sync(RunKalynaParallelCtrEquivalenceTest), TestResource.CpuHeavy, "Crypto"),

    new("crypto.kalyna-table-differential", "Kalyna-512/512 scalar-versus-parallel v12 path over 256 MiB",
        Sync(RunKalynaDifferentialTests), TestResource.CpuHeavy, "Crypto"),

    new("crypto.chacha20-split-differential", "ChaCha20 worker split against the serial keystream over 256 MiB",
        Sync(RunChaChaDifferentialTests), TestResource.CpuHeavy, "Crypto"),

    new("crypto.threefish-parallel-ctr", "Threefish-1024 parallel CTR equivalence",
        Sync(RunThreefishParallelCtrEquivalenceTest), TestResource.CpuHeavy, "Crypto"),

    new("crypto.ctr-counter-exhaustion", "native CTR counter exhaustion fails before output",
        Sync(RunNativeCtrCounterExhaustionTests), TestResource.CpuHeavy, "Crypto"),

    new("crypto.aes-runtime-provider", "AES runtime dispatch exposes the hardware provider",
        Sync(RunAesRuntimeProviderTests), TestResource.Light, "Crypto"),

    // Manual release gate: deliberately absent from bare/full/quick/changed
    // selection. Use --performance (or its exact stable id) on an otherwise
    // idle host so the medians are meaningful.
    new("performance.cipher-suites", "primitive and full-container release medians for every cipher suite and cascade",
        Sync(CipherSuitePerformanceTests.Run), TestResource.CpuHeavy, "Performance", IsPerformance: true)
    {
        Cost = new TestCost(4, 3072, true, TestConstraint.HostExclusive),
    },

    new("containers.pdf-dual-suite", "PDF ZPAQ and dual-suite encrypted containers",
        RunPdfRoundTripTestsAsync, TestResource.EntropyGlobal, "Containers"),

    new("containers.mixed-samples", "mixed text, empty, compressible and random sample data",
        RunMixedSampleRoundTripTestsAsync, TestResource.EntropyGlobal, "Containers"),

    new("containers.short-read-kalyna", "short-read Kalyna stream",
        RunShortReadKalynaStreamTestAsync, TestResource.EntropyGlobal, "Containers"),

    new("recovery.kpar2-v4-boundaries", "KPAR2 v4 dual certification, metadata redundancy and recovery boundaries",
        RunRecoveryTestsAsync, TestResource.EntropyGlobal, "Recovery"),

    new("containers.large-streaming", "large streaming container",
        RunLargeStreamingContainerTestAsync, TestResource.EntropyGlobal, "Containers"),

    new("erase.cryptographic", "cryptographic erase",
        RunCryptographicEraseTestsAsync, TestResource.EntropyGlobal, "Erase"),
};

return await TestRunner.RunAsync(args, smokeTests, comprehensiveTests);

// Wraps a synchronous group so it can be registered beside the asynchronous
// ones without each of them growing an async signature it does not need.
static Func<Task> Sync(Action body) => () =>
{
    body();
    return Task.CompletedTask;
};

// Runs a group on a single-threaded apartment and hands its exception back.
//
// WPF refuses to create a Window off an STA thread, and the scheduler's worker
// threads are not one. The thread is created per group rather than kept alive,
// because a WPF Dispatcher outlives the window it served and a second group on
// the same thread would inherit the first one's static state.
static Task Sta(Action body)
{
    var completion = new TaskCompletionSource();
    var thread = new Thread(() =>
    {
        try
        {
            body();
            completion.SetResult();
        }
        catch (Exception ex)
        {
            completion.SetException(ex);
        }
    });

    thread.SetApartmentState(ApartmentState.STA);
    thread.IsBackground = true;
    thread.Start();
    return completion.Task;
}

static void RunSettingsPersistenceTests()
{
    byte[] validSetting = Encoding.UTF8.GetBytes("Threefish1024");
    Assert(
        IsolatedStorageAppSettingsStore.DecodeValue(validSetting) == "Threefish1024",
        "bounded settings decoder accepts a valid UTF-8 value");
    Assert(
        IsolatedStorageAppSettingsStore.DecodeValue(new byte[IsolatedStorageAppSettingsStore.MaxValueBytes + 1]) is null,
        "bounded settings decoder rejects oversized values before parsing");
    Assert(
        IsolatedStorageAppSettingsStore.DecodeValue([0xC3, 0x28]) is null,
        "bounded settings decoder rejects malformed UTF-8");

    var settings = new MemoryAppSettingsStore();
    var firstWindow = new MainWindow(settings);
    string englishArgon2Profile;
    try
    {
        Assert(firstWindow.CipherSuiteBox.SelectedIndex == SuiteDisplayIndex(EncryptionSuiteCatalog.Default), "missing suite preference defaults to the catalog default");
        Assert(firstWindow.CompressionBox.SelectedIndex == 1, "missing compression preference defaults to level 1");
        Assert(firstWindow.LanguageBox.SelectedIndex == 1, "missing language preference defaults to English");
        Assert(firstWindow.Title == "Keep Vault" && firstWindow.TitleText.Text == "Keep Vault", "GUI uses the Keep Vault product name");
        Assert(
            firstWindow.SubtitleText.Text == "Create, extract, and cryptographically erase encrypted ZPAQ archives.",
            "GUI rename preserves the existing subtitle");
        Assert(typeof(MainWindow).Assembly.GetName().Name == "Keep Vault", "application assembly and executable identity use the product name");
        englishArgon2Profile = firstWindow.Argon2ProfileText.Text;
        Assert(
            englishArgon2Profile.Contains("1 GiB", StringComparison.Ordinal)
            && englishArgon2Profile.Contains("just under 2 GiB", StringComparison.Ordinal)
            && englishArgon2Profile.Contains("PMI16", StringComparison.Ordinal)
            && englishArgon2Profile.Contains("t=4", StringComparison.Ordinal)
            && englishArgon2Profile.Contains("p=4", StringComparison.Ordinal)
            && englishArgon2Profile.Contains("sequential", StringComparison.OrdinalIgnoreCase),
            "English GUI describes the PMI16 memory range and sequential t=4, p=4 Argon2 profile");
        // The help text is localized user-facing prose, not a specification of
        // the key derivation. Assert only the user semantics it must convey,
        // and assert the cryptographic contract directly against the KDF.
        Assert(
            firstWindow.PasswordGeneratorHelpText.Text.Contains("nine", StringComparison.OrdinalIgnoreCase)
            && firstWindow.PasswordGeneratorHelpText.Text.Contains("pools", StringComparison.OrdinalIgnoreCase)
            && firstWindow.PasswordGeneratorHelpText.Text.Contains("atomically", StringComparison.OrdinalIgnoreCase)
            && !firstWindow.PasswordGeneratorHelpText.Text.Contains("BCryptGenRandom", StringComparison.Ordinal),
            "archive entropy help describes the nine pools and atomic factor generation instead of nonce internals");
        Assert(
            V12MasterKdf.KdfMode == "DualArgon2id-SplitSHA3+Skein1024-Sequential-Master1024"
            && V12MasterKdf.KdfInputMode == "DualBranch-v12: SplitFactorsSHA3-512-1024 || KeyedSkeinMAC-1024-1024"
            && V12MasterKdf.PasswordMode == "UserPassword24to256+PIN6to16+GeneratedHex1024x2",
            "the v12 key-derivation contract strings are unchanged");
        Assert(
            V12MasterKdf.FactorBytes == 128
            && V12MasterKdf.FactorHalfBytes == 64
            && V12MasterKdf.MasterBytes == 128
            && V12MasterKdf.Iterations == 4
            && V12MasterKdf.Parallelism == 4,
            "the v12 factor split, master width and Argon2id cost parameters are unchanged");
        Assert(
            !firstWindow.CreateArchiveButton.IsEnabled
            && !firstWindow.ExtractArchiveButton.IsEnabled
            && !firstWindow.ListArchiveButton.IsEnabled
            && !firstWindow.EmergencyRecoveryButton.IsEnabled
            && !firstWindow.EraseContainerButton.IsEnabled,
            "security-sensitive operations fail closed before the asynchronous integrity check completes");
        FieldInfo integrityField = typeof(MainWindow).GetField("_integrityTrusted", BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("MainWindow integrity gate field was not found.");
        MethodInfo updateGate = typeof(MainWindow).GetMethod("UpdateProtectedOperationButtons", BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("MainWindow gate update method was not found.");
        MethodInfo beginOperation = typeof(MainWindow).GetMethod("TryBeginProtectedOperation", BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("MainWindow operation gate method was not found.");
        MethodInfo endOperation = typeof(MainWindow).GetMethod("EndProtectedOperation", BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("MainWindow operation gate release method was not found.");
        integrityField.SetValue(firstWindow, true);
        updateGate.Invoke(firstWindow, null);
        Assert((bool)beginOperation.Invoke(firstWindow, null)!, "first protected operation acquires the GUI gate");
        Assert(!(bool)beginOperation.Invoke(firstWindow, null)!, "a concurrent protected operation is rejected");
        Assert(!firstWindow.CreatePanel.IsEnabled && !firstWindow.ExtractPanel.IsEnabled && !firstWindow.ErasePanel.IsEnabled, "mutable archive controls are disabled while an operation is active");
        long samplesBeforeBusyMouseMove = EntropyMixer.SampleCount;
        firstWindow.RaiseEvent(new System.Windows.Input.MouseEventArgs(
            System.Windows.Input.Mouse.PrimaryDevice,
            Environment.TickCount)
        {
            RoutedEvent = System.Windows.Input.Mouse.PreviewMouseMoveEvent,
        });
        Assert(
            EntropyMixer.SampleCount == samplesBeforeBusyMouseMove,
            "mouse entropy collection pauses while a protected operation is active");
        endOperation.Invoke(firstWindow, null);
        Assert(
            firstWindow.CreateArchiveButton.IsEnabled
            && firstWindow.EmergencyRecoveryButton.IsEnabled
            && firstWindow.CreatePanel.IsEnabled,
            "operation gate restores trusted controls after completion");
        // The distribution oracle is the concrete EntropyPurpose set, not the
        // aggregated GUI counters: those are min()/alias views and cannot show
        // whether every pool actually received its share.
        EntropyPurpose[] allPurposes = Enum.GetValues<EntropyPurpose>();
        Assert(
            allPurposes.Length == 9
            && allPurposes.SequenceEqual(
            [
                EntropyPurpose.FactorA1,
                EntropyPurpose.FactorA2,
                EntropyPurpose.FactorB1,
                EntropyPurpose.FactorB2,
                EntropyPurpose.SaltSha3,
                EntropyPurpose.SaltSkein,
                EntropyPurpose.NonceFirst,
                EntropyPurpose.NonceSecond,
                EntropyPurpose.NonceThird,
            ]),
            "the entropy architecture still has exactly the nine expected purposes");
        const int DistributionSampleCount = 27;
        long samplesBeforeTabMoves = EntropyMixer.SampleCount;
        long[] purposeCountsBeforeTabMoves = [.. allPurposes.Select(EntropyMixer.GetSampleCount)];
        for (int index = 0; index < DistributionSampleCount; index++)
        {
            firstWindow.MainTabs.SelectedIndex = index % firstWindow.MainTabs.Items.Count;
            var selectedTab = (System.Windows.Controls.TabItem)firstWindow.MainTabs.SelectedItem;
            selectedTab.RaiseEvent(new System.Windows.Input.MouseEventArgs(
                System.Windows.Input.Mouse.PrimaryDevice,
                Environment.TickCount + index)
            {
                RoutedEvent = System.Windows.Input.Mouse.PreviewMouseMoveEvent,
                Handled = true,
            });
        }

        Assert(
            EntropyMixer.SampleCount == samplesBeforeTabMoves + DistributionSampleCount,
            "handled mouse moves remain visible to the window across all tabs");
        long[] purposeCountsAfterTabMoves = [.. allPurposes.Select(EntropyMixer.GetSampleCount)];
        long[] purposeDeltas = [.. purposeCountsAfterTabMoves.Zip(purposeCountsBeforeTabMoves, (after, before) => after - before)];
        Assert(
            purposeDeltas.Sum() == DistributionSampleCount,
            "every collected mouse sample lands in exactly one entropy purpose");
        Assert(
            purposeDeltas.All(delta => delta >= 0),
            "no entropy purpose loses samples while collecting");
        Assert(
            purposeDeltas.Max() - purposeDeltas.Min() <= 1,
            "tab-spanning mouse moves are distributed evenly across all nine entropy pools");
        integrityField.SetValue(firstWindow, false);
        updateGate.Invoke(firstWindow, null);
        firstWindow.CipherSuiteBox.SelectedIndex = SuiteDisplayIndex(EncryptionSuite.Kalyna512_512);
        firstWindow.CompressionBox.SelectedIndex = 5;
        firstWindow.LanguageBox.SelectedIndex = 0;
    }
    finally
    {
        firstWindow.Close();
    }

    Assert(settings.Read(MainWindow.CipherSuiteSettingsFile) == "Kalyna512_512", "Kalyna suite selection is persisted");
    Assert(settings.Read(MainWindow.CompressionSettingsFile) == "5", "compression level 5 is persisted");
    Assert(settings.Read(MainWindow.LanguageSettingsFile) == "de", "German language selection is persisted");

    var restartedWindow = new MainWindow(settings);
    try
    {
        Assert(restartedWindow.CipherSuiteBox.SelectedIndex == SuiteDisplayIndex(EncryptionSuite.Kalyna512_512), "restarted GUI restores Kalyna");
        Assert(restartedWindow.CompressionBox.SelectedIndex == 5, "restarted GUI restores compression level 5");
        Assert(restartedWindow.LanguageBox.SelectedIndex == 0, "restarted GUI restores German");
        Assert(restartedWindow.Title == "Keep Vault" && restartedWindow.TitleText.Text == "Keep Vault", "German GUI keeps the language-independent product name");
        Assert(
            restartedWindow.SubtitleText.Text == "Verschlüsselte ZPAQ-Archive erstellen, entpacken und kryptografisch löschen.",
            "German GUI keeps its existing localized subtitle");
        Assert(
            restartedWindow.Argon2ProfileText.Text.Contains("1 GiB", StringComparison.Ordinal)
            && restartedWindow.Argon2ProfileText.Text.Contains("knapp 2 GiB", StringComparison.Ordinal)
            && restartedWindow.Argon2ProfileText.Text.Contains("PMI16", StringComparison.Ordinal)
            && restartedWindow.Argon2ProfileText.Text.Contains("t=4", StringComparison.Ordinal)
            && restartedWindow.Argon2ProfileText.Text.Contains("p=4", StringComparison.Ordinal)
            && restartedWindow.Argon2ProfileText.Text.Contains("sequenziell", StringComparison.OrdinalIgnoreCase)
            && restartedWindow.Argon2ProfileText.Text != englishArgon2Profile,
            "German GUI localizes the PMI16 memory range and sequential t=4, p=4 Argon2 profile");
        restartedWindow.CipherSuiteBox.SelectedIndex = SuiteDisplayIndex(EncryptionSuiteCatalog.Default);
    }

    finally
    {
        restartedWindow.Close();
    }

    Assert(settings.Read(MainWindow.CipherSuiteSettingsFile) == EncryptionSuiteCatalog.Default.ToString(), "the default suite is persisted after changing it back");

    var corruptedSettings = new MemoryAppSettingsStore();
    corruptedSettings.Write(MainWindow.CipherSuiteSettingsFile, "999");
    corruptedSettings.Write(MainWindow.CompressionSettingsFile, "999999999999999999999");
    corruptedSettings.Write(MainWindow.LanguageSettingsFile, "invalid");
    var fallbackWindow = new MainWindow(corruptedSettings);
    try
    {
        Assert(fallbackWindow.CipherSuiteBox.SelectedIndex == SuiteDisplayIndex(EncryptionSuiteCatalog.Default), "unknown persisted suite falls back to the catalog default");
        Assert(fallbackWindow.CompressionBox.SelectedIndex == 1, "invalid persisted compression falls back to level 1");
        Assert(fallbackWindow.LanguageBox.SelectedIndex == 1, "invalid persisted language falls back to English");
    }
    finally
    {
        fallbackWindow.Close();
    }
}

static void RunFailedArchivePreservationPolicyTests()
{
    string root = Directory.CreateTempSubdirectory("keep-vault-windows-gui-preserve-").FullName;
    string archivePath = Path.Combine(root, "failed.kzpaq");
    string[] paths =
    [
        archivePath,
        RecoveryService.GetRecoveryPath(archivePath),
        ArchiveIntegrityService.GetSha3ManifestPath(archivePath),
        ArchiveIntegrityService.GetSkeinManifestPath(archivePath),
    ];
    byte[][] canaries =
    [
        [0x11, 0x22, 0x33],
        [0x44, 0x55, 0x66],
        [0x77, 0x88, 0x99],
        [0xAA, 0xBB, 0xCC],
    ];
    try
    {
        for (int index = 0; index < paths.Length; index++)
        {
            File.WriteAllBytes(paths[index], canaries[index]);
        }

        string warning = MainWindow.BuildPreservedArtifactWarning(archivePath);
        for (int index = 0; index < paths.Length; index++)
        {
            Assert(
                warning.Contains(paths[index], StringComparison.Ordinal),
                $"GUI preservation warning names possible committed output {paths[index]}");
            Assert(
                File.ReadAllBytes(paths[index]).AsSpan().SequenceEqual(canaries[index]),
                $"GUI downstream-failure policy preserves replacement canary {paths[index]}");
        }
    }
    finally
    {
        Directory.Delete(root, recursive: true);
    }
}

static void RunDropTests()
{
    string root = Path.Combine(Path.GetTempPath(), $"kalyna-dnd-test-{Guid.NewGuid():N}");
    Directory.CreateDirectory(root);

    try
    {
        string file = Path.Combine(root, "input.txt");
        string archive = Path.Combine(root, "archive.zpaq");
        string hintedArchive = Path.Combine(root, "hinted.kzpaq");
        string misnamedEncryptedArchive = Path.Combine(root, "misnamed.pdf");
        string output = Path.Combine(root, "output");
        string archiveOutputConflictDirectory = Path.Combine(root, "archive(1)");
        string archiveOutputConflictFile = Path.Combine(root, "archive(2)");
        string archiveTargetDirectoryConflict = Path.Combine(root, "conflict(1).zpaq");
        string archiveTargetInput = Path.Combine(root, "conflict.txt");
        File.WriteAllText(file, "drop me");
        File.WriteAllText(archiveTargetInput, "target naming conflict");
        File.WriteAllText(archive, "not a real archive, only path classification");
        CreateSyntheticKalynaContainer(hintedArchive, "blue notebook in the safe");
        File.WriteAllBytes(misnamedEncryptedArchive, [.. "KZPAQ2\0"u8, 0, 0, 0, 0]);
        Directory.CreateDirectory(output);
        Directory.CreateDirectory(archiveOutputConflictDirectory);
        Directory.CreateDirectory(archiveTargetDirectoryConflict);
        File.WriteAllText(archiveOutputConflictFile, "folder name conflict");

        var window = new MainWindow(new MemoryAppSettingsStore());
        try
        {
            Assert(string.IsNullOrEmpty(window.GeneratedPasswordFirstBox.Text), "first generated password is not created on startup");
            Assert(string.IsNullOrEmpty(window.GeneratedPasswordSecondBox.Text), "second generated password is not created on startup");
            Assert(!EntropyMixer.HasRequiredSamples(EntropyPurpose.FactorA1), "first generated-password entropy threshold is not met on startup");
            Assert(!EntropyMixer.HasRequiredSamples(EntropyPurpose.FactorB1), "second generated-password entropy threshold is not met on startup");
            Assert(!window.GeneratePasswordButton.IsEnabled, "generated password button is disabled until all entropy pools are ready");
            Assert(
                window.CipherSuiteBox.Items.Count == EncryptionSuiteCatalog.DisplayOrder.Count
                && EncryptionSuiteCatalog.DisplayOrder.Select((suite, index) =>
                    ((System.Windows.Controls.ComboBoxItem)window.CipherSuiteBox.Items[index]).Tag?.ToString() == suite.ToString()).All(matches => matches)
                && window.CipherSuiteBox.SelectedIndex == SuiteDisplayIndex(EncryptionSuiteCatalog.Default),
                "GUI offers every catalogued suite in display order and preselects the factory default");
            window.SetExtractArchivePath(hintedArchive);
            WaitForDispatcherTask(window.ExtractHintLoadTaskForTests);
            Assert(window.ExtractHintLabel.Text == "Optional hint from archive", "extract GUI labels the optional archive hint");
            Assert(
                window.ExtractHintText.Text.Contains("blue notebook in the safe", StringComparison.Ordinal),
                "selecting an encrypted archive immediately displays its public optional hint");
            AddMouseSamplesUntilEntropyReady();
            window.RefreshEntropyStatusForTests();
            Assert(window.GeneratePasswordButton.IsEnabled, "generated password button is enabled after all entropy pools are ready");
            Assert(
                window.EntropyStatusText.Text.Contains("nonce 1", StringComparison.OrdinalIgnoreCase)
                && window.EntropyStatusText.Text.Contains("nonce 2", StringComparison.OrdinalIgnoreCase),
                "GUI displays both independent nonce-pool counters");
            window.EncryptBox.IsChecked = false;
            Assert(window.ApplyDroppedPaths([file], DropTarget.Inputs) == DropResult.InputsAdded, "file input drop");
            Assert(window.InputList.Items.Contains(file), "input list contains file");
            Assert(window.ArchivePathBox.Text == Path.Combine(root, "input(1).zpaq"), "input drop suggests numbered archive path");
            window.InputList.Items.Clear();

            Assert(window.ApplyDroppedPaths([archive], DropTarget.Auto) == DropResult.ExtractArchiveSet, "auto archive drop");
            Assert(window.ExtractArchiveBox.Text == archive, "extract archive box");
            Assert(window.OutputFolderBox.Text == Path.Combine(root, "archive(3)"), "archive drop suggests conflict-free output folder");
            Assert(MainWindow.SuggestOutputFolderPath(archive) == Path.Combine(root, "archive(3)"), "output folder suggestion handles directory and file conflicts");
            Assert(
                MainWindow.SuggestTargetArchivePath(archiveTargetInput, encrypted: false) == Path.Combine(root, "conflict(2).zpaq"),
                "archive target suggestion skips a directory with the candidate archive name");

            Assert(window.ApplyDroppedPaths([output], DropTarget.OutputFolder) == DropResult.OutputFolderSet, "output folder drop");
            Assert(window.OutputFolderBox.Text == output, "output folder box");

            Assert(window.ApplyDroppedPaths([output], DropTarget.TargetArchive) == DropResult.TargetArchiveSet, "target archive folder drop");
            Assert(window.ArchivePathBox.Text == Path.Combine(root, "output(1).zpaq"), "folder dropped as target suggests an archive beside it, named after it");

            Assert(window.ApplyDroppedPaths([file], DropTarget.TargetArchive) == DropResult.TargetArchiveSet, "target archive file drop");
            Assert(window.ArchivePathBox.Text == Path.Combine(root, "input(1).zpaq"), "target archive file drop adds numbered suffix");
            Assert(window.InputList.Items.Contains(file), "target archive file drop also adds input file");

            window.EncryptBox.IsChecked = true;
            Assert(window.ApplyDroppedPaths([file], DropTarget.TargetArchive) == DropResult.TargetArchiveSet, "encrypted target archive file drop");
            Assert(window.ArchivePathBox.Text == Path.Combine(root, "input(1).kzpaq"), "encrypted target archive adds numbered suffix");
            Assert(window.InputList.Items.Contains(file), "encrypted target archive file drop keeps input file");
            Assert(MainWindow.NormalizeTargetArchivePath(Path.Combine(root, "wrong.pdf"), encrypted: false) == Path.Combine(root, "wrong.zpaq"), "plain target normalizes away pdf extension");
            Assert(MainWindow.NormalizeTargetArchivePath(Path.Combine(root, "wrong.pdf"), encrypted: true) == Path.Combine(root, "wrong.kzpaq"), "encrypted target normalizes away pdf extension");
            Assert(MainWindow.SuggestTargetArchivePath(Path.Combine(root, "wrong.pdf"), encrypted: false) == Path.Combine(root, "wrong(1).zpaq"), "plain target suggestion adds numbered suffix");
            Assert(MainWindow.SuggestTargetArchivePath(Path.Combine(root, "wrong.pdf"), encrypted: true) == Path.Combine(root, "wrong(1).kzpaq"), "encrypted target suggestion adds numbered suffix");
            window.EncryptBox.IsChecked = false;

            window.ArchivePathBox.Text = Path.Combine(root, "manual.zpaq");
            window.CipherSuiteBox.SelectedIndex = 0;
            window.GeneratePasswordButton.RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Primitives.ButtonBase.ClickEvent));
            Assert(window.GeneratedPasswordFirstBox.Text.Length == 256, "GUI generator shows first 256-character factor");
            Assert(window.GeneratedPasswordFirstBox.Text.All(Uri.IsHexDigit), "first GUI generator output is hexadecimal");
            Assert(window.GeneratedPasswordSecondBox.Text.Length == 256, "GUI generator shows second 256-character factor");
            Assert(window.GeneratedPasswordSecondBox.Text.All(Uri.IsHexDigit), "second GUI generator output is hexadecimal");
            Assert(!string.Equals(window.GeneratedPasswordFirstBox.Text, window.GeneratedPasswordSecondBox.Text, StringComparison.Ordinal), "GUI generator factors are independent");
            Assert(!window.GeneratePasswordButton.IsEnabled, "GUI generator is disabled again until fresh factor mouse samples are collected");
            Assert(EntropyMixer.GetPoolStatus().Total == 0, "GUI password generation clears all mouse pools atomically");
            Assert(window.HasPreparedArchiveEntropyForTests, "GUI retains the generated salt and nonce in locked RAM after resetting the visible pools");
            Assert(
                window.EntropyStatusText.Text.Contains("total 0", StringComparison.OrdinalIgnoreCase)
                && window.EntropyStatusText.Text.Contains("securely consumed", StringComparison.OrdinalIgnoreCase),
                "GUI identifies the zero counters as consumed while keeping archive entropy ready");
            Assert(string.IsNullOrEmpty(window.CreatePasswordBox.Password), "GUI generator leaves user password empty");
            Assert(string.IsNullOrEmpty(window.CreatePasswordConfirmBox.Password), "GUI generator leaves create confirmation empty");
            Assert(string.IsNullOrEmpty(window.CreatePinBox.Password), "GUI generator leaves create PIN empty");
            Assert(string.IsNullOrEmpty(window.CreatePinConfirmBox.Password), "GUI generator leaves create PIN confirm empty");
            Assert(window.EncryptBox.IsChecked == true, "GUI generator enables encryption");
            Assert(window.CipherSuiteBox.SelectedIndex == 0, "GUI generator preserves the selected Threefish suite");
            Assert(window.ArchivePathBox.Text == Path.Combine(root, "manual.kzpaq"), "GUI generator switches target extension to encrypted container");
            Assert(window.ExtractPasswordBox.IsEnabled, "extract password box is directly enabled");
            window.CreatePasswordBox.Password = TestUserPassword;
            window.CreatePasswordConfirmBox.Password = TestUserPassword;
            window.CreatePinBox.Password = TestPin;
            window.CreatePinConfirmBox.Password = TestPin;
            window.ClearCreateSecretsButton.RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Primitives.ButtonBase.ClickEvent));
            Assert(string.IsNullOrEmpty(window.CreatePasswordBox.Password), "clear-secrets button removes create user password");
            Assert(string.IsNullOrEmpty(window.CreatePasswordConfirmBox.Password), "clear-secrets button removes create confirmation");
            Assert(string.IsNullOrEmpty(window.CreatePinBox.Password), "clear-secrets button removes create PIN");
            Assert(string.IsNullOrEmpty(window.CreatePinConfirmBox.Password), "clear-secrets button removes create PIN confirm");
            Assert(string.IsNullOrEmpty(window.GeneratedPasswordFirstBox.Text), "clear-secrets button removes generated factor A");
            Assert(string.IsNullOrEmpty(window.GeneratedPasswordSecondBox.Text), "clear-secrets button removes generated factor B");
            Assert(!window.HasPreparedArchiveEntropyForTests, "clear-secrets disposes the prepared salt and nonce");

            window.ExtractPasswordBox.Password = TestUserPassword;
            window.ExtractPinBox.Password = TestPin;
            window.ExtractGeneratedPasswordFirstBox.Text = TestGeneratedPassword();
            window.ExtractGeneratedPasswordSecondBox.Text = TestGeneratedPassword('B');
            window.ClearExtractSecretsButton.RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Primitives.ButtonBase.ClickEvent));
            Assert(string.IsNullOrEmpty(window.ExtractPasswordBox.Password), "clear-secrets button removes extraction user password");
            Assert(string.IsNullOrEmpty(window.ExtractPinBox.Password), "clear-secrets button removes extraction PIN");
            Assert(string.IsNullOrEmpty(window.ExtractGeneratedPasswordFirstBox.Text), "clear-secrets button removes extraction factor A");
            Assert(string.IsNullOrEmpty(window.ExtractGeneratedPasswordSecondBox.Text), "clear-secrets button removes extraction factor B");
            RunCredentialFailureSecretClearingTests(window);

            Assert(window.ResolveDropTargetFromElement(window.InputList, [file]) == DropTarget.Inputs, "input list target resolution");
            Assert(window.ResolveDropTargetFromElement(window.ArchivePathBox, [output]) == DropTarget.TargetArchive, "target archive field target resolution");
            Assert(window.ResolveDropTargetFromElement(window.ExtractArchiveBox, [archive]) == DropTarget.ExtractArchive, "extract archive field target resolution");
            Assert(window.ResolveDropTargetFromElement(window.OutputFolderBox, [output]) == DropTarget.OutputFolder, "output folder field target resolution");
            Assert(window.ResolveDropTargetFromElement(window.ErasePathBox, [misnamedEncryptedArchive]) == DropTarget.EraseTarget, "erase field target resolution");
            Assert(window.ResolveDropTargetFromElement(window.ExtractPanel, [archive]) == DropTarget.ExtractArchive, "extract panel archive resolution");
            Assert(window.ResolveDropTargetFromElement(window.ExtractPasswordBox, [archive]) == DropTarget.ExtractArchive, "extract password area archive resolution");
            Assert(window.ResolveDropTargetFromElement(window.ExtractPanel, [output]) == DropTarget.OutputFolder, "extract panel folder resolution");
            Assert(window.ResolveDropTargetFromElement(window.ErasePanel, [misnamedEncryptedArchive]) == DropTarget.EraseTarget, "erase panel target resolution");

            window.InputList.Items.Clear();
            RaiseFileDragOver(window.InputList, file);
            RaiseFileDrop(window.InputList, file);
            Assert(window.InputList.Items.Contains(file), "preview drop on input list");

            RaiseFileDragOver(window.ExtractArchiveBox, archive);
            RaiseFileDrop(window.ExtractArchiveBox, archive);
            Assert(window.ExtractArchiveBox.Text == archive, "preview drop on extract archive box");
            WaitForDispatcherTask(window.ExtractHintLoadTaskForTests);
            Assert(window.OutputFolderBox.Text == Path.Combine(root, "archive(3)"), "preview drop on extract archive box suggests output");

            RaiseFileDragOver(window.ExtractPasswordBox, archive);
            RaiseFileDrop(window.ExtractPasswordBox, archive);
            Assert(window.ExtractArchiveBox.Text == archive, "preview drop on extract password area");
            WaitForDispatcherTask(window.ExtractHintLoadTaskForTests);
            Assert(window.OutputFolderBox.Text == Path.Combine(root, "archive(3)"), "preview drop on extract password area suggests output");

            RaiseFileDragOver(window.ExtractPanel, misnamedEncryptedArchive);
            RaiseFileDrop(window.ExtractPanel, misnamedEncryptedArchive);
            Assert(window.ExtractArchiveBox.Text == misnamedEncryptedArchive, "misnamed encrypted archive with KZPAQ header can be dropped for extraction");
            WaitForDispatcherTask(window.ExtractHintLoadTaskForTests);
            Assert(window.OutputFolderBox.Text == Path.Combine(root, "misnamed(1)"), "misnamed archive drop suggests output");
            Assert(
                MainWindow.HasEncryptedArchiveExtension("damaged.KZPAQ")
                && !MainWindow.HasEncryptedArchiveExtension("plain.zpaq"),
                "a damaged .kzpaq path remains classified as encrypted instead of falling through to the plain ZPAQ parser");

            RaiseFileDragOver(window.OutputFolderBox, output);
            RaiseFileDrop(window.OutputFolderBox, output);
            Assert(window.OutputFolderBox.Text == output, "preview drop on output folder box");

            RaiseFileDragOver(window.ErasePathBox, misnamedEncryptedArchive);
            RaiseFileDrop(window.ErasePathBox, misnamedEncryptedArchive);
            Assert(window.ErasePathBox.Text == misnamedEncryptedArchive, "preview drop on erase path box");

            window.EncryptBox.IsChecked = false;
            window.InputList.Items.Clear();
            RaiseFileDragOver(window.ArchivePathBox, output);
            RaiseFileDrop(window.ArchivePathBox, output);
            Assert(window.ArchivePathBox.Text == Path.Combine(root, "output(1).zpaq"), "preview drop on target archive box");
            Assert(!window.InputList.Items.Contains(output), "target archive folder drop does not add folder input");

            window.ExtractArchiveBox.Clear();
            RaiseFileDrop(window.ExtractPanel, archive);
            Assert(window.ExtractArchiveBox.Text == archive, "preview drop on extract panel background");
            WaitForDispatcherTask(window.ExtractHintLoadTaskForTests);
        }
        finally
        {
            // Every drop that sets an extract path starts a debounced read of
            // that archive's public hint. The assertions above only look at the
            // text box, so the last of those reads is still open on
            // archive.zpaq when this method returns - and the directory delete
            // below then fails with "used by another process".
            //
            // It passed for years because it was the second thing a single
            // script did, on an idle machine, and the read won the race. Run
            // beside twenty other groups it stops winning. Waiting here rather
            // than after each drop covers the assertion failures too, which
            // leave through this same finally.
            WaitForDispatcherTask(window.ExtractHintLoadTaskForTests);
            window.Close();
        }
    }
    finally
    {
        DeleteTestDirectory(root);
    }
}

static void RunCredentialFailureSecretClearingTests(MainWindow window)
{
    FieldInfo integrityField = typeof(MainWindow).GetField(
        "_integrityTrusted",
        BindingFlags.Instance | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("MainWindow integrity field was not found.");
    MethodInfo updateGate = typeof(MainWindow).GetMethod(
        "UpdateProtectedOperationButtons",
        BindingFlags.Instance | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("MainWindow protected-operation update method was not found.");
    integrityField.SetValue(window, true);
    updateGate.Invoke(window, null);

    int dialogs = 0;
    MainWindow.TestHookShowCredentialMessage = (_, _, _, image) =>
    {
        Assert(image == MessageBoxImage.Error, "credential-operation failure opened a non-error message");
        dialogs++;
        return MessageBoxResult.OK;
    };

    try
    {
        Exercise("extract", window.ExtractArchiveButton);
        Exercise("list", window.ListArchiveButton);
        Exercise("recovery", window.EmergencyRecoveryButton);
        Assert(dialogs == 3, $"credential failure handlers opened {dialogs} messages instead of three");
    }
    finally
    {
        MainWindow.TestHookBeforeCredentialOperation = null;
        MainWindow.TestHookShowCredentialMessage = null;
    }

    void Exercise(string expectedOperation, System.Windows.Controls.Button button)
    {
        window.ExtractPasswordBox.Password = "synthetic-password";
        window.ExtractPinBox.Password = "123456";
        window.ExtractGeneratedPasswordFirstBox.Text = "synthetic-factor-a";
        window.ExtractGeneratedPasswordSecondBox.Text = "synthetic-factor-b";
        window.LogBox.Clear();
        const string Diagnostic = "injected credential-operation failure";
        MainWindow.TestHookBeforeCredentialOperation = actualOperation =>
        {
            Assert(actualOperation == expectedOperation, $"{button.Name} reached {actualOperation} instead of {expectedOperation}");
            throw new InvalidDataException(Diagnostic);
        };
        try
        {
            button.RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Primitives.ButtonBase.ClickEvent));
        }
        finally
        {
            MainWindow.TestHookBeforeCredentialOperation = null;
        }

        Assert(string.IsNullOrEmpty(window.ExtractPasswordBox.Password), $"{expectedOperation} failure retained the password");
        Assert(string.IsNullOrEmpty(window.ExtractPinBox.Password), $"{expectedOperation} failure retained the PIN");
        Assert(string.IsNullOrEmpty(window.ExtractGeneratedPasswordFirstBox.Text), $"{expectedOperation} failure retained factor A");
        Assert(string.IsNullOrEmpty(window.ExtractGeneratedPasswordSecondBox.Text), $"{expectedOperation} failure retained factor B");
        Assert(window.LogBox.Text.Contains(Diagnostic, StringComparison.Ordinal), $"{expectedOperation} failure dropped its diagnostic");
    }
}

static async Task RunProcessContainmentTestsAsync()
{
    string root = Path.Combine(Path.GetTempPath(), $"kalyna-process-test-{Guid.NewGuid():N}");
    Directory.CreateDirectory(root);
    try
    {
        string testExecutable = Path.Combine(AppContext.BaseDirectory, "KalynaArchiver.Tests.exe");
        Assert(File.Exists(testExecutable), "test helper executable exists");
        string sentinel = Path.Combine(root, "survived.txt");
        using (var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(200)))
        {
            await AssertThrowsAsync<OperationCanceledException>(
                () => ZpaqService.RunTextProcessAsync(
                    testExecutable,
                    ["--delayed-sentinel-helper", sentinel],
                    root,
                    null,
                    cancellation.Token),
                "cancelling a text process propagates OperationCanceledException");
        }

        await Task.Delay(TimeSpan.FromMilliseconds(2300));
        Assert(!File.Exists(sentinel), "cancelled child process was terminated before it could write its sentinel");

        int progressReports = 0;
        var boundedProgress = new InlineProgress<string>(_ => progressReports++);
        ProcessResult boundedOutput = await ZpaqService.RunTextProcessAsync(
            testExecutable,
            ["--large-output-helper"],
            root,
            boundedProgress,
            CancellationToken.None);
        Assert(boundedOutput.Succeeded, "large-output helper exits successfully");
        Assert(boundedOutput.StandardOutput.Length <= (1024 * 1024) + 128, "captured process output remains bounded");
        Assert(boundedOutput.StandardOutput.Contains("[process output truncated]", StringComparison.Ordinal), "bounded process output reports truncation");
        Assert(boundedOutput.StandardOutput.Contains("[line truncated]", StringComparison.Ordinal), "oversized process line reports truncation");
        Assert(progressReports <= ZpaqService.MaxProgressLinesPerStream + 1, "process progress callbacks remain bounded");

        string failedExtraction = Path.Combine(root, "failed-extraction");
        var zpaq = new ZpaqService();
        string streamingInput = Path.Combine(root, "streaming-input.bin");
        await File.WriteAllBytesAsync(streamingInput, RandomNumberGenerator.GetBytes(1024 * 1024));
        var failFastTimer = Stopwatch.StartNew();
        using (var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
        {
            await AssertThrowsAsync<InvalidDataException>(
                () => zpaq.AddStreamingAsync(
                    [streamingInput],
                    0,
                    (_, _) => Task.FromException(new InvalidDataException("intentional stdout consumer failure")),
                    null,
                    timeout.Token),
                "stdout consumer failure is propagated without waiting for ZPAQ");
        }

        failFastTimer.Stop();
        Assert(failFastTimer.Elapsed < TimeSpan.FromSeconds(5), "stdout consumer failure terminates the ZPAQ process tree without a pipe deadlock");

        await AssertThrowsAsync<InvalidDataException>(
            () => zpaq.ExtractStreamingAsync(
                (_, _) => Task.FromException(new InvalidDataException("intentional input failure")),
                failedExtraction,
                null,
                CancellationToken.None),
            "streaming extraction propagates an input failure");
        Assert(!Directory.Exists(failedExtraction), "failed streaming extraction removes its partial output directory");
        Assert(!Directory.EnumerateDirectories(root, "*.extract-part", SearchOption.TopDirectoryOnly).Any(), "failed streaming extraction removes its hidden staging directory");
    }
    finally
    {
        DeleteTestDirectory(root);
    }
}

static void RunKeySheetTests()
{
    string root = Path.Combine(Path.GetTempPath(), $"kalyna-keysheet-test-{Guid.NewGuid():N}");
    Directory.CreateDirectory(root);

    try
    {
        string archive = Path.Combine(root, "sample.kzpaq");
        string pdf = Path.Combine(root, "key-sheet.pdf");
        string firstGeneratedPassword = TestGeneratedPassword();
        string secondGeneratedPassword = TestGeneratedPassword('B');
        var service = new KeySheetService();
        var data = new KeySheetData(archive, EncryptionSuite.Threefish1024, firstGeneratedPassword, secondGeneratedPassword, new DateTime(2026, 7, 8, 12, 0, 0, DateTimeKind.Local));

        service.SaveTestPdf(data, pdf);
        Assert(File.Exists(pdf) && new FileInfo(pdf).Length > 1024, "key sheet PDF was written");
        AssertPdfReadableAsync(pdf, "key sheet PDF", expectedPages: 3).GetAwaiter().GetResult();
        using (FileStream stream = File.OpenRead(pdf))
        {
            byte[] header = new byte[5];
            stream.ReadExactly(header);
            Assert(header.AsSpan().SequenceEqual("%PDF-"u8), "key sheet PDF header");
        }

        byte[] qrPng = KeySheetService.CreateQrPng(firstGeneratedPassword);
        Assert(qrPng.Length > 128, "QR code PNG has content");
        byte[] pngSignature = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        Assert(qrPng.AsSpan(0, 8).SequenceEqual(pngSignature), "QR code PNG signature");
        Assert(KeySheetService.GroupGeneratedPassword(firstGeneratedPassword).Contains(' '), "generated password is grouped for print");
        Assert(service.CreatePrintVisual(data, KeySheetFactor.First) is FrameworkElement, "first in-memory print visual can be created");
        Assert(service.CreatePrintVisual(data, KeySheetFactor.Second) is FrameworkElement, "second in-memory print visual can be created");
        Assert(service.CreatePrintDocument(data, new System.Windows.Size(793.7, 1122.5)).Pages.Count == 3, "print document has key sheet A, blank duplex page, and key sheet B");

        // The sheet has to carry the whole factor. It did not: the macOS sheet
        // printed the first 224 of its 256 hexadecimal characters, because
        // XTextFormatter drops the lines that do not fit the rectangle it is
        // handed and says nothing about it. A sheet missing the last 32
        // characters looks complete and cannot open its archive.
        //
        // The same construction is on this side, so it is held the same way.
        // The macOS suite runs this check as KeySheetFactorIsCompleteAsync.
        string factor = string.Concat(Enumerable.Repeat("0123456789ABCDEF", 16));
        Assert(factor.Length == PasswordKeyService.GeneratedPasswordLength, "a 1024-bit factor is 256 hexadecimal characters");

        string grouped = KeySheetService.GroupGeneratedPasswordForSheet(factor);
        string[] lines = grouped.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        string rejoined = string.Concat(lines.Select(line => line.Replace(" ", string.Empty).Trim()));
        Assert(
            string.Equals(rejoined, factor, StringComparison.Ordinal),
            $"the sheet grouping changed the factor: {rejoined.Length} characters instead of {factor.Length}");
        Assert(
            lines.Length == 7,
            $"a 256-character factor is seven rows of five groups; the grouping produced {lines.Length}");

        KeySheetService.EnsurePdfFontResolver();
        var monoFont = new PdfSharp.Drawing.XFont("Consolas", 14);
        double reserved = KeySheetService.FactorBlockHeight(monoFont, grouped);
        double needed = lines.Length * monoFont.GetHeight();
        Assert(
            reserved >= needed,
            $"the factor block reserves {reserved:F1}pt for {lines.Length} lines that need {needed:F1}pt; "
            + "the last lines would be dropped without a word");
    }
    finally
    {
        DeleteTestDirectory(root);
    }
}

static void AddMouseSamplesUntilEntropyReady()
{
    int i = 0;
    long guard = Enum.GetValues<EntropyPurpose>().Sum(p => EntropyMixer.MissingSamples(p)) + 10;
    while (!Enum.GetValues<EntropyPurpose>().All(EntropyMixer.HasRequiredSamples))
    {
        EntropyMixer.AddMouseSample(
            10 + (i % 257),
            20 + ((i * 7) % 263),
            1000 + i,
            i % 2 == 0 ? System.Windows.Input.MouseButtonState.Pressed : System.Windows.Input.MouseButtonState.Released,
            i % 3 == 0 ? System.Windows.Input.MouseButtonState.Pressed : System.Windows.Input.MouseButtonState.Released,
            i % 5 == 0 ? System.Windows.Input.MouseButtonState.Pressed : System.Windows.Input.MouseButtonState.Released);
        EntropyPoolStatus status = EntropyMixer.GetPoolStatus();
        if (!status.IsBalanced)
        {
            throw new InvalidOperationException("Mouse entropy pools diverged while filling a test epoch.");
        }

        i++;
        if (i > guard)
        {
            throw new InvalidOperationException("Could not fill entropy pools for tests.");
        }
    }

    Assert(
        EntropyMixer.GetPoolStatus().Minimum >= EntropyMixer.RequiredMouseSamplesPerPurpose,
        "all mouse entropy pools meet the required sample minimum");
    Assert(EntropyMixer.GetPoolStatus().IsBalanced, "all ready mouse entropy pools differ by at most one sample");
}

static void WaitForDispatcherTask(Task task)
{
    if (!task.IsCompleted)
    {
        System.Windows.Threading.Dispatcher dispatcher = System.Windows.Threading.Dispatcher.CurrentDispatcher;
        var frame = new System.Windows.Threading.DispatcherFrame();
        _ = task.ContinueWith(
            _ => dispatcher.BeginInvoke(
                new Action(() => frame.Continue = false)),
            CancellationToken.None,
            TaskContinuationOptions.None,
            TaskScheduler.Default);
        System.Windows.Threading.Dispatcher.PushFrame(frame);
    }

    task.GetAwaiter().GetResult();
}

static void CreateSyntheticKalynaContainer(string path, string hint)
{
    // The reader compares the header against its own canonical
    // re-serialization and accepts one container generation only, so this
    // fixture has to be a real v12 header. Every size is taken from the suite
    // catalogue rather than written out again: a second copy of the schema
    // here would drift the moment the container changes, and the drift would
    // surface as an unrelated GUI test failing.
    EncryptionSuiteParameters parameters = EncryptionSuiteCatalog.FromAlgorithm(EncryptionSuiteCatalog.KalynaAlgorithm);
    byte[] sha3Salt = RandomNumberGenerator.GetBytes(64);
    byte[] skeinSalt = RandomNumberGenerator.GetBytes(64);
    byte[] nonce = RandomNumberGenerator.GetBytes(parameters.NonceBytes);
    byte[] header = JsonSerializer.SerializeToUtf8Bytes(new
    {
        Version = 12,
        Algorithm = EncryptionSuiteCatalog.KalynaAlgorithm,
        BlockBits = parameters.BlockBytes * 8,
        CounterEndian = EncryptionSuiteCatalog.CounterEndian,
        EncryptionKeyBits = parameters.EncryptionKeyBytes * 8,
        Sha3MacKeyBits = parameters.Sha3MacKeyBytes * 8,
        Sha3TagBits = 512,
        SkeinMacKeyBits = parameters.SkeinMacKeyBytes * 8,
        SkeinTagBits = 1024,
        SaltSha3Round1 = Convert.ToBase64String(sha3Salt),
        SaltSkeinRound1 = Convert.ToBase64String(skeinSalt),
        SaltSha3Round2 = (string?)null,
        SaltSkeinRound2 = (string?)null,
        NonceBits = parameters.NonceBytes * 8,
        Nonce = Convert.ToBase64String(nonce),
        TweakBits = parameters.TweakBytes * 8,
        TweakMode = "None",
        Tweak = (string?)null,
        Hint = hint,
        Argon2MemoryKiB = 0,
        Argon2Iterations = (int)V12MasterKdf.Iterations,
        Argon2Parallelism = (int)V12MasterKdf.Parallelism,
        KdfBranchOutputBits = 512,
        MasterKeyBits = 1024,
        KdfExecutionMode = "Sequential",
        KdfMemoryMode = "PMI16",
        PasswordMode = V12MasterKdf.PasswordMode,
        KdfInputMode = V12MasterKdf.KdfInputMode,
        GeneratedPasswordBits = 1024,
        GeneratedPasswordFactorCount = 2,
        KdfMode = V12MasterKdf.KdfMode,
        SecondNonceBits = 0,
        SecondNonce = (string?)null,
    });
    try
    {
        using FileStream output = File.Create(path);
        output.Write("KZPAQ2\0"u8);
        Span<byte> headerLength = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(headerLength, header.Length);
        output.Write(headerLength);
        output.Write(header);
        output.Write(new byte[193]);
    }
    finally
    {
        CryptographicOperations.ZeroMemory(sha3Salt);
        CryptographicOperations.ZeroMemory(skeinSalt);
        CryptographicOperations.ZeroMemory(nonce);
        CryptographicOperations.ZeroMemory(header);
    }
}

// The suite list is ordered for readers, not by enum value, and gains
// entries as ciphers are added. Look the position up instead of pinning it,
// so a reordered catalogue cannot quietly test a different suite.
static int SuiteDisplayIndex(EncryptionSuite suite)
{
    for (int index = 0; index < EncryptionSuiteCatalog.DisplayOrder.Count; index++)
    {
        if (EncryptionSuiteCatalog.DisplayOrder[index] == suite)
        {
            return index;
        }
    }

    throw new InvalidOperationException($"Suite {suite} is not offered in the GUI.");
}

static void Assert(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException($"Assertion failed: {message}");
    }
}

static void RunKalynaReferenceVectorTest()
{
    byte[] key = Enumerable.Range(0x00, 64).Select(i => (byte)i).ToArray();
    byte[] nonce = Enumerable.Range(0x40, 64).Select(i => (byte)i).ToArray();
    byte[] zero = new byte[64];
    byte[] actual = new byte[64];
    byte[] expected = ULongWordsToLittleEndianBytes(
    [
        0x6a351c811be3264aUL,
        0x1a239605cad61da6UL,
        0xa1f347aa5483ba67UL,
        0xb856eb20c3ee1d3eUL,
        0x66ab5b1717f4d095UL,
        0x6cc815bb34f1d62fUL,
        0xb7fe6e85266a90cbUL,
        0xd9d90d947264bcc5UL,
    ]);

    Assert(NativeKalyna.IsAvailable(), "native Kalyna DLL is available");
    NativeKalyna.XCryptCtr512(key, nonce, zero, actual);
    Assert(CryptographicOperations.FixedTimeEquals(expected, actual), "Kalyna 512/512 first CTR block matches reference enciphering vector");

    byte[] plain = Enumerable.Range(0, 137).Select(i => (byte)(i * 17)).ToArray();
    byte[] cipher = new byte[plain.Length];
    byte[] decrypted = new byte[plain.Length];
    NativeKalyna.XCryptCtr512(key, nonce, plain, cipher);
    NativeKalyna.XCryptCtr512(key, nonce, cipher, decrypted);
    Assert(CryptographicOperations.FixedTimeEquals(plain, decrypted), "Kalyna CTR roundtrip");
}

static void RunKalynaParallelCtrEquivalenceTest()
{
    byte[] key = Enumerable.Range(0, 64).Select(i => (byte)((i * 3) + 1)).ToArray();
    byte[] nonce = Enumerable.Range(0, 64).Select(i => (byte)(255 - i)).ToArray();
    nonce[62] = 0xFE;
    nonce[63] = 0xF0;
    byte[] input = new byte[(10 * 1024 * 1024) + 333];
    byte[] parallel = new byte[input.Length];
    byte[] serial = new byte[input.Length];
    string? previousThreadSetting = Environment.GetEnvironmentVariable("KALYNA_V12_CTR_THREADS");
    RandomNumberGenerator.Fill(input);

    try
    {
        Environment.SetEnvironmentVariable("KALYNA_V12_CTR_THREADS", "4");
        NativeKalyna.XCryptCtr512(key, nonce, input, parallel, input.Length);

        byte[] counter = (byte[])nonce.Clone();
        try
        {
            int offset = 0;
            const int SerialChunkSize = 256 * 1024;
            while (offset < input.Length)
            {
                int read = Math.Min(SerialChunkSize, input.Length - offset);
                byte[] segmentIn = new byte[read];
                byte[] segmentOut = new byte[read];
                try
                {
                    Buffer.BlockCopy(input, offset, segmentIn, 0, read);
                    NativeKalyna.XCryptCtr512(key, counter, segmentIn, segmentOut, read);
                    Buffer.BlockCopy(segmentOut, 0, serial, offset, read);
                    IncrementCounterForTest(counter, BlocksForLengthForTest(read));
                    offset += read;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(segmentIn);
                    CryptographicOperations.ZeroMemory(segmentOut);
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(counter);
        }

        Assert(CryptographicOperations.FixedTimeEquals(parallel, serial), "parallel Kalyna CTR output matches serial counter composition");

        byte[] decrypted = new byte[input.Length];
        try
        {
            NativeKalyna.XCryptCtr512(key, nonce, parallel, decrypted, parallel.Length);
            Assert(CryptographicOperations.FixedTimeEquals(input, decrypted), "parallel Kalyna CTR decrypts its own ciphertext");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(decrypted);
        }
    }
    finally
    {
        Environment.SetEnvironmentVariable("KALYNA_V12_CTR_THREADS", previousThreadSetting);
        CryptographicOperations.ZeroMemory(key);
        CryptographicOperations.ZeroMemory(nonce);
        CryptographicOperations.ZeroMemory(input);
        CryptographicOperations.ZeroMemory(parallel);
        CryptographicOperations.ZeroMemory(serial);
    }
}

static long BlocksForLengthForTest(int length)
{
    return (length + 63L) / 64L;
}

static void RunThreefishReferenceAndIndependentTests()
{
    byte[] zeroKey = new byte[128];
    byte[] zeroTweak = new byte[16];
    byte[] zeroBlock = new byte[128];
    byte[] nativeOutput = new byte[128];
    byte[] officialExpected = ULongWordsToLittleEndianBytes(
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

    Assert(NativeThreefish.IsAvailable(), "native Threefish reference DLL is available");
    NativeThreefish.EncryptBlock1024(zeroKey, zeroTweak, zeroBlock, nativeOutput);
    Assert(
        CryptographicOperations.FixedTimeEquals(officialExpected, nativeOutput),
        "Threefish-1024 zero vector matches the official Skein 1.3 golden internal KAT");

    for (int vector = 0; vector < 24; vector++)
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
            int written = engine.ProcessBlock(input, 0, independent, 0);
            Assert(written == 128, "Bouncy Castle Threefish-1024 writes one full block");
            Assert(
                CryptographicOperations.FixedTimeEquals(native, independent),
                $"official Threefish reference adapter matches Bouncy Castle vector {vector}");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(tweak);
            CryptographicOperations.ZeroMemory(input);
            CryptographicOperations.ZeroMemory(native);
            CryptographicOperations.ZeroMemory(independent);
        }
    }

    CryptographicOperations.ZeroMemory(zeroKey);
    CryptographicOperations.ZeroMemory(zeroTweak);
    CryptographicOperations.ZeroMemory(zeroBlock);
    CryptographicOperations.ZeroMemory(nativeOutput);
    CryptographicOperations.ZeroMemory(officialExpected);
}

static void RunThreefishParallelCtrEquivalenceTest()
{
    byte[] key = RandomNumberGenerator.GetBytes(128);
    byte[] tweak = RandomNumberGenerator.GetBytes(16);
    byte[] nonce = RandomNumberGenerator.GetBytes(128);
    byte[] input = RandomNumberGenerator.GetBytes((10 * 1024 * 1024) + 333);
    byte[] parallel = new byte[input.Length];
    byte[] serial = new byte[input.Length];
    string? previousThreadSetting = Environment.GetEnvironmentVariable("THREEFISH_CTR_THREADS");

    try
    {
        Environment.SetEnvironmentVariable("THREEFISH_CTR_THREADS", "4");
        NativeThreefish.XCryptCtr1024(key, tweak, nonce, input, parallel, input.Length);

        byte[] counter = (byte[])nonce.Clone();
        try
        {
            int offset = 0;
            const int SerialChunkSize = 256 * 1024;
            while (offset < input.Length)
            {
                int read = Math.Min(SerialChunkSize, input.Length - offset);
                byte[] segmentIn = input.AsSpan(offset, read).ToArray();
                byte[] segmentOut = new byte[read];
                try
                {
                    NativeThreefish.XCryptCtr1024(key, tweak, counter, segmentIn, segmentOut, read);
                    segmentOut.CopyTo(serial, offset);
                    IncrementCounterForTest(counter, (read + 127L) / 128L);
                    offset += read;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(segmentIn);
                    CryptographicOperations.ZeroMemory(segmentOut);
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(counter);
        }

        Assert(
            CryptographicOperations.FixedTimeEquals(parallel, serial),
            "parallel Threefish-1024 CTR output matches serial counter composition");

        byte[] decrypted = new byte[input.Length];
        try
        {
            NativeThreefish.XCryptCtr1024(key, tweak, nonce, parallel, decrypted, parallel.Length);
            Assert(CryptographicOperations.FixedTimeEquals(input, decrypted), "parallel Threefish CTR roundtrip");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(decrypted);
        }
    }
    finally
    {
        Environment.SetEnvironmentVariable("THREEFISH_CTR_THREADS", previousThreadSetting);
        CryptographicOperations.ZeroMemory(key);
        CryptographicOperations.ZeroMemory(tweak);
        CryptographicOperations.ZeroMemory(nonce);
        CryptographicOperations.ZeroMemory(input);
        CryptographicOperations.ZeroMemory(parallel);
        CryptographicOperations.ZeroMemory(serial);
    }
}

static void IncrementCounterForTest(byte[] counter, long blocks)
{
    ulong carry = (ulong)blocks;
    for (int i = counter.Length - 1; i >= 0 && carry != 0; i--)
    {
        ulong sum = counter[i] + (carry & 0xffUL);
        counter[i] = (byte)sum;
        carry = (carry >> 8) + (sum >> 8);
    }

    Assert(carry == 0, "test counter does not overflow");
}

// The release scripts sign and manifest a list of native tools. The
// application refuses to start without a different list. Those two have to be
// the same list, and three times now they were not: Sign-Binaries.ps1,
// Generate-ReleaseManifests.ps1 and Sign-ManagedOutput.ps1 each kept a
// six-or-fewer-entry copy, so the four Crypto++ adapters were built, shipped,
// and never signed.
//
// Nothing downstream catches that on the machine that builds the release. The
// scripts succeed, the binaries are there, and the failure appears only on a
// user's machine as four tools reported missing by the integrity gate - with
// archive operations disabled and no indication why.
//
// So the list now lives in tools\NativeToolTargets.ps1, and this reads it back
// and holds it against IntegrityService.RequiredNativeTools.
// MainWindow.xaml sets a Text on most of its named TextBlocks, and
// ApplyLanguage overwrites nearly all of them from the T() table in the
// constructor. So the XAML string is never seen - and that is the trap: a fix
// applied to the XAML alone changes nothing a user can read, while the diff
// looks exactly like a fix.
//
// It has happened. "Say four factors on the extraction panel" changed
// ExtractPasswordTitle in the XAML on this side; the runtime table still said
// "Password for extraction" and "Passwort zum Entpacken", so the Windows panel
// went on contradicting its own four fields while the commit read as done.
//
// Holding the two equal makes the XAML a truthful preview of the running
// window and gives the next such edit somewhere to fail.
static void RunLocalizationDefaultsTests()
{
    string repositoryRoot = FindRepositoryRootForTest();
    string xamlPath = Path.Combine(repositoryRoot, "KalynaArchiver", "MainWindow.xaml");
    string codePath = Path.Combine(repositoryRoot, "KalynaArchiver", "MainWindow.xaml.cs");
    Assert(File.Exists(xamlPath) && File.Exists(codePath), "MainWindow.xaml and its code-behind exist");

    string xaml = File.ReadAllText(xamlPath);
    string code = File.ReadAllText(codePath);

    var xamlText = new Dictionary<string, string>(StringComparer.Ordinal);
    foreach (System.Text.RegularExpressions.Match element in
             System.Text.RegularExpressions.Regex.Matches(xaml, "<(\\w+)\\b((?:[^<>\"]|\"[^\"]*\")*?)/?>",
                 System.Text.RegularExpressions.RegexOptions.Singleline))
    {
        string attributes = element.Groups[2].Value;
        var name = System.Text.RegularExpressions.Regex.Match(attributes, "x:Name=\"([^\"]+)\"");
        var text = System.Text.RegularExpressions.Regex.Match(attributes, "\\bText=\"([^\"]*)\"");
        if (name.Success && text.Success)
        {
            xamlText[name.Groups[1].Value] = DecodeXamlAttribute(text.Groups[1].Value);
        }
    }

    Assert(xamlText.Count > 40, $"the XAML sweep found only {xamlText.Count} named TextBlocks with a Text; the layout probably moved");

    int applyStart = code.IndexOf("private void ApplyLanguage()", StringComparison.Ordinal);
    int applyEnd = code.IndexOf("private string T(string key)", StringComparison.Ordinal);
    Assert(applyStart >= 0 && applyEnd > applyStart, "ApplyLanguage and the T() table were both found");

    var englishStrings = new Dictionary<string, string>(StringComparer.Ordinal);
    foreach (System.Text.RegularExpressions.Match entry in
             System.Text.RegularExpressions.Regex.Matches(code, "\\(\"en\",\\s*\"([^\"]+)\"\\)\\s*=>\\s*\"((?:[^\"\\\\]|\\\\.)*)\""))
    {
        englishStrings[entry.Groups[1].Value] = DecodeCSharpLiteral(entry.Groups[2].Value);
    }

    // Only the unconditional one-line assignments. The conditional ones - the
    // key sheet and password-policy status lines - pick a string from the
    // control's current state, so their XAML default is the starting state and
    // is meant to differ from any single table entry.
    var mismatches = new List<string>();
    int compared = 0;
    foreach (System.Text.RegularExpressions.Match assignment in
             System.Text.RegularExpressions.Regex.Matches(
                 code[applyStart..applyEnd], @"^\s*(\w+)\.Text = T\(""([^""]+)""\);\s*$",
                 System.Text.RegularExpressions.RegexOptions.Multiline))
    {
        string element = assignment.Groups[1].Value;
        string key = assignment.Groups[2].Value;
        if (!xamlText.TryGetValue(element, out string? designTime)
            || !englishStrings.TryGetValue(key, out string? runtime))
        {
            continue;
        }

        compared++;
        if (!string.Equals(designTime.Trim(), runtime.Trim(), StringComparison.Ordinal))
        {
            mismatches.Add($"{element} [{key}]: XAML \"{designTime}\" vs English \"{runtime}\"");
        }
    }

    Assert(compared > 30, $"only {compared} localized TextBlocks were compared; the match probably broke");
    Assert(
        mismatches.Count == 0,
        "MainWindow.xaml design-time text must equal the English string ApplyLanguage puts there, "
        + "or a fix applied to one of them changes nothing:"
        + Environment.NewLine + string.Join(Environment.NewLine, mismatches));

    // And both arms have to answer for the same keys. The switch ends in
    // `_ => key`, so a key added to one language and not the other does not
    // throw and does not fall back to the other language - it paints the key's
    // own name into the window, in the middle of otherwise ordinary prose.
    // Key sets, not values: an arm may answer with an expression rather than a
    // literal - ProductInfo.Name does, for the window title - and those keys
    // count just the same. Both sides are matched the same lenient way, or the
    // comparison would report every such key as missing from whichever side was
    // read strictly.
    static HashSet<string> KeysOf(string source, string arm)
    {
        var keys = new HashSet<string>(StringComparer.Ordinal);
        foreach (System.Text.RegularExpressions.Match entry in
                 System.Text.RegularExpressions.Regex.Matches(source, "\\(" + arm + ",\\s*\"([^\"]+)\"\\)\\s*=>"))
        {
            keys.Add(entry.Groups[1].Value);
        }

        return keys;
    }

    HashSet<string> englishKeys = KeysOf(code, "\"en\"");
    HashSet<string> germanKeys = KeysOf(code, "_");

    Assert(englishKeys.Count > 100 && germanKeys.Count > 100,
        $"the localization sweep found {englishKeys.Count} English and {germanKeys.Count} German keys; the table probably moved");

    string[] englishOnly = [.. englishKeys.Where(key => !germanKeys.Contains(key)).Order()];
    string[] germanOnly = [.. germanKeys.Where(key => !englishKeys.Contains(key)).Order()];
    Assert(
        englishOnly.Length == 0 && germanOnly.Length == 0,
        $"every localization key needs both arms. English only: [{string.Join(", ", englishOnly)}]. "
        + $"German only: [{string.Join(", ", germanOnly)}].");
}

static string DecodeXamlAttribute(string value)
{
    return value
        .Replace("&#10;", "\n", StringComparison.Ordinal)
        .Replace("&quot;", "\"", StringComparison.Ordinal)
        .Replace("&lt;", "<", StringComparison.Ordinal)
        .Replace("&gt;", ">", StringComparison.Ordinal)
        .Replace("&amp;", "&", StringComparison.Ordinal);
}

static string DecodeCSharpLiteral(string value)
{
    return value
        .Replace("\\\"", "\"", StringComparison.Ordinal)
        .Replace("\\n", "\n", StringComparison.Ordinal)
        .Replace("\\\\", "\\", StringComparison.Ordinal);
}

static void RunReleaseScriptToolCoverageTests()
{
    string repositoryRoot = FindRepositoryRootForTest();
    string listScript = Path.Combine(repositoryRoot, "tools", "NativeToolTargets.ps1");
    Assert(File.Exists(listScript), $"the shared native-tool list script exists at {listScript}");

    string text = File.ReadAllText(listScript);
    int bodyStart = text.IndexOf("function Get-NativeToolNames", StringComparison.Ordinal);
    Assert(bodyStart >= 0, "NativeToolTargets.ps1 declares Get-NativeToolNames");
    int bodyEnd = text.IndexOf("function Get-NativeToolTargets", StringComparison.Ordinal);
    Assert(bodyEnd > bodyStart, "NativeToolTargets.ps1 declares Get-NativeToolTargets after Get-NativeToolNames");

    string[] scriptNames = System.Text.RegularExpressions.Regex
        .Matches(text[bodyStart..bodyEnd], "\"([A-Za-z0-9_]+\\.(?:dll|exe))\"")
        .Select(match => match.Groups[1].Value)
        .ToArray();

    string[] required = [.. IntegrityService.RequiredNativeTools];
    Assert(
        scriptNames.SequenceEqual(required, StringComparer.Ordinal),
        "tools\\NativeToolTargets.ps1 lists exactly IntegrityService.RequiredNativeTools, in the same order. "
        + $"Script: [{string.Join(", ", scriptNames)}]. Required: [{string.Join(", ", required)}].");

    // Each script has to take its targets from the shared list rather than
    // build one. Asserted by what it calls, not by whether a tool name appears
    // anywhere in the file: Sign-Binaries.ps1 legitimately names
    // threefish_ref.dll once more as the Skein-1024 provider it computes the
    // signer fingerprint with, which is a dependency, not a target.
    foreach (string scriptName in new[] { "Sign-Binaries.ps1", "Generate-ReleaseManifests.ps1", "Sign-ManagedOutput.ps1" })
    {
        string path = Path.Combine(repositoryRoot, "tools", scriptName);
        Assert(File.Exists(path), $"{scriptName} exists");
        string script = File.ReadAllText(path);
        Assert(
            script.Contains("NativeToolTargets.ps1", StringComparison.Ordinal),
            $"{scriptName} dot-sources the shared native-tool list");
        Assert(
            script.Contains("Get-NativeToolTargets", StringComparison.Ordinal)
            || script.Contains("Get-NativeToolNames", StringComparison.Ordinal),
            $"{scriptName} takes its native targets from the shared list");
    }

    // The portable-release verifier is the fourth place this list was copied
    // to. It required five native binaries while the application required
    // nine, so a portable build without the four Crypto++ adapters verified
    // clean and then refused to open an archive.
    string verifierPath = Path.Combine(repositoryRoot, "KalynaReleaseVerifier", "Program.cs");
    Assert(File.Exists(verifierPath), "the portable release verifier exists");
    string verifier = File.ReadAllText(verifierPath);
    Assert(
        verifier.Contains("IntegrityService.RequiredNativeTools", StringComparison.Ordinal),
        "the portable release verifier requires the application's native tool set rather than a copy of it");

    string portableBuilderPath = Path.Combine(repositoryRoot, "tools", "Build-Portable.ps1");
    string portableBuilder = File.ReadAllText(portableBuilderPath);
    foreach (string forbiddenClaim in new[]
    {
        "Encrypted containers use format 7",
        "encrypted version-7",
        "two independent generated 512-bit hexadecimal factors",
        "five evenly filled mouse pools",
    })
    {
        Assert(
            !portableBuilder.Contains(forbiddenClaim, StringComparison.OrdinalIgnoreCase),
            $"the generated Windows portable README no longer publishes the legacy claim: {forbiddenClaim}");
    }

    foreach (string requiredClaim in new[]
    {
        "format v12 only",
        "ten production suites",
        "6-16 digit PIN",
        "1024-bit hexadecimal",
        "nine evenly filled mouse pools",
        "PMI16",
        "KPAR2 v4 with ContainerVersion 12",
    })
    {
        Assert(
            portableBuilder.Contains(requiredClaim, StringComparison.OrdinalIgnoreCase),
            $"the generated Windows portable README states the v12 invariant: {requiredClaim}");
    }

    Assert(
        portableBuilder.Contains("Build-QrScanner-Windows.ps1", StringComparison.Ordinal)
        && portableBuilder.Contains("QR-Scanner.exe", StringComparison.Ordinal)
        && portableBuilder.Contains("-Recurse -File", StringComparison.Ordinal),
        "the Windows portable release builds, packages, and recursively signs the separate QR-Scanner companion");
}

// The check that vouches for the QR scanner.
//
// The scanner reads both secret factors off the printed sheets and cannot
// vouch for itself - an app that verifies its own signature proves nothing to
// anyone who has already replaced it. Keep Vault checks it instead, and until
// now nothing checked that check. macOS has had TestCompanionScannerAsync for a
// while; this is the Windows half.
//
// It does not need a scanner to be installed, which is the difference from the
// macOS test: any hybrid-signed artifact will do as a stand-in, because the
// signature covers the file's bytes and not its name. That makes the negative
// cases - no signature, a signature belonging to a different file, a corrupted
// one - reachable on a plain development tree.
static void RunCompanionScannerVerificationTests()
{
    string scannerDirectory = Path.Combine(AppContext.BaseDirectory, "QR-Scanner");
    string scanner = Path.Combine(scannerDirectory, "QR-Scanner.exe");
    string sidecar = scanner + HybridSignatureService.SidecarExtension;

    Assert(!File.Exists(scanner), "the test starts without a scanner in the way");
    CompanionVerificationResult absent = WindowsCompanionVerification.VerifyQrScanner();
    Assert(!absent.Found && !absent.Trusted, "a missing scanner is reported absent and never trusted");

    string signedArtifact = NativeToolIntegrity.ResolveKnownTool("zpaq.exe")
        ?? throw new InvalidOperationException("zpaq.exe is unavailable as a signed stand-in.");
    string signedSidecar = signedArtifact + HybridSignatureService.SidecarExtension;
    Assert(File.Exists(signedSidecar), "the stand-in artifact carries a hybrid signature");

    Directory.CreateDirectory(scannerDirectory);
    try
    {
        // Present, but with nothing to check it against.
        File.Copy(signedArtifact, scanner);
        CompanionVerificationResult unsigned = WindowsCompanionVerification.VerifyQrScanner();
        Assert(
            unsigned.Found && !unsigned.Trusted,
            $"a scanner without a detached signature is found but not trusted: {unsigned.Message}");

        // A real signature that belongs to a different payload. This is the
        // case that decides whether the check binds a signature to the bytes it
        // covers or merely to a filename beside it.
        string otherArtifact = NativeToolIntegrity.ResolveKnownTool("kalyna_v12.dll")
            ?? throw new InvalidOperationException("kalyna_v12.dll is unavailable as a mismatched payload.");
        File.Delete(scanner);
        File.Copy(otherArtifact, scanner);
        File.Copy(signedSidecar, sidecar);
        CompanionVerificationResult mismatched = WindowsCompanionVerification.VerifyQrScanner();
        Assert(
            mismatched.Found && !mismatched.Trusted,
            "a signature belonging to a different file must not vouch for the scanner");

        // The matching pair: same bytes, its own signature.
        File.Delete(scanner);
        File.Copy(signedArtifact, scanner);
        CompanionVerificationResult trusted = WindowsCompanionVerification.VerifyQrScanner();
        Assert(
            trusted.Found && trusted.Trusted,
            $"a correctly signed scanner is trusted: {trusted.Message}");

        // A normal .NET publish signs only the native apphost while executing
        // the adjacent managed DLL. That layout must not be vouched for even
        // when the apphost itself has a perfectly valid signature.
        string externalApplicationPart = Path.Combine(scannerDirectory, "QR-Scanner.dll");
        File.WriteAllBytes(externalApplicationPart, [0x4D, 0x5A]);
        CompanionVerificationResult openPublish = WindowsCompanionVerification.VerifyQrScanner();
        Assert(
            openPublish.Found && !openPublish.Trusted,
            "a signed apphost with unsigned external scanner code is refused");
        File.Delete(externalApplicationPart);

        // And a single flipped bit in the signature is refused.
        byte[] signature = File.ReadAllBytes(sidecar);
        byte[] corrupted = [.. signature];
        corrupted[^64] ^= 0xFF;
        File.WriteAllBytes(sidecar, corrupted);
        CompanionVerificationResult tampered = WindowsCompanionVerification.VerifyQrScanner();
        Assert(
            tampered.Found && !tampered.Trusted,
            "a corrupted scanner signature is refused");

        // As is a flipped bit in the payload, against an untouched signature.
        File.WriteAllBytes(sidecar, signature);
        byte[] payload = File.ReadAllBytes(scanner);
        payload[payload.Length / 2] ^= 0x01;
        File.WriteAllBytes(scanner, payload);
        CompanionVerificationResult patched = WindowsCompanionVerification.VerifyQrScanner();
        Assert(
            patched.Found && !patched.Trusted,
            "a modified scanner binary is refused against its unchanged signature");
    }
    finally
    {
        DeleteTestDirectory(scannerDirectory);
    }
}

// Removes a test's temporary tree, retrying briefly.
//
// Teardown only: every assertion a test makes about cleanup has already run by
// the time this is called, so retrying here weakens nothing. What it absorbs is
// Windows finishing with a directory after the code that owned it has returned
// - a killed child process whose working directory was the staging tree keeps
// the entry alive until the last handle closes, and a directory in that state
// is still enumerable and still refuses to be removed.
//
// It showed up the moment the suite began running its groups beside each other:
// as a script this raced nothing and won every time. The same retry, for the
// same reason, is in ZpaqService.TryDeletePrivateTree.
static void DeleteTestDirectory(string path)
{
    for (int attempt = 0; ; attempt++)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }

            return;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            if (attempt >= 9)
            {
                throw;
            }

            Thread.Sleep(50 * (attempt + 1));
        }
    }
}

static string FindRepositoryRootForTest()
{
    // Accepts .git as either a directory or a file: in a git worktree it is a
    // file pointing at the real git directory, and a directory-only check walks
    // past the worktree to whatever repository contains it.
    for (string? path = AppContext.BaseDirectory; path is not null; path = Path.GetDirectoryName(path))
    {
        string marker = Path.Combine(path, ".git");
        if (Directory.Exists(marker) || File.Exists(marker))
        {
            return path;
        }
    }

    throw new DirectoryNotFoundException("The Keep Vault repository root could not be located from the test binary.");
}

static void RunNativeIntegrityTests()
{
    // The set the application refuses to run without, not a copy of it. This
    // list used to be five hand-written names, so when the four Crypto++
    // adapters arrived the suite kept passing while aes_ref.dll,
    // mars_ref.dll, shacal2_ref.dll and chachapoly_ref.dll shipped unsigned
    // and unmanifested - which is the one thing this test exists to catch.
    IReadOnlyList<string> nativeTools = IntegrityService.RequiredNativeTools;
    Assert(nativeTools.Count >= 9, $"the required native tool set has shrunk to {nativeTools.Count} entries");
    foreach (string tool in nativeTools)
    {
        string path = NativeToolIntegrity.ResolveKnownTool(tool)
            ?? throw new InvalidOperationException($"{tool} is not available from the application tools directory.");
        Assert(File.Exists(path), $"{tool} exists");
        Assert(File.Exists(path + ".sha3"), $"{tool} SHA3-512 manifest exists");
        Assert(File.Exists(path + ".skein"), $"{tool} Skein-1024 manifest exists");
        Assert(File.Exists(path + ".khsig"), $"{tool} hybrid RSA/ML-DSA target signature exists");
        Assert(File.Exists(path + ".sha3.khsig"), $"{tool} SHA3-512 manifest has a hybrid signature");
        Assert(File.Exists(path + ".skein.khsig"), $"{tool} Skein-1024 manifest has a hybrid signature");
        ToolIntegrityStatus status = IntegrityService.CheckFile(path, requireManifest: true);
        Assert(status.HashMatches, $"{tool} SHA3-512/Skein-1024 dual manifest matches");
        Assert(status.ExpectedSha3_512 is { Length: 128 }, $"{tool} SHA3-512 manifest length");
        Assert(status.ExpectedSkein1024 is { Length: 256 }, $"{tool} Skein-1024 manifest length");
        Assert(status.ActualSha512 is { Length: 128 }, $"{tool} SHA-512 hybrid artifact digest length");
        Assert(status.HybridSignatureMatches, $"{tool} RSA-PSS/SHA-512 and ML-DSA-87 signatures match: {status.HybridSignatureMessage}");
        Assert(status.SignerSha256 is { Length: 64 }, $"{tool} RSA SPKI SHA-256 pin length");
        Assert(
            IntegrityService.IsAcceptedSignatureState(status.SignatureState),
            $"{tool} Authenticode signature is trusted or exactly pinned for development: {status.SignatureMessage}");
        Assert(
            SigningTrustPolicy.Matches(status.SignerSha256, status.SignerSha3_512, status.SignerSkein1024),
            $"{tool} signer matches SHA-256/SHA3-512/Skein-1024 SPKI pins");
        Assert(status.IsTrusted, $"{tool} satisfies the complete native-tool trust policy");
        Assert(
            !SigningTrustPolicy.Matches(new string('0', 64), status.SignerSha3_512, status.SignerSkein1024),
            $"{tool} signer is rejected when only its SHA-256 SPKI pin differs");
        Assert(
            !SigningTrustPolicy.Matches(status.SignerSha256, new string('0', 128), status.SignerSkein1024),
            $"{tool} signer is rejected when only its SHA3-512 SPKI pin differs");
        Assert(
            !SigningTrustPolicy.Matches(status.SignerSha256, status.SignerSha3_512, new string('0', 256)),
            $"{tool} signer is rejected when only its Skein-1024 SPKI pin differs");
    }

    string lockedTool = NativeToolIntegrity.ResolveKnownTool("zpaq.exe")
        ?? throw new InvalidOperationException("zpaq.exe is not available from the application tools directory.");
    using (TrustedNativeFileLease lease = NativeToolIntegrity.AcquireTrustedFile(lockedTool))
    {
        Assert(
            string.Equals(Path.GetFullPath(lease.Path), Path.GetFullPath(lockedTool), StringComparison.OrdinalIgnoreCase),
            "trusted native-tool lease is bound to the final handle-resolved DOS path");
        bool writeWasDenied = false;
        try
        {
            using var writeAttempt = new FileStream(lockedTool, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
        }
        catch (IOException)
        {
            writeWasDenied = true;
        }

        Assert(writeWasDenied, "trusted native-tool lease prevents replacement while it is verified and launched");
    }

    string symlinkTool = Path.Combine(AppContext.BaseDirectory, $"native-symlink-{Guid.NewGuid():N}.exe");
    bool symlinkCreated = false;
    try
    {
        File.CreateSymbolicLink(symlinkTool, lockedTool);
        symlinkCreated = true;
    }
    catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or PlatformNotSupportedException)
    {
        // Windows without Developer Mode may forbid unprivileged file symlink creation.
    }

    try
    {
        if (symlinkCreated)
        {
            AssertThrows<InvalidOperationException>(
                () =>
                {
                    using TrustedNativeFileLease _ = NativeToolIntegrity.AcquireTrustedFile(symlinkTool);
                },
                "native-tool symlink alias is rejected before loading");
            AssertThrows<InvalidOperationException>(
                () => IntegrityService.CheckFile(symlinkTool, requireManifest: true),
                "integrity-status path rejects a symlink alias instead of combining hashes and a separate Authenticode target");
        }
    }
    finally
    {
        File.Delete(symlinkTool);
    }

    string incompleteDualManifestTool = Path.Combine(Path.GetTempPath(), $"dual-manifest-{Guid.NewGuid():N}.exe");
    try
    {
        File.Copy(lockedTool, incompleteDualManifestTool);
        File.Copy(lockedTool + ".sha3", incompleteDualManifestTool + ".sha3");
        ToolIntegrityStatus missingSkein = IntegrityService.CheckFile(incompleteDualManifestTool, requireManifest: true);
        Assert(!missingSkein.HashMatches && missingSkein.ExpectedSkein1024 is null, "missing Skein-1024 half blocks an otherwise valid signed binary");

        File.Copy(lockedTool + ".skein", incompleteDualManifestTool + ".skein");
        string skeinText = File.ReadAllText(incompleteDualManifestTool + ".skein");
        char replacement = skeinText[0] == '0' ? '1' : '0';
        File.WriteAllText(incompleteDualManifestTool + ".skein", replacement + skeinText[1..]);
        ToolIntegrityStatus wrongSkein = IntegrityService.CheckFile(incompleteDualManifestTool, requireManifest: true);
        Assert(!wrongSkein.HashMatches, "wrong Skein-1024 half blocks an otherwise valid signed binary");
    }
    finally
    {
        File.Delete(incompleteDualManifestTool);
        File.Delete(incompleteDualManifestTool + ".sha3");
        File.Delete(incompleteDualManifestTool + ".skein");
    }

    string unsignedTool = Path.Combine(AppContext.BaseDirectory, $"unsigned-native-{Guid.NewGuid():N}.exe");
    try
    {
        File.WriteAllBytes(unsignedTool, RandomNumberGenerator.GetBytes(512));
        byte[] fileBytes = File.ReadAllBytes(unsignedTool);
        byte[] digest = SHA3_512.HashData(fileBytes);
        byte[] skein = Skein1024Digest.HashData(fileBytes);
        try
        {
            File.WriteAllText(unsignedTool + ".sha3", Convert.ToHexString(digest));
            File.WriteAllText(unsignedTool + ".skein", Convert.ToHexString(skein));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileBytes);
            CryptographicOperations.ZeroMemory(digest);
            CryptographicOperations.ZeroMemory(skein);
        }

        bool rejectedUnsignedTool = false;
        try
        {
            using TrustedNativeFileLease rejected = NativeToolIntegrity.AcquireTrustedFile(unsignedTool);
        }
        catch (InvalidOperationException)
        {
            rejectedUnsignedTool = true;
        }

        Assert(rejectedUnsignedTool, "unsigned native tool with matching dual manifests is blocked");
    }
    finally
    {
        File.Delete(unsignedTool);
        File.Delete(unsignedTool + ".sha3");
        File.Delete(unsignedTool + ".skein");
    }

    Assert(NativeArgon2id.IsAvailable(), "native PHC Argon2id DLL is available and manifest-verified");
}

static void RunProcessHardeningTests()
{
    ProcessHardeningStatus status = ProcessHardening.Apply();
    Assert(
        status.ErrorModeSet
        || status.WerFlagsSet
        || status.StrictHandlePolicySet
        || status.ExtensionPointsDisabled
        || status.ImageLoadPolicySet
        || status.DllSearchRestricted,
        "at least one process hardening measure was accepted");
}

static async Task RunZpaqTraversalTestsAsync()
{
    string root = Path.Combine(Path.GetTempPath(), $"zpaq-traversal-test-{Guid.NewGuid():N}");
    string buildRoot = Path.Combine(root, "build");
    string buildSubdirectory = Path.Combine(buildRoot, "sub");
    string extractDirectory = Path.Combine(root, "extract");
    string escapedPath = Path.Combine(root, "payload.txt");
    Directory.CreateDirectory(buildSubdirectory);

    try
    {
        await File.WriteAllTextAsync(Path.Combine(buildRoot, "payload.txt"), "must stay inside archive build area");
        string executable = NativeToolIntegrity.ResolveKnownTool("zpaq.exe")
            ?? throw new InvalidOperationException("zpaq.exe is unavailable for traversal test");
        ProcessResult add = await RunToolInDirectoryAsync(
            executable,
            ["add", "evil.zpaq", "../payload.txt", "-m0"],
            buildSubdirectory);
        Assert(add.Succeeded, $"construct malicious traversal archive: {add.StandardError}");
        string archive = Path.Combine(buildSubdirectory, "evil.zpaq");
        Assert(File.Exists(archive), "malicious traversal test archive exists");
        await new ArchiveIntegrityService().CreateAsync(archive, CancellationToken.None);

        var zpaq = new ZpaqService();
        string validInput = Path.Combine(buildRoot, "payload.txt");
        await AssertThrowsAsync<ArgumentOutOfRangeException>(
            () => zpaq.AddAsync(Path.Combine(root, "invalid-compression.zpaq"), [validInput], 6, null, CancellationToken.None),
            "plain ZPAQ service rejects compression levels above 5");
        await AssertThrowsAsync<ArgumentOutOfRangeException>(
            () => zpaq.AddStreamingAsync([validInput], -1, (_, _) => Task.CompletedTask, null, CancellationToken.None),
            "streaming ZPAQ service rejects negative compression levels");
        // The cross-volume rule runs after the existence check, so a path on a
        // drive letter that is not mounted never reaches it. Exercising the rule
        // needs a genuine second volume; a machine with only one is skipped
        // rather than asserted against a check that cannot fire.
        string validVolume = Path.GetPathRoot(Path.GetFullPath(validInput)) ?? string.Empty;
        string? alternateVolume = DriveInfo.GetDrives()
            .Where(drive => drive.IsReady && drive.DriveType == DriveType.Fixed)
            .Select(drive => drive.RootDirectory.FullName)
            .FirstOrDefault(volume => !string.Equals(volume, validVolume, StringComparison.OrdinalIgnoreCase));
        if (alternateVolume is not null)
        {
            string crossVolumeDirectory = Path.Combine(alternateVolume, $"kalyna-cross-volume-{Guid.NewGuid():N}");
            bool crossVolumeReady;
            try
            {
                Directory.CreateDirectory(crossVolumeDirectory);
                crossVolumeReady = true;
            }
            catch (Exception exception) when (exception is UnauthorizedAccessException or IOException)
            {
                crossVolumeReady = false;
            }

            if (crossVolumeReady)
            {
                try
                {
                    string alternateVolumeInput = Path.Combine(crossVolumeDirectory, "kalyna-cross-volume-input.txt");
                    await File.WriteAllTextAsync(alternateVolumeInput, "input on a second volume");
                    await AssertThrowsAsync<ArgumentException>(
                        () => zpaq.AddStreamingAsync([validInput, alternateVolumeInput], 1, (_, _) => Task.CompletedTask, null, CancellationToken.None),
                        "ZPAQ rejects cross-volume inputs instead of storing absolute archive member names");
                }
                finally
                {
                    Directory.Delete(crossVolumeDirectory, recursive: true);
                }
            }
        }
        await AssertThrowsAsync<ArgumentException>(
            () => zpaq.AddAsync(validInput, [validInput], 1, null, CancellationToken.None),
            "ZPAQ rejects an archive target that is also an input file");
        string existingTarget = Path.Combine(root, "existing-target.zpaq");
        await File.WriteAllTextAsync(existingTarget, "must remain untouched");
        await AssertThrowsAsync<IOException>(
            () => zpaq.AddAsync(existingTarget, [validInput], 1, null, CancellationToken.None),
            "ZPAQ refuses an existing output instead of updating or replacing it");
        Assert(
            await File.ReadAllTextAsync(existingTarget) == "must remain untouched",
            "existing ZPAQ output remains byte-for-byte untouched");
        await AssertThrowsAsync<ArgumentException>(
            () => zpaq.AddAsync(Path.Combine(buildRoot, "nested-output.zpaq"), [buildRoot], 1, null, CancellationToken.None),
            "ZPAQ rejects an archive target located inside an input directory");
        await AssertThrowsAsync<FileNotFoundException>(
            () => zpaq.AddStreamingAsync([Path.Combine(buildRoot, "missing-input.bin")], 1, (_, _) => Task.CompletedTask, null, CancellationToken.None),
            "ZPAQ rejects missing inputs before launching its native parser");
        ProcessResult extract = await zpaq.ExtractAsync(archive, extractDirectory, null, CancellationToken.None);
        Assert(!extract.Succeeded, "unsafe traversal member is rejected during extraction");
        Assert(extract.StandardError.Contains("unsafe archive member path", StringComparison.OrdinalIgnoreCase), "ZPAQ reports the unsafe member path");
        Assert(!File.Exists(escapedPath), "unsafe traversal member cannot write outside extraction root");
        Assert(!Directory.Exists(extractDirectory), "failed unsafe extraction removes its partial output directory");
        Assert(!Directory.EnumerateDirectories(root, "*.extract-part", SearchOption.TopDirectoryOnly).Any(), "failed unsafe extraction removes its hidden staging directory");

        string nonEmptyTarget = Path.Combine(root, "non-empty");
        Directory.CreateDirectory(nonEmptyTarget);
        await File.WriteAllTextAsync(Path.Combine(nonEmptyTarget, "keep.txt"), "keep");
        await AssertThrowsAsync<InvalidOperationException>(
            () => zpaq.ExtractAsync(archive, nonEmptyTarget, null, CancellationToken.None),
            "non-empty extraction targets are rejected before starting ZPAQ");

        string adsInput = Path.Combine(root, "ads-input.txt");
        string adsArchive = Path.Combine(root, "ads.zpaq");
        string adsOutput = Path.Combine(root, "ads-output");
        await File.WriteAllTextAsync(adsInput, "visible data");
        bool adsSupported;
        try
        {
            await File.WriteAllTextAsync(adsInput + ":hidden", "hidden stream must not enter the archive");
            adsSupported = true;
        }
        catch (IOException)
        {
            adsSupported = false;
        }

        if (adsSupported)
        {
            ProcessResult adsAdd = await zpaq.AddAsync(adsArchive, [adsInput], 0, null, CancellationToken.None);
            Assert(adsAdd.Succeeded, "ZPAQ creation remains valid when an input has an NTFS alternate stream");
            ProcessResult adsExtract = await zpaq.ExtractAsync(adsArchive, adsOutput, null, CancellationToken.None);
            Assert(adsExtract.Succeeded, "archive omitting NTFS alternate streams remains extractable");
            string extractedVisible = Path.Combine(adsOutput, Path.GetFileName(adsInput));
            Assert(await File.ReadAllTextAsync(extractedVisible) == "visible data", "primary NTFS stream roundtrips");
            Assert(!File.Exists(extractedVisible + ":hidden"), "hidden NTFS stream is not recreated during extraction");
        }
    }
    finally
    {
        DeleteTestDirectory(root);
    }
}

/// <summary>
/// The Windows input-binding matrix: what the security check validated has to
/// be exactly what native ZPAQ later reads, for the whole operation.
/// </summary>
/// <remarks>
/// Every adversarial case here used to be invisible to the old design, which
/// leased the files a path walk found and then handed the original directory
/// paths to ZPAQ so it could walk the live namespace a second time.
/// </remarks>
static async Task RunZpaqInputBindingTestsAsync()
{
    string root = Path.Combine(Path.GetTempPath(), $"kalyna-zpaq-binding-{Guid.NewGuid():N}");
    Directory.CreateDirectory(root);
    try
    {
        string outside = Path.Combine(root, "outside");
        Directory.CreateDirectory(outside);
        await File.WriteAllTextAsync(Path.Combine(outside, "secret.txt"), "must never enter an archive");

        string tree = Path.Combine(root, "tree");
        string nested = Path.Combine(tree, "nested");
        string empty = Path.Combine(tree, "empty");
        Directory.CreateDirectory(nested);
        Directory.CreateDirectory(empty);
        await File.WriteAllTextAsync(Path.Combine(tree, "a.txt"), "alpha");
        await File.WriteAllTextAsync(Path.Combine(nested, "b.txt"), "beta");

        // 1 + 2: an ordinary file and an ordinary tree still archive, and an
        // empty directory still survives the private mirror.
        var zpaq = new ZpaqService();
        string fileArchive = Path.Combine(root, "single.zpaq");
        ProcessResult single = await zpaq.AddAsync(fileArchive, [Path.Combine(tree, "a.txt")], 0, null, CancellationToken.None);
        Assert(single.Succeeded, $"a single regular file archives through the bound snapshot: {single.StandardError}");

        string treeArchive = Path.Combine(root, "tree.zpaq");
        ProcessResult treeAdd = await zpaq.AddAsync(treeArchive, [tree], 0, null, CancellationToken.None);
        Assert(treeAdd.Succeeded, $"a regular directory tree archives through the bound snapshot: {treeAdd.StandardError}");
        string treeOutput = Path.Combine(root, "tree-out");
        ProcessResult treeExtract = await zpaq.ExtractAsync(treeArchive, treeOutput, null, CancellationToken.None);
        Assert(treeExtract.Succeeded, "the bound snapshot produces an extractable archive");
        Assert(
            await File.ReadAllTextAsync(Path.Combine(treeOutput, "tree", "a.txt")) == "alpha"
            && await File.ReadAllTextAsync(Path.Combine(treeOutput, "tree", "nested", "b.txt")) == "beta",
            "archive member names and contents are unchanged by the private mirror");
        Assert(
            Directory.Exists(Path.Combine(treeOutput, "tree", "empty")),
            "an empty input directory is preserved by the private mirror");

        // 11: a hard link is an ordinary file object and must archive normally.
        string hardLink = Path.Combine(tree, "hardlink.txt");
        if (TryCreateHardLinkForTests(hardLink, Path.Combine(tree, "a.txt")))
        {
            string linkArchive = Path.Combine(root, "hardlink.zpaq");
            ProcessResult linkAdd = await zpaq.AddAsync(linkArchive, [hardLink], 0, null, CancellationToken.None);
            Assert(linkAdd.Succeeded, $"a hard-linked input archives normally: {linkAdd.StandardError}");
            File.Delete(hardLink);
        }

        // 3 + 4 + 5: reparse points are refused as the selected root, as an
        // ancestor of the selected root, and anywhere inside the tree.
        string junctionRoot = Path.Combine(root, "junction-root");
        if (TryCreateJunctionForTests(junctionRoot, tree))
        {
            await AssertThrowsAsync<IOException>(
                () => zpaq.AddAsync(Path.Combine(root, "junction-root.zpaq"), [junctionRoot], 0, null, CancellationToken.None),
                "a junction selected as the input root is refused");

            string throughJunction = Path.Combine(junctionRoot, "nested");
            await AssertThrowsAsync<IOException>(
                () => zpaq.AddAsync(Path.Combine(root, "junction-ancestor.zpaq"), [throughJunction], 0, null, CancellationToken.None),
                "an input reached through a junction ancestor is refused");

            Directory.Delete(junctionRoot);
        }

        string nestedJunction = Path.Combine(nested, "escape");
        if (TryCreateJunctionForTests(nestedJunction, outside))
        {
            await AssertThrowsAsync<IOException>(
                () => zpaq.AddAsync(Path.Combine(root, "nested-junction.zpaq"), [tree], 0, null, CancellationToken.None),
                "a junction nested inside the input tree is refused before ZPAQ starts");
            Directory.Delete(nestedJunction);
        }

        // 6 + 7 + 8 + 9 + 10: everything that changes after the snapshot was
        // taken must be invisible to the archive, and the leased objects must
        // not be replaceable while the snapshot is alive.
        using (IDisposable snapshot = ZpaqService.CaptureInputSnapshotForTests(
            Path.GetDirectoryName(tree)!,
            [tree],
            out string snapshotWorkingDirectory,
            out string[] snapshotPaths))
        {
            Assert(snapshotPaths.Length == 1, "one selected directory produces one mirrored input");
            Assert(
                !string.Equals(snapshotWorkingDirectory, root, StringComparison.OrdinalIgnoreCase)
                && snapshotPaths[0].StartsWith(snapshotWorkingDirectory, StringComparison.OrdinalIgnoreCase),
                "the mirror is private and never the live input tree");

            string lateJunction = Path.Combine(nested, "late-escape");
            bool lateJunctionCreated = TryCreateJunctionForTests(lateJunction, outside);
            string lateFile = Path.Combine(nested, "late.txt");
            await File.WriteAllTextAsync(lateFile, "appeared after the security check");

            string[] mirrored = Directory.GetFileSystemEntries(snapshotPaths[0], "*", SearchOption.AllDirectories);
            Assert(
                !mirrored.Any(entry => entry.EndsWith("late.txt", StringComparison.OrdinalIgnoreCase)),
                "a file created after the security check cannot reach the archived set");
            Assert(
                !mirrored.Any(entry => entry.EndsWith("late-escape", StringComparison.OrdinalIgnoreCase)),
                "a junction inserted after the security check cannot reach the archived set");
            Assert(
                mirrored.All(entry => (File.GetAttributes(entry) & FileAttributes.ReparsePoint) == 0),
                "the private mirror contains no reparse point at all");
            Assert(
                await File.ReadAllTextAsync(Path.Combine(snapshotPaths[0], "a.txt")) == "alpha",
                "the mirror holds the verified file contents");

            // The lease is held FileShare.Read | FileShare.Delete, and on Windows
            // the delete share also permits a rename. The guarantee the snapshot
            // actually provides is therefore bound to the file record, not to its
            // name: the mirror is a hard link, so renaming the original cannot
            // change a single byte of what gets archived.
            string renamedInput = Path.Combine(tree, "renamed.txt");
            File.Move(Path.Combine(tree, "a.txt"), renamedInput);
            try
            {
                Assert(
                    await File.ReadAllTextAsync(Path.Combine(snapshotPaths[0], "a.txt")) == "alpha",
                    "renaming a leased input cannot change what the snapshot archives");
            }
            finally
            {
                File.Move(renamedInput, Path.Combine(tree, "a.txt"));
            }
            AssertThrows<IOException>(
                () => File.WriteAllText(Path.Combine(tree, "a.txt"), "overwritten"),
                "a leased input file cannot be rewritten while the snapshot is alive");

            if (lateJunctionCreated)
            {
                Directory.Delete(lateJunction);
            }

            File.Delete(lateFile);
        }

        // The snapshot has been disposed. Its hard links name the same records
        // as the user's files, so a cleanup that quietly failed would have left
        // writable second names behind; the leases are then deliberately kept
        // open rather than released, and this counter is what says so.
        Assert(
            ZpaqService.RetainedInputSnapshotLeases == 0,
            "the private mirror is gone and no lease had to be retained to keep an input protected");
    }
    finally
    {
        // This tree holds junctions and leased handles. A teardown that throws
        // would replace the exception a failing assertion is trying to report,
        // so cleanup trouble is reported and not allowed to mask the result.
        try
        {
            DeleteTestDirectory(root);
        }
        catch (Exception cleanupFailure) when (cleanupFailure is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"Cleanup of {root} failed: {cleanupFailure.Message}");
        }
    }
}

static void RunObjectBoundReadTests()
{
    // The recovery sidecar and the archive are opened through
    // SecureFile.OpenReadNoReparse so that the bytes that get parsed come from
    // the object the name resolved to. Before that, both used a plain
    // FileStream, which follows a junction or a symbolic link planted under the
    // expected name without a word. macOS had the no-follow open all along;
    // these cases pin the Windows side of the same guarantee.
    string root = Path.Combine(Path.GetTempPath(), "keep-vault-object-bound-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(root);
    try
    {
        string real = Path.Combine(root, "payload.bin");
        byte[] payload = RandomNumberGenerator.GetBytes(4096);
        File.WriteAllBytes(real, payload);

        using (FileStream stream = SecureFile.OpenReadNoReparse(real, FileShare.Read))
        {
            byte[] read = new byte[payload.Length];
            stream.ReadExactly(read);
            Assert(
                CryptographicOperations.FixedTimeEquals(payload, read),
                "a plain single-link file reads back byte-for-byte through the object-bound open");
        }

        // A second name for the same record must be refused wherever the file
        // is about to be destroyed - otherwise the bytes outlive the deletion.
        string hardLink = Path.Combine(root, "second-name.bin");
        if (TryCreateHardLinkForTests(hardLink, real))
        {
            AssertThrows<IOException>(
                () => SecureFile.RequireReadableRegularFile(real, requireSingleLink: true),
                "a file with two hard links is refused where a single link is required");
            using (FileStream tolerated = SecureFile.OpenReadNoReparse(hardLink, FileShare.Read))
            {
                Assert(tolerated.Length == payload.Length, "a hard link still opens where multiple links are allowed");
            }

            File.Delete(hardLink);
        }

        // Reading "through" a junction resolves to a different final path than
        // the one that was asked for, which is exactly the substitution the
        // canonical-path check exists to catch.
        string realDirectory = Path.Combine(root, "real-dir");
        Directory.CreateDirectory(realDirectory);
        string inside = Path.Combine(realDirectory, "inside.bin");
        File.WriteAllBytes(inside, payload);
        string junction = Path.Combine(root, "junction");
        if (TryCreateJunctionForTests(junction, realDirectory))
        {
            AssertThrows<InvalidOperationException>(
                () => SecureFile.RequireReadableRegularFile(
                    Path.Combine(junction, "inside.bin"),
                    requireSingleLink: false),
                "a file reached through a junction is refused by the object-bound open");
            Directory.Delete(junction);
        }

        AssertThrows<IOException>(
            () => SecureFile.RequireReadableRegularFile(realDirectory, requireSingleLink: false),
            "a directory is refused where a regular file is required");

        string boundTemporary = Path.Combine(root, ".bound-file.part");
        string boundDestination = Path.Combine(root, "bound-file.bin");
        using (BoundFileTransaction transaction = BoundFileTransaction.CreateNew(
                   boundTemporary,
                   bufferSize: 4096,
                   FileOptions.Asynchronous | FileOptions.WriteThrough))
        {
            transaction.Stream.Write(payload);
            transaction.Stream.Flush(flushToDisk: true);
            AssertThrows<IOException>(
                () => File.Open(boundTemporary, FileMode.Open, FileAccess.Write, FileShare.None).Dispose(),
                "a bound temporary file cannot be replaced or opened for writing before commit");
            transaction.RenameTo(boundDestination, overwrite: false);
            Assert(
                !File.Exists(boundTemporary) && File.Exists(boundDestination),
                "handle-bound rename installs the exact temporary file under its final name");
        }
        Assert(
            CryptographicOperations.FixedTimeEquals(payload, File.ReadAllBytes(boundDestination)),
            "handle-bound rename preserves the exact written bytes");

        string collisionTemporary = Path.Combine(root, ".collision.part");
        string collisionDestination = Path.Combine(root, "collision.bin");
        File.WriteAllBytes(collisionDestination, [0xA5]);
        using (BoundFileTransaction transaction = BoundFileTransaction.CreateNew(
                   collisionTemporary,
                   bufferSize: 4096,
                   FileOptions.WriteThrough))
        {
            transaction.Stream.WriteByte(0x5A);
            transaction.Stream.Flush(flushToDisk: true);
            AssertThrows<IOException>(
                () => transaction.RenameTo(collisionDestination, overwrite: false),
                "an object-bound exclusive commit refuses a destination that appeared during the write");
            transaction.DeleteBound();
        }
        Assert(
            File.ReadAllBytes(collisionDestination).SequenceEqual([(byte)0xA5]),
            "a failed exclusive commit leaves the competing destination untouched");

        string unboundProducerOutput = Path.Combine(root, ".failed-zpaq-output.zpaq-part");
        File.WriteAllText(unboundProducerOutput, "foreign replacement");
        ProcessResult failedProducer = ZpaqService.PreserveUnboundProducerOutputForTests(
            new ProcessResult(2, string.Empty, "native failure"),
            unboundProducerOutput);
        Assert(
            File.Exists(unboundProducerOutput)
                && File.ReadAllText(unboundProducerOutput) == "foreign replacement",
            "failed native-output cleanup never deletes an object whose ownership was not handle-bound");
        Assert(
            failedProducer.StandardError.Contains("preserved instead of path-deleted", StringComparison.Ordinal),
            "preserving unbound native output is reported instead of becoming a silent leftover");

        string extractionDestination = Path.Combine(root, "bound-extraction");
        using (var staging = new WindowsExtractionStaging(extractionDestination))
        {
            string nested = Path.Combine(staging.StagingPath, "nested");
            Directory.CreateDirectory(nested);
            File.WriteAllBytes(Path.Combine(nested, "payload.bin"), payload);
            DirectoryTreeMeasurement measurement = staging.MeasureTree(allowWriters: false);
            Assert(
                measurement.FileCount == 1
                    && measurement.TotalBytes == payload.Length
                    && measurement.MaxFileBytes == payload.Length,
                "the Windows extraction walker measures the bound no-follow tree in one pass");
            staging.Install();
        }
        Assert(
            File.Exists(Path.Combine(extractionDestination, "nested", "payload.bin")),
            "the Windows extraction install renames the validated bound directory object");

        string preExistingDestination = Path.Combine(root, "pre-existing-empty-extraction");
        Directory.CreateDirectory(preExistingDestination);
        using (var staging = new WindowsExtractionStaging(preExistingDestination))
        {
            File.WriteAllBytes(Path.Combine(staging.StagingPath, "payload.bin"), payload);
            staging.Install();
        }
        Assert(
            File.Exists(Path.Combine(preExistingDestination, "payload.bin")),
            "the exact pre-existing empty target is removed by handle before bound installation");

        string renameProtectedDestination = Path.Combine(root, "rename-protected-extraction");
        using (var staging = new WindowsExtractionStaging(renameProtectedDestination))
        {
            string attackerName = staging.StagingPath + ".swapped";
            AssertThrows<IOException>(
                () => Directory.Move(staging.StagingPath, attackerName),
                "the held Windows staging root cannot be renamed during extraction");
        }

        string outsideTree = Path.Combine(root, "outside-tree");
        Directory.CreateDirectory(outsideTree);
        File.WriteAllBytes(Path.Combine(outsideTree, "must-not-be-counted.bin"), payload);
        string linkedTreeDestination = Path.Combine(root, "linked-tree-extraction");
        using (var staging = new WindowsExtractionStaging(linkedTreeDestination))
        {
            string nestedJunction = Path.Combine(staging.StagingPath, "foreign-junction");
            if (TryCreateJunctionForTests(nestedJunction, outsideTree))
            {
                AssertThrows<InvalidDataException>(
                    () => staging.MeasureTree(allowWriters: false),
                    "the one-pass extraction walker rejects a nested junction before descending");
            }
        }
        Assert(
            File.Exists(Path.Combine(outsideTree, "must-not-be-counted.bin")),
            "bound extraction cleanup never traverses or deletes a nested junction target");

        string racedDestination = Path.Combine(root, "raced-extraction");
        using (var staging = new WindowsExtractionStaging(racedDestination))
        {
            File.WriteAllBytes(Path.Combine(staging.StagingPath, "ours.bin"), [1, 2, 3]);
            WindowsExtractionStaging.TestHookBeforeInstallRename =
                () => Directory.CreateDirectory(racedDestination);
            try
            {
                AssertThrows<IOException>(
                    staging.Install,
                    "the bound extraction install refuses a destination inserted at the final rename boundary");
            }
            finally
            {
                WindowsExtractionStaging.TestHookBeforeInstallRename = null;
            }
        }
        Assert(
            Directory.Exists(racedDestination),
            "failed extraction cleanup does not delete the competing destination object");

        CryptographicOperations.ZeroMemory(payload);
    }
    finally
    {
        try
        {
            DeleteTestDirectory(root);
        }
        catch (IOException)
        {
        }
    }
}

static async Task RunWindowsOriginalDeletionTestsAsync()
{
    string root = Path.Combine(Path.GetTempPath(), $"keep-vault-original-deletion-{Guid.NewGuid():N}");
    string inputDirectory = Path.Combine(root, "inputs");
    string extractedDirectory = Path.Combine(root, "extracted");
    string archive = Path.Combine(root, "archive.zpaq");
    Directory.CreateDirectory(inputDirectory);

    try
    {
        string first = Path.Combine(inputDirectory, "first.txt");
        string second = Path.Combine(inputDirectory, "second.bin");
        await File.WriteAllTextAsync(first, "the first original");
        await File.WriteAllBytesAsync(second, [0, 1, 2, 3, 4, 5, 6, 7]);
        File.WriteAllBytes(archive, RandomNumberGenerator.GetBytes(257));

        string[] inputs = [first, second];
        Dictionary<string, string> entryMap = ZpaqService.BuildArchiveEntryMap(inputs);
        foreach ((string relative, string original) in entryMap)
        {
            string extracted = Path.Combine(extractedDirectory, relative);
            Directory.CreateDirectory(Path.GetDirectoryName(extracted)!);
            File.Copy(original, extracted);
        }

        WindowsOriginalDeletionService.VerificationResult verified =
            await WindowsOriginalDeletionService.VerifyExtractionAsync(
                inputs,
                extractedDirectory,
                progress: null,
                CancellationToken.None);
        Assert(verified.Verified && verified.Originals is not null, "matching extraction passes original verification");

        File.WriteAllText(first, "changed after verification");
        IReadOnlyList<string> driftFailures = WindowsOriginalDeletionService.DeleteOriginals(
            inputs,
            archive,
            WindowsOriginalDeletionService.CaptureArchiveIdentity(archive),
            verified.Originals!);
        Assert(driftFailures.Count > 0, "changed originals block deletion");
        Assert(File.Exists(first) && File.Exists(second), "drift rejection leaves every original in place");

        await File.WriteAllTextAsync(first, "the first original");
        WindowsOriginalDeletionService.VerificationResult clean =
            await WindowsOriginalDeletionService.VerifyExtractionAsync(
                inputs,
                extractedDirectory,
                progress: null,
                CancellationToken.None);
        Assert(clean.Verified && clean.Originals is not null, "restored originals can be verified again");

        IReadOnlyList<string> deletionFailures = WindowsOriginalDeletionService.DeleteOriginals(
            inputs,
            archive,
            WindowsOriginalDeletionService.CaptureArchiveIdentity(archive),
            clean.Originals!);
        Assert(deletionFailures.Count == 0, $"verified originals delete cleanly: {string.Join("; ", deletionFailures)}");
        Assert(!File.Exists(first) && !File.Exists(second), "successful verified deletion removes exactly the originals");
        Assert(File.Exists(archive), "verified original deletion leaves the archive untouched");
    }
    finally
    {
        DeleteTestDirectory(root);
    }
}

static bool TryCreateJunctionForTests(string linkPath, string targetPath)
{
    try
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe"),
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        startInfo.ArgumentList.Add("/c");
        startInfo.ArgumentList.Add("mklink");
        startInfo.ArgumentList.Add("/J");
        startInfo.ArgumentList.Add(linkPath);
        startInfo.ArgumentList.Add(targetPath);
        using Process? process = Process.Start(startInfo);
        if (process is null)
        {
            return false;
        }

        process.WaitForExit();
        return process.ExitCode == 0
            && Directory.Exists(linkPath)
            && (File.GetAttributes(linkPath) & FileAttributes.ReparsePoint) != 0;
    }
    catch (SystemException)
    {
        return false;
    }
}

static bool TryCreateHardLinkForTests(string linkPath, string existingPath)
{
    try
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe"),
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        startInfo.ArgumentList.Add("/c");
        startInfo.ArgumentList.Add("mklink");
        startInfo.ArgumentList.Add("/H");
        startInfo.ArgumentList.Add(linkPath);
        startInfo.ArgumentList.Add(existingPath);
        using Process? process = Process.Start(startInfo);
        if (process is null)
        {
            return false;
        }

        process.WaitForExit();
        return process.ExitCode == 0 && File.Exists(linkPath);
    }
    catch (SystemException)
    {
        return false;
    }
}

static async Task<ProcessResult> RunToolInDirectoryAsync(
    string executable,
    IReadOnlyList<string> arguments,
    string workingDirectory)
{
    var startInfo = new ProcessStartInfo
    {
        FileName = executable,
        WorkingDirectory = workingDirectory,
        UseShellExecute = false,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        CreateNoWindow = true,
    };
    foreach (string argument in arguments)
    {
        startInfo.ArgumentList.Add(argument);
    }

    using Process process = Process.Start(startInfo)
        ?? throw new InvalidOperationException($"Could not start {executable}.");
    string standardOutput = await process.StandardOutput.ReadToEndAsync();
    string standardError = await process.StandardError.ReadToEndAsync();
    await process.WaitForExitAsync();
    return new ProcessResult(process.ExitCode, standardOutput, standardError);
}

static async Task RunMalformedZpaqCorpusTestsAsync()
{
    string root = Path.Combine(Path.GetTempPath(), $"kalyna-zpaq-mutation-{Guid.NewGuid():N}");
    Directory.CreateDirectory(root);
    try
    {
        string source = Path.Combine(root, "source.bin");
        await File.WriteAllBytesAsync(source, RandomNumberGenerator.GetBytes(96 * 1024));
        var archiveBytes = new MemoryStream();
        var zpaq = new ZpaqService();
        ProcessResult add = await zpaq.AddStreamingAsync(
            [source],
            0,
            (archive, cancellationToken) => archive.CopyToAsync(archiveBytes, cancellationToken),
            null,
            CancellationToken.None);
        Assert(add.Succeeded && archiveBytes.Length > 64, "mutation corpus seed archive is valid");

        string executable = NativeToolIntegrity.ResolveKnownTool("zpaq.exe")
            ?? throw new InvalidOperationException("zpaq.exe is unavailable for mutation testing.");
        byte[] seed = archiveBytes.ToArray();
        try
        {
            var corpus = new List<byte[]>();
            int[] truncationLengths = [0, 1, 2, 3, 4, 7, 16, 31, 63, seed.Length / 4, seed.Length / 2, seed.Length - 1];
            corpus.AddRange(truncationLengths.Select(length => seed[..Math.Clamp(length, 0, seed.Length)]));

#pragma warning disable CA5394 // Reproducible parser mutations, never security material.
            // Seeded from the run rather than from a constant. Thirty-six fixed
            // mutations are thirty-six mutations however often the suite runs;
            // drawing them from the run's seed makes each run a different
            // thirty-six, and the seed is printed with any failure and accepted
            // back through --seed, so the run that found something can be
            // repeated exactly. The macOS suite seeds its randomised tests the
            // same way.
            var random = new Random(unchecked((int)TestState.Seed));
            for (int caseIndex = 0; caseIndex < 36; caseIndex++)
            {
                byte[] mutated = (byte[])seed.Clone();
                int mutations = 1 + (caseIndex % 8);
                for (int mutation = 0; mutation < mutations; mutation++)
                {
                    int offset = random.Next(mutated.Length);
                    mutated[offset] ^= (byte)(1 << random.Next(8));
                }

                corpus.Add(mutated);
            }
#pragma warning restore CA5394

            foreach (byte[] input in corpus)
            {
                try
                {
                    int exitCode = await RunZpaqPipeCorpusCaseAsync(executable, input, root);
                    Assert(
                        exitCode is not unchecked((int)0xC0000005)
                            and not unchecked((int)0xC0000374)
                            and not unchecked((int)0xC0000409)
                            and not unchecked((int)0xC0000602),
                        $"mutated ZPAQ input does not terminate with a memory-safety crash (0x{exitCode:X8})");
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
            archiveBytes.Dispose();
        }
    }
    finally
    {
        DeleteTestDirectory(root);
    }
}

static async Task<int> RunZpaqPipeCorpusCaseAsync(string executable, byte[] input, string workingDirectory)
{
    var startInfo = new ProcessStartInfo
    {
        FileName = executable,
        WorkingDirectory = workingDirectory,
        UseShellExecute = false,
        RedirectStandardInput = true,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        CreateNoWindow = true,
    };
    startInfo.ArgumentList.Add("--pipe");
    startInfo.ArgumentList.Add("list");
    startInfo.ArgumentList.Add("-");

    using Process process = Process.Start(startInfo)
        ?? throw new InvalidOperationException("Could not start zpaq.exe for mutation testing.");
    Task stdout = process.StandardOutput.ReadToEndAsync();
    Task stderr = process.StandardError.ReadToEndAsync();
    try
    {
        await process.StandardInput.BaseStream.WriteAsync(input);
    }
    catch (IOException) when (process.HasExited)
    {
        // Expected when a malformed prefix is rejected before the whole corpus case is written.
    }
    finally
    {
        process.StandardInput.Close();
    }

    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
    try
    {
        await process.WaitForExitAsync(timeout.Token);
    }
    catch (OperationCanceledException)
    {
        process.Kill(entireProcessTree: true);
        await process.WaitForExitAsync();
        throw new TimeoutException("Mutated ZPAQ input hung the pipe parser for more than three seconds.");
    }

    await Task.WhenAll(stdout, stderr);
    return process.ExitCode;
}

static async Task RunCompressionLevelMatrixTestsAsync()
{
    string root = Path.Combine(Path.GetTempPath(), $"kalyna-compression-matrix-{Guid.NewGuid():N}");
    Directory.CreateDirectory(root);
    try
    {
        string source = Path.Combine(root, "compression-source.bin");
        byte[] sourceBytes = new byte[192 * 1024];
        for (int index = 0; index < sourceBytes.Length; index++)
        {
            sourceBytes[index] = (byte)((index * 31) ^ (index >> 7));
        }

        await File.WriteAllBytesAsync(source, sourceBytes);
        byte[] expectedHash = SHA3_512.HashData(sourceBytes);
        CryptographicOperations.ZeroMemory(sourceBytes);
        try
        {
            var zpaq = new ZpaqService();
            for (int level = 0; level <= 5; level++)
            {
                string plainArchive = Path.Combine(root, $"plain-level-{level}.zpaq");
                string plainOutput = Path.Combine(root, $"plain-level-{level}-output");
                ProcessResult plainAdd = await zpaq.AddAsync(plainArchive, [source], level, null, CancellationToken.None);
                Assert(plainAdd.Succeeded, $"plain ZPAQ compression level {level} creates an archive");
                ProcessResult plainExtract = await zpaq.ExtractAsync(plainArchive, plainOutput, null, CancellationToken.None);
                Assert(plainExtract.Succeeded, $"plain ZPAQ compression level {level} extracts");
                await AssertFileSha3Async(
                    Path.Combine(plainOutput, Path.GetFileName(source)),
                    expectedHash,
                    $"plain ZPAQ compression level {level} roundtrip hash");

                using var streamingArchive = new MemoryStream();
                ProcessResult streamingAdd = await zpaq.AddStreamingAsync(
                    [source],
                    level,
                    (archive, cancellationToken) => archive.CopyToAsync(streamingArchive, cancellationToken),
                    null,
                    CancellationToken.None);
                Assert(streamingAdd.Succeeded && streamingArchive.Length > 0, $"streaming ZPAQ compression level {level} creates an archive");
                byte[] archiveBytes = streamingArchive.ToArray();
                try
                {
                    string streamingOutput = Path.Combine(root, $"stream-level-{level}-output");
                    ProcessResult streamingExtract = await zpaq.ExtractStreamingAsync(
                        async (destination, cancellationToken) =>
                        {
                            await destination.WriteAsync(archiveBytes, cancellationToken);
                        },
                        streamingOutput,
                        null,
                        CancellationToken.None);
                    Assert(streamingExtract.Succeeded, $"streaming ZPAQ compression level {level} extracts");
                    await AssertFileSha3Async(
                        Path.Combine(streamingOutput, Path.GetFileName(source)),
                        expectedHash,
                        $"streaming ZPAQ compression level {level} roundtrip hash");
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(archiveBytes);
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expectedHash);
        }
    }
    finally
    {
        DeleteTestDirectory(root);
    }
}

static async Task AssertFileSha3Async(string path, byte[] expectedHash, string message)
{
    await using FileStream stream = File.OpenRead(path);
    byte[] actualHash = await SHA3_512.HashDataAsync(stream);
    try
    {
        Assert(CryptographicOperations.FixedTimeEquals(expectedHash, actualHash), message);
    }
    finally
    {
        CryptographicOperations.ZeroMemory(actualHash);
    }
}

static async Task RunEntropyGeneratorTestsAsync()
{
    // The nine mouse pools are locked buffers created by EntropyMixer's static
    // constructor, and they live for the process. Reading the mixer here forces
    // that to have happened before the baseline is taken.
    //
    // Without it the baseline depends on whether something earlier in the same
    // process had already touched the mixer. As a single script something
    // always had; as one test in its own worker, nothing had, and the run ended
    // with "baseline 0, now 9" - nine pools reported as a leak because they
    // were created after the measurement rather than before it.
    _ = EntropyMixer.GetPoolStatus();

    long lockedBaseline = SecureMemory.LockedBytesForTests;
    long lockedAllocationBaseline = SecureMemory.LockedAllocationsForTests;
    long reservationBaseline = SecureMemory.ReservedWorkingSetBytesForTests;
    using Process reservationProcess = Process.GetCurrentProcess();
    reservationProcess.Refresh();
    long reservationMinimumBaseline = reservationProcess.MinWorkingSet.ToInt64();
    IDisposable? firstReservation = null;
    IDisposable? secondReservation = null;
    try
    {
        firstReservation = SecureMemory.ReserveWorkingSetCapacity(8L * 1024 * 1024);
        secondReservation = SecureMemory.ReserveWorkingSetCapacity(16L * 1024 * 1024);
        Assert(
            SecureMemory.ReservedWorkingSetBytesForTests == reservationBaseline + (24L * 1024 * 1024),
            "nested working-set reservations are added exactly");
        firstReservation.Dispose();
        firstReservation.Dispose();
        Assert(
            SecureMemory.ReservedWorkingSetBytesForTests == reservationBaseline + (16L * 1024 * 1024),
            "out-of-order and repeated reservation disposal cannot underflow accounting");
        firstReservation = null;
    }
    finally
    {
        firstReservation?.Dispose();
        secondReservation?.Dispose();
    }

    Assert(
        SecureMemory.ReservedWorkingSetBytesForTests == reservationBaseline,
        "nested working-set reservations return to baseline");
    reservationProcess.Refresh();
    Assert(
        reservationProcess.MinWorkingSet.ToInt64() == reservationMinimumBaseline,
        "nested working-set reservations restore the previous minimum working set");
    AssertThrows<ArgumentOutOfRangeException>(
        () => SecureMemory.ReserveWorkingSetCapacity(0),
        "zero-byte working-set reservations are rejected without state changes");
    AssertThrows<OverflowException>(
        () => SecureMemory.ReserveWorkingSetCapacity(long.MaxValue),
        "overflowing working-set reservations fail before changing accounting");
    Assert(
        SecureMemory.ReservedWorkingSetBytesForTests == reservationBaseline,
        "failed working-set reservations leave accounting unchanged");

    byte[] lockProbe = new byte[16 * 1024 * 1024];
    RandomNumberGenerator.Fill(lockProbe);
    try
    {
        using (SecureMemory.TryLock(lockProbe))
        {
            Assert(
                SecureMemory.LockedBytesForTests >= lockedBaseline + lockProbe.Length,
                "sensitive-memory coordinator reserves and locks a 16 MiB streaming-sized buffer");
        }

        Assert(SecureMemory.LockedBytesForTests == lockedBaseline, "sensitive-memory coordinator restores its lock accounting");
    }
    finally
    {
        CryptographicOperations.ZeroMemory(lockProbe);
    }

    AddMouseSamplesUntilEntropyReady();
    long before = EntropyMixer.SampleCount;
    EntropyMixer.AddMouseSample(12.5, 44.75, 123456, System.Windows.Input.MouseButtonState.Released, System.Windows.Input.MouseButtonState.Pressed, System.Windows.Input.MouseButtonState.Released);
    EntropyMixer.AddMouseSample(13.5, 45.75, 123457, System.Windows.Input.MouseButtonState.Pressed, System.Windows.Input.MouseButtonState.Released, System.Windows.Input.MouseButtonState.Released);
    EntropyMixer.AddMouseSample(14.5, 46.75, 123458, System.Windows.Input.MouseButtonState.Released, System.Windows.Input.MouseButtonState.Released, System.Windows.Input.MouseButtonState.Pressed);
    EntropyMixer.AddMouseSample(15.5, 47.75, 123459, System.Windows.Input.MouseButtonState.Pressed, System.Windows.Input.MouseButtonState.Pressed, System.Windows.Input.MouseButtonState.Released);
    EntropyMixer.AddMouseSample(16.5, 48.75, 123460, System.Windows.Input.MouseButtonState.Released, System.Windows.Input.MouseButtonState.Pressed, System.Windows.Input.MouseButtonState.Pressed);
    Assert(EntropyMixer.SampleCount == before + 5, "mouse entropy collection continues after all pools reach the minimum");

    long randomCallsBeforeArchiveEntropy = EntropyMixer.SystemRandomCallCountForTests;
    using GeneratedArchiveEntropy generatedArchiveEntropy = EntropyMixer.CreateArchiveEntropy();
    string firstGeneratedPassword = generatedArchiveEntropy.FirstPassword;
    string secondGeneratedPassword = generatedArchiveEntropy.SecondPassword;
    Assert(firstGeneratedPassword.Length == 256, "first generated password is 256 hex characters");
    Assert(firstGeneratedPassword.All(Uri.IsHexDigit), "first generated password is hexadecimal");
    Assert(secondGeneratedPassword.Length == 256, "second generated password is 256 hex characters");
    Assert(secondGeneratedPassword.All(Uri.IsHexDigit), "second generated password is hexadecimal");
    Assert(!string.Equals(firstGeneratedPassword, secondGeneratedPassword, StringComparison.Ordinal), "independent generated-password pools do not produce the same factor");
    Assert(generatedArchiveEntropy.HasPendingEncryptionParameters, "the same generation retains salt and nonce in locked RAM for immediate encryption");
    EntropyPoolStatus afterPasswordPair = EntropyMixer.GetPoolStatus();
    Assert(afterPasswordPair.Total == 0, "archive-entropy generation atomically replaces all nine pools with a fresh empty epoch");
    // A well-formed factor of the right length, differing in one character:
    // a longer string would be refused by the parser instead, which is a
    // different check and would leave the binding untested.
    string mismatchedSecondFactor = string.Concat(
        secondGeneratedPassword.AsSpan(0, secondGeneratedPassword.Length - 1),
        secondGeneratedPassword[^1] == '0' ? "1" : "0");
    AssertThrows<InvalidOperationException>(
        () => generatedArchiveEntropy.ConsumeEncryptionParameters(
            EncryptionSuite.Threefish1024,
            firstGeneratedPassword,
            mismatchedSecondFactor),
        "prepared salt and nonce reject different generated factors");
    Assert(generatedArchiveEntropy.HasPendingEncryptionParameters, "a factor-binding rejection does not consume prepared salt or nonce");
    (LockedSensitiveBuffer preparedSalt, LockedSensitiveBuffer preparedNonce) =
        generatedArchiveEntropy.ConsumeEncryptionParameters(
            EncryptionSuite.Threefish1024,
            firstGeneratedPassword,
            secondGeneratedPassword);
    using (preparedSalt)
    using (preparedNonce)
    {
        Assert(
            preparedSalt.Bytes.Length == EntropyMixer.SaltPairBytes && preparedSalt.Bytes.Any(value => value != 0),
            "prepared salt pair remains available after the visible pool reset");
        Assert(
            preparedNonce.Bytes.Length == EncryptionSuiteCatalog.Get(EncryptionSuite.Threefish1024).NonceBytes
            && preparedNonce.Bytes.Any(value => value != 0),
            "prepared Threefish nonce remains available after the visible pool reset");
    }

    Assert(!generatedArchiveEntropy.HasPendingEncryptionParameters, "prepared salt and nonce are single-use");
    AssertThrows<InvalidOperationException>(
        () => generatedArchiveEntropy.ConsumeEncryptionParameters(
            EncryptionSuite.Threefish1024,
            firstGeneratedPassword,
            secondGeneratedPassword),
        "prepared salt and nonce cannot be consumed twice");
    // Last use of this generation. It keeps both factors in locked pages, so
    // it has to be released here rather than at the end of the method: the
    // lock-accounting baseline is checked further down.
    generatedArchiveEntropy.Dispose();
    long randomCallsBeforeRejectedArchiveEntropy = EntropyMixer.SystemRandomCallCountForTests;
    AssertThrows<InvalidOperationException>(
        () => EntropyMixer.CreateArchiveEntropy(),
        "archive entropy cannot be regenerated without a complete fresh entropy epoch");
    Assert(
        EntropyMixer.SystemRandomCallCountForTests == randomCallsBeforeRejectedArchiveEntropy,
        "an incomplete archive-entropy epoch is rejected before requesting system randomness");

    for (int index = 0; index < 18; index++)
    {
        EntropyMixer.AddMouseSample(
            100 + index,
            200 + index,
            200000 + index,
            System.Windows.Input.MouseButtonState.Released,
            System.Windows.Input.MouseButtonState.Released,
            System.Windows.Input.MouseButtonState.Released);
    }

    EntropyPoolStatus afterEighteenFreshSamples = EntropyMixer.GetPoolStatus();
    Assert(
        afterEighteenFreshSamples.Total == 18
        && afterEighteenFreshSamples.FactorA1 == 2
        && afterEighteenFreshSamples.FactorA2 == 2
        && afterEighteenFreshSamples.FactorB1 == 2
        && afterEighteenFreshSamples.FactorB2 == 2
        && afterEighteenFreshSamples.SaltSha3 == 2
        && afterEighteenFreshSamples.SaltSkein == 2
        && afterEighteenFreshSamples.NonceFirst == 2
        && afterEighteenFreshSamples.NonceSecond == 2
        && afterEighteenFreshSamples.NonceThird == 2,
        "fresh movements after generation are distributed evenly across all nine empty pools");
    Assert(afterEighteenFreshSamples.IsBalanced, "all current pool counters remain balanced after a global reset");

    long randomCallsBeforeRejectedParameters = EntropyMixer.SystemRandomCallCountForTests;
    AssertThrows<InvalidOperationException>(
        () =>
        {
            (LockedSensitiveBuffer rejectedSalt, LockedSensitiveBuffer rejectedNonce) =
                EntropyMixer.CreateEncryptionParameters(EncryptionSuite.Kalyna512_512);
            rejectedSalt.Dispose();
            rejectedNonce.Dispose();
        },
        "salt/nonce generation rejects an incomplete entropy epoch");
    Assert(
        EntropyMixer.SystemRandomCallCountForTests == randomCallsBeforeRejectedParameters,
        "rejected salt/nonce generation neither requests system randomness nor consumes the partial epoch");
    Assert(EntropyMixer.GetPoolStatus() == afterEighteenFreshSamples, "rejected generation leaves every pool unchanged");

    AddMouseSamplesUntilEntropyReady();
    long randomCallsBeforeKalynaParameters = EntropyMixer.SystemRandomCallCountForTests;
    (LockedSensitiveBuffer kalynaSalt, LockedSensitiveBuffer kalynaNonce) =
        EntropyMixer.CreateEncryptionParameters(EncryptionSuite.Kalyna512_512);
    using (kalynaSalt)
    using (kalynaNonce)
    {
        Assert(
            kalynaSalt.Bytes.Length == EntropyMixer.SaltPairBytes && kalynaSalt.Bytes.Any(value => value != 0),
            "Kalyna salt is a nonzero SHA3/Skein salt pair");
        Assert(
            kalynaNonce.Bytes.Length == EncryptionSuiteCatalog.Get(EncryptionSuite.Kalyna512_512).NonceBytes
            && kalynaNonce.Bytes.Any(value => value != 0),
            "Kalyna takes its nonce from the unified 128-byte nonce path");
    }

    Assert(
        EntropyMixer.SystemRandomCallCountForTests == randomCallsBeforeKalynaParameters + 3,
        "Kalyna salt/nonce generation makes one BCryptGenRandom call per salt half and one for the nonce");
    Assert(
        EntropyMixer.LastSystemRandomRequestBytesForTests == EncryptionSuiteCatalog.MaxNonceBytes,
        "Kalyna requests the unified widest-nonce source value before truncation");
    Assert(EntropyMixer.GetPoolStatus().Total == 0, "Kalyna parameter generation atomically clears the complete nine-pool epoch");

    for (int index = 0; index < 4922; index++)
    {
        EntropyMixer.AddMouseSample(
            300 + (index % 101),
            400 + (index % 103),
            300000 + index,
            System.Windows.Input.MouseButtonState.Released,
            System.Windows.Input.MouseButtonState.Released,
            System.Windows.Input.MouseButtonState.Released);
    }

    EntropyPoolStatus partialEpoch = EntropyMixer.GetPoolStatus();
    Assert(partialEpoch.Total == 4922 && partialEpoch.IsBalanced, "the photographed 4922-sample scenario remains balanced and reports only current samples");
    // The point is the even spread, not a particular pair of counts: the
    // pool count has grown once already and the numbers moved with it.
    int entropyPoolCount = Enum.GetValues<EntropyPurpose>().Length;
    Assert(
        partialEpoch.Maximum == (4922 + entropyPoolCount - 1) / entropyPoolCount
        && partialEpoch.Maximum - partialEpoch.Minimum <= 1,
        "4922 movements spread evenly across every pool instead of recreating the photographed divergence");

    AddMouseSamplesUntilEntropyReady();
    long randomCallsBeforeThreefishParameters = EntropyMixer.SystemRandomCallCountForTests;
    (LockedSensitiveBuffer threefishSalt, LockedSensitiveBuffer threefishNonce) =
        EntropyMixer.CreateEncryptionParameters(EncryptionSuite.Threefish1024);
    using (threefishSalt)
    using (threefishNonce)
    {
        Assert(
            threefishSalt.Bytes.Length == EntropyMixer.SaltPairBytes && threefishSalt.Bytes.Any(value => value != 0),
            "Threefish salt is a nonzero SHA3/Skein salt pair");
        Assert(
            threefishNonce.Bytes.Length == EncryptionSuiteCatalog.Get(EncryptionSuite.Threefish1024).NonceBytes
            && threefishNonce.Bytes.Any(value => value != 0),
            "Threefish uses all nonzero bytes from the unified nonce path");
    }

    Assert(
        EntropyMixer.SystemRandomCallCountForTests == randomCallsBeforeThreefishParameters + 3,
        "Threefish salt/nonce generation makes one BCryptGenRandom call per salt half and one for the nonce");
    Assert(
        EntropyMixer.LastSystemRandomRequestBytesForTests == EncryptionSuiteCatalog.MaxNonceBytes,
        "Threefish requests the unified widest-nonce source value from BCryptGenRandom");
    Assert(EntropyMixer.GetPoolStatus().Total == 0, "Threefish parameter generation atomically clears the complete nine-pool epoch");

    AddMouseSamplesUntilEntropyReady();
    using (var raceStart = new ManualResetEventSlim(initialState: false))
    {
        Task<GeneratedArchiveEntropy> generationTask = Task.Run(() =>
        {
            raceStart.Wait();
            return EntropyMixer.CreateArchiveEntropy();
        });
        Task samplingTask = Task.Run(() =>
        {
            raceStart.Wait();
            for (int index = 0; index < 500; index++)
            {
                EntropyMixer.AddMouseSample(
                    500 + (index % 107),
                    600 + (index % 109),
                    400000 + index,
                    System.Windows.Input.MouseButtonState.Released,
                    System.Windows.Input.MouseButtonState.Released,
                    System.Windows.Input.MouseButtonState.Released);
            }
        });

        raceStart.Set();
        await Task.WhenAll(generationTask, samplingTask);
        using GeneratedArchiveEntropy raceEntropy = await generationTask;
        Assert(raceEntropy.FirstPassword.Length == 256 && raceEntropy.SecondPassword.Length == 256, "concurrent epoch generation still returns both complete factors");
        Assert(raceEntropy.HasPendingEncryptionParameters, "concurrent epoch generation keeps its prepared salt and nonce intact");
    }

    EntropyPoolStatus postRace = EntropyMixer.GetPoolStatus();
    Assert(postRace.IsBalanced && postRace.Total is >= 0 and <= 500, "generation racing with new mouse events leaves one balanced post-generation epoch");
    Assert(
        postRace.Total == postRace.FactorA1
            + postRace.FactorA2
            + postRace.FactorB1
            + postRace.FactorB2
            + postRace.SaltSha3
            + postRace.SaltSkein
            + postRace.NonceFirst
            + postRace.NonceSecond
            + postRace.NonceThird,
        "concurrent generation preserves the current-total invariant");
    // Counted, not weighed. Everything above this line has replaced each of the
    // nine mouse pools many times over, and a pool buffer is charged the pages
    // it spans: 64 bytes lands inside one page most of the time and across two
    // in about one allocation in eighty, so the byte total moves by a page
    // whenever the collector pins a replacement differently. Comparing bytes
    // here made the suite fail on roughly one clean run in five. What the check
    // is for is that nothing leaked, and the number of live locked buffers says
    // that exactly.
    Assert(
        SecureMemory.LockedAllocationsForTests == lockedAllocationBaseline,
        "entropy generation and concurrent pool replacement return every locked buffer they took "
        + $"(baseline {lockedAllocationBaseline}, now {SecureMemory.LockedAllocationsForTests})");

    Assert(PasswordKeyService.MinPasswordLength == 24, "minimum password length is 24");
    Assert(PasswordKeyService.MaxPasswordLength == 256, "maximum password length is 256");
    Assert(Argon2ExecutionProfile.Default.Iterations == 4, "default Argon2 iteration count is exactly four");
    Assert(Argon2ExecutionProfile.Default.Parallelism == 4, "default Argon2 parallelism is portable and not CPU-dependent");
    // Memory is not part of the execution profile: v12 derives it from PMI16.
    Assert(V12MasterKdf.MemoryMinKiB == 1_048_576, "v12 minimum Argon2 memory is 1 GiB");
    Assert(V12MasterKdf.MemoryMaxKiB == 2_097_136, "v12 maximum Argon2 memory is 2 GiB minus 16 KiB");
    Assert(V12MasterKdf.MemoryStepKiB == 16, "v12 Argon2 memory grid is 16 KiB");
    AssertThrows<ArgumentOutOfRangeException>(
        () => PasswordKeyService.ValidateArgon2Profile(new Argon2ExecutionProfile(3, 4)),
        "weakened Argon2 iteration count is rejected");
    AssertThrows<ArgumentOutOfRangeException>(
        () => PasswordKeyService.ValidateArgon2Profile(new Argon2ExecutionProfile(4, 3)),
        "weakened Argon2 parallelism is rejected");
    byte[] nativeProfilePassword = new byte[PasswordKeyService.Argon2PasswordInputSize];
    byte[] nativeProfileSalt = new byte[PasswordKeyService.SaltSize];
    byte[] nativeProfileOutput = new byte[PasswordKeyService.KalynaDerivedKeySize];
    long reservationBeforeRejectedProfile = SecureMemory.ReservedWorkingSetBytesForTests;
    long lockedBytesBeforeRejectedProfile = SecureMemory.LockedBytesForTests;
    using Process rejectedProfileProcess = Process.GetCurrentProcess();
    rejectedProfileProcess.Refresh();
    long minimumWorkingSetBeforeRejectedProfile = rejectedProfileProcess.MinWorkingSet.ToInt64();
    RandomNumberGenerator.Fill(nativeProfilePassword);
    RandomNumberGenerator.Fill(nativeProfileSalt);
    try
    {
        AssertThrows<CryptographicException>(
            () => NativeArgon2id.HashRaw(4, 256 * 1024, 4, nativeProfilePassword, nativeProfileSalt, nativeProfileOutput),
            "native Argon2 adapter independently rejects the legacy 256 MiB profile");
        rejectedProfileProcess.Refresh();
        Assert(
            SecureMemory.ReservedWorkingSetBytesForTests == reservationBeforeRejectedProfile,
            "rejected Argon2 profile releases its temporary working-set reservation");
        Assert(
            SecureMemory.LockedBytesForTests == lockedBytesBeforeRejectedProfile,
            "rejected Argon2 profile does not leak managed VirtualLock accounting");
        Assert(
            rejectedProfileProcess.MinWorkingSet.ToInt64() == minimumWorkingSetBeforeRejectedProfile,
            "rejected Argon2 profile restores the previous minimum working set");
        Assert(nativeProfileOutput.All(value => value == 0), "rejected Argon2 profile does not modify the output buffer");
    }
    finally
    {
        CryptographicOperations.ZeroMemory(nativeProfilePassword);
        CryptographicOperations.ZeroMemory(nativeProfileSalt);
        CryptographicOperations.ZeroMemory(nativeProfileOutput);
    }
    await AssertThrowsAsync<PasswordPolicyException>(
        () =>
        {
            PasswordKeyService.ValidateUserPasswordForCreation("too-short", TestGeneratedPassword(), TestGeneratedPassword('B'));
            return Task.CompletedTask;
        },
        "user passwords shorter than 24 characters are rejected");

    string generatedPasswordA = TestGeneratedPassword();
    string generatedPasswordB = TestGeneratedPassword('B');
    string groupedGeneratedPassword = KeySheetService.GroupGeneratedPassword(generatedPasswordA).Replace(" ", Environment.NewLine, StringComparison.Ordinal);
    Assert(PasswordKeyService.NormalizeGeneratedPassword(groupedGeneratedPassword) == generatedPasswordA, "generated password normalization accepts whitespace");
    PasswordKeyService.ValidateUserPasswordForCreation(TestConstants.TestUserPassword, generatedPasswordA, generatedPasswordB);
    PasswordPolicyAnalysis acceptedAnalysis = PasswordKeyService.AnalyzeUserPassword(TestConstants.TestUserPassword, generatedPasswordA, generatedPasswordB);
    Assert(acceptedAnalysis.IsAccepted && acceptedAnalysis.ConservativeEntropyBits >= 128, "policy accepts the high-diversity user password at 128 conservative bits");
    Assert(acceptedAnalysis.NonHexCharacterCount >= 12 && acceptedAnalysis.DistinctCharacterCount >= 12, "policy reports non-hex and distinct-character requirements");
    Assert(PasswordKeyService.UserPasswordMatchesAnyGeneratedPassword(generatedPasswordA, generatedPasswordA), "generated password cannot be reused as the user password");
    AssertThrows<ArgumentException>(
        () => PasswordKeyService.ValidateUserPasswordForCreation("aaaaaaaaaaaaaaaaaaaaaaaa", generatedPasswordA, generatedPasswordB),
        "weak repeated user password is rejected");
    AssertThrows<ArgumentException>(
        () => PasswordKeyService.ValidateUserPasswordForCreation(generatedPasswordA, generatedPasswordA, generatedPasswordB),
        "user password must differ from both generated passwords");
    AssertThrows<ArgumentException>(
        () => PasswordKeyService.ValidateUserPasswordForCreation(TestConstants.TestUserPassword, generatedPasswordA, generatedPasswordA),
        "generated password factors A and B must differ");

    ContainerKeyDerivation.ValidatePinForCreation(TestConstants.TestPin);
    PinPolicyAnalysis validPinAnalysis = ContainerKeyDerivation.AnalyzePinForCreation(TestConstants.TestPin);
    Assert(validPinAnalysis.IsAccepted, "valid PIN is accepted by policy");
    AssertThrows<PinPolicyException>(() => ContainerKeyDerivation.ValidatePinForCreation("12345"), "too short PIN is rejected");
    AssertThrows<PinPolicyException>(() => ContainerKeyDerivation.ValidatePinForCreation("111111"), "repeated digit PIN is rejected");
    AssertThrows<PinPolicyException>(() => ContainerKeyDerivation.ValidatePinForCreation("123456"), "sequential ascending PIN is rejected");

    PasswordPolicyAnalysis hexRunAnalysis = PasswordKeyService.AnalyzeUserPassword("Abcd1234!NqRsTuVwXyZ#98$LmNo", generatedPasswordA, generatedPasswordB);
    Assert(hexRunAnalysis.Violations.Contains(PasswordPolicyViolation.HexadecimalRunTooLong), "eight-character hexadecimal run is rejected case-insensitively");
    PasswordPolicyAnalysis nonHexAnalysis = PasswordKeyService.AnalyzeUserPassword("A1b2C3d4E5f6A1b2C3d4E5f6", generatedPasswordA, generatedPasswordB);
    Assert(nonHexAnalysis.Violations.Contains(PasswordPolicyViolation.NotEnoughNonHexCharacters), "hexadecimal-only user password does not satisfy non-hex requirement");

    // Fixed but distinct: the derivation refuses an identical salt pair, and
    // these comparisons only need the pair to stay the same across derivations.
    KdfSalts salts = new(
        [.. Enumerable.Repeat((byte)0x11, KdfSalts.SaltBytes)],
        [.. Enumerable.Repeat((byte)0x22, KdfSalts.SaltBytes)],
        null,
        null);
    using ContainerKeyDerivation.MasterResult first = ContainerKeyDerivation.DeriveMaster(
        EncryptionSuiteCatalog.Get(EncryptionSuite.Kalyna512_512),
        TestConstants.TestUserPassword,
        TestConstants.TestPin,
        generatedPasswordA,
        generatedPasswordB,
        salts,
        null,
        CancellationToken.None);
    using ContainerKeyDerivation.MasterResult differentFirstGenerated = ContainerKeyDerivation.DeriveMaster(
        EncryptionSuiteCatalog.Get(EncryptionSuite.Kalyna512_512),
        TestConstants.TestUserPassword,
        TestConstants.TestPin,
        TestGeneratedPassword('C'),
        generatedPasswordB,
        salts,
        null,
        CancellationToken.None);
    using ContainerKeyDerivation.MasterResult differentSecondGenerated = ContainerKeyDerivation.DeriveMaster(
        EncryptionSuiteCatalog.Get(EncryptionSuite.Kalyna512_512),
        TestConstants.TestUserPassword,
        TestConstants.TestPin,
        generatedPasswordA,
        TestGeneratedPassword('D'),
        salts,
        null,
        CancellationToken.None);
    using ContainerKeyDerivation.MasterResult differentUser = ContainerKeyDerivation.DeriveMaster(
        EncryptionSuiteCatalog.Get(EncryptionSuite.Kalyna512_512),
        TestConstants.TestUserPassword + "X",
        TestConstants.TestPin,
        generatedPasswordA,
        generatedPasswordB,
        salts,
        null,
        CancellationToken.None);
    using ContainerKeyDerivation.MasterResult differentPin = ContainerKeyDerivation.DeriveMaster(
        EncryptionSuiteCatalog.Get(EncryptionSuite.Kalyna512_512),
        TestConstants.TestUserPassword,
        "98765432",
        generatedPasswordA,
        generatedPasswordB,
        salts,
        null,
        CancellationToken.None);

    Assert(!CryptographicOperations.FixedTimeEquals(first.Master.Bytes, differentFirstGenerated.Master.Bytes), "changing first generated password changes derived master");
    Assert(!CryptographicOperations.FixedTimeEquals(first.Master.Bytes, differentSecondGenerated.Master.Bytes), "changing second generated password changes derived master");
    Assert(!CryptographicOperations.FixedTimeEquals(first.Master.Bytes, differentUser.Master.Bytes), "changing user password changes derived master");
    Assert(!CryptographicOperations.FixedTimeEquals(first.Master.Bytes, differentPin.Master.Bytes), "changing PIN changes derived master");

    using RoleKeyMaterial kalynaKeys = SuiteKeySchedule.DeriveSuiteKeys(first.Master.Bytes, EncryptionSuiteCatalog.Get(EncryptionSuite.Kalyna512_512));
    using RoleKeyMaterial threefishKeys = SuiteKeySchedule.DeriveSuiteKeys(first.Master.Bytes, EncryptionSuiteCatalog.Get(EncryptionSuite.Threefish1024));
    using RoleKeyMaterial paranoiaKeys = SuiteKeySchedule.DeriveSuiteKeys(first.Master.Bytes, EncryptionSuiteCatalog.Get(EncryptionSuite.ParanoiaCascade));
    // The widths belong to the suite, so read them from the catalogue rather
    // than restating them: the Paranoia cascade has already grown from three
    // ciphers to six, and its key width grew with it.
    foreach ((RoleKeyMaterial keys, EncryptionSuite suite) in new[]
    {
        (kalynaKeys, EncryptionSuite.Kalyna512_512),
        (threefishKeys, EncryptionSuite.Threefish1024),
        (paranoiaKeys, EncryptionSuite.ParanoiaCascade),
    })
    {
        EncryptionSuiteParameters suiteWidths = EncryptionSuiteCatalog.Get(suite);
        Assert(
            keys.EncryptionKey.Bytes.Length == suiteWidths.EncryptionKeyBytes
            && keys.Sha3MacKey.Bytes.Length == suiteWidths.Sha3MacKeyBytes
            && keys.SkeinMacKey.Bytes.Length == suiteWidths.SkeinMacKeyBytes,
            $"{suite} derives the cipher, SHA3 MAC and Skein MAC key widths its catalogue entry declares");
    }
}

static void RunMldsa87ReferenceTests()
{
    string referencePath = Path.Combine(AppContext.BaseDirectory, "mldsa87_ref.dll");
    Assert(File.Exists(referencePath), "official ML-DSA-87 reference adapter is available");
    using var reference = new Mldsa87Reference(referencePath);
    (byte[] publicKey, byte[] privateKey) = reference.GenerateKeyPair();
    byte[] message = SHA512.HashData("FIPS 204 ML-DSA-87 Kalyna release-signature interoperability"u8);
    byte[]? managedSignature = null;
    byte[]? secondManagedSignature = null;
    byte[]? referenceSignature = null;
    try
    {
        Assert(publicKey.Length == 2592, "ML-DSA-87 public key length matches FIPS 204");
        Assert(privateKey.Length == 4896, "ML-DSA-87 private key length matches FIPS 204");
        managedSignature = Mldsa87.Sign(message, privateKey);
        Assert(managedSignature.Length == 4627, "ML-DSA-87 signature length matches FIPS 204");
        Assert(reference.Verify(message, managedSignature, publicKey), "official reference accepts managed ML-DSA-87 signature");
        secondManagedSignature = Mldsa87.Sign(message, privateKey);
        Assert(
            !CryptographicOperations.FixedTimeEquals(managedSignature, secondManagedSignature),
            "ML-DSA-87 hedged signing uses fresh CSPRNG randomness");
        Assert(reference.Verify(message, secondManagedSignature, publicKey), "official reference accepts a second randomized managed signature");

        referenceSignature = reference.Sign(message, privateKey);
        Assert(Mldsa87.Verify(message, referenceSignature, publicKey), "managed verifier accepts official reference ML-DSA-87 signature");

        byte[] wrongMessage = message.ToArray();
        byte[] wrongPublicKey = publicKey.ToArray();
        byte[] wrongSignature = managedSignature.ToArray();
        try
        {
            wrongMessage[0] ^= 0x80;
            wrongPublicKey[^1] ^= 0x01;
            wrongSignature[wrongSignature.Length / 2] ^= 0x01;
            Assert(!reference.Verify(wrongMessage, managedSignature, publicKey), "official reference rejects a changed message");
            Assert(!reference.Verify(message, wrongSignature, publicKey), "official reference rejects a changed signature");
            Assert(!Mldsa87.Verify(message, managedSignature, wrongPublicKey), "managed verifier rejects a changed public key");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrongMessage);
            CryptographicOperations.ZeroMemory(wrongPublicKey);
            CryptographicOperations.ZeroMemory(wrongSignature);
        }

        string signedTool = NativeToolIntegrity.ResolveKnownTool("zpaq.exe")
            ?? throw new InvalidOperationException("zpaq.exe is unavailable for hybrid-signature tests.");
        HybridSignaturePolicy policy = SigningTrustPolicy.HybridPolicy
            ?? throw new InvalidOperationException("Compiled ML-DSA-87 policy is unavailable.");
        HybridSignatureVerificationResult valid = HybridSignatureService.VerifyFile(
            signedTool,
            signedTool + HybridSignatureService.SidecarExtension,
            policy);
        Assert(valid.IsTrusted && valid.RsaPssValid && valid.Mldsa87Valid, "real native tool has both detached signatures");

        ToolIntegrityStatus signedToolStatus = IntegrityService.CheckFile(signedTool, requireManifest: true);
        string rsaSha256Pin = signedToolStatus.SignerSha256
            ?? throw new InvalidOperationException("Signed tool does not expose its RSA SHA-256 SPKI pin.");
        string rsaSha3Pin = signedToolStatus.SignerSha3_512
            ?? throw new InvalidOperationException("Signed tool does not expose its RSA SHA3-512 SPKI pin.");
        string rsaSkeinPin = signedToolStatus.SignerSkein1024
            ?? throw new InvalidOperationException("Signed tool does not expose its RSA Skein-1024 SPKI pin.");
        (byte[] mlSha256, byte[] mlSha3, byte[] mlSkein) = HybridSignatureService.Fingerprint(policy.MldsaPublicKey.Span);
        try
        {
            string mlSha256Hex = Convert.ToHexString(mlSha256);
            string mlSha3Hex = Convert.ToHexString(mlSha3);
            string mlSkeinHex = Convert.ToHexString(mlSkein);
            foreach ((string name, string rsaSha256, string rsaSha3, string rsaSkein) in new[]
            {
                ("SHA-256", new string('0', 64), rsaSha3Pin, rsaSkeinPin),
                ("SHA3-512", rsaSha256Pin, new string('0', 128), rsaSkeinPin),
                ("Skein-1024", rsaSha256Pin, rsaSha3Pin, new string('0', 256)),
            })
            {
                var wrongRsaPolicy = new HybridSignaturePolicy(
                    rsaSha256,
                    rsaSha3,
                    rsaSkein,
                    mlSha256Hex,
                    mlSha3Hex,
                    mlSkeinHex,
                    policy.MldsaPublicKey.Span);
                HybridSignatureVerificationResult wrongRsaResult = HybridSignatureService.VerifyFile(
                    signedTool,
                    signedTool + HybridSignatureService.SidecarExtension,
                    wrongRsaPolicy);
                Assert(!wrongRsaResult.IsTrusted, $"wrong RSA {name} SPKI pin is rejected");
            }

            foreach ((string name, string candidateSha256, string candidateSha3, string candidateSkein) in new[]
            {
                ("SHA-256", new string('0', 64), mlSha3Hex, mlSkeinHex),
                ("SHA3-512", mlSha256Hex, new string('0', 128), mlSkeinHex),
                ("Skein-1024", mlSha256Hex, mlSha3Hex, new string('0', 256)),
            })
            {
                AssertThrows<CryptographicException>(
                    () => _ = new HybridSignaturePolicy(
                        rsaSha256Pin,
                        rsaSha3Pin,
                        rsaSkeinPin,
                        candidateSha256,
                        candidateSha3,
                        candidateSkein,
                        policy.MldsaPublicKey.Span),
                    $"wrong ML-DSA-87 {name} public-key pin is rejected");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(mlSha256);
            CryptographicOperations.ZeroMemory(mlSha3);
            CryptographicOperations.ZeroMemory(mlSkein);
        }

        string tamperedSidecar = Path.Combine(Path.GetTempPath(), $"tampered-{Guid.NewGuid():N}.khsig");
        string tamperedTarget = Path.Combine(Path.GetTempPath(), $"tampered-target-{Guid.NewGuid():N}.exe");
        try
        {
            byte[] encoded = File.ReadAllBytes(signedTool + HybridSignatureService.SidecarExtension);
            try
            {
                const int lengthTableOffset = 8 + sizeof(int) + sizeof(long) + 64;
                const int payloadOffset = lengthTableOffset + (3 * sizeof(int));
                int certificateLength = BinaryPrimitives.ReadInt32LittleEndian(encoded.AsSpan(lengthTableOffset));
                int rsaOffset = checked(payloadOffset + certificateLength);
                encoded[rsaOffset] ^= 0x01;
                File.WriteAllBytes(tamperedSidecar, encoded);
                HybridSignatureVerificationResult rsaTampered = HybridSignatureService.VerifyFile(signedTool, tamperedSidecar, policy);
                Assert(
                    !rsaTampered.IsTrusted && !rsaTampered.RsaPssValid && rsaTampered.Mldsa87Valid,
                    "one-bit RSA-PSS sidecar corruption is rejected independently of ML-DSA");

                encoded[rsaOffset] ^= 0x01;
                encoded[^1] ^= 0x01;
                File.WriteAllBytes(tamperedSidecar, encoded);
                HybridSignatureVerificationResult mldsaTampered = HybridSignatureService.VerifyFile(signedTool, tamperedSidecar, policy);
                Assert(
                    !mldsaTampered.IsTrusted && mldsaTampered.RsaPssValid && !mldsaTampered.Mldsa87Valid,
                    "one-bit ML-DSA sidecar corruption is rejected independently of RSA-PSS");

                encoded[^1] ^= 0x01;
                Array.Resize(ref encoded, encoded.Length + 1);
                File.WriteAllBytes(tamperedSidecar, encoded);
                HybridSignatureVerificationResult trailingData = HybridSignatureService.VerifyFile(signedTool, tamperedSidecar, policy);
                Assert(!trailingData.IsTrusted, "hybrid sidecar trailing data is rejected");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(encoded);
            }

            using (var oversized = new FileStream(tamperedSidecar, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                oversized.SetLength((64 * 1024) + 1);
            }

            HybridSignatureVerificationResult oversizedSidecar = HybridSignatureService.VerifyFile(
                signedTool,
                tamperedSidecar,
                policy);
            Assert(!oversizedSidecar.IsTrusted, "oversized hybrid sidecar is rejected before an unbounded allocation");

            File.Copy(signedTool, tamperedTarget);
            File.Copy(
                signedTool + HybridSignatureService.SidecarExtension,
                tamperedTarget + HybridSignatureService.SidecarExtension);
            using (var stream = new FileStream(tamperedTarget, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                stream.Position = stream.Length / 2;
                int original = stream.ReadByte();
                Assert(original >= 0, "signed native tool has data to mutate");
                stream.Position--;
                stream.WriteByte((byte)(original ^ 0x01));
                stream.Flush(flushToDisk: true);
            }

            HybridSignatureVerificationResult targetTampered = HybridSignatureService.VerifyFile(
                tamperedTarget,
                tamperedTarget + HybridSignatureService.SidecarExtension,
                policy);
            Assert(!targetTampered.IsTrusted, "one-bit signed-artifact corruption is rejected before signature acceptance");
        }
        finally
        {
            File.Delete(tamperedSidecar);
            File.Delete(tamperedTarget);
            File.Delete(tamperedTarget + HybridSignatureService.SidecarExtension);
        }
    }
    finally
    {
        CryptographicOperations.ZeroMemory(publicKey);
        CryptographicOperations.ZeroMemory(privateKey);
        CryptographicOperations.ZeroMemory(message);
        if (managedSignature is not null) CryptographicOperations.ZeroMemory(managedSignature);
        if (secondManagedSignature is not null) CryptographicOperations.ZeroMemory(secondManagedSignature);
        if (referenceSignature is not null) CryptographicOperations.ZeroMemory(referenceSignature);
    }
}

static void RunSha3ReferenceVectorTests()
{
    AssertHex(
        SHA3_512.HashData([]),
        "A69F73CCA23A9AC5C8B567DC185A756E97C982164FE25859E0D1DCC1475C80A615B2123AF1F5F94C11E3E9402C3AC558F500199D95B6D3E301758586281DCD26",
        "SHA3-512 empty-string vector");
    AssertHex(
        SHA3_512.HashData("abc"u8.ToArray()),
        "B751850B1A57168A5693CD924B6B096E08F621827444F70D884F5D0240D2712E10E116E9192AF3C91A7EC57647E3934057340B4CF408D5A56592F8274EEC53F0",
        "SHA3-512 abc vector");
}

static void RunSkein1024ReferenceTests()
{
    byte[] message = [0xFF];
    byte[] expectedHash = Convert.FromHexString(
        "E62C05802EA0152407CDD8787FDA9E35703DE862A4FBC119CFF8590AFE79250B" +
        "CCC8B3FAF1BD2422AB5C0D263FB2F8AFB3F796F048000381531B6F00D85161BC" +
        "0FFF4BEF2486B1EBCD3773FABF50AD4AD5639AF9040E3F29C6C931301BF79832" +
        "E9DA09857E831E82EF8B4691C235656515D437D2BDA33BCEC001C67FFDE15BA8");
    byte[] managedHash = Skein1024Digest.HashData(message);
    byte[] referenceHash = NativeThreefish.HashSkein1024Reference(message);
    try
    {
        Assert(CryptographicOperations.FixedTimeEquals(expectedHash, managedHash), "managed Skein-1024 matches official 8-bit KAT");
        Assert(CryptographicOperations.FixedTimeEquals(expectedHash, referenceHash), "native Skein-1024 reference adapter matches official 8-bit KAT");
    }
    finally
    {
        CryptographicOperations.ZeroMemory(message);
        CryptographicOperations.ZeroMemory(expectedHash);
        CryptographicOperations.ZeroMemory(managedHash);
        CryptographicOperations.ZeroMemory(referenceHash);
    }

    byte[] officialMacKey = Convert.FromHexString(
        "CB41F1706CDE09651203C2D0EFBADDF847A0D315CB2E53FF8BAC41DA0002672E" +
        "920244C66E02D5F0DAD3E94C42BB65F0D14157DECF4105EF5609D5B0984457C1" +
        "935DF3061FF06E9F204192BA11E5BB2CAC0430C1C370CB3D113FEA5EC1021EB8" +
        "75E5946D7A96AC69A1626C6206B7252736F24253C9EE9B85EB852DFC81463134");
    byte[] expectedMac = Convert.FromHexString(
        "BCF37B3459C88959D6B6B58B2BFE142CEF60C6F4EC56B0702480D7893A2B0595" +
        "AA354E87102A788B61996B9CBC1EADE7DAFBF6581135572C09666D844C90F066" +
        "B800FC4F5FD1737644894EF7D588AFC5C38F5D920BDBD3B738AEA3A3267D161E" +
        "D65284D1F57DA73B68817E17E381CA169115152B869C66B812BB9A84275303F0");
    byte[] empty = [];
    byte[] nativeMac = NativeThreefish.MacSkein1024Reference(officialMacKey, empty);
    byte[] independentMac = BouncySkeinMac(officialMacKey, empty);
    byte[] streamingMac;
    using (NativeSkein1024Mac state = NativeThreefish.CreateSkeinMac(officialMacKey))
    {
        state.AppendData(empty);
        streamingMac = state.GetTag();
    }

    try
    {
        Assert(CryptographicOperations.FixedTimeEquals(expectedMac, nativeMac), "native Skein-1024 MAC matches official empty-message KAT");
        Assert(CryptographicOperations.FixedTimeEquals(expectedMac, independentMac), "Bouncy Castle Skein-1024 MAC matches official empty-message KAT");
        Assert(CryptographicOperations.FixedTimeEquals(expectedMac, streamingMac), "streaming locked Skein-1024 MAC matches official KAT");

        int[] lengths = [0, 1, 127, 128, 129, 4096, (1024 * 1024) + 31];
        foreach (int length in lengths)
        {
            byte[] key = RandomNumberGenerator.GetBytes(128);
            byte[] data = RandomNumberGenerator.GetBytes(length);
            byte[] native = NativeThreefish.MacSkein1024Reference(key, data);
            byte[] independent = BouncySkeinMac(key, data);
            byte[] streaming;
            using (NativeSkein1024Mac state = NativeThreefish.CreateSkeinMac(key))
            {
                int split = Math.Min(data.Length, 113);
                state.AppendData(data.AsSpan(0, split));
                state.AppendData(data.AsSpan(split));
                streaming = state.GetTag();
            }

            try
            {
                Assert(CryptographicOperations.FixedTimeEquals(native, independent), $"Skein-1024 MAC native/independent equivalence at {length} bytes");
                Assert(CryptographicOperations.FixedTimeEquals(native, streaming), $"Skein-1024 MAC one-shot/streaming equivalence at {length} bytes");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
                CryptographicOperations.ZeroMemory(data);
                CryptographicOperations.ZeroMemory(native);
                CryptographicOperations.ZeroMemory(independent);
                CryptographicOperations.ZeroMemory(streaming);
            }
        }
    }
    finally
    {
        CryptographicOperations.ZeroMemory(officialMacKey);
        CryptographicOperations.ZeroMemory(expectedMac);
        CryptographicOperations.ZeroMemory(nativeMac);
        CryptographicOperations.ZeroMemory(independentMac);
        CryptographicOperations.ZeroMemory(streamingMac);
    }
}

static byte[] BouncySkeinMac(byte[] key, byte[] data)
{
    var mac = new SkeinMac(1024, 1024);
    mac.Init(new KeyParameter((byte[])key.Clone()));
    mac.BlockUpdate(data);
    byte[] output = new byte[128];
    mac.DoFinal(output);
    mac.Reset();
    return output;
}

static async Task RunArgon2WorkingSetStressAsync(int repetitions)
{
    // Copied next to the test assembly by the project file. Resolving it
    // through the working directory only worked when the run happened to be
    // launched from the repository root.
    string argon2Exe = Path.Combine(AppContext.BaseDirectory, "argon2.exe");
    Assert(File.Exists(argon2Exe), "PHC Argon2 reference CLI exists for working-set stress");

    byte[] password = "PHC-Argon2id-working-set-stress-input-2026"u8.ToArray();
    byte[] salt = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"u8.ToArray();
    byte[] reference = await RunArgon2ReferenceCliAsync(
        argon2Exe,
        password,
        salt,
        PasswordKeyService.KalynaDerivedKeySize);
    using Process process = Process.GetCurrentProcess();
    process.Refresh();
    long privateBytesBefore = process.PrivateMemorySize64;

    try
    {
        for (int attempt = 0; attempt < repetitions; attempt++)
        {
            byte[] directPassword = (byte[])password.Clone();
            byte[] directSalt = (byte[])salt.Clone();
            byte[] directOutput = new byte[PasswordKeyService.KalynaDerivedKeySize];
            try
            {
                await RunNativeArgon2WithSecureMemoryChurnAsync(directPassword, directSalt, directOutput);
                // The digests go into the message. A differential assertion
                // that says only "they differ" leaves the two interesting cases
                // - an all-zero output, meaning nothing was written, and a
                // plausible-looking but wrong digest, meaning it was computed
                // differently - indistinguishable from each other.
                Assert(
                    CryptographicOperations.FixedTimeEquals(reference, directOutput),
                    $"native Argon2id stress attempt {attempt + 1} remains byte-exact with the unmodified PHC CLI "
                    + $"(CLI {Convert.ToHexString(reference)}, adapter {Convert.ToHexString(directOutput)})");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(directPassword);
                CryptographicOperations.ZeroMemory(directSalt);
                CryptographicOperations.ZeroMemory(directOutput);
            }
        }
    }
    finally
    {
        CryptographicOperations.ZeroMemory(password);
        CryptographicOperations.ZeroMemory(salt);
        CryptographicOperations.ZeroMemory(reference);
    }

    GC.Collect();
    GC.WaitForPendingFinalizers();
    GC.Collect();
    process.Refresh();
    const long maximumPermittedPrivateGrowth = 512L * 1024 * 1024;
    Assert(
        process.PrivateMemorySize64 - privateBytesBefore < maximumPermittedPrivateGrowth,
        "repeated native Argon2id calls release the 1 GiB VirtualAlloc matrix");
}

static async Task RunNativeArgon2WithSecureMemoryChurnAsync(
    byte[] password,
    byte[] salt,
    byte[] output)
{
    const int churnWorkerCount = 4;
    long reservationBaseline = SecureMemory.ReservedWorkingSetBytesForTests;
    // Same reason as the two callers above: the mixer's nine pools have to
    // exist before the baseline, not after it.
    _ = EntropyMixer.GetPoolStatus();
    long lockedLeaseBaseline = SecureMemory.LockedAllocationsForTests;
    long maximumObservedReservation = reservationBaseline;
    int churnIterations = 0;
    using Process process = Process.GetCurrentProcess();
    process.Refresh();
    long minimumWorkingSetBaseline = process.MinWorkingSet.ToInt64();
    using var stopChurn = new CancellationTokenSource();
    using var churnStarted = new CountdownEvent(churnWorkerCount);
    Task[] churnTasks = Enumerable.Range(0, churnWorkerCount)
        .Select(workerIndex => Task.Factory.StartNew(
            () =>
            {
                bool announced = false;
                while (!stopChurn.IsCancellationRequested)
                {
                    using LockedSensitiveBuffer transientSensitiveBuffer = LockedSensitiveBuffer.Create(80 + workerIndex);
                    UpdateMaximum(
                        ref maximumObservedReservation,
                        SecureMemory.ReservedWorkingSetBytesForTests);
                    Interlocked.Increment(ref churnIterations);
                    if (!announced)
                    {
                        churnStarted.Signal();
                        announced = true;
                    }

                    Thread.Sleep(1);
                }
            },
            CancellationToken.None,
            TaskCreationOptions.LongRunning,
            TaskScheduler.Default))
        .ToArray();

    try
    {
        Assert(churnStarted.Wait(TimeSpan.FromSeconds(10)), "all secure-memory churn workers started");
        NativeArgon2id.HashRaw(
            (uint)Argon2ReferenceProfile.Iterations,
            (uint)Argon2ReferenceProfile.MemoryKiB,
            (uint)Argon2ReferenceProfile.Parallelism,
            password,
            salt,
            output);
    }
    finally
    {
        stopChurn.Cancel();
        await Task.WhenAll(churnTasks).ConfigureAwait(false);
    }

    Assert(
        Volatile.Read(ref churnIterations) >= churnWorkerCount,
        "all managed secure-memory workers overlap the native Argon2id call");
    Assert(
        Volatile.Read(ref maximumObservedReservation) >= (long)Argon2ReferenceProfile.MemoryKiB * 1024,
        "native Argon2id exposes its 1 GiB working-set reservation to every managed lock worker");
    Assert(
        SecureMemory.ReservedWorkingSetBytesForTests == reservationBaseline,
        "Argon2id releases its coordinated working-set reservation after churn");
    Assert(
        SecureMemory.LockedAllocationsForTests == lockedLeaseBaseline,
        // Leases, not bytes: see SecureMemory.LockedAllocationsForTests. The
        // byte total also moves with where the collector pins a replacement
        // buffer, which is not something this test is entitled to an opinion on.
        "parallel secure-memory churn releases every managed VirtualLock lease");
    process.Refresh();
    Assert(
        process.MinWorkingSet.ToInt64() == minimumWorkingSetBaseline,
        "Argon2id and parallel churn restore the previous minimum working set");
}

static void UpdateMaximum(ref long target, long candidate)
{
    long current = Volatile.Read(ref target);
    while (candidate > current)
    {
        long observed = Interlocked.CompareExchange(ref target, candidate, current);
        if (observed == current)
        {
            return;
        }

        current = observed;
    }
}

static async Task RunArgon2ReferenceCliTestAsync()
{
    byte[] salt = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"u8.ToArray();
    byte[] testPassword = "SamplePasswordForArgon2ReferenceVerification123!"u8.ToArray();

    try
    {
        await RunArgon2WorkingSetStressAsync(3);

        int outputLength = 64;
        byte[] reference = RunBouncyArgon2id(testPassword, salt, outputLength);
        byte[] managed = new byte[outputLength];
        NativeArgon2id.HashRaw((uint)Argon2ReferenceProfile.Iterations, (uint)Argon2ReferenceProfile.MemoryKiB, (uint)Argon2ReferenceProfile.Parallelism, testPassword, salt, managed);
        try
        {
            Assert(managed.Length == outputLength, "Argon2id output length");
            Assert(
                CryptographicOperations.FixedTimeEquals(managed, reference),
                "managed Argon2id output matches independent Bouncy Castle");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(reference);
            CryptographicOperations.ZeroMemory(managed);
        }
    }
    finally
    {
        CryptographicOperations.ZeroMemory(testPassword);
        CryptographicOperations.ZeroMemory(salt);
    }
}

static byte[] RunBouncyArgon2id(byte[] password, byte[] salt, int outputLength)
{
    var parameters = new Org.BouncyCastle.Crypto.Parameters.Argon2Parameters.Builder(
        Org.BouncyCastle.Crypto.Parameters.Argon2Parameters.Argon2id)
        .WithVersion(Org.BouncyCastle.Crypto.Parameters.Argon2Parameters.Version13)
        .WithMemoryAsKB(Argon2ReferenceProfile.MemoryKiB)
        .WithIterations(Argon2ReferenceProfile.Iterations)
        .WithParallelism(Argon2ReferenceProfile.Parallelism)
        .WithSalt((byte[])salt.Clone())
        .Build();
    var generator = new Argon2BytesGenerator();
    generator.Init(parameters);
    byte[] output = new byte[outputLength];
    int written = generator.GenerateBytes(password, output);
    Assert(written == outputLength, "Bouncy Castle Argon2id output length");
    return output;
}

static async Task<byte[]> RunArgon2ReferenceCliAsync(
    string argon2Exe,
    byte[] passwordBytes,
    byte[] salt,
    int outputLength)
{
    int memoryExponent = (int)Math.Log2(Argon2ReferenceProfile.MemoryKiB);
    Assert(1 << memoryExponent == Argon2ReferenceProfile.MemoryKiB, "Argon2 memory profile is a power of two for CLI comparison");

    var startInfo = new ProcessStartInfo
    {
        FileName = argon2Exe,
        UseShellExecute = false,
        RedirectStandardInput = true,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        CreateNoWindow = true,
    };
    startInfo.ArgumentList.Add(System.Text.Encoding.ASCII.GetString(salt));
    startInfo.ArgumentList.Add("-id");
    startInfo.ArgumentList.Add("-t");
    startInfo.ArgumentList.Add(Argon2ReferenceProfile.Iterations.ToString());
    startInfo.ArgumentList.Add("-m");
    startInfo.ArgumentList.Add(memoryExponent.ToString());
    startInfo.ArgumentList.Add("-p");
    startInfo.ArgumentList.Add(Argon2ReferenceProfile.Parallelism.ToString());
    startInfo.ArgumentList.Add("-l");
    startInfo.ArgumentList.Add(outputLength.ToString());
    startInfo.ArgumentList.Add("-r");

    using Process process = Process.Start(startInfo) ?? throw new InvalidOperationException("Could not start Argon2 reference CLI.");
    await process.StandardInput.BaseStream.WriteAsync(passwordBytes);
    process.StandardInput.Close();

    using var output = new MemoryStream();
    await process.StandardOutput.BaseStream.CopyToAsync(output);
    string stderr = await process.StandardError.ReadToEndAsync();
    await process.WaitForExitAsync();
    Assert(process.ExitCode == 0, $"Argon2 reference CLI exited {process.ExitCode}: {stderr}");
    string hex = System.Text.Encoding.ASCII.GetString(output.ToArray()).Trim();
    byte[] result = Convert.FromHexString(hex);
    Assert(result.Length == outputLength, "Argon2 reference CLI raw output length");
    return result;
}

static void AssertHex(byte[] actual, string expectedHex, string message)
{
    Assert(string.Equals(Convert.ToHexString(actual), expectedHex, StringComparison.OrdinalIgnoreCase), message);
}

static string TestGeneratedPassword(char digit = 'A')
{
    return new string(digit, PasswordKeyService.GeneratedPasswordLength);
}



static async Task RunPdfRoundTripTestsAsync()
{
    string sourcePdf = ResolveSamplePdfPath();
    const string password = TestConstants.TestUserPassword;
    const string pin = TestConstants.TestPin;
    string firstGeneratedPassword = TestGeneratedPassword();
    string secondGeneratedPassword = TestGeneratedPassword('B');

    Assert(File.Exists(sourcePdf), "sample PDF exists");
    Console.WriteLine($"Sample PDF under test: {sourcePdf}");
    await AssertPdfReadableAsync(sourcePdf, "source PDF is readable");
    byte[] originalHash = await Sha3FileAsync(sourcePdf);
    string root = Path.Combine(Path.GetTempPath(), $"kalyna-pdf-e2e-{Guid.NewGuid():N}");
    DateTime tempAuditStart = DateTime.UtcNow;
    // The nine mouse pools are locked for the life of the process and are
    // created on first use of the mixer. Touch it first, or a run where this
    // group is the first to reach the mixer counts them as its own leak.
    _ = EntropyMixer.GetPoolStatus();
    long lockedLeaseBaseline = SecureMemory.LockedAllocationsForTests;
    Directory.CreateDirectory(root);

    try
    {
        var zpaq = new ZpaqService();
        var kalyna = new KalynaContainerService();
        var archiveIntegrity = new ArchiveIntegrityService();
        string plainArchive = Path.Combine(root, "sample.zpaq");
        string plainExtractDir = Path.Combine(root, "plain-extract");
        string plainRecoveredExtractDir = Path.Combine(root, "plain-recovered-extract");
        string encryptedArchive = Path.Combine(root, "sample.kzpaq");
        string encryptedExtractDir = Path.Combine(root, "encrypted-extract");
        string encryptedRecoveredExtractDir = Path.Combine(root, "encrypted-recovered-extract");
        string threefishArchive = Path.Combine(root, "sample-threefish.kzpaq");
        string threefishExtractDir = Path.Combine(root, "threefish-extract");

        ProcessResult addResult = await zpaq.AddAsync(plainArchive, [sourcePdf], 1, null, CancellationToken.None);
        Assert(addResult.Succeeded, "ZPAQ add sample PDF");
        Assert(File.Exists(plainArchive) && new FileInfo(plainArchive).Length > 0, "plain ZPAQ archive exists");
        AssertZpaqHeader(plainArchive, "plain archive has a ZPAQ header");
        await archiveIntegrity.CreateAsync(plainArchive, CancellationToken.None);
        await archiveIntegrity.VerifyAsync(plainArchive, CancellationToken.None);
        Assert(File.Exists(plainArchive + ".sha3") && File.Exists(plainArchive + ".skein"), "plain ZPAQ has both mandatory integrity manifests");
        byte[] sourceHashAfterArchive = await Sha3FileAsync(sourcePdf);
        Assert(CryptographicOperations.FixedTimeEquals(originalHash, sourceHashAfterArchive), "creating archive does not overwrite the source PDF");
        CryptographicOperations.ZeroMemory(sourceHashAfterArchive);

        Directory.CreateDirectory(plainExtractDir);
        ProcessResult extractResult = await zpaq.ExtractAsync(plainArchive, plainExtractDir, null, CancellationToken.None);
        Assert(extractResult.Succeeded, "ZPAQ extract sample PDF");
        Assert(!Directory.EnumerateDirectories(root, "*.extract-part", SearchOption.TopDirectoryOnly).Any(), "successful extraction atomically installs and removes its staging directory");
        await AssertExtractedPdfHashAsync(plainExtractDir, Path.GetFileName(sourcePdf), originalHash, "plain ZPAQ extracted PDF hash");
        await AssertPdfReadableAsync(Path.Combine(plainExtractDir, Path.GetFileName(sourcePdf)), "plain ZPAQ extracted PDF is readable");

        var pdfRecovery = new RecoveryService();
        await pdfRecovery.CreateAsync(plainArchive, null, CancellationToken.None);
        await CorruptRangeAsync(plainArchive, 0, 4096);
        RecoveryRepairResult plainPdfRecovery = await pdfRecovery.VerifyAndRepairAsync(
            plainArchive,
            null,
            CancellationToken.None);
        Assert(plainPdfRecovery.Repaired && plainPdfRecovery.OutputPath is not null, "plain sample PDF archive is reconstructed through KPAR2 v4");
        Directory.CreateDirectory(plainRecoveredExtractDir);
        ProcessResult recoveredPlainExtract = await zpaq.ExtractAsync(
            plainPdfRecovery.OutputPath!,
            plainRecoveredExtractDir,
            null,
            CancellationToken.None);
        Assert(recoveredPlainExtract.Succeeded, "recovered plain sample PDF archive extracts with regenerated dual manifests");
        await AssertExtractedPdfHashAsync(
            plainRecoveredExtractDir,
            Path.GetFileName(sourcePdf),
            originalHash,
            "KPAR2-recovered plain PDF hash");
        await AssertPdfReadableAsync(
            Path.Combine(plainRecoveredExtractDir, Path.GetFileName(sourcePdf)),
            "KPAR2-recovered plain PDF is readable");

        await AssertThrowsAsync<ArgumentOutOfRangeException>(
            async () =>
            {
                await using var input = new MemoryStream([1, 2, 3], writable: false);
                await kalyna.EncryptZpaqStreamAsync(
                    input,
                    Path.Combine(root, "invalid-hint.kzpaq"),
                    password,
                    pin,
                    firstGeneratedPassword,
                    secondGeneratedPassword,
                    EncryptionSuite.Kalyna512_512,
                    new string('H', 181),
                    null,
                    CancellationToken.None);
            },
            "container creation rejects a public hint that its own reader would reject");

        AddMouseSamplesUntilEntropyReady();
        using GeneratedArchiveEntropy preparedPdfEntropy = EntropyMixer.CreateArchiveEntropy();
        firstGeneratedPassword = preparedPdfEntropy.FirstPassword;
        secondGeneratedPassword = preparedPdfEntropy.SecondPassword;
        Assert(EntropyMixer.GetPoolStatus().Total == 0, "sample-PDF generation visibly resets all consumed mouse pools");
        ProcessResult encryptedAddResult = await zpaq.AddStreamingAsync(
            [sourcePdf],
            1,
            (zpaqStream, ct) => kalyna.EncryptZpaqStreamWithPreparedEntropyAsync(
                zpaqStream,
                encryptedArchive,
                password,
                pin,
                firstGeneratedPassword,
                secondGeneratedPassword,
                EncryptionSuite.Kalyna512_512,
                preparedPdfEntropy,
                "test hint",
                null,
                ct),
            null,
            CancellationToken.None);
        Assert(encryptedAddResult.Succeeded, "streaming ZPAQ add into encrypted container");
        Assert(!preparedPdfEntropy.HasPendingEncryptionParameters, "sample-PDF encryption consumes its prepared salt and nonce exactly once");
        // Last use. It keeps both factors in locked pages, so it has to be
        // released here rather than at the end of the method: the lock-accounting
        // baseline is checked once both roundtrips are done.
        preparedPdfEntropy.Dispose();
        Assert(await kalyna.LooksEncryptedAsync(encryptedArchive, CancellationToken.None), "encrypted container magic");
        AssertContainerHeader(encryptedArchive, EncryptionSuite.Kalyna512_512);
        KalynaContainerInfo info = await kalyna.ReadContainerInfoAsync(encryptedArchive, CancellationToken.None);
        Assert(info.RequiresGeneratedPassword
            && info.GeneratedPasswordBits == 1024
            && info.GeneratedPasswordFactorCount == 2
            && info.Version == 12
            && info.Suite == EncryptionSuite.Kalyna512_512
            && info.Hint == "test hint",
            "v12 Kalyna container declares two generated 1024-bit factors");

        string existingTarget = Path.Combine(root, "must-not-overwrite.kzpaq");
        byte[] existingSentinel = "existing target must survive"u8.ToArray();
        await File.WriteAllBytesAsync(existingTarget, existingSentinel);
        AddMouseSamplesUntilEntropyReady();
        await AssertThrowsAsync<IOException>(
            async () =>
            {
                await using var tinyInput = new MemoryStream([1, 2, 3, 4], writable: false);
                await kalyna.EncryptZpaqStreamAsync(
                    tinyInput,
                    existingTarget,
                    password,
                    pin,
                    firstGeneratedPassword,
                    secondGeneratedPassword,
                    EncryptionSuite.Threefish1024,
                    null,
                    null,
                    CancellationToken.None);
            },
            "atomic encrypted output refuses an existing target");
        byte[] existingAfter = await File.ReadAllBytesAsync(existingTarget);
        try
        {
            Assert(CryptographicOperations.FixedTimeEquals(existingSentinel, existingAfter), "failed encrypted output does not modify or delete the existing target");
            Assert(!Directory.EnumerateFiles(root, "*.encrypted-part").Any(), "failed encrypted output removes its ciphertext-only temporary file");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(existingSentinel);
            CryptographicOperations.ZeroMemory(existingAfter);
        }

        // v12 carries no salt-width field, so the old SaltBits mutation has no
        // counterpart. What the header does guarantee is that the two round-one
        // salts differ: equal salts would put both Argon2id branches of the same
        // round on one initial hash input, which is what separate salt pools
        // exist to prevent.
        string duplicateSaltArchive = Path.Combine(root, "duplicate-round1-salt.kzpaq");
        File.Copy(encryptedArchive, duplicateSaltArchive);
        string rawSha3Round1Salt = ReadRawContainerHeaderString(duplicateSaltArchive, "SaltSha3Round1");
        string rawSkeinRound1Salt = ReadRawContainerHeaderString(duplicateSaltArchive, "SaltSkeinRound1");
        Assert(rawSha3Round1Salt != rawSkeinRound1Salt, "a freshly written container uses two different round-one salts");
        ReplaceContainerHeaderToken(
            duplicateSaltArchive,
            $"\"SaltSha3Round1\":\"{rawSha3Round1Salt}\"",
            $"\"SaltSha3Round1\":\"{rawSkeinRound1Salt}\"");
        await AssertThrowsAsync<InvalidDataException>(
            () => kalyna.ReadContainerInfoAsync(duplicateSaltArchive, CancellationToken.None),
            "a container header whose two round-one salts are equal is refused");

        string manipulatedArgon2IterationsArchive = Path.Combine(root, "argon2-t3.kzpaq");
        File.Copy(encryptedArchive, manipulatedArgon2IterationsArchive);
        ReplaceContainerHeaderToken(manipulatedArgon2IterationsArchive, "\"Argon2Iterations\":4", "\"Argon2Iterations\":3");
        await AssertThrowsAsync<InvalidDataException>(
            () => kalyna.ReadContainerInfoAsync(manipulatedArgon2IterationsArchive, CancellationToken.None),
            "v12 rejects weakened Argon2 iterations before deriving a key");

        string duplicateHeaderPropertyArchive = Path.Combine(root, "duplicate-header-property.kzpaq");
        File.Copy(encryptedArchive, duplicateHeaderPropertyArchive);
        ReplaceContainerHeaderToken(
            duplicateHeaderPropertyArchive,
            "\"Argon2Iterations\":4",
            "\"Argon2Iterations\":4,\"Argon2Iterations\":4");
        await AssertThrowsAsync<InvalidDataException>(
            () => kalyna.ReadContainerInfoAsync(duplicateHeaderPropertyArchive, CancellationToken.None),
            "v12 rejects duplicate JSON properties even when both values are identical");

        string manipulatedArgon2Archive = Path.Combine(root, "argon2-p3.kzpaq");
        File.Copy(encryptedArchive, manipulatedArgon2Archive);
        ReplaceContainerHeaderToken(manipulatedArgon2Archive, "\"Argon2Parallelism\":4", "\"Argon2Parallelism\":3");
        await AssertThrowsAsync<InvalidDataException>(
            () => kalyna.ReadContainerInfoAsync(manipulatedArgon2Archive, CancellationToken.None),
            "v12 rejects weakened Argon2 parallelism before deriving a key");

        await AssertThrowsCryptographicAsync(
            () => kalyna.DecryptToStreamAsync(encryptedArchive, password + "x", pin, firstGeneratedPassword, secondGeneratedPassword, Stream.Null, null, CancellationToken.None),
            "wrong user password is rejected");
        await AssertThrowsCryptographicAsync(
            () => kalyna.DecryptToStreamAsync(encryptedArchive, password, "98765432", firstGeneratedPassword, secondGeneratedPassword, Stream.Null, null, CancellationToken.None),
            "wrong PIN is rejected");
        await AssertThrowsCryptographicAsync(
            () => kalyna.DecryptToStreamAsync(encryptedArchive, password, pin, TestGeneratedPassword('C'), secondGeneratedPassword, Stream.Null, null, CancellationToken.None),
            "wrong first generated password is rejected");
        await AssertThrowsCryptographicAsync(
            () => kalyna.DecryptToStreamAsync(encryptedArchive, password, pin, firstGeneratedPassword, TestGeneratedPassword('D'), Stream.Null, null, CancellationToken.None),
            "wrong second generated password is rejected");

        string tamperedArchive = Path.Combine(root, "tampered.kzpaq");
        File.Copy(encryptedArchive, tamperedArchive);
        await FlipLastByteAsync(tamperedArchive);
        await AssertThrowsCryptographicAsync(
            () => kalyna.DecryptToStreamAsync(tamperedArchive, password, pin, firstGeneratedPassword, secondGeneratedPassword, Stream.Null, null, CancellationToken.None),
            "tampered container is rejected");

        string tamperedSha3TagArchive = Path.Combine(root, "tampered-sha3-tag.kzpaq");
        File.Copy(encryptedArchive, tamperedSha3TagArchive);
        await FlipContainerTagByteAsync(tamperedSha3TagArchive, skeinTag: false);
        await AssertThrowsCryptographicAsync(
            () => kalyna.DecryptToStreamAsync(tamperedSha3TagArchive, password, pin, firstGeneratedPassword, secondGeneratedPassword, Stream.Null, null, CancellationToken.None),
            "container with only its HMAC-SHA3-512 tag changed is rejected");

        string tamperedSkeinTagArchive = Path.Combine(root, "tampered-skein-tag.kzpaq");
        File.Copy(encryptedArchive, tamperedSkeinTagArchive);
        await FlipContainerTagByteAsync(tamperedSkeinTagArchive, skeinTag: true);
        await AssertThrowsCryptographicAsync(
            () => kalyna.DecryptToStreamAsync(tamperedSkeinTagArchive, password, pin, firstGeneratedPassword, secondGeneratedPassword, Stream.Null, null, CancellationToken.None),
            "container with only its Skein-1024 MAC tag changed is rejected");

        ProcessResult listResult = await zpaq.ListStreamingAsync(
            (zpaqInput, ct) => kalyna.DecryptToStreamAsync(encryptedArchive, password, pin, firstGeneratedPassword, secondGeneratedPassword, zpaqInput, null, ct),
            null,
            CancellationToken.None);
        Assert(listResult.Succeeded, "encrypted streaming container lists");
        Assert(listResult.StandardError.Contains("versions", StringComparison.OrdinalIgnoreCase), "encrypted list scans the streaming pipe without a temporary archive");

        ProcessResult encryptedExtractResult = await zpaq.ExtractStreamingAsync(
            (zpaqInput, ct) => kalyna.DecryptToStreamAsync(encryptedArchive, password, pin, firstGeneratedPassword, secondGeneratedPassword, zpaqInput, null, ct),
            encryptedExtractDir,
            null,
            CancellationToken.None);
        Assert(encryptedExtractResult.Succeeded, "encrypted container streams into ZPAQ extractor");
        Assert(encryptedExtractResult.StandardError.Contains("streaming segments", StringComparison.OrdinalIgnoreCase), "Kalyna extraction uses the bounded-memory one-pass ZPAQ path");
        await AssertExtractedPdfHashAsync(encryptedExtractDir, Path.GetFileName(sourcePdf), originalHash, "encrypted roundtrip PDF hash");
        await AssertPdfReadableAsync(Path.Combine(encryptedExtractDir, Path.GetFileName(sourcePdf)), "encrypted extracted PDF is readable");

        AddMouseSamplesUntilEntropyReady();
        ProcessResult threefishAddResult = await zpaq.AddStreamingAsync(
            [sourcePdf],
            1,
            (zpaqStream, ct) => kalyna.EncryptZpaqStreamAsync(
                zpaqStream,
                threefishArchive,
                password,
                pin,
                firstGeneratedPassword,
                secondGeneratedPassword,
                EncryptionSuite.Threefish1024,
                "Threefish test hint",
                null,
                ct),
            null,
            CancellationToken.None);
        Assert(threefishAddResult.Succeeded, "streaming ZPAQ add into Threefish container");
        AssertContainerHeader(threefishArchive, EncryptionSuite.Threefish1024);
        KalynaContainerInfo threefishInfo = await kalyna.ReadContainerInfoAsync(threefishArchive, CancellationToken.None);
        Assert(threefishInfo.Version == 12
            && threefishInfo.Suite == EncryptionSuite.Threefish1024
            && threefishInfo.NonceBits == 1024
            && threefishInfo.SaltBits == 1024,
            "v12 Threefish suite metadata");

        ProcessResult threefishList = await zpaq.ListStreamingAsync(
            (zpaqInput, ct) => kalyna.DecryptToStreamAsync(threefishArchive, password, pin, firstGeneratedPassword, secondGeneratedPassword, zpaqInput, null, ct),
            null,
            CancellationToken.None);
        Assert(threefishList.Succeeded, "Threefish encrypted streaming container lists");
        Assert(threefishList.StandardError.Contains("versions", StringComparison.OrdinalIgnoreCase), "Threefish list scans the streaming pipe directly");
        ProcessResult threefishExtract = await zpaq.ExtractStreamingAsync(
            (zpaqInput, ct) => kalyna.DecryptToStreamAsync(threefishArchive, password, pin, firstGeneratedPassword, secondGeneratedPassword, zpaqInput, null, ct),
            threefishExtractDir,
            null,
            CancellationToken.None);
        Assert(threefishExtract.Succeeded, "Threefish container streams into ZPAQ extractor");
        Assert(threefishExtract.StandardError.Contains("streaming segments", StringComparison.OrdinalIgnoreCase), "Threefish extraction uses the bounded-memory one-pass ZPAQ path");
        await AssertExtractedPdfHashAsync(threefishExtractDir, Path.GetFileName(sourcePdf), originalHash, "Threefish roundtrip PDF hash");
        await AssertPdfReadableAsync(Path.Combine(threefishExtractDir, Path.GetFileName(sourcePdf)), "Threefish extracted PDF is readable");

        await pdfRecovery.CreateAuthenticatedAsync(
            encryptedArchive,
            password,
            pin,
            firstGeneratedPassword,
            secondGeneratedPassword,
            null,
            CancellationToken.None);
        await CorruptRangeAsync(encryptedArchive, 0, 4096);
        RecoveryRepairResult encryptedPdfRecovery = await pdfRecovery.VerifyAndRepairAuthenticatedAsync(
            encryptedArchive,
            password,
            pin,
            firstGeneratedPassword,
            secondGeneratedPassword,
            null,
            CancellationToken.None);
        Assert(
            encryptedPdfRecovery.Repaired
            && encryptedPdfRecovery.Authenticated
            && encryptedPdfRecovery.OutputPath is not null,
            "Kalyna sample PDF container is reconstructed only after dual KPAR2 authentication");
        ProcessResult recoveredEncryptedExtract = await zpaq.ExtractStreamingAsync(
            (zpaqInput, ct) => kalyna.DecryptToStreamAsync(
                encryptedPdfRecovery.OutputPath!,
                password,
                pin,
                firstGeneratedPassword,
                secondGeneratedPassword,
                zpaqInput,
                null,
                ct),
            encryptedRecoveredExtractDir,
            null,
            CancellationToken.None);
        Assert(recoveredEncryptedExtract.Succeeded, "KPAR2-recovered Kalyna PDF container extracts");
        await AssertExtractedPdfHashAsync(
            encryptedRecoveredExtractDir,
            Path.GetFileName(sourcePdf),
            originalHash,
            "KPAR2-recovered encrypted PDF hash");
        await AssertPdfReadableAsync(
            Path.Combine(encryptedRecoveredExtractDir, Path.GetFileName(sourcePdf)),
            "KPAR2-recovered encrypted PDF is readable");
        AssertNoNewPlaintextTempZpaq(tempAuditStart);
        Assert(
            SecureMemory.LockedAllocationsForTests == lockedLeaseBaseline,
            // Leases, not bytes: see SecureMemory.LockedAllocationsForTests.
            // Two round trips replace the nine entropy pools many times over,
            // and each replacement may span one page or two.
            "both encrypted PDF roundtrips release every managed VirtualLock lease");
    }
    finally
    {
        DeleteTestDirectory(root);
    }
}

static async Task RunMixedSampleRoundTripTestsAsync()
{
    string root = Path.Combine(Path.GetTempPath(), $"kalyna-mixed-e2e-{Guid.NewGuid():N}");
    string inputDirectory = Path.Combine(root, "input");
    string nestedDirectory = Path.Combine(inputDirectory, "nested");
    Directory.CreateDirectory(nestedDirectory);

    byte[] compressibleData = new byte[(2 * 1024 * 1024) + 17];
    byte[] randomData = RandomNumberGenerator.GetBytes((2 * 1024 * 1024) + 137);
    var expected = new Dictionary<string, (long Length, byte[] Hash)>(StringComparer.OrdinalIgnoreCase);

    try
    {
        for (int index = 0; index < compressibleData.Length; index++)
        {
            compressibleData[index] = (byte)(index % 251);
        }

        await File.WriteAllTextAsync(
            Path.Combine(inputDirectory, "utf8-text.txt"),
            "UTF-8 example: Gr\u00fc\u00dfe, Stra\u00dfe, \u00c4pfel, \u20ac and \u03a9.\r\n",
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        await File.WriteAllBytesAsync(Path.Combine(inputDirectory, "empty.dat"), []);
        await File.WriteAllBytesAsync(Path.Combine(inputDirectory, "compressible.bin"), compressibleData);
        await File.WriteAllBytesAsync(Path.Combine(nestedDirectory, "random.bin"), randomData);

        foreach (string source in Directory.EnumerateFiles(inputDirectory, "*", SearchOption.AllDirectories))
        {
            string relativePath = Path.GetRelativePath(inputDirectory, source);
            expected.Add(relativePath, (new FileInfo(source).Length, await Sha3FileAsync(source)));
        }

        var zpaq = new ZpaqService();
        var container = new KalynaContainerService();
        var archiveIntegrity = new ArchiveIntegrityService();
        string plainArchive = Path.Combine(root, "mixed.zpaq");
        string kalynaArchive = Path.Combine(root, "mixed-kalyna.kzpaq");
        string threefishArchive = Path.Combine(root, "mixed-threefish.kzpaq");

        ProcessResult plainAdd = await zpaq.AddAsync(plainArchive, [inputDirectory], 1, null, CancellationToken.None);
        Assert(plainAdd.Succeeded, "plain mixed sample archive creation");
        AssertZpaqHeader(plainArchive, "plain mixed sample archive has a ZPAQ header");
        await archiveIntegrity.CreateAsync(plainArchive, CancellationToken.None);
        await archiveIntegrity.VerifyAsync(plainArchive, CancellationToken.None);
        using (ArchiveIntegrityLease lease = await archiveIntegrity.AcquireVerifiedAsync(plainArchive, CancellationToken.None))
        {
            bool writeDenied = false;
            try
            {
                using var writeAttempt = new FileStream(plainArchive, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
            }
            catch (IOException)
            {
                writeDenied = true;
            }

            Assert(writeDenied, "verified plain-archive lease prevents replacement until ZPAQ completes");
        }

        string archiveAlias = Path.Combine(root, "mixed-alias.zpaq");
        bool archiveAliasCreated = false;
        try
        {
            File.CreateSymbolicLink(archiveAlias, plainArchive);
            archiveAliasCreated = true;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or PlatformNotSupportedException)
        {
            // Windows without Developer Mode may forbid unprivileged file symlink creation.
        }

        try
        {
            if (archiveAliasCreated)
            {
                File.Copy(plainArchive + ".sha3", archiveAlias + ".sha3");
                File.Copy(plainArchive + ".skein", archiveAlias + ".skein");
                await AssertThrowsAsync<IOException>(
                    () => archiveIntegrity.VerifyAsync(archiveAlias, CancellationToken.None),
                    "plain-archive symlink alias is rejected between verification and ZPAQ launch");
            }
        }
        finally
        {
            File.Delete(archiveAlias);
            File.Delete(archiveAlias + ".sha3");
            File.Delete(archiveAlias + ".skein");
        }

        string damagedPlainArchive = Path.Combine(root, "mixed-damaged.zpaq");
        File.Copy(plainArchive, damagedPlainArchive);
        File.Copy(plainArchive + ".sha3", damagedPlainArchive + ".sha3");
        File.Copy(plainArchive + ".skein", damagedPlainArchive + ".skein");
        await FlipLastByteAsync(damagedPlainArchive);
        await AssertThrowsAsync<InvalidDataException>(
            () => archiveIntegrity.VerifyAsync(damagedPlainArchive, CancellationToken.None),
            "plain ZPAQ corruption is rejected by the dual manifest");

        string missingSkeinArchive = Path.Combine(root, "mixed-missing-skein.zpaq");
        File.Copy(plainArchive, missingSkeinArchive);
        File.Copy(plainArchive + ".sha3", missingSkeinArchive + ".sha3");
        await AssertThrowsAsync<InvalidDataException>(
            () => archiveIntegrity.VerifyAsync(missingSkeinArchive, CancellationToken.None),
            "plain ZPAQ without its Skein-1024 manifest is rejected");

        string oversizedManifestArchive = Path.Combine(root, "mixed-oversized-manifest.zpaq");
        File.Copy(plainArchive, oversizedManifestArchive);
        File.Copy(plainArchive + ".sha3", oversizedManifestArchive + ".sha3");
        await File.WriteAllTextAsync(oversizedManifestArchive + ".skein", new string('A', 4097));
        await AssertThrowsAsync<InvalidDataException>(
            () => archiveIntegrity.VerifyAsync(oversizedManifestArchive, CancellationToken.None),
            "oversized archive manifest is rejected before unbounded allocation");
        string plainOutput = Path.Combine(root, "plain-output");
        ProcessResult plainExtract = await zpaq.ExtractAsync(plainArchive, plainOutput, null, CancellationToken.None);
        Assert(plainExtract.Succeeded, "plain mixed sample extraction");
        await AssertSampleTreeAsync(plainOutput, Path.GetFileName(inputDirectory), expected, "plain ZPAQ");

        AddMouseSamplesUntilEntropyReady();
        ProcessResult kalynaAdd = await zpaq.AddStreamingAsync(
            [inputDirectory],
            1,
            (zpaqStream, ct) => container.EncryptZpaqStreamAsync(
                zpaqStream,
                kalynaArchive,
                TestConstants.TestUserPassword,
                TestConstants.TestPin,
                TestGeneratedPassword(),
                TestGeneratedPassword('B'),
                EncryptionSuite.Kalyna512_512,
                "mixed sample test",
                null,
                ct),
            null,
            CancellationToken.None);
        Assert(kalynaAdd.Succeeded, "Kalyna mixed sample archive creation");
        AssertContainerHeader(kalynaArchive, EncryptionSuite.Kalyna512_512);
        string kalynaOutput = Path.Combine(root, "kalyna-output");
        ProcessResult kalynaExtract = await zpaq.ExtractStreamingAsync(
            (zpaqInput, ct) => container.DecryptToStreamAsync(
                kalynaArchive,
                TestConstants.TestUserPassword,
                TestConstants.TestPin,
                TestGeneratedPassword(),
                TestGeneratedPassword('B'),
                zpaqInput,
                null,
                ct),
            kalynaOutput,
            null,
            CancellationToken.None);
        Assert(kalynaExtract.Succeeded, "Kalyna mixed sample extraction");
        await AssertSampleTreeAsync(kalynaOutput, Path.GetFileName(inputDirectory), expected, "Kalyna");

        AddMouseSamplesUntilEntropyReady();
        ProcessResult threefishAdd = await zpaq.AddStreamingAsync(
            [inputDirectory],
            1,
            (zpaqStream, ct) => container.EncryptZpaqStreamAsync(
                zpaqStream,
                threefishArchive,
                TestConstants.TestUserPassword,
                TestConstants.TestPin,
                TestGeneratedPassword(),
                TestGeneratedPassword('B'),
                EncryptionSuite.Threefish1024,
                "mixed sample test",
                null,
                ct),
            null,
            CancellationToken.None);
        Assert(threefishAdd.Succeeded, "Threefish mixed sample archive creation");
        AssertContainerHeader(threefishArchive, EncryptionSuite.Threefish1024);
        string threefishOutput = Path.Combine(root, "threefish-output");
        ProcessResult threefishExtract = await zpaq.ExtractStreamingAsync(
            (zpaqInput, ct) => container.DecryptToStreamAsync(
                threefishArchive,
                TestConstants.TestUserPassword,
                TestConstants.TestPin,
                TestGeneratedPassword(),
                TestGeneratedPassword('B'),
                zpaqInput,
                null,
                ct),
            threefishOutput,
            null,
            CancellationToken.None);
        Assert(threefishExtract.Succeeded, "Threefish mixed sample extraction");
        await AssertSampleTreeAsync(threefishOutput, Path.GetFileName(inputDirectory), expected, "Threefish");
    }
    finally
    {
        CryptographicOperations.ZeroMemory(compressibleData);
        CryptographicOperations.ZeroMemory(randomData);
        foreach ((long _, byte[] hash) in expected.Values)
        {
            CryptographicOperations.ZeroMemory(hash);
        }

        DeleteTestDirectory(root);
    }
}

static async Task AssertSampleTreeAsync(
    string outputDirectory,
    string archivedRootName,
    IReadOnlyDictionary<string, (long Length, byte[] Hash)> expected,
    string label)
{
    string extractedRoot = Path.Combine(outputDirectory, archivedRootName);
    Assert(Directory.Exists(extractedRoot), $"{label} restores the sample root directory");

    string[] extractedFiles = Directory.EnumerateFiles(extractedRoot, "*", SearchOption.AllDirectories)
        .Select(path => Path.GetRelativePath(extractedRoot, path))
        .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
        .ToArray();
    string[] expectedFiles = expected.Keys.OrderBy(path => path, StringComparer.OrdinalIgnoreCase).ToArray();
    Assert(
        extractedFiles.SequenceEqual(expectedFiles, StringComparer.OrdinalIgnoreCase),
        $"{label} restores exactly the expected sample files");

    foreach ((string relativePath, (long expectedLength, byte[] expectedHash)) in expected)
    {
        string extractedPath = Path.Combine(extractedRoot, relativePath);
        Assert(new FileInfo(extractedPath).Length == expectedLength, $"{label} preserves the length of {relativePath}");
        byte[] actualHash = await Sha3FileAsync(extractedPath);
        try
        {
            Assert(
                CryptographicOperations.FixedTimeEquals(expectedHash, actualHash),
                $"{label} preserves the SHA3-512 hash of {relativePath}");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actualHash);
        }
    }
}

static async Task RunLargeStreamingContainerTestAsync()
{
    const string password = TestUserPassword;
    string firstGeneratedPassword = TestGeneratedPassword();
    string secondGeneratedPassword = TestGeneratedPassword('B');
    string root = Path.Combine(Path.GetTempPath(), $"kalyna-large-e2e-{Guid.NewGuid():N}");
    DateTime tempAuditStart = DateTime.UtcNow;
    Directory.CreateDirectory(root);

    try
    {
        string source = Path.Combine(root, "large-random.bin");
        byte[] data = new byte[BufferSizeForTest()];
        RandomNumberGenerator.Fill(data);
        await File.WriteAllBytesAsync(source, data);
        byte[] originalHash = SHA3_512.HashData(data);
        CryptographicOperations.ZeroMemory(data);

        var zpaq = new ZpaqService();
        var kalyna = new KalynaContainerService();
        string encryptedArchive = Path.Combine(root, "large.kzpaq");
        string extractDir = Path.Combine(root, "extract");

        AddMouseSamplesUntilEntropyReady();
        ProcessResult addResult = await zpaq.AddStreamingAsync(
            [source],
            1,
            (zpaqStream, ct) => kalyna.EncryptZpaqStreamAsync(zpaqStream, encryptedArchive, password, TestConstants.TestPin, firstGeneratedPassword, secondGeneratedPassword, EncryptionSuite.Threefish1024, null, null, ct),
            null,
            CancellationToken.None);
        Assert(addResult.Succeeded, "large ZPAQ pipe add into encrypted container");
        Assert(new FileInfo(encryptedArchive).Length > 1024 * 1024, "large encrypted archive crosses streaming chunk boundary");

        ProcessResult extractResult = await zpaq.ExtractStreamingAsync(
            (zpaqInput, ct) => kalyna.DecryptToStreamAsync(encryptedArchive, password, TestConstants.TestPin, firstGeneratedPassword, secondGeneratedPassword, zpaqInput, null, ct),
            extractDir,
            null,
            CancellationToken.None);
        Assert(extractResult.Succeeded, "large encrypted ZPAQ streams into extractor");
        Assert(extractResult.StandardError.Contains("streaming segments", StringComparison.OrdinalIgnoreCase), "large extraction stays on the one-pass native pipe path");
        byte[] extractedHash = await Sha3FileAsync(Path.Combine(extractDir, Path.GetFileName(source)));
        Assert(CryptographicOperations.FixedTimeEquals(originalHash, extractedHash), "large streaming encrypted roundtrip hash");
        AssertNoNewPlaintextTempZpaq(tempAuditStart);
    }
    finally
    {
        DeleteTestDirectory(root);
    }
}

static async Task RunShortReadKalynaStreamTestAsync()
{
    const string password = TestConstants.TestUserPassword;
    const string pin = TestConstants.TestPin;
    string firstGeneratedPassword = TestGeneratedPassword();
    string secondGeneratedPassword = TestGeneratedPassword('B');
    string root = Path.Combine(Path.GetTempPath(), $"kalyna-short-read-{Guid.NewGuid():N}");
    Directory.CreateDirectory(root);

    try
    {
        byte[] data = new byte[(2 * 1024 * 1024) + 333];
        RandomNumberGenerator.Fill(data);
        byte[] originalHash = SHA3_512.HashData(data);
        string encryptedArchive = Path.Combine(root, "short-read.kzpaq");

        var kalyna = new KalynaContainerService();
        AddMouseSamplesUntilEntropyReady();
        await using (var shortRead = new ShortReadStream(data, maxRead: 1000))
        {
            await kalyna.EncryptZpaqStreamAsync(shortRead, encryptedArchive, password, pin, firstGeneratedPassword, secondGeneratedPassword, EncryptionSuite.Threefish1024, null, null, CancellationToken.None);
        }

        await using var decrypted = new MemoryStream();
        await kalyna.DecryptToStreamAsync(encryptedArchive, password, pin, firstGeneratedPassword, secondGeneratedPassword, decrypted, null, CancellationToken.None);
        byte[] decryptedBytes = decrypted.ToArray();
        byte[] decryptedHash = SHA3_512.HashData(decryptedBytes);
        try
        {
            Assert(CryptographicOperations.FixedTimeEquals(originalHash, decryptedHash), "short-read encrypted stream roundtrip hash");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(data);
            CryptographicOperations.ZeroMemory(originalHash);
            CryptographicOperations.ZeroMemory(decryptedBytes);
            CryptographicOperations.ZeroMemory(decryptedHash);
        }
    }
    finally
    {
        DeleteTestDirectory(root);
    }
}

static async Task RunRecoveryTestsAsync()
{
    string root = Path.Combine(Path.GetTempPath(), $"kalyna-recovery-{Guid.NewGuid():N}");
    Directory.CreateDirectory(root);

    try
    {
        var recovery = new RecoveryService();
        string archive = Path.Combine(root, "plain.zpaq");
        byte[] plainBytes = new byte[(3 * 1024 * 1024) + 12345];
        RandomNumberGenerator.Fill(plainBytes);
        await File.WriteAllBytesAsync(archive, plainBytes);
        byte[] originalPlainHash = SHA3_512.HashData(plainBytes);
        CryptographicOperations.ZeroMemory(plainBytes);

        string cancelledArchive = Path.Combine(root, "cancelled-recovery.zpaq");
        File.Copy(archive, cancelledArchive);
        using (var cancellation = new CancellationTokenSource())
        {
            var cancelOnProgress = new InlineProgress<string>(_ => cancellation.Cancel());
            await AssertThrowsAsync<OperationCanceledException>(
                () => recovery.CreateAsync(cancelledArchive, cancelOnProgress, cancellation.Token),
                "cancelled recovery creation reports cancellation");
        }

        Assert(!File.Exists(RecoveryService.GetRecoveryPath(cancelledArchive)), "cancelled recovery does not install a sidecar");
        Assert(
            !Directory.EnumerateFiles(root, "*.recovery-part", SearchOption.TopDirectoryOnly).Any(),
            "cancelled recovery securely removes temporary parity");

        bool archiveWriteDeniedDuringRecoveryCreation = false;
        var creationLockProbe = new InlineProgress<string>(_ =>
        {
            if (archiveWriteDeniedDuringRecoveryCreation)
            {
                return;
            }

            try
            {
                using var writeAttempt = new FileStream(archive, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
            }
            catch (IOException)
            {
                archiveWriteDeniedDuringRecoveryCreation = true;
            }
        });
        string recoveryPath = await recovery.CreateAsync(archive, creationLockProbe, CancellationToken.None);
        Assert(File.Exists(recoveryPath) && new FileInfo(recoveryPath).Length > 0, "plain recovery file exists");
        Assert(archiveWriteDeniedDuringRecoveryCreation, "recovery creation holds one immutable archive handle for hashing and parity");
        Assert(
            await recovery.TryReadProtectionModeAsync(archive, CancellationToken.None)
                == RecoveryProtectionMode.ErrorCorrectionOnly,
            "plain KPAR2 is explicitly marked as error correction only");

        byte[] recoveryBeforeCommitGateFailure = await File.ReadAllBytesAsync(recoveryPath);
        RecoveryService.SidecarHookBeforeCommitValidation = generated =>
        {
            const long firstBodyParityByte = 4L * 4096;
            generated.Position = firstBodyParityByte;
            int originalByte = generated.ReadByte();
            Assert(originalByte >= 0, "generated KPAR2 parity fixture is long enough");
            generated.Position = firstBodyParityByte;
            generated.WriteByte((byte)(originalByte ^ 0x01));
            generated.Flush(flushToDisk: true);
        };
        try
        {
            await AssertThrowsAsync<InvalidDataException>(
                () => recovery.CreateAsync(archive, null, CancellationToken.None),
                "full KPAR2 commit gate rejects corruption outside the locator and metadata regions");
        }
        finally
        {
            RecoveryService.SidecarHookBeforeCommitValidation = null;
        }

        byte[] recoveryAfterCommitGateFailure = await File.ReadAllBytesAsync(recoveryPath);
        Assert(
            CryptographicOperations.FixedTimeEquals(
                recoveryBeforeCommitGateFailure,
                recoveryAfterCommitGateFailure),
            "failed full KPAR2 commit validation leaves the previous known-good sidecar unchanged");
        Assert(
            !Directory.EnumerateFiles(root, "*.recovery-part", SearchOption.TopDirectoryOnly).Any(),
            "failed full KPAR2 commit validation securely removes the generated sidecar");
        CryptographicOperations.ZeroMemory(recoveryBeforeCommitGateFailure);
        CryptographicOperations.ZeroMemory(recoveryAfterCommitGateFailure);

        string stolenOldSidecar = Path.Combine(root, "stolen-old-sidecar.kpar2");
        string stolenGeneratedSidecar = Path.Combine(root, "stolen-generated-sidecar.kpar2");
        RecoveryService.SidecarHookBeforeOldQuarantineRename = () =>
            AssertThrows<IOException>(
                () => File.Move(recoveryPath, stolenOldSidecar),
                "the bound previous KPAR2 object cannot be renamed behind the transaction");
        RecoveryService.SidecarHookBeforeInstallRename = () =>
        {
            string generatedPath = Directory.GetFiles(
                root,
                "*.recovery-part",
                SearchOption.TopDirectoryOnly).Single();
            AssertThrows<IOException>(
                () => File.Move(generatedPath, stolenGeneratedSidecar),
                "the bound generated KPAR2 object cannot be renamed behind the transaction");
        };
        try
        {
            await recovery.CreateAsync(archive, null, CancellationToken.None);
        }
        finally
        {
            RecoveryService.SidecarHookBeforeOldQuarantineRename = null;
            RecoveryService.SidecarHookBeforeInstallRename = null;
        }
        Assert(
            !File.Exists(stolenOldSidecar) && !File.Exists(stolenGeneratedSidecar),
            "Windows KPAR2 holds both source objects through their handle-bound renames");

        byte[] transactionBaseline = await File.ReadAllBytesAsync(recoveryPath);

        RecoveryService.SidecarHookAfterQuarantine =
            () => throw new IOException("injected: after KPAR2 quarantine");
        try
        {
            await AssertThrowsAsync<IOException>(
                () => recovery.CreateAsync(archive, null, CancellationToken.None),
                "KPAR2 rollback surfaces a failure after quarantining the previous sidecar");
        }
        finally
        {
            RecoveryService.SidecarHookAfterQuarantine = null;
        }

        byte[] afterQuarantineRollback = await File.ReadAllBytesAsync(recoveryPath);
        Assert(
            CryptographicOperations.FixedTimeEquals(transactionBaseline, afterQuarantineRollback),
            "KPAR2 rollback restores the exact previous sidecar after quarantine failure");
        Assert(
            !Directory.EnumerateFiles(root, "*.previous", SearchOption.TopDirectoryOnly).Any(),
            "KPAR2 quarantine rollback leaves no stale previous-sidecar name");

        RecoveryService.SidecarHookAfterInstall =
            () => throw new IOException("injected: after KPAR2 install");
        try
        {
            await AssertThrowsAsync<IOException>(
                () => recovery.CreateAsync(archive, null, CancellationToken.None),
                "KPAR2 rollback surfaces a failure after installing the validated sidecar");
        }
        finally
        {
            RecoveryService.SidecarHookAfterInstall = null;
        }

        byte[] afterInstallRollback = await File.ReadAllBytesAsync(recoveryPath);
        Assert(
            CryptographicOperations.FixedTimeEquals(transactionBaseline, afterInstallRollback),
            "KPAR2 rollback restores the exact previous sidecar after install failure");
        Assert(
            !Directory.EnumerateFiles(root, "*.previous", SearchOption.TopDirectoryOnly).Any()
                && !Directory.EnumerateFiles(root, "*.failed-new", SearchOption.TopDirectoryOnly).Any(),
            "KPAR2 install rollback removes only its bound failed-new object");

        RecoveryService.SidecarHookBeforeBackupDestruction = generated =>
        {
            long[] locatorOffsets =
            [
                0,
                4096,
                2L * 4096,
                3L * 4096,
                generated.Length - (4L * 4096),
            ];
            foreach (long offset in locatorOffsets)
            {
                generated.Position = offset;
                int originalByte = generated.ReadByte();
                Assert(originalByte >= 0, "final KPAR2 mutation fixture is long enough");
                generated.Position = offset;
                generated.WriteByte((byte)(originalByte ^ 0x80));
            }

            generated.Flush(flushToDisk: true);
        };
        try
        {
            await AssertThrowsAsync<InvalidDataException>(
                () => recovery.CreateAsync(archive, null, CancellationToken.None),
                "final KPAR2 commit gate rejects an in-place mutation after the first installed-object validation");
        }
        finally
        {
            RecoveryService.SidecarHookBeforeBackupDestruction = null;
        }

        byte[] afterFinalCommitValidationRollback = await File.ReadAllBytesAsync(recoveryPath);
        Assert(
            CryptographicOperations.FixedTimeEquals(transactionBaseline, afterFinalCommitValidationRollback),
            "final KPAR2 commit-validation failure restores the exact previous sidecar");
        Assert(
            !Directory.EnumerateFiles(root, "*.previous", SearchOption.TopDirectoryOnly).Any()
                && !Directory.EnumerateFiles(root, "*.failed-new", SearchOption.TopDirectoryOnly).Any()
                && !Directory.EnumerateFiles(root, "*.recovery-part", SearchOption.TopDirectoryOnly).Any(),
            "final KPAR2 commit-validation rollback leaves no transaction objects");

        RecoveryService.SidecarHookAfterQuarantine =
            () => File.WriteAllBytes(recoveryPath, [0xD1]);
        try
        {
            await AssertThrowsAsync<IOException>(
                () => recovery.CreateAsync(archive, null, CancellationToken.None),
                "KPAR2 exclusive install refuses a competing final-name object");
        }
        finally
        {
            RecoveryService.SidecarHookAfterQuarantine = null;
        }

        string[] collisionBackups = Directory.GetFiles(
            root,
            "*.previous",
            SearchOption.TopDirectoryOnly);
        Assert(
            collisionBackups.Length == 1
                && File.ReadAllBytes(recoveryPath) is [0xD1],
            "KPAR2 collision rollback preserves both the foreign target and one previous-sidecar quarantine");
        byte[] collisionBackupBytes = await File.ReadAllBytesAsync(collisionBackups[0]);
        Assert(
            CryptographicOperations.FixedTimeEquals(transactionBaseline, collisionBackupBytes),
            "KPAR2 collision quarantine still contains the exact previous sidecar");
        File.Delete(recoveryPath);
        File.Move(collisionBackups[0], recoveryPath);

        RecoveryService.SidecarHookBeforePostCommitBackupCleanup =
            () => throw new IOException("injected: during KPAR2 backup cleanup");
        try
        {
            await AssertThrowsAsync<IOException>(
                () => recovery.CreateAsync(archive, null, CancellationToken.None),
                "a post-commit KPAR2 backup-destruction failure remains observable");
        }
        finally
        {
            RecoveryService.SidecarHookBeforePostCommitBackupCleanup = null;
        }

        byte[] postCommitSidecar = await File.ReadAllBytesAsync(recoveryPath);
        string[] postCommitBackups = Directory.GetFiles(
            root,
            "*.previous",
            SearchOption.TopDirectoryOnly);
        Assert(
            !CryptographicOperations.FixedTimeEquals(transactionBaseline, postCommitSidecar)
                && postCommitBackups.Length == 1,
            "post-commit backup failure keeps the validated new KPAR2 installed and preserves the old one");
        byte[] postCommitBackupBytes = await File.ReadAllBytesAsync(postCommitBackups[0]);
        Assert(
            CryptographicOperations.FixedTimeEquals(transactionBaseline, postCommitBackupBytes),
            "the post-commit KPAR2 quarantine is the exact old sidecar");
        File.Delete(postCommitBackups[0]);

        CryptographicOperations.ZeroMemory(transactionBaseline);
        CryptographicOperations.ZeroMemory(afterQuarantineRollback);
        CryptographicOperations.ZeroMemory(afterInstallRollback);
        CryptographicOperations.ZeroMemory(afterFinalCommitValidationRollback);
        CryptographicOperations.ZeroMemory(collisionBackupBytes);
        CryptographicOperations.ZeroMemory(postCommitSidecar);
        CryptographicOperations.ZeroMemory(postCommitBackupBytes);

        string replacedRecoveryPath = await recovery.CreateAsync(archive, null, CancellationToken.None);
        Assert(
            replacedRecoveryPath == recoveryPath && new FileInfo(recoveryPath).Length > 0,
            "recovery sidecar replacement installs one complete non-empty file");
        Assert(
            !Directory.EnumerateFiles(root, "*.recovery-part", SearchOption.TopDirectoryOnly).Any(),
            "recovery sidecar replacement leaves no partial parity file");

        RecoveryRepairResult healthyEmergency = await recovery.RecoverToNewFileAsync(
            archive,
            null,
            CancellationToken.None);
        Assert(
            healthyEmergency.EmergencyMode
            && healthyEmergency.ArchiveHealthy
            && !healthyEmergency.Repaired
            && healthyEmergency.OutputPath is not null
            && !string.Equals(healthyEmergency.OutputPath, archive, StringComparison.OrdinalIgnoreCase),
            "emergency mode writes a new file even when the source archive is healthy");
        byte[] healthyEmergencyHash = await Sha3FileAsync(healthyEmergency.OutputPath!);
        Assert(
            CryptographicOperations.FixedTimeEquals(originalPlainHash, healthyEmergencyHash),
            "healthy emergency copy matches the original archive");
        await new ArchiveIntegrityService().VerifyAsync(
            healthyEmergency.OutputPath!,
            CancellationToken.None);
        Assert(
            File.Exists(ArchiveIntegrityService.GetSha3ManifestPath(healthyEmergency.OutputPath!))
            && File.Exists(ArchiveIntegrityService.GetSkeinManifestPath(healthyEmergency.OutputPath!)),
            "plain emergency output receives both required integrity manifests");
        CryptographicOperations.ZeroMemory(healthyEmergencyHash);

        string hardLinkArchive = Path.Combine(root, "hardlink-guard.zpaq");
        File.Copy(healthyEmergency.OutputPath!, hardLinkArchive);
        string hardLinkTarget = Path.Combine(root, "must-not-be-overwritten.bin");
        byte[] hardLinkTargetBytes = RandomNumberGenerator.GetBytes(8192);
        byte[] hardLinkTargetHash = SHA3_512.HashData(hardLinkTargetBytes);
        await File.WriteAllBytesAsync(hardLinkTarget, hardLinkTargetBytes);
        CryptographicOperations.ZeroMemory(hardLinkTargetBytes);
        string hostileSidecarLink = RecoveryService.GetRecoveryPath(hardLinkArchive);
        Assert(
            TestNativeFileLinks.CreateHardLink(hostileSidecarLink, hardLinkTarget, nint.Zero),
            "test fixture creates a hostile hard-linked KPAR2 target");
        // Replacement includes secure destruction of the previous sidecar.
        // A second link would keep those sensitive parity bytes alive under an
        // untracked name, so both platforms now refuse it before quarantine.
        await AssertThrowsAsync<IOException>(
            () => recovery.CreateAsync(hardLinkArchive, null, CancellationToken.None),
            "KPAR2 replacement refuses a multiply linked previous sidecar");
        byte[] hardLinkTargetAfterHash = await Sha3FileAsync(hardLinkTarget);
        Assert(
            File.Exists(hostileSidecarLink)
            && CryptographicOperations.FixedTimeEquals(hardLinkTargetHash, hardLinkTargetAfterHash),
            "hard-link refusal leaves both names and the linked file byte-for-byte unchanged");
        CryptographicOperations.ZeroMemory(hardLinkTargetHash);
        CryptographicOperations.ZeroMemory(hardLinkTargetAfterHash);
        File.Delete(hostileSidecarLink);

        await CorruptRangeAsync(recoveryPath, 0, 4096);
        await CorruptRangeAsync(recoveryPath, 4096, 4096);
        await CorruptRangeAsync(recoveryPath, 8192, 4096);
        await CorruptRangeAsync(archive, 0, 4096);
        await CorruptRangeAsync(archive, 4096, 4096);
        await CorruptRangeAsync(archive, 8192, 4096);
        await CorruptRangeAsync(archive, 512 * 1024, 4096);
        await CorruptRangeAsync(archive, 1024 * 1024, 4096);
        await CorruptRangeAsync(archive, 1536 * 1024, 4096);
        bool recoveryWriteDeniedDuringRepair = false;
        var repairLockProbe = new InlineProgress<string>(_ =>
        {
            if (recoveryWriteDeniedDuringRepair)
            {
                return;
            }

            try
            {
                using var writeAttempt = new FileStream(recoveryPath, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
            }
            catch (IOException)
            {
                recoveryWriteDeniedDuringRepair = true;
            }
        });
        RecoveryRepairResult plainRepair = await recovery.VerifyAndRepairAsync(archive, repairLockProbe, CancellationToken.None);
        Assert(
            plainRepair.RecoveryAvailable
            && plainRepair.Repaired
            && plainRepair.RepairedShards >= 6
            && !plainRepair.Authenticated
            && plainRepair.ProtectionMode == RecoveryProtectionMode.ErrorCorrectionOnly,
            "plain archive header and body were repaired with three bad shards each without an authenticity claim");
        Assert(recoveryWriteDeniedDuringRepair, "repair holds the verified recovery file against replacement until repair finishes");
        Assert(
            plainRepair.OutputPath is not null
            && !string.Equals(plainRepair.OutputPath, archive, StringComparison.OrdinalIgnoreCase),
            "plain repair writes a conflict-safe new file");
        byte[] stillDamagedPlainHash = await Sha3FileAsync(archive);
        Assert(
            !CryptographicOperations.FixedTimeEquals(originalPlainHash, stillDamagedPlainHash),
            "plain repair leaves the damaged original unchanged");
        byte[] repairedPlainHash = await Sha3FileAsync(plainRepair.OutputPath!);
        Assert(CryptographicOperations.FixedTimeEquals(originalPlainHash, repairedPlainHash), "plain recovery restores original SHA3-512");
        await new ArchiveIntegrityService().VerifyAsync(plainRepair.OutputPath!, CancellationToken.None);
        CryptographicOperations.ZeroMemory(stillDamagedPlainHash);
        CryptographicOperations.ZeroMemory(repairedPlainHash);

        string mixedFailureArchive = Path.Combine(root, "mixed-data-parity.zpaq");
        byte[] mixedFailureBytes = RandomNumberGenerator.GetBytes(1024 * 1024);
        byte[] mixedFailureHash = SHA3_512.HashData(mixedFailureBytes);
        await File.WriteAllBytesAsync(mixedFailureArchive, mixedFailureBytes);
        CryptographicOperations.ZeroMemory(mixedFailureBytes);
        string mixedRecoveryPath = await recovery.CreateAsync(mixedFailureArchive, null, CancellationToken.None);
        await CorruptRangeAsync(mixedFailureArchive, 0, 4096);
        const int PrefixLocatorBytes = 4 * 4096;
        const int HeaderParityShardBytes = 4096;
        await CorruptRangeAsync(mixedRecoveryPath, PrefixLocatorBytes, HeaderParityShardBytes);
        await CorruptRangeAsync(mixedRecoveryPath, PrefixLocatorBytes + HeaderParityShardBytes, HeaderParityShardBytes);
        RecoveryRepairResult mixedRepair = await recovery.VerifyAndRepairAsync(mixedFailureArchive, null, CancellationToken.None);
        byte[] mixedRepairedHash = await Sha3FileAsync(mixedRepair.OutputPath!);
        try
        {
            Assert(mixedRepair.Repaired && mixedRepair.RepairedShards == 1, "one data shard is repaired with the one remaining valid parity row");
            Assert(CryptographicOperations.FixedTimeEquals(mixedFailureHash, mixedRepairedHash), "mixed data/parity failure restores the archive");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(mixedFailureHash);
            CryptographicOperations.ZeroMemory(mixedRepairedHash);
        }

        string candidateCleanupArchive = Path.Combine(root, "candidate-cleanup-race.zpaq");
        byte[] candidateCleanupBytes = RandomNumberGenerator.GetBytes(1024 * 1024);
        await File.WriteAllBytesAsync(candidateCleanupArchive, candidateCleanupBytes);
        CryptographicOperations.ZeroMemory(candidateCleanupBytes);
        await recovery.CreateAsync(candidateCleanupArchive, null, CancellationToken.None);
        for (int shardIndex = 0; shardIndex < 4; shardIndex++)
        {
            await CorruptRangeAsync(candidateCleanupArchive, shardIndex * 4096L, 4096);
        }

        string stolenCandidate = Path.Combine(root, "stolen-recovery-candidate.zpaq");
        string? failedCandidatePath = null;
        bool candidateRenameDenied = false;
        RecoveryService.RecoveryCandidateHookBeforeFailureCleanup = path =>
        {
            failedCandidatePath = path;
            try
            {
                File.Move(path, stolenCandidate);
            }
            catch (IOException)
            {
                candidateRenameDenied = true;
            }
        };
        try
        {
            await AssertThrowsAsync<InvalidDataException>(
                () => recovery.VerifyAndRepairAsync(candidateCleanupArchive, null, CancellationToken.None),
                "four damaged data shards fail after creating a bound recovery candidate");
        }
        finally
        {
            RecoveryService.RecoveryCandidateHookBeforeFailureCleanup = null;
        }

        Assert(
            failedCandidatePath is not null
                && candidateRenameDenied
                && !File.Exists(failedCandidatePath)
                && !File.Exists(stolenCandidate),
            "failed recovery cleanup keeps the candidate handle-bound through exact-object deletion");

        string metadataArchive = Path.Combine(root, "metadata-protection.zpaq");
        byte[] metadataBytes = RandomNumberGenerator.GetBytes(1024 * 1024);
        byte[] metadataHash = SHA3_512.HashData(metadataBytes);
        await File.WriteAllBytesAsync(metadataArchive, metadataBytes);
        CryptographicOperations.ZeroMemory(metadataBytes);
        string metadataRecoveryPath = await recovery.CreateAsync(metadataArchive, null, CancellationToken.None);
        long metadataOffset = await ReadKpar2MetadataOffsetAsync(metadataRecoveryPath);
        await CorruptRangeAsync(metadataRecoveryPath, metadataOffset, 4096);
        await CorruptRangeAsync(metadataRecoveryPath, metadataOffset + 4096, 4096);
        await CorruptRangeAsync(metadataRecoveryPath, metadataOffset + 8192, 4096);
        await CorruptRangeAsync(metadataArchive, 0, 4096);
        RecoveryRepairResult metadataRepair = await recovery.VerifyAndRepairAsync(metadataArchive, null, CancellationToken.None);
        byte[] metadataRepairedHash = await Sha3FileAsync(metadataRepair.OutputPath!);
        Assert(
            metadataRepair.Repaired
            && CryptographicOperations.FixedTimeEquals(metadataHash, metadataRepairedHash),
            "three failed 4096-byte metadata/certification blocks are RS-reconstructed before archive repair");
        CryptographicOperations.ZeroMemory(metadataHash);
        CryptographicOperations.ZeroMemory(metadataRepairedHash);

        string metadataLimitArchive = Path.Combine(root, "metadata-four-block-limit.zpaq");
        File.Copy(metadataRepair.OutputPath!, metadataLimitArchive);
        string metadataLimitRecovery = await recovery.CreateAsync(metadataLimitArchive, null, CancellationToken.None);
        long metadataLimitOffset = await ReadKpar2MetadataOffsetAsync(metadataLimitRecovery);
        for (int blockIndex = 0; blockIndex < 4; blockIndex++)
        {
            await CorruptRangeAsync(metadataLimitRecovery, metadataLimitOffset + (blockIndex * 4096L), 4096);
        }

        await AssertThrowsAsync<InvalidDataException>(
            () => recovery.VerifyAndRepairAsync(metadataLimitArchive, null, CancellationToken.None),
            "KPAR2 refuses four failed metadata data blocks in one RS(20,3) stripe");

        string locatorLimitArchive = Path.Combine(root, "locator-four-block-limit.zpaq");
        File.Copy(metadataRepair.OutputPath!, locatorLimitArchive);
        string locatorLimitRecovery = await recovery.CreateAsync(locatorLimitArchive, null, CancellationToken.None);
        for (int blockIndex = 0; blockIndex < 4; blockIndex++)
        {
            await CorruptRangeAsync(locatorLimitRecovery, blockIndex * 4096L, 4096);
        }

        await AssertThrowsAsync<InvalidDataException>(
            () => recovery.VerifyAndRepairAsync(locatorLimitArchive, null, CancellationToken.None),
            "KPAR2 locator consensus guarantees three, but deliberately rejects four, failed locator blocks");

        string lengthGuardArchive = Path.Combine(root, "length-guard.zpaq");
        byte[] lengthGuardBytes = RandomNumberGenerator.GetBytes(1024 * 1024);
        await File.WriteAllBytesAsync(lengthGuardArchive, lengthGuardBytes);
        CryptographicOperations.ZeroMemory(lengthGuardBytes);
        await recovery.CreateAsync(lengthGuardArchive, null, CancellationToken.None);
        await using (var truncate = new FileStream(lengthGuardArchive, FileMode.Open, FileAccess.Write, FileShare.None))
        {
            truncate.SetLength(truncate.Length - 4096);
        }

        long truncatedLength = new FileInfo(lengthGuardArchive).Length;
        await AssertThrowsAsync<InvalidDataException>(
            () => recovery.VerifyAndRepairAsync(lengthGuardArchive, null, CancellationToken.None),
            "KPAR2 refuses an untrusted sidecar's automatic archive-length change");
        Assert(new FileInfo(lengthGuardArchive).Length == truncatedLength, "KPAR2 length guard leaves the truncated archive untouched");

        AddMouseSamplesUntilEntropyReady();
        const string password = TestConstants.TestUserPassword;
        const string pin = TestConstants.TestPin;
        const string wrongPassword = "Q!m8$Ls2#Vx7%Tp4&Jd9*Wr5+Kn6=Zu3?Ce";
        string firstGeneratedPassword = TestGeneratedPassword();
        string secondGeneratedPassword = TestGeneratedPassword('B');
        byte[] containerPlain = new byte[(2 * 1024 * 1024) + 333];
        RandomNumberGenerator.Fill(containerPlain);
        byte[] containerPlainHash = SHA3_512.HashData(containerPlain);
        string encryptedArchive = Path.Combine(root, "encrypted.kzpaq");
        var kalyna = new KalynaContainerService();
        await using (var input = new MemoryStream(containerPlain, writable: false))
        {
            await kalyna.EncryptZpaqStreamAsync(input, encryptedArchive, password, pin, firstGeneratedPassword, secondGeneratedPassword, EncryptionSuite.Threefish1024, null, null, CancellationToken.None);
        }

        byte[] encryptedArchiveHash = await Sha3FileAsync(encryptedArchive);
        await AssertThrowsAsync<InvalidOperationException>(
            () => recovery.CreateAsync(encryptedArchive, null, CancellationToken.None),
            "encrypted containers cannot create an unauthenticated KPAR2 profile");

        string renamedPlainKzpaq = Path.Combine(root, "plain-profile-downgrade.kzpaq");
        File.Copy(metadataRepair.OutputPath!, renamedPlainKzpaq);
        File.Copy(
            RecoveryService.GetRecoveryPath(metadataArchive),
            RecoveryService.GetRecoveryPath(renamedPlainKzpaq));
        await AssertThrowsAsync<InvalidDataException>(
            () => recovery.VerifyAndRepairAsync(renamedPlainKzpaq, null, CancellationToken.None),
            "a .kzpaq path cannot be downgraded to the unauthenticated plain KPAR2 profile");

        string encryptedRecoveryPath = await recovery.CreateAuthenticatedAsync(
            encryptedArchive,
            password,
            pin,
            firstGeneratedPassword,
            secondGeneratedPassword,
            null,
            CancellationToken.None);
        Assert(
            await recovery.TryReadProtectionModeAsync(encryptedArchive, CancellationToken.None)
                == RecoveryProtectionMode.DualAuthenticatedEncrypted,
            "encrypted KPAR2 is explicitly marked dual authenticated");

        long encryptedMetadataOffset = await ReadKpar2MetadataOffsetAsync(encryptedRecoveryPath);
        await CorruptRangeAsync(encryptedRecoveryPath, encryptedMetadataOffset, 4096);
        await CorruptRangeAsync(encryptedRecoveryPath, encryptedMetadataOffset + 4096, 4096);
        await CorruptRangeAsync(encryptedRecoveryPath, encryptedMetadataOffset + 8192, 4096);
        RecoveryRepairResult metadataCertificationCheck = await recovery.VerifyAndRepairAuthenticatedAsync(
            encryptedArchive,
            password,
            pin,
            firstGeneratedPassword,
            secondGeneratedPassword,
            null,
            CancellationToken.None);
        Assert(
            metadataCertificationCheck.ArchiveHealthy
            && metadataCertificationCheck.Authenticated
            && !metadataCertificationCheck.Repaired,
            "three failed blocks containing encrypted KPAR2 certifications are reconstructed and dual-authenticated");

        await CorruptRangeAsync(encryptedArchive, 0, 4096);
        await CorruptRangeAsync(encryptedArchive, 512 * 1024, 4096);
        await CorruptRangeAsync(encryptedArchive, 1024 * 1024, 4096);
        await CorruptRangeAsync(encryptedArchive, 1536 * 1024, 4096);
        Assert(!await kalyna.LooksEncryptedAsync(encryptedArchive, CancellationToken.None), "encrypted header corruption breaks magic before recovery");

        byte[] damagedEncryptedHash = await Sha3FileAsync(encryptedArchive);
        await AssertThrowsAsync<CryptographicException>(
            () => recovery.VerifyAndRepairAuthenticatedAsync(
                encryptedArchive,
                wrongPassword,
                pin,
                firstGeneratedPassword,
                secondGeneratedPassword,
                null,
                CancellationToken.None),
            "wrong user password cannot authenticate encrypted KPAR2 metadata");
        byte[] afterWrongPasswordHash = await Sha3FileAsync(encryptedArchive);
        Assert(
            CryptographicOperations.FixedTimeEquals(damagedEncryptedHash, afterWrongPasswordHash),
            "failed KPAR2 authentication leaves the damaged original byte-for-byte unchanged");

        RecoveryRepairResult encryptedRepair = await recovery.VerifyAndRepairAuthenticatedAsync(
            encryptedArchive,
            password,
            pin,
            firstGeneratedPassword,
            secondGeneratedPassword,
            null,
            CancellationToken.None);
        Assert(
            encryptedRepair.Repaired
            && encryptedRepair.RepairedShards >= 4
            && encryptedRepair.Authenticated
            && encryptedRepair.OutputPath is not null,
            "encrypted container header and body are repaired only after dual KPAR2 authentication");
        Assert(
            !await kalyna.LooksEncryptedAsync(encryptedArchive, CancellationToken.None)
            && await kalyna.LooksEncryptedAsync(encryptedRepair.OutputPath!, CancellationToken.None),
            "authenticated recovery preserves the damaged original and emits a valid encrypted candidate");
        byte[] encryptedRepairedHash = await Sha3FileAsync(encryptedRepair.OutputPath!);
        Assert(
            CryptographicOperations.FixedTimeEquals(encryptedArchiveHash, encryptedRepairedHash),
            "authenticated encrypted recovery restores the exact container bytes");

        RecoveryRepairResult emergencyRepair = await recovery.RecoverToNewFileAuthenticatedAsync(
            encryptedArchive,
            password,
            pin,
            firstGeneratedPassword,
            secondGeneratedPassword,
            null,
            CancellationToken.None);
        Assert(
            emergencyRepair.EmergencyMode
            && !emergencyRepair.Authenticated
            && emergencyRepair.Repaired
            && emergencyRepair.OutputPath is not null
            && !string.Equals(emergencyRepair.OutputPath, encryptedArchive, StringComparison.OrdinalIgnoreCase),
            "unauthenticated emergency recovery is restricted to a new file");
        byte[] emergencyHash = await Sha3FileAsync(emergencyRepair.OutputPath!);
        Assert(
            CryptographicOperations.FixedTimeEquals(encryptedArchiveHash, emergencyHash),
            "encrypted emergency output passes the embedded container authentication and exact archive digest");
        byte[] originalAfterEmergencyHash = await Sha3FileAsync(encryptedArchive);
        Assert(
            CryptographicOperations.FixedTimeEquals(damagedEncryptedHash, originalAfterEmergencyHash),
            "encrypted emergency recovery never modifies the original");

        string transplantedTarget = Path.Combine(root, "transplanted-target.kzpaq");
        byte[] transplantedBytes = RandomNumberGenerator.GetBytes(checked((int)new FileInfo(encryptedArchive).Length));
        await File.WriteAllBytesAsync(transplantedTarget, transplantedBytes);
        byte[] transplantedOriginalHash = SHA3_512.HashData(transplantedBytes);
        CryptographicOperations.ZeroMemory(transplantedBytes);
        File.Copy(encryptedRecoveryPath, RecoveryService.GetRecoveryPath(transplantedTarget));
        await AssertThrowsAsync<InvalidDataException>(
            () => recovery.VerifyAndRepairAuthenticatedAsync(
                transplantedTarget,
                password,
                pin,
                firstGeneratedPassword,
                secondGeneratedPassword,
                null,
                CancellationToken.None),
            "authenticated sidecar transplantation cannot turn a different file into a verified archive");
        byte[] transplantedAfterHash = await Sha3FileAsync(transplantedTarget);
        Assert(
            CryptographicOperations.FixedTimeEquals(transplantedOriginalHash, transplantedAfterHash),
            "failed sidecar-transplant recovery leaves the target unchanged");

        await AssertThrowsAsync<InvalidOperationException>(
            () => recovery.VerifyAndRepairAuthenticatedAsync(
                metadataArchive,
                password,
                pin,
                firstGeneratedPassword,
                secondGeneratedPassword,
                null,
                CancellationToken.None),
            "plain error-correction KPAR2 cannot be upgraded to authenticated status by the caller");

        CryptographicOperations.ZeroMemory(containerPlain);
        CryptographicOperations.ZeroMemory(containerPlainHash);
        CryptographicOperations.ZeroMemory(originalPlainHash);
        CryptographicOperations.ZeroMemory(encryptedArchiveHash);
        CryptographicOperations.ZeroMemory(damagedEncryptedHash);
        CryptographicOperations.ZeroMemory(afterWrongPasswordHash);
        CryptographicOperations.ZeroMemory(encryptedRepairedHash);
        CryptographicOperations.ZeroMemory(emergencyHash);
        CryptographicOperations.ZeroMemory(originalAfterEmergencyHash);
        CryptographicOperations.ZeroMemory(transplantedOriginalHash);
        CryptographicOperations.ZeroMemory(transplantedAfterHash);
    }
    finally
    {
        DeleteTestDirectory(root);
    }
}

static async Task RunCryptographicEraseTestsAsync()
{
    const string password = TestConstants.TestUserPassword;
    const string pin = TestConstants.TestPin;
    string firstGeneratedPassword = TestGeneratedPassword();
    string secondGeneratedPassword = TestGeneratedPassword('B');
    string root = Path.Combine(Path.GetTempPath(), $"kalyna-erase-test-{Guid.NewGuid():N}");
    Directory.CreateDirectory(root);

    try
    {
        string source = Path.Combine(root, "secret.txt");
        string plainArchive = Path.Combine(root, "plain.zpaq");
        string encryptedArchive = Path.Combine(root, "erase-me.kzpaq");
        await File.WriteAllTextAsync(source, "erase me");

        var zpaq = new ZpaqService();
        var kalyna = new KalynaContainerService();
        var erase = new CryptographicEraseService();

        ProcessResult plainAdd = await zpaq.AddAsync(plainArchive, [source], 1, null, CancellationToken.None);
        Assert(plainAdd.Succeeded, "plain archive for erase analysis");
        CryptoEraseAnalysis plainAnalysis = await erase.AnalyzeAsync(plainArchive, CancellationToken.None);
        Assert(plainAnalysis.Exists && !plainAnalysis.IsEncryptedContainer, "plain ZPAQ is not cryptographically erasable");

        string magicOnly = Path.Combine(root, "magic-only.kzpaq");
        await File.WriteAllBytesAsync(magicOnly, [.. "KZPAQ2\0"u8, 0, 0, 0, 0]);
        CryptoEraseAnalysis magicOnlyAnalysis = await erase.AnalyzeAsync(magicOnly, CancellationToken.None);
        Assert(magicOnlyAnalysis.Exists && !magicOnlyAnalysis.IsEncryptedContainer, "magic bytes without a valid container header are not cryptographically erasable");

        string malformedHeader = Path.Combine(root, "malformed-header.kzpaq");
        byte[] malformedBytes = [.. "KZPAQ2\0"u8, 1, 0, 0, 0, (byte)'{'];
        await File.WriteAllBytesAsync(malformedHeader, malformedBytes);
        CryptographicOperations.ZeroMemory(malformedBytes);
        CryptoEraseAnalysis malformedAnalysis = await erase.AnalyzeAsync(malformedHeader, CancellationToken.None);
        Assert(malformedAnalysis.Exists && !malformedAnalysis.IsEncryptedContainer, "malformed JSON is classified as an invalid container without escaping the analyzer");

        AddMouseSamplesUntilEntropyReady();
        ProcessResult encryptedAdd = await zpaq.AddStreamingAsync(
            [source],
            1,
            (zpaqStream, ct) => kalyna.EncryptZpaqStreamAsync(zpaqStream, encryptedArchive, password, pin, firstGeneratedPassword, secondGeneratedPassword, EncryptionSuite.Threefish1024, null, null, ct),
            null,
            CancellationToken.None);
        Assert(encryptedAdd.Succeeded, "encrypted archive for erase test");
        string recoveryPath = await new RecoveryService().CreateAuthenticatedAsync(
            encryptedArchive,
            password,
            pin,
            firstGeneratedPassword,
            secondGeneratedPassword,
            null,
            CancellationToken.None);
        Assert(File.Exists(recoveryPath), "encrypted recovery file exists before erase");
        CryptoEraseAnalysis encryptedAnalysis = await erase.AnalyzeAsync(encryptedArchive, CancellationToken.None);
        Assert(encryptedAnalysis.Exists && encryptedAnalysis.IsEncryptedContainer, "encrypted Threefish container is cryptographically erasable");

        string hardLinkAlias = Path.Combine(root, "erase-hardlink-alias.kzpaq");
        Assert(
            TestNativeFileLinks.CreateHardLink(hardLinkAlias, encryptedArchive, nint.Zero),
            "cryptographic-erase hard-link fixture created");
        await AssertThrowsAsync<IOException>(
            () => erase.EraseEncryptedContainerAsync(hardLinkAlias, null, CancellationToken.None),
            "cryptographic erase refuses a multiply linked container before deleting its recovery data");
        Assert(
            File.Exists(encryptedArchive) && File.Exists(hardLinkAlias) && File.Exists(recoveryPath),
            "hard-link refusal leaves the archive and recovery sidecar intact");
        File.Delete(hardLinkAlias);

        CryptoEraseResult result = await erase.EraseEncryptedContainerAsync(encryptedArchive, null, CancellationToken.None);
        Assert(result.Deleted, "cryptographic erase reports deletion");
        Assert(!File.Exists(encryptedArchive), "encrypted container file is deleted");
        Assert(!File.Exists(recoveryPath), "encrypted recovery file is deleted with container");
    }
    finally
    {
        DeleteTestDirectory(root);
    }
}

static int BufferSizeForTest() => (16 * 1024 * 1024) + 257;


static byte[] ULongWordsToLittleEndianBytes(ulong[] words)
{
    byte[] bytes = new byte[words.Length * sizeof(ulong)];
    for (int i = 0; i < words.Length; i++)
    {
        BitConverter.GetBytes(words[i]).CopyTo(bytes, i * sizeof(ulong));
    }

    return bytes;
}

static async Task<byte[]> Sha3FileAsync(string path)
{
    await using FileStream stream = File.OpenRead(path);
    return await SHA3_512.HashDataAsync(stream);
}

static async Task<long> ReadKpar2MetadataOffsetAsync(string recoveryPath)
{
    byte[] locatorPrefix = new byte[40];
    try
    {
        await using FileStream stream = File.OpenRead(recoveryPath);
        await stream.ReadExactlyAsync(locatorPrefix);
        Assert(locatorPrefix.AsSpan(0, 8).SequenceEqual("KPR2LOC2"u8), "KPAR2 locator magic for test geometry");
        return BinaryPrimitives.ReadInt64LittleEndian(locatorPrefix.AsSpan(32));
    }
    finally
    {
        CryptographicOperations.ZeroMemory(locatorPrefix);
    }
}

static async Task AssertExtractedPdfHashAsync(string directory, string fileName, byte[] expectedHash, string message)
{
    string extracted = Path.Combine(directory, fileName);
    Assert(File.Exists(extracted), $"{message}: file exists");
    byte[] actualHash = await Sha3FileAsync(extracted);
    Assert(CryptographicOperations.FixedTimeEquals(expectedHash, actualHash), message);
}

static string ResolveSamplePdfPath()
{
    string? configured = Environment.GetEnvironmentVariable("KALYNA_SAMPLE_PDF");
    if (!string.IsNullOrWhiteSpace(configured))
    {
        return Path.GetFullPath(configured);
    }

    string desktop = @"C:\Users\Michael\OneDrive - tu-dortmund.de\Desktop";
    string[] preferred =
    [
        Path.Combine(desktop, "Aushang_Studienassistenz_2.pdf"),
        Path.Combine(desktop, "Aushang_Studienassistenz_2 - Kopie.pdf"),
        @"C:\Users\Michael\Downloads\Aushang_Studienassistenz_2.pdf",
    ];

    foreach (string path in preferred)
    {
        if (File.Exists(path))
        {
            return path;
        }
    }

    string? discovered = Directory.Exists(desktop)
        ? Directory.EnumerateFiles(desktop, "*Studienassistenz*.pdf").FirstOrDefault()
        : null;
    return discovered ?? preferred[0];
}

static async Task AssertPdfReadableAsync(string pdfPath, string message, int? expectedPages = null)
{
    byte[] header = new byte[5];
    await using (FileStream input = File.OpenRead(pdfPath))
    {
        await input.ReadExactlyAsync(header);
    }

    Assert(header.AsSpan().SequenceEqual("%PDF-"u8), $"{message}: PDF header");

    string pdfInfo = ResolveToolOnPath("pdfinfo.cmd", "pdfinfo.exe", "pdfinfo");
    ProcessResult info = await RunToolAsync(pdfInfo, [pdfPath]);
    Assert(info.Succeeded && info.StandardOutput.Contains("Pages:", StringComparison.OrdinalIgnoreCase), $"{message}: pdfinfo");
    if (expectedPages is not null)
    {
        System.Text.RegularExpressions.Match pageMatch = System.Text.RegularExpressions.Regex.Match(info.StandardOutput, @"(?m)^Pages:\s*(\d+)\s*$");
        Assert(pageMatch.Success && int.Parse(pageMatch.Groups[1].Value) == expectedPages.Value, $"{message}: expected {expectedPages.Value} pages");
    }

    string renderRoot = Path.Combine(Path.GetTempPath(), $"kalyna-pdf-render-{Guid.NewGuid():N}");
    Directory.CreateDirectory(renderRoot);
    try
    {
        string pdfToPpm = ResolveToolOnPath("pdftoppm.cmd", "pdftoppm.exe", "pdftoppm");
        string prefix = Path.Combine(renderRoot, "page");
        ProcessResult render = await RunToolAsync(pdfToPpm, ["-png", "-f", "1", "-singlefile", pdfPath, prefix]);
        string png = prefix + ".png";
        Assert(render.Succeeded && File.Exists(png) && new FileInfo(png).Length > 0, $"{message}: render first page");
    }
    finally
    {
        Directory.Delete(renderRoot, recursive: true);
    }
}

static string ResolveToolOnPath(params string[] names)
{
    // Absolute paths into one developer's package cache used to sit in front
    // of this list. They resolved on exactly one machine and carried that
    // account name into a public repository, so the search now starts beside
    // the test assembly and otherwise relies on PATH.
    string[] searchRoots =
    [
        AppContext.BaseDirectory,
        Environment.CurrentDirectory,
    ];

    foreach (string root in searchRoots)
    {
        foreach (string name in names)
        {
            string candidate = Path.Combine(root, name);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }
    }

    string path = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
    foreach (string root in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
    {
        foreach (string name in names)
        {
            string candidate = Path.Combine(root, name);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }
    }

    throw new FileNotFoundException($"Tool not found: {string.Join(", ", names)}");
}

static async Task<ProcessResult> RunToolAsync(string executable, IReadOnlyList<string> arguments)
{
    bool isCmd = string.Equals(Path.GetExtension(executable), ".cmd", StringComparison.OrdinalIgnoreCase)
        || string.Equals(Path.GetExtension(executable), ".bat", StringComparison.OrdinalIgnoreCase);
    var startInfo = new ProcessStartInfo
    {
        FileName = isCmd ? "cmd.exe" : executable,
        UseShellExecute = false,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        CreateNoWindow = true,
    };

    if (isCmd)
    {
        startInfo.ArgumentList.Add("/d");
        startInfo.ArgumentList.Add("/c");
        startInfo.ArgumentList.Add(BuildCommandLine(executable, arguments));
    }
    else
    {
        foreach (string argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }
    }

    using Process process = Process.Start(startInfo) ?? throw new InvalidOperationException($"Could not start {executable}.");
    string stdout = await process.StandardOutput.ReadToEndAsync();
    string stderr = await process.StandardError.ReadToEndAsync();
    await process.WaitForExitAsync();
    return new ProcessResult(process.ExitCode, stdout, stderr);
}

static string BuildCommandLine(string executable, IReadOnlyList<string> arguments)
{
    return string.Join(" ", new[] { executable }.Concat(arguments).Select(QuoteCmdArgument));
}

static string QuoteCmdArgument(string value)
{
    return "\"" + value.Replace("\"", "\\\"", StringComparison.Ordinal) + "\"";
}

static void AssertContainerHeader(
    string encryptedArchive,
    EncryptionSuite expectedSuite,
    int expectedArgon2Parallelism = Argon2ExecutionProfile.DefaultParallelism)
{
    using FileStream input = File.OpenRead(encryptedArchive);
    byte[] magic = new byte[7];
    input.ReadExactly(magic);
    Assert(CryptographicOperations.FixedTimeEquals("KZPAQ2\0"u8.ToArray(), magic), "container magic header");

    byte[] headerLengthBytes = new byte[sizeof(int)];
    input.ReadExactly(headerLengthBytes);
    int headerLength = BitConverter.ToInt32(headerLengthBytes);
    Assert(headerLength is > 0 and < 16 * 1024, "container header length");

    byte[] headerBytes = new byte[headerLength];
    input.ReadExactly(headerBytes);
    using JsonDocument header = JsonDocument.Parse(headerBytes);
    JsonElement root = header.RootElement;
    EncryptionSuiteParameters parameters = EncryptionSuiteCatalog.Get(expectedSuite);
    Assert(root.GetProperty("Version").GetInt32() == 12, "container version 12");
    Assert(root.GetProperty("Algorithm").GetString() == parameters.Algorithm, "container algorithm label");
    Assert(root.GetProperty("BlockBits").GetInt32() == parameters.BlockBytes * 8, "container block-size label");
    Assert(root.GetProperty("CounterEndian").GetString() == EncryptionSuiteCatalog.CounterEndian, "container counter byte order");
    Assert(root.GetProperty("EncryptionKeyBits").GetInt32() == parameters.EncryptionKeyBytes * 8, "container cipher-key size");
    Assert(root.GetProperty("Sha3MacKeyBits").GetInt32() == parameters.Sha3MacKeyBytes * 8, "container SHA3 MAC-key size");
    Assert(root.GetProperty("Sha3TagBits").GetInt32() == 512, "container HMAC-SHA3-512 tag size");
    Assert(root.GetProperty("SkeinMacKeyBits").GetInt32() == parameters.SkeinMacKeyBytes * 8, "container Skein MAC-key size");
    Assert(root.GetProperty("SkeinTagBits").GetInt32() == 1024, "container Skein-1024 MAC tag size");
    Assert(root.GetProperty("PasswordMode").GetString() == V12MasterKdf.PasswordMode, "container password mode label");
    Assert(root.GetProperty("KdfInputMode").GetString() == V12MasterKdf.KdfInputMode, "container v12 split-SHA3 KDF input label");
    Assert(root.GetProperty("GeneratedPasswordBits").GetInt32() == 1024, "container generated-password bit label");
    Assert(root.GetProperty("GeneratedPasswordFactorCount").GetInt32() == 2, "container generated-password factor count");
    byte[] sha3Round1Salt = Convert.FromBase64String(root.GetProperty("SaltSha3Round1").GetString()!);
    byte[] skeinRound1Salt = Convert.FromBase64String(root.GetProperty("SaltSkeinRound1").GetString()!);
    Assert(sha3Round1Salt.Length == 64 && skeinRound1Salt.Length == 64, "container carries a 512-bit SHA3 and Skein salt for round one");
    Assert(!sha3Round1Salt.SequenceEqual(skeinRound1Salt), "the two round-one salts differ from each other");
    bool expectsSecondRound = parameters.UsesTwoKdfRounds;
    Assert(
        (root.GetProperty("SaltSha3Round2").ValueKind != JsonValueKind.Null) == expectsSecondRound
        && (root.GetProperty("SaltSkeinRound2").ValueKind != JsonValueKind.Null) == expectsSecondRound,
        "round-two salts are present exactly for the suites that derive a second round");
    Assert(root.GetProperty("NonceBits").GetInt32() == parameters.NonceBytes * 8, "container nonce bit label");
    Assert(Convert.FromBase64String(root.GetProperty("Nonce").GetString()!).Length == parameters.NonceBytes, "container nonce length");
    Assert(root.GetProperty("TweakBits").GetInt32() == parameters.TweakBytes * 8, "container tweak bit label");
    Assert(
        root.GetProperty("TweakMode").GetString() == (parameters.TweakBytes > 0 ? EncryptionSuiteCatalog.ThreefishTweakMode : "None"),
        "container tweak derivation mode");
    if (parameters.TweakBytes == 0)
    {
        Assert(root.GetProperty("Tweak").ValueKind == JsonValueKind.Null, "Kalyna has no Threefish tweak");
    }
    else
    {
        Assert(Convert.FromBase64String(root.GetProperty("Tweak").GetString()!).Length == parameters.TweakBytes, "Threefish tweak length");
    }

    Assert(root.GetProperty("KdfBranchOutputBits").GetInt32() == 512, "container branch output width");
    Assert(root.GetProperty("MasterKeyBits").GetInt32() == 1024, "container master key width");
    Assert(root.GetProperty("KdfExecutionMode").GetString() == "Sequential", "container KDF execution mode");
    Assert(root.GetProperty("KdfMemoryMode").GetString() == "PMI16", "container KDF memory mode");
    // Under v12 the memory size is the profile's, not the header's: the field
    // stays at zero and PMI16 above is what states how memory is chosen.
    Assert(root.GetProperty("Argon2MemoryKiB").GetInt32() == 0, "the v12 header states no fixed Argon2 memory size");
    Assert(root.GetProperty("Argon2Iterations").GetInt32() == (int)V12MasterKdf.Iterations, "Argon2 iteration profile");
    Assert(root.GetProperty("Argon2Parallelism").GetInt32() == expectedArgon2Parallelism, "Argon2 parallelism profile");
    Assert(input.Length - input.Position > 64 + 128, "container has both authentication tags and payload");
}

// Returns the value exactly as it stands in the header bytes. The decoded
// JSON value is not usable for a byte-level mutation: the serializer writes
// Base64 "+" as +, so the decoded form does not occur in the file.
static string ReadRawContainerHeaderString(string path, string propertyName)
{
    byte[] fileBytes = File.ReadAllBytes(path);
    Assert(fileBytes.Length >= 7 + sizeof(int), "container-header read input has a complete prefix");
    int headerLength = BinaryPrimitives.ReadInt32LittleEndian(fileBytes.AsSpan(7, sizeof(int)));
    Assert(headerLength > 0 && 7 + sizeof(int) + headerLength <= fileBytes.Length, "container-header read input has a bounded header");
    string headerText = Encoding.UTF8.GetString(fileBytes, 7 + sizeof(int), headerLength);
    string prefix = $"\"{propertyName}\":\"";
    int start = headerText.IndexOf(prefix, StringComparison.Ordinal);
    Assert(start >= 0, $"container header contains {propertyName}");
    start += prefix.Length;
    int end = headerText.IndexOf('"', start);
    Assert(end > start, $"container header string {propertyName} is terminated");
    return headerText[start..end];
}

static void ReplaceContainerHeaderToken(string path, string oldToken, string newToken)
{
    byte[] fileBytes = File.ReadAllBytes(path);
    byte[]? replacementFile = null;
    byte[]? replacementHeader = null;
    try
    {
        Assert(fileBytes.Length >= 7 + sizeof(int), "container-header mutation input has a complete prefix");
        int headerLength = BinaryPrimitives.ReadInt32LittleEndian(fileBytes.AsSpan(7, sizeof(int)));
        int headerOffset = 7 + sizeof(int);
        Assert(headerLength > 0 && headerOffset + headerLength <= fileBytes.Length, "container-header mutation input has a bounded header");
        string headerText = Encoding.UTF8.GetString(fileBytes, headerOffset, headerLength);
        int tokenOffset = headerText.IndexOf(oldToken, StringComparison.Ordinal);
        Assert(tokenOffset >= 0 && tokenOffset == headerText.LastIndexOf(oldToken, StringComparison.Ordinal), $"container header contains exactly one {oldToken}");
        string replacementText = headerText.Remove(tokenOffset, oldToken.Length).Insert(tokenOffset, newToken);
        replacementHeader = Encoding.UTF8.GetBytes(replacementText);
        int suffixOffset = checked(headerOffset + headerLength);
        replacementFile = new byte[checked(headerOffset + replacementHeader.Length + fileBytes.Length - suffixOffset)];
        fileBytes.AsSpan(0, 7).CopyTo(replacementFile);
        BinaryPrimitives.WriteInt32LittleEndian(replacementFile.AsSpan(7, sizeof(int)), replacementHeader.Length);
        replacementHeader.CopyTo(replacementFile.AsSpan(headerOffset));
        fileBytes.AsSpan(suffixOffset).CopyTo(replacementFile.AsSpan(headerOffset + replacementHeader.Length));
        File.WriteAllBytes(path, replacementFile);
    }
    finally
    {
        CryptographicOperations.ZeroMemory(fileBytes);
        if (replacementHeader is not null)
        {
            CryptographicOperations.ZeroMemory(replacementHeader);
        }

        if (replacementFile is not null)
        {
            CryptographicOperations.ZeroMemory(replacementFile);
        }
    }
}

static void AssertZpaqHeader(string archive, string message)
{
    using FileStream input = File.OpenRead(archive);
    byte[] header = new byte[4];
    input.ReadExactly(header);
    bool hasHeader = header.AsSpan(0, 4).SequenceEqual("7kSt"u8)
        || header.AsSpan(0, 3).SequenceEqual("zPQ"u8);
    Assert(hasHeader, message);
}

static async Task FlipLastByteAsync(string path)
{
    await using FileStream stream = File.Open(path, FileMode.Open, FileAccess.ReadWrite);
    stream.Position = stream.Length - 1;
    int value = stream.ReadByte();
    stream.Position = stream.Length - 1;
    stream.WriteByte((byte)(value ^ 0x01));
}

static async Task FlipContainerTagByteAsync(string path, bool skeinTag)
{
    await using FileStream stream = File.Open(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
    stream.Position = 7;
    byte[] headerLengthBytes = new byte[sizeof(int)];
    try
    {
        await stream.ReadExactlyAsync(headerLengthBytes);
        int headerLength = BinaryPrimitives.ReadInt32LittleEndian(headerLengthBytes);
        long tagOffset = 7L + sizeof(int) + headerLength + (skeinTag ? 64 : 0);
        stream.Position = tagOffset;
        int value = stream.ReadByte();
        Assert(value >= 0, "container authentication tag byte exists");
        stream.Position = tagOffset;
        stream.WriteByte((byte)(value ^ 0x01));
        await stream.FlushAsync();
    }
    finally
    {
        CryptographicOperations.ZeroMemory(headerLengthBytes);
    }
}

static async Task CorruptRangeAsync(string path, long offset, int length)
{
    byte[] corruption = new byte[length];
    RandomNumberGenerator.Fill(corruption);
    try
    {
        await using FileStream stream = File.Open(path, FileMode.Open, FileAccess.ReadWrite);
        stream.Position = offset;
        await stream.WriteAsync(corruption);
        await stream.FlushAsync();
    }
    finally
    {
        CryptographicOperations.ZeroMemory(corruption);
    }
}

static async Task AssertThrowsCryptographicAsync(Func<Task> action, string message)
{
    try
    {
        await action();
    }
    catch (CryptographicException)
    {
        return;
    }

    throw new InvalidOperationException($"Assertion failed: {message}");
}

static async Task AssertThrowsAsync<TException>(Func<Task> action, string message)
    where TException : Exception
{
    try
    {
        await action();
    }
    catch (TException)
    {
        return;
    }

    throw new InvalidOperationException($"Assertion failed: {message}");
}

static void AssertThrows<TException>(Action action, string message)
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

    throw new InvalidOperationException($"Assertion failed: {message}");
}

static void AssertNoNewPlaintextTempZpaq(DateTime auditStartUtc)
{
    string temp = Path.GetTempPath();
    string[] patterns = ["kalyna-source-*.zpaq", "kalyna-*.zpaq"];
    foreach (string pattern in patterns)
    {
        foreach (string path in Directory.EnumerateFiles(temp, pattern))
        {
            DateTime changed = File.GetLastWriteTimeUtc(path);
            Assert(changed < auditStartUtc.AddSeconds(-1), $"no new plaintext temp ZPAQ file was created: {path}");
        }
    }
}

static void RaiseFileDragOver(UIElement target, params string[] paths)
{
    DragEventArgs args = CreateDragArgs(target, paths);
    args.RoutedEvent = DragDrop.PreviewDragOverEvent;
    target.RaiseEvent(args);
    Assert(args.Handled, $"drag over handled for {target.GetType().Name}");
    Assert(args.Effects == DragDropEffects.Copy, $"drag over copy effect for {target.GetType().Name}");
}

static void RaiseFileDrop(UIElement target, params string[] paths)
{
    DragEventArgs args = CreateDragArgs(target, paths);
    args.RoutedEvent = DragDrop.PreviewDropEvent;
    target.RaiseEvent(args);
    Assert(args.Handled, $"drop handled for {target.GetType().Name}");
    Assert(args.Effects == DragDropEffects.Copy, $"drop copy effect for {target.GetType().Name}");
}

static DragEventArgs CreateDragArgs(UIElement target, string[] paths)
{
    var data = new DataObject(DataFormats.FileDrop, paths);
    return (DragEventArgs)Activator.CreateInstance(
        typeof(DragEventArgs),
        BindingFlags.Instance | BindingFlags.NonPublic,
        binder: null,
        args:
        [
            data,
            DragDropKeyStates.None,
            DragDropEffects.Copy,
            target,
            new Point(0, 0),
        ],
        culture: null)!;
}

// The shipped parallel cipher paths against their scalar test entry points,
// over buffers the size of a real archive.
//
// Both libraries verify themselves at start-up, but a self-check runs on a few
// blocks under a handful of keys. What it cannot reach is the mode wrapped
// around the block function: the counter arithmetic across a quarter of a
// gigabyte, the carry out of a counter that starts near its own limit, the tail
// block of a length that is not a multiple of the block size, and the
// boundaries where the driver switches from one thread to many and from one
// claimed chunk to the next. Those are where a fast path that passes every
// vector still writes a container that will not open.
//
// The macOS suite carries the same two tests. They are deliberately duplicated
// rather than shared: the two suites have no common harness, and a check this
// close to the ciphertext is worth having twice.
// The shipped Kalyna v12 parallel path against its scalar entry point over
// buffers the size of a real archive.
//
// Split from the ChaCha20 half, as the macOS suite has it. They share nothing
// but the shape of the check, and together they were the longest group in the
// run; the ChaCha comparison is kept separate for useful failure isolation.
static void RunKalynaDifferentialTests()
{
    const int LargeBytes = 256 * 1024 * 1024;
    const int ChunkBytes = 256 * 1024;
    const int ParallelThresholdBytes = 1024 * 1024;
    int[] boundaryLengths =
    [
        1, 63, 64, 65,
        ChunkBytes - 1, ChunkBytes, ChunkBytes + 1,
        ParallelThresholdBytes - 1, ParallelThresholdBytes, ParallelThresholdBytes + 1,
        (4 * 1024 * 1024) + 63,
    ];

    Assert(NativeKalyna.IsAvailable(), $"Kalyna v12 library unavailable: {NativeKalyna.LastLoadError}");
    Assert(NativeChaChaPoly.IsAvailable(), $"ChaCha20-Poly1305 library unavailable: {NativeChaChaPoly.LastLoadError}");

    byte[] plaintext = DerivedBytesForTest(LargeBytes + 37, 0xABCDEF);
    byte[] fromReference = new byte[plaintext.Length];
    byte[] fromFast = new byte[plaintext.Length];

    // Four places in the counter's range. The last three start high enough that
    // a 256 MiB run carries out of the low 32 and 40 bits, which is the
    // arithmetic a worker has to reproduce when it jumps to the block it
    // claimed rather than walking there.
    (string Name, ulong KeySeed, ulong NonceSeed, ulong CounterStart, int Length)[] kalynaCases =
    [
        ("counter 0", 1, 1001, 0, LargeBytes),
        ("counter 2^32-1", 2, 1002, 0xFFFFFFFFUL, LargeBytes),
        ("counter crossing 2^40", 3, 1003, 0xFFFFFFFFFFUL - 7, LargeBytes),
        ("counter at 2^63", 4, 1004, 1UL << 63, LargeBytes),
        ("256 MiB + 37, unaligned tail", 5, 1005, 0x0123456789ABCDEFUL, LargeBytes + 37),
    ];

    foreach ((string name, ulong keySeed, ulong nonceSeed, ulong counterStart, int length) in kalynaCases)
    {
        byte[] key = DerivedBytesForTest(64, keySeed);
        byte[] counter = CounterBlockForTest(nonceSeed, counterStart);
        var stopwatch = Stopwatch.StartNew();
        RequireDifferentialExport(() => NativeKalyna.XCryptCtr512Scalar(key, counter, plaintext, fromReference, length));
        TimeSpan referenceElapsed = stopwatch.Elapsed;
        stopwatch.Restart();
        NativeKalyna.XCryptCtr512(key, counter, plaintext, fromFast, length);
        TimeSpan fastElapsed = stopwatch.Elapsed;
        RequireIdenticalForTest(fromReference, fromFast, length, $"Kalyna {name}");
        Console.WriteLine(
            $"    Kalyna {name}: identical "
            + $"({RateForTest(length, referenceElapsed)} scalar, {RateForTest(length, fastElapsed)} parallel)");
    }

    byte[] boundaryKey = DerivedBytesForTest(64, 9);
    byte[] boundaryCounter = CounterBlockForTest(9009, 0xFFFFFFFEUL);
    foreach (int length in boundaryLengths)
    {
        RequireDifferentialExport(() => NativeKalyna.XCryptCtr512Scalar(boundaryKey, boundaryCounter, plaintext, fromReference, length));
        NativeKalyna.XCryptCtr512(boundaryKey, boundaryCounter, plaintext, fromFast, length);
        RequireIdenticalForTest(fromReference, fromFast, length, $"Kalyna boundary length {length}");
    }

    Console.WriteLine($"    Kalyna boundary lengths identical: {string.Join(", ", boundaryLengths)}");
}

// Every block-wide CTR adapter must refuse the request before writing if the
// final block would carry out of the nonce. In particular, the shared Crypto++
// driver used to discard that carry and continue at zero.
static void RunNativeCtrCounterExhaustionTests()
{
    byte[] aesKey = DerivedBytesForTest(32, 0x435452414553UL);
    byte[] marsKey = DerivedBytesForTest(56, 0x4354524D415253UL);
    byte[] shacalKey = DerivedBytesForTest(64, 0x435452534841UL);
    try
    {
        AssertCryptoPpCtrMatchesBlockReference(
            "AES-256",
            NativeAes.BlockBytes,
            (nonce, input, output, length) => NativeAes.XCryptCtr256(
                aesKey, nonce, input, output, length),
            (input, output) => NativeAes.EncryptBlock(aesKey, input, output));
        AssertCryptoPpCtrMatchesBlockReference(
            "MARS-448",
            NativeMars.BlockBytes,
            (nonce, input, output, length) => NativeMars.XCryptCtr448(
                marsKey, nonce, input, output, length),
            (input, output) => NativeMars.EncryptBlock(marsKey, input, output));
        AssertCryptoPpCtrMatchesBlockReference(
            "SHACAL-2-512",
            NativeShacal2.BlockBytes,
            (nonce, input, output, length) => NativeShacal2.XCryptCtr512(
                shacalKey, nonce, input, output, length),
            (input, output) => NativeShacal2.EncryptBlock(shacalKey, input, output));
    }
    finally
    {
        CryptographicOperations.ZeroMemory(aesKey);
        CryptographicOperations.ZeroMemory(marsKey);
        CryptographicOperations.ZeroMemory(shacalKey);
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
}

// Crypto++ exposes the provider chosen by the same branches its Rijndael
// implementation uses for key setup and block encryption. This makes a build
// that accidentally omits rijndael_simd.cpp/AES-NI support fail explicitly
// instead of trying to infer instruction selection from a noisy wall clock.
static void RunAesRuntimeProviderTests()
{
    NativeAesRuntimeProvider provider = NativeAes.RuntimeProvider;
    Assert(provider != NativeAesRuntimeProvider.Unknown, "the AES adapter reports a known Crypto++ runtime provider");

    if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
    {
        Assert(
            provider == NativeAesRuntimeProvider.AesNi,
            $"AES-NI is available but the production adapter selected {provider}");
    }

    if (System.Runtime.Intrinsics.Arm.Aes.IsSupported)
    {
        Assert(
            provider == NativeAesRuntimeProvider.ArmV8,
            $"ARM AES is available but the production adapter selected {provider}");
    }

    Console.WriteLine($"    AES Crypto++ runtime provider: {provider}");
}

// CTR_Mode_ExternalCipher is the performance-critical bridge from the shared
// range scheduler into Crypto++'s AdvancedProcessBlocks fast paths. Keep an
// independent construction from the exported block primitive so an API or
// counter-layout change cannot be accepted merely because encrypt/decrypt use
// the same broken adapter. The cases cross partial-block, worker-chunk and
// parallel-dispatch boundaries and exercise an in-place production buffer.
static void AssertCryptoPpCtrMatchesBlockReference(
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
        blockBytes,
        blockBytes + 1,
        WorkerChunkBytes - 1,
        WorkerChunkBytes,
        WorkerChunkBytes + 1,
        ParallelThresholdBytes + 17,
    ];

    byte[] nonce = DerivedBytesForTest(blockBytes, 0x4354524E4F4E4345UL + (ulong)blockBytes);
    // The second block carries out of the low byte. Larger cases carry through
    // it many more times, proving that the full-width big-endian counter used
    // by the reference and by each independently scheduled range agrees.
    nonce[^2] = 0x7A;
    nonce[^1] = 0xFF;

    foreach (int length in lengths)
    {
        byte[] input = DerivedBytesForTest(length, 0x435452494E505554UL + (ulong)length);
        byte[] expected = new byte[length];
        byte[] actual = new byte[length];
        byte[] inPlace = input.ToArray();
        try
        {
            BuildCtrFromBlockReference(nonce, input, expected, encryptBlock, blockBytes);
            xcrypt(nonce, input, actual, length);
            RequireIdenticalForTest(expected, actual, length, $"{algorithm} CTR block reference at {length} bytes");

            xcrypt(nonce, inPlace, inPlace, length);
            RequireIdenticalForTest(expected, inPlace, length, $"{algorithm} in-place CTR at {length} bytes");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
            CryptographicOperations.ZeroMemory(expected);
            CryptographicOperations.ZeroMemory(actual);
            CryptographicOperations.ZeroMemory(inPlace);
        }
    }

    CryptographicOperations.ZeroMemory(nonce);
    Console.WriteLine(
        $"    {algorithm} CTR matches its block reference across {lengths.Length} boundary lengths, including in-place buffers");
}

static void BuildCtrFromBlockReference(
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
                IncrementBigEndianCounterForTest(counter);
            }
        }
    }
    finally
    {
        CryptographicOperations.ZeroMemory(counter);
        CryptographicOperations.ZeroMemory(keystream);
    }
}

static void IncrementBigEndianCounterForTest(byte[] counter)
{
    for (int index = counter.Length - 1; index >= 0; index--)
    {
        counter[index]++;
        if (counter[index] != 0)
        {
            return;
        }
    }

    throw new InvalidOperationException("The test CTR counter unexpectedly overflowed.");
}

static void AssertNativeCtrCounterBoundary(
    string algorithm,
    int blockBytes,
    Action<byte[], byte[], byte[]> xcrypt)
{
    byte[] maximumNonce = Enumerable.Repeat((byte)0xFF, blockBytes).ToArray();
    byte[] oneBlock = Enumerable.Repeat((byte)0x3C, blockBytes).ToArray();
    byte[] oneBlockOutput = new byte[blockBytes];

    // The maximum counter value itself is valid for exactly one final block.
    xcrypt(maximumNonce, oneBlock, oneBlockOutput);

    byte[] crossingInput = Enumerable.Repeat((byte)0x5A, checked(blockBytes * 2)).ToArray();
    byte[] crossingOutput = Enumerable.Repeat((byte)0xA5, crossingInput.Length).ToArray();
    bool rejected = false;
    try
    {
        xcrypt(maximumNonce, crossingInput, crossingOutput);
    }
    catch (CryptographicException)
    {
        rejected = true;
    }

    Assert(rejected, $"{algorithm} rejects a request that would wrap its CTR counter");
    Assert(
        crossingOutput.All(value => value == 0xA5),
        $"{algorithm} rejects counter exhaustion before writing any output");
}

// The ChaCha20 worker split against the same keystream produced on one thread.
// Its own group for the reason above, and its own copy of the fixtures so the
// two groups can run independently in child processes.
static void RunChaChaDifferentialTests()
{
    const int LargeBytes = 256 * 1024 * 1024;
    const int ChunkBytes = 256 * 1024;
    const int ParallelThresholdBytes = 1024 * 1024;
    int[] boundaryLengths =
    [
        1, 63, 64, 65,
        ChunkBytes - 1, ChunkBytes, ChunkBytes + 1,
        ParallelThresholdBytes - 1, ParallelThresholdBytes, ParallelThresholdBytes + 1,
        (4 * 1024 * 1024) + 63,
    ];

    Assert(NativeChaChaPoly.IsAvailable(), $"ChaCha20-Poly1305 library unavailable: {NativeChaChaPoly.LastLoadError}");

    byte[] plaintext = DerivedBytesForTest(LargeBytes + 37, 0xABCDEF);
    byte[] fromReference = new byte[plaintext.Length];
    byte[] fromFast = new byte[plaintext.Length];

    const uint LargeBlocks = LargeBytes / 64;
    (string Name, ulong KeySeed, ulong NonceSeed, uint Counter, int Length)[] chachaCases =
    [
        ("counter 0", 1, 2001, 0, LargeBytes),
        ("counter 1, where the AEAD starts", 2, 2002, 1, LargeBytes),
        ("counter 2^31-1", 3, 2003, 0x7FFFFFFF, LargeBytes),
        ("ending one block below 2^32", 4, 2004, uint.MaxValue - LargeBlocks, LargeBytes),
        ("256 MiB + 37, unaligned tail", 5, 2005, 12345, LargeBytes + 37),
    ];

    foreach ((string name, ulong keySeed, ulong nonceSeed, uint counter, int length) in chachaCases)
    {
        byte[] key = DerivedBytesForTest(32, keySeed);
        byte[] nonce = DerivedBytesForTest(12, nonceSeed);
        int serialResult = 0;
        var stopwatch = Stopwatch.StartNew();
        RequireDifferentialExport(() => serialResult = NativeChaChaPoly.XCryptSerial(key, nonce, counter, plaintext, fromReference, length));
        TimeSpan serialElapsed = stopwatch.Elapsed;
        stopwatch.Restart();
        int parallelResult = NativeChaChaPoly.XCrypt(key, nonce, counter, plaintext, fromFast, length);
        TimeSpan parallelElapsed = stopwatch.Elapsed;
        Assert(serialResult == 0 && parallelResult == 0,
            $"ChaCha20 {name}: serial returned {serialResult}, worker split returned {parallelResult}.");
        RequireIdenticalForTest(fromReference, fromFast, length, $"ChaCha20 {name}");
        Console.WriteLine(
            $"    ChaCha20 {name}: identical "
            + $"({RateForTest(length, serialElapsed)} serial, {RateForTest(length, parallelElapsed)} split)");
    }

    byte[] chachaBoundaryKey = DerivedBytesForTest(32, 19);
    byte[] chachaBoundaryNonce = DerivedBytesForTest(12, 1919);
    foreach (int length in boundaryLengths)
    {
        int serialResult = 0;
        RequireDifferentialExport(() => serialResult = NativeChaChaPoly.XCryptSerial(chachaBoundaryKey, chachaBoundaryNonce, 7, plaintext, fromReference, length));
        int parallelResult = NativeChaChaPoly.XCrypt(chachaBoundaryKey, chachaBoundaryNonce, 7, plaintext, fromFast, length);
        Assert(serialResult == 0 && parallelResult == 0,
            $"ChaCha20 boundary length {length}: serial {serialResult}, split {parallelResult}.");
        RequireIdenticalForTest(fromReference, fromFast, length, $"ChaCha20 boundary length {length}");
    }

    // RFC 8439 gives the block counter 32 bits. A run that would pass its end
    // must be refused, not served with keystream that repeats under the same
    // key: two plaintext blocks XORed with one keystream block is a two-time
    // pad.
    byte[] exhaustionKey = DerivedBytesForTest(32, 99);
    byte[] exhaustionNonce = DerivedBytesForTest(12, 98);
    byte[] finalCounterInput = plaintext[..64];
    byte[] finalCounterSerial = new byte[64];
    byte[] finalCounterSplit = new byte[64];
    int finalSerialResult = NativeChaChaPoly.XCryptSerial(
        exhaustionKey, exhaustionNonce, uint.MaxValue, finalCounterInput, finalCounterSerial, finalCounterInput.Length);
    int finalSplitResult = NativeChaChaPoly.XCrypt(
        exhaustionKey, exhaustionNonce, uint.MaxValue, finalCounterInput, finalCounterSplit, finalCounterInput.Length);
    Assert(
        finalSerialResult == 0
        && finalSplitResult == 0
        && CryptographicOperations.FixedTimeEquals(finalCounterSerial, finalCounterSplit),
        "ChaCha20 permits exactly one final block at counter 2^32-1 and both paths agree");

    Array.Fill(fromFast, (byte)0xA5, 0, 192);
    int refused = NativeChaChaPoly.XCrypt(exhaustionKey, exhaustionNonce, uint.MaxValue - 1, plaintext, fromFast, 192);
    Assert(refused == 4, $"ChaCha20 must refuse a run that would exhaust the block counter; it returned {refused}.");
    Assert(
        fromFast.AsSpan(0, 192).IndexOfAnyExcept((byte)0xA5) < 0,
        "ChaCha20 rejects counter exhaustion before writing output");

    // And the split has to reproduce this library's own RFC 8439 AEAD, whose
    // keystream starts at block 1. That ties it to the standard rather than
    // only to the implementation it replaced.
    const int AeadLength = 16 * 1024 * 1024;
    byte[] aeadTag = new byte[NativeChaChaPoly.TagBytes];
    for (int trial = 0; trial < 4; trial++)
    {
        byte[] key = DerivedBytesForTest(32, 3000 + (ulong)trial);
        byte[] nonce = DerivedBytesForTest(12, 4000 + (ulong)trial);
        NativeChaChaPoly.Encrypt(key, nonce, ReadOnlySpan<byte>.Empty, plaintext, fromReference, AeadLength, aeadTag);
        int parallelResult = NativeChaChaPoly.XCrypt(key, nonce, 1, plaintext, fromFast, AeadLength);
        Assert(parallelResult == 0, $"ChaCha20 AEAD cross-check trial {trial}: the worker split returned {parallelResult}.");
        RequireIdenticalForTest(fromReference, fromFast, AeadLength, $"ChaCha20 against the AEAD, trial {trial}");
    }
}

// The authenticated pair against the published vector and its own rules.
//
// The framing - associated data padded to 16, ciphertext padded to 16, then
// both lengths little-endian - is assembled in chachapoly_ref_export.cpp rather
// than taken from Crypto++, so the vector in RFC 8439 section 2.8.2 is what
// holds it. A padding or length-encoding slip produces a tag that is merely
// different, and nothing else in this suite would notice, because both sides of
// a round trip would be wrong in the same way.
static void RunAeadFramingTests()
{
    Assert(NativeChaChaPoly.IsAvailable(), $"ChaCha20-Poly1305 library unavailable: {NativeChaChaPoly.LastLoadError}");

    byte[] key = new byte[32];
    for (int i = 0; i < key.Length; i++)
    {
        key[i] = (byte)(0x80 + i);
    }

    byte[] nonce = Convert.FromHexString("070000004041424344454647");
    byte[] associated = Convert.FromHexString("50515253c0c1c2c3c4c5c6c7");
    byte[] plaintext = System.Text.Encoding.ASCII.GetBytes(
        "Ladies and Gentlemen of the class of '99: If I could offer you only "
        + "one tip for the future, sunscreen would be it.");
    byte[] expectedCiphertext = Convert.FromHexString(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        + "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        + "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        + "3ff4def08e4b7a9de576d26586cec64b6116");
    byte[] expectedTag = Convert.FromHexString("1ae10b594f09e26a7e902ecbd0600691");

    Assert(plaintext.Length == 114, "The RFC 8439 vector plaintext is 114 bytes.");

    byte[] ciphertext = new byte[plaintext.Length];
    byte[] tag = new byte[NativeChaChaPoly.TagBytes];
    NativeChaChaPoly.Encrypt(key, nonce, associated, plaintext, ciphertext, plaintext.Length, tag);
    Assert(ciphertext.AsSpan().SequenceEqual(expectedCiphertext),
        "ChaCha20-Poly1305 did not reproduce the RFC 8439 section 2.8.2 ciphertext.");
    Assert(tag.AsSpan().SequenceEqual(expectedTag),
        "ChaCha20-Poly1305 did not reproduce the RFC 8439 section 2.8.2 tag.");

    byte[] recovered = new byte[plaintext.Length];
    NativeChaChaPoly.Decrypt(key, nonce, associated, ciphertext, recovered, ciphertext.Length, tag);
    Assert(recovered.AsSpan().SequenceEqual(plaintext),
        "ChaCha20-Poly1305 did not recover the RFC 8439 vector plaintext.");

    RequireAeadRejectedForTest("a flipped tag bit", key, nonce, associated, ciphertext, tag, mutateTag: true);
    RequireAeadRejectedForTest("a flipped ciphertext bit", key, nonce, associated, ciphertext, tag, mutateCiphertext: true);
    RequireAeadRejectedForTest("altered associated data", key, nonce, associated, ciphertext, tag, mutateAssociated: true);

    // The container hands the same buffer in and out for both directions. The
    // tag covers the ciphertext, so encryption has to take it after writing and
    // decryption has to take it before overwriting; getting either backwards
    // works out-of-place and fails only here.
    byte[] scratch = plaintext.ToArray();
    byte[] inPlaceTag = new byte[NativeChaChaPoly.TagBytes];
    NativeChaChaPoly.Encrypt(key, nonce, associated, scratch, scratch, scratch.Length, inPlaceTag);
    Assert(scratch.AsSpan().SequenceEqual(expectedCiphertext) && inPlaceTag.AsSpan().SequenceEqual(expectedTag),
        "In-place ChaCha20-Poly1305 encryption did not match the out-of-place result.");
    NativeChaChaPoly.Decrypt(key, nonce, associated, scratch, scratch, scratch.Length, inPlaceTag);
    Assert(scratch.AsSpan().SequenceEqual(plaintext),
        "In-place ChaCha20-Poly1305 decryption did not recover the plaintext.");
}

// The differential tests need scalar exports that production does not call.
static void RequireDifferentialExport(Action action)
{
    try
    {
        action();
    }
    catch (EntryPointNotFoundException exception)
    {
        throw new InvalidOperationException(
            "The native DLL in tools\\ predates the scalar exports the differential tests need. "
            + "Re-run tools\\Build-Native.cmd on a machine with MSVC and try again.",
            exception);
    }
}

static void RequireAeadRejectedForTest(
    string what,
    byte[] key,
    byte[] nonce,
    byte[] associated,
    byte[] ciphertext,
    byte[] tag,
    bool mutateTag = false,
    bool mutateCiphertext = false,
    bool mutateAssociated = false)
{
    byte[] usedTag = tag.ToArray();
    byte[] usedCiphertext = ciphertext.ToArray();
    byte[] usedAssociated = associated.ToArray();
    if (mutateTag) { usedTag[9] ^= 0x40; }
    if (mutateCiphertext) { usedCiphertext[usedCiphertext.Length / 2] ^= 0x01; }
    if (mutateAssociated) { usedAssociated[3] ^= 0x80; }

    byte[] output = new byte[usedCiphertext.Length];
    output.AsSpan().Fill(0xCC);
    try
    {
        NativeChaChaPoly.Decrypt(key, nonce, usedAssociated, usedCiphertext, output, usedCiphertext.Length, usedTag);
    }
    catch (CryptographicException)
    {
        foreach (byte value in output)
        {
            Assert(value == 0xCC, $"ChaCha20-Poly1305 wrote into the caller's buffer while refusing {what}.");
        }

        return;
    }

    Assert(false, $"ChaCha20-Poly1305 accepted {what}.");
}

// What the two paths cost, printed beside the fact that they agree.
//
// The agreement is the assertion; the rate is what makes a lost fast path
// visible. The parallel paths must exceed their scalar paths on this machine, so
// a build that quietly fell back reads as such in the log even though every
// byte still matches. The macOS suite prints the same pair.
static string RateForTest(int length, TimeSpan elapsed)
{
    double seconds = elapsed.TotalSeconds;
    if (seconds <= 0)
    {
        return "n/a";
    }

    return $"{length / (1024.0 * 1024.0) / seconds:F0} MB/s";
}

static void RequireIdenticalForTest(byte[] reference, byte[] fast, int length, string label)
{
    // Not SequenceEqual: on a mismatch the offset is what says whether the fault
    // is in the block function, in the tail, or at a chunk boundary.
    for (int i = 0; i < length; i++)
    {
        if (reference[i] != fast[i])
        {
            throw new InvalidOperationException(
                $"{label}: the fast path and the reference differ at byte {i} "
                + $"(reference {reference[i]:x2}, fast {fast[i]:x2}) over {length} bytes.");
        }
    }
}

static byte[] CounterBlockForTest(ulong nonceSeed, ulong counterStart)
{
    byte[] block = new byte[64];
    FillDerivedForTest(block.AsSpan(0, 56), nonceSeed);
    for (int i = 0; i < 8; i++)
    {
        block[63 - i] = (byte)(counterStart >> (i * 8));
    }

    return block;
}

static byte[] DerivedBytesForTest(int length, ulong seed)
{
    byte[] buffer = new byte[length];
    FillDerivedForTest(buffer, seed);
    return buffer;
}

static void FillDerivedForTest(Span<byte> destination, ulong seed)
{
    for (int i = 0; i < destination.Length; i += 8)
    {
        ulong word = MixForTest(seed + (ulong)(i / 8));
        int count = Math.Min(8, destination.Length - i);
        for (int b = 0; b < count; b++)
        {
            destination[i + b] = (byte)(word >> (b * 8));
        }
    }
}

static ulong MixForTest(ulong value)
{
    value += 0x9E3779B97F4A7C15UL;
    value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9UL;
    value = (value ^ (value >> 27)) * 0x94D049BB133111EBUL;
    return value ^ (value >> 31);
}

sealed class ShortReadStream : Stream
{
    private readonly byte[] _data;
    private readonly int _maxRead;
    private int _position;

    public ShortReadStream(byte[] data, int maxRead)
    {
        _data = data;
        _maxRead = maxRead;
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => _data.Length;
    public override long Position
    {
        get => _position;
        set => throw new NotSupportedException();
    }

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        int remaining = _data.Length - _position;
        if (remaining <= 0)
        {
            return ValueTask.FromResult(0);
        }

        int read = Math.Min(Math.Min(buffer.Length, _maxRead), remaining);
        _data.AsMemory(_position, read).CopyTo(buffer);
        _position += read;
        return ValueTask.FromResult(read);
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        int remaining = _data.Length - _position;
        if (remaining <= 0)
        {
            return 0;
        }

        int read = Math.Min(Math.Min(count, _maxRead), remaining);
        Buffer.BlockCopy(_data, _position, buffer, offset, read);
        _position += read;
        return read;
    }

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

sealed class MemoryAppSettingsStore : IAppSettingsStore
{
    private readonly Dictionary<string, string> _values = new(StringComparer.Ordinal);

    public string? Read(string key)
    {
        return _values.TryGetValue(key, out string? value) ? value : null;
    }

    public void Write(string key, string value)
    {
        _values[key] = value;
    }
}

sealed class InlineProgress<T>(Action<T> report) : IProgress<T>
{
    public void Report(T value)
    {
        report(value);
    }
}

static class TestNativeFileLinks
{
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CreateHardLink(string fileName, string existingFileName, nint securityAttributes);
}

internal static class TestConstants
{
    public const string TestUserPassword = "N!r7$Vq2#Lm8%Tx3&Jd9*Wp4+Kg5=Zu6?Ce";
    // 24681357 ended on the 3-5-7 keypad diagonal, which the creation policy
    // has refused since the geometric rule was added.
    public const string TestPin = "29471608";
}
