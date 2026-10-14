using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using KalynaArchiver;
using KalynaArchiver.Gui;
using KalynaArchiver.Services;
using KeepVaultMac.Controls;
using Microsoft.Win32.SafeHandles;

internal static class PreflightLifetimeRev12Tests
{
    internal static IReadOnlyList<TestCase> Tests =>
    [
        new("gui.rev12-preflight-state", "V13-UI-PREFLIGHT-KEYSHEET/EXISTS/CANCEL/DOUBLECLICK and semantic binding", () => MacGuiTests.RunOnUiThread(PreflightState), TestResource.Gui, "GUI"),
        new("gui.rev12-extract-preflight", "V13-UI-PREFLIGHT-CANCEL: missing extract/list/recovery inputs retain the draft", () => MacGuiTests.RunOnUiThread(ExtractPreflight), TestResource.Gui, "GUI"),
        new("gui.rev12-verification-cleanup", "REV12 actual create owner refuses success after plaintext cleanup failure and preserves both causes/committed objects",
            () => MacGuiTests.RunOnUiThread(VerificationCleanup), TestResource.Gui, "GUI")
        { Cost = new TestCost(1, 1024, false, TestConstraint.ZpaqProcess) },
        new("gui.rev12-kdf-minimum-preflight", "V13-UI-PREFLIGHT-RESOURCES: known 64-MiB KDF refusal retains the prepared draft", () => MacGuiTests.RunOnUiThread(KdfMinimumPreflight), TestResource.Gui, "GUI"),
        new("container.rev12-kdf-minimum-preflight", "V13-UI-PREFLIGHT-RESOURCES: shared core refuses the public KDF minimum before output or entropy", CoreKdfMinimumPreflightAsync, TestResource.ProcessGlobal, "Security"),
        new("entropy.rev12-consume-boundary", "V13-UI-CONSUME-BOUNDARY: owner records irreversible single/dual transfer before failures", ConsumeBoundaryAsync, TestResource.ProcessGlobal, "Security"),
        // The late collision follows the full production KDF; fault hooks still require process isolation.
        new("container.rev12-preflight-race", "V13-UI-PREFLIGHT-RACE: exclusive output, early collision preservation, late collision consumption", OutputRaceAsync, TestResource.ProcessGlobal, "Security")
        { Cost = new TestCost(4, 2560, true, TestConstraint.ProcessExclusive) },
    ];

    private const string Password = "N!r7$Vq2#Lm8%Tx3&Jd9*Wp4+Kg5=Zu6?Ce";
    private const string Pin = "428317";
    private static readonly string FactorA = new('A', 256);
    private static readonly string FactorB = new('B', 256);
    private static void Require(bool condition, string message) => MacComprehensiveTests.Require(condition, message);
    private static T C<T>(MainWindow window, string name) where T : Control => window.FindControl<T>(name) ?? throw new InvalidOperationException(name);
    private static FieldInfo F(string name) => typeof(MainWindow).GetField(name, BindingFlags.Instance | BindingFlags.NonPublic) ?? throw new InvalidOperationException(name);
    private static object? Call(MainWindow window, string name, params object?[] args) => (typeof(MainWindow).GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic) ?? throw new InvalidOperationException(name)).Invoke(window, args);
    private static void Click(MainWindow window, string name) => C<Button>(window, name).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
    private static void Pump(MainWindow window, int timeoutSeconds = 10)
    {
        var clock = Stopwatch.StartNew();
        do
        {
            Dispatcher.UIThread.RunJobs();
            if ((int)F("_operationActive").GetValue(window)! == 0) return;
            Thread.Sleep(2);
        } while (clock.Elapsed < TimeSpan.FromSeconds(timeoutSeconds));
        throw new TimeoutException("The preflight UI gate was not released.");
    }
    private static void Enable(MainWindow window)
    {
        // Opened starts the real asynchronous trust check. Complete that check
        // before this state-only headless test installs its explicit trusted
        // wiring seam; a late startup callback must not override the fixture.
        var startup = Stopwatch.StartNew();
        while ((string?)F("_integrityStatusKey").GetValue(window) == "integrityChecking")
        {
            Dispatcher.UIThread.RunJobs();
            if (startup.Elapsed > TimeSpan.FromSeconds(15))
                throw new TimeoutException("The startup integrity check did not complete before the GUI wiring fixture.");
            Thread.Sleep(2);
        }
        F("_integrityTrusted").SetValue(window, true);
        Call(window, "UpdateProtectedOperationControls");
    }
    private static string[] Draft(MainWindow window) => new[] { "CreatePasswordBox", "CreatePasswordConfirmBox", "CreatePinBox", "CreatePinConfirmBox", "GeneratedPasswordFirstBox", "GeneratedPasswordSecondBox" }
        .Select(name => C<TextBox>(window, name).Text ?? "").ToArray();
    private static void Fill(MainWindow window)
    {
        C<TextBox>(window, "CreatePasswordBox").Text = Password;
        C<TextBox>(window, "CreatePasswordConfirmBox").Text = Password;
        C<TextBox>(window, "CreatePinBox").Text = Pin;
        C<TextBox>(window, "CreatePinConfirmBox").Text = Pin;
        C<TextBox>(window, "GeneratedPasswordFirstBox").Text = FactorA;
        C<TextBox>(window, "GeneratedPasswordSecondBox").Text = FactorB;
        Dispatcher.UIThread.RunJobs();
    }

    private static void PreflightState(MainWindow window)
    {
        string root = MacSafeFileSystem.ResolveExistingRealPath(Directory.CreateTempSubdirectory("kv-rev12-preflight-").FullName);
        string source = Path.Combine(root, "public-source.txt");
        string target = Path.Combine(root, "public-target.kzpaq");
        File.WriteAllText(source, "public REV12 preflight fixture");
        using GeneratedArchiveEntropy prepared = Entropy(dual: true);
        var warnings = new List<SecurityDialogKind>();
        MainWindow.TestHookShowDialogAsync = (kind, _) => { warnings.Add(kind); return Task.CompletedTask; };
        try
        {
            Enable(window);
            C<CheckBox>(window, "EncryptBox").IsChecked = true;
            C<ListBox>(window, "InputList").Items.Add(source);
            C<TextBox>(window, "ArchivePathBox").Text = target;
            // Headless TopLevel's BCL provider returns a real existing folder;
            // retain the ordinary native scoped-resource lease and path checks.
            IStorageFolder destination = window.StorageProvider.TryGetFolderFromPathAsync(
                new Uri(root + Path.DirectorySeparatorChar)).GetAwaiter().GetResult()
                ?? throw new InvalidOperationException("The public fixture folder was not resolved by the storage provider.");
            F("_archiveDestinationAccess").SetValue(window, MacStorageAccessLease.Acquire(destination));
            F("_generatedEntropy").SetValue(window, prepared);
            F("_generatedPairReady").SetValue(window, true);
            Fill(window);
            string[] before = Draft(window);
            Click(window, "CreateArchiveButton");
            Pump(window);
            Require(warnings.Count == 1 && warnings[0] == SecurityDialogKind.Warning, "Missing key sheet was not an expected preflight warning.");
            Require(Draft(window).SequenceEqual(before) && ReferenceEquals(F("_generatedEntropy").GetValue(window), prepared)
                && prepared.HasPendingEncryptionParameters && !prepared.ConsumptionStarted,
                "Missing key sheet erased or consumed the prepared draft.");
            Require(!File.Exists(target), "Key-sheet preflight published an archive.");

            object data = Call(window, "BuildKeySheetData")!;
            Call(window, "MarkKeySheetHandled", data);
            string? binding = (string?)F("_keySheetFingerprint").GetValue(window);
            C<TextBox>(window, "ArchivePathBox").Text = target;
            foreach (string tag in new[] { "en", "de", "en" })
            {
                ComboBox language = C<ComboBox>(window, "LanguageBox");
                language.SelectedItem = language.Items.OfType<ComboBoxItem>().Single(item => Equals(item.Tag, tag));
                Dispatcher.UIThread.RunJobs();
                Require((string?)F("_keySheetFingerprint").GetValue(window) == binding, "Localization or identical target invalidated a key sheet.");
            }
            File.WriteAllText(target, "public foreign target must be preserved");
            byte[] foreign = File.ReadAllBytes(target);
            Click(window, "CreateArchiveButton");
            Pump(window);
            Require(warnings.Count == 2 && warnings[^1] == SecurityDialogKind.Warning && Draft(window).SequenceEqual(before)
                && prepared.HasPendingEncryptionParameters && File.ReadAllBytes(target).SequenceEqual(foreign)
                && (string?)F("_keySheetFingerprint").GetValue(window) == binding,
                "Existing-target warning lost inputs, binding, entropy or the foreign object.");
            C<TextBox>(window, "ArchivePathBox").Text = Path.Combine(root, "corrected-target.kzpaq");
            Dispatcher.UIThread.RunJobs();
            Require(F("_keySheetFingerprint").GetValue(window) is null && Draft(window).SequenceEqual(before)
                && prepared.HasPendingEncryptionParameters, "A real path change erased credentials instead of only the print binding.");

            // Delayed warning plus a second click must retain single ownership.
            var dialog = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            int dialogCalls = 0;
            MainWindow.TestHookShowDialogAsync = (_, _) => ++dialogCalls == 1 ? dialog.Task : Task.CompletedTask;
            Click(window, "CreateArchiveButton");
            Dispatcher.UIThread.RunJobs();
            Require((int)F("_operationActive").GetValue(window)! == 1, "A delayed warning released its UI owner too early.");
            Click(window, "CreateArchiveButton");
            bool singleOwnerWhileWarning = (int)F("_operationActive").GetValue(window)! == 1;
            C<TextBox>(window, "CreatePasswordBox").Text = Password + "!";
            dialog.SetResult();
            Pump(window);
            bool newerDraftRetained = C<TextBox>(window, "CreatePasswordBox").Text == Password + "!";
            bool entropyRetained = prepared.HasPendingEncryptionParameters && !prepared.ConsumptionStarted;
            bool ownerReleased = (int)F("_operationActive").GetValue(window)! == 0;
            bool createEnabled = C<Button>(window, "CreateArchiveButton").IsEnabled;
            Console.WriteLine($"    REV12 preflight: warningDialogs={dialogCalls}; singleOwner={singleOwnerWhileWarning}; newerDraftRetained={newerDraftRetained}; entropyRetained={entropyRetained}; ownerReleased={ownerReleased}; createEnabled={createEnabled}");
            Require(dialogCalls is 1 or 2, "The delayed warning flow opened an unexpected number of dialogs.");
            Require(singleOwnerWhileWarning, "The second click changed the first warning's operation ownership.");
            Require(newerDraftRetained, "A stale warning callback erased the newer draft.");
            Require(entropyRetained, "The delayed warning or second click consumed the prepared entropy.");
            Require(ownerReleased, "The warning completion retained the operation gate.");
            Require(createEnabled, "The warning completion did not restore the creation control.");
            Require(!File.Exists(Path.Combine(root, "corrected-target.kzpaq")), "Delayed preflight generated an output.");
            Require(SHA256.HashData(File.ReadAllBytes(source)).SequenceEqual(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("public REV12 preflight fixture"))), "Preflight changed the source.");
            Call(window, "FlushConsoleEntries");
            string log = C<TextBox>(window, "LogBox").Text ?? "";
            Require(!log.Contains(Password, StringComparison.Ordinal) && !log.Contains(FactorA, StringComparison.Ordinal)
                && !log.Contains(FactorB, StringComparison.Ordinal), "A preflight warning retained synthetic credentials in the security log.");
        }
        finally
        {
            MainWindow.TestHookShowDialogAsync = null;
            window.ClearCreateSecrets();
            Directory.Delete(root, recursive: true);
        }
    }

    private static void ExtractPreflight(MainWindow window)
    {
        Enable(window);
        string[] fields = ["ExtractPasswordBox", "ExtractPinBox", "ExtractGeneratedPasswordFirstBox", "ExtractGeneratedPasswordSecondBox"];
        string[] values = [Password, Pin, FactorA, FactorB];
        MainWindow.TestHookShowDialogAsync = (kind, _) => { Require(kind == SecurityDialogKind.Warning, "Missing input opened a fatal dialog."); return Task.CompletedTask; };
        try
        {
            foreach (string button in new[] { "ExtractArchiveButton", "ListArchiveButton", "EmergencyRecoveryButton" })
            {
                for (int i = 0; i < fields.Length; ++i)
                {
                    if (i < 2) C<TextBox>(window, fields[i]).Text = values[i];
                    else C<FactorTextBox>(window, fields[i]).Text = values[i];
                }
                C<TextBox>(window, "ExtractArchiveBox").Text = "";
                C<TextBox>(window, "OutputFolderBox").Text = "";
                Click(window, button);
                Pump(window);
                Require(fields.Select((name, index) => index < 2
                    ? C<TextBox>(window, name).Text ?? ""
                    : C<FactorTextBox>(window, name).Text ?? "").SequenceEqual(values), "Missing input erased extraction credentials.");
                Require(C<Button>(window, button).IsEnabled, "Missing input left an extraction operation busy.");
            }
        }
        finally { MainWindow.TestHookShowDialogAsync = null; window.ClearExtractSecrets(); }
    }

    private static void VerificationCleanup(MainWindow window)
    {
        const string cleanupSentinel = "Injected public plaintext cleanup failure.";
        const string primarySentinel = "Injected public verification read failure.";
        foreach (bool primaryFailure in new[] { false, true })
        {
            string root = MacSafeFileSystem.ResolveExistingRealPath(Directory.CreateTempSubdirectory("kv-rev12-cleanup-owner-").FullName);
            string source = Path.Combine(root, "public-source.bin");
            string target = Path.Combine(root, "public-archive.zpaq");
            string committed = target + ".committed";
            string? verificationRoot = null; // The whole private verifyParent, not only its extracted child.
            SafeFileHandle? verificationParentHandle = null;
            MacFileIdentity verificationParentIdentity = default;
            byte[]? committedHash = null;
            byte[] sourceData = Enumerable.Range(0, 4096).Select(x => (byte)x).ToArray();
            byte[] foreign = "public foreign committed-path replacement"u8.ToArray();
            File.WriteAllBytes(source, sourceData);
            int cleanupCalls = 0;
            var dialogs = new List<SecurityDialogKind>();
            MainWindow.TestHookShowDialogAsync = (kind, _) => { dialogs.Add(kind); return Task.CompletedTask; };
            MainWindow.TestHookBeforeVerificationExtraction = path =>
            {
                verificationRoot = path;
                verificationParentHandle = MacSafeFileSystem.OpenDirectoryHandle(path);
                verificationParentIdentity = MacSafeFileSystem.GetIdentity(verificationParentHandle);
                MacSafeFileSystem.RequirePathStillNamesHandle(verificationParentHandle, path);
                if (primaryFailure) throw new IOException(primarySentinel);
            };
            MainWindow.TestHookBeforeVerificationRootCleanup = () =>
            {
                cleanupCalls++;
                Require(verificationRoot is not null, "The actual caller never bound its verification root.");
                Require(File.Exists(target), "The cleanup fixture did not reach a committed archive.");
                if (!primaryFailure)
                    Require(Directory.EnumerateFiles(verificationRoot!, "*", SearchOption.AllDirectories).Any(),
                        "The actual verification did not produce a private plaintext copy.");
                committedHash = SHA256.HashData(File.ReadAllBytes(target));
                File.Move(target, committed);
                File.WriteAllBytes(target, foreign);
                throw new IOException(cleanupSentinel);
            };
            try
            {
                Enable(window);
                C<ListBox>(window, "InputList").Items.Clear();
                C<ListBox>(window, "InputList").Items.Add(source);
                C<CheckBox>(window, "EncryptBox").IsChecked = false;
                C<CheckBox>(window, "DeleteOriginalsBox").IsChecked = true;
                C<ComboBox>(window, "CompressionBox").SelectedIndex = 0;
                C<TextBox>(window, "ArchivePathBox").Text = target;
                IStorageFolder destination = window.StorageProvider.TryGetFolderFromPathAsync(new Uri(root + Path.DirectorySeparatorChar))
                    .GetAwaiter().GetResult() ?? throw new InvalidOperationException("The public cleanup fixture folder is unavailable.");
                F("_archiveDestinationAccess").SetValue(window, MacStorageAccessLease.Acquire(destination));
                F("_resourcePolicy").SetValue(window, new ArchiveOperationPolicy(string.Empty, root));
                Fill(window);
                Click(window, "CreateArchiveButton");
                Pump(window, timeoutSeconds: 30);
                Require(cleanupCalls == 1, "The create owner did not execute its actual verification cleanup once.");
                Require(!(bool)F("_operationReportedSuccess").GetValue(window)! && (bool)F("_operationReportedFailure").GetValue(window)!,
                    "The create owner reported successful completion after plaintext cleanup failed.");
                Require((int)F("_operationActive").GetValue(window)! == 0 && C<Button>(window, "CreateArchiveButton").IsEnabled,
                    "The failed cleanup retained its operation owner or disabled creation.");
                Require(dialogs.Contains(SecurityDialogKind.Error) && !dialogs.Contains(SecurityDialogKind.Information),
                    "The failed cleanup announced archive success.");
                Require(File.ReadAllBytes(target).SequenceEqual(foreign) && committedHash is not null
                    && SHA256.HashData(File.ReadAllBytes(committed)).SequenceEqual(committedHash),
                    "Downstream cleanup failure deleted or modified a committed/foreign output.");
                Require(primaryFailure ? File.ReadAllBytes(source).SequenceEqual(sourceData) : !File.Exists(source),
                    "The verification failure crossed the wrong original-deletion boundary.");
                Require(Draft(window).All(string.IsNullOrEmpty), "The failed active operation retained credential controls.");
                Call(window, "FlushConsoleEntries");
                string log = C<TextBox>(window, "LogBox").Text ?? "";
                Require(log.Contains(cleanupSentinel, StringComparison.Ordinal), "The actual owner concealed the cleanup cause.");
                if (primaryFailure)
                    Require(log.Contains(primarySentinel, StringComparison.Ordinal), "Cleanup failure masked the actual verification cause.");
            }
            finally
            {
                // Do not release/erase fixture owners while actual caller work
                // could still be alive, even if an earlier assertion timed out.
                if ((int)F("_operationActive").GetValue(window)! != 0)
                {
                    Call(window, "CancelOperation_Click", null, new RoutedEventArgs());
                    Pump(window, timeoutSeconds: 30);
                }
                MainWindow.TestHookBeforeVerificationExtraction = null;
                MainWindow.TestHookBeforeVerificationRootCleanup = null;
                MainWindow.TestHookShowDialogAsync = null;
                C<CheckBox>(window, "DeleteOriginalsBox").IsChecked = false;
                C<ListBox>(window, "InputList").Items.Clear();
                window.ClearCreateSecrets();
                try
                {
                    if (verificationRoot is not null && verificationParentHandle is not null)
                        MainWindow.CleanupBoundVerificationRoot(verificationParentHandle, verificationRoot, verificationParentIdentity);
                }
                finally
                {
                    verificationParentHandle?.Dispose();
                    Directory.Delete(root, recursive: true);
                }
            }
        }
    }

    private static void KdfMinimumPreflight(MainWindow window)
    {
        string root = MacSafeFileSystem.ResolveExistingRealPath(Directory.CreateTempSubdirectory("kv-rev12-kdf-preflight-").FullName);
        string source = Path.Combine(root, "public-source.txt"), target = Path.Combine(root, "public.kzpaq");
        File.WriteAllText(source, "public minimum-admission fixture");
        using GeneratedArchiveEntropy prepared = Entropy(dual: false);
        var phases = new OperationPhaseProfile.Measurements();
        using IDisposable phaseScope = OperationPhaseProfile.ObserveForTests(phases);
        int warnings = 0, reservations = 0;
        MainWindow.TestHookShowDialogAsync = (kind, _) =>
        { Require(kind == SecurityDialogKind.Warning, "The known minimum refusal was not a preflight warning."); warnings++; return Task.CompletedTask; };
        KalynaContainerService.TestHookAfterOutputReservation = _ => reservations++;
        try
        {
            Enable(window);
            C<CheckBox>(window, "EncryptBox").IsChecked = true;
            C<ListBox>(window, "InputList").Items.Add(source);
            C<TextBox>(window, "ArchivePathBox").Text = target;
            IStorageFolder destination = window.StorageProvider.TryGetFolderFromPathAsync(new Uri(root + Path.DirectorySeparatorChar))
                .GetAwaiter().GetResult() ?? throw new InvalidOperationException("The public fixture folder is unavailable.");
            F("_archiveDestinationAccess").SetValue(window, MacStorageAccessLease.Acquire(destination));
            F("_resourcePolicy").SetValue(window, new ArchiveOperationPolicy(string.Empty, root,
                preferences: new ResourcePreferences { MemoryMode = ResourceMode.Manual, ManualMemoryLimitBytes = 64L << 20 }));
            F("_generatedEntropy").SetValue(window, prepared);
            F("_generatedPairReady").SetValue(window, true);
            Fill(window);
            Call(window, "MarkKeySheetHandled", Call(window, "BuildKeySheetData")!);
            string[] before = Draft(window);
            string? binding = (string?)F("_keySheetFingerprint").GetValue(window);
            Click(window, "CreateArchiveButton"); Pump(window);
            Require(warnings == 1 && Draft(window).SequenceEqual(before), "A known 64-MiB resource refusal erased the GUI draft.");
            Require(prepared.HasPendingEncryptionParameters && !prepared.ConsumptionStarted
                && ReferenceEquals(F("_generatedEntropy").GetValue(window), prepared), "The known resource refusal consumed or replaced preparation.");
            Require((string?)F("_keySheetFingerprint").GetValue(window) == binding, "The known resource refusal invalidated the unchanged key sheet.");
            Require(reservations == 0 && !File.Exists(target) && Directory.GetFiles(root, "*.encrypted-part").Length == 0,
                "The GUI started output work before checking the known KDF minimum.");
            Require(phases.Snapshot().Aggregates.Where(x => x.Phase is "KdfRound1" or "KdfRound2" or "ZpaqArchive").All(x => x.Calls == 0),
                "The GUI started KDF or ZPAQ work before the known minimum admission.");
            Require((int)F("_operationActive").GetValue(window)! == 0 && C<Button>(window, "CreateArchiveButton").IsEnabled,
                "The resource warning retained operation ownership.");
        }
        finally
        {
            MainWindow.TestHookShowDialogAsync = null;
            KalynaContainerService.TestHookAfterOutputReservation = null;
            window.ClearCreateSecrets();
            Directory.Delete(root, recursive: true);
        }
    }

    private static async Task CoreKdfMinimumPreflightAsync()
    {
        string root = MacSafeFileSystem.ResolveExistingRealPath(Directory.CreateTempSubdirectory("kv-rev12-core-kdf-min-").FullName);
        using GeneratedArchiveEntropy prepared = Entropy(dual: false);
        var lifetime = new ArchiveOperationLifetime();
        var policy = new ArchiveOperationPolicy(string.Empty, root,
            preferences: new ResourcePreferences { MemoryMode = ResourceMode.Manual, ManualMemoryLimitBytes = 64L << 20 });
        using IDisposable policyScope = policy.EnterScope();
        var phases = new OperationPhaseProfile.Measurements();
        using IDisposable phaseScope = OperationPhaseProfile.ObserveForTests(phases);
        int reservations = 0;
        KalynaContainerService.TestHookAfterOutputReservation = _ => reservations++;
        try
        {
            using var source = new MemoryStream(new byte[4096], writable: false);
            try
            {
                await new KalynaContainerService().EncryptZpaqStreamWithPreparedEntropyAsync(source, Path.Combine(root, "public.kzpaq"),
                    Password, Pin, FactorA, FactorB, EncryptionSuite.StandardCascade, prepared, null, null,
                    CancellationToken.None, lifetime).ConfigureAwait(false);
                throw new InvalidOperationException("The public production KDF minimum was not rejected.");
            }
            catch (ArchivePreflightException refusal) when (refusal.Reason == ArchivePreflightReason.Resources) { }
            Require(reservations == 0 && Directory.GetFileSystemEntries(root).Length == 0,
                "The shared core reserved output before rejecting the known minimum.");
            Require(prepared.HasPendingEncryptionParameters && !prepared.ConsumptionStarted && !lifetime.MustClearCredentials,
                "The shared core consumed preparation before minimum admission.");
            Require(phases.Snapshot().Aggregates.Where(x => x.Phase is "KdfRound1" or "KdfRound2").All(x => x.Calls == 0),
                "The shared core entered the KDF before the known minimum refusal.");
        }
        finally { KalynaContainerService.TestHookAfterOutputReservation = null; Directory.Delete(root, recursive: true); }
    }

    private static Task ConsumeBoundaryAsync()
    {
        long locks = SecureMemory.LockedAllocationsForTests;
        foreach (bool dual in new[] { false, true })
        {
            using GeneratedArchiveEntropy entropy = Entropy(dual);
            EncryptionSuite suite = dual ? EncryptionSuite.ParanoiaCascade : EncryptionSuite.StandardCascade;
            var lifetime = new ArchiveOperationLifetime();
            Require(entropy.HasPendingEncryptionParameters && !lifetime.MustClearCredentials, "Unconsumed single-round preparation was unavailable.");
            entropy.ValidateForEncryption(suite, FactorA, FactorB);
            Expect<InvalidOperationException>(() => entropy.ValidateForEncryption(suite, FactorB, FactorA));
            Require(entropy.HasPendingEncryptionParameters && !entropy.ConsumptionStarted, "Read-only factor validation consumed entropy.");
            GeneratedArchiveEntropy.TestHookAfterConsumption = () => throw new InvalidDataException("public injected post-consumption failure");
            try
            {
                Expect<InvalidDataException>(() =>
                {
                    if (dual) { using var ignored = entropy.ConsumeTwoRoundEncryptionParameters(suite, FactorA, FactorB, lifetime); }
                    else { var pair = entropy.ConsumeEncryptionParameters(suite, FactorA, FactorB, lifetime); pair.Salt.Dispose(); pair.Nonce.Dispose(); }
                });
            }
            finally { GeneratedArchiveEntropy.TestHookAfterConsumption = null; }
            Require(entropy.ConsumptionStarted && lifetime.ConsumptionStarted && lifetime.MustClearCredentials
                && !entropy.HasPendingEncryptionParameters, "A throwing consuming call appeared reusable after the irreversible handoff.");
            Expect<InvalidOperationException>(() => entropy.ValidateForEncryption(suite, FactorA, FactorB));
        }
        Require(SecureMemory.LockedAllocationsForTests == locks, "Consume-boundary fault retained a locked entropy allocation.");
        return Task.CompletedTask;
    }

    private static async Task OutputRaceAsync()
    {
        string root = MacSafeFileSystem.ResolveExistingRealPath(Directory.CreateTempSubdirectory("kv-rev12-output-race-").FullName);
        byte[] foreign = "public foreign collision fixture"u8.ToArray();
        var service = new KalynaContainerService();
        try
        {
            foreach (bool late in new[] { false, true })
            {
                string target = Path.Combine(root, late ? "late.kzpaq" : "early.kzpaq");
                using GeneratedArchiveEntropy entropy = Entropy(dual: false);
                var lifetime = new ArchiveOperationLifetime();
                KalynaContainerService.TestHookAfterOutputReservation = path =>
                {
                    if (!late) File.WriteAllBytes(path, foreign);
                };
                await using var payload = new CollisionStream(new byte[1024], () => File.WriteAllBytes(target, foreign), trigger: late);
                try
                {
                    await service.EncryptZpaqStreamWithPreparedEntropyAsync(payload, target, Password, Pin, FactorA, FactorB,
                        EncryptionSuite.StandardCascade, entropy, null, null, CancellationToken.None, lifetime);
                    throw new InvalidOperationException("A collision unexpectedly published an encrypted result.");
                }
                catch (ArchivePreflightException) when (!late) { }
                catch (Win32Exception collision) when (late && collision.NativeErrorCode == 17 /* macOS EEXIST */) { }
                Require(File.ReadAllBytes(target).SequenceEqual(foreign), "An output collision overwrote or deleted a foreign target.");
                Require(late ? lifetime.ConsumptionStarted && entropy.ConsumptionStarted && !entropy.HasPendingEncryptionParameters
                    : !lifetime.ConsumptionStarted && !entropy.ConsumptionStarted && entropy.HasPendingEncryptionParameters,
                    "The early/late output collision crossed the wrong entropy-consumption boundary.");
                Require(!Directory.EnumerateFiles(root, "*.encrypted-part").Any(), "An output-collision cleanup retained its own temporary object.");
            }
        }
        finally { KalynaContainerService.TestHookAfterOutputReservation = null; Directory.Delete(root, recursive: true); }
    }

    private sealed class CollisionStream(byte[] payload, Action createForeignTarget, bool trigger) : MemoryStream(payload, writable: false)
    {
        private int _triggered;
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (trigger && Interlocked.Exchange(ref _triggered, 1) == 0) createForeignTarget();
            return base.ReadAsync(buffer, cancellationToken);
        }
    }

    private static GeneratedArchiveEntropy Entropy(bool dual)
    {
        LockedSensitiveBuffer? salt = LockedSensitiveBuffer.Create(EntropyMixer.SaltPairBytes);
        LockedSensitiveBuffer? nonce = LockedSensitiveBuffer.Create(EncryptionSuiteCatalog.ArchiveNonceBytes);
        LockedSensitiveBuffer? secondSalt = dual ? LockedSensitiveBuffer.Create(EntropyMixer.SaltPairBytes) : null;
        LockedSensitiveBuffer? secondNonce = dual ? LockedSensitiveBuffer.Create(EncryptionSuiteCatalog.ArchiveNonceBytes) : null;
        try
        {
            salt.Bytes.AsSpan(0, EntropyMixer.SaltPairBytes / 2).Fill(0x17);
            salt.Bytes.AsSpan(EntropyMixer.SaltPairBytes / 2).Fill(0x19);
            nonce.Bytes.AsSpan().Fill(0x2B);
            if (secondSalt is not null)
            {
                secondSalt.Bytes.AsSpan(0, EntropyMixer.SaltPairBytes / 2).Fill(0xA1);
                secondSalt.Bytes.AsSpan(EntropyMixer.SaltPairBytes / 2).Fill(0xA3);
            }
            if (secondNonce is not null) secondNonce.Bytes.AsSpan().Fill(0xD3);
            var result = new GeneratedArchiveEntropy(FactorA, FactorB, salt, nonce, secondSalt, secondNonce);
            salt = nonce = secondSalt = secondNonce = null;
            return result;
        }
        finally { secondNonce?.Dispose(); secondSalt?.Dispose(); nonce?.Dispose(); salt?.Dispose(); }
    }
    private static void Expect<T>(Action action) where T : Exception
    { try { action(); } catch (T) { return; } throw new InvalidOperationException("Expected lifecycle refusal was not raised."); }

}
