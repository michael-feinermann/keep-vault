using KeepVaultMac.Controls;
using System.Collections.Concurrent;
using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using KalynaArchiver;
using KalynaArchiver.Gui;
using KalynaArchiver.Services;
using Microsoft.Win32.SafeHandles;

/// <summary>
/// Drives the real <see cref="MainWindow"/> through Avalonia's headless
/// windowing backend.
/// </summary>
/// <remarks>
/// The window, its XAML, its event wiring and its code-behind are exactly the
/// ones the signed app ships; only the platform backend is swapped for one that
/// needs no display. Input is injected as genuine pointer and property events
/// rather than by calling handlers directly, so the wiring itself is under test.
/// </remarks>
internal static class MacGuiTests
{
    /// <summary>Settings store that keeps preferences in memory.</summary>
    /// <remarks>
    /// Keeps the suite from reading or writing the real user's isolated storage,
    /// so a test run cannot change what the installed app shows on next launch.
    /// </remarks>
    private sealed class InMemorySettingsStore : IAppSettingsStore
    {
        private readonly ConcurrentDictionary<string, string> _values = new(StringComparer.Ordinal);

        public string? Read(string key) => _values.TryGetValue(key, out string? value) ? value : null;

        public void Write(string key, string value) => _values[key] = value;
    }

    internal static TestCase[] Tests =>
    [
        new("gui.entropy-display", "GUI eleven-pool entropy display beyond the 1024 minimum", () => RunOnUiThread(TestEntropyDisplayGrowsPastMinimum), TestResource.Gui, "GUI"),
        new("gui.encryption-toggle-target", "GUI encryption toggle and target normalization", () => RunOnUiThread(TestEncryptionToggle), TestResource.Gui, "GUI"),
        new("gui.folder-target", "GUI folder target lands beside the folder", () => RunOnUiThread(TestFolderTargetSuggestion), TestResource.Gui, "GUI"),
        new("gui.destination-folder-target", "GUI destination picker keeps the archive inside its retained folder", () => RunOnUiThread(TestDestinationFolderTargetSuggestion), TestResource.Gui, "GUI"),
        new("gui.archive-picker-filter-reset", "GUI archive picker does not poison the shared macOS folder panel", () => RunOnUiThread(TestArchivePickerFilterReset), TestResource.Gui, "GUI"),
        new("gui.password-policy", "GUI password policy feedback", () => RunOnUiThread(TestPasswordPolicyFeedback), TestResource.Gui, "GUI"),
        new("gui.credential-policy-boundary", "GUI creation pair policy and extraction without model evaluation in both languages", () => RunOnUiThread(TestCredentialPolicyBoundary), TestResource.Gui, "GUI"),
        new("gui.original-deletion-localization", "GUI verified-original-deletion localization", () => RunOnUiThread(TestDeleteOriginalsLocalization), TestResource.Gui, "GUI"),
        new("gui.erase-completion-status", "GUI erase completion survives deferred text events and language changes", () => RunOnUiThread(TestEraseCompletionSurvivesDeferredTextChange), TestResource.Gui, "GUI"),
        new("gui.resource-policy", "GUI resource choices freeze validated per-operation limits in both languages", () => RunOnUiThread(TestResourcePolicy), TestResource.Gui, "GUI"),
        new("gui.rev11-preference-restart", "Auto/manual preferences survive restart and obsolete time fields stay inactive", () => RunOnUiThread(TestResourcePreferenceRestart), TestResource.Gui, "GUI"),
        new("gui.rev11-progress", "real phase widgets, unknown work, DE/EN, cancellation and authoritative completion", () => RunOnUiThread(TestRev11Progress), TestResource.Gui, "GUI"),
        new("gui.rev11-observer-isolation", "throwing progress presentation and observer cleanup cannot retain operation ownership", () => RunOnUiThread(TestRev11ObserverIsolation), TestResource.Gui, "GUI"),
        new("gui.control-inventory", "GUI reference control inventory", () => RunOnUiThread(TestReferenceControlsPresent), TestResource.Gui, "GUI"),
        new("gui.factor-normalization", "GUI 256-character factor normalization and field handling", () => RunOnUiThread(TestFactorBoxesLengthAndNormalization), TestResource.Gui, "GUI"),
        new("gui.secret-clearing", "GUI secret clearing wipes password, PIN, and factors", () => RunOnUiThread(TestSecretClearing), TestResource.Gui, "GUI"),
        new("gui.streaming-thread-boundary", "GUI streaming callbacks execute off-thread without accessing controls", () => RunOnUiThread(TestStreamingThreadBoundary), TestResource.Gui, "GUI"),
        new("gui.create-failure-secret-clearing", "GUI create handler wipes credentials after an adversarial failure", () => RunOnUiThread(TestCreateFailureSecretClearing), TestResource.Gui, "GUI"),
        new("gui.extract-list-failure-secret-clearing", "GUI extract/list handlers wipe credentials after adversarial failures", () => RunOnUiThread(TestExtractListFailureSecretClearing), TestResource.Gui, "GUI"),
        new("gui.recovery-failure-secret-clearing", "GUI recovery handler wipes credentials after an adversarial failure", () => RunOnUiThread(TestRecoveryFailureSecretClearing), TestResource.Gui, "GUI"),
        new("gui.kdf-entropy-localization", "GUI KDF and entropy profile description localization", () => RunOnUiThread(TestKdfAndEntropyLocalization), TestResource.Gui, "GUI"),
        new("gui.cups-spool-warning-localization", "GUI warns about CUPS and printer spool persistence in both languages", () => RunOnUiThread(TestCupsSpoolWarningLocalization), TestResource.Gui, "GUI"),
        new("gui.failed-archive-preservation", "GUI downstream failure preserves committed path replacements", () => RunOnUiThread(TestFailedArchivePreservation), TestResource.Gui, "GUI"),
        new("gui.verification-root-cleanup-identity", "GUI verification plaintext cleanup stays descriptor-bound", () => RunOnUiThread(TestVerificationRootCleanupIdentity), TestResource.Gui, "GUI"),
        new("keysheet.pair-cleanup-identity", "key-sheet pair rollback preserves pathname replacements", () => RunOnUiThread(TestKeySheetPairCleanupIdentity), TestResource.Gui, "GUI"),
        new("keysheet.cleanup-failure-visible", "key-sheet cleanup failures remain visible with the export failure", () => RunOnUiThread(TestKeySheetCleanupFailureVisible), TestResource.Gui, "GUI"),
        new("keysheet.pair-atomic-commit", "key-sheet pair final gate rolls both outputs back safely", () => RunOnUiThread(TestKeySheetPairAtomicCommit), TestResource.Gui, "GUI"),
        new("gui.entropy-rev9-phases-cancel", "GUI REV9 single/dual phases, eleven counters and joined cancellation", () => RunOnUiThread(TestRev9EntropyPhasesAndCancel), TestResource.Gui, "GUI"),
        new("gui.rev12-live-capture-during-preparation", "GUI pointer events fill the independent live epoch during dual preparation and retain capture guards", () => RunOnUiThread(TestLiveCaptureDuringDualPreparation), TestResource.Gui, "GUI"),
        new("gui.operation-cancel-lifetime", "GUI operation cancellation stays separate from disposed window lifetime", () => RunOnUiThread(TestOperationCancelLifetime), TestResource.Gui, "GUI"),
        new("gui.full-creation-flow", "GUI full creation flow with mouse sampling and factor generation", () => RunOnUiThread(TestFullCreationFlowViaGui), TestResource.Gui, "GUI"),
    ];

    private static readonly BlockingCollection<(Action<MainWindow> Body, TaskCompletionSource Completion)> Work = new();
    private static Thread? _uiThread;

    /// <summary>
    /// Starts the single thread that owns the Avalonia headless platform, if it
    /// is not running yet.
    /// </summary>
    /// <remarks>
    /// Avalonia binds its UI thread to whichever thread sets the platform up,
    /// and the platform can only be set up once per process. A thread per test
    /// would therefore leave every test after the first queueing work onto a
    /// dispatcher whose thread has already exited, where it waits forever. One
    /// long-lived worker serves them all instead; the surrounding suite keeps
    /// the process main thread.
    /// </remarks>
    private static void EnsureUiThread()
    {
        if (_uiThread is not null)
        {
            return;
        }

        using var ready = new ManualResetEventSlim();
        Exception? startupFailure = null;
        _uiThread = new Thread(
            () =>
            {
                try
                {
                    AppBuilder.Configure<App>()
                        .UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = true })
                        .SetupWithoutStarting();
                }
                catch (Exception ex)
                {
                    startupFailure = ex;
                    return;
                }
                finally
                {
                    ready.Set();
                }

                // This thread is the UI thread, so each body runs inline; the
                // bodies pump the dispatcher themselves where they need to.
                foreach ((Action<MainWindow> body, TaskCompletionSource completion) in Work.GetConsumingEnumerable())
                {
                    MainWindow? window = null;
                    try
                    {
                        window = new MainWindow(new InMemorySettingsStore());
                        window.Show();
                        Dispatcher.UIThread.RunJobs();
                        body(window);
                        completion.SetResult();
                    }
                    catch (Exception ex)
                    {
                        completion.SetException(ex);
                    }
                    finally
                    {
                        try
                        {
                            window?.Close();
                            window?.Dispose();
                            Dispatcher.UIThread.RunJobs();
                        }
                        catch (Exception)
                        {
                            // A teardown fault must not mask the test result.
                        }
                    }
                }
            },
            maxStackSize: 16 * 1024 * 1024)
        {
            IsBackground = true,
            Name = "KeepVault headless UI",
        };

        _uiThread.Start();
        ready.Wait();
        if (startupFailure is not null)
        {
            throw new InvalidOperationException(
                $"The Avalonia headless platform could not be initialised: {startupFailure.Message}",
                startupFailure);
        }
    }

    internal static async Task RunOnUiThread(Action<MainWindow> body)
    {
        EnsureUiThread();
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Work.Add((body, completion));
        Task finished = await Task.WhenAny(completion.Task, Task.Delay(TimeSpan.FromMinutes(3))).ConfigureAwait(false);
        if (finished != completion.Task)
        {
            throw new TimeoutException("The headless GUI test did not finish within three minutes.");
        }

        await completion.Task.ConfigureAwait(false);
    }

    private static T Control<T>(MainWindow window, string name)
        where T : Control
        => window.FindControl<T>(name)
            ?? throw new InvalidOperationException($"The reference control is missing from the macOS window: {name}");

    private static void MoveMouse(MainWindow window, int moves)
    {
        for (int index = 0; index < moves; index++)
        {
            // Vary both axes so successive samples differ in more than one field.
            window.MouseMove(new Point(11 + (index % 337), 13 + (index % 521)));
        }

        Dispatcher.UIThread.RunJobs();
    }

    /// <summary>
    /// 1024 samples per pool is the threshold that unlocks generation, not a
    /// ceiling. Collection continues while the pointer moves, and the reported
    /// counts have to keep rising with it — an earlier build clamped the value
    /// the throttle compared against, which froze the entire status line at the
    /// threshold and made 512 look like a maximum.
    /// </summary>
    private static void TestEntropyDisplayGrowsPastMinimum(MainWindow window)
    {
        TextBlock status = Control<TextBlock>(window, "EntropyStatusText");
        ProgressBar progress = Control<ProgressBar>(window, "EntropyProgress");
        long required = EntropyMixer.RequiredMouseSamplesPerPurpose;

        long guard = 0;
        while (EntropyMixer.GetPoolStatus().Minimum < required)
        {
            MoveMouse(window, 512);
            if (++guard > 200)
            {
                throw new InvalidOperationException("The entropy pools never reached the required minimum.");
            }
        }

        EntropyPoolStatus atThreshold = EntropyMixer.GetPoolStatus();
        string textAtThreshold = status.Text ?? string.Empty;
        double progressAtThreshold = progress.Value;
        MacComprehensiveTests.Require(
            atThreshold.Minimum >= required,
            "The entropy pools did not reach the required minimum.");
        MacComprehensiveTests.Require(
            Control<Button>(window, "GeneratePasswordButton").IsEnabled,
            "Generation stayed locked after every pool reached the required minimum.");

        MoveMouse(window, 2560);

        EntropyPoolStatus beyond = EntropyMixer.GetPoolStatus();
        MacComprehensiveTests.Require(
            beyond.Minimum > atThreshold.Minimum,
            $"Sampling stopped at the {required}-sample minimum instead of continuing: {beyond.Minimum}.");
        MacComprehensiveTests.Require(
            beyond.Total > atThreshold.Total,
            "The total sample count stopped growing past the minimum.");
        MacComprehensiveTests.Require(
            !string.Equals(status.Text ?? string.Empty, textAtThreshold, StringComparison.Ordinal),
            "The entropy status line froze at the minimum instead of reporting the additional samples.");
        // The readout follows total accepted samples: independent routing can
        // leave the minimum unchanged while another pool grows. Check that the
        // displayed total catches up without assuming balanced pool counts.
        long reportedTotal = 0;
        for (int round = 0; round < 16; round++)
        {
            reportedTotal = EntropyMixer.GetPoolStatus().Total;
            if ((status.Text ?? string.Empty).Contains(
                    reportedTotal.ToString(CultureInfo.CurrentCulture),
                    StringComparison.Ordinal))
            {
                break;
            }

            MoveMouse(window, 1);
        }

        MacComprehensiveTests.Require(
            (status.Text ?? string.Empty).Contains(reportedTotal.ToString(CultureInfo.CurrentCulture), StringComparison.Ordinal),
            "The entropy status line never caught up with the current total sample count.");

        // The bar measures progress towards the minimum, so it stays full while
        // the reported counts keep climbing.
        MacComprehensiveTests.Require(
            Math.Abs(progress.Value - required) < 0.5 && Math.Abs(progressAtThreshold - required) < 0.5,
            "The entropy progress bar does not represent progress towards the required minimum.");
    }

    /// <summary>
    /// The encryption checkbox is wired in code rather than XAML on this
    /// platform, so drive the real control and assert the effects the Windows
    /// reference produces: the cipher selection follows the checkbox and the
    /// target archive extension is rewritten.
    /// </summary>
    /// <summary>
    /// A folder input must not suggest an archive inside that same folder.
    /// </summary>
    /// <remarks>
    /// Suggesting a target inside the input produced a path the safety check
    /// then refused, which reads to the user as the app objecting to a folder
    /// and a same-named archive coexisting. The suggestion has to be a path the
    /// app will actually accept.
    /// </remarks>
    private static void TestFolderTargetSuggestion(MainWindow window)
    {
        _ = window;
        string root = Directory.CreateTempSubdirectory("keep-vault-target-").FullName;
        try
        {
            string folder = Path.Combine(root, "Docs");
            Directory.CreateDirectory(folder);
            File.WriteAllText(Path.Combine(folder, "note.txt"), "content");
            File.WriteAllText(Path.Combine(root, "Docs.zip"), "not really a zip");

            string suggestion = MainWindow.SuggestTargetArchivePath(folder, encrypted: true);

            MacComprehensiveTests.Require(
                !suggestion.StartsWith(folder + Path.DirectorySeparatorChar, StringComparison.Ordinal),
                $"The suggested archive target is inside its own input folder: {suggestion}");
            MacComprehensiveTests.Require(
                string.Equals(Path.GetDirectoryName(suggestion), root, StringComparison.Ordinal),
                $"The suggested archive target is not beside the input folder: {suggestion}");
            MacComprehensiveTests.Require(
                Path.GetFileName(suggestion).StartsWith("Docs(", StringComparison.Ordinal),
                $"The suggested archive target is not named after the folder: {suggestion}");
            MacComprehensiveTests.Require(
                !File.Exists(suggestion) && !Directory.Exists(suggestion),
                $"The suggested archive target already exists: {suggestion}");

            // A same-named zip beside the folder must not block the folder: the
            // numbered name is claimed against what is actually on disk, so
            // once one target exists the next suggestion moves on by itself.
            string fromZip = MainWindow.SuggestTargetArchivePath(Path.Combine(root, "Docs.zip"), encrypted: true);
            MacComprehensiveTests.Require(
                !File.Exists(fromZip) && !Directory.Exists(fromZip),
                $"The suggested target for the same-named archive already exists: {fromZip}");

            File.WriteAllText(suggestion, "placeholder");
            string afterTaken = MainWindow.SuggestTargetArchivePath(folder, encrypted: true);
            MacComprehensiveTests.Require(
                !string.Equals(afterTaken, suggestion, StringComparison.Ordinal)
                    && !File.Exists(afterTaken),
                $"An occupied target name was suggested again: {afterTaken}");
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>
    /// A directory selected in the destination picker represents the granted
    /// parent, not an input. The suggestion must remain inside that exact
    /// folder so the retained security-scoped lease still covers the archive.
    /// </summary>
    private static void TestDestinationFolderTargetSuggestion(MainWindow window)
    {
        _ = window;
        string destination = Directory.CreateTempSubdirectory("keep-vault-destination-").FullName;
        try
        {
            File.WriteAllText(Path.Combine(destination, "archive(1).kzpaq"), "occupied");
            string encrypted = MainWindow.SuggestArchivePathInDestinationFolder(destination, encrypted: true);
            string plain = MainWindow.SuggestArchivePathInDestinationFolder(destination, encrypted: false);

            MacComprehensiveTests.Require(
                string.Equals(Path.GetDirectoryName(encrypted), destination, StringComparison.Ordinal)
                    && string.Equals(Path.GetFileName(encrypted), "archive(2).kzpaq", StringComparison.Ordinal),
                $"The encrypted picker suggestion escaped or reused its retained destination folder: {encrypted}");
            MacComprehensiveTests.Require(
                string.Equals(Path.GetDirectoryName(plain), destination, StringComparison.Ordinal)
                    && string.Equals(Path.GetFileName(plain), "archive(1).zpaq", StringComparison.Ordinal),
                $"The plain picker suggestion escaped its retained destination folder: {plain}");
        }
        finally
        {
            Directory.Delete(destination, recursive: true);
        }
    }

    /// <summary>
    /// Avalonia reuses the native NSOpenPanel. Leaving an archive type filter
    /// on that panel makes the following folder picker reject every directory.
    /// macOS therefore has to replace the retained native filter explicitly and
    /// validate the returned archive path itself. A null filter is not a reset:
    /// AppKit may retain the previous panel's content types.
    /// </summary>
    private static void TestArchivePickerFilterReset(MainWindow window)
    {
        _ = window;
        var archiveType = new FilePickerFileType("Regression archive")
        {
            Patterns = ["*.kzpaq", "*.zpaq"],
        };

        IReadOnlyList<FilePickerFileType>? pickerFilter = MainWindow.BuildArchivePickerFilter(archiveType);
        MacComprehensiveTests.Require(
            pickerFilter is { Count: 1 }
                && pickerFilter[0].Patterns is null
                && pickerFilter[0].AppleUniformTypeIdentifiers?.SequenceEqual(["public.data", "public.folder"]) == true,
            "The macOS archive picker did not expose concrete file/folder UTIs without an overriding wildcard pattern.");
        MacComprehensiveTests.Require(
            MainWindow.HasArchiveExtension("test.KZPAQ")
                && MainWindow.HasArchiveExtension("test.ZpAq")
                && !MainWindow.HasArchiveExtension("test.zip"),
            "The post-picker archive extension gate does not accept exactly .kzpaq/.zpaq case-insensitively.");
        MacComprehensiveTests.Require(
            MainWindow.HasEncryptedArchiveExtension("test.KzPaQ")
                && !MainWindow.HasEncryptedArchiveExtension("test.zpaq")
                && !MainWindow.HasEncryptedArchiveExtension("test.kzpaq.zip"),
            "The secure-erase picker extension gate does not accept exactly .kzpaq case-insensitively.");
    }

    private static void TestEncryptionToggle(MainWindow window)
    {
        CheckBox encrypt = Control<CheckBox>(window, "EncryptBox");
        ComboBox cipher = Control<ComboBox>(window, "CipherSuiteBox");
        TextBox archive = Control<TextBox>(window, "ArchivePathBox");
        Border passwordPanel = Control<Border>(window, "CreatePasswordPanel");

        MacComprehensiveTests.Require(encrypt.IsChecked == true, "Encryption is not the default.");

        archive.Text = "/tmp/keep-vault-gui/archive.kzpaq";
        encrypt.IsChecked = false;
        Dispatcher.UIThread.RunJobs();

        MacComprehensiveTests.Require(!cipher.IsEnabled, "The cipher suite stayed selectable without encryption.");
        MacComprehensiveTests.Require(!passwordPanel.IsEnabled, "The password panel stayed active without encryption.");
        MacComprehensiveTests.Require(
            string.Equals(archive.Text, "/tmp/keep-vault-gui/archive.zpaq", StringComparison.Ordinal),
            $"The target archive extension was not normalized for a plain archive: {archive.Text}");

        encrypt.IsChecked = true;
        Dispatcher.UIThread.RunJobs();

        MacComprehensiveTests.Require(cipher.IsEnabled, "The cipher suite stayed locked after re-enabling encryption.");
        MacComprehensiveTests.Require(passwordPanel.IsEnabled, "The password panel stayed disabled after re-enabling encryption.");
        MacComprehensiveTests.Require(
            string.Equals(archive.Text, "/tmp/keep-vault-gui/archive.kzpaq", StringComparison.Ordinal),
            $"The target archive extension was not restored for an encrypted archive: {archive.Text}");
    }

    /// <summary>
    /// Typing into the user-password box has to drive the live policy readout,
    /// which is the only feedback a user gets before the archive is created.
    /// </summary>
    private static void TestCredentialPolicyBoundary(MainWindow window)
    {
        ComboBox language = Control<ComboBox>(window, "LanguageBox");
        TextBox createPassword = Control<TextBox>(window, "CreatePasswordBox");
        TextBox createPin = Control<TextBox>(window, "CreatePinBox");
        TextBox confirmPin = Control<TextBox>(window, "CreatePinConfirmBox");
        TextBlock pinStatus = Control<TextBlock>(window, "PinPolicyStatusText");
        MethodInfo extraction = typeof(MainWindow).GetMethod("EnsureExtractionFactors", BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("Missing real extraction input gate.");
        foreach (string locale in new[] { "de", "en" })
        {
            SelectLanguage(language, locale);
            string version = Control<TextBlock>(window, "VersionText").Text ?? string.Empty;
            MacComprehensiveTests.Require(version == "Version 5.0.3", "The visible release version differs from the expected app build.");
            createPassword.Text = "N!r7$Vq2#Lm8%Tx3&Jd9*Wp4+Kg5=Zu6?Ce428317";
            createPin.Text = "428317";
            confirmPin.Text = "428317";
            Dispatcher.UIThread.RunJobs();
            MacComprehensiveTests.Require((pinStatus.Text ?? string.Empty).Contains(
                locale == "de" ? "nicht im Passwort" : "not be contained", StringComparison.Ordinal),
                "Changing the final pair did not show the localized PIN-substring rejection.");

            TextBox password = Control<TextBox>(window, "ExtractPasswordBox");
            TextBox pin = Control<TextBox>(window, "ExtractPinBox");
            Control<FactorTextBox>(window, "ExtractGeneratedPasswordFirstBox").Text = new string('A', 256);
            Control<FactorTextBox>(window, "ExtractGeneratedPasswordSecondBox").Text = new string('B', 256);
            int evaluationAttempts = 0;
            using (PasswordGuessabilityService.ForbidEvaluationForTesting(() => evaluationAttempts++))
            {
                foreach ((string rawPassword, string rawPin) in new[]
                {
                    (string.Empty, string.Empty),
                    ("x", "1"),
                    ("428317", "428317"),
                    ("Sommer Wiese Mond Vulkan Fluss Orange Wolke 2026!", "060926"),
                    (new string('x', 300), "42831795016283740"),
                })
                {
                    password.Text = rawPassword;
                    pin.Text = rawPin;
                    Dispatcher.UIThread.RunJobs();
                    MacComprehensiveTests.Require(password.Text == rawPassword && pin.Text == rawPin,
                        "Extraction controls truncated original credential data using creation limits.");
                    extraction.Invoke(window, null);
                }
                foreach (string nonAsciiPin in new[] { "１２３４５６", "428 317", "42831x" })
                {
                    pin.Text = nonAsciiPin;
                    try
                    {
                        extraction.Invoke(window, null);
                        throw new InvalidOperationException("Extraction accepted a PIN that cannot retain ASCII credential bytes.");
                    }
                    catch (TargetInvocationException error) when (error.InnerException is InvalidOperationException)
                    {
                        MacComprehensiveTests.Require(error.InnerException.Message == (locale == "de"
                            ? "Die PIN mit den ursprünglichen ASCII-Ziffern 0 bis 9 eingeben."
                            : "Enter the PIN using the original ASCII digits 0 to 9."),
                            "The extraction encoding error was not correctly localized.");
                    }
                }
                pin.Text = string.Empty;
                Control<FactorTextBox>(window, "ExtractGeneratedPasswordFirstBox").Text = new string('A', 255);
                try
                {
                    extraction.Invoke(window, null);
                    throw new InvalidOperationException("Extraction accepted an invalid key-sheet factor.");
                }
                catch (TargetInvocationException error) when (error.InnerException is InvalidOperationException)
                {
                    MacComprehensiveTests.Require(error.InnerException.Message == (locale == "de"
                        ? "Beide Faktoren vom Schlüsselzettel müssen jeweils aus 256 Hexadezimalzeichen bestehen."
                        : "Both key-sheet factors must contain 256 hexadecimal characters each."),
                        "The factor-format error was not correctly localized.");
                }
            }
            MacComprehensiveTests.Require(evaluationAttempts == 0, "Extraction attempted to run the password model.");
            window.ClearExtractSecrets();
        }
        window.ClearCreateSecrets();
        SelectLanguage(language, "de");
    }

    private static void TestPasswordPolicyFeedback(MainWindow window)
    {
        TextBox password = Control<TextBox>(window, "CreatePasswordBox");
        TextBlock entropy = Control<TextBlock>(window, "PasswordEntropyStatusText");

        password.Text = "kurz";
        Dispatcher.UIThread.RunJobs();
        string weakText = entropy.Text ?? string.Empty;
        MacComprehensiveTests.Require(weakText.Length > 0, "The password policy readout stayed empty for a weak password.");

        PasswordPolicyAnalysis weak = PasswordKeyService.AnalyzeUserPassword("kurz", string.Empty, string.Empty);
        MacComprehensiveTests.Require(!weak.IsAccepted, "A four-character password was treated as acceptable.");

        const string strong = "N!r7$Vq2#Lm8%Tx3&Jd9*Wp4+Kg5=Zu6?Ce";
        password.Text = strong;
        Dispatcher.UIThread.RunJobs();
        MacComprehensiveTests.Require(
            !string.Equals(entropy.Text ?? string.Empty, weakText, StringComparison.Ordinal),
            "The password policy readout did not react to a changed password.");

        PasswordPolicyAnalysis accepted = PasswordKeyService.AnalyzeUserPassword(strong, string.Empty, string.Empty);
        MacComprehensiveTests.Require(accepted.IsAccepted, "The reference-strength password was rejected by the policy.");

        TestPinPolicyFeedback(window);
    }

    /// <summary>
    /// The PIN readout has to behave like the password readout: it is a
    /// credential of equal standing, and an archive cannot be opened
    /// without it.
    /// </summary>
    private static void TestPinPolicyFeedback(MainWindow window)
    {
        TextBox pin = Control<TextBox>(window, "CreatePinBox");
        TextBox confirm = Control<TextBox>(window, "CreatePinConfirmBox");
        TextBlock readout = Control<TextBlock>(window, "PinPolicyStatusText");

        pin.Text = "123";
        confirm.Text = "123";
        Dispatcher.UIThread.RunJobs();
        string tooShort = readout.Text ?? string.Empty;
        MacComprehensiveTests.Require(
            tooShort.Length > 0,
            "The PIN readout stayed empty for a PIN that is too short.");

        pin.Text = "428317";
        confirm.Text = "428318";
        Dispatcher.UIThread.RunJobs();
        string mismatched = readout.Text ?? string.Empty;
        MacComprehensiveTests.Require(
            !string.Equals(mismatched, tooShort, StringComparison.Ordinal),
            "The PIN readout did not react to two differing PIN entries.");

        pin.Text = "428317";
        confirm.Text = "428317";
        Dispatcher.UIThread.RunJobs();
        string acceptedText = readout.Text ?? string.Empty;
        MacComprehensiveTests.Require(
            !string.Equals(acceptedText, mismatched, StringComparison.Ordinal)
                && !string.Equals(acceptedText, tooShort, StringComparison.Ordinal),
            "The PIN readout did not accept a valid, matching PIN.");

        // A letter is not a digit, and the derivation refuses it -- the readout
        // has to say so here rather than at the end of an archive run.
        pin.Text = "42831A";
        confirm.Text = "42831A";
        Dispatcher.UIThread.RunJobs();
        MacComprehensiveTests.Require(
            !string.Equals(readout.Text ?? string.Empty, acceptedText, StringComparison.Ordinal),
            "The PIN readout accepted a non-digit PIN.");

        pin.Text = string.Empty;
        confirm.Text = string.Empty;
        Dispatcher.UIThread.RunJobs();
    }

    /// <summary>
    /// The destructive option and its safety explanation must follow the
    /// language picker together. The XAML starts in German, so testing an actual
    /// switch to English catches controls that were never wired into
    /// ApplyLanguage rather than merely checking their initial text.
    /// </summary>
    private static void TestDeleteOriginalsLocalization(MainWindow window)
    {
        ComboBox language = Control<ComboBox>(window, "LanguageBox");
        CheckBox deleteOriginals = Control<CheckBox>(window, "DeleteOriginalsBox");
        TextBlock deleteOriginalsHint = Control<TextBlock>(window, "DeleteOriginalsHint");

        SelectLanguage(language, "de");
        MacComprehensiveTests.Require(
            string.Equals(
                deleteOriginals.Content as string,
                "Originaldateien nach geprüftem Abgleich löschen",
                StringComparison.Ordinal),
            "The verified-original-deletion option is not localized in German.");
        MacComprehensiveTests.Require(
            string.Equals(
                deleteOriginalsHint.Text,
                "Das Archiv wird danach erneut entpackt und bitweise mit den Originalen verglichen. Gelöscht wird erst bei vollständiger Übereinstimmung.",
                StringComparison.Ordinal),
            "The verified-original-deletion explanation is not localized in German.");

        SelectLanguage(language, "en");
        MacComprehensiveTests.Require(
            string.Equals(
                deleteOriginals.Content as string,
                "Delete original files after a verified comparison",
                StringComparison.Ordinal),
            "The verified-original-deletion option is not localized in English.");
        MacComprehensiveTests.Require(
            string.Equals(
                deleteOriginalsHint.Text,
                "The archive is then extracted again and compared byte-for-byte with the original files. Files are deleted only after a complete match.",
                StringComparison.Ordinal),
            "The verified-original-deletion explanation is not localized in English.");
    }

    /// <summary>
    /// Reproduces the successful erase handler's path clear followed by its
    /// completion status before Avalonia delivers the queued TextChanged event.
    /// No archive is opened or erased; only the post-operation UI state is seeded.
    /// </summary>
    private static void TestEraseCompletionSurvivesDeferredTextChange(MainWindow window)
    {
        TextBox path = Control<TextBox>(window, "ErasePathBox");
        CheckBox confirm = Control<CheckBox>(window, "EraseConfirmBox");
        TextBlock status = Control<TextBlock>(window, "EraseStatusText");
        ComboBox language = Control<ComboBox>(window, "LanguageBox");
        MethodInfo setStatus = typeof(MainWindow).GetMethod(
            "SetEraseStatus", BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("MainWindow erase status method was not found.");
        const string germanCompleted = "Vorhandene zugehörige KPAR2-Daten wurden unbrauchbar gemacht und gelöscht, danach dieser lokale verschlüsselte Container beschädigt und gelöscht. Backups, Snapshots und SSD-Datenreste können weiterhin vorhanden sein. Gespeicherte oder gedruckte Schlüsselzettel separat vernichten.";
        const string englishCompleted = "Any associated KPAR2 data was invalidated and deleted, then this local encrypted container was corrupted and deleted. Backups, snapshots and SSD data remnants may still exist. Destroy saved or printed key sheets separately.";

        foreach (string initialLanguage in new[] { "de", "en" })
        {
            SelectLanguage(language, initialLanguage);
            string completed = initialLanguage == "de" ? germanCompleted : englishCompleted;
            string notAnalyzed = initialLanguage == "de" ? "Noch keine Datei analysiert." : "No file analyzed yet.";
            path.Text = "/unused-keep-vault-gui-test/erased.kzpaq";
            Dispatcher.UIThread.RunJobs();
            confirm.IsChecked = true;
            int deliveredTextChanges = 0;
            EventHandler<TextChangedEventArgs> observe = (_, _) => deliveredTextChanges++;
            path.TextChanged += observe;
            try
            {
                path.Text = string.Empty;
                setStatus.Invoke(window, ["eraseCompleted"]);
                MacComprehensiveTests.Require(deliveredTextChanges == 0,
                    "The regression did not exercise Avalonia's deferred TextChanged delivery.");
                MacComprehensiveTests.Require(status.Text == completed,
                    "The erase completion was not rendered before the deferred event.");
                Dispatcher.UIThread.RunJobs();
                MacComprehensiveTests.Require(deliveredTextChanges > 0,
                    "The genuine TextChanged event was not delivered by the dispatcher.");
                MacComprehensiveTests.Require(path.Text == string.Empty && confirm.IsChecked == false,
                    "The completed erase left a path or a reusable destructive confirmation.");
                MacComprehensiveTests.Require(status.Text == completed,
                    "Deferred TextChanged replaced the completed erase status.");
            }
            finally
            {
                path.TextChanged -= observe;
            }

            SelectLanguage(language, initialLanguage == "de" ? "en" : "de");
            MacComprehensiveTests.Require(status.Text == (initialLanguage == "de" ? englishCompleted : germanCompleted),
                "The completed erase status did not follow the language switch.");
            SelectLanguage(language, initialLanguage);
            MacComprehensiveTests.Require(status.Text == completed,
                "Switching back lost the completed erase status.");

            foreach (string replacement in new[] { "/unused-keep-vault-gui-test/new.kzpaq", " " })
            {
                confirm.IsChecked = true;
                path.Text = replacement;
                Dispatcher.UIThread.RunJobs();
                MacComprehensiveTests.Require(status.Text == notAnalyzed && confirm.IsChecked == false,
                    "New nonempty path text retained a previous erase result or confirmation.");
                path.Text = string.Empty;
                setStatus.Invoke(window, ["eraseCompleted"]);
                Dispatcher.UIThread.RunJobs();
                MacComprehensiveTests.Require(status.Text == completed,
                    "A subsequent deferred path clear replaced the completed erase status.");
            }

            path.Text = "/unused-keep-vault-gui-test/analysis.kzpaq";
            Dispatcher.UIThread.RunJobs();
            setStatus.Invoke(window, ["eraseEncrypted"]);
            path.Text = string.Empty;
            Dispatcher.UIThread.RunJobs();
            MacComprehensiveTests.Require(status.Text == notAnalyzed && confirm.IsChecked == false,
                "Clearing a path retained an analysis status that was not a completed erase.");
        }
    }

    private static void SelectLanguage(ComboBox language, string expectedTag)
    {
        ComboBoxItem item = language.Items
            .OfType<ComboBoxItem>()
            .Single(candidate => string.Equals(candidate.Tag as string, expectedTag, StringComparison.Ordinal));
        language.SelectedItem = item;
        Dispatcher.UIThread.RunJobs();
    }

    /// <summary>
    /// Every interactive control the Windows reference exposes must exist here
    /// too, so a renamed or dropped control fails the suite instead of silently
    /// removing a capability from the macOS build.
    /// </summary>
    private static void TestResourcePolicy(MainWindow window)
    {
        FieldInfo field = typeof(MainWindow).GetField("_resourcePolicy", BindingFlags.Instance | BindingFlags.NonPublic)!;
        Control<TextBox>(window, "WorkingDirectoryBox").Text = "/nonexistent-unused-keep-vault-work";
        foreach (string code in new[] { "de", "en" })
        {
            SelectLanguage(Control<ComboBox>(window, "LanguageBox"), code);
            Control<Button>(window, "ApplyResourcesButton").RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
            Dispatcher.UIThread.RunJobs();
            ArchiveOperationPolicy automatic = (ArchiveOperationPolicy)field.GetValue(window)!;
            MacComprehensiveTests.Require(automatic.Preferences.CpuMode == ResourceMode.Auto
                && automatic.Preferences.MemoryMode == ResourceMode.Auto
                && automatic.RequestedCpuWorkers == 0
                && string.IsNullOrEmpty(Control<TextBox>(window, "ResourceWorkersBox").Text),
                "Apply/language resolved Auto into a persisted manual number.");
            MacComprehensiveTests.Require(window.FindControl<Control>("ResourceHoursBox") is null, "A product time-limit field survived.");
            Control<TextBox>(window, "ResourceBudgetBox").Text = "4096";
            Control<TextBox>(window, "ResourceExtractionBox").Text = "1024";
            Control<TextBox>(window, "ResourceSingleFileBox").Text = "512";
            Control<TextBox>(window, "ResourceWorkersBox").Text = "1";
            Control<Button>(window, "ApplyResourcesButton").RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
            Dispatcher.UIThread.RunJobs();
            ArchiveOperationPolicy manual = (ArchiveOperationPolicy)field.GetValue(window)!;
            MacComprehensiveTests.Require(manual.MaxContainerBytes == 4L << 30 && manual.MaxExtractedTotalBytes == 1L << 30
                && manual.MaxSingleFileBytes == 512L << 20 && manual.RequestedCpuWorkers == 1,
                "Independent archive/output limits or manual CPU=1 were not retained.");
            MacComprehensiveTests.Require(ArchiveOperationPolicy.Current != manual, "Applying preferences leaked ambient policy.");
            Control<TextBox>(window, "ResourceBudgetBox").Text = "8192";
            MacComprehensiveTests.Require(manual.MaxContainerBytes == 4L << 30, "Editing a field mutated an active policy.");
            Control<Button>(window, "ResetResourcesButton").RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
            Dispatcher.UIThread.RunJobs();
        }
    }

    private static void TestResourcePreferenceRestart(MainWindow window)
    {
        const BindingFlags flags = BindingFlags.Instance | BindingFlags.NonPublic;
        var store = (IAppSettingsStore)typeof(MainWindow).GetField("_settingsStore", flags)!.GetValue(window)!;
        FieldInfo policyField = typeof(MainWindow).GetField("_resourcePolicy", flags)!;
        store.Write("resource-hours", "1");
        store.Write("resource-cpu-hours", "1");
        Control<TextBox>(window, "ResourceWorkersBox").Text = "1";
        Control<TextBox>(window, "ResourceExtractionBox").Text = "512";
        Control<TextBox>(window, "WorkingDirectoryBox").Text = "/missing-unused-rev11-workspace";
        Control<Button>(window, "ApplyResourcesButton").RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
        Dispatcher.UIThread.RunJobs();
        using (var restarted = new MainWindow(store))
        {
            var policy = (ArchiveOperationPolicy)policyField.GetValue(restarted)!;
            MacComprehensiveTests.Require(policy.RequestedCpuWorkers == 1 && policy.MaxExtractedTotalBytes == 512L << 20,
                "Restart lost the explicit manual choice.");
            MacComprehensiveTests.Require(policy.Preferences.MemoryMode == ResourceMode.Auto
                && typeof(ArchiveOperationPolicy).GetProperty("WallTimeBudget") is null,
                "Restart converted Auto or reintroduced a time limit.");
            Control<Button>(restarted, "ResetResourcesButton").RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
            Dispatcher.UIThread.RunJobs();
        }
        using var automaticRestart = new MainWindow(store);
        var automatic = (ArchiveOperationPolicy)policyField.GetValue(automaticRestart)!;
        MacComprehensiveTests.Require(automatic.RequestedCpuWorkers == 0 && automatic.RequestedMemoryBudgetBytes == 0
            && automatic.Preferences.WorkingDirectory is null && automatic.MaxExtractedTotalBytes == 256L << 20,
            "Automatic reset persisted effective values or a stale working folder.");
    }

    private static void TestRev11Progress(MainWindow window)
    {
        const BindingFlags flags = BindingFlags.Instance | BindingFlags.NonPublic;
        void Invoke(string method) => typeof(MainWindow).GetMethod(method, flags)!.Invoke(window, null);
        foreach (string language in new[] { "de", "en" })
        {
            EnableProtectedOperationsForFailureTest(window);
            Invoke("TryBeginProtectedOperation");
            var tracker = (OperationProgressTracker)typeof(MainWindow).GetField("_operationProgress", flags)!.GetValue(window)!;
            SelectLanguage(Control<ComboBox>(window, "LanguageBox"), language);
            using var source = tracker.BeginPhase(OperationPhase.GlobalVerification, totalUnits: 10, origin: ProgressTotalOrigin.KnownInput)!;
            source.Advance(5); Invoke("RenderOperationProgress");
            var bar = Control<ProgressBar>(window, "OperationPhaseProgress");
            MacComprehensiveTests.Require(!bar.IsIndeterminate && bar.Value == 50, "Actual phase counts did not reach the real progress widget.");
            source.Advance(5); Invoke("RenderOperationProgress");
            MacComprehensiveTests.Require(tracker.Snapshot().State == OperationProgressState.Running
                && Control<TextBlock>(window, "OperationPhaseText").Text!.StartsWith("Phase:"),
                "Full phase counter claimed global success.");
            using var cleanup = tracker.BeginPhase(OperationPhase.Cleanup)!;
            Invoke("RenderOperationProgress");
            MacComprehensiveTests.Require(bar.IsIndeterminate, "Unknown cleanup work received invented progress.");
            Invoke("MarkOperationSucceeded"); Invoke("EndProtectedOperation");
            MacComprehensiveTests.Require(bar.Value == 100 && !bar.IsIndeterminate
                && Control<TextBlock>(window, "OperationPhaseText").Text == (language == "en" ? "Completed" : "Abgeschlossen"),
                "Authoritative completion or its translation was lost.");
            Invoke("TryBeginProtectedOperation");
            Invoke("MarkOperationFailed"); Invoke("EndProtectedOperation");
            MacComprehensiveTests.Require(Control<TextBlock>(window, "OperationPhaseText").Text == (language == "en" ? "Failed" : "Fehlgeschlagen"),
                "A failed operation was converted to ready/completed by cleanup.");
        }
    }

    private static void TestRev11ObserverIsolation(MainWindow window)
    {
        const BindingFlags flags = BindingFlags.Instance | BindingFlags.NonPublic;
        void Invoke(string method) => typeof(MainWindow).GetMethod(method, flags)!.Invoke(window, null);
        EnableProtectedOperationsForFailureTest(window);
        OperationProgressTracker? previous = OperationProgressTracker.Current;
        Invoke("TryBeginProtectedOperation");
        var scopeField = typeof(MainWindow).GetField("_operationProgressScope", flags)!;
        var tracker = (OperationProgressTracker)typeof(MainWindow).GetField("_operationProgress", flags)!.GetValue(window)!;
        scopeField.SetValue(window, new ThrowingObserverCleanup((IDisposable)scopeField.GetValue(window)!));
        TextBlock phase = Control<TextBlock>(window, "OperationPhaseText");
        TextBlock details = Control<TextBlock>(window, "OperationProgressDetailsText");
        int failures = 0;
        void Fail(object? sender, AvaloniaPropertyChangedEventArgs change)
        {
            if (change.Property == TextBlock.TextProperty)
            { failures++; throw new InvalidOperationException("Injected observer-only UI failure."); }
        }
        phase.PropertyChanged += Fail;
        details.PropertyChanged += Fail;
        try
        {
            using var source = tracker.BeginPhase(OperationPhase.Extraction)!;
            Invoke("RenderOperationProgress");
            Invoke("MarkOperationSucceeded");
            Invoke("EndProtectedOperation");
        }
        finally { phase.PropertyChanged -= Fail; details.PropertyChanged -= Fail; }
        MacComprehensiveTests.Require(failures > 0, "The observer fault injection did not execute.");
        MacComprehensiveTests.Require((int)typeof(MainWindow).GetField("_operationActive", flags)!.GetValue(window)! == 0
            && typeof(MainWindow).GetField("_operationCancellation", flags)!.GetValue(window) is null
            && scopeField.GetValue(window) is null && tracker.RegisterSource() is null
            && ReferenceEquals(previous, OperationProgressTracker.Current),
            "A cosmetic observer fault retained CTS, operation, scope or tracker ownership.");
    }

    private sealed class ThrowingObserverCleanup(IDisposable inner) : IDisposable
    {
        public void Dispose()
        { inner.Dispose(); throw new InvalidOperationException("Injected observer cleanup failure."); }
    }

    private static void TestReferenceControlsPresent(MainWindow window)
    {
        string[] referenceControls =
        [
            "EncryptBox", "CipherSuiteBox", "CompressionBox", "ArchivePathBox", "InputList",
            "CreatePasswordBox", "CreatePasswordConfirmBox",
            "CreatePinBox", "CreatePinConfirmBox", "PinPolicyStatusText",
            "GeneratedPasswordFirstBox",
            "GeneratedPasswordSecondBox", "GeneratePasswordButton", "EntropyStatusText",
            "DeleteOriginalsBox", "DeleteOriginalsHint",
            "ExtractArchiveBox", "OutputFolderBox", "ExtractPasswordBox",
            "ExtractPinBox",
            "ExtractGeneratedPasswordFirstBox", "ExtractGeneratedPasswordSecondBox",
            "ErasePathBox", "LogBox", "ClearLogButton", "LanguageBox",
        ];

        foreach (string name in referenceControls)
        {
            MacComprehensiveTests.Require(
                window.FindControl<Control>(name) is not null,
                $"The macOS window is missing the reference control: {name}");
        }
    }

    /// <summary>
    /// Extraction factor boxes must accept formatted 256-hex character factors
    /// (with spaces or linebreaks as printed on key sheets) and normalize them.
    /// </summary>
    private static void TestFactorBoxesLengthAndNormalization(MainWindow window)
    {
        FactorTextBox extractFactorA = Control<FactorTextBox>(window, "ExtractGeneratedPasswordFirstBox");
        FactorTextBox extractFactorB = Control<FactorTextBox>(window, "ExtractGeneratedPasswordSecondBox");

        // 256-hex characters factor (128 bytes)
        string rawHexA = new string('A', 256);
        string formattedHexA = string.Join(" ", Enumerable.Range(0, 4).Select(i => rawHexA.Substring(i * 64, 64)));
        string rawHexB = new string('B', 256);

        extractFactorA.Text = formattedHexA;
        extractFactorB.Text = rawHexB;
        Dispatcher.UIThread.RunJobs();

        string normalizedA = MainWindow.EnsureGeneratedPassword(extractFactorA.Text);
        string normalizedB = MainWindow.EnsureGeneratedPassword(extractFactorB.Text);

        MacComprehensiveTests.Require(
            string.Equals(normalizedA, rawHexA, StringComparison.Ordinal),
            "Whitespace-formatted 256-hex factor was not correctly normalized.");
        MacComprehensiveTests.Require(
            string.Equals(normalizedB, rawHexB, StringComparison.Ordinal),
            "Factor B was not correctly normalized.");
        MacComprehensiveTests.Require(
            normalizedA.Length == 256 && normalizedB.Length == 256,
            "Normalized factor length is not 256 characters.");

        // Rejection of invalid factors
        bool threwShort = false;
        try { MainWindow.EnsureGeneratedPassword(new string('C', 255)); } catch (Exception) { threwShort = true; }
        MacComprehensiveTests.Require(threwShort, "EnsureGeneratedPassword did not reject 255-character factor.");

        bool threwInvalidChar = false;
        try { MainWindow.EnsureGeneratedPassword(new string('A', 255) + "Z"); } catch (Exception) { threwInvalidChar = true; }
        MacComprehensiveTests.Require(threwInvalidChar, "EnsureGeneratedPassword did not reject non-hex character.");

        extractFactorA.Text = string.Empty;
        extractFactorB.Text = string.Empty;
        Dispatcher.UIThread.RunJobs();
    }

    /// <summary>
    /// Secret clearing must wipe user password, PIN, confirm PIN, and generated factors.
    /// </summary>
    private static void TestSecretClearing(MainWindow window)
    {
        TextBox createPassword = Control<TextBox>(window, "CreatePasswordBox");
        TextBox createConfirm = Control<TextBox>(window, "CreatePasswordConfirmBox");
        TextBox createPin = Control<TextBox>(window, "CreatePinBox");
        TextBox createPinConfirm = Control<TextBox>(window, "CreatePinConfirmBox");
        TextBox factorA = Control<TextBox>(window, "GeneratedPasswordFirstBox");
        TextBox factorB = Control<TextBox>(window, "GeneratedPasswordSecondBox");

        createPassword.Text = "SecretPassword123!456";
        createConfirm.Text = "SecretPassword123!456";
        createPin.Text = "428317";
        createPinConfirm.Text = "428317";
        factorA.Text = new string('A', 256);
        factorB.Text = new string('B', 256);
        Dispatcher.UIThread.RunJobs();

        window.ClearCreateSecrets();
        Dispatcher.UIThread.RunJobs();

        MacComprehensiveTests.Require(string.IsNullOrEmpty(createPassword.Text), "CreatePasswordBox was not cleared.");
        MacComprehensiveTests.Require(string.IsNullOrEmpty(createConfirm.Text), "CreatePasswordConfirmBox was not cleared.");
        MacComprehensiveTests.Require(string.IsNullOrEmpty(createPin.Text), "CreatePinBox was not cleared.");
        MacComprehensiveTests.Require(string.IsNullOrEmpty(createPinConfirm.Text), "CreatePinConfirmBox was not cleared.");
        MacComprehensiveTests.Require(string.IsNullOrEmpty(factorA.Text), "GeneratedPasswordFirstBox was not cleared.");
        MacComprehensiveTests.Require(string.IsNullOrEmpty(factorB.Text), "GeneratedPasswordSecondBox was not cleared.");

        TextBox extractPassword = Control<TextBox>(window, "ExtractPasswordBox");
        TextBox extractPin = Control<TextBox>(window, "ExtractPinBox");
        FactorTextBox extractFactorA = Control<FactorTextBox>(window, "ExtractGeneratedPasswordFirstBox");
        FactorTextBox extractFactorB = Control<FactorTextBox>(window, "ExtractGeneratedPasswordSecondBox");

        extractPassword.Text = "SecretPassword123!456";
        extractPin.Text = "428317";
        extractFactorA.Text = new string('A', 256);
        extractFactorB.Text = new string('B', 256);
        Dispatcher.UIThread.RunJobs();

        window.ClearExtractSecrets();
        Dispatcher.UIThread.RunJobs();

        MacComprehensiveTests.Require(string.IsNullOrEmpty(extractPassword.Text), "ExtractPasswordBox was not cleared.");
        MacComprehensiveTests.Require(string.IsNullOrEmpty(extractPin.Text), "ExtractPinBox was not cleared.");
        MacComprehensiveTests.Require(string.IsNullOrEmpty(extractFactorA.Text), "ExtractGeneratedPasswordFirstBox was not cleared.");
        MacComprehensiveTests.Require(string.IsNullOrEmpty(extractFactorB.Text), "ExtractGeneratedPasswordSecondBox was not cleared.");
    }

    /// <summary>
    /// An unclassified injected safety failure remains fatal, even during
    /// preflight. Expected prerequisite warnings are tested separately.
    /// </summary>
    private static void TestCreateFailureSecretClearing(MainWindow window)
    {
        EnableProtectedOperationsForFailureTest(window);
        TextBox password = Control<TextBox>(window, "CreatePasswordBox");
        TextBox confirm = Control<TextBox>(window, "CreatePasswordConfirmBox");
        TextBox pin = Control<TextBox>(window, "CreatePinBox");
        TextBox pinConfirm = Control<TextBox>(window, "CreatePinConfirmBox");
        TextBox factorA = Control<TextBox>(window, "GeneratedPasswordFirstBox");
        TextBox factorB = Control<TextBox>(window, "GeneratedPasswordSecondBox");
        TextBox log = Control<TextBox>(window, "LogBox");
        password.Text = "synthetic-create-password";
        confirm.Text = "synthetic-create-password";
        pin.Text = "123456";
        pinConfirm.Text = "123456";
        factorA.Text = new string('A', 256);
        factorB.Text = new string('B', 256);
        log.Text = string.Empty;

        const string Diagnostic = "injected create-credential failure";
        int errorDialogs = 0;
        MainWindow.TestHookBeforeCredentialOperation = operation =>
        {
            MacComprehensiveTests.Require(
                string.Equals(operation, "create", StringComparison.Ordinal),
                $"Create button reached the wrong operation handler: {operation}.");
            throw new InvalidDataException(Diagnostic);
        };
        MainWindow.TestHookShowDialogAsync = (kind, _) =>
        {
            MacComprehensiveTests.Require(
                kind == SecurityDialogKind.Error,
                $"Create credential failure opened a non-error dialog: {kind}.");
            errorDialogs++;
            return Task.CompletedTask;
        };

        try
        {
            Control<Button>(window, "CreateArchiveButton").RaiseEvent(
                new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
            Dispatcher.UIThread.RunJobs();
        }
        finally
        {
            MainWindow.TestHookBeforeCredentialOperation = null;
            MainWindow.TestHookShowDialogAsync = null;
        }

        typeof(MainWindow).GetMethod("FlushConsoleEntries", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(window, null);
        MacComprehensiveTests.Require(errorDialogs == 1, $"Expected one create failure dialog, got {errorDialogs}.");
        MacComprehensiveTests.Require(string.IsNullOrEmpty(password.Text), "Create failure retained the password.");
        MacComprehensiveTests.Require(string.IsNullOrEmpty(confirm.Text), "Create failure retained the confirmation password.");
        MacComprehensiveTests.Require(string.IsNullOrEmpty(pin.Text), "Create failure retained the PIN.");
        MacComprehensiveTests.Require(string.IsNullOrEmpty(pinConfirm.Text), "Create failure retained the confirmation PIN.");
        MacComprehensiveTests.Require(string.IsNullOrEmpty(factorA.Text), "Create failure retained factor A.");
        MacComprehensiveTests.Require(string.IsNullOrEmpty(factorB.Text), "Create failure retained factor B.");
        MacComprehensiveTests.Require(
            (log.Text ?? string.Empty).Contains(Diagnostic, StringComparison.Ordinal),
            "Create failure cleared credentials but dropped its diagnostic.");
    }

    /// <summary>
    /// The real Extract and List button routes must clear all four credentials
    /// when an adversarial failure reaches their exception boundary.
    /// </summary>
    private static void TestExtractListFailureSecretClearing(MainWindow window)
    {
        EnableProtectedOperationsForFailureTest(window);
        int errorDialogs = 0;
        MainWindow.TestHookShowDialogAsync = (kind, _) =>
        {
            MacComprehensiveTests.Require(
                kind == SecurityDialogKind.Error,
                $"Credential failure opened a non-error dialog: {kind}.");
            errorDialogs++;
            return Task.CompletedTask;
        };

        try
        {
            ExerciseCredentialFailureHandler(window, "extract", "ExtractArchiveButton");
            ExerciseCredentialFailureHandler(window, "list", "ListArchiveButton");
            MacComprehensiveTests.Require(errorDialogs == 2, $"Expected two credential failure dialogs, got {errorDialogs}.");
        }
        finally
        {
            MainWindow.TestHookBeforeCredentialOperation = null;
            MainWindow.TestHookShowDialogAsync = null;
        }
    }

    /// <summary>
    /// Authenticated emergency recovery shares the extraction credentials, so
    /// its real button route must enforce the same failure cleanup boundary.
    /// </summary>
    private static void TestRecoveryFailureSecretClearing(MainWindow window)
    {
        EnableProtectedOperationsForFailureTest(window);
        int errorDialogs = 0;
        MainWindow.TestHookShowDialogAsync = (kind, _) =>
        {
            MacComprehensiveTests.Require(
                kind == SecurityDialogKind.Error,
                $"Recovery failure opened a non-error dialog: {kind}.");
            errorDialogs++;
            return Task.CompletedTask;
        };

        try
        {
            ExerciseCredentialFailureHandler(window, "recovery", "EmergencyRecoveryButton");
            MacComprehensiveTests.Require(errorDialogs == 1, $"Expected one recovery failure dialog, got {errorDialogs}.");
        }
        finally
        {
            MainWindow.TestHookBeforeCredentialOperation = null;
            MainWindow.TestHookShowDialogAsync = null;
        }
    }

    private static void ExerciseCredentialFailureHandler(
        MainWindow window,
        string operation,
        string buttonName)
    {
        TextBox extractPassword = Control<TextBox>(window, "ExtractPasswordBox");
        TextBox extractPin = Control<TextBox>(window, "ExtractPinBox");
        FactorTextBox extractFactorA = Control<FactorTextBox>(window, "ExtractGeneratedPasswordFirstBox");
        FactorTextBox extractFactorB = Control<FactorTextBox>(window, "ExtractGeneratedPasswordSecondBox");
        TextBox log = Control<TextBox>(window, "LogBox");

        extractPassword.Text = "synthetic-password";
        extractPin.Text = "123456";
        extractFactorA.Text = new string('A', 255);
        extractFactorB.Text = new string('B', 255);
        log.Text = string.Empty;
        const string Diagnostic = "injected credential-operation failure";
        MainWindow.TestHookBeforeCredentialOperation = actualOperation =>
        {
            MacComprehensiveTests.Require(
                string.Equals(actualOperation, operation, StringComparison.Ordinal),
                $"{buttonName} reached the wrong operation handler: {actualOperation}.");
            throw new InvalidDataException(Diagnostic);
        };

        try
        {
            Control<Button>(window, buttonName).RaiseEvent(
                new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
            Dispatcher.UIThread.RunJobs();
        }
        finally
        {
            MainWindow.TestHookBeforeCredentialOperation = null;
        }

        typeof(MainWindow).GetMethod("FlushConsoleEntries", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(window, null);
        MacComprehensiveTests.Require(string.IsNullOrEmpty(extractPassword.Text), $"{operation} failure retained the password.");
        MacComprehensiveTests.Require(string.IsNullOrEmpty(extractPin.Text), $"{operation} failure retained the PIN.");
        MacComprehensiveTests.Require(string.IsNullOrEmpty(extractFactorA.Text), $"{operation} failure retained factor A.");
        MacComprehensiveTests.Require(string.IsNullOrEmpty(extractFactorB.Text), $"{operation} failure retained factor B.");
        MacComprehensiveTests.Require(
            (log.Text ?? string.Empty).Contains(Diagnostic, StringComparison.Ordinal),
            $"{operation} failure cleared credentials but dropped its diagnostic.");
    }

    private static void EnableProtectedOperationsForFailureTest(MainWindow window)
    {
        FieldInfo integrity = typeof(MainWindow).GetField(
            "_integrityTrusted",
            BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("MainWindow integrity field was not found.");
        MethodInfo update = typeof(MainWindow).GetMethod(
            "UpdateProtectedOperationControls",
            BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("MainWindow protected-operation update method was not found.");
        integrity.SetValue(window, true);
        update.Invoke(window, null);
    }

    /// <summary>
    /// KDF description and entropy pool readout must correctly localize in German and English.
    /// </summary>
    private static void TestKdfAndEntropyLocalization(MainWindow window)
    {
        ComboBox language = Control<ComboBox>(window, "LanguageBox");
        TextBlock kdfProfile = Control<TextBlock>(window, "Argon2ProfileText");

        SelectLanguage(language, "de");
        string deKdf = kdfProfile.Text ?? string.Empty;
        MacComprehensiveTests.Require(
            deKdf.Contains("1024-Bit-Master", StringComparison.Ordinal) || deKdf.Contains("KDF-Pfade", StringComparison.Ordinal),
            $"German KDF description is missing master details: {deKdf}");

        SelectLanguage(language, "en");
        string enKdf = kdfProfile.Text ?? string.Empty;
        MacComprehensiveTests.Require(
            enKdf.Contains("1024-bit master", StringComparison.Ordinal) || enKdf.Contains("KDF paths", StringComparison.Ordinal),
            $"English KDF description is missing master details: {enKdf}");
    }

    private static void TestCupsSpoolWarningLocalization(MainWindow window)
    {
        MethodInfo translate = typeof(MainWindow).GetMethod(
            "T",
            BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("MainWindow localization method was not found.");
        ComboBox language = Control<ComboBox>(window, "LanguageBox");

        SelectLanguage(language, "de");
        string german = (string?)translate.Invoke(window, ["cupsSpoolWarning"]) ?? string.Empty;
        MacComprehensiveTests.Require(
            german.Contains("CUPS", StringComparison.Ordinal)
                && german.Contains("Warteschlange", StringComparison.Ordinal)
                && german.Contains("außerhalb der App", StringComparison.Ordinal),
            $"German CUPS spool warning is incomplete: {german}");

        SelectLanguage(language, "en");
        string english = (string?)translate.Invoke(window, ["cupsSpoolWarning"]) ?? string.Empty;
        MacComprehensiveTests.Require(
            english.Contains("CUPS", StringComparison.Ordinal)
                && english.Contains("spool", StringComparison.OrdinalIgnoreCase)
                && english.Contains("outside the app", StringComparison.Ordinal),
            $"English CUPS spool warning is incomplete: {english}");

        string englishPdf = (string?)translate.Invoke(window, ["testPdfWarning"]) ?? string.Empty;
        MacComprehensiveTests.Require(englishPdf.Contains("two separate PDFs", StringComparison.Ordinal)
            && englishPdf.Contains("one factor per file", StringComparison.Ordinal), "English test-PDF separation warning is inaccurate.");
        SelectLanguage(language, "de");
        string germanPdf = (string?)translate.Invoke(window, ["testPdfWarning"]) ?? string.Empty;
        MacComprehensiveTests.Require(germanPdf.Contains("zwei getrennte PDFs", StringComparison.Ordinal)
            && germanPdf.Contains("einen Faktor pro Datei", StringComparison.Ordinal), "German test-PDF separation warning is inaccurate.");
    }

    private static void TestStreamingThreadBoundary(MainWindow window)
    {
        // The service's null-stream guard must be reached from a real worker.
        // Reading a TextBox in a returned callback fails before that guard with
        // Avalonia's cross-thread exception, reproducing the installed-GUI bug.
        AssertWorkerReachesStreamGuard(window.CaptureEncryptionConsumer(
            "/unused-test-target.kzpaq", EncryptionSuite.Kalyna512_512, prepared: null));
        AssertWorkerReachesStreamGuard(window.CaptureDecryptionProducer(
            "/unused-test-input.kzpaq", creationCredentials: false));
        AssertWorkerReachesStreamGuard(window.CaptureDecryptionProducer(
            "/unused-test-input.kzpaq", creationCredentials: true));
    }

    private static void AssertWorkerReachesStreamGuard(Func<Stream, CancellationToken, Task> operation)
    {
        Task.Run(async () =>
        {
            MacComprehensiveTests.Require(!Dispatcher.UIThread.CheckAccess(), "Streaming regression must run on a worker.");
            try
            {
                await operation(null!, CancellationToken.None).ConfigureAwait(false);
                throw new InvalidOperationException("The service did not reject a null stream.");
            }
            catch (ArgumentNullException)
            {
                // Correct: service validation, not a cross-thread GUI access.
            }
        }).GetAwaiter().GetResult();
    }

    /// <summary>
    /// A later failure must not turn an archive pathname into deletion
    /// authority. Simulate all four possible committed names being occupied by
    /// replacement canaries and prove the GUI failure policy only reports them.
    /// </summary>
    private static void TestFailedArchivePreservation(MainWindow window)
    {
        _ = window;
        string root = Directory.CreateTempSubdirectory("keep-vault-gui-preserve-").FullName;
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
            foreach (string path in paths)
            {
                MacComprehensiveTests.Require(
                    warning.Contains(path, StringComparison.Ordinal),
                    $"The preservation warning omitted a possible committed output: {path}");
            }

            for (int index = 0; index < paths.Length; index++)
            {
                MacComprehensiveTests.Require(
                    File.ReadAllBytes(paths[index]).AsSpan().SequenceEqual(canaries[index]),
                    $"The GUI downstream-failure policy modified or removed a replacement canary: {paths[index]}");
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static void TestVerificationRootCleanupIdentity(MainWindow window)
    {
        _ = window;
        string root = MacSafeFileSystem.ResolveExistingRealPath(
            Directory.CreateTempSubdirectory("keep-vault-verify-cleanup-").FullName);
        string displacedRoot = root + "-displaced";
        string canaryPath = Path.Combine(root, "replacement-canary.bin");
        byte[] canary = [0x56, 0x45, 0x52, 0x49, 0x46, 0x59];
        using SafeFileHandle rootHandle = MacSafeFileSystem.OpenDirectoryHandle(root);
        MacFileIdentity rootIdentity = MacSafeFileSystem.GetIdentity(rootHandle);
        try
        {
            using (SafeFileHandle plaintextHandle = MacSafeFileSystem.CreateFileAtExclusive(
                rootHandle,
                "plaintext.bin"))
            using (var plaintext = new FileStream(plaintextHandle, FileAccess.ReadWrite))
            {
                plaintext.Write(new byte[4096]);
                plaintext.Flush(flushToDisk: true);
            }

            MainWindow.TestHookBeforeVerificationRootCleanup = () =>
            {
                Directory.Move(root, displacedRoot);
                Directory.CreateDirectory(root);
                File.WriteAllBytes(canaryPath, canary);
            };

            bool rejectedReplacement = false;
            try
            {
                MainWindow.CleanupBoundVerificationRoot(rootHandle, root, rootIdentity);
            }
            catch (IOException)
            {
                rejectedReplacement = true;
            }

            MacComprehensiveTests.Require(
                rejectedReplacement,
                "Verification cleanup accepted a replacement at the private-root pathname.");
            MacComprehensiveTests.Require(
                File.ReadAllBytes(canaryPath).AsSpan().SequenceEqual(canary),
                "Verification cleanup deleted or modified the replacement-root canary.");
            MacComprehensiveTests.Require(
                !Directory.EnumerateFileSystemEntries(displacedRoot).Any(),
                "Verification cleanup left plaintext inside the displaced bound root.");
        }
        finally
        {
            MainWindow.TestHookBeforeVerificationRootCleanup = null;
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
            if (Directory.Exists(displacedRoot))
            {
                Directory.Delete(displacedRoot, recursive: true);
            }
        }
    }

    /// <summary>
    /// Replaces factor A's pathname after its PDF is durably written and then
    /// interrupts the pair export. Rollback may destroy the still-open PDF
    /// object, but it must never delete the replacement canary now occupying
    /// the original name.
    /// </summary>
    private static void TestKeySheetPairCleanupIdentity(MainWindow window)
    {
        _ = window;
        string root = MacSafeFileSystem.ResolveExistingRealPath(
            Directory.CreateTempSubdirectory("keep-vault-keysheet-pair-").FullName);
        string firstPath = Path.Combine(root, "factor-a.pdf");
        string displacedPath = Path.Combine(root, "factor-a-displaced.pdf");
        string secondPath = Path.Combine(root, "factor-b.pdf");
        byte[] canary = [0x41, 0x2D, 0x43, 0x41, 0x4E, 0x41, 0x52, 0x59];
        string first = new('a', 256);
        string second = new('b', 256);
        try
        {
            KeySheetService.TestHookBeforeSecondTestPdf = (_, expectedPath) =>
            {
                File.Move(expectedPath, displacedPath);
                File.WriteAllBytes(expectedPath, canary);
                throw new IOException("Injected second key-sheet export failure.");
            };

            var service = new KeySheetService();
            bool rejected = false;
            try
            {
                service.SaveTestPdf(
                    new KeySheetData(
                        Path.Combine(root, "archive.kzpaq"),
                        EncryptionSuite.ParanoiaCascade,
                        first,
                        second,
                        DateTime.UnixEpoch,
                        false,
                        string.Empty),
                    firstPath,
                    secondPath);
            }
            catch (IOException exception) when (exception.Message.Contains("Injected", StringComparison.Ordinal))
            {
                rejected = true;
            }

            MacComprehensiveTests.Require(rejected, "The injected key-sheet pair failure was not propagated.");
            MacComprehensiveTests.Require(
                File.ReadAllBytes(firstPath).AsSpan().SequenceEqual(canary),
                "Key-sheet rollback deleted or modified the pathname replacement canary.");
            MacComprehensiveTests.Require(
                File.Exists(displacedPath),
                "Key-sheet rollback lost the still-bound first PDF object after pathname replacement.");
            MacComprehensiveTests.Require(
                !File.Exists(secondPath),
                "The interrupted key-sheet pair unexpectedly committed factor B.");
        }
        finally
        {
            KeySheetService.TestHookBeforeSecondTestPdf = null;
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>
    /// A partial key-sheet export is sensitive output. If both the export and
    /// its descriptor-bound destruction fail, callers must receive both causes
    /// instead of a plausible-looking lone export error that hides the file
    /// which still needs attention.
    /// </summary>
    private static void TestKeySheetCleanupFailureVisible(MainWindow window)
    {
        _ = window;
        // The service canonicalizes its target before it reaches the hook, so a
        // raw /var temp root would make the hook's path assertion compare two
        // spellings of the same file.
        string root = MacSafeFileSystem.ResolveExistingRealPath(
            Directory.CreateTempSubdirectory("keep-vault-keysheet-cleanup-error-").FullName);
        string firstPath = Path.Combine(root, "factor-a.pdf");
        string secondPath = Path.Combine(root, "factor-b.pdf");
        const string exportSentinel = "Injected second key-sheet export failure.";
        const string cleanupSentinel = "Injected partial key-sheet cleanup failure.";
        try
        {
            KeySheetService.TestHookBeforeSecondTestPdf = (_, _) =>
                throw new IOException(exportSentinel);
            KeySheetService.TestHookBeforePartialTestPdfDestroy = (_, expectedPath) =>
            {
                MacComprehensiveTests.Require(
                    string.Equals(expectedPath, firstPath, StringComparison.Ordinal),
                    "The cleanup hook received a different partial PDF path.");
                throw new UnauthorizedAccessException(cleanupSentinel);
            };

            var service = new KeySheetService();
            AggregateException? observed = null;
            try
            {
                service.SaveTestPdf(
                    new KeySheetData(
                        Path.Combine(root, "archive.kzpaq"),
                        EncryptionSuite.ParanoiaCascade,
                        new string('a', 256),
                        new string('b', 256),
                        DateTime.UnixEpoch,
                        false,
                        string.Empty),
                    firstPath,
                    secondPath);
            }
            catch (AggregateException exception)
            {
                observed = exception.Flatten();
            }

            MacComprehensiveTests.Require(observed is not null, "The export hid its partial-file cleanup failure.");
            MacComprehensiveTests.Require(
                observed!.InnerExceptions.Any(exception => exception.Message.Contains(exportSentinel, StringComparison.Ordinal))
                    && observed.InnerExceptions.Any(exception => exception.Message.Contains(cleanupSentinel, StringComparison.Ordinal)),
                "The aggregate did not preserve both the export and cleanup causes.");
            MacComprehensiveTests.Require(
                File.Exists(firstPath),
                "The injected cleanup failure did not leave an observable partial file for recovery handling.");
            MacComprehensiveTests.Require(
                !File.Exists(secondPath),
                "The interrupted pair unexpectedly created factor B.");
        }
        finally
        {
            KeySheetService.TestHookBeforeSecondTestPdf = null;
            KeySheetService.TestHookBeforePartialTestPdfDestroy = null;
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>
    /// Replaces factor A only after factor B has been durably written. The
    /// final pair gate must reject the split commit, remove the still-bound B
    /// output, and preserve the replacement occupying A's pathname.
    /// </summary>
    private static void TestKeySheetPairAtomicCommit(MainWindow window)
    {
        _ = window;
        string root = MacSafeFileSystem.ResolveExistingRealPath(
            Directory.CreateTempSubdirectory("keep-vault-keysheet-atomic-").FullName);
        string firstPath = Path.Combine(root, "factor-a.pdf");
        string displacedPath = Path.Combine(root, "factor-a-displaced.pdf");
        string secondPath = Path.Combine(root, "factor-b.pdf");
        string modeFirstPath = Path.Combine(root, "mode-factor-a.pdf");
        string modeSecondPath = Path.Combine(root, "mode-factor-b.pdf");
        byte[] canary = [0x41, 0x54, 0x4F, 0x4D, 0x49, 0x43];
        string first = new('a', 256);
        string second = new('b', 256);
        try
        {
            var service = new KeySheetService();
            var data = new KeySheetData(
                Path.Combine(root, "archive.kzpaq"),
                EncryptionSuite.ParanoiaCascade,
                first,
                second,
                DateTime.UnixEpoch,
                false,
                string.Empty);
            service.SaveTestPdf(data, modeFirstPath, modeSecondPath);
            UnixFileMode expectedMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            MacComprehensiveTests.Require(
                File.GetUnixFileMode(modeFirstPath) == expectedMode
                    && File.GetUnixFileMode(modeSecondPath) == expectedMode,
                "The key-sheet pair was not initially created with exact 0600 permissions on arm64 macOS.");

            KeySheetService.TestHookBeforeTestPdfPairCommit =
                (_, expectedFirstPath, _, _) =>
                {
                    File.Move(expectedFirstPath, displacedPath);
                    File.WriteAllBytes(expectedFirstPath, canary);
                };

            bool rejected = false;
            try
            {
                service.SaveTestPdf(data, firstPath, secondPath);
            }
            catch (IOException)
            {
                rejected = true;
            }

            MacComprehensiveTests.Require(rejected, "The key-sheet pair final gate accepted a replaced factor A.");
            MacComprehensiveTests.Require(
                File.ReadAllBytes(firstPath).AsSpan().SequenceEqual(canary),
                "The pair rollback deleted or modified factor A's pathname replacement canary.");
            MacComprehensiveTests.Require(
                File.Exists(displacedPath),
                "The pair rollback lost the displaced, still-bound factor A object.");
            MacComprehensiveTests.Require(
                !File.Exists(secondPath),
                "The pair rollback left factor B behind after factor A failed its final identity gate.");
        }
        finally
        {
            KeySheetService.TestHookBeforeTestPdfPairCommit = null;
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>
    /// Exercises the entire GUI creation flow: gathering 1024 mouse samples across the 11 pools
    /// via genuine pointer movement, clicking the factor generator button, filling out PIN and password,
    /// and validating the creation gate.
    /// </summary>
    private static void TestOperationCancelLifetime(MainWindow window)
    {
        const BindingFlags flags = BindingFlags.Instance | BindingFlags.NonPublic;
        MethodInfo begin = typeof(MainWindow).GetMethod("TryBeginProtectedOperation", flags)!;
        MethodInfo end = typeof(MainWindow).GetMethod("EndProtectedOperation", flags)!;
        PropertyInfo tokenProperty = typeof(MainWindow).GetProperty("OperationToken", flags)!;
        CancellationToken ReadToken() => (CancellationToken)tokenProperty.GetValue(window)!;
        EnableProtectedOperationsForFailureTest(window);
        MacComprehensiveTests.Require((bool)begin.Invoke(window, null)!, "First operation did not begin.");
        CancellationToken first = ReadToken();
        Control<Button>(window, "CancelOperationButton").RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
        MacComprehensiveTests.Require(first.IsCancellationRequested, "Cancel did not reach the captured operation token.");
        end.Invoke(window, null);
        EnableProtectedOperationsForFailureTest(window);
        MacComprehensiveTests.Require((bool)begin.Invoke(window, null)!, "Second operation did not begin.");
        CancellationToken second = ReadToken();
        MacComprehensiveTests.Require(!second.IsCancellationRequested && first.IsCancellationRequested && second != first,
            "A cancelled operation poisoned the next operation or reused its source.");
        end.Invoke(window, null);
        window.Dispose();
        MacComprehensiveTests.Require(ReadToken().IsCancellationRequested,
            "Disposed window lost its stable cancelled lifetime token.");
    }

    private static void TestRev9EntropyPhasesAndCancel(MainWindow window)
    {
        EnableProtectedOperationsForFailureTest(window);
        void Fill()
        {
            int iterations = 0;
            while (!EntropyMixer.GetPoolStatus().IsReady)
            {
                MoveMouse(window, 512);
                if (++iterations > 200) throw new InvalidOperationException("Eleven GUI pools did not become ready.");
            }
        }
        void Join(Task task)
        {
            var time = System.Diagnostics.Stopwatch.StartNew();
            while (!task.IsCompleted)
            {
                Dispatcher.UIThread.RunJobs();
                if (time.Elapsed > TimeSpan.FromSeconds(30)) throw new TimeoutException("GUI preparation did not join.");
                Thread.Sleep(1);
            }
            task.GetAwaiter().GetResult(); Dispatcher.UIThread.RunJobs();
        }
        try
        {
            Fill();
            using var entered = new ManualResetEventSlim(); using var resume = new ManualResetEventSlim(); int once = 0;
            EntropyMixer.PreparationPhaseForTests = phase =>
            {
                if (phase == "sha3" && Interlocked.CompareExchange(ref once, 1, 0) == 0)
                {
                    entered.Set(); if (!resume.Wait(TimeSpan.FromSeconds(20))) throw new TimeoutException("GUI cancel barrier timed out.");
                }
            };
            EnableProtectedOperationsForFailureTest(window);
            Task cancelled = window.GenerateArchiveEntropyAsync();
            MacComprehensiveTests.Require(entered.Wait(TimeSpan.FromSeconds(20)), "GUI preparation never reached SHA3 replay.");
            Dispatcher.UIThread.RunJobs();
            Button cancel = Control<Button>(window, "CancelOperationButton");
            MacComprehensiveTests.Require(cancel.IsEnabled && !Control<Button>(window, "GeneratePasswordButton").IsEnabled,
                "A running preparation cannot be cancelled or allows a duplicate generator.");
            cancel.RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
            resume.Set(); Join(cancelled);
            MacComprehensiveTests.Require(string.IsNullOrEmpty(Control<TextBox>(window, "GeneratedPasswordFirstBox").Text)
                && EntropyMixer.SampleCount == 0 && SensitiveMouseRecordStore.Segment.ReservedBytes == 0,
                "Cancelled GUI preparation exposed a partial factor or retained records.");
            foreach (EncryptionSuite suite in new[] { EncryptionSuite.StandardCascade, EncryptionSuite.ParanoiaCascade })
            {
                var phases = new System.Collections.Concurrent.ConcurrentBag<string>();
                EntropyMixer.PreparationPhaseForTests = phases.Add;
                ComboBox box = Control<ComboBox>(window, "CipherSuiteBox");
                box.SelectedItem = box.Items.OfType<ComboBoxItem>().Single(item => string.Equals(item.Tag as string, suite.ToString(), StringComparison.Ordinal));
                Fill();
                string counters = Control<TextBlock>(window, "EntropyStatusText").Text ?? "";
                MacComprehensiveTests.Require(counters.Contains("Nonce 5", StringComparison.OrdinalIgnoreCase), "GUI omits the fifth nonce pool.");
                EnableProtectedOperationsForFailureTest(window);
                Join(window.GenerateArchiveEntropyAsync());
                MacComprehensiveTests.Require(phases.Contains("shuffle1") && phases.Contains("sha3") && phases.Contains("cleanup"), "GUI generation omitted a mandatory phase.");
                bool dual = suite == EncryptionSuite.ParanoiaCascade;
                MacComprehensiveTests.Require(phases.Contains("shuffle2") == dual && phases.Contains("sha512") == dual,
                    "The GUI executed phases that differ from its fixed preparation plan.");
                MacComprehensiveTests.Require(Control<TextBox>(window, "GeneratedPasswordFirstBox").Text?.Length == 256,
                    "A successful GUI preparation did not publish the completed factor.");
            }
        }
        finally { EntropyMixer.PreparationPhaseForTests = null; }
    }

    private static void TestLiveCaptureDuringDualPreparation(MainWindow window)
    {
        const BindingFlags instanceFlags = BindingFlags.Instance | BindingFlags.NonPublic;
        FieldInfo poolsField = typeof(EntropyMixer).GetField("MousePools", BindingFlags.Static | BindingFlags.NonPublic)!;
        FieldInfo captureFaultField = typeof(MainWindow).GetField("_entropyCaptureFaulted", instanceFlags)!;
        Action<string>? previousPhase = EntropyMixer.PreparationPhaseForTests;
        Action<byte[], EntropyRandomRole>? previousRandom = EntropyMixer.RandomFillForTests;
        using var entered = new ManualResetEventSlim();
        using var resume = new ManualResetEventSlim();
        var phases = new ConcurrentBag<string>();
        Task? generation = null;
        int boundaryPointer = 0;

        void MoveBoundaryPointer()
        {
            // Each guard check receives a distinct position, including after
            // Dispose, rather than depending on repeated same-point delivery.
            window.MouseMove(new Point(11 + ++boundaryPointer, 13));
            Dispatcher.UIThread.RunJobs();
        }

        void Join(Task task)
        {
            var time = System.Diagnostics.Stopwatch.StartNew();
            while (!task.IsCompleted)
            {
                Dispatcher.UIThread.RunJobs();
                if (time.Elapsed > TimeSpan.FromSeconds(30)) throw new TimeoutException("GUI live-capture preparation did not join.");
                Thread.Sleep(1);
            }
            task.GetAwaiter().GetResult();
            Dispatcher.UIThread.RunJobs();
        }

        static byte[] Fingerprint(SensitiveMouseRecordStore[] pools)
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            using LockedSensitiveBuffer record = LockedSensitiveBuffer.Create(SensitiveMouseRecordStore.RecordBytes);
            foreach (SensitiveMouseRecordStore pool in pools)
                for (long index = 0; index < pool.Count; ++index)
                {
                    pool.CopyRecord(index, record.Bytes);
                    hash.AppendData(record.Bytes);
                }
            return hash.GetHashAndReset();
        }

        bool ShowsTotal(long total) => (Control<TextBlock>(window, "EntropyStatusText").Text ?? "").Contains(
            "gesamt " + total.ToString(CultureInfo.CurrentCulture) + ";", StringComparison.Ordinal)
            || (Control<TextBlock>(window, "EntropyStatusText").Text ?? "").Contains(
                "total " + total.ToString(CultureInfo.CurrentCulture) + ";", StringComparison.Ordinal);

        try
        {
            EntropyMixer.Reset();
            ComboBox suite = Control<ComboBox>(window, "CipherSuiteBox");
            suite.SelectedItem = suite.Items.OfType<ComboBoxItem>().Single(item =>
                string.Equals(item.Tag as string, EncryptionSuite.ParanoiaCascade.ToString(), StringComparison.Ordinal));
            int fills = 0;
            while (!EntropyMixer.GetPoolStatus().IsReady)
            {
                MoveMouse(window, 512);
                if (++fills > 200) throw new InvalidOperationException("Live-capture fixture did not fill eleven pools.");
            }
            SensitiveMouseRecordStore[] originalPools = (SensitiveMouseRecordStore[])poolsField.GetValue(null)!;
            long[] originalCounts = originalPools.Select(pool => pool.Count).ToArray();
            EntropyMixer.PreparationPhaseForTests = phase =>
            {
                phases.Add(phase);
                // Hold every pool before its first replay, so no original store
                // can be cleaned while its immutable records are compared.
                if (phase == "sha3")
                {
                    entered.Set();
                    if (!resume.Wait(TimeSpan.FromSeconds(20))) throw new TimeoutException("GUI live-capture barrier timed out.");
                }
            };
            EnableProtectedOperationsForFailureTest(window);
            generation = window.GenerateArchiveEntropyAsync();
            MacComprehensiveTests.Require(entered.Wait(TimeSpan.FromSeconds(20)), "Dual GUI preparation never detached its records.");
            Dispatcher.UIThread.RunJobs();
            MacComprehensiveTests.Require(!generation.IsCompleted && EntropyMixer.GetPoolStatus().Total == 0
                && ShowsTotal(0) && Control<ProgressBar>(window, "EntropyProgress").Value == 0,
                "The running GUI preparation did not display its new empty live epoch.");
            MacComprehensiveTests.Require(!ReferenceEquals(originalPools, poolsField.GetValue(null))
                && originalPools.Select(pool => pool.Count).SequenceEqual(originalCounts),
                "Detach did not preserve a separately owned original snapshot.");
            byte[] originalFingerprint = Fingerprint(originalPools);

            // Use the real window's routed pointer events, not a direct mixer
            // injection: the production busy guard is the regression boundary.
            MoveMouse(window, 37);
            EntropyPoolStatus newLive = EntropyMixer.GetPoolStatus();
            MacComprehensiveTests.Require(newLive.Total == 37 && ShowsTotal(37)
                && originalPools.Select(pool => pool.Count).SequenceEqual(originalCounts)
                && Fingerprint(originalPools).AsSpan().SequenceEqual(originalFingerprint),
                "Pointer events changed the detached snapshot or failed to fill the separate live epoch.");
            Task duplicate = window.GenerateArchiveEntropyAsync();
            MacComprehensiveTests.Require(duplicate.IsCompleted && !generation.IsCompleted
                && EntropyMixer.GetPoolStatus() == newLive
                && !Control<Button>(window, "GeneratePasswordButton").IsEnabled
                && Control<Button>(window, "CancelOperationButton").IsEnabled
                && string.IsNullOrEmpty(Control<TextBox>(window, "GeneratedPasswordFirstBox").Text),
                "Live capture allowed a duplicate Generate or premature factor publication.");

            resume.Set();
            Join(generation);
            MacComprehensiveTests.Require(EntropyMixer.GetPoolStatus() == newLive
                && originalPools.All(pool => pool.Count == 0)
                && phases.Contains("shuffle2") && phases.Contains("sha512") && phases.Contains("cleanup")
                && Control<TextBox>(window, "GeneratedPasswordFirstBox").Text?.Length == 256,
                "Dual cleanup lost new live records or did not finish the original snapshot.");

            EntropyMixer.RandomFillForTests = (_, role) =>
            {
                if (role == EntropyRandomRole.PoolRouting) throw new CryptographicException("public injected capture RNG failure");
            };
            MoveBoundaryPointer();
            MacComprehensiveTests.Require((bool)captureFaultField.GetValue(window)! && !EntropyMixer.GetPoolStatus().Healthy
                && EntropyMixer.GetPoolStatus().Total == newLive.Total, "A capture failure did not stop the live collection safely.");
            EntropyMixer.RandomFillForTests = previousRandom;
            captureFaultField.SetValue(window, false);
            MoveBoundaryPointer();
            MacComprehensiveTests.Require(!(bool)captureFaultField.GetValue(window)! && EntropyMixer.GetPoolStatus().Total == newLive.Total,
                "An unhealthy collection reached the pointer capture path.");
            captureFaultField.SetValue(window, true);
            EntropyMixer.Reset();
            MoveBoundaryPointer();
            MacComprehensiveTests.Require(EntropyMixer.GetPoolStatus().Healthy && EntropyMixer.GetPoolStatus().Total == 0,
                "The window capture-fault guard accepted an event after the mixer reset.");
            captureFaultField.SetValue(window, false);
            MoveBoundaryPointer();
            MacComprehensiveTests.Require(EntropyMixer.GetPoolStatus().Total == 1, "The pointer fixture stopped reaching the live collection.");
            window.Dispose();
            MoveBoundaryPointer();
            MacComprehensiveTests.Require(EntropyMixer.GetPoolStatus().Healthy && EntropyMixer.GetPoolStatus().Total == 0
                && !(bool)captureFaultField.GetValue(window)!, "A disposed window accepted a new pointer record.");
        }
        finally
        {
            resume.Set();
            try { if (generation is not null) Join(generation); }
            finally
            {
                EntropyMixer.PreparationPhaseForTests = previousPhase;
                EntropyMixer.RandomFillForTests = previousRandom;
                EntropyMixer.Reset();
            }
        }
    }

    private static void TestFullCreationFlowViaGui(MainWindow window)
    {
        EnableProtectedOperationsForFailureTest(window);
        // 1. Move mouse to feed all 11 entropy pools until minimum 1024 is reached
        long required = EntropyMixer.RequiredMouseSamplesPerPurpose;
        long guard = 0;
        while (EntropyMixer.GetPoolStatus().Minimum < required)
        {
            MoveMouse(window, 512);
            if (++guard > 200)
            {
                throw new InvalidOperationException("Entropy pools failed to reach required 1024 samples.");
            }
        }

        Button generateBtn = Control<Button>(window, "GeneratePasswordButton");
        MacComprehensiveTests.Require(generateBtn.IsEnabled, "GeneratePasswordButton stayed disabled after reaching 1024 samples.");

        // 2. Click generate button
        EnableProtectedOperationsForFailureTest(window);
        Task generation = window.GenerateArchiveEntropyAsync();
        var generationDeadline = System.Diagnostics.Stopwatch.StartNew();
        while (!generation.IsCompleted)
        {
            Dispatcher.UIThread.RunJobs();
            if (generationDeadline.Elapsed > TimeSpan.FromSeconds(30)) throw new TimeoutException("GUI entropy generation did not finish.");
            Thread.Sleep(1);
        }
        generation.GetAwaiter().GetResult();
        Dispatcher.UIThread.RunJobs();

        TextBox factorA = Control<TextBox>(window, "GeneratedPasswordFirstBox");
        TextBox factorB = Control<TextBox>(window, "GeneratedPasswordSecondBox");
        MacComprehensiveTests.Require(!string.IsNullOrEmpty(factorA.Text) && factorA.Text.Length == 256, "Factor A was not generated as 256 hex chars.");
        MacComprehensiveTests.Require(!string.IsNullOrEmpty(factorB.Text) && factorB.Text.Length == 256, "Factor B was not generated as 256 hex chars.");
        MacComprehensiveTests.Require(!string.Equals(factorA.Text, factorB.Text, StringComparison.Ordinal), "Factor A and Factor B must be distinct.");

        var prepared = (GeneratedArchiveEntropy?)typeof(MainWindow).GetField("_generatedEntropy",
            BindingFlags.Instance | BindingFlags.NonPublic)?.GetValue(window)
            ?? throw new InvalidOperationException("Prepared GUI entropy is missing.");
        AssertWorkerReachesStreamGuard(window.CaptureEncryptionConsumer(
            "/unused-test-target.kzpaq", EncryptionSuite.Kalyna512_512, prepared));

        // 3. Set password and PIN
        TextBox password = Control<TextBox>(window, "CreatePasswordBox");
        TextBox confirm = Control<TextBox>(window, "CreatePasswordConfirmBox");
        TextBox pin = Control<TextBox>(window, "CreatePinBox");
        TextBox pinConfirm = Control<TextBox>(window, "CreatePinConfirmBox");

        const string validPass = "Valid#Master%Passphrase2026&v12!";
        password.Text = validPass;
        confirm.Text = validPass;
        pin.Text = "84920153";
        pinConfirm.Text = "84920153";
        Dispatcher.UIThread.RunJobs();

        TextBlock pinReadout = Control<TextBlock>(window, "PinPolicyStatusText");
        MacComprehensiveTests.Require(
            pinReadout.Text?.Contains("akzeptiert", StringComparison.OrdinalIgnoreCase) == true
            || pinReadout.Text?.Contains("accepted", StringComparison.OrdinalIgnoreCase) == true,
            $"Valid PIN was not reported as accepted by GUI readout: {pinReadout.Text}");

        // 4. Clear secrets
        window.ClearCreateSecrets();
        Dispatcher.UIThread.RunJobs();
        MacComprehensiveTests.Require(string.IsNullOrEmpty(password.Text), "Password was not cleared.");
        MacComprehensiveTests.Require(string.IsNullOrEmpty(pin.Text), "PIN was not cleared.");
    }
}
