using System.Diagnostics;
using System.Reflection;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using Avalonia.VisualTree;
using KalynaArchiver;
using KalynaArchiver.Gui;
using KalynaArchiver.Services;

internal static class KeySheetProgressTests
{
    internal static IReadOnlyList<TestCase> Tests =>
    [
        new("gui.key-sheet-operation-progress", "key-sheet button completion distinguishes export/print success, failure, stale drafts and cancellation in DE/EN",
            () => MacGuiTests.RunOnUiThread(Run), TestResource.Gui, "GUI"),
    ];

    private const BindingFlags Flags = BindingFlags.Instance | BindingFlags.NonPublic;
    private static FieldInfo Field(string name) => typeof(MainWindow).GetField(name, Flags)!;
    private static T C<T>(MainWindow w, string name) where T : Control => w.FindControl<T>(name)!;
    private static void Require(bool value, string message) => MacComprehensiveTests.Require(value, message);
    private static void Click(MainWindow w, string name) => C<Button>(w, name).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));

    private static void Run(MainWindow initial)
    {
        string root = MacSafeFileSystem.ResolveExistingRealPath(Directory.CreateTempSubdirectory("kv-key-sheet-progress-").FullName);
        var service = new ObservedKeySheets();
        using var window = new MainWindow((IAppSettingsStore)Field("_settingsStore").GetValue(initial)!, service);
        window.Show();
        try
        {
            var clock = Stopwatch.StartNew();
            while ((string?)Field("_integrityStatusKey").GetValue(window) == "integrityChecking")
            {
                Dispatcher.UIThread.RunJobs();
                if (clock.Elapsed > TimeSpan.FromSeconds(15)) throw new TimeoutException("Headless startup did not complete.");
                Thread.Sleep(2);
            }
            Field("_integrityTrusted").SetValue(window, true);
            typeof(MainWindow).GetMethod("UpdateProtectedOperationControls", Flags)!.Invoke(window, null);
            IStorageProvider originalStorage = window.StorageProvider;
            IStorageFolder folder = originalStorage.TryGetFolderFromPathAsync(new Uri(root + Path.DirectorySeparatorChar)).GetAwaiter().GetResult()!;
            Field("_archiveDestinationAccess").SetValue(window, MacStorageAccessLease.Acquire(folder));
            string selectedPath = Path.Combine(root, "public-export.pdf");
            File.WriteAllText(selectedPath, "public picker placeholder");
            var storage = DispatchProxy.Create<IStorageProvider, KeySheetStorageProviderProxy>();
            var storageProxy = (KeySheetStorageProviderProxy)storage;
            storageProxy.Inner = originalStorage;
            typeof(TopLevel).GetField("_storageProvider", Flags)!.SetValue(window, storage);
            var reports = new List<SecurityDialogKind>();
            MainWindow.TestHookShowDialogAsync = (kind, _) => { reports.Add(kind); return Task.CompletedTask; };

            foreach (string language in new[] { "de", "en" })
            foreach (bool printing in new[] { false, true })
            foreach (string outcome in new[] { "success", "decline", "failure", "stale-draft", "unexpected-cancel", printing ? "token-cancel" : "picker-cancel" })
            {
                C<ComboBox>(window, "LanguageBox").SelectedItem = C<ComboBox>(window, "LanguageBox").Items.OfType<ComboBoxItem>().Single(x => Equals(x.Tag, language));
                C<TextBox>(window, "ArchivePathBox").Text = Path.Combine(root, "public-archive.kzpaq");
                C<TextBox>(window, "CreatePasswordBox").Text = "public unchanged password fixture";
                C<TextBox>(window, "CreatePinBox").Text = "428317";
                C<TextBox>(window, "GeneratedPasswordFirstBox").Text = new string('A', 256);
                C<TextBox>(window, "GeneratedPasswordSecondBox").Text = new string('B', 256);
                Field("_generatedPairReady").SetValue(window, true);
                typeof(MainWindow).GetMethod("ResetKeySheetStatus", Flags)!.Invoke(window, null);
                Dispatcher.UIThread.RunJobs();
                reports.Clear();
                service.Reset();
                // The actual handler owns and disposes each picker result.
                // Resolve a new provider item for every accepted selection.
                storageProxy.PickFile = async () => outcome == "picker-cancel" ? null
                    : await originalStorage.TryGetFileFromPathAsync(new Uri(selectedPath));
                storageProxy.SaveCalls = 0;
                service.Outcome = outcome;
                service.DuringOutput = () => Require(C<TextBlock>(window, "OperationPhaseText").Text != "Completed"
                    && C<TextBlock>(window, "OperationPhaseText").Text != "Abgeschlossen"
                    && Field("_keySheetFingerprint").GetValue(window) is null,
                    "A key-sheet operation reported success before its output returned.");
                service.AfterOutput = () =>
                {
                    if (outcome == "stale-draft") C<TextBox>(window, "GeneratedPasswordFirstBox").Text = new string('C', 256);
                };
                Click(window, printing ? "PrintKeySheetButton" : "SaveKeySheetButton");
                bool confirmationSeen = false;
                bool pendingObserved = false;
                clock.Restart();
                while ((int)Field("_operationActive").GetValue(window)! != 0)
                {
                    Dispatcher.UIThread.RunJobs();
                    if (window.OwnedWindows.FirstOrDefault() is { } dialog)
                    {
                        confirmationSeen = true;
                        string key = outcome == "decline" ? "cancel" : "continue";
                        string caption = (string)typeof(MainWindow).GetMethod("T", Flags)!.Invoke(window, [key])!;
                        dialog.GetVisualDescendants().OfType<Button>().Single(b => Equals(b.Content, caption))
                            .RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                    }
                    if (service.Pending is { Task.IsCompleted: false } pending)
                    {
                        pendingObserved = true;
                        Require(Field("_keySheetFingerprint").GetValue(window) is null,
                            "An unfinished print received a key-sheet approval.");
                        if (outcome == "token-cancel") Click(window, "CancelOperationButton");
                        else pending.SetResult();
                    }
                    if (clock.Elapsed > TimeSpan.FromSeconds(15)) throw new TimeoutException("Key-sheet handler did not join.");
                    Thread.Sleep(1);
                }
                Dispatcher.UIThread.RunJobs();
                string expected = outcome switch
                {
                    "success" => language == "en" ? "Completed" : "Abgeschlossen",
                    "failure" or "unexpected-cancel" => language == "en" ? "Failed" : "Fehlgeschlagen",
                    _ => language == "en" ? "Cancelled" : "Abgebrochen",
                };
                Require(C<TextBlock>(window, "OperationPhaseText").Text == expected,
                    $"{language}/{(printing ? "print" : "save")}/{outcome}: wrong terminal progress state.");
                Require(C<ProgressBar>(window, "OperationPhaseProgress").Value == (outcome == "success" ? 100 : 0),
                    "An unsuccessful key-sheet operation received completed progress.");
                Require((Field("_keySheetFingerprint").GetValue(window) is not null) == (outcome == "success"),
                    "Only a fully returned output with the unchanged draft may approve the key sheets.");
                Require(service.OutputCalls == (outcome is "decline" or "picker-cancel" ? 0 : 1),
                    "A declined/cancelled selection entered output, or an accepted operation ran twice.");
                Require(storageProxy.SaveCalls == (printing ? 0 : 1), "The save picker did not follow its actual button path.");
                Require(confirmationSeen == (outcome != "picker-cancel") && (!printing || outcome == "decline" || pendingObserved),
                    "The real confirmation or asynchronous print boundary was not exercised.");
                Require(reports.Contains(SecurityDialogKind.Error) == (outcome is "failure" or "unexpected-cancel"),
                    "A real error was not reported, or a cancellation became an error.");
                Require(C<TextBox>(window, "CreatePasswordBox").Text == "public unchanged password fixture"
                    && C<TextBox>(window, "CreatePinBox").Text == "428317"
                    && (bool)Field("_generatedPairReady").GetValue(window)!,
                    "Key-sheet progress handling changed credentials or the prepared-pair state.");
                if (!printing && outcome == "success")
                    foreach (string factor in new[] { "A", "B" })
                        Require(File.ReadAllBytes(Path.Combine(root, $"public-export-Faktor-{factor}.pdf")).AsSpan(0, 5).SequenceEqual("%PDF-"u8),
                            "The successful save regression did not produce both actual PDFs.");
                foreach (string path in Directory.EnumerateFiles(root, "public-export-Faktor-*.pdf")) File.Delete(path);
            }
        }
        finally
        {
            MainWindow.TestHookShowDialogAsync = null;
            window.Close();
            window.Dispose();
            Directory.Delete(root, recursive: true);
        }
    }

    private sealed class ObservedKeySheets : IMacKeySheetService
    {
        private readonly MacKeySheetService _real = new();
        internal string Outcome = "success";
        internal Action? DuringOutput, AfterOutput;
        internal TaskCompletionSource? Pending;
        internal int OutputCalls;
        internal void Reset() { Pending = null; OutputCalls = 0; }
        public Task<IReadOnlyList<string>> GetPhysicalPrintersAsync(CancellationToken token) =>
            Task.FromResult<IReadOnlyList<string>>(["public-headless-printer"]);
        public void SaveExplicitTestPdf(MacKeySheetData data, string first, string second)
        {
            ++OutputCalls;
            DuringOutput?.Invoke();
            FailIfRequested();
            _real.SaveExplicitTestPdf(data, first, second);
            AfterOutput?.Invoke();
        }
        public async Task PrintAsync(MacKeySheetData data, string printer, CancellationToken token)
        {
            ++OutputCalls;
            DuringOutput?.Invoke();
            Pending = new(TaskCreationOptions.RunContinuationsAsynchronously);
            await Pending.Task.WaitAsync(token);
            FailIfRequested();
            AfterOutput?.Invoke();
        }
        private void FailIfRequested()
        {
            if (Outcome == "failure") throw new IOException("public key-sheet output failure");
            if (Outcome == "unexpected-cancel") throw new OperationCanceledException("public output failure without token cancellation");
        }
    }
}

// Storage pickers are replaced only inside the headless framework fixture;
// ordinary item/path/scoped-access behavior still comes from its BCL provider.
public class KeySheetStorageProviderProxy : DispatchProxy
{
    internal IStorageProvider Inner = null!;
    internal Func<Task<IStorageFile?>> PickFile = null!;
    internal int SaveCalls;
    protected override object? Invoke(MethodInfo? method, object?[]? args)
    {
        if (method!.Name == nameof(IStorageProvider.SaveFilePickerAsync))
        {
            ++SaveCalls;
            return PickFile();
        }
        return method.Invoke(Inner, args);
    }
}
