using System.Diagnostics;
using System.Collections.Specialized;
using System.Reflection;
using System.Runtime.ExceptionServices;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Input;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using KalynaArchiver;
using KalynaArchiver.Gui;
using KalynaArchiver.Services;
using KeepVaultMac.Controls;

// These cases execute the actual window/clipboard/storage disposal paths with
// public fixtures. They do not replace installed macOS UI or memory-lock proof.
internal static class WindowDisposeRev12Tests
{
    internal static IReadOnlyList<TestCase> Tests =>
    [
        new("gui.rev12-dispose-failure", "REV12 window teardown independently clears credentials and invalidates pending clipboard input after actual cleanup failures",
            () => MacGuiTests.RunOnUiThread(DisposeFailure), TestResource.Gui, "GUI"),
        new("gui.rev12-dispose-storage-ownership", "REV12 owned storage cleanup attempts independent leases, retains only failed owners for retry and waits for active operation ownership",
            () => MacGuiTests.RunOnUiThread(StorageOwnership), TestResource.Gui, "GUI"),
        new("gui.rev12-storage-transitions", "REV12 actual storage replacement, batch input, mismatch, rejected acquisition and reentry preserve every owned item and retry failure",
            () => MacGuiTests.RunOnUiThread(StorageTransitions), TestResource.Gui, "GUI"),
        new("gui.rev12-drop-storage-ownership", "REV12 actual ApplyDrop/event reporting, consumed ownership, provider Path faults, independent cleanup, alias and disposal reentry",
            () => MacGuiTests.RunOnUiThread(DropStorageOwnership), TestResource.Gui, "GUI"),
        new("gui.rev12-storage-path-callbacks", "REV12 actual mismatch/Ensure callbacks preserve current owners; plain-URL transient Dispose invocation only, no native YES-grant proof",
            () => MacGuiTests.RunOnUiThread(StoragePathCallbacks), TestResource.Gui, "GUI"),
        new("gui.rev12-storage-path-events", "REV12 actual TextBox.Text events report Path/retirement faults, preserve retry owners and retain draft/hint/erase semantics",
            () => MacGuiTests.RunOnUiThread(StoragePathEvents), TestResource.Gui, "GUI"),
        new("gui.rev12-file-activation-ownership", "REV12 actual App activation handoff preserves accepted aliases, attempts all independent cleanup and retains failed owners across window loss",
            () => MacGuiTests.RunOnUiThread(FileActivationOwnership), TestResource.Gui, "GUI"),
    ];

    private static readonly string[] NativeCredentialNames =
    [
        "CreatePasswordBox", "CreatePasswordConfirmBox", "CreatePinBox", "CreatePinConfirmBox",
        "GeneratedPasswordFirstBox", "GeneratedPasswordSecondBox", "ExtractPasswordBox", "ExtractPinBox",
    ];
    private static readonly string[] StorageNames =
    [
        "_resourceWorkingAccess", "_archiveDestinationAccess", "_extractArchiveAccess",
        "_extractArchiveParentAccess", "_extractOutputParentAccess", "_eraseArchiveAccess", "_eraseArchiveParentAccess",
    ];

    private static void DisposeFailure(MainWindow window)
    {
        WaitForIntegrity(window);
        EntropyMixer.Reset();
        long baselineBytes = SecureMemory.LockedBytesForTests;
        long baselineAllocations = SecureMemory.LockedAllocationsForTests;
        long baselineEntropyBytes = OperationMemoryBudget.EntropyReservedBytes;
        using GeneratedArchiveEntropy entropy = PublicEntropy();
        Field("_generatedEntropy").SetValue(window, entropy);
        Field("_generatedPairReady").SetValue(window, true);
        Field("_keySheetFingerprint").SetValue(window, "public printed fixture binding");
        foreach (string name in NativeCredentialNames) C<TextBox>(window, name).Text = "123456";
        FactorTextBox[] factors =
        [
            C<FactorTextBox>(window, "ExtractGeneratedPasswordFirstBox"),
            C<FactorTextBox>(window, "ExtractGeneratedPasswordSecondBox"),
        ];
        C<TabControl>(window, "MainTabs").SelectedIndex = 1;
        Dispatcher.UIThread.RunJobs();
        foreach (FactorTextBox factor in factors)
        {
            factor.Focus();
            window.KeyTextInput(FactorInputRev12Tests.FactorA);
            Require(factor.Text == FactorInputRev12Tests.FactorA, "The public teardown undo fixture was not entered.");
        }

        var clipboard = TopLevel.GetTopLevel(window)?.Clipboard
            ?? throw new InvalidOperationException("The real GUI clipboard is unavailable.");
        using var pending = new DeferredPublicText();
        Complete(clipboard.SetDataAsync(pending));
        factors[0].Focus(); factors[0].SelectAll(); factors[0].Paste();
        PumpUntil(() => pending.Requested);
        var propertyFailure = new IOException("Injected public credential-control cleanup failure.");
        var cancelFailure = new IOException("Injected public cancellation callback cleanup failure.");
        var bufferFailure = new IOException("Injected public sensitive-owner cleanup failure.");
        bool propertyFailed = false;
        EventHandler<AvaloniaPropertyChangedEventArgs> onProperty = (_, change) =>
        {
            if (change.Property == TextBox.TextProperty && !propertyFailed
                && string.IsNullOrEmpty(C<TextBox>(window, "CreatePasswordConfirmBox").Text))
            {
                propertyFailed = true;
                throw propertyFailure;
            }
        };
        C<TextBox>(window, "CreatePasswordConfirmBox").PropertyChanged += onProperty;
        var lifetime = (CancellationTokenSource)Field("_lifetime").GetValue(window)!;
        using CancellationTokenRegistration registration = lifetime.Token.Register(() => throw cancelFailure);
        try
        {
            // An actual committed mouse segment makes Reset perform locked
            // owner cleanup; the existing before-unlock seam fails that work.
            EntropyMixer.AddCanonicalRecord(new byte[SensitiveMouseRecordStore.RecordBytes]);
            ulong resetVersion = ResetVersion();
            int bufferAttempts = 0;
            SecureMemory.SensitiveBufferBeforeUnlockForTests = () =>
            {
                ++bufferAttempts;
                throw bufferFailure;
            };
            Exception actual = CaptureFailure(window.Dispose);
            Require(actual is AggregateException && Contains(actual, propertyFailure)
                && Contains(actual, cancelFailure) && Contains(actual, bufferFailure),
                "Teardown hid or replaced an independent cleanup cause.");
            Require(propertyFailed && bufferAttempts >= 6 && ResetVersion() == resetVersion + 1,
                "Teardown did not attempt control cleanup, prepared-owner cleanup and the actual entropy reset.");
            Require((bool)Field("_disposed").GetValue(window)! && !(bool)Field("_integrityTrusted").GetValue(window)!
                && Field("_generatedEntropy").GetValue(window) is null
                && Field("_keySheetFingerprint").GetValue(window) is null,
                "A failed teardown retained operation authority or the prepared draft.");
            Require(NativeCredentialNames.All(name => string.IsNullOrEmpty(C<TextBox>(window, name).Text))
                && factors.All(factor => string.IsNullOrEmpty(factor.Text)),
                "An independent cleanup failure retained another credential field.");
            Require(new[] { "CreatePanel", "ExtractPanel", "ErasePanel", "ResourcesPanel", "CreateArchiveButton",
                "ExtractArchiveButton", "ListArchiveButton", "EmergencyRecoveryButton", "EraseContainerButton", "CancelOperationButton" }
                .All(name => !C<Control>(window, name).IsEnabled),
                "The disposed window retained enabled operation entry controls.");
            Require(!(bool)Call(window, "TryBeginProtectedOperation")!,
                "A disposed window admitted a new protected operation.");
            Require(lifetime.IsCancellationRequested && IsDisposed(lifetime),
                "A throwing cancellation callback skipped cancellation-source disposal.");
            var integrity = Field("_integrity").GetValue(window)!;
            Require((bool)integrity.GetType().GetField("_disposed", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(integrity)!,
                "An earlier cleanup failure skipped integrity-service disposal.");
            pending.Complete(FactorInputRev12Tests.FactorB);
            PumpUntil(() => factors[0].ValidationMessage == FactorInput.Message(FactorInput.Error.StaleTransfer, factors[0].LanguageCode));
            foreach (FactorTextBox factor in factors)
            {
                factor.Undo(); factor.Redo(); Dispatcher.UIThread.RunJobs();
                Require(string.IsNullOrEmpty(factor.Text) && factor.CaretIndex == 0
                    && factor.SelectionStart == 0 && factor.SelectionEnd == 0,
                    "Pending input or undo repopulated a disposed factor control.");
            }
        }
        finally
        {
            SecureMemory.SensitiveBufferBeforeUnlockForTests = null;
            C<TextBox>(window, "CreatePasswordConfirmBox").PropertyChanged -= onProperty;
            Complete(clipboard.ClearAsync());
            EntropyMixer.Reset();
            entropy.Dispose();
        }
        Require(SecureMemory.LockedBytesForTests == baselineBytes
            && SecureMemory.LockedAllocationsForTests == baselineAllocations
            && OperationMemoryBudget.EntropyReservedBytes == baselineEntropyBytes,
            "Explicit entropy retry lost a failed owner or leaked its accounting.");
    }

    private static void StorageTransitions(MainWindow providerWindow)
    {
        WaitForIntegrity(providerWindow);
        string root = MacSafeFileSystem.ResolveExistingRealPath(Directory.CreateTempSubdirectory("kv-rev12-storage-transition-").FullName);
        var observed = new List<ObservedStorageItem>();
        var windows = new List<MainWindow>();
        ObservedStorageItem Folder(Exception? failure = null)
        { var item = Storage(providerWindow, root, failure); observed.Add(item); return item; }
        ObservedStorageItem FileItem(string name, Exception? failure = null)
        {
            string path = System.IO.Path.Combine(root, name);
            File.WriteAllText(path, "public storage transition fixture");
            var item = new ObservedStorageItem(providerWindow.StorageProvider.TryGetFileFromPathAsync(new Uri(path)).GetAwaiter().GetResult()
                ?? throw new InvalidOperationException("The public file fixture was not resolved."), failure);
            observed.Add(item); return item;
        }
        MainWindow Window() { var window = new MainWindow(new PublicSettings()); windows.Add(window); return window; }
        var foreign = Folder();
        MainWindow.TestHookShowDialogAsync = (_, _) => Task.CompletedTask;
        try
        {
            // Actual field replacement must retain the newly acquired item
            // before a real old-item Dispose failure. One live item reference
            // shared by two fields owns one lease until its last alias retires.
            MainWindow replace = Window();
            var replacementFailure = new IOException("Injected old selected-folder cleanup failure.");
            var oldFolder = Folder(replacementFailure);
            var nextFolder = Folder();
            Require((bool)Call(replace, "RetainArchiveDestinationAccess", oldFolder.Item)!, "Initial folder ownership did not bind.");
            MacStorageAccessLease oldLease = (MacStorageAccessLease)Field("_archiveDestinationAccess").GetValue(replace)!;
            Exception actual = CaptureFailure(() => Call(replace, "RetainArchiveDestinationAccess", nextFolder.Item));
            Require(Contains(actual, replacementFailure)
                && ReferenceEquals(((MacStorageAccessLease)Field("_archiveDestinationAccess").GetValue(replace)!).Item, nextFolder.Item)
                && oldFolder.Attempts == 1 && nextFolder.Attempts == 0,
                "A replacement cleanup fault lost its new owner or retained the terminal old field.");
            object?[] acquireArguments = [oldFolder.Item, null];
            Require(CaptureFailure(() => Call(replace, "TryAcquireStorageAccess", acquireArguments)) is ObjectDisposedException
                && oldFolder.Attempts == 1 && acquireArguments[1] is null,
                "A terminal failed item was reacquired or implicitly retried through a new ownership request.");
            Require((bool)Call(replace, "RetainExtractOutputParentAccess", nextFolder.Item)!, "Live folder alias did not bind.");
            Require(ReferenceEquals(Field("_archiveDestinationAccess").GetValue(replace), Field("_extractOutputParentAccess").GetValue(replace)),
                "The same live item reference acquired multiple disposal owners.");
            string mismatch = System.IO.Path.Combine(root, "other-parent", "public.kzpaq");
            Call(replace, "ReleaseArchiveDestinationAccessIfMismatched", mismatch);
            Require(Field("_archiveDestinationAccess").GetValue(replace) is null && nextFolder.Attempts == 0,
                "Retiring one field disposed an item still owned by its other live alias.");
            Call(replace, "ReleaseExtractOutputAccessIfMismatched", mismatch);
            replace.Dispose(); replace.Dispose(); oldLease.Dispose();
            Require(oldFolder.Attempts == 2 && oldFolder.Successes == 1
                && nextFolder.Attempts == 1 && nextFolder.Successes == 1,
                "Replacement retry lost a failed old owner or repeated a completed item cleanup.");

            MainWindow reentry = Window();
            var first = Folder(); var middle = Folder(); var last = Folder();
            Call(reentry, "RetainArchiveDestinationAccess", first.Item);
            first.BeforeDispose = () => Call(reentry, "RetainArchiveDestinationAccess", last.Item);
            Call(reentry, "RetainArchiveDestinationAccess", middle.Item);
            Require(ReferenceEquals(((MacStorageAccessLease)Field("_archiveDestinationAccess").GetValue(reentry)!).Item, last.Item)
                && first.Attempts == 1 && middle.Attempts == 1 && last.Attempts == 0,
                "A real retirement callback overwrote the later live owner or repeated its disposal.");
            reentry.Dispose(); reentry.Dispose();
            Require(last.Attempts == 1, "The final reentrant replacement owner was not released once.");

            MainWindow mismatchWindow = Window();
            var mismatchFileFailure = new IOException("Injected stale extraction-file cleanup failure.");
            var mismatchParentFailure = new IOException("Injected stale extraction-parent cleanup failure.");
            var mismatchFile = FileItem("stale-extract.kzpaq", mismatchFileFailure);
            var mismatchParent = Folder(mismatchParentFailure);
            Field("_extractArchiveAccess").SetValue(mismatchWindow, MacStorageAccessLease.Acquire(mismatchFile.Item));
            Field("_extractArchiveParentAccess").SetValue(mismatchWindow, MacStorageAccessLease.Acquire(mismatchParent.Item));
            actual = CaptureFailure(() => Call(mismatchWindow, "ReleaseExtractAccessIfMismatched", mismatch));
            Require(Contains(actual, mismatchFileFailure) && Contains(actual, mismatchParentFailure)
                && Field("_extractArchiveAccess").GetValue(mismatchWindow) is null
                && Field("_extractArchiveParentAccess").GetValue(mismatchWindow) is null
                && mismatchFile.Attempts == 1 && mismatchParent.Attempts == 1,
                "A mismatch cleanup fault retained terminal fields or skipped the independent stale parent owner.");
            mismatchWindow.Dispose(); mismatchWindow.Dispose();
            Require(mismatchFile.Attempts == 2 && mismatchParent.Attempts == 2
                && mismatchFile.Successes == 1 && mismatchParent.Successes == 1,
                "Mismatch retirement lost an owner needed for explicit retry.");

            MainWindow activation = Window();
            var activationFailure = new IOException("Injected missing activation-file cleanup failure.");
            var missingActivation = FileItem("missing-activation.kzpaq", activationFailure);
            File.Delete(PathOf(missingActivation));
            actual = CaptureFailure(() => activation.HandleFileActivation((IStorageFile)missingActivation.Item));
            Require(Contains(actual, activationFailure) && Field("_extractArchiveAccess").GetValue(activation) is null
                && missingActivation.Attempts == 1,
                "A missing activated file retained a terminal field or lost its cleanup cause.");
            activation.Dispose(); activation.Dispose();
            Require(missingActivation.Attempts == 2 && missingActivation.Successes == 1,
                "Missing activation cleanup lost its failed acquired owner.");

            // Two actual old-item failures cannot prevent the later input item
            // from binding. A repeated reference cannot dispose the active item
            // underneath a newly acquired duplicate lease.
            MainWindow batch = Window();
            var oldAFailure = new IOException("Injected first old input cleanup failure.");
            var oldBFailure = new IOException("Injected second old input cleanup failure.");
            var clearBFailure = new IOException("Injected batch-clear input cleanup failure.");
            var oldA = FileItem("input-a.txt", oldAFailure); var oldB = FileItem("input-b.txt", oldBFailure);
            Call(batch, "AddInputStorageItems", (object)new[] { oldA.Item, oldB.Item });
            var nextA = FileItem("input-a.txt"); var nextB = FileItem("input-b.txt", clearBFailure); var nextC = FileItem("input-c.txt");
            actual = CaptureFailure(() => Call(batch, "AddInputStorageItems", (object)new[] { nextA.Item, nextB.Item, nextA.Item, nextC.Item }));
            var inputs = (Dictionary<string, MacStorageAccessLease>)Field("_inputStorageAccess").GetValue(batch)!;
            Require(Contains(actual, oldAFailure) && Contains(actual, oldBFailure)
                && inputs.Count == 3 && new[] { nextA, nextB, nextC }.All(item => item.Attempts == 0)
                && inputs[PathOf(nextA)].OwnsItem(nextA.Item) && inputs[PathOf(nextB)].OwnsItem(nextB.Item)
                && inputs[PathOf(nextC)].OwnsItem(nextC.Item),
                "A batch retirement failure hid another cause or lost a new/rest input owner.");
            Call(batch, "AddInputStorageItems", (object)new[] { nextA.Item, nextA.Item });
            Call(batch, "RetainEraseArchiveAccess", nextA.Item);
            Require(ReferenceEquals(inputs[PathOf(nextA)], Field("_eraseArchiveAccess").GetValue(batch)),
                "An input/file-field alias acquired a second owner for the same item.");
            actual = CaptureFailure(() => Call(batch, "ClearInputStorageAccess"));
            Require(Contains(actual, clearBFailure) && inputs.Count == 0 && nextA.Attempts == 0
                && nextB.Attempts == 1 && nextC.Successes == 1,
                "Input clearing skipped a later owner, retained a terminal dictionary entry or freed an active alias.");
            Call(batch, "ReleaseEraseAccessIfMismatched", mismatch);
            batch.Dispose(); batch.Dispose();
            Require(oldA.Attempts == 2 && oldB.Attempts == 2 && nextB.Attempts == 2
                && new[] { oldA, oldB, nextA, nextB, nextC }.All(item => item.Successes == 1),
                "Input retirement/clear retries lost a failed owner or repeated an item release.");

            // Exercise an acquired-but-unbound reject and an actual collection
            // callback failure in AddInputPaths, followed by a later accepted
            // item. Both primary and cleanup causes must survive.
            MainWindow rejected = Window();
            var rejectFailure = new IOException("Injected missing-input cleanup failure.");
            var additionFailure = new IOException("Injected input-list collection callback failure.");
            var additionCleanupFailure = new IOException("Injected unbound input cleanup failure.");
            var missing = FileItem("missing.txt", rejectFailure);
            File.Delete(PathOf(missing));
            var failedAddition = FileItem("failed-addition.txt", additionCleanupFailure);
            var accepted = FileItem("accepted.txt");
            bool additionFaulted = false;
            NotifyCollectionChangedEventHandler onAddition = (_, change) =>
            {
                if (!additionFaulted && change.Action == NotifyCollectionChangedAction.Add
                    && change.NewItems?.OfType<string>().Contains(PathOf(failedAddition), StringComparer.Ordinal) == true)
                { additionFaulted = true; throw additionFailure; }
            };
            C<ListBox>(rejected, "InputList").Items.CollectionChanged += onAddition;
            try
            {
                actual = CaptureFailure(() => Call(rejected, "AddInputStorageItems", (object)new[] { missing.Item, failedAddition.Item, accepted.Item }));
                inputs = (Dictionary<string, MacStorageAccessLease>)Field("_inputStorageAccess").GetValue(rejected)!;
                Require(Contains(actual, rejectFailure) && Contains(actual, additionFailure) && Contains(actual, additionCleanupFailure)
                    && additionFaulted && missing.Attempts == 1 && failedAddition.Attempts == 1
                    && inputs.Count == 1 && inputs[PathOf(accepted)].OwnsItem(accepted.Item) && accepted.Attempts == 0,
                    "Rejected/unbound input cleanup lost an owner, primary cause or later accepted item.");
            }
            finally { C<ListBox>(rejected, "InputList").Items.CollectionChanged -= onAddition; }
            rejected.Dispose(); rejected.Dispose();
            Require(missing.Attempts == 2 && failedAddition.Attempts == 2 && accepted.Attempts == 1
                && new[] { missing, failedAddition, accepted }.All(item => item.Successes == 1),
                "An unbound owner was not retained for retry or was disposed twice after success.");

            MainWindow rawFailureWindow = Window();
            var rawFailure = new IOException("Injected refused-acquisition item cleanup failure.");
            var raw = Folder(rawFailure);
            raw.PathOverride = new Uri("https://example.invalid/public-fixture");
            acquireArguments = [raw.Item, null];
            actual = CaptureFailure(() => Call(rawFailureWindow, "TryAcquireStorageAccess", acquireArguments));
            Require(Contains(actual, rawFailure) && HasException<NotSupportedException>(actual)
                && raw.Attempts == 1 && acquireArguments[1] is null
                && ((List<IStorageItem>)Field("_pendingStorageItemDisposals").GetValue(rawFailureWindow)!).Count == 1,
                "Refused acquisition hid its primary cause or lost its failed raw item cleanup owner.");
            Require(CaptureFailure(() => Call(rawFailureWindow, "TryAcquireStorageAccess", acquireArguments)) is ObjectDisposedException
                && raw.Attempts == 1, "A failed raw owner was accepted before explicit cleanup retry.");
            rawFailureWindow.Dispose(); rawFailureWindow.Dispose();
            Require(raw.Attempts == 2 && raw.Successes == 1, "Failed raw-item cleanup did not retry exactly once.");

            // All actual picker handlers use this product handoff helper. An
            // extra-item failure must still clean the selected item and every
            // later extra, without taking selected authority. A subsequent
            // replacement failure must preserve the new visible path.
            MainWindow selection = Window();
            var selectedFailure = new IOException("Injected selected picker-item cleanup failure.");
            var extraFailure = new IOException("Injected extra picker-item cleanup failure.");
            var selected = Folder(selectedFailure); var extra = Folder(extraFailure); var laterExtra = Folder();
            int renders = 0;
            actual = CaptureFailure(() => Complete(ApplyFolderSelection(selection,
                [(IStorageFolder)selected.Item, (IStorageFolder)extra.Item, (IStorageFolder)laterExtra.Item, (IStorageFolder)selected.Item],
                folder => (bool)Call(selection, "RetainArchiveDestinationAccess", folder)!, _ => ++renders)));
            Require(Contains(actual, selectedFailure) && Contains(actual, extraFailure)
                && Field("_archiveDestinationAccess").GetValue(selection) is null
                && selected.Attempts == 1 && extra.Attempts == 1 && laterExtra.Successes == 1 && renders == 0,
                "Picker extra cleanup lost its selected/later owner, repeated a selected alias or transferred authority after failure.");
            selection.Dispose(); selection.Dispose();
            Require(selected.Attempts == 2 && extra.Attempts == 2 && selected.Successes == 1 && extra.Successes == 1,
                "Picker reject cleanup did not retain both failed raw owners for retry.");

            MainWindow visible = Window();
            var visibleOldFailure = new IOException("Injected visible old selection cleanup failure.");
            var visibleOld = Folder(visibleOldFailure); var visibleNext = Folder();
            Call(visible, "RetainArchiveDestinationAccess", visibleOld.Item);
            actual = CaptureFailure(() => Complete(ApplyFolderSelection(visible, [(IStorageFolder)visibleNext.Item],
                folder => (bool)Call(visible, "RetainArchiveDestinationAccess", folder)!,
                path => C<TextBox>(visible, "WorkingDirectoryBox").Text = path)));
            Require(Contains(actual, visibleOldFailure)
                && ((MacStorageAccessLease)Field("_archiveDestinationAccess").GetValue(visible)!).OwnsItem(visibleNext.Item)
                && C<TextBox>(visible, "WorkingDirectoryBox").Text == PathOf(visibleNext),
                "An old selection cleanup failure hid the new retained selection path.");
            visible.Dispose(); visible.Dispose();
            Require(visibleOld.Attempts == 2 && visibleNext.Attempts == 1
                && visibleOld.Successes == 1 && visibleNext.Successes == 1,
                "Visible-selection retirement repeated or lost an item owner.");

            MainWindow closed = Window(); closed.Dispose();
            var closedFailure = new IOException("Injected closed-window incoming item cleanup failure.");
            var closedItem = Folder(closedFailure);
            acquireArguments = [closedItem.Item, null];
            actual = CaptureFailure(() => Call(closed, "TryAcquireStorageAccess", acquireArguments));
            Require(Contains(actual, closedFailure) && acquireArguments[1] is null && StorageNames.All(name => Field(name).GetValue(closed) is null),
                "A closed window took new item ownership or hid refusal cleanup failure.");
            closed.Dispose(); closed.Dispose();
            Require(closedItem.Attempts == 2 && closedItem.Successes == 1, "Closed-window raw cleanup owner was lost or repeatedly freed.");

            MainWindow closedDuringAcquire = Window();
            var incoming = Folder();
            incoming.BeforePath = closedDuringAcquire.Dispose;
            acquireArguments = [incoming.Item, null];
            Require(!(bool)Call(closedDuringAcquire, "TryAcquireStorageAccess", acquireArguments)!
                && acquireArguments[1] is null && incoming.Attempts == 1 && incoming.Successes == 1,
                "A provider callback closing the window left an unbound acquired lease or transferred new authority.");
            Require(foreign.Attempts == 0, "Storage transitions disposed an unowned canary item.");
        }
        finally
        {
            MainWindow.TestHookShowDialogAsync = null;
            foreach (MainWindow window in windows) window.Dispose();
            foreach (ObservedStorageItem item in observed)
            {
                item.BeforeDispose = null; item.BeforePath = null;
                if (item.Successes == 0) item.Dispose();
            }
            Directory.Delete(root, recursive: true);
        }
    }

    private static void DropStorageOwnership(MainWindow providerWindow)
    {
        WaitForIntegrity(providerWindow);
        string root = MacSafeFileSystem.ResolveExistingRealPath(Directory.CreateTempSubdirectory("kv-rev12-drop-owner-").FullName);
        var observed = new List<ObservedStorageItem>();
        var windows = new List<MainWindow>();
        ObservedStorageItem FileItem(string name, Exception? failure = null)
        {
            string path = System.IO.Path.Combine(root, name);
            File.WriteAllText(path, "public actual drop fixture");
            var item = new ObservedStorageItem(providerWindow.StorageProvider.TryGetFileFromPathAsync(new Uri(path)).GetAwaiter().GetResult()
                ?? throw new InvalidOperationException("The public drop file was not resolved."), failure);
            observed.Add(item); return item;
        }
        ObservedStorageItem FolderItem(string name)
        {
            string path = Directory.CreateDirectory(System.IO.Path.Combine(root, name)).FullName;
            var item = new ObservedStorageItem(providerWindow.StorageProvider.TryGetFolderFromPathAsync(new Uri(path + System.IO.Path.DirectorySeparatorChar)).GetAwaiter().GetResult()
                ?? throw new InvalidOperationException("The public drop folder was not resolved."), null);
            observed.Add(item); return item;
        }
        MainWindow Window() { var window = new MainWindow(new PublicSettings()); windows.Add(window); return window; }
        DragEventArgs Drop(MainWindow window, MacDropTarget target, params IStorageItem[] items)
        {
            using var transfer = new DataTransfer();
            foreach (IStorageItem item in items) transfer.Add(DataTransferItem.CreateFile(item));
            var args = new DragEventArgs(DragDrop.DropEvent, transfer, window, new Point(1, 1), KeyModifiers.None)
                { DragEffects = DragDropEffects.Copy };
            Call(window, "ApplyDrop", args, target);
            return args;
        }
        var reported = new List<(SecurityDialogKind Kind, string Message)>();
        MainWindow.TestHookShowDialogAsync = (kind, message) => { reported.Add((kind, message)); return Task.CompletedTask; };
        try
        {
            MainWindow rejected = Window();
            var missing = FileItem("missing.txt"); File.Delete(PathOf(missing));
            var invalid = FileItem("invalid.txt"); invalid.PathOverride = new Uri("https://example.invalid/public-drop");
            var accepted = FileItem("accepted.txt");
            DragEventArgs drop = Drop(rejected, MacDropTarget.Inputs, missing.Item, invalid.Item, accepted.Item);
            Require(drop.Handled && drop.DragEffects == DragDropEffects.Copy && missing.Attempts == 1 && missing.Successes == 1
                && invalid.Attempts == 1 && invalid.Successes == 1 && accepted.Attempts == 0
                && ((Dictionary<string, MacStorageAccessLease>)Field("_inputStorageAccess").GetValue(rejected)!).Count == 1,
                "Actual ApplyDrop repeated consumed rejected-item cleanup or lost a later accepted input.");
            rejected.Dispose(); rejected.Dispose();
            Require(accepted.Attempts == 1 && missing.Attempts == 1 && invalid.Attempts == 1,
                "Drop window retirement repeated completed rejected cleanup.");

            MainWindow faulted = Window();
            var pathFailure = new InvalidOperationException("Injected actual drop provider Path failure.");
            var firstCleanup = new IOException("Injected first actual drop raw cleanup failure.");
            var nextCleanup = new IOException("Injected second actual drop raw cleanup failure.");
            var first = FileItem("path-fault.txt", firstCleanup); var next = FileItem("cleanup-fault.txt", nextCleanup);
            var last = FileItem("cleanup-last.txt");
            first.BeforePath = () => throw pathFailure;
            Exception actual = CaptureFailure(() => Drop(faulted, MacDropTarget.Inputs, first.Item, next.Item, last.Item));
            Require(Contains(actual, pathFailure) && Contains(actual, firstCleanup) && Contains(actual, nextCleanup)
                && new[] { first, next, last }.All(item => item.Attempts == 1) && last.Successes == 1
                && ((List<IStorageItem>)Field("_pendingStorageItemDisposals").GetValue(faulted)!).Count == 2,
                "Actual ApplyDrop Path failure escaped batch cleanup, hid another cause or skipped a later item.");
            first.BeforePath = null;
            faulted.Dispose(); faulted.Dispose();
            Require(first.Attempts == 2 && next.Attempts == 2 && last.Attempts == 1
                && new[] { first, next, last }.All(item => item.Successes == 1),
                "Explicit failed-drop retry repeated successful cleanup or lost failed raw owners.");

            // Execute all actual eventhandlers, including the ExtractPanel
            // route which used to read Path before ownership was protected.
            // The strict ApplyDrop core above still throws every original
            // cause; the UI boundary must instead report it without escape.
            string[] handlers = ["Window_Drop", "CreatePanel_Drop", "InputList_Drop", "ArchivePathBox_Drop", "ExtractPanel_Drop",
                "ExtractArchiveBox_Drop", "OutputFolderBox_Drop", "ErasePanel_Drop", "ErasePathBox_Drop"];
            for (int index = 0; index < handlers.Length; ++index)
            {
                MainWindow eventWindow = Window();
                var eventPathFailure = new InvalidOperationException("Injected actual " + handlers[index] + " Path failure.");
                var eventCleanupFailure = new IOException("Injected actual " + handlers[index] + " raw cleanup failure.");
                var eventFirst = FileItem("event-first-" + index + ".txt", eventCleanupFailure);
                var eventLaterA = FileItem("event-later-a-" + index + ".txt"); var eventLaterB = FileItem("event-later-b-" + index + ".txt");
                eventFirst.BeforePath = () => throw eventPathFailure;
                using var transfer = new DataTransfer();
                foreach (var item in new[] { eventFirst, eventLaterA, eventLaterB }) transfer.Add(DataTransferItem.CreateFile(item.Item));
                var args = new DragEventArgs(DragDrop.DropEvent, transfer, eventWindow, new Point(1, 1), KeyModifiers.None)
                    { DragEffects = DragDropEffects.Copy };
                int beforeReports = reported.Count;
                Call(eventWindow, handlers[index], eventWindow, args); // The actual event must not throw.
                Dispatcher.UIThread.RunJobs();
                Call(eventWindow, "FlushConsoleEntries");
                string history = C<TextBox>(eventWindow, "LogBox").Text ?? string.Empty;
                Require(args.Handled && args.DragEffects == DragDropEffects.None
                    && new[] { eventFirst, eventLaterA, eventLaterB }.All(item => item.Attempts == 1)
                    && eventLaterA.Successes == 1 && eventLaterB.Successes == 1
                    && reported.Skip(beforeReports).Any(report => report.Kind == SecurityDialogKind.Error
                        && report.Message.Contains(eventPathFailure.Message, StringComparison.Ordinal)
                        && report.Message.Contains(eventCleanupFailure.Message, StringComparison.Ordinal))
                    && history.Contains(eventPathFailure.Message, StringComparison.Ordinal)
                    && history.Contains(eventCleanupFailure.Message, StringComparison.Ordinal)
                    && ((List<IStorageItem>)Field("_pendingStorageItemDisposals").GetValue(eventWindow)!).Count == 1,
                    "An actual Drop event escaped, skipped independent cleanup, lost retry ownership or failed to report both original causes.");
                eventFirst.BeforePath = null; eventWindow.Dispose();
                Require(eventFirst.Attempts == 2 && eventFirst.Successes == 1 && eventLaterA.Attempts == 1 && eventLaterB.Attempts == 1,
                    "Actual Drop event retry repeated completed independent cleanup.");
            }

            MainWindow panelRoutes = Window();
            var panelFolder = FolderItem("panel-output"); var panelArchive = FileItem("panel-archive.kzpaq");
            foreach (var item in new[] { panelFolder, panelArchive })
            {
                using var transfer = new DataTransfer();
                transfer.Add(DataTransferItem.CreateFile(item.Item));
                var args = new DragEventArgs(DragDrop.DropEvent, transfer, panelRoutes, new Point(1, 1), KeyModifiers.None);
                Call(panelRoutes, "ExtractPanel_Drop", panelRoutes, args);
                string field = ReferenceEquals(item, panelFolder) ? "_extractOutputParentAccess" : "_extractArchiveAccess";
                Require(args.Handled && args.DragEffects == DragDropEffects.Copy && item.Attempts == 0
                    && ((MacStorageAccessLease)Field(field).GetValue(panelRoutes)!).OwnsItem(item.Item),
                    "Actual ExtractPanel_Drop changed archive-versus-output-folder routing or lost its selected owner.");
            }
            panelRoutes.Dispose();
            Require(panelFolder.Attempts == 1 && panelArchive.Attempts == 1, "Extract-panel routing did not retire both independent owners once.");

            MainWindow aliasWindow = Window();
            var alias = FileItem("alias.txt");
            Call(aliasWindow, "RetainEraseArchiveAccess", alias.Item);
            drop = Drop(aliasWindow, MacDropTarget.Inputs, alias.Item, alias.Item);
            var inputs = (Dictionary<string, MacStorageAccessLease>)Field("_inputStorageAccess").GetValue(aliasWindow)!;
            Require(drop.Handled && inputs.Count == 1 && alias.Attempts == 0
                && ReferenceEquals(inputs[PathOf(alias)], Field("_eraseArchiveAccess").GetValue(aliasWindow)),
                "Actual ApplyDrop disposed an active alias or created duplicate owners for one provider reference.");
            aliasWindow.Dispose(); aliasWindow.Dispose();
            Require(alias.Attempts == 1 && alias.Successes == 1, "Drop alias retirement was not once per owner.");

            MainWindow reentry = Window();
            var reentryItem = FileItem("reentry.txt");
            bool entered = false; Exception? nestedFailure = null;
            reentryItem.BeforeDispose = () =>
            {
                if (entered) return;
                entered = true;
                nestedFailure = CaptureFailure(() => Drop(reentry, MacDropTarget.Inputs, reentryItem.Item));
            };
            drop = Drop(reentry, MacDropTarget.ExtractArchive, reentryItem.Item);
            Require(entered && nestedFailure is not null && HasException<ObjectDisposedException>(nestedFailure)
                && drop.Handled && drop.DragEffects == DragDropEffects.None
                && reentryItem.Attempts == 1 && reentryItem.Successes == 1 && !reentry.HasActivationStorageOwnership,
                "Actual nested ApplyDrop reacquired a disposing reference or repeated raw provider cleanup.");
            reentry.Dispose();
        }
        finally
        {
            MainWindow.TestHookShowDialogAsync = null;
            foreach (ObservedStorageItem item in observed) { item.BeforePath = null; item.BeforeDispose = null; }
            foreach (MainWindow window in windows) { window.Close(); window.Dispose(); }
            foreach (ObservedStorageItem item in observed.Where(item => item.Successes == 0)) item.Dispose();
            Directory.Delete(root, recursive: true);
        }
    }

    private static void StoragePathCallbacks(MainWindow providerWindow)
    {
        WaitForIntegrity(providerWindow);
        string root = MacSafeFileSystem.ResolveExistingRealPath(Directory.CreateTempSubdirectory("kv-rev12-path-owner-").FullName);
        var observed = new List<ObservedStorageItem>();
        var windows = new List<MainWindow>();
        ObservedStorageItem Item(string name, bool folder, Exception? failure = null)
        {
            string path = System.IO.Path.Combine(root, name);
            IStorageItem inner;
            if (folder)
            {
                Directory.CreateDirectory(path);
                inner = providerWindow.StorageProvider.TryGetFolderFromPathAsync(new Uri(path + System.IO.Path.DirectorySeparatorChar)).GetAwaiter().GetResult()
                    ?? throw new InvalidOperationException("The public callback folder was not resolved.");
            }
            else
            {
                File.WriteAllText(path, "public provider callback fixture");
                inner = providerWindow.StorageProvider.TryGetFileFromPathAsync(new Uri(path)).GetAwaiter().GetResult()
                    ?? throw new InvalidOperationException("The public callback file was not resolved.");
            }
            var item = new ObservedStorageItem(inner, failure); observed.Add(item); return item;
        }
        MainWindow Window() { var window = new MainWindow(new PublicSettings()); windows.Add(window); return window; }
        void Bind(MainWindow window, string field, IStorageItem item)
        {
            string? retain = field switch
            {
                "_archiveDestinationAccess" => "RetainArchiveDestinationAccess", "_extractOutputParentAccess" => "RetainExtractOutputParentAccess",
                "_extractArchiveAccess" => "RetainExtractArchiveAccess", "_eraseArchiveAccess" => "RetainEraseArchiveAccess", _ => null,
            };
            if (retain is not null) { Require((bool)Call(window, retain, item)!, "Actual callback owner binding failed."); return; }
            // Parent fields have no separate Retain wrapper. Bind before the
            // actual shared retirement helper, matching ReplaceStorageAccess.
            var previous = (MacStorageAccessLease?)Field(field).GetValue(window);
            Field(field).SetValue(window, MacStorageAccessLease.Acquire(item));
            if (previous is not null) Call(window, "DisposeOwnedStorageAccess", previous);
        }
        MainWindow.TestHookShowDialogAsync = (_, _) => Task.CompletedTask;
        try
        {
            var releases = new[]
            {
                ("_archiveDestinationAccess", "ReleaseArchiveDestinationAccessIfMismatched", true),
                ("_extractOutputParentAccess", "ReleaseExtractOutputAccessIfMismatched", true),
                ("_extractArchiveAccess", "ReleaseExtractAccessIfMismatched", false),
                ("_extractArchiveParentAccess", "ReleaseExtractAccessIfMismatched", true),
                ("_eraseArchiveAccess", "ReleaseEraseAccessIfMismatched", false),
                ("_eraseArchiveParentAccess", "ReleaseEraseAccessIfMismatched", true),
            };
            int index = 0;
            foreach ((string field, string method, bool folder) in releases)
            foreach (bool close in new[] { false, true })
            {
                MainWindow window = Window();
                var old = Item("release-old-" + index + (folder ? "" : ".kzpaq"), folder);
                var next = Item("release-next-" + index + (folder ? "" : ".kzpaq"), folder); ++index;
                Bind(window, field, old.Item);
                bool entered = false;
                old.BeforePath = () => { if (entered) return; entered = true; if (close) window.Dispose(); else Bind(window, field, next.Item); };
                Call(window, method, System.IO.Path.Combine(root, "different-parent", "public.kzpaq"));
                Require(entered && old.Attempts == 1 && old.Successes == 1 && next.Attempts == 0
                    && (close ? StorageNames.All(name => Field(name).GetValue(window) is null)
                        : ((MacStorageAccessLease)Field(field).GetValue(window)!).OwnsItem(next.Item))
                    && !((List<MacStorageAccessLease>)Field("_pendingStorageDisposals").GetValue(window)!).Any(owner => owner is null),
                    "Actual mismatch Path callback retired the new owner, introduced a null pending owner or lost old cleanup.");
                old.BeforePath = null;
                window.Dispose(); window.Dispose();
                Require(old.Attempts == 1 && (close ? next.Attempts == 0 : next.Attempts == 1),
                    "Mismatch callback retirement repeated an old provider or failed to retain the new one.");
            }

            // Both actual two-owner methods must preserve independent probes
            // and cleanup even when the other provider Path throws. Reverse
            // the failing probe as well, and retain the original path cause
            // alongside failed cleanup of the already retired owner.
            foreach (bool erase in new[] { false, true })
            foreach (bool archivePathFails in new[] { false, true })
            {
                MainWindow window = Window();
                var pathFailure = new InvalidOperationException("Injected two-owner mismatch provider Path failure.");
                var cleanupFailure = new IOException("Injected two-owner mismatch retired cleanup failure.");
                var archive = Item("pair-archive-" + index + ".kzpaq", false, archivePathFails ? null : cleanupFailure);
                var parent = Item("pair-parent-" + index, true, archivePathFails ? cleanupFailure : null); ++index;
                string archiveField = erase ? "_eraseArchiveAccess" : "_extractArchiveAccess";
                string parentField = erase ? "_eraseArchiveParentAccess" : "_extractArchiveParentAccess";
                Bind(window, archiveField, archive.Item); Bind(window, parentField, parent.Item);
                var failedPathItem = archivePathFails ? archive : parent;
                var retiredItem = archivePathFails ? parent : archive;
                failedPathItem.BeforePath = () => throw pathFailure;
                Exception actual = CaptureFailure(() => Call(window,
                    erase ? "ReleaseEraseAccessIfMismatched" : "ReleaseExtractAccessIfMismatched",
                    System.IO.Path.Combine(root, "different-pair-parent", "public.kzpaq")));
                var pending = (List<MacStorageAccessLease>)Field("_pendingStorageDisposals").GetValue(window)!;
                Require(Contains(actual, pathFailure) && Contains(actual, cleanupFailure)
                    && failedPathItem.Attempts == 0 && retiredItem.Attempts == 1 && retiredItem.Successes == 0
                    && ((MacStorageAccessLease)Field(archivePathFails ? archiveField : parentField).GetValue(window)!).OwnsItem(failedPathItem.Item)
                    && Field(archivePathFails ? parentField : archiveField).GetValue(window) is null
                    && pending.Count == 1 && pending[0].OwnsItem(retiredItem.Item),
                    "Actual two-owner mismatch skipped an independent probe, lost an already retired owner or hid a Path/cleanup cause.");
                failedPathItem.BeforePath = null;
                window.Dispose(); window.Dispose();
                Require(failedPathItem.Attempts == 1 && failedPathItem.Successes == 1
                    && retiredItem.Attempts == 2 && retiredItem.Successes == 1 && pending.Count == 0,
                    "Two-owner mismatch retry lost the reachable Path-fault owner or repeated successful cleanup.");
            }

            var ensures = new[]
            {
                ("_archiveDestinationAccess", "EnsureArchiveDestinationAccessAsync"),
                ("_extractArchiveParentAccess", "EnsureExtractArchiveParentAccessAsync"),
                ("_extractOutputParentAccess", "EnsureExtractOutputParentAccessAsync"),
                ("_eraseArchiveParentAccess", "EnsureEraseArchiveParentAccessAsync"),
            };
            foreach ((string field, string method) in ensures)
            foreach (bool close in new[] { false, true })
            {
                MainWindow window = Window();
                Require(!window.StorageProvider.CanPickFolder, "The callback fixture must use the actual headless Noop folder picker.");
                var old = Item("ensure-old-" + index, true); var next = Item("ensure-next-" + index, true); ++index;
                string requested = System.IO.Path.Combine(PathOf(old), "public.kzpaq");
                Bind(window, field, old.Item);
                bool entered = false;
                old.BeforePath = () => { if (entered) return; entered = true; if (close) window.Dispose(); else Bind(window, field, next.Item); };
                var task = (Task<bool>)Call(window, method, requested)!;
                Complete(task);
                Require(entered && !task.Result && old.Attempts == 1 && next.Attempts == 0
                    && (close || ((MacStorageAccessLease)Field(field).GetValue(window)!).OwnsItem(next.Item)),
                    "Actual Ensure fastpath accepted an old owner after Close/Rebind or lost the replacement binding.");
                old.BeforePath = null; window.Dispose();
            }

            // Close during the second Path read, after the matching fastpath,
            // invalidates a newly acquired actual transient lease. An active
            // operation retains the original owner, isolating the +1 Dispose
            // call to the rejected transient. This proves plain-URL cleanup
            // invocation, not real native YES-grant/Stop behavior.
            foreach (bool erase in new[] { false, true })
            {
                MainWindow window = Window();
                var item = Item("transient-" + index + (erase ? "" : ".kzpaq"), erase); ++index;
                string requested = erase ? System.IO.Path.Combine(PathOf(item), "public.kzpaq") : PathOf(item);
                string field = erase ? "_eraseArchiveParentAccess" : "_extractArchiveAccess";
                Bind(window, field, item.Item);
                Field("_integrityTrusted").SetValue(window, true);
                Require((bool)Call(window, "TryBeginProtectedOperation")!, "The transient invalidation fixture did not begin.");
                int reads = 0;
                item.BeforePath = () => { if (++reads == 2) window.Dispose(); };
                using var observation = MacSecurityScopedResourceLease.ObserveDisposeInvocationsForTests();
                if (erase)
                    RequireThrows<UnauthorizedAccessException>(() => Call(window, "AcquireTransientEraseAccess", requested),
                        "The actual erase transient path retained authority after owner invalidation.");
                else Require(Call(window, "AcquireTransientExtractAccess", requested) is null,
                    "The actual extract transient path retained authority after owner invalidation.");
                Require(reads == 2 && item.Attempts == 0 && observation.Count == 1
                    && ((MacStorageAccessLease)Field(field).GetValue(window)!).OwnsItem(item.Item),
                    "A newly acquired invalidated transient lease was not disposed exactly once, or the active owner was prematurely retired.");
                item.BeforePath = null;
                Call(window, "EndProtectedOperation"); window.Dispose();
                Require(item.Attempts == 1 && item.Successes == 1, "Ending the active transient fixture lost its original owner cleanup.");
            }
        }
        finally
        {
            MainWindow.TestHookShowDialogAsync = null;
            foreach (ObservedStorageItem item in observed) { item.BeforePath = null; item.BeforeDispose = null; }
            foreach (MainWindow window in windows)
            {
                window.Close(); window.Dispose();
                if ((int)Field("_operationActive").GetValue(window)! != 0) Call(window, "EndProtectedOperation");
                window.Dispose();
            }
            foreach (ObservedStorageItem item in observed.Where(item => item.Successes == 0)) item.Dispose();
            Directory.Delete(root, recursive: true);
        }
    }
    private static void StoragePathEvents(MainWindow providerWindow)
    {
        WaitForIntegrity(providerWindow);
        string root = MacSafeFileSystem.ResolveExistingRealPath(Directory.CreateTempSubdirectory("kv-rev12-path-event-").FullName);
        var observed = new List<ObservedStorageItem>();
        var windows = new List<MainWindow>();
        var reported = new List<(SecurityDialogKind Kind, string Message)>();
        ObservedStorageItem Item(string name, bool folder, Exception? failure = null)
        {
            string path = System.IO.Path.Combine(root, name);
            IStorageItem inner;
            if (folder)
            {
                Directory.CreateDirectory(path);
                inner = providerWindow.StorageProvider.TryGetFolderFromPathAsync(new Uri(path + System.IO.Path.DirectorySeparatorChar)).GetAwaiter().GetResult()
                    ?? throw new InvalidOperationException("The public path-event folder was not resolved.");
            }
            else
            {
                File.WriteAllText(path, "public path-event fixture");
                inner = providerWindow.StorageProvider.TryGetFileFromPathAsync(new Uri(path)).GetAwaiter().GetResult()
                    ?? throw new InvalidOperationException("The public path-event file was not resolved.");
            }
            var item = new ObservedStorageItem(inner, failure); observed.Add(item); return item;
        }
        MainWindow Window()
        {
            var window = new MainWindow(new PublicSettings()); windows.Add(window);
            window.Show(); WaitForIntegrity(window); Dispatcher.UIThread.RunJobs();
            return window;
        }
        void ChangeTextAndRequireReport(MainWindow window, string control, string text, params Exception[] failures)
        {
            int before = reported.Count;
            C<TextBox>(window, control).Text = text; // Actual property and actual XAML-bound TextChanged event.
            PumpUntil(() => reported.Skip(before).Any(report => report.Kind == SecurityDialogKind.Error
                && failures.All(failure => report.Message.Contains(failure.Message, StringComparison.Ordinal))));
            Dispatcher.UIThread.RunJobs();
            Call(window, "FlushConsoleEntries");
            string history = C<TextBox>(window, "LogBox").Text ?? string.Empty;
            Require(C<TextBox>(window, control).Text == text && failures.All(failure => history.Contains(failure.Message, StringComparison.Ordinal)),
                "Actual path TextChanged escaped the UI boundary, lost the edited text or failed to log every original cause.");
        }
        MainWindow.TestHookShowDialogAsync = (kind, message) => { reported.Add((kind, message)); return Task.CompletedTask; };
        try
        {
            int index = 0;
            foreach ((string control, string field, string retain) in new[]
            {
                ("ArchivePathBox", "_archiveDestinationAccess", "RetainArchiveDestinationAccess"),
                ("OutputFolderBox", "_extractOutputParentAccess", "RetainExtractOutputParentAccess"),
            })
            foreach (bool pathFault in new[] { false, true })
            {
                MainWindow window = Window();
                Exception failure = pathFault
                    ? new InvalidOperationException("Injected actual " + control + " provider Path failure.")
                    : new IOException("Injected actual " + control + " retirement cleanup failure.");
                var item = Item("single-event-" + index, true, pathFault ? null : failure); ++index;
                Require((bool)Call(window, retain, item.Item)!, "The actual path-event owner was not bound.");
                if (pathFault) item.BeforePath = () => throw failure;
                long revision = (long)Field("_createDraftRevision").GetValue(window)!;
                ChangeTextAndRequireReport(window, control, System.IO.Path.Combine(root, "different-event-parent", "single-" + index + ".kzpaq"), failure);
                var pending = (List<MacStorageAccessLease>)Field("_pendingStorageDisposals").GetValue(window)!;
                Require(pathFault
                    ? item.Attempts == 0 && pending.Count == 0 && ((MacStorageAccessLease)Field(field).GetValue(window)!).OwnsItem(item.Item)
                    : item.Attempts == 1 && item.Successes == 0 && Field(field).GetValue(window) is null && pending.Count == 1 && pending[0].OwnsItem(item.Item),
                    "Actual single-owner path event lost the bound Path-fault owner or the failed retirement owner.");
                if (control == "ArchivePathBox") Require((long)Field("_createDraftRevision").GetValue(window)! == revision + 1,
                    "Actual archive path event changed normal draft revision semantics while reporting a storage failure.");
                item.BeforePath = null; window.Close(); window.Dispose();
                Require(item.Attempts == (pathFault ? 1 : 2) && item.Successes == 1 && pending.Count == 0,
                    "Actual single-owner path event retry was lost or repeated completed cleanup.");
            }

            foreach (bool erase in new[] { false, true })
            foreach (bool archivePathFault in new[] { false, true })
            {
                MainWindow window = Window();
                string control = erase ? "ErasePathBox" : "ExtractArchiveBox";
                var pathFailure = new InvalidOperationException("Injected actual " + control + " paired provider Path failure.");
                var cleanupFailure = new IOException("Injected actual " + control + " paired retirement cleanup failure.");
                var archive = Item("pair-event-" + index + ".kzpaq", false, archivePathFault ? null : cleanupFailure);
                var parent = Item("pair-parent-event-" + index, true, archivePathFault ? cleanupFailure : null); ++index;
                string archiveField = erase ? "_eraseArchiveAccess" : "_extractArchiveAccess";
                string parentField = erase ? "_eraseArchiveParentAccess" : "_extractArchiveParentAccess";
                Require((bool)Call(window, erase ? "RetainEraseArchiveAccess" : "RetainExtractArchiveAccess", archive.Item)!,
                    "The actual paired event archive owner was not bound.");
                Field(parentField).SetValue(window, MacStorageAccessLease.Acquire(parent.Item));
                var pathItem = archivePathFault ? archive : parent;
                var retiredItem = archivePathFault ? parent : archive;
                pathItem.BeforePath = () => throw pathFailure;
                int hintVersion = (int)Field("_hintLoadVersion").GetValue(window)!;
                if (erase)
                {
                    Field("_eraseStatusKey").SetValue(window, "eraseCompleted");
                    C<CheckBox>(window, "EraseConfirmBox").IsChecked = true;
                }
                ChangeTextAndRequireReport(window, control, System.IO.Path.Combine(root, "different-event-parent", "pair-" + index + ".kzpaq"),
                    pathFailure, cleanupFailure);
                var pending = (List<MacStorageAccessLease>)Field("_pendingStorageDisposals").GetValue(window)!;
                Require(pathItem.Attempts == 0 && retiredItem.Attempts == 1 && retiredItem.Successes == 0
                    && ((MacStorageAccessLease)Field(archivePathFault ? archiveField : parentField).GetValue(window)!).OwnsItem(pathItem.Item)
                    && Field(archivePathFault ? parentField : archiveField).GetValue(window) is null
                    && pending.Count == 1 && pending[0].OwnsItem(retiredItem.Item),
                    "Actual two-owner path event lost an independent binding, retired the wrong owner or dropped retry ownership.");
                if (erase) Require(C<CheckBox>(window, "EraseConfirmBox").IsChecked == false
                    && (string)Field("_eraseStatusKey").GetValue(window)! == "eraseNotAnalyzed",
                    "Actual erase path event did not clear confirmation and analysis status before reporting the storage failure.");
                else Require((int)Field("_hintLoadVersion").GetValue(window)! == hintVersion,
                    "Actual extract path event started a hint load after failed storage validation.");
                pathItem.BeforePath = null; window.Close(); window.Dispose();
                Require(pathItem.Attempts == 1 && pathItem.Successes == 1 && retiredItem.Attempts == 2 && retiredItem.Successes == 1
                    && pending.Count == 0, "Actual two-owner path event did not retire live and failed owners exactly once on retry.");
            }

            MainWindow normal = Window();
            long normalRevision = (long)Field("_createDraftRevision").GetValue(normal)!;
            C<TextBox>(normal, "ArchivePathBox").Text = System.IO.Path.Combine(root, "normal-archive.kzpaq");
            Dispatcher.UIThread.RunJobs();
            Require((long)Field("_createDraftRevision").GetValue(normal)! == normalRevision + 1,
                "Normal actual archive TextChanged no longer increments its draft revision once.");
            C<TextBox>(normal, "OutputFolderBox").Text = System.IO.Path.Combine(root, "normal-output");
            int normalHintVersion = (int)Field("_hintLoadVersion").GetValue(normal)!;
            C<TextBox>(normal, "ExtractArchiveBox").Text = System.IO.Path.Combine(root, "normal-missing.kzpaq");
            Dispatcher.UIThread.RunJobs();
            Require((int)Field("_hintLoadVersion").GetValue(normal)! == normalHintVersion + 1,
                "Normal actual extract TextChanged no longer starts its hint update after successful storage validation.");
            Field("_eraseStatusKey").SetValue(normal, "eraseCompleted");
            C<CheckBox>(normal, "EraseConfirmBox").IsChecked = true;
            C<TextBox>(normal, "ErasePathBox").Text = System.IO.Path.Combine(root, "normal-erase.kzpaq");
            Dispatcher.UIThread.RunJobs();
            Require(C<CheckBox>(normal, "EraseConfirmBox").IsChecked == false
                && (string)Field("_eraseStatusKey").GetValue(normal)! == "eraseNotAnalyzed",
                "Normal actual erase TextChanged no longer clears its confirmation and analysis status.");
            normal.Close(); normal.Dispose();
        }
        finally
        {
            MainWindow.TestHookShowDialogAsync = null;
            foreach (ObservedStorageItem item in observed) { item.BeforePath = null; item.BeforeDispose = null; }
            foreach (MainWindow window in windows) { window.Close(); window.Dispose(); }
            foreach (ObservedStorageItem item in observed.Where(item => item.Successes == 0)) item.Dispose();
            Directory.Delete(root, recursive: true);
        }
    }


    private static void FileActivationOwnership(MainWindow providerWindow)
    {
        WaitForIntegrity(providerWindow);
        var app = Application.Current as App ?? throw new InvalidOperationException("The actual headless App is unavailable.");
        FieldInfo appWindow = typeof(App).GetField("_mainWindow", BindingFlags.Instance | BindingFlags.NonPublic)!;
        MainWindow? previousWindow = (MainWindow?)appWindow.GetValue(app);
        var pendingItems = (List<IStorageItem>)typeof(App).GetField("_pendingActivationItems", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(app)!;
        var pendingWindows = (List<MainWindow>)typeof(App).GetField("_activationStorageWindows", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(app)!;
        Require(pendingItems.Count == 0 && pendingWindows.Count == 0,
            "The activation fixture would overwrite an existing application cleanup owner.");
        string root = MacSafeFileSystem.ResolveExistingRealPath(Directory.CreateTempSubdirectory("kv-rev12-activation-").FullName);
        var observed = new List<ObservedStorageItem>();
        var windows = new List<MainWindow>();
        ObservedStorageItem FileItem(string name, Exception? failure = null)
        {
            string path = System.IO.Path.Combine(root, name);
            File.WriteAllText(path, "public activation fixture");
            var item = new ObservedStorageItem(providerWindow.StorageProvider.TryGetFileFromPathAsync(new Uri(path)).GetAwaiter().GetResult()
                ?? throw new InvalidOperationException("The public activation file was not resolved."), failure);
            observed.Add(item); return item;
        }
        ObservedStorageItem Folder(Exception? failure = null)
        { var item = Storage(providerWindow, root, failure); observed.Add(item); return item; }
        MainWindow Window()
        {
            var window = new MainWindow(new PublicSettings());
            windows.Add(window); appWindow.SetValue(app, window); return window;
        }
        void Activate(params IStorageItem[] items) => CallApp(app, "ActivateFirstArchive", (object)items);
        void Exit() => CallApp(app, "Desktop_Exit", null, null);
        try
        {
            // A missing archive is consumed and released by the real window.
            // The App must not Dispose it again when accepted is false.
            MainWindow missingWindow = Window();
            var missing = FileItem("missing.kzpaq");
            var laterA = FileItem("later-a.txt"); var laterB = Folder();
            File.Delete(PathOf(missing));
            Activate(missing.Item, laterA.Item, laterB.Item);
            Require(new[] { missing, laterA, laterB }.All(item => item.Attempts == 1 && item.Successes == 1)
                && Field("_extractArchiveAccess").GetValue(missingWindow) is null,
                "A consumed missing activation archive was disposed twice or prevented later independent cleanup.");
            missingWindow.Dispose(); app.RetryActivationStorageCleanup();

            // A repeated accepted reference and a different live field alias
            // must remain owned by the actual window throughout the batch.
            MainWindow duplicateWindow = Window();
            var duplicate = FileItem("duplicate.kzpaq"); var liveAlias = FileItem("live-alias.txt");
            Call(duplicateWindow, "RetainEraseArchiveAccess", liveAlias.Item);
            Activate(duplicate.Item, duplicate.Item, liveAlias.Item);
            Require(duplicate.Attempts == 0 && liveAlias.Attempts == 0
                && ((MacStorageAccessLease)Field("_extractArchiveAccess").GetValue(duplicateWindow)!).OwnsItem(duplicate.Item)
                && C<TextBox>(duplicateWindow, "ExtractArchiveBox").Text == PathOf(duplicate),
                "The real App disposed a repeated accepted reference or another live window alias.");
            app.RetryActivationStorageCleanup();
            Require(duplicate.Attempts == 0 && liveAlias.Attempts == 0,
                "Pending activation retry disposed live window fields.");
            duplicateWindow.Dispose(); app.RetryActivationStorageCleanup();
            Require(duplicate.Attempts == 1 && liveAlias.Attempts == 1,
                "Final window retirement did not release accepted activation aliases exactly once.");

            // A real lease cleanup failure cannot stop a later accepted file
            // and the final independent extra. The failed lease is terminal.
            MainWindow leaseFailureWindow = Window();
            var leaseFailure = new IOException("Injected missing activation lease cleanup failure.");
            var failedMissing = FileItem("failed-missing.kzpaq", leaseFailure);
            File.Delete(PathOf(failedMissing));
            var accepted = FileItem("accepted.kzpaq"); var extra = Folder();
            Exception actual = CaptureFailure(() => Activate(failedMissing.Item, accepted.Item, extra.Item));
            var failedOwners = (List<MacStorageAccessLease>)Field("_pendingStorageDisposals").GetValue(leaseFailureWindow)!;
            Require(Contains(actual, leaseFailure) && failedMissing.Attempts == 1 && failedMissing.Successes == 0
                && accepted.Attempts == 0 && extra.Attempts == 1 && extra.Successes == 1 && failedOwners.Count == 1
                && ((MacStorageAccessLease)Field("_extractArchiveAccess").GetValue(leaseFailureWindow)!).OwnsItem(accepted.Item),
                "An activation failure lost its terminal lease, skipped a later item or disposed the accepted file.");
            RequireThrows<ObjectDisposedException>(() => _ = failedOwners[0].Item,
                "A failed activation lease exposed its terminal item.");
            actual = CaptureFailure(() => Activate(failedMissing.Item));
            Require(HasException<ObjectDisposedException>(actual) && failedMissing.Attempts == 1,
                "The real App reacquired or implicitly retried a terminal activation item.");
            app.RetryActivationStorageCleanup(); app.RetryActivationStorageCleanup();
            Require(failedMissing.Attempts == 2 && failedMissing.Successes == 1 && accepted.Attempts == 0,
                "Explicit activation retry lost its failed lease or disposed a live accepted field.");
            leaseFailureWindow.Dispose(); app.RetryActivationStorageCleanup();

            // Lease retirement has the same reentry interval after the field
            // is detached but before failed cleanup could become pending.
            // A missing archive takes that real acquired-owner path.
            MainWindow leaseReentryWindow = Window();
            var leaseReentryItem = FileItem("reentry-missing.kzpaq");
            File.Delete(PathOf(leaseReentryItem));
            bool leaseReentered = false;
            Exception? directLeaseReentry = null, appLeaseReentry = null;
            object?[] leaseReentryAcquire = [leaseReentryItem.Item, null];
            leaseReentryItem.BeforeDispose = () =>
            {
                if (leaseReentered) return;
                leaseReentered = true;
                directLeaseReentry = CaptureFailure(() => Call(leaseReentryWindow, "TryAcquireStorageAccess", leaseReentryAcquire));
                appLeaseReentry = CaptureFailure(() => Activate(leaseReentryItem.Item));
            };
            Activate(leaseReentryItem.Item);
            Require(leaseReentered && directLeaseReentry is ObjectDisposedException
                && appLeaseReentry is not null && HasException<ObjectDisposedException>(appLeaseReentry)
                && leaseReentryAcquire[1] is null && leaseReentryItem.Attempts == 1 && leaseReentryItem.Successes == 1
                && StorageNames.All(name => Field(name).GetValue(leaseReentryWindow) is null)
                && !leaseReentryWindow.HasActivationStorageOwnership,
                "Actual acquired-lease retirement reentry reacquired or disposed its in-progress item or lost busy refusal.");
            leaseReentryWindow.Dispose(); app.RetryActivationStorageCleanup();

            // A refused file URL consumes raw cleanup, including its failure;
            // independent later items must still be released by the App.
            MainWindow refusalWindow = Window();
            var refusedFailure = new IOException("Injected refused activation raw cleanup failure.");
            var refused = FileItem("refused.kzpaq", refusedFailure);
            int reads = 0;
            refused.BeforePath = () => { if (++reads == 2) refused.PathOverride = new Uri("https://example.invalid/public-activation"); };
            var afterRefusalA = Folder(); var afterRefusalB = Folder();
            actual = CaptureFailure(() => Activate(refused.Item, afterRefusalA.Item, afterRefusalB.Item));
            Require(Contains(actual, refusedFailure) && HasException<NotSupportedException>(actual)
                && refused.Attempts == 1 && afterRefusalA.Successes == 1 && afterRefusalB.Successes == 1
                && ((List<IStorageItem>)Field("_pendingStorageItemDisposals").GetValue(refusalWindow)!).Count == 1,
                "Refused activation acquisition hid a cause, repeated raw cleanup or skipped later items.");
            app.RetryActivationStorageCleanup();
            Require(refused.Attempts == 2 && refused.Successes == 1,
                "Explicit activation retry did not retain the refused raw item owner.");
            refusalWindow.Dispose(); app.RetryActivationStorageCleanup();

            // Actual raw Dispose reenters the real App before a pending-owner
            // entry exists. Both direct window acquisition and App reactivation
            // must explicitly refuse that in-progress reference, not Dispose it
            // again or create a new native lease around its provider item.
            MainWindow reentryWindow = Window();
            var reentryItem = FileItem("reentry.txt");
            bool reentered = false;
            Exception? directReentry = null, appReentry = null;
            object?[] reentryAcquire = [reentryItem.Item, null];
            reentryItem.BeforeDispose = () =>
            {
                if (reentered) return;
                reentered = true;
                directReentry = CaptureFailure(() => Call(reentryWindow, "TryAcquireStorageAccess", reentryAcquire));
                appReentry = CaptureFailure(() => Activate(reentryItem.Item));
            };
            Activate(reentryItem.Item);
            Require(reentered && directReentry is ObjectDisposedException
                && appReentry is not null && HasException<ObjectDisposedException>(appReentry)
                && reentryAcquire[1] is null && reentryItem.Attempts == 1 && reentryItem.Successes == 1
                && StorageNames.All(name => Field(name).GetValue(reentryWindow) is null)
                && !reentryWindow.HasActivationStorageOwnership,
                "Actual raw disposal reentry repeated Dispose, acquired a busy reference or lost its terminal-busy refusal.");
            reentryWindow.Dispose(); app.RetryActivationStorageCleanup();

            // With no window, the App itself retains only failed raw owners.
            // A failed retry and actual Desktop_Exit must preserve that owner.
            appWindow.SetValue(app, null);
            var rawFailure = new IOException("Injected App-only activation cleanup failure.");
            var raw = Folder(); var rawLaterA = Folder(); var rawLaterB = Folder();
            bool rawMayDispose = false;
            raw.BeforeDispose = () => { if (!rawMayDispose) throw rawFailure; };
            actual = CaptureFailure(() => Activate(raw.Item, raw.Item, rawLaterA.Item, rawLaterB.Item));
            Require(Contains(actual, rawFailure) && raw.Attempts == 1 && rawLaterA.Successes == 1 && rawLaterB.Successes == 1
                && pendingItems.Count == 1 && ReferenceEquals(pendingItems[0], raw.Item),
                "App-only cleanup repeated a duplicate, skipped later items or lost its failed raw owner.");
            actual = CaptureFailure(() => Activate(raw.Item));
            Require(HasException<ObjectDisposedException>(actual) && raw.Attempts == 1,
                "App-only activation reused or implicitly retried a terminal raw item.");
            actual = CaptureFailure(app.RetryActivationStorageCleanup);
            Require(Contains(actual, rawFailure) && raw.Attempts == 2 && pendingItems.Count == 1,
                "A failed explicit App-only retry lost its owner or cause.");
            Exit();
            Require(raw.Attempts == 3 && pendingItems.Count == 1 && app.LastFileActivationFailure is { } exitFailure
                && Contains(exitFailure, rawFailure), "Desktop exit lost an App-only failed owner or its cleanup cause.");
            rawMayDispose = true;
            app.RetryActivationStorageCleanup(); app.RetryActivationStorageCleanup();
            Require(raw.Attempts == 4 && raw.Successes == 1 && pendingItems.Count == 0
                && rawLaterA.Attempts == 1 && rawLaterB.Attempts == 1,
                "Successful App-only retry repeated completed item disposal or lost pending state.");

            // A provider can close the window while Path is being read. Failed
            // incoming cleanup must remain reachable after App loses the window.
            MainWindow closingWindow = Window();
            var closedFailure = new IOException("Injected closed activation window cleanup failure.");
            var closing = FileItem("closing.kzpaq"); var closingExtra = Folder();
            bool closedMayDispose = false;
            closing.BeforePath = closingWindow.Dispose;
            closing.BeforeDispose = () => { if (!closedMayDispose) throw closedFailure; };
            actual = CaptureFailure(() => Activate(closing.Item, closingExtra.Item));
            Require(Contains(actual, closedFailure) && closing.Attempts == 1 && closingExtra.Successes == 1
                && StorageNames.All(name => Field(name).GetValue(closingWindow) is null) && pendingWindows.Contains(closingWindow),
                "Window-close activation took authority, skipped a later item or lost its raw retry owner.");
            Exit();
            Require(appWindow.GetValue(app) is null && closing.Attempts == 2 && pendingWindows.Contains(closingWindow)
                && app.LastFileActivationFailure is { } closeFailure && Contains(closeFailure, closedFailure),
                "App window loss abandoned a failed cleanup owner or replaced its cause.");
            closedMayDispose = true;
            app.RetryActivationStorageCleanup(); app.RetryActivationStorageCleanup();
            Require(closing.Attempts == 3 && closing.Successes == 1 && pendingWindows.Count == 0,
                "The detached window's explicit cleanup retry was lost or repeated after success.");

            // A closed window may still own an active operation's lease. Exit
            // and later duplicate activations must not prematurely release it.
            MainWindow activeWindow = Window();
            var active = FileItem("active.kzpaq");
            Call(activeWindow, "RetainExtractArchiveAccess", active.Item);
            Field("_integrityTrusted").SetValue(activeWindow, true);
            Require((bool)Call(activeWindow, "TryBeginProtectedOperation")!, "The activation active-owner fixture did not begin.");
            activeWindow.Dispose();
            Exit();
            Activate(active.Item, active.Item);
            Require(active.Attempts == 0 && pendingWindows.Contains(activeWindow),
                "App window loss disposed a lease still owned by an active operation.");
            Call(activeWindow, "EndProtectedOperation");
            app.RetryActivationStorageCleanup(); app.RetryActivationStorageCleanup();
            Require(active.Attempts == 1 && active.Successes == 1 && pendingWindows.Count == 0 && pendingItems.Count == 0,
                "Ending the detached active operation lost or repeated activation-owner disposal.");
        }
        finally
        {
            foreach (ObservedStorageItem item in observed) { item.BeforeDispose = null; item.BeforePath = null; }
            foreach (MainWindow window in windows)
            {
                window.Close(); window.Dispose();
                if ((int)Field("_operationActive").GetValue(window)! != 0) Call(window, "EndProtectedOperation");
                window.Dispose();
            }
            app.RetryActivationStorageCleanup();
            appWindow.SetValue(app, previousWindow);
            foreach (ObservedStorageItem item in observed.Where(item => item.Successes == 0)) item.Dispose();
            Directory.Delete(root, recursive: true);
        }
    }

    private static void StorageOwnership(MainWindow window)
    {
        string root = Directory.CreateTempSubdirectory("kv-rev12-window-dispose-").FullName;
        var ownItems = new List<ObservedStorageItem>();
        ObservedStorageItem? foreign = null;
        MainWindow? activeWindow = null;
        try
        {
            WaitForIntegrity(window);
            var failure = new IOException("Injected public storage-item cleanup failure.");
            var failed = Storage(window, root, failure);
            ownItems.Add(failed);
            MacStorageAccessLease failedLease = MacStorageAccessLease.Acquire(failed.Item);
            Field(StorageNames[0]).SetValue(window, failedLease);
            Field(StorageNames[1]).SetValue(window, failedLease); // one owned alias
            foreach (string name in StorageNames.Skip(2))
            {
                var item = Storage(window, root, null); ownItems.Add(item);
                MacStorageAccessLease lease = MacStorageAccessLease.Acquire(item.Item);
                if (name == "_extractArchiveAccess") item.BeforeDispose = lease.Dispose;
                Field(name).SetValue(window, lease);
            }
            var input = (Dictionary<string, MacStorageAccessLease>)Field("_inputStorageAccess").GetValue(window)!;
            for (int i = 0; i < 2; ++i)
            {
                var item = Storage(window, root, null); ownItems.Add(item);
                input.Add("public-owned-input-" + i, MacStorageAccessLease.Acquire(item.Item));
            }
            foreign = Storage(window, root, null);
            Exception actual = CaptureFailure(window.Dispose);
            Require(Contains(actual, failure), "Actual storage cleanup failure was not retained.");
            Require(ownItems.All(item => item.Attempts == 1)
                && ownItems.Skip(1).All(item => item.Successes == 1)
                && failed.Successes == 0 && foreign.Attempts == 0,
                "A storage cleanup fault skipped an owned lease, repeated an alias, or touched an unowned item.");
            Require(StorageNames.All(name => Field(name).GetValue(window) is null) && input.Count == 0,
                "A failed storage cleanup left a disposed lease available to operations.");
            Require(((List<MacStorageAccessLease>)Field("_pendingStorageDisposals").GetValue(window)!).Count == 1,
                "Failed storage-owner retry state lost an owner or retained a successful one.");
            RequireThrows<ObjectDisposedException>(() => _ = failedLease.Item,
                "A failed lease cleanup allowed access to its terminal storage item.");
            window.Dispose();
            window.Dispose();
            failedLease.Dispose();
            Require(failed.Attempts == 2 && failed.Successes == 1
                && ownItems.Skip(1).All(item => item.Attempts == 1)
                && ((List<MacStorageAccessLease>)Field("_pendingStorageDisposals").GetValue(window)!).Count == 0
                && foreign.Attempts == 0,
                "Explicit retry lost the failed item or repeated a completed storage cleanup.");

            activeWindow = new MainWindow(new PublicSettings());
            var activeItem = Storage(window, root, null); ownItems.Add(activeItem);
            Field("_archiveDestinationAccess").SetValue(activeWindow, MacStorageAccessLease.Acquire(activeItem.Item));
            Field("_integrityTrusted").SetValue(activeWindow, true);
            Require((bool)Call(activeWindow, "TryBeginProtectedOperation")!, "The active-ownership fixture did not begin.");
            activeWindow.Dispose();
            Require(activeItem.Attempts == 0, "Window disposal released a storage lease still owned by an active operation.");
            Call(activeWindow, "EndProtectedOperation");
            activeWindow.Dispose();
            Require(activeItem.Attempts == 1 && activeItem.Successes == 1,
                "The ending active operation failed to release its retained lease exactly once.");
        }
        finally
        {
            activeWindow?.Dispose();
            foreach (ObservedStorageItem item in ownItems.Where(item => item.Successes == 0)) item.Dispose();
            foreign?.Dispose();
            Directory.Delete(root, recursive: true);
        }
    }

    private sealed class ObservedStorageItem
    {
        private readonly IStorageItem _inner;
        private readonly Exception? _failure;
        internal IStorageItem Item { get; }
        internal int Attempts { get; private set; }
        internal int Successes { get; private set; }
        internal Action? BeforeDispose { get; set; }
        internal Action? BeforePath { get; set; }
        internal Uri? PathOverride { get; set; }
        internal ObservedStorageItem(IStorageItem inner, Exception? failure)
        {
            _inner = inner; _failure = failure;
            // Avalonia's reference assembly intentionally prevents a C# client
            // implementation of IStorageItem. This test-only runtime proxy
            // delegates storage behavior to the actual provider item. Only
            // public Dispose/Path fault callbacks are configured by these
            // fixtures; production has no injection seam.
            Item = inner switch
            {
                IStorageFolder => DispatchProxy.Create<IStorageFolder, Rev12PublicStorageItemProxy>(),
                IStorageFile => DispatchProxy.Create<IStorageFile, Rev12PublicStorageItemProxy>(),
                _ => DispatchProxy.Create<IStorageItem, Rev12PublicStorageItemProxy>(),
            };
            ((Rev12PublicStorageItemProxy)Item).PublicFixtureInvocation = (method, args) =>
            {
                if (method.Name == nameof(IDisposable.Dispose)) { Dispose(); return null; }
                if (method.Name == "get_Path")
                {
                    BeforePath?.Invoke();
                    if (PathOverride is not null) return PathOverride;
                }
                return method.Invoke(_inner, args);
            };
        }
        public void Dispose()
        {
            ++Attempts;
            if (_failure is not null && Attempts == 1) throw _failure;
            BeforeDispose?.Invoke();
            _inner.Dispose();
            ++Successes;
        }
    }
    private sealed class DeferredPublicText : IAsyncDataTransfer, IAsyncDataTransferItem
    {
        private readonly TaskCompletionSource<object?> _completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public bool Requested { get; private set; }
        public IReadOnlyList<DataFormat> Formats => [DataFormat.Text];
        public IReadOnlyList<IAsyncDataTransferItem> Items => [this];
        public Task<object?> TryGetRawAsync(DataFormat format)
        {
            if (format != DataFormat.Text) return Task.FromResult<object?>(null);
            Requested = true;
            return _completion.Task;
        }
        internal void Complete(string text) => _completion.TrySetResult(text);
        public void Dispose() => _completion.TrySetResult(null);
    }
    private sealed class PublicSettings : IAppSettingsStore
    {
        private readonly Dictionary<string, string> _values = [];
        public string? Read(string key) => _values.GetValueOrDefault(key);
        public void Write(string key, string value) => _values[key] = value;
    }
    private static ObservedStorageItem Storage(MainWindow window, string root, Exception? failure) => new(
        window.StorageProvider.TryGetFolderFromPathAsync(new Uri(root + System.IO.Path.DirectorySeparatorChar)).GetAwaiter().GetResult()
            ?? throw new InvalidOperationException("The public storage fixture was not resolved."), failure);
    private static GeneratedArchiveEntropy PublicEntropy()
    {
        LockedSensitiveBuffer salt = LockedSensitiveBuffer.Create(EntropyMixer.SaltPairBytes);
        LockedSensitiveBuffer nonce = LockedSensitiveBuffer.Create(EncryptionSuiteCatalog.ArchiveNonceBytes);
        try { return new GeneratedArchiveEntropy(FactorInputRev12Tests.FactorA, FactorInputRev12Tests.FactorB, salt, nonce, null, null); }
        catch { SecureMemory.ZeroAndDisposeAll(nonce, salt); throw; }
    }
    private static T C<T>(MainWindow window, string name) where T : Control => window.FindControl<T>(name) ?? throw new InvalidOperationException(name);
    private static FieldInfo Field(string name) => typeof(MainWindow).GetField(name, BindingFlags.Instance | BindingFlags.NonPublic) ?? throw new InvalidOperationException(name);
    private static object? Call(MainWindow window, string name, params object?[] args)
    {
        try { return typeof(MainWindow).GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(window, args); }
        catch (TargetInvocationException error) when (error.InnerException is { } inner)
        { ExceptionDispatchInfo.Capture(inner).Throw(); throw; }
    }
    private static void CallApp(App app, string name, params object?[] args)
    {
        try { typeof(App).GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(app, args); }
        catch (TargetInvocationException error) when (error.InnerException is { } inner)
        { ExceptionDispatchInfo.Capture(inner).Throw(); throw; }
    }
    private static Task ApplyFolderSelection(MainWindow window, IStorageFolder[] items,
        Func<IStorageFolder, bool> retain, Action<string> render) =>
        (Task)typeof(MainWindow).GetMethod("ApplyStoragePickerSelectionAsync", BindingFlags.Instance | BindingFlags.NonPublic)!
            .MakeGenericMethod(typeof(IStorageFolder)).Invoke(window, [items, retain, render, null, null])!;
    private static string PathOf(ObservedStorageItem item) => System.IO.Path.GetFullPath(item.Item.Path.LocalPath).Normalize(System.Text.NormalizationForm.FormC);
    private static bool HasException<T>(Exception actual) where T : Exception => actual is T
        || actual is AggregateException aggregate && aggregate.InnerExceptions.Any(HasException<T>)
        || actual.InnerException is { } inner && HasException<T>(inner);
    private static ulong ResetVersion() => (ulong)typeof(EntropyMixer).GetField("_resetVersion", BindingFlags.Static | BindingFlags.NonPublic)!.GetValue(null)!;
    private static bool Contains(Exception actual, Exception expected) => ReferenceEquals(actual, expected)
        || actual is AggregateException aggregate && aggregate.InnerExceptions.Any(error => Contains(error, expected))
        || actual.InnerException is { } inner && Contains(inner, expected);
    private static bool IsDisposed(CancellationTokenSource source) { try { _ = source.Token; return false; } catch (ObjectDisposedException) { return true; } }
    private static Exception CaptureFailure(Action operation) { try { operation(); } catch (Exception error) { return error; } throw new InvalidOperationException("An injected teardown failure was reported as success."); }
    private static void RequireThrows<T>(Action operation, string message) where T : Exception { try { operation(); } catch (T) { return; } throw new InvalidOperationException(message); }
    private static void Require(bool condition, string message) => MacComprehensiveTests.Require(condition, message);
    private static void Complete(Task task) { PumpUntil(() => task.IsCompleted); task.GetAwaiter().GetResult(); }
    private static void PumpUntil(Func<bool> condition)
    {
        var clock = Stopwatch.StartNew();
        while (!condition())
        {
            if (clock.Elapsed > TimeSpan.FromSeconds(15)) throw new TimeoutException("The public GUI teardown fixture did not complete.");
            Dispatcher.UIThread.RunJobs(); Thread.Sleep(1);
        }
        Dispatcher.UIThread.RunJobs();
    }
    private static void WaitForIntegrity(MainWindow window) => PumpUntil(() => (string?)Field("_integrityStatusKey").GetValue(window) != "integrityChecking");
}

// Only the managed headless test harness creates this runtime proxy. No native
// AOT product code or installed StorageProvider is replaced.
public class Rev12PublicStorageItemProxy : DispatchProxy
{
    internal Func<MethodInfo, object?[]?, object?>? PublicFixtureInvocation { get; set; }
    protected override object? Invoke(MethodInfo? targetMethod, object?[]? args) =>
        PublicFixtureInvocation!(targetMethod ?? throw new InvalidOperationException("Missing public storage fixture method."), args);
}
