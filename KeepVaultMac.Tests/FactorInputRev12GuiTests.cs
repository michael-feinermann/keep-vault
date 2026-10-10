using System.Diagnostics;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Presenters;
using Avalonia.Headless;
using Avalonia.Input;
using Avalonia.Input.Platform;
using Avalonia.Input.TextInput;
using Avalonia.Media;
using Avalonia.Threading;
using Avalonia.VisualTree;
using KalynaArchiver;
using KalynaArchiver.Services;
using KeepVaultMac.Controls;

// Headless regression evidence supplements, and never replaces, real macOS paste/IME/AX testing.
internal static class FactorInputRev12GuiTests
{
    internal static IReadOnlyList<TestCase> Tests =>
    [
        new("gui.factor-rev12-clear-pending-paste", "V13-FACTOR-CLEAR-TRANSFER: actual deferred clipboard paste cannot repopulate an explicitly cleared empty field", () => MacGuiTests.RunOnUiThread(ClearPendingPaste), TestResource.Gui, "GUI"),
        new("gui.factor-rev12-clear-undo", "V13-FACTOR-CLEAR-HISTORY: the actual clear-secrets action cannot resurrect accepted factors through undo or redo", () => MacGuiTests.RunOnUiThread(ClearUndo), TestResource.Gui, "GUI"),
        new("gui.factor-rev12-paste", "V13-FACTOR-PASTE: actual clipboard event with 256/383/511-character factors in both fields", () => MacGuiTests.RunOnUiThread(Paste), TestResource.Gui, "GUI"),
        new("gui.factor-rev12-atomic-nowrap", "V13-FACTOR-PRESENTATION-DIAGNOSIS: the same raw boundaries and drop with no soft wrapping for a controlled public comparison", () => MacGuiTests.RunOnUiThread(w => Atomic(w, diagnosticNoWrap: true)), TestResource.Gui, "GUI"),
        new("gui.factor-rev12-atomic", "V13-FACTOR-BOUNDARIES/INVALID: atomic set-text, insertion and drop rejection preserves text and selection", () => MacGuiTests.RunOnUiThread(Atomic), TestResource.Gui, "GUI"),
        new("gui.factor-rev12-layout-spaces-nowrap", "V13-FACTOR-MAXRAW-DIAGNOSIS: the same complete public raw input with no soft wrapping", () => MacGuiTests.RunOnUiThread(w => MaximumSpacesLayout(w, diagnosticNoWrap: true)), TestResource.Gui, "GUI"),
        new("gui.factor-rev12-layout-spaces", "V13-FACTOR-MAXRAW-LAYOUT: actual text input commits and lays out all 65,536 public raw characters", () => MacGuiTests.RunOnUiThread(MaximumSpacesLayout), TestResource.Gui, "GUI"),
        new("gui.factor-rev12-edit-undo", "V13-FACTOR-EDIT-UNDO: actual text-input/selection editing and native undo/redo without rejected history", () => MacGuiTests.RunOnUiThread(EditUndo), TestResource.Gui, "GUI"),
    ];

    private static FactorTextBox[] Fields(MainWindow window) =>
    [
        window.FindControl<FactorTextBox>("ExtractGeneratedPasswordFirstBox") ?? throw new InvalidOperationException("Factor A does not use the bounded import adapter."),
        window.FindControl<FactorTextBox>("ExtractGeneratedPasswordSecondBox") ?? throw new InvalidOperationException("Factor B does not use the bounded import adapter."),
    ];

    private static void Paste(MainWindow window)
    {
        window.FindControl<TabControl>("MainTabs")!.SelectedIndex = 1;
        Dispatcher.UIThread.RunJobs();
        var clipboard = TopLevel.GetTopLevel(window)?.Clipboard ?? throw new InvalidOperationException("The GUI clipboard adapter is unavailable.");
        string hex = FactorInputRev12Tests.FactorA;
        string bytePairs = string.Join(" ", Enumerable.Range(0, 128).Select(i => hex.Substring(i * 2, 2)));
        string individual = string.Join(" ", hex.Select(c => c.ToString()));
        Require(bytePairs.Length == 383 && individual.Length == 511, "The pasted fixture lengths changed.");
        try
        {
            foreach (FactorTextBox field in Fields(window))
            foreach (string formatted in new[] { hex, bytePairs, individual, FactorInputRev12Tests.Format(hex) })
            {
                Require(field.MaxLength == 0, "A truncating framework MaxLength still applies to factor input.");
                field.TrySetText(string.Empty);
                field.Focus();
                Complete(clipboard.SetTextAsync(formatted));
                field.Paste();
                PumpUntil(() => field.Text == formatted);
                Require(FactorInput.Canonicalize(field.Text!) == hex && field.HexCharacterCount == 256, "Clipboard paste changed the complete factor payload.");
                RequireFormatStatus(window, field, complete: true);
                Require(field.CaretIndex == formatted.Length && field.SelectionStart == field.SelectionEnd, "Accepted paste left a stale selection or caret.");
            }

            FactorTextBox[] fields = Fields(window);
            foreach (string language in new[] { "de", "en" })
            foreach ((FactorTextBox field, string accepted) in new[]
            {
                (fields[0], FactorInputRev12Tests.FactorA),
                (fields[1], FactorInputRev12Tests.FactorB),
            })
            {
                field.LanguageCode = language;
                Require(field.TrySetText(accepted), "The complete public factor fixture was rejected.");
                field.Focus(); field.SelectAll();
                Complete(clipboard.SetTextAsync(accepted + "\u200B"));
                field.Paste();
                PumpUntil(() => field.ValidationMessage == FactorInput.Message(FactorInput.Error.ForbiddenCharacter, language));
                Require(field.Text == accepted && field.HexCharacterCount == 256,
                    "Rejected transfer changed the existing complete factor.");
                RequireFormatStatus(window, field, complete: false);

                field.SelectAll();
                Complete(clipboard.SetTextAsync(accepted));
                field.Paste();
                PumpUntil(() => field.IsFormatComplete);
                Require(field.Text == accepted && field.HexCharacterCount == 256,
                    "An identical accepted transfer changed the factor payload.");
                RequireFormatStatus(window, field, complete: true);
            }
            FactorTextBox first = fields[0], second = fields[1];
            first.TrySetText(hex[..255]);
            second.TrySetText(FactorInputRev12Tests.Format(FactorInputRev12Tests.FactorB));
            RequireFormatStatus(window, first, complete: false);
            RequireFormatStatus(window, second, complete: true);
            first.TrySetText(hex);
            RequireFormatStatus(window, first, complete: true);

            first.Focus(); first.SelectAll();
            Complete(clipboard.SetTextAsync(hex + "\u200B"));
            first.Paste();
            PumpUntil(() => first.ValidationMessage == FactorInput.Message(FactorInput.Error.ForbiddenCharacter, first.LanguageCode));
            Require(first.Text == hex && first.HexCharacterCount == 256, "Rejected clipboard input changed the previously complete factor.");
            RequireFormatStatus(window, first, complete: false);
            RequireFormatStatus(window, second, complete: true);

            Require(first.TrySetText(" " + hex), "Valid formatted input did not reset the rejected-paste error.");
            RequireFormatStatus(window, first, complete: true);
            second.TrySetText(FactorInputRev12Tests.FactorB[..255]);
            RequireFormatStatus(window, second, complete: false);
            RequireFormatStatus(window, first, complete: true);

            var pending = new DeferredPublicClipboardTransfer();
            Complete(clipboard.SetDataAsync(pending));
            first.Focus(); first.SelectAll(); first.Paste();
            PumpUntil(() => pending.Requested);
            first.TrySetText(hex);
            pending.Complete(FactorInputRev12Tests.FactorB);
            PumpUntil(() => first.ValidationMessage == FactorInput.Message(FactorInput.Error.StaleTransfer, first.LanguageCode));
            Require(first.Text == hex && first.HexCharacterCount == 256, "A stale clipboard transfer changed the newer complete factor.");
            RequireFormatStatus(window, first, complete: false);
            first.TrySetText(" " + hex);
            RequireFormatStatus(window, first, complete: true);

            var failed = new DeferredPublicClipboardTransfer();
            Complete(clipboard.SetDataAsync(failed));
            first.SelectAll(); first.Paste();
            PumpUntil(() => failed.Requested);
            failed.Fail();
            PumpUntil(() => first.ValidationMessage == FactorInput.Message(FactorInput.Error.TransferFailed, first.LanguageCode));
            Require(first.Text == " " + hex && first.HexCharacterCount == 256, "A failed clipboard transfer changed the complete factor.");
            RequireFormatStatus(window, first, complete: false);
            first.TrySetText(hex);
            RequireFormatStatus(window, first, complete: true);
        }
        finally { Complete(clipboard.SetTextAsync(string.Empty)); }
    }

    private static void Atomic(MainWindow window) => Atomic(window, diagnosticNoWrap: false);

    private static void Atomic(MainWindow window, bool diagnosticNoWrap)
    {
        window.FindControl<TabControl>("MainTabs")!.SelectedIndex = 1;
        Dispatcher.UIThread.RunJobs();
        string raw = FactorInputRev12Tests.FactorA;
        int fieldIndex = 0;
        foreach (FactorTextBox field in Fields(window))
        {
            if (diagnosticNoWrap) field.TextWrapping = Avalonia.Media.TextWrapping.NoWrap;
            Console.WriteLine($"FACTOR_GUI_ATOMIC_STEP field={fieldIndex} start wrapping={field.TextWrapping}");
            field.LanguageCode = "en";
            field.TrySetText(raw);
            field.CaretIndex = 7; field.SelectionStart = 3; field.SelectionEnd = 7;
            string oversized = raw + new string(' ', 65_537 - raw.Length);
            foreach (string invalid in new[] { oversized, raw + "A", raw + "\u200B", raw + "\uFEFF", raw + "\0", raw + "\uD800", raw + "\u007F" })
            {
                Require(!field.TrySetText(invalid) && field.Text == raw, "SetText silently shortened or partially accepted rejected input.");
                Require(field.CaretIndex == 7 && field.SelectionStart == 3 && field.SelectionEnd == 7, "Rejected SetText changed the existing selection.");
                field.Text = invalid; // Public Text/binding assignments share the raw coercion guard.
                Dispatcher.UIThread.RunJobs();
                Require(field.Text == raw && !string.IsNullOrEmpty(field.ValidationMessage), "Direct text assignment bypassed the import guard.");
                RequireFormatStatus(window, field, complete: false);
                TextPresenter? presenter = field.GetVisualDescendants().OfType<TextPresenter>().FirstOrDefault();
                Require(presenter is null || presenter.Text == raw, "The visual text presenter diverged from retained factor text.");
            }
            Console.WriteLine($"FACTOR_GUI_ATOMIC_STEP field={fieldIndex} rejected-sets-complete");
            // Direct public insertion must see DEL before any framework sanitizer.
            field.TrySetText("12"); field.SelectAll(); field.SelectedText = "A\u007FB";
            Require(field.Text == "12" && field.SelectionStart == 0 && field.SelectionEnd == 2,
                "The public insertion API sanitized a forbidden raw character into a valid factor.");
            field.Text = "A\u200B"; field.CaretIndex = 1; field.SelectionStart = 1; field.SelectionEnd = 1;
            Dispatcher.UIThread.RunJobs();
            Require(field.CaretIndex == 1 && field.SelectionStart == 1 && field.SelectionEnd == 1,
                "An obsolete visual restore overwrote a newer cursor or selection.");
            field.TrySetText(raw); field.SelectAll();
            Require(!field.TryReplaceSelection(oversized) && field.Text == raw, "Rejected replacement lost the existing factor.");
            Require(field.SelectionStart == 0 && field.SelectionEnd == raw.Length, "Rejected replacement collapsed the selection.");
            using (var data = new DataTransfer())
            {
                data.Add(DataTransferItem.CreateText(oversized));
                var drop = new DragEventArgs(DragDrop.DropEvent, data, field, new Point(1, 1), KeyModifiers.None);
                field.RaiseEvent(drop);
                Require(drop.Handled && drop.DragEffects == DragDropEffects.None && field.Text == raw, "Oversized drop was partly accepted.");
            }
            string atLimit = new string(' ', 65_536 - raw.Length) + raw;
            Console.WriteLine($"FACTOR_GUI_ATOMIC_STEP field={fieldIndex} before-65536-set");
            Require(field.TrySetText(atLimit) && field.Text == atLimit, "The maximum permitted raw factor text was shortened.");
            Console.WriteLine($"FACTOR_GUI_ATOMIC_STEP field={fieldIndex} after-65536-set");
            field.SelectAll();
            Console.WriteLine($"FACTOR_GUI_ATOMIC_STEP field={fieldIndex} after-65536-select-all");
            var tracedEditor = field.GetVisualDescendants().OfType<TextBox>().Single();
            var tracedPresenter = field.GetVisualDescendants().OfType<TextPresenter>().Single();
            int propertyMarkers = 0;
            void TraceEditor(object? sender, AvaloniaPropertyChangedEventArgs change)
            {
                if (propertyMarkers++ >= 128) return;
                if (change.Property == TextBox.TextProperty || change.Property == TextBox.CaretIndexProperty
                    || change.Property == TextBox.SelectionStartProperty || change.Property == TextBox.SelectionEndProperty)
                    Console.WriteLine($"FACTOR_GUI_PROPERTY field={fieldIndex} editor property={change.Property.Name} length={tracedEditor.Text?.Length ?? 0} caret={tracedEditor.CaretIndex} selection={tracedEditor.SelectionStart}:{tracedEditor.SelectionEnd}");
            }
            void TracePresenter(object? sender, AvaloniaPropertyChangedEventArgs change)
            {
                if (propertyMarkers++ >= 128) return;
                if (change.Property == TextPresenter.TextProperty || change.Property == TextPresenter.CaretIndexProperty
                    || change.Property == TextPresenter.SelectionStartProperty || change.Property == TextPresenter.SelectionEndProperty)
                    Console.WriteLine($"FACTOR_GUI_PROPERTY field={fieldIndex} presenter property={change.Property.Name} length={tracedPresenter.Text?.Length ?? 0} caret={tracedPresenter.CaretIndex} selection={tracedPresenter.SelectionStart}:{tracedPresenter.SelectionEnd}");
            }
            void TraceChanging(object? sender, TextChangingEventArgs change)
            {
                if (propertyMarkers++ < 128)
                    Console.WriteLine($"FACTOR_GUI_PROPERTY field={fieldIndex} editor text-changing length={tracedEditor.Text?.Length ?? 0}");
            }
            tracedEditor.PropertyChanged += TraceEditor;
            tracedEditor.TextChanging += TraceChanging;
            tracedPresenter.PropertyChanged += TracePresenter;
            try
            {
                using var data = new DataTransfer();
                string formatted = FactorInputRev12Tests.Format(raw, "\r\n\u00A0");
                data.Add(DataTransferItem.CreateText(formatted));
                var drop = new DragEventArgs(DragDrop.DropEvent, data, field, new Point(1, 1), KeyModifiers.None);
                field.RaiseEvent(drop);
                Require(drop.Handled && drop.DragEffects == DragDropEffects.Copy && field.Text == formatted, "Valid formatted drop was not imported atomically.");
            }
            finally
            {
                tracedEditor.PropertyChanged -= TraceEditor;
                tracedEditor.TextChanging -= TraceChanging;
                tracedPresenter.PropertyChanged -= TracePresenter;
            }
            Console.WriteLine($"FACTOR_GUI_ATOMIC_STEP field={fieldIndex} after-formatted-drop");
            // The raw bound also permits many hard line breaks. Exercise the
            // actual presenter layout separately from parsing and selection.
            string maximumLineBreaks = new string('\n', 65_536 - raw.Length) + raw;
            Console.WriteLine($"FACTOR_GUI_ATOMIC_STEP field={fieldIndex} before-65536-newlines-set");
            Require(field.TrySetText(maximumLineBreaks) && field.Text == maximumLineBreaks,
                "The maximum raw input containing hard line breaks was shortened.");
            Console.WriteLine($"FACTOR_GUI_ATOMIC_STEP field={fieldIndex} after-65536-newlines-set");
            var nativeEditor = field.GetVisualDescendants().OfType<TextBox>().Single();
            Console.WriteLine($"FACTOR_GUI_ATOMIC_STEP field={fieldIndex} before-newlines-layout");
            Require(nativeEditor.GetLineCount() >= 65_536 - raw.Length + 1,
                "The complete hard-line-break presentation lost raw lines.");
            Console.WriteLine($"FACTOR_GUI_ATOMIC_STEP field={fieldIndex} after-newlines-layout");
            field.SelectAll();
            Require(field.TryReplaceSelection(raw) && field.Text == raw,
                "The maximum input with line breaks could not be replaced atomically.");
            Console.WriteLine($"FACTOR_GUI_ATOMIC_STEP field={fieldIndex} after-newlines-replacement");
            string retained = field.Text!;
            field.LanguageCode = "de";
            Require(field.Text == retained && field.ValidationMessage.Contains("Hexadezimalzeichen", StringComparison.Ordinal), "Language change lost factor input or failed to translate its status.");
            Console.WriteLine($"FACTOR_GUI_ATOMIC_STEP field={fieldIndex++} complete");
        }
    }

    private static void MaximumSpacesLayout(MainWindow window) => MaximumSpacesLayout(window, diagnosticNoWrap: false);

    private static void MaximumSpacesLayout(MainWindow window, bool diagnosticNoWrap)
    {
        window.FindControl<TabControl>("MainTabs")!.SelectedIndex = 1;
        Dispatcher.UIThread.RunJobs();
        string raw = FactorInputRev12Tests.FactorA;
        string maximum = new string(' ', FactorInput.MaxRawCodeUnits - raw.Length) + raw;
        int index = 0;
        foreach (FactorTextBox field in Fields(window))
        {
            if (diagnosticNoWrap) field.TextWrapping = Avalonia.Media.TextWrapping.NoWrap;
            field.TrySetText(string.Empty); field.Focus();
            Console.WriteLine($"FACTOR_GUI_LAYOUT_STEP field={index} before-maximum-commit wrapping={field.TextWrapping}");
            var stopwatch = Stopwatch.StartNew();
            window.KeyTextInput(maximum);
            Console.WriteLine($"FACTOR_GUI_LAYOUT_STEP field={index} after-maximum-commit");
            Require(field.Text == maximum && field.CaretIndex == maximum.Length,
                "The maximum raw text input was shortened or its caret was lost.");
            var editor = field.GetVisualDescendants().OfType<TextBox>().Single();
            Require(editor.GetLineCount() > 0 && FactorInput.Canonicalize(field.Text!) == raw,
                "The complete maximum factor input was not presented correctly.");
            Require(editor.TextWrapping == Avalonia.Media.TextWrapping.NoWrap
                && ScrollViewer.GetHorizontalScrollBarVisibility(editor) == Avalonia.Controls.Primitives.ScrollBarVisibility.Auto,
                "The complete raw factor lacks native horizontal scrolling without soft wrapping.");
            Require(editor.MaxLines == 6 && editor.MaxLength == 0,
                "The bounded visible factor viewport changed the untruncated raw-input contract.");
            Console.WriteLine($"FACTOR_GUI_LAYOUT_STEP field={index++} after-layout seconds={stopwatch.Elapsed.TotalSeconds:F3}");
            Require(stopwatch.Elapsed < TimeSpan.FromSeconds(10),
                "The bounded maximum factor input still causes pathological text layout work.");
            field.SelectAll();
            Require(field.TryReplaceSelection(raw) && field.Text == raw,
                "The maximum displayed factor input could not be replaced atomically.");
        }
    }

    private static void EditUndo(MainWindow window)
    {
        window.FindControl<TabControl>("MainTabs")!.SelectedIndex = 1;
        Dispatcher.UIThread.RunJobs();
        foreach (FactorTextBox field in Fields(window))
        {
            field.TrySetText(string.Empty); field.Focus();
            window.KeyTextInput("0a"); window.KeyTextInput("BC");
            Dispatcher.UIThread.RunJobs();
            Require(field.Text == "0aBC" && field.HexCharacterCount == 4, "Ordinary incomplete typing was rejected or rewritten.");
            field.CaretIndex = 3; field.SelectionStart = 1; field.SelectionEnd = 3;
            window.KeyTextInput("\u200B");
            Dispatcher.UIThread.RunJobs();
            Require(field.Text == "0aBC" && field.SelectionStart == 1 && field.SelectionEnd == 3, "Invalid text input partly replaced a selection.");
            window.KeyTextInput("F");
            Dispatcher.UIThread.RunJobs();
            Require(field.Text == "0FC" && field.CaretIndex == 2, "Valid selection replacement broke cursor placement.");
            field.Undo(); Dispatcher.UIThread.RunJobs();
            Require(field.Text != "0FC" && FactorInput.Validate((field.Text ?? string.Empty).AsSpan(), false, out _) == FactorInput.Error.None, "Undo restored rejected input or failed to restore accepted input.");
            field.Redo(); Dispatcher.UIThread.RunJobs();
            Require(field.Text == "0FC", "Redo failed to restore the accepted replacement.");
            string retained = field.Text!;
            field.CaretIndex = 2; field.SelectionStart = 0; field.SelectionEnd = 2;
            var editor = field.GetVisualDescendants().OfType<TextBox>().Single();
            var request = new TextInputMethodClientRequestedEventArgs { RoutedEvent = InputElement.TextInputMethodClientRequestedEvent };
            editor.RaiseEvent(request);
            TextInputMethodClient client = request.Client ?? throw new InvalidOperationException("The factor IME client is unavailable.");
            Require(!client.SupportsPreedit, "The factor editor still allows unvalidated preedit to delete accepted selections.");
            client.SetPreeditText("\uFF21", 1);
            Require(field.Text == retained && field.SelectionStart == 0 && field.SelectionEnd == 2,
                "Preedit changed accepted factor text before complete commit validation.");
            client.SetPreeditText(null, null);
            Require(field.Text == retained && field.SelectionStart == 0 && field.SelectionEnd == 2,
                "Canceled preedit lost selected factor characters.");
            client.SetPreeditText("F", 1); window.KeyTextInput("F"); client.SetPreeditText(null, null);
            Require(field.Text == "FC" && field.CaretIndex == 1, "A valid IME commit did not replace the retained selection once.");
            retained = field.Text!;
            field.SelectedText = "Factor A:";
            Dispatcher.UIThread.RunJobs();
            Require(field.Text == retained, "The explicit insertion adapter accepted a field label.");
            // TextInput is also the committed-text path used by IME. The native
            // preedit lifecycle must additionally be exercised on the real GUI.
            window.KeyTextInput("\uFF21"); Dispatcher.UIThread.RunJobs();
            Require(field.Text == retained, "Committed full-width IME text was normalized into ASCII hex.");

            string completeFactor = ReferenceEquals(field, Fields(window)[0])
                ? FactorInputRev12Tests.FactorA : FactorInputRev12Tests.FactorB;
            Require(field.TrySetText(completeFactor), "The complete public factor fixture was rejected.");
            field.Focus(); field.SelectAll();
            window.KeyTextInput(completeFactor + "\u200B");
            Dispatcher.UIThread.RunJobs();
            Require(field.Text == completeFactor && field.HexCharacterCount == 256,
                "Rejected committed input changed the existing complete factor.");
            RequireFormatStatus(window, field, complete: false);

            editor.RaiseEvent(new TextInputEventArgs
            {
                RoutedEvent = InputElement.TextInputEvent, Text = completeFactor, Handled = true,
            });
            Require(field.Text == completeFactor, "Already handled input changed the factor.");
            RequireFormatStatus(window, field, complete: false);
            field.IsReadOnly = true;
            try
            {
                window.KeyTextInput(completeFactor);
                Require(field.Text == completeFactor, "Read-only committed input changed the factor.");
                RequireFormatStatus(window, field, complete: false);
            }
            finally { field.IsReadOnly = false; }

            field.Focus(); field.SelectAll();
            window.KeyTextInput(completeFactor);
            Dispatcher.UIThread.RunJobs();
            Require(field.Text == completeFactor && field.HexCharacterCount == 256,
                "An identical accepted committed input changed the factor payload.");
            RequireFormatStatus(window, field, complete: true);
        }
    }

    private static void ClearUndo(MainWindow window)
    {
        window.FindControl<TabControl>("MainTabs")!.SelectedIndex = 1;
        Dispatcher.UIThread.RunJobs();
        var clear = window.FindControl<Button>("ClearExtractSecretsButton")
            ?? throw new InvalidOperationException("The actual extraction secret-clear action is missing.");
        foreach (bool alreadyEmpty in new[] { false, true })
        {
            foreach (FactorTextBox field in Fields(window))
            {
                field.TrySetText(string.Empty); field.Focus();
                window.KeyTextInput(FactorInputRev12Tests.FactorA);
                Require(field.Text == FactorInputRev12Tests.FactorA, "The public clear-history fixture was not entered.");
                if (alreadyEmpty)
                {
                    field.SelectAll(); field.SelectedText = string.Empty;
                    Require(string.IsNullOrEmpty(field.Text), "The accepted selection edit did not empty the factor field.");
                }
            }
            TextBox[] nativeCredentials =
            [
                window.FindControl<TextBox>("ExtractPasswordBox")!, window.FindControl<TextBox>("ExtractPinBox")!
            ];
            foreach (TextBox native in nativeCredentials)
            {
                native.Text = string.Empty; native.Focus();
                window.KeyTextInput("123456");
                if (alreadyEmpty) { native.SelectAll(); native.SelectedText = string.Empty; }
            }
            clear.RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
            Dispatcher.UIThread.RunJobs();
            foreach (TextBox native in nativeCredentials)
            {
                native.Undo(); Dispatcher.UIThread.RunJobs();
                Require(string.IsNullOrEmpty(native.Text), "Undo resurrected a password or PIN after explicit secret clearing.");
                native.Redo(); Dispatcher.UIThread.RunJobs();
                Require(string.IsNullOrEmpty(native.Text), "Redo resurrected a password or PIN after explicit secret clearing.");
            }
            foreach (FactorTextBox field in Fields(window))
            {
                Require(string.IsNullOrEmpty(field.Text), "The actual clear-secrets action retained a factor.");
                field.Undo(); Dispatcher.UIThread.RunJobs();
                Require(string.IsNullOrEmpty(field.Text), "Undo resurrected a factor after explicit secret clearing.");
                field.Redo(); Dispatcher.UIThread.RunJobs();
                Require(string.IsNullOrEmpty(field.Text), "Redo resurrected a factor after explicit secret clearing.");
            }
        }
    }

    private static void ClearPendingPaste(MainWindow window)
    {
        window.FindControl<TabControl>("MainTabs")!.SelectedIndex = 1;
        Dispatcher.UIThread.RunJobs();
        var clipboard = TopLevel.GetTopLevel(window)?.Clipboard
            ?? throw new InvalidOperationException("The actual GUI clipboard adapter is unavailable.");
        var clear = window.FindControl<Button>("ClearExtractSecretsButton")!;
        try
        {
            foreach (FactorTextBox field in Fields(window))
            {
                field.ClearSensitiveText(); field.Focus();
                var pending = new DeferredPublicClipboardTransfer();
                Complete(clipboard.SetDataAsync(pending));
                field.Paste();
                PumpUntil(() => pending.Requested);
                clear.RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
                pending.Complete(FactorInputRev12Tests.FactorA);
                PumpUntil(() => field.ValidationMessage == FactorInput.Message(FactorInput.Error.StaleTransfer, field.LanguageCode));
                RequireFormatStatus(window, field, complete: false);
                Require(string.IsNullOrEmpty(field.Text) && field.CaretIndex == 0
                    && field.SelectionStart == 0 && field.SelectionEnd == 0,
                    "An outstanding clipboard transfer repopulated an explicitly cleared empty factor field.");
                field.Undo(); field.Redo();
                Require(string.IsNullOrEmpty(field.Text), "A rejected stale clipboard transfer entered native undo history.");
                Complete(clipboard.ClearAsync());
            }
        }
        finally { Complete(clipboard.ClearAsync()); }
    }

    // The real headless clipboard accepts lazy transfer items. This public-data
    // item suspends only delivery, so the actual product clipboard/event path
    // is exercised without a product hook or clipboard-value logging.
    private sealed class DeferredPublicClipboardTransfer : IAsyncDataTransfer, IAsyncDataTransferItem
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
        internal void Fail() => _completion.TrySetException(new InvalidOperationException("Public synthetic clipboard transfer failure."));
        public void Dispose() => _completion.TrySetResult(null);
    }

    private static void RequireFormatStatus(MainWindow window, FactorTextBox field, bool complete)
    {
        Dispatcher.UIThread.RunJobs();
        string name = ReferenceEquals(field, window.FindControl<FactorTextBox>("ExtractGeneratedPasswordFirstBox"))
            ? "ExtractFactorFirstStatus" : "ExtractFactorSecondStatus";
        var status = window.FindControl<TextBlock>(name)!;
        Require(field.IsFormatComplete == complete, "The factor format status does not match the accepted input and latest error.");
        Require(status.Foreground is ISolidColorBrush brush && brush.Color == Color.Parse(complete ? "#7EE2B8" : "#F29AA6"),
            "The factor status color does not match this field's format status.");
    }

    private static void Complete(Task task) { PumpUntil(() => task.IsCompleted); task.GetAwaiter().GetResult(); }
    private static void PumpUntil(Func<bool> condition)
    {
        var timeout = Stopwatch.StartNew();
        while (!condition())
        {
            if (timeout.Elapsed > TimeSpan.FromSeconds(5)) throw new InvalidOperationException("The GUI factor transfer did not finish.");
            Dispatcher.UIThread.RunJobs(); Thread.Sleep(1);
        }
        Dispatcher.UIThread.RunJobs();
    }
    private static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
}
