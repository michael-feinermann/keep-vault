using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Threading;
using Avalonia.VisualTree;
using KalynaArchiver;
using KalynaArchiver.Services;
using KeepVaultMac.Controls;

// The source target is the private TextBox, exactly as DragDropDevice dispatches
// to an AllowDrop editor. This tests routed integration, not only the wrapper API.
internal static class FactorEditorDropRev12Tests
{
    internal static IReadOnlyList<TestCase> Tests =>
    [
        new("gui.factor-rev12-editor-drop", "V13-FACTOR-EDITOR-DROP: actual editor target accepts full 383/511/CRLF raw input and rejects DEL/oversize atomically",
            () => MacGuiTests.RunOnUiThread(Run), TestResource.Gui, "GUI"),
    ];

    private static void Run(MainWindow window)
    {
        window.FindControl<TabControl>("MainTabs")!.SelectedIndex = 1;
        Dispatcher.UIThread.RunJobs();
        string factor = FactorInputRev12Tests.FactorA;
        string retained = FactorInputRev12Tests.FactorB;
        string pairs = string.Join(" ", Enumerable.Range(0, 128).Select(i => factor.Substring(i * 2, 2)));
        string individual = string.Join(" ", factor.Select(c => c.ToString()));
        string multiline = FactorInputRev12Tests.Format(factor, "\r\n\u00A0");
        Require(pairs.Length == 383 && individual.Length == 511, "Public formatted drop lengths changed.");
        string oversized = factor + new string(' ', 65_537 - factor.Length);
        string forbiddenDel = factor[..128] + "\u007F" + factor[128..];
        foreach (string name in new[] { "ExtractGeneratedPasswordFirstBox", "ExtractGeneratedPasswordSecondBox" })
        {
            FactorTextBox field = window.FindControl<FactorTextBox>(name)
                ?? throw new InvalidOperationException("The bounded factor import adapter is missing.");
            TextBox editor = field.GetVisualDescendants().OfType<TextBox>().Single();
            Require(DragDrop.GetAllowDrop(editor), "The actual editor is not an AllowDrop target.");
            foreach ((string raw, bool valid) in new[]
            {
                (pairs, true), (individual, true), (multiline, true),
                (forbiddenDel, false), (oversized, false), (factor + "A", false),
            })
            {
                field.ClearSensitiveText();
                Require(field.TrySetText(retained), "The public retained factor fixture was rejected.");
                field.CaretIndex = 9;
                field.SelectAll();
                Dispatcher.UIThread.RunJobs();
                int caret = field.CaretIndex, start = field.SelectionStart, end = field.SelectionEnd;
                bool canUndo = editor.CanUndo, canRedo = editor.CanRedo;
                string previousStatus = field.ValidationMessage;
                int targetCalls = 0, textCommits = 0;
                bool targetStateUnchanged = false, sourceIsEditor = false;
                EventHandler<DragEventArgs> atEditor = (_, e) =>
                {
                    targetCalls++;
                    sourceIsEditor = ReferenceEquals(e.Source, editor);
                    // Class/default handling would precede this editor handler.
                    // It must not sanitize or edit before the wrapper sees raw.
                    targetStateUnchanged = field.Text == retained && editor.Text == retained
                        && field.CaretIndex == caret && field.SelectionStart == start && field.SelectionEnd == end;
                };
                void CountCommit(object? sender, AvaloniaPropertyChangedEventArgs change)
                {
                    if (change.Property == TextBox.TextProperty) textCommits++;
                }
                editor.AddHandler(DragDrop.DropEvent, atEditor, RoutingStrategies.Bubble, handledEventsToo: true);
                editor.PropertyChanged += CountCommit;
                try
                {
                    using var transfer = new DataTransfer();
                    transfer.Add(DataTransferItem.CreateText(raw));
                    var drop = new DragEventArgs(DragDrop.DropEvent, transfer, editor, new Point(1, 1), KeyModifiers.None)
                    { DragEffects = DragDropEffects.Copy };
                    editor.RaiseEvent(drop);
                    Dispatcher.UIThread.RunJobs();
                    Require(targetCalls == 1 && sourceIsEditor && targetStateUnchanged,
                        "The actual editor route was skipped or mutated text/selection before raw validation.");
                    Require(drop.Handled, "The factor wrapper did not handle the actual editor drop.");
                    if (valid)
                    {
                        Require(drop.DragEffects == DragDropEffects.Copy && field.Text == raw && editor.Text == raw
                            && textCommits == 1, "The actual editor drop shortened or multiply committed accepted raw input.");
                        Require(FactorInput.Canonicalize(field.Text!) == factor && field.HexCharacterCount == 256,
                            "Formatted editor-target drop changed the complete factor payload.");
                        Require(field.CaretIndex == raw.Length && field.SelectionStart == field.SelectionEnd,
                            "Accepted editor-target drop retained stale caret/selection.");
                    }
                    else
                    {
                        Require(drop.DragEffects == DragDropEffects.None && field.Text == retained && editor.Text == retained
                            && textCommits == 0, "Rejected editor-target drop sanitized, shortened or partially committed raw input.");
                        Require(field.CaretIndex == caret && field.SelectionStart == start && field.SelectionEnd == end,
                            "Rejected editor-target drop changed retained caret/selection.");
                        Require(editor.CanUndo == canUndo && editor.CanRedo == canRedo && field.ValidationMessage != previousStatus,
                            "Rejected editor-target drop changed native history or concealed rejection.");
                    }
                }
                finally
                {
                    editor.RemoveHandler(DragDrop.DropEvent, atEditor);
                    editor.PropertyChanged -= CountCommit;
                }
            }
            field.ClearSensitiveText();
        }
    }

    private static void Require(bool condition, string message) => MacComprehensiveTests.Require(condition, message);
}
