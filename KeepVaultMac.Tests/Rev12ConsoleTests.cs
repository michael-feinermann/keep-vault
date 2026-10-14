using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Controls.Presenters;
using Avalonia.Controls.Primitives;
using Avalonia.Headless;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;
using Avalonia.VisualTree;
using KalynaArchiver;
using KalynaArchiver.Services;
using KeepVaultMac.Controls;
using System.Globalization;
using System.Reflection;

internal static class Rev12ConsoleTests
{
    internal static Task RunAsync() => MacGuiTests.RunOnUiThread(window => TestConsoleAndApprovedText(window, false));
    internal static Task RunNoWrapControlAsync() => MacGuiTests.RunOnUiThread(window => TestConsoleAndApprovedText(window, true));
    internal static Task RunHorizontalAsync() => MacGuiTests.RunOnUiThread(TestHorizontalConsole);
    private const BindingFlags Private = BindingFlags.Instance | BindingFlags.NonPublic;

    private static T C<T>(MainWindow window, string name) where T : Control =>
        window.FindControl<T>(name) ?? throw new InvalidOperationException($"Missing control {name}.");

    private static void Call(MainWindow window, string name, params object?[]? args) =>
        typeof(MainWindow).GetMethod(name, Private)!.Invoke(window, args);

    private static void Mark(string step) => Console.WriteLine(
        FormattableString.Invariant($"REV12CONSOLE utc={DateTimeOffset.UtcNow:O}; step={step}"));

    private static void Layout(MainWindow window)
    {
        window.UpdateLayout();
        Dispatcher.UIThread.RunJobs();
        window.UpdateLayout();
    }

    private static (string? Text, int Start, int End) FactorState(MainWindow window, string name)
    {
        if (name.StartsWith("Extract", StringComparison.Ordinal))
        {
            var box = C<FactorTextBox>(window, name + "Box");
            return (box.Text, box.SelectionStart, box.SelectionEnd);
        }
        var generated = C<TextBox>(window, name + "Box");
        return (generated.Text, generated.SelectionStart, generated.SelectionEnd);
    }

    private static string ConsoleLayoutValues(MainWindow window, TextBox log, ScrollViewer scroller, TextPresenter presenter)
    {
        var lines = presenter.TextLayout.TextLines.Take(12).ToArray();
        var main = C<ScrollViewer>(window, "CreateScrollViewer");
        var tabs = C<TabControl>(window, "MainTabs");
        var console = C<Expander>(window, "ConsoleExpander");
        var workspace = C<ScrollViewer>(window, "MainWorkspaceScrollViewer");
        return FormattableString.Invariant($"font={log.FontSize:F3}; scale={window.RenderScaling:F3}; window={window.Width:F3}x{window.Height:F3}; client={window.ClientSize}; log bounds={log.Bounds}; min/max={log.MinHeight:F3}/{log.MaxHeight:F3}; line={log.LineHeight:F3}; viewport={scroller.Viewport}; extent={scroller.Extent}; rendered first12={lines.Length}, sum={lines.Sum(line => line.Height):F3}, max={lines.Select(line => line.Height).DefaultIfEmpty().Max():F3}; tabs bounds={tabs.Bounds}; main viewport={main.Viewport}; main extent={main.Extent}; main actually visible={VisibleMainWorkspaceHeight(window):F3}; workspace viewport={workspace.Viewport}; workspace extent={workspace.Extent}; workspace offset={workspace.Offset}; console bounds={console.Bounds}; console desired={console.DesiredSize}; progress visible={C<StackPanel>(window, "OperationProgressPanel").IsVisible}");
    }

    private static double VisibleMainWorkspaceHeight(MainWindow window)
    {
        var workspace = C<ScrollViewer>(window, "MainWorkspaceScrollViewer");
        var main = C<ScrollViewer>(window, "CreateScrollViewer");
        double top = main.TranslatePoint(default, workspace)?.Y ?? throw new InvalidOperationException("The main viewport is detached.");
        return Math.Max(0, Math.Min(workspace.Viewport.Height, top + main.Bounds.Height) - Math.Max(0, top));
    }

    private static void RequireConsoleAndMainViewport(MainWindow window, TextBox log, ScrollViewer scroller, TextPresenter presenter)
    {
        var lines = presenter.TextLayout.TextLines.Take(12).ToArray();
        double mainMinimum = 3 * C<Button>(window, "CancelOperationButton").Bounds.Height;
        MacComprehensiveTests.Require(lines.Length == 12 && lines.All(line => line.Height <= log.LineHeight + 0.01) &&
            scroller.Viewport.Height + 0.01 >= Math.Max(12 * log.LineHeight, lines.Sum(line => line.Height)) &&
            C<ScrollViewer>(window, "CreateScrollViewer").Viewport.Height + 0.01 >= mainMinimum &&
            VisibleMainWorkspaceHeight(window) + 0.01 >= mainMinimum,
            "Console reflow clipped text lines or removed the usable main content viewport: " + ConsoleLayoutValues(window, log, scroller, presenter));
    }

    private static void TestConsoleAndApprovedText(MainWindow window, bool noWrapControl)
    {
        Mark(noWrapControl ? "begin-nowrap-control" : "begin-product-default");
        var expander = C<Expander>(window, "ConsoleExpander");
        var log = C<TextBox>(window, "LogBox");
        // Preserve the earlier successful comparison configuration. Its
        // historical Wrap counterpart and one-variable NoWrap comparison
        // remain bound to their original build evidence. The product test
        // below exercises the actual new defaults with the same full corpus.
        if (noWrapControl)
        {
            log.TextWrapping = TextWrapping.NoWrap;
            log.ClearSelectionOnLostFocus = true;
            ScrollViewer.SetHorizontalScrollBarVisibility(log, ScrollBarVisibility.Disabled);
            ScrollViewer.SetAllowAutoHide(log, true);
        }
        else
        {
            MacComprehensiveTests.Require(log.TextWrapping == TextWrapping.NoWrap && !log.ClearSelectionOnLostFocus &&
                ScrollViewer.GetHorizontalScrollBarVisibility(log) == ScrollBarVisibility.Auto &&
                !ScrollViewer.GetAllowAutoHide(log), "The console product defaults differ from the measured correction.");
        }
        MacComprehensiveTests.Require(!expander.IsExpanded, "A fresh profile expanded the console.");
        C<TabControl>(window, "MainTabs").SelectedItem = C<TabItem>(window, "ExtractTab");
        Layout(window);
        C<TextBox>(window, "CreatePasswordBox").Text = "public test credential only";
        C<TextBox>(window, "CreatePinBox").Text = "428317";
        string publicFactor = string.Concat(Enumerable.Repeat("07E5C3A18F6D4B29", 16));
        string[] factorNames = ["GeneratedPasswordFirst", "GeneratedPasswordSecond", "ExtractGeneratedPasswordFirst", "ExtractGeneratedPasswordSecond"];
        foreach (string name in factorNames)
        {
            if (name.StartsWith("Extract", StringComparison.Ordinal))
            {
                var imported = C<FactorTextBox>(window, name + "Box");
                imported.Text = publicFactor;
                imported.SelectionStart = 5;
                imported.SelectionEnd = 20;
            }
            else
            {
                var generated = C<TextBox>(window, name + "Box");
                generated.Text = publicFactor;
                generated.SelectionStart = 5;
                generated.SelectionEnd = 20;
            }
        }

        foreach (string language in new[] { "en", "de", "en", "de" })
        {
            bool en = language == "en";
            C<ComboBox>(window, "LanguageBox").SelectedIndex = en ? 1 : 0;
            MacComprehensiveTests.Require(C<TextBlock>(window, "CreatePasswordSetupTitle").Text == (en ? "Decryption credentials" : "Entschlüsselungsdaten") &&
                C<TextBlock>(window, "ExtractPasswordTitle").Text == (en ? "Decryption credentials" : "Entschlüsselungsdaten"), "Credential headings differ from approved text.");
            string help = en ? "Extracting the archive requires the password, the PIN, and both generated factors A and B." :
                "Zum Entpacken sind das Passwort, die PIN und beide generierten Faktoren A und B erforderlich.";
            MacComprehensiveTests.Require(C<TextBlock>(window, "CreatePasswordSetupHelpText").Text == help &&
                C<TextBlock>(window, "ExtractPasswordHelpText").Text == help, "Credential help differs from approved text.");
            MacComprehensiveTests.Require(C<TextBlock>(window, "PinHelpText").Text == (en ?
                "6 to 16 digits. The PIN is a separate credential. To extract the archive, you need the password, the PIN, and both generated factors A and B." :
                "6 bis 16 Ziffern. Die PIN ist eine eigenständige geheime Eingabe. Zum Entpacken werden das Passwort, die PIN und die beiden generierten Faktoren A und B benötigt."), "PIN explanation differs from approved text.");
            MacComprehensiveTests.Require(C<TextBlock>(window, "PasswordGeneratorTitle").Text == (en ? "Two generated key factors" : "Zwei generierte Schlüsselfaktoren"), "Generator heading differs from approved text.");
            string generator = en ?
                $"Eleven entropy pools collect randomly assigned mouse events. Each pool requires at least {EntropyMixer.RequiredMouseSamplesPerPurpose.ToString("N0", System.Globalization.CultureInfo.GetCultureInfo("en-US"))} events. Generate creates factors A and B together with the required salts and nonce values, and clears all source pools." :
                $"Elf Entropiepools werden durch zufällig zugeordnete Mausereignisse befüllt. Jeder Pool benötigt mindestens {EntropyMixer.RequiredMouseSamplesPerPurpose} Ereignisse. Generieren erstellt die Faktoren A und B sowie die benötigten Salze und Nonce-Werte und leert alle Quellpools.";
            MacComprehensiveTests.Require(C<TextBlock>(window, "PasswordGeneratorHelpText").Text == generator, "Generator source-pool text or constant differs from approved text.");
            MacComprehensiveTests.Require(C<TextBlock>(window, "GeneratedPasswordFirstLabel").Text == (en ? "Factor A" : "Faktor A") &&
                C<TextBlock>(window, "GeneratedPasswordSecondLabel").Text == (en ? "Factor B" : "Faktor B") &&
                C<TextBlock>(window, "ExtractGeneratedPasswordFirstLabel").Text == (en ? "Factor A from the key sheet" : "Faktor A vom Schlüsselzettel") &&
                C<TextBlock>(window, "ExtractGeneratedPasswordSecondLabel").Text == (en ? "Factor B from the key sheet" : "Faktor B vom Schlüsselzettel"), "Factor labels differ from approved text.");
            MacComprehensiveTests.Require(C<TextBlock>(window, "FactorImportHelpText").Text == (en ? "256 hexadecimal characters each. Spaces and line breaks are ignored." : "Jeweils 256 Hexadezimalzeichen. Leerzeichen und Zeilenumbrüche werden ignoriert."), "Factor formatting help differs from approved text.");
            MacComprehensiveTests.Require(C<TextBlock>(window, "ConsoleToggleText").Text == (en ? "Show console" : "Konsole anzeigen"), "Collapsed console text differs from approved text.");
            MacComprehensiveTests.Require(C<TextBox>(window, "CreatePasswordBox").Text == "public test credential only" &&
                C<TextBox>(window, "CreatePinBox").Text == "428317", "Language change modified the credential draft.");
            foreach (string name in factorNames)
            {
                var box = C<Control>(window, name + "Box");
                string labelName = name + "Label";
                var label = C<TextBlock>(window, labelName);
                string expectedHelp = name.StartsWith("Extract", StringComparison.Ordinal)
                    ? C<TextBlock>(window, "FactorImportHelpText").Text! : help;
                MacComprehensiveTests.Require(ReferenceEquals(AutomationProperties.GetLabeledBy(box), label) &&
                    AutomationProperties.GetHelpText(box) == expectedHelp && !expectedHelp.Contains(publicFactor, StringComparison.Ordinal),
                    "Factor accessibility rules are missing, stale, or contain factor input.");
                if (box is FactorTextBox imported)
                {
                    // The focused native input peer is the private editor. Its
                    // label/help must match the public wrapper without reading
                    // the editor's factor text into an accessibility message.
                    var editor = imported.GetVisualDescendants().OfType<TextBox>().Single();
                    MacComprehensiveTests.Require(ReferenceEquals(AutomationProperties.GetLabeledBy(editor), label) &&
                        AutomationProperties.GetHelpText(editor) == expectedHelp,
                        "The actual factor editor has no localized public accessibility rules.");
                }
                var state = FactorState(window, name);
                MacComprehensiveTests.Require(state.Text == publicFactor && state.Start == 5 && state.End == 20,
                    "Language change altered factor text or selection.");
            }
        }

        C<TabControl>(window, "MainTabs").SelectedItem = C<TabItem>(window, "ArchiveTab");
        Layout(window);
        Call(window, "ClearConsoleLog");
        for (int index = 1; index <= 200; index++) Call(window, "Log", $"Public console test line {index:000}");
        Call(window, "FlushConsoleEntries");
        expander.IsExpanded = true;
        Layout(window);
        var scroller = log.GetVisualDescendants().OfType<ScrollViewer>().First();
        var presenter = log.GetVisualDescendants().OfType<TextPresenter>().First();
        MacComprehensiveTests.Require(scroller.Viewport.Height + 0.01 >= 12 * log.LineHeight,
            $"Console text viewport has fewer than twelve full lines: {scroller.Viewport.Height}/{log.LineHeight}.");
        MacComprehensiveTests.Require(presenter.TextLayout.TextLines.Take(12).All(line => line.Height <= log.LineHeight + 0.01), "Rendered line height exceeds the measured console contract.");
        MacComprehensiveTests.Require(C<TextBlock>(window, "ConsoleToggleText").Text == "Konsole ausblenden", "Expanded console text is stale.");
        log.SelectionStart = 3;
        log.SelectionEnd = 12;
        scroller.Offset = new Vector(0, 30);
        Layout(window);
        double oldOffset = scroller.Offset.Y;
        string oldSelection = log.SelectedText;
        Call(window, "Log", "A new public entry while reading older output");
        Call(window, "FlushConsoleEntries");
        Layout(window);
        MacComprehensiveTests.Require(log.SelectedText == oldSelection && Math.Abs(scroller.Offset.Y - oldOffset) <= 1,
            "Appending output moved an older selection or scroll position.");
        foreach (string language in new[] { "en", "de" })
        {
            typeof(MainWindow).GetField("_language", Private)!.SetValue(window, language);
            Call(window, "ApplyLanguage");
            Layout(window);
            MacComprehensiveTests.Require(expander.IsExpanded && log.SelectedText == oldSelection && Math.Abs(scroller.Offset.Y - oldOffset) <= 1,
                "A language change reset console state or the reader's position.");
        }

        string history = log.Text!;
        expander.IsExpanded = false;
        Layout(window);
        expander.IsExpanded = true;
        Layout(window);
        MacComprehensiveTests.Require(log.Text == history && log.SelectedText == oldSelection,
            "Console toggle discarded history or selection.");
        MacComprehensiveTests.Require(C<Button>(window, "CancelOperationButton").IsEffectivelyVisible,
            "Cancellation is inside the collapsible log.");
        window.Width = window.MinWidth;
        window.Height = window.MinHeight;
        foreach (double size in new[] { 11d, 16d, 11d })
        {
            log.FontSize = size;
            Layout(window);
            RequireConsoleAndMainViewport(window, log, scroller, presenter);
        }
        var progress = C<StackPanel>(window, "OperationProgressPanel");
        progress.IsVisible = true;
        C<TextBlock>(window, "OperationPhaseText").Text = "Public test phase";
        C<TextBlock>(window, "OperationProgressDetailsText").Text = "Public test progress and remaining time";
        log.FontSize = 16;
        Layout(window);
        RequireConsoleAndMainViewport(window, log, scroller, presenter);
        progress.IsVisible = false;
        log.FontSize = 11;
        Layout(window);
        TestMainWorkspaceScrollRoutes(window);

        Mark("follow-end-before");
        log.SelectionStart = log.SelectionEnd = 0;
        scroller.ScrollToEnd();
        Layout(window);
        Call(window, "Log", "A public entry while following the end");
        Call(window, "FlushConsoleEntries");
        Layout(window);
        MacComprehensiveTests.Require(scroller.Offset.Y >= scroller.Extent.Height - scroller.Viewport.Height - 1,
            "The console did not follow output when already at the end.");
        Mark("follow-end-complete");
        TestPendingAppendInteractions(window, log, scroller);
        Mark("held-drag-hover-keyboard-complete");
        TestPruningKeepsReadingContext(window, log, scroller, presenter);
        Mark("pruning-context-complete");

        // Both paths are bounded: a burst waiting for the UI, then repeated
        // flushes into the retained log. No file paths or credentials are logged.
        Mark("retention-burst-before");
        for (int index = 0; index < 40; index++) Call(window, "Log", $"Public burst {index:000}: " + new string('x', 63_000));
        int queued = (int)typeof(MainWindow).GetField("_consolePendingCharacters", Private)!.GetValue(window)!;
        MacComprehensiveTests.Require(queued <= 750_000, "The pending console queue is unbounded.");
        Mark($"retention-burst-queued-characters-{queued}");
        Call(window, "FlushConsoleEntries");
        Mark("retention-burst-flushed");
        for (int index = 0; index < 20; index++)
        {
            Mark($"retention-append-{index}-before");
            Call(window, "Log", $"Public retained {index:000}: " + new string('y', 63_000));
            Call(window, "FlushConsoleEntries");
            Mark($"retention-append-{index}-flushed");
        }
        MacComprehensiveTests.Require(log.Text!.Length <= 1_000_000 &&
            C<TextBlock>(window, "ConsoleRetentionText").Text!.Length > 0, "Console retention is unbounded or removed history is hidden.");
        Call(window, "ClearConsoleLog");
        MacComprehensiveTests.Require(log.Text == string.Empty, "Explicit clear did not clear console history.");
        Mark("complete");
    }

    private static ScrollBar HorizontalBar(ScrollViewer scroller) =>
        scroller.GetVisualDescendants().OfType<ScrollBar>().Single(bar =>
            bar.Orientation == Orientation.Horizontal && ReferenceEquals(bar.TemplatedParent, scroller));

    private static void RequireHorizontalConsoleViewport(MainWindow window, TextBox log, ScrollViewer scroller, TextPresenter presenter)
    {
        ScrollBar horizontal = HorizontalBar(scroller);
        var viewport = scroller.GetVisualDescendants().OfType<ScrollContentPresenter>().Single(control =>
            ReferenceEquals(control.TemplatedParent, scroller));
        double viewportBottom = viewport.TranslatePoint(new Point(0, viewport.Bounds.Height), scroller)?.Y
            ?? throw new InvalidOperationException("The console text viewport is detached.");
        double barTop = horizontal.TranslatePoint(default, scroller)?.Y
            ?? throw new InvalidOperationException("The horizontal console scrollbar is detached.");
        double barChrome = Math.Ceiling((horizontal.Bounds.Height + horizontal.Margin.Top + horizontal.Margin.Bottom)
            * window.RenderScaling) / window.RenderScaling;
        double expected = 12 * log.LineHeight + log.Padding.Top + log.Padding.Bottom +
            log.BorderThickness.Top + log.BorderThickness.Bottom + barChrome;
        MacComprehensiveTests.Require(horizontal.IsEffectivelyVisible && horizontal.Bounds.Height > 0 &&
            horizontal.Bounds.Width > 0 && scroller.ScrollBarMaximum.X > 0 && !scroller.AllowAutoHide &&
            viewportBottom <= barTop + 0.01 && Math.Abs(log.MinHeight - expected) <= 0.01 &&
            Math.Abs(log.MaxHeight - expected) <= 0.01,
            FormattableString.Invariant($"The actual horizontal console bar clipped or overlaid the text viewport: visible={horizontal.IsEffectivelyVisible}; bar bounds={horizontal.Bounds}; margin={horizontal.Margin}; maximum={scroller.ScrollBarMaximum}; viewport bottom={viewportBottom:F6}; bar top={barTop:F6}; expected height={expected:F6}; details={ConsoleLayoutValues(window, log, scroller, presenter)}"));
        RequireConsoleAndMainViewport(window, log, scroller, presenter);
    }

    private static void TestHorizontalConsole(MainWindow window)
    {
        Mark("horizontal-begin-product-default");
        var log = C<TextBox>(window, "LogBox");
        var expander = C<Expander>(window, "ConsoleExpander");
        MacComprehensiveTests.Require(log.TextWrapping == TextWrapping.NoWrap && !log.ClearSelectionOnLostFocus &&
            ScrollViewer.GetHorizontalScrollBarVisibility(log) == ScrollBarVisibility.Auto &&
            !ScrollViewer.GetAllowAutoHide(log), "The actual product console has no non-overlay horizontal route.");
        C<TabControl>(window, "MainTabs").SelectedItem = C<TabItem>(window, "ArchiveTab");
        window.Width = window.MinWidth;
        window.Height = window.MinHeight;
        var progress = C<StackPanel>(window, "OperationProgressPanel");
        progress.IsVisible = true;
        C<TextBlock>(window, "OperationPhaseText").Text = "Public horizontal console test phase";
        C<TextBlock>(window, "OperationProgressDetailsText").Text = "Public horizontal console test progress";

        void FillPublicRows(bool longRows)
        {
            Call(window, "ClearConsoleLog");
            for (int index = 1; index <= 12; index++)
                Call(window, "Log", $"Public horizontal row {index:00}: " + (longRows ? new string('x', 2_048) : "short"));
            Call(window, "FlushConsoleEntries");
            Layout(window);
        }

        FillPublicRows(true);
        expander.IsExpanded = true;
        Layout(window);
        var scroller = log.GetVisualDescendants().OfType<ScrollViewer>().First();
        var presenter = log.GetVisualDescendants().OfType<TextPresenter>().First();
        foreach (double font in new[] { 11d, 16d, 11d })
        {
            log.FontSize = font;
            Layout(window);
            RequireHorizontalConsoleViewport(window, log, scroller, presenter);
            MacComprehensiveTests.Require(progress.IsEffectivelyVisible,
                "Console chrome reflow hid the separate progress area.");
        }
        Mark("horizontal-font-progress-reflow-complete");

        // Change a real native scrollbar bound without changing the font.
        // The original theme dimension is restored before interaction checks.
        ScrollBar horizontal = HorizontalBar(scroller);
        double themeBarHeight = horizontal.Bounds.Height;
        double themeConsoleHeight = log.MinHeight;
        horizontal.Height = themeBarHeight + 7;
        Layout(window);
        RequireHorizontalConsoleViewport(window, log, scroller, presenter);
        MacComprehensiveTests.Require(log.MinHeight > themeConsoleHeight + 6,
            "A native horizontal scrollbar bounds change was hidden by the font cache.");
        horizontal.ClearValue(Layoutable.HeightProperty);
        Layout(window);
        RequireHorizontalConsoleViewport(window, log, scroller, presenter);
        MacComprehensiveTests.Require(Math.Abs(log.MinHeight - themeConsoleHeight) <= 0.01,
            "Restoring the native scrollbar theme height retained stale console chrome.");
        Mark("horizontal-native-bounds-reflow-complete");

        log.Focus();
        log.CaretIndex = 15;
        log.SelectionStart = 3;
        log.SelectionEnd = 15;
        Layout(window);
        scroller.Offset = default;
        Layout(window);
        Point point = log.TranslatePoint(new Point(20, 20), window)
            ?? throw new InvalidOperationException("The horizontal console wheel target is detached.");
        window.MouseWheel(point, new Vector(-2, 0));
        Layout(window);
        MacComprehensiveTests.Require(scroller.Offset.X > 0 && Math.Abs(horizontal.Value - scroller.Offset.X) <= 0.01,
            "The native horizontal wheel did not move the console and its real scrollbar together.");
        double target = scroller.ScrollBarMaximum.X / 2;
        horizontal.SetCurrentValue(RangeBase.ValueProperty, target);
        Layout(window);
        MacComprehensiveTests.Require(Math.Abs(scroller.Offset.X - target) <= 0.01 &&
            Math.Abs(horizontal.Value - scroller.Offset.X) <= 0.01,
            "The native horizontal scrollbar did not control the actual console viewport.");

        string selected = log.SelectedText;
        int selectionStart = log.SelectionStart, selectionEnd = log.SelectionEnd, caret = log.CaretIndex;
        Vector offset = scroller.Offset;
        Call(window, "Log", "Public output while reading horizontally");
        Call(window, "FlushConsoleEntries");
        Layout(window);
        void RequireReadingContext() => MacComprehensiveTests.Require(log.SelectedText == selected &&
            log.SelectionStart == selectionStart && log.SelectionEnd == selectionEnd && log.CaretIndex == caret &&
            Math.Abs(scroller.Offset.X - offset.X) <= 1 && Math.Abs(scroller.Offset.Y - offset.Y) <= 1,
            FormattableString.Invariant($"A console append or reflow changed horizontal reading context: offset={scroller.Offset}; expected={offset}; selection={log.SelectionStart}/{log.SelectionEnd}; caret={log.CaretIndex}."));
        RequireReadingContext();
        string history = log.Text!;
        foreach (string language in new[] { "en", "de" })
        {
            ComboBox languageBox = C<ComboBox>(window, "LanguageBox");
            int languageIndex = language == "en" ? 1 : 0;
            MacComprehensiveTests.Require(languageBox.SelectedIndex != languageIndex &&
                C<ComboBox>(window, "CipherSuiteBox").SelectedItem is ComboBoxItem { Tag: string },
                "The horizontal locale fixture did not have a real language transition and cipher selection.");
            string suiteTag = (string)((ComboBoxItem)C<ComboBox>(window, "CipherSuiteBox").SelectedItem!).Tag!;
            EncryptionSuite suite = Enum.Parse<EncryptionSuite>(suiteTag);
            languageBox.SelectedIndex = languageIndex;
            Layout(window);
            // ApplyLanguage rebuilds the real suite picker. Its native
            // SelectionChanged logs one public, localized suite message.
            // Flush and bind that exact suffix before testing pure reflow.
            Call(window, "FlushConsoleEntries");
            Layout(window);
            string actual = log.Text!;
            string suffix = actual.StartsWith(history, StringComparison.Ordinal) ? actual[history.Length..] : string.Empty;
            string expectedMessage = (language == "en" ? "Cipher suite selected: " : "Verschlüsselungsverfahren gewählt: ") +
                EncryptionSuiteCatalog.Get(suite).DisplayName + Environment.NewLine;
            MacComprehensiveTests.Require(actual.StartsWith(history, StringComparison.Ordinal) &&
                suffix.Length == 11 + expectedMessage.Length && suffix[0] == '[' && suffix[9] == ']' && suffix[10] == ' ' &&
                DateTime.TryParseExact(suffix.Substring(1, 8), "HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.None, out _) &&
                suffix[11..] == expectedMessage &&
                C<ComboBox>(window, "CipherSuiteBox").SelectedItem is ComboBoxItem { Tag: string actualSuiteTag } && actualSuiteTag == suiteTag,
                FormattableString.Invariant($"The locale transition altered existing history or appended an unexpected public suffix: previous length={history.Length}; actual length={actual.Length}; suffix length={suffix.Length}; expected suffix length={11 + expectedMessage.Length}."));
            history = actual;
            RequireReadingContext();
            RequireHorizontalConsoleViewport(window, log, scroller, presenter);
        }
        Mark("horizontal-locale-exact-suffix-complete");
        MacComprehensiveTests.Require(log.Focus() && log.IsFocused,
            "The console focus-loss fixture did not focus the actual native text editor.");
        Layout(window);
        RequireReadingContext();
        Button endButton = C<Button>(window, "ConsoleEndButton");
        MacComprehensiveTests.Require(endButton.Focus(), "The console focus-loss fixture could not focus its native button.");
        Layout(window);
        MacComprehensiveTests.Require(endButton.IsFocused && !log.IsFocused,
            "The console focus-loss fixture never reached a real focus transition.");
        RequireReadingContext();
        MacComprehensiveTests.Require(log.Focus() && log.IsFocused,
            "The console focus-loss fixture could not return focus to the native editor.");
        Layout(window);
        RequireReadingContext();
        Mark("horizontal-native-focus-selection-complete");
        expander.IsExpanded = false;
        Layout(window);
        expander.IsExpanded = true;
        Layout(window);
        RequireReadingContext();
        window.Width = window.MinWidth + 180;
        window.Height = window.MinHeight + 90;
        Layout(window);
        RequireReadingContext();
        RequireHorizontalConsoleViewport(window, log, scroller, presenter);
        window.Width = window.MinWidth;
        window.Height = window.MinHeight;
        Layout(window);
        RequireReadingContext();
        RequireHorizontalConsoleViewport(window, log, scroller, presenter);
        MacComprehensiveTests.Require(log.Text == history, "Horizontal console reflow changed the public history.");
        Mark("horizontal-native-offset-reading-context-complete");

        // Native selection/caret work settles before a separate user scroll.
        // Automatic vertical following must retain unselected horizontal
        // reading position, including the deferred expansion path.
        log.SelectionStart = log.SelectionEnd = 0;
        Layout(window);
        horizontal.SetCurrentValue(RangeBase.ValueProperty, scroller.ScrollBarMaximum.X / 2);
        ScrollBar vertical = scroller.GetVisualDescendants().OfType<ScrollBar>().Single(bar =>
            bar.Orientation == Orientation.Vertical && ReferenceEquals(bar.TemplatedParent, scroller));
        vertical.SetCurrentValue(RangeBase.ValueProperty, scroller.ScrollBarMaximum.Y);
        Layout(window);
        double followX = scroller.Offset.X, previousMaximumY = scroller.ScrollBarMaximum.Y;
        MacComprehensiveTests.Require(followX > 0 && log.SelectionStart == log.SelectionEnd &&
            scroller.Offset.Y >= previousMaximumY - 1,
            "The horizontal follow fixture did not reach the real vertical end with empty selection and positive X.");
        long interaction = (long)typeof(MainWindow).GetField("_consoleInteractionVersion", Private)!.GetValue(window)!;
        Call(window, "Log", "Public output while following vertically with horizontal offset");
        Call(window, "FlushConsoleEntries");
        window.MouseMove(point);
        Layout(window);
        MacComprehensiveTests.Require((long)typeof(MainWindow).GetField("_consoleInteractionVersion", Private)!.GetValue(window)! == interaction &&
            scroller.ScrollBarMaximum.Y > previousMaximumY && scroller.Offset.Y >= scroller.ScrollBarMaximum.Y - 1 &&
            Math.Abs(scroller.Offset.X - followX) <= 1 && log.SelectionStart == log.SelectionEnd,
            FormattableString.Invariant($"Automatic following or ordinary hover reset horizontal reading position: actual={scroller.Offset}; expected X={followX:F6}; maximum={scroller.ScrollBarMaximum}."));
        previousMaximumY = scroller.ScrollBarMaximum.Y;
        expander.IsExpanded = false;
        Layout(window);
        Call(window, "Log", "Public output while the horizontally positioned console is collapsed");
        Call(window, "FlushConsoleEntries");
        Layout(window);
        expander.IsExpanded = true;
        Layout(window);
        MacComprehensiveTests.Require(scroller.ScrollBarMaximum.Y > previousMaximumY &&
            scroller.Offset.Y >= scroller.ScrollBarMaximum.Y - 1 && Math.Abs(scroller.Offset.X - followX) <= 1 &&
            log.SelectionStart == log.SelectionEnd,
            FormattableString.Invariant($"Deferred expansion follow reset horizontal reading position: actual={scroller.Offset}; expected X={followX:F6}; maximum={scroller.ScrollBarMaximum}."));
        RequireHorizontalConsoleViewport(window, log, scroller, presenter);
        Mark("horizontal-unselected-vertical-follow-hover-expansion-complete");

        double withBar = log.MinHeight;
        FillPublicRows(false);
        MacComprehensiveTests.Require(!horizontal.IsEffectivelyVisible && scroller.ScrollBarMaximum.X == 0 &&
            Math.Abs(log.MinHeight - (12 * log.LineHeight + log.Padding.Top + log.Padding.Bottom +
                log.BorderThickness.Top + log.BorderThickness.Bottom)) <= 0.01 && log.MinHeight < withBar,
            "The native Auto scrollbar disappeared without removing its stale console chrome.");
        RequireConsoleAndMainViewport(window, log, scroller, presenter);
        FillPublicRows(true);
        RequireHorizontalConsoleViewport(window, log, scroller, presenter);
        MacComprehensiveTests.Require(Math.Abs(log.MinHeight - withBar) <= 0.01,
            "The native Auto scrollbar reappeared without restoring its real chrome height.");
        Mark("horizontal-visibility-reflow-complete");
    }

    private static void TestPruningKeepsReadingContext(MainWindow window, TextBox log, ScrollViewer scroller, TextPresenter presenter)
    {
        // Every public source row fits the actual text viewport. Batches pass
        // through the normal bounded Log/Flush path, including its prefix.
        string PublicRows(int first, int count) => string.Concat(Enumerable.Range(first, count).Select(index =>
        {
            string prefix = $"Public pruning row {index:00000}: ";
            return prefix + new string('x', 63 - prefix.Length) + "\n";
        }));
        Mark("pruning-clear-before");
        Call(window, "ClearConsoleLog");
        Mark("pruning-clear-complete");
        for (int batch = 0; batch < 14; batch++)
        {
            Mark($"pruning-history-batch-{batch}-before");
            Call(window, "Log", PublicRows(batch * 1_000, 1_000));
            Call(window, "FlushConsoleEntries");
            Mark($"pruning-history-batch-{batch}-flushed");
        }
        Mark("pruning-history-layout-before");
        Layout(window);
        Mark($"pruning-history-layout-complete-characters-{log.Text!.Length}");
        MacComprehensiveTests.Require(log.Text!.Length is > 800_000 and < 1_000_000,
            "The pruning fixture did not establish a complete, unpruned public history.");

        const string marker = "Public pruning row 12042: ";
        int markerIndex = log.Text!.IndexOf(marker, StringComparison.Ordinal);
        MacComprehensiveTests.Require(markerIndex >= 0, "The public reading-context marker is missing.");
        Mark("pruning-caret-before");
        log.Focus();
        log.CaretIndex = markerIndex;
        log.SelectionStart = log.SelectionEnd = markerIndex;
        Layout(window);
        Mark("pruning-caret-layout-complete");
        window.KeyPress(Key.End, RawInputModifiers.Shift, PhysicalKey.End, null);
        window.KeyRelease(Key.End, RawInputModifiers.Shift, PhysicalKey.End, null);
        Layout(window);
        Mark("pruning-keyboard-layout-complete");
        string selectedContext = log.SelectedText;
        MacComprehensiveTests.Require(selectedContext.StartsWith(marker, StringComparison.Ordinal) && log.SelectionStart != log.SelectionEnd,
            "The pruning fixture did not select public reading context through the real Shift-End route.");

        Point wheelPoint = log.TranslatePoint(new Point(30, 30), window)
            ?? throw new InvalidOperationException("The public pruning wheel target is detached.");
        double beforeWheel = scroller.Offset.Y;
        Mark("pruning-wheel-before");
        window.MouseWheel(wheelPoint, new Vector(0, -1));
        Layout(window);
        Mark("pruning-wheel-layout-complete");
        MacComprehensiveTests.Require(scroller.Offset.Y > beforeWheel && log.SelectedText == selectedContext,
            "The pruning fixture's native wheel did not move the actual reading viewport while preserving selection.");

        string previousText = log.Text!;
        int previousStart = log.SelectionStart, previousEnd = log.SelectionEnd, previousCaret = log.CaretIndex;
        Vector previousOffset = scroller.Offset;
        Mark("pruning-rendered-lines-snapshot-before");
        var renderedLines = presenter.TextLayout.TextLines.Select(line => (Index: line.FirstTextSourceIndex, line.Height)).ToArray();
        Mark($"pruning-rendered-lines-snapshot-complete-count-{renderedLines.Length}");
        for (int batch = 14; batch < 17; batch++) Call(window, "Log", PublicRows(batch * 1_000, 1_000));
        Mark("pruning-trigger-flush-before");
        Call(window, "FlushConsoleEntries");
        Mark("pruning-trigger-flush-complete");
        // Derive removal from the actually retained public source context,
        // rather than reading an internal pruning count or reproducing it.
        int removed = previousText.IndexOf(log.Text![..128], StringComparison.Ordinal);
        double removedRenderedHeight = renderedLines.Where(line => line.Index < removed).Sum(line => line.Height);
        MacComprehensiveTests.Require(removed > 0 && previousStart > removed && previousEnd > removed &&
            previousOffset.Y > removedRenderedHeight && C<TextBlock>(window, "ConsoleRetentionText").Text!.Length > 0,
            "The pruning fixture did not remove actual rendered history while retaining the selected reading context.");
        Layout(window);
        Mark("pruning-retained-layout-complete");
        MacComprehensiveTests.Require(log.SelectedText == selectedContext &&
            log.SelectionStart == previousStart - removed && log.SelectionEnd == previousEnd - removed &&
            log.CaretIndex == previousCaret - removed &&
            Math.Abs(scroller.Offset.X - previousOffset.X) <= 1 &&
            Math.Abs(scroller.Offset.Y - (previousOffset.Y - removedRenderedHeight)) <= 1,
            FormattableString.Invariant($"Pruning moved surviving native reading context: removed={removed}; rendered removed height={removedRenderedHeight:F6}; old/new selection={previousStart}/{previousEnd}/{log.SelectionStart}/{log.SelectionEnd}; old/new caret={previousCaret}/{log.CaretIndex}; old/new offset={previousOffset}/{scroller.Offset}; maximum={scroller.ScrollBarMaximum.Y:F6}"));
    }

    private static void TestMainWorkspaceScrollRoutes(MainWindow window)
    {
        var workspace = C<ScrollViewer>(window, "MainWorkspaceScrollViewer");
        var scrollbar = workspace.GetVisualDescendants().OfType<ScrollBar>().Single(bar =>
            bar.Orientation == Orientation.Vertical && ReferenceEquals(bar.TemplatedParent, workspace));
        double before = workspace.Offset.Y;
        MacComprehensiveTests.Require(workspace.ScrollBarMaximum.Y > 0, "The minimum window exposes no native route back to the header.");
        workspace.Offset = default;
        Layout(window);
        Point point = workspace.TranslatePoint(new Point(10, 10), window)
            ?? throw new InvalidOperationException("The main workspace wheel target is detached.");
        window.MouseWheel(point, new Vector(0, -2));
        Layout(window);
        MacComprehensiveTests.Require(workspace.Offset.Y > 0 && Math.Abs(scrollbar.Value - workspace.Offset.Y) <= 0.01,
            "Native workspace wheel scrolling did not update its real scrollbar offset.");
        // Match the native scrollbar's own Line/Page/Thumb update path. A
        // direct Value setter installs a local override over its template
        // binding and would manufacture a stale thumb after owner scrolling.
        scrollbar.SetCurrentValue(RangeBase.ValueProperty, workspace.ScrollBarMaximum.Y / 2);
        Layout(window);
        MacComprehensiveTests.Require(Math.Abs(workspace.Offset.Y - workspace.ScrollBarMaximum.Y / 2) <= 0.01,
            "The native workspace scrollbar did not control its real scroll viewport.");
        scrollbar.ScrollToHome();
        Layout(window);
        MacComprehensiveTests.Require(workspace.Offset.Y == 0 && scrollbar.Value == 0,
            "The native scrollbar Home route did not return the real workspace to the header.");
        scrollbar.SetCurrentValue(RangeBase.ValueProperty, workspace.ScrollBarMaximum.Y / 2);
        Layout(window);
        workspace.ScrollToHome();
        double immediateHomeOffset = workspace.Offset.Y;
        double immediateHomeValue = scrollbar.Value;
        Layout(window);
        MacComprehensiveTests.Require(workspace.Offset.Y == 0 && scrollbar.Value == 0,
            FormattableString.Invariant($"The reachable header's home position was not preserved: immediate offset/value={immediateHomeOffset:F6}/{immediateHomeValue:F6}; after layout offset/value={workspace.Offset.Y:F6}/{scrollbar.Value:F6}; maximum={workspace.ScrollBarMaximum.Y:F6}; viewport={workspace.Viewport}; extent={workspace.Extent}; tabs height={C<TabControl>(window, "MainTabs").Height:F6}; pending reveal={typeof(MainWindow).GetField("_consoleWorkspaceRevealPending", Private)!.GetValue(window)}; needs reveal={typeof(MainWindow).GetField("_consoleWorkspaceNeedsReveal", Private)!.GetValue(window)}; interaction={typeof(MainWindow).GetField("_consoleWorkspaceInteractionVersion", Private)!.GetValue(window)}"));
        workspace.Offset = new Vector(0, before);
        Layout(window);
    }

    private static void TestPendingAppendInteractions(MainWindow window, TextBox log, ScrollViewer scroller)
    {
        Mark("held-drag-begin");
        long Interaction() => (long)typeof(MainWindow).GetField("_consoleInteractionVersion", Private)!.GetValue(window)!;
        string ScrollState() => FormattableString.Invariant(
            $"offset={scroller.Offset.Y:F6}; maximum={scroller.ScrollBarMaximum.Y:F6}; extent={scroller.Extent}; viewport={scroller.Viewport}; caret={log.CaretIndex}; selection={log.SelectionStart}/{log.SelectionEnd}; interaction={Interaction()}; update={typeof(MainWindow).GetField("_consoleUpdateVersion", Private)!.GetValue(window)}");
        Point Inside(Visual visual, double x, double y) => visual.TranslatePoint(new Point(x, y), window)
            ?? throw new InvalidOperationException("The console interaction target is detached.");
        void QueueAppend(string message) { Call(window, "Log", message); Call(window, "FlushConsoleEntries"); }

        log.SelectionStart = log.SelectionEnd = 0;
        scroller.Offset = new Vector(0, Math.Max(40, scroller.ScrollBarMaximum.Y / 2));
        Layout(window);
        var vertical = log.GetVisualDescendants().OfType<ScrollBar>().First(bar => bar.Orientation == Orientation.Vertical);
        var thumb = vertical.GetVisualDescendants().OfType<Thumb>().First();
        Point thumbPoint = Inside(thumb, thumb.Bounds.Width / 2, thumb.Bounds.Height / 2);
        window.MouseMove(thumbPoint);
        Layout(window);
        thumbPoint = Inside(thumb, thumb.Bounds.Width / 2, thumb.Bounds.Height / 2);
        window.MouseDown(thumbPoint, MouseButton.Left);
        long beforeMove = Interaction();
        QueueAppend("Public entry while a console thumb is held");
        Mark("held-thumb-append-flushed");
        Point movedThumb = thumbPoint + new Vector(0, 20);
        window.MouseMove(movedThumb, RawInputModifiers.LeftMouseButton);
        double draggedOffset = scroller.Offset.Y;
        MacComprehensiveTests.Require(Interaction() > beforeMove, "Held thumb movement did not invalidate the pending append restore.");
        Layout(window);
        Mark("held-thumb-drag-layout-complete");
        MacComprehensiveTests.Require(Math.Abs(scroller.Offset.Y - draggedOffset) <= 1,
            "A pending append reset the offset of an ongoing thumb drag.");
        window.MouseUp(movedThumb, MouseButton.Left);
        Layout(window);

        scroller.Offset = new Vector(0, 40);
        Layout(window);
        Point textStart = Inside(log, 20, 20);
        Point textEnd = Inside(log, 100, 55);
        window.MouseDown(textStart, MouseButton.Left);
        beforeMove = Interaction();
        QueueAppend("Public entry while a console text selection is held");
        Mark("held-selection-append-flushed");
        window.MouseMove(textEnd, RawInputModifiers.LeftMouseButton);
        int selectedStart = log.SelectionStart, selectedEnd = log.SelectionEnd;
        MacComprehensiveTests.Require(Interaction() > beforeMove && selectedStart != selectedEnd,
            "Held console selection did not reach the real text input route.");
        Layout(window);
        Mark("held-selection-drag-layout-complete");
        MacComprehensiveTests.Require(log.SelectionStart == selectedStart && log.SelectionEnd == selectedEnd,
            "Pending output changed the user's ongoing text selection.");
        window.MouseUp(textEnd, MouseButton.Left);
        Layout(window);

        log.SelectionStart = log.SelectionEnd = 0;
        // Collapsing the real selection changes the native caret. Its pending
        // bring-into-view must finish before the separate user scroll to the
        // end; otherwise the fixture itself scrolls back to caret zero.
        Layout(window);
        scroller.ScrollToEnd();
        Layout(window);
        string beforeHoverAppend = ScrollState();
        Mark("hover-fixture-layout-complete");
        MacComprehensiveTests.Require(scroller.Offset.Y >= scroller.ScrollBarMaximum.Y - 1 && log.SelectionStart == log.SelectionEnd,
            "The hover fixture did not begin at the real console end with an empty selection: " + beforeHoverAppend);
        QueueAppend("Public entry followed while the pointer only hovers");
        string afterHoverAppend = ScrollState();
        beforeMove = Interaction();
        window.MouseMove(textStart);
        string afterHoverMove = ScrollState();
        MacComprehensiveTests.Require(Interaction() == beforeMove, "Ordinary hover cancelled automatic following.");
        Layout(window);
        Mark("hover-append-layout-complete");
        MacComprehensiveTests.Require(scroller.Offset.Y >= scroller.Extent.Height - scroller.Viewport.Height - 1,
            $"Hover prevented automatic following at the end. Before append: {beforeHoverAppend}; immediately after append: {afterHoverAppend}; after hover: {afterHoverMove}; after layout: {ScrollState()}");

        log.Focus();
        log.CaretIndex = 0;
        log.SelectionStart = log.SelectionEnd = 0;
        Layout(window);
        Mark("keyboard-fixture-caret-layout-complete");
        scroller.Offset = new Vector(0, 40);
        Layout(window);
        QueueAppend("Public entry before keyboard selection");
        long beforeKey = Interaction();
        window.KeyPress(Key.End, RawInputModifiers.Shift, PhysicalKey.End, null);
        window.KeyRelease(Key.End, RawInputModifiers.Shift, PhysicalKey.End, null);
        selectedStart = log.SelectionStart; selectedEnd = log.SelectionEnd;
        MacComprehensiveTests.Require(Interaction() > beforeKey && selectedStart != selectedEnd,
            "Shift-End did not reach the console's real keyboard selection route.");
        Layout(window);
        MacComprehensiveTests.Require(log.SelectionStart == selectedStart && log.SelectionEnd == selectedEnd,
            "Pending output changed Shift-End selection.");
        Mark("keyboard-append-layout-complete");
    }
}
