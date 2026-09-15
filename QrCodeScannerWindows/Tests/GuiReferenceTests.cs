using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace QrScanner.Tests;

internal static class GuiReferenceTests
{
    internal static void Run(Action<bool, string> expect)
    {
        var window = new MainWindow();
        // Detach and measure production controls without showing a native
        // window: Loaded must never request camera access during these tests.
        var content = (UIElement)window.Content; window.Content = null;
        var surface = new Border { Background = window.Background, Child = content };
        System.Windows.Documents.TextElement.SetFontFamily(surface, window.FontFamily);
        System.Windows.Documents.TextElement.SetFontSize(surface, window.FontSize);
        try
        {
            expect(window.Width == 760 && window.Height == 800, "scanner window matches the Mac reference dimensions");
            var preview = Field<Image>(window, "_preview");
            expect(((Border)preview.Parent).Height == 430, "scanner preview stays 430 pixels high");
            var value = Field<TextBox>(window, "_valueBox");
            var copy = Field<Button>(window, "_copyButton");
            var rescan = Field<Button>(window, "_rescanButton");
            var german = Field<RadioButton>(window, "_germanButton");
            var english = Field<RadioButton>(window, "_englishButton");
            expect(german.Width == 84 && english.Width == 84, "language segments retain the reference width");
            foreach (Language language in new[] { Language.English, Language.German })
            {
                (language == Language.German ? german : english).IsChecked = true;
                string payload = string.Join('\n', Enumerable.Range(0, 60).Select(index => $"Synthetic-{index}-" + new string('X', 30))) + "\nLAST-MARKER-7319";
                Invoke(window, "OnObserved", ScanOutcome.Accepted(payload, CorroborationKind.MatchingCodes, 2));
                Layout(surface, 760, 800);
                string originalDisplay = value.Text;
                expect(value.IsReadOnly && !value.IsUndoEnabled && !SpellCheck.GetIsEnabled(value), "scanner result retains privacy-sensitive text settings");
                expect(value.ActualHeight == 120 && value.VerticalScrollBarVisibility == ScrollBarVisibility.Auto,
                    "long scan results use an internal 120-pixel scroll area");
                expect(copy.IsEnabled && rescan.IsEnabled && copy.IsDefault, "confirmed result enables actions with Enter bound to Copy");
                expect(AutomationProperties.GetName(value) == Strings.For(language).ScannedValueLabel, "the result accessibility label follows the selected language");
                value.Select(value.Text.Length - 16, 16); value.ScrollToEnd(); surface.UpdateLayout();
                expect(value.VerticalOffset > 0 && value.SelectedText.EndsWith("LAST-MARKER-7319", StringComparison.Ordinal),
                    "the final decoded marker is selectable through the internal scroll area");
                Save(surface, language == Language.German ? "de-scanner-result" : "en-scanner-result", 760, 800);
                Layout(surface, window.MinWidth - 16, window.MinHeight - 40);
                foreach (FrameworkElement control in new FrameworkElement[] { copy, rescan, german, english })
                {
                    Point p = control.TransformToAncestor(surface).Transform(new Point());
                    expect(p.X >= 0 && p.Y >= 0 && p.X + control.ActualWidth <= surface.Width + 0.1 && p.Y + control.ActualHeight <= surface.Height + 0.1,
                        "scanner actions and language controls remain reachable at minimum window size");
                }
                Save(surface, language == Language.German ? "de-scanner-minimum" : "en-scanner-minimum", (int)surface.Width, (int)surface.Height);
                (language == Language.German ? english : german).IsChecked = true;
                expect(value.Text == originalDisplay && Field<string>(window, "_payload") == payload,
                    "changing language preserves the decoded payload and escaped display exactly");
                Invoke(window, "Rescan");
                expect(value.Text.Length == 0 && !copy.IsEnabled && !rescan.IsEnabled, "rescan clears displayed data and disables stale actions");
                expect(Field<object?>(window, "_session") is null, "GUI regression never starts a camera session");
            }
        }
        finally { ((Task)Invoke(window, "ShutDownAsync")!).GetAwaiter().GetResult(); window.Close(); }
    }

    private static T Field<T>(object target, string name) => (T)target.GetType().GetField(name, BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(target)!;
    private static object? Invoke(object target, string name, params object[] args) => target.GetType().GetMethod(name, BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(target, args);
    private static void Layout(FrameworkElement surface, double width, double height)
    {
        surface.Width = width; surface.Height = height;
        surface.Measure(new Size(width, height)); surface.Arrange(new Rect(0, 0, width, height)); surface.UpdateLayout();
    }
    private static void Save(FrameworkElement surface, string name, int width, int height)
    {
        Layout(surface, width, height);
        string root = AppContext.BaseDirectory;
        while (!Directory.Exists(Path.Combine(root, "KeepVaultMac"))) root = Directory.GetParent(root)?.FullName
            ?? throw new InvalidOperationException("Repository was not found for synthetic GUI evidence.");
        string output = Path.Combine(root, "work", "v502-secondary-gui-render"); Directory.CreateDirectory(output);
        var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32); bitmap.Render(surface);
        var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var file = File.Create(Path.Combine(output, name + ".png")); encoder.Save(file);
    }
}
