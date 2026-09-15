using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Automation.Peers;
using System.Windows.Automation.Provider;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;

internal static class InstallerGuiReferenceTests
{
    internal static void Run()
    {
        Require(!InstallerWindow.NeedsScrollableDetails(new string('x', 400)), "400 UTF-16 units must retain the short result view.");
        Require(InstallerWindow.NeedsScrollableDetails(new string('x', 401)), "401 UTF-16 units must use the details viewport.");
        Require(!InstallerWindow.NeedsScrollableDetails(string.Join('\n', Enumerable.Repeat("row", 6))), "Six lines must retain the short result view.");
        Require(InstallerWindow.NeedsScrollableDetails(string.Join('\n', Enumerable.Repeat("row", 7))), "Seven lines must use the details viewport.");
        Require(InstallerWindow.NeedsScrollableDetails(string.Join('\r', Enumerable.Repeat("row", 7))), "Mac-style line endings must use the details viewport.");
        Require(InstallerWindow.NeedsScrollableDetails(string.Join('\u2028', Enumerable.Repeat("row", 7))), "Unicode line separators must use the details viewport.");
        Require(InstallerWindow.NeedsScrollableDetails(string.Concat(Enumerable.Repeat("😀", 201))), "The threshold must count UTF-16, not graphemes.");

        var window = new InstallerWindow(_ => throw new InvalidOperationException("GUI tests must never install a package."));
        var content = (UIElement)window.Content;
        window.Content = null;
        var surface = new Border { Background = window.Background, Child = content };
        System.Windows.Documents.TextElement.SetFontFamily(surface, window.FontFamily);
        System.Windows.Documents.TextElement.SetFontSize(surface, window.FontSize);
        var languages = Field<ComboBox>(window, "_languages");
        var details = Field<TextBox>(window, "_details");
        var heading = Field<TextBlock>(window, "_heading");
        var primary = Field<Button>(window, "_primary");
        foreach (bool german in new[] { false, true })
        {
            languages.SelectedIndex = german ? 0 : 1;
            string lang = german ? "de" : "en";
            string longText = string.Join('\n', Enumerable.Range(0, 160).Select(i => $"{i}: {(german ? "Synthetischer Fehlerpfad" : "Synthetic failure path")} C:\\Test\\{new string('X', 160)}")) + "\nLAST-MARKER-7319";
            window.ShowResult(false, longText);
            Layout(surface, 640, 440);
            Require(details.Visibility == Visibility.Visible && details.ActualHeight == 240, "Long installer details must remain bounded at 240 pixels.");
            Require(details.IsReadOnly && !details.IsUndoEnabled && !SpellCheck.GetIsEnabled(details), "The installer details must be read-only without learned text or undo storage.");
            Require(details.Text == longText, "The complete result must survive display unchanged.");
            Require(AutomationProperties.GetName(details) == (german ? "Installationsdetails" : "Installation details"), "The accessible details name must follow DE/EN.");
            var peer = new TextBoxAutomationPeer(details);
            var value = (IValueProvider)peer.GetPattern(PatternInterface.Value);
            Require(value.IsReadOnly && value.Value == longText, "UIA must expose the complete read-only result.");
            details.Select(longText.Length - 16, 16);
            details.ScrollToEnd(); surface.UpdateLayout();
            Require(details.SelectedText.EndsWith("LAST-MARKER-7319", StringComparison.Ordinal) && details.VerticalOffset > 0,
                "The last marker must remain selectable and scrollable.");
            Save(surface, lang + "-installer-long", 640, 440);
            Layout(surface, window.MinWidth - 16, 300);
            Require(primary.TransformToAncestor(surface).Transform(new Point()).Y + primary.ActualHeight <= 300,
                "The installer OK button must remain available at minimum width and a small viewport.");
            window.ShowResult(true, "C:\\Synthetic\\Keep Vault 5.0.2");
            Layout(surface, 560, 300);
            Require(details.Visibility == Visibility.Collapsed, "Short installation results must be directly readable.");
            string before = heading.Text;
            languages.SelectedIndex = german ? 1 : 0;
            Require(heading.Text != before && heading.Text == (german ? "Installation completed" : "Installation abgeschlossen"),
                "Changing language must retranslate an already displayed completion.");
            languages.SelectedIndex = german ? 0 : 1;
            Save(surface, lang + "-installer-short", 560, 300);
            window.ShowResult(false, "Synthetic test failure");
            before = heading.Text;
            languages.SelectedIndex = german ? 1 : 0;
            Require(heading.Text != before, "Changing language must retranslate an already displayed failure.");
        }
        window.Close();
    }

    private static T Field<T>(object value, string name) => (T)value.GetType().GetField(name, BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(value)!;
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
    private static void Require(bool condition, string reason) { if (!condition) throw new InvalidOperationException(reason); }
}
