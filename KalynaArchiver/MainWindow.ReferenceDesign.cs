using System.Reflection;
using System.IO;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using KalynaArchiver.Services;
using Brush = System.Windows.Media.Brush;

namespace KalynaArchiver;

public sealed partial class MainWindow
{
    public static readonly DependencyProperty WatermarkTextProperty = DependencyProperty.RegisterAttached(
        "WatermarkText", typeof(string), typeof(MainWindow), new PropertyMetadata(string.Empty));

    public static string GetWatermarkText(DependencyObject element) => (string)element.GetValue(WatermarkTextProperty);

    public static void SetWatermarkText(DependencyObject element, string value) =>
        element.SetValue(WatermarkTextProperty, value);

    private string _eraseStatusKey = "eraseNotAnalyzed";
    private string? _extractOutputParentDirectory;
    private static readonly Brush ReferenceWarningBrush = ReferenceBrush("#F2BD55");
    private static readonly Brush ReferenceSuccessBrush = ReferenceBrush("#7EE2B8");
    private static readonly Brush ReferenceErrorBrush = ReferenceBrush("#F29AA6");
    private static readonly Brush ReferenceAccentBrush = ReferenceBrush("#5DE4EC");

    private static Brush ReferenceBrush(string color)
    {
        var brush = (SolidColorBrush)new BrushConverter().ConvertFromString(color)!;
        brush.Freeze();
        return brush;
    }

    internal static string ProductVersion
    {
        get
        {
            Assembly assembly = typeof(MainWindow).Assembly;
            string? version = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
            return version?.Split('+')[0] ?? assembly.GetName().Version?.ToString(3) ?? string.Empty;
        }
    }

    // Matches the reference: hiding/minimizing shields secrets, while ordinary
    // deactivation keeps the drag-and-drop target usable.
    private void UpdatePrivacyShield()
    {
        PrivacyShield.Visibility = WindowState == WindowState.Minimized || !IsVisible
            ? Visibility.Visible : Visibility.Collapsed;
    }

    private void ErasePathBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        if (!_componentsReady) return;
        EraseConfirmBox.IsChecked = false;
        if (_eraseStatusKey != "eraseCompleted" || !string.IsNullOrEmpty(ErasePathBox.Text))
            SetEraseStatus("eraseNotAnalyzed");
    }

    private void SetEraseAnalysis(CryptoEraseAnalysis analysis) =>
        SetEraseStatus(!analysis.Exists ? "eraseMissing"
            : analysis.IsEncryptedContainer ? "eraseEncryptedDetected" : "erasePlainDetected");

    private void SetEraseStatus(string key)
    {
        _eraseStatusKey = key;
        RenderEraseStatus();
    }

    private void RenderEraseStatus()
    {
        EraseStatusText.Text = T(_eraseStatusKey);
        EraseHardwareNoticeText.Text = T("eraseHardwareNotice");
    }

    private void SelectExtractOutputParent(string parentDirectory)
    {
        string output = SuggestOutputFolderPath(ExtractArchiveBox.Text, parentDirectory);
        _extractOutputParentDirectory = Path.GetFullPath(parentDirectory.Trim());
        OutputFolderBox.Text = output;
    }

    private string SuggestCurrentOutputFolderPath(string archivePath) =>
        _extractOutputParentDirectory is null
            ? SuggestOutputFolderPath(archivePath)
            : SuggestOutputFolderPath(archivePath, _extractOutputParentDirectory);

    private void OutputFolderBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        if (_extractOutputParentDirectory is null) return;
        string? parent = null;
        try
        {
            if (!string.IsNullOrWhiteSpace(OutputFolderBox.Text))
                parent = Path.GetDirectoryName(Path.GetFullPath(OutputFolderBox.Text.Trim()));
        }
        catch (Exception error) when (error is ArgumentException or IOException or NotSupportedException) { }
        if (!string.Equals(parent is null ? null : Path.TrimEndingDirectorySeparator(parent),
            Path.TrimEndingDirectorySeparator(_extractOutputParentDirectory), StringComparison.OrdinalIgnoreCase))
            _extractOutputParentDirectory = null;
    }

    internal static string SuggestOutputFolderPath(string archivePath, string parentDirectory)
    {
        string parent = Path.GetFullPath(parentDirectory.Trim());
        if (!Directory.Exists(parent)) throw new DirectoryNotFoundException(parent);
        string stem = string.IsNullOrWhiteSpace(archivePath)
            ? "extract" : Path.GetFileNameWithoutExtension(archivePath.Trim());
        return BuildNumberedDirectoryPath(parent, string.IsNullOrWhiteSpace(stem) ? "extract" : stem);
    }
}

// A display-only hint: the example path never enters TextBox.Text or its UIA value.
public sealed class ReferencePathWatermarkConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        bool german = string.Equals(value as string, "de", StringComparison.Ordinal);
        return (parameter as string, german) switch
        {
            ("target", true) => @"C:\Pfad\zu\archiv(1).kzpaq",
            ("target", false) => @"C:\Path\to\archive(1).kzpaq",
            ("archive", true) => @"C:\Pfad\zum\Archiv.kzpaq",
            ("archive", false) => @"C:\Path\to\archive.kzpaq",
            ("output", true) => @"C:\Pfad\zum\neuen\Zielordner",
            ("output", false) => @"C:\Path\to\new\output-folder",
            ("erase", true) => @"C:\Pfad\zum\Container.kzpaq",
            ("erase", false) => @"C:\Path\to\container.kzpaq",
            _ => string.Empty,
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException("Path watermarks are display-only.");
}

public sealed class ReferenceWatermarkTextBlock : System.Windows.Controls.TextBlock
{
    // The actual input exposes this text through HelpText and its existing label.
    // The decorative overlay must not become a second screen-reader control.
    protected override System.Windows.Automation.Peers.AutomationPeer OnCreateAutomationPeer() => null!;
}
