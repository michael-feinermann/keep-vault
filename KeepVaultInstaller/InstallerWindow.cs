using System.Globalization;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;

// The macOS installer uses native confirmation, progress and result dialogs.
// Use the Windows system font, colours and controls for the same three states.
internal sealed class InstallerWindow : Window
{
    private enum Phase { Confirmation, Installing, Succeeded, Failed }

    private readonly Func<string, string> _installPackage;
    private readonly TextBlock _heading = new() { FontSize = 17, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap };
    private readonly TextBlock _description = new() { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 12, 0, 12) };
    private readonly TextBox _source = new() { Text = AppContext.BaseDirectory, IsReadOnly = true, Padding = new Thickness(6), IsUndoEnabled = false };
    private readonly TextBox _details = new()
    {
        IsReadOnly = true, AcceptsReturn = true, TextWrapping = TextWrapping.Wrap,
        Height = 240, Padding = new Thickness(8), FontSize = 13,
        VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
        HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
        IsUndoEnabled = false, SpellCheck = { IsEnabled = false },
    };
    private readonly Button _browse = new() { Margin = new Thickness(0, 8, 0, 0), Padding = new Thickness(12, 5, 12, 5), HorizontalAlignment = HorizontalAlignment.Left };
    private readonly Button _primary = new() { MinWidth = 90, Padding = new Thickness(12, 5, 12, 5), IsDefault = true };
    private readonly Button _cancel = new() { MinWidth = 90, Padding = new Thickness(12, 5, 12, 5), Margin = new Thickness(0, 0, 10, 0), IsCancel = true };
    private readonly ComboBox _languages = new() { ItemsSource = new[] { "Deutsch", "English" }, Width = 110, VerticalAlignment = VerticalAlignment.Center };
    private readonly StackPanel _body = new();
    private readonly Grid _buttons = new() { Margin = new Thickness(0, 16, 0, 0) };
    private bool _german = CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "de";
    private Phase _phase;
    private string _result = string.Empty;

    internal InstallerWindow(Func<string, string> installPackage)
    {
        _installPackage = installPackage;
        Title = "Keep Vault 5.0.2 · Setup";
        Width = 560; Height = 340; MinWidth = 540; MinHeight = 160;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        FontFamily = SystemFonts.MessageFontFamily; FontSize = 13;
        SetResourceReference(BackgroundProperty, SystemColors.ControlBrushKey);
        SetResourceReference(ForegroundProperty, SystemColors.ControlTextBrushKey);
        _details.SetResourceReference(Control.BackgroundProperty, SystemColors.WindowBrushKey);
        _details.SetResourceReference(Control.ForegroundProperty, SystemColors.WindowTextBrushKey);

        _languages.SelectedIndex = _german ? 0 : 1;
        _languages.SelectionChanged += (_, _) => { _german = _languages.SelectedIndex == 0; Localize(); };
        _buttons.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        _buttons.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        _buttons.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        _languages.HorizontalAlignment = HorizontalAlignment.Left;
        _buttons.Children.Add(_languages);
        Grid.SetColumn(_cancel, 1); _buttons.Children.Add(_cancel);
        Grid.SetColumn(_primary, 2); _buttons.Children.Add(_primary);
        _body.Children.Add(_heading); _body.Children.Add(_description);
        _body.Children.Add(_source); _body.Children.Add(_browse); _body.Children.Add(_details);
        var root = new DockPanel { Margin = new Thickness(20) };
        DockPanel.SetDock(_buttons, Dock.Bottom); root.Children.Add(_buttons);
        root.Children.Add(new ScrollViewer { Content = _body, VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled });
        Content = root;

        _browse.Click += (_, _) =>
        {
            var picker = new Microsoft.Win32.OpenFolderDialog { Title = _german ? "Vollständiges Keep-Vault-Paket wählen" : "Select the complete Keep Vault package" };
            if (picker.ShowDialog(this) == true) _source.Text = picker.FolderName;
        };
        _cancel.Click += (_, _) => Close();
        _primary.Click += async (_, _) =>
        {
            if (_phase is Phase.Succeeded or Phase.Failed) { Close(); return; }
            if (_phase != Phase.Confirmation) return;
            string source = _source.Text;
            _phase = Phase.Installing; Height = 160; Localize();
            try { ShowResult(true, await Task.Run(() => _installPackage(source))); }
            catch (Exception exception) { ShowResult(false, exception.Message); }
        };
        Closing += (_, e) => { if (_phase == Phase.Installing) e.Cancel = true; };
        Localize();
    }

    internal static bool NeedsScrollableDetails(string text) => text.Length > 400
        || text.Count(character => character is '\r' or '\n' or '\v' or '\f' or '\u0085' or '\u2028' or '\u2029') >= 6;

    internal void ShowResult(bool success, string details)
    {
        _phase = success ? Phase.Succeeded : Phase.Failed;
        _result = details;
        Width = NeedsScrollableDetails(details) ? 640 : 560;
        Height = NeedsScrollableDetails(details) ? 460 : 300;
        Localize();
        _details.ScrollToHome();
        _primary.Focus();
    }

    internal static void ShowStartupFailure(string details)
    {
        var window = new InstallerWindow(_ => throw new InvalidOperationException("Installation is not available in a failure dialog."));
        window.ShowResult(false, details);
        window.ShowDialog();
    }

    private void Localize()
    {
        bool confirmation = _phase == Phase.Confirmation;
        bool result = _phase is Phase.Succeeded or Phase.Failed;
        bool longDetails = result && NeedsScrollableDetails(_result);
        _heading.Text = _phase switch
        {
            Phase.Installing => _german ? "Paket prüfen und installieren …" : "Verifying and installing package …",
            Phase.Succeeded => _german ? "Installation abgeschlossen" : "Installation completed",
            Phase.Failed => _german ? "Installation angehalten" : "Installation stopped",
            _ => "Keep Vault 5.0.2",
        };
        _description.Text = confirmation
            ? (_german ? "Installiert Keep Vault und den separaten QR-Scanner für Ihr Benutzerkonto. Das vollständige signierte Paket wird vor und nach dem Kopieren geprüft. Vorhandene Installationen bleiben unverändert."
                : "Installs Keep Vault and the separate QR scanner for your user account. The complete signed package is verified before and after copying. Existing installations remain unchanged.")
            : longDetails
                ? (_german ? "Die Details kannst du im scrollbaren Feld unten lesen, markieren und kopieren."
                    : "You can read, select and copy the details in the scrollable field below.")
                : result ? _result : string.Empty;
        _description.Visibility = _phase == Phase.Installing ? Visibility.Collapsed : Visibility.Visible;
        _source.Visibility = _browse.Visibility = confirmation ? Visibility.Visible : Visibility.Collapsed;
        _details.Visibility = longDetails ? Visibility.Visible : Visibility.Collapsed;
        _details.Text = longDetails ? _result : string.Empty;
        _browse.Content = _german ? "Paketordner auswählen …" : "Choose package folder …";
        _primary.Content = result ? "OK" : _german ? "Installieren" : "Install";
        _primary.Visibility = _phase == Phase.Installing ? Visibility.Collapsed : Visibility.Visible;
        _cancel.Content = _german ? "Abbrechen" : "Cancel";
        _cancel.Visibility = confirmation ? Visibility.Visible : Visibility.Collapsed;
        AutomationProperties.SetName(_languages, _german ? "Sprache" : "Language");
        AutomationProperties.SetName(_source, _german ? "Paketordner" : "Package folder");
        AutomationProperties.SetName(_details, _german ? "Installationsdetails" : "Installation details");
        AutomationProperties.SetLiveSetting(_heading, AutomationLiveSetting.Polite);
    }
}
