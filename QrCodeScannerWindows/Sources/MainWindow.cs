using System.Windows;
using System.Windows.Controls;
using System.Windows.Automation;
using System.Windows.Markup;
using System.Windows.Documents;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Runtime.InteropServices;
using AppLanguage = QrScanner.Language;

namespace QrScanner;

/// <summary>
/// The window, and everything arranged so a scanned value does not reach disk.
/// </summary>
/// <remarks>
/// The scanned value lives in one field and one text box. What is shown is the
/// escaped rendering; what the copy button hands over is the original. The text
/// box has its spell checker off, because the checker learns words into the
/// user's dictionary, and undo history off, because that history is another
/// copy of the value in a place nothing here controls.
///
/// What this app cannot prevent is written down in README.md rather than
/// quietly omitted.
/// </remarks>
internal sealed class MainWindow : Window
{
    private static Brush Muted => SystemColors.GrayTextBrush;
    private static Brush Good => SystemParameters.HighContrast ? SystemColors.ControlTextBrush : Brushes.ForestGreen;
    private static Brush Warn => SystemParameters.HighContrast ? SystemColors.ControlTextBrush : Brushes.DarkOrange;
    private static Brush Bad => SystemParameters.HighContrast ? SystemColors.ControlTextBrush : Brushes.Firebrick;

    private readonly RadioButton _germanButton = new() { Content = Strings.OwnName(AppLanguage.German), Width = 84, GroupName = "Language" };
    private readonly RadioButton _englishButton = new() { Content = Strings.OwnName(AppLanguage.English), Width = 84, GroupName = "Language" };
    private readonly TextBlock _languageLabel = new()
    {
        Foreground = Muted,
        VerticalAlignment = VerticalAlignment.Center,
        FontSize = 11,
        Margin = new Thickness(0, 0, 10, 0),
    };
    private readonly Image _preview = new() { Stretch = Stretch.Uniform };
    private readonly TextBlock _statusText = new() { TextWrapping = TextWrapping.Wrap, Foreground = Muted, FontSize = 13, FontWeight = FontWeights.Medium };
    private readonly TextBlock _captureProtectionText = new() { TextWrapping = TextWrapping.Wrap, Foreground = Bad, FontSize = 11 };
    private readonly TextBlock _noticesText = new() { TextWrapping = TextWrapping.Wrap, Foreground = Warn, FontSize = 11 };
    private readonly TextBox _valueBox;
    private readonly Button _copyButton = new() { MinWidth = 80, Padding = new Thickness(10, 4, 10, 4), IsEnabled = false, IsDefault = true };
    private readonly Button _rescanButton = new() { MinWidth = 100, Padding = new Thickness(10, 4, 10, 4), IsEnabled = false };
    private readonly VolatileClipboard _clipboard = new();

    private ScanSession? _session;
    private AppLanguage _language = Strings.FromCurrentCulture();
    private ScanOutcome? _outcome;
    private ScannerFailure? _failure;
    private string? _payload;
    private bool _copied;
    private bool _cleared;
    private bool _copyFailed;
    private bool _closed;
    private bool _captureProtectionAttempted;
    private bool _captureProtected;

    internal MainWindow()
    {
        _valueBox = new TextBox
        {
            IsReadOnly = true,
            AcceptsReturn = true,
            TextWrapping = TextWrapping.Wrap,
            Height = 120,
            Padding = new Thickness(6),
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
            FontFamily = new FontFamily("Consolas"),
            FontSize = 12,

            // The checker writes learned words into the user's dictionary, and
            // undo keeps its own copy of everything that was ever in the box.
            // Both are places a scanned factor would outlive this window.
            SpellCheck = { IsEnabled = false },
            IsUndoEnabled = false,
            MaxLength = PayloadInspector.MaximumLength,
        };
        DataObject.AddCopyingHandler(_valueBox, OnValueBoxCopying);

        Title = Strings.For(_language).WindowTitle;
        Width = 760;
        Height = 800;
        MinWidth = 520;
        MinHeight = 560;
        FontFamily = SystemFonts.MessageFontFamily;
        FontSize = 13;
        SetResourceReference(BackgroundProperty, SystemColors.ControlBrushKey);
        SetResourceReference(ForegroundProperty, SystemColors.ControlTextBrushKey);
        _valueBox.SetResourceReference(Control.BackgroundProperty, SystemColors.WindowBrushKey);
        _valueBox.SetResourceReference(Control.ForegroundProperty, SystemColors.WindowTextBrushKey);
        WindowStartupLocation = WindowStartupLocation.CenterScreen;

        _germanButton.Checked += (_, _) => { _language = AppLanguage.German; ApplyLanguage(); };
        _englishButton.Checked += (_, _) => { _language = AppLanguage.English; ApplyLanguage(); };

        _copyButton.Click += (_, _) => CopyPayload();
        _rescanButton.Click += (_, _) => Rescan();

        Content = BuildLayout();
        ApplyLanguage();

        SourceInitialized += (_, _) =>
        {
            _captureProtectionAttempted = true;
            _captureProtected = WindowCaptureProtection.TryEnable(this);
            ApplyLanguage();
        };
        Loaded += async (_, _) => await StartAsync();
        Closed += async (_, _) => await ShutDownAsync();
    }

    private UIElement BuildLayout()
    {
        // AppKit uses rounded, mutually exclusive 84-point language segments.
        // The WPF equivalent retains radio-button keyboard and UIA semantics.
        var segmentStyle = (Style)XamlReader.Parse("""
            <Style xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                   xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" TargetType="RadioButton">
              <Setter Property="Padding" Value="6,4"/>
              <Setter Property="HorizontalContentAlignment" Value="Center"/>
              <Setter Property="VerticalContentAlignment" Value="Center"/>
              <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="RadioButton">
                <Border x:Name="Frame" CornerRadius="4" BorderThickness="1"
                    Background="{DynamicResource {x:Static SystemColors.ControlBrushKey}}"
                    BorderBrush="{DynamicResource {x:Static SystemColors.ActiveBorderBrushKey}}" Padding="{TemplateBinding Padding}">
                  <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                </Border>
                <ControlTemplate.Triggers>
                  <Trigger Property="IsChecked" Value="True">
                    <Setter TargetName="Frame" Property="Background" Value="{DynamicResource {x:Static SystemColors.HighlightBrushKey}}"/>
                    <Setter Property="Foreground" Value="{DynamicResource {x:Static SystemColors.HighlightTextBrushKey}}"/>
                  </Trigger>
                  <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Frame" Property="BorderBrush" Value="{DynamicResource {x:Static SystemColors.HighlightBrushKey}}"/></Trigger>
                  <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="Frame" Property="BorderThickness" Value="2"/></Trigger>
                  <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.5"/></Trigger>
                </ControlTemplate.Triggers>
              </ControlTemplate></Setter.Value></Setter>
            </Style>
            """);
        _germanButton.Style = _englishButton.Style = segmentStyle;
        var languageRow = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        languageRow.Children.Add(_languageLabel); languageRow.Children.Add(_germanButton); languageRow.Children.Add(_englishButton);
        var buttons = new Grid { Margin = new Thickness(0, 12, 0, 0) };
        buttons.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        buttons.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        buttons.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        _copyButton.Margin = new Thickness(0, 0, 10, 0);
        buttons.Children.Add(_copyButton);
        Grid.SetColumn(_rescanButton, 1);
        buttons.Children.Add(_rescanButton);
        Grid.SetColumn(languageRow, 2); buttons.Children.Add(languageRow);

        var stack = new StackPanel();
        stack.Children.Add(new Border
        {
            Background = Brushes.Black,
            CornerRadius = new CornerRadius(8),
            Height = 430,
            Child = _preview,
        });
        stack.Children.Add(new ScrollViewer { Content = _statusText, MaxHeight = 40, Margin = new Thickness(0, 12, 0, 0),
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled });
        _valueBox.Margin = new Thickness(0, 12, 0, 0);
        stack.Children.Add(_valueBox);
        _noticesText.Margin = new Thickness(0, 12, 0, 0);
        stack.Children.Add(_noticesText);
        _captureProtectionText.Margin = new Thickness(0, 12, 0, 0);
        stack.Children.Add(_captureProtectionText);
        var root = new DockPanel { Margin = new Thickness(16) };
        DockPanel.SetDock(buttons, Dock.Bottom); root.Children.Add(buttons);
        root.Children.Add(new ScrollViewer {
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
            Content = stack,
        });
        return root;
    }

    private async Task StartAsync()
    {
        _statusText.Text = Strings.For(_language).RequestingCamera;
        var session = new ScanSession(SynchronizationContext.Current
            ?? throw new InvalidOperationException("The window has no dispatcher context."));
        session.Observed += OnObserved;
        session.Failed += OnFailed;
        session.PreviewUpdated += frame => _preview.Source = frame;
        _session = session;
        await session.StartAsync();
        if (!_closed && _failure is null)
        {
            _outcome = ScanOutcome.Searching;
            ApplyLanguage();
        }
    }

    private async Task ShutDownAsync()
    {
        // The value goes before the window does, and the clipboard entry with
        // it: a scan left on the clipboard because the window was closed early
        // is the one case the expiry timer cannot cover.
        _closed = true;
        _payload = null;
        _outcome = null;
        _failure = null;
        _valueBox.Clear();
        _preview.Source = null;
        _clipboard.ClearIfStillOurs();
        _clipboard.Dispose();

        ScanSession? session = _session;
        _session = null;
        if (session is not null)
        {
            await session.DisposeAsync();
        }
    }

    private void OnObserved(ScanOutcome outcome)
    {
        if (_closed)
        {
            return;
        }

        _outcome = outcome;
        _failure = null;

        if (outcome.Kind == ScanOutcomeKind.Accepted && outcome.Payload is { Length: > 0 } payload)
        {
            _payload = payload;
            _copied = false;
            _cleared = false;
            _valueBox.Text = PayloadInspector.DisplayText(payload);
            _preview.Source = null;
            _copyButton.IsEnabled = true;
            _rescanButton.IsEnabled = true;

            // Stop decoding while a result is on screen, so a second code
            // drifting into view cannot silently replace what the user is
            // looking at.
            _session?.Suspend();
        }

        ApplyLanguage();
    }

    private void OnFailed(ScannerFailure failure)
    {
        if (_closed)
        {
            return;
        }

        _failure = failure;
        _outcome = null;
        ApplyLanguage();
    }

    private void CopyPayload()
    {
        if (_payload is not { Length: > 0 } payload)
        {
            return;
        }

        try
        {
            _clipboard.Copy(payload, () =>
            {
                _cleared = true;
                _copied = false;
                _copyFailed = false;
                ApplyLanguage();
            });
        }
        catch (Exception exception) when (exception is ExternalException or InvalidOperationException)
        {
            _copyFailed = true;
            _copied = false;
            _cleared = false;
            ApplyLanguage();
            return;
        }

        _copied = true;
        _cleared = false;
        _copyFailed = false;
        ApplyLanguage();
    }

    private void Rescan()
    {
        _payload = null;
        _copied = false;
        _cleared = false;
        _copyFailed = false;
        _valueBox.Clear();
        _copyButton.IsEnabled = false;
        _rescanButton.IsEnabled = false;
        _clipboard.ClearIfStillOurs();
        _outcome = ScanOutcome.Searching;
        _session?.Resume();
        ApplyLanguage();
    }

    /// <summary>
    /// Copying out of the text box must hand over the payload, not its escaped
    /// rendering.
    /// </summary>
    /// <remarks>
    /// The box shows control characters as their code points so the user can
    /// see what is there. Ctrl+C would otherwise transfer that rendering, which
    /// is not what the code contained - and for a hex factor a silently altered
    /// value is a factor that will not open the archive.
    /// </remarks>
    private void OnValueBoxCopying(object sender, DataObjectCopyingEventArgs e)
    {
        if (_payload is not { Length: > 0 })
        {
            return;
        }

        e.Handled = true;
        e.CancelCommand();
        CopyPayload();
    }

    private void ApplyLanguage()
    {
        Strings strings = Strings.For(_language);
        Title = strings.WindowTitle;
        _languageLabel.Text = strings.LanguageLabel;
        _copyButton.Content = strings.CopyButton;
        _rescanButton.Content = strings.RescanButton;
        AutomationProperties.SetName(_valueBox, strings.ScannedValueLabel);
        AutomationProperties.SetName(_germanButton, strings.LanguageLabel + ": " + Strings.OwnName(AppLanguage.German));
        AutomationProperties.SetName(_englishButton, strings.LanguageLabel + ": " + Strings.OwnName(AppLanguage.English));
        _germanButton.IsChecked = _language == AppLanguage.German;
        _englishButton.IsChecked = _language == AppLanguage.English;
        _captureProtectionText.Text = _captureProtectionAttempted && !_captureProtected
            ? strings.ScreenCaptureUnavailable
            : string.Empty;
        _captureProtectionText.Visibility = _captureProtectionText.Text.Length == 0 ? Visibility.Collapsed : Visibility.Visible;

        if (_failure is { } failure)
        {
            _statusText.Text = failure.Kind == ScannerFailureKind.AccessDenied
                ? $"{failure.Message(strings)} {strings.CameraDeniedHint}"
                : failure.Message(strings);
            _statusText.Foreground = Bad;
            _noticesText.Text = string.Empty;
            _noticesText.Visibility = Visibility.Collapsed;
            return;
        }

        if (_copyFailed)
        {
            _statusText.Text = strings.ClipboardUnavailable;
            _statusText.Foreground = Bad;
        }
        else if (_cleared)
        {
            _statusText.Text = strings.ClipboardCleared;
            _statusText.Foreground = Muted;
        }
        else if (_copied)
        {
            _statusText.Text = strings.Copied((int)_clipboard.Lifetime.TotalSeconds);
            _statusText.Foreground = Good;
        }
        else if (_outcome is { } outcome)
        {
            _statusText.Text = strings.Describe(outcome);
            _statusText.Foreground = outcome.Kind switch
            {
                ScanOutcomeKind.Accepted => Good,
                ScanOutcomeKind.Conflict => Warn,
                _ => Muted,
            };
        }
        else
        {
            _statusText.Text = strings.RequestingCamera;
            _statusText.Foreground = Muted;
        }

        _noticesText.Text = _payload is { Length: > 0 } payload
            ? string.Join(" ", PayloadInspector.Notices(payload).Select(notice => notice.Message(strings)))
            : string.Empty;
        _noticesText.Visibility = _noticesText.Text.Length == 0 ? Visibility.Collapsed : Visibility.Visible;
    }
}
