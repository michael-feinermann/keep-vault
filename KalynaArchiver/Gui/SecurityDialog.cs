using System.Windows;
using System.Windows.Controls;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Automation;
using KalynaArchiver.Services;
using Button = System.Windows.Controls.Button;
using TextBox = System.Windows.Controls.TextBox;
using Brush = System.Windows.Media.Brush;
using Color = System.Windows.Media.Color;
using Brushes = System.Windows.Media.Brushes;
using ColorConverter = System.Windows.Media.ColorConverter;
using FontFamily = System.Windows.Media.FontFamily;
using HorizontalAlignment = System.Windows.HorizontalAlignment;
using Orientation = System.Windows.Controls.Orientation;

namespace KalynaArchiver.Gui;

// Matches KeepVaultMac/Gui/SecurityDialog.cs. Windows retains its explicit
// cancel-by-default policy for destructive confirmations and caps long text.
internal sealed class SecurityDialog : Window
{
    internal Button AcceptButton { get; }
    internal Button? CancelButton { get; }
    internal TextBox MessageBox { get; }
    internal MessageBoxResult Result { get; private set; }

    internal SecurityDialog(string title, string message, bool english,
        MessageBoxButton buttons, MessageBoxImage image, MessageBoxResult defaultResult = MessageBoxResult.No)
    {
        if (buttons is not (MessageBoxButton.OK or MessageBoxButton.YesNo))
            throw new ArgumentOutOfRangeException(nameof(buttons), "Only informational and safety-confirmation dialogs are supported.");
        bool confirmation = buttons == MessageBoxButton.YesNo;
        Result = confirmation ? MessageBoxResult.No : MessageBoxResult.OK;
        Title = title;
        Width = 520; MinWidth = 420;
        SizeToContent = SizeToContent.Height;
        MaxHeight = Math.Max(240, Math.Min(680, SystemParameters.WorkArea.Height - 60));
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;
        Background = ColorBrush("#0B1422");
        FontFamily = new FontFamily("/Keep Vault;component/Assets/Fonts/#Inter");
        FontSize = 14;
        Resources.MergedDictionaries.Add(new ResourceDictionary
        {
            Source = new Uri("/Keep Vault;component/Gui/ReferenceScrollBar.xaml", UriKind.Relative),
        });

        var template = (ControlTemplate)XamlReader.Parse("""
            <ControlTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" TargetType="Button">
              <Border x:Name="Frame" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                  BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="9" Padding="{TemplateBinding Padding}">
                <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center" RecognizesAccessKey="True"/>
              </Border>
              <ControlTemplate.Triggers>
                <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Frame" Property="Opacity" Value="0.9"/></Trigger>
                <Trigger Property="IsPressed" Value="True"><Setter TargetName="Frame" Property="Opacity" Value="0.8"/></Trigger>
                <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="Frame" Property="BorderBrush" Value="#F3F7FB"/></Trigger>
                <Trigger Property="IsEnabled" Value="False"><Setter TargetName="Frame" Property="Opacity" Value="0.45"/></Trigger>
              </ControlTemplate.Triggers>
            </ControlTemplate>
            """);
        AcceptButton = MakeButton(confirmation ? (english ? "Continue" : "Fortfahren") : "OK",
            confirmation ? "#A33A4B" : "#5DE4EC", confirmation ? "#FFFFFF" : "#04121B",
            confirmation ? "#D65D6E" : "#43D8E5", template);
        AcceptButton.IsDefault = !confirmation || defaultResult == MessageBoxResult.Yes;
        AcceptButton.IsCancel = !confirmation;
        AcceptButton.Click += (_, _) => { Result = confirmation ? MessageBoxResult.Yes : MessageBoxResult.OK; Close(); };
        var actions = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        if (confirmation)
        {
            CancelButton = MakeButton(english ? "Cancel" : "Abbrechen", "#17263A", "#E8EEF6", "#31445D", template);
            CancelButton.Margin = new Thickness(0, 0, 8, 0);
            CancelButton.IsDefault = !AcceptButton.IsDefault;
            CancelButton.IsCancel = true;
            CancelButton.Click += (_, _) => Close();
            actions.Children.Add(CancelButton);
        }
        actions.Children.Add(AcceptButton);

        string accent = image == MessageBoxImage.Error ? "#F29AA6"
            : confirmation || image == MessageBoxImage.Warning ? "#F2BD55" : "#5DE4EC";
        // A read-only TextBox keeps arbitrary errors selectable and scrollable,
        // with the same borderless 14-point body as the reference TextBlock.
        MessageBox = new TextBox
        {
            Text = message, IsReadOnly = true, IsUndoEnabled = false,
            SpellCheck = { IsEnabled = false }, AcceptsReturn = true,
            TextWrapping = TextWrapping.Wrap, Background = Brushes.Transparent,
            Foreground = ColorBrush("#E8EEF6"), BorderThickness = new Thickness(0), Padding = new Thickness(0),
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
            MaxHeight = 400, MaxWidth = 470,
            HorizontalAlignment = HorizontalAlignment.Stretch,
            SelectionBrush = ColorBrush("#287C8A"),
        };
        AutomationProperties.SetName(MessageBox, english ? "Message details" : "Meldungsdetails");
        var layout = new Grid();
        layout.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        layout.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        layout.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        layout.Children.Add(new Border { Width = 46, Height = 5, CornerRadius = new CornerRadius(3),
            Background = ColorBrush(accent), HorizontalAlignment = HorizontalAlignment.Left });
        MessageBox.Margin = new Thickness(0, 15, 0, 15);
        Grid.SetRow(MessageBox, 1); layout.Children.Add(MessageBox);
        Grid.SetRow(actions, 2); layout.Children.Add(actions);
        Content = new Border { Padding = new Thickness(22), Child = layout };
        SourceInitialized += (_, _) => WindowProtection.TryExcludeFromCapture(this);
        Loaded += (_, _) => (CancelButton?.IsDefault == true ? CancelButton : AcceptButton).Focus();
    }

    private static Button MakeButton(string label, string background, string foreground, string border, ControlTemplate template) => new()
    {
        Content = label, MinWidth = 105, MinHeight = 38, Padding = new Thickness(16, 8, 16, 8),
        Background = ColorBrush(background), Foreground = ColorBrush(foreground), BorderBrush = ColorBrush(border),
        BorderThickness = new Thickness(1), FontWeight = FontWeights.SemiBold, Template = template,
        HorizontalContentAlignment = HorizontalAlignment.Center,
    };

    private static Brush ColorBrush(string hex)
    {
        var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex)); brush.Freeze(); return brush;
    }
}

// Preserve the existing handlers' MessageBoxResult checks and their injected
// credential-error hook while presenting the reference's actual dialog design.
internal static class ReferenceMessageBox
{
    internal static MessageBoxResult Show(Window owner, string message, string title,
        MessageBoxButton buttons, MessageBoxImage image, MessageBoxResult defaultResult = MessageBoxResult.No)
    {
        bool english = owner is MainWindow main
            && (main.LanguageBox.SelectedItem as ComboBoxItem)?.Tag as string == "en";
        var dialog = new SecurityDialog(title, message, english, buttons, image, defaultResult) { Owner = owner, FontFamily = owner.FontFamily };
        dialog.ShowDialog();
        return dialog.Result;
    }
}
