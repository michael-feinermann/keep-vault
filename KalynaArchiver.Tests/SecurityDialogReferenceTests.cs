using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Threading;
using KalynaArchiver.Gui;

internal static class SecurityDialogReferenceTests
{
    internal static void Run()
    {
        foreach (bool english in new[] { false, true })
        {
            string language = english ? "en" : "de";
            foreach ((string kind, MessageBoxButton buttons, MessageBoxImage image) in new[]
            {
                ("information", MessageBoxButton.OK, MessageBoxImage.Information),
                ("warning", MessageBoxButton.OK, MessageBoxImage.Warning),
                ("error", MessageBoxButton.OK, MessageBoxImage.Error),
                ("confirmation", MessageBoxButton.YesNo, MessageBoxImage.Warning),
            })
            {
                var dialog = new SecurityDialog("Keep Vault", english
                    ? "Synthetic message for the Windows dialog review. No archive or personal data is used."
                    : "Synthetische Meldung für die Windows-Dialogprüfung. Es werden kein Archiv und keine persönlichen Daten verwendet.",
                    english, buttons, image);
                bool confirmation = buttons == MessageBoxButton.YesNo;
                Require(dialog.Width == 520 && dialog.MinWidth == 420 && dialog.ResizeMode == ResizeMode.NoResize,
                    "Dialog dimensions and resize policy must match the Mac reference.");
                Require(((SolidColorBrush)dialog.Background).Color == (Color)ColorConverter.ConvertFromString("#0B1422"), "Dialog background must match the reference.");
                Require(dialog.WindowStartupLocation == WindowStartupLocation.CenterOwner && !dialog.ShowInTaskbar,
                    "Security dialogs must remain owner-centred and outside the taskbar.");
                Require(dialog.AcceptButton.IsDefault == !confirmation && dialog.AcceptButton.IsCancel == !confirmation,
                    "Enter/Escape defaults must not affirm a safety confirmation.");
                Require(!confirmation || dialog.CancelButton is { IsCancel: true, IsDefault: true },
                    "A safety confirmation must provide the default cancel button.");
                var surface = Detach(dialog);
                Layout(surface, 520, 205);
                Save(surface, language + "-" + kind, 1);
                dialog.Close();
                Require(!confirmation || dialog.Result == MessageBoxResult.No, "Closing a safety confirmation must never affirm it.");
            }

            string longText = string.Join('\n', Enumerable.Range(1, 140).Select(i =>
                $"{i}: {(english ? "Synthetic error detail" : "Synthetisches Fehlerdetail")} C:\\Test\\{new string('X', 130)}")) + "\nLAST-MARKER-7319";
            var longDialog = new SecurityDialog("Keep Vault", longText, english, MessageBoxButton.OK, MessageBoxImage.Error);
            var longSurface = Detach(longDialog);
            Layout(longSurface, 520, 545);
            var scrollBar = Descendants(longDialog.MessageBox).OfType<ScrollBar>()
                .First(bar => bar.Orientation == Orientation.Vertical);
            Require(scrollBar.Background is SolidColorBrush scrollbarBackground
                && scrollbarBackground.Color == (Color)ColorConverter.ConvertFromString("#091321"),
                "The dialog must use the existing dark application scrollbar style.");
            Require(longDialog.MessageBox.Text == longText && longDialog.MessageBox.IsReadOnly && !longDialog.MessageBox.IsUndoEnabled
                && !SpellCheck.GetIsEnabled(longDialog.MessageBox), "Full exception details must remain read-only without learned text or undo history.");
            Require(AutomationProperties.GetName(longDialog.MessageBox) == (english ? "Message details" : "Meldungsdetails"),
                "The accessible message label must follow DE/EN.");
            longDialog.MessageBox.Select(longText.Length - 16, 16);
            longDialog.MessageBox.ScrollToEnd(); longSurface.UpdateLayout();
            Require(longDialog.MessageBox.SelectedText == "LAST-MARKER-7319" && longDialog.MessageBox.VerticalOffset > 0,
                "The last message marker must remain selectable through the bounded scroll area.");
            Save(longSurface, language + "-long-error", 1);
            Layout(longSurface, 420, 300);
            longDialog.MessageBox.ScrollToEnd(); longSurface.UpdateLayout();
            Require(longDialog.AcceptButton.TransformToAncestor(longSurface).Transform(new Point()).Y
                + longDialog.AcceptButton.ActualHeight <= 300, "Long text must not push OK outside a small dialog.");
            Save(longSurface, language + "-long-error-minimum-150pct", 1.5);
            longDialog.Close();

            var cancel = new SecurityDialog("Keep Vault", "Synthetic confirmation", english, MessageBoxButton.YesNo, MessageBoxImage.Warning);
            cancel.CancelButton!.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            Require(cancel.Result == MessageBoxResult.No, "Explicit cancel must not affirm a confirmation.");
            var accept = new SecurityDialog("Keep Vault", "Synthetic confirmation", english, MessageBoxButton.YesNo, MessageBoxImage.Warning);
            accept.AcceptButton.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            Require(accept.Result == MessageBoxResult.Yes, "Only the explicit confirmation action may return Yes.");
        }
        RunModalLifecycle();
    }

    private static void RunModalLifecycle()
    {
        string evidenceDirectory = Path.Combine(RepositoryRoot(), "work", "v502-dialog-gui-review");
        Directory.CreateDirectory(evidenceDirectory);
        string evidencePath = Path.Combine(evidenceDirectory, $"modal-lifecycle-{DateTime.Now:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}.json");
        var records = new List<object>();
        foreach (bool english in new[] { false, true })
        foreach (string action in new[] { "close", "cancel", "accept" })
        {
            var owner = new Window { Title = "Keep Vault managed modal lifecycle test", Width = 620, Height = 200,
                WindowStartupLocation = WindowStartupLocation.CenterScreen,
                Content = new TextBlock { Text = "Synthetic component test. No archive or personal data is used.", Margin = new Thickness(20), TextWrapping = TextWrapping.Wrap } };
            var dialog = new SecurityDialog("Keep Vault synthetic safety confirmation", "Synthetic component message.", english,
                MessageBoxButton.YesNo, MessageBoxImage.Warning) { Owner = null };
            Exception? failure = null;
            bool rendered = false;
            bool? ownerEnabledBefore = null, ownerEnabledDuring = null, ownerEnabledAfter = null;
            bool? focusIsCancel = null, logicalFocusIsCancel = null, dialogActive = null;
            string? focusType = null, focusContent = null;
            bool? modalResult = null;
            var watchdog = new DispatcherTimer(DispatcherPriority.Send, dialog.Dispatcher) { Interval = TimeSpan.FromSeconds(8) };
            watchdog.Tick += (_, _) =>
            {
                failure ??= new TimeoutException("The synthetic modal dialog did not complete within eight seconds.");
                watchdog.Stop();
                dialog.Close();
            };
            try
            {
                owner.Show();
                owner.Activate();
                nint ownerHandle = new WindowInteropHelper(owner).Handle;
                ownerEnabledBefore = IsWindowEnabled(ownerHandle);
                Require(ownerEnabledBefore == true, "The generic owner must be enabled before ShowDialog.");
                dialog.Owner = owner;
                dialog.ContentRendered += (_, _) =>
                {
                    if (rendered) return;
                    rendered = true;
                    try
                    {
                        ownerEnabledDuring = IsWindowEnabled(ownerHandle);
                        dialogActive = dialog.IsActive;
                        IInputElement? focused = Keyboard.FocusedElement;
                        focusType = focused?.GetType().FullName;
                        focusContent = (focused as ContentControl)?.Content?.ToString();
                        focusIsCancel = ReferenceEquals(focused, dialog.CancelButton);
                        logicalFocusIsCancel = ReferenceEquals(FocusManager.GetFocusedElement(dialog), dialog.CancelButton);
                        Require(ownerEnabledDuring == false, "ShowDialog must disable its actual generic owner.");
                        Require(focusIsCancel == true, "The actual initial Keyboard.FocusedElement must be the cancel button.");
                        switch (action)
                        {
                            case "cancel": dialog.CancelButton!.RaiseEvent(new RoutedEventArgs(Button.ClickEvent)); break;
                            case "accept": dialog.AcceptButton.RaiseEvent(new RoutedEventArgs(Button.ClickEvent)); break;
                            default: dialog.Close(); break;
                        }
                    }
                    catch (Exception error) { failure = error; }
                    finally { if (dialog.IsVisible) dialog.Close(); }
                };
                watchdog.Start();
                modalResult = dialog.ShowDialog();
                watchdog.Stop();
                ownerEnabledAfter = IsWindowEnabled(ownerHandle);
                Require(rendered, "The actual dialog must reach ContentRendered.");
                Require(ownerEnabledAfter == true, "Closing the modal dialog must re-enable its generic owner.");
                if (failure is not null) throw failure;
                Require(dialog.Result == (action == "accept" ? MessageBoxResult.Yes : MessageBoxResult.No),
                    "Actual modal close/cancel/accept must preserve the safety result.");
            }
            catch (Exception error) { failure = error; }
            finally
            {
                watchdog.Stop();
                if (dialog.IsVisible) dialog.Close();
                owner.Close();
                records.Add(new { Language = english ? "en" : "de", Action = action, ContentRendered = rendered,
                    OwnerEnabledBefore = ownerEnabledBefore, OwnerEnabledDuring = ownerEnabledDuring, OwnerEnabledAfter = ownerEnabledAfter,
                    InitialKeyboardFocusIsCancel = focusIsCancel, InitialLogicalFocusIsCancel = logicalFocusIsCancel,
                    InitialDialogActive = dialogActive, InitialFocusType = focusType, InitialFocusContent = focusContent,
                    ShowDialogResult = modalResult, Result = dialog.Result.ToString(), Failure = failure?.ToString() });
                File.WriteAllText(evidencePath, JsonSerializer.Serialize(new { Scope = "Managed WPF modal component lifecycle; no OS keyboard input injected or proven.",
                    Runtime = Environment.Version.ToString(), Records = records }, new JsonSerializerOptions { WriteIndented = true }));
            }
            if (failure is not null) throw new InvalidOperationException("Synthetic WPF modal lifecycle failed; see " + evidencePath, failure);
        }
        Console.WriteLine("Managed modal lifecycle evidence: " + evidencePath);
    }

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("user32.dll", EntryPoint = "IsWindowEnabled")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowEnabled(nint window);

    private static Border Detach(SecurityDialog dialog)
    {
        var content = (UIElement)dialog.Content; dialog.Content = null;
        var surface = new Border { Child = content, Background = dialog.Background, Resources = dialog.Resources };
        System.Windows.Documents.TextElement.SetFontFamily(surface, dialog.FontFamily);
        System.Windows.Documents.TextElement.SetFontSize(surface, dialog.FontSize);
        return surface;
    }
    private static void Layout(FrameworkElement surface, double width, double height)
    {
        surface.Width = width; surface.Height = height;
        surface.Measure(new Size(width, height)); surface.Arrange(new Rect(0, 0, width, height)); surface.UpdateLayout();
    }
    private static void Save(FrameworkElement surface, string name, double scale)
    {
        string output = Path.Combine(RepositoryRoot(), "work", "v502-dialog-gui-render"); Directory.CreateDirectory(output);
        var bitmap = new RenderTargetBitmap((int)(surface.Width * scale), (int)(surface.Height * scale), 96 * scale, 96 * scale, PixelFormats.Pbgra32);
        bitmap.Render(surface);
        RenderEvidenceGuard.RequireUsable(bitmap, name);
        var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var file = File.Create(Path.Combine(output, name + ".png")); encoder.Save(file);
    }
    private static string RepositoryRoot()
    {
        string root = AppContext.BaseDirectory;
        while (!Directory.Exists(Path.Combine(root, "KeepVaultMac"))) root = Directory.GetParent(root)?.FullName
            ?? throw new InvalidOperationException("Repository was not found for dialog evidence.");
        return root;
    }
    private static IEnumerable<DependencyObject> Descendants(DependencyObject root)
    {
        for (int index = 0; index < VisualTreeHelper.GetChildrenCount(root); index++)
        {
            DependencyObject child = VisualTreeHelper.GetChild(root, index);
            yield return child;
            foreach (DependencyObject descendant in Descendants(child)) yield return descendant;
        }
    }
    private static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
}
