using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using KalynaArchiver;
using KalynaArchiver.Services;

internal static class WindowsGuiV502Tests
{
    internal static void RenderReferenceViews()
    {
        string repository = AppContext.BaseDirectory;
        while (!Directory.Exists(Path.Combine(repository, "KeepVaultMac")))
            repository = Directory.GetParent(repository)?.FullName
                ?? throw new InvalidOperationException("The reference source tree was not found.");
        string output = Path.Combine(repository, "work", "v502-gui-render");
        Directory.CreateDirectory(output);

        using var window = new MainWindow(new MemoryAppSettingsStore());
        var content = (FrameworkElement)window.Content;
        window.Content = null;
        var surface = new Border { Width = 1220, Height = 860, Background = window.Background,
            Resources = window.Resources, Child = content };
        NameScope.SetNameScope(surface, NameScope.GetNameScope(window));
        System.Windows.Documents.TextElement.SetFontFamily(surface, window.FontFamily);
        System.Windows.Documents.TextElement.SetFontSize(surface, window.FontSize);
        foreach (string language in new[] { "en", "de" })
        {
            window.LanguageBox.SelectedIndex = language == "en" ? 1 : 0;
            for (int tab = 0; tab < window.MainTabs.Items.Count; tab++)
            {
                window.MainTabs.SelectedIndex = tab;
                surface.Measure(new Size(1220, 860));
                surface.Arrange(new Rect(0, 0, 1220, 860));
                surface.UpdateLayout();
                var image = new RenderTargetBitmap(1220, 860, 96, 96, PixelFormats.Pbgra32);
                image.Render(surface);
                var encoder = new PngBitmapEncoder();
                encoder.Frames.Add(BitmapFrame.Create(image));
                using FileStream file = File.Create(Path.Combine(output, $"{language}-tab-{tab + 1}.png"));
                encoder.Save(file);
            }
            window.MainTabs.SelectedIndex = 0;
            window.CredentialPolicyHelp.IsExpanded = true;
            surface.UpdateLayout();
            ScrollViewer? scroll = null;
            DependencyObject? ancestor = window.CredentialPolicyHelp;
            while ((ancestor = VisualTreeHelper.GetParent(ancestor)) is not null)
                if (ancestor is ScrollViewer viewer) { scroll = viewer; break; }
            if (scroll is null) throw new InvalidOperationException("Creation scroll viewer is missing.");
            double helpTop = window.CredentialPolicyHelp.TransformToAncestor(scroll).Transform(new Point()).Y;
            scroll.ScrollToVerticalOffset(scroll.VerticalOffset + helpTop);
            surface.UpdateLayout();
            var helpImage = new RenderTargetBitmap(1220, 860, 96, 96, PixelFormats.Pbgra32);
            helpImage.Render(surface);
            var helpEncoder = new PngBitmapEncoder();
            helpEncoder.Frames.Add(BitmapFrame.Create(helpImage));
            using (FileStream file = File.Create(Path.Combine(output, $"{language}-create-help.png"))) helpEncoder.Save(file);
            window.CredentialPolicyHelp.IsExpanded = false;
            scroll.ScrollToTop();
            surface.UpdateLayout();
        }
        Console.WriteLine($"Rendered the unmodified production controls with empty synthetic fields to {output}.");
    }

    internal static void Run()
    {
        SecurityDialogReferenceTests.Run();
        using var window = new MainWindow(new MemoryAppSettingsStore());
        Require(window.Width == 1220 && window.Height == 860
            && window.MinWidth == 980 && window.MinHeight == 720, "Reference window dimensions changed.");
        Require(((SolidColorBrush)window.Background).Color == (Color)ColorConverter.ConvertFromString("#08101D"),
            "Reference page background changed.");
        Require(window.HeaderLogoImage.Source is not null && window.VersionText.Text == $"Version {MainWindow.ProductVersion}",
            "The header must show the reference logo and product version.");
        Require(window.CredentialPolicyHelpText.Text.Length > 500, "The password/PIN explanation is missing.");
        Require(window.ExtractPasswordBox.MaxLength == ContainerKeyDerivation.MaxCredentialCodeUnits
            && window.ExtractPinBox.MaxLength == ContainerKeyDerivation.MaxCredentialCodeUnits,
            "Extraction inputs must preserve the reference's technical credential limits.");
        Require(Grid.GetColumn((UIElement)window.CreatePasswordPanel) == 2, "Creation credentials must be in the right column.");
        CheckPathWatermarks(window);
        CheckOutputParentSelection(window);

        CheckWorker(window, window.CaptureEncryptionConsumer("unused.kzpaq", EncryptionSuite.Kalyna512_512, null));
        CheckWorker(window, window.CaptureDecryptionProducer("unused.kzpaq", creationCredentials: false));
        CheckWorker(window, window.CaptureDecryptionProducer("unused.kzpaq", creationCredentials: true));

        foreach ((string password, string pin) in new[] { ("", ""), ("short", "12"), (new string('p', 400), new string('4', 20)) })
        {
            window.ExtractPasswordBox.Password = password;
            window.ExtractPinBox.Password = pin;
            Invoke(window, "EnsurePasswordPresent");
        }
        window.ExtractPinBox.Password = "１２３４５６";
        ExpectValidationFailure(() => Invoke(window, "EnsurePasswordPresent"), "ASCII");

        window.CreatePasswordBox.Password = "prefix!428317$suffix-with-random-words";
        window.CreatePinBox.Password = "428317";
        window.CreatePinConfirmBox.Password = "428317";
        Require(window.PinPolicyStatusText.Text.Contains("password", StringComparison.OrdinalIgnoreCase),
            "The PIN preview must reject the complete PIN inside the password.");
        window.LanguageBox.SelectedIndex = 0;
        Require(window.PinPolicyStatusText.Text.Contains("Passwort", StringComparison.Ordinal)
            && window.CredentialPolicyHelpTitle.Text == "So werden Passwort und PIN geprüft",
            "German credential policy localization does not match the reference.");
        window.CreatePasswordBox.Password = string.Empty;
        Require(window.PinPolicyStatusText.Text.Contains("Passwort eingeben", StringComparison.Ordinal),
            "An incomplete password/PIN pair must never be shown as accepted.");

        window.CreatePinBox.Password = "428317";
        window.CreatePinConfirmBox.Password = "428317";
        window.ExtractPinBox.Password = "428317";
        window.Dispose();
        Require(window.CreatePinBox.Password.Length == 0 && window.CreatePinConfirmBox.Password.Length == 0
            && window.ExtractPinBox.Password.Length == 0, "Disposal retained PIN credentials.");
    }

    private static void CheckPathWatermarks(MainWindow window)
    {
        var fields = new[]
        {
            (Box: window.ArchivePathBox, Label: window.TargetArchiveLabel, English: @"C:\Path\to\archive(1).kzpaq", German: @"C:\Pfad\zu\archiv(1).kzpaq"),
            (Box: window.ExtractArchiveBox, Label: window.ArchiveFileLabel, English: @"C:\Path\to\archive.kzpaq", German: @"C:\Pfad\zum\Archiv.kzpaq"),
            (Box: window.OutputFolderBox, Label: window.OutputFolderLabel, English: @"C:\Path\to\new\output-folder", German: @"C:\Pfad\zum\neuen\Zielordner"),
            (Box: window.ErasePathBox, Label: window.EraseFileLabel, English: @"C:\Path\to\container.kzpaq", German: @"C:\Pfad\zum\Container.kzpaq"),
        };
        foreach (bool german in new[] { false, true })
        {
            window.LanguageBox.SelectedIndex = german ? 0 : 1;
            FlushBindings(window);
            foreach (var field in fields)
            {
                field.Box.ApplyTemplate();
                FlushBindings(window);
                string expected = german ? field.German : field.English;
                Require(MainWindow.GetWatermarkText(field.Box) == expected, "Path watermarks must track the selected language.");
                Require(System.Windows.Automation.AutomationProperties.GetHelpText(field.Box) == expected
                    && ReferenceEquals(System.Windows.Automation.AutomationProperties.GetLabeledBy(field.Box), field.Label),
                    "Path inputs must expose their localized hint and label to accessibility clients.");
                var watermark = (TextBlock?)field.Box.Template.FindName("Watermark", field.Box);
                Require(watermark is not null && watermark.Text == expected
                    && watermark.Visibility == Visibility.Visible && !watermark.IsHitTestVisible,
                    "Empty path inputs must show a non-interactive overlay.");
                Require(System.Windows.Automation.Peers.UIElementAutomationPeer.CreatePeerForElement(watermark!) is null,
                    "Decorative watermarks must not create duplicate accessibility controls.");
                var peer = new System.Windows.Automation.Peers.TextBoxAutomationPeer(field.Box);
                var value = (System.Windows.Automation.Provider.IValueProvider)peer.GetPattern(System.Windows.Automation.Peers.PatternInterface.Value)!;
                Require(field.Box.Text.Length == 0 && value.Value.Length == 0,
                    "A placeholder must never become input text or the accessibility value.");

                const string entered = "synthetic archive path";
                field.Box.Text = entered;
                FlushBindings(window);
                Require(watermark!.Visibility == Visibility.Collapsed && value.Value == entered,
                    "Entering a path must hide the watermark without altering its value.");
                window.LanguageBox.SelectedIndex = german ? 1 : 0;
                FlushBindings(window);
                Require(field.Box.Text == entered && value.Value == entered,
                    "Changing language must preserve an entered path byte-for-byte.");
                window.LanguageBox.SelectedIndex = german ? 0 : 1;
                field.Box.Clear();
                FlushBindings(window);
                Require(watermark.Visibility == Visibility.Visible && field.Box.Text.Length == 0,
                    "Clearing a path must restore the display-only hint.");
            }
        }
        window.LanguageBox.SelectedIndex = 1;
        FlushBindings(window);
    }

    private static void FlushBindings(MainWindow window) =>
        window.Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.DataBind, new Action(() => { }));

    private static void CheckOutputParentSelection(MainWindow window)
    {
        string directory = Path.Combine(Path.GetTempPath(), "keep-vault-output-parent-" + Guid.NewGuid().ToString("N"));
        string parent = Path.Combine(directory, "chosen-parent");
        Directory.CreateDirectory(parent);
        try
        {
            window.ExtractArchiveBox.Clear();
            window.ApplyDroppedPaths([parent], DropTarget.OutputFolder);
            Require(window.OutputFolderBox.Text == Path.Combine(parent, "extract(1)"), "Choosing a parent without an archive must suggest extract(1).");
            Directory.CreateDirectory(Path.Combine(parent, "archive(1)"));
            File.WriteAllText(Path.Combine(parent, "archive(2)"), "synthetic conflict");
            window.SetExtractArchivePath(Path.Combine(directory, "archive.kzpaq"));
            Require(window.OutputFolderBox.Text == Path.Combine(parent, "archive(3)"), "Changing the archive must preserve the selected parent and avoid conflicts.");
            window.OutputFolderBox.Text = Path.Combine(directory, "manual-output");
            window.SetExtractArchivePath(Path.Combine(directory, "other.kzpaq"));
            Require(window.OutputFolderBox.Text == Path.Combine(directory, "other(1)"), "An explicit path outside the selected parent must release that preference.");
        }
        finally
        {
            window.ExtractArchiveBox.Clear();
            window.OutputFolderBox.Clear();
            Directory.Delete(directory, recursive: true);
        }
    }

    private static void CheckWorker(MainWindow window, Func<Stream, CancellationToken, Task> operation)
    {
        Task.Run(async () =>
        {
            Require(!window.Dispatcher.CheckAccess(), "The stream regression must run on a real worker.");
            try
            {
                await operation(null!, CancellationToken.None).ConfigureAwait(false);
                throw new InvalidOperationException("The service accepted a null stream.");
            }
            catch (ArgumentNullException)
            {
                // Reaching the service guard proves no WPF control was read
                // from the background ZPAQ callback.
            }
        }).GetAwaiter().GetResult();
    }

    private static void Invoke(MainWindow window, string name)
    {
        try
        {
            typeof(MainWindow).GetMethod(name, BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(window, null);
        }
        catch (TargetInvocationException error) when (error.InnerException is { } inner)
        {
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(inner).Throw();
        }
    }

    private static void ExpectValidationFailure(Action action, string expected)
    {
        try { action(); }
        catch (InvalidOperationException error) when (error.Message.Contains(expected, StringComparison.Ordinal)) { return; }
        throw new InvalidOperationException("The GUI failed to report the expected credential validation error.");
    }

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
}
