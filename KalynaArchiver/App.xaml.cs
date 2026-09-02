using KalynaArchiver.Services;

namespace KalynaArchiver;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App : System.Windows.Application
{
    /// <summary>
    /// Same exit code the macOS launcher uses when the platform hardening a
    /// start depends on could not be established.
    /// </summary>
    internal const int StartupConfigurationErrorExitCode = 78;

    protected override void OnStartup(System.Windows.StartupEventArgs e)
    {
        // Mirrors KeepVaultMac/Program.cs: the hardening is a precondition for
        // starting, not a diagnostic. If it cannot be established the process
        // ends here, before any window, native library or key material loads.
        try
        {
            ProcessHardening.Apply();
        }
        catch (Exception)
        {
            const string title = "Keep Vault konnte nicht sicher gestartet werden";
            const string message =
                "Die erforderlichen Windows-Schutzmaßnahmen konnten nicht vollständig aktiviert werden. "
                + "Keep Vault wird beendet, bevor die Benutzeroberfläche oder Schlüssel geladen werden.";
            try
            {
                System.Windows.MessageBox.Show(
                    message,
                    title,
                    System.Windows.MessageBoxButton.OK,
                    System.Windows.MessageBoxImage.Error);
            }
            catch (Exception)
            {
                Console.Error.WriteLine(title + ". " + message);
            }

            Environment.Exit(StartupConfigurationErrorExitCode);
            return;
        }

        DispatcherUnhandledException += (_, args) =>
        {
            System.Windows.MessageBox.Show(
                args.Exception.Message,
                $"{ProductInfo.Name} - Startfehler",
                System.Windows.MessageBoxButton.OK,
                System.Windows.MessageBoxImage.Error);
            args.Handled = true;
            Shutdown(1);
        };

        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            if (args.ExceptionObject is Exception exception)
            {
                _ = exception;
            }
        };

        base.OnStartup(e);
    }
}
