using Avalonia;
using KalynaArchiver.Services;
using KalynaArchiver.Gui;

namespace KalynaArchiver;

internal static class Program
{
    internal const int StartupConfigurationErrorExitCode = 78;

    [STAThread]
    public static void Main(string[] args)
    {
        try
        {
            MacProcessHardening.Apply();
        }
        catch (Exception)
        {
            const string title = "Keep Vault konnte nicht sicher gestartet werden";
            const string message =
                "Die erforderlichen macOS-Schutzmaßnahmen konnten nicht vollständig aktiviert werden. "
                + "Keep Vault wird beendet, bevor die Benutzeroberfläche oder Schlüssel geladen werden.";
            try
            {
                MacNativeAlert.ShowCritical(title, message);
            }
            catch (Exception)
            {
                Console.Error.WriteLine(title + ". " + message);
            }

            Environment.Exit(StartupConfigurationErrorExitCode);
            return;
        }

        try
        {
            // Selection has no side effects. The actual audit fixture/scopes
            // remain unavailable until MainWindow passes normal integrity.
            ReleaseAuditSession.SelectForThisProcess(args);
        }
        catch (ArgumentException)
        {
            const string message = "The release audit accepts only a fixed case identifier, no paths, providers or extra options.";
            try { MacNativeAlert.ShowCritical("Keep Vault release audit", message); }
            catch { Console.Error.WriteLine(message); }
            Environment.Exit(StartupConfigurationErrorExitCode);
            return;
        }

        BuildAvaloniaApp().StartWithClassicDesktopLifetime(ReleaseAuditSession.Current is null ? args : []);
    }

    public static AppBuilder BuildAvaloniaApp()
    {
        return AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont();
    }
}
