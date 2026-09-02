using Avalonia;
using KalynaArchiver.Services;

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

        BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
    }

    public static AppBuilder BuildAvaloniaApp()
    {
        return AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont();
    }
}
