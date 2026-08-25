using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace QrScanner;

/// <summary>Asks the compositor to omit the camera preview and factor from captures.</summary>
internal static class WindowCaptureProtection
{
    private const uint WdaExcludeFromCapture = 0x00000011;

    public static bool TryEnable(Window window)
    {
        ArgumentNullException.ThrowIfNull(window);
        nint handle = new WindowInteropHelper(window).Handle;
        try
        {
            return handle != 0 && SetWindowDisplayAffinity(handle, WdaExcludeFromCapture);
        }
        catch (Exception exception) when (exception is DllNotFoundException
            or EntryPointNotFoundException
            or BadImageFormatException)
        {
            return false;
        }
    }

    [DllImport("user32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetWindowDisplayAffinity(nint hWnd, uint dwAffinity);
}
