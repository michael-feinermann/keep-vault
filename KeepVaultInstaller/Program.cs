using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using KalynaArchiver.Services;
using KalynaArchiver.Signing;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        try
        {
            if (args is ["--verify", var source])
            {
                using VerifiedReleaseInventory inventory = Verify(source);
                Console.WriteLine("RESULT: TRUSTED - complete Windows 5.0.2 inventory verified.");
                return 0;
            }
            if (args is ["--test-copy", var sourceForTest, var destination])
            {
                Install(sourceForTest, destination, createShortcuts: false);
                Console.WriteLine("RESULT: INSTALLED - newly created directory verified.");
                return 0;
            }
            if (args.Length != 0) throw new ArgumentException("Unsupported installer argument.");
            return new Application().Run(new InstallerWindow(source => Install(source)));
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine("RESULT: BLOCKED - " + exception.Message);
            if (args.Length == 0) InstallerWindow.ShowStartupFailure(exception.Message);
            return 3;
        }
    }

    internal static VerifiedReleaseInventory Verify(string source)
    {
        var inventory = new VerifiedReleaseInventory(source, SigningTrustPolicy.HybridPolicy
            ?? throw new InvalidOperationException("The installer's pinned release policy is unavailable."));
        try
        {
            foreach (string native in IntegrityService.RequiredNativeTools)
                if (!File.Exists(Path.Combine(source, native))) throw new InvalidDataException("Missing required native component: " + native);
            foreach (ReleaseInventoryEntry entry in inventory.Document.Files)
            {
                string path = Path.Combine(source, entry.Path);
                if (entry.Path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || entry.Path.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                {
                    ReleaseExecutablePolicy.RequireTimestampedPe(path);
                    if (!IntegrityService.CheckFile(path, requireManifest: true).IsTrusted)
                        throw new System.Security.Cryptography.CryptographicException("Executable authentication failed: " + entry.Path);
                }
            }
            ReleaseExecutablePolicy.RequireProductVersions(source);
            return inventory;
        }
        catch { inventory.Dispose(); throw; }
    }

    internal static string Install(string source, string? destination = null, bool createShortcuts = true)
    {
        using VerifiedReleaseInventory package = Verify(Path.GetFullPath(source));
        using var directoryLeases = new DirectoryLeases();
        string installParent = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Keep Vault");
        if (destination is null)
        {
            string current = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            for (string? ancestor = current; !string.IsNullOrEmpty(ancestor); ancestor = Path.GetDirectoryName(ancestor))
                directoryLeases.Items.Add(VerifiedReleaseInventory.HoldDirectory(ancestor));
            foreach (string component in new[] { "Programs", "Keep Vault" })
            {
                current = Path.Combine(current, component);
                Directory.CreateDirectory(current);
                directoryLeases.Items.Add(VerifiedReleaseInventory.HoldDirectory(current));
            }
            destination = Path.Combine(installParent, "5.0.2-" + package.InventoryDigest[..12] + "-" + Guid.NewGuid().ToString("N")[..8]);
        }
        destination = Path.GetFullPath(destination);
        var shortcuts = createShortcuts ? new[]
        {
            (Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "Keep Vault.lnk"), "Keep Vault.exe"),
            (Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs), "Keep Vault.lnk"), "Keep Vault.exe"),
            (Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs), "QR-Scanner.lnk"), "QR-Scanner/QR-Scanner.exe")
        } : Array.Empty<(string, string)>();
        foreach ((string link, _) in shortcuts)
            if (File.Exists(link) || Directory.Exists(link))
                throw new IOException("Eine vorhandene Verknüpfung bleibt unverändert. Entfernen oder verschieben Sie sie vor der Installation. / An existing shortcut was preserved; remove or move it before installing: " + link);

        package.CopyToNewDirectory(destination);
        using VerifiedReleaseInventory installed = Verify(destination);
        if (installed.InventoryDigest != package.InventoryDigest) throw new IOException("The installed inventory differs from the source package.");
        BoundFileTransaction.WriteNewBatch(shortcuts.Select(shortcut =>
            (shortcut.Item1, CreateShortcutBytes(Path.Combine(destination, shortcut.Item2)))));
        return destination;
    }

    private sealed class DirectoryLeases : IDisposable
    {
        public List<IDisposable> Items { get; } = [];
        public void Dispose() { for (int index = Items.Count - 1; index >= 0; index--) Items[index].Dispose(); }
    }

    private static byte[] CreateShortcutBytes(string target)
    {
        object shellLink = Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("00021401-0000-0000-C000-000000000046"))!)!;
        System.Runtime.InteropServices.ComTypes.IStream? stream = null;
        try
        {
            var link = (IShellLinkW)shellLink;
            link.SetPath(target);
            link.SetWorkingDirectory(Path.GetDirectoryName(target)!);
            link.SetIconLocation(target, 0);
            link.SetDescription("Keep Vault 5.0.2");
            stream = SHCreateMemStream(0, 0) ?? throw new IOException("Cannot serialize the Windows shortcut in memory.");
            ((IPersistStream)shellLink).Save(stream, true);
            stream.Stat(out var info, 1);
            if (info.cbSize is <= 0 or > 65536) throw new IOException("Invalid Windows shortcut length.");
            stream.Seek(0, 0, 0);
            byte[] bytes = new byte[checked((int)info.cbSize)];
            nint count = Marshal.AllocHGlobal(sizeof(int));
            try
            {
                stream.Read(bytes, bytes.Length, count);
                if (Marshal.ReadInt32(count) != bytes.Length) throw new IOException("The Windows shortcut was truncated.");
                return bytes;
            }
            finally { Marshal.FreeHGlobal(count); }
        }
        finally
        {
            if (stream is not null) Marshal.FinalReleaseComObject(stream);
            Marshal.FinalReleaseComObject(shellLink);
        }
    }

    [DllImport("shlwapi.dll")]
    [return: MarshalAs(UnmanagedType.Interface)]
    private static extern System.Runtime.InteropServices.ComTypes.IStream SHCreateMemStream(nint bytes, uint size);

    [ComImport, Guid("00000109-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IPersistStream
    {
        void GetClassID(out Guid classId);
        [PreserveSig] int IsDirty();
        void Load(System.Runtime.InteropServices.ComTypes.IStream stream);
        void Save(System.Runtime.InteropServices.ComTypes.IStream stream, [MarshalAs(UnmanagedType.Bool)] bool clearDirty);
        void GetSizeMax(out long size);
    }

    [ComImport, Guid("000214F9-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IShellLinkW
    {
        void GetPath(nint path, int count, nint findData, uint flags);
        void GetIDList(out nint idList);
        void SetIDList(nint idList);
        void GetDescription(nint description, int count);
        void SetDescription([MarshalAs(UnmanagedType.LPWStr)] string description);
        void GetWorkingDirectory(nint directory, int count);
        void SetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] string directory);
        void GetArguments(nint arguments, int count);
        void SetArguments([MarshalAs(UnmanagedType.LPWStr)] string arguments);
        void GetHotkey(out short hotkey);
        void SetHotkey(short hotkey);
        void GetShowCmd(out int command);
        void SetShowCmd(int command);
        void GetIconLocation(nint path, int count, out int index);
        void SetIconLocation([MarshalAs(UnmanagedType.LPWStr)] string path, int index);
        void SetRelativePath([MarshalAs(UnmanagedType.LPWStr)] string path, uint reserved);
        void Resolve(nint window, uint flags);
        void SetPath([MarshalAs(UnmanagedType.LPWStr)] string path);
    }
}
