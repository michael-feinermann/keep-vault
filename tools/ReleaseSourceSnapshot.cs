#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace KeepVaultBuild;

// A build input lease, not a claim of protection against administrators or
// termination of the owning process. Output directories remain writable.
public sealed class SourceSnapshotLease : IDisposable
{
    public string Root { get; }
    public string Commit { get; }
    public string ReportPath { get; }
    private readonly List<IDisposable> leases = new();
    private readonly List<(string Path, DirectorySecurity Acl)> acls = new();
    private readonly Dictionary<string, (FileStream Stream, string Hash)> inputs = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> sourceDirectories = new(StringComparer.OrdinalIgnoreCase);
    private static readonly string[] ProjectDirectories =
    [
        "KalynaArchiver", "KalynaArchiver.Signing", "KalynaArchiver.Tests",
        "KalynaReleaseVerifier", "KalynaSigningTool", "KeepVaultInstaller",
        "QrCodeScannerWindows", "KeepVaultMac", "KeepVaultMac.Tests",
        "KeepVaultMac.ReleaseVerifier", "KeepVaultMac/Packaging/HybridSigner"
    ];
    private bool disposed;

    public SourceSnapshotLease(string root, string commit, string[] sourcePaths, string reportPath)
    {
        Root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        Commit = commit;
        ReportPath = reportPath;
        try
        {
            sourceDirectories.Add(Root);
            foreach (string relative in sourcePaths)
            {
                string full = Path.GetFullPath(Path.Combine(Root, relative));
                if (!full.StartsWith(Root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
                    || IsOutput(relative) || inputs.ContainsKey(relative)) throw new IOException("Invalid source inventory path.");
                for (string parent = Path.GetDirectoryName(full)!; parent.Length >= Root.Length; parent = Path.GetDirectoryName(parent)!)
                {
                    sourceDirectories.Add(parent);
                    if (parent == Root) break;
                }
            }
            // Bind path components before opening and hashing leaf inputs.
            for (string? parent = Root; parent != null; parent = Path.GetDirectoryName(parent))
                leases.Add(Open(parent, true));
            foreach (string directory in sourceDirectories)
                if (directory != Root) leases.Add(Open(directory, true));
            foreach (string relative in sourcePaths)
            {
                SafeFileHandle handle = Open(Path.Combine(Root, relative), false);
                var stream = new FileStream(handle, FileAccess.Read);
                leases.Add(stream);
                inputs.Add(relative.Replace('\\', '/'), (stream, Hash(stream)));
            }
            // No path component may be renamed while tools resolve the input.
            SecurityIdentifier sid = WindowsIdentity.GetCurrent().User!;
            foreach (string directory in sourceDirectories.OrderBy(value => value.Length))
            {
                var info = new DirectoryInfo(directory);
                DirectorySecurity original = info.GetAccessControl(AccessControlSections.Access);
                var restricted = new DirectorySecurity();
                restricted.SetSecurityDescriptorBinaryForm(original.GetSecurityDescriptorBinaryForm(), AccessControlSections.Access);
                restricted.AddAccessRule(new FileSystemAccessRule(sid,
                    FileSystemRights.CreateFiles | FileSystemRights.CreateDirectories | FileSystemRights.DeleteSubdirectoriesAndFiles,
                    InheritanceFlags.None, PropagationFlags.None, AccessControlType.Deny));
                acls.Add((directory, original));
                info.SetAccessControl(restricted);
            }
            Verify();
            File.WriteAllLines(ReportPath, inputs.OrderBy(entry => entry.Key, StringComparer.Ordinal)
                .Select(entry => entry.Value.Hash + "  " + entry.Key), new UTF8Encoding(false));
        }
        catch (Exception original)
        {
            try { Dispose(); }
            catch (Exception cleanup) { throw new AggregateException("Snapshot setup and cleanup both failed.", original, cleanup); }
            throw;
        }
    }

    public static bool IsOutput(string relative)
    {
        string path = relative.Replace('\\', '/');
        if (path.StartsWith(".git/", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("work/", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("build-analysis/", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("dist/", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("QrCodeScannerWindows/dist/", StringComparison.OrdinalIgnoreCase)) return true;
        foreach (string project in ProjectDirectories)
            foreach (string output in new[] { "bin", "obj", "obj_alt", "build-obj" })
                if (path.StartsWith(project + "/" + output + "/", StringComparison.OrdinalIgnoreCase)) return true;
        if (!path.StartsWith("tools/", StringComparison.OrdinalIgnoreCase) || path[6..].Contains('/')) return false;
        // Only the named native outputs may differ from HEAD. An arbitrary
        // executable or similarly named source file is never a dirty override.
        return System.Text.RegularExpressions.Regex.IsMatch(path[6..],
            @"^(?:zpaq\.exe|argon2\.exe|(?:kalyna_v12|threefish_ref|mars_ref|shacal2_ref|aes_ref|chachapoly_ref|argon2_ref|mldsa87_ref)\.dll)(?:\.(?:sha3|skein))?(?:\.khsig)?$",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
    }

    public void Verify()
    {
        if (disposed) throw new ObjectDisposedException(nameof(SourceSnapshotLease));
        foreach (var input in inputs)
            if (Hash(input.Value.Stream) != input.Value.Hash) throw new IOException("Build source changed: " + input.Key);
        var pending = new Stack<string>();
        pending.Push(Root);
        while (pending.Count != 0)
        {
            foreach (string path in Directory.EnumerateFileSystemEntries(pending.Pop()))
            {
                string relative = Path.GetRelativePath(Root, path).Replace('\\', '/');
                FileAttributes attributes = File.GetAttributes(path);
                if (IsOutput(relative + ((attributes & FileAttributes.Directory) != 0 ? "/" : ""))) continue;
                if ((attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Source reparse point: " + relative);
                if ((attributes & FileAttributes.Directory) != 0)
                {
                    if (!sourceDirectories.Contains(path)) throw new IOException("Unreviewed source directory: " + relative);
                    pending.Push(path);
                }
                else if (!inputs.ContainsKey(relative)) throw new IOException("Unreviewed source input: " + relative);
            }
        }
    }

    private static string Hash(FileStream stream)
    {
        stream.Position = 0;
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static SafeFileHandle Open(string path, bool directory)
    {
        SafeFileHandle handle = CreateFileW(path, directory ? 0x81u : 0x80000000u, directory ? 3u : 1u,
            0, 3, directory ? 0x02200000u : 0x00200000u, 0);
        try
        {
            if (handle.IsInvalid || !GetFileInformationByHandle(handle, out FileInformation info)
                || (info.Attributes & 0x400) != 0 || (!directory && info.Links != 1)) throw new IOException("Cannot lease source object: " + path);
            var buffer = new StringBuilder(32768);
            uint length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 0);
            string final = buffer.ToString();
            if (final.StartsWith(@"\\?\")) final = final[4..];
            if (length == 0 || length >= buffer.Capacity || !string.Equals(Path.TrimEndingDirectorySeparator(final),
                    Path.TrimEndingDirectorySeparator(Path.GetFullPath(path)), StringComparison.OrdinalIgnoreCase))
                throw new IOException("A source path resolved through an alias: " + path + " => " + final);
            return handle;
        }
        catch { handle.Dispose(); throw; }
    }

    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        var errors = new List<Exception>();
        try
        {
            for (int index = acls.Count - 1; index >= 0; index--)
            {
                try
                {
                    var original = new DirectorySecurity();
                    original.SetSecurityDescriptorBinaryForm(acls[index].Acl.GetSecurityDescriptorBinaryForm(), AccessControlSections.Access);
                    new DirectoryInfo(acls[index].Path).SetAccessControl(original);
                }
                catch (Exception error) { errors.Add(error); }
            }
        }
        finally
        {
            for (int index = leases.Count - 1; index >= 0; index--)
                try { leases[index].Dispose(); } catch (Exception error) { errors.Add(error); }
        }
        if (errors.Count != 0) throw new AggregateException("Snapshot cleanup failed; all remaining restorations were attempted.", errors);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME Created, Accessed, Written;
        public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, nint attributes, uint disposition, uint flags, nint template);
    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation information);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, StringBuilder path, uint length, uint flags);
}
