using System.Reflection;
using System.ComponentModel;
using System.Runtime.InteropServices;
using KalynaArchiver.Services;
using Microsoft.Win32.SafeHandles;

/// <summary>Test attacker holding independent writable FDs before product sealing.</summary>
internal sealed class VerifiedArchiveInputAttack : IDisposable
{
    internal VerifiedArchiveInput Input { get; private set; } = null!;
    internal FileStream Spool { get; private set; } = null!;
    internal FileStream Index { get; private set; } = null!;
    internal SafeFileHandle OriginalSpoolWriter { get; private set; } = null!;
    internal SafeFileHandle OriginalIndexWriter { get; private set; } = null!;

    internal static async Task<VerifiedArchiveInputAttack> CaptureAsync(
        string path, ArchiveOperationPolicy policy, CancellationToken token)
    {
        var attacker = new VerifiedArchiveInputAttack();
        bool previousDisk = AuthenticatedRangeIndex.ForceDiskForTests.Value;
        AuthenticatedRangeIndex.ForceDiskForTests.Value = true;
        attacker.Spool = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete, 1, FileOptions.RandomAccess);
        attacker.OriginalSpoolWriter = attacker.Spool.SafeFileHandle;
        Action<VerifiedArchiveInput>? previous = VerifiedArchiveInput.BeforeSealForTests;
        VerifiedArchiveInput.BeforeSealForTests = input =>
        {
            previous?.Invoke(input);
            attacker.OriginalIndexWriter = Storage(input, "_index").SafeFileHandle;
            attacker.Index = DuplicateWriter(attacker.OriginalIndexWriter);
        };
        try
        {
            attacker.Input = await VerifiedArchiveInput.CaptureAsync(path, policy, token);
            return attacker;
        }
        catch { attacker.Dispose(); throw; }
        finally { VerifiedArchiveInput.BeforeSealForTests = previous; AuthenticatedRangeIndex.ForceDiskForTests.Value = previousDisk; }
    }

    internal static FileStream Storage(VerifiedArchiveInput input, string name)
    {
        if (name == "_spool" || name == "_original")
            return (FileStream)typeof(VerifiedArchiveInput).GetField("_original", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(input)!;
        var store = (AuthenticatedRangeIndex)typeof(VerifiedArchiveInput).GetField("_index", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(input)!;
        return store.FileForTests?.Stream ?? throw new InvalidOperationException("The attack requires an explicitly forced spilled index.");
    }

    private static FileStream DuplicateWriter(SafeFileHandle source)
    {
        // Duplication deliberately preserves write authority only in the test
        // attacker. The product uses independent O_RDONLY opens, never this API.
        // dup has a fixed one-argument ABI. A fixed three-argument P/Invoke to
        // variadic fcntl is wrong on Darwin ARM64: its third argument belongs
        // on the variadic stack, not in the third argument register.
        int descriptor = Dup(source);
        if (descriptor < 0)
            throw new IOException("Cannot retain the attacker's pre-sealing descriptor.", new Win32Exception(Marshal.GetLastPInvokeError()));
        var handle = new SafeFileHandle(descriptor, ownsHandle: true);
        try
        {
            MacSafeFileSystem.SetCloseOnExec(handle, true);
            // Independently inspect the resulting FD; no fcntl vararg is used.
            int flags = FcntlNoArgument(handle, 1); // F_GETFD
            if (flags < 0 || (flags & 1) == 0) // FD_CLOEXEC
                throw new IOException("The attacker's descriptor lacks verified close-on-exec protection.");
            return new FileStream(handle, FileAccess.ReadWrite, 1, isAsync: false);
        }
        catch { handle.Dispose(); throw; }
    }

    [DllImport("libSystem.B.dylib", EntryPoint = "dup", SetLastError = true)]
    private static extern int Dup(SafeFileHandle handle);
    [DllImport("libSystem.B.dylib", EntryPoint = "fcntl", SetLastError = true)]
    private static extern int FcntlNoArgument(SafeFileHandle handle, int command);

    public void Dispose() => SecureMemory.DisposeAll(Input, Spool, Index);
}
