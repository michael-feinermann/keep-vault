using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace KalynaArchiver.Services;

// The runtime's persistent worker pool is shared by every native module. The
// caller already owns all CPU permits; children must never acquire new permits.
internal static unsafe class NativeCipherExecutor
{
#if KEEPVAULT_EXECUTOR_TESTING
    [ThreadStatic] internal static int? RejectSubmissionAfterForTests;
    [ThreadStatic] internal static nuint LastDispatchCountForTests;
#endif
    internal static void Install(nint library)
    {
        var register = (delegate* unmanaged[Cdecl]<delegate* unmanaged[Cdecl]<nuint, delegate* unmanaged[Cdecl]<nint, nuint, void>, nint, int>, int>)NativeLibrary.GetExport(library, "keepvault_v13_register_executor");
        if (register(&Execute) != 0) throw new CryptographicException("Native v13 executor registration failed.");
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
    private static int Execute(nuint count, delegate* unmanaged[Cdecl]<nint, nuint, void> worker, nint context)
    {
        if (count == 0 || count > (nuint)Array.MaxLength || worker == null) return 1;
#if KEEPVAULT_EXECUTOR_TESTING
        LastDispatchCountForTests = count;
#endif
        Task[]? jobs = null;
        int started = 0, status = 0;
        try
        {
            jobs = new Task[checked((int)count - 1)];
            nint callback = (nint)worker;
            for (int index = 1; index < (int)count; ++index)
            {
                nuint identity = (nuint)index;
#if KEEPVAULT_EXECUTOR_TESTING
                if (started == RejectSubmissionAfterForTests) throw new InvalidOperationException("Injected test scheduling failure.");
#endif
                jobs[started] = Task.Run(() => ((delegate* unmanaged[Cdecl]<nint, nuint, void>)callback)(context, identity));
                ++started;
            }
        }
        catch { status = 3; }
        try { worker(context, 0); }
        catch { status = 3; }
        // No error, cancellation, or scheduling exception may return a native
        // stack-backed context to its caller while any queued reader is alive.
        for (int index = 0; index < started; ++index)
        {
            try { jobs![index].GetAwaiter().GetResult(); }
            catch { status = 3; }
            finally { jobs![index] = null!; }
        }
        return status;
    }
}
