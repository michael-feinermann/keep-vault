using System.Runtime.InteropServices;

namespace QrScanner;

/// <summary>
/// Applies the process policies that keep a scanned factor out of Windows
/// crash snapshots and prevent DLL search from consulting writable folders.
/// </summary>
internal static class ProcessHardening
{
    private const uint SemFailCriticalErrors = 0x0001;
    private const uint SemNoGpFaultErrorBox = 0x0002;
    private const uint SemNoOpenFileErrorBox = 0x8000;
    private const uint HardenedErrorMode = SemFailCriticalErrors | SemNoGpFaultErrorBox | SemNoOpenFileErrorBox;

    private const uint WerFaultReportingFlagNoHeap = 0x00000001;
    private const uint WerFaultReportingNoUi = 0x00000020;
    private const uint WerFaultReportingFlagNoHeapOnQueue = 0x00000040;
    private const uint WerFaultReportingDisableSnapshotCrash = 0x00000080;
    private const uint WerFaultReportingDisableSnapshotHang = 0x00000100;
    private const uint WerHardeningFlags =
        WerFaultReportingFlagNoHeap |
        WerFaultReportingNoUi |
        WerFaultReportingFlagNoHeapOnQueue |
        WerFaultReportingDisableSnapshotCrash |
        WerFaultReportingDisableSnapshotHang;

    private const uint LoadLibrarySearchSystem32 = 0x00000800;
    private const uint ImageLoadPolicyHardened = 0x00000007;

    public static void Apply()
    {
        // Hardening is best-effort on Windows editions that lack an individual
        // policy. Each call is isolated so one unavailable policy does not keep
        // the remaining protections from being applied.
        Try(() => _ = SetErrorMode(HardenedErrorMode));
        Try(() => _ = SetThreadErrorMode(HardenedErrorMode, out _));
        Try(() => _ = WerSetFlags(WerHardeningFlags));
        Try(() => SetMitigation(ProcessMitigationPolicy.ProcessStrictHandleCheckPolicy, 0x3));
        Try(() => SetMitigation(ProcessMitigationPolicy.ProcessExtensionPointDisablePolicy, 0x1));
        Try(() => SetMitigation(ProcessMitigationPolicy.ProcessImageLoadPolicy, ImageLoadPolicyHardened));
        Try(() => _ = SetDefaultDllDirectories(LoadLibrarySearchSystem32));
    }

    private static void SetMitigation(ProcessMitigationPolicy policy, uint flags) =>
        _ = SetProcessMitigationPolicy(policy, ref flags, sizeof(uint));

    private static void Try(Action action)
    {
        try
        {
            action();
        }
        catch (Exception exception) when (exception is DllNotFoundException
            or EntryPointNotFoundException
            or BadImageFormatException)
        {
            // Older supported Windows builds can lack a newer policy. There is
            // no less restrictive fallback worth substituting for it.
        }
    }

    [DllImport("kernel32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint SetErrorMode(uint uMode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetThreadErrorMode(uint dwNewMode, out uint lpOldMode);

    [DllImport("wer.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int WerSetFlags(uint dwFlags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetProcessMitigationPolicy(
        ProcessMitigationPolicy mitigationPolicy,
        ref uint lpBuffer,
        nuint dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetDefaultDllDirectories(uint directoryFlags);

    private enum ProcessMitigationPolicy
    {
        ProcessDEPPolicy,
        ProcessASLRPolicy,
        ProcessDynamicCodePolicy,
        ProcessStrictHandleCheckPolicy,
        ProcessSystemCallDisablePolicy,
        ProcessMitigationOptionsMask,
        ProcessExtensionPointDisablePolicy,
        ProcessControlFlowGuardPolicy,
        ProcessSignaturePolicy,
        ProcessFontDisablePolicy,
        ProcessImageLoadPolicy,
    }
}
