using System.Runtime.InteropServices;
using System.Threading;

namespace KalynaArchiver.Services;

internal static partial class ProcessHardening
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

    private static int _applied;

    public static ProcessHardeningStatus LastStatus { get; private set; } = new(false, false, false, false, false, false);

    /// <summary>
    /// Applies the Windows process hardening and refuses to continue if any
    /// required part of it did not take effect.
    /// </summary>
    /// <remarks>
    /// This mirrors <c>MacProcessHardening.Apply</c>. The macOS side treats its
    /// four measures as a precondition and throws when one of them fails, so
    /// the launcher can stop before the user interface or any key material is
    /// loaded. The Windows side used to record the same information in six
    /// booleans and then continue regardless; the result was written to the log
    /// where nobody reads it during an attack. A process without the System32
    /// DLL search path or without the image-load policy is exactly the process
    /// this application is built not to be, so it now fails closed as well.
    ///
    /// Every measure below is available on Windows 10 1809 and newer, which is
    /// the floor this method enforces explicitly rather than discovering it
    /// through a failed policy call.
    /// </remarks>
    public static ProcessHardeningStatus Apply()
    {
        if (Interlocked.Exchange(ref _applied, 1) != 0)
        {
            return LastStatus;
        }

        if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 17763))
        {
            throw new PlatformNotSupportedException(
                "Keep Vault requires Windows 10 version 1809 or newer.");
        }

        bool errorModeSet = TrySetErrorModes();
        bool werSet = TrySetWerFlags();
        bool strictHandleSet = TrySetMitigation(ProcessMitigationPolicy.ProcessStrictHandleCheckPolicy, 0x3);
        bool extensionPointsDisabled = TrySetMitigation(ProcessMitigationPolicy.ProcessExtensionPointDisablePolicy, 0x1);
        bool imageLoadPolicySet = TrySetMitigation(ProcessMitigationPolicy.ProcessImageLoadPolicy, ImageLoadPolicyHardened);
        bool dllSearchRestricted = TryRestrictDllSearch();
        LastStatus = new ProcessHardeningStatus(
            errorModeSet,
            werSet,
            strictHandleSet,
            extensionPointsDisabled,
            imageLoadPolicySet,
            dllSearchRestricted);

        if (!LastStatus.AllRequiredApplied)
        {
            throw new InvalidOperationException(
                "The required Windows process hardening could not be applied: "
                + string.Join(", ", LastStatus.MissingMeasures)
                + ". Keep Vault stopped before loading its user interface.");
        }

        return LastStatus;
    }

    private static bool TryRestrictDllSearch()
    {
        try
        {
            return SetDefaultDllDirectories(LoadLibrarySearchSystem32);
        }
        catch
        {
            return false;
        }
    }

    private static bool TrySetErrorModes()
    {
        try
        {
            _ = SetErrorMode(HardenedErrorMode);
            return SetThreadErrorMode(HardenedErrorMode, out _);
        }
        catch
        {
            return false;
        }
    }

    private static bool TrySetWerFlags()
    {
        try
        {
            return WerSetFlags(WerHardeningFlags) >= 0;
        }
        catch
        {
            return false;
        }
    }

    private static bool TrySetMitigation(ProcessMitigationPolicy policy, uint flags)
    {
        try
        {
            return SetProcessMitigationPolicy(policy, ref flags, sizeof(uint));
        }
        catch
        {
            return false;
        }
    }

    [LibraryImport("kernel32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial uint SetErrorMode(uint uMode);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetThreadErrorMode(uint dwNewMode, out uint lpOldMode);

    // WerSetFlags is declared in werapi.h but exported by kernel32.dll, not by
    // wer.dll. The import used to name wer.dll, the resulting
    // EntryPointNotFoundException was swallowed by the try/catch in
    // TrySetWerFlags, and the measure reported false on every start while the
    // status line said "WER=False" to nobody in particular. Verified against
    // the export tables: kernel32.dll exports WerSetFlags at ordinal 1600,
    // wer.dll exports no such name.
    [LibraryImport("kernel32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial int WerSetFlags(uint dwFlags);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetProcessMitigationPolicy(ProcessMitigationPolicy mitigationPolicy, ref uint lpBuffer, nuint dwLength);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetDefaultDllDirectories(uint directoryFlags);

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

internal sealed record ProcessHardeningStatus(
    bool ErrorModeSet,
    bool WerFlagsSet,
    bool StrictHandlePolicySet,
    bool ExtensionPointsDisabled,
    bool ImageLoadPolicySet,
    bool DllSearchRestricted)
{
    /// <summary>
    /// All six measures are required, the way all four macOS measures are.
    /// </summary>
    /// <remarks>
    /// A partial application is not a degraded mode worth running. Error mode
    /// and the WER flags keep the process out of crash dumps that would carry
    /// key material to disk, which is what the macOS core-dump limit does. The
    /// System32-only DLL search is the counterpart of clearing the dynamic
    /// loader environment. Strict handles, extension-point blocking and the
    /// image-load policy have no macOS counterpart because macOS gets the same
    /// property from library validation under the hardened runtime.
    /// </remarks>
    internal bool AllRequiredApplied => MissingMeasures.Count == 0;

    /// <summary>
    /// Names the measures that did not take effect, so a refusal to start says
    /// what is missing instead of only that something is.
    /// </summary>
    internal IReadOnlyList<string> MissingMeasures
    {
        get
        {
            var missing = new List<string>(6);
            if (!ErrorModeSet) { missing.Add("hardened error mode"); }
            if (!WerFlagsSet) { missing.Add("Windows Error Reporting flags"); }
            if (!StrictHandlePolicySet) { missing.Add("strict handle checks"); }
            if (!ExtensionPointsDisabled) { missing.Add("extension-point blocking"); }
            if (!ImageLoadPolicySet) { missing.Add("image-load policy"); }
            if (!DllSearchRestricted) { missing.Add("System32-only DLL search"); }
            return missing;
        }
    }
}
