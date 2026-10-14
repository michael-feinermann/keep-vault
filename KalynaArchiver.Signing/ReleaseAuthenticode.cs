using System.Runtime.InteropServices;

namespace KalynaArchiver.Signing;

/// <summary>Same primary-signature-only Windows trust policy used by the application.</summary>
public static class ReleaseAuthenticode
{
    private static readonly Guid WinTrustActionGenericVerifyV2 = new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");
    private const uint WtdUiNone = 2;
    private const uint WtdRevokeNone = 0;
    private const uint WtdChoiceFile = 1;
    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;
    private const uint WtdCacheOnlyUrlRetrieval = 0x00001000;
    private const uint WssVerifySpecific = 0x00000001;
    private const uint WssGetSecondarySigCount = 0x00000002;
    public static uint Verify(string path)
    {
        nint fileInfoPointer = 0;
        nint trustDataPointer = 0;
        nint signatureSettingsPointer = 0;

        try
        {
            var fileInfo = new WinTrustFileInfo
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
                pcwszFilePath = path,
            };
            fileInfoPointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
            Marshal.StructureToPtr(fileInfo, fileInfoPointer, false);

            var signatureSettings = new WinTrustSignatureSettings
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustSignatureSettings>(),
                dwIndex = 0,
                dwFlags = WssVerifySpecific | WssGetSecondarySigCount,
            };
            signatureSettingsPointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustSignatureSettings>());
            Marshal.StructureToPtr(signatureSettings, signatureSettingsPointer, false);

            var trustData = new WinTrustData
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustData>(),
                dwUIChoice = WtdUiNone,
                fdwRevocationChecks = WtdRevokeNone,
                dwUnionChoice = WtdChoiceFile,
                pFile = fileInfoPointer,
                dwStateAction = WtdStateActionVerify,
                dwProvFlags = WtdCacheOnlyUrlRetrieval,
                pSignatureSettings = signatureSettingsPointer,
            };
            trustDataPointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustData>());
            Marshal.StructureToPtr(trustData, trustDataPointer, false);

            Guid action = WinTrustActionGenericVerifyV2;
            int result = WinVerifyTrust(new nint(-1), ref action, trustDataPointer);
            signatureSettings = Marshal.PtrToStructure<WinTrustSignatureSettings>(signatureSettingsPointer);

            trustData = Marshal.PtrToStructure<WinTrustData>(trustDataPointer);
            trustData.dwStateAction = WtdStateActionClose;
            Marshal.StructureToPtr(trustData, trustDataPointer, false);
            _ = WinVerifyTrust(new nint(-1), ref action, trustDataPointer);
            if (signatureSettings.cSecondarySigs != 0 || signatureSettings.dwVerifiedSigIndex != 0)
                throw new System.Security.Cryptography.CryptographicException("Ambiguous Authenticode signatures are forbidden.");
            return unchecked((uint)result);
        }
        finally
        {
            if (trustDataPointer != 0)
            {
                Marshal.DestroyStructure<WinTrustData>(trustDataPointer);
                Marshal.FreeHGlobal(trustDataPointer);
            }

            if (fileInfoPointer != 0)
            {
                Marshal.DestroyStructure<WinTrustFileInfo>(fileInfoPointer);
                Marshal.FreeHGlobal(fileInfoPointer);
            }

            if (signatureSettingsPointer != 0)
            {
                Marshal.DestroyStructure<WinTrustSignatureSettings>(signatureSettingsPointer);
                Marshal.FreeHGlobal(signatureSettingsPointer);
            }
        }
    }

    [DllImport("wintrust.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int WinVerifyTrust(nint hwnd, ref Guid pgActionId, nint pWinTrustData);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pcwszFilePath;
        public nint hFile;
        public nint pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustData
    {
        public uint cbStruct;
        public nint pPolicyCallbackData;
        public nint pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public nint pFile;
        public uint dwStateAction;
        public nint hWVTStateData;
        public nint pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public nint pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustSignatureSettings
    {
        public uint cbStruct;
        public uint dwIndex;
        public uint dwFlags;
        public uint cSecondarySigs;
        public uint dwVerifiedSigIndex;
        public nint pCryptoPolicy;
    }

}
