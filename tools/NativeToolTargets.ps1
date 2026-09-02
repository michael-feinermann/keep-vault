# The native artifacts the release scripts sign, manifest and stage.
#
# Dot-sourced rather than copied, because it was copied. Sign-Binaries.ps1,
# Generate-ReleaseManifests.ps1 and Sign-ManagedOutput.ps1 each carried their
# own hand-written list, and when the four Crypto++ adapters arrived none of the
# three grew:
#
#   - Sign-Binaries and Generate-ReleaseManifests left aes_ref.dll,
#     mars_ref.dll, shacal2_ref.dll and chachapoly_ref.dll unsigned and without
#     manifests, which the integrity gate reads as four missing tools - the same
#     symptom as never having built them.
#   - Sign-ManagedOutput skipped them in its generation-sync loop, and then,
#     because that same list is what tells it which files are native, treated
#     them as managed assemblies and re-signed them in place.
#
# Get-NativeToolNames is
# KalynaArchiver.Services.IntegrityService.RequiredNativeTools in the same
# order; a test holds the two lists to each other. mldsa87_ref.dll is not in it:
# the application never loads it, so it is not staged beside the app, but the
# signing tool does load it, so Get-NativeToolTargets signs and manifests it.

function Get-NativeToolNames {
    return @(
        "zpaq.exe",
        "kalyna_v12.dll",
        "threefish_ref.dll",
        "mars_ref.dll",
        "shacal2_ref.dll",
        "aes_ref.dll",
        "chachapoly_ref.dll",
        "argon2_ref.dll",
        "argon2.exe"
    )
}

function Get-NativeToolTargets {
    param([Parameter(Mandatory = $true)][string] $Root)

    $names = @(Get-NativeToolNames) + @("mldsa87_ref.dll")
    return $names | ForEach-Object { Join-Path $Root "tools\$_" }
}
