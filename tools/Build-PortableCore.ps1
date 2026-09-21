param(
    [Parameter(Mandatory = $true)] $SnapshotLease,
    [string] $Configuration = "Release",
    [string] $Runtime = "win-x64",
    [string] $OutputName = "Keep Vault-portable-win-x64",
    [switch] $SkipSigning,
    [switch] $CreateDevelopmentCertificate,
    [switch] $TrustDevelopmentCertificate,
    [string] $PfxPath,
    [string] $PfxPasswordEncryptedPath,
    [string] $PfxWrappingKeyPath,
    [string] $ReleaseKeyDirectory,
    [string] $CertificateThumbprint,
    [string] $ExpectedSignerSha256,
    [string] $ExpectedSignerSha3_512,
    [string] $ExpectedSignerSkein1024,
    [string] $ExpectedMldsa87Sha256,
    [string] $ExpectedMldsa87Sha3_512,
    [string] $ExpectedMldsa87Skein1024,
    [string] $MldsaPrivateKeyPath,
    [string] $MldsaPrivateKeyEncryptedPath,
    [string] $WrappingKeyPath,
    [string] $MldsaPublicKeyPath,
    [string] $MldsaReferencePath
)

$ErrorActionPreference = "Stop"
if ($Runtime -cne 'win-x64' -or $Configuration -cne 'Release' -or $SkipSigning -or
    $CreateDevelopmentCertificate -or $TrustDevelopmentCertificate -or -not $ReleaseKeyDirectory) {
    throw 'The release core requires signed production Release/win-x64 output.'
}
if ($SnapshotLease -isnot [KeepVaultBuild.SourceSnapshotLease] -or
    $SnapshotLease.Root -ine [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))) {
    throw 'Build-PortableCore must run inside its leased committed source snapshot.'
}
$SnapshotLease.Verify()

if ($OutputName -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9._ -]{0,126}[A-Za-z0-9])?$' -or
    $OutputName -in @('.', '..')) {
    throw "OutputName must be a simple 1-128 character file name containing only letters, digits, spaces, dots, underscores, or hyphens, without trailing punctuation."
}

$root = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")
$nativeOutput = Join-Path $root 'work\native-tools'
$MldsaReferencePath = Join-Path $nativeOutput 'mldsa87_ref.dll'
& (Join-Path $PSScriptRoot 'Verify-NativeSources.ps1') -Root $root
$distRoot = Join-Path $root "dist"
$publishDir = Join-Path $distRoot $OutputName
$zipPath = Join-Path $distRoot "$OutputName.zip"
$zipSha3Path = "$zipPath.sha3"
$zipSkeinPath = "$zipPath.skein"
$zipHybridPath = "$zipPath.khsig"
$project = Join-Path $root "KalynaArchiver\KalynaArchiver.csproj"
$verifierProject = Join-Path $root "KalynaReleaseVerifier\KalynaReleaseVerifier.csproj"
$installerProject = Join-Path $root "KeepVaultInstaller\KeepVaultInstaller.csproj"
$installerPublishDir = Join-Path $distRoot ".KeepVaultInstaller-publish"
$verifierPublishDir = Join-Path $distRoot ".KalynaReleaseVerifier-publish"
$externalVerifierPath = Join-Path $distRoot "Keep Vault Release Verifier-win-x64.exe"
$scannerBuildScript = Join-Path $root "QrCodeScannerWindows\tools\Build-QrScanner-Windows.ps1"
$scannerDistribution = Join-Path $root "QrCodeScannerWindows\dist"
$packagedScannerDirectory = Join-Path $publishDir "QR-Scanner"
$signScript = Join-Path $root "tools\Sign-Binaries.ps1"
$manifestScript = Join-Path $root "tools\Generate-Sha3Manifest.ps1"
$skeinManifestScript = Join-Path $root "tools\Generate-SkeinManifest.ps1"
$hybridSignatureScript = Join-Path $root "tools\New-HybridSignature.ps1"

# Select one complete key-file variant and the committed Windows public identity
# once. Every native, application and manifest signature uses this same set.
$releaseSigning = & (Join-Path $PSScriptRoot 'New-ReleaseSigningParameters.ps1') -ReleaseKeyDirectory $ReleaseKeyDirectory
if ($MldsaPrivateKeyPath) { throw 'Production releases require the v12 encrypted ML-DSA key from ReleaseKeyDirectory.' }

function Assert-ReleaseParameterValue {
    param([string] $Name, [string] $Actual, [string] $Expected, [switch] $Path)
    if ([string]::IsNullOrEmpty($Actual)) { return }
    $normalized = if ($Path) { [IO.Path]::GetFullPath($Actual) } else { ($Actual -replace '\s', '').ToUpperInvariant() }
    if (-not [string]::Equals($normalized, $Expected, [StringComparison]::OrdinalIgnoreCase)) {
        throw "The explicit $Name differs from the committed Windows release identity or selected complete key set."
    }
}

foreach ($name in @('PfxPath', 'PfxPasswordEncryptedPath', 'PfxWrappingKeyPath',
    'MldsaPrivateKeyEncryptedPath', 'WrappingKeyPath', 'MldsaPublicKeyPath')) {
    Assert-ReleaseParameterValue $name (Get-Variable -Name $name -ValueOnly) $releaseSigning[$name] -Path
    Set-Variable -Name $name -Value $releaseSigning[$name]
}
foreach ($name in @('CertificateThumbprint', 'ExpectedSignerSha256', 'ExpectedSignerSha3_512',
    'ExpectedSignerSkein1024', 'ExpectedMldsa87Sha256', 'ExpectedMldsa87Sha3_512', 'ExpectedMldsa87Skein1024')) {
    Assert-ReleaseParameterValue $name (Get-Variable -Name $name -ValueOnly) $releaseSigning[$name]
}
$effectiveCertificateThumbprint = $releaseSigning.CertificateThumbprint
$effectiveSignerSha256 = $releaseSigning.ExpectedSignerSha256
$effectiveSignerSha3 = $releaseSigning.ExpectedSignerSha3_512
$effectiveSignerSkein = $releaseSigning.ExpectedSignerSkein1024
$effectiveMldsaSha256 = $releaseSigning.ExpectedMldsa87Sha256
$effectiveMldsaSha3 = $releaseSigning.ExpectedMldsa87Sha3_512
$effectiveMldsaSkein = $releaseSigning.ExpectedMldsa87Skein1024

function Assert-ReleasePublicFingerprints {
    param([byte[]] $Bytes, [string] $Prefix, [hashtable] $Policy)
    $stream = [IO.MemoryStream]::new($Bytes, $false)
    try {
        $actual = [KalynaArchiver.Signing.HybridSignatureService]::Fingerprint($stream)
        foreach ($entry in @(
            @('Sha256', $actual.Item1), @('Sha3_512', $actual.Item2), @('Skein1024', $actual.Item3))) {
            if ([Convert]::ToHexString($entry[1]) -cne $Policy[$Prefix + $entry[0]]) {
                throw "The release public key does not match the mandatory $Prefix$($entry[0]) pin."
            }
        }
    }
    finally { $stream.Dispose() }
}

. (Join-Path $PSScriptRoot 'Import-SigningRuntime.ps1')
Import-SigningRuntime
Assert-ReleasePublicFingerprints ([IO.File]::ReadAllBytes($MldsaPublicKeyPath)) 'ExpectedMldsa87' $releaseSigning
$releaseCertificate = $null
try {
$releaseCertificate = [KalynaArchiver.Signing.ReleaseSigningOperations]::LoadCertificate(
    $PfxPath, $PfxPasswordEncryptedPath, $PfxWrappingKeyPath)
if ($releaseCertificate.Thumbprint -cne $effectiveCertificateThumbprint) {
    throw 'The selected PFX does not contain the committed Windows release certificate.'
}
$releaseRsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($releaseCertificate)
try {
    if ($null -eq $releaseRsa -or $releaseRsa.KeySize -ne 4096) { throw 'The Windows release identity must use RSA-4096.' }
    Assert-ReleasePublicFingerprints $releaseRsa.ExportSubjectPublicKeyInfo() 'ExpectedSigner' $releaseSigning
}
finally { if ($releaseRsa) { $releaseRsa.Dispose() } }
function Assert-InRoot {
    param([string] $Path)
    $full = [System.IO.Path]::GetFullPath($Path)
    $rootFull = [System.IO.Path]::GetFullPath($root)
    $relative = [System.IO.Path]::GetRelativePath($rootFull, $full)
    $parentPrefix = "..$([System.IO.Path]::DirectorySeparatorChar)"
    if ($relative -eq "." -or
        $relative -eq ".." -or
        $relative.StartsWith($parentPrefix, [System.StringComparison]::Ordinal) -or
        [System.IO.Path]::IsPathRooted($relative)) {
        throw "Refusing to operate outside repository root. Path=$full Root=$rootFull"
    }

    $current = $full
    while (-not [string]::IsNullOrEmpty($current)) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Refusing to operate through a reparse point. Path=$($item.FullName)"
            }
        }

        if ([string]::Equals($current.TrimEnd('\'), $rootFull.TrimEnd('\'), [System.StringComparison]::OrdinalIgnoreCase)) {
            break
        }

        $current = [System.IO.Path]::GetDirectoryName($current)
    }
}

Assert-InRoot $distRoot
Assert-InRoot $publishDir
Assert-InRoot $zipPath
Assert-InRoot $zipSha3Path
Assert-InRoot $zipSkeinPath
Assert-InRoot $zipHybridPath
Assert-InRoot $verifierPublishDir
Assert-InRoot $installerPublishDir
Assert-InRoot $externalVerifierPath
Assert-InRoot $scannerDistribution
Assert-InRoot $packagedScannerDirectory

New-Item -ItemType Directory -Force -Path $distRoot | Out-Null
if (Test-Path -LiteralPath $publishDir) {
    Remove-Item -LiteralPath $publishDir -Recurse -Force
}

foreach ($oldPackageFile in @(
    $zipPath,
    $zipSha3Path,
    $zipSkeinPath,
    $zipHybridPath,
    "$zipSha3Path.khsig",
    "$zipSkeinPath.khsig",
    $externalVerifierPath,
    "$externalVerifierPath.sha3",
    "$externalVerifierPath.skein",
    "$externalVerifierPath.khsig",
    "$externalVerifierPath.sha3.khsig",
    "$externalVerifierPath.skein.khsig")) {
    if (Test-Path -LiteralPath $oldPackageFile) {
        Remove-Item -LiteralPath $oldPackageFile -Force
    }
}

if (Test-Path -LiteralPath $verifierPublishDir) {
    Remove-Item -LiteralPath $verifierPublishDir -Recurse -Force
}
if (Test-Path -LiteralPath $installerPublishDir) {
    Remove-Item -LiteralPath $installerPublishDir -Recurse -Force
}

$publishArgs = @(
    "publish",
    $project,
    "-c", $Configuration,
    "-r", $Runtime,
    "--self-contained", "true",
    "-p:PublishSingleFile=true",
    "-p:IncludeNativeLibrariesForSelfExtract=true",
    "-p:PublishReadyToRun=false",
    "-p:PublishTrimmed=false",
    "-o", $publishDir
)
$publishArgs += "-p:KalynaReleaseIdentity=$([bool]$ReleaseKeyDirectory)"
$publishArgs += "-p:KalynaNativeToolDirectory=$nativeOutput"
$publishArgs += "-p:KalynaExpectedSignerSha256=$effectiveSignerSha256"
$publishArgs += "-p:KalynaExpectedSignerSha3_512=$effectiveSignerSha3"
$publishArgs += "-p:KalynaExpectedSignerSkein1024=$effectiveSignerSkein"
$publishArgs += "-p:KalynaExpectedMldsa87Sha256=$effectiveMldsaSha256"
$publishArgs += "-p:KalynaExpectedMldsa87Sha3_512=$effectiveMldsaSha3"
$publishArgs += "-p:KalynaExpectedMldsa87Skein1024=$effectiveMldsaSkein"

# Existing tracked native PEs are generated outputs, never evidence of this
# commit's build. Remove only the exact native target set before compiling.
. (Join-Path $PSScriptRoot 'NativeToolTargets.ps1')
$nativeTargets = @(Get-NativeToolTargets -Root $root -NativeToolDirectory $nativeOutput)
[IO.Directory]::CreateDirectory($nativeOutput) | Out-Null
foreach ($target in $nativeTargets) {
    foreach ($suffix in @('', '.sha3', '.skein', '.khsig', '.sha3.khsig', '.skein.khsig')) {
        $generated = "$target$suffix"
        Assert-InRoot $generated
        if (Test-Path -LiteralPath $generated) { Remove-Item -LiteralPath $generated -Force }
    }
}
Push-Location $root
try {
    & cmd /d /c (Join-Path $PSScriptRoot 'Build-Native.cmd') $nativeOutput
    if ($LASTEXITCODE -ne 0) { throw 'The fresh native build failed.' }
}
finally { Pop-Location }
foreach ($target in $nativeTargets) {
    if (-not (Test-Path -LiteralPath $target -PathType Leaf)) { throw "Fresh native output is missing: $target" }
}
$SnapshotLease.Verify()
$nativeSigning = @{} + $releaseSigning
$nativeSigning.MldsaReferencePath = $MldsaReferencePath
& $signScript -Path $nativeTargets @nativeSigning
& (Join-Path $PSScriptRoot 'Generate-ReleaseManifests.ps1') -NativeToolDirectory $nativeOutput @nativeSigning
$SnapshotLease.Verify()

# Exercise the newly built, signed native set with this snapshot's app and
# compiled production identity before staging a distributable application.
$testOutput = Join-Path $root 'work\native-gate-tests'
$testProject = Join-Path $root 'KalynaArchiver.Tests\KalynaArchiver.Tests.csproj'
$testBuildArguments = @('build', $testProject, '-c', $Configuration, '-o', $testOutput, '--nologo')
$testBuildArguments += @($publishArgs | Where-Object { $_ -like '-p:Kalyna*' })
& dotnet @testBuildArguments
if ($LASTEXITCODE -ne 0) { throw 'The native release-gate harness build failed.' }
$testAssembly = Join-Path $testOutput 'KalynaArchiver.Tests.dll'
foreach ($gate in @(
    @('--smoke'),
    @('--full', '--no-smoke', '--category', 'Crypto'),
    @('--full', '--no-smoke', '--category', 'Zpaq'),
    @('--full', '--no-smoke', '--only', 'integrity.native-tools-signatures'),
    @('--full', '--no-smoke', '--only', 'signing.mldsa87-interop'),
    @('--full', '--no-smoke', '--only', 'kdf.argon2-reference-cli'))) {
    & dotnet $testAssembly @gate
    if ($LASTEXITCODE -ne 0) { throw "A native release test gate failed: $($gate -join ' ')" }
}
$SnapshotLease.Verify()

& dotnet @publishArgs
if ($LASTEXITCODE -ne 0) {
    throw "Portable publish failed."
}

$appExe = Join-Path $publishDir "Keep Vault.exe"
if (-not (Test-Path -LiteralPath $appExe)) {
    throw "Portable publish did not produce $appExe."
}

$verifierPublishArgs = @(
    "publish",
    $verifierProject,
    "-c", $Configuration,
    "-r", $Runtime,
    "--self-contained", "true",
    "-p:PublishSingleFile=true",
    "-p:IncludeNativeLibrariesForSelfExtract=true",
    "-p:PublishReadyToRun=false",
    "-p:PublishTrimmed=false",
    "-p:KalynaReleaseIdentity=$([bool]$ReleaseKeyDirectory)",
    "-p:KalynaNativeToolDirectory=$nativeOutput",
    "-p:KalynaExpectedSignerSha256=$effectiveSignerSha256",
    "-p:KalynaExpectedSignerSha3_512=$effectiveSignerSha3",
    "-p:KalynaExpectedSignerSkein1024=$effectiveSignerSkein",
    "-p:KalynaExpectedMldsa87Sha256=$effectiveMldsaSha256",
    "-p:KalynaExpectedMldsa87Sha3_512=$effectiveMldsaSha3",
    "-p:KalynaExpectedMldsa87Skein1024=$effectiveMldsaSkein",
    "-o", $verifierPublishDir
)
& dotnet @verifierPublishArgs
if ($LASTEXITCODE -ne 0) {
    throw "Portable release-verifier publish failed."
}

$publishedVerifier = Join-Path $verifierPublishDir "Keep Vault Release Verifier.exe"
if (-not (Test-Path -LiteralPath $publishedVerifier)) {
    throw "Release-verifier publish did not produce $publishedVerifier."
}
$packagedVerifier = Join-Path $publishDir "Keep Vault Release Verifier.exe"
Copy-Item -LiteralPath $publishedVerifier -Destination $packagedVerifier
Remove-Item -LiteralPath $verifierPublishDir -Recurse -Force

$installerPublishArgs = [string[]] $verifierPublishArgs.Clone()
$installerPublishArgs[1] = $installerProject
$installerPublishArgs[$installerPublishArgs.Length - 1] = $installerPublishDir
& dotnet @installerPublishArgs
if ($LASTEXITCODE -ne 0) { throw "Windows installer publish failed." }
$publishedInstaller = Join-Path $installerPublishDir "Keep Vault Setup.exe"
if (-not (Test-Path -LiteralPath $publishedInstaller -PathType Leaf)) { throw "Windows installer executable is missing." }
Copy-Item -LiteralPath $publishedInstaller -Destination (Join-Path $publishDir "Keep Vault Setup.exe")
Remove-Item -LiteralPath $installerPublishDir -Recurse -Force

# The QR scanner is a deliberately separate process, but it is part of the same
# Windows release. Build its closed single-file artifact here, copy it into a
# subdirectory that Keep Vault probes at startup, and then apply this release's
# exact signing pins and manifests together with the main application. Keeping
# the signing in this script also preserves all custom PFX/ML-DSA parameters.
if (-not (Test-Path -LiteralPath $scannerBuildScript -PathType Leaf)) {
    throw "Windows QR-Scanner build script is missing: $scannerBuildScript"
}

& pwsh -NoProfile -ExecutionPolicy Bypass -File $scannerBuildScript -Configuration $Configuration
if ($LASTEXITCODE -ne 0) {
    throw "Windows QR-Scanner build or test gate failed."
}

$scannerExecutable = Join-Path $scannerDistribution "QR-Scanner.exe"
if (-not (Test-Path -LiteralPath $scannerExecutable -PathType Leaf)) {
    throw "Windows QR-Scanner publish did not produce $scannerExecutable."
}

Copy-Item -LiteralPath $scannerDistribution -Destination $packagedScannerDirectory -Recurse
$packagedScanner = Join-Path $packagedScannerDirectory "QR-Scanner.exe"
if (-not (Test-Path -LiteralPath $packagedScanner -PathType Leaf)) {
    throw "Portable package did not receive $packagedScanner."
}

Get-ChildItem -LiteralPath $publishDir -Recurse -Force -Include "*.pdb", "createdump.exe" |
    Remove-Item -Force
$portableBinaries = Get-ChildItem -LiteralPath $publishDir -Recurse -File |
    Where-Object { $_.Extension -in @(".exe", ".dll") } |
    Select-Object -ExpandProperty FullName
if (-not $SkipSigning) {
    $signParameters = @{
        Path = $portableBinaries
        Configuration = $Configuration
        ExpectedSignerSha256 = $effectiveSignerSha256
        ExpectedSignerSha3_512 = $effectiveSignerSha3
        ExpectedSignerSkein1024 = $effectiveSignerSkein
        ExpectedMldsa87Sha256 = $effectiveMldsaSha256
        ExpectedMldsa87Sha3_512 = $effectiveMldsaSha3
        ExpectedMldsa87Skein1024 = $effectiveMldsaSkein
    }
    if ($releaseCertificate) { $signParameters.SigningCertificate = $releaseCertificate }
    elseif ($CreateDevelopmentCertificate) { $signParameters.CreateDevelopmentCertificate = $true }
    else { $signParameters.CertificateThumbprint = $effectiveCertificateThumbprint }
    if ($MldsaPrivateKeyPath) { $signParameters.MldsaPrivateKeyPath = $MldsaPrivateKeyPath }
    if ($MldsaPrivateKeyEncryptedPath) { $signParameters.MldsaPrivateKeyEncryptedPath = $MldsaPrivateKeyEncryptedPath }
    if ($WrappingKeyPath) { $signParameters.WrappingKeyPath = $WrappingKeyPath }
    if ($MldsaPublicKeyPath) { $signParameters.MldsaPublicKeyPath = $MldsaPublicKeyPath }
    if ($MldsaReferencePath) { $signParameters.MldsaReferencePath = $MldsaReferencePath }
    & $signScript @signParameters
}
foreach ($target in $portableBinaries) {
    & pwsh -NoProfile -ExecutionPolicy Bypass -File $manifestScript -ExecutablePath $target
    if ($LASTEXITCODE -ne 0) {
        throw "SHA3 manifest generation failed for $target."
    }

    & pwsh -NoProfile -ExecutionPolicy Bypass -File $skeinManifestScript -ExecutablePath $target
    if ($LASTEXITCODE -ne 0) {
        throw "Skein manifest generation failed for $target."
    }

    if (-not $SkipSigning) {
        $manifestHybridParameters = @{
            Path = @("$target.sha3", "$target.skein")
            ExpectedSignerSha256 = $effectiveSignerSha256
            ExpectedSignerSha3_512 = $effectiveSignerSha3
            ExpectedSignerSkein1024 = $effectiveSignerSkein
            ExpectedMldsa87Sha256 = $effectiveMldsaSha256
            ExpectedMldsa87Sha3_512 = $effectiveMldsaSha3
            ExpectedMldsa87Skein1024 = $effectiveMldsaSkein
            NoBuild = $true
        }
        if ($releaseCertificate) { $manifestHybridParameters.SigningCertificate = $releaseCertificate }
        else { $manifestHybridParameters.CertificateThumbprint = $effectiveCertificateThumbprint }
        if ($MldsaPrivateKeyPath) { $manifestHybridParameters.MldsaPrivateKeyPath = $MldsaPrivateKeyPath }
        if ($MldsaPrivateKeyEncryptedPath) { $manifestHybridParameters.MldsaPrivateKeyEncryptedPath = $MldsaPrivateKeyEncryptedPath }
        if ($WrappingKeyPath) { $manifestHybridParameters.WrappingKeyPath = $WrappingKeyPath }
        if ($MldsaPublicKeyPath) { $manifestHybridParameters.MldsaPublicKeyPath = $MldsaPublicKeyPath }
        if ($MldsaReferencePath) { $manifestHybridParameters.MldsaReferencePath = $MldsaReferencePath }
        & $hybridSignatureScript @manifestHybridParameters
        if ($LASTEXITCODE -ne 0) {
            throw "Hybrid manifest signing failed for $target."
        }
    }
}

$readmePath = Join-Path $publishDir "PORTABLE_README.txt"
@"
Keep Vault Portable 5.0.2
=========================

Start:
  Keep Vault Setup.exe (verify and install for the current user; no SDK required)
  Keep Vault.exe
  QR-Scanner\QR-Scanner.exe (separate camera process for printed key sheets)

This folder is self-contained for Windows x64 and does not require installing the .NET runtime.
The signed QR-Scanner companion is included in the same verified release tree; Keep Vault
checks its detached signature and both manifests at every start before vouching for it.
Keep the EXE, native tools, .sha3, .skein, and .khsig files together. Every executable
requires RSA-4096/SHA-512 Authenticode plus a detached RSA-PSS/SHA-512 and ML-DSA-87
signature. Hash manifests and other release artifacts are also signed by RSA-PSS and
ML-DSA-87. Keep Vault Release Verifier.exe checks a folder or the ZIP before launch.

Windows certificate selector (not a trust pin): $effectiveCertificateThumbprint
Pinned RSA SHA-256(SPKI): $effectiveSignerSha256
Pinned RSA SHA3-512(SPKI): $effectiveSignerSha3
Pinned RSA Skein-1024(SPKI): $effectiveSignerSkein
Pinned ML-DSA-87 SHA-256: $effectiveMldsaSha256
Pinned ML-DSA-87 SHA3-512: $effectiveMldsaSha3
Pinned ML-DSA-87 Skein-1024: $effectiveMldsaSkein

The release signing keys remain external to this package. The verifier checks the exact
compiled public-key pins even when Windows does not trust the certificate chain. No new
Windows root certificate is installed by this portable package.

Encrypted containers use format v12 only and offer ten production suites: four cascades
and six individual ciphers. Every suite requires a passphrase, a PIN, and two independent
generated 1024-bit hexadecimal factors. Creating a new archive requires a 24-256 character
passphrase and a 6-16 digit PIN. Extraction passes the entered credentials unchanged to
the v12 derivation and does not reapply the creation policy, so existing v12 archives
created under an earlier credential policy remain readable. No older container format
is accepted. Key sheets A and B are printed as two separate jobs, each containing its
factor page and a public installation-guidance page. Store factors A and B separately.

One atomic generation consumes nine evenly filled mouse pools with at least 1024 samples
each: A1, A2, B1, B2, the SHA3 salt, the Skein salt, and three nonce parts. The visible
counters restart at zero after that epoch is consumed. Every output also includes the
operating-system CSPRNG. The matching salt and nonce remain available exactly once in
locked RAM and stay bound to the displayed factors A and B.

The v12 KDF length-prefixes and domain-separates the passphrase, PIN and both factors in
independent SHA3 and Skein branches. PMI16 is derived from the credentials and selects an
Argon2id memory cost from 1 GiB to just under 2 GiB with t=4 and p=4; it is not stored in
the header. The Paranoia cascade performs the complete second KDF round.

Every 16 MiB container chunk derives its own nonce from the base nonce and chunk index.
CTR and ChaCha20 counter exhaustion is rejected before any output mutation.

Physical printing creates no PDF file in this app. Windows print spoolers and drivers are
outside the app's storage control and can use their own temporary storage.

The native binaries use static CRT linkage, CFG, CET compatibility, ASLR and NX. The app
also restricts DLL search to System32 and blocks remote/low-integrity images where Windows
supports those policies. ZPAQ remains a native C++ parser and is not an AppContainer.

NTFS alternate data streams are intentionally omitted during archive creation and rejected
during extraction. OneDrive/cloud versions, backups, shadow copies and print spooling can
retain data outside this app's control.

Cryptographic erase only applies to encrypted v12 ZPAQ containers. True SSD hardware secure
erase is a whole-drive firmware/vendor operation, not a reliable per-file app operation.

KPAR2 v4 with ContainerVersion 12 is this app's custom RS(20,3) recovery format, not
standard PAR2. At 1 TB, 15 percent
recovery redundancy requires about 150 GiB of additional storage and several full I/O passes.
Encrypted archives always use dual-authenticated KPAR2 metadata (HMAC-SHA3-512 and keyed
Skein-1024 with domain-separated recovery keys). Plain archives explicitly receive error
correction only. Eight redundant 4096-byte locators and an independently RS(20,3)-protected
metadata area keep the manifest and both certifications recoverable after any three failed
4096-byte sidecar blocks. Unauthenticated emergency recovery only writes a new file; an
encrypted emergency candidate must still pass the container's two embedded MACs.
Unreadable source regions are isolated in 4096-byte units and repaired in the new candidate.
A .kzpaq file without valid encrypted magic and without usable KPAR2 metadata is blocked
instead of being passed to ZPAQ as a plain archive.
"@ | Set-Content -LiteralPath $readmePath -Encoding ASCII

if (-not $SkipSigning) {
    $missingHybridTargets = Get-ChildItem -LiteralPath $publishDir -Recurse -File |
        Where-Object {
            -not $_.Name.EndsWith(".khsig", [System.StringComparison]::OrdinalIgnoreCase) -and
            -not (Test-Path -LiteralPath "$($_.FullName).khsig")
        } |
        Select-Object -ExpandProperty FullName
    if ($missingHybridTargets) {
        $catchAllParameters = @{
            Path = $missingHybridTargets
            ExpectedSignerSha256 = $effectiveSignerSha256
            ExpectedSignerSha3_512 = $effectiveSignerSha3
            ExpectedSignerSkein1024 = $effectiveSignerSkein
            ExpectedMldsa87Sha256 = $effectiveMldsaSha256
            ExpectedMldsa87Sha3_512 = $effectiveMldsaSha3
            ExpectedMldsa87Skein1024 = $effectiveMldsaSkein
            NoBuild = $true
        }
        if ($releaseCertificate) { $catchAllParameters.SigningCertificate = $releaseCertificate }
        else { $catchAllParameters.CertificateThumbprint = $effectiveCertificateThumbprint }
        if ($MldsaPrivateKeyPath) { $catchAllParameters.MldsaPrivateKeyPath = $MldsaPrivateKeyPath }
        if ($MldsaPrivateKeyEncryptedPath) { $catchAllParameters.MldsaPrivateKeyEncryptedPath = $MldsaPrivateKeyEncryptedPath }
        if ($WrappingKeyPath) { $catchAllParameters.WrappingKeyPath = $WrappingKeyPath }
        if ($MldsaPublicKeyPath) { $catchAllParameters.MldsaPublicKeyPath = $MldsaPublicKeyPath }
        if ($MldsaReferencePath) { $catchAllParameters.MldsaReferencePath = $MldsaReferencePath }
        & $hybridSignatureScript @catchAllParameters
        if ($LASTEXITCODE -ne 0) {
            throw "Hybrid catch-all signing failed for portable release artifacts."
        }
    }
}

if (-not $SkipSigning) {
    # Bind every package byte, including each detached signature. Only the
    # inventory and its own signature are excluded to avoid a circular digest.
    $inventoryFiles = @(Get-ChildItem -LiteralPath $publishDir -Recurse -File |
        Sort-Object FullName | ForEach-Object {
            [ordered]@{
                Path = [IO.Path]::GetRelativePath($publishDir, $_.FullName).Replace('\', '/')
                Length = $_.Length
                Sha512 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA512).Hash
            }
        })
    $inventoryPath = Join-Path $publishDir 'RELEASE-INVENTORY.json'
    [ordered]@{Product='Keep Vault';Version='5.0.2';Runtime='win-x64';Files=$inventoryFiles} |
        ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $inventoryPath -Encoding utf8NoBOM
    $inventorySigning = @{
        Path = @($inventoryPath)
        ExpectedSignerSha256 = $effectiveSignerSha256
        ExpectedSignerSha3_512 = $effectiveSignerSha3
        ExpectedSignerSkein1024 = $effectiveSignerSkein
        ExpectedMldsa87Sha256 = $effectiveMldsaSha256
        ExpectedMldsa87Sha3_512 = $effectiveMldsaSha3
        ExpectedMldsa87Skein1024 = $effectiveMldsaSkein
        NoBuild = $true
    }
    if ($releaseCertificate) { $inventorySigning.SigningCertificate = $releaseCertificate }
    else { $inventorySigning.CertificateThumbprint = $effectiveCertificateThumbprint }
    if ($MldsaPrivateKeyPath) { $inventorySigning.MldsaPrivateKeyPath = $MldsaPrivateKeyPath }
    if ($MldsaPrivateKeyEncryptedPath) { $inventorySigning.MldsaPrivateKeyEncryptedPath = $MldsaPrivateKeyEncryptedPath }
    if ($WrappingKeyPath) { $inventorySigning.WrappingKeyPath = $WrappingKeyPath }
    if ($MldsaPublicKeyPath) { $inventorySigning.MldsaPublicKeyPath = $MldsaPublicKeyPath }
    if ($MldsaReferencePath) { $inventorySigning.MldsaReferencePath = $MldsaReferencePath }
    & $hybridSignatureScript @inventorySigning

    & $packagedVerifier $publishDir
    if ($LASTEXITCODE -ne 0) { throw 'The complete signed package failed its release verifier.' }
    & (Join-Path $publishDir 'Keep Vault Setup.exe') --verify $publishDir
    if ($LASTEXITCODE -ne 0) { throw 'The complete signed package failed its installer verifier.' }
}

Compress-Archive -LiteralPath $publishDir -DestinationPath $zipPath -CompressionLevel Optimal

& pwsh -NoProfile -ExecutionPolicy Bypass -File $manifestScript -ExecutablePath $zipPath
if ($LASTEXITCODE -ne 0) {
    throw "SHA3 manifest generation failed for portable ZIP $zipPath."
}

& pwsh -NoProfile -ExecutionPolicy Bypass -File $skeinManifestScript -ExecutablePath $zipPath
if ($LASTEXITCODE -ne 0) {
    throw "Skein manifest generation failed for portable ZIP $zipPath."
}

if (-not $SkipSigning) {
    $zipHybridParameters = @{
        Path = @($zipPath, $zipSha3Path, $zipSkeinPath)
        ExpectedSignerSha256 = $effectiveSignerSha256
        ExpectedSignerSha3_512 = $effectiveSignerSha3
        ExpectedSignerSkein1024 = $effectiveSignerSkein
        ExpectedMldsa87Sha256 = $effectiveMldsaSha256
        ExpectedMldsa87Sha3_512 = $effectiveMldsaSha3
        ExpectedMldsa87Skein1024 = $effectiveMldsaSkein
        NoBuild = $true
    }
    if ($releaseCertificate) { $zipHybridParameters.SigningCertificate = $releaseCertificate }
        else { $zipHybridParameters.CertificateThumbprint = $effectiveCertificateThumbprint }
        if ($MldsaPrivateKeyPath) { $zipHybridParameters.MldsaPrivateKeyPath = $MldsaPrivateKeyPath }
    if ($MldsaPrivateKeyEncryptedPath) { $zipHybridParameters.MldsaPrivateKeyEncryptedPath = $MldsaPrivateKeyEncryptedPath }
    if ($WrappingKeyPath) { $zipHybridParameters.WrappingKeyPath = $WrappingKeyPath }
    if ($MldsaPublicKeyPath) { $zipHybridParameters.MldsaPublicKeyPath = $MldsaPublicKeyPath }
    if ($MldsaReferencePath) { $zipHybridParameters.MldsaReferencePath = $MldsaReferencePath }
    & $hybridSignatureScript @zipHybridParameters
    if ($LASTEXITCODE -ne 0) {
        throw "Hybrid signing failed for portable ZIP and manifests."
    }
    & $packagedVerifier $zipPath
    if ($LASTEXITCODE -ne 0) { throw 'The final ZIP or its signed hash manifests failed verification.' }
    $extractionRoot = Join-Path $root ('work\release-zip-verification-' + [Guid]::NewGuid().ToString('N'))
    Assert-InRoot $extractionRoot
    [IO.Directory]::CreateDirectory($extractionRoot) | Out-Null
    Expand-Archive -LiteralPath $zipPath -DestinationPath $extractionRoot
    $extractedPackage = Join-Path $extractionRoot $OutputName
    & $packagedVerifier $extractedPackage
    if ($LASTEXITCODE -ne 0) { throw 'The freshly extracted ZIP failed complete inventory verification.' }
    & (Join-Path $publishDir 'Keep Vault Setup.exe') --verify $extractedPackage
    if ($LASTEXITCODE -ne 0) { throw 'The freshly extracted ZIP failed installer/version/timestamp verification.' }
    $SnapshotLease.Verify()

    Copy-Item -LiteralPath $packagedVerifier -Destination $externalVerifierPath
    Copy-Item -LiteralPath "$packagedVerifier.sha3" -Destination "$externalVerifierPath.sha3"
    Copy-Item -LiteralPath "$packagedVerifier.skein" -Destination "$externalVerifierPath.skein"
    Copy-Item -LiteralPath "$packagedVerifier.khsig" -Destination "$externalVerifierPath.khsig"
    Copy-Item -LiteralPath "$packagedVerifier.sha3.khsig" -Destination "$externalVerifierPath.sha3.khsig"
    Copy-Item -LiteralPath "$packagedVerifier.skein.khsig" -Destination "$externalVerifierPath.skein.khsig"
}

[pscustomobject]@{
    PublishDirectory = $publishDir
    ZipPath = $zipPath
    ZipSha3 = $zipSha3Path
    ZipSkein = $zipSkeinPath
    ZipHybridSignature = $zipHybridPath
    ExternalVerifier = $externalVerifierPath
    AppExe = $appExe
    SizeMB = [math]::Round(((Get-ChildItem -LiteralPath $publishDir -Recurse -File | Measure-Object -Property Length -Sum).Sum / 1MB), 2)
    ZipSizeMB = [math]::Round(((Get-Item -LiteralPath $zipPath).Length / 1MB), 2)
} | Format-List

}
finally {
    if ($releaseCertificate) { $releaseCertificate.Dispose() }
}
