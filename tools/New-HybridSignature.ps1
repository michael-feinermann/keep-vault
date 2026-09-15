[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory = $true)]
    [string[]] $Path,
    [string] $CertificateThumbprint,
    [string] $PfxPath,
    [string] $PfxPasswordEncryptedPath,
    [string] $PfxWrappingKeyPath,
    [System.Security.Cryptography.X509Certificates.X509Certificate2] $SigningCertificate,
    [string] $MldsaPrivateKeyPath,
    [string] $MldsaPrivateKeyEncryptedPath,
    [string] $WrappingKeyPath,
    [string] $MldsaPublicKeyPath,
    [string] $MldsaReferencePath,
    [string] $ExpectedSignerSha256,
    [string] $ExpectedSignerSha3_512,
    [string] $ExpectedSignerSkein1024,
    [string] $ExpectedMldsa87Sha256,
    [string] $ExpectedMldsa87Sha3_512,
    [string] $ExpectedMldsa87Skein1024,
    [switch] $NoBuild
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")
$signingProject = Join-Path $root "KalynaSigningTool\KalynaSigningTool.csproj"
$signingTool = Join-Path $root "KalynaSigningTool\bin\Release\net10.0-windows\KalynaSigningTool.dll"

if ($MldsaPrivateKeyPath -and $MldsaPrivateKeyEncryptedPath) {
    throw "Provide either MldsaPrivateKeyPath or MldsaPrivateKeyEncryptedPath, not both."
}
if ($WrappingKeyPath -and -not $MldsaPrivateKeyEncryptedPath) {
    throw "WrappingKeyPath requires MldsaPrivateKeyEncryptedPath."
}
if (-not $MldsaPrivateKeyPath -and -not $MldsaPrivateKeyEncryptedPath) {
    $MldsaPrivateKeyPath = Join-Path $env:LOCALAPPDATA "KalynaZpaqVault\Signing\mldsa87-development.dpapi"
}
if (-not $MldsaPublicKeyPath) {
    $MldsaPublicKeyPath = Join-Path $root "tools\mldsa87-public.key"
}
if (-not $MldsaReferencePath) {
    $MldsaReferencePath = Join-Path $root "tools\mldsa87_ref.dll"
}

. (Join-Path $PSScriptRoot 'Import-SigningRuntime.ps1')
Import-SigningRuntime -NoBuild:$NoBuild

$privateKeyPath = if ($MldsaPrivateKeyEncryptedPath) { $MldsaPrivateKeyEncryptedPath } else { $MldsaPrivateKeyPath }
foreach ($required in @($privateKeyPath, $MldsaPublicKeyPath, $MldsaReferencePath, $signingTool)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required hybrid-signing component is missing: $required"
    }
}

[xml] $buildProperties = Get-Content -LiteralPath (Join-Path $root "Directory.Build.props")
$propertyGroup = $buildProperties.Project.PropertyGroup
if (-not $ExpectedSignerSha256) { $ExpectedSignerSha256 = $propertyGroup.SelectSingleNode("KalynaExpectedSignerSha256").InnerText }
if (-not $ExpectedSignerSha3_512) { $ExpectedSignerSha3_512 = $propertyGroup.SelectSingleNode("KalynaExpectedSignerSha3_512").InnerText }
if (-not $ExpectedSignerSkein1024) { $ExpectedSignerSkein1024 = $propertyGroup.SelectSingleNode("KalynaExpectedSignerSkein1024").InnerText }
if (-not $ExpectedMldsa87Sha256) { $ExpectedMldsa87Sha256 = $propertyGroup.SelectSingleNode("KalynaExpectedMldsa87Sha256").InnerText }
if (-not $ExpectedMldsa87Sha3_512) { $ExpectedMldsa87Sha3_512 = $propertyGroup.SelectSingleNode("KalynaExpectedMldsa87Sha3_512").InnerText }
if (-not $ExpectedMldsa87Skein1024) { $ExpectedMldsa87Skein1024 = $propertyGroup.SelectSingleNode("KalynaExpectedMldsa87Skein1024").InnerText }

$ownedCertificate = $null
try {
    if (-not $SigningCertificate) {
        if ($PfxPath) {
            if (-not $PfxPasswordEncryptedPath -or -not $PfxWrappingKeyPath) {
                throw 'PFX signing requires the v12 password envelope and its separate wrapping-key file.'
            }
            $ownedCertificate = [KalynaArchiver.Signing.ReleaseSigningOperations]::LoadCertificate(
                (Resolve-Path -LiteralPath $PfxPath).Path, $PfxPasswordEncryptedPath, $PfxWrappingKeyPath)
        }
        elseif ($CertificateThumbprint) {
            if ($CertificateThumbprint -notmatch '^[0-9A-Fa-f]{40}$') { throw 'Invalid certificate thumbprint.' }
            $ownedCertificate = Get-Item -LiteralPath "Cert:\CurrentUser\My\$CertificateThumbprint"
        }
        else {
            throw 'Hybrid signing requires a signing certificate, CertificateThumbprint, or PfxPath.'
        }
        $SigningCertificate = $ownedCertificate
    }

    foreach ($target in $Path) {
        $resolvedTarget = (Resolve-Path -LiteralPath $target).Path
        [KalynaArchiver.Signing.ReleaseSigningOperations]::SignFile(
            $resolvedTarget, $SigningCertificate, $privateKeyPath, $WrappingKeyPath,
            $MldsaPublicKeyPath, $MldsaReferencePath, (-not [bool]$MldsaPrivateKeyEncryptedPath),
            $ExpectedSignerSha256, $ExpectedSignerSha3_512, $ExpectedSignerSkein1024,
            $ExpectedMldsa87Sha256, $ExpectedMldsa87Sha3_512, $ExpectedMldsa87Skein1024)
        Write-Host "Hybrid signature verified: $resolvedTarget"
    }
}
finally {
    if ($ownedCertificate) { $ownedCertificate.Dispose() }
}