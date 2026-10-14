param(
    [string[]] $Path,
    [string] $Configuration = "Release",
    [string] $PfxPath,
    [string] $PfxPasswordEncryptedPath,
    [string] $PfxWrappingKeyPath,
    [System.Security.Cryptography.X509Certificates.X509Certificate2] $SigningCertificate,
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
    [string] $MldsaReferencePath,
    [switch] $CreateDevelopmentCertificate,
    [switch] $TrustDevelopmentCertificate,
    [switch] $AllowUntimestamped,
    [string] $TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")
$skeinManifestScript = Join-Path $root "tools\Generate-SkeinManifest.ps1"
$hybridSignatureScript = Join-Path $root "tools\New-HybridSignature.ps1"
. (Join-Path $PSScriptRoot "NativeToolTargets.ps1")

if ($TrustDevelopmentCertificate) {
    throw "Trusting the development root in CurrentUser\\Root is forbidden. Development signatures are accepted only through the compiled SHA-256/SHA3-512/Skein-1024 SPKI pins."
}

function Normalize-Hex {
    param(
        [string] $Value,
        [int] $Length,
        [string] $Name
    )
    $normalized = $Value -replace "\s", ""
    if ($normalized -notmatch "^[0-9A-Fa-f]{$Length}$") {
        throw "$Name must contain exactly $Length hexadecimal characters."
    }

    return $normalized.ToUpperInvariant()
}

[xml] $buildProperties = Get-Content -LiteralPath (Join-Path $root "Directory.Build.props")
$propertyGroup = $buildProperties.Project.PropertyGroup
$defaultSha256 = $propertyGroup.SelectSingleNode("KalynaExpectedSignerSha256").InnerText
$defaultSha3 = $propertyGroup.SelectSingleNode("KalynaExpectedSignerSha3_512").InnerText
$defaultSkein = $propertyGroup.SelectSingleNode("KalynaExpectedSignerSkein1024").InnerText
$defaultMldsaSha256 = $propertyGroup.SelectSingleNode("KalynaExpectedMldsa87Sha256").InnerText
$defaultMldsaSha3 = $propertyGroup.SelectSingleNode("KalynaExpectedMldsa87Sha3_512").InnerText
$defaultMldsaSkein = $propertyGroup.SelectSingleNode("KalynaExpectedMldsa87Skein1024").InnerText
$expectedSha256 = Normalize-Hex $(if ($ExpectedSignerSha256) { $ExpectedSignerSha256 } else { $defaultSha256 }) 64 "Expected SHA-256 SPKI fingerprint"
$expectedSha3 = Normalize-Hex $(if ($ExpectedSignerSha3_512) { $ExpectedSignerSha3_512 } else { $defaultSha3 }) 128 "Expected SHA3-512 SPKI fingerprint"
$expectedSkein = Normalize-Hex $(if ($ExpectedSignerSkein1024) { $ExpectedSignerSkein1024 } else { $defaultSkein }) 256 "Expected Skein-1024 SPKI fingerprint"
$expectedMldsaSha256 = Normalize-Hex $(if ($ExpectedMldsa87Sha256) { $ExpectedMldsa87Sha256 } else { $defaultMldsaSha256 }) 64 "Expected ML-DSA-87 SHA-256 fingerprint"
$expectedMldsaSha3 = Normalize-Hex $(if ($ExpectedMldsa87Sha3_512) { $ExpectedMldsa87Sha3_512 } else { $defaultMldsaSha3 }) 128 "Expected ML-DSA-87 SHA3-512 fingerprint"
$expectedMldsaSkein = Normalize-Hex $(if ($ExpectedMldsa87Skein1024) { $ExpectedMldsa87Skein1024 } else { $defaultMldsaSkein }) 256 "Expected ML-DSA-87 Skein-1024 fingerprint"

function Get-SignerPins {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate)

    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Certificate)
    if (-not $rsa) {
        throw "The code-signing certificate must use an RSA public key."
    }

    $spki = $rsa.ExportSubjectPublicKeyInfo()
    $stream = [IO.MemoryStream]::new($spki, $false)
    $fingerprints = $null
    try {
        $fingerprints = [KalynaArchiver.Signing.HybridSignatureService]::Fingerprint($stream)
        return [pscustomobject]@{
            Thumbprint = Normalize-Hex $Certificate.Thumbprint 40 "Signer thumbprint"
            Sha256 = [Convert]::ToHexString($fingerprints.Item1)
            Sha3 = [Convert]::ToHexString($fingerprints.Item2)
            Skein = [Convert]::ToHexString($fingerprints.Item3)
        }
    }
    finally {
        if ($fingerprints) {
            [Array]::Clear($fingerprints.Item1)
            [Array]::Clear($fingerprints.Item2)
            [Array]::Clear($fingerprints.Item3)
        }
        $stream.Dispose()
        [Array]::Clear($spki)
        $rsa.Dispose()
    }
}
function Find-SignTool {
    $kitsRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
    if (-not (Test-Path -LiteralPath $kitsRoot)) {
        throw "Windows SDK signtool.exe was not found."
    }

    $tool = Get-ChildItem -LiteralPath $kitsRoot -Recurse -Filter signtool.exe |
        Where-Object { $_.FullName -match "\\x64\\signtool\.exe$" } |
        Sort-Object FullName -Descending |
        Select-Object -First 1

    if (-not $tool) {
        throw "x64 signtool.exe was not found under $kitsRoot."
    }

    return $tool.FullName
}

function Get-DevelopmentCertificate {
    $rootSubject = "CN=Keep Vault Development Root SHA512"
    $subject = "CN=Keep Vault Development Signing SHA512"
    $root = Get-ChildItem Cert:\CurrentUser\My |
        Where-Object { $_.Subject -eq $rootSubject -and $_.HasPrivateKey } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1

    if (-not $root) {
        $root = New-SelfSignedCertificate `
            -Type Custom `
            -Subject $rootSubject `
            -KeyAlgorithm RSA `
            -KeyLength 4096 `
            -KeyUsage CertSign,CRLSign,DigitalSignature `
            -HashAlgorithm SHA512 `
            -KeyExportPolicy NonExportable `
            -CertStoreLocation Cert:\CurrentUser\My `
            -TextExtension @("2.5.29.19={critical}{text}ca=1") `
            -NotAfter (Get-Date).AddYears(10)
    }

    $cert = Get-ChildItem Cert:\CurrentUser\My |
        Where-Object { $_.Subject -eq $subject -and $_.Issuer -eq $root.Subject -and $_.HasPrivateKey } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1

    if (-not $cert) {
        $cert = New-SelfSignedCertificate `
            -Type CodeSigningCert `
            -Subject $subject `
            -Signer $root `
            -KeyAlgorithm RSA `
            -KeyLength 4096 `
            -HashAlgorithm SHA512 `
            -KeyExportPolicy NonExportable `
            -CertStoreLocation Cert:\CurrentUser\My `
            -NotAfter (Get-Date).AddYears(3)
    }

    $trustedDevelopmentRoot = Get-ChildItem Cert:\CurrentUser\Root |
        Where-Object { $_.Thumbprint -eq $root.Thumbprint } |
        Select-Object -First 1
    if ($trustedDevelopmentRoot) {
        throw "The Keep Vault development root is installed in CurrentUser\\Root. Remove thumbprint $($root.Thumbprint) from that trust store before signing."
    }

    return $cert
}

function Assert-DevelopmentRootNotTrusted {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate)

    if ($Certificate.Subject -ne "CN=Keep Vault Development Signing SHA512" -or
        $Certificate.Issuer -ne "CN=Keep Vault Development Root SHA512") {
        return
    }

    $trustedDevelopmentRoot = Get-ChildItem Cert:\CurrentUser\Root |
        Where-Object { $_.Subject -eq $Certificate.Issuer } |
        Select-Object -First 1
    if ($trustedDevelopmentRoot) {
        throw "The Keep Vault development root is globally trusted in CurrentUser\\Root (thumbprint $($trustedDevelopmentRoot.Thumbprint)). Remove it before signing."
    }
}

function Get-DefaultTargets {
    $candidates = [System.Collections.Generic.List[string]](Get-NativeToolTargets -Root $root)

    $applicationDirectory = Join-Path $root "KalynaArchiver\bin\$Configuration\net10.0-windows"
    if (Test-Path -LiteralPath $applicationDirectory) {
        Get-ChildItem -LiteralPath $applicationDirectory -File |
            Where-Object { $_.Extension -in @(".exe", ".dll") } |
            ForEach-Object { $candidates.Add($_.FullName) }
    }

    return $candidates |
        Where-Object { Test-Path -LiteralPath $_ } |
        Select-Object -Unique
}

function Invoke-SignTool {
    param(
        [string] $SignTool,
        [string] $Target,
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate
    )
    $existingSignature = Get-AuthenticodeSignature -LiteralPath $Target
    if ($existingSignature.Status -ne 'NotSigned') {
        & $SignTool remove '/s' '/q' $Target
        if ($LASTEXITCODE -ne 0) { throw "Cannot remove the previous signature: $Target" }
    }
    # SignerSignEx2 receives the ephemeral certificate and CALG_SHA_512 directly.
    # The PFX password/private key never enters signtool arguments or disk.
    [KalynaArchiver.Signing.ReleaseAuthenticodeSigner]::SignSha512($Target, $Certificate)
    $signed = Get-AuthenticodeSignature -LiteralPath $Target
    if (-not $signed.SignerCertificate -or $signed.Status -in @('NotSigned', 'HashMismatch')) {
        throw "In-memory Authenticode signing failed: $Target ($($signed.Status))"
    }
    $trustStatus = [KalynaArchiver.Signing.ReleaseAuthenticode]::Verify($Target)
    if ($trustStatus -notin @(0, 0x800B0109u)) {
        throw ("Authenticode failed Windows digest verification: 0x{0:X8}" -f $trustStatus)
    }
    if ($TimestampUrl) {
        & $SignTool timestamp '/td' 'SHA512' '/tr' $TimestampUrl $Target
        if ($LASTEXITCODE -ne 0 -and -not $AllowUntimestamped) {
            throw "RFC3161 timestamping failed: $Target"
        }
        $timestamped = Get-AuthenticodeSignature -LiteralPath $Target
        if (-not $timestamped.TimeStamperCertificate -and -not $AllowUntimestamped) {
            throw "The requested RFC3161 timestamp is missing: $Target"
        }
    }
    elseif (-not $AllowUntimestamped) {
        throw 'A timestamp server is mandatory unless AllowUntimestamped is explicitly set.'
    }
    [KalynaArchiver.Signing.ReleaseAuthenticodePolicy]::RequireSha512($Target)
}
if (-not $Path -or $Path.Count -eq 0) {
    $Path = Get-DefaultTargets
}

if (-not $Path -or $Path.Count -eq 0) {
    throw "No binaries found to sign."
}

# Hybrid signing loads the ML-DSA reference DLL into this process. Sign that
# binary first, while it is still writable, and never sign an alias twice.
$resolvedPaths = [System.Collections.Generic.List[string]]::new()
$seenPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($target in $Path) {
    $fullPath = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $target).Path)
    if ($seenPaths.Add($fullPath)) { $resolvedPaths.Add($fullPath) }
}
if ($MldsaReferencePath) {
    $referenceFullPath = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $MldsaReferencePath).Path)
    for ($targetIndex = 0; $targetIndex -lt $resolvedPaths.Count; $targetIndex++) {
        if ([StringComparer]::OrdinalIgnoreCase.Equals($resolvedPaths[$targetIndex], $referenceFullPath)) {
            $resolvedPaths.RemoveAt($targetIndex)
            $resolvedPaths.Insert(0, $referenceFullPath)
            break
        }
    }
}
$Path = $resolvedPaths.ToArray()

$signTool = Find-SignTool
. (Join-Path $PSScriptRoot 'Import-SigningRuntime.ps1')
Import-SigningRuntime -NoBuild
$ownedCertificate = $null
if (-not $SigningCertificate) {
    if ($PfxPath) {
        if (-not $PfxPasswordEncryptedPath -or -not $PfxWrappingKeyPath) {
            throw 'PFX signing requires the v12 password envelope and its separate wrapping-key file.'
        }
        $ownedCertificate = [KalynaArchiver.Signing.ReleaseSigningOperations]::LoadCertificate(
            (Resolve-Path -LiteralPath $PfxPath).Path, $PfxPasswordEncryptedPath, $PfxWrappingKeyPath)
    }
    elseif ($CertificateThumbprint) {
        $normalizedCertificateThumbprint = Normalize-Hex $CertificateThumbprint 40 'Certificate thumbprint'
        $ownedCertificate = Get-Item -LiteralPath "Cert:\CurrentUser\My\$normalizedCertificateThumbprint"
    }
    elseif ($CreateDevelopmentCertificate) {
        $ownedCertificate = Get-DevelopmentCertificate
    }
    else { throw 'Provide PfxPath, CertificateThumbprint, or CreateDevelopmentCertificate.' }
    $SigningCertificate = $ownedCertificate
}
try {
Assert-DevelopmentRootNotTrusted $SigningCertificate
$pins = Get-SignerPins $SigningCertificate
if ($pins.Sha256 -cne $expectedSha256 -or $pins.Sha3 -cne $expectedSha3 -or $pins.Skein -cne $expectedSkein) {
    throw 'The selected signing certificate does not match the mandatory RSA pins.'
}
foreach ($target in $Path) {
    $resolvedTarget = Resolve-Path -LiteralPath $target
    Invoke-SignTool -SignTool $signTool -Target $resolvedTarget -Certificate $SigningCertificate
    $signature = Get-AuthenticodeSignature -LiteralPath $resolvedTarget
    if ($signature.Status -eq "NotSigned" -or -not $signature.SignerCertificate) {
        throw "Signing did not produce an Authenticode signer certificate for $resolvedTarget."
    }

    Assert-DevelopmentRootNotTrusted $signature.SignerCertificate
    if ($signature.SignerCertificate.SignatureAlgorithm.Value -ne "1.2.840.113549.1.1.13") {
        throw "The Authenticode signer certificate is not signed with SHA-512/RSA: $resolvedTarget"
    }
    $pins = Get-SignerPins $signature.SignerCertificate
    if (($pins.Sha256 -cne $expectedSha256) -or
        ($pins.Sha3 -cne $expectedSha3) -or
        ($pins.Skein -cne $expectedSkein)) {
        throw "Signed file does not match the mandatory SHA-256/SHA3-512/Skein-1024 SPKI signer pins: $resolvedTarget"
    }

    $signer = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { "unknown signer" }
    $hybridParameters = @{
        Path = $resolvedTarget
        ExpectedSignerSha256 = $expectedSha256
        ExpectedSignerSha3_512 = $expectedSha3
        ExpectedSignerSkein1024 = $expectedSkein
        ExpectedMldsa87Sha256 = $expectedMldsaSha256
        ExpectedMldsa87Sha3_512 = $expectedMldsaSha3
        ExpectedMldsa87Skein1024 = $expectedMldsaSkein
        NoBuild = $true
    }
    $hybridParameters.SigningCertificate = $SigningCertificate
    if ($MldsaPrivateKeyPath) { $hybridParameters.MldsaPrivateKeyPath = $MldsaPrivateKeyPath }
    if ($MldsaPrivateKeyEncryptedPath) { $hybridParameters.MldsaPrivateKeyEncryptedPath = $MldsaPrivateKeyEncryptedPath }
    if ($WrappingKeyPath) { $hybridParameters.WrappingKeyPath = $WrappingKeyPath }
    if ($MldsaPublicKeyPath) { $hybridParameters.MldsaPublicKeyPath = $MldsaPublicKeyPath }
    if ($MldsaReferencePath) { $hybridParameters.MldsaReferencePath = $MldsaReferencePath }
    & $hybridSignatureScript @hybridParameters
    if ($LASTEXITCODE -ne 0) {
        throw "Hybrid signing failed for $resolvedTarget."
    }

    Write-Host "Signed $resolvedTarget [$($signature.Status)] $signer [RSA-4096/SHA-512 + ML-DSA-87 valid]"
}

}
finally {
    if ($ownedCertificate) { $ownedCertificate.Dispose() }
}
