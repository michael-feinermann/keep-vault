# Returns checked public pins and an unambiguous release-key file set. Private
# contents are opened only by Sign-Binaries/New-HybridSignature, never here.
param(
    [Parameter(Mandatory = $true)]
    [string] $ReleaseKeyDirectory
)
$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$keyRoot = [IO.Path]::GetFullPath($ReleaseKeyDirectory)
[xml] $properties = Get-Content -LiteralPath (Join-Path $repoRoot 'WindowsRelease\Signing\Directory.Build.props') -Raw
$pinLengths = [ordered]@{
    SigningCertificateThumbprint = 40
    ExpectedSignerSha256 = 64
    ExpectedSignerSha3_512 = 128
    ExpectedSignerSkein1024 = 256
    ExpectedMldsa87Sha256 = 64
    ExpectedMldsa87Sha3_512 = 128
    ExpectedMldsa87Skein1024 = 256
}
$pins = @{}
foreach ($name in $pinLengths.Keys) {
    $nodes = @($properties.SelectNodes('/Project/PropertyGroup/Kalyna' + $name))
    if ($nodes.Count -ne 1 -or $nodes[0].InnerText -cnotmatch "^[0-9A-Fa-f]{$($pinLengths[$name])}$") {
        throw "The Windows release policy must contain exactly one valid Kalyna$name."
    }
    $pins[$name] = $nodes[0].InnerText.ToUpperInvariant()
}

function Require-RegularReleaseFile {
    param([string] $Path)
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "A release key or public identity path is not a regular file: $Path"
    }
    return $item
}

$wrappingNames = @(
    'pfx-v12-wrapping-key.dpapi', 'mldsa-v12-wrapping-key.dpapi',
    'pfx-v12-wrapping-key.b64', 'mldsa-v12-wrapping-key.b64')
$present = @($wrappingNames | Where-Object { Test-Path -LiteralPath (Join-Path $keyRoot $_) })
$localPair = @('pfx-v12-wrapping-key.dpapi', 'mldsa-v12-wrapping-key.dpapi')
$portablePair = @('pfx-v12-wrapping-key.b64', 'mldsa-v12-wrapping-key.b64')
if ($present.Count -eq 2 -and $present[0] -ceq $localPair[0] -and $present[1] -ceq $localPair[1]) {
    $selectedPair = $localPair
}
elseif ($present.Count -eq 2 -and $present[0] -ceq $portablePair[0] -and $present[1] -ceq $portablePair[1]) {
    $selectedPair = $portablePair
}
else {
    throw 'Use exactly one complete wrapping-key pair: both local .dpapi files or both portable .b64 files; mixed, incomplete and ambiguous sets are forbidden.'
}
$signingParameters = @{
    CertificateThumbprint = $pins.SigningCertificateThumbprint
    PfxPath = Join-Path $keyRoot 'hybrid-rsa4096.pfx'
    PfxPasswordEncryptedPath = Join-Path $keyRoot 'hybrid-rsa4096.pfx.password.v12.usb.enc'
    PfxWrappingKeyPath = Join-Path $keyRoot $selectedPair[0]
    MldsaPrivateKeyEncryptedPath = Join-Path $keyRoot 'mldsa87-private.key.v12.enc'
    WrappingKeyPath = Join-Path $keyRoot $selectedPair[1]
    MldsaPublicKeyPath = Join-Path $repoRoot 'WindowsRelease\Signing\mldsa87-public.key'
    MldsaReferencePath = Join-Path $repoRoot 'tools\mldsa87_ref.dll'
}
foreach ($name in @('PfxPath', 'PfxPasswordEncryptedPath', 'PfxWrappingKeyPath',
    'MldsaPrivateKeyEncryptedPath', 'WrappingKeyPath')) {
    $null = Require-RegularReleaseFile $signingParameters[$name]
}
$publicKey = Require-RegularReleaseFile $signingParameters.MldsaPublicKeyPath
if ($publicKey.Length -ne 2592 -or
    (Get-FileHash -LiteralPath $publicKey.FullName -Algorithm SHA256).Hash -cne $pins.ExpectedMldsa87Sha256) {
    throw 'The Windows ML-DSA-87 public key does not match the committed release identity.'
}
$certificatePath = Join-Path $repoRoot 'WindowsRelease\Signing\hybrid-rsa4096.cer'
$null = Require-RegularReleaseFile $certificatePath
$certificate = [Security.Cryptography.X509Certificates.X509CertificateLoader]::LoadCertificateFromFile($certificatePath)
try {
    if ($certificate.HasPrivateKey -or $certificate.Thumbprint -cne $pins.SigningCertificateThumbprint) {
        throw 'The public Windows certificate does not match its committed selector.'
    }
    $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($certificate)
    try {
        if ($null -eq $rsa -or $rsa.KeySize -ne 4096 -or
            [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($rsa.ExportSubjectPublicKeyInfo())) -cne $pins.ExpectedSignerSha256) {
            throw 'The Windows RSA-4096 public key does not match the committed release identity.'
        }
    }
    finally { if ($rsa) { $rsa.Dispose() } }
}
finally { $certificate.Dispose() }
foreach ($name in @('ExpectedSignerSha256', 'ExpectedSignerSha3_512', 'ExpectedSignerSkein1024',
    'ExpectedMldsa87Sha256', 'ExpectedMldsa87Sha3_512', 'ExpectedMldsa87Skein1024')) {
    $signingParameters[$name] = $pins[$name]
}
return $signingParameters
