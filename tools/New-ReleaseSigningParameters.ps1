# Returns public paths and compiled public-key pins only. Key files are opened
# in memory by Sign-Binaries/New-HybridSignature, never by this parameter helper.
param(
    [Parameter(Mandatory = $true)]
    [string] $ReleaseKeyDirectory
)
$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$keyRoot = [IO.Path]::GetFullPath($ReleaseKeyDirectory)
[xml] $properties = Get-Content -LiteralPath (Join-Path $repoRoot 'KeepVaultMac\Directory.Build.props')
$signingParameters = @{
    PfxPath = Join-Path $keyRoot 'hybrid-rsa4096.pfx'
    PfxPasswordEncryptedPath = Join-Path $keyRoot 'hybrid-rsa4096.pfx.password.v12.usb.enc'
    PfxWrappingKeyPath = Join-Path $keyRoot 'pfx-v12-wrapping-key.b64'
    MldsaPrivateKeyEncryptedPath = Join-Path $keyRoot 'mldsa87-private.key.v12.enc'
    WrappingKeyPath = Join-Path $keyRoot 'mldsa-v12-wrapping-key.b64'
    MldsaPublicKeyPath = Join-Path $repoRoot 'KeepVaultMac\Packaging\Keys\mldsa87-public.key'
    MldsaReferencePath = Join-Path $repoRoot 'tools\mldsa87_ref.dll'
}
foreach ($name in @('ExpectedSignerSha256', 'ExpectedSignerSha3_512', 'ExpectedSignerSkein1024',
    'ExpectedMldsa87Sha256', 'ExpectedMldsa87Sha3_512', 'ExpectedMldsa87Skein1024')) {
    $value = $properties.Project.PropertyGroup.SelectSingleNode('Kalyna' + $name).InnerText
    if ([string]::IsNullOrWhiteSpace($value)) { throw "The release policy is missing $name." }
    $signingParameters[$name] = $value
}
return $signingParameters
