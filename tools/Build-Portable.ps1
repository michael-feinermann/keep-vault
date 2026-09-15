param(
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

$ErrorActionPreference = 'Stop'
if ($Runtime -cne 'win-x64' -or $Configuration -cne 'Release') { throw 'The Windows release pipeline requires Release/win-x64.' }
if ($SkipSigning -or $CreateDevelopmentCertificate -or $TrustDevelopmentCertificate) {
    throw 'Unsigned or development-certificate overrides are forbidden in the release pipeline.'
}
if (-not $ReleaseKeyDirectory) { throw 'The production release pipeline requires ReleaseKeyDirectory.' }
. (Join-Path $PSScriptRoot 'ReleaseSourceSnapshot.ps1')
$snapshot = New-ReleaseSourceSnapshot -RepositoryRoot (Join-Path $PSScriptRoot '..')
$buildFailure = $null
try {
    $parameters = @{} + $PSBoundParameters
    $parameters.Remove('MldsaReferencePath')
    $parameters.Remove('MldsaPublicKeyPath')
    $parameters.SnapshotLease = $snapshot
    & (Join-Path $snapshot.Root 'tools\Build-PortableCore.ps1') @parameters
    $snapshot.Verify()
    Copy-Item -LiteralPath $snapshot.ReportPath -Destination ($snapshot.ReportPath.Replace('-before.', '-after.'))
    Write-Host "Release source commit: $($snapshot.Commit)"
    Write-Host "Verified artifacts: $($snapshot.Root)\dist"
}
catch { $buildFailure = $_.Exception; throw }
finally {
    try { $snapshot.Dispose() }
    catch {
        if ($buildFailure) { throw [AggregateException]::new('Release build and snapshot cleanup both failed.', [Exception[]]@($buildFailure, $_.Exception)) }
        throw
    }
}
