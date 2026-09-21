# Public-identity and parameter-selection regression. No private key is read or
# generated, no native product is loaded, and no trust-store entry is changed.
param([string] $DotnetPath = 'dotnet')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$evidence = Join-Path $root ('work\windows-release-identity-' + [Guid]::NewGuid().ToString('N'))
$fixture = Join-Path $evidence 'fixture'
$keys = Join-Path $fixture 'inert-key-placeholders'
$public = Join-Path $fixture 'WindowsRelease\Signing'
foreach ($directory in @($evidence, $public, $keys, (Join-Path $fixture 'tools'))) {
    [IO.Directory]::CreateDirectory($directory) | Out-Null
}
$helper = Join-Path $fixture 'tools\New-ReleaseSigningParameters.ps1'
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'New-ReleaseSigningParameters.ps1') -Destination $helper
Copy-Item -LiteralPath (Join-Path $root 'Directory.Build.props') -Destination (Join-Path $fixture 'Directory.Build.props')
foreach ($name in @('Directory.Build.props', 'mldsa87-public.key', 'hybrid-rsa4096.cer')) {
    Copy-Item -LiteralPath (Join-Path $root "WindowsRelease\Signing\$name") -Destination (Join-Path $public $name)
}
foreach ($name in @('hybrid-rsa4096.pfx', 'hybrid-rsa4096.pfx.password.v12.usb.enc', 'mldsa87-private.key.v12.enc')) {
    [IO.File]::WriteAllText((Join-Path $keys $name), 'INERT TEST PLACEHOLDER; NEVER A PRIVATE KEY')
}
$outcomes = [Collections.Generic.List[object]]::new()
$report = [ordered]@{
    State = 'FAIL'
    Scope = 'Public identity, inert private-file placeholders, and managed/MSBuild evaluation only.'
    Checks = $outcomes
}
function Record-Pass([string] $Name) {
    $outcomes.Add([pscustomobject]@{ Name = $Name; Passed = $true })
    Write-Host "PASS $Name"
}
function Require-Rejection([scriptblock] $Operation, [string] $Name) {
    $rejected = $false
    try { & $Operation | Out-Null }
    catch { $rejected = $true }
    if (-not $rejected) { throw "Unexpected acceptance: $Name" }
    Record-Pass $Name
}
$wrappers = @('pfx-v12-wrapping-key.dpapi', 'mldsa-v12-wrapping-key.dpapi',
    'pfx-v12-wrapping-key.b64', 'mldsa-v12-wrapping-key.b64')
function Set-WrapperMask([int] $Mask) {
    for ($index = 0; $index -lt $wrappers.Count; $index++) {
        $path = Join-Path $keys $wrappers[$index]
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
        if ($Mask -band (1 -shl $index)) { [IO.File]::WriteAllText($path, 'INERT WRAPPER PLACEHOLDER') }
    }
}
$policyPath = Join-Path $public 'Directory.Build.props'
$originalPolicy = [IO.File]::ReadAllText($policyPath)
$originalPublic = [IO.File]::ReadAllBytes((Join-Path $public 'mldsa87-public.key'))
try {
    for ($mask = 0; $mask -lt 16; $mask++) {
        Set-WrapperMask $mask
        if ($mask -in @(3, 12)) {
            $selected = & $helper -ReleaseKeyDirectory $keys
            $extension = if ($mask -eq 3) { '.dpapi' } else { '.b64' }
            if (-not $selected.PfxWrappingKeyPath.EndsWith($extension) -or
                -not $selected.WrappingKeyPath.EndsWith($extension) -or
                $selected.MldsaPublicKeyPath -cne (Join-Path $public 'mldsa87-public.key')) {
                throw 'The selected complete wrapping-key variant changed.'
            }
            Record-Pass "complete wrapping pair $extension"
        }
        else { Require-Rejection { & $helper -ReleaseKeyDirectory $keys } "reject incomplete/mixed/ambiguous wrapper mask $mask" }
    }
    Set-WrapperMask 3
    $selected = & $helper -ReleaseKeyDirectory $keys
    foreach ($mutation in @('missing-pin', 'duplicate-pin', 'invalid-pin')) {
        [xml] $xml = $originalPolicy
        $node = $xml.SelectSingleNode('/Project/PropertyGroup/KalynaExpectedSignerSha256')
        switch ($mutation) {
            'missing-pin' { $null = $node.ParentNode.RemoveChild($node) }
            'duplicate-pin' { $null = $node.ParentNode.AppendChild($node.CloneNode($true)) }
            'invalid-pin' { $node.InnerText = 'X' * 64 }
        }
        $xml.Save($policyPath)
        Require-Rejection { & $helper -ReleaseKeyDirectory $keys } "reject $mutation"
        [IO.File]::WriteAllText($policyPath, $originalPolicy)
    }
    [xml] $xml = $originalPolicy
    $node = $xml.SelectSingleNode('/Project/PropertyGroup/KalynaExpectedSignerSha256')
    $null = $node.ParentNode.RemoveChild($node)
    $xml.Save($policyPath)
    $evaluationProject = Join-Path $fixture 'policy-defaults.proj'
    [IO.File]::WriteAllText($evaluationProject, '<Project><Import Project="Directory.Build.props"/></Project>')
    $missingPin = & $DotnetPath msbuild $evaluationProject -nologo -p:KalynaReleaseIdentity=true -getProperty:KalynaExpectedSignerSha256
    if ($LASTEXITCODE -ne 0 -or -not [string]::IsNullOrWhiteSpace(($missingPin -join ''))) {
        throw 'An incomplete release policy silently inherited a development signer.'
    }
    Record-Pass 'incomplete Windows policy cannot inherit development defaults'
    [IO.File]::WriteAllText($policyPath, $originalPolicy)
    $changedPublic = $originalPublic.Clone()
    $changedPublic[0] = $changedPublic[0] -bxor 1
    [IO.File]::WriteAllBytes((Join-Path $public 'mldsa87-public.key'), $changedPublic)
    Require-Rejection { & $helper -ReleaseKeyDirectory $keys } 'reject modified public ML-DSA bytes'
    [IO.File]::WriteAllBytes((Join-Path $public 'mldsa87-public.key'), $originalPublic)
    [xml] $xml = $originalPolicy
    $xml.SelectSingleNode('/Project/PropertyGroup/KalynaSigningCertificateThumbprint').InnerText = '0' * 40
    $xml.Save($policyPath)
    Require-Rejection { & $helper -ReleaseKeyDirectory $keys } 'reject a different public certificate selector'
    [IO.File]::WriteAllText($policyPath, $originalPolicy)
    $missing = Join-Path $keys 'hybrid-rsa4096.pfx'
    Remove-Item -LiteralPath $missing -Force
    Require-Rejection { & $helper -ReleaseKeyDirectory $keys } 'reject missing private-file placeholder without opening any private contents'
    [IO.File]::WriteAllText($missing, 'INERT TEST PLACEHOLDER; NEVER A PRIVATE KEY')

    # Import only the two actual preflight functions, never the release core.
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $PSScriptRoot 'Build-PortableCore.ps1'), [ref] $tokens, [ref] $errors)
    if ($errors.Count) { throw 'The release core has parser errors.' }
    foreach ($name in @('Assert-ReleaseParameterValue', 'Assert-ReleasePublicFingerprints')) {
        $definition = $ast.Find({ param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
        }, $true)
        if ($null -eq $definition) { throw "Missing actual preflight function: $name" }
        . ([scriptblock]::Create($definition.Extent.Text))
    }
    foreach ($name in @('CertificateThumbprint', 'ExpectedSignerSha256', 'ExpectedSignerSha3_512',
        'ExpectedSignerSkein1024', 'ExpectedMldsa87Sha256', 'ExpectedMldsa87Sha3_512', 'ExpectedMldsa87Skein1024')) {
        Assert-ReleaseParameterValue $name $selected[$name].ToLowerInvariant() $selected[$name]
        Require-Rejection { Assert-ReleaseParameterValue $name ('0' * $selected[$name].Length) $selected[$name] } "reject overridden $name"
    }
    foreach ($name in @('PfxPath', 'PfxPasswordEncryptedPath', 'PfxWrappingKeyPath',
        'MldsaPrivateKeyEncryptedPath', 'WrappingKeyPath', 'MldsaPublicKeyPath')) {
        Assert-ReleaseParameterValue $name $selected[$name] $selected[$name] -Path
        Require-Rejection { Assert-ReleaseParameterValue $name ($selected[$name] + '.other') $selected[$name] -Path } "reject overridden $name"
    }

    # Load the already built managed signing library only; never trigger a
    # concurrent build or load any native reference/cryptographic product.
    $managed = Join-Path $root 'KalynaSigningTool\bin\Release\net10.0-windows'
    foreach ($name in @('BouncyCastle.Cryptography.dll', 'KalynaArchiver.Signing.dll')) {
        [Reflection.Assembly]::LoadFrom((Join-Path $managed $name)) | Out-Null
    }
    Assert-ReleasePublicFingerprints $originalPublic 'ExpectedMldsa87' $selected
    $certificate = [Security.Cryptography.X509Certificates.X509CertificateLoader]::LoadCertificateFromFile(
        (Join-Path $public 'hybrid-rsa4096.cer'))
    $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($certificate)
    try {
        $spki = $rsa.ExportSubjectPublicKeyInfo()
        Assert-ReleasePublicFingerprints $spki 'ExpectedSigner' $selected
        Record-Pass 'all six public RSA/ML-DSA fingerprints match the actual Windows identity'
        foreach ($prefix in @('ExpectedSigner', 'ExpectedMldsa87')) {
            foreach ($suffix in @('Sha256', 'Sha3_512', 'Skein1024')) {
                $changed = @{} + $selected
                $pin = $prefix + $suffix
                $changed[$pin] = '0' * $changed[$pin].Length
                $bytes = if ($prefix -eq 'ExpectedSigner') { $spki } else { $originalPublic }
                Require-Rejection { Assert-ReleasePublicFingerprints $bytes $prefix $changed } "reject wrong $pin"
            }
        }
    }
    finally { $rsa.Dispose(); $certificate.Dispose() }

    $properties = 'KalynaExpectedSignerSha256,KalynaExpectedSignerSha3_512,KalynaExpectedSignerSkein1024,KalynaExpectedMldsa87Sha256,KalynaExpectedMldsa87Sha3_512,KalynaExpectedMldsa87Skein1024'
    $evaluations = @(
        @{ Name = 'Windows development'; Release = 'false'; Project = 'KalynaArchiver\KalynaArchiver.csproj'; Policy = 'Directory.Build.props'; PublicKey = 'tools\mldsa87-public.key' },
        @{ Name = 'Windows release'; Release = 'true'; Project = 'KalynaArchiver\KalynaArchiver.csproj'; Policy = 'WindowsRelease\Signing\Directory.Build.props'; PublicKey = 'WindowsRelease\Signing\mldsa87-public.key' },
        @{ Name = 'macOS remains separate'; Release = 'true'; Project = 'KeepVaultMac\KeepVaultMac.csproj'; Policy = 'KeepVaultMac\Directory.Build.props'; PublicKey = 'KeepVaultMac\Packaging\Keys\mldsa87-public.key' })
    foreach ($case in $evaluations) {
        $arguments = @('msbuild', (Join-Path $root $case.Project), '-nologo',
            "-p:KalynaReleaseIdentity=$($case.Release)", "-getProperty:$properties", '-getItem:EmbeddedResource')
        $evaluation = & $DotnetPath @arguments
        if ($LASTEXITCODE -ne 0) { throw "MSBuild identity evaluation failed ($($case.Name))." }
        $evaluation = ($evaluation -join [Environment]::NewLine) | ConvertFrom-Json
        $resource = @($evaluation.Items.EmbeddedResource | Where-Object LogicalName -eq 'KeepVault.MLDsa87.PublicKey')
        $expected = Join-Path $root $case.PublicKey
        if ($resource.Count -ne 1 -or $resource[0].FullPath -ine $expected) { throw 'The embedded ML-DSA identity selection changed.' }
        [xml] $expectedPolicy = Get-Content -LiteralPath (Join-Path $root $case.Policy) -Raw
        foreach ($property in $properties.Split(',')) {
            if ($evaluation.Properties.$property -cne $expectedPolicy.SelectSingleNode('/Project/PropertyGroup/' + $property).InnerText) {
                throw "The evaluated $property does not match the selected policy."
            }
        }
        Record-Pass "MSBuild public identity and exact embedded key: $($case.Name)"
    }
    $report.State = 'PASS'
}
finally {
    $report | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $evidence 'results.json') -Encoding utf8NoBOM
    Write-Host "Public-only identity evidence: $evidence"
}
