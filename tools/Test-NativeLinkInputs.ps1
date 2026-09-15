#requires -Version 7.4
<#
Harmless build-input regression: executes only the marked response-file
generation block from Build-Native.cmd in an isolated synthetic directory.
No compiler, assembler, linker, product EXE/DLL, key, or AV setting is used.
#>
[CmdletBinding()]
param([string] $Root = (Join-Path $PSScriptRoot '..'))
$ErrorActionPreference = 'Stop'
$rootPath = [IO.Path]::GetFullPath($Root)
$buildPath = Join-Path $rootPath 'tools\Build-Native.cmd'
$buildText = [IO.File]::ReadAllText($buildPath)
$match = [regex]::Match($buildText, '(?s)REM BEGIN CRYPTOPP RESPONSE INPUTS\r?\n(.*?)REM END CRYPTOPP RESPONSE INPUTS')
if (-not $match.Success) { throw 'The marked Crypto++ response-file generator is missing.' }
$fragment = $match.Groups[1].Value
if ($fragment -match '(?im)^\s*(?:cl|lib|ml64|pwsh|powershell|start|call)\b') { throw 'The test block unexpectedly contains a build/process command.' }
if ($buildText -notmatch '(?m)^lib /nologo /OUT:"%CPPOBJ%\\cryptopp\.lib" @"%CPPOBJ%\\cryptopp-objects\.rsp"\r?$' -or
    $buildText -match '(?m)^lib .*\\\*\.obj') { throw 'The production linker is not restricted to the explicit object response file.' }

$fixture = Join-Path $rootPath ('work\native-link-inputs-' + [Guid]::NewGuid().ToString('N'))
$fixturePrefix = [IO.Path]::GetFullPath($fixture) + '\'
function Assert-FixturePath([string] $Path) {
    $full = [IO.Path]::GetFullPath($Path)
    if (-not $full.StartsWith($fixturePrefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe synthetic test path.' }
    return $full
}
$cppDirectory = Assert-FixturePath (Join-Path $fixture 'external\cryptopp')
$objectDirectory = Assert-FixturePath (Join-Path $fixture 'work\cryptopp-objects')
[IO.Directory]::CreateDirectory($cppDirectory) | Out-Null
[IO.Directory]::CreateDirectory($objectDirectory) | Out-Null
$cppNames = @(Get-ChildItem -LiteralPath (Join-Path $rootPath 'external\cryptopp') -Filter '*.cpp' -File |
    ForEach-Object Name | Sort-Object)
if ($cppNames.Count -ne 202) { throw "Review changed vendor source inventory: expected 202, got $($cppNames.Count)." }
foreach ($sourceName in $cppNames) {
    if ($sourceName -cnotmatch '^[A-Za-z0-9_.+-]+\.cpp$') { throw 'Unexpected source filename syntax.' }
    [IO.File]::WriteAllText((Assert-FixturePath (Join-Path $cppDirectory $sourceName)), '// synthetic name-only fixture')
}
$sourceRsp = Assert-FixturePath (Join-Path $objectDirectory 'cryptopp-sources.rsp')
$objectRsp = Assert-FixturePath (Join-Path $objectDirectory 'cryptopp-objects.rsp')
[IO.File]::WriteAllText($sourceRsp, 'unreviewed-old-source.cpp')
[IO.File]::WriteAllText($objectRsp, 'unreviewed-old-object.obj')
foreach ($staleName in @('stale-unreviewed.obj', 'test.obj', 'validat0.obj', 'removed-algorithm.obj')) {
    [IO.File]::WriteAllText((Assert-FixturePath (Join-Path $objectDirectory $staleName)), 'synthetic stale object; never linked')
}
$generator = Assert-FixturePath (Join-Path $fixture 'generate-inputs.cmd')
$generatorText = [string]::Join([Environment]::NewLine, @(
    '@echo off',
    'setlocal',
    'cd /d "%~dp0"',
    'set "CRYPTOPP=external\cryptopp"',
    'set "CPPOBJ=work\cryptopp-objects"',
    $fragment,
    'exit /b 0'
))
[IO.File]::WriteAllText($generator, $generatorText, [Text.Encoding]::ASCII)
& $env:ComSpec /d /c $generator
if ($LASTEXITCODE -ne 0) { throw "Synthetic response generation failed: $LASTEXITCODE" }

# Expected set is defined independently of the production batch's filtering.
$drivers = @('test.cpp','bench1.cpp','bench2.cpp','bench3.cpp','datatest.cpp','dlltest.cpp','fipsalgt.cpp','adhoc.cpp')
$compiledCpp = @($cppNames | Where-Object { $_ -notin $drivers -and $_ -notmatch '^(regtest|validat)' })
$optimizedCpp = @($compiledCpp | Where-Object { $_ -notin @('gfpcrypt.cpp', 'hight.cpp') })
$expectedObjects = @($compiledCpp | ForEach-Object { [IO.Path]::GetFileNameWithoutExtension($_) + '.obj' }) + @('x64dll.obj','x64masm.obj')
$actualSources = @([IO.File]::ReadAllLines($sourceRsp) | Where-Object { $_ })
$actualObjects = @([IO.File]::ReadAllLines($objectRsp) | Where-Object { $_ } | ForEach-Object {
    if ($_ -cnotmatch '^"work\\cryptopp-objects\\[A-Za-z0-9_.+-]+\.obj"$') { throw "Unexpected object input: $_" }
    [IO.Path]::GetFileName($_.Trim('"'))
})
if ($actualSources.Count -ne $optimizedCpp.Count -or (Compare-Object $optimizedCpp $actualSources -CaseSensitive)) {
    throw 'Optimized C++ response-file set differs from reviewed library sources.'
}
if ($actualObjects.Count -ne $expectedObjects.Count -or (Compare-Object $expectedObjects $actualObjects -CaseSensitive)) {
    throw 'Library object response-file set differs from the exact C++ plus MASM set.'
}
if (@($actualObjects | Select-Object -Unique).Count -ne $actualObjects.Count) { throw 'Duplicate object input.' }
Write-Host "PASS exact inputs: vendor=$($cppNames.Count); optimized_cpp=$($optimizedCpp.Count); separate_cpp=2; masm=2; library_objects=$($actualObjects.Count)"
Write-Host 'PASS stale/unreviewed/test-driver objects excluded and previous response contents replaced'

# Both output files are fail-closed. A blocked write must stop generation,
# rather than allowing a stale/partially generated response file to be reused.
foreach ($blockedRsp in @($sourceRsp, $objectRsp)) {
    $originalAttributes = [IO.File]::GetAttributes($blockedRsp)
    [IO.File]::SetAttributes($blockedRsp, $originalAttributes -bor [IO.FileAttributes]::ReadOnly)
    try {
        & $env:ComSpec /d /c $generator
        if ($LASTEXITCODE -ne 1) { throw "Response write failure was not rejected: exit=$LASTEXITCODE" }
    } finally { [IO.File]::SetAttributes($blockedRsp, $originalAttributes) }
}
Write-Host 'PASS source/object response-file write failure aborts generation'
[ordered]@{
    Executed='Only marked batch response-file generation; no native build or product execution'
    VendorSources=$cppNames.Count; OptimizedCpp=$optimizedCpp.Count; SeparateCpp=2; Masm=2; LibraryObjects=$actualObjects.Count
    StaleObjectsExcluded=$true; FailedWritesRejected=$true; BuildScriptSha256=(Get-FileHash -LiteralPath $buildPath -Algorithm SHA256).Hash
} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $fixture 'result.json') -Encoding utf8NoBOM
Write-Host "Synthetic evidence retained: $fixture"
