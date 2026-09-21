# Explicitly creates a NEW portable, private folder. Unlike the local DPAPI
# store, this export contains the AES wrapping keys needed on another machine.
param(
    [Parameter(Mandatory = $true)] [string] $ReleaseKeyDirectory,
    [Parameter(Mandatory = $true)] [string] $Destination,
    [string] $DotnetPath = 'dotnet'
)
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Push-Location -LiteralPath $root
try {
    & $DotnetPath build (Join-Path $root 'KalynaSigningTool\KalynaSigningTool.csproj') -c Release -p:RestoreLockedMode=true --nologo
    if ($LASTEXITCODE -ne 0) { throw 'The release-key export tool build failed.' }
    $tool = Join-Path $root 'KalynaSigningTool\bin\Release\net10.0-windows\KalynaSigningTool.dll'
    & $DotnetPath $tool release-key-export --directory ([IO.Path]::GetFullPath($ReleaseKeyDirectory)) --destination ([IO.Path]::GetFullPath($Destination))
    if ($LASTEXITCODE -ne 0) { throw 'The Windows release-key export failed; no existing destination is overwritten.' }
}
finally { Pop-Location }
