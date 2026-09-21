# Creates a new Windows-only public release identity and its private local key
# store. The destination must not exist and must be outside Git and OneDrive.
param(
    [Parameter(Mandatory = $true)] [string] $ReleaseKeyDirectory,
    [string] $DotnetPath = 'dotnet'
)
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Push-Location -LiteralPath $root
try {
    & $DotnetPath build (Join-Path $root 'KalynaSigningTool\KalynaSigningTool.csproj') -c Release -p:RestoreLockedMode=true --nologo
    if ($LASTEXITCODE -ne 0) { throw 'The release-key generator build failed.' }
    $tool = Join-Path $root 'KalynaSigningTool\bin\Release\net10.0-windows\KalynaSigningTool.dll'
    & $DotnetPath $tool release-keygen --directory ([IO.Path]::GetFullPath($ReleaseKeyDirectory)) --public-directory (Join-Path $root 'WindowsRelease\Signing')
    if ($LASTEXITCODE -ne 0) { throw 'The Windows release-key generator failed; inspect the error without deleting or overwriting a key directory.' }
}
finally { Pop-Location }
