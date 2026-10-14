# Load the reviewed signing implementation into this process. Secret values
# never need a command-line argument, an environment variable, or a temp file.
function Import-SigningRuntime {
    param([switch] $NoBuild)

    $signingRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
    $signingProject = Join-Path $signingRoot 'KalynaSigningTool\KalynaSigningTool.csproj'
    $signingDirectory = Join-Path $signingRoot 'KalynaSigningTool\bin\Release\net10.0-windows'
    $assemblyPath = Join-Path $signingDirectory 'KalynaArchiver.Signing.dll'
    if (-not $NoBuild -or -not (Test-Path -LiteralPath $assemblyPath -PathType Leaf)) {
        & dotnet build $signingProject -c Release --nologo
        if ($LASTEXITCODE -ne 0) { throw 'The release signing runtime build failed.' }
    }

    $loaded = [AppDomain]::CurrentDomain.GetAssemblies() |
        Where-Object { $_.GetName().Name -eq 'KalynaArchiver.Signing' } |
        Select-Object -First 1
    if ($loaded) {
        if (-not [string]::Equals($loaded.Location, $assemblyPath, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Another signing runtime is already loaded. Start a fresh PowerShell process for this snapshot.'
        }
        return
    }
    foreach ($name in @('BouncyCastle.Cryptography.dll', 'System.Security.Cryptography.ProtectedData.dll', 'KalynaArchiver.Signing.dll')) {
        $dependency = Join-Path $signingDirectory $name
        if (Test-Path -LiteralPath $dependency -PathType Leaf) {
            [Reflection.Assembly]::LoadFrom($dependency) | Out-Null
        }
    }
}
