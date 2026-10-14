param([string] $Root = (Join-Path $PSScriptRoot '..'))
$ErrorActionPreference = 'Stop'
$rootPath = [IO.Path]::GetFullPath($Root)
. (Join-Path $PSScriptRoot 'LocalWorkspacePolicy.ps1')
Assert-LocalReleaseWorkspace $rootPath
$paths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

foreach ($manifest in @('external/NATIVE_SOURCE_SHA256SUMS', 'native/WINDOWS_SOURCE_SHA256SUMS')) {
    $manifestPath = Join-Path $rootPath $manifest
    $manifestInfo = Get-Item -LiteralPath $manifestPath
    if ($manifestInfo.PSIsContainer -or ($manifestInfo.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "The native source manifest is not a regular file: $manifest"
    }
    $count = 0
    foreach ($line in [IO.File]::ReadAllLines($manifestPath)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -cnotmatch '^([0-9A-F]{64}) (external/[A-Za-z0-9_./+-]+|native/[A-Za-z0-9_./+-]+)$') {
            throw "Invalid native source manifest entry in $manifest."
        }
        $expected = $Matches[1]
        $relative = $Matches[2]
        if (@($relative.Split('/') | Where-Object { $_ -in @('', '.', '..') -or $_.EndsWith('.') }).Count -ne 0 -or -not $paths.Add($relative)) {
            throw "Duplicate or unsafe native source path: $relative"
        }
        $sourcePath = [IO.Path]::GetFullPath((Join-Path $rootPath $relative))
        if (-not $sourcePath.StartsWith($rootPath.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw "Native source escapes the repository: $relative"
        }
        $source = Get-Item -LiteralPath $sourcePath
        if ($source.PSIsContainer) { throw "Pinned native source is a directory: $relative" }
        for ($item = $source; $null -ne $item -and $item.FullName -ne $rootPath; $item = $(if ($item -is [IO.FileInfo]) { $item.Directory } else { $item.Parent })) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Native source traverses a reparse point: $relative" }
        }
        if ((Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash -cne $expected) {
            throw "Pinned native source SHA-256 mismatch: $relative"
        }
        $count++
    }
    if ($count -eq 0) { throw "The native source manifest is empty: $manifest" }
    Write-Output "$manifest verified: $count files"
}

$pinnedCpp = @($paths | Where-Object { $_ -cmatch '^external/cryptopp/[^/]+\.cpp$' } | Sort-Object)
$actualCpp = @(Get-ChildItem -LiteralPath (Join-Path $rootPath 'external/cryptopp') -Filter '*.cpp' -File |
    ForEach-Object { 'external/cryptopp/' + $_.Name } | Sort-Object)
if ($pinnedCpp.Count -eq 0 -or $pinnedCpp.Count -ne $actualCpp.Count -or
    (Compare-Object -ReferenceObject $pinnedCpp -DifferenceObject $actualCpp -CaseSensitive)) {
    throw 'The Crypto++ source inventory differs from the reviewed manifest.'
}
Write-Output "Crypto++ compilation inventory verified: $($actualCpp.Count) translation units"
