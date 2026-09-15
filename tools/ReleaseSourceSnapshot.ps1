$ErrorActionPreference = 'Stop'
if (-not ('KeepVaultBuild.SourceSnapshotLease' -as [type])) {
    Add-Type -Path (Join-Path $PSScriptRoot 'ReleaseSourceSnapshot.cs')
}

function Invoke-SnapshotGit {
    param([string] $Directory, [string[]] $Arguments)
    $output = & git -C $Directory @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Git snapshot operation failed: $($Arguments[0])" }
    return $output
}

function New-ReleaseSourceSnapshot {
    param([Parameter(Mandatory)][string] $RepositoryRoot)
    $repository = [IO.Path]::GetFullPath($RepositoryRoot)
    $gitRoot = Invoke-SnapshotGit $repository @('rev-parse', '--show-toplevel')
    if ([IO.Path]::GetFullPath($gitRoot) -ine $repository) { throw 'Release must start at the repository root.' }
    if (Get-UncommittedReleaseSources $repository) {
        throw 'Commit and review every source change before packaging; the release tree must be clean.'
    }
    $commit = Invoke-SnapshotGit $repository @('rev-parse', '--verify', 'HEAD^{commit}')
    if ($commit -cnotmatch '^[0-9a-f]{40}$') { throw 'A full committed source identity is required.' }
    $settings = @{}
    foreach ($name in @('core.autocrlf', 'core.eol')) {
        $value = & git -C $repository config --get $name
        if ($LASTEXITCODE -notin @(0, 1)) { throw "Cannot read checkout setting $name." }
        $settings[$name] = if ($value) { $value } elseif ($name -eq 'core.eol') { 'native' } else { 'false' }
    }
    # Keep compiler/archiver paths short even when the checkout lives below
    # a long OneDrive directory. This is independent, disposable build storage.
    $snapshotParent = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.codex\release-builds'
    [IO.Directory]::CreateDirectory($snapshotParent) | Out-Null
    $container = Join-Path $snapshotParent ($commit.Substring(0, 12) + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 16))
    [IO.Directory]::CreateDirectory($container) | Out-Null
    $source = Join-Path $container 'src'
    & git -c core.longpaths=true clone --local --no-hardlinks --no-checkout -- $repository $source
    if ($LASTEXITCODE -ne 0) { throw 'The independent committed source clone failed.' }
    foreach ($name in $settings.Keys) { $null = Invoke-SnapshotGit $source @('config', $name, $settings[$name]) }
    $null = Invoke-SnapshotGit $source @('config', 'core.longpaths', 'true')
    $null = Invoke-SnapshotGit $source @('checkout', '--detach', $commit)
    $null = Invoke-SnapshotGit $source @('remote', 'remove', 'origin')
    if (Test-Path -LiteralPath (Join-Path $source '.git\objects\info\alternates')) { throw 'Shared Git object storage is forbidden.' }
    if ((Invoke-SnapshotGit $source @('rev-parse', 'HEAD')) -cne $commit -or
        (Invoke-SnapshotGit $repository @('rev-parse', 'HEAD')) -cne $commit -or
        (Get-UncommittedReleaseSources $repository) -or
        (Invoke-SnapshotGit $source @('status', '--porcelain=v1', '--untracked-files=all'))) {
        throw 'Source identity changed during snapshot creation.'
    }
    $tracked = (Invoke-SnapshotGit $source @('ls-files', '-z', '--')).Split([char]0, [StringSplitOptions]::RemoveEmptyEntries)
    $inputs = @($tracked | Where-Object { -not [KeepVaultBuild.SourceSnapshotLease]::IsOutput($_) })
    if ($inputs.Count -eq 0) { throw 'The committed source inventory is empty.' }
    foreach ($directory in @('work', 'dist', 'build-analysis')) {
        [IO.Directory]::CreateDirectory((Join-Path $source $directory)) | Out-Null
    }
    if (Test-Path -LiteralPath (Join-Path $source 'QrCodeScannerWindows') -PathType Container) {
        [IO.Directory]::CreateDirectory((Join-Path $source 'QrCodeScannerWindows\dist')) | Out-Null
    }
    foreach ($project in $inputs | Where-Object { $_.EndsWith('.csproj', [StringComparison]::OrdinalIgnoreCase) }) {
        $projectDirectory = Split-Path -Parent (Join-Path $source $project)
        foreach ($directory in @('bin', 'obj', 'obj_alt', 'build-obj')) {
            [IO.Directory]::CreateDirectory((Join-Path $projectDirectory $directory)) | Out-Null
        }
    }
    [ordered]@{ Commit = $commit; Source = $source; CheckoutSettings = $settings; NativeBinariesAreGeneratedOutputs = $true } |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $container 'provenance.json') -Encoding utf8NoBOM
    $lease = [KeepVaultBuild.SourceSnapshotLease]::new($source, $commit, [string[]]$inputs,
        (Join-Path $container 'source-inputs-before.sha256'))
    try {
        if (Get-UncommittedReleaseSources $source) { throw 'The leased source bytes do not match the committed tree.' }
        return $lease
    }
    catch {
        $sourceFailure = $_.Exception
        try { $lease.Dispose() }
        catch { throw [AggregateException]::new('Source validation and snapshot cleanup both failed.', [Exception[]]@($sourceFailure, $_.Exception)) }
        throw
    }
}

function Get-UncommittedReleaseSources {
    param([string] $RepositoryRoot)
    foreach ($arguments in @(@('diff', '--name-only', '-z', 'HEAD', '--'), @('ls-files', '--others', '--exclude-standard', '-z'))) {
        $raw = Invoke-SnapshotGit $RepositoryRoot $arguments
        if ($raw) {
            ([string]$raw).Split([char]0, [StringSplitOptions]::RemoveEmptyEntries) |
                Where-Object { -not [KeepVaultBuild.SourceSnapshotLease]::IsOutput($_) }
        }
    }
}
