# Synthetic filesystem/Git regression only. Does not build or sign a product,
# run native code, read release keys, or change antivirus configuration.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ReleaseSourceSnapshot.ps1')

function Require-Rejection {
    param([scriptblock] $Operation, [string] $Name)
    $rejected = $false
    try { & $Operation | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw "Unexpected success: $Name" }
    Write-Host "PASS reject: $Name"
}

$testRoot = Join-Path (Join-Path $PSScriptRoot '..\work') ('snapshot-regression-' + [Guid]::NewGuid().ToString('N'))
$repository = Join-Path $testRoot 'repository'
foreach ($name in @('KalynaArchiver', 'tools', 'external')) { [IO.Directory]::CreateDirectory((Join-Path $repository $name)) | Out-Null }
[IO.File]::WriteAllText((Join-Path $repository '.gitignore'), "work/`nbin/`nobj/`nbuild-obj/`nobj_alt/`ndist/`nbuild-analysis/`n")
[IO.File]::WriteAllText((Join-Path $repository 'KalynaArchiver\Demo.csproj'), '<Project Sdk="Microsoft.NET.Sdk" />')
[IO.File]::WriteAllText((Join-Path $repository 'KalynaArchiver\Input.cs'), '// committed source')
[IO.File]::WriteAllText((Join-Path $repository 'external\unit.cpp'), '// reviewed wildcard input')
[IO.File]::WriteAllText((Join-Path $repository 'tools\Build.ps1'), '# committed script')
[IO.File]::WriteAllText((Join-Path $repository 'tools\zpaq.exe'), 'synthetic text output; never executed')
$null = Invoke-SnapshotGit $repository @('init', '--quiet')
$null = Invoke-SnapshotGit $repository @('config', 'core.autocrlf', 'false')
$null = Invoke-SnapshotGit $repository @('config', 'user.name', 'Synthetic release test')
$null = Invoke-SnapshotGit $repository @('config', 'user.email', 'synthetic@example.invalid')
$null = Invoke-SnapshotGit $repository @('add', '--all')
$null = Invoke-SnapshotGit $repository @('commit', '--quiet', '-m', 'Synthetic source baseline')
$commit = Invoke-SnapshotGit $repository @('rev-parse', 'HEAD')

[IO.File]::WriteAllText((Join-Path $repository 'tools\zpaq.exe'), 'different generated output; never executed')
if (Get-UncommittedReleaseSources $repository) { throw 'A named generated native output was classified as source.' }
[IO.File]::WriteAllText((Join-Path $repository 'tools\unexpected.exe'), 'unreviewed executable')
Require-Rejection { New-ReleaseSourceSnapshot $repository } 'unknown executable is not a dirty-tree exemption'
[IO.File]::Delete((Join-Path $repository 'tools\unexpected.exe'))
[IO.File]::AppendAllText((Join-Path $repository 'KalynaArchiver\Input.cs'), ' changed')
Require-Rejection { New-ReleaseSourceSnapshot $repository } 'modified source cannot enter a snapshot'
$null = Invoke-SnapshotGit $repository @('restore', '--', 'KalynaArchiver/Input.cs')
[IO.File]::WriteAllText((Join-Path $repository 'external\extra.cpp'), '// unreviewed wildcard input')
Require-Rejection { New-ReleaseSourceSnapshot $repository } 'untracked wildcard source cannot enter a snapshot'
[IO.File]::Delete((Join-Path $repository 'external\extra.cpp'))

$snapshot = New-ReleaseSourceSnapshot $repository
$snapshotRoot = $snapshot.Root
try {
    if ($snapshot.Commit -cne $commit -or $snapshotRoot -eq $repository) { throw 'Snapshot identity was not bound to a separate exact commit.' }
    if (([IO.File]::ReadAllText((Join-Path $snapshotRoot 'tools\zpaq.exe'))) -ne 'synthetic text output; never executed') {
        throw 'Snapshot copied a dirty generated output from the live source.'
    }
    $report = Get-Content -LiteralPath $snapshot.ReportPath
    if ($report.Count -ne 5 -or $report -match 'zpaq.exe') { throw 'Source hash inventory includes generated output or omits source.' }
    Require-Rejection { [IO.File]::WriteAllText((Join-Path $snapshotRoot 'KalynaArchiver\Input.cs'), 'mutation') } 'source write while leased'
    Require-Rejection { [IO.File]::WriteAllText((Join-Path $snapshotRoot 'external\new.cpp'), 'insertion') } 'new wildcard input while leased'
    Require-Rejection { [IO.File]::WriteAllText((Join-Path $snapshotRoot 'tools\injected.ps1'), 'insertion') } 'new script while leased'
    Require-Rejection { [IO.Directory]::Move($snapshotRoot, "$snapshotRoot-renamed") } 'source root rename while leased'
    [IO.File]::WriteAllText((Join-Path $snapshotRoot 'KalynaArchiver\bin\generated.dll'), 'synthetic managed output')
    $nativeOutputs = Join-Path $snapshotRoot 'work\native-tools'
    [IO.Directory]::CreateDirectory($nativeOutputs) | Out-Null
    foreach ($suffix in @('.dll', '.lib', '.exp', '.dll.khsig', '.dll.sha3', '.signature-temp')) {
        [IO.File]::WriteAllText((Join-Path $nativeOutputs "synthetic$suffix"), 'synthetic linker/signing output')
    }
    [IO.File]::WriteAllText((Join-Path $repository 'KalynaArchiver\Input.cs'), 'later live edit')
    $snapshot.Verify()
    Write-Host 'PASS exact committed clone, independent source, source-only hashes, and writable managed/native/linker/signing outputs'
}
finally { $snapshot.Dispose() }

# DACLs and handles must both be restored, including after output creation.
[IO.File]::WriteAllText((Join-Path $snapshotRoot 'KalynaArchiver\Input.cs'), 'writable after dispose')
[IO.File]::WriteAllText((Join-Path $snapshotRoot 'external\after.cpp'), 'creatable after dispose')
[IO.File]::WriteAllText((Join-Path $snapshotRoot 'tools\after.ps1'), 'creatable after dispose')
[IO.Directory]::Move($snapshotRoot, "$snapshotRoot-released")
Write-Host 'PASS all source ACLs and path/file leases restored after Dispose'

# An empty unreviewed directory must not remain available for a transient
# source injection that disappears again before the final hash comparison.
$emptyTree = Join-Path $testRoot 'empty-insertion'
[IO.Directory]::CreateDirectory((Join-Path $emptyTree 'Injected')) | Out-Null
[IO.File]::WriteAllText((Join-Path $emptyTree 'Input.cs'), '// synthetic')
Require-Rejection {
    $unexpectedLease = [KeepVaultBuild.SourceSnapshotLease]::new($emptyTree, $commit, [string[]]@('Input.cs'), (Join-Path $testRoot 'empty-before.sha256'))
    $unexpectedLease.Dispose()
} 'preexisting empty unreviewed directory'
[IO.File]::WriteAllText((Join-Path $emptyTree 'after-failed-construction.cs'), '// restored')
$nestedTree = Join-Path $testRoot 'nested-output-insertion'
[IO.Directory]::CreateDirectory((Join-Path $nestedTree 'KalynaArchiver\Features\bin')) | Out-Null
[IO.File]::WriteAllText((Join-Path $nestedTree 'KalynaArchiver\Features\Input.cs'), '// reviewed')
Require-Rejection {
    $unexpectedLease = [KeepVaultBuild.SourceSnapshotLease]::new($nestedTree, $commit,
        [string[]]@('KalynaArchiver/Features/Input.cs'), (Join-Path $testRoot 'nested-before.sha256'))
    $unexpectedLease.Dispose()
} 'nested bin directory is not a project output exemption'
[IO.File]::WriteAllText((Join-Path $nestedTree 'KalynaArchiver\Features\after.cs'), '// restored')

# Force one ACL restoration failure and verify that the remaining directories
# and all held handles are still released before the aggregate error returns.
$cleanupTree = Join-Path $testRoot 'cleanup-failure'
[IO.Directory]::CreateDirectory($cleanupTree) | Out-Null
[IO.File]::WriteAllText((Join-Path $cleanupTree 'Input.cs'), '// synthetic')
$cleanupLease = [KeepVaultBuild.SourceSnapshotLease]::new($cleanupTree, $commit, [string[]]@('Input.cs'), (Join-Path $testRoot 'cleanup-before.sha256'))
$aclField = $cleanupLease.GetType().GetField('acls', [Reflection.BindingFlags]'NonPublic,Instance')
$aclList = $aclField.GetValue($cleanupLease)
$aclList.Add([ValueTuple[string, Security.AccessControl.DirectorySecurity]]::new((Join-Path $cleanupTree 'missing'), [Security.AccessControl.DirectorySecurity]::new()))
Require-Rejection { $cleanupLease.Dispose() } 'aggregate cleanup error after all remaining restorations'
[IO.File]::WriteAllText((Join-Path $cleanupTree 'Input.cs'), '// handles released')
[IO.File]::WriteAllText((Join-Path $cleanupTree 'after.cs'), '// ACL restored')
[IO.Directory]::Move($cleanupTree, "$cleanupTree-released")
Write-Host 'PASS failed construction and failed ACL restoration do not retain remaining restrictions'
Write-Host "Synthetic evidence directory: $testRoot"
