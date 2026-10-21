#requires -Version 7.4
<#
Parent must select the reviewed 5.0.3 candidate and label its run purpose.
Preliminary candidate evidence never replaces final release acceptance.
Run only against the finished output of the exact committed Windows source snapshot.
Actual verifier/setup EXEs are exercised; mutated EXEs are never executed.
No rebuild/signing, quarantine restore, antivirus change, trust installation,
GUI interaction, or user shortcut creation occurs. --test-copy omits shortcuts.
Fixtures and logs are retained beneath this work directory; no recursive cleanup.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $SourceRoot,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{40}$')][string] $ExpectedCommit,
    [string] $EvidenceParent = $PSScriptRoot,
    [ValidateSet('Preliminary','Final')][string] $RunPurpose = 'Final',
    [ValidateRange(30, 900)][int] $PerProcessTimeoutSeconds = 300
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $IsWindows) { throw 'Windows is required.' }
$source = [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath($SourceRoot))
$SourceCommit = $ExpectedCommit.ToLowerInvariant()
$workRoot = 'C:\Dev\Kalyna\work'
$evidenceParentPath = [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath($EvidenceParent))
if ($evidenceParentPath -ine $workRoot -and -not $evidenceParentPath.StartsWith($workRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Acceptance evidence must remain below C:\Dev\Kalyna\work.'
}
$releaseBuildsRoot = Join-Path $workRoot 'release-builds'
if ($evidenceParentPath -ieq $releaseBuildsRoot -or
    $evidenceParentPath.StartsWith($releaseBuildsRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Acceptance fixtures and evidence must stay outside every immutable release snapshot container.'
}
if (-not [IO.Directory]::Exists($evidenceParentPath)) { throw 'The evidence parent must already exist.' }
$outputName = 'Keep Vault-portable-win-x64'
$release = Join-Path $source "dist\$outputName"
$zip = "$release.zip"
$externalVerifier = Join-Path $source 'dist\Keep Vault Release Verifier-win-x64.exe'
$testRoot = Join-Path $evidenceParentPath ('package-acceptance-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' + [Guid]::NewGuid().ToString('N'))

function Assert-TestPath([string] $Path) {
    $full = [IO.Path]::GetFullPath($Path)
    if (-not $full.StartsWith($testRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { throw "Unsafe test output: $full" }
    return $full
}
function Assert-RegularAncestors([string] $Path) {
    for ($current = [IO.Path]::GetFullPath($Path); $current; $current = [IO.Path]::GetDirectoryName($current)) {
        if (([IO.File]::GetAttributes($current) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Unexpected input/storage alias: $current" }
    }
}
function Assert-CommittedSource {
    if (-not $source.StartsWith('C:\Dev\Kalyna\work\release-builds\', [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($source) -cne 'src') {
        throw 'The source must be an existing local release snapshot.'
    }
    Assert-RegularAncestors $source
    if ((& git --no-optional-locks -C $source rev-parse HEAD).Trim() -cne $SourceCommit -or $LASTEXITCODE -ne 0) { throw 'Source commit mismatch.' }
    $manifest = Join-Path (Split-Path $source) 'source-inputs-before.sha256'
    $afterManifest = Join-Path (Split-Path $source) 'source-inputs-after.sha256'
    if ((Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash -cne
        (Get-FileHash -LiteralPath $afterManifest -Algorithm SHA256).Hash) { throw 'Build before/after source inventories differ or are unavailable.' }
    $lines = @(Get-Content -LiteralPath $manifest)
    $required = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($name in @('WindowsRelease/Signing/Directory.Build.props', 'WindowsRelease/Signing/hybrid-rsa4096.cer',
        'WindowsRelease/Signing/mldsa87-public.key', 'KalynaArchiver.Signing/ReleaseAuthenticode.cs')) { $null = $required.Add($name) }
    foreach ($line in $lines) {
        if ($line -cnotmatch '^([0-9A-F]{64})  (.+)$') { throw 'Invalid committed source manifest.' }
        $digest = $Matches[1]; $relative = $Matches[2]
        $path = [IO.Path]::GetFullPath((Join-Path $source $relative))
        if (-not $path.StartsWith($source + '\', [StringComparison]::OrdinalIgnoreCase) -or
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $digest) { throw 'Committed source bytes differ from the release snapshot.' }
        Assert-RegularAncestors $path
        $null = $required.Remove($relative.Replace('\','/'))
    }
    if ($required.Count) { throw 'The snapshot does not contain the separate committed Windows public identity.' }
    return $lines.Count
}
function Get-ShortcutState {
    $state = [Collections.Generic.SortedDictionary[string,string]]::new([StringComparer]::Ordinal)
    foreach ($path in @(
        (Join-Path ([Environment]::GetFolderPath('DesktopDirectory')) 'Keep Vault.lnk'),
        (Join-Path ([Environment]::GetFolderPath('Programs')) 'Keep Vault.lnk'),
        (Join-Path ([Environment]::GetFolderPath('Programs')) 'QR-Scanner.lnk'))) {
        if ([IO.File]::Exists($path)) { $state[$path] = 'F:' + (Get-FileHash -LiteralPath $path -Algorithm SHA512).Hash }
        elseif ([IO.Directory]::Exists($path)) { $state[$path] = 'D' }
        else { $state[$path] = 'MISSING' }
    }
    return ,$state
}
function Assert-SameMapping($Expected, $Actual, [string] $Label) {
    if ($Expected.Count -ne $Actual.Count) { throw "$Label membership changed." }
    foreach ($entry in $Expected.GetEnumerator()) {
        if (-not $Actual.ContainsKey($entry.Key) -or $Actual[$entry.Key] -cne $entry.Value) { throw "$Label changed: $($entry.Key)" }
    }
}
function Get-ZipSet([string] $Path) {
    $result = [Collections.Generic.SortedDictionary[string,string]]::new([StringComparer]::Ordinal)
    foreach ($suffix in @('', '.khsig', '.sha3', '.sha3.khsig', '.skein', '.skein.khsig')) {
        $result[$suffix] = (Get-FileHash -LiteralPath "$Path$suffix" -Algorithm SHA512).Hash
    }
    return ,$result
}
function Get-AssetSet {
    $result = [Collections.Generic.SortedDictionary[string,string]]::new([StringComparer]::Ordinal)
    foreach ($asset in @($zip, $externalVerifier)) {
        foreach ($suffix in @('', '.khsig', '.sha3', '.sha3.khsig', '.skein', '.skein.khsig')) {
            $path = "$asset$suffix"
            $result[[IO.Path]::GetFileName($path)] = 'F:{0}:{1}' -f (Get-Item -LiteralPath $path).Length, (Get-FileHash -LiteralPath $path -Algorithm SHA512).Hash
        }
    }
    return ,$result
}
function Get-Tree([string] $Root) {
    $entries = [Collections.Generic.SortedDictionary[string,string]]::new([StringComparer]::Ordinal)
    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push($Root)
    while ($pending.Count -gt 0) {
        foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($pending.Pop())) {
            $attributes = [IO.File]::GetAttributes($entry)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Unexpected reparse entry: $entry" }
            $relative = [IO.Path]::GetRelativePath($Root, $entry)
            if (($attributes -band [IO.FileAttributes]::Directory) -ne 0) {
                $entries.Add($relative, 'D')
                $pending.Push($entry)
            } else {
                $entries.Add($relative, ('F:{0}:{1}' -f ([IO.FileInfo]$entry).Length, (Get-FileHash -LiteralPath $entry -Algorithm SHA512).Hash))
            }
        }
    }
    return ,$entries
}
function Assert-SameTree([string] $Root, $Expected) {
    $actual = Get-Tree $Root
    if ($actual.Count -ne $Expected.Count) { throw "Tree membership changed: $Root" }
    foreach ($entry in $Expected.GetEnumerator()) {
        if (-not $actual.ContainsKey($entry.Key) -or $actual[$entry.Key] -cne $entry.Value) { throw "Tree/file mismatch: $($entry.Key)" }
    }
}
function Copy-FreshTree([string] $Source, [string] $Destination, $Manifest) {
    $Destination = Assert-TestPath $Destination
    if ([IO.Path]::Exists($Destination)) { throw 'Fresh copy destination exists.' }
    [IO.Directory]::CreateDirectory($Destination) | Out-Null
    foreach ($entry in $Manifest.GetEnumerator()) {
        $destinationPath = Assert-TestPath (Join-Path $Destination $entry.Key)
        if ($entry.Value -eq 'D') { [IO.Directory]::CreateDirectory($destinationPath) | Out-Null }
        else {
            [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destinationPath)) | Out-Null
            [IO.File]::Copy((Join-Path $Source $entry.Key), $destinationPath, $false)
        }
    }
    Assert-SameTree $Destination $Manifest
}
function Register-ControlExecutable([string] $Path, [string] $Role) {
    $Path = Assert-TestPath $Path
    if ($Role -cnotin @('installer', 'verifier')) { throw 'Unsupported executable role.' }
    Assert-RegularAncestors $Path
    $status = [KalynaArchiver.Signing.ReleaseAuthenticode]::Verify($Path)
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    $certificate = $signature.SignerCertificate
    if ($null -eq $certificate -or $status -notin @(0, [Convert]::ToUInt32('800B0109',16)) -or
        [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($certificate.RawData)) -cne $publicCertificateSha256 -or
        [Diagnostics.FileVersionInfo]::GetVersionInfo($Path).ProductVersion -cne $productVersion) {
        throw 'A control executable is not intact and signed by the committed Windows product identity.'
    }
    $controlExecutables.Add($Path, (Get-FileHash -LiteralPath $Path -Algorithm SHA512).Hash)
    $controlRoles.Add($Path, $Role)
    $controlAuthenticode.Add([ordered]@{Path=$Path;Role=$Role;WinVerifyTrust=('0x{0:X8}' -f $status);CertificateSha256=$publicCertificateSha256})
}
function Invoke-ExpectedProcess {
    param([string] $Executable, [string[]] $Arguments, [int] $ExpectedExit, [string] $Marker, [string] $Label)
    # The only launchable files are immutable copies of the authenticated
    # verifier/setup. A path into any mutable test fixture is never allowed.
    if (-not $controlExecutables.ContainsKey($Executable) -or
        (Get-FileHash -LiteralPath $Executable -Algorithm SHA512).Hash -cne $controlExecutables[$Executable]) {
        throw 'The executable is not an unchanged authenticated control program.'
    }
    $role = $controlRoles[$Executable]
    if (($role -ceq 'installer' -and -not (
        ($Arguments.Count -eq 2 -and $Arguments[0] -ceq '--verify') -or
        ($Arguments.Count -eq 3 -and $Arguments[0] -ceq '--test-copy'))) -or
        ($role -ceq 'verifier' -and $Arguments.Count -ne 1) -or $role -cnotin @('installer', 'verifier')) {
        throw 'Only verifier, installer --verify, and shortcut-free --test-copy modes are permitted.'
    }
    $script:InvocationNumber++
    $id = '{0:D3}-{1}' -f $script:InvocationNumber, ($Label -replace '[^A-Za-z0-9_-]', '_')
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Executable
    $start.WorkingDirectory = $control
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    Write-Host "RUN $id"
    $started = $false
    $treeAtTimeout = @()
    $treeCaptureError = $null
    $watch = [Diagnostics.Stopwatch]::StartNew()
    [ordered]@{Executable=$Executable;Arguments=$Arguments;ExpectedExit=$ExpectedExit;Marker=$Marker;Role=$role;
        StartedUtc=[DateTime]::UtcNow.ToString('O');ExecutableSha512=$controlExecutables[$Executable]} |
        ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $logs "$id.start.json") -Encoding utf8NoBOM
    try {
        $started = $process.Start()
        if (-not $started) { throw "Cannot start $Executable" }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $timedOut = -not $process.WaitForExit($PerProcessTimeoutSeconds * 1000)
        if ($timedOut) {
            try {
                $allProcesses = @(Get-CimInstance Win32_Process -ErrorAction Stop)
                $ids = [Collections.Generic.HashSet[uint32]]::new()
                $null = $ids.Add([uint32]$process.Id)
                do {
                    $added = $false
                    foreach ($item in $allProcesses) {
                        if ($ids.Contains([uint32]$item.ParentProcessId) -and $ids.Add([uint32]$item.ProcessId)) { $added = $true }
                    }
                } while ($added)
                $treeAtTimeout = @($allProcesses | Where-Object { $ids.Contains([uint32]$_.ProcessId) } |
                    Select-Object ProcessId, ParentProcessId, Name, CreationDate, KernelModeTime, UserModeTime, WorkingSetSize)
            } catch { $treeCaptureError = $_.Exception.Message }
            $process.Kill($true)
            if (-not $process.WaitForExit(10000)) { throw 'The timed-out control process did not exit after termination.' }
        }
        if (-not $stdout.Wait(10000) -or -not $stderr.Wait(10000)) { throw 'Control output pipes did not close within the bounded drain interval.' }
        $output = $stdout.GetAwaiter().GetResult()
        $errorOutput = $stderr.GetAwaiter().GetResult()
        $exit = $process.ExitCode
        [IO.File]::WriteAllText((Join-Path $logs "$id.stdout.txt"), $output)
        [IO.File]::WriteAllText((Join-Path $logs "$id.stderr.txt"), $errorOutput)
        [ordered]@{ Executable=$Executable; Arguments=$Arguments; Exit=$exit; ExpectedExit=$ExpectedExit; Marker=$Marker; TimedOut=$timedOut;
            Seconds=$watch.Elapsed.TotalSeconds; TreeAtTimeout=$treeAtTimeout; TreeCaptureError=$treeCaptureError } |
            ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $logs "$id.json") -Encoding utf8NoBOM
        $combined = $output + [Environment]::NewLine + $errorOutput
        if ($timedOut -or $exit -ne $ExpectedExit -or -not $combined.Contains($Marker, [StringComparison]::Ordinal)) {
            throw "$id failed: exit=$exit expected=$ExpectedExit timeout=$timedOut output=$combined"
        }
    } catch {
        [ordered]@{Executable=$Executable;Arguments=$Arguments;Started=$started;Seconds=$watch.Elapsed.TotalSeconds;
            Error=$_.Exception.ToString();TreeAtTimeout=$treeAtTimeout;TreeCaptureError=$treeCaptureError} |
            ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $logs "$id.failure.json") -Encoding utf8NoBOM
        throw
    } finally {
        try {
            if ($started -and -not $process.HasExited) {
                $process.Kill($true)
                if (-not $process.WaitForExit(10000)) { throw 'Owned acceptance process did not terminate during exceptional cleanup.' }
            }
        } finally { $process.Dispose() }
    }
}
function Invoke-Case([string] $CaseName, [scriptblock] $Body) {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    try {
        $null = & $Body
        $script:Results.Add([pscustomobject]@{ Name=$CaseName; Status='PASS'; Seconds=$watch.Elapsed.TotalSeconds; Error=$null })
        Write-Host "PASS $CaseName"
    } catch {
        $script:Results.Add([pscustomobject]@{ Name=$CaseName; Status='FAIL'; Seconds=$watch.Elapsed.TotalSeconds; Error=$_.Exception.ToString() })
        throw
    } finally {
        $script:Results | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $testRoot 'results.json') -Encoding utf8NoBOM
    }
}
function Assert-PackageRejected([string] $Target, [string] $Label) {
    Invoke-ExpectedProcess $verifier @($Target) 3 'RESULT: BLOCKED' "$Label-verifier"
    Invoke-ExpectedProcess $installer @('--verify', $Target) 3 'RESULT: BLOCKED' "$Label-installer"
}
function With-MissingFile([string] $Path, [scriptblock] $Body) {
    $Path = Assert-TestPath $Path
    $backup = Assert-TestPath (Join-Path $backups ([Guid]::NewGuid().ToString('N') + '.data'))
    [IO.File]::Move($Path, $backup)
    try { & $Body }
    finally {
        if (-not [IO.File]::Exists($backup)) { throw 'Backup disappeared; no reconstruction is attempted.' }
        [IO.File]::Move($backup, $Path) # Fails if a replacement exists; never overwrites it.
    }
}
function With-BitFlip([string] $Path, [long] $RequestedOffset, [scriptblock] $Body) {
    $Path = Assert-TestPath $Path
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        $length = $stream.Length
        if ($length -lt 1) { throw 'Cannot mutate an empty file.' }
        $offset = [Math]::Min($RequestedOffset, $length - 1)
        $stream.Position = $offset
        $original = $stream.ReadByte()
        $stream.Position = $offset
        $stream.WriteByte([byte]($original -bxor 1))
        $stream.Flush($true)
    } finally { $stream.Dispose() }
    try { & $Body }
    finally {
        if (-not [IO.File]::Exists($Path)) { throw 'Mutated file disappeared, possibly quarantined; no reconstruction is attempted.' }
        $restore = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        try {
            if ($restore.Length -ne $length) { throw 'Fixture length changed unexpectedly; retained for inspection.' }
            $restore.Position = $offset
            $restore.WriteByte([byte]$original)
            $restore.Flush($true)
        } finally { $restore.Dispose() }
    }
}
function New-TestJunction([string] $Path, [string] $Target) {
    $Path = Assert-TestPath $Path
    $Target = Assert-TestPath $Target
    if ([IO.Path]::Exists($Path)) { throw 'Junction path exists.' }
    New-Item -ItemType Junction -Path $Path -Target $Target | Out-Null
}
function Remove-TestJunction([string] $Path) {
    $Path = Assert-TestPath $Path
    if (([IO.File]::GetAttributes($Path) -band [IO.FileAttributes]::ReparsePoint) -eq 0) { throw 'Junction fixture was replaced.' }
    [IO.Directory]::Delete($Path, $false) # Unlink the reparse object without traversing its target.
}

Assert-RegularAncestors $workRoot
Assert-RegularAncestors $evidenceParentPath
Assert-RegularAncestors $release
Assert-RegularAncestors $zip
$sourceInputCount = Assert-CommittedSource
$sourceManifest = Join-Path (Split-Path $source) 'source-inputs-before.sha256'
$sourceAfterManifest = Join-Path (Split-Path $source) 'source-inputs-after.sha256'
Assert-RegularAncestors $sourceManifest
Assert-RegularAncestors $sourceAfterManifest
$sourceManifestHash = (Get-FileHash -LiteralPath $sourceManifest -Algorithm SHA256).Hash
[xml] $versionProps = Get-Content -LiteralPath (Join-Path $source 'Directory.Build.props') -Raw
$productVersion = $versionProps.SelectSingleNode('/Project/PropertyGroup/Version').InnerText
if ($productVersion -cne '5.0.3') { throw 'This acceptance harness is scoped to Keep Vault 5.0.3.' }
if (-not $release.StartsWith($source + '\dist\', [StringComparison]::OrdinalIgnoreCase) -or
    -not $zip.StartsWith($source + '\dist\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Both release inputs must be outputs of this committed snapshot.'
}
$policyRoot = Join-Path $source 'WindowsRelease\Signing'
[xml] $policy = Get-Content -LiteralPath (Join-Path $policyRoot 'Directory.Build.props') -Raw
$publicPins = [ordered]@{}
foreach ($entry in @(@('SigningCertificateThumbprint',40),@('ExpectedSignerSha256',64),@('ExpectedSignerSha3_512',128),
    @('ExpectedSignerSkein1024',256),@('ExpectedMldsa87Sha256',64),@('ExpectedMldsa87Sha3_512',128),@('ExpectedMldsa87Skein1024',256))) {
    $nodes = @($policy.SelectNodes('/Project/PropertyGroup/Kalyna' + $entry[0]))
    if ($nodes.Count -ne 1 -or $nodes[0].InnerText -cnotmatch "^[0-9A-F]{$($entry[1])}$") { throw 'Invalid Windows public release policy.' }
    $publicPins[$entry[0]] = $nodes[0].InnerText
}
$publicCertificate = [Security.Cryptography.X509Certificates.X509CertificateLoader]::LoadCertificateFromFile((Join-Path $policyRoot 'hybrid-rsa4096.cer'))
try {
    if ($publicCertificate.HasPrivateKey -or $publicCertificate.Thumbprint -cne $publicPins.SigningCertificateThumbprint) { throw 'Windows public certificate selector mismatch.' }
    $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($publicCertificate)
    try {
        if ($null -eq $rsa -or $rsa.KeySize -ne 4096 -or
            [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($rsa.ExportSubjectPublicKeyInfo())) -cne $publicPins.ExpectedSignerSha256) { throw 'Windows RSA public identity mismatch.' }
    } finally { if ($rsa) { $rsa.Dispose() } }
    $publicCertificateSha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($publicCertificate.RawData))
} finally { $publicCertificate.Dispose() }
if ((Get-Item -LiteralPath (Join-Path $policyRoot 'mldsa87-public.key')).Length -ne 2592 -or
    (Get-FileHash -LiteralPath (Join-Path $policyRoot 'mldsa87-public.key') -Algorithm SHA256).Hash -cne $publicPins.ExpectedMldsa87Sha256) { throw 'Windows ML-DSA public identity mismatch.' }
# This small committed helper invokes Windows WinVerifyTrust only. It neither
# loads Vault native products nor uses a release private key or certificate store.
Add-Type -TypeDefinition ("using System;`n" + [IO.File]::ReadAllText((Join-Path $source 'KalynaArchiver.Signing\ReleaseAuthenticode.cs')))
foreach ($required in @('Keep Vault.exe', 'Keep Vault Release Verifier.exe', 'Keep Vault Setup.exe', 'RELEASE-INVENTORY.json', 'RELEASE-INVENTORY.json.khsig')) {
    if (-not [IO.File]::Exists((Join-Path $release $required))) { throw "Incomplete release: $required" }
}
foreach ($suffix in @('', '.khsig', '.sha3', '.sha3.khsig', '.skein', '.skein.khsig')) {
    if (-not [IO.File]::Exists("$zip$suffix")) { throw "Incomplete ZIP: $zip$suffix" }
    if (-not [IO.File]::Exists("$externalVerifier$suffix")) { throw "Incomplete external verifier: $externalVerifier$suffix" }
    Assert-RegularAncestors "$externalVerifier$suffix"
}
if ((Get-FileHash -LiteralPath $externalVerifier -Algorithm SHA512).Hash -cne
    (Get-FileHash -LiteralPath (Join-Path $release 'Keep Vault Release Verifier.exe') -Algorithm SHA512).Hash) {
    throw 'The external and packaged verifier executable bytes differ.'
}
if ([IO.Path]::Exists($testRoot)) { throw 'Fresh test root exists.' }
[IO.Directory]::CreateDirectory($testRoot) | Out-Null
$logs = Join-Path $testRoot 'logs'
$backups = Join-Path $testRoot 'backups'
$control = Join-Path $testRoot 'control'
foreach ($directory in @($logs, $backups, $control)) { [IO.Directory]::CreateDirectory($directory) | Out-Null }
$script:Results = [Collections.Generic.List[object]]::new()
$script:InvocationNumber = 0
$inputLeases = [Collections.Generic.List[IDisposable]]::new()
$primaryFailure = $null
$baseline = $null; $zipBaseline = $null; $controlBaseline = $null; $assetBaseline = $null
$shortcutBaseline = Get-ShortcutState
$acceptanceSucceeded = $false
[ordered]@{State='IN_PROGRESS';RunPurpose=$RunPurpose;SourceCommit=$SourceCommit;ProductVersion=$productVersion;StartedUtc=[DateTime]::UtcNow.ToString('O')} |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $testRoot 'summary.json') -Encoding utf8NoBOM
try {
$baseline = Get-Tree $release
foreach ($entry in $baseline.GetEnumerator()) {
    if ($entry.Value -ne 'D') { $inputLeases.Add([IO.File]::Open((Join-Path $release $entry.Key), [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)) }
}
foreach ($suffix in @('', '.khsig', '.sha3', '.sha3.khsig', '.skein', '.skein.khsig')) {
    $inputLeases.Add([IO.File]::Open("$zip$suffix", [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read))
    $inputLeases.Add([IO.File]::Open("$externalVerifier$suffix", [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read))
}
$zipBaseline = Get-ZipSet $zip
$assetBaseline = Get-AssetSet
$baseline | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $testRoot 'package-before.json') -Encoding utf8NoBOM
$assetBaseline | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $testRoot 'assets-before.json') -Encoding utf8NoBOM
[IO.File]::Copy($sourceManifest, (Join-Path $testRoot 'source-inputs-before.sha256'), $false)
$candidate = Join-Path $testRoot 'candidate'
Copy-FreshTree $release $candidate $baseline
$verifier = Join-Path $control 'Keep Vault Release Verifier.exe'
$installer = Join-Path $control 'Keep Vault Setup.exe'
foreach ($product in @('Keep Vault Release Verifier.exe', 'Keep Vault Setup.exe')) {
    foreach ($suffix in @('', '.khsig', '.sha3', '.sha3.khsig', '.skein', '.skein.khsig')) {
        [IO.File]::Copy((Join-Path $release "$product$suffix"), (Join-Path $control "$product$suffix"), $false)
    }
}
$externalControl = Join-Path $control ([IO.Path]::GetFileName($externalVerifier))
foreach ($suffix in @('', '.khsig', '.sha3', '.sha3.khsig', '.skein', '.skein.khsig')) {
    [IO.File]::Copy("$externalVerifier$suffix", "$externalControl$suffix", $false)
}
$controlBaseline = Get-Tree $control
$controlExecutables = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
$controlRoles = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
$controlAuthenticode = [Collections.Generic.List[object]]::new()
foreach ($entry in $controlBaseline.GetEnumerator()) {
    if ($entry.Value -ne 'D') { $inputLeases.Add([IO.File]::Open((Join-Path $control $entry.Key), [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)) }
}
Register-ControlExecutable $verifier 'verifier'
Register-ControlExecutable $installer 'installer'
Register-ControlExecutable $externalControl 'verifier'
$zipCopy = Join-Path $testRoot 'candidate.zip'
foreach ($suffix in @('', '.khsig', '.sha3', '.sha3.khsig', '.skein', '.skein.khsig')) { [IO.File]::Copy("$zip$suffix", "$zipCopy$suffix", $false) }
$zipHash = (Get-FileHash -LiteralPath $zip -Algorithm SHA512).Hash
[ordered]@{
    SourceCommit=$SourceCommit;RunPurpose=$RunPurpose;ProductVersion=$productVersion;ReleaseDirectory=$release;ReleaseZip=$zip;ExternalVerifier=$externalVerifier
    SourceSnapshotRoot=$source; SourceInputCount=$sourceInputCount; WindowsPublicPolicy=$publicPins; ControlAuthenticode=$controlAuthenticode
    SourceManifestSha256=$sourceManifestHash;HarnessSha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
    AwaitedProcessHelperReviewedSha256=(Get-FileHash -LiteralPath (Join-Path $source 'tools\Invoke-ReleaseExecutable.ps1') -Algorithm SHA256).Hash
    StartedUtc=[DateTime]::UtcNow.ToString('O'); ZipSha512=$zipHash
    VerifierSha512=(Get-FileHash -LiteralPath $verifier -Algorithm SHA512).Hash
    InstallerSha512=(Get-FileHash -LiteralPath $installer -Algorithm SHA512).Hash
    Scope='Actual EXE black-box verification and --test-copy; no GUI, shortcuts, signing, trust, or AV changes.'
    Limits='Unsigned mutations may fail at inventory/hybrid authentication before inner timestamp/version/path validation. These cases do not isolate those inner validators.'
} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $testRoot 'provenance.json') -Encoding utf8NoBOM

Invoke-Case 'baseline-package' {
    Invoke-ExpectedProcess $verifier @($release) 0 'RESULT: TRUSTED' 'original-release-verifier'
    Invoke-ExpectedProcess $installer @('--verify', $release) 0 'RESULT: TRUSTED' 'original-release-installer'
    Invoke-ExpectedProcess $verifier @($candidate) 0 'RESULT: TRUSTED' 'baseline-verifier'
    Invoke-ExpectedProcess $installer @('--verify', $candidate) 0 'RESULT: TRUSTED' 'baseline-installer'
}
Invoke-Case 'baseline-zip' {
    Invoke-ExpectedProcess $verifier @($zip) 0 'RESULT: TRUSTED' 'original-zip'
    Invoke-ExpectedProcess $verifier @($zipCopy) 0 'RESULT: TRUSTED' 'baseline-zip'
}
Invoke-Case 'external-standalone-verifier' {
    Invoke-ExpectedProcess $externalControl @($externalControl) 0 'RESULT: TRUSTED' 'external-verifier-self'
    Invoke-ExpectedProcess $externalControl @($release) 0 'RESULT: TRUSTED' 'external-verifier-package'
    Invoke-ExpectedProcess $externalControl @($zip) 0 'RESULT: TRUSTED' 'external-verifier-zip'
}
Invoke-Case 'fresh-zip-extraction-exact-package' {
    $extraction = Assert-TestPath (Join-Path $testRoot 'zip-extracted')
    [IO.Directory]::CreateDirectory($extraction) | Out-Null
    Expand-Archive -LiteralPath $zipCopy -DestinationPath $extraction
    $entries = @([IO.Directory]::EnumerateFileSystemEntries($extraction))
    $package = Join-Path $extraction ([IO.Path]::GetFileName($release))
    if ($entries.Count -ne 1 -or -not [IO.Directory]::Exists($package)) { throw 'The ZIP does not contain exactly the expected package directory.' }
    Assert-SameTree $package $baseline
    Invoke-ExpectedProcess $verifier @($package) 0 'RESULT: TRUSTED' 'zip-extracted-verifier'
    Invoke-ExpectedProcess $installer @('--verify',$package) 0 'RESULT: TRUSTED' 'zip-extracted-installer'
}
$installed = Join-Path $testRoot 'installed-new'
Invoke-Case 'fresh-install-exact-copy' {
    Invoke-ExpectedProcess $installer @('--test-copy', $candidate, $installed) 0 'RESULT: INSTALLED' 'install-fresh'
    Assert-SameTree $installed $baseline
    Invoke-ExpectedProcess $verifier @($installed) 0 'RESULT: TRUSTED' 'installed-verifier'
    Invoke-ExpectedProcess $installer @('--verify', $installed) 0 'RESULT: TRUSTED' 'installed-installer'
}
Invoke-Case 'installed-verifier-standalone' {
    $standalone = Assert-TestPath (Join-Path $testRoot 'installed-verifier-standalone')
    [IO.Directory]::CreateDirectory($standalone) | Out-Null
    $installedVerifier = Join-Path $standalone 'Keep Vault Release Verifier.exe'
    foreach ($suffix in @('', '.khsig', '.sha3', '.sha3.khsig', '.skein', '.skein.khsig')) {
        [IO.File]::Copy((Join-Path $installed "Keep Vault Release Verifier.exe$suffix"), "$installedVerifier$suffix", $false)
        if ((Get-FileHash -LiteralPath "$installedVerifier$suffix" -Algorithm SHA512).Hash -cne
            (Get-FileHash -LiteralPath (Join-Path $release "Keep Vault Release Verifier.exe$suffix") -Algorithm SHA512).Hash) { throw 'Installed standalone verifier bytes changed.' }
        $inputLeases.Add([IO.File]::Open("$installedVerifier$suffix", [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read))
    }
    Register-ControlExecutable $installedVerifier 'verifier'
    Invoke-ExpectedProcess $installedVerifier @($installedVerifier) 0 'RESULT: TRUSTED' 'installed-standalone-self'
    Invoke-ExpectedProcess $installedVerifier @($installed) 0 'RESULT: TRUSTED' 'installed-standalone-package'
}
Invoke-Case 'existing-install-preserved' {
    Invoke-ExpectedProcess $installer @('--test-copy', $candidate, $installed) 3 'RESULT: BLOCKED' 'install-existing'
    Assert-SameTree $installed $baseline
}
Invoke-Case 'existing-empty-directory-rejected' {
    $empty = Join-Path $testRoot 'existing-empty'
    [IO.Directory]::CreateDirectory($empty) | Out-Null
    Invoke-ExpectedProcess $installer @('--test-copy', $candidate, $empty) 3 'RESULT: BLOCKED' 'install-empty'
    if (@([IO.Directory]::EnumerateFileSystemEntries($empty)).Count -ne 0) { throw 'Existing destination changed.' }
}
Invoke-Case 'existing-file-preserved' {
    $existingFile = Join-Path $testRoot 'existing-file'
    [IO.File]::WriteAllText($existingFile, 'original destination canary')
    Invoke-ExpectedProcess $installer @('--test-copy', $candidate, $existingFile) 3 'RESULT: BLOCKED' 'install-file'
    if ([IO.File]::ReadAllText($existingFile) -cne 'original destination canary') { throw 'Destination file changed.' }
}
Invoke-Case 'destination-junction-rejected-canary-preserved' {
    $outside = Join-Path $testRoot 'outside-destination'
    [IO.Directory]::CreateDirectory($outside) | Out-Null
    [IO.File]::WriteAllText((Join-Path $outside 'canary.txt'), 'outside destination canary')
    $outsideBefore = Get-Tree $outside
    $alias = Join-Path $testRoot 'destination-alias'
    New-TestJunction $alias $outside
    try {
        Invoke-ExpectedProcess $installer @('--test-copy', $candidate, (Join-Path $alias 'new-install')) 3 'RESULT: BLOCKED' 'install-parent-junction'
        Assert-SameTree $outside $outsideBefore
    } finally { Remove-TestJunction $alias }
}
Invoke-Case 'source-junction-and-single-file-alias-rejected' {
    $alias = Join-Path $testRoot 'package-alias'
    New-TestJunction $alias $candidate
    try {
        Assert-PackageRejected $alias 'package-root-junction'
        Invoke-ExpectedProcess $verifier @((Join-Path $alias 'PORTABLE_README.txt')) 3 'RESULT: BLOCKED' 'single-file-alias'
        $destination = Join-Path $testRoot 'alias-source-install'
        Invoke-ExpectedProcess $installer @('--test-copy', $alias, $destination) 3 'RESULT: BLOCKED' 'install-source-junction'
        if ([IO.Path]::Exists($destination)) { throw 'Rejected source created a destination.' }
    } finally { Remove-TestJunction $alias }
}
Invoke-Case 'inner-junction-rejected' {
    $scanner = Assert-TestPath (Join-Path $candidate 'QR-Scanner')
    $scannerBackup = Assert-TestPath (Join-Path $testRoot 'scanner-backup')
    [IO.Directory]::Move($scanner, $scannerBackup)
    try {
        New-TestJunction $scanner $scannerBackup
        try { Assert-PackageRejected $candidate 'inner-junction' }
        finally { Remove-TestJunction $scanner }
    } finally { [IO.Directory]::Move($scannerBackup, $scanner) }
}
Invoke-Case 'hardlink-rejected' {
    $hardlink = Assert-TestPath (Join-Path $testRoot 'readme-hardlink.txt')
    New-Item -ItemType HardLink -Path $hardlink -Target (Join-Path $candidate 'PORTABLE_README.txt') | Out-Null
    try { Assert-PackageRejected $candidate 'hardlink' }
    finally { [IO.File]::Delete($hardlink) }
}
foreach ($relativeFile in @('RELEASE-INVENTORY.json', 'RELEASE-INVENTORY.json.khsig', 'Keep Vault.exe.sha3.khsig', 'QR-Scanner/QR-Scanner.exe',
    'zpaq.exe', 'kalyna_v13.dll', 'threefish_ref.dll', 'mars_ref.dll', 'camellia_v13.dll', 'serpent_v13.dll', 'shacal2_ref.dll', 'aes_ref.dll', 'xchachapoly_v13.dll', 'argon2_ref.dll', 'argon2.exe')) {
    Invoke-Case "missing-$relativeFile" {
        With-MissingFile (Join-Path $candidate $relativeFile) { Assert-PackageRejected $candidate "missing-$relativeFile" }
    }
}
foreach ($relativeFile in @('RELEASE-INVENTORY.json', 'RELEASE-INVENTORY.json.khsig', 'Keep Vault.exe', 'Keep Vault.exe.khsig', 'zpaq.exe')) {
    Invoke-Case "bitflip-$relativeFile" {
        With-BitFlip (Join-Path $candidate $relativeFile) 4096 {
            Assert-PackageRejected $candidate "bitflip-$relativeFile"
            if ($relativeFile -in @('Keep Vault.exe', 'Keep Vault.exe.khsig')) {
                Invoke-ExpectedProcess $verifier @((Join-Path $candidate 'Keep Vault.exe')) 3 'RESULT: BLOCKED' "standalone-$relativeFile"
            }
        }
    }
}
Invoke-Case 'extra-file-rejected' {
    $extra = Assert-TestPath (Join-Path $candidate 'unexpected.txt')
    [IO.File]::WriteAllText($extra, 'not in signed inventory')
    try { Assert-PackageRejected $candidate 'extra-file' } finally { [IO.File]::Delete($extra) }
}
Invoke-Case 'extra-empty-directory-rejected' {
    $extra = Assert-TestPath (Join-Path $candidate 'UnexpectedEmpty')
    [IO.Directory]::CreateDirectory($extra) | Out-Null
    try { Assert-PackageRejected $candidate 'extra-empty-directory' } finally { [IO.Directory]::Delete($extra, $false) }
}
Invoke-Case 'zip-bitflip-rejected' {
    With-BitFlip $zipCopy 65536 { Invoke-ExpectedProcess $verifier @($zipCopy) 3 'RESULT: BLOCKED' 'zip-bitflip' }
}
foreach ($zipSuffix in @('.khsig', '.sha3.khsig', '.skein')) {
    Invoke-Case "zip-missing-$zipSuffix" {
        With-MissingFile "$zipCopy$zipSuffix" { Invoke-ExpectedProcess $verifier @($zipCopy) 3 'RESULT: BLOCKED' "zip-missing-$zipSuffix" }
    }
}
Invoke-Case 'restoration-accepted-and-original-inputs-unchanged' {
    Assert-SameTree $candidate $baseline
    Assert-SameTree $release $baseline
    if ((Get-FileHash -LiteralPath $zipCopy -Algorithm SHA512).Hash -cne $zipHash -or
        (Get-FileHash -LiteralPath $zip -Algorithm SHA512).Hash -cne $zipHash) { throw 'ZIP restoration/input preservation failed.' }
    Assert-SameMapping $zipBaseline (Get-ZipSet $zipCopy) 'Restored ZIP/signature/manifest set'
    Invoke-ExpectedProcess $verifier @($candidate) 0 'RESULT: TRUSTED' 'restored-package'
    Invoke-ExpectedProcess $installer @('--verify', $candidate) 0 'RESULT: TRUSTED' 'restored-installer'
    Invoke-ExpectedProcess $verifier @($zipCopy) 0 'RESULT: TRUSTED' 'restored-zip'
}
$acceptanceSucceeded = $true
} catch { $primaryFailure = $_.Exception; throw }
finally {
    $preservation = [ordered]@{OriginalPackage=$false;OriginalZipSet=$false;OriginalAssets=$false;ControlPrograms=$false;UserShortcuts=$false;SourceSnapshot=$false;HandlesReleased=$false}
    $cleanupErrors = [Collections.Generic.List[Exception]]::new()
    try {
        try {
            if ($baseline) {
                $packageAfter = Get-Tree $release
                $packageAfter | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $testRoot 'package-after.json') -Encoding utf8NoBOM
                Assert-SameMapping $baseline $packageAfter 'Original complete package'
                $preservation.OriginalPackage=$true
            }
        } catch { $cleanupErrors.Add($_.Exception) }
        try { if ($zipBaseline) { Assert-SameMapping $zipBaseline (Get-ZipSet $zip) 'Original ZIP set'; $preservation.OriginalZipSet=$true } } catch { $cleanupErrors.Add($_.Exception) }
        try {
            if ($assetBaseline) {
                $assetsAfter = Get-AssetSet
                $assetsAfter | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $testRoot 'assets-after.json') -Encoding utf8NoBOM
                Assert-SameMapping $assetBaseline $assetsAfter 'All twelve original release assets'
                $preservation.OriginalAssets=$true
            }
        } catch { $cleanupErrors.Add($_.Exception) }
        try {
            if ($controlBaseline) {
                Assert-SameTree $control $controlBaseline
                foreach ($entry in $controlExecutables.GetEnumerator()) {
                    if ((Get-FileHash -LiteralPath $entry.Key -Algorithm SHA512).Hash -cne $entry.Value) { throw 'A registered control executable changed.' }
                }
                $controlAuthenticode | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $testRoot 'control-programs.json') -Encoding utf8NoBOM
                $preservation.ControlPrograms=$true
            }
        } catch { $cleanupErrors.Add($_.Exception) }
        try { Assert-SameMapping $shortcutBaseline (Get-ShortcutState) 'User shortcuts'; $preservation.UserShortcuts=$true } catch { $cleanupErrors.Add($_.Exception) }
        try {
            if ((Assert-CommittedSource) -ne $sourceInputCount -or
                (Get-FileHash -LiteralPath $sourceManifest -Algorithm SHA256).Hash -cne $sourceManifestHash -or
                (Get-FileHash -LiteralPath $sourceAfterManifest -Algorithm SHA256).Hash -cne $sourceManifestHash) {
                throw 'Source inventory count, bytes or build evidence changed.'
            }
            [IO.File]::Copy($sourceAfterManifest, (Join-Path $testRoot 'source-inputs-after.sha256'), $false)
            $preservation.SourceSnapshot=$true
        } catch { $cleanupErrors.Add($_.Exception) }
    } finally {
        $handlesReleased=$true
        for ($index=$inputLeases.Count-1; $index -ge 0; $index--) { try { $inputLeases[$index].Dispose() } catch { $handlesReleased=$false; $cleanupErrors.Add($_.Exception) } }
        $preservation.HandlesReleased=$handlesReleased
        $preservation.Errors=@($cleanupErrors | ForEach-Object Message)
        $preservation | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $testRoot 'preservation.json') -Encoding utf8NoBOM
        [ordered]@{
            State=$(if ($acceptanceSucceeded -and -not $primaryFailure -and $cleanupErrors.Count -eq 0) { 'PASS' } else { 'FAIL' })
            SourceCommit=$SourceCommit;RunPurpose=$RunPurpose;ProductVersion=$productVersion;Cases=$script:Results.Count;ExecutableInvocations=$script:InvocationNumber
            Scope='Actual awaited signed verifier/setup processes and shortcut-free isolated test copy; no desktop, camera, printing, normal user installation, trust or antivirus changes.'
            Error=$(if($primaryFailure){$primaryFailure.ToString()}else{$null});CompletedUtc=[DateTime]::UtcNow.ToString('O')
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $testRoot 'summary.json') -Encoding utf8NoBOM
    }
    if ($cleanupErrors.Count) {
        if ($primaryFailure) { $cleanupErrors.Insert(0,$primaryFailure) }
        throw [AggregateException]::new('Acceptance or input-preservation verification failed.',[Exception[]]$cleanupErrors.ToArray())
    }
}
Write-Host "Evidence retained: $testRoot"
Write-Host "All $($script:Results.Count) actual executable acceptance cases and final input-preservation checks passed."
