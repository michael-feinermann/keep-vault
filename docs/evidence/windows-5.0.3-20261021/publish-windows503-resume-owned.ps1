#requires -Version 7.5
<#
PREPARED ONLY. This copy has not been executed. Resume only the exact owned
empty draft left by the pinned failed publication session; create no tag/draft.
All original final-gate, artifact, download and preservation checks are retained.
No signing, rebuilding, trust changes, private keys, overwrite, deletion or rollback.
An interrupted run leaves its own tag/draft/assets for explicit inspection.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $SourceRoot,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{40}$')][string] $ExpectedCommit,
    [Parameter(Mandatory)][string] $AcceptanceEvidence,
    [Parameter(Mandatory)][string] $FinalGateReceipt,
    [Parameter(Mandatory)][string] $ReleaseNotes,
    [Parameter(Mandatory)][string] $ResumeEvidenceRoot,
    [string] $EvidenceParent = $PSScriptRoot,
    [ValidateRange(30,1800)][int] $PerProcessTimeoutSeconds = 900,
    [switch] $ExecutePublication
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if (-not $ExecutePublication) { throw 'Prepared only: the parent must explicitly select ExecutePublication after final gates pass.' }
if (-not $IsWindows) { throw 'Windows is required.' }
$Repository='michael-feinermann/keep-vault'
$repoArg='github.com/'+$Repository
$tag='v5.0.3-windows'
$macTag='v5.0.3'
$SourceCommit=$ExpectedCommit.ToLowerInvariant()
$source=[IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath($SourceRoot))
$workRoot='C:\Dev\Kalyna\work'
$evidenceParentPath=[IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath($EvidenceParent))
$releaseBuildsRoot=Join-Path $workRoot 'release-builds'
if (($evidenceParentPath -ine $workRoot -and -not $evidenceParentPath.StartsWith($workRoot+'\',[StringComparison]::OrdinalIgnoreCase)) -or
    $evidenceParentPath -ieq $releaseBuildsRoot -or $evidenceParentPath.StartsWith($releaseBuildsRoot+'\',[StringComparison]::OrdinalIgnoreCase)) {
    throw 'Evidence must be beneath C:\Dev\Kalyna\work and outside every release snapshot container.'
}
if (-not [IO.Directory]::Exists($evidenceParentPath)) { throw 'EvidenceParent must already exist.' }
if ($env:GH_HOST -and $env:GH_HOST -ine 'github.com') { throw 'GH_HOST must be unset or github.com.' }
$gh=(Get-Command gh -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$git=(Get-Command git -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$recoveryRunId=[Guid]::NewGuid().ToString('N')
$recoveryStartedUtc=[DateTime]::UtcNow.ToString('O')
$testRoot=Join-Path $evidenceParentPath ('publication-recovery-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')+'-'+$recoveryRunId)
$resumeRoot=[IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath($ResumeEvidenceRoot))
$expectedResumeRoot='C:\Dev\Kalyna\work\windows-503-20261021\publication-20261021T223456Z-3d06edadc22848e1b48e4b7a529e82ea'
$originalHarnessPath=Join-Path $PSScriptRoot 'Publish-Windows503.ps1'
$originalHarnessSha256='857641B1CD238EAE9D22FF60D8398E61555377946F0E448E0A7F44AF70081DBC'
$expectedPriorSummarySha256='FC77AD97D4122DAF79D7F2D6133457F21EC685B3A0ACF39FBA1DD1C47E185DC1'
$expectedPriorNotesSha256='92666A64FF5A1F9DA4B41F08C5F88C1B4A2176C76BD582DDC1577C7AB0C7156B'
$expectedResumeReleaseId=[long]420121815
$expectedDraftUrl='https://github.com/michael-feinermann/keep-vault/releases/tag/untagged-0f216fe90c74d5e9e756'
if($resumeRoot -ine $expectedResumeRoot -or $SourceCommit -cne '103e87fd6335bdc4ef8a2ffafa2384ecaad6504b'){
    throw 'This recovery is limited to the explicitly inspected failed session and exact source.'
}
$sessionId=$null
$priorFailedRun=$null
$priorDraftCommand=$null
$priorMac=$null
$priorLatest=$null
$recoveryProvenance=$null
$gateValidationTimeProof=$null
$resumeRecords=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
$release=Join-Path $source 'dist\Keep Vault-portable-win-x64'
$zip="$release.zip"
$externalVerifier=Join-Path $source 'dist\Keep Vault Release Verifier-win-x64.exe'
$suffixes=@('', '.khsig', '.sha3', '.sha3.khsig', '.skein', '.skein.khsig')
$script:InvocationNumber=0
$script:CliNumber=0
$script:CreatedReleaseId=$null
$script:CreatedTag=$false
$script:PublishCommandCompleted=$false
$script:RemotePublishedObserved=$false
$script:Phase='LOCAL_PREFLIGHT'
$inputLeases=[Collections.Generic.List[IDisposable]]::new()
$primaryFailure=$null
$sourceInputCount=0
$packageBaseline=$null
$assetBaseline=$null
$controlBaseline=$null
$controlExecutables=$null
$macBefore=$null
$latestBefore=$null
$script:AnonymousDownloads=[Collections.Generic.List[object]]::new()
$success=$false

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
    if ((& $git --no-optional-locks -C $source rev-parse HEAD).Trim() -cne $SourceCommit -or $LASTEXITCODE -ne 0) { throw 'Source commit mismatch.' }
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

function Write-Json([string]$Path,$Value) {
    $Path=Assert-TestPath $Path
    $Value | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath $Path -Encoding utf8NoBOM
}
function Read-Json([string]$Path) {
    Assert-RegularAncestors $Path
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable -DateKind String
}
function Get-PriorRecord([string]$Relative,[switch]$Binary) {
    if($resumeRecords.ContainsKey($Relative)){return $resumeRecords[$Relative]}
    $path=[IO.Path]::GetFullPath((Join-Path $resumeRoot $Relative))
    if(-not $path.StartsWith($resumeRoot+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Prior proof escaped the pinned failed run.'}
    Assert-RegularAncestors $path
    $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $retained=$false
    try {
        if(-not $Binary -and $stream.Length -gt 8MB){throw 'Prior textual proof is unexpectedly large.'}
        $hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream))
        $text=$null
        if(-not $Binary){
            $stream.Position=0
            $reader=[IO.StreamReader]::new($stream,[Text.Encoding]::UTF8,$true,4096,$true)
            try{$text=$reader.ReadToEnd()}finally{$reader.Dispose()}
        }
        $record=[ordered]@{Path=$path;Sha256=$hash;Bytes=$stream.Length;Text=$text}
        $resumeRecords.Add($Relative,$record);$inputLeases.Add($stream);$retained=$true
        return $record
    }finally{if(-not $retained){$stream.Dispose()}}
}
function Read-PriorJson([string]$Relative){
    return (Get-PriorRecord $Relative).Text | ConvertFrom-Json -AsHashtable -DateKind String
}
function Assert-PriorCli([string]$Name,[string[]]$ExpectedArguments){
    $start=Read-PriorJson ('logs/'+$Name+'.start.json')
    $result=Read-PriorJson ('logs/'+$Name+'.json')
    if($start.Executable -ine $gh -or ($result.Exit -isnot [long] -and $result.Exit -isnot [int]) -or
        $result.Exit -ne 0 -or $result.TimedOut -isnot [bool] -or $result.TimedOut -or
        -not [double]::IsFinite([double]$result.Seconds) -or [double]$result.Seconds -le 0){throw 'Prior mutation did not complete with actual exit0 and no timeout.'}
    Assert-EqualJson @($ExpectedArguments) @($start.Arguments) ('Prior exact '+$Name+' arguments')
    $started=[DateTimeOffset]::Parse($start.StartedUtc,[Globalization.CultureInfo]::InvariantCulture)
    return [ordered]@{Name=$Name;StartedUtc=$started.ToUniversalTime().ToString('O');CompletedUtc=$started.AddSeconds([double]$result.Seconds).ToUniversalTime().ToString('O');Seconds=[double]$result.Seconds}
}
function Initialize-ResumeEvidence {
    Assert-RegularAncestors $resumeRoot
    Assert-RegularAncestors $originalHarnessPath
    if((Get-FileHash -LiteralPath $originalHarnessPath -Algorithm SHA256).Hash -cne $originalHarnessSha256){throw 'Original frozen publication harness changed.'}
    $inputLeases.Add([IO.File]::Open($originalHarnessPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read))
    $summaryRecord=Get-PriorRecord 'summary.json'
    if($summaryRecord.Sha256 -cne $expectedPriorSummarySha256){throw 'The inspected prior failure summary bytes changed.'}
    $q=Read-PriorJson 'summary.json'
    if($q.State -cne 'FAIL' -or $q.SourceCommit -cne $SourceCommit -or $q.SourceRoot -ine $source -or $q.Tag -cne $tag -or
        $q.SessionId -cne '3d06edadc22848e1b48e4b7a529e82ea' -or $q.HarnessSha256 -cne $originalHarnessSha256 -or
        $q.Phase -cne 'CREATE_OWN_TAG_AND_DRAFT' -or $null -ne $q.ReleaseId -or
        $q.CreatedTag -isnot [bool] -or -not $q.CreatedTag -or $q.PublishCommandCompleted -isnot [bool] -or $q.PublishCommandCompleted -or
        $q.RemotePublishedObserved -isnot [bool] -or $q.RemotePublishedObserved){throw 'Prior failed run is not the explicitly authorized empty-draft recovery state.'}
    $script:sessionId=$q.SessionId
    $tagCommand=Assert-PriorCli 'cli-008-create-windows-tag' @('api','--hostname','github.com','--method','POST',"repos/$Repository/git/refs",'-f',"ref=refs/tags/$tag",'-f',"sha=$SourceCommit")
    $script:priorDraftCommand=Assert-PriorCli 'cli-010-create-own-draft' @('release','create',$tag,'--repo',$repoArg,'--verify-tag','--target',$SourceCommit,'--draft','--latest=false','--title','Keep Vault 5.0.3 for Windows','--notes-file',(Join-Path $resumeRoot 'release-notes.md'))
    if([DateTimeOffset]::Parse($priorDraftCommand.StartedUtc) -lt [DateTimeOffset]::Parse($tagCommand.CompletedUtc) -or
        [DateTimeOffset]::Parse($q.CompletedUtc) -lt [DateTimeOffset]::Parse($priorDraftCommand.CompletedUtc)){throw 'Prior mutation timing is inconsistent.'}
    $tagCreated=Read-PriorJson 'logs/cli-008-create-windows-tag.stdout.txt'
    if($tagCreated.ref -cne "refs/tags/$tag" -or $tagCreated.object.type -cne 'commit' -or $tagCreated.object.sha -cne $SourceCommit){throw 'Prior tag-create response does not identify the exact product source.'}
    $draftUrl=(Get-PriorRecord 'logs/cli-010-create-own-draft.stdout.txt').Text.Trim()
    if($draftUrl -cne $expectedDraftUrl){throw 'Prior successful draft-create URL changed.'}
    $failedLookup=Read-PriorJson 'logs/cli-011-api-repos_michael-feinermann_keep-vault_releases_tags_v5_0_3-windows.json'
    $failedError=(Get-PriorRecord 'logs/cli-011-api-repos_michael-feinermann_keep-vault_releases_tags_v5_0_3-windows.stderr.txt').Text
    if($failedLookup.Exit -ne 1 -or $failedLookup.TimedOut -isnot [bool] -or $failedLookup.TimedOut -or -not $failedError.Contains('(HTTP 404)',[StringComparison]::Ordinal)){throw 'The prior failure was not the inspected draft-by-tag lookup failure.'}
    $p=Read-PriorJson 'preservation.json'
    Assert-ReceiptFlags $p @('Source','OriginalPackage','OriginalAssets','Controls','UserShortcuts','MacTagMetadata','MacAssetBytes','LatestRelease','HandlesReleased') 'Prior failed-run preservation'
    if($p.WindowsRelease -isnot [bool] -or $p.WindowsRelease){throw 'Prior failure unexpectedly observed a completed Windows release.'}
    $script:priorMac=Read-PriorJson 'mac-before.json'
    Assert-EqualJson $priorMac (Read-PriorJson 'mac-after.json') 'Prior macOS before/after preservation'
    $script:priorLatest=Read-PriorJson 'latest-before.json'
    Assert-EqualJson $priorLatest (Read-PriorJson 'latest-after.json') 'Prior latest before/after preservation'
    if($priorLatest.Tag -cne $macTag -or $priorLatest.Id -ne 410709242){throw 'Prior latest release was not the retained macOS release.'}
    $script:priorFailedRun=[ordered]@{EvidenceRoot=$resumeRoot;SummaryPath=$summaryRecord.Path;SummarySha256=$summaryRecord.Sha256;PreservationPath=(Get-PriorRecord 'preservation.json').Path;PreservationSha256=(Get-PriorRecord 'preservation.json').Sha256;HarnessSha256=$q.HarnessSha256;SessionId=$q.SessionId;SourceCommit=$q.SourceCommit;State=$q.State;Phase=$q.Phase}
}
function Assert-PriorLocalBindings {
    if((Get-PriorRecord 'parent-final-gates.json').Sha256 -cne (Get-FileHash -LiteralPath $gatePath -Algorithm SHA256).Hash -or
        (Get-PriorRecord 'source-inputs-before.sha256').Sha256 -cne $sourceManifestHash){throw 'Prior parent final gates or committed source manifest differ from the newly validated actual inputs.'}
    foreach($path in @($gatePath,$notesPath)){$inputLeases.Add([IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read))}
    $notesRecord=Get-PriorRecord 'release-notes.md'
    $expectedNotes=$notes+"`n`n"+$sessionMarker+"`n"
    $expectedNotesHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes($expectedNotes)))
    if($notes -match '\{\{[^}]+\}\}' -or $notesRecord.Sha256 -cne $expectedPriorNotesSha256 -or $notesRecord.Sha256 -cne $expectedNotesHash -or $notesRecord.Text -cne $expectedNotes){throw 'Current notes plus old ownership marker are not byte-identical to the inspected prior notes.'}
    $oldGate=Read-PriorJson 'validated-final-gate-content.json'
    $oldValidated=Get-ReceiptTime $oldGate.ValidatedUtc 'prior actual gate validation'
    $freshValidated=Get-ReceiptTime $gateSemanticValidation.ValidatedUtc 'fresh actual gate validation'
    $tagStart=Get-ReceiptTime (Read-PriorJson 'logs/cli-008-create-windows-tag.start.json').StartedUtc 'prior tag-create start'
    $oldCompleted=Get-ReceiptTime (Read-PriorJson 'summary.json').CompletedUtc 'prior failed-run completion'
    if($oldValidated -ge $tagStart -or $freshValidated -le $oldCompleted -or
        $freshValidated -lt (Get-ReceiptTime $recoveryStartedUtc 'recovery start') -or $freshValidated -gt [DateTimeOffset]::UtcNow.UtcTicks){throw 'Prior/fresh gate validation timestamps are inconsistent with their actual runs.'}
    $oldStable=[ordered]@{};$freshStable=[ordered]@{}
    foreach($entry in $oldGate.GetEnumerator()){if($entry.Key -cne 'ValidatedUtc'){$oldStable[$entry.Key]=$entry.Value}}
    foreach($entry in $gateSemanticValidation.GetEnumerator()){if($entry.Key -cne 'ValidatedUtc'){$freshStable[$entry.Key]=$entry.Value}}
    Assert-EqualJson $oldStable $freshStable 'Every stable prior/current validated final gate field'
    $freshGatePath=Join-Path $testRoot 'validated-final-gate-content.json'
    $freshGateLease=[IO.File]::Open($freshGatePath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $inputLeases.Add($freshGateLease)
    $freshGateHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($freshGateLease))
    $script:gateValidationTimeProof=[ordered]@{PriorValidatedUtc=$oldGate.ValidatedUtc;FreshValidatedUtc=$gateSemanticValidation.ValidatedUtc;PriorRecordSha256=(Get-PriorRecord 'validated-final-gate-content.json').Sha256;FreshRecordPath=$freshGatePath;FreshRecordSha256=$freshGateHash;ExcludedComparisonField='ValidatedUtc (top-level timestamp only)';EveryOtherSemanticFieldEqual=$true}
    Assert-EqualJson (Read-PriorJson 'accepted-summary.json') $accepted 'Prior/current exact accepted package summary'
    Assert-SameMapping (Read-PriorJson 'assets-before.json') $assetBaseline 'Prior/current actual original assets'
    Assert-SameMapping (Read-PriorJson 'package-before.json') $packageBaseline 'Prior/current actual original package'
    Assert-EqualJson @(Read-PriorJson 'asset-plan.json') @($assetRecords) 'Prior/current twelve-asset plan including all hashes and source paths'
    Assert-DownloadedAssets (Join-Path $resumeRoot 'stage')
    $priorControl=Join-Path $resumeRoot 'control'
    Assert-SameTree $priorControl $controlBaseline
    foreach($entry in $controlBaseline.GetEnumerator()){
        if($entry.Value -ne 'D'){$null=Get-PriorRecord ('control/'+$entry.Key) -Binary}
    }
    $downloads=@(Read-PriorJson 'anonymous-downloads.json')
    if($downloads.Count -ne 12 -or @($priorMac.Assets).Count -ne 6){throw 'Prior anonymous macOS download evidence is incomplete.'}
    foreach($phase in @('before','after')){
        $directory=Join-Path $resumeRoot ('mac-assets-'+$phase)
        if(@([IO.Directory]::EnumerateFileSystemEntries($directory)).Count -ne 6){throw 'Prior macOS byte set membership changed.'}
        foreach($asset in $priorMac.Assets){
            $relative='mac-assets-'+$phase+'/'+$asset.Name
            $record=Get-PriorRecord $relative -Binary
            if($record.Bytes -ne $asset.Size -or $record.Sha256 -cne $asset.Sha256){throw 'Prior preserved macOS asset bytes changed.'}
            $proof=@($downloads | Where-Object { $_.Destination -ieq $record.Path })
            if($proof.Count -ne 1 -or $proof[0].Url -cne $asset.Url -or $proof[0].HttpStatus -ne 200 -or $proof[0].ReceivedBytes -ne $asset.Size -or
                $proof[0].CredentialsUsed -isnot [bool] -or $proof[0].CredentialsUsed -or $proof[0].CookiesUsed -isnot [bool] -or $proof[0].CookiesUsed){throw 'Prior anonymous macOS download proof is invalid.'}
        }
    }
}
function Assert-ResumeDraftIdentity($Info){
    if([long]$Info.id -ne $expectedResumeReleaseId -or $Info.tag_name -cne $tag -or $Info.name -cne 'Keep Vault 5.0.3 for Windows' -or
        $Info.target_commitish -cne $SourceCommit -or $Info.draft -isnot [bool] -or -not $Info.draft -or
        $Info.prerelease -isnot [bool] -or $Info.prerelease -or $null -ne $Info.published_at -or @($Info.assets).Count -ne 0 -or
        $Info.author.login -cne 'michael-feinermann' -or $Info.html_url -cne $expectedDraftUrl -or
        $Info.body -cne (Get-PriorRecord 'release-notes.md').Text){throw 'Remote draft is not the exact explicitly authorized owned empty draft.'}
    $bodyHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes([string]$Info.body)))
    if($bodyHash -cne $expectedPriorNotesSha256){throw 'Remote draft body bytes differ from the original ownership proof.'}
    # GitHub created_at can describe the target commit date, not draft creation.
    # updated_at has whole-second precision. Correlate only that timestamp with
    # the recorded CLI creation interval, rounded outward to whole seconds.
    $updated=[DateTimeOffset]::Parse([string]$Info.updated_at,[Globalization.CultureInfo]::InvariantCulture).ToUnixTimeSeconds()
    $start=[DateTimeOffset]::Parse($priorDraftCommand.StartedUtc).ToUnixTimeSeconds()
    $end=[DateTimeOffset]::Parse($priorDraftCommand.CompletedUtc).ToUnixTimeSeconds()+1
    if($updated -lt $start -or $updated -gt $end){throw 'Remote draft last-update time does not correlate with the successful original create command.'}
}
function Find-ExactOwnedDraft {
    $tagMatches=[Collections.Generic.List[object]]::new();$markerMatches=[Collections.Generic.List[object]]::new()
    $ids=[Collections.Generic.HashSet[long]]::new();$complete=$false;$pages=0
    for($page=1;$page -le 20;$page++){
        $entries=@(Get-Api "repos/$Repository/releases?per_page=100&page=$page")
        $pages=$page
        if($entries.Count -gt 100){throw 'Release-list page exceeds its explicit bound.'}
        foreach($entry in $entries){
            if(-not $ids.Add([long]$entry.id)){throw 'Release pagination repeated an ID; ownership enumeration is ambiguous.'}
            if($entry.tag_name -ceq $tag){$tagMatches.Add($entry)}
            if($entry.body -is [string] -and $entry.body.Contains($sessionMarker,[StringComparison]::Ordinal)){$markerMatches.Add($entry)}
        }
        if($entries.Count -lt 100){$complete=$true;break}
    }
    if(-not $complete -or $tagMatches.Count -ne 1 -or $markerMatches.Count -ne 1 -or
        [long]$tagMatches[0].id -ne [long]$markerMatches[0].id){throw 'No unique exact tag/old-marker draft was proven within bounded authenticated pagination.'}
    Assert-ResumeDraftIdentity $tagMatches[0]
    $byId=Get-Api "repos/$Repository/releases/$expectedResumeReleaseId"
    Assert-ResumeDraftIdentity $byId
    if((Get-TagCommit $tag) -cne $SourceCommit){throw 'Existing owned Windows tag no longer identifies the exact accepted source.'}
    Write-Json (Join-Path $testRoot 'identified-own-draft.json') $byId
    $script:recoveryProvenance=[ordered]@{State='OWNED_EMPTY_DRAFT_VERIFIED_NOT_YET_PUBLISHED';RecoveryRunId=$recoveryRunId;PriorFailedRun=$priorFailedRun;SessionId=$sessionId;SourceCommit=$SourceCommit;SourceRoot=$source;ReleaseId=$expectedResumeReleaseId;Tag=$tag;TagCreatedByThisInvocation=$false;TagCreatedByPriorAttempt=$true;DraftCreatedByThisInvocation=$false;AuthenticatedEnumerationPages=$pages;EnumeratedReleaseCount=$ids.Count;ExactTagMatches=$tagMatches.Count;ExactSessionMarkerMatches=$markerMatches.Count;Title=$byId.name;PriorCreateUrl=$expectedDraftUrl;NotesSha256=$expectedPriorNotesSha256;UpdatedAt=[string]$byId.updated_at;PriorCreateInterval=$priorDraftCommand;GateValidationTimeProof=$gateValidationTimeProof;SourceManifestSha256=$sourceManifestHash;CurrentFinalGateSha256=(Get-FileHash -LiteralPath $gatePath -Algorithm SHA256).Hash;AssetCount=$assetRecords.Count;OriginalHarnessSha256=$originalHarnessSha256;ValidatedPriorFiles=@($resumeRecords.GetEnumerator()|Sort-Object Key|ForEach-Object{[ordered]@{Name=$_.Key;Sha256=$_.Value.Sha256;Bytes=$_.Value.Bytes}});Checks=@('Pinned failed summary and original harness','Actual prior tag/draft create exits0, exact arguments and response','Exact old-session notes/body/title/source/URL/author/ID','Whole-second updated_at correlated with original CLI, created_at not treated as draft creation','Newly revalidated build/full/performance/acceptance/source/assets/pins/controls','Prior macOS/latest metadata and all12 anonymous macOS before/after byte proofs','Current existing tag/macOS/latest preservation before mutation');Scope='Recovery of this exact previously created empty draft only; no new tag/draft creation, unrelated release adoption, overwrite or deletion. No raw process/UI/shortcut states are included.'}
    Write-Json (Join-Path $testRoot 'recovery-provenance.json') $recoveryProvenance
    return $byId
}
function Invoke-Cli([string]$Executable,[string[]]$Arguments,[string]$Label,[int[]]$AllowedExit=@(0)) {
    if ($Executable -cnotin @($gh,$git)) { throw 'Unsupported administrative executable.' }
    $script:CliNumber++
    $id='cli-{0:D3}-{1}' -f $script:CliNumber,($Label -replace '[^A-Za-z0-9_-]','_')
    $start=[Diagnostics.ProcessStartInfo]::new()
    $start.FileName=$Executable; $start.WorkingDirectory=$testRoot
    $start.UseShellExecute=$false; $start.CreateNoWindow=$true
    $start.RedirectStandardOutput=$true; $start.RedirectStandardError=$true
    foreach($argument in $Arguments){$start.ArgumentList.Add($argument)}
    $process=[Diagnostics.Process]::new(); $process.StartInfo=$start
    $started=$false; $tree=@(); $treeError=$null
    $watch=[Diagnostics.Stopwatch]::StartNew()
    Write-Json (Join-Path $logs "$id.start.json") ([ordered]@{Executable=$Executable;Arguments=$Arguments;StartedUtc=[DateTime]::UtcNow.ToString('O')})
    try {
        $started=$process.Start(); if(-not $started){throw 'Administrative process did not start.'}
        $stdout=$process.StandardOutput.ReadToEndAsync(); $stderr=$process.StandardError.ReadToEndAsync()
        $timedOut=-not $process.WaitForExit($PerProcessTimeoutSeconds*1000)
        if($timedOut){
            try {
                $all=@(Get-CimInstance Win32_Process -ErrorAction Stop)
                $ids=[Collections.Generic.HashSet[uint32]]::new(); $null=$ids.Add([uint32]$process.Id)
                do{$added=$false; foreach($item in $all){if($ids.Contains([uint32]$item.ParentProcessId) -and $ids.Add([uint32]$item.ProcessId)){$added=$true}}}while($added)
                $tree=@($all | Where-Object {$ids.Contains([uint32]$_.ProcessId)} | Select-Object ProcessId,ParentProcessId,Name,CreationDate,KernelModeTime,UserModeTime)
            } catch {$treeError=$_.Exception.Message}
            $process.Kill($true)
            if(-not $process.WaitForExit(10000)){throw 'Timed-out administrative process did not terminate.'}
        }
        if(-not $stdout.Wait(10000) -or -not $stderr.Wait(10000)){throw 'Administrative output drain timed out.'}
        $out=$stdout.GetAwaiter().GetResult(); $err=$stderr.GetAwaiter().GetResult(); $exit=$process.ExitCode
        [IO.File]::WriteAllText((Join-Path $logs "$id.stdout.txt"),$out)
        [IO.File]::WriteAllText((Join-Path $logs "$id.stderr.txt"),$err)
        Write-Json (Join-Path $logs "$id.json") ([ordered]@{Exit=$exit;TimedOut=$timedOut;Seconds=$watch.Elapsed.TotalSeconds;TreeAtTimeout=$tree;TreeCaptureError=$treeError})
        if($timedOut -or $exit -notin $AllowedExit){throw "Administrative command $id failed; inspect retained logs (exit=$exit, timeout=$timedOut)."}
        return [pscustomobject]@{Exit=$exit;Output=$out;Error=$err}
    } catch {
        Write-Json (Join-Path $logs "$id.failure.json") ([ordered]@{Error=$_.Exception.ToString();TreeAtTimeout=$tree;TreeCaptureError=$treeError})
        throw
    } finally {
        try {if($started -and -not $process.HasExited){$process.Kill($true); if(-not $process.WaitForExit(10000)){throw 'Administrative process survived exceptional cleanup.'}}}
        finally {$process.Dispose()}
    }
}
function Get-Api([string]$Endpoint,[switch]$Optional) {
    $result=Invoke-Cli $gh @('api','--hostname','github.com',$Endpoint) ('api-'+$Endpoint) $(if($Optional){@(0,1)}else{@(0)})
    if($result.Exit -ne 0){
        if($Optional -and $result.Error.Contains('(HTTP 404)',[StringComparison]::Ordinal)){return $null}
        throw 'API absence was not proven by an explicit HTTP 404.'
    }
    return $result.Output | ConvertFrom-Json -AsHashtable -DateKind String
}
function Get-TagCommit([string]$Name,[switch]$Optional) {
    $ref=Get-Api "repos/$Repository/git/ref/tags/$Name" -Optional:$Optional
    if($null -eq $ref){return $null}
    $object=$ref.object
    for($depth=0;$depth -lt 5;$depth++){
        if($object.type -ceq 'commit'){return [string]$object.sha}
        if($object.type -cne 'tag'){throw 'Unexpected tag object type.'}
        $object=(Get-Api "repos/$Repository/git/tags/$($object.sha)").object
    }
    throw 'Annotated tag chain exceeds bound.'
}
function Get-MacSnapshot {
    $info=Get-Api "repos/$Repository/releases/tags/$macTag"
    if($info.draft -or $info.tag_name -cne $macTag -or @($info.assets).Count -ne 6){throw 'Existing macOS release identity/assets are unexpected.'}
    $commit=Get-TagCommit $macTag
    if($commit -cne $macExpected.productSourceCommit){throw 'Existing macOS source tag differs from its retained Build21 identity.'}
    $assets=@(foreach($asset in ($info.assets | Sort-Object name)){
        $expected=@($macExpected.assets | Where-Object name -CEQ $asset.name)
        if($expected.Count -ne 1 -or [long]$asset.size -ne [long]$expected[0].sizeBytes -or
            ($asset.digest -and $asset.digest -ine ('sha256:'+$expected[0].sha256))){throw 'Existing macOS asset metadata differs from retained Build21 identity.'}
        [ordered]@{Id=$asset.id;Name=$asset.name;Size=$asset.size;Digest=$asset.digest;State=$asset.state;Url=$asset.browser_download_url;Sha256=$expected[0].sha256.ToUpperInvariant()}
    })
    return [ordered]@{ReleaseId=$info.id;Tag=$info.tag_name;TagCommit=$commit;Name=$info.name;Body=$info.body;Draft=$info.draft;Prerelease=$info.prerelease;PublishedAt=$info.published_at;Assets=$assets}
}
function Assert-EqualJson($Expected,$Actual,[string]$Label){
    if(($Expected | ConvertTo-Json -Depth 15 -Compress) -cne ($Actual | ConvertTo-Json -Depth 15 -Compress)){throw "$Label changed."}
}
function Download-Anonymous([string]$Url,[string]$Destination,[string]$Name) {
    $Destination=Assert-TestPath $Destination
    if([IO.Path]::Exists($Destination)){throw 'Anonymous download destination already exists.'}
    $uri=[Uri]$Url
    if($uri.Scheme -cne 'https' -or $uri.Host -cne 'github.com' -or
        $uri.AbsolutePath -cne "/$Repository/releases/download/$Name/$([Uri]::EscapeDataString([IO.Path]::GetFileName($Destination)))") {
        throw 'Anonymous input URL is not the expected exact GitHub asset.'
    }
    $handler=[Net.Http.HttpClientHandler]::new()
    $handler.UseCookies=$false; $handler.UseDefaultCredentials=$false; $handler.Credentials=$null
    $handler.AllowAutoRedirect=$true; $handler.MaxAutomaticRedirections=10
    $client=[Net.Http.HttpClient]::new($handler)
    $client.DefaultRequestHeaders.UserAgent.ParseAdd('KeepVault-Windows-release-verification/5.0.3')
    $client.Timeout=[TimeSpan]::FromSeconds(300)
    try {
        for($attempt=1;$attempt -le 5;$attempt++){
            $cancel=[Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(300))
            $response=$null; $stream=$null; $output=$null
            try {
                $response=$client.GetAsync($uri,[Net.Http.HttpCompletionOption]::ResponseHeadersRead,$cancel.Token).GetAwaiter().GetResult()
                if([int]$response.StatusCode -in @(404,502,503) -and $attempt -lt 5){Start-Sleep -Seconds 2; continue}
                $null=$response.EnsureSuccessStatusCode()
                $final=$response.RequestMessage.RequestUri
                if($final.Scheme -cne 'https' -or ($final.Host -cne 'github.com' -and -not $final.Host.EndsWith('.githubusercontent.com',[StringComparison]::OrdinalIgnoreCase))){throw 'Unexpected anonymous download redirect.'}
                $stream=$response.Content.ReadAsStreamAsync($cancel.Token).GetAwaiter().GetResult()
                $output=[IO.File]::Open($Destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
                $stream.CopyToAsync($output,$cancel.Token).GetAwaiter().GetResult(); $output.Flush($true)
                $script:AnonymousDownloads.Add([ordered]@{Url=$Url;Destination=$Destination;Attempt=$attempt;HttpStatus=[int]$response.StatusCode;FinalHost=$final.Host;FinalPath=$final.AbsolutePath;ReceivedBytes=$output.Length;CredentialsUsed=$false;CookiesUsed=$false;CompletedUtc=[DateTime]::UtcNow.ToString('O')})
                return
            } finally {
                if($output){$output.Dispose()}; if($stream){$stream.Dispose()}; if($response){$response.Dispose()}; $cancel.Dispose()
            }
        }
        throw 'Anonymous download attempts exhausted.'
    } finally {$client.Dispose();$handler.Dispose()}
}
function Download-MacSet($Snapshot,[string]$Destination){
    $Destination=Assert-TestPath $Destination
    [IO.Directory]::CreateDirectory($Destination) | Out-Null
    foreach($asset in $Snapshot.Assets){
        $path=Join-Path $Destination $asset.Name
        Download-Anonymous $asset.Url $path $macTag
        if((Get-Item -LiteralPath $path).Length -ne [long]$asset.Size -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $asset.Sha256){throw 'Existing macOS public asset bytes differ.'}
    }
}
function Assert-OwnedRelease([bool]$Draft){
    if(-not $script:CreatedReleaseId){throw 'No exact previously owned release has been identified for this recovery.'}
    $info=Get-Api "repos/$Repository/releases/$script:CreatedReleaseId"
    if([long]$info.id -ne [long]$script:CreatedReleaseId -or $info.tag_name -cne $tag -or
        [bool]$info.draft -ne $Draft -or $info.name -cne 'Keep Vault 5.0.3 for Windows' -or
        $info.target_commitish -cne $SourceCommit -or $info.author.login -cne 'michael-feinermann' -or
        $info.prerelease -isnot [bool] -or $info.prerelease -or
        $info.body -cne (Get-PriorRecord 'release-notes.md').Text -or
        (Get-TagCommit $tag) -cne $SourceCommit){throw 'Remote release ownership, state or exact source tag changed.'}
    return $info
}
function Assert-RemoteAssets($ReleaseInfo){
    if(@($ReleaseInfo.assets).Count -ne 12){throw 'Remote release must contain exactly twelve assets.'}
    foreach($asset in $ReleaseInfo.assets){
        $expected=@($assetRecords | Where-Object Name -CEQ $asset.name)
        if($expected.Count -ne 1 -or [long]$asset.size -ne [long]$expected[0].Size -or $asset.state -cne 'uploaded' -or
            $asset.digest -ine ('sha256:'+$expected[0].Sha256)){throw 'Remote asset name, size, upload state or GitHub SHA-256 digest mismatch.'}
    }
}
function Assert-DownloadedAssets([string]$Root){
    $entries=@([IO.Directory]::EnumerateFileSystemEntries($Root))
    if($entries.Count -ne 12){throw 'Downloaded asset set is not exactly twelve files.'}
    foreach($record in $assetRecords){
        $path=Join-Path $Root $record.Name
        Assert-RegularAncestors $path
        if(-not [IO.File]::Exists($path) -or (Get-Item -LiteralPath $path).Length -ne $record.Size -or
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $record.Sha256 -or
            (Get-FileHash -LiteralPath $path -Algorithm SHA512).Hash -cne $record.Sha512){throw 'Downloaded asset bytes differ from accepted local artifact.'}
        $inputLeases.Add([IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read))
    }
}
function Verify-DownloadedSet([string]$Root,[string]$Label){
    Assert-DownloadedAssets $Root
    $downloadVerifier=Join-Path $Root $verifierAssetName
    $downloadZip=Join-Path $Root $zipAssetName
    Invoke-ExpectedProcess $verifier @($downloadVerifier) 0 'RESULT: TRUSTED' "$Label-local-verifier-check"
    Invoke-ExpectedProcess $verifier @($downloadZip) 0 'RESULT: TRUSTED' "$Label-local-zip-check"
    Register-ControlExecutable $downloadVerifier 'verifier'
    Invoke-ExpectedProcess $downloadVerifier @($downloadVerifier) 0 'RESULT: TRUSTED' "$Label-downloaded-verifier-self"
    Invoke-ExpectedProcess $downloadVerifier @($downloadZip) 0 'RESULT: TRUSTED' "$Label-downloaded-verifier-zip"
}

# These validators consume the actual hash-bound proof content. A parent's
# PASS label, or a matching hash of an unrelated/failed JSON file, is insufficient.
function Get-NormalReceiptPath([string]$Path){
    if([string]::IsNullOrWhiteSpace($Path) -or -not [IO.Path]::IsPathFullyQualified($Path)){throw 'Receipt paths must be absolute.'}
    return [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath($Path))
}
function Read-HashedGateFile($Evidence){
    $path=Get-NormalReceiptPath $Evidence.Path
    if(-not $path.StartsWith($workRoot+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Gate proof escaped canonical work.'}
    Assert-RegularAncestors $path
    $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try{
        if($Evidence.Sha256 -cnotmatch '^[0-9A-F]{64}$' -or [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream)) -cne $Evidence.Sha256){throw 'Gate proof hash mismatch.'}
        $value=$null
        if([IO.Path]::GetExtension($path) -ieq '.json'){
            $stream.Position=0
            $reader=[IO.StreamReader]::new($stream,[Text.Encoding]::UTF8,$true,4096,$true)
            try{$value=$reader.ReadToEnd() | ConvertFrom-Json -AsHashtable -DateKind String}finally{$reader.Dispose()}
        }
    }finally{$stream.Dispose()}
    return [ordered]@{Path=$path;Sha256=$Evidence.Sha256;Value=$value}
}
function Find-OneGateProof($Records,[string[]]$Keys,[string]$Label){
    $found=[Collections.Generic.List[object]]::new()
    foreach($record in $Records){
        if($record.Value -isnot [Collections.IDictionary]){continue}
        $matches=$true
        foreach($key in $Keys){if(-not $record.Value.Contains($key)){$matches=$false;break}}
        if($matches){$found.Add($record)}
    }
    if($found.Count -ne 1){throw "Required $Label proof is absent or ambiguous."}
    return $found[0]
}
function Assert-ReceiptInteger($Value,[long]$Expected,[string]$Label){
    if(($Value -isnot [int] -and $Value -isnot [long]) -or $Value -ne $Expected){throw "Invalid $Label."}
}
function Assert-ReceiptFlags($Value,[string[]]$Names,[string]$Label){
    foreach($name in $Names){if(-not $Value.Contains($name) -or $Value[$name] -isnot [bool] -or -not $Value[$name]){throw "$Label did not preserve $name."}}
    if(-not $Value.Contains('Errors') -or @($Value.Errors).Count){throw "$Label contains preservation errors."}
}
function Get-ReceiptTime($Value,[string]$Label){
    if($Value -isnot [string] -or [string]::IsNullOrWhiteSpace($Value)){throw "Missing $Label timestamp."}
    return [DateTimeOffset]::Parse($Value,[Globalization.CultureInfo]::InvariantCulture).UtcTicks
}
function Assert-ActualSuiteResults($Value,[int]$Count,[string]$OnlyId,[string]$InventoryHash){
    Assert-ReceiptInteger $Value.schemaVersion 2 'suite result schema'
    if($Value.head -cne $SourceCommit -or $Value.platform -cne 'windows' -or $Value.architecture -cne 'x64' -or
        $Value.testInventoryHash -cne $InventoryHash -or @($Value.tests).Count -ne $Count){throw 'Actual suite results do not identify the exact final Windows test inventory.'}
    Assert-ReceiptInteger $Value.budget.maxWorkers 1 'suite worker count'
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($test in $Value.tests){
        if($test.id -isnot [string] -or [string]::IsNullOrWhiteSpace($test.id) -or -not $seen.Add($test.id) -or
            $test.status -cne 'PASS' -or -not $test.Contains('failure') -or $null -ne $test.failure -or -not $test.Contains('seconds') -or $null -eq $test.seconds -or
            -not [double]::IsFinite([double]$test.seconds) -or [double]$test.seconds -lt 0){throw 'Actual suite results contain a duplicate, failed, blocked or invalid test.'}
        if($OnlyId -and ($test.id -cne $OnlyId -or [double]$test.seconds -le 0)){throw 'The fresh performance result names another group or has no measured duration.'}
    }
}
function Assert-ActualFinalGates($Proofs){
    $inventoryHash='f8bfbcf6973ff56e0a8fd7744fb682ae37285d82733880f41b3a87df46f518a3'
    $testDll=Join-Path $source 'work\native-gate-tests\KalynaArchiver.Tests.dll'
    Assert-RegularAncestors $testDll
    $testDllHash=(Get-FileHash -LiteralPath $testDll -Algorithm SHA256).Hash
    $build=Find-OneGateProof $Proofs['ImmutableBuild'] @('SourceCommit','PreexistingAuditPreserved','PreexistingAuditSha256','StartedAt','FinishedAt') 'immutable-build receipt'
    $b=$build.Value
    if($b.State -cne 'PASS' -or $b.SourceCommit -cne $SourceCommit -or $b.PreexistingAuditPreserved -isnot [bool] -or
        -not $b.PreexistingAuditPreserved -or $b.PreexistingAuditSha256 -cnotmatch '^[0-9A-F]{64}$'){throw 'Actual immutable build or preexisting audit preservation did not PASS.'}
    $buildStarted=Get-ReceiptTime $b.StartedAt 'build start'
    $buildFinished=Get-ReceiptTime $b.FinishedAt 'build completion'
    if($buildFinished -lt $buildStarted){throw 'Build timestamps are inconsistent.'}
    $receipt=Find-OneGateProof $Proofs['FullSuite'] @('Mode','Commit','SourceRoot','ProcessExitCode','UnchangedSourceFiles','FinishedAt') 'full-suite receipt'
    $preflight=Find-OneGateProof $Proofs['FullSuite'] @('Commit','SourceRoot','BuildState','BuildFinishedAt','MatchingCompletedManifestSha256','SourceInputCount','TestAssemblySha256') 'full-suite source/test-DLL preflight'
    $results=Find-OneGateProof $Proofs['FullSuite'] @('schemaVersion','head','testInventoryHash','tests','budget') 'full-suite actual results'
    $r=$receipt.Value; $f=$preflight.Value
    if($r.Mode -cne 'full' -or $r.State -cne 'PASS' -or $r.Commit -cne $SourceCommit -or
        (Get-NormalReceiptPath $r.SourceRoot) -ine $source -or ($r.Contains('RunPurpose') -and $r.RunPurpose -cne 'Final')){throw 'Actual final full-suite receipt does not PASS for this candidate.'}
    Assert-ReceiptInteger $r.ProcessExitCode 0 'full-suite process exit'
    Assert-ReceiptInteger $r.UnchangedSourceFiles $sourceInputCount 'full-suite preserved source count'
    if($f.Commit -cne $SourceCommit -or (Get-NormalReceiptPath $f.SourceRoot) -ine $source -or $f.BuildState -cne 'PASS' -or
        $f.MatchingCompletedManifestSha256 -cne $sourceManifestHash -or $f.TestAssemblySha256 -cne $testDllHash -or
        (Get-ReceiptTime $f.BuildFinishedAt 'preflight build completion') -ne $buildFinished){throw 'Full-suite preflight is not bound to the actual build, source manifest and current compiled test DLL.'}
    Assert-ReceiptInteger $f.SourceInputCount $sourceInputCount 'full-suite preflight source count'
    $fullStarted=Get-ReceiptTime $r.StartedAt 'full-suite start'
    $fullFinished=Get-ReceiptTime $r.FinishedAt 'full-suite completion'
    if($fullStarted -lt $buildFinished -or $fullFinished -lt $fullStarted -or
        (Get-ReceiptTime $f.StartedAt 'full-suite preflight') -gt $fullStarted){throw 'Full-suite timestamps do not follow the completed immutable build.'}
    Assert-ActualSuiteResults $results.Value 109 '' $inventoryHash

    $summary=Find-OneGateProof $Proofs['Performance'] @('Name','RunPurpose','SourceCommit','SourceRoot','SourceManifestSha256','Groups','Preservation','Evidence') 'performance summary'
    $s=$summary.Value
    if($s.Name -cne 'Performance' -or $s.RunPurpose -cne 'Final' -or $s.State -cne 'PASS' -or $s.SourceCommit -cne $SourceCommit -or
        (Get-NormalReceiptPath $s.SourceRoot) -ine $source -or $s.SourceManifestSha256 -cne $sourceManifestHash -or
        -not $s.Contains('Error') -or $null -ne $s.Error -or $s.HistoricalComparison -cnotin @('PASS','NOT_RUN')){throw 'Actual performance summary is not a final PASS for this candidate.'}
    $flags=@('Source','TwelveAssets','CompiledTestInputs','Manifest','HandlesReleased')
    Assert-ReceiptFlags $s.Preservation $flags 'Performance summary'
    $performanceRoot=[IO.Path]::GetDirectoryName($summary.Path)
    $bundle=[Collections.Generic.List[object]]::new()
    $bundleByPath=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($entry in $s.Evidence){
        $proof=Read-HashedGateFile $entry
        if(-not $proof.Path.StartsWith($performanceRoot+'\',[StringComparison]::OrdinalIgnoreCase) -or $bundleByPath.ContainsKey($proof.Path)){throw 'Performance evidence is duplicated or escaped its own run directory.'}
        $bundle.Add($proof); $bundleByPath.Add($proof.Path,$proof)
    }
    $provenance=Find-OneGateProof $bundle.ToArray() @('RunPurpose','SourceRoot','SourceCommit','SourceManifestSha256','Tests','TestDllSha256','GroupPlan') 'performance provenance'
    $preservation=Find-OneGateProof $bundle.ToArray() $flags 'performance preservation receipt'
    Assert-ReceiptFlags $preservation.Value $flags 'Performance preservation receipt'
    $p=$provenance.Value
    if($p.RunPurpose -cne 'Final' -or $p.SourceCommit -cne $SourceCommit -or (Get-NormalReceiptPath $p.SourceRoot) -ine $source -or
        $p.SourceManifestSha256 -cne $sourceManifestHash -or (Get-NormalReceiptPath $p.Tests) -ine $testDll -or
        $p.TestDllSha256 -cne $testDllHash -or $p.Sdk -cne '10.0.402'){throw 'Performance provenance is not bound to the exact source and tested DLL.'}
    $expectedGroups=@('performance.cipher-suites','release.paranoia-256mib-level5','performance.entropy-rev9-phases','release.paranoia-complex-tree-level5-repair')
    if(@($s.Groups).Count -ne 4 -or @($p.GroupPlan).Count -ne 4){throw 'Performance did not execute exactly four planned groups.'}
    $lastCompleted=$fullFinished
    $summaryCompleted=Get-ReceiptTime $s.CompletedUtc 'performance summary completion'
    $validatedGroups=[Collections.Generic.List[object]]::new()
    for($index=0;$index -lt 4;$index++){
        $group=$s.Groups[$index]; $plan=$p.GroupPlan[$index]; $id=$expectedGroups[$index]
        Assert-ReceiptInteger $group.Number ($index+1) 'performance group number'
        Assert-ReceiptInteger $plan.Number ($index+1) 'performance planned group number'
        Assert-ReceiptInteger $group.ExitCode 0 'performance actual process exit'
        if($group.Id -cne $id -or $plan.Id -cne $id -or $group.State -cne 'PASS' -or
            $group.ResultFresh -isnot [bool] -or -not $group.ResultFresh -or $group.CleanupPassed -isnot [bool] -or -not $group.CleanupPassed -or
            $group.TimedOut -isnot [bool] -or $group.TimedOut -or -not $group.Contains('Error') -or $null -ne $group.Error){throw 'Performance group order, real process completion or fresh cleanup did not PASS.'}
        $started=Get-ReceiptTime $group.StartedUtc 'performance group start'
        $completed=Get-ReceiptTime $group.CompletedUtc 'performance group completion'
        if($started -lt $lastCompleted -or $completed -lt $started -or $completed -gt $summaryCompleted -or
            -not [double]::IsFinite([double]$group.Seconds) -or [double]$group.Seconds -le 0){throw 'Performance groups were not completed sequentially after the final full suite.'}
        $lastCompleted=$completed
        $resultPath=Get-NormalReceiptPath $group.ResultsPath
        if(-not $bundleByPath.ContainsKey($resultPath) -or $group.ResultsSha256 -cne $bundleByPath[$resultPath].Sha256){throw 'Performance group result is not bound into this exact run evidence.'}
        $actual=$bundleByPath[$resultPath]
        Assert-ActualSuiteResults $actual.Value 1 $id $inventoryHash
        $validatedGroups.Add([ordered]@{Id=$id;ResultsPath=$resultPath;Sha256=$actual.Sha256;State='PASS'})
    }
    return [ordered]@{State='PASS';SourceRoot=$source;SourceCommit=$SourceCommit;SourceManifestSha256=$sourceManifestHash;TestDllSha256=$testDllHash;FullSuiteTestCount=109;TestInventoryHash=$inventoryHash;BuildReceipt=[ordered]@{Path=$build.Path;Sha256=$build.Sha256};FullReceipt=[ordered]@{Path=$receipt.Path;Sha256=$receipt.Sha256};FullPreflight=[ordered]@{Path=$preflight.Path;Sha256=$preflight.Sha256};FullResults=[ordered]@{Path=$results.Path;Sha256=$results.Sha256};PerformanceSummary=[ordered]@{Path=$summary.Path;Sha256=$summary.Sha256};PerformanceGroups=$validatedGroups.ToArray();HistoricalComparison=$s.HistoricalComparison;ValidatedUtc=[DateTime]::UtcNow.ToString('O')}
}

Assert-RegularAncestors $workRoot
Assert-RegularAncestors $evidenceParentPath
$sourceInputCount=Assert-CommittedSource
$sourceManifest=Join-Path (Split-Path $source) 'source-inputs-before.sha256'
$sourceAfterManifest=Join-Path (Split-Path $source) 'source-inputs-after.sha256'
$sourceManifestHash=(Get-FileHash -LiteralPath $sourceManifest -Algorithm SHA256).Hash
Assert-RegularAncestors $release
Assert-RegularAncestors $externalVerifier
$acceptancePath=[IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath($AcceptanceEvidence))
if(-not $acceptancePath.StartsWith($workRoot+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Acceptance evidence must be beneath the canonical work directory.'}
$accepted=Read-Json (Join-Path $acceptancePath 'summary.json')
$acceptedProvenance=Read-Json (Join-Path $acceptancePath 'provenance.json')
$acceptedPreservation=Read-Json (Join-Path $acceptancePath 'preservation.json')
if($accepted.State -cne 'PASS' -or $accepted.RunPurpose -cne 'Final' -or $accepted.SourceCommit -cne $SourceCommit -or $accepted.ProductVersion -cne '5.0.3' -or
    [int]$accepted.Cases -ne 40 -or [int]$accepted.ExecutableInvocations -ne 81 -or
    $acceptedProvenance.RunPurpose -cne 'Final' -or $acceptedProvenance.SourceSnapshotRoot -ine $source -or $acceptedProvenance.SourceCommit -cne $SourceCommit -or
    $acceptedProvenance.SourceManifestSha256 -cne $sourceManifestHash){throw 'Final package acceptance is not PASS for this exact source/candidate.'}
foreach($name in @('OriginalPackage','OriginalZipSet','OriginalAssets','ControlPrograms','UserShortcuts','SourceSnapshot','HandlesReleased')){
    if($acceptedPreservation[$name] -isnot [bool] -or -not $acceptedPreservation[$name]){throw 'Acceptance input preservation did not pass.'}
}
if(@($acceptedPreservation.Errors).Count){throw 'Acceptance preservation errors exist.'}
$gatePath=[IO.Path]::GetFullPath($FinalGateReceipt)
if(-not $gatePath.StartsWith($workRoot+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Final gate receipt must be beneath canonical work.'}
$gate=Read-Json $gatePath
if($gate.State -cne 'PASS' -or $gate.SourceCommit -cne $SourceCommit -or $gate.SourceRoot -ine $source -or
    $gate.AcceptanceEvidence -ine $acceptancePath){throw 'Parent final-gate receipt is not bound to this candidate.'}
$gateProofs=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
if(@($gate.Checks).Count -ne 3){throw 'Exactly the three required parent gates must be supplied.'}
foreach($name in @('ImmutableBuild','FullSuite','Performance')){
    $checks=@($gate.Checks | Where-Object Name -CEQ $name)
    if($checks.Count -ne 1 -or $checks[0].State -cne 'PASS' -or @($checks[0].Evidence).Count -lt 1){throw "Required parent gate $name is not PASS with evidence."}
    $records=[Collections.Generic.List[object]]::new()
    $paths=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($evidence in $checks[0].Evidence){$proof=Read-HashedGateFile $evidence;if(-not $paths.Add($proof.Path)){throw 'A parent gate repeats the same evidence file.'};$records.Add($proof)}
    $gateProofs.Add($name,$records.ToArray())
}
$gateSemanticValidation=Assert-ActualFinalGates $gateProofs
$notesPath=[IO.Path]::GetFullPath($ReleaseNotes); Assert-RegularAncestors $notesPath
$notes=[IO.File]::ReadAllText($notesPath)
if([string]::IsNullOrWhiteSpace($notes) -or $notes.Length -gt 100000){throw 'Release notes must be nonempty and bounded.'}
[xml]$versionProps=Get-Content -LiteralPath (Join-Path $source 'Directory.Build.props') -Raw
$productVersion=$versionProps.SelectSingleNode('/Project/PropertyGroup/Version').InnerText
if($productVersion -cne '5.0.3'){throw 'Only product 5.0.3 is supported.'}
$policyRoot=Join-Path $source 'WindowsRelease\Signing'
$publicCertificate=[Security.Cryptography.X509Certificates.X509CertificateLoader]::LoadCertificateFromFile((Join-Path $policyRoot 'hybrid-rsa4096.cer'))
try {
    [xml]$policy=Get-Content -LiteralPath (Join-Path $policyRoot 'Directory.Build.props') -Raw
    if($publicCertificate.HasPrivateKey -or $publicCertificate.Thumbprint -cne $policy.Project.PropertyGroup.KalynaSigningCertificateThumbprint){throw 'Windows public certificate policy mismatch.'}
    $publicCertificateSha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($publicCertificate.RawData))
} finally {$publicCertificate.Dispose()}
Add-Type -TypeDefinition ("using System;`n"+[IO.File]::ReadAllText((Join-Path $source 'KalynaArchiver.Signing\ReleaseAuthenticode.cs')))
$macExpected=Read-Json (Join-Path $source 'docs\evidence\v13-build21-published-20261012\administration\github-asset-set-build21.json')
if(@($macExpected.assets).Count -ne 6){throw 'Unexpected retained macOS asset baseline.'}
Initialize-ResumeEvidence
$sessionMarker="<!-- windows-publication-session:$sessionId source:$SourceCommit -->"
if([IO.Path]::Exists($testRoot)){throw 'Fresh publication evidence root exists.'}
[IO.Directory]::CreateDirectory($testRoot) | Out-Null
$logs=Join-Path $testRoot 'logs'; $control=Join-Path $testRoot 'control'; $stage=Join-Path $testRoot 'stage'
foreach($path in @($logs,$control,$stage)){[IO.Directory]::CreateDirectory($path) | Out-Null}
$shortcutBaseline=Get-ShortcutState
try {
    $packageBaseline=Get-Tree $release
    $assetBaseline=Get-AssetSet
    Assert-SameMapping (Read-Json (Join-Path $acceptancePath 'assets-before.json')) $assetBaseline 'Accepted original artifacts'
    Assert-SameMapping (Read-Json (Join-Path $acceptancePath 'package-before.json')) $packageBaseline 'Accepted original package'
    Write-Json (Join-Path $testRoot 'package-before.json') $packageBaseline
    Write-Json (Join-Path $testRoot 'assets-before.json') $assetBaseline
    [IO.File]::Copy($sourceManifest,(Join-Path $testRoot 'source-inputs-before.sha256'),$false)
    [IO.File]::Copy($gatePath,(Join-Path $testRoot 'parent-final-gates.json'),$false)
    Write-Json (Join-Path $testRoot 'validated-final-gate-content.json') $gateSemanticValidation
    [IO.File]::Copy((Join-Path $acceptancePath 'summary.json'),(Join-Path $testRoot 'accepted-summary.json'),$false)
    [IO.File]::WriteAllText((Join-Path $testRoot 'release-notes.md'),$notes+"`n`n"+$sessionMarker+"`n")
    foreach($entry in $packageBaseline.GetEnumerator()){
        if($entry.Value -ne 'D'){$inputLeases.Add([IO.File]::Open((Join-Path $release $entry.Key),[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read))}
    }
    $assetRecords=@(foreach($asset in @($zip,$externalVerifier)){
        foreach($suffix in $suffixes){
            $path="$asset$suffix"; Assert-RegularAncestors $path
            $name=[IO.Path]::GetFileName($path).Replace(' ','.')
            if($name -cnotmatch '^[A-Za-z0-9_.-]+$'){throw 'Unexpected normalized publication asset name.'}
            $destination=Join-Path $stage $name
            [IO.File]::Copy($path,$destination,$false)
            $inputLeases.Add([IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read))
            $inputLeases.Add([IO.File]::Open($destination,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read))
            [ordered]@{Name=$name;OriginalName=[IO.Path]::GetFileName($path);Source=$path;Size=(Get-Item -LiteralPath $path).Length;Sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash;Sha512=(Get-FileHash -LiteralPath $path -Algorithm SHA512).Hash}
        }
    })
    if($assetRecords.Count -ne 12 -or @($assetRecords.Name | Select-Object -Unique).Count -ne 12){throw 'Publication requires twelve unique assets.'}
    Write-Json (Join-Path $testRoot 'asset-plan.json') $assetRecords
    Assert-DownloadedAssets $stage
    $verifierAssetName=[IO.Path]::GetFileName($externalVerifier).Replace(' ','.')
    $zipAssetName=[IO.Path]::GetFileName($zip).Replace(' ','.')
    foreach($name in @('Keep Vault Release Verifier.exe','Keep Vault Setup.exe')){
        foreach($suffix in $suffixes){[IO.File]::Copy((Join-Path $release "$name$suffix"),(Join-Path $control "$name$suffix"),$false)}
    }
    $controlBaseline=Get-Tree $control
    $controlExecutables=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
    $controlRoles=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
    $controlAuthenticode=[Collections.Generic.List[object]]::new()
    foreach($entry in $controlBaseline.GetEnumerator()){
        if($entry.Value -ne 'D'){$inputLeases.Add([IO.File]::Open((Join-Path $control $entry.Key),[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read))}
    }
    $verifier=Join-Path $control 'Keep Vault Release Verifier.exe'
    $installer=Join-Path $control 'Keep Vault Setup.exe'
    Register-ControlExecutable $verifier 'verifier'; Register-ControlExecutable $installer 'installer'
    Invoke-ExpectedProcess $verifier @($release) 0 'RESULT: TRUSTED' 'local-package'
    Invoke-ExpectedProcess $installer @('--verify',$release) 0 'RESULT: TRUSTED' 'local-setup-package'
    Invoke-ExpectedProcess $verifier @((Join-Path $stage $verifierAssetName)) 0 'RESULT: TRUSTED' 'normalized-exe'
    Invoke-ExpectedProcess $verifier @((Join-Path $stage $zipAssetName)) 0 'RESULT: TRUSTED' 'normalized-zip'
    $script:Phase='VALIDATE_PRIOR_FAILED_RUN_BINDINGS'
    Assert-PriorLocalBindings
    $script:Phase='REMOTE_BASELINE'
    $remoteCommit=Get-Api "repos/$Repository/commits/$SourceCommit"
    if($remoteCommit.sha -cne $SourceCommit){throw 'Exact final commit is not present on GitHub.'}
    if((Get-TagCommit $tag) -cne $SourceCommit){throw 'Recovery requires the exact tag previously created by the inspected original attempt.'}
    $macBefore=Get-MacSnapshot
    Assert-EqualJson $priorMac $macBefore 'Prior/current existing macOS release/tag/assets'
    Write-Json (Join-Path $testRoot 'mac-before.json') $macBefore
    $latest=Get-Api "repos/$Repository/releases/latest"
    $latestBefore=[ordered]@{Id=$latest.id;Tag=$latest.tag_name}
    Assert-EqualJson $priorLatest $latestBefore 'Prior/current existing latest release'
    Write-Json (Join-Path $testRoot 'latest-before.json') $latestBefore
    Download-MacSet $macBefore (Join-Path $testRoot 'mac-assets-before')
    $script:Phase='RECOVER_EXACT_OWN_EMPTY_DRAFT'
    $created=Find-ExactOwnedDraft
    # This flag describes the same publication operation's validated lineage;
    # this recovery invocation creates neither a tag nor a draft.
    $script:CreatedTag=$true
    $script:CreatedReleaseId=[long]$created.id
    Write-Json (Join-Path $testRoot 'owned-release.json') ([ordered]@{SessionId=$sessionId;RecoveryRunId=$recoveryRunId;ReleaseId=$script:CreatedReleaseId;Tag=$tag;SourceCommit=$SourceCommit;Marker=$sessionMarker;ResumedOwnedDraft=$true;TagCreatedByThisInvocation=$false;TagCreatedByPriorAttempt=$true;PriorFailedRun=$priorFailedRun})
    $rechecked=Assert-OwnedRelease $true
    Assert-ResumeDraftIdentity $rechecked
    $script:Phase='UPLOAD_OWN_DRAFT'
    $uploadArgs=@('release','upload',$tag,'--repo',$repoArg)+@($assetRecords | ForEach-Object {Join-Path $stage $_.Name})
    $null=Invoke-Cli $gh $uploadArgs 'upload-twelve-assets'
    $draft=Assert-OwnedRelease $true
    Assert-RemoteAssets $draft
    Write-Json (Join-Path $testRoot 'draft-release-with-digests.json') $draft
    $script:Phase='AUTHENTICATED_DRAFT_DOWNLOAD'
    $authenticated=Join-Path $testRoot 'authenticated-download'
    [IO.Directory]::CreateDirectory($authenticated) | Out-Null
    $null=Invoke-Cli $gh @('release','download',$tag,'--repo',$repoArg,'--dir',$authenticated,'--pattern','*') 'download-own-draft'
    Verify-DownloadedSet $authenticated 'authenticated'
    $draftBeforePublish=Assert-OwnedRelease $true
    Assert-RemoteAssets $draftBeforePublish
    Write-Json (Join-Path $testRoot 'draft-rechecked-before-publication.json') $draftBeforePublish
    $script:Phase='PUBLISH_OWN_RELEASE'
    $null=Invoke-Cli $gh @('release','edit',$tag,'--repo',$repoArg,'--draft=false','--latest=false') 'publish-own-release'
    $script:PublishCommandCompleted=$true
    $published=Assert-OwnedRelease $false
    $script:RemotePublishedObserved=$true
    Assert-RemoteAssets $published
    Write-Json (Join-Path $testRoot 'published-release-with-digests.json') $published
    $script:Phase='ANONYMOUS_PUBLIC_DOWNLOAD'
    $anonymous=Join-Path $testRoot 'anonymous-download'
    [IO.Directory]::CreateDirectory($anonymous) | Out-Null
    foreach($asset in $published.assets){Download-Anonymous $asset.browser_download_url (Join-Path $anonymous $asset.name) $tag}
    Verify-DownloadedSet $anonymous 'anonymous'
    $extraction=Join-Path $testRoot 'anonymous-extracted'
    [IO.Directory]::CreateDirectory($extraction) | Out-Null
    Expand-Archive -LiteralPath (Join-Path $anonymous $zipAssetName) -DestinationPath $extraction
    $extracted=Join-Path $extraction ([IO.Path]::GetFileName($release))
    if(@([IO.Directory]::EnumerateFileSystemEntries($extraction)).Count -ne 1 -or -not [IO.Directory]::Exists($extracted)){throw 'Public ZIP package directory is unexpected.'}
    Assert-SameTree $extracted $packageBaseline
    foreach($entry in $packageBaseline.GetEnumerator()){
        if($entry.Value -ne 'D'){$inputLeases.Add([IO.File]::Open((Join-Path $extracted $entry.Key),[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read))}
    }
    $downloadedSetup=Join-Path $extracted 'Keep Vault Setup.exe'
    Register-ControlExecutable $downloadedSetup 'installer'
    Invoke-ExpectedProcess (Join-Path $anonymous $verifierAssetName) @($extracted) 0 'RESULT: TRUSTED' 'anonymous-extracted-verifier'
    Invoke-ExpectedProcess $downloadedSetup @('--verify',$extracted) 0 'RESULT: TRUSTED' 'anonymous-extracted-setup'
    $script:Phase='FINAL_PRESERVATION'
    $success=$true
} catch {$primaryFailure=$_.Exception;throw}
finally {
    $errors=[Collections.Generic.List[Exception]]::new()
    $preservation=[ordered]@{Source=$false;OriginalPackage=$false;OriginalAssets=$false;Controls=$false;UserShortcuts=$false;MacTagMetadata=$false;MacAssetBytes=$false;LatestRelease=$false;WindowsRelease=$false;HandlesReleased=$false}
    try {
        try {if((Assert-CommittedSource) -ne $sourceInputCount -or (Get-FileHash -LiteralPath $sourceManifest -Algorithm SHA256).Hash -cne $sourceManifestHash -or (Get-FileHash -LiteralPath $sourceAfterManifest -Algorithm SHA256).Hash -cne $sourceManifestHash){throw 'Source snapshot changed.'};$preservation.Source=$true}catch{$errors.Add($_.Exception)}
        try {if($packageBaseline){Assert-SameTree $release $packageBaseline;$preservation.OriginalPackage=$true}}catch{$errors.Add($_.Exception)}
        try {if($assetBaseline){Assert-SameMapping $assetBaseline (Get-AssetSet) 'Original twelve assets';$preservation.OriginalAssets=$true}}catch{$errors.Add($_.Exception)}
        try {if($controlBaseline){Assert-SameTree $control $controlBaseline;foreach($entry in $controlExecutables.GetEnumerator()){if((Get-FileHash -LiteralPath $entry.Key -Algorithm SHA512).Hash -cne $entry.Value){throw 'A registered control program changed.'}};$preservation.Controls=$true}}catch{$errors.Add($_.Exception)}
        try {Assert-SameMapping $shortcutBaseline (Get-ShortcutState) 'User shortcuts';$preservation.UserShortcuts=$true}catch{$errors.Add($_.Exception)}
        try {
            if($macBefore){$macAfter=Get-MacSnapshot;Write-Json (Join-Path $testRoot 'mac-after.json') $macAfter;Assert-EqualJson $macBefore $macAfter 'Existing macOS release/tag/asset metadata';$preservation.MacTagMetadata=$true;Download-MacSet $macAfter (Join-Path $testRoot 'mac-assets-after');$preservation.MacAssetBytes=$true}
        }catch{$errors.Add($_.Exception)}
        try {if($latestBefore){$latest=Get-Api "repos/$Repository/releases/latest";$latestAfter=[ordered]@{Id=$latest.id;Tag=$latest.tag_name};Write-Json (Join-Path $testRoot 'latest-after.json') $latestAfter;Assert-EqualJson $latestBefore $latestAfter 'Existing latest release';$preservation.LatestRelease=$true}}catch{$errors.Add($_.Exception)}
        try {if($script:RemotePublishedObserved){$finalRelease=Assert-OwnedRelease $false;Assert-RemoteAssets $finalRelease;Write-Json (Join-Path $testRoot 'final-published-release.json') $finalRelease;$preservation.WindowsRelease=$true}}catch{$errors.Add($_.Exception)}
    } finally {
        $released=$true
        for($index=$inputLeases.Count-1;$index -ge 0;$index--){try{$inputLeases[$index].Dispose()}catch{$released=$false;$errors.Add($_.Exception)}}
        $preservation.HandlesReleased=$released
        $preservation.Errors=@($errors | ForEach-Object Message)
        Write-Json (Join-Path $testRoot 'anonymous-downloads.json') @($script:AnonymousDownloads)
        Write-Json (Join-Path $testRoot 'preservation.json') $preservation
        $allPreserved=@($preservation.GetEnumerator() | Where-Object {$_.Key -ne 'Errors' -and $_.Value -ne $true}).Count -eq 0
        $recoveryProof=if($recoveryProvenance){[ordered]@{Path=(Join-Path $testRoot 'recovery-provenance.json');Sha256=(Get-FileHash -LiteralPath (Join-Path $testRoot 'recovery-provenance.json') -Algorithm SHA256).Hash}}else{$null}
        Write-Json (Join-Path $testRoot 'summary.json') ([ordered]@{State=$(if($success -and -not $primaryFailure -and $errors.Count -eq 0 -and $allPreserved){'PASS'}else{'FAIL'});SessionId=$sessionId;RecoveryRunId=$recoveryRunId;SourceRoot=$source;SourceCommit=$SourceCommit;Tag=$tag;ReleaseId=$script:CreatedReleaseId;CreatedTag=$script:CreatedTag;CreatedTagByThisInvocation=$false;TagCreatedByThisInvocation=$false;TagCreatedByPriorAttempt=$script:CreatedTag;ResumedOwnedDraft=($null -ne $script:CreatedReleaseId);PriorFailedRun=$priorFailedRun;RecoveryProvenance=$recoveryProof;PublishCommandCompleted=$script:PublishCommandCompleted;RemotePublishedObserved=$script:RemotePublishedObserved;Phase=$script:Phase;AdministrativeInvocations=$script:CliNumber;ProductInvocations=$script:InvocationNumber;Error=$(if($primaryFailure){$primaryFailure.ToString()}else{$null});HarnessSha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash;CompletedUtc=[DateTime]::UtcNow.ToString('O');Recovery='Only the exact previously created empty draft is resumed. No tag/draft creation, unrelated adoption, overwrite, deletion or rollback is attempted. Original failed evidence is retained byte-exact in its separate directory.'})
    }
    if($errors.Count){if($primaryFailure){$errors.Insert(0,$primaryFailure)};throw [AggregateException]::new('Publication/preservation verification failed.',[Exception[]]$errors.ToArray())}
    if($success -and -not $allPreserved){throw 'Publication did not pass every preservation gate.'}
}
Write-Host "Verified public Windows release: https://github.com/$Repository/releases/tag/$tag"
Write-Host "Retained publication evidence: $testRoot"
