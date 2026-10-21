#requires -Version 7.5
<#
Prepared runner only. Run after the parent has finished the final full suite and
package acceptance, and has made the host idle. No build, signing, network,
installation, user-process termination, or historical baseline creation.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $SourceRoot,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{40}$')][string] $ExpectedCommit,
    [string] $EvidenceParent = $PSScriptRoot,
    [ValidateRange(60,14400)][int] $PerGroupTimeoutSeconds = 7200,
    [ValidateRange(2,60)][int] $HeartbeatSeconds = 10,
    [switch] $ExecutePerformance
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $ExecutePerformance) { throw 'Prepared only. The parent must explicitly select ExecutePerformance after the other final gates finish and the host is idle.' }
if (-not $IsWindows) { throw 'This runner requires Windows.' }
$expectedCommit = $ExpectedCommit.ToLowerInvariant()
$source = [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath($SourceRoot))
$workRoot = 'C:\Dev\Kalyna\work'
$releaseBuildsRoot = Join-Path $workRoot 'release-builds'
$container = [IO.Path]::GetDirectoryName($source)
if ([IO.Path]::GetFileName($source) -cne 'src' -or [IO.Path]::GetDirectoryName($container) -ine $releaseBuildsRoot -or
    -not [IO.Path]::GetFileName($container).StartsWith($expectedCommit.Substring(0,12)+'-',[StringComparison]::Ordinal)) {
    throw 'SourceRoot must be the exact supplied commit snapshot beneath canonical release-builds.'
}
$evidenceParentPath = [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath($EvidenceParent))
if (-not $evidenceParentPath.StartsWith($workRoot+'\',[StringComparison]::OrdinalIgnoreCase) -or
    $evidenceParentPath.StartsWith($workRoot+'\release-builds\',[StringComparison]::OrdinalIgnoreCase) -or
    $evidenceParentPath -ieq ($workRoot+'\release-builds')) { throw 'Evidence must be beneath canonical work and outside all release snapshot containers.' }
if (-not [IO.Directory]::Exists($evidenceParentPath)) { throw 'EvidenceParent must already exist.' }
$runRoot = Join-Path $evidenceParentPath ('performance-'+$expectedCommit.Substring(0,12)+'-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')+'-'+[Guid]::NewGuid().ToString('N'))
$testDirectory = Join-Path $source 'work\native-gate-tests'
$tests = Join-Path $testDirectory 'KalynaArchiver.Tests.dll'
$defaultResults = Join-Path $testDirectory '.test-results.json'
$phaseResult = Join-Path $source 'work\v13-evidence\entropy-rev9-phase-performance.json'
$manifestBefore = Join-Path (Split-Path $source) 'source-inputs-before.sha256'
$manifestAfter = Join-Path (Split-Path $source) 'source-inputs-after.sha256'
$dotnet = (Get-Command dotnet -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$git = (Get-Command git -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$inputLeases = [Collections.Generic.List[IDisposable]]::new()
$groupResults = [Collections.Generic.List[object]]::new()
$originalSource = $null; $originalAssets = $null; $originalTests = $null
$manifestDigest = $null; $primaryFailure = $null; $allGroupsFinished = $false
$sourcePreservationScope = 'Manifest-covered committed source inputs, HEAD and original source-manifest bytes; allowed output-slot membership is not inventoried.'
$baselinePath = [Environment]::GetEnvironmentVariable('KEEPVAULT_PERF_BASELINE')
$historicalComparison = if ([string]::IsNullOrWhiteSpace($baselinePath)) { 'NOT_RUN' } else { 'PENDING' }
$groupPlan = @(
    [ordered]@{Number=1;Id='performance.cipher-suites';Label='cipher-suites'},
    [ordered]@{Number=2;Id='release.paranoia-256mib-level5';Label='paranoia-256mib'},
    [ordered]@{Number=3;Id='performance.entropy-rev9-phases';Label='entropy-rev9-phases'},
    [ordered]@{Number=4;Id='release.paranoia-complex-tree-level5-repair';Label='complex-tree-last'}
)

function Assert-RegularPath([string] $Path) {
    for ($part=[IO.Path]::GetFullPath($Path); $part; $part=[IO.Path]::GetDirectoryName($part)) {
        if (([IO.File]::GetAttributes($part) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Unexpected path alias: $part" }
    }
}
function Assert-OwnOutput([string] $Path) {
    $full=[IO.Path]::GetFullPath($Path)
    if (-not $full.StartsWith($runRoot+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Output escaped the fresh performance evidence directory.' }
    return $full
}
function Write-Json([string] $Path, $Value) {
    $Path=Assert-OwnOutput $Path
    $temporary=$Path+'.writing'
    [IO.File]::WriteAllText($temporary,($Value | ConvertTo-Json -Depth 18),[Text.UTF8Encoding]::new($false))
    [IO.File]::Move($temporary,$Path,$true)
}
function New-FileRecord([string] $Path) {
    Assert-RegularPath $Path
    return [ordered]@{Path=$Path;Length=([IO.FileInfo]$Path).Length;Sha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash;Sha512=(Get-FileHash -LiteralPath $Path -Algorithm SHA512).Hash}
}
function Assert-SameFiles($Before,$After,[string] $Label) {
    if ($Before.Count -ne $After.Count) { throw "$Label membership changed." }
    foreach ($entry in $Before.GetEnumerator()) {
        if (-not $After.ContainsKey($entry.Key) -or ($entry.Value | ConvertTo-Json -Compress) -cne ($After[$entry.Key] | ConvertTo-Json -Compress)) { throw "$Label changed: $($entry.Key)" }
    }
}
function Get-SourceFiles {
    Assert-RegularPath $source
    $head=(& $git --no-optional-locks -C $source rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $head -cne $expectedCommit) { throw 'The immutable source HEAD changed.' }
    if ((Get-FileHash -LiteralPath $manifestBefore -Algorithm SHA256).Hash -cne (Get-FileHash -LiteralPath $manifestAfter -Algorithm SHA256).Hash) { throw 'Immutable build source inventories differ or are unavailable.' }
    $files=[Collections.Generic.SortedDictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($line in [IO.File]::ReadAllLines($manifestBefore)) {
        if ($line -cnotmatch '^([0-9A-F]{64})  (.+)$') { throw 'Invalid source inventory line.' }
        $expected=$Matches[1]; $relative=$Matches[2]
        $path=[IO.Path]::GetFullPath((Join-Path $source $relative))
        if (-not $path.StartsWith($source+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Source inventory escaped the snapshot.' }
        $record=New-FileRecord $path
        if ($record.Sha256 -cne $expected) { throw "Source differs from the immutable build: $relative" }
        $files.Add($relative,$record)
    }
    if ($files.Count -lt 1) { throw 'The source inventory is empty.' }
    return ,$files
}
function Get-AssetFiles {
    $files=[Collections.Generic.SortedDictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($base in @('Keep Vault-portable-win-x64.zip','Keep Vault Release Verifier-win-x64.exe')) {
        foreach ($suffix in @('','.khsig','.sha3','.sha3.khsig','.skein','.skein.khsig')) {
            $name=$base+$suffix
            $files.Add($name,(New-FileRecord (Join-Path $source ('dist\'+$name))))
        }
    }
    if ($files.Count -ne 12) { throw 'Exactly twelve final release assets are required.' }
    return ,$files
}
function Get-TestFiles {
    Assert-RegularPath $testDirectory
    $files=[Collections.Generic.SortedDictionary[string,object]]::new([StringComparer]::Ordinal)
    $pending=[Collections.Generic.Stack[string]]::new(); $pending.Push($testDirectory)
    while ($pending.Count) {
        foreach ($path in [IO.Directory]::EnumerateFileSystemEntries($pending.Pop())) {
            $attributes=[IO.File]::GetAttributes($path)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Unexpected compiled-test input alias.' }
            if (($attributes -band [IO.FileAttributes]::Directory) -ne 0) { $pending.Push($path); continue }
            $relative=[IO.Path]::GetRelativePath($testDirectory,$path)
            if ($relative -in @('.test-results.json','.test-timings.json')) { continue }
            $files.Add($relative,(New-FileRecord $path))
        }
    }
    if (-not $files.ContainsKey('KalynaArchiver.Tests.dll')) { throw 'The final compiled test DLL is missing.' }
    return ,$files
}
function Get-ProcessSnapshot {
    return @(Get-CimInstance Win32_Process -OperationTimeoutSec 5 -ErrorAction Stop | Select-Object ProcessId,ParentProcessId,Name,CreationDate,KernelModeTime,UserModeTime,WorkingSetSize)
}
function Test-CimProcessIdentity([Diagnostics.Process] $Candidate,$CimItem) {
    if ($Candidate.Id -ne [int]$CimItem.ProcessId) { return $false }
    # CIM's DMTF CreationDate has microsecond precision; Process.StartTime
    # retains 100-ns ticks. Compare exactly after truncating those sub-us ticks,
    # rather than accepting an unrelated later process with a reused PID.
    $actual=$Candidate.StartTime.ToUniversalTime().Ticks
    $observed=([DateTime]$CimItem.CreationDate).ToUniversalTime().Ticks
    return ($actual-($actual % 10)) -eq ($observed-($observed % 10))
}
function Get-OwnTree($Process,[Collections.Generic.Dictionary[int,Diagnostics.Process]] $Owned) {
    $all=Get-ProcessSnapshot
    $tree=[Collections.Generic.List[object]]::new()
    $queue=[Collections.Generic.Queue[Diagnostics.Process]]::new()
    $seen=[Collections.Generic.HashSet[int]]::new()
    $queue.Enqueue($Process)
    foreach ($known in $Owned.Values) { $queue.Enqueue($known) }
    while ($queue.Count) {
        $parent=$queue.Dequeue()
        if (-not $seen.Add($parent.Id)) { continue }
        $parentStart=$parent.StartTime.ToUniversalTime()
        $parentEnd=if ($parent.HasExited) { $parent.ExitTime.ToUniversalTime() } else { [DateTime]::UtcNow }
        # Root/known entries are emitted only when CIM still names that exact
        # held identity. Exited held parents may still identify legitimate
        # orphan children, bounded by the original parent's lifetime.
        foreach ($item in $all) {
            if ([int]$item.ProcessId -eq $parent.Id -and (Test-CimProcessIdentity $parent $item)) { $tree.Add($item) }
            if ([int]$item.ParentProcessId -ne $parent.Id) { continue }
            $birth=([DateTime]$item.CreationDate).ToUniversalTime()
            if ($birth -lt $parentStart.AddTicks(-9) -or $birth -gt $parentEnd) { continue }
            if ($Owned.ContainsKey([int]$item.ProcessId)) { continue }
            $child=$null
            try {
                $child=[Diagnostics.Process]::GetProcessById([int]$item.ProcessId)
                $null=$child.Handle
                if (-not (Test-CimProcessIdentity $child $item)) { $child.Dispose(); continue }
                $Owned.Add([int]$item.ProcessId,$child); $queue.Enqueue($child); $child=$null
            } catch { if ($child) { $child.Dispose() } }
        }
    }
    return ,$tree.ToArray()
}
function Stop-OwnProcesses($Process,[bool] $Started,[Collections.Generic.Dictionary[int,Diagnostics.Process]] $Owned) {
    $errors=[Collections.Generic.List[string]]::new()
    $targets=[Collections.Generic.List[Diagnostics.Process]]::new()
    if ($Started) { $targets.Add($Process) }
    foreach ($child in $Owned.Values) { $targets.Add($child) }
    foreach ($target in $targets) {
        try { if (-not $target.HasExited) { $target.Kill($true) } }
        catch { if (-not $target.HasExited) { $errors.Add($_.Exception.Message) } }
    }
    $deadline=[DateTime]::UtcNow.AddSeconds(15)
    foreach ($target in $targets) {
        try {
            $remaining=[Math]::Max(1,[int]($deadline-[DateTime]::UtcNow).TotalMilliseconds)
            if (-not $target.WaitForExit($remaining)) { $errors.Add("Owned process $($target.Id) did not terminate.") }
        } catch { $errors.Add($_.Exception.Message) }
    }
    if ($errors.Count) { throw ('Owned-process cleanup failed: '+($errors -join '; ')) }
}
function Invoke-PerformanceGroup($Plan) {
    $label=('{0:D2}-{1}' -f $Plan.Number,$Plan.Label)
    $directory=Join-Path $runRoot $label
    [IO.Directory]::CreateDirectory($directory) | Out-Null
    if ([IO.File]::Exists($defaultResults)) { throw 'A prior results file still exists before a fresh group.' }
    $record=[ordered]@{Number=$Plan.Number;Id=$Plan.Id;State='FAIL';ExitCode=$null;StartedUtc=[DateTime]::UtcNow.ToString('O');CompletedUtc=$null;Seconds=0;TimedOut=$false;ResultFresh=$false;ResultsPath=$null;ResultsSha256=$null;Stdout=(Join-Path $directory 'stdout.log');Stderr=(Join-Path $directory 'stderr.log');Error=$null;CleanupPassed=$false}
    $start=[Diagnostics.ProcessStartInfo]::new()
    $start.FileName=$dotnet; $start.WorkingDirectory=$source
    $start.UseShellExecute=$false; $start.CreateNoWindow=$true
    $start.RedirectStandardOutput=$true; $start.RedirectStandardError=$true
    foreach ($argument in @($tests,'--performance','--only',$Plan.Id,'--parallel','1','--timings',(Join-Path $directory 'timings.json'))) { $start.ArgumentList.Add($argument) }
    $start.Environment['KEEPVAULT_TEST_REPOSITORY_ROOT']=$source
    if ([string]::IsNullOrWhiteSpace($baselinePath)) { $null=$start.Environment.Remove('KEEPVAULT_PERF_BASELINE') }
    else { $start.Environment['KEEPVAULT_PERF_BASELINE']=$baselinePath }
    $process=[Diagnostics.Process]::new(); $process.StartInfo=$start
    $owned=[Collections.Generic.Dictionary[int,Diagnostics.Process]]::new()
    $started=$false; $watch=[Diagnostics.Stopwatch]::StartNew(); $nextHeartbeat=0.0; $drainDeadline=$null
    $streams=@(); $cleanupFailure=$null
    Write-Json (Join-Path $directory 'invocation.json') ([ordered]@{Executable=$dotnet;Arguments=@($start.ArgumentList);WorkingDirectory=$source;RepositoryEnvironment=$source;BaselinePath=$baselinePath;TimeoutSeconds=$PerGroupTimeoutSeconds;StartedUtc=$record.StartedUtc})
    Write-Host "START $label ($($Plan.Id))"
    try {
        $started=$process.Start(); if (-not $started) { throw 'Performance process did not start.' }
        $null=$process.Handle
        foreach ($spec in @(@($process.StandardOutput,$record.Stdout,'stdout'),@($process.StandardError,$record.Stderr,'stderr'))) {
            $writer=[IO.StreamWriter]::new([string]$spec[1],$false,[Text.UTF8Encoding]::new($false)); $writer.AutoFlush=$true
            $streams+=@{Reader=$spec[0];Writer=$writer;Task=$spec[0].ReadLineAsync();Done=$false;Lines=0;Name=$spec[2];LastLine=$null}
        }
        while ($true) {
            foreach ($stream in $streams) {
                for ($batch=0; $batch -lt 256 -and -not $stream.Done -and $stream.Task.IsCompleted; $batch++) {
                    $line=$stream.Task.GetAwaiter().GetResult()
                    if ($null -eq $line) { $stream.Done=$true; break }
                    $stream.Writer.WriteLine($line); $stream.Lines++
                    $stream.LastLine=if ($line.Length -gt 400) { $line.Substring(0,400)+' [full line in log]' } else { $line }
                    Write-Host "[$label/$($stream.Name)] $($stream.LastLine)"
                    $stream.Task=$stream.Reader.ReadLineAsync()
                }
            }
            if ($watch.Elapsed.TotalSeconds -ge $nextHeartbeat) {
                $tree=@(); $captureError=$null
                try { $tree=Get-OwnTree $process $owned } catch { $captureError=$_.Exception.Message }
                $live=[ordered]@{State='RUNNING';Id=$Plan.Id;ProcessId=$process.Id;Seconds=$watch.Elapsed.TotalSeconds;ObservedUtc=[DateTime]::UtcNow.ToString('O');HasExited=$process.HasExited;Streams=@($streams | ForEach-Object { [ordered]@{Name=$_.Name;Lines=$_.Lines;LastLine=$_.LastLine;Ended=$_.Done} });OwnedProcessTree=$tree;TreeCaptureError=$captureError}
                Write-Json (Join-Path $directory 'progress.json') $live
                Write-Json (Join-Path $runRoot 'progress.json') $live
                Write-Host ("HEARTBEAT {0}: {1:F1}s, own tree {2} process(es)" -f $label,$watch.Elapsed.TotalSeconds,@($tree).Count)
                $nextHeartbeat=$watch.Elapsed.TotalSeconds+$HeartbeatSeconds
            }
            if ($watch.Elapsed.TotalSeconds -ge $PerGroupTimeoutSeconds) {
                $record.TimedOut=$true
                $tree=@(); $captureError=$null
                try { $tree=Get-OwnTree $process $owned } catch { $captureError=$_.Exception.Message }
                Write-Json (Join-Path $directory 'timeout-tree-before-kill.json') ([ordered]@{ProcessTree=$tree;CaptureError=$captureError;ObservedUtc=[DateTime]::UtcNow.ToString('O')})
                Stop-OwnProcesses $process $started $owned
                throw "The performance group exceeded $PerGroupTimeoutSeconds seconds."
            }
            if ($process.HasExited) {
                if (@($streams | Where-Object {-not $_.Done}).Count -eq 0) { break }
                if ($null -eq $drainDeadline) { $drainDeadline=$watch.Elapsed.TotalSeconds+30 }
                if ($watch.Elapsed.TotalSeconds -ge $drainDeadline) { throw 'Output pipes did not close within 30 seconds of process exit.' }
                [Threading.Thread]::Sleep(50)
            } else { $null=$process.WaitForExit(200) }
        }
        if (-not $process.WaitForExit(10000)) { throw 'The observed performance process did not join within the bounded final wait.' }
        $record.ExitCode=$process.ExitCode
        if (-not [IO.File]::Exists($defaultResults)) { throw 'No fresh coordinator results file was produced.' }
        Assert-RegularPath $defaultResults
        $resultPath=Join-Path $directory 'results.json'
        [IO.File]::Move($defaultResults,$resultPath,$false)
        $record.ResultFresh=$true; $record.ResultsPath=$resultPath
        $record.ResultsSha256=(Get-FileHash -LiteralPath $resultPath -Algorithm SHA256).Hash
        $result=[IO.File]::ReadAllText($resultPath) | ConvertFrom-Json -AsHashtable
        if ($record.ExitCode -ne 0 -or $result.schemaVersion -ne 2 -or $result.head -cne $expectedCommit -or
            $result.platform -cne 'windows' -or $result.architecture -cne 'x64' -or $result.budget.maxWorkers -ne 1 -or
            @($result.tests).Count -ne 1 -or $result.tests[0].id -cne $Plan.Id -or $result.tests[0].status -cne 'PASS' -or
            $null -ne $result.tests[0].failure -or -not [double]::IsFinite([double]$result.tests[0].seconds) -or $result.tests[0].seconds -le 0) { throw 'Actual process exit or exact fresh single-group results did not PASS.' }
        if ($Plan.Id -ceq 'performance.entropy-rev9-phases') {
            Assert-RegularPath $phaseResult
            [IO.File]::Copy($phaseResult,(Join-Path $directory 'entropy-rev9-phase-performance.json'),$false)
        }
        $record.State='PASS'
    } catch { $record.Error=$_.Exception.ToString() }
    finally {
        # Diagnostics must never prevent termination of processes this runner
        # started or pinned as descendants of that exact process identity.
        if ($started) {
            try {
                if (-not $process.HasExited -or @($owned.Values | Where-Object {-not $_.HasExited}).Count) {
                    $tree=@(); $captureError=$null
                    try { $tree=Get-OwnTree $process $owned } catch { $captureError=$_.Exception.Message }
                    Write-Json (Join-Path $directory 'cleanup-tree-before-kill.json') ([ordered]@{ProcessTree=$tree;CaptureError=$captureError;ObservedUtc=[DateTime]::UtcNow.ToString('O')})
                }
            } catch { $record.State='FAIL'; $record.Error=($record.Error+"`n"+$_.Exception.ToString()) }
        }
        try { Stop-OwnProcesses $process $started $owned; $record.CleanupPassed=$true }
        catch { $cleanupFailure=$_.Exception; $record.State='FAIL'; $record.Error=($record.Error+"`n"+$cleanupFailure.ToString()) }
        if ($started -and $process.HasExited) { $record.ExitCode=$process.ExitCode }
        foreach ($stream in $streams) {
            try { $stream.Reader.Dispose(); $stream.Writer.Dispose() }
            catch { $record.State='FAIL'; $record.Error=($record.Error+"`n"+$_.Exception.ToString()) }
        }
        foreach ($child in $owned.Values) { $child.Dispose() }
        $process.Dispose(); $watch.Stop()
        # Preserve a newly produced failure/crash result too. Never carry it into
        # the next invocation, and never treat a previous group's result as fresh.
        if ([IO.File]::Exists($defaultResults)) {
            $failureResult=Join-Path $directory 'failure-results.json'
            Assert-RegularPath $defaultResults
            [IO.File]::Move($defaultResults,$failureResult,$false)
            $record.ResultFresh=$true; $record.ResultsPath=$failureResult
            $record.ResultsSha256=(Get-FileHash -LiteralPath $failureResult -Algorithm SHA256).Hash
        }
        $record.CompletedUtc=[DateTime]::UtcNow.ToString('O'); $record.Seconds=$watch.Elapsed.TotalSeconds
        Write-Json (Join-Path $directory 'receipt.json') $record
        Write-Json (Join-Path $directory 'progress.json') $record
        Write-Json (Join-Path $runRoot 'progress.json') $record
        $groupResults.Add($record)
        Write-Host "END ${label}: $($record.State), exit=$($record.ExitCode), $($record.Seconds)s"
    }
    if ($cleanupFailure) { throw $cleanupFailure }
}

Assert-RegularPath $source
Assert-RegularPath $evidenceParentPath
if ([IO.Path]::Exists($runRoot)) { throw 'Fresh performance evidence directory already exists.' }
[IO.Directory]::CreateDirectory($runRoot) | Out-Null
try {
    $sdk=(& $dotnet --version).Trim()
    if ($LASTEXITCODE -ne 0 -or $sdk -cne '10.0.402') { throw 'The final performance runner requires installed SDK 10.0.402.' }
    $originalSource=Get-SourceFiles
    $manifestDigest=(Get-FileHash -LiteralPath $manifestBefore -Algorithm SHA256).Hash
    $originalAssets=Get-AssetFiles
    $originalTests=Get-TestFiles
    Write-Json (Join-Path $runRoot 'source-before.json') $originalSource
    Write-Json (Join-Path $runRoot 'assets-before.json') $originalAssets
    Write-Json (Join-Path $runRoot 'tests-before.json') $originalTests
    foreach ($inventory in @($originalSource,$originalAssets,$originalTests)) {
        foreach ($record in $inventory.Values) { $inputLeases.Add([IO.File]::Open($record.Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)) }
    }
    if (-not [string]::IsNullOrWhiteSpace($baselinePath)) {
        $baselinePath=[IO.Path]::GetFullPath($baselinePath); $baselineRecord=New-FileRecord $baselinePath
        $inputLeases.Add([IO.File]::Open($baselinePath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read))
        [IO.File]::Copy($baselinePath,(Join-Path $runRoot 'supplied-historical-baseline.json'),$false)
    } else { $baselineRecord=$null }
    Write-Json (Join-Path $runRoot 'provenance.json') ([ordered]@{RunPurpose='Final';SourceRoot=$source;SourceCommit=$expectedCommit;SourceManifestSha256=$manifestDigest;SourcePreservationScope=$sourcePreservationScope;Sdk=$sdk;Dotnet=$dotnet;Tests=$tests;TestDllSha256=$originalTests['KalynaArchiver.Tests.dll'].Sha256;HarnessSha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash;GroupPlan=$groupPlan;HistoricalComparison=$historicalComparison;HistoricalBaseline=$baselineRecord;IndependentWindowsNativeHistoricalBenchmark='NOT_RUN: native_benchmark hardcodes macOS dylibs; no Windows baseline was invented';ParentPrerequisite='Parent must finish final full suite and acceptance, then make host idle before selecting ExecutePerformance.'})
    $processesBefore=Get-ProcessSnapshot
    Write-Json (Join-Path $runRoot 'host-processes-before.json') $processesBefore
    $cpuBefore=@(Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'" -OperationTimeoutSec 5 -ErrorAction Stop | Select-Object Name,PercentProcessorTime)
    [Threading.Thread]::Sleep(3000)
    $cpuAfter=@(Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'" -OperationTimeoutSec 5 -ErrorAction Stop | Select-Object Name,PercentProcessorTime)
    Write-Json (Join-Path $runRoot 'host-idle-observation-before.json') ([ordered]@{ObservedUtc=[DateTime]::UtcNow.ToString('O');CpuBefore=$cpuBefore;CpuAfter=$cpuAfter;ObservationOnly=$true;UserProcessesTerminated=$false;LogicalProcessors=[Environment]::ProcessorCount;FreeDiskBytes=([IO.DriveInfo]::new('C:\')).AvailableFreeSpace})
    if ([IO.File]::Exists($defaultResults)) {
        Assert-RegularPath $defaultResults
        [IO.File]::Move($defaultResults,(Join-Path $runRoot 'previous-results-preserved-before-run.json'),$false)
    }
    if ([IO.File]::Exists($phaseResult)) {
        Assert-RegularPath $phaseResult
        [IO.File]::Move($phaseResult,(Join-Path $runRoot 'previous-entropy-phase-result-preserved.json'),$false)
    }
    foreach ($plan in $groupPlan) { Invoke-PerformanceGroup $plan }
    $allGroupsFinished=$true
    if (-not [string]::IsNullOrWhiteSpace($baselinePath)) {
        $historicalComparison=if ($groupResults[0].State -ceq 'PASS') { 'PASS' } else { 'NOT_PROVEN' }
    }
} catch { $primaryFailure=$_.Exception }
finally {
    $errors=[Collections.Generic.List[string]]::new()
    $preservation=[ordered]@{Source=$false;TwelveAssets=$false;CompiledTestInputs=$false;Manifest=$false;HandlesReleased=$false;Errors=@()}
    try {
        if ($originalSource) { $after=Get-SourceFiles; Write-Json (Join-Path $runRoot 'source-after.json') $after; Assert-SameFiles $originalSource $after 'Actual source input'; $preservation.Source=$true }
        if ($manifestDigest -and (Get-FileHash -LiteralPath $manifestBefore -Algorithm SHA256).Hash -ceq $manifestDigest -and (Get-FileHash -LiteralPath $manifestAfter -Algorithm SHA256).Hash -ceq $manifestDigest) { $preservation.Manifest=$true }
    } catch { $errors.Add($_.Exception.ToString()) }
    try { if ($originalAssets) { $after=Get-AssetFiles; Write-Json (Join-Path $runRoot 'assets-after.json') $after; Assert-SameFiles $originalAssets $after 'Twelve release assets'; $preservation.TwelveAssets=$true } } catch { $errors.Add($_.Exception.ToString()) }
    try { if ($originalTests) { $after=Get-TestFiles; Write-Json (Join-Path $runRoot 'tests-after.json') $after; Assert-SameFiles $originalTests $after 'Compiled test input'; $preservation.CompiledTestInputs=$true } } catch { $errors.Add($_.Exception.ToString()) }
    $released=$true
    for ($index=$inputLeases.Count-1; $index -ge 0; $index--) { try { $inputLeases[$index].Dispose() } catch { $released=$false; $errors.Add($_.Exception.ToString()) } }
    $preservation.HandlesReleased=$released; $preservation.Errors=$errors.ToArray()
    Write-Json (Join-Path $runRoot 'preservation.json') $preservation
    $pass=$allGroupsFinished -and $groupResults.Count -eq 4 -and @($groupResults | Where-Object { $_.State -cne 'PASS' -or $_.ExitCode -ne 0 -or -not $_.ResultFresh -or -not $_.CleanupPassed }).Count -eq 0 -and -not $primaryFailure -and $errors.Count -eq 0 -and $preservation.Source -and $preservation.TwelveAssets -and $preservation.CompiledTestInputs -and $preservation.Manifest -and $preservation.HandlesReleased
    $summaryPath=Join-Path $runRoot 'summary.json'
    if ($historicalComparison -ceq 'PENDING') { $historicalComparison='NOT_PROVEN' }
    $evidence=@([IO.Directory]::EnumerateFiles($runRoot,'*',[IO.SearchOption]::AllDirectories) | Sort-Object | ForEach-Object {
        [ordered]@{Path=$_;Sha256=(Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash}
    })
    Write-Json $summaryPath ([ordered]@{State=$(if ($pass) {'PASS'} else {'FAIL'});Name='Performance';RunPurpose='Final';SourceRoot=$source;SourceCommit=$expectedCommit;SourceManifestSha256=$manifestDigest;SourcePreservationScope=$sourcePreservationScope;Groups=$groupResults.ToArray();HistoricalComparison=$historicalComparison;IndependentWindowsNativeHistoricalBenchmark='NOT_RUN';HistoricalComparisonScope='An unset KEEPVAULT_PERF_BASELINE means no historical regression comparison. Current scalar/parallel and Auto scaling invariants still run. No current result is relabeled as an independent baseline.';Error=$(if ($primaryFailure) {$primaryFailure.ToString()} else {$null});Preservation=$preservation;Evidence=$evidence;CompletedUtc=[DateTime]::UtcNow.ToString('O')})
    Write-Json (Join-Path $runRoot 'publication-performance-gate.json') ([ordered]@{Name='Performance';State=$(if ($pass) {'PASS'} else {'FAIL'});Evidence=@([ordered]@{Path=$summaryPath;Sha256=(Get-FileHash -LiteralPath $summaryPath -Algorithm SHA256).Hash},[ordered]@{Path=(Join-Path $runRoot 'preservation.json');Sha256=(Get-FileHash -LiteralPath (Join-Path $runRoot 'preservation.json') -Algorithm SHA256).Hash})})
    Write-Host "Performance receipt: $summaryPath"
    Write-Host "Parent publication gate entry: $(Join-Path $runRoot 'publication-performance-gate.json')"
}
if (-not $pass) { throw "Final performance did not pass all four groups and preservation checks. Inspect $runRoot" }
Write-Host "PASS: four real, sequential final performance groups; evidence $runRoot"
