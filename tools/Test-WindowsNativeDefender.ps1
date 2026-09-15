# Builds and scans unsigned native outputs only on a disposable GitHub-hosted VM.
# No product EXE/DLL is executed, signed, restored, or uploaded. Build-Native's
# managed fingerprint command reads public ML-DSA source files only.
# This evidence does not clear another antivirus engine's quarantine or replace
# the signed Windows release tests. Protection setup happens before checkout.
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

function Assert-HostedRunner {
    if (-not $IsWindows -or $env:GITHUB_ACTIONS -cne 'true' -or
        $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
        $env:RUNNER_OS -cne 'Windows') {
        throw 'This build/scan script is restricted to a GitHub-hosted Windows runner.'
    }
}

function Assert-DefenderHealth {
    param([Parameter(Mandatory)] $Status, [Parameter(Mandatory)] $Preference)
    foreach ($name in @('AMServiceEnabled', 'AntivirusEnabled', 'RealTimeProtectionEnabled',
        'BehaviorMonitorEnabled', 'IoavProtectionEnabled', 'OnAccessProtectionEnabled')) {
        if ($Status.$name -ne $true) { throw "Defender is not healthy: $name." }
    }
    if ($Status.AMRunningMode -cne 'Normal') { throw 'Defender must run in Normal mode.' }
    foreach ($name in @('DisableRealtimeMonitoring', 'DisableBehaviorMonitoring',
        'DisableIOAVProtection', 'DisableScriptScanning', 'DisableArchiveScanning')) {
        if ($Preference.$name -ne $false) { throw "Defender protection is disabled: $name." }
    }
    if ($Preference.DisableAutoExclusions -ne $true) {
        throw 'Automatic server-role exclusions must be disabled.'
    }
    foreach ($name in @('ExclusionPath', 'ExclusionProcess', 'ExclusionExtension')) {
        if (@($Preference.$name | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count) {
            throw "Defender exclusions remain: $name."
        }
    }
    if ([int]$Preference.SubmitSamplesConsent -ne 2) {
        throw 'Automatic sample submission must already be NeverSend; no binary upload is allowed.'
    }
    $age = [DateTime]::UtcNow - ([DateTime]$Status.AntivirusSignatureLastUpdated).ToUniversalTime()
    if ([string]::IsNullOrWhiteSpace($Status.AntivirusSignatureVersion) -or
        $age.TotalHours -gt 24 -or $age.TotalMinutes -lt -5) {
        throw 'Defender definitions must be dated within the last 24 hours.'
    }
}

function Convert-DefenderEvent {
    param([Parameter(Mandatory)] $Event)
    $xml = [xml]$Event.ToXml()
    $data = [ordered]@{}
    foreach ($item in $xml.SelectNodes("/*[local-name()='Event']/*[local-name()='EventData']/*[local-name()='Data']")) {
        $data[$item.GetAttribute('Name')] = $item.InnerText
    }
    [pscustomobject]@{
        recordId = $Event.RecordId
        id = $Event.Id
        utc = $Event.TimeCreated.ToUniversalTime().ToString('o')
        data = $data
        xml = $xml.OuterXml
    }
}

function Get-EventScanId {
    param([Parameter(Mandatory)] $Event)
    foreach ($key in $Event.data.Keys) {
        if (($key -replace '[^a-zA-Z]', '') -eq 'ScanID') { return [string]$Event.data[$key] }
    }
    return ''
}

function Test-EventScanPath {
    param([Parameter(Mandatory)] $Event, [Parameter(Mandatory)][string] $ScanPath)
    foreach ($key in $Event.data.Keys) {
        if (($key -replace '[^a-zA-Z]', '') -eq 'ScanResources') {
            $resource = [string]$Event.data[$key]
            # Defender 4.18 records a directory as "folder:_<absolute path>".
            # Decode only that observed type marker, never a path list or URI.
            if ($resource.StartsWith('folder:_', [StringComparison]::Ordinal)) {
                $resource = $resource.Substring('folder:_'.Length)
            }
            return $resource.TrimEnd('\') -ieq $ScanPath.TrimEnd('\')
        }
    }
    return $false
}

function Assert-ScanCompleted {
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Events,
        [Parameter(Mandatory)][string] $ScanPath)
    $starts = @($Events | Where-Object {
        $_.id -eq 1000 -and (Test-EventScanPath $_ $ScanPath)
    })
    foreach ($start in $starts) {
        $scanId = Get-EventScanId $start
        if (-not [string]::IsNullOrWhiteSpace($scanId) -and @($Events | Where-Object {
            $_.id -eq 1001 -and $_.recordId -gt $start.recordId -and
            (Get-EventScanId $_) -eq $scanId
        }).Count -gt 0) { return }
    }
    throw 'No matching Defender custom-scan start/completion events were recorded.'
}

function Get-NativeOutputInventory {
    param([Parameter(Mandatory)][string] $Directory)
    $expected = @('aes_ref.dll', 'argon2.exe', 'argon2_ref.dll', 'chachapoly_ref.dll',
        'kalyna_v12.dll', 'mars_ref.dll', 'mldsa87_ref.dll', 'shacal2_ref.dll',
        'threefish_ref.dll', 'zpaq.exe')
    $files = @(Get-ChildItem -LiteralPath $Directory -File -Force |
        Where-Object { $_.Extension -in @('.exe', '.dll') } | Sort-Object Name)
    if (($files.Name -join '|') -cne (($expected | Sort-Object) -join '|')) {
        throw 'The fresh native output set is incomplete or contains an unexpected PE file.'
    }
    foreach ($file in $files) {
        if ($file.Length -eq 0 -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Invalid native output: $($file.Name)."
        }
        [pscustomobject]@{
            name = $file.Name
            bytes = $file.Length
            sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
            sha512 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA512).Hash
        }
    }
}

Assert-HostedRunner
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if ($root -ine [IO.Path]::GetFullPath($env:GITHUB_WORKSPACE)) {
    throw 'The script must run from the event checkout.'
}
. (Join-Path $PSScriptRoot 'LocalWorkspacePolicy.ps1')
Assert-LocalReleaseWorkspace $root
$evidence = Join-Path $env:RUNNER_TEMP 'keepvault-native-defender-evidence'
$preflight = Get-Content -LiteralPath (Join-Path $evidence 'preflight.json') -Raw | ConvertFrom-Json
if ($preflight.result -cne 'PASS' -or $preflight.commit -cne $env:GITHUB_SHA) {
    throw 'A successful pre-checkout protection preflight for this commit is required.'
}
$startUtc = [DateTime]::Parse($preflight.startedUtc).ToUniversalTime()
$output = Join-Path $root 'work\native-scan'
$report = [ordered]@{
    schema = 1
    result = 'FAIL'
    scope = 'Fresh unsigned native source build and Microsoft Defender scan; no product execution or release approval.'
    commit = $env:GITHUB_SHA
    runId = $env:GITHUB_RUN_ID
    runAttempt = $env:GITHUB_RUN_ATTEMPT
    runnerImage = $env:ImageVersion
    startedUtc = [DateTime]::UtcNow.ToString('o')
    outputDirectory = $output
    states = [Collections.Generic.List[object]]::new()
    buildExitCode = $null
    error = $null
}

function Save-Json {
    param([string] $Name, $Value)
    ConvertTo-Json -InputObject $Value -Depth 20 |
        Set-Content -LiteralPath (Join-Path $evidence $Name) -Encoding utf8
}

function Test-ProtectionCheckpoint {
    param([string] $Name)
    $status = Get-MpComputerStatus
    $preference = Get-MpPreference
    $report.states.Add([pscustomobject]@{
        name = $Name; utc = [DateTime]::UtcNow.ToString('o')
        status = ($status | Select-Object * -ExcludeProperty CimClass, CimInstanceProperties, CimSystemProperties)
        preference = ($preference | Select-Object * -ExcludeProperty CimClass, CimInstanceProperties, CimSystemProperties)
    })
    Assert-DefenderHealth $status $preference
    $history = @(Get-MpThreatDetection)
    $active = @(Get-MpThreat | Where-Object IsActive)
    Save-Json 'detections.json' @{ history = $history; active = $active }
    $newDetections = @($history | Where-Object {
        ([DateTime]$_.InitialDetectionTime).ToUniversalTime() -ge $startUtc -or
        ([DateTime]$_.LastThreatStatusChangeTime).ToUniversalTime() -ge $startUtc -or
        @($_.Resources | Where-Object { ([string]$_).IndexOf($root, [StringComparison]::OrdinalIgnoreCase) -ge 0 }).Count -gt 0
    })
    if ($active.Count -or $newDetections.Count) {
        throw 'Defender reported an active threat or a detection during this job, including remediated detections.'
    }
}

Push-Location $root
try {
    $commit = (& git rev-parse --verify HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $commit -cne $env:GITHUB_SHA) { throw 'Checkout commit mismatch.' }
    $trackedChanges = @(& git status --porcelain --untracked-files=no)
    if ($LASTEXITCODE -ne 0 -or $trackedChanges.Count) { throw 'Tracked source changes before build.' }
    foreach ($relative in @('work\native-scan', 'work\native-objects', 'work\cryptopp-objects')) {
        if (Test-Path -LiteralPath (Join-Path $root $relative)) {
            throw "A fresh checkout without previous outputs is required: $relative."
        }
    }
    Test-ProtectionCheckpoint 'before-build'
    $sdkVersion = (& dotnet --version).Trim()
    if ($LASTEXITCODE -ne 0 -or $sdkVersion -cne '10.0.401') { throw 'Unexpected .NET SDK.' }
    $report.sdkVersion = $sdkVersion
    $report.sourceManifests = @('external\NATIVE_SOURCE_SHA256SUMS',
        'native\WINDOWS_SOURCE_SHA256SUMS', 'external\ML-DSA-reference\SOURCE_SHA256SUMS',
        'external\ML-DSA-reference\SHA256SUMS') |
        ForEach-Object { [pscustomobject]@{
            path = $_; sha256 = (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash
        } }
    & pwsh -NoProfile -File tools\Verify-NativeSources.ps1 2>&1 |
        Tee-Object -FilePath (Join-Path $evidence 'source-pins.log')
    if ($LASTEXITCODE -ne 0) { throw 'Pinned native source verification failed.' }
    & $env:ComSpec /d /c 'tools\Build-Native.cmd work\native-scan' 2>&1 |
        Tee-Object -FilePath (Join-Path $evidence 'build.log')
    $report.buildExitCode = $LASTEXITCODE
    Test-ProtectionCheckpoint 'after-build'
    if ($report.buildExitCode -ne 0) { throw "Native build failed: $($report.buildExitCode)." }
    $before = @(Get-NativeOutputInventory $output)
    Save-Json 'native-hashes-before.json' $before
    Test-ProtectionCheckpoint 'before-scan'
    $logName = 'Microsoft-Windows-Windows Defender/Operational'
    $log = Get-WinEvent -ListLog $logName
    if (-not $log.IsEnabled) { throw 'Defender operational event logging is unavailable.' }
    $lastRecord = (Get-WinEvent -LogName $logName -MaxEvents 1).RecordId
    $report.scanStartedUtc = [DateTime]::UtcNow.ToString('o')
    # Request an ordinary custom scan. Only matching events prove completion;
    # successful return from the cmdlet alone is not accepted as scan evidence.
    $events = @()
    Save-Json 'scan-events.json' $events
    Start-MpScan -ScanType CustomScan -ScanPath $output
    $report.scanCallReturnedUtc = [DateTime]::UtcNow.ToString('o')
    # Keep the same ten-second event observation limit, including on failure.
    $report.scanCompletionObserved = $false
    for ($attempt = 0; $attempt -le 10; $attempt++) {
        try {
            $events = @(Get-WinEvent -LogName $logName -FilterXPath "*[System[EventRecordID > $lastRecord]]" |
                ForEach-Object { Convert-DefenderEvent $_ })
        }
        catch {
            if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
            $events = @()
        }
        # Preserve the actual records before validation, even when matching
        # fails. The XML and normalized fields diagnose provider differences.
        Save-Json 'scan-events.json' $events
        $report.scanEventCounts = @($events | Group-Object id | ForEach-Object {
            [pscustomobject]@{ id = [int]$_.Name; count = $_.Count }
        })
        try {
            Assert-ScanCompleted $events $output
            $report.scanCompletionObserved = $true
            break
        }
        catch {
            if ($attempt -eq 10) { break }
        }
        Start-Sleep -Seconds 1
    }
    $report.scanEvidenceCollectedUtc = [DateTime]::UtcNow.ToString('o')
    # Collect final health and byte evidence on a matching failure as well.
    Test-ProtectionCheckpoint 'after-scan-call'
    $after = @(Get-NativeOutputInventory $output)
    Save-Json 'native-hashes-after.json' $after
    if (@($events | Where-Object { $_.id -in @(1002, 1006, 1007, 1008, 1116, 1117, 1118, 1119, 5001, 5008, 5010, 5012) }).Count) {
        throw 'Defender recorded a cancellation, detection, remediation, or protection failure.'
    }
    Assert-ScanCompleted $events $output
    if ((ConvertTo-Json -InputObject $before -Compress) -cne (ConvertTo-Json -InputObject $after -Compress)) {
        throw 'Native output bytes changed or disappeared during the scan.'
    }
    $trackedChanges = @(& git status --porcelain --untracked-files=no)
    if ($LASTEXITCODE -ne 0 -or $trackedChanges.Count) { throw 'Tracked source bytes changed during the build/scan.' }
    $report.result = 'PASS'
}
catch {
    $report.error = $_.Exception.Message
    throw
}
finally {
    $report.finishedUtc = [DateTime]::UtcNow.ToString('o')
    Save-Json 'scan-result.json' $report
    Pop-Location
}
