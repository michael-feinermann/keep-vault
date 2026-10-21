param(
    [string] $Root = (Join-Path $PSScriptRoot '..'),
    [string] $EvidenceParent = ''
)
$ErrorActionPreference = 'Stop'
$rootPath = [IO.Path]::GetFullPath($Root)
. (Join-Path $PSScriptRoot 'LocalWorkspacePolicy.ps1')
Assert-LocalReleaseWorkspace $rootPath
$work = Join-Path $rootPath 'work'
$parent = if ($EvidenceParent) { [IO.Path]::GetFullPath($EvidenceParent) } else { $work }
if (-not ($parent -ieq $work -or $parent.StartsWith($work + '\', [StringComparison]::OrdinalIgnoreCase))) {
    throw 'Lifecycle evidence must remain below the local repository work directory.'
}
$evidence = Join-Path $parent ('control-lifecycle-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($evidence) | Out-Null
$developer = @(
    'C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat',
    'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat',
    'C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat'
) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
if (-not $developer) { throw 'Visual Studio C/C++ tools were not found.' }
$utf8 = [Text.UTF8Encoding]::new($false)
$headerHash = (Get-FileHash -LiteralPath (Join-Path $rootPath 'native\zpaq_control.hpp')).Hash
$header = [IO.File]::ReadAllText((Join-Path $rootPath 'native\zpaq_control.hpp'), $utf8)
$before = (& git -C $rootPath show 'ba9949ad1b93a89f75dd8078414371d1a1b7ad0d:native/zpaq_control.hpp') -join "`n"
if ($LASTEXITCODE -ne 0) { throw 'Cannot read the exact original v13 control source for the negative control.' }
function Add-ReadDelay([string] $Source) {
    $member = 'bool orderly_closed_=false;'
    $notify = 'entry->second->changed.notify_one();'
    $read = 'std::array<unsigned char,48> h{}; transfer(h.data(),h.size(),false);'
    foreach ($needle in @($member,$notify,$read)) {
        if ([regex]::Matches($Source,[regex]::Escape($needle)).Count -ne 1) { throw 'The reviewed control-loop fixture injection point changed.' }
    }
    # Identical scheduling perturbation in generated old/current copies only.
    # Delay after releasing the previous response's gate lock. The ordinary
    # delay also lets the original synchronous transport submit its next write.
    # Current production code returns after close ACK and never enters that delay.
    return $Source.Replace($member,$member + "`n    bool fixture_first_read_=true,fixture_reply_delivered_=false,fixture_close_delivered_=false;").Replace(
        $notify,$notify + "`n                fixture_reply_delivered_=true;`n                if(entry->second->result.kind==(std::uint32_t(control_kind::close)|0x80000000u)) fixture_close_delivered_=true;").Replace(
        $read,"if(fixture_first_read_) {fixture_first_read_=false;Sleep(20);}`n                if(fixture_reply_delivered_) {fixture_reply_delivered_=false;Sleep(fixture_close_delivered_?500:50);}`n                " + $read)
}
foreach ($variant in @('before-delayed','current-delayed')) {
    [IO.Directory]::CreateDirectory((Join-Path $evidence $variant)) | Out-Null
    $source = if ($variant -eq 'before-delayed') { $before } else { $header }
    [IO.File]::WriteAllText((Join-Path $evidence "$variant\zpaq_control.hpp"),(Add-ReadDelay $source),$utf8)
}
$fixture = Join-Path $rootPath 'native\tests\zpaq_control_lifecycle.cpp'
$fixtureHash = (Get-FileHash -LiteralPath $fixture).Hash
$commands = [Collections.Generic.List[string]]::new()
$commands.Add('@echo off');$commands.Add('setlocal')
$commands.Add('call "' + $developer + '" -arch=x64 -host_arch=x64')
$commands.Add('if errorlevel 1 exit /b 1')
foreach ($variant in @('current','before-delayed','current-delayed')) {
    $include = if ($variant -eq 'current') { Join-Path $rootPath 'native' } else { Join-Path $evidence $variant }
    $commands.Add('cl /nologo /O2 /MT /std:c++17 /EHsc /W4 /WX /GS /sdl /guard:cf /DNOMINMAX /I"' + $include + '" /Fo"' + (Join-Path $evidence "$variant.obj") + '" /Fe"' + (Join-Path $evidence "$variant.exe") + '" "' + $fixture + '" /link /guard:cf /CETCOMPAT')
    $commands.Add('if errorlevel 1 exit /b 1')
}
$compile = Join-Path $evidence 'compile.cmd'
[IO.File]::WriteAllLines($compile,$commands,$utf8)
& $env:ComSpec /d /c $compile *> (Join-Path $evidence 'compile.log')
if ($LASTEXITCODE -ne 0) { Get-Content (Join-Path $evidence 'compile.log'); throw 'The isolated control lifecycle fixture did not compile.' }
$checks = [Collections.Generic.List[object]]::new()
function Invoke-Bounded([string] $Variant,[string] $Mode,[int] $Repetitions,[bool] $ExpectTimeout=$false) {
    $start = [Diagnostics.ProcessStartInfo]::new((Join-Path $evidence "$Variant.exe"))
    $start.UseShellExecute=$false;$start.CreateNoWindow=$true
    $start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    $start.ArgumentList.Add($Mode);$start.ArgumentList.Add([string]$Repetitions)
    $process = [Diagnostics.Process]::new();$process.StartInfo=$start
    $started=$false
    try {
        $started=$process.Start()
        if (-not $started) { throw 'Cannot start lifecycle fixture.' }
        $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
        $timedOut=-not $process.WaitForExit(10000)
        $tree=@();$treeError=$null
        if ($timedOut) {
            try {
                $all=@(Get-CimInstance Win32_Process -ErrorAction Stop)
                $ids=[Collections.Generic.HashSet[uint32]]::new();$null=$ids.Add([uint32]$process.Id)
                do {
                    $added=$false
                    foreach($item in $all) {if($ids.Contains([uint32]$item.ParentProcessId) -and $ids.Add([uint32]$item.ProcessId)) {$added=$true}}
                } while($added)
                $tree=@($all | Where-Object {$ids.Contains([uint32]$_.ProcessId)} | Select-Object ProcessId,ParentProcessId,Name,CreationDate,KernelModeTime,UserModeTime,WorkingSetSize)
            }
            catch { $treeError=$_.Exception.Message }
            finally {
                if(-not $process.HasExited) {$process.Kill($true)}
                if(-not $process.WaitForExit(5000)) {throw 'Timed out fixture tree did not terminate.'}
            }
        }
        $out=$stdout.GetAwaiter().GetResult();$err=$stderr.GetAwaiter().GetResult()
        $closeRaceProven=$timedOut -and $err.Contains('fixture: ordinary request completed') -and
            $err.Contains('fixture: peer sent close ACK') -and $err.Contains('fixture: finish returned') -and
            $err.Contains('fixture: destroying channel')
        $record=[ordered]@{Variant=$Variant;Mode=$Mode;Repetitions=$Repetitions;TimedOut=$timedOut;ExpectedTimeout=$ExpectTimeout;CloseRaceNegativeControlProven=$closeRaceProven;ExitCode=$process.ExitCode;Stdout=$out;Stderr=$err;TreeAtTimeout=$tree;TreeCaptureError=$treeError}
        $checks.Add($record)
        $record | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $evidence "$Variant-$Mode.json") -Encoding utf8NoBOM
    }
    finally {
        try {if($started -and -not $process.HasExited) {$process.Kill($true);if(-not $process.WaitForExit(5000)) {throw 'Owned lifecycle fixture remained live after exceptional cleanup.'}}}
        finally {$process.Dispose()}
    }
    if($timedOut -ne $ExpectTimeout -or (-not $timedOut -and $record.ExitCode -ne 0)) {throw "Unexpected lifecycle result: $Variant/$Mode"}
    if($ExpectTimeout -and -not $closeRaceProven) {throw 'The negative control hung before the close acknowledgment; no close-race reproduction is established.'}
    Write-Output "PASS $Variant/$Mode repetitions=$Repetitions expectedTimeout=$ExpectTimeout"
}
$state='FAIL'
try {
    Invoke-Bounded 'before-delayed' 'close-race' 1 $true
    foreach($mode in @('normal','pending-close','wrong-kind','wrong-sequence','close-field','close-payload','peer-drop')) {
        Invoke-Bounded 'current' $mode $(if($mode -eq 'normal') {64} else {16})
    }
    Invoke-Bounded 'current-delayed' 'close-race' 64
    if ((Get-FileHash -LiteralPath (Join-Path $rootPath 'native\zpaq_control.hpp')).Hash -cne $headerHash -or
        (Get-FileHash -LiteralPath $fixture).Hash -cne $fixtureHash) { throw 'Lifecycle inputs changed during compilation or execution.' }
    $state='PASS'
}
finally {
    [ordered]@{State=$state;ProductionHeaderSha256=$headerHash;FixtureSha256=$fixtureHash;Scope='Real Windows named pipes and production control_channel; scheduling hook only in generated negative/positive copies.';Checks=$checks} | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $evidence 'result.json') -Encoding utf8NoBOM
    Write-Output "Control lifecycle evidence: $evidence"
}
