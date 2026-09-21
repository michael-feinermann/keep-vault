# Exercise the actual release process gate with a newly compiled, inert WinExe.
# No product executable, private key, signing operation, or native vault code is used.
param([string] $DotnetPath = 'dotnet')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$helper = Join-Path $PSScriptRoot 'Invoke-ReleaseExecutable.ps1'
$helperHash = (Get-FileHash -LiteralPath $helper -Algorithm SHA256).Hash
. $helper
$dotnet = (Get-Command $DotnetPath -CommandType Application -ErrorAction Stop).Source
$evidence = Join-Path $root ('work\release-executable-process-' + [Guid]::NewGuid().ToString('N'))
$fixture = Join-Path $evidence 'synthetic WinExe Grüße'
[IO.Directory]::CreateDirectory($fixture) | Out-Null
$outcomes = [Collections.Generic.List[object]]::new()
$report = [ordered]@{
    State = 'FAIL'
    StartedAt = (Get-Date).ToString('o')
    Scope = 'Actual process helper and synthetic managed WinExe only; no product executable or private keys.'
    HelperSha256 = $helperHash
    Checks = $outcomes
}
$savedEnvironment = @{}
foreach ($name in @('DOTNET_ROOT', 'DOTNET_ROOT_X64', 'DOTNET_MULTILEVEL_LOOKUP')) {
    $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
$oldLastExitCode = Get-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue
$oldLastExitCodeValue = if ($null -ne $oldLastExitCode) { $oldLastExitCode.Value } else { $null }

function Require([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw $Message }
}
function Record-Pass([string] $Name, $Details) {
    $outcomes.Add([pscustomobject]@{ Name = $Name; Passed = $true; Details = $Details })
    Write-Host "PASS $Name"
}
function Invoke-CapturedRelease {
    param([string] $Path, [string[]] $Argv, [int] $Expected = 0, [int] $Timeout = 10)
    $messages = [Collections.Generic.List[string]]::new()
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $failure = $null
    try {
        Invoke-ReleaseExecutable -Executable $Path -Arguments $Argv -ExpectedExitCode $Expected -TimeoutSeconds $Timeout 6>&1 |
            ForEach-Object {
                if ($_ -is [Management.Automation.InformationRecord]) {
                    $messages.Add($_.MessageData.ToString())
                }
                else { throw 'The process helper emitted an unexpected success-stream value.' }
            }
    }
    catch { $failure = $_.Exception.Message }
    finally { $watch.Stop() }
    [pscustomobject]@{ Failure = $failure; Messages = $messages.ToArray(); ElapsedMilliseconds = $watch.ElapsedMilliseconds }
}
function Require-Completed([string] $Record, [int] $ExpectedCode) {
    Require (Test-Path -LiteralPath ($Record + '.completed.json') -PathType Leaf) 'The helper returned before the WinExe finished.'
    $completed = Get-Content -LiteralPath ($Record + '.completed.json') -Raw | ConvertFrom-Json
    Require ($completed.ExitCode -eq $ExpectedCode) 'The fixture did not complete its intended exit branch.'
}
function Require-Streams($Result, [int] $Fill = 0) {
    $expectedOut = 'stdout: Grüße 世界 🌲' + ('O' * $Fill)
    $expectedErr = 'stderr: Grüße 世界 🌲' + ('E' * $Fill)
    Require ($Result.Messages.Count -eq 2) 'Expected independently captured stdout and stderr.'
    Require ($Result.Messages[0] -ceq $expectedOut) 'stdout was truncated or changed.'
    Require ($Result.Messages[1] -ceq $expectedErr) 'stderr was truncated or changed.'
}

try {
    $env:DOTNET_ROOT = Split-Path $dotnet
    $env:DOTNET_ROOT_X64 = Split-Path $dotnet
    $env:DOTNET_MULTILEVEL_LOOKUP = '0'
    $report.Sdk = (& $dotnet --version).Trim()
    Require ($LASTEXITCODE -eq 0) 'Cannot query the selected .NET SDK.'

    # Stop repository build/signing imports at this isolated project boundary.
    foreach ($name in @('Directory.Build.props', 'Directory.Build.targets')) {
        [IO.File]::WriteAllText((Join-Path $fixture $name), '<Project/>')
    }
    [IO.File]::WriteAllText((Join-Path $fixture 'NuGet.Config'), '<configuration><packageSources><clear /></packageSources></configuration>')
    $project = Join-Path $fixture 'Synthetic.csproj'
    [IO.File]::WriteAllText($project, @'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>WinExe</OutputType>
    <TargetFramework>net10.0-windows</TargetFramework>
    <AssemblyName>KeepVault.ReleaseProcessFixture</AssemblyName>
    <EnableDefaultCompileItems>false</EnableDefaultCompileItems>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <NuGetAudit>false</NuGetAudit>
  </PropertyGroup>
  <ItemGroup><Compile Include="Program.cs" /></ItemGroup>
</Project>
'@)
    [IO.File]::WriteAllText((Join-Path $fixture 'Program.cs'), @'
using System.Text;
using System.Text.Json;

internal static class Program
{
    private static int Main(string[] args)
    {
        if (args.Length < 4) return 91;
        string record = args[0];
        int delay = int.Parse(args[1], System.Globalization.CultureInfo.InvariantCulture);
        int exitCode = int.Parse(args[2], System.Globalization.CultureInfo.InvariantCulture);
        int fill = int.Parse(args[3], System.Globalization.CultureInfo.InvariantCulture);
        var evidence = new { Pid = Environment.ProcessId, Arguments = args.Skip(4).ToArray(),
            WorkingDirectory = Environment.CurrentDirectory, Runtime = Environment.Version.ToString(), ExitCode = exitCode };
        File.WriteAllText(record + ".started.json", JsonSerializer.Serialize(evidence));
        using var output = new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false)) { AutoFlush = true };
        using var error = new StreamWriter(Console.OpenStandardError(), new UTF8Encoding(false)) { AutoFlush = true };
        output.WriteLine("stdout: Grüße 世界 🌲" + new string('O', fill));
        error.WriteLine("stderr: Grüße 世界 🌲" + new string('E', fill));
        Thread.Sleep(delay);
        File.WriteAllText(record + ".completed.json", JsonSerializer.Serialize(evidence));
        return exitCode;
    }
}
'@)
    $buildOutput = & $dotnet build $project --configuration Release --nologo --verbosity minimal 2>&1
    $buildExit = $LASTEXITCODE
    $buildOutput | Set-Content -LiteralPath (Join-Path $evidence 'build.log') -Encoding utf8NoBOM
    Require ($buildExit -eq 0) "Synthetic managed fixture build failed; see $evidence\build.log"
    $exe = Join-Path $fixture 'bin\Release\net10.0-windows\KeepVault.ReleaseProcessFixture.exe'
    $report.Fixture = $exe
    $report.FixtureSha256 = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
    $pe = [IO.File]::ReadAllBytes($exe)
    $peOffset = [BitConverter]::ToInt32($pe, 0x3c)
    Require ([BitConverter]::ToUInt32($pe, $peOffset) -eq 0x00004550) 'Fixture has no PE signature.'
    Require ([BitConverter]::ToUInt16($pe, $peOffset + 24 + 68) -eq 2) 'Fixture is not a Windows GUI subsystem executable.'
    Record-Pass 'fresh managed fixture really has WinExe subsystem' @{ Sha256 = $report.FixtureSha256; Sdk = $report.Sdk }

    $record = Join-Path $evidence 'delayed-zero'
    $global:LASTEXITCODE = 3
    $result = Invoke-CapturedRelease $exe @($record, '1000', '0', '0')
    Require ($null -eq $result.Failure) "Exit 0 rejected because of stale LASTEXITCODE: $($result.Failure)"
    Require-Completed $record 0
    Require ($result.ElapsedMilliseconds -ge 900) 'WinExe was not awaited for its delay.'
    Require-Streams $result
    $started = Get-Content -LiteralPath ($record + '.started.json') -Raw | ConvertFrom-Json
    Require ([IO.Path]::GetFullPath($started.WorkingDirectory) -ieq (Split-Path $exe)) 'Unexpected executable working directory.'
    $report.FixtureRuntime = $started.Runtime
    Record-Pass 'delayed Exit 0 waits and ignores stale LASTEXITCODE 3' @{ ElapsedMilliseconds = $result.ElapsedMilliseconds; Streams = 'exact UTF-8 stdout/stderr' }

    $record = Join-Path $evidence 'delayed-three'
    $global:LASTEXITCODE = 0
    $result = Invoke-CapturedRelease $exe @($record, '1000', '3', '0')
    Require ($result.Failure -like '*exited 3, expected 0*') 'Real Exit 3 was accepted or obscured by stale LASTEXITCODE 0.'
    Require-Completed $record 3
    Require ($result.ElapsedMilliseconds -ge 900) 'Nonzero WinExe was not awaited.'
    Require-Streams $result
    Record-Pass 'delayed Exit 3 rejects despite stale LASTEXITCODE 0' @{ ElapsedMilliseconds = $result.ElapsedMilliseconds; Error = $result.Failure }

    $record = Join-Path $evidence 'expected-three'
    $result = Invoke-CapturedRelease $exe @($record, '150', '3', '0') -Expected 3
    Require ($null -eq $result.Failure) 'ExpectedExitCode 3 was rejected.'
    Require-Completed $record 3
    Require-Streams $result
    Record-Pass 'explicit ExpectedExitCode 3 is honored' $null

    $record = Join-Path $evidence 'exact-argv'
    $values = [string[]]@('plain', 'space in value', '', 'Grüße 世界 🌲', '  leading and trailing  ',
        'quote"value', 'endswith\', 'C:\path with spaces\', 'one\"two', '--option', '; & $() literal', "line`nbreak")
    $result = Invoke-CapturedRelease $exe (@($record, '0', '0', '0') + $values)
    Require ($null -eq $result.Failure) "Argument round trip failed: $($result.Failure)"
    $actual = (Get-Content -LiteralPath ($record + '.completed.json') -Raw | ConvertFrom-Json).Arguments
    Require ($actual.Count -eq $values.Count) 'The argument count changed (including an empty argument).'
    for ($i = 0; $i -lt $values.Count; $i++) {
        Require ($actual[$i] -ceq $values[$i]) "Argument $i changed."
    }
    Require-Streams $result
    Record-Pass 'exact argv including Unicode, spaces, empty, quotes and trailing backslashes' @{ Count = $values.Count }

    $record = Join-Path $evidence 'pipe-capacity'
    $result = Invoke-CapturedRelease $exe @($record, '0', '0', '131072')
    Require ($null -eq $result.Failure) "Concurrent stdout/stderr draining failed: $($result.Failure)"
    Require-Completed $record 0
    Require-Streams $result 131072
    Record-Pass 'stdout and stderr both exceed pipe capacity without deadlock or truncation' @{ FillCharactersPerStream = 131072 }

    $missing = Join-Path $evidence 'does-not-exist.exe'
    $result = Invoke-CapturedRelease $missing @()
    Require ($null -ne $result.Failure) 'A nonexistent executable was accepted.'
    Require ($result.Messages.Count -eq 0) 'A nonexistent executable emitted fixture output.'
    Record-Pass 'missing executable fails closed' @{ Error = $result.Failure }

    $record = Join-Path $evidence 'timeout'
    $result = Invoke-CapturedRelease $exe @($record, '30000', '0', '0') -Timeout 1
    Require ($result.Failure -like '*exceeded 1 seconds*') 'Timeout was not reported as a failure.'
    Require ($result.ElapsedMilliseconds -ge 900 -and $result.ElapsedMilliseconds -lt 15000) 'Timeout was not bounded.'
    Require (Test-Path -LiteralPath ($record + '.started.json')) 'Timeout did not exercise a running fixture.'
    $started = Get-Content -LiteralPath ($record + '.started.json') -Raw | ConvertFrom-Json
    $stillRunning = Get-Process -Id $started.Pid -ErrorAction SilentlyContinue
    if ($null -ne $stillRunning) {
        # Cleanup is restricted to this test's verified executable identity.
        if ([IO.Path]::GetFullPath($stillRunning.Path) -ieq [IO.Path]::GetFullPath($exe)) {
            $stillRunning.Kill($true)
            $stillRunning.WaitForExit()
        }
        throw 'The process helper left its timed-out fixture alive.'
    }
    Require (-not (Test-Path -LiteralPath ($record + '.completed.json'))) 'Timed-out fixture reached normal completion.'
    Require-Streams $result
    Record-Pass 'timeout rejects and terminates its own running WinExe' @{ ElapsedMilliseconds = $result.ElapsedMilliseconds; Pid = $started.Pid; Error = $result.Failure }

    Require ((Get-FileHash -LiteralPath $helper -Algorithm SHA256).Hash -ceq $helperHash) 'Process helper changed during regression.'
    $report.State = 'PASS'
}
catch {
    $report.Error = $_.Exception.Message
    throw
}
finally {
    foreach ($name in $savedEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process')
    }
    if ($null -ne $oldLastExitCode) { $global:LASTEXITCODE = $oldLastExitCodeValue }
    else { Remove-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue }
    $report.CompletedAt = (Get-Date).ToString('o')
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $evidence 'result.json') -Encoding utf8NoBOM
    Write-Host "Synthetic process evidence: $evidence"
}
