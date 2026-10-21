param([Parameter(Mandatory)][string]$SourceRoot,[Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$ExpectedCommit,[ValidateSet('full','performance')][string]$Mode='full')
$ErrorActionPreference='Stop'
$evidence=$PSScriptRoot
$commit=(& git -C $SourceRoot rev-parse HEAD).Trim()
$dll=Join-Path $SourceRoot 'work\native-gate-tests\KalynaArchiver.Tests.dll'
$results=Join-Path (Split-Path $dll) '.test-results.json'
$log=Join-Path $evidence ('final-'+$Mode+'.log')
$receipt=Join-Path $evidence ('final-'+$Mode+'-receipt.json')
$record=[ordered]@{Mode=$Mode;Commit=$commit;SourceRoot=$SourceRoot;StartedAt=(Get-Date).ToString('o');State='FAIL';ProcessExitCode=$null}
try {
 if($commit -cne $ExpectedCommit){throw 'Unexpected final source commit'}
 if(Test-Path -LiteralPath $results){Copy-Item -LiteralPath $results -Destination (Join-Path $evidence ('before-final-'+$Mode+'-results.json'));Remove-Item -LiteralPath $results}
 $argMode='--'+$Mode
 $previousRepositoryRoot=$env:KEEPVAULT_TEST_REPOSITORY_ROOT
 $env:KEEPVAULT_TEST_REPOSITORY_ROOT=$SourceRoot
 Push-Location -LiteralPath $SourceRoot
 try {
  & 'C:\Program Files\dotnet\dotnet.exe' $dll $argMode --parallel 1 *> $log
  $record.ProcessExitCode=$LASTEXITCODE
 } finally {
  Pop-Location
  $env:KEEPVAULT_TEST_REPOSITORY_ROOT=$previousRepositoryRoot
 }
 if(Test-Path -LiteralPath $results){Copy-Item -LiteralPath $results -Destination (Join-Path $evidence ('final-'+$Mode+'-results.json'))}
 if($record.ProcessExitCode -ne 0){throw ('Test runner exited '+$record.ProcessExitCode)}
 if(-not(Test-Path -LiteralPath $results)){throw 'Test runner did not write fresh results'}
 $manifest=Join-Path (Split-Path $SourceRoot) 'source-inputs-before.sha256'
 $count=0
 foreach($line in Get-Content -LiteralPath $manifest){
  if($line -cnotmatch '^([0-9A-F]{64})  (.+)$'){throw 'Malformed source manifest'}
  $expected=$Matches[1];$path=Join-Path $SourceRoot $Matches[2]
  if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $expected){throw ('Source changed: '+$Matches[2])}
  $count++
 }
 $record.UnchangedSourceFiles=$count
 $record.State='PASS'
} catch {$record.Error=$_.Exception.Message}
finally {$record.FinishedAt=(Get-Date).ToString('o');$record | ConvertTo-Json | Set-Content -LiteralPath $receipt -Encoding utf8NoBOM}
Get-Content -LiteralPath $log -Tail 25
$record | ConvertTo-Json
if($record.State -cne 'PASS'){exit 1}
