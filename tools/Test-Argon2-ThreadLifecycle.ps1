param([string] $Root = (Join-Path $PSScriptRoot '..'))
$ErrorActionPreference = 'Stop'
$rootPath = [IO.Path]::GetFullPath($Root)
& (Join-Path $PSScriptRoot 'Verify-NativeSources.ps1') -Root $rootPath

$developerCommand = @(
    'C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat',
    'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat'
) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
if (-not $developerCommand) { throw 'Visual Studio C/C++ tools were not found.' }

# All generated files are isolated test artifacts; no product binary is built
# or replaced. The negative control changes only the erroneous wait target.
$testPath = Join-Path $rootPath 'work/argon2-lifecycle'
[IO.Directory]::CreateDirectory($testPath) | Out-Null
$utf8 = [Text.UTF8Encoding]::new($false, $true)
$core = [IO.File]::ReadAllText((Join-Path $rootPath 'external/phc-winner-argon2/src/core.c'), $utf8)
$fixed = 'wait_for_completed(&completed, created);'
if ([regex]::Matches($core, [regex]::Escape($fixed)).Count -ne 1) { throw 'The reviewed cumulative completion check is missing.' }
[IO.File]::WriteAllText((Join-Path $testPath 'argon2-core-before.c'),
    $core.Replace($fixed, 'wait_for_completed(&completed, active);'), $utf8)

$compilePath = Join-Path $testPath 'compile-regression.cmd'
$compile = @(
    '@echo off',
    'setlocal',
    ('call "' + $developerCommand + '" -arch=x64 -host_arch=x64'),
    'if errorlevel 1 exit /b 1',
    ('cd /d "' + $rootPath + '"'),
    'if errorlevel 1 exit /b 1',
    'set "CHECKFLAGS=/nologo /W4 /WX /GS /sdl /Gy /D_CRT_SECURE_NO_WARNINGS /Iexternal\phc-winner-argon2\include /Iexternal\phc-winner-argon2\src /Iexternal\phc-winner-argon2\src\blake2 /Iwork\argon2-lifecycle /Fowork\argon2-lifecycle\"',
    'cl %CHECKFLAGS% /DKEEPVAULT_TEST_UNSAFE_COMPLETION /Fework\argon2-lifecycle\before.exe native\argon2_thread_lifecycle_test.c external\phc-winner-argon2\src\blake2\blake2b.c /link /OPT:REF /INCREMENTAL:NO',
    'if errorlevel 1 exit /b 1',
    'cl %CHECKFLAGS% /Fework\argon2-lifecycle\after.exe native\argon2_thread_lifecycle_test.c external\phc-winner-argon2\src\blake2\blake2b.c /link /OPT:REF /INCREMENTAL:NO',
    'if errorlevel 1 exit /b 1',
    'exit /b 0'
)
[IO.File]::WriteAllText($compilePath, ($compile -join "`r`n") + "`r`n", $utf8)
& $env:ComSpec /d /c $compilePath
if ($LASTEXITCODE -ne 0) { throw 'The isolated thread-lifecycle regression did not compile.' }

$beforeOutput = @(& (Join-Path $testPath 'before.exe') 2>&1)
$beforeExit = $LASTEXITCODE
$beforeOutput | Write-Output
if ($beforeExit -ne 1 -or
    -not ($beforeOutput -match '^argon2_late_join=premature_free_detected completion_waits=0 ') -or
    -not ($beforeOutput -match '^argon2_late_create=premature_free_detected completion_waits=0 ')) {
    throw 'The negative control did not reproduce both premature-free failure paths.'
}

$afterOutput = @(& (Join-Path $testPath 'after.exe') 2>&1)
$afterExit = $LASTEXITCODE
$afterOutput | Write-Output
if ($afterExit -ne 0 -or
    -not ($afterOutput -match '^argon2_late_join=all_workers_completed_before_free ') -or
    -not ($afterOutput -match '^argon2_late_create=all_workers_completed_before_free ')) {
    throw 'The corrected core did not safely complete both late-worker failure paths.'
}
Write-Output 'Argon2 thread-lifecycle regression passed with a failing negative control.'
