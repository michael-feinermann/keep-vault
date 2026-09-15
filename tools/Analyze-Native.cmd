@echo off
setlocal

set "ROOT=%~dp0.."
set "VSDEVCMD=C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"

if not exist "%VSDEVCMD%" (
  set "VSDEVCMD=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat"
)

if not exist "%VSDEVCMD%" (
  echo Visual Studio Developer Command Prompt was not found.
  exit /b 1
)

call "%VSDEVCMD%" -arch=x64 -host_arch=x64
if errorlevel 1 exit /b 1

cd /d "%ROOT%"
if errorlevel 1 exit /b 1
pwsh -NoProfile -File tools\Verify-NativeSources.ps1
if errorlevel 1 exit /b 1
if not exist build-analysis mkdir build-analysis
if errorlevel 1 exit /b 1

REM Analyze every translation unit even if an earlier one fails. Keep the
REM aggregate failure exit code so incomplete coverage can never look green.
REM /c is mandatory: this task never links or replaces a shipped native tool.
set "ANALYZE=/nologo /c /analyze /W4 /sdl /GS"
set "ANALYSIS_FAILED="

cl %ANALYZE% /DNOJIT /EHsc /std:c++17 /Fobuild-analysis\zpaq.obj /analyze:log build-analysis\zpaq.xml external\zpaq\zpaq.cpp
if errorlevel 1 set "ANALYSIS_FAILED=1"

cl %ANALYZE% /DNOJIT /EHsc /std:c++17 /Fobuild-analysis\libzpaq.obj /analyze:log build-analysis\libzpaq.xml external\zpaq\libzpaq.cpp
if errorlevel 1 set "ANALYSIS_FAILED=1"

cl %ANALYZE% /WX /D_CRT_SECURE_NO_WARNINGS ^
  /Iexternal\Skein-reference\NIST\CD\Reference_Implementation ^
  /Fobuild-analysis\threefish_ref_export.obj ^
  /analyze:log build-analysis\threefish_ref_export.xml ^
  native\threefish_ref_export.c
if errorlevel 1 set "ANALYSIS_FAILED=1"

for %%F in (
  external\Skein-reference\NIST\CD\Reference_Implementation\skein.c
  external\Skein-reference\NIST\CD\Reference_Implementation\skein_block.c
) do (
  cl %ANALYZE% /D_CRT_SECURE_NO_WARNINGS ^
    /Iexternal\Skein-reference\NIST\CD\Reference_Implementation ^
    /Fobuild-analysis\skein_%%~nF.obj ^
    /analyze:log build-analysis\skein_%%~nF.xml ^
    %%F
  if errorlevel 1 set "ANALYSIS_FAILED=1"
)

cl %ANALYZE% /WX /D_CRT_SECURE_NO_WARNINGS ^
  /Iexternal\phc-winner-argon2\include ^
  /Iexternal\phc-winner-argon2\src ^
  /Iexternal\phc-winner-argon2\src\blake2 ^
  /Fobuild-analysis\argon2_ref_export.obj ^
  /analyze:log build-analysis\argon2_ref_export.xml ^
  native\argon2_ref_export.c
if errorlevel 1 set "ANALYSIS_FAILED=1"

for %%F in (
  external\phc-winner-argon2\src\run.c
  external\phc-winner-argon2\src\argon2.c
  external\phc-winner-argon2\src\core.c
  external\phc-winner-argon2\src\encoding.c
  external\phc-winner-argon2\src\ref.c
  external\phc-winner-argon2\src\thread.c
  external\phc-winner-argon2\src\blake2\blake2b.c
) do (
  cl %ANALYZE% /D_CRT_SECURE_NO_WARNINGS ^
    /Iexternal\phc-winner-argon2\include ^
    /Iexternal\phc-winner-argon2\src ^
    /Iexternal\phc-winner-argon2\src\blake2 ^
    /Fobuild-analysis\argon2_%%~nF.obj ^
    /analyze:log build-analysis\argon2_%%~nF.xml ^
    %%F
  if errorlevel 1 set "ANALYSIS_FAILED=1"
)

cl %ANALYZE% /WX /D_CRT_SECURE_NO_WARNINGS /DDILITHIUM_MODE=5 ^
  /Iexternal\ML-DSA-reference\ref ^
  /Fobuild-analysis\mldsa_mldsa87_ref_export.obj ^
  /analyze:log build-analysis\mldsa_mldsa87_ref_export.xml ^
  native\mldsa87_ref_export.c
if errorlevel 1 set "ANALYSIS_FAILED=1"

for %%F in (
  external\ML-DSA-reference\ref\sign.c
  external\ML-DSA-reference\ref\packing.c
  external\ML-DSA-reference\ref\polyvec.c
  external\ML-DSA-reference\ref\poly.c
  external\ML-DSA-reference\ref\ntt.c
  external\ML-DSA-reference\ref\reduce.c
  external\ML-DSA-reference\ref\rounding.c
  external\ML-DSA-reference\ref\symmetric-shake.c
  external\ML-DSA-reference\ref\fips202.c
) do (
  cl %ANALYZE% /D_CRT_SECURE_NO_WARNINGS /DDILITHIUM_MODE=5 ^
    /Iexternal\ML-DSA-reference\ref ^
    /Fobuild-analysis\mldsa_%%~nF.obj ^
    /analyze:log build-analysis\mldsa_%%~nF.xml ^
    %%F
  if errorlevel 1 set "ANALYSIS_FAILED=1"
)

if defined ANALYSIS_FAILED (
  echo Native static analysis completed with compilation or adapter warning failures.
  exit /b 1
)
echo Native static analysis complete.
exit /b 0
