@echo off
setlocal

set "ROOT=%~dp0.."
set "VSDEVCMD=C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"

if not exist "%VSDEVCMD%" (
  set "VSDEVCMD=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat"
)

REM GitHub-hosted windows-2022 uses the Enterprise installation.
if not exist "%VSDEVCMD%" (
  set "VSDEVCMD=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat"
)

if not exist "%VSDEVCMD%" (
  echo Visual Studio Developer Command Prompt was not found.
  exit /b 1
)

call "%VSDEVCMD%" -arch=x64 -host_arch=x64
if errorlevel 1 exit /b 1

cd /d "%ROOT%"
set "NATIVEOUTPUT=tools"
if not "%~1"=="" set "NATIVEOUTPUT=%~1"
if not exist "%NATIVEOUTPUT%" mkdir "%NATIVEOUTPUT%"

pwsh -NoProfile -ExecutionPolicy Bypass -File tools\Verify-NativeSources.ps1
if errorlevel 1 exit /b 1

pwsh -NoProfile -ExecutionPolicy Bypass -File tools\Verify-MldsaReference.ps1
if errorlevel 1 exit /b 1

REM Object files land in work\, not wherever cl happened to be started. The
REM Crypto++ branch below already directs its own; the targets above it did
REM not, so every translation unit left its .obj in the checkout root - some
REM thirty files beside README.md, ignored by git and puzzling to anyone who
REM looked.
set "NATIVEOBJ=work\native-objects"
if not exist "%NATIVEOBJ%" mkdir "%NATIVEOBJ%"

set "HARDEN_COMPILE=/O2 /MT /GS /sdl /guard:cf /Fo%NATIVEOBJ%\"
set "HARDEN_LINK=/link /guard:cf /CETCOMPAT"

cl %HARDEN_COMPILE% /DNOJIT /EHsc /Fe"%NATIVEOUTPUT%\zpaq.exe" external\zpaq\zpaq.cpp external\zpaq\libzpaq.cpp advapi32.lib %HARDEN_LINK%
if errorlevel 1 exit /b 1

cl %HARDEN_COMPILE% /LD /D_CRT_SECURE_NO_WARNINGS ^
  /Iexternal\Skein-reference\NIST\CD\Reference_Implementation ^
  /Fe"%NATIVEOUTPUT%\threefish_ref.dll" ^
  native\threefish_ref_export.c ^
  external\Skein-reference\NIST\CD\Reference_Implementation\skein.c ^
  external\Skein-reference\NIST\CD\Reference_Implementation\skein_block.c ^
  %HARDEN_LINK%
if errorlevel 1 exit /b 1

cl %HARDEN_COMPILE% /LD /D_CRT_SECURE_NO_WARNINGS /DDILITHIUM_MODE=5 ^
  /Iexternal\ML-DSA-reference\ref ^
  /Fe"%NATIVEOUTPUT%\mldsa87_ref.dll" ^
  native\mldsa87_ref_export.c ^
  external\ML-DSA-reference\ref\sign.c ^
  external\ML-DSA-reference\ref\packing.c ^
  external\ML-DSA-reference\ref\polyvec.c ^
  external\ML-DSA-reference\ref\poly.c ^
  external\ML-DSA-reference\ref\ntt.c ^
  external\ML-DSA-reference\ref\reduce.c ^
  external\ML-DSA-reference\ref\rounding.c ^
  external\ML-DSA-reference\ref\symmetric-shake.c ^
  external\ML-DSA-reference\ref\fips202.c ^
  bcrypt.lib ^
  %HARDEN_LINK%
if errorlevel 1 exit /b 1

if exist external\phc-winner-argon2 (
  cl %HARDEN_COMPILE% /LD /D_CRT_SECURE_NO_WARNINGS ^
    /Iexternal\phc-winner-argon2\include ^
    /Iexternal\phc-winner-argon2\src ^
    /Iexternal\phc-winner-argon2\src\blake2 ^
    /Fe"%NATIVEOUTPUT%\argon2_ref.dll" ^
    native\argon2_ref_export.c ^
    external\phc-winner-argon2\src\argon2.c ^
    external\phc-winner-argon2\src\core.c ^
    external\phc-winner-argon2\src\encoding.c ^
    external\phc-winner-argon2\src\ref.c ^
    external\phc-winner-argon2\src\thread.c ^
    external\phc-winner-argon2\src\blake2\blake2b.c ^
    %HARDEN_LINK%
  if errorlevel 1 exit /b 1

  cl %HARDEN_COMPILE% /D_CRT_SECURE_NO_WARNINGS ^
    /Iexternal\phc-winner-argon2\include ^
    /Iexternal\phc-winner-argon2\src ^
    /Iexternal\phc-winner-argon2\src\blake2 ^
    /Fe"%NATIVEOUTPUT%\argon2.exe" ^
    external\phc-winner-argon2\src\run.c ^
    external\phc-winner-argon2\src\argon2.c ^
    external\phc-winner-argon2\src\core.c ^
    external\phc-winner-argon2\src\encoding.c ^
    external\phc-winner-argon2\src\ref.c ^
    external\phc-winner-argon2\src\thread.c ^
    external\phc-winner-argon2\src\blake2\blake2b.c ^
    %HARDEN_LINK%
  if errorlevel 1 exit /b 1
)

REM --------------------------------------------------------------------
REM Crypto++ adapters: AES-256, MARS-448, SHACAL-2-512 and
REM ChaCha20-Poly1305. The managed side refuses to enable archive
REM operations without all four, and the cascade suites cannot run
REM without them at all.
REM
REM Crypto++ is archived whole rather than cherry-picked. Its algorithm
REM sources reach cryptlib, misc, secblock and from there the integer
REM machinery, so a hand-picked subset does not link and would have to be
REM re-picked at every update.
REM
REM Both release builds keep their architecture-specific acceleration enabled.
REM On Windows, MSVC selects the SIMD paths through intrinsics without per-file flags, and
REM x64dll.asm supplies the CPUID and XGETBV helpers cpu.cpp needs on
REM x64. CRYPTOPP_DISABLE_ASM must therefore stay unset for the archive
REM AND for every adapter compiled against it - the headers branch on it,
REM so a mismatch gives the two sides different class layouts.
set "CRYPTOPP=external\cryptopp"
set "CPPOBJ=work\cryptopp-objects"
if not exist "%CPPOBJ%" mkdir "%CPPOBJ%"
if not exist "%CPPOBJ%\adapters" mkdir "%CPPOBJ%\adapters"
set "CPPFLAGS=/nologo /c /MT /GS /guard:cf /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS /W0 /MP4"

REM The library, its test drivers and its validation suites live in one
REM directory; the drivers carry a main() and the suites are not shipped.
REM BEGIN CRYPTOPP RESPONSE INPUTS
REM Reset both lists before generating them. The object list is the exact
REM compilation set; unrelated or stale .obj files must never enter the library.
type nul >"%CPPOBJ%\cryptopp-sources.rsp" || exit /b 1
type nul >"%CPPOBJ%\cryptopp-objects.rsp" || exit /b 1
pushd "%CRYPTOPP%" || exit /b 1
for %%F in (*.cpp) do (
  set "SKIP="
  if /i "%%F"=="test.cpp" set "SKIP=1"
  if /i "%%F"=="bench1.cpp" set "SKIP=1"
  if /i "%%F"=="bench2.cpp" set "SKIP=1"
  if /i "%%F"=="bench3.cpp" set "SKIP=1"
  if /i "%%F"=="datatest.cpp" set "SKIP=1"
  if /i "%%F"=="dlltest.cpp" set "SKIP=1"
  if /i "%%F"=="fipsalgt.cpp" set "SKIP=1"
  if /i "%%F"=="adhoc.cpp" set "SKIP=1"
  echo %%F | findstr /b /i "regtest validat" >nul && set "SKIP=1"
  REM gfpcrypt.cpp and hight.cpp make this compiler abort with C1001 at
  REM /O2; they are rebuilt below without it. Neither is on any path this
  REM application uses - they are archived only so the library links.
  if /i "%%F"=="gfpcrypt.cpp" set "SKIP=1"
  if /i "%%F"=="hight.cpp" set "SKIP=1"
  if not defined SKIP (
    echo %%F>>"..\..\%CPPOBJ%\cryptopp-sources.rsp"|| (popd & exit /b 1)
    echo "%CPPOBJ%\%%~nF.obj">>"..\..\%CPPOBJ%\cryptopp-objects.rsp"|| (popd & exit /b 1)
  )
)
popd
REM These C++ units use a separate optimization command; MASM emits the other two.
for %%F in (gfpcrypt hight x64dll x64masm) do (
  echo "%CPPOBJ%\%%F.obj">>"%CPPOBJ%\cryptopp-objects.rsp"|| exit /b 1
)
REM END CRYPTOPP RESPONSE INPUTS

pushd "%CRYPTOPP%"
cl %CPPFLAGS% /O2 /MP /Fo"..\..\%CPPOBJ%\\" @"..\..\%CPPOBJ%\cryptopp-sources.rsp"
if errorlevel 1 (popd & exit /b 1)
cl %CPPFLAGS% /Fo"..\..\%CPPOBJ%\\" gfpcrypt.cpp hight.cpp
if errorlevel 1 (popd & exit /b 1)
ml64 /nologo /c /Fo"..\..\%CPPOBJ%\x64dll.obj" x64dll.asm
if errorlevel 1 (popd & exit /b 1)
ml64 /nologo /c /Fo"..\..\%CPPOBJ%\x64masm.obj" x64masm.asm
if errorlevel 1 (popd & exit /b 1)
popd

lib /nologo /OUT:"%CPPOBJ%\cryptopp.lib" @"%CPPOBJ%\cryptopp-objects.rsp"
if errorlevel 1 exit /b 1

for %%A in (aes mars shacal2 chachapoly) do (
  cl %HARDEN_COMPILE% /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS /LD ^
    /I"%CRYPTOPP%" ^
    /Fo"%CPPOBJ%\adapters\\" ^
    /Fe"%NATIVEOUTPUT%\%%A_ref.dll" ^
    native\%%A_ref_export.cpp ^
    "%CPPOBJ%\cryptopp.lib" ^
    %HARDEN_LINK%
  if errorlevel 1 exit /b 1
)

cl %HARDEN_COMPILE% /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS /LD ^
  /I"%CRYPTOPP%" ^
  /Fo"%CPPOBJ%\adapters\\" ^
  /Fe"%NATIVEOUTPUT%\kalyna_v12.dll" ^
  native\kalyna_v12_export.cpp ^
  "%CPPOBJ%\cryptopp.lib" ^
  %HARDEN_LINK%
if errorlevel 1 exit /b 1

echo Keep Vault v12 Windows native toolset built.
exit /b 0
