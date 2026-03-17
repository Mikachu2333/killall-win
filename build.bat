@echo off
setlocal

:: ── Locate MSVC ──────────────────────────────────────────────────────────────
set VCVARS=
for %%E in (Community BuildTools Enterprise Professional) do (
    if exist "C:\Program Files\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat" (
        set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat"
        goto :found
    )
)
echo ERROR: Visual Studio 2022 not found. Install MSVC or Build Tools from:
echo   https://visualstudio.microsoft.com/downloads/
exit /b 1
:found

call "%VCVARS%" >nul 2>&1

set SRC=%~dp0killall.cpp
set OUT=%~dp0killall.exe

echo Building killall.exe ...

cl.exe /nologo /O2 /W3 /EHsc /std:c++17 /Fe:"%OUT%" "%SRC%" ^
    /link psapi.lib iphlpapi.lib wbemuuid.lib ^
          ole32.lib oleaut32.lib advapi32.lib shell32.lib

if %ERRORLEVEL% == 0 (
    echo.
    echo  Build succeeded: %OUT%
    echo  Run install.bat to add killall to PATH.
) else (
    echo.
    echo  Build FAILED - check errors above.
    exit /b 1
)

endlocal
