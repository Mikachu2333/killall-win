@echo off
setlocal

set SRC=%~dp0killall.exe

if not exist "%SRC%" (
    echo ERROR: killall.exe not found. Run build.bat first.
    exit /b 1
)

:: ── Try System32 (requires admin) ────────────────────────────────────────────
copy /Y "%SRC%" "%SystemRoot%\System32\killall.exe" >nul 2>&1
if %ERRORLEVEL% == 0 (
    echo Installed to %SystemRoot%\System32\killall.exe
    echo killall is now available system-wide.
    goto :done
)

:: ── Fallback: user bin in AppData ─────────────────────────────────────────────
set USERBIN=%LOCALAPPDATA%\Programs\killall
if not exist "%USERBIN%" mkdir "%USERBIN%"
copy /Y "%SRC%" "%USERBIN%\killall.exe" >nul 2>&1

:: Add to user PATH if not already there
powershell -NoProfile -Command "
    \$p = [Environment]::GetEnvironmentVariable('PATH','User')
    if (\$p -notlike '*%USERBIN%*') {
        [Environment]::SetEnvironmentVariable('PATH', \$p + ';%USERBIN%', 'User')
        Write-Host 'Added to user PATH: %USERBIN%'
    } else {
        Write-Host 'Already in PATH'
    }
"

echo.
echo Installed to %USERBIN%\killall.exe
echo Open a new terminal and run: killall --help

:done
endlocal
