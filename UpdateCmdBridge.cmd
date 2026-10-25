@echo off
setlocal
title Update Cmd Bridge

REM The running copy stages itself into %TEMP% first, so the original
REM files can be safely replaced while this script keeps running.
if /i "%~1"=="run" goto :run

set "STAGE=%TEMP%\CmdBridgeUpdate_stage.cmd"
copy /y "%~f0" "%STAGE%" >nul || goto :failstage
call "%STAGE%" run "%~dp0"
set "RC=%ERRORLEVEL%"
del "%STAGE%" >nul 2>nul
echo.
if "%RC%"=="0" (
    echo Update finished successfully.
) else (
    echo Update FAILED with code %RC%. Nothing was changed.
)
pause
exit /b %RC%

:run
set "TARGET=%~2"
set "PS=%TARGET%UpdateCmdBridge.ps1"
REM Strip the trailing backslash so PowerShell argument parsing is safe.
if "%TARGET:~-1%"=="\" set "TARGET=%TARGET:~0,-1%"
if not exist "%PS%" goto :nops
set "STAGEPS=%TEMP%\CmdBridgeUpdate_stage.ps1"
copy /y "%PS%" "%STAGEPS%" >nul || goto :failstageps
powershell -NoProfile -ExecutionPolicy Bypass -File "%STAGEPS%" -Target "%TARGET%"
set "PSRC=%ERRORLEVEL%"
del "%STAGEPS%" >nul 2>nul
exit /b %PSRC%

:nops
echo UpdateCmdBridge.ps1 was not found next to this file.
echo Extract the whole tools\cmd-bridge folder and try again.
exit /b 1

:failstage
echo Could not create a temporary copy in %TEMP%.
exit /b 1

:failstageps
echo Could not create a temporary copy of UpdateCmdBridge.ps1.
exit /b 1
