@echo off
setlocal
title Cmd Bridge - Free Model Radar

set "SCRIPT=%~dp0cmd_bridge.py"
set "PY="

if exist "%LOCALAPPDATA%\FreeModelRadar\.venv\Scripts\python.exe" set "PY=%LOCALAPPDATA%\FreeModelRadar\.venv\Scripts\python.exe"

if not defined PY where py >nul 2>nul && set "PY=py -3"
if not defined PY where python >nul 2>nul && set "PY=python"

if not defined PY goto :nopython
if not exist "%SCRIPT%" goto :noscript

%PY% "%SCRIPT%" %*
set "RC=%ERRORLEVEL%"
if "%RC%"=="0" exit /b 0
echo.
echo Cmd Bridge exited with code %RC%.
pause
exit /b %RC%

:noscript
echo cmd_bridge.py was not found next to this launcher:
echo %SCRIPT%
echo Extract the whole tools\cmd-bridge folder and try again.
pause
exit /b 1

:nopython
echo Python was not found. Install Python 3.11+ from
echo https://www.python.org/downloads/ and run this file again.
pause
exit /b 1
