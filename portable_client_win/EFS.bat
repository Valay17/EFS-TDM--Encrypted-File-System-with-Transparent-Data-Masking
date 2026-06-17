@echo off
setlocal
set "DIR=%~dp0"
set "PATH=%DIR%libs;%PATH%"
if "%~1"=="" (
    "%DIR%libs\EFS_bin.exe" web-login
    pause
) else (
    "%DIR%libs\EFS_bin.exe" %*
    if errorlevel 1 exit /b %errorlevel%
)
