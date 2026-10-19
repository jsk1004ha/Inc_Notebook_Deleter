@echo off
setlocal EnableExtensions
cd /d "%~dp0"
chcp 65001 >nul 2>&1
set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"
if exist "%~dp0reference_opendrop_20261019.json" (
    echo [INFO] Local reference report found. SHA256 verification enabled.
    py -3 -u "%~dp0verified_delete.py" --reference-report "%~dp0reference_opendrop_20261019.json" %*
) else (
    echo [INFO] No local reference report. Using default file checks.
    py -3 -u "%~dp0verified_delete.py" %*
)
set "CODE=%ERRORLEVEL%"
echo.
echo Program exit code: %CODE%
if "%~1"=="" pause
exit /b %CODE%
