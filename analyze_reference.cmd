@echo off
setlocal EnableExtensions
cd /d "%~dp0"
chcp 65001 >nul 2>&1
set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"
echo =====================================================
echo Read-only file protection and reference assessment
echo No deletion or service termination is performed.
echo =====================================================
if exist "%~dp0reference_opendrop_20261019.json" (
    echo [INFO] Comparing with local historical report.
    py -3 -u "%~dp0verified_delete.py" --analyze-protection --target-dir "%SystemRoot%\SysWOW64" --reference-report "%~dp0reference_opendrop_20261019.json" %*
) else (
    echo [INFO] No local reference report. Live analysis only.
    py -3 -u "%~dp0verified_delete.py" --analyze-protection --target-dir "%SystemRoot%\SysWOW64" %*
)
set "CODE=%ERRORLEVEL%"
echo.
echo Exit code: %CODE%
echo Reports are in %%LOCALAPPDATA%%\IncNotebookDeleter\reports
pause
exit /b %CODE%
