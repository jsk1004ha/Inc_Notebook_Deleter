@echo off
setlocal
cd /d "%~dp0"
chcp 65001 >nul 2>&1
set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"
echo =========================================================
echo Inc Notebook Deleter - Read-only Windows diagnostics
echo This mode does NOT delete files or stop any services.
echo =========================================================
py -3 -u "%~dp0verified_delete.py" --analyze-protection --target-dir "%SystemRoot%\SysWOW64" %*
set "CODE=%ERRORLEVEL%"
echo.
echo Exit code: %CODE%
echo See the JSON/TXT report locations above.
pause
exit /b %CODE%
