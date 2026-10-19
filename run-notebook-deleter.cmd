@echo off
setlocal EnableExtensions DisableDelayedExpansion
cd /d "%~dp0"

rem A stub can echo "Python" without running Python.
rem Require proof that -c executed a real Python statement.
set "INC_PYTHON="
for /f "delims=" %%I in ('py -3 -c "print(733445)" 2^>nul') do (
    if "%%I"=="733445" set "INC_PYTHON=py -3"
)
if not defined INC_PYTHON (
    for /f "delims=" %%I in ('python -c "print(733445)" 2^>nul') do (
        if "%%I"=="733445" set "INC_PYTHON=python"
    )
)
if not defined INC_PYTHON (
    echo [ERROR] A working Python interpreter was not found.
    echo Your 'python' command may be a placeholder that only prints "Python".
    echo Try: py -3 --version
    echo Try: where python
    echo Install Python 3.10+ from https://www.python.org/downloads/windows/
    echo Or use the separately built EXE.
    pause
    exit /b 2
)

%INC_PYTHON% -c "import sys;assert sys.version_info.major==3 and sys.version_info.minor>=10" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python 3.10 or later is required.
    %INC_PYTHON% --version
    pause
    exit /b 2
)
if not exist "%~dp0bulk_delete_agent_targets.py" (
    echo [ERROR] bulk_delete_agent_targets.py is missing next to this launcher.
    pause
    exit /b 3
)

set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"
echo [INFO] Verified runtime: %INC_PYTHON%
%INC_PYTHON% -u "%~dp0bulk_delete_agent_targets.py" %*
set "INC_EXIT=%ERRORLEVEL%"
echo.
echo [INFO] Exit code: %INC_EXIT%
if "%~1"=="" pause
exit /b %INC_EXIT%
