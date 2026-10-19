@echo off
setlocal EnableDelayedExpansion
chcp 65001 >nul 2>&1
cd /d "%~dp0"
set "LOG=%TEMP%\inc-notebook-deleter-diagnostic.log"
> "%LOG%" echo Read-only Inc Notebook Deleter startup check
>> "%LOG%" echo Started: %DATE% %TIME%
echo [1] Python launcher...
where py >> "%LOG%" 2>&1
py -3 --version >> "%LOG%" 2>&1
echo py version exit code: !ERRORLEVEL!>> "%LOG%"
where python >> "%LOG%" 2>&1
python --version >> "%LOG%" 2>&1
echo python version exit code: !ERRORLEVEL!>> "%LOG%"
echo [2] Python interpreter validation...
set "PY_EXEC="
for /f "delims=" %%I in ('py -3 -c "print(733445)" 2^>nul') do (
    if "%%I"=="733445" set "PY_EXEC=py -3"
)
if not defined PY_EXEC (
    for /f "delims=" %%I in ('python -c "print(733445)" 2^>nul') do (
        if "%%I"=="733445" set "PY_EXEC=python"
    )
)
if not defined PY_EXEC (
    echo ERROR: Python is unavailable or is a stub that prints "Python".>> "%LOG%"
    echo Check: where python, py -3 --version, python -c "print(123)">> "%LOG%"
) else (
    echo Verified interpreter: !PY_EXEC!>> "%LOG%"
    if exist "bulk_delete_agent_targets.py" (
        !PY_EXEC! -u "bulk_delete_agent_targets.py" --diagnose >> "%LOG%" 2>&1
        echo Python script exit code: !ERRORLEVEL!>> "%LOG%"
    ) else (
        echo bulk_delete_agent_targets.py not found.>> "%LOG%"
    )
)
echo [3] Packaged EXE...
set "EXE=inc-notebook-deleter.exe"
if not exist "!EXE!" set "EXE=dist\inc-notebook-deleter.exe"
if exist "!EXE!" (
    "!EXE!" --diagnose >> "%LOG%" 2>&1
    echo EXE exit code: !ERRORLEVEL!>> "%LOG%"
) else (
    echo inc-notebook-deleter.exe not found.>> "%LOG%"
)
echo.
echo -------- DIAGNOSTIC RESULTS --------
type "%LOG%"
echo ------------------------------------
echo Log: %LOG%
echo No files were deleted.
echo.
pause
