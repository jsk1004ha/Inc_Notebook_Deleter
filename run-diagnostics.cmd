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
echo [2] Python script...
if exist "bulk_delete_agent_targets.py" (
    py -3 -u "bulk_delete_agent_targets.py" --diagnose >> "%LOG%" 2>&1
    set "PY_RESULT=!ERRORLEVEL!"
    echo py script exit code: !PY_RESULT!>> "%LOG%"
    if not "!PY_RESULT!"=="0" (
        python -u "bulk_delete_agent_targets.py" --diagnose >> "%LOG%" 2>&1
        echo python fallback exit code: !ERRORLEVEL!>> "%LOG%"
    )
) else (
    echo bulk_delete_agent_targets.py not found.>> "%LOG%"
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
