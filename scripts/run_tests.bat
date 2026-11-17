@echo off
REM Malaz - Test-Suite ausführen
setlocal
cd /d "%~dp0\.."

REM venv-Python bevorzugen, sonst System-Python
set "PY=python"
if exist ".venv\Scripts\python.exe" set "PY=.venv\Scripts\python.exe"
set "TEST_TEMP=%CD%\.pytest-tmp\run-tests"
if not exist "%TEST_TEMP%" mkdir "%TEST_TEMP%"

"%PY%" -m pytest -q --basetemp="%TEST_TEMP%"
if errorlevel 1 (
    echo Tests fehlgeschlagen.
    exit /b 1
)
echo Alle Tests bestanden.
endlocal
