@echo off
REM ============================================================
REM  Malaz — Headless-Scan (Kommandozeile)
REM  Nutzung:  scan.bat DATEI [DATEI ...]
REM  Erzeugt automatisch malaz_report_<Datum>.html im Projektordner.
REM ============================================================
setlocal
set "PSModulePath="
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo [!] Virtuelle Umgebung nicht gefunden. Siehe start.bat.
    pause
    exit /b 1
)

if "%~1"=="" (
    echo Nutzung: scan.bat DATEI [DATEI ...]
    exit /b 1
)

REM Datum regionunabhaengig als yyyy-mm-dd ermitteln (PowerShell ist auf
REM jedem Windows 10/11 vorhanden; %DATE% haengt von der Ländereinstellung ab).
for /f %%i in ('powershell -NoProfile -Command "Get-Date -Format yyyy-MM-dd"') do set "TODAY=%%i"
set "REPORT=%~dp0malaz_report_%TODAY%.html"

set "PYTHONPATH=%~dp0src"
".venv\Scripts\python.exe" -m malaz --cli %* --report "%REPORT%"
set "RC=%ERRORLEVEL%"
echo.
echo Report: %REPORT%
if not "%RC%"=="0" echo [!] Scan-Exitcode %RC% (2=RED, 3=unvollstaendig) - siehe Ausgabe/Report.
pause
exit /b %RC%
