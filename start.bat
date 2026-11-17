@echo off
REM ============================================================
REM  Malaz — GUI starten (Doppelklick)
REM ============================================================
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo.
    echo [!] Virtuelle Umgebung nicht gefunden.
    echo     Bitte EINMALIG in der Eingabeaufforderung ausfuehren:
    echo.
    echo       python -m venv .venv
    echo       .venv\Scripts\activate
    echo       pip install -r requirements.txt
    echo.
    pause
    exit /b 1
)

REM src-Layout bekannt machen und GUI ohne Konsolenfenster starten
set "PYTHONPATH=%~dp0src"
start "" ".venv\Scripts\pythonw.exe" -m malaz
