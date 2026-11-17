@echo off
REM ============================================================
REM  Malaz — ClamAV-Signaturen aktualisieren (freshclam)
REM  Sucht freshclam.exe in den bekannten Installationspfaden
REM  oder auf dem PATH und fuehrt EINEN Update-Lauf aus.
REM  Rein lokal: freshclam laedt ausschliesslich von den
REM  ClamAV-Servern — Malaz selbst geht nie online.
REM ============================================================
setlocal

set "FRESHCLAM="
for %%p in (
    "C:\Program Files\ClamAV\freshclam.exe"
    "C:\Program Files (x86)\ClamAV\freshclam.exe"
    "C:\clamav\freshclam.exe"
) do (
    if exist %%p if not defined FRESHCLAM set "FRESHCLAM=%%~p"
)

if not defined FRESHCLAM (
    where freshclam.exe >nul 2>&1
    if not errorlevel 1 set "FRESHCLAM=freshclam.exe"
)

if not defined FRESHCLAM (
    echo [!] freshclam.exe nicht gefunden.
    echo     ClamAV installieren (z. B. https://www.clamav.net/downloads)
    echo     oder den Pfad oben in diesem Skript anpassen.
    pause
    exit /b 1
)

echo [*] Aktualisiere ClamAV-Signaturen mit: %FRESHCLAM%
"%FRESHCLAM%"
if errorlevel 1 (
    echo.
    echo [!] Update fehlgeschlagen — siehe Ausgabe oben.
    echo     Ohne Adminrechte ggf. --datadir auf ein beschreibbares
    echo     Verzeichnis setzen und den Pfad in config.py hinterlegen.
    pause
    exit /b 1
) else (
    echo.
    echo [OK] Signaturen aktualisiert. Status pruefen mit:
    echo     python -m malaz --clamav-status
)
pause
