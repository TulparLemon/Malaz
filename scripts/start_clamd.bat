@echo off
REM ============================================================
REM  Malaz - clamd-Daemon starten (optionaler Turbo-Modus)
REM ------------------------------------------------------------
REM  OHNE Daemon:  jeder Scan startet clamscan neu und laedt die
REM                ~170 MB Signaturbasis erneut -> ~16 s pro Datei.
REM  MIT Daemon:   die Basis liegt einmal im Speicher -> Millisekunden.
REM                Gemessen: 15000 ms -> 41 ms.
REM
REM  Kein Dienst, keine Adminrechte: clamd laeuft als normaler
REM  Prozess und lauscht NUR auf 127.0.0.1:3310.
REM
REM  Aufruf:
REM    scripts\start_clamd.bat          -> im Vordergrund (Fenster offen lassen)
REM    scripts\start_clamd.bat /min     -> minimiert starten
REM
REM  Beenden: Fenster schliessen bzw. Strg+C.
REM ============================================================
setlocal enableextensions

set "ROOT=%~dp0.."
set "CONF=%LocalAppData%\ClamAV\clamd.conf"
set "CLAMD=C:\Program Files\ClamAV\clamd.exe"
if not exist "%CLAMD%" set "CLAMD=C:\Program Files (x86)\ClamAV\clamd.exe"

if not exist "%CLAMD%" (
    echo [!] clamd.exe nicht gefunden.
    echo     Erwartet unter "C:\Program Files\ClamAV\".
    echo     ClamAV installieren: https://www.clamav.net/downloads
    pause
    exit /b 1
)

set "PY=%ROOT%\.venv\Scripts\python.exe"
if not exist "%PY%" set "PY=python"

if not exist "%CONF%" (
    echo [clamd] Keine Konfiguration gefunden - erzeuge sie...
    "%PY%" -c "import sys; sys.path.insert(0, r'%ROOT%\src'); from malaz.analysis.clamav_update import ensure_clamd_conf; print('  erzeugt:', ensure_clamd_conf())" 2>nul
)

if not exist "%CONF%" (
    echo [!] clamd.conf konnte nicht erzeugt werden: %CONF%
    echo     Diese Datei beschreibt, wie clamdscan den Daemon erreicht.
    echo     Ohne sie findet clamdscan den Daemon nicht und Malaz faellt
    echo     still auf den langsamen clamscan-Weg zurueck.
    echo.
    echo     Manuell anlegen mit diesem Inhalt:
    echo       DatabaseDirectory %%LocalAppData%%\ClamAV\db
    echo       TCPSocket 3310
    echo       TCPAddr 127.0.0.1
    echo       ConnectTimeout 1
    echo       Foreground yes
    echo       EnableShutdownCommand no
    echo       EnableReloadCommand no
    pause
    exit /b 1
)

echo [clamd] Starte Daemon (laedt die Signaturbasis, dauert ~30-60 s)...
echo [clamd] Config: %CONF%
echo [clamd] Lauscht nur auf 127.0.0.1:3310 - nicht im Netz erreichbar.
echo [clamd] Fenster offen lassen; Schliessen beendet den Daemon.
echo.

if /i "%~1"=="/min" (
    start "Malaz clamd" /min "%CLAMD%" --config-file="%CONF%"
) else (
    "%CLAMD%" --config-file="%CONF%"
)

endlocal
