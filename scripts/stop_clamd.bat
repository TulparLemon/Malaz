@echo off
REM ============================================================
REM  Malaz - clamd-Daemon beenden
REM ------------------------------------------------------------
REM  Gegenstueck zu start_clamd.bat. Malaz startet den Daemon
REM  beim Programmstart selbst (analysis/clamav_update.start_clamd)
REM  und beendet ihn ABSICHTLICH NICHT: er soll die Signaturen
REM  ueber Programmstarts hinweg im Speicher halten. Sonst zahlte
REM  jeder Start die ~14 s Ladezeit erneut.
REM
REM  Der Preis dafuer: danach laeuft ein unsichtbarer Prozess mit
REM  rund 170 MB im Speicher. Dieses Skript ist der Weg zurueck.
REM
REM  Aufruf:
REM    scripts\stop_clamd.bat
REM ============================================================
setlocal enableextensions

echo [clamd] Suche laufende Daemon-Prozesse...
tasklist /fi "imagename eq clamd.exe" 2>nul | findstr /i "clamd.exe" >nul
if errorlevel 1 (
    echo [clamd] Kein clamd-Prozess gefunden - nichts zu tun.
    exit /b 0
)

taskkill /im clamd.exe /f 2>nul
if errorlevel 1 (
    echo [!] Beenden fehlgeschlagen. Prozess im Task-Manager pruefen
    echo     oder: taskkill /im clamd.exe /f
    exit /b 1
)

echo [clamd] Beendet. Der naechste Malaz-Start startet ihn wieder -
echo         dann sind die ersten Scans noch langsam (~1 s), bis er
echo         die Signaturen geladen hat.
exit /b 0
