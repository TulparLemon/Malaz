@echo off
REM ============================================================
REM  Malaz - Neo23x0 signature-base Regeln beschaffen (DRL 1.1)
REM  Einmaliger, bewusster Nutzerlauf: laedt das Regel-Archiv von
REM  der festen Quell-URL und installiert es nach
REM  rules\yara\signature_base\ (NICHT nach external\ - das loescht
REM  der ReversingLabs-Update).
REM  Nur dieser Aufruf geht online; der Scan bleibt offline.
REM  Malaz liefert die Regeln nicht mit aus - bei Weitergabe gelten
REM  die Attributionspflichten der DRL 1.1.
REM ============================================================
setlocal

set "PY="
if exist "%~dp0..\.venv\Scripts\python.exe" set "PY=%~dp0..\.venv\Scripts\python.exe"
if not defined PY (
    where py >nul 2>&1
    if not errorlevel 1 set "PY=py"
)
if not defined PY (
    where python >nul 2>&1
    if not errorlevel 1 set "PY=python"
)

if not defined PY (
    echo [!] Python nicht gefunden.
    echo     Bitte die virtuelle Umgebung anlegen/aktivieren oder Python
    echo     auf den PATH legen, dann dieses Skript erneut starten.
    pause
    exit /b 1
)

echo [*] Beschaffe Regeln mit: %PY%
"%PY%" "%~dp0update_signature_base.py"
if errorlevel 1 (
    echo.
    echo [!] Abruf fehlgeschlagen - siehe Ausgabe oben.
    echo     Ohne Internetzugang ist das erwartbar; Malaz arbeitet ohne
    echo     diese Regeln weiter.
    pause
    exit /b 1
) else (
    echo.
    echo [OK] Regeln installiert. Stand pruefen mit:
    echo     "%PY%" "%~dp0update_signature_base.py" --status
)
pause
