@echo off
rem ============================================================
rem  Malaz Security-Check (ein Klick)
rem  Fuehrt aus: ruff (Lint) + bandit (Sicherheit) + pip-audit
rem  (Abhaengigkeiten) + pytest (Testsuite)
rem ============================================================
cd /d "%~dp0.."
set "ROOT=%CD%"
echo === Malaz Security-Check ===
echo.
if not exist .venv\Scripts\python.exe (
    echo FEHLER: venv nicht gefunden. Bitte zuerst:
    echo   python -m venv .venv
    echo   .venv\Scripts\pip install -r requirements.txt -r requirements-dev.txt
    pause
    exit /b 1
)
set PY=.venv\Scripts\python.exe
set "CHECK_TEMP=%ROOT%\.pytest-tmp\security-check"
if not exist "%CHECK_TEMP%" mkdir "%CHECK_TEMP%"

echo --- [1/4] ruff (Lint) ---
%PY% -m ruff check src scripts tests || goto :fehler
echo ruff: OK
echo.

echo --- [2/4] bandit (Sicherheits-Audit) ---
rem -ll = nur ab Medium melden. OHNE den Schalter endet bandit bei JEDEM
rem Befund mit 1 — auch bei den 41 Low-Funden (B110 try/except/pass,
rem B404 subprocess-Import), und der Check schlug durchgehend fehl,
rem obwohl die Zeile darunter "keine Medium/High" verspricht.
%PY% -m bandit -q -ll -r src -f txt || goto :fehler
echo bandit: OK (keine Medium/High)
echo.

echo --- [3/4] pip-audit (Abhaengigkeiten) ---
%PY% -m pip_audit || goto :fehler
echo pip-audit: OK
echo.

echo --- [4/4] pytest (Testsuite) ---
rem --basetemp: das System-Temp ist auf diesem Rechner gesperrt
rem (WinError 5 auf ...\Temp\pytest-of-<user>). Ohne den Schalter
rem bricht die ganze Suite mit 1299 Fehlern ab — nicht wegen des
rem Codes, sondern wegen des Ablageorts.
%PY% -m pytest -q --basetemp="%CHECK_TEMP%" || goto :fehler

echo.
echo ============================================================
echo  ALLE CHECKS BESTANDEN
echo ============================================================
pause
exit /b 0

:fehler
echo.
echo !!! CHECK FEHLGESCHLAGEN - siehe Meldung oben !!!
pause
exit /b 1
