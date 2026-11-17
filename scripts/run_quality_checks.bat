@echo off
REM ============================================================
REM  Malaz Quality Gate — vor jedem Update/Release ausfuehren
REM  Ruft scripts\run_quality_checks.py auf (pytest, ruff, bandit,
REM  mypy, pip check, pip-audit). Exit-Code 0 = alles gruen.
REM ============================================================
cd /d "%~dp0.."

if not exist ".venv\Scripts\python.exe" (
    echo [!] Virtuelle Umgebung nicht gefunden. Bitte zuerst:
    echo     python -m venv .venv
    echo     .venv\Scripts\activate
    echo     pip install -r requirements.txt
    echo     pip install ruff bandit mypy coverage pytest-cov pip-audit
    pause
    exit /b 1
)

".venv\Scripts\python.exe" scripts\run_quality_checks.py %*
exit /b %ERRORLEVEL%
