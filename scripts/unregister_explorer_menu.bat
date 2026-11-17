@echo off
REM ============================================================
REM  Malaz - Explorer-Kontextmenue entfernen
REM  Loescht die Eintraege, die register_explorer_menu.bat
REM  angelegt hat (HKCU, keine Adminrechte noetig).
REM ============================================================
setlocal enableextensions

echo [*] Entferne Kontextmenue-Eintraege...
reg delete "HKCU\Software\Classes\*\shell\MalazScan" /f >nul 2>&1
reg delete "HKCU\Software\Classes\Directory\shell\MalazScan" /f >nul 2>&1

echo [OK] Entfernt (oder war nicht vorhanden).
pause
exit /b 0
