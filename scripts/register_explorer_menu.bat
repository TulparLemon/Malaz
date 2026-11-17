@echo off
REM ============================================================
REM  Malaz - Explorer-Kontextmenue eintragen (portable)
REM ------------------------------------------------------------
REM  Traegt "Mit Malaz pruefen" fuer Dateien und Ordner in den
REM  BENUTZER-Zweig der Registry ein (HKCU, keine Adminrechte).
REM  Der Eintrag zeigt auf die Malaz.exe neben diesem Skript
REM  bzw. auf den ersten gefundenen Build unter dist\.
REM
REM  Fuer Portable-Nutzung: dieses Skript ZUSAMMEN MIT Malaz.exe
REM  in einen Ordner kopieren und dort ausfuehren. Wechselt der
REM  Laufwerksbuchstabe (USB-Stick), das Skript einfach erneut
REM  ausfuehren - es aktualisiert den Pfad.
REM
REM  Entfernen: unregister_explorer_menu.bat
REM ============================================================
setlocal enableextensions

REM -- Malaz.exe suchen: zuerst neben dem Skript (Portable), dann dist\.
set "EXE=%~dp0Malaz.exe"
if not exist "%EXE%" set "EXE=%~dp0..\dist\Malaz-Standalone\Malaz.exe"
if not exist "%EXE%" set "EXE=%~dp0..\dist\Malaz.exe"
if not exist "%EXE%" (
    echo [!] Malaz.exe nicht gefunden.
    echo     Entweder neben dieses Skript legen oder erst mit
    echo     scripts\build_nuitka.bat bauen.
    pause
    exit /b 1
)

REM cmd kann '&' in Variablen innerhalb gemischter Quoting-Zustaende nicht
REM sicher durchreichen; solche Pfade brechen die reg add Zeilen. Deutlich
REM ablehnen statt halbfertige Eintraege zu hinterlassen.
if not "%EXE:&=%"=="%EXE%" (
    echo [!] Der Pfad enthaelt ein '^&' ^(z.B. "Tools ^& More"^).
    echo     Bitte den Ordner ohne Sonderzeichen umbenennen und erneut versuchen.
    pause
    exit /b 1
)

echo [*] Registriere Kontextmenue fuer: %EXE%

REM -- Dateien: Rechtsklick auf jede beliebige Datei -------------------
reg add "HKCU\Software\Classes\*\shell\MalazScan" /ve /d "Mit Malaz pruefen" /f >nul || goto :fail
reg add "HKCU\Software\Classes\*\shell\MalazScan" /v "Icon" /d "\"%EXE%\",0" /f >nul || goto :fail
reg add "HKCU\Software\Classes\*\shell\MalazScan\command" /ve /d "\"%EXE%\" \"%%1\"" /f >nul || goto :fail

REM -- Ordner: Rechtsklick auf einen Ordner scannt seinen Inhalt -------
reg add "HKCU\Software\Classes\Directory\shell\MalazScan" /ve /d "Mit Malaz pruefen" /f >nul || goto :fail
reg add "HKCU\Software\Classes\Directory\shell\MalazScan" /v "Icon" /d "\"%EXE%\",0" /f >nul || goto :fail
reg add "HKCU\Software\Classes\Directory\shell\MalazScan\command" /ve /d "\"%EXE%\" \"%%V\"" /f >nul || goto :fail

echo.
echo [OK] Eingetragen. Rechtsklick auf eine Datei oder einen Ordner
echo      zeigt jetzt "Mit Malaz pruefen". Die GUI oeffnet sich und
echo      scannt automatisch.
echo      Entfernen: unregister_explorer_menu.bat
pause
exit /b 0

:fail
echo [!] Registry-Eintrag fehlgeschlagen.
pause
exit /b 1
