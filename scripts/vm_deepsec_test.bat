@echo off
setlocal enabledelayedexpansion
rem ============================================================
rem  Malaz Deepsec-Test (VM / isolierter Laptop)
rem
rem  SO VORBEREITEN (nur das!):
rem   1. Bringe die bösen ZIPs (MalwareBazaar, Passwort "infected")
rem      nach  C:\test\downloads   (keine andere Arbeit noetig)
rem   2. ACHTUNG: Echtzeitschutz in Windows-Sicherheit PAUSIEREN,
rem      bevor dieses Skript laeuft (Samples duerfen nicht blockiert
rem      werden). Das Skript prueft das und bricht sonst ab.
rem   3. Dieses Skript doppelklicken.
rem
rem  Das Skript macht alles andere: ZIPs entpacken, Good-Samples
rem  bereitstellen, Testlauf, Ergebnis schreiben, Nachkontrolle.
rem ============================================================

cd /d C:\test\malaz
set PYTHONPATH=src

echo ============================================================
echo  Malaz Deepsec-Test
echo ============================================================
echo.

REM ---- 1) Ordner pruefen -------------------------------------
if not exist C:\test\downloads (
    echo FEHLER: Ordner C:\test\downloads existiert nicht.
    echo Bitte anlegen und die boesen ZIPs hineinlegen.
    pause
    exit /b 1
)
set zipcount=0
for %%f in (C:\test\downloads\*.zip) do set /a zipcount+=1
if %zipcount%==0 (
    echo FEHLER: Keine ZIP-Dateien in C:\test\downloads gefunden.
    echo Lege die MalwareBazaar-ZIPs dort ab und starte erneut.
    pause
    exit /b 1
)
echo [1/6] ZIPs gefunden: %zipcount%

REM ---- 2) Echtzeitschutz-Status pruefen -----------------------
echo [2/6] Echtzeitschutz-Status pruefen ...
powershell -NoProfile -Command "$s=(Get-MpComputerStatus).RealTimeProtectionEnabled; if($s){Write-Host 'WARNUNG: Echtzeitschutz ist AN - er wuerde Samples blockieren!'; exit 1} else {Write-Host 'Echtzeitschutz: AUS - OK'}"
if errorlevel 1 (
    echo.
    echo ABBRUCH: Bitte zuerst in Windows-Sicherheit - Viren- und Bedrohungsschutz -
    echo Einstellungen - Echtzeitschutz auf AUS stellen, dann erneut starten.
    pause
    exit /b 1
)

REM ---- 3) ZIPs entpacken --------------------------------------
echo [3/6] Entpacke ZIPs nach C:\test\known_bad ...
if not exist "C:\Program Files\7-Zip\7z.exe" (
    echo FEHLER: 7-Zip nicht gefunden unter C:\Program Files\7-Zip\7z.exe
    pause
    exit /b 1
)
if exist C:\test\known_bad rmdir /s /q C:\test\known_bad
mkdir C:\test\known_bad
for %%f in (C:\test\downloads\*.zip) do (
    echo   Entpacke: %%~nxf
    "C:\Program Files\7-Zip\7z.exe" x "%%f" -oC:\test\known_bad -pinfected -y >nul
)

REM ---- 4) Good-Samples sicherstellen --------------------------
echo [4/6] Good-Samples pruefen ...
if exist C:\test\good_input (
    if exist C:\test\known_good rmdir /s /q C:\test\known_good
    mkdir C:\test\known_good
    copy /y C:\test\good_input\* C:\test\known_good\ >nul
    echo   Good-Samples aus C:\test\good_input kopiert.
) else (
    if not exist C:\test\known_good (
        echo FEHLER: Weder C:\test\known_good noch C:\test\good_input vorhanden.
        echo Lege die Good-Samples nach C:\test\good_input und starte erneut.
        pause
        exit /b 1
    )
    echo   Good-Samples vorhanden: C:\test\known_good
)

REM ---- 5) Sample-Anzahl vor dem Test --------------------------
set badcount=0
for %%f in (C:\test\known_bad\*) do set /a badcount+=1
set goodcount=0
for %%f in (C:\test\known_good\*) do set /a goodcount+=1
echo [5/6] Samples: %badcount% boesartig, %goodcount% harmlos

REM ---- 6) Testlauf --------------------------------------------
echo [6/6] Testlauf gestartet - bitte warten ...
.venv\Scripts\python.exe scripts\evaluate_corpus.py C:\test\known_bad C:\test\known_good --csv C:\test\ergebnis.csv --report C:\test\ergebnis.html
if errorlevel 1 (
    echo.
    echo FEHLER: Testlauf fehlgeschlagen ^(Exit !ERRORLEVEL!^) - Ergebnisse ungueltig.
    pause
    exit /b 1
)

REM ---- Nachkontrolle ------------------------------------------
set badcount2=0
for %%f in (C:\test\known_bad\*) do set /a badcount2+=1
echo.
if %badcount2% LSS %badcount% (
    set /a fehlend=%badcount%-%badcount2%
    echo ACHTUNG: !fehlend! Datei(en) fehlen nach dem Test in known_bad.
    echo Der Echtzeitschutz hat vermutlich zugegriffen. Betroffene Dateien
    echo stehen in der CSV mit Urteil FEHLER - Ergebnisse fuer sie ungueltig.
) else (
    echo OK: Alle %badcount% Dateien sind nach dem Test noch vorhanden.
    echo Kein AV-Eingriff - Ergebnis ist valide.
)
echo.
echo ============================================================
echo  FERTIG! Ergebnisse:
echo    CSV:   C:\test\ergebnis.csv
echo    HTML:  C:\test\ergebnis.html
echo  Bitte beide Dateien per USB zurueckbringen.
echo ============================================================
pause
