@echo off
setlocal enabledelayedexpansion
rem ============================================================
rem  Malaz All-in-One Test (PORTABLE - VM / isolierter Laptop)
rem
rem  Komplettlauf OHNE Python: portablen Malaz-Ordner entpacken
rem  (z.B. nach Desktop), boese ZIPs + Good-Files ablegen, dieses
rem  Skript doppelklicken. Basis: docs/INSTALLATION.md.
rem
rem  VORBEREITUNG (nur das):
rem   1. VM/Laptop frisch aufsetzen: Windows aktuell, KEIN Firmennetz,
rem      keine Cloud-Sync. Netz nur fuer den Sample-Download.
rem   2. 7-Zip installieren (zum Entpacken der Passwort-ZIPs noetig):
rem      https://www.7-zip.org  (Standardpfad C:\Program Files\7-Zip)
rem   3. Boese ZIPs (MalwareBazaar, Passwort "infected") nach
rem      C:\test\downloads legen (50-100 Stueck, gemischt PDF/
rem      Office/PE/Archive/EML).
rem   4. Harmlose Vergleichsdateien nach C:\test\good_input
rem      (Dokumente, Installer, PDFs).
rem   5. Dieses Skript doppelklicken.
rem
rem  Das Skript macht alles andere: Defender-Status pruefen, ZIPs
rem  entpacken, EICAR-Lebendigkeitstest, Korpus-Messung ueber
rem  Malaz.exe --evaluate, Nachkontrolle, Ergebnisse schreiben.
rem
rem  SICHERHEIT: Alles laeuft rein statisch. Nichts wird ausge-
rem  fuehrt oder geoeffnet. Trotzdem: nur in der VM/isolierten
rem  Umgebung laufen lassen, niemals am Arbeits-PC.
rem ============================================================

rem Der Ordner dieses Skripts IST der portable Malaz-Ordner.
cd /d "%~dp0"

echo ============================================================
echo  Malaz All-in-One Test (Portable: EICAR + Korpus)
echo ============================================================
echo.

REM ---- 0) Malaz.exe vorhanden? --------------------------------
if not exist "%~dp0Malaz.exe" (
    echo FEHLER: Malaz.exe nicht neben diesem Skript gefunden.
    echo Das Skript muss IM entpackten Malaz-Ordner liegen und
    echo von dort gestartet werden.
    pause
    exit /b 1
)

REM ---- 1) Ordner + ZIPs pruefen --------------------------------
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
    pause
    exit /b 1
)
echo [1/8] ZIPs gefunden: %zipcount%

REM ---- 2) Echtzeitschutz-Status protokollieren -----------------
echo [2/8] Defender-Echtzeitschutz-Status ...
powershell -NoProfile -Command "$s=(Get-MpComputerStatus).RealTimeProtectionEnabled; Write-Host ('Echtzeitschutz: ' + $(if($s){'AN'}else{'AUS'}))"
rem Bewusst KEIN Abbruch hier: Der Test misst auch, wie sich Malaz
rem verhaelt, wenn der Echtzeitschutz Samples blockiert (die Nach-
rem kontrolle in Schritt 8 deckt das auf). Fuer die sauberste
rem Messung: Echtzeitschutz vorher eine Weile AUS stellen.

REM ---- 3) ZIPs entpacken ---------------------------------------
echo [3/8] Entpacke ZIPs nach C:\test\known_bad ...
if not exist "C:\Program Files\7-Zip\7z.exe" (
    echo FEHLER: 7-Zip nicht gefunden unter C:\Program Files\7-Zip\7z.exe
    echo Bitte 7-Zip installieren: https://www.7-zip.org
    pause
    exit /b 1
)
if exist C:\test\known_bad rmdir /s /q C:\test\known_bad
mkdir C:\test\known_bad
for %%f in (C:\test\downloads\*.zip) do (
    echo   Entpacke: %%~nxf
    "C:\Program Files\7-Zip\7z.exe" x "%%f" -oC:\test\known_bad -pinfected -y >nul
)

REM ---- 4) Good-Samples sicherstellen ---------------------------
echo [4/8] Good-Samples pruefen ...
if exist C:\test\good_input (
    if exist C:\test\known_good rmdir /s /q C:\test\known_good
    mkdir C:\test\known_good
    copy /y C:\test\good_input\* C:\test\known_good\ >nul
    echo   Good-Samples aus C:\test\good_input kopiert.
) else (
    if not exist C:\test\known_good (
        echo FEHLER: Weder C:\test\known_good noch C:\test\good_input vorhanden.
        pause
        exit /b 1
    )
    echo   Good-Samples vorhanden: C:\test\known_good
)

REM ---- 5) EICAR-Lebendigkeitstest (ohne Python) ----------------
echo [5/8] EICAR-Lebendigkeitstest - echte Defender-Reaktionstest ...
rem Die harmlose EICAR-Testdatei wird zur Laufzeit aus Zeichencodes
rem zusammengesetzt. Der Teststring steht bewusst NICHT komplett in
rem dieser Skriptdatei, sonst wuerde ein Virenscanner dieses Skript
rem selbst in Quarantaene nehmen.
mkdir C:\test\eicar_probe 2>nul
powershell -NoProfile -Command "[IO.File]::WriteAllText('C:\test\eicar_probe\eicar.com', -join(88,53,79,33,80,37,64,65,80,91,52,92,80,90,88,53,52,40,80,94,41,55,67,67,41,55,125,36,69,73,67,65,82,45,83,84,65,78,68,65,82,68,45,65,78,84,73,86,73,82,85,83,45,84,69,83,84,45,70,73,76,69,33,36,72,43,72,42 | ForEach-Object {[char]$_}))"
rem Dem Echtzeitschutz Zeit zum Reagieren geben.
ping -n 4 127.0.0.1 >nul
if exist C:\test\eicar_probe\eicar.com (
    del /q C:\test\eicar_probe\eicar.com 2>nul
    echo HINWEIS: Defender hat die EICAR-Testdatei NICHT entfernt.
    echo Echtzeitschutz vermutlich AUS oder nicht aktiv - die
    echo AV-Spalten der Ergebnisse sind dann fragwuerdig.
) else (
    echo OK: Defender hat die EICAR-Testdatei erkannt und entfernt.
)
rmdir /s /q C:\test\eicar_probe 2>nul

REM ---- 6) Sample-Anzahl vor dem Test ---------------------------
REM Rekursive Zaehlung (dir /s): die Auswertung scannt ebenfalls
REM rekursiv (expand_scan_paths) - eine flache Zaehlung wuerde
REM Samples in Unterordnern uebersehen und die Nachkontrolle
REM falsch beruhigen.
set badcount=0
for /f %%c in ('dir /s /b /a:-d C:\test\known_bad 2^>nul ^| find /c /v ""') do set badcount=%%c
set goodcount=0
for /f %%c in ('dir /s /b /a:-d C:\test\known_good 2^>nul ^| find /c /v ""') do set goodcount=%%c
echo [6/8] Samples: %badcount% boesartig, %goodcount% harmlos
if %badcount%==0 (
    echo FEHLER: known_bad ist leer - Entpacken fehlgeschlagen?
    pause
    exit /b 1
)

REM ---- 7) Korpus-Messung ueber Malaz.exe -----------------------
echo [7/8] Korpus-Messung gestartet - bitte warten ...
"%~dp0Malaz.exe" --evaluate C:\test\known_bad C:\test\known_good --csv C:\test\ergebnis.csv --report C:\test\ergebnis.html
set "MALAZ_RC=!errorlevel!"
if not "%MALAZ_RC%"=="0" (
    echo.
    echo FEHLER: Malaz.exe wurde mit Code %MALAZ_RC% beendet - Details oben.
    echo Die CSV/Report sind moeglicherweise unvollstaendig.
) else (
    echo OK: Messung beendet, Exit-Code 0.
)

REM ---- 8) Nachkontrolle ----------------------------------------
set badcount2=0
for /f %%c in ('dir /s /b /a:-d C:\test\known_bad 2^>nul ^| find /c /v ""') do set badcount2=%%c
echo [8/8] Nachkontrolle ...
if %badcount2% LSS %badcount% (
    set /a fehlend=%badcount%-%badcount2%
    echo !!! ACHTUNG: !fehlend! Datei(en) fehlen nach dem Test in known_bad.
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
echo  Beide per USB zurueckbringen, dann:
echo    - Samples loeschen ODER VM-Snapshot zuruecksetzen
echo    - Host war nie betroffen
echo ============================================================
pause
