@echo off
REM ============================================================
REM  Malaz - Nuitka Build (native Windows-EXE)
REM ------------------------------------------------------------
REM  Aufruf:
REM    scripts\build_nuitka.bat              -> Ordner-Build + ZIP (Standalone, Standard)
REM    scripts\build_nuitka.bat standalone   -> Ordner-Build + ZIP
REM    scripts\build_nuitka.bat onefile      -> Einzelne One-File-EXE
REM    scripts\build_nuitka.bat standalone Malaz-2.0
REM                                          -> Ordner-Build + ZIP unter
REM                                             eigenem Namen (der vorhandene
REM                                             Stand bleibt unberuehrt)
REM
REM  Der Standalone-Modus (--standalone) vermeidet den selbstentpackenden
REM  One-File-Stub, der bei ML-Heuristiken (VirusTotal & Co.) als "Packer"
REM  auffaellt; dafuer entsteht ein Ordner statt einer einzelnen Datei.
REM
REM  Die PDF-Pipeline nutzt pikepdf (MPL-2.0, GPL-vertraeglich).
REM  Nuitka kompiliert das Paket regulaer; nur die qpdf-DLLs liegen als
REM  Daten (pikepdf.libs) bei.
REM
REM  Voraussetzungen:
REM    - virtuelles Umfeld unter .venv (wird hier direkt genutzt)
REM    - pip install nuitka
REM    - KEIN manueller C-Compiler noetig: --assume-yes-for-downloads laesst
REM      Nuitka MinGW-w64 (GCC) selbst nachladen, falls keiner gefunden wird.
REM      Ein vorhandenes MSVC/MinGW wird bevorzugt.
REM      Achtung: 'where cl gcc' beweist nichts - ein fehlender PATH-Treffer
REM      heisst nicht, dass kein Compiler verfuegbar ist.
REM ============================================================
setlocal enableextensions
REM PowerShell 7 setzt PSModulePath ohne System32\WindowsPowerShell\v1.0\Modules;
REM beim Leeren baut powershell.exe seinen Standard-Modulpfad (Compress-Archive) neu auf.
set "PSModulePath="
REM Der Smoke-Test gibt die CLI-Ausgabe aus, und die enthaelt U+2212
REM ("-" als Minuszeichen). Auf dem cp1252-stdout eines Scheduled-Task-
REM Kontos wirft das einen UnicodeEncodeError und bricht den Build ab,
REM bevor Zip und Gates laufen (gemessen).
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
chcp 65001 >nul

REM -- Projektroot und venv-Python ----------------------------------------
set "ROOT=%~dp0.."
pushd "%ROOT%"
set "ROOT=%CD%"
set "PY=%ROOT%\.venv\Scripts\python.exe"
set "MODE=%~1"
if not defined MODE set "MODE=standalone"
if /i not "%MODE%"=="standalone" if /i not "%MODE%"=="onefile" (
    echo FEHLER: Unbekannter Modus "%MODE%" ^(erlaubt: standalone, onefile^).
    popd
    exit /b 1
)
REM Name des Ausgabeordners/Zips. Frei waehlbar, damit ein Teststand NEBEN
REM dem vorhandenen liegen kann, statt ihn zu ersetzen.
set "NAME=%~2"
if "%NAME%"=="" set "NAME=Malaz-Standalone"
REM Version aus EINER Quelle: src/malaz/__init__.py. Eine zweite Angabe hier
REM wuerde irgendwann auseinanderlaufen - die Fensteranzeige und die
REM Dateieigenschaften kaemen sich dann in die Quere.
if not exist "%PY%" (
    echo venv-Python nicht gefunden: %PY%
    echo Bitte zuerst das virtuelle Umfeld anlegen und die Anforderungen installieren.
    popd
    exit /b 1
)

set "APPVER4="
for /f "usebackq delims=" %%v in (`.venv\Scripts\python.exe -c "import re,sys; sys.path.insert(0,'src'); import malaz; v=malaz.__version__.split('+',1)[0]; nums=[min(65535,max(0,int(x))) for x in re.findall(r'\d+',v)][:4]; nums+=[0]*(4-len(nums)); print('.'.join(map(str,nums)))"`) do set "APPVER4=%%v"
if not defined APPVER4 (
    echo Version konnte nicht aus src\malaz\__init__.py berechnet werden.
    popd
    exit /b 1
)

REM -- NAME haerten -------------------------------------------------------
REM %NAME% wird zu einem Pfad unter dist UND weiter unten zu einem
REM Loeschziel (rmdir /s /q). "." , ".." , Pfadtrenner oder Sonderzeichen
REM wuerden aus dist ausbrechen bzw. die Kommandozeile zerlegen. Darum VOR
REM jedem rmdir pruefen; der berechnete Pfad wird danach zusaetzlich gegen
REM dist abgeglichen (Realpath, deckt auch Symlinks ab).
"%PY%" -c "import re,sys; n=sys.argv[1]; sys.exit(0 if re.fullmatch(r'^[A-Za-z0-9._-]+$', n) and n not in {'.','..'} else 1)" "%NAME%"
if errorlevel 1 (
    echo FEHLER: Ungueltiger NAME.
    echo Erlaubt sind nur Buchstaben, Ziffern, Punkt, Unterstrich und Bindestrich;
    echo "." und ".." sind gesperrt.
    popd
    exit /b 1
)
set "TARGET=%ROOT%\dist\%NAME%"
"%PY%" -c "import os,sys; b=os.path.realpath(sys.argv[1]); t=os.path.realpath(sys.argv[2]); sys.exit(0 if os.path.dirname(t)==b else 1)" "%ROOT%\dist" "%TARGET%"
if errorlevel 1 (
    echo FEHLER: Ziel liegt nicht unter %ROOT%\dist.
    popd
    exit /b 1
)

echo [1/2] Pruefe Nuitka...
"%PY%" -c "import importlib.metadata as m; print(m.version('nuitka'))" >nul 2>&1
if errorlevel 1 (
    echo Nuitka nicht gefunden. Installation: pip install nuitka
    popd
    exit /b 1
)

REM pikepdf.libs enthaelt die nativen qpdf-DLLs (delvewheel-Layout); das
REM Verzeichnis ist kein Python-Paket, wird daher als Daten gebuendelt.
set "PKLIBS=%ROOT%\.venv\Lib\site-packages\pikepdf.libs"
set "ZXLIBS=%ROOT%\.venv\Lib\site-packages\zxing_cpp.libs"
if not exist "%PKLIBS%" (
    echo pikepdf.libs nicht gefunden: %PKLIBS%
    popd
    exit /b 1
)

REM -- YARA-Regeln vorkompilieren (.yarc) ----------------------------------
REM Die Engine laedt .yarc bevorzugt (schnellerer Anwendungsstart) und die
REM Dateien reisen ueber --include-data-dir=..\rules automatisch mit.
REM
REM AUSGENOMMEN: die beiden Dritt-Feeds rules/yara/external (ReversingLabs,
REM MIT) und rules/yara/signature_base (Neo23x0, DRL 1.1). Sie sind reine
REM Laufzeit-Artefakte einer bewussten Nutzeraktion, gitignored, und duerfen
REM nicht in eine Distribution wandern -- das ist die ausdrueckliche Zusage
REM in core/yara_update.py, core/yara_signature_base.py und docs/INSTALLATION.md (Abschnitt
REM 6b/8e): "Malaz liefert diese Regeln NICHT mit aus". Ohne die beiden
REM --noinclude-data-files-Zeilen packt Nuitka sie mit ein (gemessen: 14
REM Datendateien unter ..\rules, davon 4 MB ReversingLabs + 14 MB signature-base).
echo [+] Kompiliere YARA-Regeln vor...
"%PY%" "%ROOT%\scripts\compile_yara.py" --force
if errorlevel 1 (
    echo YARA-Vorkompilierung fehlgeschlagen.
    popd
    exit /b 1
)

REM -- Modus-spezifische Schalter ------------------------------------------
if /i "%MODE%"=="standalone" (
    set "MODESWITCH=--standalone"
    echo [2/2] Kompiliere Standalone-Build ^(Ordner, weniger ML-Trigger^)...
) else (
    set "MODESWITCH=--onefile"
    echo [2/2] Kompiliere One-File-EXE...
)

pushd "%ROOT%\src"
"%PY%" -m nuitka ^
    %MODESWITCH% ^
    --enable-plugin=pyside6 ^
    --include-package=malaz ^
    --include-package=XLMMacroDeobfuscator ^
    --include-package=xlrd2 ^
    --include-package=msoffcrypto ^
    --include-package=pyxlsb2 ^
    --include-package=jaraco ^
    --include-package=zxingcpp ^
    --include-package-data=XLMMacroDeobfuscator ^
    --include-module=XLMMacroDeobfuscator.deobfuscator ^
    --include-module=XLMMacroDeobfuscator.configs.settings ^
    --include-module=XLMMacroDeobfuscator.excel_wrapper ^
    --include-module=XLMMacroDeobfuscator.xlsm_wrapper ^
    --include-module=XLMMacroDeobfuscator.xls_wrapper ^
    --include-module=XLMMacroDeobfuscator.xlsb_wrapper ^
    --include-data-dir="%PKLIBS%"=pikepdf.libs ^
    --include-data-dir="%ZXLIBS%"=zxing_cpp.libs ^
    --no-deployment-flag=excluded-module-usage ^
    --include-data-dir=..\rules=rules ^
    --noinclude-data-files=rules/yara/external ^
    --noinclude-data-files=rules/yara/signature_base ^
    --include-data-dir=..\assets=assets ^
    --windows-icon-from-ico=..\assets\malaz.ico ^
    --windows-console-mode=attach ^
    --assume-yes-for-downloads ^
    --product-name="Malaz" ^
    --product-version="%APPVER4%" ^
    --file-version="%APPVER4%" ^
    --file-description="Offline Datei-Sicherheits-Triage" ^
    --output-dir=..\dist ^
    --remove-output ^
    malaz_exe.py

if errorlevel 1 (
    echo Build fehlgeschlagen.
    popd
    popd
    exit /b 1
)

popd

REM -- Ergebnis aufraeumen / benennen --------------------------------------
if /i "%MODE%"=="standalone" (
    if exist "%TARGET%" rmdir /s /q "%TARGET%"
    ren "%ROOT%\dist\malaz_exe.dist" "%NAME%"
    ren "%TARGET%\malaz_exe.exe" "Malaz.exe"
    rem All-in-One-VM-Test und Explorer-Kontextmenue-Registrierung mit in
    rem den portablen Ordner legen - laufen ohne Python direkt neben Malaz.exe
    rem Hinweis: keine Klammern in rem-Zeilen innerhalb if-Bloecken - eine
    rem schliessende Klammer beendet den Block vorzeitig, beide Zweige laufen.
    copy /y "%ROOT%\scripts\vm_portable_test.bat" "%TARGET%\" >nul
    copy /y "%ROOT%\scripts\register_explorer_menu.bat" "%TARGET%\" >nul
    copy /y "%ROOT%\scripts\unregister_explorer_menu.bat" "%TARGET%\" >nul
    rem Lizenz und Attribution gehoeren in jedes Release-Artefakt, nicht nur
    rem in den Quellbaum (GPL-6 / Lizenztexte der Wheels).
    copy /y "%ROOT%\LICENSE" "%TARGET%\" >nul
    copy /y "%ROOT%\THIRD_PARTY_NOTICES.md" "%TARGET%\" >nul
    rem SBOM und Funktions-Smoke gehoeren VOR das Release-Gate: der Gate prueft
    rem Dateien, der Smoke prueft die gebuendelte PDF-Stufe im echten EXE.
    "%PY%" "%ROOT%\scripts\make_sbom.py" --output "%TARGET%\sbom.json"
    if errorlevel 1 (
        echo FEHLER: SBOM konnte nicht erzeugt werden.
        exit /b 1
    )
    "%PY%" "%ROOT%\scripts\smoke_build.py" --exe "%TARGET%\Malaz.exe"
    if errorlevel 1 (
        echo FEHLER: Smoke-Build-Test am gebauten EXE fehlgeschlagen.
        exit /b 1
    )
    rem Kein Runtime-Inhalt darf in die Lieferung gelangen. Das Gate prueft
    rem den frischen Build-Ordner, bevor Compress-Archive ueber einen Wildcard-
    rem Pfad alles einsammelt.
    rem Der Smoke-Lauf startet die EXE, und die schreibt malaz.log neben sich.
    rem .log steht in _FORBIDDEN_SUFFIXES, das Gate wuerde den frischen Build
    rem abweisen (gemessen). Vor dem Gate entfernen.
    if exist "%TARGET%\malaz.log" del /q "%TARGET%\malaz.log"
    "%PY%" "%ROOT%\scripts\check_release.py" --directory "%TARGET%"
    if errorlevel 1 (
        echo FEHLER: Release-Gate hat den Build-Ordner abgewiesen.
        exit /b 1
    )
    rem Das ALTE Zip erst NACH erfolgreicher Kompression loeschen. Vorher
    rem geloescht: schlaegt Compress-Archive fehl (gemessen
    rem CompressArchiveUnauthorizedAccessError), gibt es gar kein Zip mehr,
    rem das Skript meldet trotzdem "Fertig" und der Auslieferungspfad ist leer.
    rem Achtung, cmd-Falle: dieser Block ist ein if-Block, und cmd ersetzt
    rem %VAR% beim PARSEN des GANZEN Blocks. Variablen, die VOR dem Block
    rem gesetzt wurden (%NAME%), sind darin verfuegbar; eine Variable, die
    rem ERST IM Block gesetzt wird, ist darin leer. Genau das war der Fehler
    rem vom 22.09.: ein im Block gesetztes %ZIP_NEU% verschwand, und das
    rem Verschieben scheiterte mit "Das System kann die angegebene Datei
    rem nicht finden". Deshalb steht %NAME% oben bei der Auswertung.
    if exist "%ROOT%\dist\%NAME%.neu.zip" del "%ROOT%\dist\%NAME%.neu.zip"
    powershell -NoProfile -Command "Compress-Archive -Path '%TARGET%\*' -DestinationPath '%ROOT%\dist\%NAME%.neu.zip' -Force"
    if errorlevel 1 (
        echo FEHLER: Das Zip konnte nicht erstellt werden. Das vorige bleibt erhalten.
        exit /b 1
    )
    rem Zusaetzlich die Existenz pruefen. Hygiene, NICHT die Ursache des
    rem Fehlers vom 22.09.: der war die Variablen-Expansion weiter unten.
    rem PowerShell kann bei einem nicht abbrechenden Fehler mit 0 enden.
    if not exist "%ROOT%\dist\%NAME%.neu.zip" (
        echo FEHLER: Kompression ohne Ergebnis. Das vorige Zip bleibt erhalten.
        exit /b 1
    )
    if exist "%ROOT%\dist\%NAME%.zip" del "%ROOT%\dist\%NAME%.zip"
    move /y "%ROOT%\dist\%NAME%.neu.zip" "%ROOT%\dist\%NAME%.zip" >nul
    "%PY%" "%ROOT%\scripts\check_release.py" --archive "%ROOT%\dist\%NAME%.zip"
    if errorlevel 1 (
        echo FEHLER: Release-Gate hat das ZIP abgewiesen.
        exit /b 1
    )
    if not exist "%ROOT%\dist\%NAME%.zip" (
        echo FEHLER: Zip fehlt nach dem Verschieben.
        exit /b 1
    )
    echo.
    echo Fertig: %TARGET%\  und  %NAME%.zip
) else (
    rem ren ueberschreibt nicht - alte Exe vorher loeschen, sonst bleibt
    rem der frische Build als malaz_exe.exe liegen und veraltet still.
    if exist "%ROOT%\dist\Malaz.exe" del "%ROOT%\dist\Malaz.exe"
    ren "%ROOT%\dist\malaz_exe.exe" "Malaz.exe" 2>nul
    "%PY%" "%ROOT%\scripts\make_sbom.py" --output "%ROOT%\dist\Malaz.sbom.json"
    if errorlevel 1 (
        echo FEHLER: SBOM konnte nicht erzeugt werden.
        exit /b 1
    )
    "%PY%" "%ROOT%\scripts\smoke_build.py" --exe "%ROOT%\dist\Malaz.exe"
    if errorlevel 1 (
        echo FEHLER: Smoke-Build-Test am gebauten EXE fehlgeschlagen.
        exit /b 1
    )
    if exist "%ROOT%\dist\malaz.log" del /q "%ROOT%\dist\malaz.log"
    echo.
    echo Fertig: %ROOT%\dist\Malaz.exe
)
popd
endlocal
