"""Ein Fenster rendern und als PNG ablegen — fuer die Design-Arbeit.

WARUM ES DIESEN HELFER GIBT
===========================
Ein Design ohne Blick auf das Ergebnis ist Raten. In dieser Umgebung gibt es
keinen interaktiven Desktop (Bildschirmaufnahmen kommen weiss zurueck), aber
``QWidget.grab()`` rendert direkt in ein Bild — ohne Bildschirm.

WARUM DIE SCHRIFTEN GELADEN WERDEN MUESSEN
==========================================
Qt liefert seit Jahren keine Schriften mehr mit, und unter der
``offscreen``-Plattform ist die Schriftdatenbank leer: jeder Text kam als
Kaestchen heraus. GEMESSEN: die erste Fassung dieses Skripts war damit fuer
jede Aussage ueber Typografie unbrauchbar. ``QFontDatabase.addApplicationFont``
mit einer Systemschrift behebt das (dasselbe Verfahren wie in
``tests/test_pdf_report.py``).

Aufruf:
    .venv/Scripts/python.exe scripts/render_ui.py [ziel.png]
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
import zipfile
from contextlib import suppress
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parent))  # qt_fonts
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from qt_fonts import ensure_fonts


def _testdateien() -> list[str]:
    """Ein Archiv mit gemischtem Inhalt — der Fall, der die Farben zeigt."""
    t = Path(tempfile.mkdtemp())
    z = t / "paket.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("harmlos.txt", "nur text")
        zf.writestr("boese.pdf", b"%PDF-1.7\n/Launch\n%%EOF")
    leer = t / "rechnung.zip"
    with zipfile.ZipFile(leer, "w") as zf:
        zf.writestr("notiz.txt", "ok")
    return [str(z), str(leer)]


def render(ziel: Path, *, scannen: bool = True) -> Path:
    """Das Hauptfenster rendern und ablegen."""
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])

    # EINSTELLUNGEN IN EINE TEMPDATEI, NICHT IN DIE REGISTRY.
    #
    # GEMESSEN: ein Ad-hoc-Skript hat "dns_auth_enabled=true" in die ECHTE
    # Registry geschrieben (HKCU\Software\Malaz\Malaz). Das Fenster setzt
    # beim Bau sein Kaestchen aus der gespeicherten Einstellung, und
    # ``apply_saved_opt_ins`` liest sie beim Start — auf dem Rechner des
    # Nutzers lief der DNS-Abgleich danach OHNE seine Entscheidung, also eine
    # Netzabfrage (Domainname an den DNS-Server) bei jedem Mail-Scan. Genau
    # das soll "Vorgabe aus" verhindern.
    #
    # Ein Werkzeug, das die Oberflaeche rendert, darf die Einstellungen des
    # Nutzers nicht anfassen.
    from PySide6.QtCore import QSettings

    from malaz.gui import settings as _settings

    _isolated = QSettings(
        str(Path(tempfile.mkdtemp()) / "render_ui.ini"), QSettings.Format.IniFormat
    )
    _settings.app_settings = lambda: _isolated  # type: ignore[assignment]
    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher
    from malaz.gui.main_window import MainWindow
    from malaz.gui.theme import apply_theme

    apply_theme(app)
    # Die Scanner haengen am Dispatcher, nicht am Fenster (MainWindow hat
    # keine av_scanner/clam_scanner-Attribute). Ein Render-Lauf darf weder
    # Defender noch ClamAV starten, deshalb bekommt das Fenster einen
    # Dispatcher mit beiden Engines AUS — der Default-Dispatcher waere aktiv.
    fenster = MainWindow(
        dispatcher=Dispatcher(
            av_scanner=WindowsDefenderScanner(enabled=False),
            clam_scanner=ClamAVScanner(enabled=False),
        )
    )
    fenster.resize(1400, 900)

    if scannen:
        fenster.add_paths(_testdateien())
        fenster._on_scan()
        for _ in range(1200):
            if fenster._worker is None:
                break
            app.processEvents()
            time.sleep(0.05)
        app.processEvents()
        if fenster.table.topLevelItemCount():
            fenster.table.topLevelItem(0).setExpanded(True)
        app.processEvents()

    fenster.grab().save(str(ziel))
    return ziel


if __name__ == "__main__":
    if len(sys.argv) > 2:
        print(
            f"FEHLER: hoechstens ein Zielargument erwartet, bekam {len(sys.argv) - 1}",
            file=sys.stderr,
        )
        sys.exit(2)
    ziel = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("ui.png")

    # NUR eine PNG-Ausgabe ersetzen: ein Tippfehler oder ein manipuliertes
    # Argument darf keine beliebige Datei loeschen. Und nicht vorab loeschen,
    # sondern in eine Temp-Datei rendern und erst nach erfolgreicher Pruefung
    # atomar ersetzen — ein abgestuerzter Lauf laesst die alte Datei
    # unangetastet und endet trotzdem mit Exit != 0.
    if ziel.suffix.lower() != ".png":
        print(
            f"FEHLER: Ziel muss eine .png-Datei sein, nicht {ziel}",
            file=sys.stderr,
        )
        sys.exit(2)

    if not ensure_fonts():
        print("FEHLER: keine Schriften — Text kaeme als Kaestchen", file=sys.stderr)
        sys.exit(2)

    try:
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{ziel.stem}.render-", suffix=".png", dir=ziel.parent
        )
        os.close(fd)
    except OSError as exc:
        print(f"FEHLER: kein Ausgabeverzeichnis fuer {ziel}: {exc}", file=sys.stderr)
        sys.exit(2)
    tmp_ziel = Path(tmp_name)
    try:
        render(tmp_ziel)

        if not tmp_ziel.is_file() or tmp_ziel.stat().st_size < 1000:
            print(f"FEHLER: {ziel} wurde nicht geschrieben", file=sys.stderr)
            sys.exit(3)
        os.replace(tmp_ziel, ziel)
    finally:
        # Bei Erfolg ist die Temp-Datei bereits verschoben; sonst raeumen.
        with suppress(OSError):
            tmp_ziel.unlink()
    print(f"  gerendert: {ziel} ({ziel.stat().st_size} Bytes)")
