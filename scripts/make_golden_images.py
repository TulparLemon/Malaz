"""Golden Images: Referenzbilder der Oberflaeche erzeugen und pruefen.

WHY THIS EXISTS
===============
The golden snapshot secures numbers and verdicts. It cannot see whether the
window still draws anything: a broken stylesheet, a widget without a parent,
a collapsed layout keeps the suite green while the user sees a blank surface.

The reference images show the states a user actually reads: empty state,
scanning, green/yellow/red result, engine chips (threat/clean/skipped), batch
summary, archive tree, mail panel/viewer, options, capabilities, HTML report
and PDF report.

WHY NO PIXEL COMPARISON
=======================
Fonts, DPI and Qt versions differ per machine; a pixel-exact test would be
disabled instead of repaired. The check therefore asserts what carries the
statement and still breaks when the UI is broken:

* the image is not empty,
* the risk colour (where expected) really occurs,
* the image has a plausible size.

The images themselves are for HUMAN review: a UI change shows up in the file
diff.
"""

from __future__ import annotations

import os
import sys
import tempfile

os.environ.setdefault("QT_SCALE_FACTOR", "1")
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from malaz.gui.theme import RISK_COLORS  # noqa: E402

BILD_DIR = Path(__file__).resolve().parents[1] / "tests" / "data" / "golden_images"

# Groesse, in der die Bilder entstehen. Fest, damit zwei Laeufe vergleichbar
# sind — die Fenstergroesse des Nutzers spielt fuer die Referenz keine Rolle.
BREITE, HOEHE = 1180, 860


def _farbanteil(bild, farbe: str) -> float:
    """Anteil der Pixel, die ungefaehr dieser Farbe entsprechen."""
    ziel = tuple(int(farbe[i : i + 2], 16) for i in (1, 3, 5))
    treffer = 0
    gesamt = 0
    for y in range(0, bild.height(), 2):
        for x in range(0, bild.width(), 2):
            pixel = bild.pixelColor(x, y)
            gesamt += 1
            if all(
                abs(pixel.red() - ziel[0]) <= 40
                and abs(pixel.green() - ziel[1]) <= 40
                and abs(pixel.blue() - ziel[2]) <= 40
                for _ in (0,)
            ):
                treffer += 1
    return treffer / max(gesamt, 1)


def _ist_leer(bild) -> bool:
    """Ein Block aus einer einzigen Farbe — das Zeichen fuer ein leeres Fenster."""
    farben = set()
    for y in range(0, bild.height(), 7):
        for x in range(0, bild.width(), 7):
            farben.add(bild.pixelColor(x, y).rgb())
            if len(farben) > 12:
                return False
    return len(farben) <= 2


def _fixture_mail() -> bytes:
    """Eine Phishing-Mail mit allem, was die Anzeige zeigen soll."""
    return (
        b"Received: from mx.firma.de (mx.firma.de [203.0.113.9]) by postfach.opfer.de "
        b"with ESMTPS; Tue, 1 Jan 2030 10:00:00 +0000\r\n"
        b'From: "post@serioese-bank.tld" <boese@evil.tld>\r\n'
        b"To: opfer@firma.de\r\nSubject: Ihre Rechnung\r\n"
        b"Message-ID: <x@evil.tld>\r\nDate: Tue, 1 Jan 2030 10:00:00 +0000\r\n"
        b"Authentication-Results: mx.microsoft.com; spf=pass; dkim=pass; dmarc=pass\r\n"
        b"DKIM-Signature: v=1; d=andere.tld; s=sel; bh=abc\r\n"
        b"Return-Path: <b@nochwas.tld>\r\n"
        b"X-Spam-Status: No, score=-2.1\r\n"
        b"MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        b"<p>Bitte zahlen Sie.</p>"
        b"<a href='http://bit.ly/xyz'>https://serioese-bank.tld/login</a>"
        b"<p style='font-size:0px'>Ihre Rechnung ist ueberfaellig</p>\r\n"
    )


def _result(
    name: str,
    *,
    score: int = 0,
    risk=None,
    indicators=None,
    children=None,
    detected_type: str = "text",
):
    """Build a ScanResult with engine verdicts, without running the engines."""
    from malaz.core.engine_verdicts import build_engine_verdicts
    from malaz.models import RiskLevel, ScanResult

    result = ScanResult(
        path=name,
        size=1024,
        sha256="0" * 64,
        md5="0" * 32,
        detected_type=detected_type,
        duration_ms=42,
        indicators=list(indicators or []),
        children=list(children or []),
    )
    result.score = score
    result.risk_level = risk or (
        RiskLevel.RED if score >= 50 else RiskLevel.YELLOW if score >= 20 else RiskLevel.GREEN
    )
    result.engine_verdicts = build_engine_verdicts(result, yara_available=True)
    return result


def _indicator(rule_id: str, title: str, weight: int = 0, severity=None):
    from malaz.models import Severity

    return __import__("malaz.models", fromlist=["Indicator"]).Indicator(
        rule_id=rule_id,
        title=title,
        detail="Beispielbefund fuer das Referenzbild.",
        severity=severity or (Severity.CRITICAL if weight >= 50 else Severity.MEDIUM),
        weight=weight,
    )


def _select(row: int = 0):
    def apply(fenster):
        item = fenster.table.topLevelItem(row)
        if item is not None:
            fenster.table.setCurrentItem(item)

    return apply


def _grab(widget, path: Path) -> Path:
    widget.grab().save(str(path))
    return path


def erzeuge(ziel: Path | None = None) -> dict[str, Path]:
    """Render all reference images. Returns ``{name: path}``."""
    from PySide6.QtWidgets import QApplication

    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher
    from malaz.gui.capability_panel import CapabilityPanel
    from malaz.gui.mail_viewer_dialog import MailViewerDialog
    from malaz.gui.main_window import MainWindow
    from malaz.gui.options_dialog import OptionsDialog
    from malaz.gui.theme import apply_theme
    from malaz.models import RiskLevel

    app = QApplication.instance() or QApplication([])
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from qt_fonts import ensure_fonts

    ensure_fonts()
    apply_theme(app)
    ordner = ziel or BILD_DIR
    ordner.mkdir(parents=True, exist_ok=True)
    tmp = Path(app.property("malaz_tmp") or _tmp_dir())
    tmp.mkdir(parents=True, exist_ok=True)

    disp = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    fenster = MainWindow(dispatcher=disp, fixed_size=(BREITE, HOEHE))
    ergebnis: dict[str, Path] = {}

    def reset():
        fenster.table.clear()
        fenster._results = []
        fenster.summary.update_results([])
        fenster._clear_result_panes()
        app.processEvents()

    # 1. Empty state.
    reset()
    ergebnis["empty_state"] = _grab(fenster, ordner / "empty_state.png")

    # 2. Scanning state.
    fenster.scan_banner.show()
    fenster.progress.show()
    fenster.progress.setValue(42)
    fenster._set_scanning(True)
    app.processEvents()
    ergebnis["scanning"] = _grab(fenster, ordner / "scanning.png")
    fenster._set_scanning(False)
    fenster.scan_banner.hide()
    fenster.progress.hide()

    # 3. Green result.
    reset()
    green = _result("harmlos.pdf", score=5, risk=RiskLevel.GREEN, detected_type="pdf")
    fenster._on_result(green)
    _select()(fenster)
    app.processEvents()
    ergebnis["result_green"] = _grab(fenster, ordner / "result_green.png")

    # 4. Yellow result with an incomplete stage.
    reset()
    yellow = _result(
        "hinweis.docx",
        score=25,
        risk=RiskLevel.YELLOW,
        detected_type="office",
        indicators=[
            _indicator("GEN_ENTROPY", "Hohe Entropie", 25),
            _indicator("AV_SKIPPED", "Defender uebersprungen", 0),
        ],
    )
    fenster._on_result(yellow)
    _select()(fenster)
    app.processEvents()
    ergebnis["result_yellow"] = _grab(fenster, ordner / "result_yellow.png")

    # 5. Red result (anchor).
    reset()
    red = _result(
        "rechnung.pdf",
        score=100,
        risk=RiskLevel.RED,
        detected_type="pdf",
        indicators=[
            _indicator("PDF_JS", "JavaScript im PDF", 50),
            _indicator("PDF_OPENACTION", "OpenAction", 30),
        ],
    )
    red.anchored = True
    fenster._on_result(red)
    _select()(fenster)
    app.processEvents()
    ergebnis["result_red"] = _grab(fenster, ordner / "result_red.png")

    # 6-8. Engine strip states.
    reset()
    threat = _result(
        "trojan.exe",
        score=100,
        risk=RiskLevel.RED,
        detected_type="pe",
        indicators=[
            _indicator("AV_THREAT", "Defender: Bedrohung", 50),
            _indicator("CLAMAV_THREAT", "ClamAV: Bedrohung", 50),
            _indicator("YARA_TestRule", "YARA-Treffer", 20),
        ],
    )
    fenster._on_result(threat)
    _select()(fenster)
    app.processEvents()
    ergebnis["engines_threat"] = _grab(fenster, ordner / "engines_threat.png")

    reset()
    clean = _result(
        "sauber.pdf",
        score=0,
        risk=RiskLevel.GREEN,
        detected_type="pdf",
        indicators=[
            _indicator("AV_CLEAN", "Defender: sauber", 0),
            _indicator("CLAMAV_CLEAN", "ClamAV: sauber", 0),
        ],
    )
    fenster._on_result(clean)
    _select()(fenster)
    app.processEvents()
    ergebnis["engines_clean"] = _grab(fenster, ordner / "engines_clean.png")

    reset()
    skipped = _result(
        "gross.bin",
        score=25,
        risk=RiskLevel.YELLOW,
        detected_type="unknown",
        indicators=[
            _indicator("AV_SKIPPED", "Defender: uebersprungen", 0),
            _indicator("CLAMAV_SIZE_LIMIT", "ClamAV: Groessenlimit", 25),
        ],
    )
    fenster._on_result(skipped)
    _select()(fenster)
    app.processEvents()
    ergebnis["engines_skipped"] = _grab(fenster, ordner / "engines_skipped.png")

    # 9. Batch summary.
    reset()
    for index, (score, risk) in enumerate(
        [
            (0, RiskLevel.GREEN),
            (5, RiskLevel.GREEN),
            (25, RiskLevel.YELLOW),
            (30, RiskLevel.YELLOW),
            (100, RiskLevel.RED),
        ]
    ):
        fenster._on_result(
            _result(
                f"datei_{index}.bin",
                score=score,
                risk=risk,
                indicators=[_indicator("GEN_ENTROPY", "Entropie", score)] if score else [],
            )
        )
    fenster.summary.update_results(fenster._results)
    fenster._show_batch_overview()
    app.processEvents()
    ergebnis["batch_summary"] = _grab(fenster, ordner / "batch_summary.png")

    # 10. Archive tree expanded.
    reset()
    child = _result(
        "inner.pdf",
        score=100,
        risk=RiskLevel.RED,
        detected_type="pdf",
        indicators=[_indicator("PDF_JS", "JavaScript im PDF", 50)],
    )
    parent = _result(
        "archiv.zip",
        score=100,
        risk=RiskLevel.RED,
        detected_type="zip",
        children=[child],
        indicators=[_indicator("ARCH_ZIPSLIP", "Zip-Slip", 50)],
    )
    fenster._on_result(parent)
    item = fenster.table.topLevelItem(0)
    if item is not None:
        item.setExpanded(True)
        fenster.table.setCurrentItem(item)
    app.processEvents()
    ergebnis["archive_tree"] = _grab(fenster, ordner / "archive_tree.png")

    # 11-12. Mail panel and viewer from a real parsed mail.
    pfad = tmp / "phishing.eml"
    pfad.write_bytes(_fixture_mail())
    reset()
    mail_result = disp.scan_path(pfad)
    fenster._on_result(mail_result)
    _select()(fenster)
    app.processEvents()
    fenster.detail_view.select_tab(2)
    app.processEvents()
    ergebnis["mail_panel"] = _grab(fenster, ordner / "mail_panel.png")
    dialog = MailViewerDialog(pfad)
    dialog.resize(820, 680)
    dialog.show()
    app.processEvents()
    ergebnis["mail_viewer"] = _grab(dialog, ordner / "mail_viewer.png")
    dialog.close()

    # 13. Options dialog.
    options = OptionsDialog(switches={})
    options.resize(680, 620)
    options.show()
    app.processEvents()
    ergebnis["options"] = _grab(options, ordner / "options.png")
    options.close()

    # 14. Capability panel.
    panel = CapabilityPanel()
    cap = _result("programm.exe", score=0, risk=RiskLevel.GREEN, detected_type="pe")
    cap.capa_capabilities = [
        {"name": "create process", "namespace": "host-interaction/process"},
        {"name": "write file", "namespace": "data-manipulation/file"},
        {"name": "persist via Run key", "namespace": "persistence/registry"},
    ]
    panel.show_result(cap)
    panel.resize(900, 620)
    panel.show()
    app.processEvents()
    ergebnis["capabilities"] = _grab(panel, ordner / "capabilities.png")
    panel.close()

    # 15. HTML report rendered into an image.
    from PySide6.QtWidgets import QTextBrowser

    from malaz.reporting.html_report import generate_report

    html = generate_report([red, yellow, green], title="Malaz Referenzbericht")
    browser = QTextBrowser()
    browser.resize(BREITE, HOEHE)
    browser.setHtml(html)
    browser.show()
    app.processEvents()
    ergebnis["report_html"] = _grab(browser, ordner / "report_html.png")
    browser.close()

    # 16. PDF report first page rendered with QtPdf.
    from PySide6.QtCore import QSize
    from PySide6.QtPdf import QPdfDocument

    from malaz.reporting.pdf_report import generate_pdf

    pdf_path = tmp / "report.pdf"
    generate_pdf([red, yellow, green], pdf_path, title="Malaz Referenzbericht")
    pdf = QPdfDocument()
    pdf.load(str(pdf_path))
    if pdf.pageCount() > 0:
        size = pdf.pagePointSize(0)
        image = pdf.render(0, QSize(int(size.width() * 1.6), int(size.height() * 1.6)))
        image.save(str(ordner / "report_pdf.png"))
        ergebnis["report_pdf"] = ordner / "report_pdf.png"

    fenster.close()
    return ergebnis


def _tmp_dir() -> Path:
    return Path(tempfile.mkdtemp(prefix="malaz_golden_"))


def pruefe() -> list[str]:
    """Render the images fresh and check their statement.

    The reference images themselves are NOT touched: ``--check`` renders into
    a temporary directory. It used to call ``erzeuge()`` without a target and
    overwrote ``tests/data/golden_images`` on every check — with
    ``QT_QPA_PLATFORM=offscreen`` that produced 11 modified PNGs in a clean
    worktree, i.e. the check dirtied what it was supposed to guard.
    """
    beanstandungen: list[str] = []

    import shutil

    from PySide6.QtGui import QImage

    tmp = Path(tempfile.mkdtemp(prefix="malaz_golden_check_"))
    try:
        ergebnis = erzeuge(tmp)

        # Expected risk colour per scene (None = no risk card asserted).
        erwartet = {
            "result_green": RISK_COLORS["green"],
            "result_yellow": RISK_COLORS["yellow"],
            "result_red": RISK_COLORS["red"],
            "engines_threat": RISK_COLORS["red"],
            "engines_clean": RISK_COLORS["green"],
            "engines_skipped": RISK_COLORS["yellow"],
            "batch_summary": RISK_COLORS["red"],
            "archive_tree": RISK_COLORS["red"],
            "mail_panel": RISK_COLORS["red"],
            "mail_viewer": RISK_COLORS["red"],
            "report_pdf": RISK_COLORS["red"],
        }
        required = {
            "empty_state",
            "scanning",
            "result_green",
            "result_yellow",
            "result_red",
            "engines_threat",
            "engines_clean",
            "engines_skipped",
            "batch_summary",
            "archive_tree",
            "mail_panel",
            "mail_viewer",
            "options",
            "capabilities",
            "report_html",
            "report_pdf",
        }
        missing = required - set(ergebnis)
        if missing:
            beanstandungen.append(f"fehlende Ansichten: {sorted(missing)}")
        for name, pfad in ergebnis.items():
            bild = QImage(str(pfad))
            if bild.isNull():
                beanstandungen.append(f"{name}: Bild nicht lesbar")
                continue
            if bild.width() < 400 or bild.height() < 300:
                beanstandungen.append(
                    f"{name}: unerwartet klein ({bild.width()}x{bild.height()})"
                )
            if _ist_leer(bild):
                beanstandungen.append(f"{name}: Flaeche ist leer — Layout zusammengefallen")
        for name, farbe in erwartet.items():
            pfad = ergebnis.get(name)
            if pfad is None or not pfad.exists():
                beanstandungen.append(f"{name}: Bild fehlt")
                continue
            anteil = _farbanteil(QImage(str(pfad)), farbe)
            if anteil < 0.0002:
                beanstandungen.append(
                    f"{name}: die Risikofarbe {farbe} kommt praktisch nicht vor "
                    f"({anteil:.5%}) — wird die Karte ueberhaupt gezeichnet?"
                )
        return beanstandungen
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if "--check" in argv:
        beanstandungen = pruefe()
        for text in beanstandungen:
            print(f"  {text}")
        print(f"  {len(beanstandungen)} Beanstandung(en)")
        return 1 if beanstandungen else 0

    ergebnis = erzeuge()
    for name, pfad in sorted(ergebnis.items()):
        print(f"  {name}: {pfad} ({pfad.stat().st_size / 1024:.0f} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
