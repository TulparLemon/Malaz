"""Engine verdicts reach the table, the strip, the score tab and exports."""

from __future__ import annotations

from malaz.analysis.clamav import ClamAVScanner
from malaz.analysis.windows_av import WindowsDefenderScanner
from malaz.core.dispatcher import Dispatcher
from malaz.core.engine_verdicts import build_engine_verdicts
from malaz.gui.engine_strip import EngineChip
from malaz.gui.main_window import MainWindow
from malaz.models import (
    CAT_AV,
    CAT_CLAMAV,
    Indicator,
    RiskLevel,
    ScanResult,
    Severity,
)


def _result() -> ScanResult:
    result = ScanResult(
        path="probe.exe",
        size=10,
        detected_type="pe",
        score=50,
        risk_level=RiskLevel.RED,
        indicators=[
            Indicator("AV_THREAT", "Defender: Treffer", category=CAT_AV, weight=50),
            Indicator("CLAMAV_CLEAN", "ClamAV: sauber", category=CAT_CLAMAV),
            Indicator("YARA_Test", "YARA: Treffer", weight=20),
        ],
    )
    result.engine_verdicts = build_engine_verdicts(result)
    return result


def test_strip_and_score_tab_are_populated(qapp):
    dispatcher = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    window = MainWindow(dispatcher=dispatcher)
    result = _result()
    window._on_result(result)
    window.table.setCurrentItem(window.table.topLevelItem(0))
    qapp.processEvents()

    chips = window.engines.findChildren(EngineChip)
    text = " | ".join(chip.text() for chip in chips)
    assert "Defender" in text and "Bedrohung" in text
    assert "ClamAV" in text and "sauber" in text.lower()
    assert "YARA" in text and "1 Treffer" in text
    from PySide6.QtWidgets import QLabel

    detail_texts = " ".join(lbl.text() for lbl in window.detail_view.findChildren(QLabel))
    assert "AV_THREAT" in detail_texts
    from malaz.gui.engine_strip import compact_engine_text

    compact = compact_engine_text(result)
    assert "D:" in compact and "C:" in compact and "Y:" in compact
    window.close()


def test_exports_carry_engine_fields(tmp_path):
    from malaz.reporting.export import write_csv, write_json
    from malaz.reporting.html_report import generate_report

    result = _result()
    csv_path = write_csv([result], tmp_path / "r.csv")
    text = csv_path.read_text(encoding="utf-8-sig")
    assert "Defender" in text and "ClamAV" in text and "YARA" in text

    json_path = write_json([result], tmp_path / "r.json")
    data = json_path.read_text(encoding="utf-8")
    assert '"engines"' in data and '"engine": "Defender"' in data

    html = generate_report([result])
    assert "Defender" in html and "ClamAV" in html and "YARA" in html
    assert "engine" in html


def test_score_breakdown_includes_child_findings(qapp):
    from malaz.gui.score_breakdown import ScoreBreakdown
    from malaz.models import CAT_STEGO

    child = ScanResult(
        path="inner.pdf",
        score=50,
        risk_level=RiskLevel.RED,
        indicators=[Indicator("PDF_JS", "JavaScript", weight=50, category=CAT_STEGO)],
    )
    parent = ScanResult(path="outer.zip", score=50, risk_level=RiskLevel.RED, children=[child])
    widget = ScoreBreakdown()
    widget.show_result(parent)
    text = widget.toPlainText()
    assert "PDF_JS" in text, text
    assert "Keine scorewirksamen" not in text


def test_batch_summary_uses_child_rules(qapp):
    from malaz.gui.batch_summary import BatchSummary
    from malaz.models import CAT_ARCHIVE

    child = ScanResult(
        path="inner.pdf",
        score=50,
        risk_level=RiskLevel.RED,
        indicators=[Indicator("PDF_JS", "JavaScript", weight=50)],
    )
    parent = ScanResult(
        path="outer.zip",
        score=50,
        risk_level=RiskLevel.RED,
        children=[child],
        indicators=[Indicator("ARCH_ZIPSLIP", "Zip-Slip", weight=50, category=CAT_ARCHIVE)],
    )
    summary = BatchSummary()
    summary.update_results([parent])
    assert "PDF_JS" in summary.detail.text(), summary.detail.text()


def test_batch_summary_zaehlt_regeln_ohne_eigenes_gewicht(qapp):
    """BUG-060: ``if indicator.weight`` warf alle Regeln ohne Explicit-Weight weg.

    ``GEN_FORMAT_MISMATCH`` traegt kein ``weight``; das Scoring gibt ihm ueber
    Severity.HIGH trotzdem 30 Punkte. Die Zusammenfassung nannte es deshalb
    nicht unter "Top-Regeln", obwohl die Einzelzeile 30/100 zeigte.
    """
    from malaz.core.scoring import compute_score
    from malaz.gui.batch_summary import BatchSummary

    indicator = Indicator(
        "GEN_FORMAT_MISMATCH", "Format-Taeuschung", severity=Severity.HIGH
    )
    breakdown = compute_score([indicator])
    assert breakdown.score == 30, breakdown

    result = ScanResult(
        path="tarnung.pdf",
        score=breakdown.score,
        risk_level=breakdown.risk_level,
        indicators=[indicator],
    )
    summary = BatchSummary()
    summary.update_results([result])

    detail = summary.detail.text()
    assert "Top-Regeln" in detail, detail
    assert "GEN_FORMAT_MISMATCH (1)" in detail, detail


def test_batch_summary_zaehlt_fehler_als_unvollstaendig(qapp):
    """BUG-060: alle Zustaende (gruen/gelb/rot/unvollstaendig) muessen stimmen.

    Ein fehlgeschlagener Scan traegt keinen verwertbaren Risiko-Grad; er darf
    nicht als vollstaendig gezaehlt werden. Nicht jede Fehlerquelle setzt
    einen CORE_ERROR-Indikator — der ``error``-Marker allein muss reichen.
    """
    from malaz.gui.batch_summary import BatchSummary

    gruen = ScanResult(path="ok.txt", risk_level=RiskLevel.GREEN)
    # Wie ein realer Fehlschlag: der Finalizer setzt mindestens YELLOW.
    fehler = ScanResult(
        path="gesperrt.exe", risk_level=RiskLevel.YELLOW, error="OSError: gesperrt"
    )
    rot = ScanResult(path="boese.exe", risk_level=RiskLevel.RED)
    summary = BatchSummary()
    summary.update_results([gruen, fehler, rot])

    headline = summary.headline.text()
    assert "3 Dateien" in headline, headline
    assert "1 unauffällig" in headline, headline
    assert "1 verdächtig" in headline, headline
    assert "1 gefährlich" in headline, headline
    assert "1 unvollständig" in headline, headline


def test_engine_chip_escapes_tooltip_html(qapp):
    from malaz.gui.engine_strip import EngineChip
    from malaz.models import EngineVerdict

    chip = EngineChip(
        EngineVerdict(
            engine="ClamAV",
            state="threat",
            label="Bedrohung",
            detail="<b>evil.pdf</b> & <script>alert(1)</script>",
        )
    )
    assert "&lt;b&gt;" in chip.toolTip()
    assert "<b>" not in chip.toolTip()


def test_score_breakdown_dedupliziert_und_zeigt_jeden_rechenschritt(qapp):
    """BUG-055: der Reiter summierte je Indikator statt je Regel.

    Drei GEN_IOC-Befunde standen als 15 im Reiter, waehrend compute_score 5
    vergab. Ausserdem fehlten Rabatt, Gruen-Untergrenze und Kappung — die
    angezeigten Zahlen fuehrten nicht zum Endscore.
    """
    from malaz.gui.score_breakdown import ScoreBreakdown

    widget = ScoreBreakdown()
    widget.show_result(
        _mit_score(
            [Indicator("GEN_IOC", "IO", weight=5) for _ in range(3)]
        )
    )
    text = widget.toPlainText()
    assert text.count("GEN_IOC") == 1, text
    assert "Rohpunkte: 5" in text, text
    assert "Rohpunkte: 15" not in text, text
    assert "3× gefunden" in text, text
    assert text.rstrip().endswith("= 5/100"), text

    # 25 Rohpunkte minus 8 AV-Rabatt ergeben 17 — der Score bleibt durch die
    # Gruen-Untergrenze aber bei 20. Beide Schritte muessen dastehen.
    rabatt = _mit_score(
        [
            Indicator("ARCH_MEMBER_ERROR", "Mitglied nicht lesbar", weight=25),
            Indicator("AV_CLEAN", "Defender: sauber"),
            Indicator("CLAMAV_CLEAN", "ClamAV: sauber"),
        ]
    )
    assert rabatt.av_discount == 8, rabatt.av_discount
    assert rabatt.score == 20, rabatt.score
    widget.show_result(rabatt)
    text = widget.toPlainText()
    assert "Rohpunkte: 25" in text, text
    assert "−8" in text, text
    assert "= 17/100" in text, text
    assert "Grün-Untergrenze: mindestens 20/100" in text, text
    assert "= 20/100" in text, text

    # Die Kappung bei 100 wird ebenfalls ausgewiesen.
    gekappt = _mit_score(
        [Indicator(f"REGEL_{nr}", "Befund", weight=30) for nr in range(5)]
    )
    assert gekappt.score == 100, gekappt.score
    widget.show_result(gekappt)
    text = widget.toPlainText()
    assert "Rohpunkte: 150" in text, text
    assert "Kappung: höchstens 100/100" in text, text
    assert text.rstrip().endswith("= 100/100"), text


def _mit_score(indicators):
    """Ein ScanResult mit genau den Werten, die compute_score liefert."""
    from malaz.core.scoring import compute_score

    breakdown = compute_score(indicators)
    return ScanResult(
        path="probe.bin",
        score=breakdown.score,
        risk_level=breakdown.risk_level,
        anchored=breakdown.anchored,
        av_discount=breakdown.discount,
        indicators=indicators,
    )
