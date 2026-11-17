"""Tests for the native PDF report (reporting/pdf_report.py).

QPdfWriter only needs a QGuiApplication (no widgets); the offscreen platform
keeps this headless.
"""

import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytest.importorskip("PySide6")

from PySide6.QtGui import QGuiApplication

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from qt_fonts import ensure_fonts

from malaz.models import (
    CAT_STRUCTURE,
    Indicator,
    RiskLevel,
    ScanResult,
    Severity,
)
from malaz.reporting.pdf_report import save_pdf_report


def _app() -> QGuiApplication:
    app = QGuiApplication.instance()
    return app if app is not None else QGuiApplication([])


def _ensure_fonts() -> None:
    """Make real fonts available under the offscreen test platform.

    Die Ladung steht in ``scripts/qt_fonts.py`` — sie war zweimal im Baum
    (hier und in ``scripts/render_ui.py``), und eine Kopie in einer Funktion
    findet ``check_duplicate_logic.py`` nicht.
    """
    _app()
    ensure_fonts()


def _result(name: str = "test.pdf", level: RiskLevel = RiskLevel.YELLOW) -> ScanResult:
    result = ScanResult(path=name, size=1024, depth=0)
    result.detected_type = "pdf"
    result.mime_hint = "application/pdf"
    result.risk_level = level
    result.score = 35 if level == RiskLevel.YELLOW else 10
    result.sha256 = "ab" * 32
    result.md5 = "cd" * 16
    result.duration_ms = 12
    result.indicators = [
        Indicator(
            rule_id="TEST_RULE",
            title="Testbefund mit längerem Titel zum Umbruch-Verhalten",
            detail="Detailzeile\nmit Zeilenumbruch und Sonderzeichen: äöüß <>&",
            severity=Severity.MEDIUM,
            category=CAT_STRUCTURE,
            weight=15,
        )
    ]
    return result


def _text_operator_count(path) -> int:
    """Count Tj/TJ operators: real embedded text instead of tofu paths.

    Regression guard: an early smoke test once produced a PDF whose text was
    drawn as tofu boxes (glyph-less paths, no text operators). Structural
    checks alone (%PDF header, size) would not have caught that.
    """
    import pikepdf

    total = 0
    with pikepdf.open(str(path)) as pdf:
        for page in pdf.pages:
            for _operands, operator in pikepdf.parse_content_stream(page):
                if str(operator) in ("Tj", "TJ"):
                    total += 1
    return total


def _page_count(path) -> int:
    """Number of real PAGE objects.

    ``raw.count(b"/Type /Page")`` also counts ``/Type /Pages`` (the page
    tree), so the old assertion was satisfied by a single-page report —
    exactly the blind spot TEST-015 describes.
    """
    import pikepdf

    with pikepdf.open(str(path)) as pdf:
        return len(pdf.pages)


def test_pdf_report_creates_valid_pdf(tmp_path):
    _ensure_fonts()
    from PySide6.QtGui import QFontDatabase

    if not QFontDatabase().families():
        pytest.skip("keine Fonts verfügbar — TextOperator-Prüfung nicht möglich")
    out = tmp_path / "bericht.pdf"
    save_pdf_report([_result()], out)
    raw = out.read_bytes()
    assert raw.startswith(b"%PDF-")
    assert b"%%EOF" in raw
    assert len(raw) > 1500  # header + one page of content
    assert _page_count(out) >= 1
    assert _text_operator_count(out) > 100  # real, selectable text — no tofu


def test_pdf_report_multiple_results_and_children(tmp_path):
    """TEST-015: the report must actually RENDER children and further rows.

    The old assertions (``%PDF-`` prefix, ``>= 1`` ``/Type /Page``) were also
    satisfied by a single result with no children, so dropping the child block
    or the second result stayed green. The drawn text volume is the observable
    the test can measure without a text extractor.
    """
    _app()
    child = _result("inner.txt", RiskLevel.GREEN)

    parent_without = _result("archiv.zip", RiskLevel.RED)
    parent_with = _result("archiv.zip", RiskLevel.RED)
    parent_with.children = [child, child]

    alone = tmp_path / "nur-parent.pdf"
    with_children = tmp_path / "mit-kindern.pdf"
    multiple = tmp_path / "mehrere.pdf"
    save_pdf_report([parent_without], alone)
    save_pdf_report([parent_with], with_children)
    save_pdf_report([parent_with, _result("zweite.pdf")], multiple)

    assert _page_count(alone) >= 1
    # Each child block draws its own name/verdict/metadata/indicators.
    assert _text_operator_count(with_children) > _text_operator_count(alone) + 200
    # A second top-level result adds another block on top.
    assert _text_operator_count(multiple) > _text_operator_count(with_children)
    for path in (alone, with_children, multiple):
        raw = path.read_bytes()
        assert raw.startswith(b"%PDF-")
        assert b"%%EOF" in raw


def test_pdf_report_empty_batch(tmp_path):
    _app()
    out = tmp_path / "leer.pdf"
    save_pdf_report([], out)
    assert out.read_bytes().startswith(b"%PDF-")


def test_pdf_report_overwrites_existing(tmp_path):
    _app()
    out = tmp_path / "overwrite.pdf"
    out.write_bytes(b"old content")
    save_pdf_report([_result()], out)
    assert out.read_bytes().startswith(b"%PDF-")


def _recording_renderer(tmp_path):
    """Renderer that records every text line handed to the painter."""
    from PySide6.QtGui import QPdfWriter

    from malaz.reporting.pdf_report import _PdfRenderer

    _ensure_fonts()
    writer = QPdfWriter(str(tmp_path / "record-scratch.pdf"))
    writer.setResolution(96)

    class _Recording(_PdfRenderer):
        def __init__(self, w):
            super().__init__(w)
            self.drawn: list[str] = []

        def draw_lines_at(self, lines, x, y, font, color):
            self.drawn.extend(lines)
            super().draw_lines_at(lines, x, y, font, color)

    return _Recording(writer)


def test_pdf_result_error_is_masked(tmp_path):
    """Regression (Audit Lauf 2, malaz/reporting/result-error-field-not-masked).

    ``result.error`` trägt den Zip-Slip-Hinweis samt rohem Eintragsnamen. Die
    Maskierung klebte an den Aufrufstellen (Name, Titel, Detail, Pfad) und
    deckte genau dieses Feld nicht ab. Sie sitzt jetzt im Text-Wrapper des
    Renderers — geprüft an den Zeilen, die tatsächlich gezeichnet werden.
    """
    from malaz.reporting.pdf_report import _render_result

    result = _result()
    result.error = "Archiv-Eintrag '../rechnung\u202eexe.pdf' verlässt das Zielverzeichnis"
    r = _recording_renderer(tmp_path)
    try:
        _render_result(r, result, 500)
    finally:
        r.painter.end()
    shown = "\n".join(r.drawn)
    assert "\u202e" not in shown, "das Steuerzeichen wird roh in das PDF gezeichnet"
    assert "\\u202e" in shown, "die Maskierung fehlt"


def test_pdf_report_draws_every_child_block(tmp_path):
    """Each archive entry gets its own block — the child NAME is drawn."""
    from malaz.reporting.pdf_report import _render_result

    child1 = _result("erster-eintrag.txt", RiskLevel.GREEN)
    child2 = _result("zweiter-eintrag.txt", RiskLevel.YELLOW)
    parent = _result("archiv.zip", RiskLevel.RED)
    parent.children = [child1, child2]

    r = _recording_renderer(tmp_path)
    try:
        _render_result(r, parent, 500)
    finally:
        r.painter.end()
    shown = "\n".join(r.drawn)
    assert "erster-eintrag.txt" in shown, shown
    assert "zweiter-eintrag.txt" in shown, shown
    assert "Archiv-Inhalt (2 Einträge):" in shown


def _renderer_for_wrap(tmp_path):
    """A throwaway _PdfRenderer over a scratch PDF (metrics need a painter)."""
    from PySide6.QtGui import QPdfWriter

    from malaz.reporting.pdf_report import _PdfRenderer

    _ensure_fonts()
    writer = QPdfWriter(str(tmp_path / "wrap-scratch.pdf"))
    writer.setResolution(96)
    return _PdfRenderer(writer)


def test_pdf_wrap_never_breaks_inside_words(tmp_path):
    """Regression (Feld-Report): Qt TextWrapAnywhere brach gewöhnliche
    Wörter mitten im Wort ("informieren" -> "inf/ormieren"). Das eigene
    Wort-Wrapping darf nur an Wortgrenzen umbrechen."""
    r = _renderer_for_wrap(tmp_path)
    try:
        font = r.painter.font()
        font.setPointSizeF(9)
        lines = r.wrap_lines(
            "Gefährlich = nicht öffnen, löschen und ggf. die IT informieren.",
            120,
            font,
        )
        assert len(lines) > 1  # wrapping actually happened at this width
        assert any("informieren." in line for line in lines)
        r.painter.setFont(font)
        metrics = r.painter.fontMetrics()
        assert all(metrics.horizontalAdvance(line) <= 120 for line in lines)
    finally:
        r.painter.end()


def test_pdf_wrap_hard_splits_overlong_tokens(tmp_path):
    """Ein Token, das allein breiter als die Spalte ist (SHA-256, Pfade),
    wird zeichenweise geteilt — ohne Zeichen zu verlieren oder zu clippen."""
    r = _renderer_for_wrap(tmp_path)
    try:
        from malaz.reporting.pdf_report import _font

        font = _font(8, mono=True)
        sha = "e955a5bcf67516195954c1f1aee2f7a83d29ee6dd277b39a6df1b1e2e57e95a5b"
        lines = r.wrap_lines(sha, 150, font)
        assert len(lines) > 1
        assert "".join(lines) == sha  # no characters lost or inserted
        r.painter.setFont(font)
        metrics = r.painter.fontMetrics()
        assert all(metrics.horizontalAdvance(line) <= 150 for line in lines)
    finally:
        r.painter.end()


def test_pdf_wrap_preserves_explicit_line_breaks(tmp_path):
    r = _renderer_for_wrap(tmp_path)
    try:
        font = r.painter.font()
        lines = r.wrap_lines("erste Zeile\nzweite Zeile", 400, font)
        assert lines == ["erste Zeile", "zweite Zeile"]
    finally:
        r.painter.end()


def _recording_painter_renderer(tmp_path):
    """Renderer whose painter records every drawn string with its rect.

    The score sits in the file head, drawn straight onto the painter (not via
    ``draw_lines_at``), so the recording renderer above would not see it. This
    one wraps the painter itself and keeps, per ``drawText`` call, the text, the
    target ``QRectF`` (``None`` for point-draws) and the width the string needs
    in the font that is current AT DRAW TIME — i.e. whether Qt had to clip it.
    """
    from PySide6.QtCore import QRectF
    from PySide6.QtGui import QPdfWriter

    from malaz.reporting.pdf_report import _PdfRenderer

    _ensure_fonts()
    writer = QPdfWriter(str(tmp_path / "score-scratch.pdf"))
    writer.setResolution(96)

    class _Painter:
        def __init__(self, inner):
            self._inner = inner
            self.draws: list[tuple[str, object, float]] = []

        def drawText(self, *args):
            rect = args[0] if isinstance(args[0], QRectF) else None
            needed = float(self._inner.fontMetrics().horizontalAdvance(args[-1]))
            self.draws.append((args[-1], rect, needed))
            return self._inner.drawText(*args)

        def __getattr__(self, name):
            return getattr(self._inner, name)

    class _Recording(_PdfRenderer):
        def __init__(self, w):
            super().__init__(w)
            self.painter = _Painter(self.painter)

    return _Recording(writer)


def _score_draw(tmp_path, result):
    """The single ``Score …`` string the PDF draws for ``result``."""
    from malaz.reporting.pdf_report import _render_result

    r = _recording_painter_renderer(tmp_path)
    try:
        _render_result(r, result, 500)
        draws = list(r.painter.draws)
    finally:
        r.painter.end()
    score = [d for d in draws if d[0].startswith("Score")]
    assert score, "keine Score-Zeile gezeichnet"
    return score[0]


def test_pdf_score_names_the_av_discount(tmp_path):
    """Regression (malaz/reporting/html_report/av-discount-missing-in-reports).

    Identische Indikatoren mit 55 Rohpunkten ergeben mit zwei AV-Stimmen ohne
    Fund 47 Punkte — also Gelb statt Rot. Der Bericht zeigte nur „Score
    47/100", die Herabsetzung blieb unbegruendet (nur die CLI nannte sie).
    """
    import re

    result = _result()
    result.score, result.av_discount = 47, 8

    text, rect, needed = _score_draw(tmp_path, result)
    assert "47/100" in text
    assert re.search(r"8[^0-9]{0,40}AV-ohne-Fund", text), f"Abzug fehlt: {text!r}"
    # Ein laengerer String in einem FESTEN Rect waere stillschweigend
    # abgeschnitten worden — Qt clippt drawText am Rechteck.
    assert rect is not None, "Score-Zeile wird ohne Rechteck gezeichnet"
    assert needed <= rect.width(), (
        f"Score-Zeile passt nicht ins Rechteck: {needed:.0f}px > {rect.width():.0f}px"
    )


def test_pdf_score_without_discount_stays_plain(tmp_path):
    """Gegenrichtung: ohne AV-Rabatt keine erfundene Begruendung."""
    result = _result()
    result.score, result.av_discount = 55, 0
    text, _rect, _needed = _score_draw(tmp_path, result)
    assert "55/100" in text
    assert "AV-ohne-Fund" not in text
