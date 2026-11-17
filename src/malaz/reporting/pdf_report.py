"""Self-contained PDF report generation (native, offline).

Renders the same verdict data as the HTML report as a real PDF file using
Qt's ``QPdfWriter`` — no third-party dependency, no browser engine, no
network. Text is drawn as vector glyphs, so the output stays sharp and
small. Like the HTML report it contains nothing executable.

Layout: header band with title/meta, four summary cards, then one block per
file (name, verdict, recommendation, metadata, indicator table) with nested
archive members rendered indented. Pagination inserts page breaks with a
footer (product, offline note, page number).
"""

from __future__ import annotations

import datetime
import os
from contextlib import suppress
from pathlib import Path

from PySide6.QtCore import QMarginsF, QPointF, QRectF, Qt
from PySide6.QtGui import (
    QColor,
    QFont,
    QPageLayout,
    QPageSize,
    QPainter,
    QPdfWriter,
)

from .. import __version__, config
from ..core.mail_view import MAX_DISPLAY_CHARS, _clip
from ..models import Indicator, RiskLevel, ScanResult, Severity, type_description
from ..security.escaping import mask_invisible
from .mail_section import is_mail_result, mail_lines

# Palette mirrors the HTML report (light background).
_INK = QColor("#1a1a1a")
_MUTED = QColor("#555555")
_FAINT = QColor("#888888")
_HEAD_BG = QColor("#10243e")
_CARD_BG = QColor("#ffffff")
_ADVICE_BG = QColor("#f2f6fa")
_ROW_BG = QColor("#f6f8fa")
_LINE = QColor("#e0e4ea")

_RISK_COLORS = {
    RiskLevel.GREEN: QColor("#2e7d32"),
    RiskLevel.YELLOW: QColor("#f9a825"),
    RiskLevel.RED: QColor("#c62828"),
}

_SEV_COLORS = {
    Severity.INFO: QColor("#607d8b"),
    Severity.LOW: QColor("#26a69a"),
    Severity.MEDIUM: QColor("#f9a825"),
    Severity.HIGH: QColor("#ef6c00"),
    Severity.CRITICAL: QColor("#c62828"),
}



class _PdfRenderer:
    """Incremental painter over one PDF document with page-break handling."""

    def __init__(self, writer: QPdfWriter):
        self.writer = writer
        self.painter = QPainter(writer)
        self.page = 1
        self.page_rect = writer.pageLayout().paintRectPixels(writer.resolution())
        self.x = self.page_rect.x()
        self.y: float = float(self.page_rect.y())
        self.right = self.x + self.page_rect.width()

    # -- page management -------------------------------------------------- #

    def footer(self) -> None:
        text = (
            f"Malaz v{__version__} — rein statische Analyse, 100% offline · "
            f"Seite {self.page}"
        )
        font = QFont("Segoe UI")
        font.setPointSizeF(7.5)
        self.painter.setFont(font)
        self.painter.setPen(_FAINT)
        rect = QRectF(
            self.x,
            self.page_rect.bottom() - 22,
            self.page_rect.width(),
            16,
        )
        self.painter.drawText(rect, int(Qt.AlignmentFlag.AlignHCenter | Qt.TextFlag.TextSingleLine), text)

    def new_page(self) -> None:
        self.footer()
        self.writer.newPage()
        self.page += 1
        self.y = self.page_rect.y()

    def ensure(self, height: float) -> None:
        """Start a new page when ``height`` no longer fits (footer reserve)."""
        if self.y + height > self.page_rect.bottom() - 30:
            self.new_page()

    def gap(self, px: float) -> None:
        self.y += px

    # -- primitives ------------------------------------------------------- #

    def wrap_lines(self, text: str, width: float, font: QFont) -> list[str]:
        """Greedy word wrap under the painter's real PDF metrics.

        Every field value drawn into the report is laid out through here (only
        internal constants such as chip labels bypass it), so the
        invisible/bidi masking happens HERE (see security.escaping). Masking at
        the call sites covered the fields someone remembered — name, indicator
        title/detail, path — and missed ``result.error``, which carries the
        Zip-Slip note together with the raw archive entry name; a U+202E in it
        reached the PDF unmodified. A sink masks every present and future field,
        and masking an already-masked string is a no-op.

        Qt's ``TextWrapAnywhere`` flag broke ordinary words mid-word (field
        report: "informieren" rendered as "inf/ormieren"), so wrapping is done
        here instead. Only a token that is wider than the whole column on its
        own (SHA-256, long paths) is split at character level — the
        alternative would be clipping it out of the report.
        """
        self.painter.setFont(font)
        metrics = self.painter.fontMetrics()
        limit = max(int(width), 1)
        lines: list[str] = []
        for paragraph in (mask_invisible(text) or " ").split("\n"):
            current = ""
            for word in paragraph.split():
                joined = f"{current} {word}" if current else word
                if metrics.horizontalAdvance(joined) <= limit:
                    current = joined
                    continue
                if current:
                    lines.append(current)
                    current = ""
                if metrics.horizontalAdvance(word) <= limit:
                    current = word
                    continue
                chunk = ""
                for ch in word:
                    if chunk and metrics.horizontalAdvance(chunk + ch) > limit:
                        lines.append(chunk)
                        chunk = ch
                    else:
                        chunk += ch
                current = chunk
            lines.append(current)
        return lines or [" "]

    def lines_height(self, lines: list[str], font: QFont) -> int:
        if not lines:
            return 0
        self.painter.setFont(font)
        metrics = self.painter.fontMetrics()
        return (len(lines) - 1) * metrics.lineSpacing() + metrics.height()

    def draw_lines_at(
        self, lines: list[str], x: float, y: float, font: QFont, color: QColor
    ) -> None:
        """Draw pre-wrapped lines with the first baseline at ``y`` (top)."""
        self.painter.setFont(font)
        self.painter.setPen(color)
        metrics = self.painter.fontMetrics()
        for i, line in enumerate(lines):
            self.painter.drawText(
                QPointF(x, y + i * metrics.lineSpacing() + metrics.ascent()), line
            )

    def draw_text(
        self,
        text: str,
        x: float,
        width: float,
        font: QFont,
        color: QColor,
        min_height: float = 4,
    ) -> None:
        """Draw wrapped text at the cursor; advances y by its height."""
        lines = self.wrap_lines(text, width, font)
        height = max(self.lines_height(lines, font), int(min_height))
        self.ensure(height)
        self.draw_lines_at(lines, x, self.y, font, color)
        self.y += height

    def chip(self, label: str, color: QColor, x: float, y: float) -> float:
        """Small filled rounded label; returns its width."""
        font = QFont("Segoe UI")
        font.setPointSizeF(8)
        font.setBold(True)
        self.painter.setFont(font)
        metrics = self.painter.fontMetrics()
        w = metrics.horizontalAdvance(label) + 12
        h = metrics.height() + 4
        self.painter.setFont(font)
        self.painter.setPen(Qt.PenStyle.NoPen)
        self.painter.setBrush(color)
        self.painter.drawRoundedRect(QRectF(x, y, w, h), 3, 3)
        self.painter.setPen(QColor("#ffffff"))
        self.painter.drawText(
            QRectF(x, y, w, h), int(Qt.AlignmentFlag.AlignCenter | Qt.TextFlag.TextSingleLine), label
        )
        self.painter.setBrush(Qt.BrushStyle.NoBrush)
        return w

    def fill(self, rect: QRectF, color: QColor) -> None:
        self.painter.setPen(Qt.PenStyle.NoPen)
        self.painter.setBrush(color)
        self.painter.drawRect(rect)
        self.painter.setBrush(Qt.BrushStyle.NoBrush)

    def hline(self, color: QColor = _LINE) -> None:
        self.ensure(6)
        self.painter.setPen(color)
        self.painter.drawLine(
            QPointF(self.x, self.y + 2), QPointF(self.right, self.y + 2)
        )
        self.y += 6


def _font(size: float, bold: bool = False, mono: bool = False) -> QFont:
    font = QFont("Consolas" if mono else "Segoe UI")
    font.setPointSizeF(size)
    font.setBold(bold)
    return font


def _kv_line(r: _PdfRenderer, label: str, value: object, width: float) -> None:
    if value in (None, ""):
        return
    x = r.x + 4
    label_w = 88.0
    value_font = _font(8, mono=True)
    label_font = _font(8)
    # MASKIEREN an der Senke. Der Fliesstext daneben laeuft ueber _paragraph und
    # ist maskiert; diese Funktion zeichnete ``str(value)`` roh, und damit ging
    # jeder angreiferkontrollierte Wert unmaskiert ins PDF: der Pfad, der
    # Anzeigename, der Link-Host. Qt wendet den Bidi-Algorithmus an — aus
    # "rechnung<U+202E>gpj.exe" wird beim Zeichnen "rechnungexe.jpg", und der
    # Leser liest eine andere Adresse als die, die in der Datei steht.
    value_lines = r.wrap_lines(
        mask_invisible(str(value)), width - label_w - 8, value_font
    )
    label_lines = r.wrap_lines(mask_invisible(str(label)), label_w, label_font)
    height = max(
        r.lines_height(value_lines, value_font),
        r.lines_height(label_lines, label_font),
        12,
    )
    r.ensure(height)
    r.draw_lines_at(label_lines, x, r.y, label_font, _MUTED)
    r.draw_lines_at(
        value_lines, x + label_w, r.y, value_font, _INK
    )
    r.y += height


def _indicator_row(
    r: _PdfRenderer, ind: Indicator, width: float, indent: float
) -> None:
    sev_w, rule_w = 66.0, 150.0
    title_w = width - sev_w - rule_w - 12
    title_font = _font(8.5, bold=True)
    detail_font = _font(7.5, mono=True)
    rule_font = _font(7.5, mono=True)
    title_lines = r.wrap_lines(ind.title, title_w, title_font)
    detail_lines = (
        r.wrap_lines(ind.detail or "", title_w, detail_font)
        if ind.detail
        else []
    )
    rule_lines = r.wrap_lines(f"{ind.rule_id} · {ind.source}", rule_w, rule_font)
    height = (
        max(
            r.lines_height(title_lines, title_font)
            + (r.lines_height(detail_lines, detail_font) + 4 if detail_lines else 0),
            r.lines_height(rule_lines, rule_font),
            16,
        )
        + 6
    )
    r.ensure(height)

    top = r.y
    # Zebra background for readability.
    r.fill(QRectF(r.x + indent, top, width, height), _ROW_BG)

    sev_color = _SEV_COLORS.get(ind.severity, _SEV_COLORS[Severity.INFO])
    r.chip(ind.severity.label, sev_color, r.x + indent + 5, top + 5)

    title_x = r.x + indent + sev_w
    r.draw_lines_at(title_lines, title_x, top + 3, title_font, _INK)
    if detail_lines:
        r.draw_lines_at(
            detail_lines,
            title_x,
            top + 3 + r.lines_height(title_lines, title_font),
            detail_font,
            _MUTED,
        )

    r.draw_lines_at(
        rule_lines,
        title_x + title_w + 6,
        top + 3,
        rule_font,
        _FAINT,
    )
    r.y = top + height


def _render_result(
    r: _PdfRenderer, result: ScanResult, width: float, indent: float = 0, depth: int = 0
) -> None:
    # File head: name (wrapped) + verdict chip + score in fixed right-hand
    # columns: chip in the last 115 px, score right-aligned in the 125 px
    # before it. The name stops 260 px short of the right edge, so the three
    # areas can never overlap — previously the score was clipped to whatever
    # the chip left free (regression caught in review).
    name_font = _font(10.5 if depth == 0 else 9, bold=True)
    chip_x = r.x + indent + width - 115
    score_text = f"Score {result.score}/100" + (" · Anker" if result.anchored else "")
    if result.av_discount:
        # Same reason the CLI prints it (§ models.ScanResult.av_discount): a
        # score that sits below its raw findings — and the colour that follows
        # from it — must name the discount, otherwise the number is arbitrary.
        score_text += f" · −{result.av_discount} AV-ohne-Fund"
    # The score strip is MEASURED, not a fixed 125 px: Qt clips drawText to the
    # rect, so a longer string (German text, the discount) would vanish
    # silently. The name column gives up exactly what the score needs.
    r.painter.setFont(_font(8))
    score_w = max(125.0, r.painter.fontMetrics().horizontalAdvance(score_text) + 6.0)
    name_w = max(width - 260 - (score_w - 125.0), 60)
    name_lines = r.wrap_lines(
        mask_invisible(_clip(result.display_name, MAX_DISPLAY_CHARS)),
        name_w,
        name_font,
    )
    name_h = r.lines_height(name_lines, name_font)
    r.ensure(name_h + 34)
    r.draw_lines_at(name_lines, r.x + indent, r.y, name_font, _INK)
    # Der Chip ist das, was der Kunde auf einen Blick sieht. Traegt die
    # Pruefung Luecken, steht das IM Chip: ein Grün ohne diesen Zusatz liest
    # sich als Freispruch, und genau das ist es nicht.
    r.chip(
        f"{result.risk_level.short} (unvollständig)"
        if result.is_incomplete
        else result.risk_level.short,
        _RISK_COLORS[result.risk_level],
        chip_x,
        r.y,
    )
    r.painter.setFont(_font(8))
    r.painter.setPen(_MUTED)
    r.painter.drawText(
        QRectF(chip_x - 5 - score_w, r.y, score_w, 20),
        int(Qt.AlignmentFlag.AlignRight | Qt.TextFlag.TextSingleLine),
        score_text,
    )
    r.y += max(name_h, 22) + 3

    # Was NICHT geprüft wurde — vor der Empfehlung, nicht danach. Die
    # Empfehlung ("kann verwendet werden") ist ohne diesen Satz irreführend,
    # wenn eine Stufe nie lief.
    if result.is_incomplete:
        fehlt_font = _font(8.5)
        fehlt_lines = r.wrap_lines(
            "Nicht geprüft: "
            + " | ".join(i.title for i in result.incomplete_stages)
            + " — das Urteil oben deckt diese Stufen NICHT ab.",
            width - 110,
            fehlt_font,
        )
        fehlt_h = r.lines_height(fehlt_lines, fehlt_font)
        r.ensure(fehlt_h + 10)
        r.fill(QRectF(r.x + indent, r.y, width, fehlt_h + 10), _ADVICE_BG)
        r.draw_lines_at(
            fehlt_lines, r.x + indent + 8, r.y + 4, fehlt_font, _INK
        )
        r.y += fehlt_h + 14

    # Recommendation band.
    advice_font = _font(8.5)
    label_font = _font(8.5, bold=True)
    advice_lines = r.wrap_lines(
        result.risk_level.advice, width - 110, advice_font
    )
    label_lines = r.wrap_lines("Empfehlung:", 90, label_font)
    advice_h = max(
        r.lines_height(advice_lines, advice_font),
        r.lines_height(label_lines, label_font),
    )
    r.ensure(advice_h + 10)
    r.fill(QRectF(r.x + indent, r.y, width, advice_h + 10), _ADVICE_BG)
    r.draw_lines_at(
        label_lines, r.x + indent + 8, r.y + 4, label_font, _INK
    )
    r.draw_lines_at(
        advice_lines, r.x + indent + 98, r.y + 4, advice_font, _INK
    )
    r.y += advice_h + 14

    # Metadata.
    _kv_line(r, "Pfad", _clip(result.path, MAX_DISPLAY_CHARS), width)
    _kv_line(r, "Typ", type_description(result.detected_type, result.mime_hint), width)
    _kv_line(r, "Größe", f"{result.size} Bytes", width)
    _kv_line(r, "SHA-256", result.sha256 or "—", width)
    _kv_line(r, "Dauer", f"{result.duration_ms} ms", width)
    if result.error:
        _kv_line(r, "Hinweis", result.error, width)
    # Das Absender-Urteil. Ohne diese Zeilen zeigte der Bericht nur den
    # Rohbefund MAIL_AUTH_FAIL und nicht die Aussage dahinter — und nicht, ob
    # der angezeigte Name zur Absenderadresse passt. Die Daten kommen aus
    # reporting.mail_section, damit HTML und PDF dasselbe sagen.
    for label, value in mail_lines(result):
        _kv_line(r, label, value, width)
    if result.engine_verdicts:
        _kv_line(
            r,
            "Engines",
            " · ".join(
                f"{v.engine}: {v.label}" for v in result.engine_verdicts
            ),
            width,
        )
    r.gap(4)

    # Indicator table (worst first).
    indicators = sorted(result.indicators, key=lambda i: i.severity, reverse=True)
    if indicators:
        r.painter.setFont(_font(8, bold=True))
        r.painter.setPen(_MUTED)
        r.ensure(16)
        r.painter.drawText(
            QRectF(r.x + indent, r.y, width, 14),
            int(Qt.TextFlag.TextSingleLine),
            f"Befunde ({len(indicators)}):",
        )
        r.y += 16
        for ind in indicators:
            _indicator_row(r, ind, width - indent, indent)
    else:
        r.ensure(14)
        r.draw_text(
            "Keine Auffälligkeiten.", r.x + indent, width - indent,
            _font(8), _MUTED, min_height=12,
        )

    # Nested members: attachments for a mail, archive entries otherwise.
    if result.children:
        r.gap(4)
        if is_mail_result(result):
            head = f"Anhänge ({len(result.children)}):"
        else:
            head = f"Archiv-Inhalt ({len(result.children)} Einträge):"
        head_font = _font(8.5, bold=True)
        head_lines = r.wrap_lines(head, width - indent, head_font)
        head_h = r.lines_height(head_lines, head_font)
        r.ensure(head_h)
        r.draw_lines_at(
            head_lines, r.x + indent, r.y, head_font, _INK
        )
        r.y += head_h + 6
        for child in result.children:
            r.ensure(30)
            _render_result(r, child, width - 18, indent + 18, depth + 1)

    r.hline()
    r.gap(6)


def _header(r: _PdfRenderer, title: str) -> None:
    now = datetime.datetime.now().astimezone().strftime("%d.%m.%Y %H:%M")
    r.fill(QRectF(r.x, r.y, r.page_rect.width(), 64), _HEAD_BG)
    r.painter.setFont(_font(15, bold=True))
    r.painter.setPen(QColor("#ffffff"))
    r.painter.drawText(
        QRectF(r.x + 16, r.y + 8, r.page_rect.width() - 32, 24),
        int(Qt.TextFlag.TextSingleLine),
        title,
    )
    r.painter.setFont(_font(8))
    r.painter.setPen(QColor("#cfd8e3"))
    r.painter.drawText(
        QRectF(r.x + 16, r.y + 34, r.page_rect.width() - 32, 18),
        int(Qt.TextFlag.TextSingleLine),
        f"Analysebericht · erstellt {now} · Version {__version__} · 100% offline · "
        "kein JavaScript, keine Cloud",
    )
    r.y += 64 + 14


def _summary_cards(r: _PdfRenderer, results: list[ScanResult]) -> None:
    counts = {level: 0 for level in RiskLevel}
    for res in results:
        counts[res.risk_level] += 1
    gap = 10.0
    card_w = (r.page_rect.width() - 3 * gap) / 4
    cards = (
        ("Dateien gesamt", len(results), _INK),
        ("Unauffällig", counts[RiskLevel.GREEN], _RISK_COLORS[RiskLevel.GREEN]),
        ("Verdächtig", counts[RiskLevel.YELLOW], _RISK_COLORS[RiskLevel.YELLOW]),
        ("Gefährlich", counts[RiskLevel.RED], _RISK_COLORS[RiskLevel.RED]),
    )
    r.ensure(74)
    for index, (label, value, color) in enumerate(cards):
        x = r.x + index * (card_w + gap)
        rect = QRectF(x, r.y, card_w, 64)
        r.fill(rect, _CARD_BG)
        r.painter.setPen(_LINE)
        r.painter.setBrush(Qt.BrushStyle.NoBrush)
        r.painter.drawRect(rect)
        r.fill(QRectF(x, r.y, 4, 64), color)
        r.painter.setFont(_font(16, bold=True))
        r.painter.setPen(color)
        r.painter.drawText(
            QRectF(x + 10, r.y + 6, card_w - 16, 26),
            int(Qt.TextFlag.TextSingleLine),
            str(value),
        )
        r.painter.setFont(_font(8))
        r.painter.setPen(_MUTED)
        r.painter.drawText(
            QRectF(x + 10, r.y + 36, card_w - 16, 16),
            int(Qt.TextFlag.TextSingleLine),
            label,
        )
    r.y += 64 + 8

    legend = (
        "Einordnung: Unauffällig = keine Anzeichen für Manipulation · "
        "Verdächtig = nur bei vertrauenswürdigem Absender öffnen · "
        "Gefährlich = nicht öffnen, löschen und ggf. die IT informieren."
    )
    r.draw_text(legend, r.x, r.page_rect.width(), _font(8), _MUTED)
    r.gap(10)


def generate_pdf(results: list[ScanResult], path: str | Path, title: str | None = None) -> Path:
    """Render the batch of results into a real PDF file at ``path``.

    The document is rendered to a temporary file in the same directory and
    atomically moved into place on success — a crash or viewer-lock mid-write
    can never leave a half-written PDF at the target path (the previous
    behaviour let QPdfWriter create the 0-byte target at begin() and only
    flush content at end()).

    Raises ``OSError`` when the target cannot be written (e.g. the PDF is
    open in a viewer that locks it) — a silent "success" with a missing or
    half-written file is worse than a visible failure.
    """
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    doc_title = title or f"{config.APP_NAME} — Analysebericht"

    # Same directory as the target so os.replace stays on one volume (atomic).
    tmp_out = out.with_name(f".{out.name}.tmp-{os.getpid()}")
    try:
        _render_to_file(results, tmp_out, doc_title, out)
        # Windows: os.replace is atomic and replaces an existing read-only-
        # locked target with a clear error instead of corrupting it.
        os.replace(tmp_out, out)
    except Exception:
        with suppress(OSError):
            tmp_out.unlink(missing_ok=True)
        raise
    return out


def _render_to_file(
    results: list[ScanResult], target: Path, doc_title: str, original: Path
) -> None:
    writer = QPdfWriter(str(target))
    writer.setTitle(doc_title)
    writer.setCreator(f"{config.APP_NAME} v{__version__}")
    writer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
    writer.setPageMargins(QMarginsF(14, 12, 14, 16), QPageLayout.Unit.Millimeter)
    writer.setResolution(96)

    r = _PdfRenderer(writer)
    if not r.painter.isActive():
        # QPdfWriter could not open the file (locked by a viewer, read-only
        # directory, ...) — it does not raise on its own.
        raise OSError(f"PDF-Zieldatei nicht schreibbar: {original}")
    try:
        _header(r, doc_title)
        _summary_cards(r, results)
        if results:
            for result in results:
                _render_result(r, result, r.page_rect.width())
        else:
            r.draw_text(
                "Keine Dateien analysiert.", r.x, r.page_rect.width(),
                _font(9.5), _MUTED,
            )
    except Exception:
        # Best-effort cleanup of the partial file, then re-raise — replacing
        # the original error with an end()-OSError would hide the cause.
        with suppress(Exception):
            r.painter.end()
        raise
    r.footer()
    if not r.painter.end():
        raise OSError(f"PDF konnte nicht abgeschlossen werden: {original}")


# Friendly alias matching html_report.save_report.
save_pdf_report = generate_pdf
