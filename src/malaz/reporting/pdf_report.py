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
from ..i18n import (
    get_language,
    language_context,
    localized_engine_label,
    localized_engine_name,
    localized_incomplete_reason,
    localized_indicator_detail,
    localized_indicator_title,
    pick,
    resolve_language,
)
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

    def __init__(self, writer: QPdfWriter, *, lang: str = "de"):
        self.writer = writer
        self.painter = QPainter(writer)
        self.page = 1
        self.lang = lang
        self.page_rect = writer.pageLayout().paintRectPixels(writer.resolution())
        self.x = self.page_rect.x()
        self.y: float = float(self.page_rect.y())
        self.right = self.x + self.page_rect.width()

    # -- page management -------------------------------------------------- #

    def footer(self) -> None:
        if self.lang == "tr":
            text = f"Malaz v{__version__} — yerel statik analiz, %100 çevrimdışı · Sayfa {self.page}"
        elif self.lang == "en":
            text = f"Malaz v{__version__} — local static analysis, 100% offline · Page {self.page}"
        else:
            text = f"Malaz v{__version__} — rein statische Analyse, 100% offline · Seite {self.page}"
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

    def draw_lines_at(self, lines: list[str], x: float, y: float, font: QFont, color: QColor) -> None:
        """Draw pre-wrapped lines with the first baseline at ``y`` (top)."""
        self.painter.setFont(font)
        self.painter.setPen(color)
        metrics = self.painter.fontMetrics()
        for i, line in enumerate(lines):
            self.painter.drawText(QPointF(x, y + i * metrics.lineSpacing() + metrics.ascent()), line)

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
        self.painter.drawLine(QPointF(self.x, self.y + 2), QPointF(self.right, self.y + 2))
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
    value_lines = r.wrap_lines(mask_invisible(str(value)), width - label_w - 8, value_font)
    label_lines = r.wrap_lines(mask_invisible(str(label)), label_w, label_font)
    height = max(
        r.lines_height(value_lines, value_font),
        r.lines_height(label_lines, label_font),
        12,
    )
    r.ensure(height)
    r.draw_lines_at(label_lines, x, r.y, label_font, _MUTED)
    r.draw_lines_at(value_lines, x + label_w, r.y, value_font, _INK)
    r.y += height


def _indicator_row(r: _PdfRenderer, ind: Indicator, width: float, indent: float) -> None:
    sev_w, rule_w = 66.0, 150.0
    title_w = width - sev_w - rule_w - 12
    title_font = _font(8.5, bold=True)
    detail_font = _font(7.5, mono=True)
    rule_font = _font(7.5, mono=True)
    title_txt = localized_indicator_title(ind, lang=r.lang)
    detail_txt = localized_indicator_detail(ind, lang=r.lang)
    title_lines = r.wrap_lines(title_txt, title_w, title_font)
    detail_lines = r.wrap_lines(detail_txt, title_w, detail_font) if detail_txt else []
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
    r.chip(ind.severity.label_for(r.lang), sev_color, r.x + indent + 5, top + 5)

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
    is_en = r.lang == "en"
    is_tr = r.lang == "tr"
    name_font = _font(10.5 if depth == 0 else 9, bold=True)
    chip_x = r.x + indent + width - 115
    anchor_lbl = pick(" · Anker", " · Anchor", " · Kritik eşik", lang=r.lang)
    score_word = "Puan" if is_tr else "Score"
    score_text = f"{score_word} {result.score}/100" + (anchor_lbl if result.anchored else "")
    if result.av_discount:
        score_text += pick(
            f" · −{result.av_discount} AV-ohne-Fund",
            f" · −{result.av_discount} AV clean",
            f" · −{result.av_discount} AV temiz",
            lang=r.lang,
        )
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
    short_lbl = result.risk_level.short_for(r.lang)
    if result.is_incomplete:
        if (is_en or is_tr) and result.risk_level == RiskLevel.GREEN:
            chip_lbl = "Taranamadı" if is_tr else "Unchecked"
        else:
            inc_tag = pick("unvollständig", "incomplete", "eksik", lang=r.lang)
            chip_lbl = f"{short_lbl} ({inc_tag})"
    else:
        chip_lbl = short_lbl
    chip_color = (
        _RISK_COLORS[RiskLevel.YELLOW]
        if ((is_en or is_tr) and result.is_incomplete and result.risk_level == RiskLevel.GREEN)
        else _RISK_COLORS[result.risk_level]
    )
    r.chip(chip_lbl, chip_color, chip_x, r.y)
    r.painter.setFont(_font(8))
    r.painter.setPen(_MUTED)
    r.painter.drawText(
        QRectF(chip_x - 5 - score_w, r.y, score_w, 20),
        int(Qt.AlignmentFlag.AlignRight | Qt.TextFlag.TextSingleLine),
        score_text,
    )
    r.y += max(name_h, 22) + 3

    if result.is_incomplete:
        fehlt_font = _font(8.5)
        stage_names = " | ".join(localized_indicator_title(i, lang=r.lang) for i in result.incomplete_stages)
        inc_line = pick(
            f"Nicht geprüft: {stage_names} — das Urteil oben deckt diese Stufen NICHT ab.",
            f"Unchecked: {stage_names} — the verdict above does NOT cover these stages.",
            f"Taranamadı: {stage_names} — yukarıdaki karar bu aşamaları KAPSAMAZ.",
            lang=r.lang,
        )
        fehlt_lines = r.wrap_lines(inc_line, width - 110, fehlt_font)
        fehlt_h = r.lines_height(fehlt_lines, fehlt_font)
        r.ensure(fehlt_h + 10)
        r.fill(QRectF(r.x + indent, r.y, width, fehlt_h + 10), _ADVICE_BG)
        r.draw_lines_at(fehlt_lines, r.x + indent + 8, r.y + 4, fehlt_font, _INK)
        r.y += fehlt_h + 14

    # Recommendation band.
    advice_font = _font(8.5)
    label_font = _font(8.5, bold=True)
    advice_lines = r.wrap_lines(result.risk_level.advice_for(r.lang), width - 110, advice_font)
    label_lines = r.wrap_lines(pick("Empfehlung:", "Advice:", "Öneri:", lang=r.lang), 90, label_font)
    advice_h = max(
        r.lines_height(advice_lines, advice_font),
        r.lines_height(label_lines, label_font),
    )
    r.ensure(advice_h + 10)
    r.fill(QRectF(r.x + indent, r.y, width, advice_h + 10), _ADVICE_BG)
    r.draw_lines_at(label_lines, r.x + indent + 8, r.y + 4, label_font, _INK)
    r.draw_lines_at(advice_lines, r.x + indent + 98, r.y + 4, advice_font, _INK)
    r.y += advice_h + 14

    # Metadata.
    _kv_line(r, pick("Pfad", "Path", "Konum", lang=r.lang), _clip(result.path, MAX_DISPLAY_CHARS), width)
    _kv_line(
        r,
        pick("Typ", "Type", "Tür", lang=r.lang),
        type_description(result.detected_type, result.mime_hint, lang=r.lang),
        width,
    )
    _kv_line(
        r,
        pick("Größe", "Size", "Boyut", lang=r.lang),
        pick(f"{result.size} Bytes", f"{result.size} bytes", f"{result.size} bayt", lang=r.lang),
        width,
    )
    _kv_line(r, "SHA-256", result.sha256 or "—", width)
    _kv_line(r, pick("Dauer", "Duration", "Süre", lang=r.lang), f"{result.duration_ms} ms", width)
    if result.error:
        _kv_line(
            r,
            pick("Hinweis", "Note", "Not", lang=r.lang),
            localized_incomplete_reason(mask_invisible(result.error), lang=r.lang),
            width,
        )
    for label, value in mail_lines(result, lang=r.lang):
        _kv_line(r, label, value, width)
    if result.engine_verdicts:
        _kv_line(
            r,
            "Engines",
            " · ".join(
                f"{localized_engine_name(v.engine, lang=r.lang)}: "
                f"{localized_engine_label(v.state, v.label, lang=r.lang)}"
                for v in result.engine_verdicts
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
            pick(
                f"Befunde ({len(indicators)}):",
                f"Findings ({len(indicators)}):",
                f"Bulgular ({len(indicators)}):",
                lang=r.lang,
            ),
        )
        r.y += 16
        for ind in indicators:
            _indicator_row(r, ind, width - indent, indent)
    else:
        r.ensure(14)
        r.draw_text(
            pick("Keine Auffälligkeiten.", "No findings.", "Bulgu yok.", lang=r.lang),
            r.x + indent,
            width - indent,
            _font(8),
            _MUTED,
            min_height=12,
        )

    # Nested members: attachments for a mail, archive entries otherwise.
    if result.children:
        r.gap(4)
        if is_mail_result(result):
            head = pick(
                f"Anhänge ({len(result.children)}):",
                f"Attachments ({len(result.children)}):",
                f"Ekler ({len(result.children)}):",
                lang=r.lang,
            )
        else:
            head = pick(
                f"Archiv-Inhalt ({len(result.children)} Einträge):",
                f"Archive contents ({len(result.children)} entries):",
                f"Arşiv içeriği ({len(result.children)} öğe):",
                lang=r.lang,
            )
        head_font = _font(8.5, bold=True)
        head_lines = r.wrap_lines(head, width - indent, head_font)
        head_h = r.lines_height(head_lines, head_font)
        r.ensure(head_h)
        r.draw_lines_at(head_lines, r.x + indent, r.y, head_font, _INK)
        r.y += head_h + 6
        for child in result.children:
            r.ensure(30)
            _render_result(r, child, width - 18, indent + 18, depth + 1)

    r.hline()
    r.gap(6)


def _header(r: _PdfRenderer, title: str) -> None:
    now = (
        datetime.datetime.now()
        .astimezone()
        .strftime("%Y-%m-%d %H:%M" if r.lang == "en" else "%d.%m.%Y %H:%M")
    )
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
    subtitle = pick(
        f"Analysebericht · erstellt {now} · Version {__version__} · "
        "100% offline · kein JavaScript, keine Cloud",
        f"Security report · generated {now} · Version {__version__} · 100% offline · no JavaScript, no cloud",
        f"Güvenlik raporu · oluşturma {now} · Sürüm {__version__} · "
        "%100 çevrimdışı · JavaScript yok, bulut yok",
        lang=r.lang,
    )
    r.painter.drawText(
        QRectF(r.x + 16, r.y + 34, r.page_rect.width() - 32, 18),
        int(Qt.TextFlag.TextSingleLine),
        subtitle,
    )
    r.y += 64 + 14


def _summary_cards(r: _PdfRenderer, results: list[ScanResult]) -> None:
    counts = {level: 0 for level in RiskLevel}
    for res in results:
        counts[res.risk_level] += 1
    gap = 10.0
    card_w = (r.page_rect.width() - 3 * gap) / 4
    cards = (
        (pick("Dateien gesamt", "Total files", "Toplam dosya", lang=r.lang), len(results), _INK),
        (RiskLevel.GREEN.short_for(r.lang), counts[RiskLevel.GREEN], _RISK_COLORS[RiskLevel.GREEN]),
        (RiskLevel.YELLOW.short_for(r.lang), counts[RiskLevel.YELLOW], _RISK_COLORS[RiskLevel.YELLOW]),
        (RiskLevel.RED.short_for(r.lang), counts[RiskLevel.RED], _RISK_COLORS[RiskLevel.RED]),
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

    legend = pick(
        "Einordnung: Unauffällig = keine Anzeichen für Manipulation · "
        "Verdächtig = nur bei vertrauenswürdigem Absender öffnen · "
        "Gefährlich = nicht öffnen, löschen und ggf. die IT informieren.",
        "Classification: Clean = no signs of tampering · "
        "Suspicious = only open if you trust the sender · "
        "Dangerous = do not open, delete and notify IT.",
        "Değerlendirme: Temiz = teknik tehdit işareti yok · "
        "Şüpheli = yalnızca göndericiye güveniyorsanız açın · "
        "Tehlikeli = açmayın, silin ve BT ekibinize bildirin.",
        lang=r.lang,
    )
    r.draw_text(legend, r.x, r.page_rect.width(), _font(8), _MUTED)
    r.gap(10)


def generate_pdf(
    results: list[ScanResult],
    path: str | Path,
    title: str | None = None,
    *,
    lang: str | None = None,
) -> Path:
    """Render the batch of results into a real PDF file at ``path``."""
    eff = resolve_language(lang) if lang is not None else get_language()
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    default_title = pick(
        f"{config.APP_NAME} — Analysebericht",
        f"{config.APP_NAME} — Security Scan Report",
        f"{config.APP_NAME} — Güvenlik Tarama Raporu",
        lang=eff,
    )
    doc_title = title or default_title

    tmp_out = out.with_name(f".{out.name}.tmp-{os.getpid()}")
    try:
        with language_context(eff):
            _render_to_file(results, tmp_out, doc_title, out, lang=eff)
        os.replace(tmp_out, out)
    except Exception:
        with suppress(OSError):
            tmp_out.unlink(missing_ok=True)
        raise
    return out


def _render_to_file(
    results: list[ScanResult],
    target: Path,
    doc_title: str,
    original: Path,
    *,
    lang: str = "de",
) -> None:
    writer = QPdfWriter(str(target))
    writer.setTitle(doc_title)
    writer.setCreator(f"{config.APP_NAME} v{__version__}")
    writer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
    writer.setPageMargins(QMarginsF(14, 12, 14, 16), QPageLayout.Unit.Millimeter)
    writer.setResolution(96)

    r = _PdfRenderer(writer, lang=lang)
    if not r.painter.isActive():
        raise OSError(f"PDF-Zieldatei nicht schreibbar: {original}")
    try:
        _header(r, doc_title)
        _summary_cards(r, results)
        if results:
            for result in results:
                _render_result(r, result, r.page_rect.width())
        else:
            r.draw_text(
                pick("Keine Dateien analysiert.", "No files analyzed.", "Taranan dosya yok.", lang=lang),
                r.x,
                r.page_rect.width(),
                _font(9.5),
                _MUTED,
            )
    except Exception:
        with suppress(Exception):
            r.painter.end()
        raise
    r.footer()
    if not r.painter.end():
        raise OSError(f"PDF konnte nicht abgeschlossen werden: {original}")


# Friendly aliases matching html_report.save_report and spec naming.
save_pdf_report = generate_pdf
export_pdf_report = generate_pdf
