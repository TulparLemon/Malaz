"""Self-contained HTML5 report generation.

Security contract: every piece of data that originates from a scanned file
(indicator titles/details, extracted strings, metadata) is HTML-escaped before
it is embedded. The document contains no JavaScript and references no external
resources, so an escaped payload cannot execute even if opened in a browser.
"""

from __future__ import annotations

import datetime
from pathlib import Path

from .. import __version__, config
from ..core.mail_view import MAX_DISPLAY_CHARS, _clip
from ..i18n import (
    get_language,
    language_context,
    localized_engine_label,
    localized_engine_name,
    localized_indicator_detail,
    localized_indicator_title,
    pick,
    resolve_language,
)
from ..models import Indicator, RiskLevel, ScanResult, Severity, type_description
from ..security.escaping import escape_html
from .mail_section import is_mail_result, mail_lines

_CSS = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { font-family: 'Segoe UI', system-ui, Arial, sans-serif; margin: 0;
       background: #f4f6f8; color: #1a1a1a; line-height: 1.5; }
header { background: #10243e; color: #fff; padding: 24px 32px; }
header h1 { margin: 0 0 4px; font-size: 22px; }
header .meta { font-size: 13px; opacity: .85; }
.wrap { max-width: 1100px; margin: 0 auto; padding: 24px 32px 64px; }
.summary { display: flex; gap: 16px; flex-wrap: wrap; margin: 20px 0 32px; }
.card { flex: 1 1 160px; background: #fff; border-radius: 10px; padding: 16px 20px;
        box-shadow: 0 1px 3px rgba(0,0,0,.12); border-left: 6px solid #ccc; }
.card .num { font-size: 30px; font-weight: 700; }
.card .lbl { font-size: 13px; color: #555; }
.card.green { border-left-color: #2e7d32; }
.card.yellow { border-left-color: #f9a825; }
.card.red { border-left-color: #c62828; }
.file { background: #fff; border-radius: 10px; margin-bottom: 24px;
        box-shadow: 0 1px 3px rgba(0,0,0,.12); overflow: hidden; }
.file-head { display: flex; align-items: center; gap: 12px; padding: 16px 20px;
             border-bottom: 1px solid #eee; flex-wrap: wrap; }
.file-head .name { font-weight: 600; font-size: 16px; word-break: break-all; }
.badge { display: inline-block; padding: 3px 10px; border-radius: 12px; color: #fff;
         font-size: 12px; font-weight: 600; white-space: nowrap; }
.score { font-size: 13px; color: #444; }
.engines { margin: 6px 0 10px; display: flex; flex-wrap: wrap; gap: 6px; }
.engine { display: inline-block; border: 1px solid; border-radius: 10px;
          padding: 2px 9px; font-size: 12px; }
.kv { display: grid; grid-template-columns: 140px 1fr; gap: 4px 12px;
      padding: 12px 20px; font-size: 13px; background: #fafbfc; }
.kv .k { color: #666; }
.kv .v { word-break: break-all; font-family: Consolas, monospace; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #f0f0f0;
         vertical-align: top; }
th { background: #f6f8fa; color: #444; font-weight: 600; }
td.detail { font-family: Consolas, monospace; white-space: pre-wrap;
            word-break: break-word; color: #333; }
.sev { display: inline-block; padding: 2px 8px; border-radius: 4px; color: #fff;
       font-size: 11px; font-weight: 600; }
.sev.info { background: #607d8b; }
.sev.low { background: #26a69a; }
.sev.medium { background: #f9a825; }
.sev.high { background: #ef6c00; }
.sev.critical { background: #c62828; }
.child { margin: 8px 20px 16px; border: 1px solid #e3e8ee; border-radius: 8px; }
.children-head { margin: 4px 20px 0; padding: 10px 12px 0; font-weight: 600;
                 font-size: 13px; color: #444; }
.child-head { padding: 8px 12px; background: #f6f8fa; font-size: 13px;
              display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.empty { padding: 16px 20px; color: #777; font-size: 13px; }
footer { text-align: center; color: #888; font-size: 12px; padding: 24px; }
.mono { font-family: Consolas, monospace; }
.advice { padding: 10px 20px; font-size: 13px; background: #f2f6fa;
          border-bottom: 1px solid #eee; color: #333; }
.incomplete { padding: 10px 20px; font-size: 13px; background: #fff4ce;
            border-bottom: 1px solid #ead38a; color: #5c4700; }
.legend { font-size: 13px; color: #555; margin: 0 0 24px; }
"""

_SEV_CLASS = {
    Severity.INFO: "info",
    Severity.LOW: "low",
    Severity.MEDIUM: "medium",
    Severity.HIGH: "high",
    Severity.CRITICAL: "critical",
}


def _esc_newlines(text: str) -> str:
    """Escape, then turn newlines into <br> for readable detail cells."""
    return escape_html(text).replace("\n", "<br>")


def _severity_badge(severity: Severity, *, lang: str) -> str:
    cls = _SEV_CLASS.get(severity, "info")
    return f'<span class="sev {cls}">{escape_html(severity.label_for(lang))}</span>'


def _risk_badge(result: ScanResult, *, lang: str) -> str:
    color = result.risk_level.color
    if result.is_incomplete:
        if lang == "tr":
            label = f"{escape_html(result.risk_level.short_for('tr'))} (Denetlenmedi / eksik)"
            if result.risk_level == RiskLevel.GREEN:
                color = "#8a5a00"
        elif lang == "en":
            label = f"{escape_html(result.risk_level.short_for('en'))} (Unchecked / incomplete)"
            if result.risk_level == RiskLevel.GREEN:
                color = "#8a5a00"
        else:
            label = f"{escape_html(result.risk_level.short_for('de'))} (unvollständig)"
    else:
        label = escape_html(result.risk_level.label_for(lang))
    return f'<span class="badge" style="background:{color}">{label}</span>'


_ENGINE_COLORS = {
    "threat": "#b3261e",
    "clean": "#2e7d32",
    "skipped": "#8a5a00",
    "error": "#b3261e",
    "off": "#5f6368",
}
_ENGINE_MARKS = {
    "threat": "\u2716",
    "clean": "\u2714",
    "skipped": "\u26a0",
    "error": "!",
    "off": "\u2013",
}


def _engine_strip(result: ScanResult, *, lang: str) -> str:
    if not result.engine_verdicts:
        return ""
    parts = []
    for verdict in result.engine_verdicts:
        colour = _ENGINE_COLORS.get(verdict.state, _ENGINE_COLORS["off"])
        mark = _ENGINE_MARKS.get(verdict.state, "\u2013")
        eng_name = localized_engine_name(verdict.engine, lang=lang)
        eng_lbl = localized_engine_label(verdict.state, verdict.label, lang=lang)
        parts.append(
            f'<span class="engine" style="border-color:{colour};color:{colour}">'
            f"{mark} {escape_html(eng_name)}: {escape_html(eng_lbl)}"
            "</span>"
        )
    return '<div class="engines">' + "".join(parts) + "</div>"


def _indicator_rows(indicators: list[Indicator], *, lang: str) -> str:
    if not indicators:
        empty_txt = pick("Keine Auffälligkeiten.", "No findings.", "Bulgu yok.", lang=lang)
        return f'<tr><td colspan="4" class="empty">{escape_html(empty_txt)}</td></tr>'
    rows = []
    for ind in sorted(indicators, key=lambda i: i.severity, reverse=True):
        title_txt = localized_indicator_title(ind, lang=lang)
        detail_txt = localized_indicator_detail(ind, lang=lang)
        rows.append(
            "<tr>"
            f"<td>{_severity_badge(ind.severity, lang=lang)}</td>"
            f"<td class='mono'>{escape_html(ind.rule_id)}<br>"
            f"<span style='color:#999'>{escape_html(ind.source)}</span></td>"
            f"<td>{escape_html(title_txt)}</td>"
            f"<td class='detail'>{_esc_newlines(detail_txt)}</td>"
            "</tr>"
        )
    return "".join(rows)


def _kv(label: str, value: object) -> str:
    return f'<div class="k">{escape_html(label)}</div><div class="v">{escape_html(value)}</div>'


def _render_result(result: ScanResult, is_child: bool = False, *, lang: str = "de") -> str:
    anchor_str = pick(" · Anker aktiv", " · Anchor active", " · Kritik eşik aktif", lang=lang)
    discount_str = pick(
        f" · {result.av_discount} Punkte Nachlass (AV-ohne-Fund)",
        f" · {result.av_discount} pts discount (AV clean)",
        f" · {result.av_discount} puan indirim (AV temiz)",
        lang=lang,
    )
    head = (
        '<div class="file-head">'
        f'<span class="name">{escape_html(_clip(result.display_name, MAX_DISPLAY_CHARS))}</span>'
        f"{_risk_badge(result, lang=lang)}"
        f'<span class="score">Score: {result.score}/100'
        + (anchor_str if result.anchored else "")
        + (discount_str if result.av_discount else "")
        + "</span>"
        "</div>"
    )
    engines = _engine_strip(result, lang=lang)

    meta = (
        '<div class="kv">'
        + _kv(pick("Pfad", "Path", "Konum", lang=lang), _clip(result.path, MAX_DISPLAY_CHARS))
        + _kv(
            pick("Typ", "Type", "Tür", lang=lang),
            type_description(result.detected_type, result.mime_hint, lang=lang),
        )
        + _kv(
            pick("Größe", "Size", "Boyut", lang=lang),
            pick(f"{result.size} Bytes", f"{result.size} bytes", f"{result.size} bayt", lang=lang),
        )
        + _kv("SHA-256", result.sha256 or "—")
        + _kv("MD5", result.md5 or "—")
        + _kv(pick("Dauer", "Duration", "Süre", lang=lang), f"{result.duration_ms} ms")
        + (_kv(pick("Fehler", "Error", "Hata", lang=lang), result.error) if result.error else "")
        + "".join(_kv(label, value) for label, value in mail_lines(result, lang=lang))
        + "</div>"
    )

    th_sev = pick("Schwere", "Severity", "Önem", lang=lang)
    th_rule = pick("Regel", "Rule", "Kural", lang=lang)
    th_find = pick("Befund", "Finding", "Bulgu", lang=lang)
    table = (
        "<table><thead><tr>"
        f"<th style='width:90px'>{th_sev}</th><th style='width:200px'>{th_rule}</th>"
        f"<th style='width:280px'>{th_find}</th><th>Detail</th>"
        "</tr></thead><tbody>" + _indicator_rows(result.indicators, lang=lang) + "</tbody></table>"
    )

    children_html = ""
    if result.children:
        noun = (
            pick("Anhänge", "Attachments", "Ekler", lang=lang)
            if is_mail_result(result)
            else pick("Archiveinträge", "Archive entries", "Arşiv öğeleri", lang=lang)
        )
        children_html = (
            f'<div class="children-head">{escape_html(noun)} '
            f"({len(result.children)}):</div>"
            + "".join(_render_result(c, is_child=True, lang=lang) for c in result.children)
        )

    container_cls = "child" if is_child else "file"
    head_cls = "child-head" if is_child else "file-head"
    head = head.replace('class="file-head"', f'class="{head_cls}"', 1)
    incomplete = ""
    if result.is_incomplete:
        titles = " | ".join(
            escape_html(localized_indicator_title(i, lang=lang)) for i in result.incomplete_stages
        )
        if lang == "tr":
            incomplete = (
                '<div class="incomplete"><b>Denetlenmedi:</b> '
                f"{titles}. Yukarıdaki karar bu aşamaları KAPSAMAZ.</div>"
            )
        elif lang == "en":
            incomplete = (
                '<div class="incomplete"><b>Unchecked:</b> '
                f"{titles}. The verdict above does NOT cover these stages.</div>"
            )
        else:
            incomplete = (
                '<div class="incomplete"><b>Nicht geprüft:</b> '
                f"{titles}. Das Urteil oben deckt diese Stufen NICHT ab.</div>"
            )
    advice_lbl = pick("Empfehlung:", "Recommendation:", "Öneri:", lang=lang)
    advice = (
        f'<div class="advice"><b>{advice_lbl}</b> {escape_html(result.risk_level.advice_for(lang))}</div>'
    )
    return (
        f'<div class="{container_cls}">{head}{incomplete}{advice}{engines}{meta}{table}{children_html}</div>'
    )


def generate_report(
    results: list[ScanResult],
    title: str | None = None,
    *,
    lang: str | None = None,
) -> str:
    """Build the full self-contained HTML5 document for a batch of results."""
    eff = resolve_language(lang) if lang is not None else get_language()
    is_en = eff == "en"
    with language_context(eff):
        now = datetime.datetime.now(datetime.UTC).astimezone().strftime("%Y-%m-%d %H:%M:%S")
        default_title = pick(
            f"{config.APP_NAME} — Analysebericht",
            f"{config.APP_NAME} — Security Scan Report",
            f"{config.APP_NAME} — Güvenlik Tarama Raporu",
            lang=eff,
        )
        doc_title = title or default_title

        counts = {RiskLevel.GREEN: 0, RiskLevel.YELLOW: 0, RiskLevel.RED: 0}
        for r in results:
            counts[r.risk_level] = counts.get(r.risk_level, 0) + 1
        incomplete_count = sum(1 for r in results if r.is_incomplete)

        if eff == "tr":
            summary = (
                '<div class="summary">'
                f'<div class="card"><div class="num">{len(results)}</div>'
                '<div class="lbl">Toplam dosya</div></div>'
                f'<div class="card green"><div class="num">{counts[RiskLevel.GREEN]}</div>'
                f'<div class="lbl">{escape_html(RiskLevel.GREEN.short_for("tr"))} (Yeşil)</div></div>'
                f'<div class="card yellow"><div class="num">{counts[RiskLevel.YELLOW]}</div>'
                f'<div class="lbl">{escape_html(RiskLevel.YELLOW.short_for("tr"))} (Sarı)</div></div>'
                f'<div class="card red"><div class="num">{counts[RiskLevel.RED]}</div>'
                f'<div class="lbl">{escape_html(RiskLevel.RED.short_for("tr"))} (Kırmızı)</div></div>'
                f'<div class="card"><div class="num">{incomplete_count}</div>'
                '<div class="lbl">Eksik / denetlenmedi</div></div>'
                "</div>"
                '<div class="legend"><b>Değerlendirme:</b> Temiz = teknik tehdit işareti yok · '
                "Şüpheli = yalnızca göndericiye güveniyorsanız açın · "
                "Tehlikeli = açmayın, silin ve BT ekibinize bildirin.</div>"
            )
        elif is_en:
            summary = (
                '<div class="summary">'
                f'<div class="card"><div class="num">{len(results)}</div>'
                '<div class="lbl">Total files</div></div>'
                f'<div class="card green"><div class="num">{counts[RiskLevel.GREEN]}</div>'
                f'<div class="lbl">{escape_html(RiskLevel.GREEN.short_for("en"))} (Green)</div></div>'
                f'<div class="card yellow"><div class="num">{counts[RiskLevel.YELLOW]}</div>'
                f'<div class="lbl">{escape_html(RiskLevel.YELLOW.short_for("en"))} (Yellow)</div></div>'
                f'<div class="card red"><div class="num">{counts[RiskLevel.RED]}</div>'
                f'<div class="lbl">{escape_html(RiskLevel.RED.short_for("en"))} (Red)</div></div>'
                f'<div class="card"><div class="num">{incomplete_count}</div>'
                '<div class="lbl">Unchecked / incomplete</div></div>'
                "</div>"
                '<div class="legend"><b>Classification:</b> Clean = no signs of tampering · '
                "Suspicious = only open if you trust the sender · "
                "Dangerous = do not open, delete and notify IT.</div>"
            )
        else:
            summary = (
                '<div class="summary">'
                f'<div class="card"><div class="num">{len(results)}</div>'
                '<div class="lbl">Dateien gesamt</div></div>'
                f'<div class="card green"><div class="num">{counts[RiskLevel.GREEN]}</div>'
                f'<div class="lbl">{escape_html(RiskLevel.GREEN.short_for("de"))} (Grün)</div></div>'
                f'<div class="card yellow"><div class="num">{counts[RiskLevel.YELLOW]}</div>'
                f'<div class="lbl">{escape_html(RiskLevel.YELLOW.short_for("de"))} (Gelb)</div></div>'
                f'<div class="card red"><div class="num">{counts[RiskLevel.RED]}</div>'
                f'<div class="lbl">{escape_html(RiskLevel.RED.short_for("de"))} (Rot)</div></div>'
                f'<div class="card"><div class="num">{incomplete_count}</div>'
                '<div class="lbl">Nicht vollständig geprüft</div></div>'
                "</div>"
                '<div class="legend"><b>Einordnung:</b> Unauffällig = keine Anzeichen für '
                "Manipulation · Verdächtig = nur bei vertrauenswürdigem Absender öffnen · "
                "Gefährlich = nicht öffnen, löschen und ggf. die IT informieren.</div>"
            )

        if results:
            body = "".join(_render_result(r, lang=eff) for r in results)
        else:
            empty_msg = pick(
                "Keine Dateien analysiert.", "No files analyzed.", "Taranan dosya yok.", lang=eff
            )
            body = f'<div class="file"><div class="empty">{empty_msg}</div></div>'

        yes_word, no_word = ("evet", "hayır") if eff == "tr" else (("yes", "no") if is_en else ("ja", "nein"))
        caps = ", ".join(
            f"{name}={yes_word if ok else no_word}"
            for name, ok in sorted(config.available_capabilities().items())
        )

        if eff == "tr":
            meta_line = (
                f"Güvenlik raporu · oluşturma {escape_html(now)} · "
                f"Sürüm {escape_html(__version__)} · %100 çevrimdışı"
            )
            footer_line = (
                f"Malaz v{escape_html(__version__)} — yerel statik analiz, "
                "zararlı kod çalıştırılmaz. Mevcut modüller: "
                f"{escape_html(caps)}. Bu rapor JavaScript içermez."
            )
        elif is_en:
            meta_line = (
                f"Security report · generated {escape_html(now)} · "
                f"Version {escape_html(__version__)} · 100% offline"
            )
            footer_line = (
                f"Malaz v{escape_html(__version__)} — static local analysis, "
                "zero payload execution. Available modules: "
                f"{escape_html(caps)}. This report contains no JavaScript."
            )
        else:
            meta_line = (
                f"Analysebericht · erstellt {escape_html(now)} · "
                f"Version {escape_html(__version__)} · 100% offline"
            )
            footer_line = (
                f"Malaz v{escape_html(__version__)} — rein statische Analyse, "
                "keine Ausführung von Payloads. Verfügbare Module: "
                f"{escape_html(caps)}. Dieser Bericht enthält kein JavaScript."
            )

        return (
            "<!DOCTYPE html>\n"
            f'<html lang="{eff}"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            f"<title>{escape_html(doc_title)}</title>"
            f"<style>{_CSS}</style></head><body>"
            f"<header><h1>{escape_html(config.APP_NAME)}</h1>"
            f'<div class="meta">{meta_line}</div></header>'
            f'<div class="wrap">{summary}{body}</div>'
            f"<footer>{footer_line}</footer>"
            "</body></html>"
        )


def save_report(
    results: list[ScanResult],
    path: str | Path,
    title: str | None = None,
    *,
    lang: str | None = None,
) -> Path:
    """Generate the report and write it to ``path`` (UTF-8)."""
    html = generate_report(results, title=title, lang=lang)
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    return out


render_html_report = generate_report
