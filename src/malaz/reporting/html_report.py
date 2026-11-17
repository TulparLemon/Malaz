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


def _severity_badge(severity: Severity) -> str:
    cls = _SEV_CLASS.get(severity, "info")
    return f'<span class="sev {cls}">{escape_html(severity.label)}</span>'


def _risk_badge(result: ScanResult) -> str:
    color = result.risk_level.color
    label = escape_html(result.risk_level.label)
    if result.is_incomplete:
        label = f"{escape_html(result.risk_level.short)} (unvollständig)"
    return f'<span class="badge" style="background:{color}">{label}</span>'


_ENGINE_COLORS = {
    "threat": "#b3261e",
    "clean": "#2e7d32",
    "skipped": "#8a5a00",
    "error": "#b3261e",
    "off": "#5f6368",
}
_ENGINE_MARKS = {
    "threat": "\u2716", "clean": "\u2714", "skipped": "\u26a0",
    "error": "!", "off": "\u2013",
}


def _engine_strip(result: ScanResult) -> str:
    if not result.engine_verdicts:
        return ""
    parts = []
    for verdict in result.engine_verdicts:
        colour = _ENGINE_COLORS.get(verdict.state, _ENGINE_COLORS["off"])
        mark = _ENGINE_MARKS.get(verdict.state, "\u2013")
        parts.append(
            f'<span class="engine" style="border-color:{colour};color:{colour}">'
            f"{mark} {escape_html(verdict.engine)}: {escape_html(verdict.label)}"
            "</span>"
        )
    return '<div class="engines">' + "".join(parts) + "</div>"


def _indicator_rows(indicators: list[Indicator]) -> str:
    if not indicators:
        return '<tr><td colspan="4" class="empty">Keine Auffälligkeiten.</td></tr>'
    rows = []
    # Highest severity first for readability.
    for ind in sorted(indicators, key=lambda i: i.severity, reverse=True):
        rows.append(
            "<tr>"
            f"<td>{_severity_badge(ind.severity)}</td>"
            f"<td class='mono'>{escape_html(ind.rule_id)}<br>"
            f"<span style='color:#999'>{escape_html(ind.source)}</span></td>"
            f"<td>{escape_html(ind.title)}</td>"
            f"<td class='detail'>{_esc_newlines(ind.detail)}</td>"
            "</tr>"
        )
    return "".join(rows)


def _kv(label: str, value: object) -> str:
    return f'<div class="k">{escape_html(label)}</div><div class="v">{escape_html(value)}</div>'


def _render_result(result: ScanResult, is_child: bool = False) -> str:
    head = (
        '<div class="file-head">'
        f'<span class="name">{escape_html(_clip(result.display_name, MAX_DISPLAY_CHARS))}</span>'
        f"{_risk_badge(result)}"
        f'<span class="score">Score: {result.score}/100'
        + (" · Anker aktiv" if result.anchored else "")
        # Why the score can be lower than its raw findings: clean AV votes
        # (§ models.ScanResult.av_discount). Without this line the verdict
        # colour is inexplicable to the reader.
        + (
            f" · {result.av_discount} Punkte Nachlass (AV-ohne-Fund)"
            if result.av_discount
            else ""
        )
        + "</span>"
        "</div>"
    )
    engines = _engine_strip(result)

    meta = (
        '<div class="kv">'
        + _kv("Pfad", _clip(result.path, MAX_DISPLAY_CHARS))
        + _kv("Typ", type_description(result.detected_type, result.mime_hint))
        + _kv("Größe", f"{result.size} Bytes")
        + _kv("SHA-256", result.sha256 or "—")
        + _kv("MD5", result.md5 or "—")
        + _kv("Dauer", f"{result.duration_ms} ms")
        + (_kv("Fehler", result.error) if result.error else "")
        + "".join(_kv(label, value) for label, value in mail_lines(result))
        + "</div>"
    )

    table = (
        "<table><thead><tr>"
        "<th style='width:90px'>Schwere</th><th style='width:200px'>Regel</th>"
        "<th style='width:280px'>Befund</th><th>Detail</th>"
        "</tr></thead><tbody>"
        + _indicator_rows(result.indicators)
        + "</tbody></table>"
    )

    children_html = ""
    if result.children:
        # Name the group: a mail's attachments and an archive's members are
        # both children, but a reader scanning a phishing report needs to see
        # "Attachments", not a bare list of nested blocks.
        noun = "Anhänge" if is_mail_result(result) else "Archiveinträge"
        children_html = (
            f'<div class="children-head">{escape_html(noun)} '
            f"({len(result.children)}):</div>"
            + "".join(_render_result(c, is_child=True) for c in result.children)
        )

    container_cls = "child" if is_child else "file"
    head_cls = "child-head" if is_child else "file-head"
    head = head.replace('class="file-head"', f'class="{head_cls}"', 1)
    incomplete = ""
    if result.is_incomplete:
        titles = " | ".join(escape_html(i.title) for i in result.incomplete_stages)
        incomplete = (
            '<div class="incomplete"><b>Nicht geprüft:</b> '
            f"{titles}. Das Urteil oben deckt diese Stufen NICHT ab.</div>"
        )
    advice = (
        '<div class="advice"><b>Empfehlung:</b> '
        f"{escape_html(result.risk_level.advice)}</div>"
    )
    return (
        f'<div class="{container_cls}">{head}{incomplete}{advice}{engines}'
        f"{meta}{table}{children_html}</div>"
    )


def generate_report(results: list[ScanResult], title: str | None = None) -> str:
    """Build the full self-contained HTML5 document for a batch of results."""
    now = datetime.datetime.now(datetime.UTC).astimezone().strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    title = title or f"{config.APP_NAME} — Analysebericht"

    counts = {RiskLevel.GREEN: 0, RiskLevel.YELLOW: 0, RiskLevel.RED: 0}
    for r in results:
        counts[r.risk_level] = counts.get(r.risk_level, 0) + 1
    incomplete_count = sum(1 for r in results if r.is_incomplete)

    summary = (
        '<div class="summary">'
        f'<div class="card"><div class="num">{len(results)}</div>'
        '<div class="lbl">Dateien gesamt</div></div>'
        f'<div class="card green"><div class="num">{counts[RiskLevel.GREEN]}</div>'
        f'<div class="lbl">{escape_html(RiskLevel.GREEN.short)} (Grün)</div></div>'
        f'<div class="card yellow"><div class="num">{counts[RiskLevel.YELLOW]}</div>'
        f'<div class="lbl">{escape_html(RiskLevel.YELLOW.short)} (Gelb)</div></div>'
        f'<div class="card red"><div class="num">{counts[RiskLevel.RED]}</div>'
        f'<div class="lbl">{escape_html(RiskLevel.RED.short)} (Rot)</div></div>'
        f'<div class="card"><div class="num">{incomplete_count}</div>'
        '<div class="lbl">Nicht vollständig geprüft</div></div>'
        "</div>"
        '<div class="legend"><b>Einordnung:</b> Unauffällig = keine Anzeichen für '
        "Manipulation · Verdächtig = nur bei vertrauenswürdigem Absender öffnen · "
        "Gefährlich = nicht öffnen, löschen und ggf. die IT informieren.</div>"
    )

    if results:
        body = "".join(_render_result(r) for r in results)
    else:
        body = '<div class="file"><div class="empty">Keine Dateien analysiert.</div></div>'

    caps = ", ".join(
        f"{name}={'ja' if ok else 'nein'}"
        for name, ok in sorted(config.available_capabilities().items())
    )

    return (
        "<!DOCTYPE html>\n"
        '<html lang="de"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{escape_html(title)}</title>"
        f"<style>{_CSS}</style></head><body>"
        f"<header><h1>{escape_html(config.APP_NAME)}</h1>"
        f'<div class="meta">Analysebericht · erstellt {escape_html(now)} · '
        f"Version {escape_html(__version__)} · 100% offline</div></header>"
        f'<div class="wrap">{summary}{body}</div>'
        f"<footer>Malaz v{escape_html(__version__)} — rein statische Analyse, "
        "keine Ausführung von Payloads. Verfügbare Module: "
        f"{escape_html(caps)}. Dieser Bericht enthält kein JavaScript.</footer>"
        "</body></html>"
    )


def save_report(results: list[ScanResult], path: str | Path, title: str | None = None) -> Path:
    """Generate the report and write it to ``path`` (UTF-8)."""
    html = generate_report(results, title=title)
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    return out
