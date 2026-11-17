"""Auswertung des Realwelt-Tests: Recall, FP-Rate, Fehlerquote, p95, Wilson-95 %.

Warum die Trennung so streng ist
================================

Ein "GRÜN" auf einer Datei, deren tiefe Parser nur ein 8-MB-Präfix gesehen
haben (``CORE_READ_TRUNCATED``) oder deren AV-Engine übersprungen wurde
(``*_SKIPPED``), ist **kein** sauberer Negativbefund. Solche Zeilen zählen
weder als Treffer noch als Fehlschlag: sie fliegen aus dem Nenner und werden
separat als "unchecked" ausgewiesen. Dieselbe Regel gilt für Scan-Fehler und
fehlende Dateien — ein blockierter Scan ist kein Freispruch.

Die Rohdaten bleiben unangetastet; dieser Baustein liest nur Metadaten
(Dateiname, Typ, Urteil, Score, Regel-IDs, Dauer). Es werden keine Proben
geöffnet oder ausgeführt.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..core.unchecked import has_unchecked_markers
from ..security.escaping import mask_invisible
from .manifest import Manifest, ManifestEntry, ManifestError, load_manifest

# Die Menge der „nicht geprüft"-Regeln steht in ``core/unchecked.py``, weil
# auch ``evaluation.py`` sie braucht. Eine zweite Abschrift hier wäre genau
# die Drift, die zwei Messungen unterschiedlich zählen lässt.
_RULE_ID = re.compile(r"^([A-Za-z][A-Za-z0-9_]*)")
_VERDICTS = {
    "GRÜN": "GREEN",
    "GRUEN": "GREEN",
    "GREEN": "GREEN",
    "GELB": "YELLOW",
    "YELLOW": "YELLOW",
    "ROT": "RED",
    "RED": "RED",
    "FEHLER": "ERROR",
    "ERROR": "ERROR",
}
_GROUPS = {
    "bad": "malicious",
    "malicious": "malicious",
    "bösartig": "malicious",
    "boesartig": "malicious",
    "good": "benign",
    "benign": "benign",
    "harmlos": "benign",
}

# Ab so vielen offenen Faellen wird die Einzelliste gekappt. Die Restzahl
# MUSS im Bericht stehen (BUG-046), sonst wirkt die Liste vollstaendig.
_MAX_OPEN_CASES = 50


def _md(value: object, *, cell: bool = False) -> str:
    """Einen untrusted Wert fuer Markdown entschaerfen.

    Ergebnisnamen stammen aus einer CSV/JSON-Datei und sind damit
    angreiferkontrolliert. Ein Zeilenumbruch beendet die Tabellenzeile bzw.
    das Listenelement und laesst eine eigene Ueberschrift entstehen
    (``evil.exe\\n\\n## Recall 100 %``); ein ``|`` spaltet die Tabelle in
    zusaetzliche Spalten. Unsichtbare/bidi- und C0-Zeichen werden sichtbar
    maskiert statt entfernt — der Bericht soll zeigen, was wirklich dastand.
    """
    text = mask_invisible(value)
    text = "".join(
        f"\\x{ord(ch):02x}" if ord(ch) < 32 or ord(ch) == 0x7F else ch
        for ch in text
    )
    if cell:
        # HTML-Entitaet statt Backslash: ``\\|`` waere nach einem vorhandenen
        # Backslash im Namen wieder ein Spaltentrenner.
        text = text.replace("|", "&#124;")
    return text



@dataclass(frozen=True)
class ResultRow:
    """Eine Ergebniszeile, egal ob aus CSV (evaluate_corpus) oder JSON."""

    name: str
    group: str = ""
    type: str = ""
    verdict: str = "ERROR"
    score: int | None = None
    rules: tuple[str, ...] = ()
    duration_ms: float | None = None
    error: str = ""
    raw: dict[str, Any] = field(default_factory=dict, compare=False)


@dataclass(frozen=True)
class _Outcome:
    entry: ManifestEntry
    row: ResultRow | None
    status: str  # detected | flagged | clean | miss | unchecked | error | missing
    unchecked: bool

    @property
    def evaluated(self) -> bool:
        return self.status in {"detected", "flagged", "clean", "miss"}


def _rule_id(cell: str) -> str | None:
    match = _RULE_ID.match(cell.strip())
    return match.group(1) if match else None


def _split_rules(value: object) -> tuple[str, ...]:
    if isinstance(value, list):
        parts = [str(item) for item in value]
    elif value is None:
        parts = []
    else:
        parts = re.split(r"[|;,]", str(value))
    ids: list[str] = []
    for part in parts:
        rule = _rule_id(part)
        if rule:
            ids.append(rule)
    return tuple(dict.fromkeys(ids))


def _int_or_none(value: object) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(str(value).strip())
    except ValueError:
        return None


def _float_or_none(value: object) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(str(value).replace(",", "."))
    except ValueError:
        return None


def _verdict(value: object) -> str:
    text = str(value or "").strip().upper()
    return _VERDICTS.get(text, "ERROR")


def _group(value: object) -> str:
    return _GROUPS.get(str(value or "").strip().lower(), "")


def _column_lookup(fieldnames: Sequence[str] | None) -> dict[str, str]:
    return {(name or "").strip().lower(): name or "" for name in fieldnames or []}


_CSV_ALIASES = {
    # "datei_id" zuerst: die Anzeige-Spalte "Datei" ist beim Schreiben
    # entschaerft (safe_cell: fuehrendes ' gegen Formeln, \uXXXX gegen Bidi/
    # NUL) und damit NICHT mehr der Dateiname — "-report.pdf" wurde als
    # "'-report.pdf" gelesen und matchte keinen Manifest-Eintrag. Die
    # Identitaetsspalte schreibt evaluation.py unveraendert.
    "name": ("datei_id", "datei", "name", "file", "filename"),
    "group": ("gruppe", "group", "label"),
    "type": ("typ", "type", "detected_type"),
    "verdict": ("urteil", "verdict", "risk", "risk_level"),
    "score": ("score", "punkte"),
    "rules": ("top-findings", "top_findings", "regeln", "rules", "findings"),
    # AP4: eigene Spalte, damit ein Marker außerhalb der vier Top-Findings
    # nicht verloren geht (die Zelle trägt Regel-IDs, kein Prosa-Wort).
    "unchecked": ("ungeprueft", "unchecked", "nicht_geprueft"),
    "duration_ms": ("dauer_ms", "duration_ms", "dauer", "ms", "duration"),
    "error": ("fehler", "error"),
}


def _pick(row: dict[str, str], lookup: dict[str, str], key: str) -> str:
    for alias in _CSV_ALIASES[key]:
        column = lookup.get(alias)
        if column is not None and column in row:
            return row[column]
    return ""


def _load_csv(path: Path) -> list[ResultRow]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        lookup = _column_lookup(reader.fieldnames)
        rows: list[ResultRow] = []
        for raw in reader:
            name = _pick(raw, lookup, "name").strip()
            if not name:
                continue
            verdict = _verdict(_pick(raw, lookup, "verdict"))
            error = _pick(raw, lookup, "error").strip()
            if verdict == "ERROR" and not error:
                error = "Scan-Fehler (Ergebniszeile FEHLER)"
            rules = _split_rules(_pick(raw, lookup, "rules"))
            rules += _split_rules(_pick(raw, lookup, "unchecked"))
            rows.append(
                ResultRow(
                    name=name,
                    group=_group(_pick(raw, lookup, "group")),
                    type=_pick(raw, lookup, "type").strip(),
                    verdict=verdict,
                    score=_int_or_none(_pick(raw, lookup, "score")),
                    rules=tuple(dict.fromkeys(rules)),
                    duration_ms=_float_or_none(_pick(raw, lookup, "duration_ms")),
                    error=error,
                    raw=dict(raw),
                )
            )
    return rows


def _load_json(path: Path) -> list[ResultRow]:
    document = json.loads(path.read_text(encoding="utf-8"))
    raw_rows = (
        document.get("rows", document.get("results", document.get("files")))
        if isinstance(document, dict)
        else document
    )
    if not isinstance(raw_rows, list):
        raise ValueError(f"{path}: JSON enthält keine Ergebnisliste ('rows')")

    rows: list[ResultRow] = []
    for item in raw_rows:
        if not isinstance(item, dict):
            continue
        name = str(
            item.get("name")
            or item.get("file")
            or item.get("datei")
            or ""
        ).strip()
        if not name:
            continue
        verdict = _verdict(item.get("verdict") or item.get("risk") or item.get("urteil"))
        error = str(item.get("error") or item.get("fehler") or "").strip()
        if verdict == "ERROR" and not error:
            error = "Scan-Fehler (Ergebniszeile ERROR)"
        rules = _split_rules(item.get("rules") or item.get("findings"))
        rules += _split_rules(item.get("unchecked"))
        rows.append(
            ResultRow(
                name=name,
                group=_group(item.get("group") or item.get("label")),
                type=str(item.get("type") or item.get("typ") or "").strip(),
                verdict=verdict,
                score=_int_or_none(item.get("score")),
                rules=tuple(dict.fromkeys(rules)),
                duration_ms=_float_or_none(
                    item.get("duration_ms") or item.get("dauer_ms") or item.get("ms")
                ),
                error=error,
                raw=dict(item),
            )
        )
    return rows


def load_results(path: Path) -> list[ResultRow]:
    """CSV (evaluate_corpus) oder JSON (Lab-Lauf) einlesen."""
    if path.suffix.lower() == ".json":
        return _load_json(path)
    if path.suffix.lower() in {".csv", ".txt"}:
        return _load_csv(path)
    raise ValueError(f"{path}: nur .csv oder .json werden gelesen")


def wilson_interval(
    successes: int, total: int, z: float = 1.959963984540054
) -> tuple[float | None, float | None]:
    """Wilson-95-%-Intervall einer Proportion (auch bei n=0/100 % definiert)."""
    if total <= 0:
        return None, None
    p = successes / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    margin = (
        z
        * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total))
        / denominator
    )
    return max(0.0, center - margin), min(1.0, center + margin)


def percentile(values: list[float], fraction: float) -> float | None:
    """Nearest-Rank-Perzentil (keine Interpolation, keine Zusatzabhängigkeit)."""
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, math.ceil(fraction * len(ordered)) - 1)
    return ordered[index]


def _outcome(entry: ManifestEntry, row: ResultRow | None) -> _Outcome:
    if row is None:
        return _Outcome(entry, None, "missing", False)
    if row.verdict == "ERROR":
        return _Outcome(entry, row, "error", has_unchecked_markers(row.rules))
    detected = row.verdict in {"YELLOW", "RED"}
    unchecked = has_unchecked_markers(row.rules)
    if detected:
        return _Outcome(entry, row, "detected" if entry.label == "malicious" else "flagged", unchecked)
    if unchecked:
        return _Outcome(entry, row, "unchecked", True)
    return _Outcome(entry, row, "miss" if entry.label == "malicious" else "clean", False)


def _ratio(successes: int, total: int) -> float | None:
    return successes / total if total else None


def _group_counts(outcomes: list[_Outcome], label: str) -> dict[str, Any]:
    selected = [o for o in outcomes if o.entry.label == label]
    evaluable = [o for o in selected if o.evaluated]
    red = sum(1 for o in evaluable if o.row is not None and o.row.verdict == "RED")
    yellow_or_red = sum(
        1 for o in evaluable if o.row is not None and o.row.verdict in {"YELLOW", "RED"}
    )
    if label == "malicious":
        denominator = len(evaluable)
        primary, primary_ci = red, wilson_interval(red, denominator)
        secondary, secondary_ci = yellow_or_red, wilson_interval(yellow_or_red, denominator)
        return {
            "total": len(selected),
            "evaluable": denominator,
            "detected_red": red,
            "detected_yellow_or_red": yellow_or_red,
            "missed": sum(1 for o in evaluable if o.status == "miss"),
            "unchecked": sum(1 for o in selected if o.status == "unchecked"),
            "errors": sum(1 for o in selected if o.status == "error"),
            "missing": sum(1 for o in selected if o.status == "missing"),
            "recall_red": _ratio(primary, denominator),
            "recall_red_ci": list(primary_ci),
            "recall_yellow": _ratio(secondary, denominator),
            "recall_yellow_ci": list(secondary_ci),
        }

    denominator = len(evaluable)
    flagged_red = sum(1 for o in evaluable if o.row is not None and o.row.verdict == "RED")
    flagged = sum(
        1 for o in evaluable if o.row is not None and o.row.verdict in {"YELLOW", "RED"}
    )
    low, high = wilson_interval(flagged, denominator)
    low_red, high_red = wilson_interval(flagged_red, denominator)
    return {
        "total": len(selected),
        "evaluable": denominator,
        "flagged_red": flagged_red,
        "flagged_yellow_or_red": flagged,
        "clean": sum(1 for o in evaluable if o.status == "clean"),
        "unchecked": sum(1 for o in selected if o.status == "unchecked"),
        "errors": sum(1 for o in selected if o.status == "error"),
        "missing": sum(1 for o in selected if o.status == "missing"),
        "fp_yellow": _ratio(flagged, denominator),
        "fp_yellow_ci": [low, high],
        "fp_red": _ratio(flagged_red, denominator),
        "fp_red_ci": [low_red, high_red],
    }


def _duration(outcomes: list[_Outcome]) -> dict[str, Any]:
    values = [
        o.row.duration_ms
        for o in outcomes
        if o.row is not None and o.row.duration_ms is not None
    ]
    return {"count": len(values), "p95_ms": percentile(values, 0.95)}


def _bucket(outcomes: list[_Outcome], attribute: str) -> list[dict[str, Any]]:
    groups: dict[str, list[_Outcome]] = {}
    for outcome in outcomes:
        groups.setdefault(getattr(outcome.entry, attribute), []).append(outcome)
    result: list[dict[str, Any]] = []
    for key in sorted(groups):
        items = groups[key]
        result.append(
            {
                attribute: key,
                "malicious": _group_counts(items, "malicious"),
                "benign": _group_counts(items, "benign"),
                "duration": _duration(items),
            }
        )
    return result


def build_report(manifest: Manifest, rows: list[ResultRow]) -> dict[str, Any]:
    """Alle Kennzahlen aus Manifest + Ergebniszeilen.

    Zeilen ohne Manifest-Eintrag werden nicht ausgewertet (sie sind keiner
    Absicht zuordenbar) und als Warnung gemeldet. Manifest-Einträge ohne
    Ergebnis zählen als ``missing`` — nie als sauber.
    """
    by_name = {row.name: row for row in rows}
    outcomes = [_outcome(entry, by_name.get(entry.name)) for entry in manifest.entries]
    manifest_names = {entry.name for entry in manifest.entries}
    unexpected = sorted(name for name in by_name if name not in manifest_names)

    malicious = _group_counts(outcomes, "malicious")
    benign = _group_counts(outcomes, "benign")
    total = len(outcomes)
    unchecked = sum(1 for o in outcomes if o.status == "unchecked")
    errors = sum(1 for o in outcomes if o.status == "error")
    missing = sum(1 for o in outcomes if o.status == "missing")
    # Jede der drei Gruppen ist ein eigener Grund, warum eine Datei NICHT
    # ausgewertet wird. Die Summe ist die Quote der nicht belastbaren Zeilen.
    unchecked_rate = _ratio(unchecked, total)
    error_rate = _ratio(errors + missing, total)
    incomplete = errors + missing + unchecked

    labels_in_conflict = [
        o.entry.name
        for o in outcomes
        if o.row is not None and o.row.group and o.row.group != o.entry.label
    ]

    return {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "manifest": {
            "corpus_id": manifest.corpus_id,
            "created": manifest.created,
            "source": manifest.source,
            "schema_version": manifest.schema_version,
            "files": len(manifest.entries),
            "split_counts": {
                split: sum(1 for e in manifest.entries if e.split == split)
                for split in ("dev", "test")
            },
        },
        "totals": {
            "manifest_files": len(outcomes),
            "matched": sum(1 for o in outcomes if o.row is not None),
            "missing_results": missing,
            "unexpected_results": len(unexpected),
            "errors": errors,
            "unchecked": unchecked,
            "unchecked_rate": unchecked_rate,
            "unchecked_ci": list(wilson_interval(unchecked, total)),
            "error_rate": error_rate,
            "error_ci": list(wilson_interval(errors + missing, total)),
            "incomplete_rate": _ratio(incomplete, total),
            "incomplete_ci": list(wilson_interval(incomplete, total)),
            "duration": _duration(outcomes),
            "malicious": malicious,
            "benign": benign,
        },
        "by_type": _bucket(outcomes, "type"),
        "by_family": _bucket(outcomes, "family"),
        "files": [
            {
                "name": o.entry.name,
                "label": o.entry.label,
                "type": o.entry.type,
                "family": o.entry.family,
                "split": o.entry.split,
                "status": o.status,
                "verdict": o.row.verdict if o.row else None,
                "score": o.row.score if o.row else None,
                "duration_ms": o.row.duration_ms if o.row else None,
                "rules": list(o.row.rules) if o.row else [],
                "error": o.row.error if o.row else "",
                "unchecked": o.unchecked,
            }
            for o in outcomes
        ],
        "warnings": [
            f"{len(unexpected)} Ergebniszeile(n) ohne Manifest-Eintrag: "
            + ", ".join(unexpected[:10])
        ]
        if unexpected
        else [],
        "label_conflicts": labels_in_conflict,
    }


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f} %"


def _ci(pair: list[float | None]) -> str:
    low, high = pair
    if low is None or high is None:
        return "n/a"
    return f"{low * 100:.0f}–{high * 100:.0f} %"


def _metric_row(label: str, bad: dict[str, Any], good: dict[str, Any]) -> str:
    return (
        f"| {label} | {bad['total']} | {bad['evaluable']} | "
        f"{_pct(bad['recall_red'])} ({_ci(bad['recall_red_ci'])}) | "
        f"{_pct(bad['recall_yellow'])} ({_ci(bad['recall_yellow_ci'])}) | "
        f"{_pct(good['fp_yellow'])} ({_ci(good['fp_yellow_ci'])}) | "
        f"{_pct(good['fp_red'])} | {bad['unchecked'] + good['unchecked']} |"
    )


def render_markdown(report: dict[str, Any]) -> str:
    totals = report["totals"]
    bad, good = totals["malicious"], totals["benign"]
    lines = [
        "# Realwelt-Auswertung",
        "",
        (
            f"- Korpus: `{report['manifest']['corpus_id']}` "
            f"(angelegt {report['manifest']['created']}, "
            f"Quelle: {report['manifest']['source']})"
        ),
        (
            f"- Manifest-Dateien: {totals['manifest_files']} "
            f"(dev/test: {report['manifest']['split_counts']['dev']}/"
            f"{report['manifest']['split_counts']['test']})"
        ),
        f"- Ergebniszeilen ohne Manifest: {totals['unexpected_results']}",
        f"- Scan-Fehler: {totals['errors']} · fehlende Ergebnisse: {totals['missing_results']}",
        (
            f"- Nicht vollständig geprüft (unchecked): {totals['unchecked']} "
            f"({_pct(totals['unchecked_rate'])})"
        ),
        (
            f"- Fehler + fehlende Ergebnisse: {_pct(totals['error_rate'])} "
            f"(Wilson {_ci(totals['error_ci'])})"
        ),
        (
            f"- Nicht belastbar insgesamt (Fehler + fehlend + unchecked): "
            f"{_pct(totals['incomplete_rate'])} "
            f"(Wilson {_ci(totals['incomplete_ci'])})"
        ),
        (
            f"- p95-Dauer: {totals['duration']['p95_ms']} ms "
            f"(n={totals['duration']['count']})"
        ),
        "",
        (
            "> Ein GRÜN auf einer Datei mit `*_SKIPPED`, `CORE_READ_TRUNCATED`, "
            "`CORE_TIME_BUDGET` oder einem Scan-Fehler zählt **nicht** als sauber. "
            "Solche Zeilen stehen unter „unchecked\" und fallen aus dem Nenner."
        ),
        "",
        "| Gruppe | Dateien | auswertbar | Recall@ROT | Recall@≥GELB | FP@≥GELB | FP@ROT | unchecked |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
        _metric_row("gesamt", bad, good),
        "",
    ]

    if report["by_type"]:
        lines += [
            "## Nach Typ",
            "",
            (
                "| Typ | bösartig | auswertbar | Recall@ROT | Recall@≥GELB | "
                "harmlos | FP@≥GELB | p95 ms |"
            ),
            "|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
        for bucket in report["by_type"]:
            b, g = bucket["malicious"], bucket["benign"]
            lines.append(
                f"| {bucket['type']} | {b['total']} | {b['evaluable']} | "
                f"{_pct(b['recall_red'])} | {_pct(b['recall_yellow'])} | "
                f"{g['total']} | {_pct(g['fp_yellow'])} | "
                f"{bucket['duration']['p95_ms'] or 'n/a'} |"
            )
        lines.append("")

    if report["by_family"]:
        lines += [
            "## Nach Familie",
            "",
            "| Familie | bösartig | auswertbar | Recall@ROT | Recall@≥GELB | FP@≥GELB |",
            "|---|---:|---:|---:|---:|---:|",
        ]
        for bucket in report["by_family"]:
            b, g = bucket["malicious"], bucket["benign"]
            lines.append(
                f"| {bucket['family']} | {b['total']} | {b['evaluable']} | "
                f"{_pct(b['recall_red'])} | {_pct(b['recall_yellow'])} | "
                f"{_pct(g['fp_yellow'])} |"
            )
        lines.append("")

    misses = [f for f in report["files"] if f["status"] in {"miss", "unchecked"}]
    if misses:
        lines += [
            "## Offene Fälle (kein eindeutiges ROT/GELB, nicht als sauber gezählt)",
            "",
            "| Datei | Label | Typ | Familie | Status | Urteil | Score |",
            "|---|---|---|---|---|---|---:|",
        ]
        for item in misses[:_MAX_OPEN_CASES]:
            lines.append(
                f"| {_md(item['name'], cell=True)} | {_md(item['label'], cell=True)} "
                f"| {_md(item['type'], cell=True)} | {_md(item['family'], cell=True)} "
                f"| {_md(item['status'], cell=True)} | {_md(item['verdict'], cell=True)} "
                f"| {item['score'] if item['score'] is not None else ''} |"
            )
        if len(misses) > _MAX_OPEN_CASES:
            lines.append(
                f"| … und {len(misses) - _MAX_OPEN_CASES} weitere | | | | | | |"
            )
        lines.append("")

    if report["warnings"]:
        lines += ["## Warnungen", ""] + [f"- {_md(w)}" for w in report["warnings"]] + [""]
    if report["label_conflicts"]:
        lines += [
            "## Label-Konflikte",
            "",
            "Die CSV-Gruppe widerspricht dem Manifest-Label (das Manifest gewinnt):",
            "",
        ] + [f"- {_md(name)}" for name in report["label_conflicts"]] + [""]

    lines += [
        "## Methode",
        "",
        "- Recall@ROT: Anteil der auswertbaren bösartigen Dateien mit Urteil ROT.",
        "- Recall@≥GELB: Anteil mit GELB oder ROT.",
        (
            "- FP@≥GELB / FP@ROT: Anteil der auswertbaren harmlosen Dateien mit "
            "GELB/ROT (beziehungsweise ROT)."
        ),
        (
            "- Fehler, fehlende Ergebnisse und unchecked-Fälle sind aus dem Nenner "
            "ausgeschlossen und separat ausgewiesen."
        ),
        "- 95-%-Intervalle: Wilson-Score-Intervall. p95: Nearest-Rank.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("manifest", type=Path, help="realworld_manifest.json")
    parser.add_argument("results", type=Path, help="Ergebnis-CSV oder -JSON")
    parser.add_argument("--json", type=Path, default=None, help="Report als JSON schreiben")
    parser.add_argument("--markdown", type=Path, default=None, help="Report als Markdown schreiben")
    args = parser.parse_args(argv)

    try:
        manifest = load_manifest(args.manifest)
        rows = load_results(args.results)
    except (ManifestError, ValueError, OSError, json.JSONDecodeError) as exc:
        if isinstance(exc, ManifestError):
            for problem in exc.problems:
                print(f"  !! {problem}", file=sys.stderr)
        else:
            print(f"  !! {exc}", file=sys.stderr)
        return 1

    report = build_report(manifest, rows)
    markdown = render_markdown(report)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        print(f"JSON: {args.json}")
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(markdown, encoding="utf-8")
        print(f"Markdown: {args.markdown}")
    if not args.json and not args.markdown:
        print(markdown)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
