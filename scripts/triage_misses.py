"""triage_misses.py — Fehlschläge aus einer Korpus-Messung gruppieren.

Liest die CSV/JSON-Ausgabe von ``scripts/evaluate_corpus.py`` (oder die
Ergebnisdatei eines Lab-Laufs) und beantwortet die Frage, die eine nackte
Trefferquote offen lässt: **welche** bösartigen Dateien bleiben GRÜN, und
welche schwachen Signale tragen sie?

Ausgegeben werden nur Metadaten (Name, Typ, Score, Regel-IDs). Keine
Rohpayloads, keine Dateiinhalte, keine URLs aus der Probe — die Triage läuft
auf dem Auswertungsrechner, nicht auf der Probe.

    python scripts/triage_misses.py ergebnis.csv --markdown misses.md
    python scripts/triage_misses.py ergebnis.json --json misses.json
    python scripts/triage_misses.py ergebnis.csv --manifest lab.json

Gruppiert wird nach Typ, Familie (aus einem optionalen Manifest), Regel-ID
und Score-Band. „Ungeprüft" (``CORE_READ_TRUNCATED``, ``*_SKIPPED`` …) und
Scan-Fehler sind eigene Töpfe und zählen **nicht** als Fehlschlag — dieselbe
Trennung wie in ``evaluate_corpus`` und ``lab.report``.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
for _path in (_ROOT / "src", _ROOT / "scripts"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from malaz.core.unchecked import has_unchecked_markers  # noqa: E402
from malaz.lab.report import ResultRow, load_results  # noqa: E402
from malaz.security.escaping import mask_invisible  # noqa: E402

# Dateinamen, Familien und Typen sind angreiferkontrolliert. In Markdown sind
# "|", Zeilenumbrüche und Link-/Bildsyntax aktiv: ein Name
# "a|b![](http://…)" zerlegt die Tabelle oder löst beim Betrachter einen
# Abruf aus. Dieselbe Senken-Härtung wie safe_cell/escape_html, nur für
# Markdown — mask_invisible kommt zuerst (Bidi/NUL), dann die Syntax.
_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#!<>|~])")


def _md_cell(value: object) -> str:
    text = mask_invisible(value).replace("\r", " ").replace("\n", " ")
    return _MD_SPECIAL.sub(r"\\\1", text)

_SCORE_BANDS: tuple[tuple[str, int, int], ...] = (
    ("0–4", 0, 4),
    ("5–9", 5, 9),
    ("10–14", 10, 14),
    ("15–19", 15, 19),
    ("20+", 20, 10**9),
)


def _family(row: ResultRow, families: dict[str, str]) -> str:
    return families.get(row.name) or row.type or "unbekannt"


def _band(score: int | None) -> str:
    if score is None:
        return "ohne Score"
    for label, low, high in _SCORE_BANDS:
        if low <= score <= high:
            return label
    return "20+"


def triage(rows: list[ResultRow], families: dict[str, str] | None = None) -> dict[str, Any]:
    """Split malicious rows into detected / miss / unchecked / error.

    A GREEN row with an unchecked marker is *not* a miss: the file was not
    fully examined, so calling it a detection gap would be a false accusation
    of the detector. It gets its own bucket and its own list.
    """
    families = families or {}
    malicious = [row for row in rows if row.group == "malicious"]
    detected: list[ResultRow] = []
    misses: list[ResultRow] = []
    unchecked: list[ResultRow] = []
    errors: list[ResultRow] = []
    for row in malicious:
        if row.error or row.verdict == "ERROR":
            errors.append(row)
        elif row.verdict in {"YELLOW", "RED"}:
            detected.append(row)
        elif has_unchecked_markers(row.rules):
            unchecked.append(row)
        else:
            misses.append(row)

    def by_type(bucket: list[ResultRow]) -> dict[str, int]:
        return dict(Counter(row.type or "unbekannt" for row in bucket).most_common())

    def by_family(bucket: list[ResultRow]) -> dict[str, int]:
        return dict(Counter(_family(row, families) for row in bucket).most_common())

    def payload(bucket: list[ResultRow]) -> list[dict[str, Any]]:
        return [
            {
                "name": row.name,
                "type": row.type,
                "family": _family(row, families),
                "verdict": row.verdict,
                "score": row.score,
                "rules": list(row.rules),
            }
            for row in sorted(bucket, key=lambda r: (r.type, r.name))
        ]

    miss_rules = Counter(rule for row in misses for rule in row.rules)
    detected_rules = Counter(rule for row in detected for rule in row.rules)
    return {
        "schema": "malaz.triage/1",
        "total_malicious": len(malicious),
        "detected": len(detected),
        "misses": len(misses),
        "unchecked": len(unchecked),
        "errors": len(errors),
        "by_type": by_type(misses),
        "by_family": by_family(misses),
        "miss_rules": dict(miss_rules.most_common()),
        "detected_rules": dict(detected_rules.most_common()),
        "by_score": dict(
            Counter(_band(row.score) for row in misses).most_common()
        ),
        "miss_rows": payload(misses),
        "unchecked_rows": payload(unchecked),
        "error_rows": payload(errors),
    }


def _table(counts: dict[str, int]) -> str:
    if not counts:
        return "_keine_"
    lines = ["| Gruppe | Anzahl |", "|---|---:|"]
    lines.extend(
        f"| {_md_cell(name)} | {count} |" for name, count in counts.items()
    )
    return "\n".join(lines)


def render_markdown(report: dict[str, Any], source: str) -> str:
    lines = [
        "# Miss-Triage",
        "",
        f"Quelle: `{source}`",
        "",
        "| Kennzahl | Wert |",
        "|---|---:|",
        f"| Bösartige Dateien | {report['total_malicious']} |",
        f"| Erkannt (≥ GELB) | {report['detected']} |",
        f"| Fehlschläge (GRÜN) | {report['misses']} |",
        f"| Ungeprüft | {report['unchecked']} |",
        f"| Fehler | {report['errors']} |",
        "",
        "## Fehlschläge nach Typ",
        "",
        _table(report["by_type"]),
        "",
        "## Fehlschläge nach Familie",
        "",
        _table(report["by_family"]),
        "",
        "## Fehlschläge nach Score-Band",
        "",
        _table(report["by_score"]),
        "",
        "## Schwache Signale in Fehlschlägen (Regel-IDs)",
        "",
        _table(report["miss_rules"]),
        "",
        "## Fehlschläge im Detail",
        "",
    ]
    if report["miss_rows"]:
        lines.extend(
            ["| Datei | Typ | Familie | Score | Regeln |", "|---|---|---|---:|---|"]
        )
        for row in report["miss_rows"]:
            rules = ", ".join(row["rules"]) or "—"
            lines.append(
                f"| {_md_cell(row['name'])} | {_md_cell(row['type'])} | "
                f"{_md_cell(row['family'])} | "
                f"{row['score'] if row['score'] is not None else '—'} | "
                f"{_md_cell(rules)} |"
            )
    else:
        lines.append("_keine_")
    if report["unchecked_rows"] or report["error_rows"]:
        lines.extend(["", "## Nicht auswertbar (kein Freispruch)", ""])
        for title, key in (("Ungeprüft", "unchecked_rows"), ("Fehler", "error_rows")):
            if not report[key]:
                continue
            lines.extend([f"### {title}", "", "| Datei | Typ | Regeln |", "|---|---|---|"])
            for row in report[key]:
                lines.append(
                    f"| {_md_cell(row['name'])} | {_md_cell(row['type'])} | "
                    f"{_md_cell(', '.join(row['rules']) or '—')} |"
                )
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _families_from_manifest(path: Path) -> dict[str, str]:
    from malaz.lab.manifest import load_manifest

    manifest = load_manifest(path)
    return {entry.name: entry.family for entry in manifest.entries}


def _validate_output(path: Path | None) -> bool:
    if path is not None and ".." in path.parts:
        print("!! Ausgabepfad darf keine ../-Komponenten enthalten.", file=sys.stderr)
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("input", type=Path, help="Ergebnis-CSV/JSON aus evaluate_corpus")
    parser.add_argument("--markdown", type=Path, default=None, help="Markdown-Bericht")
    parser.add_argument("--json", type=Path, default=None, help="JSON-Bericht")
    parser.add_argument("--manifest", type=Path, default=None,
                        help="optionales Lab-Manifest für Familiennamen")
    args = parser.parse_args(argv)

    if not args.input.is_file():
        print(f"FEHLER: Eingabe fehlt: {args.input}", file=sys.stderr)
        return 1
    if not _validate_output(args.markdown) or not _validate_output(args.json):
        return 1
    try:
        rows = load_results(args.input)
    except (OSError, ValueError) as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        return 1
    families: dict[str, str] = {}
    if args.manifest is not None:
        try:
            families = _families_from_manifest(args.manifest)
        except Exception as exc:
            print(f"FEHLER: Manifest nicht lesbar: {exc}", file=sys.stderr)
            return 1

    report = triage(rows, families)
    if report["total_malicious"] == 0:
        print(
            "Hinweis: keine bösartigen Zeilen gefunden (Spalte Gruppe/label "
            "prüfen) — die Triage ist leer.",
            file=sys.stderr,
        )

    print(
        f"Bösartig {report['total_malicious']}: erkannt {report['detected']}, "
        f"Fehlschläge {report['misses']}, ungeprüft {report['unchecked']}, "
        f"Fehler {report['errors']}"
    )
    if args.markdown is not None:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(
            render_markdown(report, str(args.input)), encoding="utf-8"
        )
        print(f"Markdown: {args.markdown}")
    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"JSON: {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
