"""Maschinenlesbarer Export: CSV und JSON.

WARUM ES DIESE DATEI GIBT
=========================
Malaz konnte Ergebnisse als HTML- und PDF-Bericht ausgeben — beide sind fuer
Menschen. Fuer die Weitergabe an eine IT-Abteilung, ein Ticketsystem oder ein
Skript gab es nichts: der einzige CSV-Pfad lag im Sondermodus ``--evaluate``
und war fuer Korpusmessungen gedacht, nicht fuer einen normalen Scan.

WAS EXPORTIERT WIRD
===================
Je Datei eine Zeile: Name, Pfad, Typ, Urteil, Score, Befundzahl, Hashes,
Dauer und die Regel-IDs. Die Regel-IDs sind der Grund, warum es diese Datei
gibt: sie sind stabil und maschinenlesbar, waehrend der angezeigte Titel
deutsch und ausformuliert ist.

WARUM DIE VERSCHACHTELUNG ALS EIGENE ZEILEN
===========================================
Eine .eml mit drei Anhaengen und ein ZIP mit zwanzig Eintraegen sind EIN
Ergebnis mit vielen Befunden. Wer die Anhaenge nicht sieht, uebersieht die
Datei, wegen der die Mail ueberhaupt verdaechtig war. Der Export gibt deshalb
auch die Kinder aus, mit ihrer Tiefe und dem Pfad im Container.

WARUM DIE AUSGABE MASKIERT UND ENTSCHAERFT WIRD
=============================================
Dateinamen und Container-Pfade sind angreiferkontrolliert. Zwei Gefahren:

* Ein Steuerzeichen ist in der Tabelle unsichtbar, aber vorhanden — wer sie in
  Excel oeffnet, liest eine andere Datei als die, die dasteht.
  ``mask_invisible`` macht es sichtbar.
* Eine Zelle, die mit ``=``, ``+``, ``-``, ``@``, Tab oder CR beginnt, wertet
  Excel als FORMEL aus. Eine Datei namens
  ``=HYPERLINK("http://boese.tld","Rechnung")`` war vor dem Fix eine aktive
  Formel in der Pfad-Spalte.

Beides erledigt :func:`safe_cell` — eine Stelle fuer beide Exporte.

JSON ist die Ausnahme: es ist eine DATENSCHNITTSTELLE fuer Programme, kein
Tabellenformat. Ein fuehrendes Hochkomma waere dort eine Verfaelschung der
Daten. Wer JSON in eine Tabelle kippt, muss das dort tun.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from ..models import ScanResult, type_description
from ..security.escaping import mask_invisible
from .mail_section import is_mail_result

# Spalten der CSV-Ausgabe. Die Reihenfolge ist die, in der ein Mensch liest:
# erst was es ist, dann wie schlimm, dann die Belege.
CSV_COLUMNS = (
    "Tiefe",
    "Name",
    "Pfad",
    "Typ",
    "Ergebnis",
    "Score",
    "Befunde",
    "SHA-256",
    "MD5",
    "Dauer_ms",
    "Regeln",
    "Vollständig",
    "Fehler",
    "Nicht_geprüfte_Stufen",
    "Engines",
    "Defender",
    "ClamAV",
    "YARA",
)


# Zeichen, mit denen eine Tabellenzelle zur FORMEL wird. Excel, LibreOffice
# und Google Sheets werten sie beim Oeffnen aus.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def safe_cell(value: str) -> str:
    """Ein Zellwert fuer eine TABELLE: maskiert und entschaerft.

    Zwei Gefahren, eine Stelle:

    * **Unsichtbare Zeichen.** Ein U+202E im Namen ist in der Tabelle nicht zu
      sehen, aber vorhanden — wer sie oeffnet, liest eine andere Datei als die,
      die dasteht. Dieselbe Regel wie in der Oberflaeche (``mask_invisible``).
    * **Formel-Praefix.** Beginnt eine Zelle mit ``=``, ``+``, ``-``, ``@``,
      Tab oder CR, wertet Excel sie als FORMEL aus. Gemessen vor diesem Fix:
      eine Datei namens ``=HYPERLINK("http://boese.tld","Rechnung")`` stand als
      aktive Formel in der Pfad-Spalte. Der Schaden trifft den Nutzer, der die
      Tabelle oeffnet — der Angreifer ist die Datei, die er prueft.

    Entschaerft wird mit einem fuehrenden Hochkomma: Excel zeigt es nicht an
    und behandelt den Rest als Text. Der Wert bleibt also lesbar — ihn zu
    veraendern waere schlimmer als die Gefahr, weil der Nutzer die Datei sonst
    nicht mehr wiedererkennt.
    """
    text = mask_invisible(value)
    if text[:1] in _FORMULA_PREFIXES:
        return "'" + text
    return text


def _flatten(result: ScanResult, depth: int = 0, prefix: str = ""):
    """Ergebnis und alle verschachtelten Ergebnisse als flache Folge."""
    yield result, depth, prefix
    for child in result.children:
        # Der Pfad im Container macht die Zeile zuordenbar: "anhang.pdf"
        # allein sagt nicht, in welcher Mail er steckte.
        kind = "Anhang" if is_mail_result(result) else "Eintrag"
        yield from _flatten(
            child, depth + 1, f"{prefix}{result.display_name} > {kind}: "
        )


def _row(result: ScanResult, depth: int, prefix: str) -> dict[str, str]:
    return {
        "Tiefe": str(depth),
        "Name": safe_cell(result.display_name),
        "Pfad": safe_cell(prefix + str(result.path)),
        "Typ": type_description(result.detected_type, result.mime_hint, lang="de"),
        "Ergebnis": result.risk_level.short_for("de"),
        "Score": str(result.score),
        "Befunde": str(len(result.all_indicators())),
        "SHA-256": result.sha256 or "",
        "MD5": result.md5 or "",
        "Dauer_ms": str(result.duration_ms),
        # Die stabilen IDs, nicht die deutschen Titel: damit laesst sich
        # filtern und auswerten, ohne die Anzeigetexte zu kennen.
        "Regeln": " ".join(sorted(ind.rule_id for ind in result.all_indicators())),
        "Vollständig": "nein" if result.is_incomplete else "ja",
        "Fehler": safe_cell(result.error or ""),
        "Nicht_geprüfte_Stufen": " ".join(
            sorted(i.rule_id for i in result.incomplete_stages)
        ),
        "Engines": " | ".join(
            f"{v.engine}: {v.label}" for v in result.engine_verdicts
        ),
        "Defender": _engine_label(result, "Defender"),
        "ClamAV": _engine_label(result, "ClamAV"),
        "YARA": _engine_label(result, "YARA"),
    }


def _engine_label(result: ScanResult, name: str) -> str:
    for verdict in result.engine_verdicts:
        if verdict.engine == name:
            return verdict.label
    return ""


def write_csv(results: list[ScanResult], path: str | Path) -> Path:
    """Ergebnisse als CSV schreiben (UTF-8 mit BOM)."""
    ziel = Path(path)
    ziel.parent.mkdir(parents=True, exist_ok=True)
    # utf-8-sig: ohne BOM zeigt Excel deutsche Umlaute falsch an.
    with ziel.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS, delimiter=";")
        writer.writeheader()
        for result in results:
            for kind, depth, prefix in _flatten(result):
                writer.writerow(_row(kind, depth, prefix))
    return ziel


def write_json(results: list[ScanResult], path: str | Path) -> Path:
    """Ergebnisse als JSON schreiben (verschachtelt, wie gescannt)."""
    ziel = Path(path)
    ziel.parent.mkdir(parents=True, exist_ok=True)

    def baum(result: ScanResult) -> dict:
        return {
            "name": mask_invisible(result.display_name),
            "path": mask_invisible(str(result.path)),
            "type": result.detected_type,
            "type_label": type_description(result.detected_type, result.mime_hint, lang="de"),
            "risk": result.risk_level.short_for("de"),
            "score": result.score,
            "sha256": result.sha256,
            "md5": result.md5,
            "duration_ms": result.duration_ms,
            "av_discount": result.av_discount,
            "anchored": result.anchored,
            "complete": not result.is_incomplete,
            "incomplete_stages": [i.rule_id for i in result.incomplete_stages],
            "engines": [
                {
                    "engine": verdict.engine,
                    "state": verdict.state,
                    "label": mask_invisible(verdict.label),
                    "detail": mask_invisible(verdict.detail),
                }
                for verdict in result.engine_verdicts
            ],
            "error": mask_invisible(result.error) if result.error else "",
            "findings": [
                {
                    "rule": ind.rule_id,
                    "title": mask_invisible(ind.title),
                    "severity": ind.severity.label_for("de"),
                    "weight": ind.weight,
                    "category": ind.category,
                    "detail": mask_invisible(ind.detail),
                }
                for ind in result.all_indicators()
            ],
            "children": [baum(child) for child in result.children],
        }

    daten = {
        "tool": "Malaz",
        "count": len(results),
        "files": [baum(r) for r in results],
    }
    ziel.write_text(
        json.dumps(daten, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return ziel
