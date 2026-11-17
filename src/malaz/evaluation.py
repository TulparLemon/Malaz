"""Korpus-Auswertung — Trefferquote und False-Positive-Rate messen.

Scannt zwei Verzeichnisse (bösartig/harmlos) mit dem echten Dispatcher
(inkl. lokalem Defender und ClamAV) und aggregiert die Ergebnisse:

* Trefferquote: Anteil der bösartigen Dateien >= GELB / >= ROT, nach Typ
* False-Positive-Rate: Anteil der harmlosen Dateien >= GELB / >= ROT
* Score-Verteilung und Top-Findings je Datei (um zu sehen, WARUM erkannt
  wurde — YARA/Signatur ist stark, reine Entropie ist schwach)
* „nicht geprüft": Dateien, deren GRÜN nicht belastbar ist
  (``CORE_READ_TRUNCATED``, ``*_SKIPPED`` …). Sie fliegen aus dem Nenner und
  werden separat ausgewiesen, statt als sauber zu zählen — dieselbe Regel wie
  in ``malaz.lab.report`` (Definition: ``malaz.core.unchecked``).

Diese Logik läuft auch im Standalone-Build (``Malaz.exe --evaluate``),
damit der Live-Malware-Test auf einer VM ohne Python-Installation möglich
ist (siehe ``scripts/vm_portable_test.bat``). Das Wrapper-Skript
``scripts/evaluate_corpus.py`` ruft dieselbe Funktion auf.

Regeln: NICHTS auf den Samples ausführen/öffnen (nur statisch scannen);
Samples nie außerhalb der isolierten VM/des Laptops entpacken.
"""

from __future__ import annotations

import csv
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import config
from .core.dispatcher import Dispatcher, expand_scan_paths
from .core.unchecked import is_unchecked_rule
from .models import RiskLevel, ScanResult

# Engine notes that mean "disabled on request" when the operator passes
# ``--static-only``. They stay unchecked markers for a normal ``--with-av``
# run: there, a skipped engine is a real gap.
_AV_SKIP_RULES = frozenset({"AV_SKIPPED", "CLAMAV_SKIPPED"})

# Position of the exact identity column ("Datei_ID") in the CSV rows built by
# ``_print_section``. It is the ONE column written without ``safe_cell``.
_CSV_ID_COLUMN = 7


def _scan_dir(
    dispatcher: Dispatcher, directory: Path
) -> tuple[list[ScanResult], bool]:
    """Scan every file under ``directory``; returns ``(results, truncated)``.

    ``expand_scan_paths`` yields files only (no directories), so the result
    order is the deterministic file order and every row in the CSV maps to one
    scanned file. ``truncated`` is the batch cap having stopped the walk: the
    measurement then covers a SUBSET of the corpus, which must be reported —
    dropping the flag made a capped run look like a complete one (recall/FP
    computed on a silently shortened list, exit 0, no warning).
    """
    files, truncated = expand_scan_paths([str(directory)])
    results = []
    for path in files:
        results.append(dispatcher.scan_path(path))
    return results, truncated


def _verdict(level: RiskLevel) -> str:
    return {RiskLevel.GREEN: "GRÜN", RiskLevel.YELLOW: "GELB", RiskLevel.RED: "ROT"}[
        level
    ]


def _type_of(result: ScanResult) -> str:
    return result.detected_type or "unknown"


def _rule_ids(result: ScanResult) -> tuple[str, ...]:
    return tuple(i.rule_id for i in result.all_indicators())


def _top_findings(
    result: ScanResult,
    limit: int = 4,
    ignore_rules: frozenset[str] = frozenset(),
) -> list[str]:
    """Most severe rule_ids with their source, so weak vs. strong detection
    is distinguishable (signature/YARA > generic entropy).

    Skipped engines carry their reason in the indicator detail (missing
    signature DB, timeout, …) — surfacing it here makes CLAMAV_SKIPPED rows
    in the CSV self-explanatory instead of a silent blind spot.

    ``ignore_rules`` must be applied HERE as well, not only to the
    "Ungeprueft" column: the readers (``malaz.lab.report`` and
    ``scripts/triage_misses.py``) concatenate top-findings and unchecked
    markers and re-derive the markers from the rule ids. With
    ``--static-only`` an ``AV_SKIPPED(windows_av)`` cell therefore made every
    GREEN malicious sample count as "ungeprueft" instead of as a MISS — the
    detection gap disappeared from the measurement. Filtering happens before
    the limit so an ignored marker cannot occupy one of the ``limit`` slots.
    """
    inds = sorted(
        (
            i for i in result.all_indicators()
            if i.rule_id not in ignore_rules
        ),
        key=lambda i: (i.severity, i.weight or 0), reverse=True,
    )
    out: list[str] = []
    for i in inds[:limit]:
        cell = f"{i.rule_id}({i.source})"
        if i.rule_id.endswith("_SKIPPED") and i.detail:
            cell += f" — {i.detail[:90]}"
        out.append(cell)
    return out


def _scan_failed(result: ScanResult) -> bool:
    """True if the file could not be analysed at all (blocked, locked,
    unreadable, …). Such files must NOT count as "GRÜN/sauber" — otherwise a
    Defender-blocked sample silently lowers the hit rate."""
    return bool(getattr(result, "error", None))


def _is_unchecked(
    result: ScanResult, ignore_rules: frozenset[str] = frozenset()
) -> bool:
    """True if a GRÜN row carries a „not (fully) examined" marker.

    Only a non-detection can be wrongly read as clean; a GELB/ROT row is a
    finding regardless of any skipped stage. The marker is the same set
    ``malaz.lab.report`` uses (``core/unchecked.py``): the two measurements
    must not disagree about what counts as examined.

    ``ignore_rules`` is for a run the operator explicitly configured: with
    ``--static-only`` the ``AV_SKIPPED``/``CLAMAV_SKIPPED`` notes mean "engine
    disabled on request", not "content not examined". Counting them would mark
    every GRÜN file unchecked and make the static measurement useless. Every
    other marker (``CORE_READ_TRUNCATED``, size limits, other engines) stays.
    """
    if result.risk_level >= RiskLevel.YELLOW:
        return False
    return any(
        is_unchecked_rule(rule) and rule not in ignore_rules
        for rule in _rule_ids(result)
    )


@dataclass(frozen=True)
class SectionStats:
    """Counts of one corpus half. ``evaluated`` excludes errors and unchecked."""

    total: int
    evaluated: int
    unchecked: int
    errors: int
    green: int
    yellow: int
    red: int
    unchecked_rules: tuple[str, ...] = field(default_factory=tuple)
    by_type: dict[str, SectionStats] = field(default_factory=dict, compare=False)

    @property
    def yellow_or_higher(self) -> int:
        return self.yellow + self.red

    @property
    def rate_yellow(self) -> float:
        return self.yellow_or_higher / self.evaluated if self.evaluated else 0.0

    @property
    def rate_red(self) -> float:
        return self.red / self.evaluated if self.evaluated else 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "evaluated": self.evaluated,
            "unchecked": self.unchecked,
            "errors": self.errors,
            "green": self.green,
            "yellow": self.yellow,
            "red": self.red,
            "yellow_or_higher": self.yellow_or_higher,
            "rate_yellow": round(self.rate_yellow, 4),
            "rate_red": round(self.rate_red, 4),
            "unchecked_rules": list(self.unchecked_rules),
            "by_type": {name: stats.as_dict() for name, stats in sorted(self.by_type.items())},
        }


def _section_stats(
    results: list[ScanResult], ignore_rules: frozenset[str] = frozenset()
) -> SectionStats:
    """Split one corpus half into evaluated / unchecked / errors.

    The buckets are disjoint and sum to ``total``. Rates use ``evaluated``;
    an unchecked row is reported with its rule IDs so the reason is visible
    without opening the raw findings.
    """
    errors = [r for r in results if _scan_failed(r)]
    unchecked = [
        r for r in results if not _scan_failed(r) and _is_unchecked(r, ignore_rules)
    ]
    evaluated = [
        r
        for r in results
        if not _scan_failed(r) and not _is_unchecked(r, ignore_rules)
    ]

    def counts(rows: list[ScanResult]) -> tuple[int, int, int]:
        return (
            sum(1 for r in rows if r.risk_level == RiskLevel.GREEN),
            sum(1 for r in rows if r.risk_level == RiskLevel.YELLOW),
            sum(1 for r in rows if r.risk_level == RiskLevel.RED),
        )

    green, yellow, red = counts(evaluated)
    by_type: dict[str, SectionStats] = {}
    for ftype in sorted({_type_of(r) for r in evaluated}):
        group = [r for r in evaluated if _type_of(r) == ftype]
        group_green, group_yellow, group_red = counts(group)
        by_type[ftype] = SectionStats(
            total=len(group),
            evaluated=len(group),
            unchecked=0,
            errors=0,
            green=group_green,
            yellow=group_yellow,
            red=group_red,
        )

    rules = tuple(
        sorted({
            rule
            for r in unchecked
            for rule in _rule_ids(r)
            if is_unchecked_rule(rule) and rule not in ignore_rules
        })
    )
    return SectionStats(
        total=len(results),
        evaluated=len(evaluated),
        unchecked=len(unchecked),
        errors=len(errors),
        green=green,
        yellow=yellow,
        red=red,
        unchecked_rules=rules,
        by_type=by_type,
    )


def _print_section(
    title: str,
    results: list[ScanResult],
    csv_rows: list[list[str]],
    path_label: str,
    ignore_rules: frozenset[str] = frozenset(),
) -> SectionStats:
    stats = _section_stats(results, ignore_rules)
    print(f"\n=== {title} ({len(results)} Dateien) ===")
    if results:
        print(
            f"  ausgewertet: {stats.evaluated}  "
            f"(nicht geprüft: {stats.unchecked}, Fehler: {stats.errors})"
        )
    if stats.evaluated:
        print(
            f"  gesamt:  >= GELB {stats.rate_yellow * 100:5.1f}%  "
            f">= ROT {stats.rate_red * 100:5.1f}%"
        )
        for ftype, group in stats.by_type.items():
            print(
                f"  {ftype:12s}: {group.rate_yellow * 100:5.1f}% >= GELB  "
                f"{group.rate_red * 100:5.1f}% >= ROT  ({group.evaluated} Dateien)"
            )
    if stats.unchecked:
        reason = ", ".join(stats.unchecked_rules) or "Teilprüfung"
        print(
            f"  NICHT GEPRÜFT: {stats.unchecked} Dateien ({reason}) — "
            "zählen weder als Treffer noch als sauber"
        )
    if stats.errors:
        print(
            f"  FEHLER   : {stats.errors} Dateien nicht auswertbar "
            "(blockiert/unlesbar/Scan-Fehler) — siehe CSV"
        )
    for r in results:
        failed = _scan_failed(r)
        verdict = "FEHLER" if failed else _verdict(r.risk_level)
        # Die Spalte trägt die REGEL-IDs, nicht nur ein Wort: ``lab.report``
        # und ``triage_misses`` lesen die CSV weiter und müssen den Grund
        # sehen. Die Top-Findings-Zelle ist auf 4 Einträge gekappt — ein
        # CORE_READ_TRUNCATED an Position 5 wäre dort verloren.
        markers = [
            rule
            for rule in _rule_ids(r)
            if is_unchecked_rule(rule) and rule not in ignore_rules
        ]
        csv_rows.append([
            path_label,
            r.display_name,
            _type_of(r),
            verdict,
            str(r.score),
            "|".join(_top_findings(r, ignore_rules=ignore_rules)),
            "|".join(dict.fromkeys(markers)),
            # Exakte Identitaet fuer Maschinenleser. Die Anzeige-Spalte
            # "Datei" wird beim Schreiben entschaerft (safe_cell: fuehrendes
            # ' gegen Formeln, \uXXXX gegen Bidi/NUL) — damit ist sie NICHT
            # mehr der Dateiname: lab.report matcht Manifest-Eintraege ueber
            # genau diesen Namen, und ein "-report.pdf" wurde als
            # "'-report.pdf" gelesen -> matched 0, missing 1, unexpected 1.
            # Diese Spalte wird unveraendert geschrieben und von den Lesern
            # bevorzugt (lab.report._load_csv: Alias datei_id).
            r.display_name,
        ])
    return stats


def build_dispatcher(*, with_av: bool = True) -> Dispatcher:
    """Dispatcher for the measurement; ``with_av=False`` disables both engines.

    ``--static-only`` must not silently probe ``MpCmdRun``/``clamscan``: a
    measurement that claims to be static and still starts AV subprocesses is
    neither fast nor reproducible. The scanners stay disabled at the object.
    The dispatcher still emits weight-0 ``AV_SKIPPED``/``CLAMAV_SKIPPED``
    notes per file (the score contract wants them visible); ``evaluate``
    therefore treats them as configuration via ``_AV_SKIP_RULES``.
    """
    if with_av:
        return Dispatcher()
    from .analysis.clamav import ClamAVScanner
    from .analysis.windows_av import WindowsDefenderScanner

    return Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )


def _validate_output(path: Path | None, label: str) -> bool:
    if path is None:
        return True
    if ".." in path.parts:
        print(
            f"!! Ausgabepfad ({label}) darf keine ../-Komponenten enthalten.",
            file=sys.stderr,
        )
        return False
    return True


def _write_json(
    path: Path,
    *,
    known_bad: Path,
    known_good: Path,
    bad: SectionStats,
    good: SectionStats,
    results: list[ScanResult],
    path_labels: dict[int, str],
    with_av: bool,
    ignore_rules: frozenset[str],
    truncated: dict[str, bool],
) -> None:
    document = {
        "schema": "malaz.evaluation/1",
        "mode": {
            "with_av": with_av,
            "ignored_skips": sorted(ignore_rules),
        },
        "corpora": {"bad": str(known_bad), "good": str(known_good)},
        # Der Batch-Deckel je Korpus-Haelfte. Ein Programm, das die Raten
        # weiterverarbeitet, muss sehen, ob sie auf dem ganzen Korpus oder
        # nur auf dem gelesenen Teil beruhen.
        "truncated": dict(truncated),
        "bad": bad.as_dict(),
        "good": good.as_dict(),
        "files": [
            {
                "group": path_labels[id(result)],
                "name": result.display_name,
                "type": _type_of(result),
                "verdict": "FEHLER" if _scan_failed(result) else _verdict(result.risk_level),
                "score": result.score,
                "findings": _top_findings(
                    result, limit=8, ignore_rules=ignore_rules
                ),
                "unchecked": [
                    rule
                    for rule in _rule_ids(result)
                    if is_unchecked_rule(rule) and rule not in ignore_rules
                ],
                "error": getattr(result, "error", "") or "",
            }
            for result in results
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def evaluate(
    known_bad: Path,
    known_good: Path,
    csv_path: Path | None = None,
    report_path: Path | None = None,
    dispatcher: Dispatcher | None = None,
    *,
    with_av: bool = True,
    json_path: Path | None = None,
) -> int:
    """Scan both corpora, print rates, optionally write CSV/JSON/HTML report.

    Returns the exit code: 0 = Messung gelaufen, 1 = Argumente ungültig
    (Ordner fehlen, Ausgabepfad enthält ../, oder --static-only/--with-av
    widersprechen sich), 2 = Messung gelaufen, aber UNVOLLSTÄNDIG (das
    Batch-Limit hat einen Korpus abgeschnitten — siehe ``truncated`` im JSON).
    """
    if not known_bad.is_dir() or not known_good.is_dir():
        print("FEHLER: beide Ordner müssen existieren.", file=sys.stderr)
        return 1

    # Validate BEFORE any work. The operator's output paths are arguments; a
    # bad one must be rejected immediately. It used to be checked after both
    # corpora were scanned, so an invalid path cost the full scan first —
    # measured 31.5 s for a two-byte corpus, and minutes on a real one.
    if not _validate_output(csv_path, "CSV"):
        return 1
    if not _validate_output(json_path, "JSON"):
        return 1
    # BUG-041: the HTML report was the only output path without this guard,
    # although the docstring promised it for every path.
    if not _validate_output(report_path, "HTML"):
        return 1

    # Only now build the live engines: constructing a Dispatcher probes
    # Defender and ClamAV (subprocesses), which must not happen for a call
    # that is rejected anyway.
    if dispatcher is None:
        dispatcher = build_dispatcher(with_av=with_av)

    # With --static-only the AV notes are a configuration fact, not a content
    # gap (see _is_unchecked). The decision is printed once so the number is
    # reproducible from the log alone.
    ignore_rules = frozenset() if with_av else _AV_SKIP_RULES
    if ignore_rules:
        print(
            "Modus: statisch — AV_SKIPPED/CLAMAV_SKIPPED gelten als "
            "Konfiguration, nicht als ungeprüft."
        )

    csv_rows: list[list[str]] = [
        [
            "Gruppe",
            "Datei",
            "Typ",
            "Urteil",
            "Score",
            "Top-Findings",
            "Ungeprueft",
            "Datei_ID",
        ]
    ]
    print(f"Scanne {known_bad} (bösartig) …")
    bad_results, bad_truncated = _scan_dir(dispatcher, known_bad)
    bad = _print_section(
        "BÖSARTIG (Trefferquote)", bad_results, csv_rows, "bad", ignore_rules
    )
    print(f"\nScanne {known_good} (harmlos) …")
    good_results, good_truncated = _scan_dir(dispatcher, known_good)
    good = _print_section(
        "HARMLOS (False-Positive-Rate)", good_results, csv_rows, "good", ignore_rules
    )

    truncated_halves = [
        label
        for label, flag in (("bösartig", bad_truncated), ("harmlos", good_truncated))
        if flag
    ]
    if truncated_halves:
        # Der Batch-Deckel hat den Lauf gestoppt: Recall/FP gelten dann nur
        # fuer eine TEILMENGE, und ein Exit 0 wuerde sie als vollstaendige
        # Messung ausgeben. Sichtbar auf stderr (wie im CLI) und im Exit-Code.
        print(
            f"!! Korpus-Limit von {config.MAX_BATCH_FILES} Dateien erreicht "
            f"({', '.join(truncated_halves)}) — die Messung deckt nur eine "
            "Teilmenge des Korpus ab.",
            file=sys.stderr,
        )

    if csv_path:
        # Traversal was already rejected above, before any scanning.
        #
        # safe_cell + utf-8-sig wie in der Geschwisterstelle
        # (reporting/export.py): die Zellen tragen Dateinamen und Befundtexte,
        # also angreiferkontrollierten Inhalt. Ohne die Entschaerfung wird ein
        # Name wie "=HYPERLINK(...)" beim Oeffnen in Excel als FORMEL
        # ausgewertet (CWE-1236), und ein U+202E darin ist in der Tabelle
        # unsichtbar. Die BOM sorgt dafuer, dass Excel die Umlaute richtig
        # liest — der dokumentierte Arbeitsweg ist VM -> USB -> Excel.
        #
        # AUDIT-BEFUND 3: diese Senke war ungeprueft. Die Pruefung "CSV-
        # Formel-Injection geprueft ohne Befund" im Changelog traf nur
        # export.py; docs/SECURITY_MODEL.md nennt ausdruecklich nur diese eine
        # Datei.
        from .reporting.export import safe_cell

        csv_path.parent.mkdir(parents=True, exist_ok=True)
        with csv_path.open("w", newline="", encoding="utf-8-sig") as fh:
            writer = csv.writer(fh)
            writer.writerows(
                [
                    # Die Identitaetsspalte bleibt roh: sie ist der Dateiname,
                    # den lab.report/triage_misses zum Matchen brauchen. Eine
                    # Entschaerfung hier machte aus "-report.pdf" ein
                    # "'-report.pdf" und aus jedem Bidi-Namen ein \uXXXX —
                    # der Leser fand das Manifest nicht mehr (matched 0,
                    # missing 1, unexpected 1). Die Anzeige-Spalte "Datei"
                    # behaelt die Entschaerfung, damit die Tabelle beim
                    # Oeffnen in Excel weiterhin Text und keine Formel zeigt.
                    str(zelle) if index == _CSV_ID_COLUMN else safe_cell(str(zelle))
                    for index, zelle in enumerate(zeile)
                ]
                for zeile in csv_rows
            )
        print(f"\nCSV: {csv_path}")

    if json_path:
        all_results = bad_results + good_results
        labels = {id(r): "bad" for r in bad_results} | {id(r): "good" for r in good_results}
        _write_json(
            json_path,
            known_bad=known_bad,
            known_good=known_good,
            bad=bad,
            good=good,
            results=all_results,
            path_labels=labels,
            with_av=with_av,
            ignore_rules=ignore_rules,
            truncated={"bad": bad_truncated, "good": good_truncated},
        )
        print(f"JSON: {json_path}")

    if report_path:
        from .reporting.html_report import save_report

        save_report(bad_results + good_results, report_path)
        print(f"Report: {report_path}")

    return 2 if truncated_halves else 0
