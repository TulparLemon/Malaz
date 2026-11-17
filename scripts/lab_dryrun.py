"""Trockenlauf des Realwelt-Labors — ausschließlich synthetische Fixtures.

Erzeugt ein kleines Korpus aus den **mitgelieferten** Builder-Funktionen
(keine heruntergeladenen Proben), hasht es, scannt es mit abgeschalteten
AV-Engines (deterministisch, offline) und schreibt Manifest + Ergebnis-CSV +
Ergebnis-JSON in das Arbeitsverzeichnis. Anschließend wird jeder Hash erneut
geprüft — die Chain of Custody ist Teil des Trockenlaufs.

    python scripts/lab_dryrun.py --work-dir .lab-dryrun

``scripts/run_lab.ps1 -DryRun`` ruft genau dieses Skript auf und wertet danach
mit ``scripts/realworld_report.py`` aus. Es wird **keine** VM gestartet und
**keine** echte Probe angefasst.
"""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import corpus_determinism as det  # noqa: E402
import make_benign_corpus as benign  # noqa: E402
import make_test_corpus as base  # noqa: E402

from malaz import config  # noqa: E402
from malaz.analysis.clamav import ClamAVScanner  # noqa: E402
from malaz.analysis.windows_av import WindowsDefenderScanner  # noqa: E402
from malaz.core.dispatcher import Dispatcher  # noqa: E402
from malaz.core.scoring import BASE_WEIGHTS  # noqa: E402
from malaz.lab.manifest import (  # noqa: E402
    load_manifest,
    manifest_sha256,
    sha256_file,
    verify_files,
)

# Kleine, repräsentative Auswahl. Die Namen sind die Dateinamen der
# Builder-Tabellen, nicht frei erfunden — so bleibt der Trockenlauf an die
# echten Korpus-Verträge gekoppelt.
MALICIOUS = ("launch.pdf", "zipslip.zip", "packed.exe", "mail.eml")
BENIGN = ("vertrag.pdf", "unterlagen.zip", "rechnung.eml", "logo.png")

# Dieselbe Sprache wie der Produktionspfad (evaluation._verdict): der
# Trockenlauf soll den echten Ablauf ueben, nicht ein eigenes Vokabular
# erfinden. Der Report akzeptiert beide Schreibweisen.
_VERDICT = {"GREEN": "GRÜN", "YELLOW": "GELB", "RED": "ROT"}

_TYPES = {
    ".pdf": "pdf",
    ".zip": "zip",
    ".exe": "pe",
    ".eml": "email",
    ".png": "image",
    ".jpg": "image",
    ".txt": "text",
    ".docx": "office",
    ".xlsx": "office",
    ".gz": "archive",
}


def _type_for(name: str) -> str:
    lower = name.lower()
    if lower.endswith(".tar.gz"):
        return "archive"
    return _TYPES.get(Path(lower).suffix, "unknown")


def _builders() -> dict[str, object]:
    table = {name: builder for name, builder, *_ in base.CORPUS}
    table.update(dict(benign.BENIGN))
    return table


def _write_fixtures(target: Path) -> list[tuple[Path, str]]:
    builders = _builders()
    written: list[tuple[Path, str]] = []
    for name, label in [(n, "malicious") for n in MALICIOUS] + [
        (n, "benign") for n in BENIGN
    ]:
        builder = builders.get(name)
        if builder is None:  # pragma: no cover - table drift is a bug
            raise SystemExit(f"Fixture-Builder fehlt: {name}")
        path = target / name
        path.write_bytes(builder())  # type: ignore[operator]
        written.append((path, label))
    return written


def _manifest_document(entries: list[tuple[Path, str]]) -> dict:
    return {
        "schema_version": 1,
        "corpus": {
            "id": "dryrun-synthetic",
            "created": "2026-11-01",
            "source": "synthetic-fixtures (scripts/make_*_corpus.py)",
            "notes": (
                "Trockenlauf. Keine echten Proben, keine Netzwerk-Downloads. "
                "Alle Hashes beziehen sich auf zur Laufzeit erzeugte Fixtures."
            ),
        },
        "files": [
            {
                "sha256": sha256_file(path),
                "name": path.name,
                "type": _type_for(path.name),
                "family": f"synthetic_{label}",
                "label": label,
                "source": "synthetic-fixtures",
                "first_seen": "2026-11-01",
                "split": "dev",
                "notes": "Trockenlauf-Fixture",
            }
            for path, label in entries
        ],
    }


def _scan(corpus_dir: Path) -> list[dict]:
    with det.pin_user_threat_intel():
        dispatcher = Dispatcher(
            av_scanner=WindowsDefenderScanner(enabled=False),
            clam_scanner=ClamAVScanner(enabled=False),
        )
        rows: list[dict] = []
        for path in sorted(corpus_dir.iterdir()):
            started = time.perf_counter()
            result = dispatcher.scan_path(path)
            duration = (time.perf_counter() - started) * 1000
            rules = sorted(
                {
                    indicator.rule_id
                    for indicator in result.all_indicators()
                    if indicator.effective_weight(BASE_WEIGHTS)
                    and not indicator.rule_id.endswith("_SKIPPED")
                    and indicator.rule_id not in config.ENGINE_STATUS_RULE_IDS
                }
            )
            rows.append(
                {
                    "group": "bad" if path.name in MALICIOUS else "good",
                    "name": path.name,
                    "type": result.detected_type or _type_for(path.name),
                    "verdict": _VERDICT.get(result.risk_level.name, "FEHLER"),
                    "score": result.score,
                    "rules": rules,
                    "duration_ms": round(duration, 1),
                    "error": result.error or "",
                }
            )
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args(argv)

    work = args.work_dir.resolve()
    # Loeschen nur mit Marker und nie ein Laufwerks-/Repo-Wurzelverzeichnis:
    # ein Tippfehler bei --work-dir darf nicht C:\ oder das Projekt entfernen.
    if work == Path(work.anchor) or work == ROOT or work in ROOT.parents:
        print(f"  !! Unsicheres Arbeitsverzeichnis: {work}", file=sys.stderr)
        return 1
    if work.exists() and any(work.iterdir()):
        if not args.overwrite:
            print(f"  !! Arbeitsverzeichnis nicht leer: {work}", file=sys.stderr)
            return 1
        if not (work / ".malaz_dryrun").is_file():
            print(
                f"  !! --overwrite nur fuer ein frueheres DryRun-Verzeichnis: {work}",
                file=sys.stderr,
            )
            return 1
        shutil.rmtree(work)
    work.mkdir(parents=True, exist_ok=True)
    (work / ".malaz_dryrun").write_text("synthetic dry-run work dir\n", encoding="utf-8")
    corpus_dir = work / "corpus"
    corpus_dir.mkdir()

    entries = _write_fixtures(corpus_dir)
    manifest_path = work / "dryrun_manifest.json"
    manifest_path.write_text(
        json.dumps(_manifest_document(entries), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    before = load_manifest(manifest_path)
    checks_before = verify_files(before, corpus_dir)
    rows = _scan(corpus_dir)

    csv_path = work / "dryrun_results.csv"
    with csv_path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            ["Gruppe", "Datei", "Typ", "Urteil", "Score", "Top-Findings", "Dauer_ms"]
        )
        for row in rows:
            writer.writerow(
                [
                    row["group"],
                    row["name"],
                    row["type"],
                    row["verdict"],
                    row["score"],
                    "|".join(row["rules"]),
                    row["duration_ms"],
                ]
            )

    json_path = work / "dryrun_results.json"
    json_path.write_text(
        json.dumps(
            {
                "profile": {
                    "id": "static-only",
                    "av_engines": "disabled",
                    "note": (
                        "Engine-Status-Marker (*_SKIPPED) sind bewusst nicht in "
                        "den Regeln: AV ist hier absichtlich aus. Live-Laeufe "
                        "behandeln *_SKIPPED weiterhin als unchecked."
                    ),
                },
                "rows": rows,
                "chain_of_custody": {
                    "manifest_sha256": manifest_sha256(manifest_path),
                    "before": [check.status for check in checks_before],
                },
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    # Hash vor und nach dem Scan identisch? Ein AV-Eingriff im Trockenlauf
    # wäre ein Hinweis auf echte Echtzeitschutz-Interaktion.
    after = load_manifest(manifest_path)
    checks_after = verify_files(after, corpus_dir)
    changed = [c.name for c in checks_after if not c.ok]
    if changed:
        print(f"  !! Fixtures nach dem Scan verändert/fehlend: {changed}", file=sys.stderr)
        return 1

    print(f"Manifest: {manifest_path}")
    print(f"CSV:      {csv_path}")
    print(f"JSON:     {json_path}")
    print(f"Dateien:  {len(entries)} (Hash vor/nach identisch)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
