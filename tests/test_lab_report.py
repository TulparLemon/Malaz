"""Auswertung: Recall, FP-Rate, unchecked, Fehler, p95 und Wilson-Intervall."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from malaz.lab.manifest import Manifest, ManifestEntry, load_manifest
from malaz.lab.report import (
    ResultRow,
    build_report,
    load_results,
    percentile,
    render_markdown,
    wilson_interval,
)


def test_csv_unchecked_column_survives_the_four_finding_cap(tmp_path: Path):
    """AP4: Die Spalte trägt Regel-IDs und wird von load_results gelesen."""
    from malaz.core.unchecked import has_unchecked_markers

    path = tmp_path / "results.csv"
    path.write_text(
        "Gruppe,Datei,Typ,Urteil,Score,Top-Findings,Ungeprueft\n"
        "bad,truncated.tar,unknown,GRÜN,0,A(1)|B(1)|C(1)|D(1),"
        "CORE_READ_TRUNCATED\n",
        encoding="utf-8-sig",
    )
    rows = load_results(path)
    assert len(rows) == 1
    assert rows[0].rules[-1] == "CORE_READ_TRUNCATED"
    assert has_unchecked_markers(rows[0].rules)


def _manifest(tmp_path: Path):
    document = {
        "schema_version": 1,
        "corpus": {
            "id": "unit-test",
            "created": "2026-11-01",
            "source": "synthetic",
            "notes": "",
        },
        "files": [],
    }
    entries = [
        ("red.exe", "pe", "dropper", "malicious"),
        ("yellow.pdf", "pdf", "pdf_js", "malicious"),
        ("unchecked.zip", "zip", "nested", "malicious"),
        ("error.doc", "office", "macro", "malicious"),
        ("missing.eml", "email", "phish", "malicious"),
        ("clean.txt", "text", "normal", "benign"),
        ("fp.png", "image", "normal", "benign"),
        ("fp_red.pdf", "pdf", "document", "benign"),
        ("benign_unchecked.txt", "text", "normal", "benign"),
    ]
    for index, (name, ftype, family, label) in enumerate(entries):
        document["files"].append(
            {
                "sha256": f"{index:064x}",
                "name": name,
                "type": ftype,
                "family": family,
                "label": label,
                "source": "synthetic",
                "first_seen": "2026-11-01",
                "split": "dev",
                "notes": "",
            }
        )
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return load_manifest(path)


def _csv(tmp_path: Path) -> Path:
    path = tmp_path / "results.csv"
    path.write_text(
        "\ufeffGruppe,Datei,Typ,Urteil,Score,Top-Findings,Dauer_ms\n"
        "bad,red.exe,pe,ROT,100,PE_PACKED|YARA_Packer,10\n"
        "bad,yellow.pdf,pdf,GELB,30,PDF_JS,20\n"
        "bad,unchecked.zip,zip,GRÜN,20,CORE_READ_TRUNCATED(20),30\n"
        "bad,error.doc,office,FEHLER,,,\n"
        "good,clean.txt,text,GRÜN,0,,40\n"
        "good,fp.png,image,GELB,25,IMG_EXIF,50\n"
        "good,fp_red.pdf,pdf,ROT,50,PDF_LAUNCH,60\n"
        "good,benign_unchecked.txt,text,GRÜN,0,CLAMAV_SKIPPED,70\n"
        "good,extra.bin,unknown,GRÜN,0,,\n",
        encoding="utf-8",
    )
    return path


def test_load_results_csv_with_bom_and_optional_duration(tmp_path):
    rows = load_results(_csv(tmp_path))
    assert [row.name for row in rows][:3] == ["red.exe", "yellow.pdf", "unchecked.zip"]
    assert rows[0].verdict == "RED"
    assert rows[0].duration_ms == 10
    assert rows[2].rules == ("CORE_READ_TRUNCATED",)
    assert rows[3].verdict == "ERROR"
    assert rows[3].error


def test_build_report_counts_errors_and_unchecked_separately(tmp_path):
    report = build_report(_manifest(tmp_path), load_results(_csv(tmp_path)))
    totals = report["totals"]
    bad, good = totals["malicious"], totals["benign"]

    assert totals["manifest_files"] == 9
    assert totals["missing_results"] == 1
    assert totals["unexpected_results"] == 1  # extra.bin
    assert totals["errors"] == 1
    assert totals["unchecked"] == 2

    # Der unchecked-Fall und der Fehler fallen aus dem Nenner — nicht als
    # sauber, nicht als Fehlschlag.
    assert bad["total"] == 5
    assert bad["evaluable"] == 2
    assert bad["detected_red"] == 1
    assert bad["detected_yellow_or_red"] == 2
    assert bad["missed"] == 0
    assert bad["recall_red"] == pytest.approx(0.5)
    assert bad["recall_yellow"] == pytest.approx(1.0)
    assert bad["unchecked"] == 1
    assert bad["errors"] == 1
    assert bad["missing"] == 1

    assert good["total"] == 4
    assert good["evaluable"] == 3
    assert good["flagged_yellow_or_red"] == 2
    assert good["clean"] == 1  # nur clean.txt, nicht der unchecked-Fall
    assert good["fp_yellow"] == pytest.approx(2 / 3)
    assert good["fp_red"] == pytest.approx(1 / 3)
    assert good["unchecked"] == 1

    assert totals["incomplete_rate"] == pytest.approx(4 / 9)
    assert totals["duration"] == {"count": 7, "p95_ms": 70.0}
    assert report["warnings"] and "extra.bin" in report["warnings"][0]


def test_wilson_interval_and_nearest_rank():
    low, high = wilson_interval(1, 2)
    assert low == pytest.approx(0.09453, abs=1e-4)
    assert high == pytest.approx(0.90547, abs=1e-4)
    assert wilson_interval(0, 0) == (None, None)
    assert wilson_interval(0, 10)[0] == 0.0
    assert percentile([], 0.95) is None
    assert percentile([10, 20, 30, 40, 50], 0.95) == 50
    assert percentile([10, 20, 30, 40, 50, 60], 0.95) == 60


def test_per_type_and_family_buckets(tmp_path):
    report = build_report(_manifest(tmp_path), load_results(_csv(tmp_path)))
    by_type = {bucket["type"]: bucket for bucket in report["by_type"]}
    assert by_type["pdf"]["malicious"]["evaluable"] == 1
    assert by_type["pdf"]["malicious"]["recall_red"] == pytest.approx(0.0)
    assert by_type["pdf"]["malicious"]["recall_yellow"] == pytest.approx(1.0)
    assert by_type["pdf"]["benign"]["fp_yellow"] == pytest.approx(1.0)
    by_family = {bucket["family"]: bucket for bucket in report["by_family"]}
    assert by_family["dropper"]["malicious"]["recall_red"] == pytest.approx(1.0)


def test_markdown_states_the_limits_and_rates(tmp_path):
    report = build_report(_manifest(tmp_path), load_results(_csv(tmp_path)))
    markdown = render_markdown(report)
    assert "Recall@ROT" in markdown
    assert "50.0 %" in markdown
    assert "unchecked" in markdown
    assert "Wilson" in markdown
    assert "extra.bin" in markdown


def test_json_input_and_label_conflict(tmp_path):
    document = {
        "rows": [
            {
                "name": "clean.txt",
                "group": "bad",  # widerspricht dem Manifest
                "type": "text",
                "verdict": "GREEN",
                "score": 0,
                "rules": [],
                "duration_ms": 12,
            },
            {
                "name": "unexpected.dat",
                "group": "bad",
                "type": "unknown",
                "verdict": "RED",
                "score": 60,
                "rules": ["YARA_X"],
            },
        ]
    }
    path = tmp_path / "results.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    rows = load_results(path)
    assert rows[0].group == "malicious"
    report = build_report(_manifest(tmp_path), rows)
    assert report["label_conflicts"] == ["clean.txt"]
    assert report["totals"]["unexpected_results"] == 1
    assert report["totals"]["benign"]["evaluable"] == 1  # clean.txt bleibt bewertbar


def test_unknown_extension_is_rejected(tmp_path):
    path = tmp_path / "results.xlsx"
    path.write_bytes(b"x")
    with pytest.raises(ValueError):
        load_results(path)


def _synthetic_manifest(names: list[str]) -> Manifest:
    entries = tuple(
        ManifestEntry(
            sha256=f"{index:064x}",
            name=name,
            type="text",
            family="normal",
            label="malicious",
            source="synthetic",
            first_seen="2026-11-01",
            split="dev",
        )
        for index, name in enumerate(names)
    )
    return Manifest(
        schema_version=1,
        corpus_id="unit",
        created="2026-11-01",
        source="synthetic",
        entries=entries,
    )


def test_markdown_states_the_number_of_truncated_open_cases():
    """BUG-046: eine gekappte Liste darf nicht vollstaendig wirken."""
    names = [f"case{index:02d}.bin" for index in range(60)]
    manifest = _synthetic_manifest(names)
    rows = [ResultRow(name=name, verdict="GREEN") for name in names]

    markdown = render_markdown(build_report(manifest, rows))
    assert "case49.bin" in markdown
    assert "case50.bin" not in markdown
    assert "… und 10 weitere" in markdown


def test_markdown_neutralises_control_characters_in_names_and_warnings():
    """SEC-027: Ergebnisnamen/CSV-Warnungen duerfen keine Sektion einschmuggeln.

    Ein Name mit ``\\n\\n## Recall 100 %`` erzeugte vorher eine eigene
    Ueberschrift; ein ``|`` zerlegte die Tabelle in zusaetzliche Spalten.
    """
    evil = "evil.exe\n\n## Recall 100 %"
    pipe = "a|b.exe"
    manifest = _synthetic_manifest([evil, pipe])
    rows = [
        ResultRow(name=evil, verdict="GREEN"),
        ResultRow(name=pipe, verdict="GREEN"),
        # Nicht im Manifest -> Warnungsliste, ebenfalls untrusted.
        ResultRow(name="warn\n\n## Recall 100 %", verdict="GREEN"),
    ]

    markdown = render_markdown(build_report(manifest, rows))
    lines = markdown.splitlines()
    assert not any(line.startswith("## Recall") for line in lines), markdown
    assert "\\x0a" in markdown
    assert "a&#124;b.exe" in markdown

    # Die Tabellenzeilen der offenen Faelle bleiben bei sieben Spalten.
    open_rows = [
        line for line in lines if line.startswith(("| evil", "| a&#124;"))
    ]
    assert open_rows, markdown
    assert all(line.count("|") == 8 for line in open_rows), open_rows
