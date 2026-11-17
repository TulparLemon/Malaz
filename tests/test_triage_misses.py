"""Tests für die Miss-Triage (AP5).

Die Triage läuft auf Metadaten: Name, Typ, Score, Regel-IDs. Sie darf keine
Rohpayloads ausgeben und muss „ungeprüft" von „Fehlschlag" trennen — sonst
beschuldigt sie den Detektor für eine Datei, die nie vollständig geprüft wurde.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import triage_misses as triage  # noqa: E402

from malaz.lab.report import ResultRow  # noqa: E402


def _row(name, verdict="GREEN", group="malicious", rules=(), score=0, error="", type="pdf"):
    return ResultRow(
        name=name,
        group=group,
        type=type,
        verdict=verdict,
        score=score,
        rules=tuple(rules),
        error=error,
    )


def test_triage_separates_miss_unchecked_error_and_detected():
    rows = [
        _row("miss.pdf"),
        _row("truncated.tar", rules=("CORE_READ_TRUNCATED",)),
        _row("hit.pdf", verdict="RED", rules=("PDF_LAUNCH_ACTION",), score=50),
        _row("blocked.exe", error="OSError", type="pe"),
        _row("harmlos.txt", group="benign"),
    ]
    report = triage.triage(rows)
    assert report["total_malicious"] == 4
    assert report["detected"] == 1
    assert report["misses"] == 1
    assert report["unchecked"] == 1
    assert report["errors"] == 1
    assert [row["name"] for row in report["miss_rows"]] == ["miss.pdf"]
    assert [row["name"] for row in report["unchecked_rows"]] == ["truncated.tar"]
    assert [row["name"] for row in report["error_rows"]] == ["blocked.exe"]


def test_triage_groups_by_type_family_rule_and_score():
    rows = [
        _row("a.pdf", rules=("GEN_IOC",)),
        _row("b.pdf", rules=("GEN_SUSPICIOUS_STRINGS",), score=15),
        _row("c.exe", type="pe", score=5),
    ]
    families = {"a.pdf": "pdf_js", "b.pdf": "pdf_js", "c.exe": "dropper"}
    report = triage.triage(rows, families)
    assert report["by_type"] == {"pdf": 2, "pe": 1}
    assert report["by_family"] == {"pdf_js": 2, "dropper": 1}
    assert report["miss_rules"] == {"GEN_IOC": 1, "GEN_SUSPICIOUS_STRINGS": 1}
    assert report["by_score"]["0–4"] == 1
    assert report["by_score"]["5–9"] == 1
    assert report["by_score"]["15–19"] == 1


def test_csv_from_evaluate_is_read_with_unchecked_column(tmp_path):
    """Die AP4-Spalte trägt die Regel-IDs und wird hier wiederverwendet."""
    csv_path = tmp_path / "r.csv"
    csv_path.write_text(
        "Gruppe,Datei,Typ,Urteil,Score,Top-Findings,Ungeprueft\n"
        "bad,miss.pdf,pdf,GRÜN,0,,\n"
        "bad,truncated.tar,unknown,GRÜN,0,A(1)|B(1)|C(1)|D(1),CORE_READ_TRUNCATED\n"
        "bad,hit.pdf,pdf,GELB,30,PDF_KW_JS(20),\n",
        encoding="utf-8-sig",
    )
    rows = triage.load_results(csv_path)
    report = triage.triage(rows)
    assert report["misses"] == 1
    assert report["unchecked"] == 1
    assert report["detected"] == 1


def test_evaluation_json_files_list_is_accepted(tmp_path):
    json_path = tmp_path / "e.json"
    json_path.write_text(
        json.dumps({
            "schema": "malaz.evaluation/1",
            "bad": {},
            "good": {},
            "files": [
                {
                    "group": "bad",
                    "name": "miss.pdf",
                    "type": "pdf",
                    "verdict": "GRÜN",
                    "score": 0,
                    "findings": ["GEN_IOC(generic)"],
                    "unchecked": [],
                    "error": "",
                }
            ],
        }),
        encoding="utf-8",
    )
    rows = triage.load_results(json_path)
    report = triage.triage(rows)
    assert report["misses"] == 1
    assert report["miss_rows"][0]["rules"] == ["GEN_IOC"]


def test_main_writes_markdown_and_json_without_payloads(tmp_path):
    csv_path = tmp_path / "r.csv"
    csv_path.write_text(
        "Gruppe,Datei,Typ,Urteil,Score,Top-Findings,Ungeprueft\n"
        "bad,miss.pdf,pdf,GRÜN,0,GEN_IOC(generic),\n",
        encoding="utf-8-sig",
    )
    md = tmp_path / "misses.md"
    js = tmp_path / "misses.json"
    assert triage.main([str(csv_path), "--markdown", str(md), "--json", str(js)]) == 0
    text = md.read_text(encoding="utf-8")
    assert "Miss-Triage" in text
    assert "miss.pdf" in text
    assert "GEN\\_IOC" in text
    document = json.loads(js.read_text(encoding="utf-8"))
    assert document["misses"] == 1
    assert set(document["miss_rows"][0]) == {
        "name", "type", "family", "verdict", "score", "rules",
    }
    # Keine Rohpayloads: nur Metadaten, keine Bytes/Base64/URLs aus der Probe.
    assert "%PDF" not in text
    assert "file://" not in text


def test_markdown_escapes_attacker_controlled_cells(tmp_path):
    from malaz.lab.report import ResultRow

    row = ResultRow(
        name="evil|name![](http://example.invalid/x)\u202eevil",
        group="malicious",
        type="pdf",
        verdict="GREEN",
        score=0,
        rules=("GEN_IOC",),
    )
    text = triage.render_markdown(triage.triage([row]), "quelle.csv")
    assert "\\|" in text
    assert "](http" not in text  # kein aktiver Markdown-Link
    assert "\u202e" not in text  # Bidi maskiert
    evil_line = next(line for line in text.splitlines() if "evil" in line)
    assert "\n" not in evil_line


def test_main_rejects_traversal_and_missing_input(tmp_path, capsys):
    assert triage.main([str(tmp_path / "fehlt.csv")]) == 1
    csv_path = tmp_path / "r.csv"
    csv_path.write_text("Gruppe,Datei,Typ,Urteil,Score,Top-Findings,Ungeprueft\n",
                        encoding="utf-8-sig")
    assert triage.main([
        str(csv_path), "--markdown", str(tmp_path / ".." / "x.md"),
    ]) == 1
