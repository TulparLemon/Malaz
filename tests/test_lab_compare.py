"""T3 tests for scripts/lab_compare.py, malaz.lab.opsec, and triage_misses --split (Spec 017 §4)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import lab_compare  # noqa: E402
import triage_misses  # noqa: E402

from malaz.lab.opsec import find_opsec_leaks  # noqa: E402

_SHA_A = "a" * 64
_SHA_B = "b" * 64


def _write_run(
    run_dir: Path,
    files: list[dict],
    *,
    engine_profile: str = "static_only",
    av_engines: str = "disabled",
    dryrun: bool = False,
    manifest_sha256: str = _SHA_A,
    ingest_rejected: int = 0,
    sandbox_status: str = "ok",
    run_date_utc: str = "2026-11-26",
    write_meta: bool = True,
) -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "report.json").write_text(
        json.dumps({"schema_version": 1, "files": files}, indent=2),
        encoding="utf-8",
    )
    if write_meta:
        (run_dir / "lab_meta.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "run_date_utc": run_date_utc,
                    "engine_profile": engine_profile,
                    "av_engines": av_engines,
                    "dryrun": dryrun,
                    "manifest_sha256": manifest_sha256,
                    "ingest_rejected": ingest_rejected,
                    "ingest_rejected_detail": {},
                    "sandbox_status": sandbox_status,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    return run_dir


def _row(
    name: str,
    label: str,
    status: str,
    verdict: str | None,
    *,
    split: str = "test",
    ftype: str = "pdf",
    family: str = "Emotet",
) -> dict:
    return {
        "name": name,
        "label": label,
        "type": ftype,
        "family": family,
        "split": split,
        "status": status,
        "verdict": verdict,
        "score": 80 if verdict == "RED" else 0,
        "duration_ms": 10.0,
        "rules": [],
        "error": "",
        "unchecked": [],
    }


def test_compare_split_deltas_completeness_denominator_and_buckets(tmp_path):
    base = _write_run(
        tmp_path / "base",
        [
            # test split: 4 malicious (2 RED detected, 1 miss, 1 missing -> 2/4 = 50%!)
            _row("m1.pdf", "malicious", "detected", "RED", ftype="pdf", family="Emotet"),
            _row("m2.pdf", "malicious", "detected", "RED", ftype="pdf", family="Emotet"),
            _row("m3.exe", "malicious", "miss", "GREEN", ftype="pe", family="QakBot"),
            _row("m4.exe", "malicious", "missing", None, ftype="pe", family="OldFam"),
            # test split: 2 benign (0 RED, 1 unchecked -> 0/2 = 0%)
            _row("b1.pdf", "benign", "clean", "GREEN", ftype="pdf", family="benign"),
            _row("b2.pdf", "benign", "unchecked", "GREEN", ftype="pdf", family="benign"),
            # dev split (must be ignored for --split test)
            _row("d1.pdf", "malicious", "miss", "GREEN", split="dev"),
        ],
    )
    curr = _write_run(
        tmp_path / "curr",
        [
            # test split: 4 malicious (3 RED detected, 1 miss -> 3/4 = 75%, +25 pp!)
            _row("m1.pdf", "malicious", "detected", "RED", ftype="pdf", family="Emotet"),
            _row("m2.pdf", "malicious", "detected", "RED", ftype="pdf", family="Emotet"),
            _row("m3.exe", "malicious", "detected", "RED", ftype="pe", family="QakBot"),
            _row("m5.js", "malicious", "miss", "GREEN", ftype="js", family="NewFam"),
            # test split: 2 benign (0 RED, 0 unchecked)
            _row("b1.pdf", "benign", "clean", "GREEN", ftype="pdf", family="benign"),
            _row("b2.pdf", "benign", "clean", "GREEN", ftype="pdf", family="benign"),
            # dev split
            _row("d1.pdf", "malicious", "detected", "RED", split="dev"),
        ],
    )

    json_out = tmp_path / "delta.json"
    md_out = tmp_path / "delta.md"
    pub_out = tmp_path / "public.md"

    rc = lab_compare.main(
        [
            "--baseline",
            str(base),
            "--current",
            str(curr),
            "--split",
            "test",
            "--json",
            str(json_out),
            "--markdown",
            str(md_out),
            "--public-summary",
            str(pub_out),
            "--fail-on-regression",
        ]
    )
    assert rc == 0

    comp = json.loads(json_out.read_text(encoding="utf-8"))
    assert comp["baseline"]["recall_red"] == pytest.approx(0.5)  # 2/4 including missing!
    assert comp["current"]["recall_red"] == pytest.approx(0.75)  # 3/4
    assert comp["delta"]["recall_red_pp"] == pytest.approx(25.0)
    assert comp["delta"]["fp_red_pp"] == pytest.approx(0.0)
    assert comp["by_family"]["NewFam"]["status"] == "added"
    assert comp["by_family"]["NewFam"]["recall_red_pp"] is None
    assert comp["by_family"]["OldFam"]["status"] == "removed"
    assert comp["by_family"]["OldFam"]["recall_red_pp"] is None
    assert pub_out.is_file()
    pub_text = pub_out.read_text(encoding="utf-8")
    assert "75.00%" in pub_text
    assert "Emotet" not in pub_text  # allowlisted summary contains no free-text family names


def test_compare_empty_split_n_zero_yields_null_and_na(tmp_path):
    base = _write_run(tmp_path / "b0", [_row("d1.pdf", "malicious", "detected", "RED", split="dev")])
    curr = _write_run(tmp_path / "c0", [_row("d1.pdf", "malicious", "detected", "RED", split="dev")])

    json_out = tmp_path / "d0.json"
    pub_out = tmp_path / "p0.md"
    rc = lab_compare.main(
        [
            "--baseline",
            str(base),
            "--current",
            str(curr),
            "--split",
            "test",
            "--json",
            str(json_out),
            "--public-summary",
            str(pub_out),
            "--fail-on-regression",
        ]
    )
    assert rc == 0
    comp = json.loads(json_out.read_text(encoding="utf-8"))
    assert comp["current"]["recall_red"] is None
    assert comp["delta"]["recall_red_pp"] is None
    assert "N/A" in pub_out.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("case_name", "curr_files", "curr_rej"),
    [
        (
            "fp_increase",
            [
                _row("m1.pdf", "malicious", "detected", "RED"),
                _row("b1.pdf", "benign", "flagged", "RED"),
            ],
            0,
        ),
        (
            "recall_drop",
            [
                _row("m1.pdf", "malicious", "miss", "GREEN"),
                _row("b1.pdf", "benign", "clean", "GREEN"),
            ],
            0,
        ),
        (
            "delta_unchecked",
            [
                _row("m1.pdf", "malicious", "detected", "RED"),
                _row("b1.pdf", "benign", "unchecked", "GREEN"),
            ],
            0,
        ),
        (
            "delta_missing",
            [
                _row("m1.pdf", "malicious", "detected", "RED"),
                _row("b1.pdf", "benign", "missing", None),
            ],
            0,
        ),
        (
            "delta_ingest_rejected",
            [
                _row("m1.pdf", "malicious", "detected", "RED"),
                _row("b1.pdf", "benign", "clean", "GREEN"),
            ],
            1,
        ),
    ],
)
def test_compare_fail_on_regression_triggers_exit_1(tmp_path, case_name, curr_files, curr_rej):
    base = _write_run(
        tmp_path / f"b_{case_name}",
        [
            _row("m1.pdf", "malicious", "detected", "RED"),
            _row("b1.pdf", "benign", "clean", "GREEN"),
        ],
        ingest_rejected=0,
    )
    curr = _write_run(tmp_path / f"c_{case_name}", curr_files, ingest_rejected=curr_rej)
    rc = lab_compare.main(["--baseline", str(base), "--current", str(curr), "--fail-on-regression"])
    assert rc == 1, case_name


def test_compare_fail_closed_exit_2_gates(tmp_path):
    ok_files = [_row("m1.pdf", "malicious", "detected", "RED")]
    base = _write_run(tmp_path / "base", ok_files)

    # 1. Missing lab_meta.json
    no_meta = _write_run(tmp_path / "no_meta", ok_files, write_meta=False)
    assert lab_compare.main(["--baseline", str(base), "--current", str(no_meta)]) == 2

    # 2. sandbox_status != "ok"
    bad_status = _write_run(tmp_path / "bad_status", ok_files, sandbox_status="custody_failed")
    assert lab_compare.main(["--baseline", str(base), "--current", str(bad_status)]) == 2

    # 3. dryrun == true without --allow-dryrun
    dry = _write_run(tmp_path / "dry", ok_files, dryrun=True)
    assert lab_compare.main(["--baseline", str(base), "--current", str(dry)]) == 2
    assert lab_compare.main(["--baseline", str(base), "--current", str(dry), "--allow-dryrun"]) == 0

    # 4. --public-summary with dryrun == true ALWAYS Exit 2 even WITH --allow-dryrun!
    pub_blocked = tmp_path / "pub_blocked.md"
    assert (
        lab_compare.main(
            [
                "--baseline",
                str(base),
                "--current",
                str(dry),
                "--allow-dryrun",
                "--public-summary",
                str(pub_blocked),
            ]
        )
        == 2
    )
    assert not pub_blocked.exists()

    # 5. engine_profile mismatch
    with_av = _write_run(tmp_path / "with_av", ok_files, engine_profile="with_av")
    assert lab_compare.main(["--baseline", str(base), "--current", str(with_av)]) == 2

    # 6. manifest_sha256 mismatch without --allow-corpus-change
    other_corpus = _write_run(tmp_path / "other_c", ok_files, manifest_sha256=_SHA_B)
    assert lab_compare.main(["--baseline", str(base), "--current", str(other_corpus)]) == 2
    assert (
        lab_compare.main(
            ["--baseline", str(base), "--current", str(other_corpus), "--allow-corpus-change"]
        )
        == 0
    )


def test_find_opsec_leaks_and_env_edge_cases(monkeypatch):
    # Clean summary with COMPUTERNAME=MALAZ must allow "Malaz"
    monkeypatch.setenv("COMPUTERNAME", "MALAZ")
    monkeypatch.setenv("USERNAME", "a")  # len < 2 ignored
    assert find_opsec_leaks("Malaz Real-World Benchmark Summary: 92.5%") == []

    # Regex special chars in USERNAME escaped safely & caught
    monkeypatch.setenv("USERNAME", "kim.dev+1")
    assert find_opsec_leaks("Operator: kim.dev+1 ran this") != []
    assert find_opsec_leaks("Operator: kimXdev+1 ran this") == []

    # Empty env vars ignored
    monkeypatch.setenv("COMPUTERNAME", "")
    monkeypatch.setenv("USERNAME", "")
    assert find_opsec_leaks("Malaz clean text 100%") == []

    # Blocks hashes (>=32 hex), paths, UNC, email, IPv4, URLs
    assert find_opsec_leaks("md5: " + "a" * 32)
    assert find_opsec_leaks("sha1: " + "b" * 40)
    assert find_opsec_leaks("sha256: " + "c" * 64)
    assert find_opsec_leaks(r"file C:\Users\alice\secret.pdf")
    assert find_opsec_leaks(r"share \\corp-srv\drop\a.zip")
    assert find_opsec_leaks("unix /home/bob/sample.bin")
    assert find_opsec_leaks("contact alice@example.org")
    assert find_opsec_leaks("host 198.51.100.7")
    assert find_opsec_leaks("link https://evil.example/a")


def test_triage_misses_split_filtering_and_fail_closed(tmp_path):
    csv_path = tmp_path / "results.csv"
    csv_path.write_text(
        "Gruppe,Datei,Typ,Urteil,Score,Top-Findings,Ungeprueft,Datei_ID\n"
        "bad,dev_miss.pdf,pdf,GRÜN,0,,,dev_miss.pdf\n"
        "bad,test_miss.pdf,pdf,GRÜN,0,,,test_miss.pdf\n",
        encoding="utf-8",
    )
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "corpus": {
                    "id": "t3",
                    "created": "2026-11-26",
                    "source": "unit",
                    "notes": "",
                },
                "files": [
                    {
                        "sha256": "1" * 64,
                        "name": "dev_miss.pdf",
                        "type": "pdf",
                        "family": "DevFam",
                        "label": "malicious",
                        "source": "unit",
                        "first_seen": "2026-11-26",
                        "split": "dev",
                        "notes": "",
                    },
                    {
                        "sha256": "2" * 64,
                        "name": "test_miss.pdf",
                        "type": "pdf",
                        "family": "TestFam",
                        "label": "malicious",
                        "source": "unit",
                        "first_seen": "2026-11-26",
                        "split": "test",
                        "notes": "",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    # --split dev without --manifest -> Fail-Closed Exit 2
    assert triage_misses.main([str(csv_path), "--split", "dev"]) == 2

    # --split dev with --manifest excludes test_miss.pdf
    out_json = tmp_path / "misses_dev.json"
    rc = triage_misses.main(
        [str(csv_path), "--manifest", str(manifest_path), "--split", "dev", "--json", str(out_json)]
    )
    assert rc == 0
    rep = json.loads(out_json.read_text(encoding="utf-8"))
    assert rep["total_malicious"] == 1
    assert rep["misses"] == 1
    assert [r["name"] for r in rep["miss_rows"]] == ["dev_miss.pdf"]
