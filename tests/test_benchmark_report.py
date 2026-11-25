"""Unit and integration tests for benchmark report generation & drift gate (Spec 013)."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
_SCRIPTS_DIR = str(ROOT / "scripts")
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

import check_doc_claims  # noqa: E402
import run_corpus  # noqa: E402

from malaz.models import Indicator, RiskLevel, ScanResult, Severity  # noqa: E402

_OPSEC_LEAK_RE = re.compile(
    r"(?i)(?:c:[/\\]users[/\\]|c:[/\\]malaz|/home/|/Users/|appdata[/\\]local[/\\]temp)"
)


def _sample_stats() -> dict:
    return {
        "schema_version": 1,
        "profile": "deterministic_static_only",
        "active_engines": ["static_pipelines", "yara_builtin"],
        "skipped_engines": [
            "windows_defender",
            "clamav",
            "7zip",
            "die",
            "capa",
            "user_threat_intel_feeds",
        ],
        "mutations_registered": 36,
        "corpora": {
            "malicious": {
                "total": 10,
                "red": 9,
                "yellow": 1,
                "green": 0,
                "crashes": 0,
                "incomplete_unexpected": 0,
                "flagged_rate_pct": 100.0,
                "red_rate_pct": 90.0,
            },
            "benign": {
                "total": 10,
                "red": 0,
                "yellow": 0,
                "green": 10,
                "crashes": 0,
                "incomplete_unexpected": 0,
                "red_fp_rate_pct": 0.0,
                "yellow_rate_pct": 0.0,
            },
        },
    }


def test_measure_corpora_counts_crashes_incomplete_and_zero_total(tmp_path: Path) -> None:
    class _FakeDispatcher:
        yara = SimpleNamespace(available=False)

        def scan_path(self, path: Path) -> ScanResult:
            if path.name == "boom.bin":
                raise RuntimeError("simulated parser crash")
            if path.name == "trunc.bin":
                return ScanResult(
                    path=str(path),
                    size=10,
                    sha256="0" * 64,
                    md5="0" * 32,
                    detected_type="unknown",
                    risk_level=RiskLevel.YELLOW,
                    score=20,
                    indicators=[
                        Indicator(
                            rule_id="CORE_READ_TRUNCATED",
                            title="truncated",
                            detail="prefix only",
                            severity=Severity.MEDIUM,
                            weight=20,
                        ),
                        Indicator(
                            rule_id="AV_SKIPPED",
                            title="av skipped",
                            detail="configured off",
                            severity=Severity.INFO,
                            weight=0,
                        ),
                    ],
                )
            return ScanResult(
                path=str(path),
                size=5,
                sha256="1" * 64,
                md5="1" * 32,
                detected_type="text",
                risk_level=RiskLevel.GREEN,
                score=0,
                indicators=[
                    Indicator(
                        rule_id="AV_SKIPPED",
                        title="av skipped",
                        detail="configured off",
                        severity=Severity.INFO,
                        weight=0,
                    )
                ],
            )

    def _build_mal(d: Path) -> list[Path]:
        d.mkdir(parents=True, exist_ok=True)
        files = [d / "boom.bin", d / "trunc.bin", d / "clean.txt"]
        for f in files:
            f.write_bytes(b"test")
        return files

    def _build_empty(d: Path) -> list[Path]:
        d.mkdir(parents=True, exist_ok=True)
        return []

    stats = run_corpus.measure_corpora(
        {"malicious": _build_mal, "benign": _build_empty},
        dispatcher=_FakeDispatcher(),  # type: ignore[arg-type]
    )
    assert stats["active_engines"] == ["static_pipelines"]
    assert "yara_builtin" in stats["skipped_engines"]
    assert stats["mutations_registered"] == len(run_corpus.check_tests_bite.MUTATIONS)

    mal = stats["corpora"]["malicious"]
    assert mal["total"] == 3
    assert mal["crashes"] == 1
    assert mal["yellow"] == 1
    assert mal["green"] == 1
    assert mal["red"] == 0
    assert mal["red"] + mal["yellow"] + mal["green"] + mal["crashes"] == mal["total"]
    assert mal["incomplete_unexpected"] == 1

    ben = stats["corpora"]["benign"]
    assert ben["total"] == 0
    assert ben["red_fp_rate_pct"] == 0.0
    assert ben["yellow_rate_pct"] == 0.0


def test_render_update_and_check_roundtrip_and_drift(tmp_path: Path) -> None:
    stats = _sample_stats()
    doc = tmp_path / "BENCHMARKS.md"
    doc.write_text(
        "# Title\n\n<!-- BENCHMARK_STATS_START -->\nold\n<!-- BENCHMARK_STATS_END -->\n",
        encoding="utf-8",
    )

    run_corpus.update_benchmark_doc(doc, stats)
    raw_bytes = doc.read_bytes()
    assert b"\r\n" not in raw_bytes, "update_benchmark_doc must write LF line endings"

    ok, diff = run_corpus.check_benchmark_doc(doc, stats)
    assert ok is True and diff == ""

    # Drift detection
    tampered = doc.read_text(encoding="utf-8").replace("| 10 | 9 |", "| 10 | 8 |")
    doc.write_text(tampered, encoding="utf-8")
    ok, diff = run_corpus.check_benchmark_doc(doc, stats)
    assert ok is False and "-| Malicious" in diff


@pytest.mark.parametrize(
    "bad_content",
    [
        "# No markers at all\n",
        "<!-- BENCHMARK_STATS_START -->\nonly start\n",
        "<!-- BENCHMARK_STATS_END -->\n<!-- BENCHMARK_STATS_START -->\n",
        "<!-- BENCHMARK_STATS_START -->\n<!-- BENCHMARK_STATS_START -->\n<!-- BENCHMARK_STATS_END -->\n",
    ],
)
def test_marker_errors_rejected_by_check_and_update(tmp_path: Path, bad_content: str) -> None:
    doc = tmp_path / "BAD.md"
    doc.write_text(bad_content, encoding="utf-8")
    ok, err = run_corpus.check_benchmark_doc(doc, _sample_stats())
    assert ok is False and err
    with pytest.raises(ValueError):
        run_corpus.update_benchmark_doc(doc, _sample_stats())


def test_cli_flag_validation_and_fail_fast(tmp_path: Path) -> None:
    doc = tmp_path / "BENCH.md"
    doc.write_text("# missing markers\n", encoding="utf-8")
    missing = tmp_path / "does_not_exist.md"

    assert run_corpus.main(["--update-doc", str(doc), "--check-doc", str(doc)]) == 2
    assert run_corpus.main(["--check-doc", str(doc), "--benign"]) == 2
    assert run_corpus.main(["--check-doc", str(doc), "--malicious"]) == 2
    assert run_corpus.main(["--check-doc", str(doc), "--v2"]) == 2
    assert run_corpus.main(["--json", str(tmp_path / "x.json"), "--csv", str(tmp_path / "x.csv")]) == 2
    assert run_corpus.main(["--check-doc", str(missing)]) == 2
    # Fail-fast on broken markers (exit 1 without scanning full corpus)
    assert run_corpus.main(["--check-doc", str(doc)]) == 1
    assert run_corpus.main(["--update-doc", str(doc)]) == 1


def test_benchmarks_doc_opsec_and_gate_wiring(tmp_path: Path, monkeypatch) -> None:
    bench_doc = ROOT / "docs" / "BENCHMARKS.md"
    assert bench_doc.is_file()
    content = bench_doc.read_text(encoding="utf-8")
    assert _OPSEC_LEAK_RE.search(content) is None, "OpSec path leak in docs/BENCHMARKS.md"

    # Also verify JSON output has no OpSec leaks
    out_json = tmp_path / "bench.json"
    monkeypatch.setattr(run_corpus, "measure_corpora", _sample_stats)
    assert run_corpus.main(["--json", str(out_json)]) == 0
    raw_json = out_json.read_text(encoding="utf-8")
    assert _OPSEC_LEAK_RE.search(raw_json) is None
    parsed = json.loads(raw_json)
    assert parsed["schema_version"] == 1
    assert parsed["active_engines"] and parsed["skipped_engines"]

    # Gate wiring checks (T3)
    assert "docs/BENCHMARKS.md" in check_doc_claims.CURRENT_DOCS
    assert check_doc_claims.main() == 0

    ci = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    steps = ci["jobs"]["gate"]["steps"]
    runs = [str(s.get("run", "")) for s in steps]
    assert any("python scripts/run_corpus.py --check-doc docs/BENCHMARKS.md" in r for r in runs)
