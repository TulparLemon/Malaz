"""Trockenlauf des Labors: synthetische Fixtures, Guard, Report, Hash-Kette.

Der Test ruft ``scripts/run_lab.ps1 -DryRun`` auf — denselben Einstiegspunkt,
den ein Operator benutzt. Damit ist nicht nur ``lab_dryrun.py`` geprüft,
sondern die Verdrahtung: Guard → Scan → Manifest-Hash → Auswertung.
"""

from __future__ import annotations

import csv
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from malaz.lab.manifest import load_manifest, verify_files

ROOT = Path(__file__).resolve().parent.parent
RUN_LAB = ROOT / "scripts" / "run_lab.ps1"
POWERSHELL = shutil.which("powershell") or shutil.which("pwsh")

pytestmark = pytest.mark.skipif(
    sys.platform != "win32" or POWERSHELL is None,
    reason="run_lab.ps1 braucht Windows-PowerShell",
)


def test_dry_run_reaches_report_with_synthetic_fixtures_only(tmp_path, monkeypatch):
    monkeypatch.setenv("PSModulePath", r"C:\nonexistent_ps7_modules")
    work = tmp_path / "lab"
    result = tmp_path / "lab" / "out" / "results.csv"
    proc = subprocess.run(
        [
            POWERSHELL,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(RUN_LAB),
            "-DryRun",
            "-WorkDir",
            str(work),
            "-ResultPath",
            str(result),
        ],
        capture_output=True,
        text=True,
        timeout=300,
        env={k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"},
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr

    summary = json.loads((work / "out" / "results.summary.json").read_text(encoding="utf-8"))
    assert summary["mode"] == "dry-run"
    assert summary["ok"] is True
    assert summary["synthetic_only"] is True
    assert summary["hyperv_touched"] is False
    assert summary["guard_ok"] is True

    guard = json.loads((work / "guard.json").read_text(encoding="utf-8-sig"))
    assert guard["ok"] is True
    assert all(check["status"] == "pass" for check in guard["checks"])

    report = json.loads(
        (work / "out" / "results.report.json").read_text(encoding="utf-8")
    )
    totals = report["totals"]
    assert totals["manifest_files"] == 8
    assert totals["unexpected_results"] == 0
    assert totals["errors"] == 0
    assert totals["malicious"]["recall_yellow"] == pytest.approx(1.0)
    assert totals["benign"]["fp_yellow"] == pytest.approx(0.0)

    # Die Hash-Kette muss den Scan überleben und im Manifest wiederfindbar sein.
    manifest = load_manifest(work / "run" / "dryrun_manifest.json")
    checks = verify_files(manifest, work / "run" / "corpus")
    assert len(checks) == 8
    assert all(check.ok for check in checks)

    with result.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 8
    assert {row["Urteil"] for row in rows} <= {"GRÜN", "GELB", "ROT", "FEHLER"}

    markdown = (work / "out" / "results.report.md").read_text(encoding="utf-8")
    assert "Realwelt-Auswertung" in markdown
    assert "Wilson" in markdown
