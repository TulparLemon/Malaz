"""lab_guard.ps1: fail-closed-Prüfungen mit simulierten Zuständen.

Kein Hyper-V nötig — der Guard wird mit einer State-JSON aufgerufen, die die
Umgebung beschreibt. Jede fehlende Angabe und jeder Verstoß muss Exit 1 und
``ok: false`` ergeben. Die Live-Probes werden hier bewusst nicht ausgeführt:
sie würden den Zustand des Entwicklungsrechners messen, nicht den Vertrag.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
GUARD = ROOT / "scripts" / "lab_guard.ps1"
POWERSHELL = shutil.which("powershell") or shutil.which("pwsh")

pytestmark = pytest.mark.skipif(
    sys.platform != "win32" or POWERSHELL is None,
    reason="lab_guard.ps1 braucht Windows-PowerShell",
)


def _clean_state() -> dict:
    return {
        "adapters": [],
        "default_routes": [],
        "dns_servers": [],
        "dns_resolves": False,
        "shared_folders": [],
        "clipboard_text": "",
        "drag_and_drop": False,
        "enhanced_session": False,
        "drive_redirection": False,
        "usb_storage": [],
        "is_admin": False,
        "vm_name": "Malaz-Analyzer",
        "vm_state": "Off",
        "checkpoint": "clean",
        "eicar": "detected",
    }


def _run_guard(
    tmp_path: Path,
    state: dict | None,
    *,
    expected_hash: str | None = None,
    output_dir: Path | None = None,
    vm_name: str = "Malaz-Analyzer",
    checkpoint: str = "clean",
    skip_eicar: bool = False,
) -> tuple[subprocess.CompletedProcess, dict]:
    state_path = tmp_path / "state.json"
    state_path.write_text(json.dumps(state if state is not None else {}), encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text('{"schema_version": 1}\n', encoding="utf-8")
    digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    out_dir = output_dir or (tmp_path / "out")
    out_dir.mkdir(parents=True, exist_ok=True)

    args = [
        POWERSHELL,
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(GUARD),
        "-StatePath",
        str(state_path),
        "-ManifestPath",
        str(manifest),
        "-ManifestSha256",
        expected_hash or digest,
        "-OutputDir",
        str(out_dir),
        "-VmName",
        vm_name,
        "-CheckpointName",
        checkpoint,
    ]
    if skip_eicar:
        args.append("-SkipEicar")
    clean_env = {k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"}
    proc = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=120,
        env=clean_env,
    )
    data = json.loads(proc.stdout)
    return proc, data


def _failing_ids(data: dict) -> set[str]:
    return {check["id"] for check in data["checks"] if check["status"] == "fail"}


def test_clean_state_passes_all_checks(tmp_path):
    proc, data = _run_guard(tmp_path, _clean_state())
    assert proc.returncode == 0, proc.stderr
    assert data["ok"] is True
    assert data["source"] == "simulated"
    assert _failing_ids(data) == set()


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (lambda s: s["adapters"].append({"name": "Ethernet", "status": "Up"}), "network_offline"),
        (lambda s: s["default_routes"].append("0.0.0.0/0 via Ethernet"), "no_default_route"),
        (lambda s: s["dns_servers"].append("10.0.0.1"), "dns_offline"),
        (lambda s: s.update({"dns_resolves": True}), "dns_offline"),
        (lambda s: s["shared_folders"].append("\\\\host\\share"), "no_shared_folders"),
        (lambda s: s.update({"clipboard_text": "secret"}), "clipboard_clear"),
        (lambda s: s.update({"drag_and_drop": True}), "no_drag_and_drop"),
        (lambda s: s.update({"enhanced_session": True}), "no_drag_and_drop"),
        (lambda s: s["usb_storage"].append("USB Mass Storage"), "no_usb_storage"),
        (lambda s: s.update({"is_admin": True}), "not_admin"),
        (lambda s: s.update({"vm_name": "AndereVM"}), "vm_identity"),
        (lambda s: s.update({"checkpoint": "dirty"}), "vm_identity"),
        (lambda s: s.update({"vm_state": "Running"}), "vm_identity"),
        (lambda s: s.update({"eicar": "none"}), "eicar_av_alive"),
        # BUG-097: ein Schreibfehler (auch mit fehlgeschlagener Kontrollprobe)
        # ist kein AV-Lebendigkeitsnachweis.
        (lambda s: s.update({"eicar": "error"}), "eicar_av_alive"),
        (lambda s: s.pop("dns_resolves"), "dns_offline"),
        (lambda s: s.pop("adapters"), "network_offline"),
    ],
)
def test_each_violation_fails_closed(tmp_path, mutate, expected):
    state = copy.deepcopy(_clean_state())
    mutate(state)
    proc, data = _run_guard(tmp_path, state)
    assert proc.returncode == 1
    assert data["ok"] is False
    assert expected in _failing_ids(data)


def test_wrong_manifest_hash_fails(tmp_path):
    proc, data = _run_guard(tmp_path, _clean_state(), expected_hash="0" * 64)
    assert proc.returncode == 1
    assert "manifest_hash" in _failing_ids(data)


def test_non_empty_output_directory_fails(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "leftover.csv").write_text("x", encoding="utf-8")
    proc, data = _run_guard(tmp_path, _clean_state(), output_dir=out)
    assert proc.returncode == 1
    assert "output_dir_empty" in _failing_ids(data)


def test_skip_eicar_allows_unknown_av_status(tmp_path):
    state = _clean_state()
    state["eicar"] = "none"
    proc, data = _run_guard(tmp_path, state, skip_eicar=True)
    assert proc.returncode == 0
    assert "eicar_av_alive" not in _failing_ids(data)


def test_missing_state_file_fails(tmp_path):
    state_path = tmp_path / "does-not-exist.json"
    manifest = tmp_path / "manifest.json"
    manifest.write_text("x", encoding="utf-8")
    digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    out = tmp_path / "out"
    out.mkdir()
    proc = subprocess.run(
        [
            POWERSHELL,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(GUARD),
            "-StatePath",
            str(state_path),
            "-ManifestPath",
            str(manifest),
            "-ManifestSha256",
            digest,
            "-OutputDir",
            str(out),
            "-VmName",
            "Malaz-Analyzer",
            "-CheckpointName",
            "clean",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        env={k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"},
    )
    assert proc.returncode == 1
    data = json.loads(proc.stdout)
    assert "state" in _failing_ids(data)
    assert data["ok"] is False


def test_guard_survives_poisoned_psmodulepath(tmp_path, monkeypatch):
    monkeypatch.setenv("PSModulePath", r"C:\nonexistent_ps7_modules")
    proc, data = _run_guard(tmp_path, _clean_state())
    assert proc.returncode == 0, proc.stderr
    assert data["ok"] is True
