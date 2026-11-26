"""Tests für die CycloneDX-SBOM (AP7)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import make_sbom  # noqa: E402


def test_sbom_lists_runtime_components_without_paths(tmp_path):
    target = tmp_path / "sbom.json"
    assert make_sbom.main(["--output", str(target)]) == 0
    text = target.read_text(encoding="utf-8")
    document = json.loads(text)
    assert document["bomFormat"] == "CycloneDX"
    assert document["metadata"]["component"]["name"] == "Malaz"
    names = {component["name"].lower() for component in document["components"]}
    assert {"pyside6", "pikepdf", "pefile", "yara-python"} <= names
    assert all(component["version"] for component in document["components"])
    # Keine privaten Pfade/Benutzernamen im Artefakt.
    assert "C:\\Users" not in text
    assert "AliceDev" not in text
    assert str(Path.home()) not in text
    assert "/home/" not in text
    assert make_sbom.main(["--output", str(target), "--check"]) == 0


def test_sbom_check_rejects_missing_or_empty(tmp_path):
    missing = tmp_path / "fehlt.json"
    assert make_sbom.main(["--output", str(missing), "--check"]) == 1
    empty = tmp_path / "leer.json"
    empty.write_text('{"bomFormat": "CycloneDX", "components": []}', encoding="utf-8")
    assert make_sbom.main(["--output", str(empty), "--check"]) == 1


def test_sbom_fails_on_uninstalled_runtime_package(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("gibt-es-nicht-xyz>=1\n", encoding="utf-8")
    target = tmp_path / "sbom.json"
    assert make_sbom.main(
        ["--requirements", str(requirements), "--output", str(target)]
    ) == 1
    assert not target.exists()


def test_sbom_follows_requirement_includes(tmp_path):
    """BUG-096: ``-r other.txt`` ist eine Anforderungsquelle, keine Option."""
    nested = tmp_path / "nested.txt"
    nested.write_text("PySide6>=6.6\n", encoding="utf-8")
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("-r nested.txt\nnumpy>=1.26\n", encoding="utf-8")
    assert make_sbom._roots(requirements) == ["pyside6", "numpy"]


def test_sbom_requirement_include_cycle_terminates(tmp_path):
    first = tmp_path / "a.txt"
    second = tmp_path / "b.txt"
    first.write_text("-r b.txt\nnumpy\n", encoding="utf-8")
    second.write_text("-r a.txt\npikepdf\n", encoding="utf-8")
    assert set(make_sbom._roots(first)) == {"numpy", "pikepdf"}


def test_sbom_puts_spdx_expressions_in_the_expression_field(tmp_path):
    """BUG-096: CycloneDX 1.5 trennt ``license.name`` und ``expression``."""
    target = tmp_path / "sbom.json"
    assert make_sbom.main(["--output", str(target)]) == 0
    document = json.loads(target.read_text(encoding="utf-8"))
    entries = [component["licenses"][0] for component in document["components"]]
    assert entries
    for entry in entries:
        assert ("expression" in entry) ^ ("license" in entry), entry
    assert any("expression" in entry for entry in entries), "keine SPDX-Expression erkannt"


def test_sbom_ignores_setuptools_vendored_sys_path():
    import setuptools  # noqa: F401 - appends setuptools/_vendor to sys.path

    components = make_sbom.collect(ROOT / "requirements.txt")
    names = {c["name"].lower() for c in components}
    assert "autocommand" not in names
    assert len(components) == 48
