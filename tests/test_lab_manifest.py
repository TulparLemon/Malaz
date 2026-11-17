"""Manifest-Validierung: Struktur, Hash, Pfad- und Feldprüfungen."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from malaz.lab.manifest import (
    ManifestError,
    load_manifest,
    manifest_sha256,
    sha256_file,
    validate_document,
    verify_files,
)

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "tests" / "data" / "realworld_manifest.example.json"
SCHEMA = ROOT / "tests" / "data" / "realworld_manifest.schema.json"


def _document() -> dict:
    return json.loads(EXAMPLE.read_text(encoding="utf-8"))


def _problems(mutate) -> list[str]:
    doc = copy.deepcopy(_document())
    mutate(doc)
    return validate_document(doc)


def test_example_manifest_is_valid_and_loads():
    manifest = load_manifest(EXAMPLE)
    assert len(manifest.entries) == 8
    assert manifest.by_name["nested_archive.zip"].label == "malicious"
    assert manifest.label_of("normal_report.pdf") == "benign"
    assert manifest.label_of("fehlt.bin") is None
    assert {entry.split for entry in manifest.entries} == {"dev", "test"}


def test_schema_and_example_agree_on_required_fields():
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    required = set(schema["$defs"]["file"]["required"])
    for entry in _document()["files"]:
        assert required <= set(entry)
    assert set(schema["properties"]) == {"schema_version", "corpus", "files"}
    assert set(schema["$defs"]["file"]["properties"]) == required


def test_missing_field_is_reported():
    problems = _problems(lambda doc: doc["files"][0].pop("family"))
    assert any("family" in problem for problem in problems)


def test_unknown_field_is_reported():
    problems = _problems(lambda doc: doc["files"][0].update({"payload": "x"}))
    assert any("unbekannte Felder" in problem for problem in problems)


def test_sha256_must_be_lowercase_hex():
    problems = _problems(lambda doc: doc["files"][0].update({"sha256": "A" * 64}))
    assert any("sha256" in problem for problem in problems)


def test_duplicate_name_and_hash_are_reported():
    def duplicate(doc):
        doc["files"][1]["name"] = doc["files"][0]["name"]
        doc["files"][1]["sha256"] = doc["files"][0]["sha256"]

    problems = _problems(duplicate)
    assert any("doppelter Dateiname" in problem for problem in problems)
    assert any("doppelter Hash" in problem for problem in problems)


@pytest.mark.parametrize(
    "name",
    [
        "../evil.pdf",
        "sub/evil.pdf",
        "..",
        "C:\\evil.pdf",
        "/evil.pdf",
        "C:evil",
        "D:",
    ],
)
def test_path_components_in_name_are_rejected(name):
    problems = _problems(lambda doc: doc["files"][0].update({"name": name}))
    assert any("Pfadanteile" in problem or "kein Dateiname" in problem for problem in problems)


def test_schema_version_must_not_be_a_boolean():
    """BUG-048: ``True == 1`` liess ein JSON-``true`` als schema_version durch.

    Das Schema fordert ``const: 1`` (Typ Zahl); ``validate_document`` meldete
    fuer ``true`` vorher nichts.
    """
    problems = _problems(lambda doc: doc.update({"schema_version": True}))
    assert any("schema_version" in problem for problem in problems)

    doc = _document()
    doc["schema_version"] = False
    assert validate_document(doc)


def test_control_character_in_name_is_rejected():
    problems = _problems(lambda doc: doc["files"][0].update({"name": "evil\x00.pdf"}))
    assert any("Steuerzeichen" in problem for problem in problems)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("label", "malware"),
        ("split", "holdout"),
        ("type", "PDF"),
        ("family", "has space"),
        ("first_seen", "2026-13-40"),
        ("first_seen", "01.01.2026"),
    ],
)
def test_enum_and_format_violations(field, value):
    problems = _problems(lambda doc: doc["files"][0].update({field: value}))
    assert problems


def test_empty_file_list_is_rejected():
    assert validate_document({"schema_version": 1, "corpus": _document()["corpus"], "files": []})


def test_load_reports_every_problem_not_just_the_first(tmp_path):
    doc = _document()
    doc["files"][0]["label"] = "nope"
    doc["files"][1]["sha256"] = "x"
    path = tmp_path / "broken.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(ManifestError) as excinfo:
        load_manifest(path)
    assert len(excinfo.value.problems) >= 2


def test_verify_files_detects_missing_and_changed_bytes(tmp_path):
    payload = tmp_path / "a.bin"
    payload.write_bytes(b"expected")
    other = tmp_path / "b.bin"
    other.write_bytes(b"different")

    doc = _document()
    doc["files"][0]["name"] = "a.bin"
    doc["files"][0]["sha256"] = sha256_file(payload)
    doc["files"][1]["name"] = "b.bin"
    doc["files"][1]["sha256"] = "f" * 64
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(doc), encoding="utf-8")

    manifest = load_manifest(path)
    checks = verify_files(manifest, tmp_path)
    statuses = {check.name: check.status for check in checks}
    assert statuses["a.bin"] == "ok"
    assert statuses["b.bin"] == "hash_mismatch"
    assert statuses["macro.docm"] == "missing"  # übrige Manifest-Zeilen


def test_manifest_file_hash_changes_with_content(tmp_path):
    path = tmp_path / "m.json"
    path.write_text('{"a":1}', encoding="utf-8")
    first = manifest_sha256(path)
    path.write_text('{"a":2}', encoding="utf-8")
    assert manifest_sha256(path) != first
