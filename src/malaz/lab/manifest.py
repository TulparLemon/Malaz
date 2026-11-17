"""Manifest für den Realwelt-Test: Hashes, Typen, Familien, Labels.

Das Manifest ist die **einzige** Beschreibung des Korpus. Es enthält keine
Proben, nur Metadaten und SHA-256-Werte. Die Validierung ist absichtlich
streng und ohne Zusatzabhängigkeit: ein Tippfehler im Feldnamen würde sonst
still als "Feld fehlt" durchgehen, und ein doppelter Eintrag würde Recall und
False-Positive-Rate doppelt zählen.

Die Struktur entspricht ``tests/data/realworld_manifest.schema.json``
(Draft 2020-12). Abweichungen zwischen Schema und dieser Prüfung sind ein
Fehler; ``tests/test_lab_manifest.py`` hält beide Seiten zusammen.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
LABELS = ("malicious", "benign")
SPLITS = ("dev", "test")

_TOP_LEVEL = {"schema_version", "corpus", "files"}
_CORPUS_FIELDS = {"id", "created", "source", "notes"}
_ENTRY_FIELDS = {
    "sha256",
    "name",
    "type",
    "family",
    "label",
    "source",
    "first_seen",
    "split",
    "notes",
}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TYPE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,31}$")
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class ManifestError(ValueError):
    """Das Manifest ist nicht verwendbar; ``problems`` nennt alle Gründe."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = list(problems)
        super().__init__("; ".join(problems))


@dataclass(frozen=True)
class ManifestEntry:
    sha256: str
    name: str
    type: str
    family: str
    label: str
    source: str
    first_seen: str
    split: str
    notes: str = ""


@dataclass(frozen=True)
class Manifest:
    schema_version: int
    corpus_id: str
    created: str
    source: str
    entries: tuple[ManifestEntry, ...]
    notes: str = ""

    @property
    def by_name(self) -> dict[str, ManifestEntry]:
        return {entry.name: entry for entry in self.entries}

    def label_of(self, name: str) -> str | None:
        entry = self.by_name.get(name)
        return entry.label if entry else None


@dataclass(frozen=True)
class FileCheck:
    """Ergebnis der Hash-Prüfung einer Manifest-Zeile gegen die Platte."""

    name: str
    expected: str
    actual: str | None
    status: str  # ok | missing | hash_mismatch

    @property
    def ok(self) -> bool:
        return self.status == "ok"


def sha256_file(path: Path, chunk_size: int = 1 << 20) -> str:
    """SHA-256 streamen — keine 4-GB-Datei im RAM, keine Probe öffnen."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def manifest_sha256(path: Path) -> str:
    """Hash der Manifest-DATEI (Chain of Custody, nicht der Proben)."""
    return sha256_file(path)


def _check_iso_date(value: object, field: str, problems: list[str]) -> None:
    if not isinstance(value, str) or not _DATE.fullmatch(value):
        problems.append(f"{field}: Datum als YYYY-MM-DD erwartet")
        return
    try:
        date.fromisoformat(value)
    except ValueError:
        problems.append(f"{field}: kein gültiges Kalenderdatum: {value!r}")


def _check_text(
    value: object, field: str, problems: list[str], *, max_len: int = 200
) -> None:
    if not isinstance(value, str) or not value.strip():
        problems.append(f"{field}: nicht-leerer Text erwartet")
        return
    if len(value) > max_len:
        problems.append(f"{field}: länger als {max_len} Zeichen")
    if any(ord(ch) < 32 or ch == "\x7f" for ch in value):
        problems.append(f"{field}: Steuerzeichen sind nicht erlaubt")


def _check_name(value: object, problems: list[str]) -> None:
    if not isinstance(value, str) or not value:
        problems.append("files[].name: nicht-leerer Dateiname erwartet")
        return
    # ``C:evil`` ist ein LAUFWERKS-RELATIVER Pfad: ``Path("D:/corpus") /
    # "C:evil"`` ergibt ``C:evil`` und verlaesst damit das Korpus-Verzeichnis.
    # Der Doppelpunkt ist auf Windows ausserdem in keinem Dateinamen erlaubt
    # (nur als Alternate-Data-Stream-Trenner), also ist die Pruefung exakt.
    if "/" in value or "\\" in value or ":" in value:
        problems.append(f"files[].name: Pfadanteile sind nicht erlaubt: {value!r}")
    if value in (".", ".."):
        problems.append("files[].name: '.'/'..' ist kein Dateiname")
    if len(value) > 255:
        problems.append("files[].name: länger als 255 Zeichen")
    if any(ord(ch) < 32 or ch == "\x7f" for ch in value):
        problems.append("files[].name: Steuerzeichen sind nicht erlaubt")


def validate_document(document: object) -> list[str]:
    """Alle Verstöße gegen das Manifest-Schema. Leere Liste = gültig.

    Bewusst Sammeln statt Abbruch beim ersten Fehler: ein Manifest mit drei
    Tippfehlern soll alle drei melden, nicht den Operator dreimal laufen lassen.
    """
    problems: list[str] = []
    if not isinstance(document, dict):
        return ["Wurzel: JSON-Objekt erwartet"]

    unknown = sorted(set(document) - _TOP_LEVEL)
    if unknown:
        problems.append(f"unbekannte Felder auf Wurzelebene: {unknown}")
    missing = sorted(_TOP_LEVEL - set(document))
    if missing:
        problems.append(f"fehlende Felder auf Wurzelebene: {missing}")

    # ``True == 1`` in Python: der reine Vergleich liess ein JSON-``true`` als
    # schema_version durch, obwohl das Schema ``const: 1`` fordert. Zahlen
    # bleiben erlaubt — JSON vergleicht 1 und 1.0 mathematisch gleich.
    version = document.get("schema_version")
    if (
        isinstance(version, bool)
        or not isinstance(version, (int, float))
        or version != SCHEMA_VERSION
    ):
        problems.append(f"schema_version: {SCHEMA_VERSION} erwartet")

    corpus = document.get("corpus")
    if not isinstance(corpus, dict):
        problems.append("corpus: Objekt erwartet")
    else:
        unknown = sorted(set(corpus) - _CORPUS_FIELDS)
        if unknown:
            problems.append(f"corpus: unbekannte Felder: {unknown}")
        _check_text(corpus.get("id"), "corpus.id", problems, max_len=100)
        _check_iso_date(corpus.get("created"), "corpus.created", problems)
        _check_text(corpus.get("source"), "corpus.source", problems)
        if "notes" in corpus and not isinstance(corpus["notes"], str):
            problems.append("corpus.notes: Text erwartet")

    files = document.get("files")
    if not isinstance(files, list) or not files:
        problems.append("files: nicht-leere Liste erwartet")
        return problems

    seen_names: set[str] = set()
    seen_hashes: set[str] = set()
    for index, entry in enumerate(files):
        prefix = f"files[{index}]"
        if not isinstance(entry, dict):
            problems.append(f"{prefix}: Objekt erwartet")
            continue
        unknown = sorted(set(entry) - _ENTRY_FIELDS)
        if unknown:
            problems.append(f"{prefix}: unbekannte Felder: {unknown}")
        missing = sorted(_ENTRY_FIELDS - set(entry))
        if missing:
            problems.append(f"{prefix}: fehlende Felder: {missing}")

        digest = entry.get("sha256")
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            problems.append(f"{prefix}.sha256: 64 Hex-Zeichen (klein) erwartet")
        else:
            if digest in seen_hashes:
                problems.append(f"{prefix}.sha256: doppelter Hash {digest[:12]}…")
            seen_hashes.add(digest)

        _check_name(entry.get("name"), problems)
        name = entry.get("name")
        if isinstance(name, str) and name:
            if name in seen_names:
                problems.append(f"{prefix}.name: doppelter Dateiname {name!r}")
            seen_names.add(name)

        entry_type = entry.get("type")
        if not isinstance(entry_type, str) or not _TYPE.fullmatch(entry_type):
            problems.append(f"{prefix}.type: kleingeschriebener Typ erwartet")

        family = entry.get("family")
        if not isinstance(family, str) or not _TOKEN.fullmatch(family):
            problems.append(f"{prefix}.family: Token (Buchstaben/Ziffern/._-) erwartet")

        if entry.get("label") not in LABELS:
            problems.append(f"{prefix}.label: einer von {LABELS} erwartet")
        if entry.get("split") not in SPLITS:
            problems.append(f"{prefix}.split: einer von {SPLITS} erwartet")
        _check_text(entry.get("source"), f"{prefix}.source", problems)
        _check_iso_date(entry.get("first_seen"), f"{prefix}.first_seen", problems)
        if not isinstance(entry.get("notes"), str):
            problems.append(f"{prefix}.notes: Text erwartet")
        elif len(entry["notes"]) > 500:
            problems.append(f"{prefix}.notes: länger als 500 Zeichen")

    return problems


def _entry_from_dict(raw: dict[str, Any]) -> ManifestEntry:
    return ManifestEntry(
        sha256=str(raw["sha256"]),
        name=str(raw["name"]),
        type=str(raw["type"]),
        family=str(raw["family"]),
        label=str(raw["label"]),
        source=str(raw["source"]),
        first_seen=str(raw["first_seen"]),
        split=str(raw["split"]),
        notes=str(raw.get("notes", "")),
    )


def load_manifest(path: Path) -> Manifest:
    """Manifest lesen und vollständig validieren.

    ``ManifestError.problems`` enthält jeden Verstoß, nicht nur den ersten.
    """
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ManifestError([f"{path}: nicht lesbar: {exc}"]) from exc
    except json.JSONDecodeError as exc:
        raise ManifestError([f"{path}: kein gültiges JSON: {exc}"]) from exc

    problems = validate_document(document)
    if problems:
        raise ManifestError(problems)

    # validate_document garantiert die Struktur; cast ist hier dokumentiert.
    doc = document
    assert isinstance(doc, dict)
    corpus = doc["corpus"]
    assert isinstance(corpus, dict)
    files = doc["files"]
    assert isinstance(files, list)
    return Manifest(
        schema_version=int(doc["schema_version"]),
        corpus_id=str(corpus["id"]),
        created=str(corpus["created"]),
        source=str(corpus["source"]),
        notes=str(corpus.get("notes", "")),
        entries=tuple(_entry_from_dict(raw) for raw in files),
    )


def verify_files(manifest: Manifest, directory: Path) -> list[FileCheck]:
    """Jede Manifest-Zeile gegen die Platte prüfen (Hash vor UND nach dem Lauf).

    Kein Öffnen im Sinne von "ausführen" — nur sequenzielles Lesen zum Hashen.
    Fehlt eine Datei, ist das ein Befund, kein stiller Skip.
    """
    checks: list[FileCheck] = []
    for entry in manifest.entries:
        path = directory / entry.name
        if not path.is_file():
            checks.append(FileCheck(entry.name, entry.sha256, None, "missing"))
            continue
        actual = sha256_file(path)
        status = "ok" if actual == entry.sha256 else "hash_mismatch"
        checks.append(FileCheck(entry.name, entry.sha256, actual, status))
    return checks
