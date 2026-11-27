"""Signed (HMAC) manifest and rollback for imported offline feeds.

What this is
============

The imported blocklists under ``%LocalAppData%\\Malaz\\hashes`` are files the
scanner silently trusts. A truncated or half-replaced file does not raise —
it simply finds fewer hits, and a missing hit looks like a clean file. The
atomic writer closes the "half-written" window; this manifest answers the
remaining question: *is what the scanner reads still what the importer wrote?*

Every successful import writes ``feeds/feed-manifest.json`` with the SHA-256
and size of each blocklist and each per-source snapshot, plus an HMAC-SHA256
over that document. The key is generated locally on first use
(``feeds/manifest.key``). Verification detects corruption and accidental or
third-party modification after the import.

What this is NOT
================

It is **not** a vendor signature. HMAC with a local key cannot prove that a
feed came from URLhaus/Spamhaus; an attacker who can write the user profile
can also read the key. Real feed signatures would need a published public key
and a signed upstream format — neither exists for these sources. The state is
therefore named "hmac-local" in the output, not "verified publisher".
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .. import config
from .atomicwrite import write_text_atomic

SCHEMA = 1


@dataclass(frozen=True)
class ManifestStatus:
    state: str  # ok | missing | unsigned | tampered | changed | error
    problems: tuple[str, ...] = ()
    checked_files: int = 0

    @property
    def ok(self) -> bool:
        return self.state == "ok"


def _feed_dir() -> Path:
    # Same location rule as ``core.feeds.feed_dir``: user state, never the
    # repository. Imported lazily so tests can monkeypatch config cleanly.
    from .feeds import feed_dir

    return feed_dir()


def manifest_path() -> Path:
    return _feed_dir() / "feed-manifest.json"


def key_path() -> Path:
    return _feed_dir() / "manifest.key"


def _target_files() -> list[tuple[str, Path]]:
    return [
        ("hashes", Path(config.USER_HASH_BLOCKLIST_FILE)),
        ("urls", Path(config.URL_BLOCKLIST_FILE)),
        ("domains", Path(config.DOMAIN_BLOCKLIST_FILE)),
        ("networks", Path(config.IP_BLOCKLIST_FILE)),
    ]


def _canonical(document: dict) -> bytes:
    return json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _load_key(*, create: bool) -> bytes | None:
    path = key_path()
    try:
        text = path.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        if not create:
            return None
    except OSError:
        return None
    else:
        try:
            return bytes.fromhex(text)
        except ValueError:
            # A corrupt key must not silently become a different key.
            return None
    key = os.urandom(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    # `write_text_atomic` writes text; hex keeps the key inspectable and
    # avoids a second binary writer. The key never leaves the user profile.
    write_text_atomic(path, key.hex() + "\n")
    with suppress(OSError):
        os.chmod(path, 0o600)
    return key


def _describe_files() -> tuple[list[dict], list[dict]]:
    targets: list[dict] = []
    for key, path in _target_files():
        try:
            data = path.read_bytes()
        except OSError:
            continue
        targets.append(
            {
                "id": key,
                "name": path.name,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
        )
    sources_dir = _feed_dir() / "sources"
    sources: list[dict] = []
    if sources_dir.is_dir():
        for path in sorted(sources_dir.glob("*.txt")):
            try:
                data = path.read_bytes()
            except OSError:
                continue
            sources.append(
                {
                    "file": path.name,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "size": len(data),
                }
            )
    return targets, sources


def write_manifest(now: datetime | None = None) -> Path:
    """Write the signed manifest for the current on-disk state.

    Raises ``OSError`` when the key or the manifest cannot be written. Callers
    that already imported successfully should log the failure instead of
    turning a completed import into a failed one — the verify script will then
    report ``missing``/``unsigned`` plainly.
    """
    moment = (now or datetime.now(UTC)).astimezone(UTC)
    targets, sources = _describe_files()
    document = {
        "schema": SCHEMA,
        "generated": moment.isoformat(),
        "targets": targets,
        "sources": sources,
    }
    key = _load_key(create=True)
    if key is None:
        raise OSError("Manifest-Schlüssel konnte nicht gelesen/erzeugt werden")
    signed = dict(document)
    signed["hmac_sha256"] = hmac.new(
        key, _canonical(document), hashlib.sha256
    ).hexdigest()
    path = manifest_path()
    write_text_atomic(
        path, json.dumps(signed, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    )
    return path


def verify_manifest() -> ManifestStatus:
    """Compare the manifest with the files the scanner will actually read."""
    path = manifest_path()
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ManifestStatus("missing", ("feed-manifest.json fehlt",))
    except OSError as exc:
        return ManifestStatus("error", (f"Manifest nicht lesbar: {exc}",))
    try:
        document = json.loads(raw)
    except ValueError as exc:
        return ManifestStatus("tampered", (f"Manifest ist kein JSON: {exc}",))
    if not isinstance(document, dict) or document.get("schema") != SCHEMA:
        return ManifestStatus("tampered", ("unbekanntes Manifest-Schema",))
    signature = document.pop("hmac_sha256", None)
    key = _load_key(create=False)
    if key is None:
        return ManifestStatus("unsigned", ("Signaturschlüssel fehlt",))
    if not isinstance(signature, str) or not hmac.compare_digest(
        signature,
        hmac.new(key, _canonical(document), hashlib.sha256).hexdigest(),
    ):
        return ManifestStatus(
            "tampered", ("HMAC stimmt nicht — Manifest wurde verändert",)
        )

    problems: list[str] = []
    checked = 0
    targets = document.get("targets")
    if not isinstance(targets, list):
        return ManifestStatus("tampered", ("Manifest ohne Ziel-Liste",))
    by_id = dict(_target_files())
    for entry in targets:
        if not isinstance(entry, dict):
            problems.append("ungültiger Ziel-Eintrag")
            continue
        key_name = str(entry.get("id", ""))
        target = by_id.get(key_name)
        if target is None:
            problems.append(f"unbekanntes Ziel: {key_name}")
            continue
        checked += 1
        try:
            data = target.read_bytes()
        except OSError:
            problems.append(f"{key_name}: Datei fehlt")
            continue
        if hashlib.sha256(data).hexdigest() != entry.get("sha256"):
            problems.append(f"{key_name}: Inhalt weicht vom Manifest ab")

    sources = document.get("sources")
    if not isinstance(sources, list):
        return ManifestStatus("tampered", ("Manifest ohne Quellen-Liste",))
    sources_dir = _feed_dir() / "sources"
    for entry in sources:
        if not isinstance(entry, dict):
            problems.append("ungültiger Quellen-Eintrag")
            continue
        name = str(entry.get("file", ""))
        if not name or "/" in name or "\\" in name:
            problems.append(f"ungültiger Quellenname: {name[:60]}")
            continue
        checked += 1
        path_src = sources_dir / name
        try:
            data = path_src.read_bytes()
        except OSError:
            problems.append(f"sources/{name}: Datei fehlt")
            continue
        if hashlib.sha256(data).hexdigest() != entry.get("sha256"):
            problems.append(f"sources/{name}: Inhalt weicht ab")

    return ManifestStatus(
        "changed" if problems else "ok", tuple(problems), checked
    )


def summary(status: ManifestStatus | None = None) -> str:
    status = status or verify_manifest()
    if status.state == "ok":
        return f"Feed-Manifest ok ({status.checked_files} Dateien, HMAC lokal)"
    if status.state == "missing":
        return "Feed-Manifest fehlt — noch kein Import mit Manifest geschrieben"
    if status.state == "unsigned":
        return "Feed-Manifest ohne lokalen Schlüssel — nicht prüfbar"
    if status.state == "tampered":
        return "Feed-Manifest verändert: " + "; ".join(status.problems[:3])
    if status.state == "changed":
        return (
            "Feed-Inhalte weichen vom Manifest ab: "
            + "; ".join(status.problems[:3])
        )
    return "Feed-Manifest-Fehler: " + "; ".join(status.problems[:3])


@dataclass(frozen=True)
class AgeEntry:
    """One update source with its age and a human-readable detail line."""

    name: str
    age_days: int | None
    detail: str
    state: str  # ok | warn | off


def _age_days(mtime: float, now: datetime) -> int:
    changed = datetime.fromtimestamp(mtime, UTC)
    return max(0, (now - changed).days)


def directory_age(path: Path | str, now: datetime | None = None) -> int | None:
    """Age in days of the NEWEST file under ``path`` (``None`` if empty).

    Filesystem-only: safe for window construction. The newest file is the
    right measure for a signature database (daily/main update independently)
    and for a staged rules directory (bundle published last).
    """
    moment = (now or datetime.now(UTC)).astimezone(UTC)
    root = Path(path)
    try:
        if root.is_file():
            return _age_days(root.stat().st_mtime, moment)
        newest = max(
            (entry.stat().st_mtime for entry in root.rglob("*") if entry.is_file()),
            default=None,
        )
    except OSError:
        return None
    return None if newest is None else _age_days(newest, moment)


def yara_rules_age(now: datetime | None = None) -> AgeEntry:
    """Age of the externally downloaded YARA rules (filesystem only)."""
    moment = (now or datetime.now(UTC)).astimezone(UTC)
    files: list[Path] = []
    try:
        for path in config.YARA_EXTERNAL_DIR.rglob("*"):
            if path.is_file() and path.suffix.lower() in {".yar", ".yara", ".yarc"}:
                files.append(path)
    except OSError:
        files = []
    if not files:
        return AgeEntry(
            "Externe YARA-Regeln",
            None,
            "keine externen Regeln installiert (nur mitgelieferte)",
            "off",
        )
    newest = max(path.stat().st_mtime for path in files)
    age = _age_days(newest, moment)
    return AgeEntry(
        "Externe YARA-Regeln",
        age,
        f"{len(files)} Regeldatei(en), neueste {age} Tag(e) alt",
        "warn" if age >= 30 else "ok",
    )


def update_ages(now: datetime | None = None) -> list[AgeEntry]:
    """Age of ClamAV DB and external YARA rules (blocklists have their badge).

    Read-only and offline. Missing pieces are ``off`` (not installed); a stale
    piece is ``warn``. Thresholds reuse the documented update cadence
    (``*_AUTO_UPDATE_MIN_AGE_DAYS``), not a second number that can drift.
    """
    moment = (now or datetime.now(UTC)).astimezone(UTC)
    entries: list[AgeEntry] = []

    try:
        from ..analysis.clamav_status import collect_status, db_age_days

        status = collect_status()
    except Exception as exc:  # diagnosis must never break the window
        entries.append(
            AgeEntry("ClamAV-Datenbank", None, f"Status nicht lesbar: {exc}", "off")
        )
    else:
        if status.db_dates:
            age = db_age_days(status.db_dates, now=moment)
            state = "warn" if age is not None and age >= 30 else "ok"
            entries.append(
                AgeEntry(
                    "ClamAV-Datenbank",
                    age,
                    f"Signaturdatenbank {age} Tag(e) alt"
                    if age is not None
                    else "Signaturdatenbank ohne Datum",
                    state,
                )
            )
        else:
            entries.append(
                AgeEntry(
                    "ClamAV-Datenbank",
                    None,
                    "keine Signaturdatenbank gefunden",
                    "off",
                )
            )

    entries.append(yara_rules_age(moment))
    return entries

