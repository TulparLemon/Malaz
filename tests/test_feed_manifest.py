"""Tests für Feed-Manifest, Rollback und Altersanzeige (AP6)."""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from malaz import config
from malaz.core import feed_import, feed_manifest
from malaz.core.feeds import FEEDS
from malaz.core.hashlist import extract_sha256_hashes

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import verify_feeds  # noqa: E402


@pytest.fixture()
def feed_home(tmp_path, monkeypatch):
    """Alle vier Blocklisten + Feed-Ablage in einem isolierten Benutzerordner."""
    home = tmp_path / "user"
    home.mkdir()
    monkeypatch.setattr(config, "USER_HASH_BLOCKLIST_FILE", home / "hashes.sha256")
    monkeypatch.setattr(config, "URL_BLOCKLIST_FILE", home / "urls.sha256")
    monkeypatch.setattr(config, "DOMAIN_BLOCKLIST_FILE", home / "domains.txt")
    monkeypatch.setattr(config, "IP_BLOCKLIST_FILE", home / "netze.txt")
    return home


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_manifest_roundtrip_and_tamper_detection(feed_home):
    _write(Path(config.USER_HASH_BLOCKLIST_FILE), "a" * 64 + "\n")
    _write(Path(config.URL_BLOCKLIST_FILE), "b" * 64 + "\n")
    _write(feed_home / "feeds" / "sources" / "urlhaus.url.txt", "# x\n" + "c" * 64 + "\n")
    path = feed_manifest.write_manifest()
    assert path.is_file()
    status = feed_manifest.verify_manifest()
    assert status.state == "ok"
    assert status.checked_files == 3

    # Inhalt einer Liste verändert -> changed, Manifest selbst bleibt gültig.
    _write(Path(config.USER_HASH_BLOCKLIST_FILE), "d" * 64 + "\n")
    changed = feed_manifest.verify_manifest()
    assert changed.state == "changed"
    assert any("hashes" in problem for problem in changed.problems)

    # Manifest manipuliert -> tampered (HMAC).
    document = json.loads(path.read_text(encoding="utf-8"))
    document["generated"] = "2000-01-01T00:00:00+00:00"
    path.write_text(json.dumps(document), encoding="utf-8")
    assert feed_manifest.verify_manifest().state == "tampered"


def test_manifest_without_key_is_unsigned(feed_home):
    _write(Path(config.USER_HASH_BLOCKLIST_FILE), "a" * 64 + "\n")
    feed_manifest.write_manifest()
    feed_manifest.key_path().unlink()
    assert feed_manifest.verify_manifest().state == "unsigned"


def test_missing_manifest_is_reported(feed_home):
    assert feed_manifest.verify_manifest().state == "missing"


def test_rollback_restores_previous_blocklist(feed_home, monkeypatch):
    target = Path(config.URL_BLOCKLIST_FILE)
    _write(target, "ALTER-BESTAND\n")
    original = feed_import.write_text_atomic

    def failing(path, text, **kwargs):
        if Path(path) == target:
            raise OSError("Swap fehlgeschlagen (Test)")
        return original(path, text, **kwargs)

    monkeypatch.setattr(feed_import, "write_text_atomic", failing)
    with pytest.raises(OSError, match="Swap fehlgeschlagen"):
        feed_import._replace_feed_snapshot(
            FEEDS[0], "url", ["e" * 64], target, extract_sha256_hashes,
            preserve_legacy=True,
        )
    assert target.read_text(encoding="utf-8") == "ALTER-BESTAND\n"
    source_dir = feed_home / "feeds" / "sources"
    assert not (source_dir / "urlhaus.url.txt").exists()
    assert not list(source_dir.glob(".*.bak-*"))


def test_successful_import_writes_manifest(feed_home):
    target = Path(config.URL_BLOCKLIST_FILE)
    feed_import._replace_feed_snapshot(
        FEEDS[0], "url", ["e" * 64], target, extract_sha256_hashes,
        preserve_legacy=False,
    )
    assert feed_manifest.verify_manifest().state == "ok"


def test_yara_and_directory_age_are_filesystem_only(tmp_path, monkeypatch):
    rules = tmp_path / "rules"
    rules.mkdir()
    monkeypatch.setattr(config, "YARA_EXTERNAL_DIR", rules)
    now = datetime.now(UTC)

    empty = feed_manifest.yara_rules_age(now)
    assert empty.state == "off" and empty.age_days is None

    bundle = rules / "bundle.yarc"
    bundle.write_bytes(b"x")
    old = (now - timedelta(days=40)).timestamp()
    os.utime(bundle, (old, old))
    entry = feed_manifest.yara_rules_age(now)
    assert entry.state == "warn"
    assert entry.age_days == 40
    assert feed_manifest.directory_age(rules, now) == 40
    assert feed_manifest.directory_age(tmp_path / "fehlt", now) is None


def test_verify_cli_exit_codes_and_json(monkeypatch, tmp_path):
    document = {
        "schema": "malaz.feed-status/1",
        "ages": [],
        "blocklists": [],
        "manifest": {"state": "ok", "checked_files": 0, "problems": [], "summary": "ok"},
    }
    monkeypatch.setattr(verify_feeds, "collect", lambda: document)
    target = tmp_path / "status.json"
    assert verify_feeds.main(["--json", str(target)]) == 0
    assert json.loads(target.read_text(encoding="utf-8"))["manifest"]["state"] == "ok"

    document["manifest"]["state"] = "changed"
    document["manifest"]["problems"] = ["hashes: Inhalt weicht ab"]
    assert verify_feeds.main([]) == 1
