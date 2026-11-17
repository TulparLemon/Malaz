"""Persistent blocklist cache: fast warm start without stale data."""

from __future__ import annotations

import os
import time
from pathlib import Path

from malaz import config
from malaz.core import listcache


def _source(tmp_path: Path) -> Path:
    path = tmp_path / "domains.txt"
    path.write_text("evil.example\nmail.evil.example\n", encoding="utf-8")
    return path


def test_roundtrip_and_invalidation(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(listcache, "MIN_CACHE_SIZE", 0)
    source = _source(tmp_path)
    values = frozenset({"evil.example", "mail.evil.example"})
    listcache.store_cached(source, "domains", values)
    assert listcache.load_cached(source, "domains") == values

    # Same file, new content -> the key changes and the old cache is ignored.
    time.sleep(0.01)
    source.write_text("other.example\n", encoding="utf-8")
    os.utime(source, None)
    assert listcache.load_cached(source, "domains") is None


def test_corrupt_cache_is_ignored(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(listcache, "MIN_CACHE_SIZE", 0)
    source = _source(tmp_path)
    target = listcache._cache_path(source, "domains")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"not a marshal payload")
    assert listcache.load_cached(source, "domains") is None


def test_hashlist_persists_and_reloads(tmp_path, monkeypatch):
    from malaz.core import hashlist

    monkeypatch.setattr(config, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(listcache, "MIN_CACHE_SIZE", 0)
    path = tmp_path / "hashes.txt"
    digest = "a" * 64
    path.write_text(f"{digest}\n", encoding="utf-8")
    hashlist._load_blocklist.cache_clear()
    assert hashlist.load_blocklist(path) == frozenset({digest})
    assert listcache.load_cached(path, "hashes") == frozenset({digest})

    # New process simulation: drop the in-memory LRU, keep the disk cache.
    hashlist._load_blocklist.cache_clear()
    assert hashlist.load_blocklist(path) == frozenset({digest})


def test_domain_loader_persists(tmp_path, monkeypatch):
    from malaz.core import domain_blocklist

    monkeypatch.setattr(config, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(listcache, "MIN_CACHE_SIZE", 0)
    path = tmp_path / "domains.txt"
    path.write_text("Evil.Example\n*.mail.evil.example\n", encoding="utf-8")
    values, error = domain_blocklist.load_domain_blocklist_or_error(path)
    assert not error
    assert "evil.example" in values
    assert listcache.load_cached(path, "domains") == values


def test_store_skips_values_parsed_from_the_old_content(tmp_path, monkeypatch):
    """BUG-010: the key must describe the bytes that were PARSED.

    A feed import replaces the list atomically while another process parses
    it. Previously the stat was taken AFTER parsing, so the old values were
    written under the NEW mtime/size key — a permanent stale hit that no
    later check could invalidate (new hashes stayed unblocked).
    """
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(listcache, "MIN_CACHE_SIZE", 0)
    source = _source(tmp_path)
    captured = listcache.stat_key(source)
    assert captured is not None

    time.sleep(0.01)
    source.write_text("frisch.example\n", encoding="utf-8")
    os.utime(source, None)
    assert listcache.stat_key(source) != captured

    listcache.store_cached(
        source,
        "domains",
        frozenset({"evil.example"}),
        expected_key=captured,
    )

    assert listcache.load_cached(source, "domains") is None, (
        "Werte aus dem ALTEN Inhalt wurden unter dem NEUEN Schluessel "
        "abgelegt — der Cache liefert dauerhaft eine veraltete Liste"
    )
