"""Tests for the blocklist import (core.hashlist merge/extract)."""

import datetime

from malaz.core.hashlist import (
    extract_sha256_hashes,
    is_listed,
    load_blocklist,
    merge_blocklist,
)

_H1 = "a" * 64
_H2 = "b" * 64
_H3 = "C" * 64  # uppercase in the feed, lowercased on import


def test_extract_finds_hashes_in_mixed_formats():
    feed = (
        "# Kommentar\n"
        f"{_H1} Trojan.Generic/Alpha\n"
        f"12345,{_H2},2026-08-20\n"
        f'{{"sha256": "{_H3}"}}\n'
        "\n"
    )
    found = extract_sha256_hashes(feed)
    assert found == [_H1, _H2, _H3.lower()]


def test_extract_ignores_non_sha256_hex():
    sha1 = "a" * 40
    sha512 = "d" * 128
    assert extract_sha256_hashes(f"{sha1} {_H1} {sha512}") == [_H1]
    assert extract_sha256_hashes("") == []


def test_merge_blocklist_appends_and_dedupes(tmp_path):
    target = tmp_path / "blocklist.sha256"
    target.write_text(f"{_H1} # Altbestand\n", encoding="utf-8")

    added = merge_blocklist(
        [_H1, _H2, _H3, "kein-hash", _H2],
        source_label="feed.txt",
        path=target,
        now=datetime.datetime(2026, 8, 20),
    )
    assert added == 2  # _H1 war schon drin, _H2 doppelt, kein-hash ungültig

    content = target.read_text(encoding="utf-8")
    assert "# Import feed.txt 2026-08-20" in content
    assert _H2 in content and _H3.lower() in content

    listed = load_blocklist(target)
    assert _H1 in listed and _H2 in listed and _H3.lower() in listed


def test_merge_keeps_last_hash_when_file_has_no_trailing_newline(tmp_path):
    """BUG-012: appending ``# Import …`` glued the comment to the last hash.

    ``H1# Import test …`` no longer matched the 64-hex parser, so the
    previously listed hash silently disappeared from detection.
    """
    target = tmp_path / "blocklist.sha256"
    target.write_text(_H1, encoding="utf-8")  # deliberately no "\n"

    assert merge_blocklist(
        [_H2], source_label="feed.txt", path=target,
        now=datetime.datetime(2026, 8, 20),
    ) == 1

    listed = load_blocklist(target)
    assert _H1 in listed, "der letzte Hash ohne Zeilenumbruch ging verloren"
    assert _H2 in listed


def test_merge_blocklist_without_changes_writes_nothing(tmp_path):
    target = tmp_path / "blocklist.sha256"
    target.write_text(f"{_H1}\n", encoding="utf-8")
    before = target.read_text(encoding="utf-8")
    assert merge_blocklist([_H1], path=target) == 0
    assert target.read_text(encoding="utf-8") == before


def test_merged_hash_is_listed_without_restart(tmp_path):
    # The mtime-keyed cache must pick up the appended entry immediately.
    target = tmp_path / "blocklist.sha256"
    assert not is_listed(_H2, path=target)
    merge_blocklist([_H2], path=target)
    assert is_listed(_H2, path=target)


# -- getrennte Listen: kuratiert (getrackt) vs. Nutzer-Importe --------------
#
# Der Import schreibt NICHT in die git-getrackte rules/hashes/blocklist.sha256:
# dort gelandete Fremd-Hashes wuerden in Releases wandern (abuse.ch-ToS
# verbietet Weiterverbreitung). Beide Dateien werden beim Laden vereinigt.


def test_merge_defaults_to_user_file_not_curated(tmp_path, monkeypatch):
    from malaz import config

    curated = tmp_path / "tracked.sha256"
    user = tmp_path / "user.sha256"
    monkeypatch.setattr(config, "HASH_BLOCKLIST_FILE", curated)
    monkeypatch.setattr(config, "USER_HASH_BLOCKLIST_FILE", user)

    merge_blocklist([_H2], source_label="feed.txt")

    assert user.is_file(), "Import muss in die Nutzerdatei schreiben"
    assert not curated.exists(), "getrackte Datei darf unangetastet bleiben"


def test_load_merges_curated_and_user_lists(tmp_path, monkeypatch):
    from malaz import config

    curated = tmp_path / "tracked.sha256"
    user = tmp_path / "user.sha256"
    curated.write_text(f"{_H1}\n", encoding="utf-8")
    user.write_text(f"{_H2}\n", encoding="utf-8")
    monkeypatch.setattr(config, "HASH_BLOCKLIST_FILE", curated)
    monkeypatch.setattr(config, "USER_HASH_BLOCKLIST_FILE", user)

    listed = load_blocklist()
    assert _H1 in listed, "kuratierter Eintrag fehlt"
    assert _H2 in listed, "importierter Eintrag fehlt"
    assert is_listed(_H1) and is_listed(_H2)


def test_load_tolerates_missing_user_file(tmp_path, monkeypatch):
    from malaz import config

    curated = tmp_path / "tracked.sha256"
    curated.write_text(f"{_H1}\n", encoding="utf-8")
    monkeypatch.setattr(config, "HASH_BLOCKLIST_FILE", curated)
    monkeypatch.setattr(config, "USER_HASH_BLOCKLIST_FILE", tmp_path / "fehlt.sha256")

    assert load_blocklist() == frozenset({_H1})
    assert is_listed(_H1)
    assert not is_listed(_H2)


def test_import_does_not_duplicate_curated_hash(tmp_path, monkeypatch):
    """Ein kuratierter Hash darf nicht zusaetzlich in die Nutzerdatei."""
    from malaz import config

    curated = tmp_path / "tracked.sha256"
    user = tmp_path / "user.sha256"
    curated.write_text(f"{_H1}\n", encoding="utf-8")
    monkeypatch.setattr(config, "HASH_BLOCKLIST_FILE", curated)
    monkeypatch.setattr(config, "USER_HASH_BLOCKLIST_FILE", user)

    assert merge_blocklist([_H1, _H2], source_label="feed.txt") == 1
    assert _H1 not in user.read_text(encoding="utf-8")
    assert _H2 in user.read_text(encoding="utf-8")


def test_matched_source_names_the_hitting_list(tmp_path, monkeypatch):
    """Der Befund muss die getroffene Liste benennen, nicht einen festen Pfad.

    Ein Treffer kann aus der mitgelieferten ODER der importierten Datei
    kommen; ein fest verdrahteter Pfad waere fuer eine davon schlicht falsch.
    """
    from malaz import config
    from malaz.core.hashlist import matched_source

    curated = tmp_path / "tracked.sha256"
    user = tmp_path / "user.sha256"
    curated.write_text(f"{_H1}\n", encoding="utf-8")
    user.write_text(f"{_H2}\n", encoding="utf-8")
    monkeypatch.setattr(config, "HASH_BLOCKLIST_FILE", curated)
    monkeypatch.setattr(config, "USER_HASH_BLOCKLIST_FILE", user)

    assert matched_source(_H1) == "Projekt-Liste"
    assert matched_source(_H2) == "importierte Liste"
    assert matched_source("c" * 64) == ""


def test_finding_names_the_imported_list(tmp_path, monkeypatch):
    """Der gemeldete Text darf nicht 'rules/hashes/...' behaupten, wenn ein
    Nutzer-Import getroffen hat."""
    from malaz import config
    from malaz.core import hashlist
    from malaz.models import AnalysisContext
    from malaz.pipelines.generic_pipeline import GenericPipeline

    user = tmp_path / "user.sha256"
    user.write_text(f"{_H1}\n", encoding="utf-8")
    monkeypatch.setattr(config, "HASH_BLOCKLIST_FILE", tmp_path / "leer.sha256")
    monkeypatch.setattr(config, "USER_HASH_BLOCKLIST_FILE", user)
    hashlist._load_blocklist.cache_clear()

    data = b"malware-bytes"
    ctx = AnalysisContext(
        path=__import__("pathlib").Path("x.bin"),
        data=data,
        detected_type="binary",
        size=len(data),
        sha256=_H1,
    )
    hits = [i for i in GenericPipeline().analyze(ctx) if i.rule_id == "GEN_HASH_BLOCKLIST"]
    assert hits, "Treffer auf der Nutzerliste muss gemeldet werden"
    assert "importierte Liste" in hits[0].detail
    assert "rules/hashes" not in hits[0].detail
    hashlist._load_blocklist.cache_clear()


def test_import_script_dedupes_against_curated_list(tmp_path, monkeypatch):
    """BUG-090: der Standardimport darf kuratierte Hashes nicht duplizieren.

    ``merge_blocklist(path=dest)`` schaltet die Union aus kuratierter und
    Nutzerliste ab; das Skript muss deshalb fuer das Standardziel ``path=None``
    verwenden.
    """
    from malaz import config
    from malaz.core import hashlist
    from scripts import import_blocklist

    curated = tmp_path / "tracked.sha256"
    user = tmp_path / "user.sha256"
    feed = tmp_path / "feed.txt"
    curated.write_text(f"{_H1}\n", encoding="utf-8")
    feed.write_text(f"{_H1}\n{_H2}\n", encoding="utf-8")
    monkeypatch.setattr(config, "HASH_BLOCKLIST_FILE", curated)
    monkeypatch.setattr(config, "USER_HASH_BLOCKLIST_FILE", user)
    hashlist._load_blocklist.cache_clear()

    assert import_blocklist.main([str(feed)]) == 0
    imported = user.read_text(encoding="utf-8")
    assert _H1 not in imported, "kuratierter Hash wurde in die Nutzerdatei dupliziert"
    assert _H2 in imported
    hashlist._load_blocklist.cache_clear()
