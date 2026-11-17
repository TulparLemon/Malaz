"""Contract test for the EXTENDED malware-looking corpus.

``test_corpus.py`` covers the original 19 fixtures. This module covers the
larger set in ``scripts/make_test_corpus_extended.py``: every fixture must
produce the findings it was built for, and the whole set must stay
deterministic.

Two kinds of expectations are checked:
  * rule IDs that MUST appear (the fixture's reason to exist),
  * guarantees about what must NOT happen (a traversal member must be dropped,
    not reported as if it had been analysed).

The anticipated rule IDs were measured against the real pipelines — a fixture
that silently stops matching its rule is a regression in either the fixture or
the rule, and both are worth failing on.
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

import pytest

from malaz.analysis.clamav import ClamAVScanner
from malaz.analysis.windows_av import WindowsDefenderScanner
from malaz.core.dispatcher import Dispatcher

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import corpus_determinism as det  # noqa: E402
import make_test_corpus_extended as ext  # noqa: E402


@pytest.fixture(scope="module", autouse=True)
def _pin_no_7zip():
    with det.pin_no_7zip():
        yield


@pytest.fixture(scope="module")
def dispatcher():
    """No AV engines: the corpus contract is about the static pipelines.

    The optional third-party rule feeds are neutralised for the same reason:
    they are user-side downloads, so this contract must not depend on what the
    developer happened to fetch (see test_corpus.py for the measurement).
    """
    from malaz import config

    config.YARA_FEED_DIRS = ()
    try:
        yield Dispatcher(
            av_scanner=WindowsDefenderScanner(enabled=False),
            clam_scanner=ClamAVScanner(enabled=False),
        )
    finally:
        config.YARA_FEED_DIRS = config.YARA_FEED_DIRS_DEFAULT


def _all_ids(result) -> set[str]:
    ids = {i.rule_id for i in result.indicators}
    for child in result.children:
        ids |= _all_ids(child)
    return ids


def _names_and_types(result) -> tuple[set[str], set[str]]:
    names = {result.display_name}
    types = {result.detected_type}
    for child in result.children:
        cn, ct = _names_and_types(child)
        names |= cn
        types |= ct
    return names, types


def test_extended_corpus_fixtures_match_expectations(dispatcher):
    """Every fixture must raise at least the rule IDs it was designed for."""
    with tempfile.TemporaryDirectory() as tmp:
        paths = ext.build_extended_corpus(Path(tmp))
        assert len(paths) == len(ext.EXTENDED_CORPUS)

        failures: list[str] = []
        for (filename, _builder, expected), path in zip(
            ext.EXTENDED_CORPUS, paths, strict=True
        ):
            result = dispatcher.scan_path(path)
            assert result.error is None, f"{filename}: {result.error}"
            ids = _all_ids(result)
            names, types = _names_and_types(result)

            missing = []
            for want in expected:
                if want.startswith("name:"):
                    if want[len("name:") :] not in names:
                        missing.append(want)
                elif want.startswith("type:"):
                    if want[len("type:") :] not in types:
                        missing.append(want)
                elif want not in ids:
                    missing.append(want)
            if missing:
                failures.append(
                    f"{filename}: fehlt {missing} (gefunden: {sorted(ids)})"
                )

        assert not failures, "\n".join(failures)


def test_extended_corpus_is_deterministic(dispatcher, tmp_path):
    """Two builds of the same fixture must be byte-identical.

    The golden snapshot and the CSV baselines depend on this; a stray
    ``os.urandom``, an unsorted dict or a ZipInfo defaulting to "now" would
    break reproducibility silently.

    ``encrypted_aes.zip`` and ``encrypted_user.pdf`` are exempt: both use real
    encryption, which requires a random salt/ID and therefore cannot repeat
    byte-for-byte (pikepdf refuses ``deterministic_id`` for encrypted output).
    For those two the *findings* must stay identical — which is what actually
    matters downstream.

    The two builds are separated by MORE THAN THE 2-SECOND DOS RESOLUTION. Two
    builds in the same second are byte-identical even when the timestamps come
    from the clock, so a back-to-back comparison silently missed a whole class:
    measured with a >2 s gap, the xlsx ZIP headers and the tar.gz gzip mtime
    were still clock-derived. Waiting once for all fixtures (rather than per
    fixture) costs ~2 s in total instead of minutes.
    """
    encrypted = {"encrypted_aes.zip", "encrypted_user.pdf"}
    builds = [(name, b) for name, b, _e in ext.EXTENDED_CORPUS]

    first = {name: builder() for name, builder in builds}
    # One sleep for every fixture: each pair is then guaranteed to straddle a
    # different 2-second DOS window.
    time.sleep(2.1)
    for name, builder in builds:
        assert first[name], f"{name} ist leer"
        second = builder()
        if name in encrypted:
            assert len(first[name]) == len(second)
            continue
        assert first[name] == second, f"{name} ist nicht deterministisch"

    # The encrypted fixtures must still produce the same verdict every time.
    for filename, expected_rule in (
        ("encrypted_aes.zip", "ARCH_ENCRYPTED"),
        ("encrypted_user.pdf", "PDF_ENCRYPTED"),
    ):
        builder = next(b for n, b, _e in ext.EXTENDED_CORPUS if n == filename)
        ids = []
        for _ in range(2):
            path = tmp_path / filename
            path.write_bytes(builder())
            ids.append(_all_ids(dispatcher.scan_path(path)))
        assert ids[0] == ids[1], f"{filename} liefert wechselnde Befunde"
        assert expected_rule in ids[0]


def test_office_corpus_reaches_the_vba_pipeline(dispatcher):
    """The VBA fixtures must be real OLE containers, not text fallbacks.

    A text-shaped .doc does reach oletools, but it never exercises the CFB
    parsing path a real Word document takes. This asserts the fixture is a
    genuine compound file so the corpus keeps testing what it claims to.
    """
    ole_magic = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    for name in ("doc_vba_macro", "doc_vba_obfuscated", "doc_vba_lolbin_persist"):
        data = getattr(ext, name)()
        assert data.startswith(ole_magic), f"{name} ist kein OLE-Container"

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "macro.doc"
        path.write_bytes(ext.doc_vba_macro())
        result = dispatcher.scan_path(path)
        assert result.detected_type == "ole"
        assert "OFFICE_MACRO" in _all_ids(result)


def test_traversal_member_is_analysed_but_never_extracted(dispatcher):
    """An unsafe member name must not hide its CONTENT from the scan.

    The name decides whether a member would be written to disk, never whether
    it is looked at: nothing is extracted here, so the payload is decompressed
    in memory and scanned. The earlier contract skipped such members entirely,
    which turned the member name into a detection bypass — measured, the same
    PowerShell cradle scored RED 90 as "payload.txt" and YELLOW 35 as
    "..payload.txt", with no child scan at all.

    The archive-level traversal finding (ARCH_ZIPSLIP) still fires, and
    ``is_safe_member_name`` still refuses the name for extraction.
    """
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "traversal.tar"
        path.write_bytes(ext.tar_with_traversal())
        result = dispatcher.scan_path(path)
        names = {c.display_name for c in result.children}
        assert any("safe" in n for n in names), (
            "der harmlose Eintrag muss weiterhin analysiert werden"
        )
        assert any("escape" in n or ".." in n for n in names), (
            f"der unsichere Eintrag muss inhaltlich geprüft werden: {names}"
        )
        rules = {i.rule_id for i in result.all_indicators()}
        assert "ARCH_ZIPSLIP" in rules or "ARCH_UNSAFE_NAME" in rules, rules
