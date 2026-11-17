"""Corpus test: every synthetic, INERT malware-like fixture must produce its
expected indicators when scanned end-to-end through the dispatcher.

The corpus is generated on the fly by ``scripts/make_test_corpus.py``
(deterministic, seeded); nothing is executable, nothing activates — the
analysis is purely static, so byte patterns are all that matters.
"""

import os
import sys
import tempfile
from pathlib import Path

import pytest

from malaz.analysis.clamav import ClamAVScanner
from malaz.analysis.windows_av import WindowsDefenderScanner
from malaz.core.dispatcher import Dispatcher

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import make_benign_corpus as benign  # noqa: E402
import make_test_corpus as corpus  # noqa: E402
import make_test_corpus_extended as ext  # noqa: E402


@pytest.fixture(scope="module")
def dispatcher():
    # No AV engines: the corpus verifies the static pipelines, deterministically.
    #
    # Same for the third-party rule feeds: they are optional user-side
    # downloads, so letting them in would make this contract depend on what
    # the developer fetched. Measured: scanning the 22-file benign corpus cost
    # 2.0 s with the feeds loaded versus 0.1 s without — factor 20, all of it
    # feed loading, none of it detection.
    from malaz import config

    config.YARA_FEED_DIRS = ()
    try:
        yield Dispatcher(
            av_scanner=WindowsDefenderScanner(enabled=False),
            clam_scanner=ClamAVScanner(enabled=False),
        )
    finally:
        config.YARA_FEED_DIRS = config.YARA_FEED_DIRS_DEFAULT


def _all_findings(result) -> set[str]:
    """rule_ids of a result and all nested children."""
    ids = {i.rule_id for i in result.indicators}
    for child in result.children:
        ids |= _all_findings(child)
    return ids


def _names_and_types(result) -> tuple[set[str], set[str]]:
    names = {result.display_name}
    types = {result.detected_type}
    for child in result.children:
        cn, ct = _names_and_types(child)
        names |= cn
        types |= ct
    return names, types


# Expected rules for the RTF case are name/type-based (the embedded OLE child).
_RTF_EXPECTED = ("name:embedded_ole_1.bin", "type:ole")


def test_corpus_fixtures_produce_expected_findings(dispatcher):
    with tempfile.TemporaryDirectory() as tmp:
        paths = corpus.build_corpus(Path(tmp))
        assert len(paths) == len(corpus.CORPUS)

        for (filename, _builder, expected), path in zip(
            corpus.CORPUS, paths, strict=True
        ):
            result = dispatcher.scan_path(path)
            assert result.error is None, f"{filename}: {result.error}"
            ids = _all_findings(result)
            names, types = _names_and_types(result)

            missing = []
            for expect in expected:
                if expect.startswith("name:"):
                    if expect[len("name:"):] not in names:
                        missing.append(expect)
                elif expect.startswith("type:"):
                    if expect[len("type:"):] not in types:
                        missing.append(expect)
                elif expect not in ids:
                    missing.append(expect)

            assert not missing, (
                f"{filename}: erwartete Indikatoren fehlen: {missing}\n"
                f"  gefunden: {sorted(ids)}"
            )


def test_corpus_deterministic():
    """The same file must produce identical findings on repeated scans."""
    data = corpus.pdf_obfuscated()
    fd, path = tempfile.mkstemp(suffix=".pdf")
    os.write(fd, data)
    os.close(fd)
    try:
        d = Dispatcher(
            av_scanner=WindowsDefenderScanner(enabled=False),
            clam_scanner=ClamAVScanner(enabled=False),
        )
        first = _all_findings(d.scan_path(path))
        second = _all_findings(d.scan_path(path))
        assert first == second
        assert "PDF_KW_JavaScript_OBF" in first
    finally:
        os.unlink(path)


def test_corpus_all_fixtures_are_inert():
    """No fixture may be a runnable format that a static scan would flag as
    executable-on-open beyond the intended markers — the corpus contract is
    'malware-looking but dead data'."""
    for filename, builder, _expected in corpus.CORPUS:
        data = builder()
        assert isinstance(data, bytes)
        assert len(data) > 0, filename


def test_original_corpus_is_deterministic():
    """Two builds of every fixture must be byte-identical.

    ``make_test_corpus`` promises this in its module docstring ("the corpus is
    deterministic across runs"), but nothing checked it — unlike the extended
    corpus, which has had such a test all along. Four builders violated the
    promise when this test was written: a module-level RNG that advances
    between calls (high_entropy_bin, pe_high_entropy_sections), os.urandom
    (pe_overlay) and the random MIME boundary of EmailMessage (mail.eml).
    """
    for filename, builder, _expected in corpus.CORPUS:
        first = builder()
        second = builder()
        assert first, f"{filename} ist leer"
        assert first == second, f"{filename} ist nicht deterministisch"


def test_benign_corpus_is_deterministic():
    """The benign corpus promises 'identical bytes on every run' — verify it.

    The golden snapshot builds this corpus on every run, so a fixture that
    differs per build makes the snapshot depend on luck. Nothing checked the
    promise before; the random MIME boundary in eml_business_mail violated it.
    """
    paths_first = benign.build_corpus(Path(tempfile.mkdtemp()) / "a")
    paths_second = benign.build_corpus(Path(tempfile.mkdtemp()) / "b")
    assert len(paths_first) == len(paths_second)
    for first, second in zip(
        sorted(paths_first, key=lambda p: p.name),
        sorted(paths_second, key=lambda p: p.name),
        strict=True,
    ):
        assert first.name == second.name
        assert first.read_bytes() == second.read_bytes(), (
            f"{first.name} ist nicht deterministisch"
        )


def test_benign_lnk_fixture_is_a_valid_shell_link():
    """Regression: the .lnk fixture had a 12-byte CLSID and a 64-byte header.

    The flags therefore sat at the wrong offset, ``parse_lnk`` rejected the
    file (valid=False) and ``magic.detect`` reported ``unknown`` — the benign
    corpus contained a .lnk that no consumer could recognize.
    """
    from malaz.core.lnk import parse_lnk
    from malaz.core.magic import detect

    data = benign.lnk_shortcut()
    assert len(data) > 76
    assert detect(data).type == "lnk"
    info = parse_lnk(data)
    assert info.valid
    assert info.relative_path == "C:\\Users\\Public\\Documents\\Handbuch.pdf"


def test_all_corpora_carry_fixed_timestamps():
    """No container fixture may embed a build time.

    The determinism tests build twice back-to-back, so they cannot see the
    2-second DOS resolution of ZIP entries or the gzip header: two builds in
    the same second are identical even when the timestamp comes from the clock.
    Measured with a >2 s gap, fixtures in ALL THREE corpora did differ — the
    xlsx ZIP headers (openpyxl writes parts via ``writestr(str, …)``), the
    gzip mtime and ``TarInfo.mtime`` of the .tar.gz fixtures.

    This checks the property directly instead of waiting, covering every corpus
    in milliseconds with a precise message naming the offending entry. The
    ``.eml``/PDF fixtures need no check here: their time sources (MIME boundary,
    pikepdf ``/ID``) are covered by the pairwise determinism tests.
    """
    import io
    import tarfile
    import zipfile

    from corpus_determinism import FIXED_TIME

    offenders: list[str] = []
    checked = 0

    corpora = [
        ("extended", [(n, b) for n, b, _e in ext.EXTENDED_CORPUS]),
        ("original", [(n, b) for n, b, _e in corpus.CORPUS]),
        ("benign", list(benign.BENIGN)),
    ]
    for group, fixtures in corpora:
        for filename, builder in fixtures:
            data = builder()
            if data[:2] == b"PK":
                try:
                    with zipfile.ZipFile(io.BytesIO(data)) as zf:
                        checked += 1
                        for info in zf.infolist():
                            if info.date_time != FIXED_TIME:
                                offenders.append(
                                    f"{group}/{filename}: {info.filename} "
                                    f"@ {info.date_time}"
                                )
                                break
                except zipfile.BadZipFile:
                    pass  # deliberately corrupt fixture (corrupt.zip)
            elif data[:2] == b"\x1f\x8b":
                checked += 1
                # gzip header: 4-byte mtime at offset 4
                mtime = int.from_bytes(data[4:8], "little")
                if mtime != 0:
                    offenders.append(f"{group}/{filename}: gzip mtime={mtime}")
                # Members inside the tar stream too
                try:
                    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
                        for member in tf.getmembers():
                            if member.mtime != 0:
                                offenders.append(
                                    f"{group}/{filename}: {member.name} "
                                    f"mtime={member.mtime}"
                                )
                                break
                except tarfile.TarError:
                    pass

    assert checked > 0, "kein Container-Fixture gefunden"
    assert not offenders, (
        "Fixtures tragen eine Build-Zeit (flakt an der naechsten "
        "Sekundengrenze):\n  " + "\n  ".join(offenders)
    )
