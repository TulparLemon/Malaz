"""Expanded corpus: 500+ fixtures, expectations, determinism, manifest."""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

import pytest

from malaz import config
from malaz.analysis.clamav import ClamAVScanner
from malaz.analysis.windows_av import WindowsDefenderScanner
from malaz.core.dispatcher import Dispatcher
from malaz.core.scoring import BASE_WEIGHTS

_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import corpus_determinism as det  # noqa: E402
import make_benign_corpus as benign  # noqa: E402
import make_corpus_v2 as v2  # noqa: E402
import make_test_corpus_extended as ext  # noqa: E402

MANIFEST = Path(__file__).resolve().parent / "data" / "corpus_v2_manifest.json"


@pytest.fixture(scope="module", autouse=True)
def _pin_no_7zip():
    """Same scan environment on dev machines with and without 7-Zip."""
    with det.pin_no_7zip():
        yield


@pytest.fixture(scope="module")
def fixtures():
    return v2.build_fixtures()


@pytest.fixture(scope="module")
def v2_dispatcher():
    old_die = config.DIE_ENABLED
    config.DIE_ENABLED = False
    try:
        with det.pin_user_threat_intel():
            yield Dispatcher(
                av_scanner=WindowsDefenderScanner(enabled=False),
                clam_scanner=ClamAVScanner(enabled=False),
            )
    finally:
        config.DIE_ENABLED = old_die


def _scan(dispatcher, tmp_path: Path, fixture):
    path = tmp_path / fixture.name
    path.write_bytes(fixture.data)
    return dispatcher.scan_path(path)


def test_manifest_matches_generator(fixtures):
    assert MANIFEST.exists(), "tests/data/corpus_v2_manifest.json fehlt"
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest["count"] == len(fixtures)
    assert manifest["count"] >= 400
    assert {entry["name"] for entry in manifest["fixtures"]} == {
        fixture.name for fixture in fixtures
    }


def test_total_corpus_exceeds_500_and_covers_many_extensions(fixtures, tmp_path):
    base = [
        *benign.build_corpus(tmp_path / "b"),
        *ext.build_extended_corpus(tmp_path / "m"),
    ]
    total = len(base) + len(fixtures)
    assert total >= 500, total
    extensions = {Path(path).suffix.lower() for path in base}
    extensions |= {Path(fixture.name).suffix.lower() for fixture in fixtures}
    # 37 magic-detected types plus the extension families (docx/xlsx/doc/...).
    assert len(extensions) >= 40, sorted(extensions)
    families = Counter(fixture.family for fixture in fixtures)
    assert len(families) >= 9, families


def test_malicious_fixtures_reach_yellow(v2_dispatcher, fixtures, tmp_path):
    """A fixture labelled ``flag`` must be at least YELLOW.

    The previous criterion accepted any weighted finding, so PE_UNSIGNED (5)
    or OFFICE_DDE (15) stayed GREEN and still counted as "malicious". That
    overstated the corpus; this assertion matches the roadmap's >= YELLOW
    contract.
    """
    failures = []
    for fixture in fixtures:
        if fixture.expected != "flag":
            continue
        result = _scan(v2_dispatcher, tmp_path, fixture)
        if result.risk_level.name == "GREEN":
            failures.append(
                f"{fixture.name}: GREEN {result.score} "
                f"{[i.rule_id for i in result.all_indicators() if i.effective_weight(BASE_WEIGHTS)]}"
            )
    assert not failures, "\n".join(failures)


def test_benign_fixtures_stay_green(v2_dispatcher, fixtures, tmp_path):
    failures = []
    for fixture in fixtures:
        if fixture.expected != "green":
            continue
        result = _scan(v2_dispatcher, tmp_path, fixture)
        if result.risk_level.name != "GREEN":
            failures.append(
                f"{fixture.name}: {result.risk_level.name} {result.score} "
                f"{[i.rule_id for i in result.indicators if i.effective_weight(BASE_WEIGHTS)]}"
            )
    assert not failures, "\n".join(failures)


def test_edge_fixtures_do_not_crash(v2_dispatcher, fixtures, tmp_path):
    for fixture in fixtures:
        if fixture.expected != "any":
            continue
        result = _scan(v2_dispatcher, tmp_path, fixture)
        assert result is not None
        assert result.detected_type


def test_corpus_has_enough_unique_bytes(fixtures):
    import hashlib

    unique = {hashlib.sha256(fixture.data).hexdigest() for fixture in fixtures}
    assert len(unique) >= 350, f"nur {len(unique)} eindeutige Fixtures von {len(fixtures)}"
    # Encrypted ZIPs need a random salt/ID; their findings are compared by the
    # main suites instead of their bytes.
    nondeterministic = {"zip_encrypted"}
    rebuilt = {fixture.name: fixture.data for fixture in v2.build_fixtures()}
    for fixture in fixtures:
        if any(fixture.name.startswith(prefix) for prefix in nondeterministic):
            continue
        assert rebuilt[fixture.name] == fixture.data, fixture.name


def test_script_fixtures_use_the_languages_comment_syntax():
    """TEST-037: ``#`` ist in .vbs/.js/.bat kein Kommentar."""
    scripts = [
        fixture
        for fixture in v2.build_fixtures()
        if fixture.family == "scripts" and fixture.kind == "malicious"
    ]
    assert scripts
    for fixture in scripts:
        suffix = Path(fixture.name).suffix
        first = fixture.data.splitlines()[0].decode("utf-8")
        if suffix == ".vbs":
            assert first.startswith("'"), fixture.name
        elif suffix == ".js":
            assert first.startswith("//"), fixture.name
        elif suffix in (".bat", ".cmd"):
            assert first.startswith("REM "), fixture.name
        elif suffix in (".ps1", ".sh"):
            assert first.startswith("#"), fixture.name
        else:  # coverage guard: the generator only emits the above types
            raise AssertionError(f"unerwarteter Skripttyp: {fixture.name}")
