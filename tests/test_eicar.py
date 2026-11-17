"""EICAR live AV test.

The EICAR test string is the industry-standard, fully harmless AV test
pattern: it contains no code and cannot activate, but every AV engine
recognizes it.

Two outcomes are accepted, both proving the Defender integration works:

1. the scan completes and reports ``AV_THREAT`` (anchored, RED), or
2. the real-time protection blocks/removes the EICAR file as it is written
   (Windows raises ``OSError 22`` on open / the file disappears) — Defender
   reacted before our static scan could even read it.

Note: Defender will log/clean the EICAR file — that is its intended purpose.
"""

import os
import tempfile
from contextlib import suppress

import pytest

from malaz.core.dispatcher import Dispatcher

EICAR = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)


def _assert_or_skip_eicar_result(result, path: str) -> None:
    threat = any(i.rule_id == "AV_THREAT" for i in result.indicators)
    if threat:
        assert result.anchored
        assert result.risk_level.name == "RED"
        return
    # Real-time protection may have blocked the file before our scan
    # (OSError 22) or removed it entirely — either way Defender reacted.
    blocked = result.error is not None or not os.path.exists(path)
    if blocked:
        return
    # On runners/hosts where %TEMP% is on Defender's ExclusionPath, MpCmdRun
    # outputs "Scanning <path> was skipped." (rc=0). Malaz must flag that as
    # incomplete (AV_SKIPPED) and never as AV_CLEAN.
    av_skipped = any(
        i.rule_id == "AV_SKIPPED"
        and (
            "übersprungen" in i.detail.lower()
            or "uebersprungen" in i.detail.lower()
        )
        for i in result.indicators
    )
    if av_skipped:
        assert result.is_incomplete, (
            "Übersprungener Defender-Scan muss is_incomplete=True setzen"
        )
        assert not any(i.rule_id == "AV_CLEAN" for i in result.indicators), (
            "Übersprungener Defender-Scan darf niemals AV_CLEAN setzen"
        )
        pytest.skip("Defender überspringt %TEMP% per System-Ausschlussliste")
    raise AssertionError(
        "Defender hat auf EICAR nicht reagiert (weder Scan-Erkennung "
        "noch Echtzeitschutz-Sperre)"
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows Defender required")
def test_eicar_triggers_defender():
    dispatcher = Dispatcher()  # real AV engines
    if not dispatcher.av_scanner.available:
        pytest.skip("Defender/MpCmdRun nicht verfügbar")

    fd, path = tempfile.mkstemp(suffix=".txt")
    os.write(fd, EICAR)
    os.close(fd)
    try:
        result = dispatcher.scan_path(path)
        _assert_or_skip_eicar_result(result, path)
    finally:
        with suppress(OSError):
            os.unlink(path)


def test_eicar_helper_skips_only_on_incomplete_exclusion(tmp_path):
    from malaz.models import Indicator, ScanResult

    target = tmp_path / "eicar.txt"
    target.write_bytes(EICAR)

    # (a) Genuine exclusion skip -> incomplete + pytest.skip
    skipped_res = ScanResult(
        path=str(target),
        indicators=[
            Indicator(
                rule_id="AV_SKIPPED",
                title="Windows Defender übersprungen",
                detail=(
                    "Windows Defender hat den Scan dieser Datei übersprungen "
                    "(z. B. Ausschlussliste oder Richtlinie)"
                ),
            )
        ],
    )
    assert skipped_res.is_incomplete is True
    with pytest.raises(pytest.skip.Exception, match="System-Ausschlussliste"):
        _assert_or_skip_eicar_result(skipped_res, str(target))

    # (b) False clean -> hard AssertionError
    clean_res = ScanResult(
        path=str(target),
        indicators=[
            Indicator(
                rule_id="AV_CLEAN",
                title="Sauber",
                detail="Windows Defender: keine Bedrohung gefunden.",
            )
        ],
    )
    with pytest.raises(AssertionError, match="Defender hat auf EICAR nicht reagiert"):
        _assert_or_skip_eicar_result(clean_res, str(target))

    # (c) AV_SKIPPED due to timeout (not exclusion) -> hard AssertionError
    timeout_res = ScanResult(
        path=str(target),
        indicators=[
            Indicator(
                rule_id="AV_SKIPPED",
                title="Timeout",
                detail="Zeitüberschreitung nach 90s",
            )
        ],
    )
    with pytest.raises(AssertionError, match="Defender hat auf EICAR nicht reagiert"):
        _assert_or_skip_eicar_result(timeout_res, str(target))

    # (d) Contradictory AV_SKIPPED + AV_CLEAN -> hard AssertionError
    both_res = ScanResult(
        path=str(target),
        indicators=[
            Indicator(
                rule_id="AV_SKIPPED",
                title="Übersprungen",
                detail="Windows Defender hat den Scan dieser Datei übersprungen",
            ),
            Indicator(rule_id="AV_CLEAN", title="Sauber", detail="ok"),
        ],
    )
    with pytest.raises(AssertionError, match="niemals AV_CLEAN"):
        _assert_or_skip_eicar_result(both_res, str(target))
