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
        threat = any(i.rule_id == "AV_THREAT" for i in result.indicators)
        if threat:
            assert result.anchored
            assert result.risk_level.name == "RED"
        # Real-time protection may have blocked the file before our scan
        # (OSError 22) or removed it entirely — either way Defender reacted.
        blocked = result.error is not None or not os.path.exists(path)
        assert threat or blocked, (
            "Defender hat auf EICAR nicht reagiert (weder Scan-Erkennung "
            "noch Echtzeitschutz-Sperre)"
        )
    finally:
        with suppress(OSError):
            os.unlink(path)
