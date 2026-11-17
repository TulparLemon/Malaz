"""EICAR live AV probe — runs inside the VM, called by vm_live_malware_test.bat.

Writes the industry-standard EICAR test string (harmless, no code) and
reports how the local Defender reacted:
  1. real-time protection blocked the write (virus-specific WinError 225/226),
  2. the on-demand scan reports AV_THREAT / CLAMAV_THREAT,
  3. the file vanished during the scan (quarantined mid-scan).

Exit code 0 = AV integration alive; 1 = no reaction (results questionable).
Other write errors (full/locked TEMP) also exit 1 — they prove nothing about AV.
"""

from __future__ import annotations

import os
import sys
import tempfile
from contextlib import suppress
from pathlib import Path

# Source layout: the CWD may be anywhere (and is attacker-writable when this
# runs from a download folder); the import must resolve to THIS tree.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from malaz.core.dispatcher import Dispatcher

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

# Windows AV filter drivers report a blocked write as ERROR_VIRUS_INFECTED
# (225) or ERROR_VIRUS_DELETED (226). Python maps those Win32 codes to
# errno 22 (EINVAL), so the check must look at `winerror` as well.
# Everything else — full disk, locked TEMP, permission denied — says nothing
# about AV being alive and must not be counted as a reaction.
_AV_WRITE_CODES = frozenset({225, 226})


def _av_blocked(exc: OSError) -> bool:
    return (
        exc.errno in _AV_WRITE_CODES
        or getattr(exc, "winerror", None) in _AV_WRITE_CODES
    )


def main() -> int:
    fd, path = tempfile.mkstemp(suffix=".txt")
    try:
        try:
            os.write(fd, EICAR)
        except OSError as exc:
            if _av_blocked(exc):
                print(
                    f"EICAR: Echtzeitschutz hat Schreiben blockiert "
                    f"(OSError {exc.errno}/WinError {getattr(exc, 'winerror', None)})"
                )
                print("=> AV-Integration AKTIV (Reaktion vor dem Scan)")
                return 0
            print(
                f"EICAR: Schreiben fehlgeschlagen, aber ohne AV-Signatur "
                f"(OSError {exc.errno}/WinError {getattr(exc, 'winerror', None)}: {exc}) "
                "— kein AV-Nachweis."
            )
            return 1
        finally:
            with suppress(OSError):
                os.close(fd)

        dispatcher = Dispatcher()
        result = dispatcher.scan_path(path)
        threat = any(
            i.rule_id in ("AV_THREAT", "CLAMAV_THREAT")
            for i in result.all_indicators()
        )
        still_exists = os.path.exists(path)

        if threat:
            print("EICAR: Scan erkannt Bedrohung (AV_THREAT/CLAMAV_THREAT)")
            print("=> AV-Integration AKTIV (On-Demand-Erkennung)")
            return 0
        if not still_exists:
            print("EICAR: Datei wurde während des Scans entfernt (Quarantäne)")
            print("=> AV-Integration AKTIV (Echtzeit-Reaktion)")
            return 0

        print("!!! EICAR: Defender hat NICHT reagiert — AV-Integration oder")
        print("    Signaturen defekt. Korpus-Ergebnisse mit Vorsicht lesen.")
        return 1
    finally:
        with suppress(OSError):
            if os.path.exists(path):
                os.remove(path)


if __name__ == "__main__":
    raise SystemExit(main())
