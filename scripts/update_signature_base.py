"""Fetch the Neo23x0 signature-base YARA rules (explicit user action only).

Usage (from the project root, venv active):

    python scripts/update_signature_base.py            # fetch + install
    python scripts/update_signature_base.py --status   # what is installed?

This is the only part of Malaz that ever goes online for signature-base, and
only when the user runs it (``scripts/update_signature_base.bat`` is the same
thing for a double-click). Scans stay 100 % offline. Malaz ships no
third-party rules, so the rules land in ``rules/yara/signature_base/`` —
explicitly NOT in ``rules/yara/external/``, whose contents the ReversingLabs
update deletes on every run — and the engine compiles them into
``bundle.yarc`` on the next start (see core.yara_signature_base).

Licence: Detection Rule License (DRL) 1.1. The fetched revision's LICENSE is
written next to the rules together with an attribution note.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Make `malaz` importable when the package is not installed (source layout).
_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from malaz.core import yara_signature_base  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="update_signature_base",
        description=(
            "Neo23x0 signature-base Regeln (DRL 1.1) laden und nach "
            "rules/yara/signature_base/ installieren."
        ),
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="nur den Installationsstand anzeigen (kein Netzwerkzugriff)",
    )
    args = parser.parse_args(argv)

    if args.status:
        for line in yara_signature_base.describe_install():
            print(line)
        return 0

    result = yara_signature_base.update_signature_base_rules(line_callback=print)
    if not result.ok:
        print(f"\n[!] Fehlgeschlagen: {result.error}", file=sys.stderr)
        return 1
    print(
        f"\n[OK] {result.installed} Regel-Dateien mit {result.rules} Regeln "
        f"installiert."
    )
    print("     Pruefen mit: python scripts/update_signature_base.py --status")
    print(
        "     Hinweis: Regeln nicht mit dem Programm ausliefern (DRL 1.1 "
        "verlangt Attribution)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
