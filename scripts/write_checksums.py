"""Write dist/SHA256SUMS-<version>.txt for the three release archives.

Run this AFTER the source archive is rebuilt and BEFORE signing: the signature
covers this file, so it has to hold the final hashes.

    python scripts/write_checksums.py --version 1.0.0

Why a script and not a one-liner: the previous instruction printed the hashes
to the terminal and left the file untouched, so the next step signed stale
checksums that did not match the rebuilt archive.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DIST = REPO / "dist"


def sha256(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest().upper(), path.stat().st_size


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--version", required=True, help="z. B. 1.0.0")
    ap.add_argument("--dist", type=Path, default=DIST)
    args = ap.parse_args()

    version = args.version
    names = [
        f"Malaz-{version}.zip",
        f"Malaz-{version}-source.zip",
        f"Malaz-{version}-licenses.zip",
    ]

    missing = [n for n in names if not (args.dist / n).is_file()]
    if missing:
        print("FEHLER: diese Archive fehlen:")
        for name in missing:
            print(f"  {args.dist / name}")
        return 2

    lines = []
    for name in names:
        digest, size = sha256(args.dist / name)
        lines.append(f"{digest}  {name}  ({size} Bytes)")
        print(lines[-1])

    target = args.dist / f"SHA256SUMS-{version}.txt"
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\nGeschrieben: {target}")

    # Read back: the file, not the terminal output, is what gets signed.
    written = target.read_text(encoding="utf-8").splitlines()
    if len(written) != len(names):
        print(f"FEHLER: {target} hat {len(written)} Zeilen, erwartet {len(names)}.")
        return 1
    print("Kontrolle: alle drei Zeilen stehen in der Datei.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
