"""Write and parse SHA256SUMS-<version>.txt manifests for Malaz releases.

Run this AFTER all release archives are finalized and BEFORE signing: the
OpenPGP signature covers this manifest, so it must never be rewritten after
signing.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from collections.abc import Sequence
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DIST = REPO / "dist"
_SUMS_LINE_RE = re.compile(r"^([0-9A-F]{64})  (\S+)  \((\d+) Bytes\)$")


def sha256(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest().upper(), path.stat().st_size


def release_assets(version: str) -> list[str]:
    """Canonical asset list for a complete Malaz release directory."""
    return [
        f"Malaz-{version}.zip",
        f"Malaz-{version}-source.zip",
        f"Malaz-{version}-licenses.zip",
        "sbom.json",
    ]


def write_sums(directory: Path, version: str, names: Sequence[str]) -> Path:
    """Compute SHA-256 + byte lengths for ``names`` in ``directory`` and write manifest."""
    if not names:
        raise ValueError("names must not be empty")
    lines: list[str] = []
    for name in names:
        asset = directory / name
        if not asset.is_file():
            raise FileNotFoundError(f"Missing release asset: {asset}")
        digest, size = sha256(asset)
        line = f"{digest}  {name}  ({size} Bytes)"
        lines.append(line)
        print(line)

    target = directory / f"SHA256SUMS-{version}.txt"
    with target.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines) + "\n")
    print(f"\nGeschrieben: {target}")

    written = target.read_text(encoding="utf-8").splitlines()
    if len(written) != len(names):
        raise RuntimeError(f"{target} hat {len(written)} Zeilen, erwartet {len(names)}.")
    return target


def parse_sums(path: Path) -> dict[str, tuple[str, int]]:
    """Parse ``SHA256SUMS-<ver>.txt`` into ``{filename: (hex_sha256, size_bytes)}``."""
    entries: dict[str, tuple[str, int]] = {}
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        match = _SUMS_LINE_RE.fullmatch(raw)
        if match is None:
            raise ValueError(f"Ungueltige Zeile {lineno} in {path.name}: {raw!r}")
        digest, name, size_str = match.groups()
        if "/" in name or "\\" in name or name in {".", ".."}:
            raise ValueError(f"Unsicherer Dateiname in Zeile {lineno}: {name!r}")
        if name in entries:
            raise ValueError(f"Doppelter Dateiname in Zeile {lineno}: {name!r}")
        entries[name] = (digest, int(size_str))
    if not entries:
        raise ValueError(f"Leere Pruefsummendatei: {path.name}")
    return entries


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--version", required=True, help="z. B. 1.0.0")
    ap.add_argument("--dist", type=Path, default=DIST)
    ap.add_argument(
        "--include-sbom",
        action="store_true",
        help="sbom.json als viertes Release-Asset aufnehmen",
    )
    args = ap.parse_args(argv)

    version = args.version
    names = (
        release_assets(version)
        if args.include_sbom
        else [
            f"Malaz-{version}.zip",
            f"Malaz-{version}-source.zip",
            f"Malaz-{version}-licenses.zip",
        ]
    )

    missing = [n for n in names if not (args.dist / n).is_file()]
    if missing:
        print("FEHLER: diese Archive fehlen:")
        for name in missing:
            print(f"  {args.dist / name}")
        return 2

    try:
        write_sums(args.dist, version, names)
    except Exception as exc:
        print(f"FEHLER: {exc}")
        return 1
    print(f"Kontrolle: alle {len(names)} Zeilen stehen in der Datei.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
