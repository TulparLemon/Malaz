"""Verify a downloaded or assembled Malaz release directory before/after signing."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

_SCRIPTS_DIR = str(Path(__file__).resolve().parent)
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)
import sign_sums  # noqa: E402
import write_checksums  # noqa: E402

EXPECTED_SIGNING_FPR = "AD927E805BE3B440BD676872F350D77C8D498335"
_SUMS_NAME_RE = re.compile(r"^SHA256SUMS-(\d+\.\d+\.\d+)\.txt$")


def verify_directory(directory: Path) -> int:
    if not directory.is_dir():
        print(f"FEHLER: Ordner existiert nicht: {directory}")
        return 2

    sums_files = [p for p in directory.iterdir() if p.is_file() and _SUMS_NAME_RE.match(p.name)]
    if len(sums_files) != 1:
        print(f"FEHLER: Erwartet genau eine SHA256SUMS-<ver>.txt in {directory}, gefunden: {len(sums_files)}")
        return 2

    sums_path = sums_files[0]
    match = _SUMS_NAME_RE.match(sums_path.name)
    assert match is not None
    version = match.group(1)

    try:
        entries = write_checksums.parse_sums(sums_path)
    except ValueError as exc:
        print(f"FEHLER: {exc}")
        return 1

    expected_assets = set(write_checksums.release_assets(version))
    if set(entries) != expected_assets:
        print(
            f"FEHLER: Asset-Menge in {sums_path.name} stimmt nicht. "
            f"Erwartet: {sorted(expected_assets)}, gefunden: {sorted(entries)}"
        )
        return 1

    allowed_extra = {
        sums_path.name,
        f"{sums_path.name}.asc",
        "RELEASE-SIGNING-KEY.asc",
    }
    for item in sorted(directory.iterdir()):
        if not item.is_file():
            print(f"FEHLER: Unerwarteter Unterordner oder Sonderpfad: {item.name}")
            return 1
        if item.name not in entries and item.name not in allowed_extra:
            print(f"FEHLER: Fremddatei im Release-Ordner: {item.name}")
            return 1

    for name, (expected_hash, expected_size) in entries.items():
        asset = directory / name
        if not asset.is_file():
            print(f"FEHLER: Gelistetes Asset fehlt: {name}")
            return 1
        actual_hash, actual_size = write_checksums.sha256(asset)
        if actual_size != expected_size or actual_hash != expected_hash:
            print(
                f"FEHLER: Hash/Groesse weicht ab fuer {name}: "
                f"erwartet {expected_hash} ({expected_size} B), "
                f"ist {actual_hash} ({actual_size} B)"
            )
            return 1

    asc_path = directory / f"{sums_path.name}.asc"
    if not asc_path.is_file():
        print("UNSIGNIERT: Alle 4 Assets und Hashes stimmen, aber .asc fehlt noch.")
        return 3

    gpg = sign_sums.find_gpg()
    if gpg is None:
        print("SIGNATUR NICHT GEPRUEFT (gpg fehlt)")
        return 3

    proc = subprocess.run(
        [str(gpg), "--status-fd", "1", "--verify", str(asc_path), str(sums_path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    validsig = any(
        line.split()[:3] == ["[GNUPG:]", "VALIDSIG", EXPECTED_SIGNING_FPR]
        for line in proc.stdout.splitlines()
    )
    if proc.returncode != 0 or not validsig:
        print(
            f"FEHLER: Ungueltige GPG-Signatur oder falscher Schluessel-Fingerprint "
            f"(erwartet {EXPECTED_SIGNING_FPR}).\n{proc.stderr.strip()}"
        )
        return 1

    print(
        f"OK: Release-Set {version} vollstaendig, Hashes und Signatur ({EXPECTED_SIGNING_FPR}) verifiziert."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("directory", type=Path, help="Ordner mit Release-Assets")
    args = ap.parse_args(argv)
    return verify_directory(args.directory)


if __name__ == "__main__":
    raise SystemExit(main())
