"""Export the secret signing key, encrypted, for offline storage.

A release key that exists only on one machine is a single point of failure:
lose the machine and no past or future release can be verified against the
same identity. The export is passphrase-protected and must be stored offline -
never in the repository, never in a cloud folder that syncs the project.
"""

from __future__ import annotations

import argparse
import getpass
import subprocess
from pathlib import Path

GPG_EXE = r"C:\Program Files\GnuPG\bin\gpg.exe"
RELEASE_FINGERPRINT = "11F51D1BEE30EAA3C88AE01B36F1852E0ADE4A08"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path.home() / "malaz-release-key-SECRET.asc.gpg",
        help="Zielpfad ausserhalb des Repositorys (niemals im Projektordner)",
    )
    parser.add_argument("--gpg", default=GPG_EXE, help="Pfad zu gpg.exe")
    parser.add_argument("--key", default=RELEASE_FINGERPRINT, help="Fingerprint des Schluessels")
    args = parser.parse_args(argv)

    out = args.output.resolve()
    repo_root = Path(__file__).resolve().parent.parent
    try:
        out.relative_to(repo_root)
    except ValueError:
        pass
    else:
        raise SystemExit("Zielpfad liegt innerhalb des Repositorys - abgebrochen.")

    pw = getpass.getpass("Passphrase fuer die Sicherung: ")
    if len(pw) < 12:
        raise SystemExit("Zu kurz - mindestens 12 Zeichen.")

    # The passphrase travels through stdin, never argv: a command line is visible
    # to every process on the machine (WMI Win32_Process, Process Explorer).
    proc = subprocess.run(
        [
            args.gpg,
            "--batch",
            "--yes",
            "--pinentry-mode",
            "loopback",
            "--passphrase-fd",
            "0",
            "--armor",
            "--symmetric",
            "--output",
            str(out),
            "--export-secret-keys",
            args.key,
        ],
        input=pw + "\n",
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
        check=False,
    )
    if proc.returncode != 0:
        raise SystemExit(f"Export fehlgeschlagen: {proc.stderr[:300]}")
    print(f"Sicherung: {out}  ({out.stat().st_size} Bytes)")
    print("Diese Datei gehoert NICHT ins Repository und NICHT in ein Cloud-Sync.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
