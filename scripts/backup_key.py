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
RELEASE_FINGERPRINT = "AD927E805BE3B440BD676872F350D77C8D498335"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path.home() / "malaz-release-key-SECRET.asc.gpg",
        help="Destination path outside the repository (never inside the project tree)",
    )
    parser.add_argument("--gpg", default=GPG_EXE, help="Path to gpg.exe")
    parser.add_argument("--key", default=RELEASE_FINGERPRINT, help="Signing key fingerprint")
    args = parser.parse_args(argv)

    out = args.output.resolve()
    repo_root = Path(__file__).resolve().parent.parent
    try:
        out.relative_to(repo_root)
    except ValueError:
        pass
    else:
        raise SystemExit("Destination path is inside the repository; aborted.")

    pw = getpass.getpass("Backup encryption passphrase: ")
    if len(pw) < 12:
        raise SystemExit("Too short: at least 12 characters required.")

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
        raise SystemExit(f"Export failed: {proc.stderr[:300]}")
    print(f"Backup written: {out}  ({out.stat().st_size} bytes)")
    print("Do NOT commit this file to the repository or place it in a cloud-synced folder.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
