"""Sign the built Malaz.exe, if a certificate is configured.

Ordering matters and is the whole point of this script: sign BEFORE zipping.
A signature covers the file bytes, so signing afterwards leaves the ZIP with
an unsigned EXE (docs/INSTALLATION.md). Once a build is signed, the ZIP and
SHA256SUMS must be regenerated and the tag moved - this script says so
instead of leaving it to memory.

No certificate is configured today, so the script explains what is missing
and exits 0. It never invents a signature and never touches a build that is
already signed.

Environment:
  MALAZ_SIGN_PFX        path to a .pfx (classic certificate)
  MALAZ_SIGN_PASSWORD   its password (never commit it)
  MALAZ_SIGN_THUMBPRINT thumbprint for a certificate in the store
  MALAZ_SIGNTOOL        path to signtool.exe (default: look on PATH)

Usage:
  python scripts/sign_release.py --exe dist/Malaz-1.0.0/Malaz.exe
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
from pathlib import Path

TIMESTAMP_URL = "https://timestamp.digicert.com"


def find_signtool() -> Path | None:
    override = os.environ.get("MALAZ_SIGNTOOL")
    if override:
        p = Path(override)
        return p if p.is_file() else None
    found = shutil.which("signtool")
    return Path(found) if found else None


def already_signed(signtool: Path, exe: Path) -> bool:
    proc = subprocess.run(
        [str(signtool), "verify", "/pa", "/q", str(exe)],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    return proc.returncode == 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--exe", required=True, type=Path)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    exe: Path = args.exe
    if not exe.is_file():
        print(f"FEHLER: {exe} existiert nicht.")
        return 2

    signtool = find_signtool()
    if signtool is None:
        print("Kein signtool.exe gefunden (PATH oder MALAZ_SIGNTOOL).")
        print("Bezugsquelle: NuGet Microsoft.Windows.SDK.BuildTools.")
        return 0

    if already_signed(signtool, exe):
        print(f"Bereits signiert: {exe}")
        return 0

    pfx = os.environ.get("MALAZ_SIGN_PFX")
    password = os.environ.get("MALAZ_SIGN_PASSWORD")
    thumbprint = os.environ.get("MALAZ_SIGN_THUMBPRINT")

    if not pfx and not thumbprint:
        print("Nicht signiert: kein Zertifikat konfiguriert.")
        print("  MALAZ_SIGN_PFX + MALAZ_SIGN_PASSWORD  (klassisches Zertifikat)")
        print("  MALAZ_SIGN_THUMBPRINT                 (Zertifikat im Store)")
        print("  oder Azure Artifact Signing (frueher Trusted Signing),")
        print("  Microsofts empfohlener Weg: ab 9,99 $/Monat, kein Token.")
        print()
        print("Reihenfolge nach dem Signieren: ZIP neu bauen, SHA256SUMS neu,")
        print("Release-Gates erneut, Tag verschieben.")
        return 0

    cmd = [str(signtool), "sign", "/fd", "SHA256", "/tr", TIMESTAMP_URL,
           "/td", "SHA256"]
    if pfx:
        cmd += ["/f", pfx]
        if password:
            cmd += ["/p", password]
    else:
        cmd += ["/sha1", thumbprint or ""]
    cmd.append(str(exe))

    if args.dry_run:
        shown = [c if c != password else "***" for c in cmd]
        print("DRY-RUN:", " ".join(shown))
        return 0

    proc = subprocess.run(cmd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    print(proc.stdout.strip() or proc.stderr.strip())
    if proc.returncode != 0:
        print(f"FEHLER: signtool meldet Returncode {proc.returncode}.")
        return 1

    if not already_signed(signtool, exe):
        print("FEHLER: signtool meldet Erfolg, die Pruefung schlaegt fehl.")
        return 1

    print(f"Signiert und verifiziert: {exe}")
    print("Jetzt: ZIP neu bauen, SHA256SUMS neu, Gates erneut, Tag verschieben.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
