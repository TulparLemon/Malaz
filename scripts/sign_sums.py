"""Detached GPG signature for the release checksum file.

This is the route open-source Windows projects take when they have no
Authenticode certificate: the binary stays unsigned (SmartScreen will warn),
but the download is verifiable - a signature over SHA256SUMS proves the file
came from the project and was not swapped.

Signing the CHECKSUM file, not each artifact, is deliberate: one signature
covers every download listed in it, and the verification step is short enough
to put in a README.

Usage:
  python scripts/sign_sums.py --sums dist/SHA256SUMS-1.0.0.txt

Requires a secret key in the local keyring. Without one the script explains
how to create it and exits 0 - it never invents a signature.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
from pathlib import Path

CANDIDATES = (
    r"C:\Program Files\GnuPG\bin\gpg.exe",
    r"C:\Malaz\tools\Git\usr\bin\gpg.exe",
)


def find_gpg() -> Path | None:
    for c in CANDIDATES:
        p = Path(c)
        if p.is_file():
            return p
    found = shutil.which("gpg")
    return Path(found) if found else None


def secret_keys(gpg: Path) -> list[str]:
    proc = subprocess.run(
        [str(gpg), "--list-secret-keys", "--with-colons"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    keys = []
    for line in proc.stdout.splitlines():
        if line.startswith("fpr:"):
            keys.append(line.split(":")[9])
    return keys


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sums", required=True, type=Path)
    ap.add_argument("--key", help="Signaturschlüssel (Fingerprint oder UID)")
    ap.add_argument("--require-signature", action="store_true", help="Exit 1 statt 0 wenn gpg/Key fehlt")
    args = ap.parse_args(argv)

    sums: Path = args.sums
    if not sums.is_file():
        print(f"FEHLER: {sums} existiert nicht.")
        return 2

    gpg = find_gpg()
    if gpg is None:
        print("Kein gpg gefunden (PATH oder Git-Installation).")
        return 1 if args.require_signature else 0

    keys = secret_keys(gpg)
    if not keys:
        print("Kein geheimer GPG-Schlüssel im Keyring.")
        print("Anlegen (einmalig). Die Passphrase steht in einer Datei, NICHT")
        print("als --passphrase \"\": das legt einen SCHUTZLOSEN Schluessel an,")
        print("und jede damit erzeugte Signatur kann jeder nachbauen.")
        print("In einer SSH-Sitzung kann pinentry kein Fenster oeffnen - deshalb")
        print("--pinentry-mode loopback, sonst haengt der Aufruf bis zum Timeout.")
        print('  gpg --batch --pinentry-mode loopback --passphrase-file <datei> \\')
        print('      --quick-gen-key "Malaz Release Signing <release@malaz.local>" \\')
        print('      ed25519 sign never')
        print("Danach pruefen, dass der Schluessel WIRKLICH geschuetzt ist:")
        print('  gpg --batch --pinentry-mode error --detach-sign -u <fpr> \\')
        print('      --output NUL <irgendeine-datei>')
        print("  -> scheitert mit \"can't get input\"; gelingt es, fehlt die Passphrase.")
        print("Danach den öffentlichen Schlüssel veröffentlichen:")
        print("  gpg --armor --export <Fingerprint> > docs/RELEASE-SIGNING-KEY.asc")
        print("und in die README aufnehmen.")
        return 1 if args.require_signature else 0

    # NEVER fall back to "the first key in the ring": on a machine with more
    # than one secret key that signs a release with the wrong identity and
    # still reports success. Measured here: a test key and the release key
    # coexist, and keys[0] would have picked the test key.
    if args.key:
        key = args.key
    elif len(keys) == 1:
        key = keys[0]
    else:
        print(f"FEHLER: {len(keys)} geheime Schluessel im Keyring - --key ist Pflicht.")
        for k in keys:
            print(f"  {k}")
        return 2
    out = sums.with_suffix(sums.suffix + ".asc")
    # The passphrase travels through the environment, never argv: a command
    # line is visible to every process on the machine (WMI Win32_Process,
    # Process Explorer). --pinentry-mode loopback is required because a SSH
    # session has no window for pinentry to open - without it gpg blocks until
    # it times out (measured: "signing failed: Timeout").
    passphrase = os.environ.get("MALAZ_GPG_PASSPHRASE")
    cmd = [str(gpg), "--batch", "--yes", "--pinentry-mode", "loopback",
           "--armor", "--detach-sign", "--local-user", key,
           "--output", str(out)]
    if passphrase is not None:
        cmd += ["--passphrase-fd", "0"]
    cmd.append(str(sums))

    # A failed run leaves the PREVIOUS signature in place, so a stale .asc
    # over the old checksums would survive next to the new SHA256SUMS - and a
    # later upload would ship a signature that cannot verify. Measured: a
    # "signing failed: Timeout" left the old file untouched.
    out.unlink(missing_ok=True)

    proc = subprocess.run(
        cmd,
        input=(passphrase + "\n") if passphrase is not None else None,
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    if proc.returncode != 0:
        # gpg creates the output file before it fails, so an empty .asc would
        # sit next to the checksums and look like a signature. Remove it.
        out.unlink(missing_ok=True)
        print(proc.stderr.strip())
        print(f"FEHLER: gpg meldet Returncode {proc.returncode}.")
        return 1

    verify = subprocess.run(
        [str(gpg), "--verify", str(out), str(sums)],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    if verify.returncode != 0:
        out.unlink(missing_ok=True)
        print(f"FEHLER: Signatur nicht verifizierbar.\n{verify.stderr.strip()}")
        return 1

    if passphrase is None:
        print("Hinweis: MALAZ_GPG_PASSPHRASE war nicht gesetzt.")
    print(f"Signiert und verifiziert: {out.name} (Schlüssel {key})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
