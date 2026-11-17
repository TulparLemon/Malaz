"""Create the release signing key with YOUR passphrase.

Run this yourself, in a terminal on the build machine. The passphrase is read
with getpass (no echo), written to a temporary file only for the duration of
the gpg call, and deleted afterwards. It never appears in argv - a command line
is readable by every process on the machine - and never in this repository.

    python scripts/new_release_key.py

What it does:
  1. generates an ed25519 signing key with your passphrase
  2. proves the key is protected: a signature WITHOUT the passphrase must fail
  3. exports the public key to docs/RELEASE-SIGNING-KEY.asc
  4. updates the fingerprint in docs/VERIFYING_RELEASES.md and scripts/backup_key.py
  5. offers to delete the previous key

The old key signed nothing that was published, so replacing it costs nothing.
"""
from __future__ import annotations

import getpass
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

GPG_CANDIDATES = (
    r"C:\Program Files\GnuPG\bin\gpg.exe",
    r"C:\Program Files (x86)\GnuPG\bin\gpg.exe",
)
REPO = Path(__file__).resolve().parents[1]
UID = "Malaz Release Signing <release@malaz.local>"
OLD_FINGERPRINT = "11F51D1BEE30EAA3C88AE01B36F1852E0ADE4A08"
MIN_LENGTH = 12


def find_gpg() -> Path:
    for candidate in GPG_CANDIDATES:
        path = Path(candidate)
        if path.is_file():
            return path
    raise SystemExit(
        "gpg nicht gefunden. Erwartet unter:\n  " + "\n  ".join(GPG_CANDIDATES)
    )


def run(gpg: Path, args: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(gpg), *args], capture_output=True, text=True,
        encoding="utf-8", errors="replace", **kwargs,
    )


def secret_keys(gpg: Path) -> list[tuple[str, str]]:
    """``(fingerprint, uid)`` for every secret key in the ring."""
    proc = run(gpg, ["--list-secret-keys", "--with-colons"])
    keys: list[tuple[str, str]] = []
    fingerprint = ""
    for line in proc.stdout.splitlines():
        if line.startswith("fpr:"):
            fingerprint = line.split(":")[9]
        elif line.startswith("uid:") and fingerprint:
            keys.append((fingerprint, line.split(":")[9]))
            fingerprint = ""
    return keys


def ask_passphrase() -> str:
    while True:
        first = getpass.getpass("Neue Passphrase (keine Anzeige): ")
        if len(first) < MIN_LENGTH:
            print(f"Zu kurz - mindestens {MIN_LENGTH} Zeichen.")
            continue
        second = getpass.getpass("Wiederholen: ")
        if first != second:
            print("Die Eingaben stimmen nicht ueberein.")
            continue
        return first


def generate(gpg: Path, passphrase: str, before: set[str]) -> str:
    """Create the key, return the fingerprint that was NOT there before.

    Matching on the UID would return the OLD key: both carry
    "Malaz Release Signing <release@malaz.local>", and the loop would stop at
    the first hit. The difference between the key sets is the only reliable
    answer.
    """
    # The passphrase goes through stdin, never a temp file: a file on disk is
    # readable by anything on the machine and survives a crash, which is
    # exactly the leak this script exists to avoid.
    proc = run(
        gpg,
        [
            "--batch", "--yes", "--pinentry-mode", "loopback",
            "--passphrase-fd", "0",
            "--quick-gen-key", UID, "ed25519", "sign", "never",
        ],
        input=passphrase + "\n",
    )
    if proc.returncode != 0:
        raise SystemExit(f"Schluesselerzeugung fehlgeschlagen:\n{proc.stderr}")

    after = {fingerprint for fingerprint, _uid in secret_keys(gpg)}
    created = after - before
    if len(created) != 1:
        raise SystemExit(
            f"Erwartet genau einen neuen Schluessel, gefunden: {len(created)} "
            f"({', '.join(sorted(created)) or 'keiner'})"
        )
    return created.pop()


def clear_agent_cache(gpg: Path) -> None:
    """Drop the cached passphrase before claiming anything about protection.

    Generation runs with --pinentry-mode loopback, which caches the passphrase
    in gpg-agent. A probe right after would sign successfully and the script
    would reject a perfectly good key. Measured earlier: the cache made a
    passphrase-less run succeed and the conclusion "no passphrase" was wrong
    until the agent was killed.
    """
    gpgconf = gpg.with_name("gpgconf.exe")
    if gpgconf.is_file():
        subprocess.run([str(gpgconf), "--kill", "gpg-agent"],
                       capture_output=True, timeout=60)


def prove_protected(gpg: Path, fingerprint: str) -> bool:
    """A signature without the passphrase must fail."""
    handle, name = tempfile.mkstemp(suffix=".txt")
    os.close(handle)  # mkstemp leaves the descriptor open; Windows then
                      # refuses the unlink below (measured WinError 32).
    probe = Path(name)
    try:
        probe.write_text("probe", encoding="ascii")
        proc = run(gpg, [
            "--batch", "--pinentry-mode", "error", "--detach-sign",
            "-u", fingerprint, "--output", "NUL", str(probe),
        ])
        return proc.returncode != 0
    finally:
        probe.unlink(missing_ok=True)


def export_public(gpg: Path, fingerprint: str) -> Path:
    proc = run(gpg, ["--armor", "--export", fingerprint])
    if proc.returncode != 0 or not proc.stdout:
        raise SystemExit(f"Export fehlgeschlagen:\n{proc.stderr}")
    target = REPO / "docs" / "RELEASE-SIGNING-KEY.asc"
    # Write bytes, not through a shell redirect: PowerShell would mangle the
    # armour (measured: "partial length invalid for packet type").
    target.write_bytes(proc.stdout.encode("utf-8"))
    return target


def update_references(old: str, new: str, pretty_new: str) -> list[Path]:
    """Replace the pinned fingerprint in the docs and the backup script."""
    changed: list[Path] = []
    # new_release_key.py itself carries OLD_FINGERPRINT. Without it the next
    # rotation would update the docs but leave this constant on the previous
    # key, so the "--key ..." line in docs/VERIFYING_RELEASES.md would point at the old one.
    for rel in (
        "docs/VERIFYING_RELEASES.md",
        "scripts/backup_key.py",
        "scripts/new_release_key.py",
    ):
        path = REPO / rel
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        original = text
        text = text.replace(old, new)
        text = re.sub(
            r"Fingerprint: [0-9A-F ]+",
            f"Fingerprint: {pretty_new}",
            text,
        )
        if text != original:
            path.write_text(text, encoding="utf-8")
            changed.append(path)
    return changed


def main() -> int:
    gpg = find_gpg()
    print(f"gpg: {gpg}")

    existing = secret_keys(gpg)
    if existing:
        print("\nVorhandene geheime Schluessel:")
        for fingerprint, uid in existing:
            print(f"  {fingerprint}  {uid}")
        print("\nDer neue Schluessel kommt hinzu; der alte wird am Ende angeboten.")

    print("\nDie Passphrase wird nicht angezeigt und nicht gespeichert.")
    passphrase = ask_passphrase()

    before = {fingerprint for fingerprint, _uid in existing}
    print("\nErzeuge Schluessel ...")
    fingerprint = generate(gpg, passphrase, before)
    print(f"Fingerprint: {fingerprint}")

    clear_agent_cache(gpg)
    if not prove_protected(gpg, fingerprint):
        raise SystemExit(
            "FEHLER: Signieren ohne Passphrase gelingt - der Schluessel ist "
            "ungeschuetzt. Nicht verwenden."
        )
    print("Schutz geprueft: Signieren ohne Passphrase scheitert.")

    key_file = export_public(gpg, fingerprint)
    print(f"Oeffentlicher Schluessel: {key_file.relative_to(REPO)}")

    # The old signature belongs to the OLD key. Once the public key file is
    # replaced and the old key is deleted, nobody can verify it any more
    # ("No public key"), and it would ship next to the new checksums. Remove
    # it here so the next signing step cannot leave a dead signature behind.
    stale = sorted((REPO / "dist").glob("SHA256SUMS-*.txt.asc"))
    for path in stale:
        path.unlink(missing_ok=True)
        print(f"Alte Signatur entfernt: dist/{path.name}")

    pretty = " ".join(
        fingerprint[i:i + 4] for i in range(0, len(fingerprint), 4)
    )
    for path in update_references(OLD_FINGERPRINT, fingerprint, pretty):
        print(f"Aktualisiert: {path.relative_to(REPO)}")

    print("\n--- Naechste Schritte ---")
    print("1. Schluessel sichern (Passphrase der Sicherung waehlen):")
    print("     python scripts/backup_key.py")
    print("2. Die Passphrase in einen Passwortmanager legen.")
    print("3. `git diff` pruefen, committen, Tag neu setzen, Source-Zip neu,")
    print("   Pruefsummen neu - ERST DANN signieren, sonst deckt die Signatur")
    print("   veraltete Hashes:")
    print("     python scripts/sign_sums.py --sums dist/SHA256SUMS-1.0.0.txt \\")
    print(f"         --key {fingerprint}")

    if existing:
        print("\nAlten Schluessel loeschen?")
        for old_fingerprint, uid in existing:
            if old_fingerprint == fingerprint:
                continue
            answer = input(f"  {old_fingerprint} ({uid}) [j/N] ").strip().lower()
            if answer != "j":
                continue
            proc = run(gpg, [
                "--batch", "--yes", "--delete-secret-and-public-key",
                old_fingerprint,
            ])
            if proc.returncode == 0:
                print(f"  geloescht: {old_fingerprint}")
            else:
                print(f"  nicht geloescht: {proc.stderr.strip()[:200]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
