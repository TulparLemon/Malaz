"""Create the release signing key with YOUR passphrase.

Run this yourself, in a terminal on the build machine. The passphrase is read
with getpass (no echo) and piped to gpg over stdin (never written to disk). It
never appears in argv - a command line is readable by every process on the
machine - and never in this repository.

    python scripts/new_release_key.py

What it does:
  1. generates an ed25519 signing key with your passphrase
  2. proves the key is protected: a signature WITHOUT the passphrase must fail
  3. exports the public key to docs/RELEASE-SIGNING-KEY.asc
  4. updates the fingerprint in docs, scripts, and tests
  5. offers to delete the previous key
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
OLD_FINGERPRINT = "AD927E805BE3B440BD676872F350D77C8D498335"
MIN_LENGTH = 12


def find_gpg() -> Path:
    for candidate in GPG_CANDIDATES:
        path = Path(candidate)
        if path.is_file():
            return path
    raise SystemExit(
        "gpg executable not found. Expected at:\n  " + "\n  ".join(GPG_CANDIDATES)
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
        first = getpass.getpass("New passphrase (no echo): ")
        if len(first) < MIN_LENGTH:
            print(f"Too short: at least {MIN_LENGTH} characters required.")
            continue
        second = getpass.getpass("Repeat passphrase: ")
        if first != second:
            print("Passphrases do not match.")
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
        raise SystemExit(f"Key generation failed:\n{proc.stderr}")

    after = {fingerprint for fingerprint, _uid in secret_keys(gpg)}
    created = after - before
    if len(created) != 1:
        raise SystemExit(
            f"Expected exactly one new key, found: {len(created)} "
            f"({', '.join(sorted(created)) or 'none'})"
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
        raise SystemExit(f"Public key export failed:\n{proc.stderr}")
    target = REPO / "docs" / "RELEASE-SIGNING-KEY.asc"
    # Write bytes, not through a shell redirect: PowerShell would mangle the
    # armour (measured: "partial length invalid for packet type").
    target.write_bytes(proc.stdout.encode("utf-8"))
    return target


def format_pretty(fingerprint: str) -> str:
    """Format 40-hex OpenPGP v4 fingerprint in GnuPG 5+5 group layout."""
    groups = [fingerprint[i:i + 4] for i in range(0, len(fingerprint), 4)]
    return " ".join(groups[:5]) + "  " + " ".join(groups[5:])


def update_references(old: str, new: str, pretty_new: str) -> list[Path]:
    """Replace the pinned fingerprint across all docs, scripts, and tests."""
    changed: list[Path] = []
    pretty_old = format_pretty(old)
    for rel in (
        "SECURITY.md",
        "docs/RELEASING.md",
        "docs/VERIFYING_RELEASES.md",
        "scripts/backup_key.py",
        "scripts/new_release_key.py",
        "scripts/verify_release_set.py",
        "tests/test_sign_sums.py",
    ):
        path = REPO / rel
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        original = text
        text = text.replace(old, new).replace(pretty_old, pretty_new)
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
        print("\nExisting secret keys:")
        for fingerprint, uid in existing:
            print(f"  {fingerprint}  {uid}")
        print("\nThe new key will be added; you will be prompted before deleting old keys.")

    print("\nThe passphrase is neither echoed nor stored on disk.")
    passphrase = ask_passphrase()

    before = {fingerprint for fingerprint, _uid in existing}
    print("\nGenerating key ...")
    fingerprint = generate(gpg, passphrase, before)
    print(f"Fingerprint: {fingerprint}")

    clear_agent_cache(gpg)
    if not prove_protected(gpg, fingerprint):
        raise SystemExit(
            "ERROR: Signing succeeded without a passphrase; the key is "
            "unprotected. Do not use it."
        )
    print("Protection verified: signing without a passphrase fails.")

    key_file = export_public(gpg, fingerprint)
    print(f"Public key written: {key_file.relative_to(REPO)}")

    # The old signature belongs to the OLD key. Once the public key file is
    # replaced and the old key is deleted, nobody can verify it any more
    # ("No public key"), and it would ship next to the new checksums. Remove
    # it here so the next signing step cannot leave a dead signature behind.
    stale = sorted((REPO / "dist").glob("SHA256SUMS-*.txt.asc"))
    for path in stale:
        path.unlink(missing_ok=True)
        print(f"Removed stale signature: dist/{path.name}")

    pretty = format_pretty(fingerprint)
    for path in update_references(OLD_FINGERPRINT, fingerprint, pretty):
        print(f"Updated: {path.relative_to(REPO)}")

    print("\n--- Next steps ---")
    print("1. Back up the secret key (choose a backup encryption passphrase):")
    print("     python scripts/backup_key.py")
    print("2. Store the passphrase in a password manager.")
    print("3. Review `git diff`, commit, re-tag, rebuild source archive and")
    print("   checksums; sign ONLY AFTER checksums are final:")
    print("     python scripts/sign_sums.py --sums dist/SHA256SUMS-1.0.0.txt \\")
    print(f"         --key {fingerprint}")

    if existing:
        print("\nDelete previous secret key?")
        for old_fingerprint, uid in existing:
            if old_fingerprint == fingerprint:
                continue
            answer = input(f"  {old_fingerprint} ({uid}) [y/N] ").strip().lower()
            if answer not in ("y", "yes"):
                continue
            proc = run(gpg, [
                "--batch", "--yes", "--delete-secret-and-public-key",
                old_fingerprint,
            ])
            if proc.returncode == 0:
                print(f"  deleted: {old_fingerprint}")
            else:
                print(f"  not deleted: {proc.stderr.strip()[:200]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
