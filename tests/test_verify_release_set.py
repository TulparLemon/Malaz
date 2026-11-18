"""Tests for scripts/verify_release_set.py (T10)."""

from __future__ import annotations

import subprocess
from pathlib import Path

from scripts import verify_release_set, write_checksums

FPR = verify_release_set.EXPECTED_SIGNING_FPR


def _populate_valid_set(folder: Path, ver: str = "1.0.0") -> Path:
    names = write_checksums.release_assets(ver)
    for idx, name in enumerate(names, 1):
        (folder / name).write_bytes(f"asset-{idx}".encode())
    return write_checksums.write_sums(folder, ver, names)


def test_unsigned_valid_set_returns_3_and_tampered_before_sign_returns_1(
    tmp_path: Path,
):
    _populate_valid_set(tmp_path)
    assert verify_release_set.main([str(tmp_path)]) == 3

    (tmp_path / "Malaz-1.0.0.zip").write_bytes(b"corrupted")
    assert verify_release_set.main([str(tmp_path)]) == 1


def test_signed_valid_set_checks_exact_fingerprint_and_extras(tmp_path: Path, monkeypatch):
    sums = _populate_valid_set(tmp_path)
    asc = tmp_path / f"{sums.name}.asc"
    asc.write_text("-----BEGIN PGP SIGNATURE-----\n", encoding="utf-8")
    (tmp_path / "RELEASE-SIGNING-KEY.asc").write_text("pubkey\n", encoding="utf-8")

    monkeypatch.setattr(verify_release_set.sign_sums, "find_gpg", lambda: None)
    assert verify_release_set.main([str(tmp_path)]) == 3

    monkeypatch.setattr(verify_release_set.sign_sums, "find_gpg", lambda: Path("C:/fake/gpg.exe"))

    wrong = "0" * 40
    monkeypatch.setattr(
        verify_release_set.subprocess,
        "run",
        lambda cmd, **kw: subprocess.CompletedProcess(
            cmd,
            0,
            f"[GNUPG:] VALIDSIG {wrong} 2026-11-17 1700000000 0 4 0 22 8 00 {wrong}\n",
            "",
        ),
    )
    assert verify_release_set.main([str(tmp_path)]) == 1

    monkeypatch.setattr(
        verify_release_set.subprocess,
        "run",
        lambda cmd, **kw: subprocess.CompletedProcess(
            cmd,
            0,
            f"[GNUPG:] VALIDSIG {FPR} 2026-11-17 1700000000 0 4 0 22 8 00 {FPR}\n",
            "",
        ),
    )
    assert verify_release_set.main([str(tmp_path)]) == 0

    (tmp_path / "stray.txt").write_text("oops", encoding="utf-8")
    assert verify_release_set.main([str(tmp_path)]) == 1
    (tmp_path / "stray.txt").unlink()

    (tmp_path / "sbom.json").unlink()
    write_checksums.write_sums(
        tmp_path,
        "1.0.0",
        ["Malaz-1.0.0.zip", "Malaz-1.0.0-source.zip", "Malaz-1.0.0-licenses.zip"],
    )
    assert verify_release_set.main([str(tmp_path)]) == 1


def test_release_signing_key_fingerprint_synced_across_repo():
    """Verify docs/RELEASE-SIGNING-KEY.asc RFC 4880 v4 fingerprint matches all pinned docs/scripts."""
    import base64
    import hashlib

    from scripts import backup_key, new_release_key

    repo_root = Path(__file__).resolve().parents[1]
    armor_lines = (repo_root / "docs" / "RELEASE-SIGNING-KEY.asc").read_text(encoding="utf-8").splitlines()
    b64_body = "".join(
        line.strip()
        for line in armor_lines
        if line.strip() and not line.startswith("-----") and not line.startswith("=")
    )
    raw = base64.b64decode(b64_body)
    # RFC 4880 §4.2: Tag 6 Public-Key Packet (old-format 0x98 or new-format 0xC6, 1-byte length)
    assert raw[0] in (0x98, 0xC6), f"Unexpected OpenPGP packet header: {raw[0]:#x}"
    pkt_len = raw[1]
    pkt_body = raw[2 : 2 + pkt_len]
    assert len(pkt_body) == pkt_len and pkt_body[0] == 4, "Expected v4 OpenPGP public key packet"
    computed_fpr = hashlib.sha1(b"\x99" + pkt_len.to_bytes(2, "big") + pkt_body).hexdigest().upper()

    expected = verify_release_set.EXPECTED_SIGNING_FPR
    pretty = new_release_key.format_pretty(expected)
    assert computed_fpr == expected
    assert expected == backup_key.RELEASE_FINGERPRINT
    assert expected == new_release_key.OLD_FINGERPRINT
    assert pretty in (repo_root / "SECURITY.md").read_text(encoding="utf-8")
    assert (repo_root / "docs" / "VERIFYING_RELEASES.md").read_text(encoding="utf-8").count(pretty) == 2
    assert expected in (repo_root / "docs" / "RELEASING.md").read_text(encoding="utf-8")
