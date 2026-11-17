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
