"""Tests for scripts/sign_sums.py failure, --require-signature, and CLI output paths (T11)."""

from __future__ import annotations

import subprocess
from pathlib import Path

from scripts import sign_sums

FPR = "AD927E805BE3B440BD676872F350D77C8D498335"


def test_failed_verify_deletes_unverifiable_asc_and_returns_1(
    tmp_path: Path, monkeypatch, capsys
):
    sums = tmp_path / "SHA256SUMS-1.0.0.txt"
    sums.write_text("0" * 64 + "  Malaz-1.0.0.zip  (1 Bytes)\n", encoding="utf-8")
    asc = tmp_path / "SHA256SUMS-1.0.0.txt.asc"

    monkeypatch.setattr(sign_sums, "find_gpg", lambda: Path("C:/fake/gpg.exe"))
    monkeypatch.setattr(sign_sums, "secret_keys", lambda _gpg: [FPR])

    def fake_run(cmd, **_kwargs):
        if "--detach-sign" in cmd:
            asc.write_text("-----BEGIN PGP SIGNATURE-----\ncorrupt\n", encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if "--verify" in cmd:
            return subprocess.CompletedProcess(cmd, 1, "", "gpg: BAD signature")
        raise AssertionError(f"Unexpected command: {cmd}")

    monkeypatch.setattr(sign_sums.subprocess, "run", fake_run)
    rc = sign_sums.main(["--sums", str(sums)])
    assert rc == 1
    assert not asc.exists()
    assert "ERROR: Signature verification failed." in capsys.readouterr().out


def test_require_signature_fails_closed_without_gpg_or_secret_key(
    tmp_path: Path, monkeypatch, capsys
):
    sums = tmp_path / "SHA256SUMS-1.0.0.txt"
    sums.write_text("0" * 64 + "  Malaz-1.0.0.zip  (1 Bytes)\n", encoding="utf-8")

    monkeypatch.setattr(sign_sums, "find_gpg", lambda: None)
    assert sign_sums.main(["--sums", str(sums)]) == 0
    assert "gpg executable not found" in capsys.readouterr().out
    assert sign_sums.main(["--sums", str(sums), "--require-signature"]) == 1
    capsys.readouterr()

    monkeypatch.setattr(sign_sums, "find_gpg", lambda: Path("C:/fake/gpg.exe"))
    monkeypatch.setattr(sign_sums, "secret_keys", lambda _gpg: [])
    assert sign_sums.main(["--sums", str(sums)]) == 0
    assert "No secret GPG key found in keyring." in capsys.readouterr().out
    assert sign_sums.main(["--sums", str(sums), "--require-signature"]) == 1


def test_missing_sums_ambiguous_keys_and_verified_success(
    tmp_path: Path, monkeypatch, capsys
):
    missing = tmp_path / "SHA256SUMS-missing.txt"
    assert sign_sums.main(["--sums", str(missing)]) == 2
    assert "does not exist." in capsys.readouterr().out

    sums = tmp_path / "SHA256SUMS-1.0.0.txt"
    sums.write_text("0" * 64 + "  Malaz-1.0.0.zip  (1 Bytes)\n", encoding="utf-8")
    asc = tmp_path / "SHA256SUMS-1.0.0.txt.asc"

    monkeypatch.setattr(sign_sums, "find_gpg", lambda: Path("C:/fake/gpg.exe"))
    monkeypatch.setattr(sign_sums, "secret_keys", lambda _gpg: [FPR, "B" * 40])
    assert sign_sums.main(["--sums", str(sums)]) == 2
    assert "--key is required." in capsys.readouterr().out

    def fake_ok(cmd, **_kwargs):
        if "--detach-sign" in cmd:
            asc.write_text("-----BEGIN PGP SIGNATURE-----\nok\n", encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(sign_sums.subprocess, "run", fake_ok)
    assert sign_sums.main(["--sums", str(sums), "--key", FPR]) == 0
    assert f"Signed and verified: {asc.name} (key {FPR})" in capsys.readouterr().out
