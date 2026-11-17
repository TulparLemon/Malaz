"""Tests for scripts/sign_sums.py failure & --require-signature paths (T11)."""

from __future__ import annotations

import subprocess
from pathlib import Path

from scripts import sign_sums


def test_failed_verify_deletes_unverifiable_asc_and_returns_1(tmp_path: Path, monkeypatch):
    sums = tmp_path / "SHA256SUMS-1.0.0.txt"
    sums.write_text("0" * 64 + "  Malaz-1.0.0.zip  (1 Bytes)\n", encoding="utf-8")
    asc = tmp_path / "SHA256SUMS-1.0.0.txt.asc"

    monkeypatch.setattr(sign_sums, "find_gpg", lambda: Path("C:/fake/gpg.exe"))
    monkeypatch.setattr(
        sign_sums,
        "secret_keys",
        lambda _gpg: ["11F51D1BEE30EAA3C88AE01B36F1852E0ADE4A08"],
    )

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


def test_require_signature_fails_closed_without_gpg_or_secret_key(tmp_path: Path, monkeypatch):
    sums = tmp_path / "SHA256SUMS-1.0.0.txt"
    sums.write_text("0" * 64 + "  Malaz-1.0.0.zip  (1 Bytes)\n", encoding="utf-8")

    monkeypatch.setattr(sign_sums, "find_gpg", lambda: None)
    assert sign_sums.main(["--sums", str(sums)]) == 0
    assert sign_sums.main(["--sums", str(sums), "--require-signature"]) == 1

    monkeypatch.setattr(sign_sums, "find_gpg", lambda: Path("C:/fake/gpg.exe"))
    monkeypatch.setattr(sign_sums, "secret_keys", lambda _gpg: [])
    assert sign_sums.main(["--sums", str(sums)]) == 0
    assert sign_sums.main(["--sums", str(sums), "--require-signature"]) == 1
