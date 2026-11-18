"""Tests for scripts/verify_release_set.py, backup_key.py, and new_release_key.py (T10)."""

from __future__ import annotations

import builtins
import subprocess
import tempfile
from pathlib import Path

import pytest

from scripts import backup_key, new_release_key, verify_release_set, write_checksums

FPR = verify_release_set.EXPECTED_SIGNING_FPR


def _populate_valid_set(folder: Path, ver: str = "1.0.0") -> Path:
    names = write_checksums.release_assets(ver)
    for idx, name in enumerate(names, 1):
        (folder / name).write_bytes(f"asset-{idx}".encode())
    return write_checksums.write_sums(folder, ver, names)


def test_unsigned_valid_set_returns_3_and_tampered_before_sign_returns_1(
    tmp_path: Path, capsys
):
    _populate_valid_set(tmp_path)
    assert verify_release_set.main([str(tmp_path)]) == 3
    assert "UNSIGNED:" in capsys.readouterr().out

    (tmp_path / "Malaz-1.0.0.zip").write_bytes(b"corrupted")
    assert verify_release_set.main([str(tmp_path)]) == 1
    assert "ERROR: Hash or size mismatch" in capsys.readouterr().out


def test_signed_valid_set_checks_exact_fingerprint_and_extras(
    tmp_path: Path, monkeypatch, capsys
):
    sums = _populate_valid_set(tmp_path)
    asc = tmp_path / f"{sums.name}.asc"
    asc.write_text("-----BEGIN PGP SIGNATURE-----\n", encoding="utf-8")
    (tmp_path / "RELEASE-SIGNING-KEY.asc").write_text("pubkey\n", encoding="utf-8")

    monkeypatch.setattr(verify_release_set.sign_sums, "find_gpg", lambda: None)
    assert verify_release_set.main([str(tmp_path)]) == 3
    assert "SIGNATURE NOT VERIFIED (gpg not found)" in capsys.readouterr().out

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
    assert "ERROR: Invalid GPG signature" in capsys.readouterr().out

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
    assert "OK: Release set 1.0.0 complete;" in capsys.readouterr().out

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

    repo_root = Path(__file__).resolve().parents[1]
    armor_lines = (
        (repo_root / "docs" / "RELEASE-SIGNING-KEY.asc").read_text(encoding="utf-8").splitlines()
    )
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


def test_backup_key_rejects_repo_output_short_passphrase_and_passes_stdin(
    monkeypatch, capsys
):
    repo_root = Path(backup_key.__file__).resolve().parent.parent
    inside = repo_root / "dist" / "secret-backup.asc.gpg"
    with pytest.raises(SystemExit, match="inside the repository"):
        backup_key.main(["--output", str(inside)])

    with tempfile.TemporaryDirectory() as ext_dir:
        out = Path(ext_dir) / "backup.asc.gpg"
        monkeypatch.setattr(backup_key.getpass, "getpass", lambda _p: "short")
        with pytest.raises(SystemExit, match="at least 12 characters"):
            backup_key.main(["--output", str(out)])

        secret_pw = "correct-horse-battery-staple"
        monkeypatch.setattr(backup_key.getpass, "getpass", lambda _p: secret_pw)

        seen_calls: list[tuple[list[str], str | None]] = []

        def fake_export(cmd, *, input=None, **_kw):
            seen_calls.append((list(cmd), input))
            out.write_bytes(b"PGP-BACKUP")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        monkeypatch.setattr(backup_key.subprocess, "run", fake_export)
        assert backup_key.main(["--output", str(out), "--gpg", "C:/fake/gpg.exe"]) == 0
        assert len(seen_calls) == 1
        cmd_args, stdin_payload = seen_calls[0]
        assert secret_pw not in cmd_args
        assert stdin_payload == secret_pw + "\n"
        assert "Backup written:" in capsys.readouterr().out


def test_new_release_key_passphrase_validation_and_english_delete_prompt(
    tmp_path: Path, monkeypatch, capsys
):
    answers = iter(
        [
            "short",
            "valid-passphrase-1",
            "mismatch-passphrase",
            "valid-passphrase-1",
            "valid-passphrase-1",
        ]
    )
    monkeypatch.setattr(new_release_key.getpass, "getpass", lambda _p: next(answers))
    assert new_release_key.ask_passphrase() == "valid-passphrase-1"
    out_text = capsys.readouterr().out
    assert "at least 12 characters" in out_text
    assert "Passphrases do not match." in out_text

    old_fpr = "A" * 40
    new_fpr = "B" * 40
    deleted: list[str] = []

    monkeypatch.setattr(new_release_key, "REPO", tmp_path)
    (tmp_path / "docs").mkdir()
    monkeypatch.setattr(new_release_key, "find_gpg", lambda: Path("C:/fake/gpg.exe"))
    monkeypatch.setattr(new_release_key, "secret_keys", lambda _g: [(old_fpr, "Old Key")])
    monkeypatch.setattr(new_release_key, "ask_passphrase", lambda: "valid-passphrase-1")
    monkeypatch.setattr(new_release_key, "generate", lambda _g, _pw, _before: new_fpr)
    monkeypatch.setattr(new_release_key, "clear_agent_cache", lambda _g: None)
    monkeypatch.setattr(new_release_key, "prove_protected", lambda _g, _f: True)
    monkeypatch.setattr(
        new_release_key,
        "export_public",
        lambda _g, _f: tmp_path / "docs" / "RELEASE-SIGNING-KEY.asc",
    )
    monkeypatch.setattr(new_release_key, "update_references", lambda *_a: [])

    def fake_run(_gpg, args, **_kw):
        if "--delete-secret-and-public-key" in args:
            deleted.append(args[-1])
        return subprocess.CompletedProcess(["gpg", *args], 0, "", "")

    monkeypatch.setattr(new_release_key, "run", fake_run)

    def assert_yn(prompt: str) -> None:
        assert "[y/N]" in prompt

    # Legacy German "j" must NOT trigger deletion when prompt asks [y/N].
    monkeypatch.setattr(builtins, "input", lambda prompt: (assert_yn(prompt), "j")[1])
    assert new_release_key.main() == 0
    assert deleted == []

    monkeypatch.setattr(builtins, "input", lambda _prompt: "y")
    assert new_release_key.main() == 0
    assert deleted == [old_fpr]
    assert f"deleted: {old_fpr}" in capsys.readouterr().out
