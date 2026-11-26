"""T1 tests for scripts/lab_ingest.py (Spec 017 §4)."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
import pyzipper

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import lab_ingest  # noqa: E402

from malaz import config  # noqa: E402
from malaz.lab.manifest import load_manifest, sha256_file  # noqa: E402


def _make_aes_zip(path: Path, members: list[tuple[str, bytes]], password: str = "infected") -> None:
    with pyzipper.AESZipFile(
        path, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
    ) as zf:
        zf.setpassword(password.encode("utf-8"))
        for name, data in members:
            zf.writestr(name, data)


def _make_zipcrypto_zip(path: Path, members: list[tuple[str, bytes]], password: str = "infected") -> None:
    """Create a traditional ZipCrypto encrypted archive via 7-Zip or pyzipper."""
    # pyzipper supports ZipCrypto writing via ZipFile + pwd or standard zip encryption;
    # use WZ_AES fallback only if ZipCrypto writer unavailable — pyzipper supports
    # standard ZipCrypto decryption natively; craft valid ZipCrypto header using 7z if present,
    # else verify with pyzipper's AESZipFile reader on ZipCrypto bytes.
    with pyzipper.ZipFile(path, "w", compression=pyzipper.ZIP_DEFLATED) as zf:
        zf.setpassword(password.encode("utf-8"))
        # Build a genuine traditional ZipCrypto entry via pure-Python CRC32 stream cipher
        for name, data in members:
            _write_zipcrypto_member(zf, name, data, password.encode("utf-8"))


def _zipcrypto_encrypt(data: bytes, password: bytes, crc32_val: int) -> bytes:
    """Pure-Python PKWARE traditional ZipCrypto encryption for test fixtures."""
    import zlib

    # Standard CRC32 table
    def _crc32_byte(crc: int, b: int) -> int:
        return (crc >> 8) ^ _CRC_TABLE[(crc ^ b) & 0xFF]

    k0, k1, k2 = 0x12345678, 0x23456789, 0x34567890

    def _update(b: int) -> None:
        nonlocal k0, k1, k2
        k0 = _crc32_byte(k0, b)
        k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        k2 = _crc32_byte(k2, (k1 >> 24) & 0xFF)

    def _decrypt_byte() -> int:
        t = (k2 | 2) & 0xFFFF
        return ((t * (t ^ 1)) >> 8) & 0xFF

    for pb in password:
        _update(pb)

    header = bytearray(12)
    for i in range(11):
        header[i] = (i * 17 + 3) & 0xFF
    header[11] = (crc32_val >> 24) & 0xFF

    raw = bytes(header) + zlib.compress(data)[2:-4]
    out = bytearray(len(raw))
    for i, b in enumerate(raw):
        c = b ^ _decrypt_byte()
        _update(b)
        out[i] = c
    return bytes(out)


def _make_crc_table() -> list[int]:
    tbl: list[int] = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = ((c >> 1) ^ 0xEDB88320) if (c & 1) else (c >> 1)
        tbl.append(c)
    return tbl


_CRC_TABLE = _make_crc_table()


def _write_zipcrypto_member(zf: zipfile.ZipFile, name: str, data: bytes, password: bytes) -> None:
    """Write a single traditional ZipCrypto deflated member directly into a fresh ZIP file."""
    import struct
    import zlib

    crc = zlib.crc32(data) & 0xFFFFFFFF
    enc = _zipcrypto_encrypt(data, password, crc)
    name_b = name.encode("utf-8")
    # Build minimal valid ZIP with local header + central directory + EOCD
    local_hdr = struct.pack(
        "<IHHHHHIIIHH",
        0x04034B50,
        20,
        0x0001,  # encrypted bit
        8,  # deflate
        0,
        0,
        crc,
        len(enc),
        len(data),
        len(name_b),
        0,
    )
    cd_offset = len(local_hdr) + len(name_b) + len(enc)
    cd_hdr = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        0x02014B50,
        20,
        20,
        0x0001,
        8,
        0,
        0,
        crc,
        len(enc),
        len(data),
        len(name_b),
        0,
        0,
        0,
        0,
        0,
        0,
    )
    cd_size = len(cd_hdr) + len(name_b)
    eocd = struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        1,
        1,
        cd_size,
        cd_offset,
        0,
    )
    zf.close()
    Path(zf.filename).write_bytes(local_hdr + name_b + enc + cd_hdr + name_b + eocd)


def test_ingest_aes_and_zipcrypto_zero_unpack_manifest_and_sha256(tmp_path):
    bad_dir = tmp_path / "bad_zips"
    ben_dir = tmp_path / "benign"
    staging = tmp_path / "staging"
    bad_dir.mkdir()
    ben_dir.mkdir()

    mal_pdf = b"%PDF-1.7\n% harmless dummy pdf payload for AES test\n%%EOF\n"
    mal_pe = b"MZ" + b"\x00" * 126 + b"ZipCrypto dummy sample"
    ben_txt = b"Hello benign document content.\n"

    _make_aes_zip(bad_dir / "sample_aes.zip", [("Invoice.PDF", mal_pdf)])
    _make_zipcrypto_zip(bad_dir / "sample_zc.zip", [("Dropper.EXE", mal_pe)])
    (ben_dir / "readme.PDF").write_bytes(ben_txt)

    fam_map = tmp_path / "families.json"
    fam_map.write_text(json.dumps({"sample_aes": "Emotet"}), encoding="utf-8")

    rc = lab_ingest.main(
        [
            "--bad-zips",
            str(bad_dir),
            "--benign-dir",
            str(ben_dir),
            "--staging-dir",
            str(staging),
            "--corpus-id",
            "t1-corpus",
            "--family-map",
            str(fam_map),
        ]
    )
    assert rc == 0

    input_ro = staging / "input_ro"
    # Zero-Unpack-on-Host: decrypted malicious payloads MUST NOT exist on disk
    mal_pdf_sha = hashlib.sha256(mal_pdf).hexdigest()
    mal_pe_sha = hashlib.sha256(mal_pe).hexdigest()
    for p in staging.rglob("*"):
        if p.is_file() and p.suffix.lower() != ".zip":
            assert p.name != f"{mal_pdf_sha}.pdf"
            assert p.name != f"{mal_pe_sha}.exe"

    # Manifest validates strictly via load_manifest()
    manifest = load_manifest(input_ro / "manifest.json")
    assert len(manifest.entries) == 3
    by_hash = {e.sha256: e for e in manifest.entries}
    assert by_hash[mal_pdf_sha].name == f"{mal_pdf_sha}.pdf"
    assert by_hash[mal_pdf_sha].family == "Emotet"
    assert by_hash[mal_pdf_sha].type == "pdf"
    assert by_hash[mal_pe_sha].name == f"{mal_pe_sha}.exe"

    ben_sha = hashlib.sha256(ben_txt).hexdigest()
    assert by_hash[ben_sha].name == f"{ben_sha}.pdf"  # .PDF -> .pdf
    assert (input_ro / "benign" / f"{ben_sha}.pdf").is_file()

    # Checksums match
    m_sha = sha256_file(input_ro / "manifest.json")
    assert (input_ro / "manifest.sha256").read_text(encoding="utf-8").startswith(m_sha)
    s_sha = sha256_file(input_ro / "ingest_summary.json")
    assert (input_ro / "ingest_summary.sha256").read_text(encoding="utf-8").startswith(s_sha)
    summary = json.loads((input_ro / "ingest_summary.json").read_text(encoding="utf-8"))
    assert summary["accepted_malicious"] == 2
    assert summary["accepted_benign"] == 1
    assert summary["manifest_sha256"] == m_sha
    assert summary["rejected_total"] == 0


def test_ingest_zip_bomb_header_spoof_symlink_zipslip_and_atomic_rollback(tmp_path, monkeypatch):
    bad_dir = tmp_path / "bad_zips"
    ben_dir = tmp_path / "benign"
    staging = tmp_path / "staging"
    bad_dir.mkdir()
    ben_dir.mkdir()

    # Pin MAX_READ_SIZE to 1024 B so a 4096 B member triggers oversize cleanly
    monkeypatch.setattr(config, "MAX_READ_SIZE", 1024)

    # 1. Spoofed file_size header (claims 10 B in CD/local header, actual stream is 4096 B!)
    spoof_zip = bad_dir / "01_spoof.zip"
    _make_aes_zip(spoof_zip, [("ok.bin", b"A" * 200), ("bomb.bin", b"B" * 4096)])
    raw_z = bytearray(spoof_zip.read_bytes())
    # Patch uncompressed size 4096 (0x1000) -> 10 (0x0A) in ZIP headers
    raw_z = raw_z.replace((4096).to_bytes(4, "little"), (10).to_bytes(4, "little"))
    spoof_zip.write_bytes(bytes(raw_z))

    # 2. Unix symlink member inside encrypted ZIP
    sym_zip = bad_dir / "02_symlink.zip"
    with pyzipper.AESZipFile(sym_zip, "w", encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(b"infected")
        zf.writestr("good.bin", b"good_data_12345")
        zi = zf.zipinfo_cls("link.txt")
        zi.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(zi, b"/etc/passwd")

    # 3. Multi-member all-or-nothing Zip-Slip (1 good + 1 traversal -> 0 accepted, count = 1)
    slip_zip = bad_dir / "03_zipslip.zip"
    _make_aes_zip(slip_zip, [("good2.bin", b"good_data_67890"), ("../evil.exe", b"MZ" + b"X" * 64)])

    # 4. Unencrypted ZIP
    plain_zip = bad_dir / "04_unenc.zip"
    with zipfile.ZipFile(plain_zip, "w") as zf:
        zf.writestr("plain.bin", b"unencrypted_payload")

    # 5. Exceeds --max-members-per-zip=2
    many_zip = bad_dir / "05_many.zip"
    _make_aes_zip(many_zip, [("a.bin", b"11111"), ("b.bin", b"22222"), ("c.bin", b"33333")])

    # 6. One valid benign file so ingest completes and writes summary
    ben_ok = ben_dir / "good.txt"
    ben_ok.write_bytes(b"clean benign text")
    # Oversized benign file (> 1024 B)
    (ben_dir / "too_big.txt").write_bytes(b"Z" * 2048)

    rc = lab_ingest.main(
        [
            "--bad-zips",
            str(bad_dir),
            "--benign-dir",
            str(ben_dir),
            "--staging-dir",
            str(staging),
            "--corpus-id",
            "t1-atomic",
            "--max-members-per-zip",
            "2",
        ]
    )
    assert rc == 0

    summary = json.loads((staging / "input_ro/ingest_summary.json").read_text(encoding="utf-8"))
    assert summary["accepted_malicious"] == 0
    assert summary["accepted_benign"] == 1
    # Full rollback: ONLY the 17-byte benign file counts in total_unpacked_bytes!
    assert summary["total_unpacked_bytes"] == len(b"clean benign text")
    assert summary["rejected"]["oversize"] == 2  # 1 spoof_zip + 1 too_big benign
    assert summary["rejected"]["zipslip"] == 2  # sym_zip + slip_zip
    assert summary["rejected"]["unencrypted"] == 1
    assert summary["rejected"]["member_limit"] == 1
    # Zero bad ZIPs copied into input_ro/bad_zips/
    assert list((staging / "input_ro/bad_zips").iterdir()) == []


def test_ingest_label_conflict_empty_password_repo_guard_and_stable_split(tmp_path, monkeypatch):
    bad_dir = tmp_path / "bad_zips"
    ben_dir = tmp_path / "benign"
    bad_dir.mkdir()
    ben_dir.mkdir()

    shared = b"identical payload in malicious and benign"
    _make_aes_zip(bad_dir / "dup.zip", [("m.bin", shared)])
    (ben_dir / "b.bin").write_bytes(shared)

    # 1. Label conflict -> Exit 1, input_ro NOT created/populated
    staging_conf = tmp_path / "st_conflict"
    rc_conf = lab_ingest.main(
        [
            "--bad-zips",
            str(bad_dir),
            "--benign-dir",
            str(ben_dir),
            "--staging-dir",
            str(staging_conf),
            "--corpus-id",
            "t1-conf",
        ]
    )
    assert rc_conf == 1
    assert not (staging_conf / "input_ro").exists()

    # 2. Empty password file -> Exit 2
    empty_pw = tmp_path / "empty_pw.txt"
    empty_pw.write_text("\r\n", encoding="utf-8")
    rc_pw = lab_ingest.main(
        [
            "--bad-zips",
            str(bad_dir),
            "--benign-dir",
            str(ben_dir),
            "--staging-dir",
            str(tmp_path / "st_pw"),
            "--corpus-id",
            "t1-pw",
            "--password-file",
            str(empty_pw),
        ]
    )
    assert rc_pw == 2

    # 3. Repo path guard: fake ROOT -> ROOT/sub blocked (Exit 2), sibling ROOT_lab allowed!
    fake_root = tmp_path / "Malaz"
    fake_root.mkdir()
    monkeypatch.setattr(lab_ingest, "ROOT", fake_root)
    rc_inside = lab_ingest.main(
        [
            "--bad-zips",
            str(bad_dir),
            "--benign-dir",
            str(ben_dir),
            "--staging-dir",
            str(fake_root / "sub"),
            "--corpus-id",
            "t1-inside",
        ]
    )
    assert rc_inside == 2

    # Fix conflict so sibling staging succeeds
    (ben_dir / "b.bin").write_bytes(b"distinct benign payload 12345")
    sibling = tmp_path / "Malaz_lab"
    rc_sib = lab_ingest.main(
        [
            "--bad-zips",
            str(bad_dir),
            "--benign-dir",
            str(ben_dir),
            "--staging-dir",
            str(sibling),
            "--corpus-id",
            "t1-sib",
            "--test-ratio",
            "0.0",
        ]
    )
    assert rc_sib == 0

    # Non-empty input_ro -> Exit 2
    rc_nonempty = lab_ingest.main(
        [
            "--bad-zips",
            str(bad_dir),
            "--benign-dir",
            str(ben_dir),
            "--staging-dir",
            str(sibling),
            "--corpus-id",
            "t1-sib2",
        ]
    )
    assert rc_nonempty == 2

    # 4. Previous-manifest split preservation (even with --test-ratio 1.0, old dev entries stay dev!)
    prev_m = sibling / "input_ro/manifest.json"
    staging_next = tmp_path / "Malaz_lab_next"
    rc_next = lab_ingest.main(
        [
            "--bad-zips",
            str(bad_dir),
            "--benign-dir",
            str(ben_dir),
            "--staging-dir",
            str(staging_next),
            "--corpus-id",
            "t1-next",
            "--test-ratio",
            "1.0",
            "--previous-manifest",
            str(prev_m),
        ]
    )
    assert rc_next == 0
    m_next = load_manifest(staging_next / "input_ro/manifest.json")
    assert all(e.split == "dev" for e in m_next.entries)


def test_ingest_rejects_benign_symlink_or_junction(tmp_path):
    bad_dir = tmp_path / "bad_zips"
    ben_dir = tmp_path / "benign"
    bad_dir.mkdir()
    ben_dir.mkdir()

    real_file = tmp_path / "outside.txt"
    real_file.write_bytes(b"outside secret")
    (ben_dir / "ok.txt").write_bytes(b"normal benign file")

    # Create a Windows directory junction (no admin needed) or symlink
    junc_target = tmp_path / "target_dir"
    junc_target.mkdir()
    (junc_target / "inner.txt").write_bytes(b"inside junction")
    junc_path = ben_dir / "junc_sub"
    subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junc_path), str(junc_target)],
        capture_output=True,
        check=False,
    )
    if not junc_path.exists():
        pytest.skip("Junction creation unavailable in this environment")

    # Direct symlink/reparse check on _is_reparse_or_symlink
    assert lab_ingest._is_reparse_or_symlink(junc_path) is True
    # Junction inside staging path blocked with Exit 2
    rc = lab_ingest.main(
        [
            "--bad-zips",
            str(bad_dir),
            "--benign-dir",
            str(ben_dir),
            "--staging-dir",
            str(junc_path / "nested_stage"),
            "--corpus-id",
            "t1-junc",
        ]
    )
    assert rc == 2
    # Clean up junction cleanly
    os.rmdir(junc_path)
