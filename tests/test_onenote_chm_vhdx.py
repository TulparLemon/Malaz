"""Tests for OneNote (.one), CHM, VHDX/NTFS/FAT routing & risky_types (Spec 014)."""

from __future__ import annotations

import io
import random
import struct
import zipfile
from pathlib import Path

from malaz import config
from malaz.analysis.clamav import ClamAVScanner
from malaz.analysis.windows_av import WindowsDefenderScanner
from malaz.core import magic, onenote_extract, sevenzip
from malaz.core.archive import BUDGET_STOP_PREFIX
from malaz.core.dispatcher import Dispatcher
from malaz.core.risky_types import RISKY_SUFFIXES
from malaz.models import RiskLevel

_ONENOTE_MAGIC = b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d\xae\xb1\x53\x78\xd0\x29\x96\xd3"
_FDSO_HEADER = b"\xe7\x16\xe3\xbd\x65\x26\x11\x45\xa4\xc4\x8d\x4d\x0b\x7a\x9e\xac"
_FDSO_FOOTER = b"\x22\xa7\xfb\x71\x79\x0f\x0b\x4a\xbb\x13\x89\x92\x56\x42\x6b\x24"


def _dispatcher() -> Dispatcher:
    return Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )


def _rule_ids(res) -> set[str]:
    return {i.rule_id for i in res.all_indicators()}


def _build_fdso(payload: bytes, *, bad_footer: bool = False) -> bytes:
    pad = (-len(payload)) % 8
    header = _FDSO_HEADER + struct.pack("<Q", len(payload)) + b"\x00" * 12
    footer = (b"\x00" * 16) if bad_footer else _FDSO_FOOTER
    return header + payload + (b"\x00" * pad) + footer


def _build_one(*blocks: bytes) -> bytes:
    return _ONENOTE_MAGIC + b"\x00" * 64 + b"".join(blocks)


def _ntfs_boot_sector() -> bytes:
    buf = bytearray(512)
    buf[0:3] = b"\xeb\x52\x90"
    buf[3:11] = b"NTFS    "
    buf[510:512] = b"\x55\xaa"
    return bytes(buf)


def _fat32_boot_sector() -> bytes:
    buf = bytearray(512)
    buf[0:3] = b"\xeb\x58\x90"
    buf[82:90] = b"FAT32   "
    buf[510:512] = b"\x55\xaa"
    return bytes(buf)


def _exfat_boot_sector() -> bytes:
    buf = bytearray(512)
    buf[0:3] = b"\xeb\x76\x90"
    buf[3:11] = b"EXFAT   "
    buf[510:512] = b"\x55\xaa"
    return bytes(buf)


def _valid_png_with_high_entropy(size_bytes: int = 140_000) -> bytes:
    rng = random.Random(42)
    body = rng.randbytes(size_bytes)
    return (
        b"\x89PNG\r\n\x1a\n"
        b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde"
        + struct.pack(">I", len(body))
        + b"IDAT"
        + body
        + b"\x00\x00\x00\x00"
        + b"\x00\x00\x00\x00IEND\xaeB`\x82"
    )


def test_onenote_extracts_embedded_payloads_and_iso_and_hta(tmp_path: Path) -> None:
    vbs = b'Set sh = CreateObject("WScript.Shell")\nsh.Run "powershell -enc SQBFAFgA"\n'
    hta = b"<html><HTA:APPLICATION ID='x'><script>eval(atob('YWxlcnQoMSk='))</script></html>"
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        zf.writestr("a.txt", b"hello")
    iso = bytearray(0x8020)
    iso[0x8001:0x8006] = b"CD001"

    one_bytes = _build_one(
        _build_fdso(vbs),  # odd/non-aligned length -> 8-byte padding tested
        _build_fdso(hta),
        _build_fdso(bio.getvalue()),
        _build_fdso(bytes(iso)),
    )
    assert magic.detect(one_bytes).type == "onenote"

    objs = list(onenote_extract.iter_onenote_objects(one_bytes))
    assert len(objs) == 4
    assert [name for name, _, err in objs if err is None] == [
        "onenote_obj_1.vbs",
        "onenote_obj_2.hta",
        "onenote_obj_3.zip",
        "onenote_obj_4.iso",
    ]

    p = tmp_path / "note.one"
    p.write_bytes(_build_one(_build_fdso(vbs)))
    res = _dispatcher().scan_path(p)
    assert res.detected_type == "onenote"
    assert len(res.children) == 1
    assert res.children[0].path == "onenote_obj_1.vbs"
    assert res.risk_level in (RiskLevel.YELLOW, RiskLevel.RED)


def test_benign_onenote_with_large_png_screenshot_stays_green(tmp_path: Path) -> None:
    one_bytes = _build_one(_build_fdso(_valid_png_with_high_entropy(150_000)))
    p = tmp_path / "meeting_notes.one"
    p.write_bytes(one_bytes)
    res = _dispatcher().scan_path(p)
    assert res.detected_type == "onenote"
    assert res.risk_level == RiskLevel.GREEN, _rule_ids(res)
    assert res.score == 0


def test_onenote_edge_cases_and_incomplete_errors(tmp_path: Path, monkeypatch) -> None:
    # 1. cb_length == 0 with valid footer -> skipped cleanly without alarm
    zero_valid = _build_one(_build_fdso(b""))
    assert list(onenote_extract.iter_onenote_objects(zero_valid)) == []

    # 2. cb_length == 0 without footer -> ONENOTE_OBJ_ERROR
    zero_bad = _build_one(_build_fdso(b"", bad_footer=True))
    p_zb = tmp_path / "zero_bad.one"
    p_zb.write_bytes(zero_bad)
    res_zb = _dispatcher().scan_path(p_zb)
    assert "ONENOTE_OBJ_ERROR" in _rule_ids(res_zb)
    assert res_zb.is_incomplete

    # 3. Truncated header (pos + 36 > len)
    trunc_hdr = _ONENOTE_MAGIC + _FDSO_HEADER + b"\x01\x00\x00"
    objs_th = list(onenote_extract.iter_onenote_objects(trunc_hdr))
    assert len(objs_th) == 1 and objs_th[0][2] is not None

    # 4. cb_length > MAX_EXTRACTED_FILE_SIZE -> error without OOM
    huge = _ONENOTE_MAGIC + _FDSO_HEADER + struct.pack("<Q", 10**12) + b"\x00" * 12
    objs_huge = list(onenote_extract.iter_onenote_objects(huge))
    assert len(objs_huge) == 1 and "Größenlimit" in (objs_huge[0][2] or "")

    # 5. Bad footer -> ONENOTE_OBJ_ERROR
    p_bf = tmp_path / "bad_footer.one"
    p_bf.write_bytes(_build_one(_build_fdso(b"hello world", bad_footer=True)))
    res_bf = _dispatcher().scan_path(p_bf)
    assert "ONENOTE_OBJ_ERROR" in _rule_ids(res_bf)
    assert res_bf.is_incomplete

    # 6. Exactly MAX_ARCHIVE_ENTRIES valid objects -> NO false budget stop;
    #    MAX_ARCHIVE_ENTRIES + 20 fake headers -> capped with BUDGET_STOP_PREFIX.
    monkeypatch.setattr(config, "MAX_ARCHIVE_ENTRIES", 5)
    exact5 = _build_one(*(_build_fdso(f"doc {i}".encode()) for i in range(5)))
    objs_exact = list(onenote_extract.iter_onenote_objects(exact5))
    assert len(objs_exact) == 5
    assert all(not (err or "").startswith(BUDGET_STOP_PREFIX) for _, _, err in objs_exact)

    flood = _ONENOTE_MAGIC + (_FDSO_HEADER + b"\xff" * 20) * 50
    objs_flood = list(onenote_extract.iter_onenote_objects(flood))
    assert len(objs_flood) == 6
    assert (objs_flood[-1][2] or "").startswith(BUDGET_STOP_PREFIX)

    # 7. Depth limit for nested .one
    monkeypatch.setattr(config, "MAX_ARCHIVE_DEPTH", 1)
    inner_one = _build_one(_build_fdso(b"inner"))
    outer_one = _build_one(_build_fdso(inner_one))
    p_nest = tmp_path / "nested.one"
    p_nest.write_bytes(outer_one)
    res_nest = _dispatcher().scan_path(p_nest)
    assert "ARCH_DEPTH_LIMIT" in _rule_ids(res_nest)

    # 8. Truncated large .one (> MAX_READ_SIZE) -> CORE_READ_TRUNCATED + incomplete
    monkeypatch.setattr(config, "MAX_READ_SIZE", 128)
    monkeypatch.setattr(config, "MAX_LARGE_PREFIX_SIZE", 128)
    p_trunc = tmp_path / "large.one"
    p_trunc.write_bytes(_build_one(_build_fdso(b"A" * 512)))
    res_trunc = _dispatcher().scan_path(p_trunc)
    assert "CORE_READ_TRUNCATED" in _rule_ids(res_trunc)
    assert res_trunc.is_incomplete


def test_magic_chm_vhdx_ntfs_fat_and_spoofed_extension() -> None:
    assert magic.detect(b"ITSF\x03\x00\x00\x00" + b"\x00" * 64).type == "chm"
    assert magic.detect(b"ITSF\x02\x00\x00\x00" + b"\x00" * 64).type == "chm"
    assert magic.detect(b"vhdxfile" + b"\x00" * 64).type == "vhdx"
    assert magic.detect(_ntfs_boot_sector()).type == "ntfs"
    assert magic.detect(_fat32_boot_sector()).type == "fat"
    assert magic.detect(_exfat_boot_sector()).type == "fat"


def test_chm_and_vhdx_two_stage_sevenzip_routing(tmp_path: Path, monkeypatch) -> None:
    # Missing 7-Zip -> ARCH_7Z_MISSING (YELLOW, incomplete)
    monkeypatch.setattr(sevenzip, "find_7z_binary", lambda: None)
    p_chm = tmp_path / "help.dat"  # spoofed extension!
    p_chm.write_bytes(b"ITSF\x03\x00\x00\x00" + b"\x00" * 128)
    res_miss = _dispatcher().scan_path(p_chm)
    assert res_miss.detected_type == "chm"
    assert "ARCH_7Z_MISSING" in _rule_ids(res_miss)
    assert res_miss.risk_level != RiskLevel.GREEN

    # Disabled 7-Zip -> ARCH_7Z_DISABLED (YELLOW)
    monkeypatch.setattr(config, "SEVENZIP_ENABLED", False)
    p_vhdx = tmp_path / "disk.vhdx"
    p_vhdx.write_bytes(b"vhdxfile" + b"\x00" * 128)
    res_dis = _dispatcher().scan_path(p_vhdx)
    assert res_dis.detected_type == "vhdx"
    assert "ARCH_7Z_DISABLED" in _rule_ids(res_dis)

    # Enabled + 2-stage VHDX -> 0.ntfs -> malicious HTML inside NTFS
    monkeypatch.setattr(config, "SEVENZIP_ENABLED", True)
    monkeypatch.setattr(sevenzip, "find_7z_binary", lambda: Path("7z.exe"))
    seen_suffixes: list[str] = []

    def fake_iter_7z(data: bytes, suffix: str, passwords=None):
        seen_suffixes.append(suffix)
        if suffix == ".vhdx":
            yield ("0.ntfs", _ntfs_boot_sector(), None)
        elif suffix == ".ntfs":
            chm_html = (
                b'<object classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11">'
                b'<param name="Command" value="ShortCut"></object>'
            )
            yield ("dropper.html", chm_html, None)
        elif suffix == ".chm":
            yield ("", b"", "7-Zip Fehler: Archiv beschädigt")

    monkeypatch.setattr(sevenzip, "iter_7z_members", fake_iter_7z)

    p_vhdx_spoof = tmp_path / "invoice.bin"
    p_vhdx_spoof.write_bytes(b"vhdxfile" + b"\x00" * 128)
    res_2stage = _dispatcher().scan_path(p_vhdx_spoof)
    assert seen_suffixes == [".vhdx", ".ntfs"]
    assert "HTML_CHM_ACTIVEX" in _rule_ids(res_2stage)
    assert res_2stage.risk_level == RiskLevel.RED

    # Corrupt CHM -> ARCH_7Z_ERROR
    res_err = _dispatcher().scan_path(p_chm)
    assert ".chm" in seen_suffixes
    assert "ARCH_7Z_ERROR" in _rule_ids(res_err)


def test_risky_suffixes_cover_all_13_new_extensions_and_not_svg_html(tmp_path: Path) -> None:
    expected_new = {
        ".vhdx", ".chm", ".one", ".onepkg", ".msix", ".appx", ".appinstaller",
        ".scf", ".library-ms", ".search-ms", ".settingcontent-ms", ".msc", ".inf",
    }
    assert expected_new.issubset(set(RISKY_SUFFIXES))
    assert ".svg" not in RISKY_SUFFIXES
    assert ".html" not in RISKY_SUFFIXES
    assert ".htm" not in RISKY_SUFFIXES

    # Verify EML attachment detection for one representative new suffix (.one)
    eml = (
        b"From: sender@example.org\r\n"
        b"To: victim@example.org\r\n"
        b"Subject: Notes\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="B"\r\n\r\n'
        b"--B\r\nContent-Type: text/plain\r\n\r\nSee notes.\r\n"
        b'--B\r\nContent-Type: application/octet-stream; name="notes.one"\r\n'
        b'Content-Disposition: attachment; filename="notes.one"\r\n\r\n'
        + _ONENOTE_MAGIC
        + b"\r\n--B--\r\n"
    )
    p = tmp_path / "mail.eml"
    p.write_bytes(eml)
    res = _dispatcher().scan_path(p)
    assert "MAIL_ATTACH_RISKY_TYPE" in _rule_ids(res)
