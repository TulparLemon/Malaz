from malaz.core.magic import detect, expected_type_for_extension


def test_pdf():
    assert detect(b"%PDF-1.7").type == "pdf"


def test_zip():
    assert detect(b"PK\x03\x04rest").type == "zip"


def test_png():
    assert detect(b"\x89PNG\r\n\x1a\n").type == "png"


def test_jpeg():
    assert detect(b"\xff\xd8\xff\xe0").type == "jpeg"


def test_ole():
    assert detect(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1").type == "ole"


def test_pe():
    pe = b"MZ" + b"\x00" * 0x3a + (0x80).to_bytes(4, "little")
    pe += b"\x00" * (0x80 - 0x40) + b"PE\x00\x00"
    assert detect(pe).type == "pe"


def test_empty():
    assert detect(b"").type == "empty"


def test_unknown():
    # Pure binary noise with no signature and too many control bytes.
    import os

    assert detect(os.urandom(256)).type == "unknown"


def test_text_family():
    assert detect(b"hello world, just a normal text file").type == "text"
    assert detect(b'<!DOCTYPE html><html><body>x</body></html>').type == "html"
    assert detect(b'<?xml version="1.0"?><r/>').type == "xml"
    assert detect(b'{"key": "value"}').type == "json"
    assert detect(b"From: a@b\r\nMessage-ID: <x>\r\nReceived: from y\r\n").type == "eml"


def test_extra_signatures():
    assert detect(b"{\\rtf1").type == "rtf"
    assert detect(b"\x7fELF").type == "elf"
    assert detect(b"\xca\xfe\xba\xbe").type == "class"
    assert detect(b"MSCF").type == "cab"
    lnk = b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
    assert detect(lnk).type == "lnk"


def _tiff(offset: int = 8, *, big_endian: bool = False) -> bytes:
    import struct

    if big_endian:
        return b"MM\x00*" + struct.pack(">I", offset) + b"\x00" * 64
    return b"II*\x00" + struct.pack("<I", offset) + b"\x00" * 64


def test_tiff_requires_a_plausible_ifd_offset():
    assert detect(_tiff()).type == "tiff"
    assert detect(_tiff(big_endian=True)).type == "tiff"
    # Four magic bytes alone are not a TIFF: the first IFD must be inside
    # the file (at least its 2-byte entry count must be readable).
    assert detect(b"II*\x00" + (9999).to_bytes(4, "little")).type == "unknown"


def test_webp_requires_the_webp_fourcc():
    import struct

    def riff(fourcc: bytes) -> bytes:
        return b"RIFF" + struct.pack("<I", 8) + fourcc + b"data"

    assert detect(riff(b"WEBP")).type == "webp"
    # RIFF also prefixes AVI/WAV; only the WEBP fourcc is an image.
    assert detect(riff(b"AVI ")).type == "unknown"
    assert detect(riff(b"WAVE")).type == "unknown"


def test_ico_requires_a_nonzero_directory():
    import struct

    ico = b"\x00\x00\x01\x00" + struct.pack("<H", 1) + b"\x00" * 60
    assert detect(ico).type == "ico"
    leer = b"\x00\x00\x01\x00" + struct.pack("<H", 0) + b"\x00" * 60
    assert detect(leer).type != "ico"


def test_mp3_id3_and_frame_sync_need_structure():
    id3 = b"ID3\x03\x00\x00\x00\x00\x00\x0a" + b"\x00" * 32
    assert detect(id3).type == "mp3"
    # ID3v2.4 uses 0x10 for the footer flag — valid, not a reserved bit.
    id3_24 = b"ID3\x04\x00\x10\x00\x00\x00\x0a" + b"\x00" * 32
    assert detect(id3_24).type == "mp3"
    # A reserved low flag bit is not a valid ID3 header.
    id3_reserved = b"ID3\x04\x00\x01\x00\x00\x00\x0a" + b"\x00" * 32
    assert detect(id3_reserved).type != "mp3"
    # A bare 0xFF is not an MPEG frame; the sync is 11 bits and the
    # version/layer/bitrate fields must not be reserved values.
    assert detect(b"\xff" + b"A" * 32).type != "mp3"
    assert detect(b"ID3" + b"x" * 32).type != "mp3"
    # 0xFF 0xFB 0x90 0x64 = MPEG-1 Layer III, valid bitrate/sample rate.
    assert detect(b"\xff\xfb\x90\x64" + b"\x00" * 32).type == "mp3"
    # The UTF-16LE BOM (FF FE) also satisfies the MPEG sync — it must stay
    # text, otherwise every UTF-16 .txt becomes "mp3".
    assert detect("Hallo Welt".encode("utf-16")).type == "text"
    assert detect(b"\xff\xfe" + "Welt".encode("utf-16-le")).type == "text"


def _ftyp(brand: bytes) -> bytes:
    import struct

    return (
        struct.pack(">I", 24)
        + b"ftyp"
        + brand
        + struct.pack(">I", 0)
        + b"isommp42"
    )


def test_mp4_brands_and_heif_precedence():
    for brand in (b"isom", b"iso2", b"mp41", b"mp42", b"avc1", b"M4V ", b"qt  "):
        assert detect(_ftyp(brand)).type == "mp4", brand
    # Not every ISO-BMFF brand is a video: an unknown brand must stay unknown
    # and HEIF/AVIF keep their own types (checked before the mp4 entry).
    assert detect(_ftyp(b"3gp4")).type == "unknown"
    assert detect(_ftyp(b"dash")).type == "unknown"
    assert detect(_ftyp(b"heic")).type == "heic"
    assert detect(_ftyp(b"avif")).type == "avif"


def test_url_shortcut_is_content_detected_not_extension_based():
    shortcut = b"[InternetShortcut]\r\nURL=https://intranet.example.local/\r\n"
    assert detect(shortcut).type == "url"
    # The section header alone, or a URL line without the section, is plain
    # text — the extension is never evidence on its own.
    assert detect(b"[InternetShortcut]\r\nIconFile=x.ico\r\n").type == "text"
    assert detect(b"URL=https://example.invalid/\r\n").type == "text"
    # A UTF-8 BOM must not hide the section header.
    assert detect(b"\xef\xbb\xbf" + shortcut).type == "url"


def test_new_extensions_are_mapped():
    assert expected_type_for_extension(".tif") == "tiff"
    assert expected_type_for_extension(".TIFF") == "tiff"
    assert expected_type_for_extension(".webp") == "webp"
    assert expected_type_for_extension(".ico") == "ico"
    assert expected_type_for_extension(".mp3") == "mp3"
    assert expected_type_for_extension(".mp4") == "mp4"
    assert expected_type_for_extension(".m4v") == "mp4"
    assert expected_type_for_extension(".url") == "url"


def test_extension_map():
    assert expected_type_for_extension(".PDF") == "pdf"
    assert expected_type_for_extension(".docx") == "zip"
    assert expected_type_for_extension(".exe") == "pe"
    assert expected_type_for_extension(".nope") is None


def test_xml_without_declaration_detected():
    # Valid XML without the <?xml declaration (openpyxl-style) must be "xml",
    # not "text" — otherwise XLSX members produce format-mismatch FPs.
    data = b'<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData/></worksheet>'
    assert detect(data).type == "xml"


def test_xhtml_with_namespace_stays_html():
    data = b'<html xmlns="http://www.w3.org/1999/xhtml"><body>hi</body></html>'
    assert detect(data).type == "html"


def test_large_json_is_recognised():
    # Regression (Hunt 8.1): >64-KiB-JSON wurde als text/plain klassifiziert.
    import json as _json

    big = _json.dumps({"schluessel": ["wert"] * 20000}).encode()  # ~300 KB
    assert len(big) > 65536
    assert detect(big).type == "json"


def test_large_json_with_string_spanning_probe_boundary():
    # Truncatur mitten in einem String-Literal ("Unterminated string") am
    # Probe-Ende muss ebenfalls die Vollparse ausloesen, nicht text/plain.
    import json as _json

    # Lange Strings sicher ueber die 64-KiB-Grenze schieben
    big = _json.dumps({"text": "x" * 300000}).encode()
    assert len(big) > 65536
    assert detect(big).type == "json"


def test_bom_wird_vor_der_typerkennung_entfernt():
    """Eine UTF-8-BOM darf das Format nicht verschleiern.

    GEMESSEN: die XML-Mitglieder in .docx/.xlsx/.pptx beginnen mit
    "\\xef\\xbb\\xbf<?xml". ``lstrip()`` kennt die BOM nicht, der Inhalt galt
    deshalb als "text" — und weil die Endung ".xml" etwas anderes behauptet,
    feuerte GEN_FORMAT_MISMATCH (Schwere HOCH) auf JEDEM XML-Mitglied JEDES
    Office-Dokuments. Eine echte .docx kam damit auf ROT 100.
    """
    from malaz.core.magic import detect

    ohne = b'<?xml version="1.0" encoding="utf-8"?><w:document xmlns:w="x"/>'
    mit = b"\xef\xbb\xbf" + ohne
    assert detect(ohne).type == "xml"
    assert detect(mit).type == "xml", "die BOM darf das XML nicht verdecken"

    # Mehrere BOMs hintereinander: die erste wird entfernt, der Rest bleibt
    # Inhalt. (Eine \xff\xfe-BOM bedeutet UTF-16-Inhalt — ASCII dahinter ist
    # keine sinnvolle Probe und wird hier bewusst nicht geprueft.)
