"""Generate a synthetic corpus of *legitimate* files (the false-positive side).

The malware-looking corpus in ``make_test_corpus.py`` proves that the pipelines
*find* things. This corpus proves the opposite: that ordinary files — the kind
every user has on disk — are not flagged. Both sides are needed to catch a
change that trades one for the other.

Every fixture is a real, valid file of its format (a genuine PNG, a genuine
PDF, a genuine ZIP) built with the same libraries the tool analyses with. That
matters: a fixture that is merely "some bytes with a PNG header" would not
exercise the code paths that decide false positives on real files.

Usage:
    python scripts/make_benign_corpus.py [target-dir]

The set is deterministic: identical bytes on every run, so the golden snapshot
in ``tests/test_corpus_golden.py`` stays stable.
"""

from __future__ import annotations

import io
import struct
import sys
import zipfile
import zlib
from pathlib import Path

import corpus_determinism as _det
import make_test_corpus_extended as ext

# -- formats that must stay GREEN -------------------------------------------- #


def plain_text() -> bytes:
    return (
        "Quartalsbericht\n\n"
        "Die Umsätze stiegen im dritten Quartal um 4,2 Prozent.\n"
        "Nächster Termin: 14.10.2026, 10:00 Uhr, Konferenzraum 2.\n"
    ).encode()


def text_with_urls_and_mail() -> bytes:
    """Legitimate IOCs: a real contact page mentions URLs and addresses."""
    return (
        b"Kontakt\n\n"
        b"Web:      https://www.bundesdruckerei.de/service\n"
        b"Support:  support@example-verlag.de\n"
        b"Telefon:  +49 30 1234567\n"
        b"Notfall:  192.0.2.10 (interner Server, TEST-NET-1)\n"
        b"Doku:     https://docs.python.org/3/library/pathlib.html\n"
    )


def utf8_text_umlauts() -> bytes:
    return "Ärger mit Öl und Übung: Maße, Größe, Straße. 中文测试.\n".encode()


def csv_business_data() -> bytes:
    return (
        b"Artikel;Menge;Preis;Datum\n"
        b"Schraube M4;1200;0,08;2026-01-15\n"
        b"Mutter M4;1200;0,03;2026-01-15\n"
        b"Unterlegscheibe;800;0,02;2026-01-16\n"
    )


def json_config() -> bytes:
    return (
        b'{\n  "server": "intranet.example.local",\n'
        b'  "port": 8443,\n  "features": ["scan", "report"],\n'
        b'  "retention_days": 30\n}\n'
    )


def xml_business_document() -> bytes:
    return (
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b'<invoice xmlns="urn:example:invoice">\n'
        b"  <number>2026-0042</number>\n"
        b"  <total currency=\"EUR\">1190.00</total>\n"
        b"</invoice>\n"
    )


def html_local_page() -> bytes:
    return (
        b"<!DOCTYPE html>\n<html lang=\"de\">\n<head>\n"
        b"  <meta charset=\"utf-8\">\n  <title>Handbuch</title>\n</head>\n"
        b"<body>\n  <h1>Handbuch</h1>\n  <p>Kapitel 1: Einrichtung.</p>\n"
        b"</body>\n</html>\n"
    )


# -- images ------------------------------------------------------------------ #


def _png(width: int, height: int, noise: bool = False) -> bytes:
    """A real, standards-compliant PNG (correct CRCs, ends with IEND)."""
    import random

    rng = random.Random(7)

    def chunk(tag: bytes, payload: bytes) -> bytes:
        body = tag + payload
        return (
            struct.pack(">I", len(payload))
            + body
            + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)
        )

    raw = bytearray()
    for _y in range(height):
        raw.append(0)  # filter type 0
        for _x in range(width):
            if noise:
                raw += bytes((rng.randrange(256), rng.randrange(256), rng.randrange(256)))
            else:
                raw += b"\x20\x60\xa0"  # flat colour: low entropy, like a logo

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
        + chunk(b"IEND", b"")
    )


def png_logo() -> bytes:
    return _png(32, 32)


def png_screenshot_like() -> bytes:
    return _png(64, 64, noise=True)


def jpeg_photo() -> bytes:
    """A real baseline JPEG built by Pillow (ends with EOI)."""
    from PIL import Image

    img = Image.new("RGB", (48, 48), (200, 120, 60))
    px = img.load()
    for x in range(48):  # a gradient: compressible, photo-like
        for y in range(48):
            px[x, y] = (x * 5 % 256, y * 5 % 256, (x + y) * 3 % 256)
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=85)
    return buf.getvalue()


def gif_animation_stub() -> bytes:
    """A real single-frame GIF87a."""
    from PIL import Image

    img = Image.new("P", (16, 16), 3)
    buf = io.BytesIO()
    img.save(buf, format="GIF")
    return buf.getvalue()


def bmp_bitmap() -> bytes:
    from PIL import Image

    img = Image.new("RGB", (24, 24), (10, 90, 160))
    buf = io.BytesIO()
    img.save(buf, format="BMP")
    return buf.getvalue()


# -- documents --------------------------------------------------------------- #


def pdf_contract() -> bytes:
    """A real PDF with real text, produced by pikepdf."""
    import pikepdf

    pdf = pikepdf.new()
    page = pikepdf.Page(
        pikepdf.Dictionary(Type=pikepdf.Name.Page, MediaBox=[0, 0, 595, 842])
    )
    pdf.pages.append(page)
    return _det.save_pdf_deterministic(pdf)


def xlsx_price_list() -> bytes:
    from openpyxl import Workbook

    wb = Workbook()
    ws = wb.active
    ws.title = "Preise"
    ws["A1"], ws["B1"] = "Artikel", "Preis"
    ws["A2"], ws["B2"] = "Schraube", 0.08
    ws["A3"], ws["B3"] = "Mutter", 0.03
    return _det.save_workbook_deterministic(wb)


def docx_like_zip() -> bytes:
    """An OOXML container with the REAL member layout and namespaces.

    The member must look like genuine WordprocessingML: ``<document>`` alone
    would be fine, but a bare ``<body>`` tag makes the content sniffer classify
    the member as HTML (``<body>`` is an HTML marker) and run the HTML
    heuristics on it. Real .docx files use the ``w:`` namespace, so the
    fixture does too.
    """
    buf = io.BytesIO()
    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/'
        'wordprocessingml/2006/main">'
        "<w:body><w:p><w:r><w:t>Vertragstext</w:t></w:r></w:p></w:body>"
        "</w:document>"
    )
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        _det.zip_write(
            zf,
            "[Content_Types].xml",
            '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/'
            'package/2006/content-types"><Default Extension="xml" '
            'ContentType="application/xml"/></Types>',
        )
        _det.zip_write(zf, "_rels/.rels", '<?xml version="1.0"?><Relationships/>')
        _det.zip_write(zf, "word/document.xml", document)
    return buf.getvalue()


# -- archives --------------------------------------------------------------- #


def zip_documents() -> bytes:
    """A normal archive with internal, non-traversing member names."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        _det.zip_write(zf, "bericht/q3.txt", plain_text())
        _det.zip_write(zf, "bericht/daten.csv", csv_business_data())
        _det.zip_write(zf, "README.txt", "Alle Dateien dieses Archivs sind intern.")
    return buf.getvalue()


def tar_gz_sources() -> bytes:
    buf = io.BytesIO()
    with _det.open_tar_gz(buf) as tf:
        for name, data in (
            ("src/main.py", b"print('hello')\n"),
            ("src/util.py", b"def add(a, b):\n    return a + b\n"),
            ("README.md", b"# Projekt\n\nBeschreibung.\n"),
        ):
            _det.tar_write(tf, name, data)
    return buf.getvalue()


def zip_nested_legit() -> bytes:
    """A ZIP containing a ZIP — the resource layout Office/Java tools use."""
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as zf:
        _det.zip_write(zf, "data/values.csv", csv_business_data())
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        _det.zip_write(zf, "bundle/inner.zip", inner.getvalue())
        _det.zip_write(zf, "bundle/manifest.txt", "Version 1.0\n")
    return buf.getvalue()


# -- scripts and mail -------------------------------------------------------- #


def batch_maintenance() -> bytes:
    """An ordinary admin script — mentions system tools, does nothing hostile."""
    return (
        b"@echo off\r\n"
        b"REM Wartungsskript: laufende Dienste neu starten\r\n"
        b"echo Wartung startet...\r\n"
        b"net stop Spooler\r\n"
        b"net start Spooler\r\n"
        b"echo Fertig.\r\n"
    )


def powershell_inventory() -> bytes:
    """A legitimate reporting script (no encoded command, no download)."""
    return (
        b"# Inventar-Skript fuer den Admin-Report\r\n"
        b"Get-ChildItem -Path C:\\Reports | Select-Object Name, Length\r\n"
        b"Get-Service | Where-Object { $_.Status -eq 'Running' }\r\n"
        b"Write-Output 'Inventar abgeschlossen.'\r\n"
    )


def eml_business_mail() -> bytes:
    """A normal mail with a text body and a harmless attachment."""
    import email.message
    import email.policy

    msg = email.message.EmailMessage(policy=email.policy.default)
    msg["From"] = "einkauf@example-verlag.de"
    msg["To"] = "buchhaltung@example-verlag.de"
    msg["Subject"] = "Rechnung 2026-0042"
    msg["Message-ID"] = "<benign-1@example-verlag.de>"
    msg.set_content("Guten Tag,\n\nanbei die Rechnung.\n\nMit freundlichen Grüßen")
    msg.add_attachment(
        pdf_contract(),
        maintype="application",
        subtype="pdf",
        filename="rechnung-2026-0042.pdf",
    )
    # set_content/add_attachment generate a random MIME boundary; pinning it
    # keeps the module's "identical bytes on every run" promise.
    _det.pin_mime_boundary(msg)
    return msg.as_bytes()


def lnk_shortcut() -> bytes:
    """A real, minimal shell link pointing at a local document."""
    target = "C:\\Users\\Public\\Documents\\Handbuch.pdf"
    # MS-SHLLINK 2.1: the fixed header is exactly 76 bytes. The previous
    # builder used a 12-byte CLSID and a 64-byte header, which shifted the
    # flags; parse_lnk rejected the file and magic.detect reported unknown.
    flags = (1 << 3) | (1 << 7)  # HasRelativePath | IsUnicode
    header = (
        struct.pack("<I", 0x4C)  # HeaderSize
        + b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
        + struct.pack("<I", flags)
        + struct.pack("<I", 0x20)  # FileAttributes: FILE_ATTRIBUTE_ARCHIVE
        + b"\x00" * 24  # CreationTime, AccessTime, WriteTime
        + struct.pack("<I", 0)  # FileSize
        + struct.pack("<i", 0)  # IconIndex
        + struct.pack("<I", 1)  # ShowCommand: SW_SHOWNORMAL
        + struct.pack("<H", 0)  # HotKey
        + struct.pack("<H", 0)  # Reserved
        + b"\x00" * 8  # Reserved2, Reserved3
    )
    assert len(header) == 76, len(header)
    rel = target.encode("utf-16-le")
    return header + struct.pack("<H", len(target)) + rel


# -- corpus table ------------------------------------------------------------- #

# Every entry must stay GREEN. The rule is: an ordinary file of a real format.
# (filename, builder)
BENIGN: list[tuple[str, object]] = [
    # -- Echte Container, die im Golden-Snapshot fehlten ---------------------- #
    # GEMESSEN: neun Typen, die magic.detect() kennt, hatten keine Abdeckung.
    # HIER stehen nur die, die WIRKLICH harmlos sind und darum gruen bleiben
    # muessen — echte Stroeme bzw. vollstaendige Pakete.
    ("harmlos.bz2", ext.bzip2_stream),
    ("harmlos.xz", ext.xz_stream),
    ("animation.swf", ext.swf_cws_container),
    ("klasse.class", ext.class_file),
    # HEIC/AVIF: Format-komprimierte Fotos. Ohne eigene Erkennung landeten sie
    # als "unknown" im Entropie-Zweig und wurden mit 30 bewertet.
    ("IMG_0042.HEIC", ext.heic_photo),
    ("bild.avif", lambda: ext.heic_photo(b"avif")),
    # text-shaped
    ("bericht.txt", plain_text),
    ("kontakte.txt", text_with_urls_and_mail),
    ("umlaute.txt", utf8_text_umlauts),
    ("artikel.csv", csv_business_data),
    ("konfiguration.json", json_config),
    ("rechnung.xml", xml_business_document),
    ("handbuch.html", html_local_page),
    # images
    ("logo.png", png_logo),
    ("screenshot.png", png_screenshot_like),
    ("foto.jpg", jpeg_photo),
    ("animation.gif", gif_animation_stub),
    ("diagramm.bmp", bmp_bitmap),
    # documents
    ("vertrag.pdf", pdf_contract),
    ("preisliste.xlsx", xlsx_price_list),
    ("dokument.docx", docx_like_zip),
    # archives
    ("unterlagen.zip", zip_documents),
    ("quellen.tar.gz", tar_gz_sources),
    ("bundle.zip", zip_nested_legit),
    # scripts
    ("wartung.bat", batch_maintenance),
    ("inventar.ps1", powershell_inventory),
    # mail and shortcuts
    ("rechnung.eml", eml_business_mail),
    ("handbuch.lnk", lnk_shortcut),
]


#: Signatur-Fixtures, die KEINE gueltigen Container sind — nur ein
#: signaturgueltiger Kopf. Sie belegen die ERKENNUNG und dass die Pipeline sie
#: ohne Absturz verarbeitet, NICHT die Extraktion.
#:
#: WARUM GETRENNT: sie sind YELLOW (ein nicht parsebarer Container ist kein
#: Freispruch — "a scan that could not run is YELLOW, never green"). Der
#: harmlose Korpus verlangt aber GRUEN, und das zu Recht: dort liegen Dateien,
#: die ein Nutzer gefahrlos oeffnen kann. Ein RAR-Kopf ohne Inhalt ist keine
#: davon.
TYPE_COVERAGE: list[tuple[str, object]] = [
    ("archiv.rar", ext.rar_archive),
    ("paket.rpm", ext.rpm_package),
    ("archiv.cab", ext.cab_archive),
    # AP11: CAB/ISO werden über 7-Zip rekursiert. Ohne 7-Zip ist der Inhalt
    # NICHT geprüft und das Urteil GELB (ARCH_7Z_MISSING) — deshalb gehören
    # sie zur Typabdeckung, nicht in den "muss GRÜN bleiben"-Korpus.
    ("abbild.iso", ext.iso_image),
    # Auch ein vollstaendiges .deb bleibt YELLOW: die Pipeline oeffnet es
    # nicht, und "nicht geoeffnet" ist kein Freispruch. GEMESSEN.
    ("paket.deb", ext.deb_package),
]


def build_type_coverage(target_dir: Path) -> list[Path]:
    """Nur die Signatur-Fixtures schreiben (fuer den Golden-Snapshot)."""
    target_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for filename, builder in TYPE_COVERAGE:
        path = target_dir / filename
        path.write_bytes(builder())
        written.append(path)
    return written


def build_corpus(target_dir: Path) -> list[Path]:
    """Write every benign fixture into ``target_dir``; returns the paths."""
    target_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for filename, builder in BENIGN:
        data = builder()
        path = target_dir / filename
        path.write_bytes(data)
        written.append(path)
    return written


if __name__ == "__main__":
    target = (
        Path(sys.argv[1]) if len(sys.argv) > 1 else Path("tests/data/benign")
    )
    files = build_corpus(target)
    print(f"{len(files)} harmlose Fixtures nach {target} geschrieben:")
    for path in files:
        print(f"  {path.name} ({path.stat().st_size} Bytes)")
