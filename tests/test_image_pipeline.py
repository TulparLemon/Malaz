"""Tests for the image pipeline (PNG trailer, JPEG EOI, EXIF branches)."""

import io

import pytest

from malaz.models import AnalysisContext
from malaz.pipelines.image_pipeline import ImagePipeline

pytest.importorskip("PIL")  # EXIF-Zweig braucht Pillow


def _ctx(data: bytes, dtype: str) -> AnalysisContext:
    return AnalysisContext(path="test" + dtype, data=data, detected_type=dtype,
                           size=len(data), depth=0)


def _ids(inds):
    return {i.rule_id for i in inds}


# -- PNG -------------------------------------------------------------------- #

def _png(iend_crc: bool = True, trailer: bytes = b"") -> bytes:
    from zlib import crc32

    chunk = b"IEND"
    crc = crc32(chunk).to_bytes(4, "big") if iend_crc else b"\x00\x00\x00\x00"
    return b"\x89PNG\r\n\x1a\n" + chunk + crc + trailer


def test_png_clean_no_findings():
    inds = ImagePipeline().analyze(_ctx(_png(), "png"))
    assert "PNG_TRAILER" not in _ids(inds)
    assert "PNG_NO_IEND" not in _ids(inds)


def test_png_trailer_appended_payload():
    inds = ImagePipeline().analyze(_ctx(_png(trailer=b"MZpayload"), "png"))
    assert "PNG_TRAILER" in _ids(inds)


def test_png_no_iend_at_all():
    data = b"\x89PNG\r\n\x1a\nIDAT-salat ohne ende"
    inds = ImagePipeline().analyze(_ctx(data, "png"))
    assert "PNG_NO_IEND" in _ids(inds)


def test_png_iend_without_crc_is_truncated():
    # IEND-Marker vorhanden, CRC fehlt (Datei exakt nach 'IEND' abgeschnitten):
    # das ist eine beschädigte Datei und wird jetzt als PNG_NO_IEND gemeldet
    # statt still als sauber zu gelten (Audit-Fund W1).
    data = b"\x89PNG\r\n\x1a\nIDATxx" + b"IEND"  # exakt nach 'IEND' abgeschnitten
    inds = ImagePipeline().analyze(_ctx(data, "png"))
    assert "PNG_NO_IEND" in _ids(inds)
    assert "PNG_TRAILER" not in _ids(inds)


# -- JPEG ------------------------------------------------------------------- #

def _jpeg(trailer: bytes = b"") -> bytes:
    # Spec-konformes Minimal-JPEG: SOI + APP0/JFIF (Laenge 16) + EOI.
    app0 = b"\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    return b"\xff\xd8" + app0 + b"\xff\xd9" + trailer


def test_jpeg_clean_no_findings():
    inds = ImagePipeline().analyze(_ctx(_jpeg(), "jpeg"))
    assert "JPEG_TRAILER" not in _ids(inds)
    assert "JPEG_NO_EOI" not in _ids(inds)


def test_jpeg_no_eoi_truncated():
    inds = ImagePipeline().analyze(_ctx(b"\xff\xd8\xff\xe0JFIF", "jpeg"))
    assert "JPEG_NO_EOI" in _ids(inds)


def test_jpeg_trailer_suspicious_payload():
    # Angehaengtes ZIP realistisch gross (siehe Mindestgroesse in der Regel).
    inds = ImagePipeline().analyze(
        _ctx(_jpeg(trailer=b"PK\x03\x04zip" * 12), "jpeg")
    )
    hit = next(i for i in inds if i.rule_id == "JPEG_TRAILER")
    assert hit.severity.name == "MEDIUM"
    assert hit.weight == 15


def test_jpeg_trailer_with_soi_is_still_suspicious():
    # Trailer beginnt mit SOI: frueher LOW ("Thumbnail-Look"), aber echte
    # Thumbnails liegen VOR dem Haupt-EOI — ein SOI dahinter ist ein
    # angehaengtes Bild/Payload und bleibt MEDIUM (Audit-Fund).
    # REALISTISCHE GROESSE: die Regel hat eine Mindestgroesse (64 Bytes) —
    # drei Bytes Ausrichtung sind Auffuellung, keine Nutzlast (gemessen an
    # einem echten Word-Dokument). Ein angehaengtes Bild ist Kilobyte-gross;
    # der Test prueft den SOI-Fall, nicht einen 6-Byte-Anhang.
    inds = ImagePipeline().analyze(
        _ctx(_jpeg(trailer=b"\xff\xd8" + b"mini" * 32), "jpeg")
    )
    hit = next(i for i in inds if i.rule_id == "JPEG_TRAILER")
    assert hit.severity.name == "MEDIUM"
    assert hit.weight == 15


# -- EXIF ------------------------------------------------------------------- #

def test_exif_metadata_reported():
    from PIL import Image

    buf = io.BytesIO()
    image = Image.new("RGB", (8, 8), color=(1, 2, 3))
    # EXIF direkt schreiben ist ohne Plugin-Pfad muehsam; stattdessen ein
    # Beschreibungs-Feld via PNG-Text (PIL packt das als EXIF-ables Metadaten
    # fuer JPEG nur mit exif=...). Einfachster verlaesslicher Weg: ein JPEG
    # mit exif-Argument von PIL erzeugen.
    exif = Image.Exif()
    exif[0x010E] = "Beschreibung fuer den Test"  # ImageDescription
    image.save(buf, format="JPEG", exif=exif)
    inds = ImagePipeline().analyze(_ctx(buf.getvalue(), "jpeg"))
    hit = next(i for i in inds if i.rule_id == "IMG_EXIF")
    assert "Beschreibung" in hit.detail


def test_exif_without_metadata_no_indicator():
    from PIL import Image

    buf = io.BytesIO()
    Image.new("RGB", (4, 4)).save(buf, format="JPEG")
    inds = ImagePipeline().analyze(_ctx(buf.getvalue(), "jpeg"))
    assert "IMG_EXIF" not in _ids(inds)


def test_exif_unparseable_stays_silent():
    # Kein Bild, aber als jpeg klassifiziert: EXIF-Zweig muss still
    # absehen (dokumentierte Design-Entscheidung), keinen Crash liefern.
    inds = ImagePipeline().analyze(_ctx(b"kaputtes bild", "jpeg"))
    assert "IMG_EXIF" not in _ids(inds)


def test_long_exif_values_are_capped():
    from PIL import Image

    buf = io.BytesIO()
    image = Image.new("RGB", (4, 4))
    exif = Image.Exif()
    exif[0x010E] = "x" * 500  # langer Wert muss auf 120 Zeichen gekappt werden
    image.save(buf, format="JPEG", exif=exif)
    inds = ImagePipeline().analyze(_ctx(buf.getvalue(), "jpeg"))
    hit = next(i for i in inds if i.rule_id == "IMG_EXIF")
    assert "x" * 121 not in hit.detail


def test_png_trailer_bypass_with_fake_iend_is_detected():
    # Regression (Audit M4): Payload + Fake-IEND am Dateiende durfte die
    # rfind-Erkennung nicht mehr aushebeln — das ERSTE IEND zaehlt.
    real_end = b"\x89PNG\r\n\x1a\n" + b"IEND" + b"\xae\x42\x60\x82"
    data = real_end + b"MZpayload" + b"IEND\xae\x42\x60\x82"
    inds = ImagePipeline().analyze(_ctx(data, "png"))
    hit = next(i for i in inds if i.rule_id == "PNG_TRAILER")
    assert b"MZpayload" in hit.detail.encode("latin-1", "ignore") or "MZpayload" in hit.detail


def test_jpeg_trailer_bypass_with_fake_eoi_is_detected():
    # Regression (Audit M4): angehaengtes \xff\xd9 darf den Trailer nicht
    # unsichtbar machen — der Segment-Walk findet das echte Hauptbild-Ende.
    inds = ImagePipeline().analyze(
        _ctx(_jpeg(trailer=b"MZpayload" * 12 + b"\xff\xd9"), "jpeg")
    )
    hit = next(i for i in inds if i.rule_id == "JPEG_TRAILER")
    assert "MZpayload" in hit.detail


def test_kleine_auffuellung_ist_ein_hinweis_ohne_gewicht():
    """Drei Bytes hinter dem EOI sind Ausrichtung — sichtbar, aber ohne Urteil.

    GEMESSEN an having-images.docx (echtes Word-Dokument aus dem Testbestand
    von python-docx): hinter dem Bildende standen b'\x0bO\x00' — drei Bytes
    — und die Regel meldete daraus "Daten hinter JPEG-EOI (3 Bytes)" mit
    MEDIUM/15. Ein Dokument mit Bildern kam damit auf GELB.

    Der Befund verschwindet NICHT: ein Angreifer setzt ein fruehes EOI und
    haengt dahinter an, und eine unterdrueckte Regel waere dafuer der stille
    Weg (siehe test_jpeg_trailer_bypass_with_fake_eoi_is_detected). Nur das
    GEWICHT haengt an der Aussagekraft — wie bei /JS, /ObjStm und der
    erklaerten Entropie.
    """
    inds = ImagePipeline().analyze(_ctx(_jpeg(trailer=b"\x0bO\x00"), "jpeg"))
    treffer = [i for i in inds if i.rule_id == "JPEG_TRAILER"]
    assert treffer, "der Rest muss SICHTBAR bleiben — ein fruehes EOI darf nicht still werden"
    assert treffer[0].weight == 0, "drei Bytes Auffuellung tragen kein Urteil"

    # Und die Gegenrichtung: ein nennenswerter Rest wird gewertet.
    gross = ImagePipeline().analyze(_ctx(_jpeg(trailer=b"X" * 100), "jpeg"))
    assert [i for i in gross if i.rule_id == "JPEG_TRAILER" and i.weight]
