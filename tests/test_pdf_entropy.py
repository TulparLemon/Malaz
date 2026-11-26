"""Entropie-Ausnahme für PDFs mit deklarierter Kompression/Verschlüsselung.

Ein PDF, das /FlateDecode & Co. deklariert, besteht zu Recht aus
High-Entropie-Streams — Malaz' eigene Reports (QPdfWriter, FlateDecode)
landeten damit bei 27/GELB (Feld-Report). Der Befund bleibt sichtbar,
darf aber nur noch LOW/Cap tragen.
"""

import os

from malaz.config import ENTROPY_EXPLAINED_CAP
from malaz.core.entropy import shannon_entropy
from malaz.core.scoring import compute_score
from malaz.models import AnalysisContext, Indicator, Severity
from malaz.pipelines.generic_pipeline import (
    GenericPipeline,
    _pdf_compression_explained,
)

_HIGH_ENTROPY = os.urandom(120_000)  # > 7.9 bit/Byte


def _ctx(data: bytes, ftype: str) -> AnalysisContext:
    return AnalysisContext(
        path="x.bin", data=data, detected_type=ftype, size=len(data)
    )


def _pdf_with_declared_flate_stream(payload: bytes) -> bytes:
    """Ein echtes PDF, dessen Seiteninhalt ein deklarierter FlateDecode-Stream ist.

    Nur die Deklaration im Objektgraphen zählt: vorher genügte die ASCII-Bytes
    ``/FlateDecode`` irgendwo im Inhalt, und 12 eingefügte Zeichen senkten ein
    PDF mit Zufallsnutzlast von GELB 30 auf GRÜN 5.
    """
    import io

    import pikepdf

    pdf = pikepdf.new()
    page = pdf.add_blank_page(page_size=(612, 792))
    stream = pikepdf.Stream(pdf, payload)
    stream[pikepdf.Name.Filter] = pikepdf.Name("/FlateDecode")
    page.obj["/Contents"] = pdf.make_indirect(stream)
    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


def test_declaration_decides_not_the_byte_sequence():
    """Der deklarierte Filter erklärt — die Bytefolge im Inhalt nicht."""
    data = _pdf_with_declared_flate_stream(_HIGH_ENTROPY)
    assert _pdf_compression_explained(_ctx(data, "pdf")) is True

    # Dieselben Bytes, aber nur mit eingefügtem Filternamen (Kommentar oder
    # totes Objekt): keine deklarierte Struktur, also keine Erklärung.
    plain = b"%PDF-1.7\n" + _HIGH_ENTROPY + b"\n/FlateDecode\n"
    assert _pdf_compression_explained(_ctx(plain, "pdf")) is False
    # Unlesbar bleibt strikt — auch mit Encrypt-Marker im Text.
    assert _pdf_compression_explained(
        _ctx(b"%PDF-1.7\n" + _HIGH_ENTROPY + b"trailer << /Encrypt 5 0 R >>", "pdf")
    ) is False


def test_pdf_with_flate_declares_low_severity_only():
    data = _pdf_with_declared_flate_stream(_HIGH_ENTROPY)
    assert shannon_entropy(data) >= 7.5  # Testvoraussetzung: Entropie hoch
    (ind,) = GenericPipeline()._entropy(_ctx(data, "pdf"))
    assert ind.severity == Severity.LOW
    assert ind.weight <= ENTROPY_EXPLAINED_CAP
    assert "erklärbar" in ind.detail


def test_pdf_without_compression_markers_stays_strict():
    # Hohe Entropie ohne deklarierten Filter = potentiell versteckte Nutzdaten.
    data = b"%PDF-1.7\n" + _HIGH_ENTROPY
    (ind,) = GenericPipeline()._entropy(_ctx(data, "pdf"))
    assert ind.severity == Severity.HIGH  # >= 7.9
    assert ind.weight > ENTROPY_EXPLAINED_CAP


def test_non_pdf_types_not_downgraded():
    data = b"MZ" + _HIGH_ENTROPY
    (ind,) = GenericPipeline()._entropy(_ctx(data, "pe"))
    assert ind.severity == Severity.HIGH
    assert ind.weight > ENTROPY_EXPLAINED_CAP


def test_compressed_image_types_explained():
    """JPEG/PNG/GIF sind per Format komprimiert (Feld-Report: JPEG 26/GELB
    allein durch Entropie) — dieselbe Erklaerung wie beim PDF, BMP bleibt
    strikt, weil unkomprimiert."""
    for ftype in ("jpeg", "png", "gif"):
        (ind,) = GenericPipeline()._entropy(_ctx(_HIGH_ENTROPY, ftype))
        assert ind.severity == Severity.LOW, ftype
        assert ind.weight <= ENTROPY_EXPLAINED_CAP, ftype
        assert "erklärbar" in ind.detail, ftype


def test_compressed_stream_types_explained():
    """gzip/bzip2/xz sind spezifikationsgemaess komprimierte Stroeme."""
    for ftype in ("gzip", "bzip2", "xz"):
        (ind,) = GenericPipeline()._entropy(_ctx(_HIGH_ENTROPY, ftype))
        assert ind.severity == Severity.LOW, ftype
        assert ind.weight <= ENTROPY_EXPLAINED_CAP, ftype


def test_swf_only_compressed_variants_explained():
    """CWS/ZWS sind komprimiert, FWS (unkomprimiert) bleibt strikt — hohe
    Entropie in FWS ist ein echtes Anomalie-Signal."""
    cws = GenericPipeline()._entropy(_ctx(b"CWS" + _HIGH_ENTROPY, "swf"))
    zws = GenericPipeline()._entropy(_ctx(b"ZWS" + _HIGH_ENTROPY, "swf"))
    fws = GenericPipeline()._entropy(_ctx(b"FWS" + _HIGH_ENTROPY, "swf"))
    assert cws[0].severity == Severity.LOW and cws[0].weight <= ENTROPY_EXPLAINED_CAP
    assert zws[0].severity == Severity.LOW and zws[0].weight <= ENTROPY_EXPLAINED_CAP
    assert fws[0].severity == Severity.HIGH and fws[0].weight > ENTROPY_EXPLAINED_CAP


def test_archive_types_skipped_entirely():
    """Container-Entropie ist bedeutungslos: Malaz analysiert die Mitglieder
    rekursiv, dort greifen die Regeln. cab/iso waren bisher LUECKE."""
    from malaz.pipelines.generic_pipeline import _ENTROPY_ARCHIVE_TYPES

    assert sorted(_ENTROPY_ARCHIVE_TYPES) == [
        "7z", "cab", "chm", "deb", "fat", "iso", "ntfs", "onenote",
        "rar", "rpm", "tar", "vhdx", "zip",
    ]
    for ftype in _ENTROPY_ARCHIVE_TYPES:
        assert GenericPipeline()._entropy(_ctx(_HIGH_ENTROPY, ftype)) == [], ftype


def test_uncompressed_and_binary_types_stay_strict():
    """PE/ELF/Mach-O/OLE/RTF/Java-class/BMP/unknown haben eine Klartext-
    bzw. unkomprimierte Basislinie — hohe Entropie bleibt ein Befund."""
    for ftype in ("pe", "elf", "macho", "ole", "rtf", "class", "bmp", "unknown"):
        (ind,) = GenericPipeline()._entropy(_ctx(_HIGH_ENTROPY, ftype))
        assert ind.severity == Severity.HIGH, ftype
        assert ind.weight > ENTROPY_EXPLAINED_CAP, ftype


def test_bmp_stays_strict():
    (ind,) = GenericPipeline()._entropy(_ctx(b"BM" + _HIGH_ENTROPY, "bmp"))
    assert ind.severity == Severity.HIGH
    assert ind.weight > ENTROPY_EXPLAINED_CAP


def test_cap_leaves_real_scores_small():
    """Der komplette Pfad (Entropie + 2 AV-Clean-Voten) muss unter GELB landen:
    5 (Cap) - 8 (Discount, auf 0 geklemmt) = 0 -> GRUEN.

    Die Entropie-Erklärung braucht eine echte Deklaration: mit einer bloßen
    Bytefolge ``/Filter /FlateDecode`` bleibt sie strikt (30/GELB) — genau die
    Umgehung, die Audit-Befund gen-entropy-selfdeclared-explanation beschreibt.
    """
    data = _pdf_with_declared_flate_stream(_HIGH_ENTROPY)
    inds = GenericPipeline()._entropy(_ctx(data, "pdf"))
    inds += [
        Indicator("AV_CLEAN", "x", severity=Severity.INFO),
        Indicator("CLAMAV_CLEAN", "x", severity=Severity.INFO),
    ]
    breakdown = compute_score(inds)
    assert breakdown.score == 0
