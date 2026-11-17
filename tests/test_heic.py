"""HEIC/HEIF/AVIF: Format-komprimierte Fotos dürfen nicht als verdächtig gelten.

DER FALL
========
Der Nutzer meldete: „HEIC-Dateien werden alle als schädlich erkannt bzw. haben
einen Wert von 31". Reproduziert mit einer realistischen Struktur (ISO-BMFF,
``ftyp``-Brand, rauschhafter ``mdat`` wie bei einem echten Foto):

    IMG_0042.HEIC   Score 30 GELB
      GEN_ENTROPY  30  Hohe Shannon-Entropie (7.99 bit/Byte)

Ursache: ``magic.detect`` kannte HEIC nicht und las den Typ als ``unknown``.
Damit griff ``_ENTROPY_SPEC_COMPRESSED`` nicht, und die Entropie — bei einem
HEVC-komprimierten Foto der Normalfall — zählte mit dem vollen Gewicht 30.

DIE GRENZE, DIE HIER GEPRÜFT WIRD
=================================
Der Fix erkennt über den **Brand** an Offset 8, nicht über ``ftyp`` allein.
Sonst würde jedes MP4/MOV/3GP als HEIC gelten — und weil ``heic`` in
``_ENTROPY_SPEC_COMPRESSED`` steht, fiele damit die Entropie **jedes Videos**
auf 0: ein stiller Freibrief für ein Container-Format, das Nutzdaten tragen
kann. Diese Datei hält beide Seiten fest.
"""

from __future__ import annotations

import struct

import pytest

from malaz.core import magic


def _box(typ: bytes, nutz: bytes) -> bytes:
    return struct.pack(">I", 8 + len(nutz)) + typ + nutz


def _bmff(brand: bytes, *, gross: bool = False) -> bytes:
    """Ein ISO-BMFF mit gegebenem ``ftyp``-Brand."""
    ftyp = _box(b"ftyp", brand + struct.pack(">I", 0) + b"heicmif1")
    if not gross:
        return ftyp + _box(b"mdat", b"\x00" * 64)
    # Rauschhafte Nutzdaten: so sieht ein echtes Foto aus (HEVC/AV1).
    import random

    rng = random.Random(7)
    return ftyp + _box(b"mdat", bytes(rng.randint(0, 255) for _ in range(20000)))


@pytest.mark.parametrize(
    ("brand", "erwartet"),
    [
        (b"heic", "heic"),
        (b"heix", "heic"),
        (b"heim", "heic"),
        (b"heis", "heic"),
        (b"hevc", "heic"),
        (b"hevx", "heic"),
        (b"mif1", "heic"),
        (b"msf1", "heic"),
        (b"avif", "avif"),
        (b"avis", "avif"),
    ],
)
def test_bild_brands_werden_erkannt(brand, erwartet):
    """Jeder Bild-Brand ergibt einen eigenen Typ — nicht ``unknown``."""
    assert magic.detect(_bmff(brand)).type == erwartet


@pytest.mark.parametrize(
    ("brand", "mime"),
    [
        (b"isom", "video/mp4"),
        (b"iso2", "video/mp4"),
        (b"mp41", "video/mp4"),
        (b"mp42", "video/mp4"),
        (b"avc1", "video/mp4"),
        (b"M4V ", "video/mp4"),
        (b"qt  ", "video/quicktime"),
    ],
)
def test_video_brands_werden_als_mp4_erkannt(brand, mime):
    """AP8: bekannte MP4/MOV-Brands sind ein eigener Typ.

    Die Gegenprobe zu HEIC: nur eine explizite Brand-Allowlist ergibt
    ``mp4``; ein unbekanntes ISO-BMFF bleibt ``unknown``. MP4 steht in
    ``_ENTROPY_SPEC_COMPRESSED`` (H.264/HEVC/AV1), aber die
    Embedded-Signatur- und IOC-Stufe laufen weiterhin — die Entropie ist
    nur als Packer-Hinweis wertlos, nicht die Anhangsprüfung.
    """
    assert magic.detect(_bmff(brand)).type == "mp4"
    assert magic.detect(_bmff(brand)).mime == mime


@pytest.mark.parametrize("brand", [b"3gp4", b"dash"])
def test_unbekannte_video_brands_bleiben_unknown(brand):
    """Kein Freibrief für jedes ISO-BMFF: nur die Allowlist zählt."""
    assert magic.detect(_bmff(brand)).type == "unknown"


def test_heic_ist_als_bild_typisiert():
    """``TYPE_LABELS`` braucht den Eintrag: GUI-Spalte und Kunden-PDF zeigen
    sonst den rohen Token ``heic``."""
    from malaz.models import TYPE_LABELS, type_description

    assert "heic" in TYPE_LABELS
    assert "avif" in TYPE_LABELS
    # Kein roher Token in der Anzeige.
    assert type_description("heic").lower() != "heic"


def test_heic_foto_bekommt_keine_entropiepunkte(tmp_path):
    """Ein Foto mit hoher Entropie darf nicht bewertet werden.

    Der eigentliche gemeldete Fall: Score 30 aus ``GEN_ENTROPY``, weil das
    Format die Entropie erklärt, die Stufe das aber nicht wusste.
    """
    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher
    from malaz.core.scoring import BASE_WEIGHTS

    p = tmp_path / "IMG_0042.HEIC"
    p.write_bytes(_bmff(b"heic", gross=True))

    d = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    r = d.scan_path(p)

    entropie = [i for i in r.all_indicators() if i.rule_id == "GEN_ENTROPY"]
    assert entropie, "die Entropie-Stufe lief gar nicht — Testaufbau prüfen"
    assert all(i.effective_weight(BASE_WEIGHTS) == 0 for i in entropie), (
        f"erklärbare Entropie vergibt {[i.effective_weight(BASE_WEIGHTS) for i in entropie]} Punkte"
    )
    assert r.risk_level.name == "GREEN", (
        f"ein normales Foto ergibt {r.risk_level.name}/{r.score}: "
        f"{[(i.rule_id, i.effective_weight(BASE_WEIGHTS)) for i in r.all_indicators()]}"
    )


def test_avif_foto_bekommt_keine_entropiepunkte(tmp_path):
    """AVIF ist AV1-komprimiert — dieselbe Begründung, eigener Typ."""
    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher

    p = tmp_path / "bild.avif"
    p.write_bytes(_bmff(b"avif", gross=True))

    d = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    r = d.scan_path(p)
    assert r.risk_level.name == "GREEN", f"{r.risk_level.name}/{r.score}"


@pytest.mark.parametrize(
    ("name", "brand", "typ"),
    [
        ("bild.heif", b"mif1", "heic"),
        ("bild.HEIC", b"heic", "heic"),
        ("bild.avif", b"avif", "avif"),
    ],
)
def test_richtige_endung_ergibt_keinen_format_mismatch(tmp_path, name, brand, typ):
    """Eine echte HEIC/HEIF/AVIF-Datei darf NICHT als Format-Täuschung gelten.

    GEMESSEN: ``.heif`` muss auf ``heic`` abgebildet sein — ``_heif_type``
    liefert für ``mif1`` genau diesen Typ. Eine Abbildung auf ``"heif"``
    würde ``GEN_FORMAT_MISMATCH`` (HIGH/30) auf jeder echten .heif-Datei
    auslösen, also genau die Falschmeldung, die der Nutzer gemeldet hat.
    """
    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher

    assert magic.detect(_bmff(brand)).type == typ

    p = tmp_path / name
    p.write_bytes(_bmff(brand, gross=True))
    d = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    r = d.scan_path(p)
    assert not [i for i in r.all_indicators() if i.rule_id == "GEN_FORMAT_MISMATCH"], (
        f"{name} wurde als Format-Täuschung gelesen"
    )
    assert r.risk_level.name == "GREEN"


def test_getarntes_pe_als_heic_faellt_auf(tmp_path):
    """Die Gegenprobe: die neue Endung ist nicht nur Kosmetik.

    Ein PE, das sich ``.heic`` nennt, fällt jetzt als Format-Täuschung auf —
    vorher war ``.heic`` in ``_EXTENSION_MAP`` unbekannt und die Prüfung
    schwieg für diese Endung grundsätzlich.
    """
    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher

    pe = b"MZ" + b"\x00" * 58 + (64).to_bytes(4, "little") + b"PE\x00\x00" + b"\x00" * 200
    p = tmp_path / "falsch.heic"
    p.write_bytes(pe)

    d = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    r = d.scan_path(p)
    treffer = [i for i in r.all_indicators() if i.rule_id == "GEN_FORMAT_MISMATCH"]
    assert treffer, "ein PE mit .heic-Endung blieb unauffällig"


def _scan(tmp_path, name: str, data: bytes):
    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher

    p = tmp_path / name
    p.write_bytes(data)
    return Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    ).scan_path(p)


def test_heic_trailer_wird_gemeldet(tmp_path):
    """AP8b: Daten hinter dem letzten Container-Box-Ende sind sichtbar.

    Gleiche Trennung wie bei PNG/JPEG: der Befund bleibt, das Gewicht hängt
    an der Aussagekraft (erst ab 64 Bytes 15, darunter 0).
    """
    from malaz.core.scoring import BASE_WEIGHTS

    payload = b"\x90" * 128
    r = _scan(tmp_path, "foto.heic", _bmff(b"heic") + payload)
    treffer = [i for i in r.all_indicators() if i.rule_id == "HEIC_TRAILER"]
    assert treffer, "angehängte Daten hinter dem HEIC-Container blieben unsichtbar"
    assert treffer[0].effective_weight(BASE_WEIGHTS) == 15
    assert "Anfang:" in treffer[0].detail
    assert "\\x90" in treffer[0].detail


def test_heic_abgeschnittene_box_wird_gemeldet(tmp_path):
    """Eine Box, die über das Dateiende reicht, ist eine kaputte Struktur."""
    from malaz.core.scoring import BASE_WEIGHTS

    data = _bmff(b"heic")[:-16]
    r = _scan(tmp_path, "kaputt.heic", data)
    treffer = [i for i in r.all_indicators() if i.rule_id == "HEIC_BOX_TRUNCATED"]
    assert treffer, "die abgeschnittene mdat-Box blieb unsichtbar"
    assert treffer[0].effective_weight(BASE_WEIGHTS) == 15


def test_heic_exif_pruefung_ist_sichtbar_nicht_geprueft(tmp_path):
    """Ohne HEIF-Decoder darf „kein EXIF-Fund" nicht als „kein EXIF" gelten."""
    from malaz.core.scoring import BASE_WEIGHTS

    r = _scan(tmp_path, "foto.heic", _bmff(b"heic"))
    treffer = [i for i in r.all_indicators() if i.rule_id == "HEIC_EXIF_UNCHECKED"]
    assert treffer, "die fehlende EXIF-Prüfung wurde stillschweigend verschluckt"
    assert treffer[0].effective_weight(BASE_WEIGHTS) == 0
    assert "NICHT geprüft" in treffer[0].detail
    assert r.risk_level.name == "GREEN"


def test_mp4_video_bekommt_keine_entropiepunkte(tmp_path):
    """AP8: MP4 ist spezifikationskomprimiert — kein GEN_ENTROPY-Verdacht."""
    import random

    from malaz.core.scoring import BASE_WEIGHTS

    rng = random.Random(11)
    payload = bytes(rng.randrange(256) for _ in range(20000))
    ftyp = _box(b"ftyp", b"isom" + struct.pack(">I", 0) + b"mp42")
    data = ftyp + _box(b"mdat", payload)
    r = _scan(tmp_path, "video.mp4", data)

    entropie = [i for i in r.all_indicators() if i.rule_id == "GEN_ENTROPY"]
    assert entropie, "die Entropie-Stufe lief gar nicht — Testaufbau prüfen"
    assert all(i.effective_weight(BASE_WEIGHTS) == 0 for i in entropie)
    assert r.risk_level.name == "GREEN", f"{r.risk_level.name}/{r.score}"


def test_heic_prefix_am_leselimit_ist_kein_trailer():
    """Ein Lesekappen-Rand ist kein angehängtes Payload.

    Bei großen Dateien ist ``ctx.data`` nur ein Präfix (``ctx.size`` bleibt
    die volle Größe). Ein angeschnittenes Box-Ende an dieser Grenze ist
    erwartbar; CORE_READ_TRUNCATED markiert den Lauf bereits als unvollständig.
    """
    from pathlib import Path

    from malaz.models import AnalysisContext
    from malaz.pipelines.image_pipeline import ImagePipeline

    ftyp = _box(b"ftyp", b"heic" + struct.pack(">I", 0) + b"heicmif1")
    data = ftyp + b"\x00\x00\x10"  # 3 Bytes eines abgeschnittenen Box-Kopfes
    ctx = AnalysisContext(
        path=Path("gross.heic"),
        data=data,
        detected_type="heic",
        size=len(data) + 999,
    )
    ids = {i.rule_id for i in ImagePipeline().analyze(ctx)}
    assert "HEIC_TRAILER" not in ids
    assert "HEIC_BOX_TRUNCATED" not in ids


def test_heic_abgeschnittener_64bit_boxkopf():
    """The largesize field itself can be cut — that is not "0 Bytes"."""
    from pathlib import Path

    from malaz.models import AnalysisContext
    from malaz.pipelines.image_pipeline import ImagePipeline

    ftyp = _box(b"ftyp", b"heic" + struct.pack(">I", 0) + b"heicmif1")
    data = ftyp + b"\x00\x00\x00\x01mdat\x00\x00\x00"
    ctx = AnalysisContext(
        path=Path("kaputt.heic"), data=data, detected_type="heic", size=len(data)
    )
    hit = next(
        i
        for i in ImagePipeline().analyze(ctx)
        if i.rule_id == "HEIC_BOX_TRUNCATED"
    )
    assert "64-Bit-Größenkopf" in hit.detail
    assert "deklariert 0 Bytes" not in hit.detail

    # A bounded prefix (ctx.size larger than data) is not a malformed file.
    prefix = AnalysisContext(
        path=Path("gross.heic"),
        data=data,
        detected_type="heic",
        size=len(data) + 1000,
    )
    ids = {i.rule_id for i in ImagePipeline().analyze(prefix)}
    assert "HEIC_BOX_TRUNCATED" not in ids
