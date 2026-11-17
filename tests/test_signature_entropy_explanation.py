"""Vom Sample selbst geschriebene Bytes dürfen hohe Entropie nicht entschuldigen.

Zwei Befunde aus Audit-Lauf 3, beide an derselben Nahtstelle:

* ``malaz/pipelines/generic_pipeline/gen-entropy-selfdeclared-explanation`` —
  ``GEN_ENTROPY`` (Gewicht bis 30) wurde auf ``ENTROPY_EXPLAINED_CAP`` (5)
  gedeckelt, sobald das Sample selbst eine Erklärung *behauptete*: 10 angehängte
  OID-Bytes im PE, 12 ASCII-Zeichen (``/FlateDecode``) in einem PDF. Beides hob
  das Urteil über eine Schwelle (ROT 50 -> GELB 30, GELB 30 -> GRÜN 5).
* ``malaz/pipelines/pe_pipeline/overlay-fake-authenticode-header`` —
  ``_looks_like_authenticode_blob`` verglich das vom Anhang selbst gelieferte
  ``dwLength`` mit der Länge desselben Anhangs. Ein 22 Byte langer, frei
  gewählter Kopf machte aus ``PE_OVERLAY`` (15) ein ``PE_OVERLAY_SIGNATURE``
  (0): GELB 20 -> GRÜN 5.

Beide Testsuiten messen die *Gegenrichtung* mit: ein **verifizierter**
Signaturanhang beziehungsweise eine **tatsächlich deklarierte** Kompression darf
hohe Entropie weiterhin erklären (sonst entstehen Falschalarme auf signierter
Software bzw. auf eingescannten PDFs). Die Verifikation wird an der Naht
``run_tool`` eingespeist (dieselbe Attrappe wie in ``test_pe_extras``) — kein
PowerShell-Aufruf im Test, keine Netzverbindung.
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

import pytest

from malaz import config
from malaz.analysis.clamav import ClamAVScanner
from malaz.analysis.windows_av import WindowsDefenderScanner
from malaz.core.dispatcher import Dispatcher
from malaz.models import Severity
from malaz.pipelines.generic_pipeline import GenericPipeline

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

# DER-OID 1.2.840.113549.1.1.1 — die 10 Bytes, die der Befund angehängt hat.
_OID = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d"


@pytest.fixture(scope="module")
def dispatcher():
    """No AV engines: the contract is about the static pipelines.

    The optional third-party rule feeds are neutralised the same way the corpus
    tests do it — they are user-side downloads, so this contract must not
    depend on what the developer happened to fetch.
    """
    config.YARA_FEED_DIRS = ()
    try:
        yield Dispatcher(
            av_scanner=WindowsDefenderScanner(enabled=False),
            clam_scanner=ClamAVScanner(enabled=False),
        )
    finally:
        config.YARA_FEED_DIRS = config.YARA_FEED_DIRS_DEFAULT


@pytest.fixture
def fake_authenticode(monkeypatch):
    """Feed a signature status through the ``run_tool`` seam (no PowerShell)."""

    def _set(status: str) -> None:
        import malaz.pipelines.pe_pipeline as module

        monkeypatch.setattr(module, "which_absolute", lambda name: "pwsh")
        monkeypatch.setattr(
            module,
            "run_tool",
            lambda *a, **k: (0, json.dumps({"Status": status, "Message": "m"}).encode(), b""),
        )

    return _set


def _entropy_blob(n: int) -> bytes:
    """Deterministic incompressible bytes (same generator as the corpus)."""
    import random

    return random.Random(0xE17A0).randbytes(n)


def _pe32plus(dll_chars: int, raw_size: int, overlay: bytes) -> bytes:
    """A structurally valid PE32+ with one section and an appended overlay."""
    dos = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0x00F0, 0x0022)
    opt = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B, 0, 0, 0x1000, 0x200, 0, 0x1000, 0x1000, 0x140000000, 0x1000,
        0x200, 0, 0, 0, 0, 0, 0, 0, 0x20000, 0x200, 0, 3, dll_chars,
        0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    ) + b"\x00" * (16 * 8)
    sec = b".text\x00\x00\x00" + struct.pack(
        "<IIIIIIHHI", raw_size, 0x1000, raw_size, 0x200, 0, 0, 0, 0, 0x60000020
    )
    headers = len(dos) + 4 + len(coff) + len(opt) + len(sec)
    body = b"\x00" * (0x200 - headers) + _entropy_blob(raw_size)
    return dos + b"PE\x00\x00" + coff + opt + sec + body + overlay


def _fake_cert_overlay(payload: bytes) -> bytes:
    """A WIN_CERTIFICATE-shaped header in front of an arbitrary payload.

    Exactly the artefact the second finding measured: the header (length,
    revision, certificate type, PKCS#7 OID) is free to choose, and
    ``dwLength`` is set to the length of this very overlay, so a check that
    compares the header's claim against its own attachment always agrees.
    """
    body = _OID + payload
    return (len(body) + 8).to_bytes(4, "little") + b"\x00\x02\x02\x00" + body


def _gen_entropy(result):
    hits = [i for i in result.all_indicators() if i.rule_id == "GEN_ENTROPY"]
    assert len(hits) == 1, [i.rule_id for i in result.all_indicators()]
    return hits[0]


def _ids(result) -> set[str]:
    return {i.rule_id for i in result.all_indicators()}


# -- Befund 1: PE ------------------------------------------------------------ #


def test_appended_oid_bytes_do_not_explain_pe_entropy(dispatcher, tmp_path):
    """10 angehängte Bytes dürfen aus einem gepackten PE kein grünes machen.

    Gemessen vor dem Fix: ROT 50 -> GELB 30, weil ``GEN_ENTROPY`` von 30 auf 5
    gedeckelt wurde ("durch eine Signatur erklärt"), obwohl nur ein aus dem
    Dateiinhalt stammender Substring gefunden wurde.
    """
    sample = tmp_path / "packed_plus_oid.exe"
    sample.write_bytes(b"MZ" + _entropy_blob(64 * 1024) + _OID)

    ind = _gen_entropy(dispatcher.scan_path(sample))

    assert ind.weight > config.ENTROPY_EXPLAINED_CAP, (
        f"GEN_ENTROPY wurde auf {ind.weight} gedeckelt — die Signatur-Erklärung "
        "stammt aus 10 angehängten Bytes des Samples selbst"
    )


def test_fake_authenticode_header_is_not_a_signature(dispatcher, tmp_path, fake_authenticode):
    """Ein frei gebauter Zertifikatskopf bleibt angehängter Inhalt.

    Gemessen vor dem Fix: ``GRÜN 5 [PE_OVERLAY_SIGNATURE 0, PE_UNSIGNED 5]`` —
    der Anhang verschwand hinter einem selbstgelieferten Längenfeld, obwohl
    die Datei gar nicht signiert ist (Status der Verifikation: NotSigned).
    """
    fake_authenticode("NotSigned")
    payload = _entropy_blob(4096)
    sample = tmp_path / "fake_cert_overlay.exe"
    sample.write_bytes(_pe32plus(0x0140, 1024, _fake_cert_overlay(payload)))

    result = dispatcher.scan_path(sample)
    ids = _ids(result)

    assert "PE_OVERLAY" in ids, f"Anhang nicht gemeldet: {sorted(ids)}"
    assert "PE_OVERLAY_SIGNATURE" not in ids, (
        "ein gefälschter Kopf wurde als Signatur-Anhang gewertet"
    )
    assert result.risk_level.name != "GREEN", (
        f"{result.risk_level.name} {result.score} — angehängter Inhalt mit "
        "gefälschtem Signatur-Kopf muss sichtbar bleiben"
    )


def test_verified_signature_is_still_excused(dispatcher, tmp_path, fake_authenticode):
    """Gegenrichtung: ein *verifizierter* Signaturanhang bleibt eine Signatur.

    Ohne diese Richtung wäre der Fix eine Überkorrektur: signierte Software mit
    selbstentpackendem Nutzlastanteil (der Fall, für den ``GEN_ENTROPY``
    gedeckelt wird) und jeder Anhang unmittelbar nach dem letzten Sektor
    müssten sonst als versteckter Inhalt gelten.
    """
    fake_authenticode("Valid")
    sample = tmp_path / "signed_overlay.exe"
    sample.write_bytes(
        _pe32plus(0x0140, 1024, _fake_cert_overlay(_entropy_blob(4096)))
    )

    result = dispatcher.scan_path(sample)
    ids = _ids(result)

    assert "PE_OVERLAY_SIGNATURE" in ids, sorted(ids)
    assert "PE_OVERLAY" not in ids, sorted(ids)
    assert _gen_entropy(result).weight <= config.ENTROPY_EXPLAINED_CAP, (
        "der verifizierte Signaturanhang erklärt die Entropie nicht mehr"
    )
    sig = next(i for i in result.indicators if i.rule_id == "PE_OVERLAY_SIGNATURE")
    assert (sig.weight, sig.severity) == (0, Severity.INFO)


def test_unverifiable_attachment_is_not_weight_free(tmp_path):
    """Ohne Verifizierer ist der Anhang Inhalt, keine Signatur.

    Ein Archiv-Mitglied (``depth`` 1) hat keinen Verifizierer. Ein
    zertifikatsförmiger Anhang darf dort nicht mit Gewicht 0 verschwinden —
    sonst wäre "nicht geprüft" wieder eine Entlastung, und genau das war der
    Befund.
    """
    from malaz.models import AnalysisContext
    from malaz.pipelines.pe_pipeline import PePipeline

    data = _pe32plus(0x0140, 1024, _fake_cert_overlay(_entropy_blob(4096)))
    ctx = AnalysisContext(
        path=Path("member.exe"),
        data=data,
        detected_type="pe",
        size=len(data),
        depth=1,
    )
    ids = {i.rule_id for i in PePipeline().analyze(ctx)}
    assert "PE_OVERLAY" in ids, sorted(ids)
    assert "PE_OVERLAY_SIGNATURE" not in ids, sorted(ids)


# -- Befund 1: PDF ----------------------------------------------------------- #


@pytest.mark.parametrize("marker", [b"/FlateDecode", b"/Encrypt"])
def test_pdf_marker_in_a_comment_does_not_explain_entropy(dispatcher, tmp_path, marker):
    """Ein Filter-Name im Dateiinhalt ist keine Deklaration.

    Gemessen vor dem Fix: dieselben 32 KB Zufallsnutzlast fielen von GELB 30 auf
    GRÜN 5, sobald die ASCII-Bytes des Markers irgendwo im Inhalt standen.
    """
    sample = tmp_path / "junk.pdf"
    sample.write_bytes(b"%PDF-1.7\n" + _entropy_blob(32 * 1024) + b"\n" + marker + b"\n")

    ind = _gen_entropy(dispatcher.scan_path(sample))

    assert ind.weight > config.ENTROPY_EXPLAINED_CAP, (
        f"GEN_ENTROPY wurde auf {ind.weight} gedeckelt — {marker!r} steht nur als "
        "Bytefolge im Inhalt, es gibt keine deklarierte Struktur"
    )


def test_real_flate_stream_still_explains_entropy(dispatcher, tmp_path):
    """Gegenrichtung: ein echtes PDF mit deklariertem FlateDecode bleibt ruhig.

    Die Nutzlast (Zufallsbytes als komprimierter Stream) erzeugt dieselbe
    Dateientropie wie der Angriff oben — der Unterschied ist, dass die
    Kompression hier tatsächlich im Objektgraphen deklariert ist.
    """
    import corpus_determinism as det
    import pikepdf

    pdf = pikepdf.new()
    page = pdf.add_blank_page(page_size=(612, 792))
    stream = pikepdf.Stream(pdf, _entropy_blob(600_000))
    stream[pikepdf.Name.Filter] = pikepdf.Name("/FlateDecode")
    page.obj["/Contents"] = pdf.make_indirect(stream)
    sample = tmp_path / "scan.pdf"
    sample.write_bytes(det.save_pdf_deterministic(pdf))

    result = dispatcher.scan_path(sample)
    ind = _gen_entropy(result)

    assert ind.weight <= config.ENTROPY_EXPLAINED_CAP, (
        f"GEN_ENTROPY {ind.weight} auf einem PDF mit deklariertem FlateDecode-"
        "Stream — eingescannte Dokumente würden als gepackt gelesen"
    )


def test_unparseable_pdf_stays_strict():
    """Ein nicht lesbares PDF belegt keine Kompression — es bleibt strikt."""
    from malaz.models import AnalysisContext

    data = b"%PDF-1.7\n" + _entropy_blob(32 * 1024)
    ctx = AnalysisContext(path=Path("x.pdf"), data=data, detected_type="pdf", size=len(data))
    (ind,) = GenericPipeline()._entropy(ctx)
    assert ind.weight > config.ENTROPY_EXPLAINED_CAP


def test_pdf_object_graph_is_used_not_only_the_read_cap(tmp_path):
    """Die Struktur wird am vollständigen File geprüft, nicht am Lesefenster.

    ``ctx.data`` ist auf ``config.READ_CHUNK_SIZE`` (1 MiB) gekappt. Ein
    abgeschnittenes PDF liefert beim Parsen der Kappung keinen deklarierten
    Stream mehr — ein 1,4 MB eingescanntes Dokument würde dann als "gepackt"
    gelesen, obwohl seine Kompression im Dokument steht.
    """
    import corpus_determinism as det
    import pikepdf

    from malaz.models import AnalysisContext
    from malaz.pipelines.generic_pipeline import _pdf_compression_explained

    pdf = pikepdf.new()
    page = pdf.add_blank_page(page_size=(612, 792))
    stream = pikepdf.Stream(pdf, _entropy_blob(1_400_000))
    stream[pikepdf.Name.Filter] = pikepdf.Name("/FlateDecode")
    page.obj["/Contents"] = pdf.make_indirect(stream)
    raw = det.save_pdf_deterministic(pdf)
    sample = tmp_path / "gross.pdf"
    sample.write_bytes(raw)
    assert len(raw) > config.READ_CHUNK_SIZE

    ctx = AnalysisContext(
        path=sample,
        data=raw[: config.READ_CHUNK_SIZE],
        detected_type="pdf",
        size=len(raw),
    )
    assert _pdf_compression_explained(ctx) is True

    # Nur das Lesefenster (kein ganzes File auf der Platte): keine belegte
    # Struktur im Ausschnitt -> strikt. Genau deshalb ist der Pfad nötig.
    capped = AnalysisContext(
        path=tmp_path / "fehlt.pdf",
        data=raw[: config.READ_CHUNK_SIZE],
        detected_type="pdf",
        size=len(raw),
    )
    assert _pdf_compression_explained(capped) is False
