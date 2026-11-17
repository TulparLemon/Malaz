"""Edge-case tests: degenerate inputs and unusual states must not crash.

These complement the focused unit tests by exercising boundary conditions
end-to-end through the dispatcher and the GUI/report rendering helpers.
"""

import io
import os
import tempfile
import zipfile
from pathlib import Path

import pytest

from malaz.analysis.windows_av import WindowsDefenderScanner
from malaz.core.dispatcher import Dispatcher
from malaz.models import RiskLevel
from malaz.reporting.html_report import generate_report


@pytest.fixture()
def dispatcher():
    # Disable AV in unit tests for speed/determinism.
    return Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=__import__(
            "malaz.analysis.clamav", fromlist=["ClamAVScanner"]
        ).ClamAVScanner(enabled=False),
    )


def _scan(dispatcher, data: bytes, suffix: str):
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.write(fd, data)
    os.close(fd)
    try:
        return dispatcher.scan_path(path)
    finally:
        os.unlink(path)


# -- degenerate files -------------------------------------------------------- #

def test_empty_file_is_handled(dispatcher):
    r = _scan(dispatcher, b"", ".bin")
    assert r.error is None
    assert r.detected_type == "empty"
    assert r.risk_level == RiskLevel.GREEN


def test_empty_zip_archive(dispatcher):
    # PK\x05\x06 = empty central directory; must not crash or recurse.
    r = _scan(dispatcher, b"PK\x05\x06" + b"\x00" * 18, ".zip")
    assert r.detected_type == "zip"
    assert r.children == []


def test_nonexistent_path_returns_error_result(dispatcher):
    r = dispatcher.scan_path(tempfile.gettempdir() + "/sentinel_does_not_exist.bin")
    assert r.error is not None


def test_unicode_filename(dispatcher):
    fd, path = tempfile.mkstemp(suffix="_ÜnICODE_测试.txt")
    os.write(fd, "Grüße aus der Datei".encode())
    os.close(fd)
    try:
        r = dispatcher.scan_path(path)
        assert r.error is None
        assert "ÜnICODE" in r.display_name
    finally:
        os.unlink(path)


def test_truncated_read_still_hashes(dispatcher, monkeypatch):
    from malaz import config

    # File fits the size limit but exceeds the read cap: only the capped prefix
    # is analysed, yet the scan must succeed and produce hashes.
    monkeypatch.setattr(config, "MAX_FILE_SIZE", 10_000)
    monkeypatch.setattr(config, "MAX_READ_SIZE", 100)
    r = _scan(dispatcher, b"A" * 5_000, ".bin")
    assert r.error is None
    assert len(r.sha256) == 64


def test_nested_zip_hits_depth_limit(dispatcher, monkeypatch):
    from malaz import config

    monkeypatch.setattr(config, "MAX_ARCHIVE_DEPTH", 1)
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("leaf.txt", b"hello")
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w") as zf:
        zf.writestr("inner.zip", inner.getvalue())
    r = _scan(dispatcher, outer.getvalue(), ".zip")
    # Depth 0 -> inner.zip scanned at depth 1; its content is NOT expanded.
    assert len(r.children) == 1
    child = r.children[0]
    assert child.children == []
    assert any(i.rule_id == "ARCH_DEPTH_LIMIT" for i in child.indicators)


def test_rar_without_7z_degrades_gracefully(dispatcher, monkeypatch):
    from malaz.core import sevenzip

    monkeypatch.setattr(sevenzip, "find_7z_binary", lambda: None)
    r = _scan(dispatcher, b"Rar!\x1a\x07\x00" + b"\x00" * 32, ".rar")
    assert r.detected_type == "rar"
    assert r.error is None
    # A note child explains that the content was not scanned.
    assert any(c.error and "7-Zip" in c.error for c in r.children)


# -- models / wording -------------------------------------------------------- #

def test_risk_level_layman_properties():
    assert RiskLevel.GREEN.short == "Unauffällig"
    assert RiskLevel.YELLOW.short == "Verdächtig"
    assert RiskLevel.RED.short == "Gefährlich"
    for level in RiskLevel:
        assert level.advice  # non-empty plain-language recommendation


# -- GUI detail rendering ---------------------------------------------------- #

def _detail_module():
    pytest.importorskip("PySide6")
    from malaz.gui import main_window

    return main_window


def test_format_detail_green_file():
    mw = _detail_module()
    from malaz.models import ScanResult

    r = ScanResult(path="dokument.pdf", detected_type="pdf", score=0)
    # Das Urteil und die Empfehlung stehen seit dem UI-Umbau in der Karte
    # (gui/verdict_card.py), nicht mehr im Befundtext — der erste Satz des
    # Detailfelds war vorher "ERGEBNIS: ... Score 0/100", also eine Zahl,
    # bevor stand, was zu tun ist.
    #
    # Die KARTE wird hier NICHT gebaut: sie ist ein QWidget und braucht eine
    # QApplication. Ohne sie beendet Qt den Prozess ohne Fehlermeldung — der
    # Testlauf brach nach acht Tests ab, ohne zu sagen warum. Die Karte selbst
    # prueft tests/test_gui.py, wo Qt laeuft.
    text = mw._format_detail(r)
    assert "Unauffällig" not in text, "das Urteil gehoert in die Karte"
    assert "Keine Auffälligkeiten." in text


def test_format_detail_red_file_with_error_and_anchor():
    mw = _detail_module()
    from malaz.models import Indicator, ScanResult, Severity

    r = ScanResult(
        path="böse datei (1).pdf",
        detected_type="pdf",
        score=80,
        risk_level=RiskLevel.RED,
        anchored=True,
        error="Testfehler",
    )
    r.indicators.append(
        Indicator(
            rule_id="PDF_JS_SUSPICIOUS",
            title="Verdächtiges JavaScript",
            detail="app.launchURL()",
            severity=Severity.CRITICAL,
            category="script",
        )
    )
    # Das Urteil traegt die Karte (tests/test_gui.py prueft sie mit Qt).
    assert "Gefährlich" not in mw._format_detail(r)
    # Der Anker-Hinweis gehoert zur Technik: er erklaert, warum der Score so
    # hoch ist, und ist kein Befund.
    technik = mw._format_technical(r)
    assert "Anker-Regel" in technik
    assert "Testfehler" in mw._format_detail(r)
    assert "Skripte" in mw._format_detail(r)  # category display name
    assert "app.launchURL()" in mw._format_detail(r)


def test_format_detail_archive_children():
    mw = _detail_module()
    from malaz.models import ScanResult

    child = ScanResult(path="inner.txt", detected_type="text", depth=1)
    parent = ScanResult(path="pack.zip", detected_type="zip")
    parent.children.append(child)
    assert "Enthaltene Einträge (1):" in mw._format_detail(parent)
    # Der Name des Kindes steht in der Technik-Ebene — dort steht, WAS drin
    # war; der Befundtext sagt, was daran auffiel.
    assert "inner.txt" in mw._format_technical(parent)


def test_format_detail_email_children_are_attachments():
    """A mail's children are attachments, an archive's are entries.

    Both are `children` internally, so the label has to follow the parent type
    — calling a phishing mail's attachments "archive contents" misread the file.
    """
    mw = _detail_module()
    from malaz.models import ScanResult

    child = ScanResult(path="rechnung.pdf.exe", detected_type="text", depth=1)
    parent = ScanResult(path="mail.eml", detected_type="eml")
    parent.children.append(child)
    text = mw._format_detail(parent)
    assert "Enthaltene Anhänge (1):" in text
    assert "Enthaltene Einträge" not in text


def test_format_detail_masks_control_chars_in_error_field():
    """Regression (Audit Lauf 2, malaz/reporting/result-error-field-not-masked).

    ``result.error`` trägt den Zip-Slip-Hinweis samt rohem Eintragsnamen. Die
    Maskierung klebte an den Aufrufstellen und deckte genau dieses Feld nicht
    ab, sodass ein U+202E bis in das Panel kam. Sie sitzt jetzt im Zeilenaufbau
    des Panels — damit ist auch ein künftiges Feld abgedeckt.
    """
    mw = _detail_module()
    from malaz.models import ScanResult

    r = ScanResult(
        path="archiv.tar",
        detected_type="tar",
        score=50,
        risk_level=RiskLevel.RED,
        error="Archiv-Eintrag '../rechnung\u202eexe.pdf' verlässt das Zielverzeichnis",
    )
    text = mw._format_detail(r)
    assert "\u202e" not in text, "das Steuerzeichen wird roh angezeigt"
    assert "\\u202e" in text, "die Maskierung fehlt"


def test_format_detail_shows_readable_type():
    """The detail panel must not show the internal type id ("eml", "pe")."""
    mw = _detail_module()
    from malaz.models import ScanResult

    result = ScanResult(path="mail.eml", detected_type="eml", mime_hint="message/rfc822")
    # Der Typ gehoert zur Technik-Ebene (eigener Reiter), nicht zu den
    # Befunden — ein Laie liest "E-Mail-Nachricht", nicht "message/rfc822".
    text = mw._format_technical(result)
    assert "E-Mail-Nachricht (message/rfc822)" in text
    assert "Typ: eml" not in text


# -- report ------------------------------------------------------------------ #

def test_report_with_empty_results():
    html = generate_report([])
    assert "Keine Dateien analysiert." in html
    assert "<!DOCTYPE html>" in html


def test_report_escapes_layman_advice():
    from malaz.models import ScanResult

    r = ScanResult(path="a.txt", risk_level=RiskLevel.RED, score=90)
    html = generate_report([r])
    assert "Empfehlung" in html
    # Fixed internal texts are escaped anyway; ensure nothing broke the doc.
    assert html.count("<div class=\"file\">") == 1


# -- magic / type detection edges -------------------------------------------- #

def test_one_byte_file_is_handled(dispatcher):
    r = _scan(dispatcher, b"P", ".bin")
    assert r.error is None
    assert r.detected_type in ("unknown", "text")


def test_mz_without_pe_header_is_pe(dispatcher):
    # Exactly 64 bytes "MZ" + zeros: no PE header, but a DOS executable.
    r = _scan(dispatcher, b"MZ" + b"\x00" * 62, ".exe")
    assert r.detected_type == "pe"
    assert r.error is None


def test_truncated_pe_signature_only(dispatcher):
    # "MZ" + e_lfanew pointing at "PE" that then ends immediately.
    import struct

    data = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40) + b"PE\x00\x00"
    r = _scan(dispatcher, data, ".exe")
    assert r.error is None
    assert any(i.rule_id == "PE_PARSE_WARN" for i in r.indicators)


def test_utf16_bom_text_detected(dispatcher):
    r = _scan(dispatcher, "Hallo Welt".encode("utf-16"), ".txt")
    assert r.detected_type == "text"
    assert r.error is None


# -- PDF obfuscation edges ---------------------------------------------------- #

def test_invalid_hex_escape_is_not_obfuscation(dispatcher):
    # "#zz" is NOT a valid #xx escape and must not trigger the obfuscation rule.
    r = _scan(dispatcher, b"%PDF-1.7\n/#zzavaScript (x)\n%%EOF", ".pdf")
    ids = [i.rule_id for i in r.indicators]
    assert "PDF_KW_JavaScript_OBF" not in ids


def test_pdf_only_header_bytes(dispatcher):
    r = _scan(dispatcher, b"%PDF-1.7", ".pdf")
    assert r.error is None
    assert r.detected_type == "pdf"


# -- embedded signature edges ------------------------------------------------- #

def test_embedded_hit_at_very_end_is_ignored(dispatcher):
    # A PE stub too short to contain its own e_lfanew target must not count.
    import struct

    stub = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x80)  # no PE at +0x80
    r = _scan(dispatcher, b"\x89PNG\r\n\x1a\n" + b"\x00" * 32 + stub, ".png")
    hits = [i for i in r.indicators
            if i.rule_id == "GEN_EMBEDDED" and "pe" in i.title]
    assert not hits


def test_embedded_capped_at_max_findings(dispatcher, monkeypatch):
    from malaz import config

    monkeypatch.setattr(config, "EMBEDDED_SIGNATURE_MAX", 3)
    # Many plausible gzip headers -> at most 3 embedded indicators.
    import gzip

    payload = gzip.compress(b"x")
    data = b"".join(payload for _ in range(20))
    r = _scan(dispatcher, data, ".bin")
    embedded = [i for i in r.indicators if i.rule_id == "GEN_EMBEDDED"]
    assert len(embedded) <= 3


def test_own_signature_at_offset_zero_not_flagged(dispatcher):
    r = _scan(dispatcher, b"%PDF-1.7\n%%EOF" + b"x" * 10, ".pdf")
    assert not any("pdf" in i.title for i in r.indicators
                   if i.rule_id == "GEN_EMBEDDED")


# -- filename IOC edges -------------------------------------------------------- #

def test_ioc_score_boundaries(tmp_path, monkeypatch):
    from pathlib import Path as _P

    from malaz import config
    from malaz.models import AnalysisContext
    from malaz.pipelines.generic_pipeline import GenericPipeline

    rules_dir = tmp_path / "iocs"
    rules_dir.mkdir()
    (rules_dir / "t.txt").write_text(
        "evil-low;5\n"
        "evil-mid;15\n"
        "evil-high;30\n"
        "evil-crit;50\n"
        "evil-invalid;abc\n"
        "evil-negative;-5\n"
    )
    monkeypatch.setattr(config, "FILENAME_IOC_RULES_DIR", rules_dir)
    p = GenericPipeline()
    for name, expected in (
        ("evil-low.exe", 5),
        ("evil-mid.exe", 15),
        ("evil-high.exe", 30),
        ("evil-crit.exe", 50),
        ("evil-invalid.exe", 5),    # unparseable score -> 0 -> LOW
        ("evil-negative.exe", 5),   # negative score clamped to 0 -> LOW
    ):
        inds = p.analyze(
            AnalysisContext(path=_P(name), data=b"x", detected_type="unknown", size=1)
        )
        hits = [i for i in inds if i.rule_id == "GEN_FILENAME_IOC"]
        assert hits, name
        assert hits[0].weight == expected, name


def test_ioc_description_containing_semicolon(tmp_path, monkeypatch):
    from pathlib import Path as _P

    from malaz import config
    from malaz.models import AnalysisContext
    from malaz.pipelines.generic_pipeline import GenericPipeline

    rules_dir = tmp_path / "iocs"
    rules_dir.mkdir()
    (rules_dir / "t.txt").write_text("semi;40;Beschreibung mit; Semikolon\n")
    monkeypatch.setattr(config, "FILENAME_IOC_RULES_DIR", rules_dir)
    inds = GenericPipeline().analyze(
        AnalysisContext(path=_P("semi.exe"), data=b"x", detected_type="unknown", size=1)
    )
    hit = next(i for i in inds if i.rule_id == "GEN_FILENAME_IOC")
    assert "Semikolon" in hit.detail


def test_ioc_empty_rules_dir_no_errors(tmp_path, monkeypatch):
    from pathlib import Path as _P

    from malaz import config
    from malaz.models import AnalysisContext
    from malaz.pipelines.generic_pipeline import GenericPipeline

    monkeypatch.setattr(config, "FILENAME_IOC_RULES_DIR", tmp_path / "leer")
    inds = GenericPipeline().analyze(
        AnalysisContext(path=_P("a.exe"), data=b"x", detected_type="unknown", size=1)
    )
    assert not any(i.rule_id == "GEN_FILENAME_IOC" for i in inds)


# -- MOTW edges (Windows only) ------------------------------------------------- #

@pytest.mark.skipif(os.name != "nt", reason="Windows ADS only")
def test_motw_only_internet_zones(tmp_path):
    target = tmp_path / "z.pdf"
    target.write_bytes(b"x")
    for zone, expect in (("0", False), ("1", False), ("2", False),
                         ("3", True), ("4", True), ("9", False), ("abc", False)):
        try:
            ads = Path(f"{target}:Zone.Identifier")
            ads.write_text(f"[ZoneTransfer]\r\nZoneId={zone}\r\n", encoding="utf-8")
        except OSError:
            pytest.skip("ADS nicht unterstützt")
        from malaz.models import AnalysisContext
        from malaz.pipelines.generic_pipeline import GenericPipeline

        inds = GenericPipeline().analyze(
            AnalysisContext(
                path=target, data=b"x", detected_type="pdf",
                size=1, depth=0,
            )
        )
        hit = any(i.rule_id == "GEN_MOTW" for i in inds)
        assert hit is expect, f"ZoneId={zone}"


@pytest.mark.skipif(os.name != "nt", reason="Windows ADS only")
def test_motw_broken_ads_no_flag(tmp_path):
    target = tmp_path / "b.pdf"
    target.write_bytes(b"x")
    try:
        ads = Path(f"{target}:Zone.Identifier")
        ads.write_text("kein ZoneTransfer-Format\n", encoding="utf-8")
    except OSError:
        pytest.skip("ADS nicht unterstützt")
    from malaz.models import AnalysisContext
    from malaz.pipelines.generic_pipeline import GenericPipeline

    inds = GenericPipeline().analyze(
        AnalysisContext(path=target, data=b"x", detected_type="pdf", size=1, depth=0)
    )
    assert not any(i.rule_id == "GEN_MOTW" for i in inds)


# -- tar / gzip edges ------------------------------------------------------------ #

def test_empty_tar_no_children(dispatcher):
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w"):
        pass
    r = _scan(dispatcher, buf.getvalue(), ".tar")
    assert r.error is None
    assert r.children == []


def test_tar_with_only_dirs_no_children(dispatcher):
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo("nur/verzeichnis")
        info.type = tarfile.DIRTYPE
        tf.addfile(info)
    r = _scan(dispatcher, buf.getvalue(), ".tar")
    assert r.children == []


def test_corrupt_gzip_degrades(dispatcher):
    # Valid magic, corrupt payload: single-stream fallback must yield an error
    # entry, not crash the scan.
    r = _scan(dispatcher, b"\x1f\x8b\x08\x00" + b"\xff" * 64, ".gz")
    assert r.error is None
    assert r.children  # error note or partial member


# -- entropy edges ---------------------------------------------------------------- #

def test_entropy_boundaries():
    from malaz.core.entropy import shannon_entropy

    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 100) == 0.0
    assert shannon_entropy(bytes(range(256)) * 4) > 7.9


# -- scoring edges ---------------------------------------------------------------- #

def test_scoring_empty_and_info_only():
    from malaz.core.scoring import compute_score
    from malaz.models import Indicator, Severity

    empty = compute_score([])
    assert empty.score == 0 and empty.risk_level == RiskLevel.GREEN
    info = compute_score(
        [Indicator(rule_id="X", title="x", severity=Severity.INFO)]
    )
    assert info.score == 0 and info.risk_level == RiskLevel.GREEN
    assert not info.anchored


# -- DIE parsing edges -------------------------------------------------------------- #

def test_die_parse_odd_shapes():
    from malaz.analysis.die import _parse_die_output

    assert _parse_die_output('{"detects": "kein list"}') == []
    assert _parse_die_output('[{"type": "Packer"}]') == []          # no name
    assert _parse_die_output('[{"name": "UPX"}]') == []             # no type
    assert _parse_die_output('[{"type": "Packer", "name": "UPX", "values": []}]') == []
    assert _parse_die_output('{"detects": [{"values": [{"type": "linker",'
                             ' "name": "MS", "version": "1"}]}]}') == [
        {"type": "linker", "name": "MS", "version": "1"}
    ]


# -- PE edges ----------------------------------------------------------------------- #

def test_pe_with_zero_sections(dispatcher):
    import struct

    dos = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40)
    coff = struct.pack("<HHIIIHH", 0x8664, 0, 0, 0, 0, 0x00F0, 0x0022)
    opt = b"\x00" * 0xF0
    r = _scan(dispatcher, dos + b"PE\x00\x00" + coff + opt, ".exe")
    assert r.error is None
    assert r.detected_type == "pe"


def test_pe_lies_about_overlay_size(dispatcher):
    # A section whose raw end is *beyond* the file (truncated): the overlay
    # guard must not flag and the scan must stay fast.
    import struct

    dos = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0x00F0, 0x0022)
    opt = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII", 0x20B, 0, 0, 0x1000, 0x200, 0,
        0x1000, 0x1000, 0x140000000, 0x1000, 0x200, 0, 0, 0, 0, 0, 0, 0,
        0x20000, 0x200, 0, 3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    ) + b"\x00" * 128
    sec = b".text\x00\x00\x00" + struct.pack(
        "<IIIIIIHHI", 0x100, 0x1000, 0x7FFFFFFF, 0x200, 0, 0, 0, 0, 0x60000020
    )
    r = _scan(dispatcher, dos + b"PE\x00\x00" + coff + opt + sec + b"\x00" * 32, ".exe")
    assert r.error is None
    assert not any(i.rule_id == "PE_OVERLAY" for i in r.indicators)


def test_technical_view_clips_long_member_names():
    """Ein Archivmitglied darf einen 60 000 Zeichen langen Namen tragen.

    Gemessen: _format_technical erzeugte daraus einen Text mit 120 244 Zeichen
    und einer Einzelzeile von 60 013 Zeichen. Der Name ist angreiferkontrolliert
    (ZIP erlaubt bis 65 535 Zeichen), und core/mail_view kuerzt solche Werte
    seit jeher mit _clip und einem sichtbaren Hinweis.
    """
    mw = _detail_module()
    from malaz.models import RiskLevel, ScanResult

    kind = ScanResult(
        path="x" * 60_000 + ".exe",
        detected_type="pe",
        depth=1,
        risk_level=RiskLevel.RED,
        score=90,
    )
    eltern = ScanResult(path="paket.zip", detected_type="zip")
    eltern.children.append(kind)

    text = mw._format_technical(eltern)
    laengste = max(len(z) for z in text.splitlines())
    assert laengste < 2000, f"laengste Zeile hat {laengste} Zeichen — nicht gekuerzt"
    # Gekuerzt, nicht verschwiegen.
    assert "gekürzt" in text, "der Hinweis fehlt — der Schnitt waere still"


def test_reports_clip_absurdly_long_paths():
    """Ein 60 000-Zeichen-Pfad darf den Bericht nicht fluten.

    Runde 2 des Audits: gemessen war der HTML-Bericht fuer EINE Datei 125 173
    Zeichen lang, weil der Pfad ungekuerzt hineinging. Im PDF ist es schlimmer
    — dort bricht der Text um und erzeugt hunderte Zeilen. Beide Berichte
    gehen an Dritte; ein Bericht, der wegen eines Dateinamens unlesbar wird,
    erfuellt seinen Zweck nicht.
    """
    from malaz.models import RiskLevel, ScanResult
    from malaz.reporting.html_report import generate_report

    r = ScanResult(
        path="x" * 60_000 + ".exe",
        detected_type="pe",
        risk_level=RiskLevel.RED,
        score=90,
    )
    html = generate_report([r], "T")
    assert len(html) < 40_000, f"Bericht hat {len(html)} Zeichen — Pfad nicht gekuerzt"
    assert "gekürzt" in html, "der Hinweis fehlt — der Schnitt waere still"
