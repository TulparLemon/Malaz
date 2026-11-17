"""Tests für die Office-Pipeline-Stages (VBA, DDE, XLM, Formeln).

Die externen Bibliotheken (oletools/msodde, XLMMacroDeobfuscator, openpyxl)
werden gemockt — getestet wird UNSERE Logik: Indikator-Kombinationen,
Auto-Exec-Eskalation, Timeout-Pfad, Fehlerpfade.

Die Materialisierung (Temp-Datei) passiert EINMAL pro Lauf in ``analyze()``;
die Stages bekommen den Pfad. Die Helfer hier reichen den Stages denselben
Pfad, den der Aufrufer erzeugen würde (``_staged``).
"""

import io
import os
import struct
import sys
import tempfile
import time
import zipfile
from contextlib import contextmanager, suppress
from pathlib import Path

import pytest

from malaz import config
from malaz.models import AnalysisContext
from malaz.pipelines.office_pipeline import OfficePipeline

_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"


def _ctx(data: bytes, name="test.doc", detected_type="ole") -> AnalysisContext:
    # Der Dispatcher liefert immer Path-Objekte; auch die Pipeline verlässt
    # sich darauf (ctx.path.suffix).
    return AnalysisContext(path=Path(name), data=data, detected_type=detected_type,
                           size=len(data), depth=0)


def _readable_docx() -> bytes:
    """Ein echtes, lesbares OOXML — die Route, auf der die DDE-Stufe laeuft.

    Die Stufe wiegt ihren Ausfall nur, wenn der CONTAINER lesbar war (sonst
    traegt die Container-Meldung des Dispatchers das Gewicht schon); ein
    Fixture aus Zufallsbytes waere für diesen Test also das falsche Objekt.
    """
    sys.path.insert(0, str(_SCRIPTS))
    import make_benign_corpus as benign

    return benign.docx_like_zip()


def _broken_ole() -> bytes:
    """CFB-Magic mit unbrauchbarem Inhalt: olefile kann ihn nicht oeffnen."""
    return b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 504 + b"junk" * 64


def _readable_ole(streams=None) -> bytes:
    """Ein echtes, von olefile lesbares CFB (Fixture-Bauer des Projekts).

    Standard: eine BIFF-Arbeitsmappe (Workbook-Stream) — genau das, was die
    XLM-Emulation als "anwendbar" ansieht. Ohne Workbook-Stream ist die Stufe
    nicht anwendbar (``_xlm_applicable``), dafuer gibt es ``_ole_without_workbook``.
    """
    sys.path.insert(0, str(_SCRIPTS))
    from ole_writer import write_ole

    if streams is None:
        streams = {"Workbook": b"\x09\x08" + b"\x00" * 1020}
    return write_ole(streams)


def _ole_without_workbook() -> bytes:
    """Lesbarer OLE-Container ohne Workbook/Book-Stream (z.B. ein umbenanntes Word-Dokument)."""
    return _readable_ole({"WordDocument": b"\xec\xa5" + b"\x00" * 1020})


@contextmanager
def _staged(data: bytes, suffix: str = ".doc"):
    """Temp-Datei mit genau diesen Bytes — was ``analyze()`` den Stages gibt."""
    fd, path = tempfile.mkstemp(suffix=suffix, prefix="malaz_test_")
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    try:
        yield path
    finally:
        with suppress(OSError):
            os.unlink(path)


def _ids(inds):
    return {i.rule_id for i in inds}


def _by_rule(inds, rule):
    return next(i for i in inds if i.rule_id == rule)


# -- Stage 1: VBA ------------------------------------------------------------ #

class _FakeVbaParser:
    """Fake für oletools.olevba.VBA_Parser."""
    has_macros: bool = True
    macros = None  # type: ignore[assignment]  # pro Test per Subklasse gesetzt

    def __init__(self, path):
        pass

    def detect_vba_macros(self):
        return self.has_macros

    def extract_macros(self):
        return list(self.macros)

    def close(self):
        pass


def _run_vba(monkeypatch, macros, has_macros=True):
    fake = type("P", (_FakeVbaParser,), {"macros": macros, "has_macros": has_macros})
    monkeypatch.setattr("oletools.olevba.VBA_Parser", fake)
    ctx = _ctx(b"ole-bytes")
    with _staged(ctx.data) as tmp:
        return OfficePipeline()._vba_analysis(ctx, tmp)


def test_vba_no_macros_returns_empty(monkeypatch):
    inds = _run_vba(monkeypatch, [], has_macros=False)
    assert inds == []


def test_vba_plain_macro_is_medium(monkeypatch):
    inds = _run_vba(monkeypatch, [("f", "s", "Makro1", "MsgBox 1")])
    assert "OFFICE_MACRO" in _ids(inds)
    hit = _by_rule(inds, "OFFICE_MACRO")
    assert hit.severity.name == "MEDIUM" and hit.weight == 15


def test_vba_autoexec_only_is_high(monkeypatch):
    code = "Sub Auto_Open()\nEnd Sub"
    inds = _run_vba(monkeypatch, [("f", "s", "m", code)])
    assert "OFFICE_AUTOEXEC" in _ids(inds)
    assert "OFFICE_SUSPICIOUS_API" not in _ids(inds)


def test_vba_autoexec_plus_shell_api_is_critical_anchor(monkeypatch):
    code = "Sub Auto_Open()\n Shell \"cmd\"\nEnd Sub"
    inds = _run_vba(monkeypatch, [("f", "s", "m", code)])
    hit = _by_rule(inds, "OFFICE_SUSPICIOUS_API")
    assert hit.severity.name == "CRITICAL" and hit.weight == 50


def test_vba_shell_api_without_autoexec_stays_high(monkeypatch):
    code = "Sub x()\n Shell \"cmd\"\nEnd Sub"
    inds = _run_vba(monkeypatch, [("f", "s", "m", code)])
    hit = _by_rule(inds, "OFFICE_SUSPICIOUS_API")
    assert hit.severity.name == "HIGH" and hit.weight == 30


def test_vba_parser_crash_yields_warn(monkeypatch):
    class Boom:
        def __init__(self, path):
            raise RuntimeError("kaputt")

    monkeypatch.setattr("oletools.olevba.VBA_Parser", Boom)
    ctx = _ctx(b"x")
    with _staged(ctx.data) as tmp:
        inds = OfficePipeline()._vba_analysis(ctx, tmp)
    assert "OFFICE_VBA_WARN" in _ids(inds)


def test_vba_recursion_error_is_weighted_stop(monkeypatch):
    """Regression (Hunt 3): der Ausfall der Makro-Stufe darf nicht Gewicht 0 sein.

    olefile laeuft ueber den angreiferkontrollierten CFB-Verzeichnisbaum
    rekursiv; ab ~496 verschachtelten Storages (77 KB) wirft der Parser
    RecursionError. Die Stufe fiel damit auf OFFICE_VBA_WARN mit Gewicht 0
    zurueck: das Dokument mit unveraendertem Makro scannte als GELB 25 statt
    ROT 100. Ein nicht ausgewerteter Makro-Pfad ist "ungeprueft", nicht "sauber".
    """
    class Boom:
        def __init__(self, path):
            raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr("oletools.olevba.VBA_Parser", Boom)
    ctx = _ctx(b"x")
    with _staged(ctx.data) as tmp:
        inds = OfficePipeline()._vba_analysis(ctx, tmp)
    ids = _ids(inds)
    assert "OFFICE_VBA_STOP" in ids, f"Stufenausfall nicht gemeldet: {sorted(ids)}"
    hit = _by_rule(inds, "OFFICE_VBA_STOP")
    assert hit.severity.name == "MEDIUM" and hit.weight == 25
    assert "nicht als 'sauber'" in hit.detail
    assert "OFFICE_VBA_WARN" not in ids


def test_vba_stage_crash_on_a_readable_container_stays_out_of_green(monkeypatch):
    """Regression (Runde 5): jeder andere Bibliotheksfehler der Makro-Stufe war GRUEN.

    ``OFFICE_VBA_STOP`` deckt nur RecursionError ab (Test oben). Jede andere
    Ausnahme — etwa ein ``struct.error`` aus einem kaputten MS-OVBA-Verzeichnis —
    lief in ``OFFICE_VBA_WARN`` mit Gewicht 0. Gemessen vor dem Fix am echten
    Makro-Dokument (echte Streams, AutoOpen + WScript.Shell) mit werfendem
    Parser: Score 0, Urteil GRUEN, und die einzige Meldung des ganzen Scans war
    jene 0. Ein Container derselben Bauart, den der Scan LESEN kann, macht den
    Ausfall zur eigenen Nachricht der Stufe (MEDIUM/25).
    """
    class Boom:
        def __init__(self, path):
            raise ValueError("malformed VBA storage")

    monkeypatch.setattr("oletools.olevba.VBA_Parser", Boom)
    result = _scan_doc(_macro_doc())
    weights = {i.rule_id: i.weight for i in result.all_indicators()}
    assert weights.get("OFFICE_VBA_WARN") == 25, weights
    assert "OFFICE_VBA_STOP" not in weights, weights
    assert result.score > config.SCORE_GREEN_MAX, result.score
    assert result.risk_level.name == "YELLOW"


def test_vba_close_always_called(monkeypatch):
    closed = []
    fake = type("P", (_FakeVbaParser,), {
        "macros": [], "has_macros": False,
        "close": lambda self: closed.append(1),
    })
    monkeypatch.setattr("oletools.olevba.VBA_Parser", fake)
    ctx = _ctx(b"x")
    with _staged(ctx.data) as tmp:
        OfficePipeline()._vba_analysis(ctx, tmp)
    assert closed == [1]


# -- Stage 2: DDE ------------------------------------------------------------- #

def _run_dde(monkeypatch, links, error=False, data=None, detected_type="zip"):
    import oletools.msodde as msodde_module

    def fake_process(path, **kwargs):
        if error:
            raise RuntimeError("dde kaputt")
        return links

    monkeypatch.setattr(msodde_module, "process_file", fake_process)
    ctx = _ctx(
        data if data is not None else _readable_docx(),
        name="t.docx" if detected_type == "zip" else "t.doc",
        detected_type=detected_type,
    )
    with _staged(ctx.data) as tmp:
        return OfficePipeline()._dde_analysis(ctx, tmp)


def test_dde_link_reported_high(monkeypatch):
    inds = _run_dde(monkeypatch, "CMD|cmd.exe /c calc!A0")
    hit = _by_rule(inds, "OFFICE_DDE")
    assert hit.severity.name == "HIGH" and hit.weight == 30
    assert "cmd.exe" in hit.detail


def test_dde_empty_links_no_indicator(monkeypatch):
    assert _run_dde(monkeypatch, "") == []
    assert _run_dde(monkeypatch, "   ") == []


_WORD_CONTENT_TYPES = (
    '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/'
    'package/2006/content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-'
    'package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>'
    '<Override PartName="/word/document.xml" ContentType="application/vnd.'
    'openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'
)


def _docx_with_word_fields(*instructions: str) -> bytes:
    """Echtes .docx mit Word-Feldern (FLDCHAR begin -> INSTRTEXT -> end).

    Die Felder sind der Normalfall, den msodde ohne Filter als "DDE" meldet:
    Seitenzahl (``PAGE``), Serienbrief (``MERGEFIELD``), echtes DDE.
    """
    paragraphs = "".join(
        '<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r>'
        f'<w:r><w:instrText xml:space="preserve">{instr}</w:instrText></w:r>'
        '<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>'
        for instr in instructions
    )
    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/'
        '2006/main"><w:body>' + paragraphs + "</w:body></w:document>"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", _WORD_CONTENT_TYPES)
        zf.writestr(
            "_rels/.rels",
            '<?xml version="1.0"?><Relationships xmlns="http://schemas.'
            'openxmlformats.org/package/2006/relationships"/>',
        )
        zf.writestr("word/document.xml", document)
    return buf.getvalue()


def _run_real_dde(data: bytes) -> list:
    """``_dde_analysis`` mit der ECHTEN msodde-Bibliothek (kein Mock)."""
    ctx = _ctx(data, name="t.docx", detected_type="zip")
    with _staged(ctx.data, suffix=".docx") as tmp:
        return OfficePipeline()._dde_analysis(ctx, tmp)


def test_dde_ordinary_word_fields_are_not_dde():
    """Regression BUG-025: ``PAGE``/``MERGEFIELD`` sind keine DDE-Links.

    Gemessen vor dem Fix: ``msodde.process_file`` ohne Feld-Filter liefert
    ALLE Felder (``FIELD_FILTER_ALL``) -> ein harmloses .docx mit Seitenzahl
    und Serienbrieffeld wurde OFFICE_DDE HIGH 30 (GELB). Der DDE-Filter darf
    nur Felder durchlassen, deren Anweisung mit ``DDE``/``DDEAUTO`` beginnt.
    """
    inds = _run_real_dde(_docx_with_word_fields(" PAGE ", " MERGEFIELD Name "))
    assert "OFFICE_DDE" not in _ids(inds), inds
    assert inds == []


def test_dde_real_command_is_still_reported():
    """Gegenrichtung: ein echtes DDE-Feld bleibt ein HIGH-Befund."""
    inds = _run_real_dde(_docx_with_word_fields(' DDE cmd "/C calc" '))
    hit = _by_rule(inds, "OFFICE_DDE")
    assert hit.severity.name == "HIGH" and hit.weight == 30
    assert "DDE" in hit.detail


def test_dde_processing_error_is_reported_not_silent(monkeypatch):
    """Regression (Runde 4): der msodde-Ausfall war zweifach unsichtbar.

    Gemessen vor dem Fix: `process_file` wirft -> `dde_links = ""` -> KEIN
    Indikator; die Stage-Ausnahme waere nur auf einem praktisch
    unerreichbaren Pfad beim Gewicht 0 (INFO) gelandet. Beides zusammen
    bedeutet: eine Probe, deren DDE-Links nie gelesen wurden, sieht aus wie
    eine ohne DDE-Links. Die Stufe ist nicht gelaufen -> gewichtete Meldung
    ueber SCORE_GREEN_MAX, gleiche Klasse wie OFFICE_VBA_STOP (25).
    """
    inds = _run_dde(monkeypatch, None, error=True)
    # Kein Fund — die Stufe hat nichts gesehen, und genau das muss dastehen.
    assert "OFFICE_DDE" not in _ids(inds)
    hit = _by_rule(inds, "OFFICE_DDE_PARSE_WARN")
    assert hit.severity.name == "MEDIUM"
    assert hit.weight is not None and hit.weight > config.SCORE_GREEN_MAX
    assert "nicht als 'sauber'" in hit.detail


def test_dde_failure_on_an_unreadable_container_stays_a_diagnosis(monkeypatch):
    """Gegenrichtung (Runde 4): keine zweite Gewichtung derselben Ursache.

    Ist der Container selbst nicht lesbar, meldet der Dispatcher genau das
    bereits mit Gewicht 25 (MAIL_CONTAINER_WARN, aus ``probe_outlook_msg`` —
    dieselbe Funktion, dieselben Bytes). Eine zweite 25 fuer dieselbe Ursache
    summierte sich zu 50 = ANCHOR_CRITICAL_SCORE und behauptete „bösartig", wo
    nur „ungeprueft" gilt; genau dafuer steht ``ARCH_BADZIP`` in der
    Archiv-Pipeline auf 0. Die DDE-Meldung bleibt als Diagnose erhalten.
    """
    inds = _run_dde(monkeypatch, None, error=True, data=_broken_ole(),
                    detected_type="ole")
    hit = _by_rule(inds, "OFFICE_DDE_PARSE_WARN")
    assert hit.weight == 0
    assert hit.severity.name == "INFO"
    assert "Container-Meldung" in hit.detail
    assert "OFFICE_DDE" not in _ids(inds)


def test_corrupt_ole_container_costs_25_not_50(monkeypatch):
    """Guard-Test in beide Richtungen (wie test_archive.py fuer BadZipFile).

    Fehlende Meldung (GRUEN) UND Ueberkorrektur (ROT 50) sind rot: der nicht
    lesbare Container kostet genau einmal 25 (YELLOW), die Stufen-Diagnosen
    tragen 0.
    """
    monkeypatch.setattr(config, "YARA_FEED_DIRS", ())
    result = _scan_office_bytes(_broken_ole(), ".doc")
    weights = {i.rule_id: i.weight for i in result.all_indicators()}
    assert weights.get("MAIL_CONTAINER_WARN") == 25, weights
    assert "OFFICE_DDE_PARSE_WARN" in weights
    assert weights["OFFICE_DDE_PARSE_WARN"] == 0, weights
    # Runde 5: dieselbe Regel fuer den Ausfall der Makro-Stufe — die Ursache
    # (nicht lesbarer Container) traegt ihre 25 schon, die Stufe bleibt Diagnose.
    assert weights.get("OFFICE_VBA_WARN") == 0, weights
    assert result.score == 25, f"Score {result.score} statt 25 — Doppelzaehlung?"
    assert result.risk_level.name == "YELLOW"


def test_dde_stage_failure_keeps_the_scan_out_of_green(monkeypatch):
    """Ende-zu-Ende: ein msodde-Ausfall darf das Urteil nicht GRUEN lassen.

    Fixture ist ein vollstaendig harmloses OOXML (GRUEN, Score 0), das durch
    den Ausfall seine DDE-Pruefung verliert. Gemessen vor dem Fix: Score 0 /
    GRUEN — die Erkennungsstufe verschwand spurlos (genau die Umgehung).
    """
    sys.path.insert(0, str(_SCRIPTS))
    import make_benign_corpus as benign
    import oletools.msodde as msodde

    def boom(path):
        raise AssertionError("msodde kaputt")

    data = benign.docx_like_zip()
    monkeypatch.setattr(config, "YARA_FEED_DIRS", ())
    assert _scan_office_bytes(data, ".docx").risk_level.name == "GREEN", (
        "Fixture muss vor dem Ausfall GRUEN sein"
    )

    monkeypatch.setattr(msodde, "process_file", boom)
    result = _scan_office_bytes(data, ".docx")
    ids = {i.rule_id for i in result.all_indicators()}
    assert "OFFICE_DDE_PARSE_WARN" in ids, ids
    assert result.risk_level.name != "GREEN", (
        f"nicht gelesene DDE-Links als GRUEN ({result.score}) gewertet"
    )
    assert result.score > config.SCORE_GREEN_MAX


def _docx_with_broken_document_xml() -> bytes:
    """Ein LESBARES OOXML-Archiv mit abgeschnittenem ``word/document.xml``.

    Der Container selbst ist in Ordnung (zipfile oeffnet und liest ihn), nur
    das Mitglied ist unbalanciertes XML — genau die Bauart, an der ``msodde``
    mit einem AssertionError aussteigt, waehrend keine andere Stufe anschlaegt.
    """
    sys.path.insert(0, str(_SCRIPTS))
    import make_benign_corpus as benign

    src = zipfile.ZipFile(io.BytesIO(benign.docx_like_zip()))
    members = {name: src.read(name) for name in src.namelist()}
    members["word/document.xml"] = (
        b'<?xml version="1.0"?>'
        b'<w:document xmlns:w="http://schemas.openxmlformats.org/'
        b'wordprocessingml/2006/main"><w:body><w:p>'
    )
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, payload in members.items():
            zf.writestr(name, payload)
    return out.getvalue()


def test_real_msodde_failure_on_a_readable_container_is_not_green(monkeypatch):
    """Regression (Runde 4): die Umgehung, ungemockt und gemessen.

    Gemessen vor dem Fix (HEAD 3f2f038, echtes msodde, echtes Fixture):
    `dde_formula`-freies .docx mit abgeschnittenem document.xml scannt
    GRUEN 0 — msodde warf AssertionError, die Stufe verschwand ohne Indikator,
    und KEINE andere Stufe trug etwas. Nach dem Fix traegt allein die
    DDE-Meldung das Urteil ueber die GRUEN-Schwelle.
    """
    data = _docx_with_broken_document_xml()
    monkeypatch.setattr(config, "YARA_FEED_DIRS", ())

    # Vorbedingung der Messung: die Bibliothek scheitert wirklich (kein Mock).
    import oletools.msodde as msodde

    fd, tmp_path = tempfile.mkstemp(suffix=".docx")
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    try:
        with pytest.raises(Exception) as excinfo:
            msodde.process_file(tmp_path)
        assert type(excinfo.value).__name__ == "AssertionError"
    finally:
        with suppress(OSError):
            os.unlink(tmp_path)

    result = _scan_office_bytes(data, ".docx")
    ids = {i.rule_id for i in result.all_indicators()}
    assert "OFFICE_DDE_PARSE_WARN" in ids, ids
    assert result.risk_level.name != "GREEN", f"Urteil {result.risk_level.name} ({result.score})"
    assert result.score > config.SCORE_GREEN_MAX


# -- Stage 3: XLM (echtes Modul, process_file gemockt) ------------------------ #

def _run_xlm(monkeypatch, cells=None, error=None, hang=False, budget=None, data=None):
    import XLMMacroDeobfuscator.deobfuscator as xlm_module

    def fake_process_file(**kwargs):
        if error is not None:
            raise error
        if hang:
            import threading

            threading.Event().wait(5)  # laenger als das Test-Budget
        return cells if cells is not None else []

    monkeypatch.setattr(xlm_module, "process_file", fake_process_file)
    pipe = OfficePipeline()
    if budget is not None:
        pipe._XLM_TIMEOUT_SECONDS = budget
    ctx = _ctx(data if data is not None else _readable_ole(), name="t.xls")
    with _staged(ctx.data, suffix=".xls") as tmp:
        return pipe._xlm_analysis(ctx, tmp)


def test_xlm_exec_found_is_critical(monkeypatch):
    cells = ['CELL: A1, =EXEC("cmd"), value', 'CELL: B2, =HALT(), x']
    inds = _run_xlm(monkeypatch, cells)
    hit = _by_rule(inds, "OFFICE_XLM")
    assert hit.severity.name == "CRITICAL" and hit.weight == 50


def test_xlm_call_found_is_critical(monkeypatch):
    inds = _run_xlm(monkeypatch, ['CELL: C3, =CALL(x), v'])
    assert "OFFICE_XLM" in _ids(inds)


def test_xlm_benign_cells_no_indicator(monkeypatch):
    inds = _run_xlm(monkeypatch, ['CELL: A1, =SUM(A1:A9), 42'])
    assert "OFFICE_XLM" not in _ids(inds)
    assert "OFFICE_XLM_TIMEOUT" not in _ids(inds)


def test_xlm_empty_result_no_indicator(monkeypatch):
    inds = _run_xlm(monkeypatch, [])
    assert "OFFICE_XLM" not in _ids(inds)


def test_xlm_emulator_error_is_reported_not_silent(monkeypatch):
    """Regression (Runde 4): ein Emulator-Fehler liess die XLM-Stufe verschwinden.

    Gemessen vor dem Fix: `process_file` wirft -> `status == "error"` ->
    `return out` ohne Indikator; die Ausnahme-Meldung der Stufe trug Gewicht 0.
    Ein .xls, dessen Excel-4.0-Makros nie emuliert wurden, sah damit aus wie
    eines ohne XLM-Makros. Gleiche Klasse wie OFFICE_VBA_STOP: die Stufe ist
    nicht gelaufen, das Ergebnis ist unvollstaendig, nicht "sauber".
    """
    inds = _run_xlm(monkeypatch, [], error=RuntimeError("emulator crash"))
    assert "OFFICE_XLM" not in _ids(inds)
    assert "OFFICE_XLM_TIMEOUT" not in _ids(inds)
    hit = _by_rule(inds, "OFFICE_XLM_PARSE_WARN")
    assert hit.severity.name == "MEDIUM"
    assert hit.weight is not None and hit.weight > config.SCORE_GREEN_MAX
    assert "emulator crash" in hit.detail
    assert "nicht als 'sauber'" in hit.detail


def test_xlm_failure_on_an_unreadable_container_stays_a_diagnosis(monkeypatch):
    """Gegenrichtung: dieselbe Regel wie bei DDE (eine Ursache, ein Gewicht)."""
    inds = _run_xlm(monkeypatch, [], error=RuntimeError("emulator crash"),
                    data=_broken_ole())
    hit = _by_rule(inds, "OFFICE_XLM_PARSE_WARN")
    assert hit.weight == 0 and hit.severity.name == "INFO"
    assert "Container-Meldung" in hit.detail


def test_xlm_failure_without_a_workbook_is_a_diagnosis(monkeypatch):
    """Regression (Runde 4): "nicht anwendbar" ist nicht "nicht geprueft".

    Gemessen: ein harmloses Word-Dokument, das ``.xls`` heisst, brachte die
    Emulation zum Scheitern (``XLRDError: Can't find workbook in OLE2 compound
    document`` — xlrd2 sucht einen Stream ``Workbook``/``Book``). Eine
    unbedingte 25 drehte die harmlose Datei von GRUEN 0 auf GELB 25; es gibt
    aber nichts zu emulieren, also nichts verloren.
    """
    inds = _run_xlm(monkeypatch, [], error=RuntimeError("emulator crash"),
                    data=_ole_without_workbook())
    hit = _by_rule(inds, "OFFICE_XLM_PARSE_WARN")
    assert hit.weight == 0 and hit.severity.name == "INFO"
    assert "keine Arbeitsmappe" in hit.detail


def test_mislabelled_ole_stays_green(monkeypatch):
    """Guard-Test gegen die Ueberkorrektur: umbenanntes Word-Dokument als .xls.

    Der Container ist lesbar, hat aber keine Arbeitsmappe -> die XLM-Meldung
    bleibt Diagnose, das Urteil GRUEN. (Mit einem echten Workbook-Stream muss
    dieselbe Datei dagegen GELB werden — siehe
    test_xlm_emulator_error_is_reported_not_silent.)
    """
    monkeypatch.setattr(config, "YARA_FEED_DIRS", ())
    plain = _scan_office_bytes(_ole_without_workbook(), ".xls")
    assert plain.risk_level.name == "GREEN", (
        f"harmloses, nur falsch benanntes OLE als {plain.risk_level.name} "
        f"({plain.score}) gewertet"
    )


def test_xlm_hang_triggers_wallclock_timeout(monkeypatch):
    # Regression (Hunt): der eingebaute Timeout der Bibliothek ist WEICH
    # (keine Exception, stoppt nur zwischen Zell-Evaluationen) — nur die
    # Wall-Clock um den Daemon-Worker meldet den Abbruch zuverlaessig.
    # Runde 4: Gewicht 15 lag UNTER SCORE_GREEN_MAX (19) — ein per
    # Verzoegerungs-Konstrukt abgewuergtes .xls blieb damit GRUEN, obwohl
    # seine XLM-Zellen nie emuliert wurden. Der Abbruch ist derselbe Fakt wie
    # OFFICE_XLM_PARSE_WARN ("Stufe hat kein Urteil geliefert") und traegt
    # deshalb dieselbe Gewichtsklasse (25) statt einer, die den absichtlichen
    # Ausfall SCHWAECHER bewertet als einen zufaelligen.
    inds = _run_xlm(monkeypatch, cells=[], hang=True, budget=0.3)
    hit = _by_rule(inds, "OFFICE_XLM_TIMEOUT")
    assert hit.severity.name == "MEDIUM" and hit.weight == 25
    assert hit.weight > config.SCORE_GREEN_MAX


def test_xlm_process_file_kwargs_hardened(monkeypatch):
    import XLMMacroDeobfuscator.deobfuscator as xlm_module

    seen = {}

    def fake_process_file(**kwargs):
        seen.update(kwargs)
        return []

    monkeypatch.setattr(xlm_module, "process_file", fake_process_file)
    ctx = _ctx(b"xlsm", name="t.xlsm")
    with _staged(ctx.data, suffix=".xlsm") as tmp:
        OfficePipeline()._xlm_analysis(ctx, tmp)
    assert seen.get("noninteractive") is True
    assert seen.get("return_deobfuscated") is True
    assert seen.get("timeout") == OfficePipeline._XLM_TIMEOUT_SECONDS
    # DoS-/Leak-Haertung (Hunt): guess_day-Skip + kein VelvetSweatshop
    assert seen.get("day") == 1
    assert seen.get("password") == "malaz-no-default-pw"


def _xlsm_with_xlm_macrosheet() -> bytes:
    """Minimale, gültige ``.xlsm`` mit einem Excel-4.0-Makroblatt.

    Der Container ist ein Zip (wie jede echte .xlsm): ``[Content_Types].xml``,
    ``xl/workbook.xml`` mit ``Auto_Open`` und die über die ``xlMacrosheet``-
    Beziehung eingebundene ``xl/macrosheets/sheet1.xml``. A1 setzt
    ``f = EXEC``, A2 ruft es auf — die klassische XLM-Ausführung.
    """
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-'
        'package.relationships+xml"/><Default Extension="xml" '
        'ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.ms-'
        'excel.sheet.macroEnabled.main+xml"/>'
        '<Override PartName="/xl/macrosheets/sheet1.xml" '
        'ContentType="application/vnd.ms-excel.macrosheet+xml"/></Types>'
    )
    workbook = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets>'
        '<definedNames><definedName name="_xlnm.Auto_Open">Sheet1!$A$1'
        "</definedName></definedNames></workbook>"
    )
    workbook_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/'
        'relationships"><Relationship Id="rId1" Type="http://schemas.microsoft.com/'
        'office/2006/relationships/xlMacrosheet" Target="macrosheets/sheet1.xml"/>'
        "</Relationships>"
    )
    macrosheet = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<xm:macrosheet xmlns:xm="http://schemas.microsoft.com/office/excel/2006/main" '
        'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheetData><row r="1"><c r="A1"><f>SET.NAME("f",EXEC)</f></c></row>'
        '<row r="2"><c r="A2"><f>f("calc.exe")</f></c></row></sheetData>'
        "</xm:macrosheet>"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("xl/workbook.xml", workbook)
        zf.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        zf.writestr("xl/macrosheets/sheet1.xml", macrosheet)
    return buf.getvalue()


def test_real_xlsm_with_xlm_macrosheet_is_red(monkeypatch):
    """Regression BUG-024: echte .xlsm ist ein ZIP — die Stufe lief nie.

    Gemessen vor dem Fix: ``analyze()`` verlangte ``detected_type == "ole"``;
    die XLM-only-Arbeitsmappe (olevba: vba=False, xlm=True) lieferte ``[]``
    und der Dispatcher GRÜN 0, obwohl ``_xlm_analysis()`` allein OFFICE_XLM
    CRITICAL 50 (ROT) ergibt.
    """
    monkeypatch.setattr(config, "YARA_FEED_DIRS", ())
    result = _scan_office_bytes(_xlsm_with_xlm_macrosheet(), ".xlsm")
    weights = {i.rule_id: i.weight for i in result.all_indicators()}
    assert "OFFICE_XLM" in weights, weights
    assert weights["OFFICE_XLM"] == 50, weights
    assert result.risk_level.name == "RED", (
        f"{result.risk_level.name} {result.score}: {weights}"
    )


def test_xlm_macrosheet_in_a_foreign_container_is_weighted(monkeypatch):
    """Gegenrichtung BUG-024: erkanntes Makroblatt, aber Stufe lief nicht -> 25.

    Dieselben Bytes unter ``.docx``: die XLM-Stufe ist für diese Endung nicht
    zuständig, ``detect_vba_macros()`` meldet kein VBA. Vorher endete die
    Makro-Stufe mit ``[]`` — "sauber", obwohl nie jemand die XLM-Formeln
    angesehen hat. Jetzt trägt OFFICE_XLM_PRESENT 25 ("nicht ausgewertet").
    """
    monkeypatch.setattr(config, "YARA_FEED_DIRS", ())
    result = _scan_office_bytes(_xlsm_with_xlm_macrosheet(), ".docx")
    weights = {i.rule_id: i.weight for i in result.all_indicators()}
    assert weights.get("OFFICE_XLM_PRESENT") == 25, weights
    assert "OFFICE_XLM" not in weights, weights
    assert result.score > config.SCORE_GREEN_MAX, f"{result.score}: {weights}"


def _biff_workbook_with_macrosheet() -> bytes:
    """BIFF-Workbook-Stream mit einer BOUNDSHEET vom Typ „Excel 4.0 macro sheet"."""
    def record(opcode: int, data: bytes) -> bytes:
        return struct.pack("<HH", opcode, len(data)) + data

    bof = record(0x0809, struct.pack("<HHHH", 0x0600, 0x0005, 0x0DBB, 0x07CC) + b"\x00" * 4)
    # BOUNDSHEET: BOF-Position, Sichtbarkeit, Sheet-Typ 1 (Makroblatt), Name.
    boundsheet = record(
        0x0085, struct.pack("<IBB", 0, 0, 1) + bytes([6, 0]) + b"Macro1"
    )
    return bof + boundsheet + record(0x000A, b"")


def test_xlm_macrosheet_in_a_renamed_biff_workbook_is_weighted():
    """Auch der OLE-Fall (Sec-Befund 6): ``.xls`` -> ``.docx`` umbenannt.

    Die XLM-Stufe läuft nur für Excel-Endungen; eine als ``.docx`` gespeicherte
    BIFF-Arbeitsmappe mit Makroblatt wurde vorher ohne jedes Makro-Urteil
    GRÜN. Die Erkennung liest die BOUNDSHEET-Records über das bereits offene
    olefile-Handle des VBA-Parsers (kein zweiter Zugriff auf den Container).
    """
    import olefile

    data = _readable_ole({"Workbook": _biff_workbook_with_macrosheet()})
    ctx = _ctx(data, name="t.docx", detected_type="ole")
    with olefile.OleFileIO(io.BytesIO(data)) as ole:
        inds = OfficePipeline()._xlm_unchecked_indicators(ctx, type("P", (), {"ole_file": ole})())
    hit = _by_rule(inds, "OFFICE_XLM_PRESENT")
    assert hit.severity.name == "MEDIUM" and hit.weight == 25
    assert "NICHT ausgewertet" in hit.detail


# -- Stage 4: Formeln (openpyxl, echt — kleine Workbooks im Speicher) --------- #

def _xlsx_with(cell_values: dict[str, str]) -> bytes:
    import io

    from openpyxl import Workbook

    wb = Workbook()
    ws = wb.active
    for ref, value in cell_values.items():
        ws[ref] = value
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def _xlsx_with_uncastable_number(dangerous: bool = True) -> bytes:
    """Gültiger xlsx, der openpyxl erst MITTEN im Iterieren scheitern lässt.

    ``A1`` trägt (optional) eine echte DDE-Formel, ``C3`` deklariert mit
    ``t="n"`` einen Zahlenwert, der keine Zahl ist. ``read_only=True`` parst das
    Sheet-XML lazy, also liefert ``iter_rows()`` Zeile 1 noch aus und wirft
    danach — der Container selbst bleibt ein lesbarer Zip.
    """
    values = {"C3": 5}
    if dangerous:
        values["A1"] = '=cmd|"/C calc"!A0'
    raw = _xlsx_with(values)
    name = "xl/worksheets/sheet1.xml"
    zin = zipfile.ZipFile(io.BytesIO(raw))
    xml = zin.read(name).decode("utf-8")
    xml = xml.replace('<c r="C3" t="n"><v>5</v></c>', '<c r="C3" t="n"><v>abc</v></c>')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename == name:
                data = xml.encode("utf-8")
            zout.writestr(item, data)
    zin.close()
    return buf.getvalue()


def _run_formula(data: bytes):
    return OfficePipeline()._formula_analysis(
        AnalysisContext(path="t.xlsx", data=data, detected_type="zip",
                        size=len(data), depth=0)
    )


def test_formula_dangerous_command_found(monkeypatch):
    data = _xlsx_with({"A1": '=cmd|"/C calc"!A0', "B2": "normal"})
    inds = _run_formula(data)
    hit = _by_rule(inds, "OFFICE_FORMULA")
    assert hit.severity.name == "HIGH" and hit.weight == 30
    assert "A1" in hit.detail or "cmd" in hit.detail


def test_formula_hyperlink_not_flagged(monkeypatch):
    # Regression (Hunt 2): =HYPERLINK ist eine Standardformel.
    data = _xlsx_with({"A1": '=HYPERLINK("https://firma.example/preisliste")'})
    inds = _run_formula(data)
    assert "OFFICE_FORMULA" not in _ids(inds)


def test_formula_clean_workbook_no_indicator(monkeypatch):
    inds = _run_formula(_xlsx_with({"A1": "=SUM(B1:B9)", "B1": "42"}))
    assert "OFFICE_FORMULA" not in _ids(inds)


def test_formula_corrupt_xlsx_warns_not_crashes(monkeypatch):
    inds = _run_formula(b"PK\x03\x04 aber kein gueltiges xlsx")
    assert "OFFICE_FORMULA_PARSE_WARN" in _ids(inds)


def test_formula_hit_survives_a_later_parse_error(monkeypatch):
    """Regression (Runde 5): ein gefundener DDE-Treffer verschwand beim Abbruch.

    Gemessen vor dem Fix: dasselbe Workbook (A1 = ``=cmd|"/C calc"!A0``) lieferte
    nur ``OFFICE_FORMULA_PARSE_WARN`` (0) — der Treffer aus Zeile 1 wurde mit der
    Ausnahme verworfen, die Zeile 3 beim Iterieren auslöst, und der Scan endete
    GRUEN 0. Die Abbruchmeldung darf den Treffer nicht ersetzen, sondern kommt
    dazuklein.
    """
    data = _xlsx_with_uncastable_number()
    inds = _run_formula(data)
    ids = _ids(inds)
    assert "OFFICE_FORMULA" in ids, ids
    hit = _by_rule(inds, "OFFICE_FORMULA")
    assert hit.severity.name == "HIGH" and hit.weight == 30
    assert "A1" in hit.detail
    assert "OFFICE_FORMULA_PARSE_WARN" in ids, ids

    result = _scan_office_bytes(data, ".xlsx")
    assert result.score > config.SCORE_GREEN_MAX, result.score


def test_formula_parse_failure_on_a_readable_container_is_weighted(monkeypatch):
    """Regression (Runde 5): der Ausfall der Formelstufe war auf einem LESBAREN
    Container unsichtbar.

    Gemessen vor dem Fix: ein xlsx mit gültigem Container, sauberem Sheet und
    einer nicht wandelbaren Zahlzelle scannte GRUEN 0 — die einzige Meldung des
    ganzen Scans trug Gewicht 0. Dieselbe Klasse wie OFFICE_FORMULA_STOP (25):
    die Stufe hat kein Urteil geliefert.
    """
    clean = _xlsx_with_uncastable_number(dangerous=False)
    inds = _run_formula(clean)
    assert "OFFICE_FORMULA" not in _ids(inds)
    hit = _by_rule(inds, "OFFICE_FORMULA_PARSE_WARN")
    assert hit.severity.name == "MEDIUM" and hit.weight == 25
    assert _scan_office_bytes(clean, ".xlsx").score > config.SCORE_GREEN_MAX


def test_formula_parse_warning_stays_a_diagnosis_without_an_ooxml_container(monkeypatch):
    """Gegenrichtung (Runde 5): kein OOXML-Container -> nichts zu prüfen.

    Ein umbenanntes Word-Dokument (``.xlsx``-Suffix, OLE-Inhalt) kann keine
    Arbeitsmappe tragen — dieselbe Regel und derselbe gemessene Präzedenzfall
    wie ``_xlm_applicable``. Und ein kaputter Zip-Container trägt seine 25
    bereits aus der Archiv-/Dispatcher-Meldung; die Stufe bleibt Diagnose.
    """
    ctx = AnalysisContext(path=Path("t.xlsx"), data=_ole_without_workbook(),
                          detected_type="ole", size=0, depth=0)
    hit = _by_rule(OfficePipeline()._formula_analysis(ctx), "OFFICE_FORMULA_PARSE_WARN")
    assert hit.weight == 0 and hit.severity.name == "INFO"
    assert "OOXML" in hit.detail

    hit = _by_rule(_run_formula(b"PK\x03\x04 aber kein gueltiges xlsx"),
                   "OFFICE_FORMULA_PARSE_WARN")
    assert hit.weight == 0 and hit.severity.name == "INFO"


# -- Stage 4: Formeln — Bombenschutz fuer den OOXML-Container ----------------- #

_OOXML_HEAD = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '\'<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedoc'
    'ument.spreadsheetml.sheet.main+xml"/>\''
    '\'<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-'
    'officedocument.spreadsheetml.worksheet+xml"/>\''
    '\'<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-offi'
    'cedocument.spreadsheetml.sharedStrings+xml"/>\''
    "</Types>"
)
_OOXML_ROOT_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '\'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relatio'
    'nships/officeDocument" Target="xl/workbook.xml"/>\''
    "</Relationships>"
)
_OOXML_WB_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '\'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relatio'
    'nships/worksheet" Target="worksheets/sheet1.xml"/>\''
    '\'<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relatio'
    'nships/sharedStrings" Target="sharedStrings.xml"/>\''
    "</Relationships>"
)
_OOXML_WB = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
    '<sheets><sheet name="Tabelle1" sheetId="1" r:id="rId1"/></sheets></workbook>'
)
# A1 references shared string 0, B1 is a plain DDE formula.
_OOXML_SHEET = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
    '<dimension ref="A1:B1"/><sheetData><row r="1">'
    '<c r="A1" t="s"><v>0</v></c><c r="B1"><f>cmd|"/C calc"!A0</f><v>0</v></c>'
    "</row></sheetData></worksheet>"
)


def _xlsx_declaring(shared_mib: int) -> bytes:
    """xlsx, dessen ``xl/sharedStrings.xml`` ``shared_mib`` MiB deklariert.

    Der Inhalt ist hochgradig komprimierbar — die Datei bleibt winzig, waehrend
    der Deklarationsteil des Containers (das, was openpyxl entpackt und parst)
    gross ist. Gestreamt geschrieben, damit der Test nicht selbst Hunderte MiB
    im Heap haelt.
    """
    head = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'count="1" uniqueCount="1"><si><t>'
    ).encode("ascii")
    tail = b"</t></si></sst>"
    target = shared_mib * 1024 * 1024
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", _OOXML_HEAD)
        zf.writestr("_rels/.rels", _OOXML_ROOT_RELS)
        zf.writestr("xl/_rels/workbook.xml.rels", _OOXML_WB_RELS)
        zf.writestr("xl/workbook.xml", _OOXML_WB)
        zf.writestr("xl/worksheets/sheet1.xml", _OOXML_SHEET)
        with zf.open("xl/sharedStrings.xml", "w") as member:
            member.write(head)
            chunk = b"A" * (1024 * 1024)
            for _ in range((target - len(head) - len(tail)) // len(chunk)):
                member.write(chunk)
            member.write(tail)
    return buf.getvalue()


def test_formula_bomb_container_is_refused_before_openpyxl(monkeypatch):
    """Regression (Hunt 3): der Container wird VOR openpyxl geprueft.

    Gemessen vor dem Fix: 132 KB xlsx mit deklarierten 128 MiB sharedStrings
    -> 0,98 s Rechenzeit und 256 MiB Heap-Spitze, 0 Indikatoren (256 MiB: 13,5 s
    und 391,8 MiB). Die Nachbarstelle im Archiv-Zweig verweigert dasselbe
    Mitglied laengst (core/archive.py). Der Fix prueft die deklarierten Groessen
    vorher — die Stufe meldet gewichtet und parst nicht.
    """
    openpyxl = pytest.importorskip("openpyxl")
    calls: list[tuple] = []
    real = openpyxl.load_workbook

    def spy(*args, **kwargs):
        calls.append(args)
        return real(*args, **kwargs)

    monkeypatch.setattr(openpyxl, "load_workbook", spy)
    data = _xlsx_declaring(128)
    started = time.perf_counter()
    inds = _run_formula(data)
    elapsed = time.perf_counter() - started

    ids = _ids(inds)
    assert calls == [], "openpyxl wurde auf den ungeprueften Container angesetzt"
    assert "OFFICE_FORMULA_STOP" in ids, f"Verweigerung nicht gemeldet: {sorted(ids)}"
    hit = _by_rule(inds, "OFFICE_FORMULA_STOP")
    assert hit.severity.name == "MEDIUM" and hit.weight == 25
    assert "sharedStrings.xml" in hit.detail and "NICHT geprüft" in hit.detail
    # Die Stufe bleibt bei Millisekunden (ohne Vorpruefung: ~1 s, 256 MiB Spitze).
    assert elapsed < 2.0, f"Formelstufe dauerte {elapsed:.2f}s"


def test_formula_moderately_large_container_is_still_parsed(monkeypatch):
    """Gegenrichtung: ein legaler Container wird weiterhin geprueft.

    Die Vorpruefung ist dieselbe Regel wie im Archiv-Zweig (Mitglied <=
    MAX_EXTRACTED_FILE_SIZE, Gesamtvolumen <= MAX_UNCOMPRESSED_SIZE); sie darf
    normale Arbeitsmappen mit grossem String-Pool nicht stilllegen.
    """
    pytest.importorskip("openpyxl")
    inds = _run_formula(_xlsx_declaring(2))
    assert "OFFICE_FORMULA_STOP" not in _ids(inds)
    assert "OFFICE_FORMULA_PARSE_WARN" not in _ids(inds)
    # Die DDE-Formel in B1 wird gefunden — die Stufe laeuft also wirklich.
    assert "OFFICE_FORMULA" in _ids(inds)


# -- Suffix-Härtung von _materialize ----------------------------------------- #

def test_materialize_sanitizes_hostile_suffix(tmp_path):
    pipe = OfficePipeline()
    ctx = AnalysisContext(path=Path('bo"es<>.d<oc|x'), data=b"x",
                          detected_type="ole", size=1, depth=0)
    with pipe._materialize(ctx) as tmp:
        name = Path(tmp).name
        assert all(ch not in name for ch in '<>|"')
        assert len(Path(tmp).suffix) <= 17


# -- Temp-Staging: eine Datei je Lauf --------------------------------------- #

def test_materialize_failure_is_reported_not_swallowed(monkeypatch):
    """Ohne Temp-Datei laufen VBA/DDE/XLM nicht — das muss sichtbar sein.

    Die Materialisierung passiert seit der Zusammenführung EINMAL pro Lauf in
    ``analyze()``. Schlägt sie fehl (volles/gesperrtes Temp-Verzeichnis),
    meldet die Pipeline das als OFFICE_STAGE_WARN (INFO, Gewicht 0) — vorher
    meldete jede Stufe ihren eigenen Warn. Die Formelprüfung liest ctx.data,
    braucht keine Temp-Datei und läuft weiter.
    """
    def boom(*args, **kwargs):
        raise OSError("disk full")

    data = _xlsx_with({"A1": '=cmd|"/C calc"!A0'})
    monkeypatch.setattr("malaz.pipelines.office_pipeline.tempfile.mkstemp", boom)
    inds = OfficePipeline().analyze(
        AnalysisContext(path=Path("t.xlsm"), data=data, detected_type="zip",
                        size=len(data), depth=0)
    )
    ids = _ids(inds)
    assert "OFFICE_STAGE_WARN" in ids, ids
    assert "OFFICE_FORMULA" in ids, ids


def test_analyze_materializes_once_per_run(monkeypatch):
    """Alle Stufen teilen EINE Temp-Datei (vorher: eine je Stufe).

    Gemessen am Korpus vorher: eine .xls erzeugte drei Temp-Dateien (VBA, DDE,
    XLM), eine .msg vier. Die Stufen laufen sequenziell — der olevba-Parser ist
    geschlossen, bevor DDE startet —, also genügt eine Datei für alle.
    """
    import XLMMacroDeobfuscator.deobfuscator as xlm_module

    monkeypatch.setattr(xlm_module, "process_file", lambda **kwargs: [])

    created = []
    real_mkstemp = tempfile.mkstemp

    def counting_mkstemp(*args, **kwargs):
        fd, path = real_mkstemp(*args, **kwargs)
        created.append(path)
        return fd, path

    monkeypatch.setattr("malaz.pipelines.office_pipeline.tempfile.mkstemp", counting_mkstemp)
    OfficePipeline().analyze(_ctx(b"ole-bytes", name="t.xls"))
    assert len(created) == 1, created


# -- Stage 1: VBA — tiefer OLE-Verzeichnisbaum (Fix Runde 3) ------------------ #
#
# olefile walkt den CFB-Verzeichnisbaum rekursiv (append_kids -> sid_left/
# sid_right, build_storage_tree -> append_kids je verschachtelter Storage). Die
# Tiefe ist reiner Dateiinhalt: 496 ineinander geschachtelte Storages erzeugen
# einen 128-Byte-Verzeichniseintrag pro Ebene und lassen den Parser mit
# RecursionError abbrechen. Fixtures dafuer baut der Test selbst, damit sie ohne
# echte Probe reproduzierbar sind.

_CFB_SECTOR = 512
_CFB_CUTOFF = 4096  # Streams ab dieser Groesse liegen in der Haupt-FAT
_CFB_FREESECT = 0xFFFFFFFF
_CFB_ENDOFCHAIN = 0xFFFFFFFE
_CFB_FATSECT = 0xFFFFFFFD
_CFB_NOSTREAM = 0xFFFFFFFF
_CFB_ENTRY = 128


class _CfbEntry:
    __slots__ = ("child", "data", "etype", "left", "name", "right", "size", "start")

    def __init__(self, name: str = "", etype: int = 0, data: bytes = b"") -> None:
        self.name = name
        self.etype = etype
        self.data = data
        self.start = _CFB_ENDOFCHAIN
        self.size = 0
        self.left = _CFB_NOSTREAM
        self.right = _CFB_NOSTREAM
        self.child = _CFB_NOSTREAM


def _cfb_entry_bytes(entry: _CfbEntry) -> bytes:
    raw = bytearray(_CFB_ENTRY)
    if entry.name:
        name = entry.name.encode("utf-16-le") + b"\x00\x00"
        raw[0 : len(name)] = name
        struct.pack_into("<H", raw, 64, len(name))
    raw[66] = entry.etype
    raw[67] = 1  # colour: black
    struct.pack_into("<I", raw, 68, entry.left)
    struct.pack_into("<I", raw, 72, entry.right)
    struct.pack_into("<I", raw, 76, entry.child)
    struct.pack_into("<I", raw, 116, entry.start)
    struct.pack_into("<Q", raw, 120, entry.size)
    return bytes(raw)


def _build_cfb(streams: dict[str, bytes], nesting: int = 0) -> bytes:
    """Kleinster CFB, den olefile/oletools akzeptieren.

    ``streams`` bildet ``"Storage/Sub/Name"``-Pfade auf Inhalte ab; ``nesting``
    haengt so viele leere Storages aneinander, wie ein Angreifer ueber den
    Verzeichnisbaum steuern kann. Alle Streams werden auf die Mini-Stream-
    Schwelle aufgefuellt und liegen damit in der Haupt-FAT (ein Codepfad).
    """
    entries: list[_CfbEntry] = [_CfbEntry("Root Entry", 5)]
    storages: dict[str, int] = {"": 0}

    def link(parent_idx: int, obj: _CfbEntry) -> int:
        idx = len(entries)
        entries.append(obj)
        parent = entries[parent_idx]
        if parent.child == _CFB_NOSTREAM:
            parent.child = idx
        else:
            last = parent.child
            while entries[last].right != _CFB_NOSTREAM:
                last = entries[last].right
            entries[last].right = idx
        return idx

    def storage(path: str) -> int:
        if path not in storages:
            parent, _, name = path.rpartition("/")
            storages[path] = link(storage(parent) if parent else 0, _CfbEntry(name, 1))
        return storages[path]

    for path, data in sorted(streams.items()):
        if len(data) < _CFB_CUTOFF:
            data = data.ljust(_CFB_CUTOFF, b"\x00")
        entry = _CfbEntry(path.rpartition("/")[2], 2, data)
        entry.size = len(data)
        parent = storage(path.rpartition("/")[0]) if "/" in path else 0
        link(parent, entry)

    parent = 0
    for i in range(nesting):
        parent = link(parent, _CfbEntry(f"C{i:04d}", 1))

    sections: list[bytes] = []
    fat: list[int] = []

    def chain(payload: bytes) -> int:
        padded = payload.ljust(-(-len(payload) // _CFB_SECTOR) * _CFB_SECTOR, b"\x00")
        first = len(sections)
        count = max(len(padded) // _CFB_SECTOR, 1)
        for i in range(count):
            sections.append(padded[i * _CFB_SECTOR : (i + 1) * _CFB_SECTOR])
            fat.append(first + i + 1 if i + 1 < count else _CFB_ENDOFCHAIN)
        return first

    for entry in entries:
        if entry.etype == 2:
            entry.start = chain(entry.data)
            entry.data = b""

    dir_first = len(sections)
    dir_count = max(-(-len(entries) // (_CFB_SECTOR // _CFB_ENTRY)), 1)
    for i in range(dir_count):
        block = bytearray()
        for j in range(_CFB_SECTOR // _CFB_ENTRY):
            k = i * (_CFB_SECTOR // _CFB_ENTRY) + j
            block += _cfb_entry_bytes(entries[k]) if k < len(entries) else bytes(_CFB_ENTRY)
        sections.append(bytes(block))
        fat.append(dir_first + i + 1 if i + 1 < dir_count else _CFB_ENDOFCHAIN)

    fat_per_sector = _CFB_SECTOR // 4
    fat_count = max(-(-(len(sections) + 1) // fat_per_sector), 1)
    fat_first = len(sections)
    fat.extend([_CFB_FATSECT] * fat_count)
    fat.extend([_CFB_FREESECT] * (fat_count * fat_per_sector - len(fat)))

    header = bytearray(_CFB_SECTOR)
    header[0:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    struct.pack_into("<H", header, 24, 0x003E)  # minor version
    struct.pack_into("<H", header, 26, 0x0003)  # major version
    struct.pack_into("<H", header, 28, 0xFFFE)  # little endian
    struct.pack_into("<H", header, 30, 9)  # 512-byte sectors
    struct.pack_into("<H", header, 32, 6)  # 64-byte mini sectors
    struct.pack_into("<I", header, 44, fat_count)
    struct.pack_into("<I", header, 48, dir_first)
    struct.pack_into("<I", header, 56, _CFB_CUTOFF)
    struct.pack_into("<I", header, 60, _CFB_ENDOFCHAIN)  # no mini FAT
    struct.pack_into("<I", header, 64, 0)
    struct.pack_into("<I", header, 68, _CFB_ENDOFCHAIN)  # no DIFAT chain
    struct.pack_into("<I", header, 72, 0)
    for i in range(109):
        struct.pack_into("<I", header, 76 + i * 4, fat_first + i if i < fat_count else _CFB_FREESECT)
    return bytes(header) + b"".join(sections) + struct.pack(
        "<" + "I" * len(fat), *fat
    )


# Weder "powershell" noch "cmd.exe" noch eine Download-URL: die YARA-Regeln
# (Suspicious_VBA_Shell braucht $sh/$co UND $url/$pwsh/$cmd) sollen hier nicht
# feuern — der Test misst die Office-Stufe, nicht den YARA-Zweig.
_MACRO_SOURCE = (
    "Sub Document_Open()\r\n"
    "  Dim sh As Object\r\n"
    "  Set sh = CreateObject(\"WScript.Shell\")\r\n"
    "  sh.Run Environ(\"APPDATA\") & \"\\update.vbs\"\r\n"
    "  CreateObject(\"ADODB.Stream\")\r\n"
    "  CallByName sh, \"Run\", VbMethod\r\n"
    "End Sub\r\n"
)
_MACRO_NAME = "Module1"


def _macro_doc(nesting: int = 0, dir_stream: bytes | None = None) -> bytes:
    """Makro-Dokument (echtes MS-OVBA-Geruest) mit ``nesting`` Storage-Ebenen.

    ``dir_stream`` ersetzt den komprimierten ``VBA/dir``-Stream — damit laesst
    sich ein Projekt bauen, dessen Verzeichnis die Bibliothek nicht lesen kann,
    waehrend der Modul-Stream (der eigentliche Makro-Quelltext) unveraendert
    bleibt. Voreinstellung: das gueltige Verzeichnis.
    """
    sys.path.insert(0, str(_SCRIPTS))
    from ole_writer import _dir_stream, compress_vba  # Fixture-Bauer des Projekts

    project = (
        'ID="{00000000-0000-0000-0000-000000000000}"\r\n'
        "Document=ThisDocument/&H00000000\r\n"
        f"Module={_MACRO_NAME}\r\n"
        'Name="VBAProject"\r\n'
        'HelpContextID="0"\r\n'
        'VersionCompatible32="393222000"\r\n'
        "\r\n"
        "[Host Extender Info]\r\n"
        "[Workspace]\r\n"
    ).encode("latin-1")
    return _build_cfb(
        {
            "Macros/VBA/dir": (
                dir_stream if dir_stream is not None else compress_vba(_dir_stream(_MACRO_NAME))
            ),
            "Macros/VBA/_VBA_PROJECT": b"\xcc\x61" + b"\x00" * 30,
            "Macros/VBA/" + _MACRO_NAME: compress_vba(_MACRO_SOURCE.encode("latin-1")),
            "Macros/PROJECT": project,
            "WordDocument": b"\xec\xa5" + b"\x00" * 1020,
        },
        nesting=nesting,
    )


def _scan_office_bytes(data: bytes, suffix: str = ".doc"):
    """End-to-End ueber den Dispatcher — das Urteil, das der Nutzer sieht."""
    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher

    fd, path = tempfile.mkstemp(suffix=suffix, prefix="malaz_test_")
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    try:
        dispatcher = Dispatcher(
            av_scanner=WindowsDefenderScanner(enabled=False),
            clam_scanner=ClamAVScanner(enabled=False),
        )
        return dispatcher.scan_path(path)
    finally:
        with suppress(OSError):
            os.unlink(path)


def _scan_doc(data: bytes):
    return _scan_office_bytes(data, ".doc")


def test_vba_stage_refuses_only_beyond_the_structural_ceiling(monkeypatch):
    """Die Stufe wird nur jenseits der harten Grenze abgebrochen.

    Diese Schwelle hat sich in Runde 4 zweimal verschoben und ist jetzt
    begruendet: eine feste Frame-Zahl war in beide Richtungen falsch. Runde 3
    brach bei 500 Frames ab — ein mit 476 Storages gepolstertes Makro-Dokument
    verlor damit seine gesamte Makro-Evidenz, obwohl olevba den Baum liest.
    Eine Schwelle aus ``sys.getrecursionlimit()`` machte dieselben Bytes
    davon abhaengig, wie tief der Aufrufer gerade steht (gemessen: 954
    Walk-Frames gelingen aus einem Skript und scheitern unter pytest).

    Jetzt misst ``core/ole_depth.directory_frames`` die Tiefe vorab und
    ``walk_headroom`` gibt dem Durchlauf den Stack, den er braucht — bis zur
    strukturellen Obergrenze. Erst DARUEBER wird abgebrochen, und dieser
    Abbruch ist der Test hier: er wird ueber die Grenze selbst ausgeloest,
    nicht ueber eine Fixture, die 8000 Frames bauen muesste.
    """
    from malaz.core import ole_depth

    called: list[str] = []

    def boom(path):
        called.append(path)
        raise AssertionError("VBA_Parser jenseits der Obergrenze")

    monkeypatch.setattr("oletools.olevba.VBA_Parser", boom)
    # Die Grenze kuenstlich unter die gemessene Tiefe legen: das ist genau der
    # Zustand "jenseits der Obergrenze", ohne einen 8000-Frame-Container bauen
    # zu muessen. Der Pre-Check und die Meldung sind derselbe Code wie vorher.
    #
    # TEST-017: die fruehere zusaetzliche lambda-Patch auf
    # ``_ole_directory_too_deep`` ersetzte genau die zu pruefende
    # Schwellenlogik (``frames > 100``) durch eine Kopie ihrer selbst — eine
    # Regression in ``directory_too_deep`` waere gruen geblieben. Die echte
    # Funktion liest ``HARD_MAX_FRAMES`` zur Laufzeit aus ``ole_depth``.
    monkeypatch.setattr(ole_depth, "HARD_MAX_FRAMES", 100)
    data = _macro_doc(nesting=700)
    ctx = AnalysisContext(
        path=Path("deep.doc"), data=data, detected_type="ole", size=len(data)
    )
    with _staged(data) as tmp:
        inds = OfficePipeline()._vba_analysis(ctx, tmp)
    ids = _ids(inds)
    assert called == [], "olefile lief oberhalb der Obergrenze"
    assert "OFFICE_VBA_STOP" in ids, f"Tiefe nicht gemeldet: {sorted(ids)}"
    hit = _by_rule(inds, "OFFICE_VBA_STOP")
    # Die gemessene Tiefe steht in der Meldung (Frames + Storage-Ebenen).
    assert "Storage-Ebenen" in hit.detail


def test_deep_ole_directory_still_rates_macro_document_red():
    """Regression (Hunt 3/Runde 4): Polsterung darf das Makro-Signal nicht verschlucken.

    Gemessen vor dem Fix: dasselbe Makro-Dokument scannt ohne Polsterung ROT 95,
    mit 476 verschachtelten Storages dagegen GELB 25 — die Makro-Stufe lief nie,
    weil die Tiefenschwelle bei der Haelfte des Interpreter-Budgets lag (250
    Ebenen), obwohl olevba einen 476er-Baum problemlos liest. Der Fix setzt die
    Schwelle auf das gemessene Budget (der Verzeichnisdurchlauf stirbt erst bei
    496 Ebenen) — damit bleibt ein gepolstertes Makro-Dokument ROT und traegt
    seine Makrobeweise weiter selbst.

    Oberhalb des Budgets (496/700) kann die Stufe nicht laufen: dort bleibt nur
    die "ungeprueft"-Aussage (25, GELB) — nie GRUEN, siehe
    ``test_deep_ole_container_without_content_costs_one_25``.
    """
    from malaz.models import RiskLevel

    plain = _scan_doc(_macro_doc())
    assert plain.risk_level == RiskLevel.RED, f"Fixture selbst nicht erkannt: {plain.score}"
    plain_ids = {i.rule_id for i in plain.all_indicators()}
    assert "OFFICE_MACRO" in plain_ids and "OFFICE_AUTOEXEC" in plain_ids, plain_ids

    deep = _scan_doc(_macro_doc(nesting=476))
    deep_ids = {i.rule_id for i in deep.all_indicators()}
    # Der Fix darf die Makrobeweise nicht gegen eine Stufen-Notiz tauschen.
    assert "OFFICE_MACRO" in deep_ids and "OFFICE_AUTOEXEC" in deep_ids, deep_ids
    assert "OFFICE_SUSPICIOUS_API" in deep_ids, deep_ids
    assert "OFFICE_VBA_STOP" not in deep_ids, deep_ids
    assert deep.risk_level == RiskLevel.RED, f"nur noch {deep.score} Punkte"
    assert deep.score >= 50


def test_vba_project_with_unreadable_source_is_not_green():
    """Regression (Runde 5): erkanntes VBA-Projekt mit leerem Export war GRUEN.

    ``parser.extract_macros()`` verschluckt den Parse-Fehler des ``dir``-Streams:
    ``VBA_Project`` wirft (ValueError "invalid signature byte" bzw.
    UnexpectedDataError), die Bibliothek faengt das je Projekt mit
    ``except Exception`` ab und liefert stillschweigend nichts. Kein Fehler
    erreicht malaz, der gewichtete Ausnahmezweig der Stufe feuerte also nie —
    uebrig blieb ``OFFICE_MACRO`` (15), und 15 < ``SCORE_GREEN_MAX`` (19) hiess
    GRUEN, obwohl AutoOpen + WScript.Shell unveraendert im Modul-Stream lagen.

    Gemessen wird der Unterschied, den allein der ``dir``-Stream macht:
    identischer Modul-Stream, gueltiges Verzeichnis => ROT mit den Makro-Beweisen;
    abgeschnittenes Verzeichnis => gewichtete "ungeprueft"-Aussage statt "sauber".
    """
    sys.path.insert(0, str(_SCRIPTS))
    from ole_writer import _dir_stream, compress_vba

    from malaz.models import RiskLevel

    red = _scan_doc(_macro_doc())
    red_ids = {i.rule_id for i in red.all_indicators()}
    assert {"OFFICE_MACRO", "OFFICE_AUTOEXEC", "OFFICE_SUSPICIOUS_API"} <= red_ids, red_ids
    assert "OFFICE_VBA_WARN" not in red_ids, red_ids
    assert red.score > config.SCORE_YELLOW_MAX, red.score
    assert red.risk_level == RiskLevel.RED, red.risk_level

    # Nur das komprimierte Verzeichnis ist unlesbar (abgeschnitten); der
    # Modul-Stream mit AutoOpen + WScript.Shell bleibt Byte fuer Byte gleich.
    broken = _scan_doc(_macro_doc(dir_stream=compress_vba(_dir_stream(_MACRO_NAME))[:40]))
    broken_inds = {i.rule_id: i for i in broken.all_indicators()}
    assert "OFFICE_VBA_WARN" in broken_inds, sorted(broken_inds)
    assert broken_inds["OFFICE_VBA_WARN"].weight == 25, broken_inds
    assert broken.score > config.SCORE_GREEN_MAX, broken.score
    assert broken.risk_level == RiskLevel.YELLOW, broken.risk_level

    # Gegenrichtung: ohne Makro-Projekt haengt die "ungeprueft"-Aussage nirgends —
    # ein leerer, lesbarer Container bleibt unveraendert.
    harmless = _scan_office_bytes(_build_cfb({}), ".doc")
    harmless_ids = {i.rule_id for i in harmless.all_indicators()}
    assert "OFFICE_VBA_WARN" not in harmless_ids, harmless_ids
    assert "OFFICE_MACRO" not in harmless_ids, harmless_ids


def test_vba_warn_needs_a_project_not_only_the_attribut_byte_pattern():
    """Regression (Runde 6): die "ungeprueft"-Aussage hing an einer Rohbyte-Heuristik.

    Runde 5 band sie an ``detect_vba_macros()``. Dieses Flag ist breiter als die
    Projektliste: olevba setzt es zusaetzlich fuer das blosse Byte-Muster
    ``b'Attribut\\x00'`` in irgendeinem Stream (der Kommentar an der Stelle nennt
    es "happens in some malformed files"). Gemessen: ein Word-97-Container ohne
    jedes VBA-Projekt, dessen ``WordDocument``-Stream den gewoehnlichen deutschen
    Satz "Das Attribut\\x00 des Datensatzes wurde geprueft." traegt, liefert
    ``find_vba_projects()==0`` bei ``detect_vba_macros()==True`` — und scannte
    GELB 40 statt GRUEN 15 (Runde-4-Stand, nur ``OFFICE_MACRO``).

    Die Praemisse des Fixes wird mitgeprueft: das Fixture mit echtem Projekt
    liefert ``find_vba_projects() >= 1``, sonst waere das schmalere Praedikat ein
    stiller Verlust des beabsichtigten Falls.
    """
    sys.path.insert(0, str(_SCRIPTS))
    from ole_writer import _dir_stream, compress_vba, write_ole

    sentence = "Das Attribut\x00 des Datensatzes wurde geprueft.".encode("latin-1")
    harmless = write_ole({"WordDocument": b"\xec\xa5" + sentence + b"\x00" * 256})
    result = _scan_doc(harmless)
    weights = {i.rule_id: i.weight for i in result.all_indicators()}
    assert "OFFICE_VBA_WARN" not in weights, weights
    assert weights.get("OFFICE_MACRO") == 15, weights
    assert result.score < config.SCORE_GREEN_MAX, f"Score {result.score} statt 15"
    assert result.risk_level.name == "GREEN", result.risk_level

    # Gegenrichtung, zugleich Praemisse: ein echtes Projekt mit unlesbarem
    # Verzeichnis steht sehr wohl in der Projektliste und bleibt GELB 40.
    broken_bytes = _macro_doc(
        dir_stream=compress_vba(_dir_stream(_MACRO_NAME))[:40]
    )
    from oletools.olevba import VBA_Parser

    with _staged(broken_bytes) as tmp:
        parser = VBA_Parser(tmp)
        try:
            assert parser.find_vba_projects(), "Fixture hat kein VBA-Projekt"
        finally:
            parser.close()
    broken = _scan_doc(broken_bytes)
    broken_weights = {i.rule_id: i.weight for i in broken.all_indicators()}
    assert broken_weights.get("OFFICE_VBA_WARN") == 25, broken_weights
    assert broken.risk_level.name == "YELLOW", broken.risk_level


def test_vba_warn_reaches_into_openxml_subfiles():
    """Gegenrichtung zum Fix (Runde 6): die OOXML-Route darf nicht still verlieren.

    ``find_vba_projects()`` antwortet auf dem Top-Level-Parser eines OpenXML-
    Containers mit ``None`` — er hat kein ``ole_file``; das Projekt liegt im
    ``ole_subfiles``-Eintrag ``word/vbaProject.bin``, in den ``extract_macros``
    hineinrecurrt. Ein Praedikat, das nur den Top-Level fragt, machte aus dem
    beabsichtigten Fall (.docm mit Projekt und unlesbarem Verzeichnis) einen
    stillen Verlust. Und die Rohbyte-Heuristik darf auch hier nicht greifen.
    """
    def _docm(subfile: bytes) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("[Content_Types].xml", "<Types/>")
            z.writestr("word/vbaProject.bin", subfile)
        return buf.getvalue()

    def _stage(data: bytes):
        ctx = _ctx(data, name="test.docm", detected_type="zip")
        with _staged(data, suffix=".docm") as tmp:
            return OfficePipeline()._vba_analysis(ctx, tmp)

    sys.path.insert(0, str(_SCRIPTS))
    from ole_writer import _dir_stream, compress_vba, write_ole

    broken = _stage(
        _docm(_macro_doc(dir_stream=compress_vba(_dir_stream(_MACRO_NAME))[:40]))
    )
    weights = {i.rule_id: i.weight for i in broken}
    assert weights.get("OFFICE_VBA_WARN") == 25, weights
    assert weights.get("OFFICE_MACRO") == 15, weights

    # Gegenrichtung: eine eingebettete "Projekt"-Datei ohne Projekt, die nur
    # das Byte-Muster traegt, bleibt ohne die "ungeprueft"-Aussage.
    sentence = "Das Attribut\x00 des Datensatzes wurde geprueft.".encode("latin-1")
    harmless = _stage(_docm(write_ole({"WordDocument": b"\xec\xa5" + sentence})))
    assert "OFFICE_VBA_WARN" not in _ids(harmless), _ids(harmless)


@pytest.mark.parametrize("suffix", [".doc", ".xls"])
@pytest.mark.parametrize("nesting", [496, 700])
def test_deep_ole_container_without_content_stays_clean(monkeypatch, suffix, nesting):
    """Ein inhaltsloser, tief verschachtelter Container bleibt unauffaellig.

    Diese Erwartung hat sich in Runde 4 geaendert und der Grund gehoert
    festgehalten: vorher erzeugte derselbe Container drei bis vier 25er-Notizen
    derselben Ursache, weil olefile bei dieser Tiefe mit RecursionError
    abbrach — gemessen 496 Ebenen ROT 75 (.doc) bzw. ROT 100 (.xls),
    "boesartig" fuer eine Datei ohne jeden Inhaltsbefund.

    Seit ``core/ole_depth`` bekommt der Durchlauf den Stack, den er braucht,
    und die 496/700 Ebenen werden gelesen. Ein lesbarer Container ohne Inhalt
    hat kein Inhaltssignal — die Polsterung allein ist keine Boesartigkeit.
    Weder die Stufen-Notiz noch die Container-Meldung duerfen hier feuern:
    beide waeren eine erfundene "ungeprueft"-Aussage ueber einen Container,
    den der Scan sehr wohl gelesen hat.

    Die "ungeprueft"-Aussage gibt es weiterhin, nur jenseits der strukturellen
    Obergrenze — belegt in
    ``test_vba_stage_refuses_only_beyond_the_structural_ceiling``.
    """
    monkeypatch.setattr(config, "YARA_FEED_DIRS", ())
    result = _scan_office_bytes(_build_cfb({}, nesting=nesting), suffix)
    weights = {i.rule_id: i.weight for i in result.all_indicators() if i.weight}
    assert not weights, f"erfundene Meldung fuer einen gelesenen Container: {weights}"
    assert result.score == 0, f"Score {result.score} ohne Inhaltssignal"
    assert result.risk_level.name == "GREEN"



def test_fehlende_makro_bibliothek_wird_sichtbar(monkeypatch):
    """BEISSPROBE fuer OFFICE_LIB_MISSING.

    Ohne ``oletools`` lieferte die VBA-Stufe stillschweigend eine leere Liste
    — ein makrotragendes .docm war damit GRUEN. Der Befund traegt Gewicht 0
    (eine fehlende Bibliothek ist der Datei nicht anzulasten), aber er muss
    erscheinen; sonst ist er von "geprueft, sauber" nicht zu unterscheiden.
    """
    import sys

    # sys.modules auf None setzen laesst "import oletools" mit ImportError
    # scheitern, auch wenn das Paket schon geladen war. Ein Patch von
    # builtins.__import__ genuegt NICHT: der Import-Cache greift vorher
    # (gemessen — der Test war gruen, ohne den Pfad zu beruehren).
    monkeypatch.setitem(sys.modules, "oletools", None)
    monkeypatch.setitem(sys.modules, "oletools.olevba", None)
    inds = OfficePipeline().analyze(_ctx(b"ole-bytes", name="t.docm"))

    treffer = [i for i in inds if i.rule_id == "OFFICE_LIB_MISSING"]
    assert treffer, "die fehlende Makro-Pruefung blieb unsichtbar"
    assert all(i.weight == 0 for i in treffer)
    assert any("Makro" in i.title for i in treffer), [i.title for i in treffer]


def test_missing_xlm_library_is_score_effective(monkeypatch):
    """BUG-103: without XLMMacroDeobfuscator an XLM macrosheet must not be GREEN."""
    import sys

    for name in list(sys.modules):
        if name == "XLMMacroDeobfuscator" or name.startswith("XLMMacroDeobfuscator."):
            monkeypatch.setitem(sys.modules, name, None)
    result = _scan_office_bytes(_xlsm_with_xlm_macrosheet(), ".xlsm")
    hits = [i for i in result.all_indicators() if i.rule_id == "OFFICE_LIB_MISSING"]
    assert hits, "die fehlende XLM-Stufe blieb unsichtbar"
    assert hits[0].weight == 25
    assert result.risk_level.name != "GREEN"
