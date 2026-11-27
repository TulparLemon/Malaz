"""Regression tests for Cloudflare/malaz-audit Run-1 findings (F1-F4)."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

from malaz.analysis.clamav import ClamAVScanner
from malaz.analysis.windows_av import WindowsDefenderScanner
from malaz.core.dispatcher import Dispatcher
from malaz.core.yara_signature_base import _flat_members
from malaz.models import _INCOMPLETE_RULES, Indicator, RiskLevel, ScanResult, Severity
from malaz.security.safe_extract import ATTACK_REASONS, is_safe_member_name, unsafe_name_reason


def test_f1_top_level_bidi_rlo_filename_is_detected_as_red(tmp_path: Path) -> None:
    r"""F1: Top-level RLO trojan filename (Rechnung\u202efdp.exe) must fire GEN_BIDI_NAME -> RED."""
    disp = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    spoof = tmp_path / "Rechnung\u202efdp.exe"
    spoof.write_bytes(b"MZ" + b"\x00" * 128)
    res = disp.scan_path(spoof)
    rule_ids = {i.rule_id for i in res.indicators}
    assert "GEN_BIDI_NAME" in rule_ids, f"GEN_BIDI_NAME missing: {rule_ids}"
    assert res.risk_level == RiskLevel.RED, f"expected RED, got {res.risk_level} ({res.score})"


def test_f1_genuine_arabic_and_hebrew_filenames_do_not_trigger_bidi(tmp_path: Path) -> None:
    """F1 counter-check: legitimate RTL letters without BiDi overrides stay clean GREEN."""
    disp = Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )
    for name in ("فاتورة.txt", "שלום.txt"):
        p = tmp_path / name
        p.write_text("Harmloses Dokument.\n", encoding="utf-8")
        res = disp.scan_path(p)
        rule_ids = {i.rule_id for i in res.indicators}
        assert "GEN_BIDI_NAME" not in rule_ids
        assert res.risk_level == RiskLevel.GREEN


def test_f2_missing_completeness_rules_mark_result_incomplete() -> None:
    """F2: All 8 silent/timeout incomplete rules must belong to _INCOMPLETE_RULES."""
    expected = {
        "PE_LIB_MISSING",
        "PE_SECTION_ENTROPY_LIMIT",
        "PE_SECTION_PARSE_WARN",
        "PE_TLS_PARSE_WARN",
        "PE_IMPORT_PARSE_WARN",
        "OFFICE_REL_TRUNCATED",
        "OFFICE_XLM_TIMEOUT",
        "HEIC_BOX_LIMIT",
    }
    missing = expected - _INCOMPLETE_RULES
    assert not missing, f"Missing from _INCOMPLETE_RULES: {sorted(missing)}"

    for rid in sorted(expected):
        sr = ScanResult(
            path="sample.bin",
            detected_type="pe",
            size=100,
            indicators=[
                Indicator(
                    rule_id=rid,
                    title="test",
                    detail="test",
                    severity=Severity.INFO,
                    category="structure",
                    source="test",
                    weight=0,
                )
            ],
        )
        assert sr.is_incomplete, f"{rid} did not mark ScanResult as incomplete"


def test_f3_safe_extract_rejects_embedded_nul_bytes() -> None:
    """F3: Archive member names with embedded NUL bytes must be rejected as attack."""
    for bad in ("evil.exe\x00.pdf", "a\x00/b.yar", "\x00"):
        assert not is_safe_member_name(bad), f"NUL member accepted: {bad!r}"
        reason = unsafe_name_reason(bad)
        assert reason in ATTACK_REASONS, f"NUL reason {reason!r} not in ATTACK_REASONS"


def test_f4_yara_signature_base_rejects_windows_device_and_nul_names() -> None:
    """F4: Sibling control to yara_update.py — _flat_members must reject device/NUL/dot names."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("repo-main/yara/CON.yar", b"rule r1 { condition: true }")
        zf.writestr("repo-main/yara/NUL.yar", b"rule r2 { condition: true }")
        zf.writestr("repo-main/yara/trailing.yar.", b"rule r3 { condition: true }")
        zf.writestr("repo-main/yara/ok_rule.yar", b"rule r4 { condition: true }")
    members = _flat_members(buf.getvalue())
    assert set(members.keys()) == {"ok_rule.yar"}


def test_f1_bidi_display_path_isolates_and_clean_child_in_bidi_parent() -> None:
    """M1 regression: display_path RLO, BiDi isolates (U+2066..U+2069), and clean child isolation."""
    from malaz.i18n import localized_indicator_detail, localized_indicator_title
    from malaz.models import AnalysisContext
    from malaz.pipelines.generic_pipeline import GenericPipeline

    pipe = GenericPipeline(yara=None)

    # (a) Sanitized temp path on disk + RLO in display_path leaf -> MUST detect
    ctx_disp = AnalysisContext(
        path=Path("C:/Temp/sanitized_member.exe"),
        data=b"MZ" + b"\x00" * 64,
        detected_type="pe",
        size=66,
        depth=1,
        display_path="outer.zip -> invoice\u202efdp.exe",
    )
    inds_disp = pipe._bidi_filename(ctx_disp)
    assert [i.rule_id for i in inds_disp] == ["GEN_BIDI_NAME"]

    # M1 regression: '!' is a valid filename char and must NOT truncate RLO detection
    ctx_bang = AnalysisContext(
        path=Path("C:/Temp/sanitized_member.exe"),
        data=b"MZ" + b"\x00" * 64,
        detected_type="pe",
        size=66,
        depth=1,
        display_path="outer.zip -> Rechnung\u202e!fdp.exe",
    )
    assert [i.rule_id for i in pipe._bidi_filename(ctx_bang)] == ["GEN_BIDI_NAME"]

    # M2 verification: EN & TR translations genuinely differ from German fallback
    ind = inds_disp[0]
    en_title = localized_indicator_title(ind, lang="en")
    en_detail = localized_indicator_detail(ind, lang="en")
    tr_title = localized_indicator_title(ind, lang="tr")
    tr_detail = localized_indicator_detail(ind, lang="tr")
    assert en_title != ind.title and "override" in en_title.lower()
    assert en_detail != ind.detail and "disguise" in en_detail.lower()
    assert tr_title != ind.title and "dosya" in tr_title.lower()
    assert tr_detail != ind.detail and "uzantıyı" in tr_detail.lower()

    # (b) BiDi isolate U+2066..U+2069 -> MUST detect
    for cp in (0x2066, 0x2067, 0x2068, 0x2069):
        ctx_iso = AnalysisContext(
            path=Path(f"doc_{chr(cp)}fdp.exe"),
            data=b"hello",
            detected_type="text",
            size=5,
        )
        assert [i.rule_id for i in pipe._bidi_filename(ctx_iso)] == ["GEN_BIDI_NAME"]

    # (c) Clean child inside a BiDi parent archive -> MUST NOT falsely flag the clean child
    ctx_clean_child = AnalysisContext(
        path=Path("C:/Temp/clean.txt"),
        data=b"clean",
        detected_type="text",
        size=5,
        depth=1,
        display_path="bad_\u202earchive.zip -> clean.txt",
    )
    assert pipe._bidi_filename(ctx_clean_child) == []
