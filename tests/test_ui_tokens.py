"""Automated UI contract tests for Malaz v1.1.0 ("Klare Fläche v2").

Verifies:
1. WCAG 2.1 contrast floors (>= 4.5:1 text, >= 7:1 CTA, >= 3:1 focus) in both
   Dark and Light palettes.
2. Zero hardcoded hex colour literals anywhere under ``src/malaz/gui/``.
3. Zero duplicate QSS selectors in ``build_stylesheet("dark" | "light")``.
4. Monotone & fail-closed completeness invariant in ``visual_state()``.
5. Automatic High-DPI screen clamping (1080p @ 150% = 1280x672, 960x560 min,
   off-screen saved geometry recovery).
6. Sink hardening: ``defang_ioc()`` and UNC/device rejection in
   ``reveal_in_explorer()``.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import QRect

from malaz.design_tokens import (
    PALETTES,
    contrast_ratio,
    format_size_de,
    format_tag_code,
    type_filter_bucket,
    visual_state,
)
from malaz.gui.display import compute_clamped_rect
from malaz.gui.sanitize import defang_ioc, is_unc_or_device_path, reveal_in_explorer
from malaz.gui.theme import build_stylesheet
from malaz.models import RiskLevel

_GUI_DIR = Path(__file__).resolve().parents[1] / "src" / "malaz" / "gui"
_HEX_RE = re.compile(r"#[0-9a-fA-F]{6}")
_QSS_BLOCK_RE = re.compile(r"^([^{}\n][^{}]*?)\s*\{", re.M)


def test_wcag_contrast_ratios_pass_in_both_themes():
    for mode, p in PALETTES.items():
        for fg in ("ink_1", "ink_2"):
            for bg in ("canvas", "sidebar", "surface", "elevated"):
                ratio = contrast_ratio(p[fg], p[bg])
                assert ratio >= 4.5, f"{mode}: {fg} on {bg} = {ratio:.2f}:1 < 4.5:1"

        for bg in ("canvas", "sidebar", "surface"):
            ratio = contrast_ratio(p["ink_3"], p[bg])
            assert ratio >= 4.5, f"{mode}: ink_3 on {bg} = {ratio:.2f}:1 < 4.5:1"

        cta_ratio = contrast_ratio(p["cta_ink"], p["cta_bg"])
        assert cta_ratio >= 7.0, f"{mode}: cta = {cta_ratio:.2f}:1 < 7.0:1"

        for st in ("st_bad", "st_warn", "st_ok", "st_info"):
            for bg in ("canvas", "surface"):
                ratio = contrast_ratio(p[st], p[bg])
                assert ratio >= 4.5, f"{mode}: {st} on {bg} = {ratio:.2f}:1 < 4.5:1"
            for suffix in ("_soft", "_badge"):
                key = f"{st}{suffix}"
                if key in p:
                    ratio = contrast_ratio(p[st], p[key])
                    assert ratio >= 4.5, f"{mode}: {st} on {key} = {ratio:.2f}:1 < 4.5:1"

        for bg in ("canvas", "sidebar", "surface"):
            ratio = contrast_ratio(p["st_info"], p[bg])
            assert ratio >= 3.0, f"{mode}: focus ring on {bg} = {ratio:.2f}:1 < 3.0:1"


def test_zero_hardcoded_hex_colors_in_gui_package():
    offenders: list[str] = []
    for py_file in sorted(_GUI_DIR.glob("*.py")):
        hits = _HEX_RE.findall(py_file.read_text(encoding="utf-8"))
        if hits:
            offenders.append(f"{py_file.name}: {hits}")
    assert not offenders, f"Hardcoded hex values belong in design_tokens.py only: {offenders}"


@pytest.mark.parametrize("mode", ("dark", "light"))
def test_no_duplicate_qss_selectors(mode):
    qss = build_stylesheet(mode)
    seen: set[str] = set()
    dupes: list[str] = []
    for raw in _QSS_BLOCK_RE.findall(qss):
        sel = " ".join(raw.split())
        if sel in seen:
            dupes.append(sel)
        seen.add(sel)
    assert not dupes, f"Duplicate QSS selectors in {mode}: {dupes}"


def test_visual_state_monotonicity_and_fail_closed():
    # Completeness invariant: unchecked GREEN is NEVER green!
    assert visual_state(RiskLevel.GREEN, is_incomplete=False) == "ok"
    assert visual_state(RiskLevel.GREEN, is_incomplete=True) == "unk"

    # Monotonicity: confirmed RED is NEVER downgraded to unk/warn!
    assert visual_state(RiskLevel.RED, is_incomplete=False) == "bad"
    assert visual_state(RiskLevel.RED, is_incomplete=True) == "bad"

    # YELLOW stays warn whether complete or incomplete
    assert visual_state(RiskLevel.YELLOW, is_incomplete=False) == "warn"
    assert visual_state(RiskLevel.YELLOW, is_incomplete=True) == "warn"

    # Fail-closed on unknown / None inputs
    assert visual_state(None, is_incomplete=False) == "unk"
    assert visual_state("MYSTERY", is_incomplete=False) == "unk"


def test_compute_clamped_rect_fits_1080p_at_150_dpi_and_960x560():
    # Standard 1920x1080 laptop at Windows 150% DPI scaling: available area = 1280x672
    laptop_avail = QRect(0, 0, 1280, 672)
    r = compute_clamped_rect(laptop_avail, preferred_w=1280, preferred_h=760)
    assert r.width() <= laptop_avail.width()
    assert r.height() <= laptop_avail.height()
    assert laptop_avail.contains(r)

    # Minimum supported viewport 960x560
    min_avail = QRect(0, 0, 960, 560)
    r_min = compute_clamped_rect(min_avail, preferred_w=1280, preferred_h=760)
    assert r_min.width() <= 960 and r_min.height() <= 560
    assert min_avail.contains(r_min)

    # Off-screen / oversized saved geometry from a disconnected 4K monitor is clamped back in
    r_saved = compute_clamped_rect(laptop_avail, saved=(3200, 1800, 1900, 1100))
    assert r_saved.width() <= 1280 and r_saved.height() <= 672
    assert laptop_avail.contains(r_saved)


def test_defang_ioc_and_unc_rejection(tmp_path):
    assert defang_ioc("http://198.51.100.42/verify") == "hxxp://198.51.100.42/verify"
    assert defang_ioc("HTTPS://evil.example/login") == "hxxps://evil.example/login"

    # UNC & Windows device paths must ALWAYS be rejected (Offline-by-Default!)
    assert is_unc_or_device_path(r"\\attacker.example\share\file.pdf")
    assert is_unc_or_device_path(r"\\?\C:\Windows\notepad.exe")
    assert reveal_in_explorer(r"\\attacker.example\share\file.pdf") is False
    assert reveal_in_explorer(tmp_path / "does_not_exist.pdf") is False


def test_format_helpers():
    assert format_tag_code("pe", "Bewerbung.pdf.exe", spoofed=True) == ("EXE", "spoof")
    assert format_tag_code("zip", "a.zip") == ("ZIP", "container")
    assert format_tag_code("eml", "m.eml") == ("EML", "container")
    assert type_filter_bucket("ole", "doc.docx") == "DOC"
    assert type_filter_bucket("7z", "x.7z") == "ZIP"
    assert format_size_de(1536) == "1,5 KB"


def test_is_unc_or_device_path_exact_prefixes():
    from malaz.gui.sanitize import is_unc_or_device_path

    for blocked in (
        r"\\server\share\file.pdf",
        "//server/share/file.pdf",
        "\\/server\\share",
        "/\\server/share",
        r"\\?\C:\file.pdf",
        r"\\.\pipe\malaz",
    ):
        assert is_unc_or_device_path(blocked) is True, blocked
    for allowed in (r"C:\Users\alice\doc.pdf", r"\foo\bar.pdf", "relative/doc.pdf"):
        assert is_unc_or_device_path(allowed) is False, allowed


def test_ooxml_msg_tiff_macho_tags_and_labels():
    from malaz.design_tokens import format_short_type, format_tag_code, type_filter_bucket

    assert format_tag_code("zip", "bericht.docx") == ("DOC", "container")
    assert format_short_type("zip", "bericht.docx") == "Word (.docx)"
    assert type_filter_bucket("zip", "bericht.docx") == "DOC"
    assert format_tag_code("zip", "kalk.xlsx") == ("XLS", "container")
    assert format_short_type("zip", "kalk.xlsx") == "Excel (.xlsx)"
    assert format_tag_code("zip", "makro.docm") == ("DOC", "container")
    assert format_short_type("zip", "makro.docm") == "Word-Makro (.docm)"
    # Spoofed ZIP with .docx name keeps spoof style!
    assert format_tag_code("zip", "fake.docx", spoofed=True)[1] == "spoof"
    # .msg OLE container -> MSG / E-Mail (.msg)
    assert format_tag_code("ole", "mail.msg") == ("MSG", "container")
    assert format_short_type("ole", "mail.msg") == "E-Mail (.msg)"
    # TIFF, Mach-O, SWF
    assert format_tag_code("tiff", "scan.tiff")[0] == "TIF"
    assert format_tag_code("macho", "app.macho")[0] == "MAC"
    assert format_short_type("macho", "app.macho") == "Mach-O"
    assert format_short_type("swf", "movie.swf") == "Flash (SWF)"
