"""Pure-Python design tokens and monotone visual-state helpers for Malaz.

Lives at package root (zero Qt imports, zero runtime imports from ``core`` or
``models``) so ``gui/`` and future ``reporting/`` modules share one single
source of truth without violating ``scripts/arch_gate.py``.
"""

from __future__ import annotations

from typing import Any

# -- Colour Palettes (WCAG 2.1 AA verified in tests/test_ui_tokens.py) ----- #

PALETTE_DARK: dict[str, str] = {
    "canvas": "#090C10",
    "sidebar": "#0D1117",
    "surface": "#11161F",
    "elevated": "#171E2A",
    "border_subtle": "#1C2330",
    "border_default": "#2A3444",
    "border_strong": "#475569",
    "tree_guide": "#2D384A",
    "ink_1": "#F0F4F8",
    "ink_2": "#A3B0C2",
    "ink_3": "#8492A6",
    "cta_bg": "#F0F4F8",
    "cta_ink": "#090C10",
    "st_bad": "#F25555",
    "st_bad_soft": "#1D1116",
    "st_bad_badge": "#2A151B",
    "st_bad_line": "#5C242A",
    "st_warn": "#ECA614",
    "st_warn_soft": "#1B170E",
    "st_warn_badge": "#292112",
    "st_warn_line": "#57421A",
    "st_ok": "#34C759",
    "st_ok_soft": "#0E1A15",
    "st_ok_badge": "#13261D",
    "st_ok_line": "#1E4D33",
    "st_info": "#58A6FF",
    "st_info_badge": "#132236",
    "st_info_line": "#21456E",
    "tag_bg": "#1A212D",
    "row_hover": "#161D28",
    "row_active": "#132236",
    "row_active_line": "#58A6FF",
    "track_bg": "#1F2836",
}

PALETTE_LIGHT: dict[str, str] = {
    "canvas": "#FFFFFF",
    "sidebar": "#F6F8FA",
    "surface": "#F8FAFC",
    "elevated": "#EEF2F6",
    "border_subtle": "#E2E8F0",
    "border_default": "#CBD5E1",
    "border_strong": "#94A3B8",
    "tree_guide": "#CBD5E1",
    "ink_1": "#0F172A",
    "ink_2": "#475569",
    "ink_3": "#526075",
    "cta_bg": "#0F172A",
    "cta_ink": "#FFFFFF",
    "st_bad": "#B91C1C",
    "st_bad_soft": "#FEF2F2",
    "st_bad_badge": "#FEE2E2",
    "st_bad_line": "#FCA5A5",
    "st_warn": "#8F5100",
    "st_warn_soft": "#FFFBEB",
    "st_warn_badge": "#FEF3C7",
    "st_warn_line": "#FCD34D",
    "st_ok": "#116932",
    "st_ok_soft": "#F0FDF4",
    "st_ok_badge": "#DCFCE7",
    "st_ok_line": "#86EFAC",
    "st_info": "#0969DA",
    "st_info_badge": "#E0F2FE",
    "st_info_line": "#93C5FD",
    "tag_bg": "#E9EEF4",
    "row_hover": "#EEF2F6",
    "row_active": "#E8F1FD",
    "row_active_line": "#0969DA",
    "track_bg": "#DDE4EE",
}

PALETTES: dict[str, dict[str, str]] = {
    "dark": PALETTE_DARK,
    "light": PALETTE_LIGHT,
}

# -- Typography & Spacing Ramps (px) --------------------------------------- #

TYPE: dict[str, tuple[int, int]] = {
    "title": (20, 600),
    "hero": (17, 700),
    "body": (13, 400),
    "body_strong": (13, 600),
    "meta": (12, 400),
    "caption": (11, 600),
    "mono": (12, 400),
    "hash": (11, 400),
    "mark": (16, 700),
}

SPACE: dict[str, int] = {
    "xs": 4,
    "s": 8,
    "m": 12,
    "l": 16,
    "xl": 20,
    "xxl": 28,
}

RADIUS: dict[str, int] = {
    "s": 4,
    "m": 6,
    "l": 8,
    "xl": 10,
}

# -- WCAG 2.1 Contrast Helper ---------------------------------------------- #


def _srgb_channel(hex_pair: str) -> float:
    c = int(hex_pair, 16) / 255.0
    return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4


def relative_luminance(hex_color: str) -> float:
    h = hex_color.lstrip("#")
    if len(h) != 6:
        raise ValueError(f"Expected 6-digit hex colour, got {hex_color!r}")
    r = _srgb_channel(h[0:2])
    g = _srgb_channel(h[2:4])
    b = _srgb_channel(h[4:6])
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast_ratio(fg_hex: str, bg_hex: str) -> float:
    l1 = relative_luminance(fg_hex)
    l2 = relative_luminance(bg_hex)
    hi, lo = (l1, l2) if l1 >= l2 else (l2, l1)
    return (hi + 0.05) / (lo + 0.05)


def palette_for(mode: str) -> dict[str, str]:
    """Return the token dictionary for ``dark`` or ``light`` (defaults to dark)."""
    return PALETTE_LIGHT if mode == "light" else PALETTE_DARK


# -- Monotone Visual-State Model (Completeness Invariant) ------------------ #

STATE_ORDER: dict[str, int] = {"ok": 0, "unk": 1, "warn": 2, "bad": 3}

STATE_LABELS_DE: dict[str, str] = {
    "bad": "Gefährlich",
    "warn": "Verdächtig",
    "unk": "Ungeprüft",
    "ok": "Sauber",
    "pending": "Wartet",
    "scanning": "Prüft…",
    "cancelled": "Abgebrochen",
}


def state_label(state: str, *, lang: str | None = None) -> str:
    """Return localized visual-state label dynamically (no import-time cache)."""
    from .i18n import t

    key = f"state.{state}"
    val = t(key, lang=lang)
    return STATE_LABELS_DE.get(state, state) if val == key else val


def visual_state(risk_level: Any, is_incomplete: bool) -> str:
    """Map ``(risk_level, is_incomplete)`` to ``ok | unk | warn | bad``.

    Hard invariants:
    - Monotone severity: ``ok < unk < warn < bad``.
    - ``RED`` always yields ``"bad"`` (never downgraded when incomplete).
    - ``GREEN`` with ``is_incomplete=True`` yields ``"unk"`` (never green!).
    - Unknown / ``None`` values fail closed to ``"unk"``.
    """
    if risk_level is None:
        return "unk"
    raw = getattr(risk_level, "name", None)
    key = (raw if isinstance(raw, str) else str(risk_level)).strip().upper()
    if key in ("RED", "2", "BAD"):
        return "bad"
    if key in ("YELLOW", "1", "WARN"):
        return "warn"
    if key in ("GREEN", "0", "OK"):
        return "unk" if is_incomplete else "ok"
    return "unk"


# -- File-Type Tagging & Concise Formatting -------------------------------- #

ARCHIVE_TYPES = frozenset({"zip", "7z", "rar", "tar", "gzip", "bzip2", "xz", "cab", "iso"})
MAIL_TYPES = frozenset({"eml", "msg"})
OOXML_EXT_MAP: dict[str, tuple[str, str]] = {
    ".docx": ("DOC", "Word (.docx)"),
    ".docm": ("DOC", "Word-Makro (.docm)"),
    ".xlsx": ("XLS", "Excel (.xlsx)"),
    ".xlsm": ("XLS", "Excel-Makro (.xlsm)"),
    ".pptx": ("PPT", "PowerPoint (.pptx)"),
    ".pptm": ("PPT", "PowerPoint-Makro (.pptm)"),
}


def is_ooxml_filename(filename: str | None) -> bool:
    """True when ``filename`` ends with a standard ZIP-based OOXML Office extension."""
    low = (filename or "").lower()
    return any(low.endswith(ext) for ext in OOXML_EXT_MAP)
PROGRAM_TYPES = frozenset({"pe", "elf", "macho", "ps1", "batch", "vbs", "js", "lnk"})
DOCUMENT_TYPES = frozenset({"ole", "office", "rtf", "html", "xml", "json", "text"})

_TAG_BY_TYPE: dict[str, str] = {
    "eml": "EML",
    "msg": "MSG",
    "zip": "ZIP",
    "7z": "7Z",
    "rar": "RAR",
    "tar": "TAR",
    "gzip": "GZ",
    "bzip2": "BZ2",
    "xz": "XZ",
    "cab": "CAB",
    "iso": "ISO",
    "pe": "EXE",
    "elf": "ELF",
    "macho": "MAC",
    "pdf": "PDF",
    "ole": "DOC",
    "office": "DOC",
    "rtf": "RTF",
    "ps1": "PS1",
    "batch": "BAT",
    "vbs": "VBS",
    "js": "JS",
    "lnk": "LNK",
    "url": "URL",
    "html": "HTM",
    "xml": "XML",
    "json": "JSN",
    "text": "TXT",
    "png": "PNG",
    "jpeg": "JPG",
    "gif": "GIF",
    "bmp": "BMP",
    "webp": "WBP",
    "heic": "IMG",
    "avif": "IMG",
    "ico": "ICO",
    "tiff": "TIF",
    "tif": "TIF",
    "swf": "SWF",
    "mp3": "MP3",
    "mp4": "MP4",
}

_SHORT_TYPE_DE: dict[str, str] = {
    "pe": "EXE",
    "pdf": "PDF",
    "eml": "E-Mail (.eml)",
    "msg": "E-Mail (.msg)",
    "zip": "ZIP-Archiv",
    "7z": "7z-Archiv",
    "rar": "RAR-Archiv",
    "tar": "TAR-Archiv",
    "gzip": "GZip",
    "bzip2": "BZip2",
    "xz": "XZ",
    "cab": "CAB",
    "iso": "ISO",
    "ole": "Office",
    "office": "Office",
    "rtf": "RTF",
    "ps1": "PowerShell",
    "batch": "Batch (.bat)",
    "vbs": "VBScript",
    "js": "JavaScript",
    "lnk": "Verknüpfung",
    "html": "HTML",
    "xml": "XML",
    "json": "JSON",
    "text": "Text",
    "png": "PNG",
    "jpeg": "JPEG",
    "gif": "GIF",
    "bmp": "BMP",
    "ico": "ICO",
    "webp": "WebP",
    "tiff": "TIFF",
    "tif": "TIFF",
    "macho": "Mach-O",
    "swf": "Flash (SWF)",
    "empty": "Leer",
    "unknown": "Unbekannt",
}


def type_filter_bucket(detected_type: str, filename: str = "") -> str:
    """Return the sidebar type-filter bucket key for a file."""
    dt = (detected_type or "").lower()
    low = (filename or "").lower()
    if dt in MAIL_TYPES or low.endswith((".eml", ".msg")):
        return "EML"
    if dt == "zip" and is_ooxml_filename(low):
        return "DOC"
    if dt in ARCHIVE_TYPES or low.endswith((".zip", ".7z", ".rar", ".tar", ".gz")):
        return "ZIP"
    if dt in PROGRAM_TYPES or low.endswith((".exe", ".dll", ".scr", ".bat", ".ps1", ".lnk")):
        return "EXE"
    if dt == "pdf" or low.endswith(".pdf"):
        return "PDF"
    if dt in DOCUMENT_TYPES or low.endswith((".doc", ".docx", ".xls", ".xlsx", ".rtf", ".txt")):
        return "DOC"
    return "OTHER"


def format_tag_code(detected_type: str, filename: str = "", *, spoofed: bool = False) -> tuple[str, str]:
    """Return ``(code_2_to_3_chars, style_kind)`` for the tree monospace tag.

    ``style_kind`` is ``"spoof"`` | ``"container"`` | ``""``.
    """
    dt = (detected_type or "").lower()
    code = _TAG_BY_TYPE.get(dt)
    if not code and filename and "." in filename:
        ext = filename.rsplit(".", 1)[-1].upper()
        if ext.isalnum() and 1 <= len(ext) <= 3:
            code = ext
    if not code:
        code = "DAT"
    low = (filename or "").lower()
    if dt == "pe" and low.endswith(".dll"):
        code = "DLL"
    if spoofed:
        return (code, "spoof")
    if dt == "zip":
        for ext, (ox_tag, _ox_label) in OOXML_EXT_MAP.items():
            if low.endswith(ext):
                return (ox_tag, "container")
    if dt == "ole" and low.endswith(".msg"):
        return ("MSG", "container")
    if dt in MAIL_TYPES or dt in ARCHIVE_TYPES:
        return (code, "container")
    return (code, "")


def format_short_type(
    detected_type: str, filename: str = "", *, lang: str | None = None
) -> str:
    """Concise localized type string for footer & origin strip."""
    from .i18n import get_language, localized_type_label, resolve_language

    eff = resolve_language(lang) if lang is not None else get_language()
    if eff in ("en", "tr"):
        return localized_type_label(detected_type, filename, lang=eff, short=True)
    dt = (detected_type or "").lower()
    low = (filename or "").lower()
    if dt == "pe" and low.endswith(".dll"):
        return "DLL"
    if dt == "zip":
        for ext, (_ox_tag, ox_label) in OOXML_EXT_MAP.items():
            if low.endswith(ext):
                return ox_label
    if dt == "ole" and low.endswith(".msg"):
        return "E-Mail (.msg)"
    return _SHORT_TYPE_DE.get(dt, dt.upper() if dt else "Datei")


def format_size(size_bytes: int, *, lang: str | None = None) -> str:
    """Format byte size concisely (comma for DE, dot for EN)."""
    from .i18n import get_language, resolve_language

    eff = resolve_language(lang) if lang is not None else get_language()
    sep = "." if eff == "en" else ","
    if size_bytes < 0:
        return "0 B"
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        kb = size_bytes / 1024
        return f"{kb:.0f} KB" if kb >= 10 else f"{kb:.1f} KB".replace(".", sep)
    mb = size_bytes / (1024 * 1024)
    return f"{mb:.1f} MB".replace(".", sep) if mb < 100 else f"{mb:.0f} MB"


def format_size_de(size_bytes: int) -> str:
    """Format byte size concisely using active language (legacy alias)."""
    return format_size(size_bytes)
