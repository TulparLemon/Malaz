"""Central GUI sink-hardening helpers and safe file-manager reveal.

One shared module so every widget masks BiDi/control characters, clips
absurdly long names, escapes HTML tooltips, defangs IOCs, and reveals files
in Windows Explorer safely without duplicating logic across GUI modules.
"""

from __future__ import annotations

import ctypes
import html
import os
import re
import sys
from contextlib import suppress
from pathlib import Path

from ..core.mail_view import MAX_DISPLAY_CHARS
from ..security.escaping import mask_invisible

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def masked_widget_text(value: str | None) -> str:
    """Mask Unicode BiDi/invisible controls before handing text to Qt."""
    if not value:
        return ""
    masked = mask_invisible(str(value))
    return _CONTROL_RE.sub("?", masked)


def clip_text(value: str | None, limit: int = MAX_DISPLAY_CHARS) -> str:
    """Clip attacker-controlled strings (e.g. 65k-char ZIP names) with explicit note."""
    text = str(value or "")
    if len(text) <= limit:
        return text
    return text[: max(1, limit)] + " … (gekürzt)"


def escape_tooltip(value: str | None, limit: int = 400) -> str:
    """Mask, clip, and HTML-escape a string for Qt tooltips (safe from rich-text injection)."""
    return html.escape(clip_text(masked_widget_text(value), limit), quote=True)


def defang_ioc(value: str | None) -> str:
    """Defang URLs/schemes for display so analysts never click a live phishing link."""
    text = masked_widget_text(value).strip()
    if not text:
        return ""
    low = text.lower()
    if low.startswith("https://"):
        return "hxxps://" + text[8:]
    if low.startswith("http://"):
        return "hxxp://" + text[7:]
    if low.startswith("ftp://"):
        return "fxp://" + text[6:]
    return text


def is_unc_or_device_path(raw: str | Path) -> bool:
    r"""True for UNC shares (\server\share) or Windows device paths (\\?\, \\.\)."""
    s = str(raw or "").strip()
    return s.startswith(("\\", "//"))


def reveal_in_explorer(raw_path: str | Path | None) -> bool:
    """Highlight an existing local file or directory in Windows Explorer safely.

    Uses ``SHOpenFolderAndSelectItems`` via ``ctypes`` (no ``subprocess``, no
    ``explorer.exe /select,`` space/comma quoting bugs, no Bandit B603/B607).
    Rejects UNC/device paths to guarantee offline-by-default (no implicit SMB).
    Returns ``True`` when the OS shell call succeeded, ``False`` otherwise.
    """
    if not raw_path:
        return False
    if is_unc_or_device_path(raw_path):
        return False
    try:
        resolved = Path(raw_path).resolve(strict=True)
    except OSError:
        return False
    resolved_str = str(resolved)
    if is_unc_or_device_path(resolved_str):
        return False
    if sys.platform != "win32" or os.environ.get("QT_QPA_PLATFORM") == "offscreen":
        return False

    shell32 = ctypes.windll.shell32
    ole32 = ctypes.windll.ole32
    shell32.ILCreateFromPathW.argtypes = [ctypes.c_wchar_p]
    shell32.ILCreateFromPathW.restype = ctypes.c_void_p
    shell32.ILFree.argtypes = [ctypes.c_void_p]
    shell32.ILFree.restype = None
    shell32.SHOpenFolderAndSelectItems.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint,
        ctypes.c_void_p,
        ctypes.c_ulong,
    ]
    shell32.SHOpenFolderAndSelectItems.restype = ctypes.c_long

    com_inited = False
    with suppress(Exception):
        hr = ole32.CoInitializeEx(None, 0x2)  # COINIT_APARTMENTTHREADED
        com_inited = hr in (0, 1)

    pidl = shell32.ILCreateFromPathW(resolved_str)
    if not pidl:
        if com_inited:
            with suppress(Exception):
                ole32.CoUninitialize()
        return False
    try:
        hr = shell32.SHOpenFolderAndSelectItems(pidl, 0, None, 0)
        return hr == 0
    finally:
        shell32.ILFree(pidl)
        if com_inited:
            with suppress(Exception):
                ole32.CoUninitialize()


def indicator_weight(ind) -> int:
    """Resolve effective numeric score weight (handles ``weight=None`` via BASE_WEIGHTS)."""
    from ..core.scoring import BASE_WEIGHTS

    return int(ind.effective_weight(BASE_WEIGHTS))


def result_is_incomplete(result) -> bool:
    """True when any stage failed/skipped OR the scan carries an ``error`` marker."""
    return bool(result.is_incomplete or getattr(result, "error", None))
