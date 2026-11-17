"""Branding assets (icon, logo) and where to find them.

The window/taskbar icon MUST come from the ``.ico`` file: ``QIcon(exe_path)``
returns a null icon because Qt's icon loader reads image files, not PE
resources — the icon embedded in the exe (by Nuitka's
``--windows-icon-from-ico``) is only seen by Explorer. The build therefore
ships ``assets/malaz.ico`` next to the binary as well.
"""

from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtGui import QIcon


def _frozen() -> bool:
    # Nuitka standalone/onefile: sys.frozen may be absent, but __compiled__
    # is always present in compiled modules.
    return getattr(sys, "frozen", False) or "__compiled__" in globals()


def asset_dir() -> Path:
    """Bundled assets: next to the exe when frozen, source tree otherwise."""
    if _frozen():
        return Path(sys.executable).parent / "assets"
    return Path(__file__).resolve().parents[2] / "assets"


def app_icon() -> QIcon:
    """Application icon from ``assets/malaz.ico``; null icon if unavailable."""
    candidate = asset_dir() / "malaz.ico"
    if candidate.is_file():
        icon = QIcon(str(candidate))
        if not icon.isNull():
            return icon
    return QIcon()


def logo_path() -> Path:
    """Full-colour logo file (About dialog, header) if present."""
    return asset_dir() / "malaz_logo.png"
