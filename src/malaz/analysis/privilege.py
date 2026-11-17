"""Process privilege detection (read-only, no elevation performed).

Reports whether the current process runs with administrator / root privileges.
This is informational only (shown in the engine status line) and helps answer
"does this tool need admin rights?" at a glance. The check never requests
elevation and never fails hard.
"""

from __future__ import annotations

import ctypes
import os
import sys


def is_admin() -> bool | None:
    """Return True/False when determinable, else None.

    * Windows: ``IsUserAnAdmin`` via ctypes (a query, not a UAC prompt).
    * POSIX: ``os.geteuid() == 0``.
    * Anything else / any error: ``None``.
    """
    try:
        if sys.platform == "win32":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        if hasattr(os, "geteuid"):
            return os.geteuid() == 0
    except Exception:
        return None
    return None


def privilege_label() -> str:
    """Human-readable German label for the current privilege level."""
    admin = is_admin()
    if admin is True:
        return "Administrator"
    if admin is False:
        return "normaler Nutzer (keine Adminrechte nötig)"
    return "unbekannt"
