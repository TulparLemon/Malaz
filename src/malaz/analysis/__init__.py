"""Auxiliary analysis integrations (local AV engines + status diagnosis)."""

from .clamav import ClamAVResult, ClamAVScanner
from .defender_status import DefenderStatus
from .defender_status import probe as probe_defender_status
from .external_scanner import ExternalScanner, ExternalScanResult, build_scanners
from .privilege import is_admin, privilege_label
from .windows_av import AVResult, WindowsDefenderScanner

__all__ = [
    "AVResult",
    "ClamAVResult",
    "ClamAVScanner",
    "DefenderStatus",
    "ExternalScanResult",
    "ExternalScanner",
    "WindowsDefenderScanner",
    "build_scanners",
    "is_admin",
    "privilege_label",
    "probe_defender_status",
]
