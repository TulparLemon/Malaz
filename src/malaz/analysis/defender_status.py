"""Windows Defender status diagnosis (read-only).

Reports whether Defender can actually scan on this machine, which matters when
a third-party EDR is the primary AV. The probe is performed with a fixed
PowerShell command (argument list, ``shell=False``); no services are started and
no system state is changed.

The result is informational (shown in the UI / CLI) and is *not* a per-file
finding, so it never influences the risk score.
"""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass

from ..core.toolpath import which_absolute
from ..procio import decode_tool_output, run_tool, tool_output_truncated

log = logging.getLogger(__name__)

# Fixed, internal PowerShell expression. Never built from user/payload data.
_PS_COMMAND = (
    "Get-MpComputerStatus | Select-Object "
    "AMRunningMode,RealTimeProtectionEnabled,AntivirusEnabled,AntispywareEnabled,"
    "AMServiceEnabled,IsTamperProtected,AMProductVersion,NISEngineVersion,"
    "AntivirusSignatureVersion | ConvertTo-Json"
)

_MODE_HINT = {
    "normal": "Aktiv (Echtzeitschutz läuft)",
    "passive": "Passivmodus (On-Demand-Scans möglich, Echtzeitschutz durch EDR/anderes AV)",
    "edr": "EDR-blockiert (Defender-Engine durch MDE/EDR gesperrt)",
    "not running": "Dienst läuft nicht",
    "unknown": "Unbekannter Modus",
}


def _canon_mode(raw: str) -> str:
    """Reduce a free-form AMRunningMode string to a canonical key.

    PowerShell returns values like "Normal", "Passive Mode", "EDR Blocked Mode"
    or "SxS Passive Mode"; matching on keywords is more robust than exact keys.
    """
    text = (raw or "").strip().lower()
    if not text:
        return "unknown"
    if "not running" in text:
        return "not running"
    if "edr" in text:
        return "edr"
    if "passive" in text:
        return "passive"
    if "normal" in text:
        return "normal"
    return "unknown"


@dataclass
class DefenderStatus:
    probed: bool = False
    mode: str = ""                 # AMRunningMode, normalised
    realtime_enabled: bool | None = None
    antivirus_enabled: bool | None = None
    service_enabled: bool | None = None
    tamper_protected: bool | None = None
    product_version: str = ""
    signature_version: str = ""
    summary: str = ""
    error: str | None = None

    @property
    def can_scan(self) -> bool:
        """Best-effort: is an on-demand scan likely to work?"""
        if not self.probed:
            return False
        canon = _canon_mode(self.mode)
        # Passive mode and normal mode both allow MpCmdRun on-demand scans.
        return canon in ("normal", "passive") or bool(self.service_enabled)


def _norm_mode(value: object) -> str:
    return str(value or "").strip().lower()


def _report(status: DefenderStatus) -> DefenderStatus:
    """Log the probe outcome so malaz.log answers 'why is Defender odd?'."""
    if status.probed:
        log.info("Defender-Status: %s", status.summary)
    else:
        log.warning("Defender-Status nicht abrufbar: %s", status.error)
    return status


def probe(timeout: int = 20) -> DefenderStatus:
    """Query Defender status via PowerShell. Never raises."""
    pwsh = which_absolute("powershell") or which_absolute("pwsh")
    if not pwsh:
        return _report(DefenderStatus(error="PowerShell nicht gefunden (powershell/pwsh)"))

    args = [str(pwsh), "-NoProfile", "-NonInteractive", "-Command", _PS_COMMAND]
    try:
        proc = run_tool(args, timeout=timeout)
    except subprocess.TimeoutExpired:
        return _report(DefenderStatus(error=f"Status-Abfrage abgebrochen (Timeout > {timeout}s)"))
    except Exception as exc:
        return _report(DefenderStatus(error=f"Status-Abfrage fehlgeschlagen: {type(exc).__name__}: {exc}"))

    if tool_output_truncated(proc):
        # SEC-023: a cut-off status document is unknown, not "normal mode".
        return _report(
            DefenderStatus(
                error=(
                    "Status-Ausgabe wurde an der Ausgabe-Obergrenze "
                    "abgeschnitten — Defender-Status unbekannt"
                )
            )
        )
    _rc, raw_out, raw_err = proc
    raw = decode_tool_output(raw_out).strip()
    if not raw:
        err = decode_tool_output(raw_err).strip()
        return _report(DefenderStatus(error=f"Keine Status-Ausgabe. {err[:200]}"))

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return _report(DefenderStatus(error=f"Status-Ausgabe nicht parsebar: {exc}"))
    if isinstance(data, list):
        data = data[0] if data else {}
    if not isinstance(data, dict):
        return _report(DefenderStatus(error="Unerwartetes Status-Format"))

    mode = _norm_mode(data.get("AMRunningMode"))
    status = DefenderStatus(
        probed=True,
        mode=mode or "unknown",
        realtime_enabled=_bool(data.get("RealTimeProtectionEnabled")),
        antivirus_enabled=_bool(data.get("AntivirusEnabled")),
        service_enabled=_bool(data.get("AMServiceEnabled")),
        tamper_protected=_bool(data.get("IsTamperProtected")),
        product_version=str(data.get("AMProductVersion") or ""),
        signature_version=str(
            data.get("AntivirusSignatureVersion") or data.get("NISEngineVersion") or ""
        ),
    )
    status.summary = _summarise(status)
    return _report(status)


def _bool(value: object) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "1", "yes")


def _summarise(s: DefenderStatus) -> str:
    hint = _MODE_HINT.get(_canon_mode(s.mode), _MODE_HINT["unknown"])
    parts = [f"Modus: {s.mode or '?'} ({hint})"]
    if s.realtime_enabled is not None:
        parts.append("Echtzeitschutz " + ("an" if s.realtime_enabled else "aus"))
    if s.antivirus_enabled is not None:
        parts.append("AV-Engine " + ("aktiv" if s.antivirus_enabled else "inaktiv"))
    if s.tamper_protected is not None:
        # Tamper Protection is what keeps a malware process from switching
        # Defender off — without it the AV verdict is a statement about a
        # configuration that the malware could have changed. The probe has
        # always read it; now the operator sees it next to the verdict.
        parts.append(
            "Tamper Protection "
            + ("an" if s.tamper_protected else "AUS (Defender-Verdikt weniger belastbar)")
        )
    if s.signature_version:
        parts.append(f"Signaturen: {s.signature_version}")
    if s.product_version:
        parts.append(f"Produktversion: {s.product_version}")
    verdict = "On-Demand-Scan voraussichtlich möglich." if s.can_scan else (
        "On-Demand-Scan voraussichtlich NICHT möglich (Defender deaktiviert/kein Passivmodus)."
    )
    return " | ".join(parts) + " || " + verdict
