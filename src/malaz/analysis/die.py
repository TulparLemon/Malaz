"""Detect-It-Easy integration (optional external engine, MIT license).

DIE (``diec.exe``) identifies packers, protectors, compilers and installers of
executable files — the classic "what made this binary" question that static
triage otherwise cannot answer. Like ClamAV/7-Zip it is an *external* binary the
user installs; when it is missing the stage is skipped gracefully with a hint.

Scope note: DIE also ships heuristic malware-family detection. We deliberately
only surface format/type information (Packer/Protector/Compiler/Installer/…),
never family verdicts — the AV scope of this application stays with
Defender/ClamAV.

Security notes (see docs/SECURITY_MODEL.md):
* subprocess with an argument list and ``shell=False``; the file path is a
  single literal argv element (no injection).
* the binary is resolved from fixed install locations / PATH only.
* a hard timeout bounds the scan.
"""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .. import config
from ..core.toolpath import which_absolute
from ..procio import decode_tool_output, run_tool, tool_output_truncated

log = logging.getLogger(__name__)


@dataclass
class DieResult:
    scanned: bool = False
    findings: list[dict] = None  # type: ignore[assignment]
    returncode: int | None = None
    detail: str = ""
    skipped_reason: str | None = None

    def __post_init__(self) -> None:
        if self.findings is None:
            self.findings = []


class DieScanner:
    """Thin wrapper around ``diec.exe -j``."""

    def __init__(self, enabled: bool | None = None, timeout: int | None = None):
        self.enabled = config.DIE_ENABLED if enabled is None else enabled
        self.timeout = config.DIE_TIMEOUT_SECONDS if timeout is None else timeout
        self.binary: Path | None = self._locate() if self.enabled else None

    @property
    def available(self) -> bool:
        return self.enabled and self.binary is not None

    def _locate(self) -> Path | None:
        for candidate in config.DIE_CANDIDATES:
            path = Path(candidate)
            if path.is_file():
                return path
        for name in ("diec", "diec.exe"):
            found = which_absolute(name)
            if found:
                return Path(found)
        return None

    def scan_path(self, path: Path | str) -> DieResult:
        """Run DIE on an existing file; returns structured findings."""
        if not self.available:
            return DieResult(
                skipped_reason="Detect It Easy nicht installiert oder deaktiviert"
            )
        # Same contract as the other external engines: always hand over an
        # absolute path so the tool never resolves relative to its own cwd.
        target = Path(path).resolve()
        if not target.is_file():
            return DieResult(skipped_reason="Datei existiert nicht auf dem Datenträger")
        return self._run(str(target))

    def _run(self, target: str) -> DieResult:
        if self.binary is None:  # callers check .available; stay defensive
            return DieResult(skipped_reason="diec nicht gefunden")
        args = [str(self.binary), "-j", target]
        try:
            proc = run_tool(args, timeout=self.timeout)
        except subprocess.TimeoutExpired:
            return DieResult(
                skipped_reason=f"DIE-Scan abgebrochen (Timeout > {self.timeout}s)"
            )
        except FileNotFoundError:
            return DieResult(skipped_reason="diec nicht gefunden")
        except Exception as exc:
            return DieResult(
                skipped_reason=f"DIE-Scan fehlgeschlagen: {type(exc).__name__}: {exc}"
            )

        rc, raw_out, raw_err = proc
        output = self._decode(raw_out) + self._decode(raw_err)
        if tool_output_truncated(proc):
            # SEC-023: the visible text is a prefix. Parsing it could miss the
            # actual packer/protector entry (the JSON is a single document) and
            # report "no usable results" — a statement about output that was
            # never seen. Stay explicit: not checked.
            return DieResult(
                scanned=False,
                returncode=rc,
                skipped_reason=(
                    "DIE-Ausgabe wurde an der Ausgabe-Obergrenze abgeschnitten "
                    "— Teilausgabe nicht ausgewertet (Packer-/Protector-"
                    "Erkennung nicht aussagekräftig)"
                ),
                detail=output.strip()[: config.MAX_STRING_CAPTURE],
            )
        if rc != 0:
            return DieResult(
                scanned=False,
                returncode=rc,
                skipped_reason=f"DIE-Scan nicht aussagekräftig (Returncode {rc})",
                detail=output.strip()[: config.MAX_STRING_CAPTURE],
            )
        findings = _parse_die_output(output)
        if not findings:
            return DieResult(
                scanned=False,
                returncode=rc,
                skipped_reason="DIE-Scan ohne verwertbare Ergebnisse",
                detail=output.strip()[: config.MAX_STRING_CAPTURE],
            )
        return DieResult(
            scanned=True,
            findings=findings,
            returncode=rc,
            detail=" | ".join(_finding_label(f) for f in findings),
        )

    @staticmethod
    def _decode(raw: bytes | None) -> str:
        return decode_tool_output(raw)


# -- output parsing -------------------------------------------------------- #


def _parse_die_output(output: str) -> list[dict]:
    """Parse ``diec -j`` JSON into a list of ``{type, name, version}`` dicts.

    DIE 3.x wraps everything: ``{"detects": [{..., "values": [{type, name,
    version, string}]}]}``. Malformed output degrades to an empty list (caller
    reports a skip).
    """
    text = output.strip()
    if not text:
        return []
    start = text.find("{")
    if start == -1:
        return []
    try:
        # raw_decode tolerates extra lines after the JSON object (warnings,
        # hints) that diec may append to the combined stdout/stderr capture.
        payload, _ = json.JSONDecoder().raw_decode(text[start:])
    except json.JSONDecodeError:
        return []
    if isinstance(payload, dict):
        for key in ("detects", "detections", "entries"):
            if isinstance(payload.get(key), list):
                payload = payload[key]
                break
        else:
            return []
    if not isinstance(payload, list):
        return []
    out: list[dict] = []
    for detect in payload:
        if not isinstance(detect, dict):
            continue
        filetype = str(detect.get("filetype") or "").strip()
        for value in detect.get("values") or []:
            if not isinstance(value, dict):
                continue
            ftype = str(value.get("type") or filetype or "").strip()
            name = str(value.get("name") or "").strip()
            if not ftype or not name:
                continue
            entry = {"type": ftype, "name": name}
            version = str(value.get("version") or "").strip()
            if version:
                entry["version"] = version
            out.append(entry)
    return out


# Types whose presence raises the risk score vs. mere fingerprints.
_RISK_TYPES = ("packer", "protector", "cryptor", "installer", "obfuscator")


def _finding_label(finding: dict) -> str:
    parts = [str(finding.get("type") or "?"), str(finding.get("name") or "?")]
    if finding.get("version"):
        parts.append(finding["version"])
    return ": ".join(parts)


def finding_risk(finding: dict) -> int:
    """Map a DIE finding to a score weight (0 = fingerprint only)."""
    ftype = str(finding.get("type") or "").lower()
    if ftype in _RISK_TYPES:
        # Installers are common and benign on their own.
        return 10 if ftype == "installer" else 30
    return 0
